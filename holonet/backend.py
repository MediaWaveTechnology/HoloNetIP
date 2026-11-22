"""HoloNet backend: live router telemetry and speed-test streams for the HoloNet map.

Originally developed inside ASUSRouterControl; now standalone in exampleTechnology/HOLONET.

What it does
  1. Fast sampler: one persistent SSH connection to the router (dedicated key,
     pinned host key), one batched command every few seconds. Reads
     /proc/net/dev (WAN) and `wl sta_info` byte counters per Wi-Fi client,
     turns deltas into Mbps. Read-only: it never writes to the router.
  2. Speed-test streams: runs the multi-provider speed test (holonet.speedtest_providers)
     on a schedule and keeps every provider's result separately
     (Ookla, Cloudflare, and a CDN stream = median of the CDN HTTP providers).
  3. Local HTTP (GET only):
       /api/live   JSON for the map
       /metrics    Prometheus text (raw byte counters + speed-test gauges)
       /healthz

Honesty rules
  - A value that could not be measured is null, never 0.
  - Every block carries its sample time and status.
  - Router tx = the device's download, router rx = the device's upload.

Run:  python -m holonet.backend
Config comes from ~/.holonet/router.env and/or the environment (see Settings).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import logging.handlers
import os
import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("holonet.backend")

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_CDN_MEMBERS = ("cachefly", "cloudfront", "fastly")
_BAND = {"2": "2.4GHz", "1": "5GHz", "4": "6GHz"}


def _now() -> float:
    return time.time()


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _norm_mac(mac: str) -> str:
    return mac.strip().lower()


# --------------------------------------------------------------------------- settings


@dataclass
class Settings:
    router_host: str = "192.0.2.1"
    router_port: int = 1313
    router_user: str = ""
    key_path: Path = Path.home() / ".ssh" / "id_ed25519_holonet_router"
    known_hosts: Path = Path.home() / ".holonet" / "known_hosts"
    bind: str = "127.0.0.1"
    port: int = 9108
    sample_s: float = 5.0
    speedtest_every_min: int = 240
    speedtest_enabled: bool = True
    data_dir: Path = Path.home() / ".holonet" / "data"


def _read_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


def load_settings() -> Settings:
    env = _read_env_file(Path.home() / ".holonet" / "router.env")
    env.update({k: v for k, v in os.environ.items() if k.startswith(("ROUTER_SSH_", "HOLONET_"))})
    s = Settings()
    s.router_host = env.get("ROUTER_SSH_HOST", s.router_host)
    s.router_port = int(env.get("ROUTER_SSH_PORT", s.router_port))
    s.router_user = env.get("ROUTER_SSH_USER", s.router_user)
    if env.get("ROUTER_SSH_KEY"):
        s.key_path = Path(env["ROUTER_SSH_KEY"]).expanduser()
    if env.get("ROUTER_SSH_KNOWN_HOSTS"):
        s.known_hosts = Path(env["ROUTER_SSH_KNOWN_HOSTS"]).expanduser()
    s.bind = env.get("HOLONET_BIND", s.bind)
    s.port = int(env.get("HOLONET_PORT", s.port))
    s.sample_s = max(2.0, float(env.get("HOLONET_SAMPLE_S", s.sample_s)))
    s.speedtest_every_min = max(
        15, int(env.get("HOLONET_SPEEDTEST_EVERY_MIN", s.speedtest_every_min))
    )
    s.speedtest_enabled = env.get("HOLONET_SPEEDTEST", "1") not in ("0", "false", "no")
    if env.get("HOLONET_DATA_DIR"):
        s.data_dir = Path(env["HOLONET_DATA_DIR"]).expanduser()
    try:
        s.data_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log.warning("could not create data dir %s", s.data_dir)
    return s


LEGACY_DATA_DIR = Path.home() / ".asusroutercontrol"  # where results lived before the move


# --- parsing (pure, unit-testable) ----------------------------------------


def parse_discovery(text: str) -> dict:
    """Parse the one-off discovery command output."""
    sect: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            sect[cur] = []
        elif cur is not None:
            sect[cur].append(line.strip())
    wan = next((x for x in sect.get("WAN", []) if x and _IFACE_RE.match(x)), None)
    net = {x for x in sect.get("NET", []) if _IFACE_RE.match(x)}
    wl: dict[str, dict] = {}
    for line in sect.get("WL", []):
        m = re.match(r"^wl(\d+)=(\S*) band=(\S*)$", line)
        if not m or not m.group(2) or not _IFACE_RE.match(m.group(2)):
            continue
        wl[m.group(2)] = {"unit": int(m.group(1)), "band": _BAND.get(m.group(3), "")}
    # guest / IoT / MLO sub-interfaces (wl0.1 ...) that exist as netdevs
    for name in sorted(net):
        m = re.match(r"^wl(\d+)\.(\d+)$", name)
        if m and name not in wl:
            parent = next((v for v in wl.values() if v["unit"] == int(m.group(1))), None)
            wl[name] = {
                "unit": int(m.group(1)),
                "band": (parent or {}).get("band", ""),
                "sub": True,
            }
    model = " ".join(x for x in sect.get("MODEL", []) if x)
    return {"wan_iface": wan, "wl_ifaces": wl, "model": model, "netdevs": sorted(net)}


def build_tick_command(wl_ifaces: list[str]) -> str:
    ifs = " ".join(i for i in wl_ifaces if _IFACE_RE.match(i))
    return (
        "cat /proc/uptime; echo @@DEV; cat /proc/net/dev; "
        f"for i in {ifs}; do for m in $(wl -i $i assoclist 2>/dev/null | awk '{{print $2}}'); do "
        'echo "@@STA $i $m"; wl -i $i sta_info $m 2>/dev/null | '
        "grep -E 'tx total bytes|tx data bytes|tx ucast bytes|"
        "rx data bytes|rx ucast bytes|in network|"
        "rate of last tx pkt|rate of last rx pkt|"
        "per antenna rssi of last rx data frame'; done; done; echo @@END"
    )


def parse_tick(text: str) -> dict:
    """Parse one sampler tick. Returns {uptime, dev: {iface: (rx, tx)}, sta: [..], complete}."""
    uptime = None
    dev: dict[str, tuple[int, int]] = {}
    sta: list[dict] = []
    cur = None
    mode = "head"
    complete = False
    for raw in text.splitlines():
        line = raw.strip()
        if line == "@@DEV":
            mode = "dev"
            continue
        if line == "@@END":
            complete = True
            continue
        if line.startswith("@@STA "):
            parts = line.split()
            cur = None
            if len(parts) == 3 and _IFACE_RE.match(parts[1]) and _MAC_RE.match(parts[2]):
                cur = {"iface": parts[1], "mac": _norm_mac(parts[2])}
                sta.append(cur)
            mode = "sta"
            continue
        if mode == "head":
            if uptime is None and line:
                try:
                    uptime = float(line.split()[0])
                except ValueError:
                    pass
        elif mode == "dev":
            if ":" in line:
                name, rest = line.split(":", 1)
                f = rest.split()
                if len(f) >= 9 and f[0].isdigit():
                    dev[name.strip()] = (int(f[0]), int(f[8]))
        elif mode == "sta" and cur is not None:
            # Field names differ by firmware: RT-BE92U stock has "tx total bytes" and no
            # "tx data bytes"; older Merlin builds have "tx data bytes". First match per field wins.
            m = re.search(
                r"(tx total bytes|tx data bytes|tx ucast bytes|"
                r"rx data bytes|rx ucast bytes):\s*(\d+)",
                line,
            )
            if m:
                key = "tx_bytes" if m.group(1).startswith("tx") else "rx_bytes"
                rank = {
                    "tx total bytes": 0,
                    "tx data bytes": 1,
                    "tx ucast bytes": 2,
                    "rx data bytes": 0,
                    "rx ucast bytes": 1,
                }[m.group(1)]
                if rank < cur.get(key + "_rank", 99):
                    cur[key], cur[key + "_rank"] = int(m.group(2)), rank
            m = re.search(r"in network\s+(\d+)\s+seconds", line)
            if m:
                cur["in_network_s"] = int(m.group(1))
            m = re.search(r"rate of last tx pkt:\s*(\d+)\s*kbps", line)
            if m:
                cur["phy_tx_mbps"] = int(m.group(1)) / 1000
            m = re.search(r"rate of last rx pkt:\s*(\d+)\s*kbps", line)
            if m:
                cur["phy_rx_mbps"] = int(m.group(1)) / 1000
            m = re.search(r"per antenna rssi of last rx data frame:\s*(.+)", line)
            if m:
                vals = [int(v) for v in re.findall(r"-?\d+", m.group(1)) if int(v) != 0]
                if vals:
                    cur["rssi"] = max(vals)
    return {"uptime": uptime, "dev": dev, "sta": sta, "complete": complete}


_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def parse_neighbors(text: str) -> list[dict]:
    """Router ARP table + DHCP leases -> [{ip, mac, hostname, complete}].

    Hostnames are device-supplied: treat them as data only.
    """
    arp_part, _, lease_part = text.partition("@@LEASES")
    names: dict[str, str] = {}
    for line in lease_part.splitlines():
        f = line.split()
        if len(f) >= 4 and _MAC_RE.match(f[1]):
            hn = f[3] if f[3] != "*" else ""
            names[_norm_mac(f[1])] = re.sub(r"[^A-Za-z0-9._ -]", "", hn)[:63]
    out: dict[str, dict] = {}
    for line in arp_part.splitlines():
        f = line.split()
        if (
            len(f) >= 6
            and _IPV4_RE.match(f[0])
            and _MAC_RE.match(f[3])
            and f[3] != "00:00:00:00:00:00"
        ):
            if not f[5].startswith("br"):
                continue  # LAN bridge only; skips the WAN side
            mac = _norm_mac(f[3])
            out[f[0]] = {
                "ip": f[0],
                "mac": mac,
                "hostname": names.get(mac, ""),
                "complete": f[2] == "0x2",
            }
    return sorted(out.values(), key=lambda d: tuple(int(x) for x in d["ip"].split(".")))


class RateBook:
    """Turns byte counters into Mbps. Returns None (not 0) when a delta is not trustworthy."""

    def __init__(self) -> None:
        self.prev: dict[str, tuple[int, int, float, tuple]] = {}
        self.total: dict[str, list[int]] = {}  # monotonic [down_bytes, up_bytes] for Prometheus

    def reset(self) -> None:
        self.prev.clear()

    def update(
        self, key: str, down_bytes: int, up_bytes: int, t: float, sig: tuple = ()
    ) -> dict | None:
        p = self.prev.get(key)
        self.prev[key] = (down_bytes, up_bytes, t, sig)
        self.total.setdefault(key, [0, 0])
        if p is None or p[3] != sig:
            return None
        dd, du, dt = down_bytes - p[0], up_bytes - p[1], t - p[2]
        if dt <= 0 or dd < 0 or du < 0:  # reset, roam or 32-bit wrap: discard the sample
            return None
        self.total[key][0] += dd
        self.total[key][1] += du
        return {"down_mbps": round(dd * 8 / dt / 1e6, 3), "up_mbps": round(du * 8 / dt / 1e6, 3)}

    def forget(self, keep: set[str], prefix: str) -> None:
        for k in [k for k in self.prev if k.startswith(prefix) and k not in keep]:
            self.prev.pop(k, None)


def merge_stations(sta: list[dict]) -> dict[str, dict]:
    """Group per-interface station rows by MAC.

    A MAC seen on several interfaces (Wi-Fi 7 MLO) is summed.
    """
    out: dict[str, dict] = {}
    for s in sta:
        if "tx_bytes" not in s and "rx_bytes" not in s:
            continue
        d = out.setdefault(s["mac"], {"mac": s["mac"], "ifaces": [], "tx_bytes": 0, "rx_bytes": 0})
        d["ifaces"].append(s["iface"])
        d["tx_bytes"] += s.get("tx_bytes", 0)
        d["rx_bytes"] += s.get("rx_bytes", 0)
        for k in ("rssi", "phy_tx_mbps", "phy_rx_mbps"):
            if k in s:
                d[k] = max(d.get(k, s[k]), s[k])
        if "in_network_s" in s:
            d["in_network_s"] = min(d.get("in_network_s", s["in_network_s"]), s["in_network_s"])
    return out


# --------------------------------------------------------------------------- sampler


class Sampler:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.rates = RateBook()
        self.status = "starting"
        self.error: str | None = None
        self.last_ok: float | None = None
        self.disc: dict = {}
        self.wan: dict | None = None
        self.clients: list[dict] = []
        self.router_uptime: float | None = None
        self.tick_ms: float | None = None
        self.ticks = 0
        self.neighbors: list[dict] = []
        self.neighbors_at: float | None = None

    async def run(self) -> None:
        import asyncssh

        backoff = 5.0
        while True:
            if (
                not self.s.router_user
                or not self.s.key_path.exists()
                or not self.s.known_hosts.exists()
            ):
                self.status, self.error = (
                    "not_configured",
                    "router user, key or pinned host key missing",
                )
                await asyncio.sleep(30)
                continue
            try:
                async with asyncssh.connect(
                    self.s.router_host,
                    port=self.s.router_port,
                    username=self.s.router_user,
                    client_keys=[str(self.s.key_path)],
                    known_hosts=str(self.s.known_hosts),
                    agent_path=None,
                    password=None,
                    preferred_auth=["publickey"],
                    config=[],
                    keepalive_interval=15,
                    login_timeout=10,
                    connect_timeout=10,
                ) as conn:
                    backoff = 5.0
                    await self._session(conn)
            except asyncio.CancelledError:
                raise
            except asyncssh.PermissionDenied:
                self.status, self.error = (
                    "no_router_access",
                    "router refused the key (not in Authorized Keys?)",
                )
                backoff = 60.0  # do not hammer the router's login
            except asyncssh.HostKeyNotVerifiable as e:
                self.status, self.error = (
                    "host_key_mismatch",
                    f"router host key does not match the pinned key: {e}",
                )
                backoff = 300.0
            except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
                self.status, self.error = "error", f"{type(e).__name__}: {str(e)[:160]}"
            except Exception as e:  # never die
                log.exception("sampler crashed")
                self.status, self.error = "error", f"{type(e).__name__}: {str(e)[:160]}"
            self.rates.reset()
            self.wan, self.clients = None, []
            log.warning("sampler: %s (%s); retry in %.0fs", self.status, self.error, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60.0) if backoff < 60 else backoff

    async def _session(self, conn) -> None:
        disc_cmd = (
            "echo @@WAN; nvram get wan0_ifname; nvram get wan_ifname; echo @@WL; "
            'for u in 0 1 2 3; do echo "wl${u}=$(nvram get wl${u}_ifname) '
            'band=$(nvram get wl${u}_nband)"; done; '
            "echo @@NET; ls /sys/class/net; echo @@MODEL; "
            "nvram get productid; nvram get firmver; nvram get buildno"
        )
        r = await asyncio.wait_for(conn.run(disc_cmd, check=False), timeout=10)
        self.disc = parse_discovery(str(r.stdout or ""))
        ifaces = list(self.disc["wl_ifaces"].keys())
        log.info(
            "router %s wan=%s wl=%s", self.disc.get("model"), self.disc.get("wan_iface"), ifaces
        )
        cmd = build_tick_command(ifaces)
        timeout = max(3.0, self.s.sample_s - 0.5)
        nb_cmd = "cat /proc/net/arp; echo @@LEASES; cat /var/lib/misc/dnsmasq.leases 2>/dev/null"
        while True:
            t0 = time.monotonic()
            if self.neighbors_at is None or _now() - self.neighbors_at > 60:
                try:
                    nb = await asyncio.wait_for(conn.run(nb_cmd, check=False), timeout=timeout)
                    self.neighbors, self.neighbors_at = (
                        parse_neighbors(str(nb.stdout or "")),
                        _now(),
                    )
                except asyncio.TimeoutError:
                    log.warning("router neighbor read timed out")
            r = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
            self._ingest(parse_tick(str(r.stdout or "")), time.monotonic())
            self.tick_ms = round((time.monotonic() - t0) * 1000, 1)
            await asyncio.sleep(max(0.2, self.s.sample_s - (time.monotonic() - t0)))

    def _ingest(self, tick: dict, t: float) -> None:
        if not tick["complete"]:
            self.status, self.error = "error", "incomplete sample from router"
            return
        up = tick["uptime"]
        if up is not None and self.router_uptime is not None and up < self.router_uptime:
            self.rates.reset()  # router rebooted
        self.router_uptime = up
        wan_if = self.disc.get("wan_iface")
        self.wan = None
        if wan_if and wan_if in tick["dev"]:
            rx, tx = tick["dev"][wan_if]
            rate = self.rates.update("wan", rx, tx, t)  # WAN rx = download
            self.wan = {
                "iface": wan_if,
                "down_mbps": rate and rate["down_mbps"],
                "up_mbps": rate and rate["up_mbps"],
            }
        merged = merge_stations(tick["sta"])
        clients = []
        for mac, d in merged.items():
            sig = tuple(sorted(d["ifaces"]))
            rate = self.rates.update(
                "c:" + mac, d["tx_bytes"], d["rx_bytes"], t, sig
            )  # AP tx = device download
            first = d["ifaces"][0]
            clients.append(
                {
                    "mac": mac,
                    "ifaces": d["ifaces"],
                    "links": len(d["ifaces"]),
                    "band": self.disc["wl_ifaces"].get(first, {}).get("band", ""),
                    "down_mbps": rate and rate["down_mbps"],
                    "up_mbps": rate and rate["up_mbps"],
                    "rssi": d.get("rssi"),
                    "phy_down_mbps": d.get("phy_tx_mbps"),
                    "phy_up_mbps": d.get("phy_rx_mbps"),
                    "in_network_s": d.get("in_network_s"),
                }
            )
        self.rates.forget({"c:" + m for m in merged}, "c:")
        self.clients = clients
        self.status, self.error, self.last_ok = "ok", None, _now()
        self.ticks += 1

    def snapshot(self) -> dict:
        age = None if self.last_ok is None else round(_now() - self.last_ok, 1)
        status = self.status
        if status == "ok" and age is not None and age > self.s.sample_s * 3:
            status = "stale"
        fresh = status == "ok"
        return {
            "status": status,
            "error": self.error,
            "interval_s": self.s.sample_s,
            "sampled_at": _iso(self.last_ok),
            "age_s": age,
            "tick_ms": self.tick_ms,
            "router": self.disc.get("model") or None,
            "wan_iface": self.disc.get("wan_iface"),
            "wl_ifaces": list(self.disc.get("wl_ifaces", {}).keys()),
            "wan": self.wan if fresh else None,
            "clients": self.clients if fresh else [],
            "neighbors": self.neighbors,
            "neighbors_at": _iso(self.neighbors_at),
            "coverage": (
                "Wi-Fi clients and WAN only; wired LAN devices are not measured by the router"
            ),
        }


# --------------------------------------------------------------------------- speed-test streams


async def run_providers(cooldown: float = 10.0) -> list:
    """Run Ookla, Cloudflare and the CDN HTTP providers one after another.

    A provider that is not installed or fails is reported, never skipped silently.
    """
    from holonet import speedtest_providers as sp

    providers = [sp.OoklaProvider(), sp.CloudflareProvider()]
    providers += sp.build_cdn_http_providers(_CDN_MEMBERS)
    results: list = []
    for i, p in enumerate(providers):
        if not await p.is_available():
            results.append(sp.ProviderResult(provider=p.name, error="not available"))
            continue
        log.info("running %s speed test", p.name)
        results.append(await p.run())
        if i < len(providers) - 1:
            await asyncio.sleep(cooldown)
    return results


class SpeedStreams:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.file = s.data_dir / "holonet_speedtests.json"
        self.providers: dict[str, dict] = {}
        self.running = False
        self.started_at: float | None = None
        self.next_run_at: float | None = None
        self.last_run_at: float | None = None
        self.host = host_link_info()
        self._load()

    def _load(self) -> None:
        try:
            d = json.loads(self.file.read_text())
            self.providers = d.get("providers", {})
            self.last_run_at = d.get("last_run_at")
            return
        except (FileNotFoundError, ValueError):
            pass
        # first start after the move out of ASUSRouterControl: carry the last results over
        legacy = LEGACY_DATA_DIR / "holonet_speedtests.json"
        try:
            d = json.loads(legacy.read_text())
            self.providers = d.get("providers", {})
            self.last_run_at = d.get("last_run_at")
            log.info("seeded speed-test streams from %s", legacy)
        except (FileNotFoundError, ValueError, OSError):
            pass

    def _save(self) -> None:
        try:
            tmp = self.file.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"providers": self.providers, "last_run_at": self.last_run_at})
            )
            tmp.replace(self.file)
        except OSError:
            log.exception("could not persist speed test results")

    async def loop(self) -> None:
        every = self.s.speedtest_every_min * 60
        await asyncio.sleep(20)
        while True:
            due = (self.last_run_at or 0) + every
            self.next_run_at = max(due, _now())
            await asyncio.sleep(max(0, self.next_run_at - _now()))
            await self.run_once()

    async def run_once(self) -> None:
        self.running, self.started_at = True, _now()
        try:
            results = await asyncio.wait_for(run_providers(), timeout=600)
        except Exception as e:
            log.exception("speed test run failed")
            results = []
            for name in ("ookla", "cloudflare", *_CDN_MEMBERS):
                self.providers.setdefault(name, {})["error"] = f"run failed: {type(e).__name__}"
        finally:
            self.running = False
        now = _now()
        for r in results:
            cur = self.providers.setdefault(r.provider, {})
            if r.error or not r.download_bps:
                cur["error"], cur["error_at"] = (r.error or "no result"), now
                continue
            cur.update(
                {
                    "down_mbps": round(r.download_bps / 1e6, 1),
                    "up_mbps": round(r.upload_bps / 1e6, 1) if r.upload_bps else None,
                    "ping_ms": round(r.ping_ms, 1) if r.ping_ms else None,
                    "jitter_ms": round(r.jitter_ms, 1) if r.jitter_ms else None,
                    "server": r.server_name or r.pop_code,
                    "measured_at": now,
                    "error": None,
                    "from": f"{self.host['host']} ({self.host['link']})",
                }
            )
            cur.pop("error_at", None)
        self.last_run_at = now
        self._save()

    def _stream(self, sid: str, label: str, p: dict | None, note: str | None = None) -> dict:
        p = p or {}
        has = p.get("down_mbps") is not None
        at = p.get("measured_at")
        return {
            "id": sid,
            "label": label,
            "status": "ok"
            if has and not p.get("error")
            else "error"
            if p.get("error") and not has
            else "stale_error"
            if p.get("error")
            else "never",
            "down_mbps": p.get("down_mbps"),
            "up_mbps": p.get("up_mbps"),
            "ping_ms": p.get("ping_ms"),
            "jitter_ms": p.get("jitter_ms"),
            "server": p.get("server"),
            "measured_at": _iso(at),
            "age_s": None if at is None else round(_now() - at),
            "error": p.get("error"),
            "measured_from": p.get("from"),
            "note": note,
        }

    def snapshot(self) -> dict:
        members = []
        for m in _CDN_MEMBERS:
            p = self.providers.get(m) or {}
            if p.get("down_mbps") is not None:
                members.append(
                    {
                        "id": m,
                        "down_mbps": p["down_mbps"],
                        "ping_ms": p.get("ping_ms"),
                        "measured_at": p.get("measured_at"),
                        "from": p.get("from"),
                    }
                )
        cdn = None
        if members:
            pings = [x["ping_ms"] for x in members if x.get("ping_ms") is not None]
            cdn = {
                "down_mbps": round(statistics.median(x["down_mbps"] for x in members), 1),
                "up_mbps": None,
                "ping_ms": round(statistics.median(pings), 1) if pings else None,
                "server": ", ".join(f"{x['id']} {x['down_mbps']:g}" for x in members),
                "measured_at": max(x["measured_at"] for x in members),
                "error": None,
                "from": members[0].get("from"),
            }
        return {
            "running": self.running,
            "started_at": _iso(self.started_at) if self.running else None,
            "next_run_at": _iso(self.next_run_at),
            "every_min": self.s.speedtest_every_min,
            "host": self.host,
            "streams": [
                self._stream(
                    "ookla", "Ookla", self.providers.get("ookla"), "multi-stream, down + up"
                ),
                self._stream(
                    "cloudflare",
                    "Cloudflare",
                    self.providers.get("cloudflare"),
                    "4 parallel streams, down + up",
                ),
                self._stream(
                    "cdn",
                    "CDN median",
                    cdn,
                    "median of CacheFly, CloudFront, Fastly; "
                    "single-stream download only, reads lower than Ookla",
                ),
            ],
        }


def host_link_info() -> dict:
    """Which machine and link the speed tests run from.

    They measure this path, not only the WAN.
    """
    host = os.uname().nodename.split(".")[0]
    link = "unknown link"
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5
            ).stdout
            m = re.search(r"interface:\s*(\S+)", out)
            if m:
                iface = m.group(1)
                media = subprocess.run(
                    ["ifconfig", iface], capture_output=True, text=True, timeout=5
                ).stdout
                mm = re.search(r"media:\s*(.+)", media)
                ports = subprocess.run(
                    ["networksetup", "-listallhardwareports"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout
                kind = (
                    "Wi-Fi"
                    if re.search(r"Hardware Port: Wi-Fi\s*\nDevice: " + re.escape(iface), ports)
                    else "Ethernet"
                )
                link = f"{kind} {iface}" + (
                    f", {mm.group(1).strip()}" if mm and kind == "Ethernet" else ""
                )
    except Exception:
        pass
    return {"host": host, "link": link}


# --------------------------------------------------------------------------- HTTP


def render_metrics(sampler: Sampler, speed: SpeedStreams) -> str:
    L: list[str] = []
    snap = sampler.snapshot()
    L += [
        "# HELP holonet_sampler_up 1 when the router sampler has a fresh sample",
        "# TYPE holonet_sampler_up gauge",
        f"holonet_sampler_up {1 if snap['status'] == 'ok' else 0}",
    ]
    if sampler.last_ok:
        L += [
            "# TYPE holonet_sampler_last_success_timestamp_seconds gauge",
            f"holonet_sampler_last_success_timestamp_seconds {sampler.last_ok:.0f}",
        ]
    tot = sampler.rates.total
    if "wan" in tot:
        L += [
            "# HELP holonet_wan_download_bytes_total Bytes received on the router WAN interface",
            "# TYPE holonet_wan_download_bytes_total counter",
            f"holonet_wan_download_bytes_total {tot['wan'][0]}",
            "# TYPE holonet_wan_upload_bytes_total counter",
            f"holonet_wan_upload_bytes_total {tot['wan'][1]}",
        ]
    cl = {k[2:]: v for k, v in tot.items() if k.startswith("c:") and _MAC_RE.match(k[2:])}
    if cl:
        L += [
            "# HELP holonet_client_download_bytes_total Bytes the router sent to a Wi-Fi client",
            "# TYPE holonet_client_download_bytes_total counter",
        ]
        L += [
            f'holonet_client_download_bytes_total{{mac="{m}"}} {v[0]}'
            for m, v in sorted(cl.items())
        ]
        L += [
            "# HELP holonet_client_upload_bytes_total "
            "Bytes the router received from a Wi-Fi client",
            "# TYPE holonet_client_upload_bytes_total counter",
        ]
        L += [
            f'holonet_client_upload_bytes_total{{mac="{m}"}} {v[1]}' for m, v in sorted(cl.items())
        ]
    rssi = [(c["mac"], c["rssi"]) for c in snap["clients"] if c.get("rssi") is not None]
    if rssi:
        L += ["# TYPE holonet_client_rssi_dbm gauge"] + [
            f'holonet_client_rssi_dbm{{mac="{m}"}} {v}' for m, v in rssi
        ]
    L += [
        "# TYPE holonet_speedtest_in_progress gauge",
        f"holonet_speedtest_in_progress {1 if speed.running else 0}",
    ]
    rows = []
    for name, p in sorted(speed.providers.items()):
        if not re.match(r"^[a-z0-9_]+$", name) or p.get("down_mbps") is None:
            continue  # a failed provider exports no sample, never 0
        rows.append((name, p))
    if rows:
        L += ["# TYPE holonet_speedtest_download_mbps gauge"]
        L += [
            f'holonet_speedtest_download_mbps{{provider="{n}"}} {p["down_mbps"]}' for n, p in rows
        ]
        L += ["# TYPE holonet_speedtest_upload_mbps gauge"]
        L += [
            f'holonet_speedtest_upload_mbps{{provider="{n}"}} {p["up_mbps"]}'
            for n, p in rows
            if p.get("up_mbps") is not None
        ]
        L += ["# TYPE holonet_speedtest_ping_ms gauge"]
        L += [
            f'holonet_speedtest_ping_ms{{provider="{n}"}} {p["ping_ms"]}'
            for n, p in rows
            if p.get("ping_ms") is not None
        ]
        L += ["# TYPE holonet_speedtest_last_success_timestamp_seconds gauge"]
        L += [
            f'holonet_speedtest_last_success_timestamp_seconds{{provider="{n}"}} '
            f'{p["measured_at"]:.0f}'
            for n, p in rows
            if p.get("measured_at")
        ]
    return "\n".join(L) + "\n"


def make_app(sampler: Sampler, speed: SpeedStreams):
    from aiohttp import web

    async def live(_req):
        snap = sampler.snapshot()
        body = {
            "generated_at": _iso(_now()),
            "backend": "holonet.backend",
            "sampler": {
                k: snap[k]
                for k in (
                    "status",
                    "error",
                    "interval_s",
                    "sampled_at",
                    "age_s",
                    "tick_ms",
                    "router",
                    "wan_iface",
                    "wl_ifaces",
                    "coverage",
                )
            },
            "wan": snap["wan"],
            "clients": snap["clients"],
            "neighbors": snap["neighbors"],
            "neighbors_at": snap["neighbors_at"],
            "speedtests": speed.snapshot(),
        }
        return web.json_response(body, headers={"Cache-Control": "no-store"})

    async def metrics(_req):
        return web.Response(
            text=render_metrics(sampler, speed), content_type="text/plain", charset="utf-8"
        )

    async def health(_req):
        return web.json_response(
            {
                "ok": True,
                "sampler": sampler.snapshot()["status"],
                "release": os.environ.get("HOLONET_RELEASE") or None,
            }
        )

    app = web.Application()
    app.router.add_get("/api/live", live)
    app.router.add_get("/metrics", metrics)
    app.router.add_get("/healthz", health)
    return app


async def amain(args) -> None:
    from aiohttp import web

    s = load_settings()
    if args.port:
        s.port = args.port
    if args.no_speedtest:
        s.speedtest_enabled = False
    sampler, speed = Sampler(s), SpeedStreams(s)
    runner = web.AppRunner(make_app(sampler, speed), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, s.bind, s.port).start()
    log.info(
        "holonet export on http://%s:%d (sample %.0fs, speed tests every %d min, host %s)",
        s.bind,
        s.port,
        s.sample_s,
        s.speedtest_every_min,
        speed.host,
    )
    tasks = [asyncio.create_task(sampler.run())]
    if s.speedtest_enabled:
        tasks.append(asyncio.create_task(speed.loop()))
    if args.speedtest_now:
        tasks.append(asyncio.create_task(speed.run_once()))
    await asyncio.gather(*tasks)


def main() -> None:
    ap = argparse.ArgumentParser(description="HoloNet backend: live router telemetry + speed tests")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--no-speedtest", action="store_true")
    ap.add_argument("--speedtest-now", action="store_true", help="run one speed test at start")
    args = ap.parse_args()
    data_dir = load_settings().data_dir
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    try:
        handlers.append(
            logging.handlers.RotatingFileHandler(
                data_dir / "holonet.log", maxBytes=2_000_000, backupCount=3
            )
        )
    except OSError:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
