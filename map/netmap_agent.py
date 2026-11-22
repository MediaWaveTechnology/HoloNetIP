#!/usr/bin/env python3
"""
MWT Holo Net agent: the nmap connector for the 3D network map.

Runs on the monitoring host. On a schedule it:
  1. runs an nmap ping sweep of the LAN (who is up right now),
  2. reads the ARP cache (who was here recently but isn't answering),
  3. port-scans the hosts that are up (slower, less often),
  4. checks every device against inventory.json (anything not in it is flagged),
  5. serves the map page plus /api/topology (JSON) and /api/stream (live push).

Standard library only. Needs nmap (brew install nmap).
Run as root so nmap can use ARP pings and report MAC addresses and vendors;
without root you still get IPs and hostnames, but no MACs.

    sudo python3 netmap_agent.py --subnet 192.0.2.0/24 --gateway 192.0.2.1

Then open http://localhost:8787 on the monitoring host.
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = threading.Lock()
CHANGED = threading.Condition(LOCK)

STATE = {
    "devices": {},
    "scanned_at": None,
    "version": 0,
    "traffic": {},
    "traffic_mac": {},
    "backend": None,
}


def log(*a):
    print(dt.datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def norm_mac(mac):
    """macOS arp prints '2:00:00:00:00:1f'. Normalise to '02:00:00:00:00:1f'."""
    if not mac:
        return ""
    parts = re.split(r"[:-]", mac.strip().lower())
    if len(parts) != 6:
        return ""
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return ""


def is_private_mac(mac):
    """Locally administered bit set: phones/laptops using randomised Wi-Fi addresses."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


# --------------------------------------------------------------------------- scanning


def run(cmd, timeout):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if out.returncode != 0:
            log("command failed:", " ".join(cmd), out.stderr.strip()[:300])
        return out.stdout
    except FileNotFoundError:
        log("not found:", cmd[0])
    except subprocess.TimeoutExpired:
        log("timed out:", " ".join(cmd))
    return ""


def parse_nmap_hosts(xml_text):
    """Return {ip: {...}} for hosts nmap reports as up."""
    hosts = {}
    if not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log("nmap XML parse error:", e)
        return hosts
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        rec = {"ip": "", "mac": "", "vendor": "", "hostname": "", "ports": None}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                rec["ip"] = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                rec["mac"] = norm_mac(a.get("addr", ""))
                rec["vendor"] = a.get("vendor", "") or ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            rec["hostname"] = (hn.get("name") or "").split(".")[0]
        ports_el = h.find("ports")
        if ports_el is not None:
            ports = []
            for p in ports_el.findall("port"):
                s = p.find("state")
                if s is None or s.get("state") != "open":
                    continue
                svc = p.find("service")
                name = svc.get("name", "") if svc is not None else ""
                ver = " ".join(
                    x
                    for x in [
                        svc.get("product", "") if svc is not None else "",
                        svc.get("version", "") if svc is not None else "",
                    ]
                    if x
                )
                ports.append(
                    {
                        "port": int(p.get("portid", 0)),
                        "proto": p.get("protocol", "tcp"),
                        "service": name,
                        "version": ver,
                    }
                )
            rec["ports"] = sorted(ports, key=lambda x: x["port"])
        if rec["ip"]:
            hosts[rec["ip"]] = rec
    return hosts


ARP_RE = re.compile(r"^(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:\-]+)")


def parse_arp(text, subnet):
    """Parse `arp -an` (macOS/BSD) or `arp -a` output. Returns {ip: {mac, hostname}}."""
    net = ipaddress.ip_network(subnet, strict=False)
    out = {}
    for line in text.splitlines():
        m = ARP_RE.match(line.strip())
        if not m:
            continue
        name, ip, mac = m.groups()
        try:
            if ipaddress.ip_address(ip) not in net:
                continue
        except ValueError:
            continue
        mac = norm_mac(mac)
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            continue
        out[ip] = {"mac": mac, "hostname": "" if name == "?" else name.split(".")[0]}
    return out


# --- inventory + classification ----------------------------------------


def load_inventory(path):
    try:
        with open(path) as f:
            inv = json.load(f).get("devices", [])
    except FileNotFoundError:
        log("no inventory file at", path, "- every device will be flagged as unknown")
        return []
    for d in inv:
        d["mac"] = norm_mac(d.get("mac", ""))
    return inv


def match_inventory(dev, inv):
    for item in inv:
        if item.get("mac") and item["mac"] == dev.get("mac"):
            return item
    # Hostname fallback ONLY for inventory entries that have no MAC on file. A hostname is
    # chosen by the device itself, so matching on it for an entry with a known MAC would let
    # any device that calls itself "iphone" be approved.
    for item in inv:
        hn = (item.get("hostname") or "").lower()
        if not item.get("mac") and hn and hn == (dev.get("hostname") or "").lower():
            return item
    return None


def guess_kind(dev, gateway):
    if dev["ip"] == gateway:
        return "router"
    hn = (dev.get("hostname") or "").lower()
    v = (dev.get("vendor") or "").lower()
    if "iphone" in hn or "ipad" in hn or "android" in hn or "pixel" in hn:
        return "phone"
    if "macbook" in hn or "mbp" in hn or hn == "mac":
        return "laptop"
    if "mini" in hn or "server" in hn or "nas" in hn:
        return "server"
    if any(x in v for x in ("denon", "sonos", "bose", "marantz", "yamaha")) or "denon" in hn:
        return "audio"
    if any(x in v for x in ("synology", "qnap")):
        return "server"
    if any(x in v for x in ("roku", "samsung", "lg", "google", "amazon")):
        return "media"
    return ""


def findings_for(devs):
    out = []
    for d in devs:
        ip = d["ip"]
        if not d["approved"]:
            out.append(
                {
                    "ip": ip,
                    "severity": "high",
                    "title": "Unknown device",
                    "detail": "Not in the approved inventory"
                    + (f" (MAC {d['mac']}, vendor {d['vendor'] or 'unknown'})" if d["mac"] else "")
                    + ". Identify it, then add it to inventory.json or block it on the router.",
                }
            )
        ports = {p["port"] for p in d.get("ports") or []}
        if 23 in ports:
            out.append(
                {
                    "ip": ip,
                    "severity": "med",
                    "title": "Telnet open (23/tcp)",
                    "detail": "Unencrypted remote access. Keep it LAN-only, never port-forward it.",
                }
            )
        if 21 in ports:
            out.append(
                {
                    "ip": ip,
                    "severity": "med",
                    "title": "FTP open (21/tcp)",
                    "detail": "Plaintext credentials. Use SFTP instead.",
                }
            )
        if 1723 in ports:
            out.append(
                {
                    "ip": ip,
                    "severity": "med",
                    "title": "PPTP VPN enabled",
                    "detail": (
                        "PPTP is broken crypto. Switch to WireGuard or OpenVPN and disable PPTP."
                    ),
                }
            )
        if 445 in ports or 5900 in ports:
            out.append(
                {
                    "ip": ip,
                    "severity": "info",
                    "title": "SMB / VNC exposed",
                    "detail": (
                        "File or screen sharing on. Fine on the LAN, keep it off the internet."
                    ),
                }
            )
    return out


# --------------------------------------------------------------------------- state


def merge_scan(up, arp, args, inv):
    ts = now_iso()
    with LOCK:
        devs = STATE["devices"]
        seen_keys = set()

        def upsert(ip, mac, hostname, vendor, status):
            key = mac or f"ip:{ip}"
            # if we previously only had the IP, migrate to the MAC key
            if mac and f"ip:{ip}" in devs and key not in devs:
                devs[key] = devs.pop(f"ip:{ip}")
            d = devs.setdefault(key, {"first_seen": ts, "ports": []})
            d.update({"ip": ip, "mac": mac or d.get("mac", "")})
            if hostname:
                d["hostname"] = hostname
            if vendor:
                d["vendor"] = vendor
            d.setdefault("hostname", "")
            d.setdefault("vendor", "")
            d["status"] = status
            d["last_seen"] = ts
            seen_keys.add(key)

        for ip, h in up.items():
            mac = h["mac"] or arp.get(ip, {}).get("mac", "")
            upsert(
                ip, mac, h["hostname"] or arp.get(ip, {}).get("hostname", ""), h["vendor"], "online"
            )
        for ip, a in arp.items():
            if ip in up:
                continue
            upsert(ip, a["mac"], a["hostname"], "", "asleep")
        # anything not seen this round is absent; forget it after N days
        cutoff = dt.datetime.now().astimezone() - dt.timedelta(days=args.forget_after_days)
        for key in list(devs):
            if key in seen_keys:
                continue
            d = devs[key]
            d["status"] = "absent"
            try:
                if dt.datetime.fromisoformat(d["last_seen"]) < cutoff:
                    del devs[key]
            except (KeyError, ValueError):
                pass
        STATE["scanned_at"] = ts
        STATE["version"] += 1
        CHANGED.notify_all()


def merge_ports(scanned):
    with LOCK:
        for d in STATE["devices"].values():
            h = scanned.get(d["ip"])
            if h and h["ports"] is not None:
                d["ports"] = h["ports"]
        STATE["version"] += 1
        CHANGED.notify_all()


def topology(args):
    inv = load_inventory(args.inventory)
    with LOCK:
        raw = [dict(d) for d in STATE["devices"].values()]
        scanned_at = STATE["scanned_at"]
        traffic = dict(STATE["traffic"])
        traffic_mac = dict(STATE.get("traffic_mac") or {})
        backend = STATE.get("backend")
        sources = list(STATE.get("traffic_sources", []))
    devices = []
    for d in raw:
        item = match_inventory(d, inv)
        kind = (
            (item or {}).get("kind")
            or guess_kind(d, args.gateway)
            or ("media" if item else "unknown")
        )
        if d["ip"] == args.gateway:
            kind = "router"
        label = (
            (item or {}).get("label")
            or (d.get("hostname") or "").upper()
            or f"UNKNOWN .{d['ip'].split('.')[-1]}"
        )
        dev = {
            "ip": d["ip"],
            "mac": d.get("mac", ""),
            "hostname": d.get("hostname", ""),
            "vendor": d.get("vendor", "")
            or ("private MAC" if d.get("mac") and is_private_mac(d["mac"]) else ""),
            "label": label,
            "model": (item or {}).get("model", ""),
            "kind": kind,
            "status": d.get("status", "absent"),
            "approved": item is not None or d["ip"] == args.gateway,
            "ports": d.get("ports") or [],
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
        }
        for k in ("cap_mbps", "cap_down_mbps", "cap_up_mbps"):
            if (item or {}).get(k):
                dev[k] = item[k]
        mac = norm_mac(d.get("mac", ""))
        if d["ip"] in traffic:
            dev["traffic"] = traffic[d["ip"]]
        elif mac and mac in traffic_mac:
            dev["traffic"] = traffic_mac[mac]
            if dev["status"] != "online":
                dev["status"] = (
                    "online"  # associated to the router's Wi-Fi right now, even if it ignores pings
                )
                dev["presence"] = "Wi-Fi associated (does not answer ping)"
        devices.append(dev)
    devices.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
    return {
        "source": "live",
        "release": os.environ.get("HOLONET_RELEASE") or None,
        "network": args.subnet,
        "scanned_at": scanned_at,
        "scanner": "netmap_agent (nmap + ARP) on " + os.uname().nodename,
        "wan": {"down_mbps": args.wan_down, "up_mbps": args.wan_up},
        "traffic_sources": sources,
        "backend": backend,
        "devices": devices,
        "findings": findings_for(devices),
    }


# --------------------------------------------------------------------------- workers


def discovery_loop(args):
    # The router's neighbor table arrives via the traffic loop. Give it a moment so the first
    # sweep after a (re)start already shows the whole LAN instead of only what macOS ARP sees.
    # Local-only mode (e.g. the client-Mac fallback) has no router feed: don't wait for one.
    deadline = time.time() + (20 if "holonet" in args.traffic_source else 0)
    while time.time() < deadline:
        with LOCK:
            if STATE.get("router_neighbors"):
                break
        time.sleep(0.5)
    # Port scans can take minutes; they run on their own thread so discovery never waits.
    threading.Thread(target=portscan_loop, args=(args,), daemon=True).start()
    while True:
        inv = load_inventory(args.inventory)
        xml = run(
            [args.nmap, "-sn", *(["-n"] if args.no_dns else []), "-oX", "-", args.subnet],
            timeout=180,
        )
        up = parse_nmap_hosts(xml)
        arp = parse_arp(run(args.arp_cmd.split(), timeout=20), args.subnet)
        # The router's own ARP table and DHCP leases are the source of truth for MACs and names:
        # a background process on macOS may not see the whole LAN.
        with LOCK:
            router_nb = list(STATE.get("router_neighbors") or [])
        net = ipaddress.ip_network(args.subnet, strict=False)
        for n in router_nb:
            try:
                if ipaddress.ip_address(n["ip"]) not in net:
                    continue
            except (KeyError, ValueError):
                continue
            mac = norm_mac(n.get("mac", ""))
            if not mac:
                continue
            cur = arp.setdefault(n["ip"], {"mac": mac, "hostname": ""})
            cur["mac"] = cur.get("mac") or mac
            if n.get("hostname") and not cur.get("hostname"):
                cur["hostname"] = n["hostname"]
            if n["ip"] in up and not up[n["ip"]].get("mac"):
                up[n["ip"]]["mac"] = mac
        merge_scan(up, arp, args, inv)
        log(f"discovery: {len(up)} up, {len(arp)} in ARP")
        time.sleep(args.discover_every)


def portscan_loop(args):
    time.sleep(30)  # let the first discovery sweeps settle
    while True:
        with LOCK:
            targets = sorted(
                {d["ip"] for d in STATE["devices"].values() if d.get("status") == "online"}
            )
        if targets:
            xml = run(
                [
                    args.nmap,
                    "-sT",
                    "-sV",
                    "--version-light",
                    "--top-ports",
                    str(args.top_ports),
                    "-n",
                    "-oX",
                    "-",
                    *targets,
                ],
                timeout=900,
            )
            merge_ports(parse_nmap_hosts(xml))
            log(f"port scan: {len(targets)} hosts")
        time.sleep(args.portscan_every)


# --- traffic (uplink / downlink) ----------------------------------------
#
# Every source returns {ip: {"down": Mbps, "up": Mbps}}.
#   down = data flowing TO the device (from the router / internet)
#   up   = data flowing FROM the device
# For the gateway IP, down/up mean WAN download/upload.
#
# Sources:
#   local    : this machine's own NIC byte counters (monitoring host). Real, zero config.
#   asus-ssh : SSH into the ASUS router: WAN interface counters + per-device
#              internet traffic from the conntrack table. Needs SSH enabled on the router.
#   cmd      : any command printing that JSON (e.g. your own router CLI).


class Rate:
    """Turns ever-increasing byte counters into Mbps."""

    def __init__(self):
        self.prev = {}

    def update(self, key, rx_bytes, tx_bytes, now):
        p = self.prev.get(key)
        self.prev[key] = (rx_bytes, tx_bytes, now)
        if not p:
            return None
        drx, dtx, dtime = rx_bytes - p[0], tx_bytes - p[1], now - p[2]
        if dtime <= 0 or drx < 0 or dtx < 0:  # counter reset / reboot
            return None
        return {"down": drx * 8 / dtime / 1e6, "up": dtx * 8 / dtime / 1e6}


def local_ip_toward(gateway):
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((gateway, 9))  # UDP connect sends nothing; it just picks the route
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def read_local_counters(ip):
    """(rx_bytes, tx_bytes) for the interface that owns `ip`. macOS via netstat, Linux via /sys."""
    if sys.platform == "darwin":
        out = run(["netstat", "-ibn"], timeout=10)
        for line in out.splitlines():
            f = line.split()
            # Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            if len(f) >= 10 and f[3] == ip:
                try:
                    return int(f[6]), int(f[9])
                except ValueError:
                    return None
        return None
    # Linux: the default-route interface's counters from /proc/net/dev
    try:
        with open("/proc/net/route") as f:
            iface = next(
                (ln.split()[0] for ln in f.readlines()[1:] if ln.split()[1] == "00000000"), ""
            )
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" in line and line.split(":")[0].strip() == iface:
                    v = line.split(":")[1].split()
                    return int(v[0]), int(v[8])
    except (OSError, IndexError, ValueError):
        pass
    return None


CT_RE = re.compile(r"src=(\S+) dst=(\S+) .*?bytes=(\d+).*?src=(\S+) dst=(\S+) .*?bytes=(\d+)")
CT_KEY_RE = re.compile(r"\b(tcp|udp)\b.*?src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)")


class AsusSSH:
    """WAN totals from the router's WAN interface, per-device internet traffic from conntrack.

    Caveats (read these):
      - Conntrack only counts traffic that crosses the router (internet traffic).
        Device-to-device LAN traffic is switched and invisible here.
      - Byte counting must be on:  echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
        (on the router; resets on reboot).
      - With NAT hardware acceleration on, most packets bypass conntrack and the
        per-device numbers will read low. WAN totals stay accurate.
    """

    SCRIPT = (
        "W=$(nvram get wan0_ifname); "
        "cat /sys/class/net/$W/statistics/rx_bytes /sys/class/net/$W/statistics/tx_bytes; "
        "echo ---; cat /proc/net/nf_conntrack 2>/dev/null || cat /proc/net/ip_conntrack 2>/dev/null"
    )

    def __init__(self, args):
        self.args = args
        self.net = ipaddress.ip_network(args.subnet, strict=False)
        self.wan = Rate()
        self.flows = {}
        self.t_prev = None
        self.warned = False

    def cmd(self):
        a = self.args
        return [
            a.ssh_bin,
            "-p",
            str(a.router_ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPath=/tmp/mwt-netmap-%r@%h:%p",
            "-o",
            "ControlPersist=120",
            a.router_ssh,
            self.SCRIPT,
        ]

    def lan(self, ip):
        try:
            return ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    def poll(self):
        out = run(self.cmd(), timeout=15)
        if "---" not in out:
            return {}
        head, ct = out.split("---", 1)
        now = time.monotonic()
        result = {}
        nums = [ln.strip() for ln in head.splitlines() if ln.strip().isdigit()]
        if len(nums) >= 2:
            r = self.wan.update("wan", int(nums[0]), int(nums[1]), now)
            if r:
                result[self.args.gateway] = r
        if "bytes=" not in ct and ct.strip():
            if not self.warned:
                log(
                    "router conntrack has no byte counters; per-device rates unavailable. "
                    "On the router run: echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct"
                )
                self.warned = True
            return result
        per = {}
        seen = {}
        for line in ct.splitlines():
            m, k = CT_RE.search(line), CT_KEY_RE.search(line)
            if not m or not k:
                continue
            s1, d1, b1, _, _, b2 = m.groups()
            b1, b2 = int(b1), int(b2)
            if self.lan(s1) and not self.lan(d1):
                ip, up_b, down_b = s1, b1, b2  # device opened the connection
            elif self.lan(d1) and not self.lan(s1):
                ip, up_b, down_b = d1, b2, b1  # inbound (port forward)
            else:
                continue
            key = k.groups()  # proto, src, dst, sport, dport (excludes the ticking timeout field)
            seen[key] = (up_b, down_b)
            pu, pd = self.flows.get(key, (0, 0)) if self.t_prev else (up_b, down_b)
            du = up_b - pu if up_b >= pu else up_b
            dd = down_b - pd if down_b >= pd else down_b
            acc = per.setdefault(ip, [0, 0])
            acc[0] += du
            acc[1] += dd
        self.flows = seen
        if self.t_prev:
            dtime = now - self.t_prev
            for ip, (u, d) in per.items():
                result.setdefault(ip, {"down": d * 8 / dtime / 1e6, "up": u * 8 / dtime / 1e6})
        self.t_prev = now
        return result


def fetch_holonet(url):
    """Read the HoloNet backend. Returns (by_mac, wan, backend_meta) or None."""
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read().decode())
    except (OSError, ValueError) as e:
        return None, None, {"status": "unreachable", "error": f"{type(e).__name__}: {str(e)[:120]}"}
    smp = d.get("sampler") or {}
    by_mac = {}
    if smp.get("status") == "ok":
        for c in d.get("clients") or []:
            mac = norm_mac(c.get("mac", ""))
            if mac:
                by_mac[mac] = {
                    "down": c.get("down_mbps"),
                    "up": c.get("up_mbps"),
                    "source": "router Wi-Fi counters",
                    "band": c.get("band"),
                    "rssi": c.get("rssi"),
                    "phy_down_mbps": c.get("phy_down_mbps"),
                    "phy_up_mbps": c.get("phy_up_mbps"),
                    "iface": ",".join(c.get("ifaces") or []),
                }
    wan = d.get("wan") if smp.get("status") == "ok" else None
    with LOCK:
        STATE["router_neighbors"] = d.get("neighbors") or []
    meta = {
        "status": smp.get("status"),
        "error": smp.get("error"),
        "sampled_at": smp.get("sampled_at"),
        "interval_s": smp.get("interval_s"),
        "router": smp.get("router"),
        "coverage": smp.get("coverage"),
        "speedtests": d.get("speedtests"),
    }
    return by_mac, wan, meta


def parse_traffic_json(out):
    data = json.loads(out) if out.strip() else {}
    res = {}
    for ip, v in (data or {}).items():
        if isinstance(v, dict):
            res[ip] = {"down": float(v.get("down", 0)), "up": float(v.get("up", 0))}
        else:  # legacy: a single number is treated as download
            res[ip] = {"down": float(v), "up": 0.0}
    return res


def traffic_loop(args):
    sources = [s.strip() for s in args.traffic_source.split(",") if s.strip()]
    if args.traffic_cmd and "cmd" not in sources:
        sources.append("cmd")
    local_rate, asus = Rate(), (AsusSSH(args) if "asus-ssh" in sources else None)
    my_ip = args.local_ip or local_ip_toward(args.gateway)
    log("traffic sources:", ", ".join(sources) or "none", f"(this host {my_ip or 'unknown'})")
    while True:
        merged, used, by_mac, meta = {}, [], {}, None
        if "holonet" in sources:
            by_mac, wan, meta = fetch_holonet(args.holonet_url)
            by_mac = by_mac or {}
            if wan and wan.get("down_mbps") is not None:
                merged[args.gateway] = {
                    "down": wan["down_mbps"],
                    "up": wan["up_mbps"],
                    "source": "router WAN counters",
                }
            if meta and meta.get("status") == "ok":
                used.append("holonet")
        if asus:
            r = asus.poll()
            if r:
                merged.update(r)
                used.append("asus-ssh")
        if "cmd" in sources and args.traffic_cmd:
            try:
                r = parse_traffic_json(run(args.traffic_cmd.split(), timeout=20))
                merged.update(r)
                used.append("cmd")
            except (ValueError, TypeError, AttributeError) as e:
                log("traffic command returned bad JSON:", e)
        if "local" in sources and my_ip:
            c = read_local_counters(my_ip)
            if c:
                r = local_rate.update("local", c[0], c[1], time.monotonic())
                if r:
                    r["source"] = "this host's network card"
                    merged[my_ip] = r  # the NIC sees LAN + internet traffic, so it wins
                    used.append("local")

        def _clean(v):
            out = {k: v[k] for k in v if k not in ("down", "up")}
            out["down"] = None if v.get("down") is None else round(v["down"], 2)
            out["up"] = None if v.get("up") is None else round(v["up"], 2)
            return out

        with LOCK:
            STATE["traffic"] = {ip: _clean(v) for ip, v in merged.items()}
            STATE["traffic_mac"] = {m: _clean(v) for m, v in by_mac.items()}
            STATE["backend"] = meta
            STATE["traffic_sources"] = used
            STATE["version"] += 1
            CHANGED.notify_all()
        time.sleep(args.traffic_every)


# --------------------------------------------------------------------------- HTTP


def make_handler(args):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            b = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                try:
                    with open(os.path.join(HERE, "index.html"), "rb") as f:
                        self._send(200, f.read(), "text/html; charset=utf-8")
                except FileNotFoundError:
                    self._send(404, "index.html not found next to the agent", "text/plain")
            elif path == "/healthz":
                with LOCK:
                    backend = STATE.get("backend") or {}
                    n = len(STATE["devices"])
                body = {
                    "ok": True,
                    "release": os.environ.get("HOLONET_RELEASE") or None,
                    "devices": n,
                    "backend": backend.get("status"),
                }
                self._send(200, json.dumps(body), "application/json")
            elif path == "/api/topology":
                self._send(200, json.dumps(topology(args)), "application/json")
            elif path == "/api/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                seen = -1
                try:
                    while True:
                        with CHANGED:
                            CHANGED.wait_for(lambda: STATE["version"] != seen, timeout=15)
                            v = STATE["version"]
                        if v != seen:
                            seen = v
                            self.wfile.write(
                                b"data: " + json.dumps(topology(args)).encode() + b"\n\n"
                            )
                        else:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self._send(404, "not found", "text/plain")

    return H


def main():
    ap = argparse.ArgumentParser(description="MWT Holo Net nmap connector")
    ap.add_argument("--subnet", default="192.0.2.0/24")
    ap.add_argument("--gateway", default="192.0.2.1")
    ap.add_argument(
        "--host", default="127.0.0.1", help="use 0.0.0.0 to let other LAN machines open the map"
    )
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--discover-every", type=int, default=60, help="seconds between ping sweeps")
    ap.add_argument("--portscan-every", type=int, default=1800, help="seconds between port scans")
    ap.add_argument("--top-ports", type=int, default=100)
    ap.add_argument("--forget-after-days", type=int, default=7)
    ap.add_argument("--inventory", default=os.path.join(HERE, "inventory.json"))
    ap.add_argument("--nmap", default=shutil.which("nmap") or "/opt/homebrew/bin/nmap")
    ap.add_argument("--arp-cmd", default="arp -an")
    ap.add_argument(
        "--traffic-source",
        default="holonet,local",
        help="comma list of: holonet, local, asus-ssh, cmd  (default: holonet,local)",
    )
    ap.add_argument(
        "--holonet-url",
        default="http://127.0.0.1:9108/api/live",
        help="HoloNet backend JSON endpoint (holonet.backend /api/live)",
    )
    ap.add_argument(
        "--traffic-cmd", default="", help='command printing JSON {"ip": {"down": Mbps, "up": Mbps}}'
    )
    ap.add_argument(
        "--traffic-every", type=float, default=2, help="seconds between traffic samples"
    )
    ap.add_argument(
        "--router-ssh", default="admin@192.0.2.1", help="user@host for --traffic-source asus-ssh"
    )
    ap.add_argument("--router-ssh-port", type=int, default=22)
    ap.add_argument("--ssh-bin", default="ssh")
    ap.add_argument("--local-ip", default="", help="override this host's LAN IP (auto-detected)")
    ap.add_argument(
        "--wan-down", type=float, default=1000, help="ISP plan download, Mbps (for WAN load %%)"
    )
    ap.add_argument("--wan-up", type=float, default=1000, help="ISP plan upload, Mbps")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    args = ap.parse_args()

    if os.name != "nt" and os.geteuid() != 0:
        log("warning: not running as root, nmap won't report MAC addresses or vendors")

    threading.Thread(target=discovery_loop, args=(args,), daemon=True).start()
    if args.traffic_source or args.traffic_cmd:
        threading.Thread(target=traffic_loop, args=(args,), daemon=True).start()

    srv = ThreadingHTTPServer((args.host, args.port), make_handler(args))
    srv.daemon_threads = True
    log(
        f"map at http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}"
        f":{args.port}"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
