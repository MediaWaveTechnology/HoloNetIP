"""Tests for the HoloNet backend (holonet.backend).

Router output below mirrors the RT-BE92U stock firmware shapes seen on the example LAN,
with synthetic MAC addresses.
"""

from __future__ import annotations

import pytest

from holonet import backend as hn

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"

DISCOVERY = """@@WAN
eth0

@@WL
wl0=eth4 band=2
wl1=eth5 band=1
wl2=eth6 band=4
wl3= band=
@@NET
br0
eth0
eth4
eth5
eth6
wl1.1
wl2.1
lo
@@MODEL
RT-BE92U
3.0.0.6
102_40497
"""


def _dev(wan_rx: int, wan_tx: int) -> str:
    return (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes ...\n"
        f"  eth0: {wan_rx} 10 0 0 0 0 0 0 {wan_tx} 10 0 0 0 0 0 0\n"
        "    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n"
    )


def _sta(iface: str, mac: str, tx: int, rx: int, extra: str = "") -> str:
    return (
        f"@@STA {iface} {mac}\n"
        f"\t in network 3600 seconds\n"
        f"\t tx total bytes: {tx}\n"
        f"\t tx ucast bytes: {tx // 2}\n"
        f"\t rx data bytes: {rx}\n"
        f"\t rx ucast bytes: {rx // 2}\n"
        f"\t rate of last tx pkt: 1729000 kbps\n"
        f"\t rate of last rx pkt: 864000 kbps\n"
        f"\t per antenna rssi of last rx data frame: -51 -48 0 0\n" + extra
    )


def _tick(uptime: float, wan_rx: int, wan_tx: int, stations: str, end: bool = True) -> str:
    return f"{uptime} 1000.0\n@@DEV\n{_dev(wan_rx, wan_tx)}{stations}" + (
        "@@END\n" if end else ""
    )


# --- discovery --------------------------------------------------------------


def test_parse_discovery_finds_wan_bands_and_sub_interfaces():
    d = hn.parse_discovery(DISCOVERY)
    assert d["wan_iface"] == "eth0"
    assert d["model"] == "RT-BE92U 3.0.0.6 102_40497"
    wl = d["wl_ifaces"]
    assert wl["eth5"]["band"] == "5GHz"
    assert wl["eth6"]["band"] == "6GHz"
    # sub-interfaces that exist as netdevs inherit their parent's band
    assert wl["wl1.1"] == {"unit": 1, "band": "5GHz", "sub": True}
    assert wl["wl2.1"]["band"] == "6GHz"
    assert "" not in wl


def test_tick_command_drops_unsafe_interface_names():
    cmd = hn.build_tick_command(["wl1.1", "eth5; reboot", "$(id)"])
    assert "wl1.1" in cmd
    assert "reboot" not in cmd
    assert "$(id)" not in cmd


# --- tick parsing -----------------------------------------------------------


def test_parse_tick_prefers_tx_total_and_rx_data():
    t = hn.parse_tick(_tick(500.0, 1000, 2000, _sta("wl1.1", MAC_A.upper(), 9000, 4000)))
    assert t["complete"] is True
    assert t["uptime"] == 500.0
    assert t["dev"]["eth0"] == (1000, 2000)
    (s,) = t["sta"]
    assert s["mac"] == MAC_A  # normalised to lower case
    assert s["tx_bytes"] == 9000  # "tx total bytes" beats "tx ucast bytes"
    assert s["rx_bytes"] == 4000  # "rx data bytes" beats "rx ucast bytes"
    assert s["rssi"] == -48  # zero antennas ignored, strongest wins
    assert s["phy_tx_mbps"] == 1729.0
    assert s["in_network_s"] == 3600


def test_parse_tick_falls_back_to_tx_data_bytes_on_older_firmware():
    block = "@@STA eth5 " + MAC_A + "\n\t tx data bytes: 77\n\t rx data bytes: 66\n"
    (s,) = hn.parse_tick(_tick(1.0, 0, 0, block))["sta"]
    assert (s["tx_bytes"], s["rx_bytes"]) == (77, 66)


def test_parse_tick_without_end_marker_is_incomplete():
    assert hn.parse_tick(_tick(1.0, 0, 0, "", end=False))["complete"] is False


def test_parse_tick_ignores_malformed_station_header():
    t = hn.parse_tick(_tick(1.0, 0, 0, "@@STA wl1.1 not-a-mac\n\t tx total bytes: 5\n"))
    assert t["sta"] == []


# --- rates ------------------------------------------------------------------


def test_ratebook_first_sample_is_none_then_mbps():
    rb = hn.RateBook()
    assert rb.update("k", 0, 0, 0.0) is None
    r = rb.update("k", 1_250_000, 625_000, 1.0)
    assert r == {"down_mbps": 10.0, "up_mbps": 5.0}
    assert rb.total["k"] == [1_250_000, 625_000]


@pytest.mark.parametrize(
    "down,up,t",
    [(-1, 10, 2.0), (10, -1, 2.0), (10, 10, 1.0)],
    ids=["download-counter-reset", "upload-counter-reset", "no-time-elapsed"],
)
def test_ratebook_untrustworthy_delta_is_none_not_zero(down, up, t):
    rb = hn.RateBook()
    rb.update("k", 100, 100, 1.0)
    assert rb.update("k", 100 + down, 100 + up, t) is None


def test_ratebook_interface_change_discards_sample():
    rb = hn.RateBook()
    rb.update("k", 0, 0, 0.0, sig=("wl1.1",))
    assert rb.update("k", 1000, 1000, 1.0, sig=("wl2.1",)) is None  # roamed bands


def test_merge_stations_sums_one_mac_across_mlo_links():
    sta = [
        {"iface": "wl1.1", "mac": MAC_A, "tx_bytes": 100, "rx_bytes": 10, "rssi": -60},
        {"iface": "wl2.1", "mac": MAC_A, "tx_bytes": 50, "rx_bytes": 5, "rssi": -55},
        {"iface": "wl1.1", "mac": MAC_B},  # no counters -> skipped
    ]
    m = hn.merge_stations(sta)
    assert list(m) == [MAC_A]
    assert m[MAC_A]["tx_bytes"] == 150
    assert m[MAC_A]["rx_bytes"] == 15
    assert m[MAC_A]["ifaces"] == ["wl1.1", "wl2.1"]
    assert m[MAC_A]["rssi"] == -55


# --- neighbors --------------------------------------------------------------

NEIGHBORS = """IP address       HW type     Flags       HW address            Mask     Device
192.0.2.20    0x1         0x2         02:00:00:00:00:0A     *        br0
192.0.2.21    0x1         0x0         02:00:00:00:00:0b     *        br0
203.0.113.1      0x1         0x2         02:00:00:00:00:0c     *        eth0
192.0.2.22    0x1         0x0         00:00:00:00:00:00     *        br0
@@LEASES
1794851221 02:00:00:00:00:0a 192.0.2.20 Guest's<iPhone>;rm 01:02
1794851221 02:00:00:00:00:0b 192.0.2.21 * 01:03
"""


def test_parse_neighbors_lan_only_and_sanitised_names():
    n = hn.parse_neighbors(NEIGHBORS)
    assert [d["ip"] for d in n] == ["192.0.2.20", "192.0.2.21"]  # WAN + 00:00 dropped
    a, b = n
    assert a["mac"] == MAC_A
    assert a["complete"] is True and b["complete"] is False
    # device-supplied hostnames are stripped of shell/HTML metacharacters
    assert a["hostname"] == "GuestsiPhonerm"
    assert b["hostname"] == ""


# --- sampler end to end -----------------------------------------------------


def _sampler() -> hn.Sampler:
    s = hn.Sampler(hn.Settings(sample_s=5.0))
    s.disc = hn.parse_discovery(DISCOVERY)
    return s


def test_sampler_maps_ap_tx_to_device_download_and_wan_rx_to_download():
    s = _sampler()
    s._ingest(hn.parse_tick(_tick(100, 0, 0, _sta("wl1.1", MAC_A, 0, 0))), 0.0)
    # 5 s later: AP sent 62.5 MB to the device (100 Mbps), received 6.25 MB (10 Mbps)
    big = _sta("wl1.1", MAC_A, 62_500_000, 6_250_000)
    s._ingest(hn.parse_tick(_tick(105, 62_500_000, 6_250_000, big)), 5.0)
    snap = s.snapshot()
    assert snap["status"] == "ok"
    (c,) = snap["clients"]
    assert (c["down_mbps"], c["up_mbps"]) == (100.0, 10.0)
    assert c["band"] == "5GHz"
    assert (snap["wan"]["down_mbps"], snap["wan"]["up_mbps"]) == (100.0, 10.0)


def test_sampler_router_reboot_yields_null_rates_not_zero():
    s = _sampler()
    s._ingest(hn.parse_tick(_tick(100, 10**9, 10**9, _sta("wl1.1", MAC_A, 10**9, 10**9))), 0.0)
    s._ingest(hn.parse_tick(_tick(3, 10, 10, _sta("wl1.1", MAC_A, 10, 10))), 5.0)
    snap = s.snapshot()
    assert snap["wan"]["down_mbps"] is None
    assert snap["clients"][0]["down_mbps"] is None


def test_sampler_incomplete_tick_marks_error_and_hides_stale_clients():
    s = _sampler()
    s._ingest(hn.parse_tick(_tick(100, 0, 0, _sta("wl1.1", MAC_A, 0, 0))), 0.0)
    s._ingest(hn.parse_tick(_tick(105, 0, 0, "", end=False)), 5.0)
    snap = s.snapshot()
    assert snap["status"] == "error"
    assert snap["clients"] == [] and snap["wan"] is None


# --- metrics + HTTP surface -------------------------------------------------


class _Speed:
    running = False
    providers = {
        "ookla": {"down_mbps": 260.7, "up_mbps": 39.6, "ping_ms": 12.5, "measured_at": 1.0},
        "fastly": {"down_mbps": None},  # failed provider exports nothing
        'bad"name': {"down_mbps": 1.0},  # label injection guard
    }


def test_render_metrics_counters_and_no_zero_for_failed_providers():
    s = _sampler()
    s._ingest(hn.parse_tick(_tick(100, 0, 0, _sta("wl1.1", MAC_A, 0, 0))), 0.0)
    s._ingest(hn.parse_tick(_tick(105, 800, 400, _sta("wl1.1", MAC_A, 800, 400))), 5.0)
    text = hn.render_metrics(s, _Speed())
    assert "holonet_sampler_up 1" in text
    assert "holonet_wan_download_bytes_total 800" in text
    assert f'holonet_client_download_bytes_total{{mac="{MAC_A}"}} 800' in text
    assert 'holonet_speedtest_download_mbps{provider="ookla"} 260.7' in text
    assert "fastly" not in text
    assert "bad" not in text
    assert text.endswith("\n")


def test_http_surface_is_get_only():
    pytest.importorskip("aiohttp")
    app = hn.make_app(_sampler(), _Speed())
    methods = {r.method for r in app.router.routes()}
    assert methods <= {"GET", "HEAD"}
    paths = {r.resource.canonical for r in app.router.routes()}
    assert {"/api/live", "/metrics", "/healthz"} <= paths


def test_default_bind_is_loopback():
    assert hn.Settings().bind == "127.0.0.1"


async def test_run_providers_reports_unavailable_providers(monkeypatch):
    from holonet import speedtest_providers as sp

    class Fake:
        def __init__(self, name, ok):
            self.name, self.ok = name, ok

        async def is_available(self):
            return self.ok

        async def run(self):
            return sp.ProviderResult(provider=self.name, download_bps=1e8)

    monkeypatch.setattr(sp, "OoklaProvider", lambda: Fake("ookla", False))
    monkeypatch.setattr(sp, "CloudflareProvider", lambda: Fake("cloudflare", True))
    monkeypatch.setattr(sp, "build_cdn_http_providers", lambda names: [Fake("cachefly", True)])
    res = await hn.run_providers(cooldown=0)
    assert [(r.provider, r.error) for r in res] == [
        ("ookla", "not available"),
        ("cloudflare", None),
        ("cachefly", None),
    ]


def test_backend_has_no_asusroutercontrol_dependency():
    import pathlib

    src = pathlib.Path(hn.__file__).read_text()
    assert "from asusroutercontrol" not in src and "import asusroutercontrol" not in src
