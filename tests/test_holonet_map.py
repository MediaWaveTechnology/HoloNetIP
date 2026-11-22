"""Tests for the HoloNet map agent (holonet/netmap_agent.py)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def agent():
    spec = importlib.util.spec_from_file_location(
        "holonet_netmap_agent", ROOT / "map" / "netmap_agent.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_norm_mac_pads_macos_arp_output(agent):
    assert agent.norm_mac("2:00:00:00:00:1f") == "02:00:00:00:00:1f"
    assert agent.norm_mac("02-00-00-00-00-1F") == "02:00:00:00:00:1f"
    assert agent.norm_mac("garbage") == ""
    assert agent.norm_mac("") == ""


def test_private_mac_detection(agent):
    assert agent.is_private_mac("02:00:00:00:00:1f") is True  # randomised Wi-Fi address
    assert agent.is_private_mac("00:00:5e:00:53:1e") is False


def test_inventory_approval_is_by_mac_not_hostname(agent):
    inv = [{"mac": "aa:bb:cc:00:00:01", "hostname": "iPhone", "name": "Guest's phone"}]
    impostor = {"mac": "02:00:00:00:00:1f", "hostname": "iPhone"}
    assert agent.match_inventory(impostor, inv) is None
    real = {"mac": "aa:bb:cc:00:00:01", "hostname": "whatever"}
    assert agent.match_inventory(real, inv) is inv[0]


def test_hostname_fallback_only_for_entries_without_mac(agent):
    inv = [{"mac": "", "hostname": "printer"}]
    assert agent.match_inventory({"mac": "aa:bb:cc:00:00:02", "hostname": "Printer"}, inv)


def test_load_inventory_normalises_macs(agent, tmp_path):
    p = tmp_path / "inventory.json"
    p.write_text(json.dumps({"devices": [{"mac": "AA-BB-CC-00-00-01", "name": "x"}]}))
    assert agent.load_inventory(str(p))[0]["mac"] == "aa:bb:cc:00:00:01"
    assert agent.load_inventory(str(tmp_path / "missing.json")) == []


def test_parse_arp_keeps_subnet_and_drops_broadcast(agent):
    text = (
        "? (192.0.2.9) at 2:00:00:00:00:1f on en0 ifscope [ethernet]\n"
        "router.example (192.0.2.1) at 2:0:0:0:0:1 on en0 ifscope [ethernet]\n"
        "? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        "? (198.51.100.5) at 2:0:0:0:0:5 on en1 ifscope [ethernet]\n"
    )
    out = agent.parse_arp(text, "192.0.2.0/24")
    assert set(out) == {"192.0.2.9", "192.0.2.1"}
    assert out["192.0.2.9"]["mac"] == "02:00:00:00:00:1f"
    assert out["192.0.2.1"]["hostname"] == "router"


def test_rate_reset_is_none(agent):
    r = agent.Rate()
    assert r.update("k", 0, 0, 0.0) is None
    assert r.update("k", 1_250_000, 0, 1.0) == {"down": 10.0, "up": 0.0}
    assert r.update("k", 5, 5, 2.0) is None


def test_fetch_holonet_unreachable_is_reported_not_raised(agent):
    by_mac, wan, meta = agent.fetch_holonet("http://127.0.0.1:9/api/live")
    assert by_mac is None and wan is None
    assert meta["status"] == "unreachable"


def test_page_escapes_device_supplied_text():
    html = (ROOT / "map" / "index.html").read_text()
    assert "function esc(" in html or "const esc" in html
    assert "<script src=\"http://" not in html  # no plain-http script includes


def test_page_offers_both_icon_sets():
    html = (ROOT / "map" / "index.html").read_text()
    assert 'data-set="abstract"' in html and 'data-set="device"' in html
    assert "function deviceGeo(" in html
