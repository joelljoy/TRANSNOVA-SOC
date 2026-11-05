"""Unit tests for the shared anonymizer lookup."""

import json

import pytest

from anonintel import AnonIntel


@pytest.fixture
def d(tmp_path):
    (tmp_path / "tor_exits.txt").write_text("185.220.101.7\n2a0b:f4c2::1\n")
    # A sloppy list that includes private ranges must still never label LAN visitors.
    (tmp_path / "vpn_ipv4.txt").write_text("45.86.200.0/24\n10.0.0.0/8\n")
    (tmp_path / "datacenter_ipv4.txt").write_text("45.86.0.0/16\n192.168.0.0/16\n34.64.0.0/10\n")
    (tmp_path / "META.json").write_text(json.dumps({"fetched_at": "2026-11-01T05:33:41Z"}))
    return tmp_path


def test_priority_tor_over_vpn_over_hosting(d):
    a = AnonIntel(d)
    assert a.classify("185.220.101.7").category == "tor"
    assert a.classify("45.86.200.1").category == "vpn"
    assert a.classify("45.86.1.1").category == "hosting"
    assert a.classify("8.8.4.4") is None


def test_ipv6_and_ipv4_mapped(d):
    a = AnonIntel(d)
    assert a.classify("2a0b:f4c2::1").category == "tor"
    assert a.classify("::ffff:185.220.101.7").category == "tor"


@pytest.mark.parametrize("ip", ["192.168.43.50", "10.1.2.3", "127.0.0.1", "169.254.1.1"])
def test_private_never_matched_by_real_lists(d, ip):
    assert AnonIntel(d).classify(ip) is None


def test_demo_list_can_label_lan_for_rehearsal(d):
    (d / "demo.txt").write_text("192.168.43.50 tor\n")
    v = AnonIntel(d).classify("192.168.43.50")
    assert v.category == "tor" and v.source == "demo"


@pytest.mark.parametrize("bad", [None, "", "not-an-ip", "300.1.1.1", "1.2.3.4; DROP"])
def test_garbage_input(d, bad):
    assert AnonIntel(d).classify(bad) is None


def test_range_boundaries(d):
    a = AnonIntel(d)
    assert a.classify("34.64.0.0").category == "hosting" and a.classify("34.127.255.255").category == "hosting"
    assert a.classify("34.128.0.0") is None and a.classify("34.63.255.255") is None


def test_status_reports_counts_and_date(d):
    s = AnonIntel(d).status()
    assert s["list_date"] == "2026-11-01T05:33:41Z" and s["counts"]["tor_exit_list"] == 2


def test_bundled_snapshot_loads():
    a = AnonIntel()
    assert a.counts["tor_exit_list"] > 300 and a.counts["x4b_datacenter"] > 5000


def test_demo_priority_tor_beats_overlapping_hosting(d):
    (d / "demo.txt").write_text("192.168.43.0/24 hosting\n192.168.43.50 tor\n")
    a = AnonIntel(d)
    assert a.classify("192.168.43.50").category == "tor"
    assert a.classify("192.168.43.51").category == "hosting"
