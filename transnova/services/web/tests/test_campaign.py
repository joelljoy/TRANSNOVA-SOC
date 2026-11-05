"""Phase 3: campaign IDs and source IPs cannot be spoofed (PLAN §0.1 P1, P2)."""

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from web_decoy.app import create_app
from .conftest import OUTSIDE_IP, read_events

SIM_IP = "172.28.0.50"


def _client(settings, ip):
    return TestClient(create_app(settings), client=(ip, 5555), follow_redirects=False)


def test_trusted_simulator_campaign_accepted(settings):
    _client(settings, SIM_IP).get("/admin", headers={"X-Campaign-Id": "demo-2026_01"})
    e = read_events(settings)[-1]
    assert e["campaign_id"] == "demo-2026_01"
    assert "untrusted_campaign_header" not in e["tags"]


def test_outside_source_campaign_rejected(settings):
    _client(settings, OUTSIDE_IP).get("/admin", headers={"X-Campaign-Id": "demo-2026_01"})
    e = read_events(settings)[-1]
    assert e["campaign_id"] is None and "untrusted_campaign_header" in e["tags"]


@pytest.mark.parametrize("ip", ["172.28.0.1", "172.28.0.51", "127.0.0.1"])
def test_gateway_and_neighbours_not_trusted(settings, ip):
    """P9: the Docker gateway and other lab hosts are not the simulator."""
    _client(settings, ip).get("/", headers={"X-Campaign-Id": "demo"})
    assert read_events(settings)[-1]["campaign_id"] is None


@pytest.mark.parametrize("value", ["", "a" * 65, "demo campaign", "demo;drop", "<script>", "démo"])
def test_invalid_campaign_format_rejected_even_from_simulator(settings, value):
    _client(settings, SIM_IP).get("/", headers={"X-Campaign-Id": value.encode()})
    e = read_events(settings)[-1]
    assert e["campaign_id"] is None and "untrusted_campaign_header" in e["tags"]


def test_no_header_no_tag(settings):
    _client(settings, SIM_IP).get("/")
    e = read_events(settings)[-1]
    assert e["campaign_id"] is None and "untrusted_campaign_header" not in e["tags"]


def test_forwarded_for_ignored_by_default(settings):
    _client(settings, OUTSIDE_IP).get("/", headers={"X-Forwarded-For": SIM_IP, "X-Campaign-Id": "demo"})
    e = read_events(settings)[-1]
    assert e["source_ip"] == OUTSIDE_IP and e["campaign_id"] is None


def test_trust_proxy_uses_rightmost_entry(settings):
    s = replace(settings, trust_proxy=True)
    _client(s, "10.0.0.2").get("/", headers={"X-Forwarded-For": f"{SIM_IP}, 198.51.100.7"})
    # Leftmost is attacker-chosen; rightmost is what our proxy saw.
    assert read_events(s)[-1]["source_ip"] == "198.51.100.7"


def test_trust_proxy_garbage_falls_back_to_peer(settings):
    s = replace(settings, trust_proxy=True)
    _client(s, "10.0.0.2").get("/", headers={"X-Forwarded-For": "not-an-ip, also bad"})
    assert read_events(s)[-1]["source_ip"] == "10.0.0.2"


def test_raw_campaign_header_value_not_in_evidence(settings):
    _client(settings, OUTSIDE_IP).get("/", headers={"X-Campaign-Id": "attacker-chosen-123"})
    assert "attacker-chosen-123" not in open(settings.event_log_path).read()
