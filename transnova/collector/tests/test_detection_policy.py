"""Alert policy: a match is not an alert, and one failed login is never an attack.

Each rule the catalogue cites from this file (W-AUTH-01, SOC-AUTH-00, SOC-AUTH-01, X-CORR-01) has a
positive, negative and boundary case here.
"""

from __future__ import annotations

from conftest import console_headers, failed_web_login, read_headers, stamp, web_event


def alerts(client):
    return client.get("/api/v2/alerts", headers=read_headers()).json()["items"]


def auth_event(client, outcome="failed", username="analyst", source_ip="127.0.0.1", action="login"):
    r = client.post("/api/v2/console/auth-event", headers=console_headers(),
                    json={"action": action, "outcome": outcome, "source_ip": source_ip, "username": username,
                          "reason": "invalid_credentials" if outcome == "failed" else None})
    assert r.status_code == 200, r.text
    return r.json()["event_id"]


# ---- W-AUTH-01: one failed web login ---------------------------------------------------------

def test_w_auth_01_single_failed_login_is_event_not_alert(client):
    event = failed_web_login()
    assert client.post("/api/events", json=[event]).status_code == 200
    assert alerts(client) == []
    stored = client.get(f"/api/v2/events/{event['event_id']}", headers=read_headers()).json()["event"]
    assert stored["detection_status"] == "matched" and stored["rules"] == ["W-AUTH-01"]
    assert stored["classification"] == "unclassified"


def test_w_auth_01_many_single_matches_still_no_alert_without_threshold_rule(client):
    client.post("/api/events", json=[failed_web_login() for _ in range(4)])
    assert alerts(client) == []


def test_threshold_rule_w_auth_02_alerts_with_evidence(client):
    event = failed_web_login()
    event["raw_evidence_redacted"]["detections"].append({
        "rule": "W-AUTH-02", "category": "behavior_detected", "label": "auth:bruteforce", "confidence": "medium",
        "owasp": "A07:2021-Identification and Authentication Failures", "field": "form.username",
        "rationale": "5 failures for one username in 60 s",
        "attack": [{"technique": "T1110.001", "status": "candidate", "confidence": "medium", "rationale": "x"}]})
    client.post("/api/events", json=[event])
    [alert] = alerts(client)
    assert alert["rule"] == "W-AUTH-02" and alert["severity"] == "medium" and alert["status"] == "open"
    detail = client.get(f"/api/v2/alerts/{alert['alert_id']}", headers=read_headers()).json()
    assert [e["event_id"] for e in detail["events"]] == [event["event_id"]]
    assert detail["matched_detections"][0]["rule"] == "W-AUTH-02"
    assert detail["attack"][0]["valid"] is True and detail["attack"][0]["name"] == "Password Guessing"
    assert detail["rule"]["false_positives"]


# ---- SOC-AUTH-00 / SOC-AUTH-01: console logins -----------------------------------------------

def test_soc_auth_00_one_failed_console_login_is_recorded_not_alerted(client):
    event_id = auth_event(client)
    detail = client.get(f"/api/v2/events/{event_id}", headers=read_headers()).json()["event"]
    assert detail["service"] == "soc" and detail["outcome"] == "failed" and detail["action"] == "login"
    assert detail["detection_status"] == "matched" and detail["rules"] == ["SOC-AUTH-00"]
    assert "password" not in str(detail).lower().replace("password_check", "")
    assert alerts(client) == []


def test_soc_auth_01_boundary_four_failures_no_alert(client):
    for _ in range(4):
        auth_event(client)
    assert alerts(client) == []


def test_soc_auth_01_five_failures_from_one_source_alert_medium(client):
    ids = [auth_event(client, username=f"user{i}") for i in range(5)]
    [alert] = alerts(client)
    assert alert["rule"] == "SOC-AUTH-01" and alert["severity"] == "medium" and alert["confidence"] == "medium"
    detail = client.get(f"/api/v2/alerts/{alert['alert_id']}", headers=read_headers()).json()
    assert set(ids) <= {e["event_id"] for e in detail["events"]}
    assert "mistyped" in detail["rationale"]


def test_soc_auth_01_successes_do_not_count(client):
    for _ in range(6):
        auth_event(client, outcome="succeeded")
    assert alerts(client) == []


def test_soc_auth_01_failures_spread_over_sources_and_users_do_not_alert(client):
    for i in range(6):
        auth_event(client, username=f"u{i}", source_ip=f"10.0.0.{i + 1}")
    assert alerts(client) == []


def test_console_events_cannot_be_forged_through_ingest(client):
    forged = web_event(service="soc", sensor_id="soc-auth", destination_service="soc-console",
                       event_type="authentication", action="login", outcome="succeeded")
    assert client.post("/api/events", json=[forged]).status_code == 422


def test_console_auth_route_requires_console_token(client):
    body = {"action": "login", "outcome": "failed", "source_ip": "127.0.0.1"}
    assert client.post("/api/v2/console/auth-event", json=body).status_code == 401
    assert client.post("/api/v2/console/auth-event", json=body, headers=read_headers()).status_code == 401


def test_console_auth_rejects_unknown_fields_and_non_address_source(client):
    base = {"action": "login", "outcome": "failed", "source_ip": "127.0.0.1"}
    assert client.post("/api/v2/console/auth-event", headers=console_headers(),
                       json={**base, "password": "x"}).status_code == 422
    assert client.post("/api/v2/console/auth-event", headers=console_headers(),
                       json={**base, "source_ip": "not-an-ip"}).status_code == 422


# ---- X-CORR-01: shared IP across decoys ------------------------------------------------------

def test_x_corr_01_is_a_low_confidence_hint(client):
    client.post("/api/events", json=[web_event(), web_event(service="database", sensor_id="db-01",
                                                            destination_service="database-honeypot",
                                                            event_type="sql_query", action="reconnaissance",
                                                            request_path=None, http_method=None, http_status=None)])
    [alert] = alerts(client)
    assert alert["rule"] == "X-CORR-01" and alert["severity"] == "medium" and alert["confidence"] == "low"
    detail = client.get(f"/api/v2/alerts/{alert['alert_id']}", headers=read_headers()).json()
    assert {e["service"] for e in detail["events"]} == {"web", "database"}  # both sides of the link


def test_x_corr_01_negative_single_decoy(client):
    client.post("/api/events", json=[web_event(), web_event()])
    assert alerts(client) == []


def test_x_corr_01_ignores_console_logins_from_same_address(client):
    client.post("/api/events", json=[web_event(source_ip="127.0.0.1")])
    auth_event(client, source_ip="127.0.0.1", outcome="succeeded")
    assert alerts(client) == []


def test_duplicate_events_do_not_inflate_alerts(client):
    event = failed_web_login()
    event["raw_evidence_redacted"]["detections"][0]["rule"] = "W-AUTH-02"
    for _ in range(3):
        client.post("/api/events", json=[event])
    [alert] = alerts(client)
    assert alert["event_count"] == 1


def test_benign_requests_stay_observed(client):
    events = [web_event(request_path=p) for p in ("/", "/about", "/track?id=TN-1")]
    client.post("/api/events", json=events)
    page = client.get("/api/v2/events", headers=read_headers()).json()
    assert {e["detection_status"] for e in page["items"]} == {"observed"}
    assert alerts(client) == []


def test_timestamps_are_preserved(client):
    event = web_event(timestamp=stamp(3600))
    client.post("/api/events", json=[event])
    stored = client.get(f"/api/v2/events/{event['event_id']}", headers=read_headers()).json()["event"]
    assert stored["timestamp"] == event["timestamp"]


def test_threshold_alert_links_the_failures_that_led_up_to_it(client):
    prior = [failed_web_login(timestamp=stamp(40 - i)) for i in range(4)]
    crossing = failed_web_login(timestamp=stamp(1))
    crossing["raw_evidence_redacted"]["detections"].append({
        "rule": "W-AUTH-02", "category": "behavior_detected", "label": "auth:bruteforce", "confidence": "medium",
        "rationale": "5 failures for one username in 60 s", "attack": []})
    other_user = failed_web_login(timestamp=stamp(20), username="bob")
    old = failed_web_login(timestamp=stamp(600))
    client.post("/api/events", json=[*prior, other_user, old, crossing])
    [alert] = alerts(client)
    assert alert["title"] == "Repeated failed web logins" and alert["event_count"] == 1
    detail = client.get(f"/api/v2/alerts/{alert['alert_id']}", headers=read_headers()).json()
    assert {e["event_id"] for e in detail["events"]} == {e["event_id"] for e in [*prior, crossing]}
