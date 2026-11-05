"""Phase 3: no secret ever reaches an event or the JSONL log (PLAN §4.1)."""

import json

import pytest

from web_decoy.telemetry import redact
from .conftest import read_events

SECRETS = {
    "password": "Pl41nTextP@ss",
    "cookie": "sessvalue-ABCDEF123456",
    "authz": "Bearer abcdefghijklmnop.qrstuv",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "gh": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----",
    "inline": "hunter2hunter2",
}


def _log_text(settings) -> str:
    with open(settings.event_log_path, encoding="ascii") as fh:
        return fh.read()


def _assert_absent(settings, *values):
    text = _log_text(settings)
    decoded = json.dumps(read_events(settings))  # also check after JSON unescaping
    for v in values:
        for piece in (v, v.split("\n")[1] if "\n" in v else v):
            assert piece not in text and piece not in decoded, f"leaked: {piece[:20]}"


def test_secrets_in_headers_never_logged(client, settings):
    client.cookies.set("hf_session", SECRETS["cookie"])
    client.get("/", headers={"Authorization": SECRETS["authz"], "X-Api-Key": SECRETS["aws"],
                             "Proxy-Authorization": "Basic dXNlcjpwYXNzd29yZA==",
                             "X-Custom": SECRETS["gh"]})
    _assert_absent(settings, SECRETS["cookie"], SECRETS["authz"], SECRETS["aws"], SECRETS["gh"],
                   "dXNlcjpwYXNzd29yZA==")
    headers = read_events(settings)[-1]["raw_evidence_redacted"]["headers"]
    assert set(headers) <= set(redact.HEADER_ALLOWLIST)


def test_secrets_in_query_never_logged(client, settings):
    client.get("/search", params={"q": f"x password={SECRETS['inline']} y", "token": "tok-999999",
                                  "access_token": SECRETS["jwt"], "note": SECRETS["aws"]})
    _assert_absent(settings, SECRETS["inline"], "tok-999999", SECRETS["jwt"], SECRETS["aws"])
    q = read_events(settings)[-1]["raw_evidence_redacted"]["query"]
    assert q["token"] == "[REDACTED]" and q["access_token"] == "[REDACTED]"
    assert "password=[REDACTED]" in q["q"]


def test_secrets_in_form_never_logged(client, settings):
    client.post("/login", data={"username": "u", "password": SECRETS["password"],
                                "api_key": "k-55555555", "comment": SECRETS["pem"]})
    _assert_absent(settings, SECRETS["password"], "k-55555555", SECRETS["pem"])


def test_secret_in_path_never_logged(client, settings):
    client.get(f"/reset/{SECRETS['jwt']}")
    _assert_absent(settings, SECRETS["jwt"])


def test_secret_in_username_field_never_logged(client, settings):
    # Users sometimes paste a token into the username box.
    client.post("/login", data={"username": SECRETS["gh"], "password": "x"})
    _assert_absent(settings, SECRETS["gh"])


def test_secret_in_user_agent_never_logged(client, settings):
    client.get("/", headers={"User-Agent": f"curl/8 {SECRETS['authz']}"})
    _assert_absent(settings, SECRETS["authz"])


@pytest.mark.parametrize("glued", ["xx" + SECRETS["jwt"], "my" + "password=" + SECRETS["inline"],
                                   "id" + SECRETS["aws"] + "zz", "pre" + SECRETS["gh"]])
def test_secret_glued_to_text_is_redacted(glued):
    out = redact.safe_value(glued)
    for marker in ("eyJhbGci", SECRETS["inline"], "AKIAIOSFODNN7", "ghp_abcdef"):
        assert marker not in out, out


def test_secret_straddling_truncation_point_is_redacted():
    value = "a" * 500 + SECRETS["jwt"]  # starts before the 512 cut
    out = redact.safe_value(value)
    assert "eyJhbGci" not in out


# --- bounds -----------------------------------------------------------------------

def test_value_truncated_with_marker():
    out = redact.safe_value("x" * 5000)
    assert out.startswith("x" * 512) and "[truncated" in out


def test_key_count_bounded():
    out, _ = redact.redact_pairs([(f"k{i}", "v") for i in range(200)])
    assert len(out) == redact.MAX_KEYS + 1 and out["_dropped_keys"] == 150


def test_evidence_total_budget(client, settings):
    params = {f"p{i}": "y" * 500 for i in range(40)}
    client.get("/search", params=params)
    ev = read_events(settings)[-1]["raw_evidence_redacted"]
    size = len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode())
    assert size <= redact.MAX_EVIDENCE_BYTES and ev["_truncated"] is True


def test_huge_path_bounded(client, settings):
    client.get("/" + "a" * 6000)
    e = read_events(settings)[-1]
    assert len(e["request_path"]) < 2100


# --- log injection / markup ---------------------------------------------------------

def test_control_chars_cannot_forge_log_lines(client, settings):
    evil = 'x\r\n{"event_id":"forged"} \x00\x1b[31m'
    client.get("/search", params={"q": evil}, headers={"User-Agent": "ua\u2028{}".encode()})
    with open(settings.event_log_path, "rb") as fh:
        lines = fh.read().splitlines()
    assert len(lines) == 1  # one request, one line
    e = read_events(settings)[0]
    assert "\n" not in e["raw_evidence_redacted"]["query"]["q"]
    assert "\x1b" not in e["raw_evidence_redacted"]["query"]["q"]
    assert lines[0].isascii()


@pytest.mark.parametrize("payload", ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
                                     "javascript:alert(1)", "<svg/onload=alert(1)>"])
def test_markup_tagged_for_dashboard(client, settings, payload):
    client.get("/search", params={"q": payload})
    e = read_events(settings)[-1]
    assert "contains_markup" in e["tags"]
    assert e["raw_evidence_redacted"]["query"]["q"] == payload  # kept verbatim as evidence


def test_plain_text_not_tagged(client, settings):
    client.get("/search", params={"q": "HFCU1234567 container"})
    assert "contains_markup" not in read_events(settings)[-1]["tags"]


def test_redos_inputs_are_fast():
    import time
    nasty = ["a" * 100000, "password=" + "=" * 100000, "eyJ" + "a" * 100000 + ".",
             "<" * 100000, "-----BEGIN RSA PRIVATE KEY-----" + "A" * 100000, "bearer " + " " * 100000]
    start = time.perf_counter()
    for n in nasty:
        redact.safe_value(n)
        redact.contains_markup(n)
    assert time.perf_counter() - start < 0.5
