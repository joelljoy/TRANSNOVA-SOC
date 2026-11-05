"""USP 6: adaptive deception. The bait is shown only after attack intent and works only for that source."""

from fastapi.testclient import TestClient

from web_decoy.adaptive import BAIT_PATH, ENGAGED_TTL_S, AdaptiveDeception
from web_decoy.app import create_app
from .conftest import read_events
from .detect_helpers import dets, last, rules

ATTACKER, VISITOR = "203.0.113.66", "203.0.113.77"


def _c(app, ip):
    return TestClient(app, client=(ip, 40000), follow_redirects=False)


def test_ordinary_visitor_never_sees_the_bait(settings):
    app = create_app(settings)
    v = _c(app, VISITOR)
    for path in ("/", "/status", "/search?q=50211"):
        assert BAIT_PATH not in v.get(path).text
    assert v.get(BAIT_PATH).status_code == 404  # guessing the path does not work either
    assert "W-ADAPT-01" not in rules(last(settings))


def test_intent_reveals_the_bait_and_taking_it_is_high(settings):
    app = create_app(settings)
    a = _c(app, ATTACKER)
    a.get("/search", params={"q": "1' OR '1'='1"})          # SQLi intent (W-SQLI-01)
    page = a.get("/")
    assert BAIT_PATH in page.text
    e = last(settings)
    assert "adaptive:revealed" in e["tags"] and e["raw_evidence_redacted"]["adaptive"] == {"stage": "revealed", "bait": BAIT_PATH}
    r = a.get(BAIT_PATH)
    assert r.status_code == 200 and "erp_report" in r.text and "attachment" in r.headers["content-disposition"]
    e = last(settings)
    d = next(x for x in dets(e) if x["rule"] == "W-ADAPT-01")
    assert d["confidence"] == "high" and d["category"] == "decoy_interaction"
    assert d["attack"][0]["technique"] == "T1213" and d["attack"][0]["status"] == "candidate"
    assert e["raw_evidence_redacted"]["adaptive"]["stage"] == "taken"


def test_bait_is_per_source(settings):
    app = create_app(settings)
    _c(app, ATTACKER).get("/search", params={"q": "<script>alert(1)</script>"})
    _c(app, ATTACKER).get("/status")
    v = _c(app, VISITOR)
    assert BAIT_PATH not in v.get("/").text
    assert v.get(BAIT_PATH).status_code == 404  # another address cannot use the attacker's reveal


def test_engagement_requires_a_reveal_before_the_bait_works(settings):
    app = create_app(settings)
    a = _c(app, ATTACKER)
    a.get("/download", params={"file": "../../etc/passwd"})  # intent, but no page with the link viewed yet
    assert a.get(BAIT_PATH).status_code == 404
    a.get("/search", params={"q": "x"})                       # now the link is shown
    assert a.get(BAIT_PATH).status_code == 200


def test_bait_body_is_synthetic_and_never_a_real_file(settings):
    app = create_app(settings)
    a = _c(app, ATTACKER)
    a.get("/search", params={"q": "1' OR 1=1--"})
    a.get("/")
    body = a.get(BAIT_PATH).text
    assert "transnova.internal" in body and "root:" not in body
    assert a.get("/backup/../../etc/passwd").status_code == 404


def test_engagement_expires():
    t = [1000.0]
    ad = AdaptiveDeception(clock=lambda: t[0])
    ad.observe(ATTACKER, {"W-SQLI-01"})
    assert ad.engaged(ATTACKER)
    t[0] += ENGAGED_TTL_S + 1
    assert not ad.engaged(ATTACKER)
    ad.observe(VISITOR, {"W-AUTH-01", "W-ENUM-01"})  # single-occurrence signals are not intent
    assert not ad.engaged(VISITOR)


def test_bait_path_is_logged_but_never_leaks_contents(settings):
    app = create_app(settings)
    a = _c(app, ATTACKER)
    a.get("/search", params={"q": "1' OR 1=1--"})
    a.get("/")
    a.get(BAIT_PATH)
    assert "Rpt#Replica2026" not in str(read_events(settings))
