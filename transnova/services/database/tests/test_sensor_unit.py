"""Unit tests. Audit lines here are copied in shape from a real MariaDB 11.4.9 audit log."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
from db_sensor.adaptive import AdaptiveEngine
from db_sensor.audit import LineAssembler, parse_line
from db_sensor.classify import classify, outcome_for, redact
from db_sensor.config import DEFAULT_RULES, Settings, load_rules
from db_sensor.emitter import DurableSender
from db_sensor.events import EventBuilder
from db_sensor.risk import assess_query
from db_sensor.state import SensorState, SourceTracker
from db_sensor.tailer import AuditTailer, Position

RULES = load_rules(str(DEFAULT_RULES))
DB = "transnova_logistics"


def line(sql="SELECT 1", ret=0, user="decoy_user", host="172.28.0.51", conn=7, qid=100, op="QUERY", db=DB):
    obj = "'" + sql.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'" if op == "QUERY" else ""
    return f"20261031 14:54:45,dbhost,{user},{host},{conn},{qid},{op},{db},{obj},{ret}"


def cat(sql, ret=0):
    return classify(sql, ret, DB, RULES)


# ---- audit parsing -------------------------------------------------------------------
def test_parse_query_line():
    r = parse_line(line("SELECT * FROM shipments LIMIT 2"))
    assert (r.user, r.host, r.connection_id, r.query_id, r.operation) == ("decoy_user", "172.28.0.51", 7, 100, "QUERY")
    assert r.query == "SELECT * FROM shipments LIMIT 2" and r.retcode == 0 and not r.truncated


def test_parse_keeps_quotes_newlines_and_commas_in_sql():
    sql = "SELECT 'it''s, ok',\n  a FROM t"
    r = parse_line(line(sql, ret=1142))
    assert r.query == sql and r.retcode == 1142


def test_parse_failed_connect():
    r = parse_line(line(op="FAILED_CONNECT", ret=1045, db="", conn=8, qid=0))
    assert r.operation == "FAILED_CONNECT" and r.retcode == 1045


def test_attacker_username_with_commas_cannot_shift_fields():
    r = parse_line("20261031 14:54:45,dbhost,evil,1.2.3.4,99,0,CONNECT,x,172.28.0.51,8,0,FAILED_CONNECT,,,1045")
    assert r.host == "172.28.0.51" and r.operation == "FAILED_CONNECT" and r.user == "evil,1.2.3.4,99,0,CONNECT,x"


def test_truncated_query_is_flagged_not_dropped():
    r = parse_line("20261031 14:54:45,h,decoy_user,1.1.1.1,7,9,QUERY,db,'SELECT aaaaa")
    assert r is not None and r.truncated and r.query.startswith("SELECT aaaaa")


def test_garbage_line_returns_none():
    assert parse_line("this is not an audit line") is None


# ---- classification ------------------------------------------------------------------
@pytest.mark.parametrize("sql,ret,expected", [
    ("SHOW DATABASES", 0, "reconnaissance"),
    ("SHOW TABLES", 0, "reconnaissance"),
    ("DESCRIBE shipments", 0, "reconnaissance"),
    ("SHOW COLUMNS FROM customers", 0, "reconnaissance"),
    ("SELECT table_name FROM information_schema.tables", 0, "reconnaissance"),
    ("SELECT VERSION()", 0, "reconnaissance"),
    ("SELECT * FROM shipments LIMIT 10", 0, "data_exploration"),
    ("SELECT s.status FROM shipments s JOIN customers c USING (customer_id)", 0, "data_exploration"),
    ("SELECT * FROM api_credentials", 0, "sensitive_access"),
    ("DESCRIBE admin_accounts", 0, "sensitive_access"),
    ("SELECT * FROM backup_credentials", 0, "adaptive_decoy_access"),
    ("SELECT * FROM backup_credentials", 1142, "restricted_access"),
    ("SELECT user FROM mysql.user", 1142, "restricted_access"),
    ("UPDATE shipments SET status='x'", 1142, "modification_attempt"),
    ("DELETE FROM shipments", 1142, "modification_attempt"),
    ("CREATE TABLE unauthorized_test (id INT)", 1142, "schema_change_attempt"),
    ("DROP TABLE shipments", 1142, "schema_change_attempt"),
    ("GRANT ALL ON *.* TO 'decoy_user'@'%'", 1045, "privilege_attempt"),
    ("CREATE USER 'x'@'%' IDENTIFIED BY 'y'", 1227, "privilege_attempt"),
    ("SET PASSWORD = PASSWORD('x')", 0, "privilege_attempt"),
    ("SELECT LOAD_FILE('/etc/passwd')", 0, "file_access_attempt"),
    ("SELECT 1 INTO OUTFILE '/tmp/x'", 1045, "file_access_attempt"),
    ("USE transnova_logistics", 0, "session_control"),
    ("select @@version_comment limit 1", 0, "client_noise"),
])
def test_categories(sql, ret, expected):
    assert cat(sql, ret).category == expected


def test_string_literal_is_not_a_statement():
    assert cat("SELECT 'DROP TABLE shipments'", 0).category == "client_noise"


def test_comment_cannot_hide_sensitive_table():
    c = cat("SELECT /* innocent */ * FROM /* shipments */ `api_credentials` -- x", 0)
    assert c.category == "sensitive_access" and "api_credentials" in c.tables


def test_union_and_subquery_tables_are_all_found():
    c = cat("SELECT tracking_no FROM shipments UNION SELECT api_key FROM api_credentials", 0)
    assert {"shipments", "api_credentials"} <= set(c.tables) and c.category == "sensitive_access"
    assert "admin_accounts" in cat("SELECT 1 FROM customers WHERE 1 IN (SELECT admin_id FROM admin_accounts)", 0).tables


def test_case_and_schema_qualifier_normalised():
    assert cat("select * from TRANSNOVA_LOGISTICS.API_CREDENTIALS", 0).tables == ["api_credentials"]


def test_cte_alias_is_not_a_table():
    assert cat("WITH x AS (SELECT * FROM shipments) SELECT * FROM x", 0).tables == ["shipments"]


def test_unparseable_sql_keeps_going():
    c = cat("SELEC bad syntax here", 1064)
    assert c.category == "unknown" and "sql:syntax_error" in c.tags


def test_executable_comment_flagged():
    assert "sql:executable_comment" in cat("/*!50000 SELECT * FROM api_credentials */", 0).tags


def test_unbounded_detection():
    assert cat("SELECT * FROM shipments", 0).unbounded
    assert not cat("SELECT * FROM shipments LIMIT 5", 0).unbounded


def test_outcome_distinguishes_attempt_from_success():
    assert outcome_for(1142) == "blocked" and outcome_for(0) == "succeeded" and outcome_for(1064) == "failed"


def test_redaction_of_password_literals():
    assert "s3cret" not in redact("CREATE USER a IDENTIFIED BY 's3cret'")
    assert "s3cret" not in redact("SET PASSWORD FOR a = PASSWORD('s3cret')")


# ---- risk + MITRE --------------------------------------------------------------------
def test_ordinary_select_stays_low_with_no_mitre():
    c = cat("SELECT * FROM shipments LIMIT 10")
    a = assess_query(c, "succeeded", SourceTracker(key="k"), RULES)
    assert a.severity == "LOW" and a.mitre == []


def test_repeated_plain_selects_never_reach_critical():
    t = SourceTracker(key="k", table_hits={f"t{i}": 3 for i in range(9)})
    a = assess_query(cat("SELECT * FROM shipments JOIN customers"), "succeeded", t, RULES)
    assert a.severity in ("LOW", "MEDIUM")


def test_credential_read_maps_t1552_and_every_point_is_explained():
    t = SourceTracker(key="k", enumeration_count=2, table_hits={"api_credentials": 1})
    a = assess_query(cat("SELECT * FROM api_credentials"), "succeeded", t, RULES)
    assert a.severity in ("HIGH", "CRITICAL")
    assert [m["technique"] for m in a.mitre] == ["T1552"] and a.mitre[0]["status"] == "observed"
    points = sum(int(r.split()[0].lstrip("+")) for r in a.reasons)
    assert points == a.risk_score


def test_admin_table_maps_account_discovery_not_credentials():
    a = assess_query(cat("SELECT * FROM admin_accounts"), "succeeded", SourceTracker(key="k"), RULES)
    assert [m["technique"] for m in a.mitre] == ["T1087"]


def test_denied_read_is_attempted_not_observed():
    a = assess_query(cat("SELECT user FROM mysql.user", 1142), "blocked", SourceTracker(key="k"), RULES)
    assert a.mitre[0]["technique"] == "T1087" and a.mitre[0]["status"] == "attempted"


def test_denied_modification_has_no_technique_forced():
    a = assess_query(cat("UPDATE shipments SET x=1", 1142), "blocked", SourceTracker(key="k"), RULES)
    assert a.mitre == []


# ---- events --------------------------------------------------------------------------
def settings(tmp_path, **kw):
    return Settings(data_dir=str(tmp_path), controller_password="x", destination_ip="172.28.0.30",
                    internal_accounts=frozenset({("deception_ctrl", "172.29.0.21")}), **kw)


def builder(tmp_path, **kw):
    b = EventBuilder(settings(tmp_path, **kw), RULES, SensorState(str(tmp_path)))
    b.build(parse_line(line(op="CONNECT", db="", qid=0)))  # statements need a real login first
    return b


def test_event_matches_canonical_schema(tmp_path):
    from collector.schema import CanonicalEvent

    event, _, _ = builder(tmp_path).build(parse_line(line("SELECT * FROM api_credentials")))
    parsed = CanonicalEvent.model_validate(event)
    assert parsed.service == "database" and parsed.table_names == ["api_credentials"] and parsed.query_type == "SELECT"
    ev = event["raw_evidence_redacted"]
    assert ev["source"] == "database-honeypot" and ev["severity"] in ("HIGH", "CRITICAL") and ev["detections"]


def test_controller_activity_is_internal_only_from_its_own_host(tmp_path):
    b = builder(tmp_path)
    assert b.is_internal(parse_line(line(user="deception_ctrl", host="172.29.0.21")))
    assert not b.is_internal(parse_line(line(user="deception_ctrl", host="172.28.0.51")))
    assert not b.is_internal(parse_line(line(user="deception_ctrl", host="172.29.0.21", op="FAILED_CONNECT", ret=1045)))


def test_event_id_is_stable_for_the_same_line(tmp_path):
    b = builder(tmp_path)
    rec = parse_line(line())
    assert b.build(rec)[0]["event_id"] == b.build(rec)[0]["event_id"]


def test_query_text_is_redacted_in_event_and_raw(tmp_path):
    event, _, _ = builder(tmp_path).build(parse_line(line("CREATE USER a IDENTIFIED BY 'hunter2'", ret=1227)))
    assert "hunter2" not in json.dumps(event)


def test_bruteforce_escalates_and_maps_t1110(tmp_path):
    b = builder(tmp_path)
    events = [b.build(parse_line(line(op="FAILED_CONNECT", ret=1045, conn=i, qid=0)))[0] for i in range(5)]
    assert events[0]["raw_evidence_redacted"]["severity"] == "LOW"
    assert events[-1]["raw_evidence_redacted"]["severity"] == "HIGH"
    assert events[-1]["raw_evidence_redacted"]["mitre"][0]["technique"] == "T1110.001"


def test_spraying_maps_t1110_003(tmp_path):
    b = builder(tmp_path)
    last = None
    for i, user in enumerate(["a", "b", "c", "d", "e"]):
        last = b.build(parse_line(line(user=user, op="FAILED_CONNECT", ret=1045, conn=i, qid=0)))[0]
    assert last["raw_evidence_redacted"]["mitre"][0]["technique"] == "T1110.003"


def test_campaign_only_trusted_from_simulator(tmp_path):
    b = builder(tmp_path)
    b.build(parse_line(line(op="CONNECT", db="", qid=0, host="172.28.0.51", conn=1)))
    b.build(parse_line(line(op="CONNECT", db="", qid=0, host="172.28.0.50", conn=2)))
    forged = b.build(parse_line(line("SET @campaign_id='x1'", host="172.28.0.51", conn=1)))[0]
    assert forged["campaign_id"] is None
    trusted = b.build(parse_line(line("SET @campaign_id='x1'", host="172.28.0.50", conn=2)))[0]
    assert trusted["campaign_id"] == "x1"


def test_load_file_with_retcode_zero_is_not_reported_as_success(tmp_path):
    event, _, _ = builder(tmp_path).build(parse_line(line("SELECT LOAD_FILE('/etc/passwd')")))
    assert event["outcome"] == "blocked" and event["action"] == "file_access_attempt"


# ---- tailer --------------------------------------------------------------------------
def test_partial_line_waits_for_newline(tmp_path):
    log = tmp_path / "a.log"
    log.write_bytes(b"one\ntw")
    t = AuditTailer(str(log))
    assert t.poll() == ["one"]
    assert t.poll() == []
    with open(log, "ab") as fh:
        fh.write(b"o\n")
    assert t.poll() == ["two"]


def test_restart_resumes_without_duplicates(tmp_path):
    log = tmp_path / "a.log"
    log.write_bytes(b"one\ntwo\n")
    t = AuditTailer(str(log))
    t.poll()
    with open(log, "ab") as fh:
        fh.write(b"three\n")
    assert AuditTailer(str(log), Position(t.position.identity, t.position.offset)).poll() == ["three"]


def test_rotation_drains_old_file_then_new(tmp_path):
    log = tmp_path / "a.log"
    log.write_bytes(b"one\n")
    t = AuditTailer(str(log))
    t.poll()
    with open(log, "ab") as fh:
        fh.write(b"two\n")
    os.replace(log, tmp_path / "a.log.1")
    log.write_bytes(b"three\n")
    got = t.poll() + t.poll()
    assert got == ["two", "three"]


def test_missing_log_is_not_an_error(tmp_path):
    assert AuditTailer(str(tmp_path / "none.log")).poll() == []


# ---- delivery ------------------------------------------------------------------------
def sender(tmp_path, handler):
    return DurableSender("http://collector/api/events", tmp_path / "e.jsonl", tmp_path / "s.jsonl", 2, 1, 10**6,
                         httpx.MockTransport(handler))


def test_outage_spools_then_replays_in_order_without_loss(tmp_path):
    up, got = [False], []

    def handler(req):
        if not up[0]:
            return httpx.Response(503)
        got.extend(json.loads(req.content))
        return httpx.Response(200)

    s = sender(tmp_path, handler)
    for i in range(5):
        s.add({"n": i})
    s.flush()
    assert s.spool_depth() == 5 and got == []
    up[0] = True
    s._retry_at = 0
    s.flush()
    assert [r["n"] for r in got] == [0, 1, 2, 3, 4] and s.spool_depth() == 0


def test_batches_never_exceed_limit(tmp_path):
    sizes = []

    def handler(req):
        sizes.append(len(json.loads(req.content)))
        return httpx.Response(200)

    s = sender(tmp_path, handler)
    for i in range(5):
        s.add({"n": i})
    s.flush()
    assert sizes == [2, 2, 1]


def test_connection_error_keeps_events(tmp_path):
    def handler(req):
        raise httpx.ConnectError("down")

    s = sender(tmp_path, handler)
    s.add({"n": 1})
    s.flush()
    assert s.spool_depth() == 1 and Path(tmp_path / "e.jsonl").exists()


# ---- adaptive ------------------------------------------------------------------------
class FakeBackend:
    def __init__(self, fail=False):
        self.grants, self.calls, self.fail = set(), [], fail

    def has_grant(self, table):
        return table in self.grants

    def grant(self, table):
        import pymysql
        if self.fail:
            raise pymysql.err.OperationalError(2003, "down")
        self.calls.append(table)
        self.grants.add(table)
        return f"GRANT {table}"


def engine(tmp_path, backend):
    emitted = []
    state = SensorState(str(tmp_path))
    return AdaptiveEngine(settings(tmp_path), RULES, state, backend, emitted.append), state, emitted


EVENT = {"event_type": "sql_query", "outcome": "succeeded", "event_id": "e1", "session_id": "s1", "source_ip": "172.28.0.51"}


def test_rule_a_needs_both_thresholds(tmp_path):
    e, state, _ = engine(tmp_path, FakeBackend())
    t = state.tracker("k")
    t.table_hits = {"shipments": 3}
    assert e.evaluate("k", EVENT) == []
    t.table_hits["tracking_events"] = 1
    assert {r["asset_revealed"] for r in e.evaluate("k", EVENT)} == {"shipment_archive", "premium_customer_records"}


def test_reveal_is_idempotent_and_recorded(tmp_path):
    b = FakeBackend()
    e, state, emitted = engine(tmp_path, b)
    state.tracker("k").table_hits = {"shipments": 3, "customers": 1}
    e.evaluate("k", EVENT)
    assert e.evaluate("k", EVENT) == [] and len(b.calls) == 2
    r = emitted[0]
    assert r["status"] == "applied" and r["privilege_before"] is False and r["privilege_after"] is True
    assert r["trigger_event_id"] == "e1" and "threshold" in r["trigger_reason"]


def test_existing_grant_is_not_granted_again(tmp_path):
    b = FakeBackend()
    b.grants.add("backup_credentials")
    e, state, emitted = engine(tmp_path, b)
    state.tracker("k").table_hits = {"api_credentials": 2}
    e.evaluate("k", EVENT)
    assert b.calls == [] and emitted[0]["status"] == "already_present"


def test_stage_two_needs_a_stage_one_rule_first(tmp_path):
    e, state, _ = engine(tmp_path, FakeBackend())
    t = state.tracker("k")
    # Meets D's thresholds but no stage 1 rule: none of these tables feed rules A, B or C.
    t.table_hits = {"partner_contracts": 3, "premium_customer_records": 1, "shipment_archive": 1}
    assert e.evaluate("k", EVENT) == []
    t.rules_fired = ["A-SHIPMENT-EXPLORATION"]
    assert "executive_shipments" in {r["asset_revealed"] for r in e.evaluate("k", EVENT)}


def test_failed_grant_is_recorded_and_retried_boundedly(tmp_path):
    e, state, emitted = engine(tmp_path, FakeBackend(fail=True))
    state.tracker("k").table_hits = {"api_credentials": 2}
    for _ in range(8):
        e.evaluate("k", EVENT)
    assert emitted[0]["status"] == "failed" and "OperationalError" in emitted[0]["error"]
    assert len(emitted) == 5  # MAX_ATTEMPTS, then the rule stops


def test_denied_event_never_triggers(tmp_path):
    e, state, _ = engine(tmp_path, FakeBackend())
    state.tracker("k").table_hits = {"api_credentials": 2}
    assert e.evaluate("k", {**EVENT, "outcome": "blocked"}) == []


def test_rules_cannot_reference_tables_outside_the_allowlist(tmp_path):
    bad = json.loads(Path(DEFAULT_RULES).read_text(encoding="utf-8"))
    bad["adaptive_rules"][0]["reveal"] = ["mysql.user"]
    path = tmp_path / "r.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(str(path))


# ---- log injection (reproduced on MariaDB 11.4.9 with a newline in the login username) ---
def assemble(lines):
    a = LineAssembler()
    return [out for ln in lines for out in a.feed(ln)]


def test_split_record_is_rejoined_and_forged_line_absorbed():
    raw = ["20261031 15:08:24,HOST,x", "20261031 15:00:00,h,decoy_user,9.9.9.9,1,1,QUERY,d,'FORGED',0",
           "y,127.0.0.1,101,0,FAILED_CONNECT,,,1045"]
    records = assemble(raw)
    assert len(records) == 1
    r = parse_line(records[0])
    assert r.operation == "FAILED_CONNECT" and r.host == "127.0.0.1" and "FORGED" in r.user


def test_normal_lines_pass_straight_through():
    lines = [line(), line(qid=101)]
    assert assemble(lines) == lines


def test_unterminated_record_is_released_after_a_bound():
    out = assemble(["20261031 15:08:24,HOST,x"] + ["junk"] * (LineAssembler.MAX_LINES - 1))
    assert len(out) == 1 and parse_line(out[0]) is None


def test_query_without_a_login_is_flagged_and_changes_nothing(tmp_path):
    b = builder(tmp_path)
    event, _, _ = b.build(parse_line(line("SELECT * FROM api_credentials", host="9.9.9.9", conn=555)))
    assert event["action"] == "log_tampering" and event["source_ip"] == "unverified"
    assert not [t for t in b.state.trackers.values() if t.table_hits]
    assert 555 not in b.state.sessions


def test_query_cannot_borrow_another_users_connection(tmp_path):
    b = builder(tmp_path)  # connection 7 belongs to decoy_user@172.28.0.51
    event, _, _ = b.build(parse_line(line("SELECT 1", user="root", host="10.0.0.1", conn=7)))
    assert event["action"] == "log_tampering"


def test_newline_username_raises_injection_detection(tmp_path):
    b = builder(tmp_path)
    rec = parse_line("20261031 15:08:24,HOST,x\n20261031 15:00:00,h,u,9.9.9.9,1,1,QUERY,d,'F',0\ny,127.0.0.1,101,0,FAILED_CONNECT,,,1045")
    event, _, _ = b.build(rec)
    assert event["raw_evidence_redacted"]["detections"][0]["rule"] == "D-INJ-01"
    assert event["source_ip"] == "127.0.0.1"


# ---- server-reported tables (audit TABLE events) --------------------------------------
def read_line(table, conn=7, qid=100, db=DB, user="decoy_user", host="172.28.0.51"):
    return f"20261031 14:54:45,dbhost,{user},{host},{conn},{qid},READ,{db},{table},"


def test_read_line_parses():
    r = parse_line(read_line("api_credentials"))
    assert (r.operation, r.database, r.query, r.truncated) == ("READ", DB, "api_credentials", False)


def test_server_table_reclassifies_dynamic_sql(tmp_path):
    b = builder(tmp_path)
    b.build(parse_line(read_line("api_credentials")))
    event, _, _ = b.build(parse_line(line("EXECUTE IMMEDIATE @q")))
    assert event["action"] == "sensitive_access" and event["table_names"] == ["api_credentials"]
    assert "db:server_resolved_tables" in event["tags"]


def test_server_table_counts_toward_adaptive_rules(tmp_path):
    b = builder(tmp_path)
    b.build(parse_line(read_line("api_credentials")))
    b.build(parse_line(line("EXECUTE IMMEDIATE @q")))
    assert b.state.tracker("decoy_user@172.28.0.51").table_hits == {"api_credentials": 1}


def test_table_line_for_another_query_id_is_not_applied(tmp_path):
    b = builder(tmp_path)
    b.build(parse_line(read_line("api_credentials", qid=99)))
    event, _, _ = b.build(parse_line(line("SELECT 1", qid=100)))
    assert event["table_names"] == [] and event["action"] == "client_noise"


def test_optimizer_statistics_are_ignored(tmp_path):
    b = builder(tmp_path)
    b.build(parse_line(read_line("routes")))
    b.build(parse_line(read_line("table_stats", db="mysql")))
    event, _, _ = b.build(parse_line(line("SELECT * FROM routes LIMIT 1")))
    assert event["table_names"] == ["routes"]


def test_forged_read_line_without_a_login_counts_for_nothing(tmp_path):
    b = builder(tmp_path)
    event, _, _ = b.build(parse_line(read_line("api_credentials", conn=555, host="9.9.9.9")))
    assert event is None and b.opened == {}


def test_handler_alias_is_replaced_by_the_real_table(tmp_path):
    b = builder(tmp_path)
    b.build(parse_line(read_line("api_credentials")))
    event, _, _ = b.build(parse_line(line("HANDLER h READ FIRST")))
    assert event["table_names"] == ["api_credentials"] and event["action"] == "sensitive_access"


# ---- found on the first real container run ----------------------------------------------
def test_decoy_user_on_the_local_socket_is_not_internal(tmp_path):
    b = builder(tmp_path)
    assert not b.is_internal(parse_line(line("SELECT COUNT(*) FROM shipments", host="localhost")))


def test_listed_socket_accounts_are_internal_and_others_are_not(tmp_path):
    b = EventBuilder(Settings(data_dir=str(tmp_path), internal_accounts=frozenset(
        {("healthcheck", "localhost"), ("root", "localhost"), ("boot", "")})), RULES, SensorState(str(tmp_path)))
    assert b.is_internal(parse_line(line(user="healthcheck", host="localhost")))
    assert b.is_internal(parse_line(line(user="root", host="localhost")))
    assert not b.is_internal(parse_line(line(user="someone", host="localhost")))


def test_real_bootstrap_line_parses_as_internal_account(tmp_path):
    rec = parse_line("20261031 17:07:09,0c22e0e8c0a8,boot,,3,1,QUERY,mysql,'CREATE OR REPLACE VIEW x',0")
    assert (rec.user, rec.host) == ("boot", "")
    b = EventBuilder(Settings(data_dir=str(tmp_path), internal_accounts=frozenset({("boot", "")})), RULES,
                     SensorState(str(tmp_path)))
    assert b.is_internal(rec)


def test_compose_lists_every_internal_account_and_never_the_decoy():
    compose = (Path(__file__).resolve().parents[3] / "docker-compose.yml").read_text(encoding="utf-8")
    value = next(ln.split(":", 1)[1].strip() for ln in compose.splitlines() if ln.strip().startswith("INTERNAL_ACCOUNTS:"))
    accounts = set(value.split(","))
    assert {"deception_ctrl@172.29.0.21", "root@localhost", "healthcheck@localhost", "boot@"} <= accounts
    assert not [a for a in accounts if a.startswith("decoy_user")]


@pytest.mark.parametrize("sql", ["SELECT ',1,2,READ,x,y' FROM api_credentials", "SELECT ',9,9,QUERY,d,z' FROM api_credentials",
                                 "SELECT ',1,0,CONNECT,,,0' FROM api_credentials", "SELECT 'a,b,c,1,2,DROP,x,y'"])
def test_query_text_cannot_rewrite_the_line_it_is_on(sql):
    r = parse_line(line(sql, conn=7, qid=100))
    assert (r.user, r.host, r.connection_id, r.query_id, r.operation) == ("decoy_user", "172.28.0.51", 7, 100, "QUERY")
    assert r.query == sql and r.retcode == 0 and not r.truncated


def test_spoof_literal_still_counts_as_a_sensitive_read(tmp_path):
    event, _, _ = builder(tmp_path).build(parse_line(line("SELECT ',1,2,READ,x,y' FROM api_credentials")))
    assert event["action"] == "sensitive_access" and event["username"] == "decoy_user"


def test_comma_username_on_a_login_line_still_parses_from_the_right():
    r = parse_line("20261031 14:54:45,h,a,1.1.1.1,5,5,QUERY,d,'x',0,172.28.0.51,8,0,FAILED_CONNECT,,,1045")
    assert r.operation == "FAILED_CONNECT" and r.host == "172.28.0.51" and r.connection_id == 8
