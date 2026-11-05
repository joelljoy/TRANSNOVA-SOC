"""Live end-to-end tests: a real MySQL client → real MariaDB → audit log → sensor → collector.

Nothing is mocked and no event is injected. Run services/database/scripts/run_live_tests.ps1,
which starts a clean native lab and sets the environment this file needs:

    LIVE_MYSQL_CLIENT   path to mysql.exe / mariadb.exe
    LIVE_AUDIT_LOG      path to server_audit.log
    DECOY_DB_PASSWORD, CONTROLLER_DB_PASSWORD

The attacker binds to 127.0.0.2, so its source address really differs from the sensor's.
Numbering follows the module test plan (Tests 1 to 8).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pymysql
import pytest

CLIENT = os.environ.get("LIVE_MYSQL_CLIENT")
pytestmark = pytest.mark.skipif(not CLIENT, reason="live lab not configured; use scripts/run_live_tests.ps1")

ROOT = Path(__file__).resolve().parents[4]
HOST, PORT = "127.0.0.1", 3307
API_PORT = 8011
API = f"http://127.0.0.1:{API_PORT}"
ATTACKER_IP = "127.0.0.2"
SECOND_IP = "127.0.0.3"
DECOY_PW = os.environ.get("DECOY_DB_PASSWORD", "")
DB = "transnova_logistics"


def attacker(sql: str, ip: str = ATTACKER_IP, password: str | None = None, user: str = "decoy_user",
             database: str | None = DB) -> subprocess.CompletedProcess:
    """One genuine client process per call, as a human at a terminal would use it."""
    args = [CLIENT, f"--host={HOST}", f"--port={PORT}", f"--bind-address={ip}", f"--user={user}",
            f"--password={DECOY_PW if password is None else password}", "--batch", "--force",
            "--skip-auto-rehash", "-e", sql]
    if database:
        args.append(database)
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


def api(path: str, **params):
    return httpx.get(f"{API}{path}", params=params, timeout=5, trust_env=False).json()


def wait_for(predicate, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    return predicate()


def db_events(**params):
    return api("/api/events", service="database", limit=1000, **params)


def find_event(fragment: str, timeout=10.0):
    return wait_for(lambda: next((e for e in db_events() if fragment in (e["command"] or "")), None), timeout)


def root_conn():
    return pymysql.connect(host=HOST, port=PORT, user="root", password=os.environ.get("NATIVE_ROOT_PASSWORD", "native-lab-root"),
                           database=DB, autocommit=True)


@pytest.fixture(scope="module", autouse=True)
def stack():
    work = tempfile.mkdtemp(prefix="dbhp-live-")
    env = {**os.environ, "COLLECTOR_DB_PATH": f"{work}/collector.db", "PYTHONPATH": str(ROOT)}
    collector = subprocess.Popen([sys.executable, "-m", "uvicorn", "collector.app:app", "--port", str(API_PORT),
                                  "--log-level", "warning"], cwd=ROOT, env=env)
    wait_for(lambda: _healthy(), 15)
    sensor_env = {
        **os.environ, "PYTHONPATH": str(ROOT / "services/database/sensor"), "AUDIT_LOG_PATH": os.environ["LIVE_AUDIT_LOG"],
        "SENSOR_DATA_DIR": f"{work}/sensor", "COLLECTOR_BASE_URL": API, "DB_HOST": HOST, "DB_PORT": str(PORT),
        "POLL_INTERVAL_S": "0.2", "INTERNAL_ACCOUNTS": "deception_ctrl@127.0.0.1,root@127.0.0.1",
    }
    sensor = subprocess.Popen([sys.executable, "-m", "db_sensor.main"], cwd=ROOT, env=sensor_env)
    state = {"work": work, "sensor": sensor, "sensor_env": sensor_env}
    yield state
    state["sensor"].terminate()  # read from the dict: the restart test replaces this process
    collector.terminate()


def _healthy() -> bool:
    try:
        return httpx.get(f"{API}/health", timeout=1, trust_env=False).status_code == 200
    except httpx.HTTPError:
        return False


# ---- Test 1: startup -----------------------------------------------------------------
def test_1_database_exists_with_all_tables():
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT VERSION()")
        assert "MariaDB" in cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s", (DB,))
        assert cur.fetchone()[0] == 31
        cur.execute("SELECT plugin_status FROM information_schema.plugins WHERE plugin_name='SERVER_AUDIT'")
        assert cur.fetchone()[0] == "ACTIVE"


# ---- Test 2: synthetic data ----------------------------------------------------------
@pytest.mark.parametrize("table,low,high", [
    ("customers", 100, 200), ("shipments", 250, 500), ("employees", 30, 50), ("delivery_agents", 15, 30),
    ("vehicles", 10, 20), ("warehouses", 5, 10)])
def test_2_record_counts(table, low, high):
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        assert low <= cur.fetchone()[0] <= high


def test_2_multiple_children_per_shipment():
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT AVG(n) FROM (SELECT COUNT(*) n FROM shipment_items GROUP BY shipment_id) x")
        assert cur.fetchone()[0] > 1
        cur.execute("SELECT AVG(n) FROM (SELECT COUNT(*) n FROM tracking_events GROUP BY shipment_id) x")
        assert cur.fetchone()[0] > 1


def test_2_no_orphans_and_joins_work():
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute("""SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
                       FROM information_schema.KEY_COLUMN_USAGE
                       WHERE TABLE_SCHEMA=%s AND REFERENCED_TABLE_NAME IS NOT NULL""", (DB,))
        foreign_keys = cur.fetchall()
        assert len(foreign_keys) > 30
        for table, col, ref, ref_col in foreign_keys:
            cur.execute(f"SELECT COUNT(*) FROM `{table}` c LEFT JOIN `{ref}` p ON c.`{col}`=p.`{ref_col}` "
                        f"WHERE c.`{col}` IS NOT NULL AND p.`{ref_col}` IS NULL")
            assert cur.fetchone()[0] == 0, f"orphans in {table}.{col}"
        cur.execute("""SELECT c.company_name, s.tracking_no, i.invoice_no, p.reference FROM customers c
                       JOIN shipments s USING (customer_id) JOIN invoices i USING (shipment_id)
                       JOIN payments p USING (invoice_id) LIMIT 5""")
        assert len(cur.fetchall()) == 5


def test_2_seed_is_reproducible(tmp_path):
    out = tmp_path / "seed.sql"
    subprocess.run([sys.executable, str(ROOT / "services/database/seed/generate_seed.py"), "--out", str(out)],
                   check=True, capture_output=True)
    assert out.read_bytes() == (ROOT / "services/database/initdb/02_seed.sql").read_bytes()


# ---- Isolation of the hidden tables, before any reveal --------------------------------
def test_adaptive_tables_are_hidden_from_metadata_before_reveal():
    tables = attacker("SHOW TABLES").stdout
    assert "api_credentials" in tables and "backup_credentials" not in tables
    meta = attacker("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='transnova_logistics'").stdout
    assert "\n23" in meta
    hidden = attacker("SELECT COUNT(*) FROM information_schema.columns WHERE table_name='backup_credentials'").stdout
    assert "\n0" in hidden


def test_denial_does_not_reveal_whether_a_table_exists():
    real = attacker("SELECT * FROM backup_credentials").stderr
    fake = attacker("SELECT * FROM no_such_table_xyz").stderr
    assert "1142" in real and "1142" in fake


# ---- Test 3: attacker connection and genuine capture ----------------------------------
def test_3_real_client_queries_are_captured():
    assert "transnova_logistics" in attacker("SHOW DATABASES;", database=None).stdout
    attacker("SHOW TABLES;")
    assert "tracking_no" in attacker("SELECT * FROM shipments LIMIT 10;").stdout
    assert "tracking_event_id" in attacker("SELECT * FROM tracking_events LIMIT 10;").stdout
    for fragment in ("SHOW DATABASES", "SHOW TABLES", "SELECT * FROM shipments LIMIT 10", "SELECT * FROM tracking_events LIMIT 10"):
        event = find_event(fragment)
        assert event, fragment
        assert event["source_ip"] == ATTACKER_IP and event["username"] == "decoy_user"
        assert event["outcome"] == "succeeded" and event["session_id"]
        assert fragment in event["raw_evidence_redacted"]["raw_event"]  # the audit line itself


def test_3_connection_events_and_failed_login():
    attacker("SELECT 1", password="wrong-password")
    failed = wait_for(lambda: [e for e in db_events() if e["action"] == "db_login" and e["outcome"] == "failed"])
    assert failed and failed[0]["username"] == "decoy_user" and failed[0]["source_ip"] == ATTACKER_IP
    assert wait_for(lambda: [e for e in db_events() if e["action"] == "db_login" and e["outcome"] == "succeeded"])
    assert wait_for(lambda: [e for e in db_events() if e["action"] == "db_disconnect"])


# ---- Test 4: restricted operations ----------------------------------------------------
@pytest.mark.parametrize("sql,category", [
    ("CREATE TABLE unauthorized_test (id INT)", "schema_change_attempt"),
    ("INSERT INTO customers (account_no) VALUES ('X')", "modification_attempt"),
    ("UPDATE shipments SET status='Delivered' WHERE shipment_id=1", "modification_attempt"),
    ("DELETE FROM shipments WHERE shipment_id=-1", "modification_attempt"),
    ("DROP TABLE unauthorized_test", "schema_change_attempt"),
    ("ALTER TABLE shipments ADD COLUMN x INT", "schema_change_attempt"),
    ("GRANT ALL ON *.* TO 'decoy_user'@'%'", "privilege_attempt"),
    ("CREATE USER 'pwn'@'%' IDENTIFIED BY 'x'", "privilege_attempt"),
])
def test_4_writes_are_denied_and_reported_as_blocked(sql, category):
    result = attacker(sql)
    assert "ERROR" in result.stderr
    event = find_event(sql[:30])
    assert event["action"] == category and event["outcome"] == "blocked"
    assert event["raw_evidence_redacted"]["server_retcode"] != 0


def test_4_no_write_privilege_and_data_unchanged():
    grants = attacker("SHOW GRANTS").stdout.upper()
    for bad in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", " CREATE", "SUPER", " FILE", "ALL PRIVILEGES", "GRANT OPTION"):
        assert bad not in grants, bad
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_name='unauthorized_test'")
        assert cur.fetchone()[0] == 0


def test_4_no_server_file_or_os_access():
    assert "NULL" in attacker("SELECT LOAD_FILE('C:/Windows/win.ini')").stdout
    assert "ERROR" in attacker("SELECT 1 INTO OUTFILE 'x.txt'").stderr
    assert "ERROR" in attacker("SELECT user FROM mysql.user").stderr


# ---- Test 5 and Test 8: sensitive access, risk and MITRE ------------------------------
def test_5_sensitive_read_is_classified_with_reasons():
    assert "tnk_TEST_" in attacker("SELECT * FROM api_credentials LIMIT 3").stdout
    event = find_event("FROM api_credentials LIMIT 3")
    ev = event["raw_evidence_redacted"]
    assert event["action"] == "sensitive_access" and ev["severity"] in ("HIGH", "CRITICAL")
    assert ev["risk_reasons"] and ev["mitre"][0]["technique"] == "T1552"
    assert wait_for(lambda: [a for a in api("/api/alerts") if a["rule"] == "D-SENS-01"])


def test_8_routine_select_has_no_mitre_and_low_severity():
    ev = find_event("SELECT * FROM shipments LIMIT 10")["raw_evidence_redacted"]
    assert ev["severity"] == "LOW" and ev["mitre"] == [] and ev["detections"] == []


def test_8_recon_categorised_and_denied_is_attempted():
    assert find_event("SHOW TABLES")["action"] == "reconnaissance"
    ev = find_event("SELECT user FROM mysql.user")["raw_evidence_redacted"]
    assert ev["mitre"][0]["status"] == "attempted"


def test_8_controller_and_root_activity_never_reach_the_soc():
    attacker("SHOW TABLES")
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT 'root-marker-should-not-appear'")
    time.sleep(1.5)
    events = db_events()
    assert not [e for e in events if e["username"] in ("root", "deception_ctrl")]
    assert not [e for e in events if "root-marker" in (e["command"] or "")]


# ---- Test 6: adaptive deception -------------------------------------------------------
def revealed():
    return {r["asset_revealed"]: r for r in api("/api/adaptations") if r["status"] == "applied"}


def test_6a_shipment_exploration_reveals_archive_and_premium():
    assert "ERROR" in attacker("SELECT * FROM shipment_archive LIMIT 1").stderr  # not yet
    attacker("SELECT c.company_name, s.tracking_no FROM shipments s JOIN customers c USING (customer_id) LIMIT 5")
    attacker("SELECT * FROM shipment_items LIMIT 5")
    got = wait_for(lambda: {"shipment_archive", "premium_customer_records"} <= set(revealed()) and revealed())
    assert got, api("/api/adaptations")
    record = got["shipment_archive"]
    assert record["rule_id"] == "A-SHIPMENT-EXPLORATION" and record["privilege_before"] is False
    assert record["privilege_after"] is True and record["trigger_event_id"]
    assert "GRANT SELECT" in record["statement"]

    tables = attacker("SHOW TABLES").stdout
    assert "shipment_archive" in tables and "premium_customer_records" in tables
    assert "backup_credentials" not in tables
    assert "archive/2026" in attacker("SELECT * FROM shipment_archive LIMIT 3").stdout
    event = find_event("FROM shipment_archive LIMIT 3")
    assert event["action"] == "adaptive_decoy_access" and event["outcome"] == "succeeded"
    follow = wait_for(lambda: next(r for r in api("/api/adaptations") if r["asset_revealed"] == "shipment_archive")["followup_event_ids"])
    assert event["event_id"] in follow


def test_6b_credential_exploration_reveals_backup_credentials():
    attacker("SELECT * FROM api_integrations LIMIT 3")
    attacker("SELECT username, role FROM admin_accounts LIMIT 3")
    assert wait_for(lambda: "backup_credentials" in revealed())
    assert revealed()["backup_credentials"]["rule_id"] == "B-CREDENTIAL-EXPLORATION"
    assert "TEST-only-" in attacker("SELECT * FROM backup_credentials LIMIT 2").stdout
    assert find_event("FROM backup_credentials LIMIT 2")["raw_evidence_redacted"]["severity"] == "CRITICAL"


def test_6c_infrastructure_exploration_reveals_security_logs():
    attacker("SELECT * FROM warehouse_access LIMIT 3")
    attacker("SELECT * FROM internal_network_assets LIMIT 3")
    assert wait_for(lambda: {"warehouse_security_logs", "internal_transfer_records"} <= set(revealed()))


def test_6d_sustained_interest_reveals_stage_two():
    attacker("SELECT * FROM partner_contracts LIMIT 3")
    assert wait_for(lambda: {"executive_shipments", "restricted_routes", "disaster_recovery_backup"} <= set(revealed()))
    assert revealed()["executive_shipments"]["stage"] == 2
    assert attacker("SELECT * FROM executive_shipments LIMIT 1").returncode == 0


def test_6e_reveal_stays_read_only_and_writes_still_denied():
    assert "ERROR" in attacker("UPDATE backup_credentials SET account='x'").stderr
    assert "ERROR" in attacker("DROP TABLE backup_credentials").stderr


def test_6f_no_duplicate_grant_on_repeated_triggers():
    before = len(api("/api/adaptations"))
    for _ in range(3):
        attacker("SELECT * FROM shipments LIMIT 1")
    time.sleep(1.5)
    assert len(api("/api/adaptations")) == before


def test_6g_every_grant_has_an_audit_record_and_controller_is_limited():
    records = [r for r in api("/api/adaptations") if r["status"] == "applied"]
    assert len({r["asset_revealed"] for r in records}) == 8
    with root_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM mysql.tables_priv WHERE User='decoy_user'")
        assert cur.fetchone()[0] == 31
    ctrl = pymysql.connect(host=HOST, port=PORT, user="deception_ctrl", password=os.environ["CONTROLLER_DB_PASSWORD"],
                           database=DB, autocommit=True)
    with ctrl, ctrl.cursor() as cur:
        cur.execute("SHOW GRANTS")
        grants = " ".join(r[0] for r in cur.fetchall())
        assert "ALL PRIVILEGES" not in grants and "SUPER" not in grants
        for sql in ("SELECT * FROM api_credentials", "DROP TABLE shipment_archive", "CREATE USER 'z'@'%'",
                    "GRANT SELECT ON transnova_logistics.api_credentials TO 'decoy_user'@'%'"):
            with pytest.raises(pymysql.MySQLError):
                cur.execute(sql)


# ---- Test 7: SOC integration ----------------------------------------------------------
def test_7_collector_views_show_real_data():
    summary = api("/api/database/summary")
    assert summary["queries_captured"] > 20 and summary["denied_statements"] >= 8
    assert summary["sensitive_access"] > 0 and dict(summary["top_tables"])
    assert any("T1552" in row[0] for row in summary["mitre"])
    source = next(s for s in api("/api/attackers") if s["source_ip"] == ATTACKER_IP)
    assert source["alert_count"] > 0 and source["services"] == ["database"]
    assert any(a["severity"] == "critical" for a in api("/api/alerts"))


def test_7_sensor_heartbeat_reports_sessions():
    def beat():
        return next((s for s in api("/api/sensors") if s["sensor_id"] == "db-01"), None)
    sensor = wait_for(lambda: beat() and beat()["details"]["sessions"], 20) and beat()
    assert sensor["details"]["database_reachable"] is True
    assert sensor["details"]["internal_ignored"] > 0
    assert any(s["risk_score"] > 0 for s in sensor["details"]["sessions"])


def test_7_restart_does_not_duplicate_and_catches_up(stack):
    stack["sensor"].terminate()
    stack["sensor"].wait(timeout=10)
    count = len(db_events())
    attacker("SELECT * FROM routes LIMIT 1 -- while sensor is down")
    stack["sensor"] = subprocess.Popen([sys.executable, "-m", "db_sensor.main"], cwd=ROOT, env=stack["sensor_env"])
    assert wait_for(lambda: find_event("FROM routes LIMIT 1", 1), 10)
    time.sleep(1)
    ids = [e["event_id"] for e in db_events()]
    assert len(ids) == len(set(ids)) and len(ids) > count


def test_7_brute_force_detected_from_a_second_source():
    for i in range(6):
        attacker("SELECT 1", ip=SECOND_IP, password=f"guess{i}")
    alert = wait_for(lambda: [a for a in api("/api/alerts") if a["rule"] == "D-AUTH-01" and a["source_ip"] == SECOND_IP])
    assert alert and "T1110.001" in alert[0]["attack_ids"]


def test_padding_cannot_push_a_table_out_of_the_log():
    # Quotes double in length when escaped, which is the worst case for the audit limit.
    filler = "''" * 25000
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB,
                           bind_address=ATTACKER_IP)
    with conn, conn.cursor() as cur:
        cur.execute(f"SELECT '{filler}' AS pad, api_key FROM /*padded*/ api_credentials LIMIT 1")
    event = wait_for(lambda: next((e for e in db_events() if "db:command_bounded" in e["tags"]), None))
    assert event and event["table_names"] == ["api_credentials"] and event["action"] == "sensitive_access"
    assert "db:truncated" not in event["tags"]


def test_statement_over_the_packet_limit_is_refused():
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB,
                           bind_address=ATTACKER_IP)
    with pytest.raises(pymysql.MySQLError):
        with conn, conn.cursor() as cur:
            cur.execute(f"SELECT '{'x' * 70000}' FROM api_credentials")


def test_forged_audit_line_via_username_newline_is_not_believed():
    forged = "x\n20261031 15:00:00,h,decoy_user,9.9.9.9,1,1,QUERY,d,'SELECT * FROM api_credentials',0\ny"
    with pytest.raises(pymysql.MySQLError):
        pymysql.connect(host=HOST, port=PORT, user=forged, password="nope", connect_timeout=3,
                        bind_address=ATTACKER_IP)
    alert = wait_for(lambda: [a for a in api("/api/alerts") if a["rule"] == "D-INJ-01"])
    assert alert and alert[0]["source_ip"] == ATTACKER_IP
    assert not [e for e in db_events() if e["source_ip"] == "9.9.9.9"]


def test_valid_looking_forged_query_is_flagged_and_changes_nothing():
    # This shape leaves no broken fragment: both physical lines parse on their own.
    head = "x,9.9.9.9,5555,1,QUERY,d,'SELECT * FROM api_credentials',0\n20261031 15:00:00,h,z"
    with pytest.raises(pymysql.MySQLError):
        pymysql.connect(host=HOST, port=PORT, user=head, password="nope", connect_timeout=3, bind_address=ATTACKER_IP)
    alert = wait_for(lambda: [a for a in api("/api/alerts") if a["rule"] == "D-INJ-02"])
    assert alert
    assert not [e for e in db_events() if e["source_ip"] == "9.9.9.9"]


def test_malicious_usernames_do_not_break_the_pipeline():
    attacker("SELECT 1", user="a,b,c',0", password="x", database=None)
    assert wait_for(lambda: [e for e in db_events() if e["username"] and e["username"].startswith("a,b,c")])
    assert "unparsed" not in " ".join(e["action"] for e in db_events())
