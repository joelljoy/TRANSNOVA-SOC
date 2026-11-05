"""Database honeypot readiness audit: the 20 checks, against a real server.

Nothing is mocked or injected. Results are checked against MariaDB's own logs and grant tables
rather than against the sensor's opinion of itself: every statement in the raw audit log must
become exactly one SOC event, and GRANTs in the log must match the adaptive records.

Tests run in file order on purpose: a reveal cannot be undone mid-run, so restricted-state
checks come first and hostile reads come last.

    .\\services\\database\\scripts\\run_live_tests.ps1 -MariaDbHome ... -WorkDir ... -Suite audit
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pymysql
import pytest
from pymysql.constants import CLIENT

CLIENT_BIN = os.environ.get("LIVE_MYSQL_CLIENT")
pytestmark = pytest.mark.skipif(not CLIENT_BIN, reason="use scripts/run_live_tests.ps1 -Suite audit")

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT), str(ROOT / "services/database/sensor")]
HOST, PORT, API_PORT = "127.0.0.1", 3307, 8012
API = f"http://127.0.0.1:{API_PORT}"
ATTACKER, OTHER, HOSTILE = "127.0.0.2", "127.0.0.3", "127.0.0.4"
DB = "transnova_logistics"
DECOY_PW = os.environ.get("DECOY_DB_PASSWORD", "")
CTRL_PW = os.environ.get("CONTROLLER_DB_PASSWORD", "")
ROOT_PW = os.environ.get("NATIVE_ROOT_PASSWORD", "native-lab-root")
AUDIT_LOG = Path(os.environ.get("LIVE_AUDIT_LOG", "."))

VISIBLE = {"customers", "shipments", "shipment_items", "tracking_events", "delivery_addresses", "invoices", "payments",
           "employees", "delivery_agents", "vehicles", "warehouses", "inventory", "routes", "dispatch_records",
           "maintenance_records", "shipping_partners", "support_tickets", "api_integrations", "api_credentials",
           "admin_accounts", "warehouse_access", "partner_contracts", "internal_network_assets"}
HIDDEN = {"shipment_archive", "premium_customer_records", "restricted_routes", "backup_credentials",
          "warehouse_security_logs", "internal_transfer_records", "executive_shipments", "disaster_recovery_backup"}


def sh(sql, ip=ATTACKER, user="decoy_user", password=None, database=DB):
    args = [CLIENT_BIN, f"--host={HOST}", f"--port={PORT}", f"--bind-address={ip}", f"--user={user}",
            f"--password={DECOY_PW if password is None else password}", "--batch", "--force", "--skip-auto-rehash",
            "--comments", "-e", sql]  # without --comments the client strips them before sending
    if database:
        args.append(database)
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


def root_sql(sql, params=None):
    conn = pymysql.connect(host=HOST, port=PORT, user="root", password=ROOT_PW, database=DB, autocommit=True)
    with conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def api(path, **params):
    return httpx.get(f"{API}{path}", params=params, timeout=5, trust_env=False).json()


def all_events():
    out, offset = [], 0
    while True:
        page = api("/api/events", service="database", limit=1000, offset=offset)
        out += page
        if len(page) < 1000:
            return out
        offset += 1000


def wait_for(predicate, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    return predicate()


def event_with(fragment, timeout=10.0):
    return wait_for(lambda: next((e for e in all_events() if fragment in (e["command"] or "")), None), timeout)


def settle():
    """Wait until everything MariaDB has logged so far has been processed."""
    target = len(raw_statements())
    wait_for(lambda: len([e for e in all_events() if e["event_type"] == "sql_query"]) >= target, 12)
    time.sleep(0.5)


def log_files():
    return [p for p in (AUDIT_LOG.with_name(AUDIT_LOG.name + ".1"), AUDIT_LOG) if p.exists()]


def raw_lines():
    return [ln for p in log_files() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()]


def raw_statements(user="decoy_user"):
    """Independent of the sensor: a plain regex over MariaDB's own file."""
    pattern = re.compile(rf"^\d{{8}} \d\d:\d\d:\d\d,[^,]*,{user},[\d.]+,\d+,\d+,QUERY,")
    return [ln for ln in raw_lines() if pattern.match(ln)]


def revealed():
    return {r["asset_revealed"]: r for r in api("/api/adaptations") if r["status"] == "applied"}


def granted():
    rows = root_sql("SELECT Table_name, Table_priv FROM mysql.tables_priv WHERE User='decoy_user' AND Db=%s", (DB,))
    return {name: str(priv) for name, priv in rows}


def start_collector(work):
    env = {**os.environ, "COLLECTOR_DB_PATH": f"{work}/collector.db", "PYTHONPATH": str(ROOT)}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "collector.app:app", "--port", str(API_PORT),
                             "--log-level", "warning"], cwd=ROOT, env=env)
    wait_for(healthy, 15)
    return proc


def healthy():
    try:
        return httpx.get(f"{API}/health", timeout=1, trust_env=False).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="module", autouse=True)
def stack():
    work = tempfile.mkdtemp(prefix="dbhp-audit-")
    state = {"work": work, "collector": start_collector(work)}
    state["sensor_env"] = {
        **os.environ, "PYTHONPATH": str(ROOT / "services/database/sensor"), "AUDIT_LOG_PATH": str(AUDIT_LOG),
        "SENSOR_DATA_DIR": f"{work}/sensor", "COLLECTOR_BASE_URL": API, "DB_HOST": HOST, "DB_PORT": str(PORT),
        "POLL_INTERVAL_S": "0.2", "INTERNAL_ACCOUNTS": "deception_ctrl@127.0.0.1,root@127.0.0.1",
    }
    state["sensor"] = subprocess.Popen([sys.executable, "-m", "db_sensor.main"], cwd=ROOT, env=state["sensor_env"])
    yield state
    state["sensor"].terminate()
    state["collector"].terminate()


# ---- 1. server start ----------------------------------------------------------------
def test_01_server_runs_with_the_honeypot_configuration():
    assert "MariaDB" in root_sql("SELECT VERSION()")[0][0]
    assert root_sql("SELECT plugin_status FROM information_schema.plugins WHERE plugin_name='SERVER_AUDIT'")[0][0] == "ACTIVE"
    expected = {"local_infile": "OFF", "skip_name_resolve": "ON", "general_log": "ON", "max_allowed_packet": "65536",
                "server_audit_logging": "ON", "server_audit_events": "CONNECT,QUERY,TABLE",
                "server_audit_query_log_limit": "131072"}
    for name, value in expected.items():
        assert root_sql("SELECT @@" + name)[0][0] in (value, 1 if value == "ON" else 0 if value == "OFF" else int(value) if value.isdigit() else value), name


# ---- 2. tables ----------------------------------------------------------------------
def test_02_exactly_the_31_expected_tables_exist():
    rows = root_sql("SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (DB,))
    assert {r[0] for r in rows} == VISIBLE | HIDDEN
    assert len(VISIBLE) == 23 and len(HIDDEN) == 8


# ---- 3. data ------------------------------------------------------------------------
def test_03_every_table_has_data_and_counts_are_in_range():
    for table in VISIBLE | HIDDEN:
        assert root_sql(f"SELECT COUNT(*) FROM `{table}`")[0][0] > 0, table
    for table, low, high in (("customers", 100, 200), ("shipments", 250, 500), ("employees", 30, 50),
                             ("delivery_agents", 15, 30), ("vehicles", 10, 20), ("warehouses", 5, 10)):
        assert low <= root_sql(f"SELECT COUNT(*) FROM {table}")[0][0] <= high, table


def test_03_no_foreign_key_has_an_orphan():
    fks = root_sql("""SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
                      FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=%s AND REFERENCED_TABLE_NAME IS NOT NULL""", (DB,))
    assert len(fks) >= 30
    for table, col, ref, ref_col in fks:
        n = root_sql(f"SELECT COUNT(*) FROM `{table}` c LEFT JOIN `{ref}` p ON c.`{col}`=p.`{ref_col}` "
                     f"WHERE c.`{col}` IS NOT NULL AND p.`{ref_col}` IS NULL")[0][0]
        assert n == 0, f"{table}.{col}"


@pytest.mark.parametrize("name,sql", [
    ("address belongs to shipment's customer", "SELECT COUNT(*) FROM shipments s JOIN delivery_addresses a USING (address_id) WHERE a.customer_id<>s.customer_id"),
    ("invoice customer matches shipment", "SELECT COUNT(*) FROM invoices i JOIN shipments s USING (shipment_id) WHERE i.customer_id<>s.customer_id"),
    ("only delivered shipments have delivered_at", "SELECT COUNT(*) FROM shipments WHERE (status='Delivered')<>(delivered_at IS NOT NULL)"),
    ("every delivery agent is a Fleet employee", "SELECT COUNT(*) FROM delivery_agents d JOIN employees e USING (employee_id) WHERE e.department<>'Fleet'"),
    ("payments only exist for paid invoices", "SELECT COUNT(*) FROM payments p JOIN invoices i USING (invoice_id) WHERE i.status<>'Paid'"),
    ("every paid invoice has a payment", "SELECT COUNT(*) FROM invoices i LEFT JOIN payments p USING (invoice_id) WHERE i.status='Paid' AND p.payment_id IS NULL"),
    ("payment equals invoice amount", "SELECT COUNT(*) FROM payments p JOIN invoices i USING (invoice_id) WHERE p.amount_inr<>i.amount_inr"),
    ("tracking events follow creation", "SELECT COUNT(*) FROM tracking_events t JOIN shipments s USING (shipment_id) WHERE t.event_time<s.created_at"),
    ("archive repeats the real tracking number", "SELECT COUNT(*) FROM shipment_archive a JOIN shipments s USING (shipment_id) WHERE a.tracking_no<>s.tracking_no"),
    ("archive holds delivered shipments only", "SELECT COUNT(*) FROM shipment_archive a JOIN shipments s USING (shipment_id) WHERE s.status<>'Delivered'"),
    ("premium records are Premium customers", "SELECT COUNT(*) FROM premium_customer_records p JOIN customers c USING (customer_id) WHERE c.tier<>'Premium'"),
])
def test_03_business_rules_hold(name, sql):
    assert root_sql(sql)[0][0] == 0, name


def test_03_all_six_business_statuses_exist():
    statuses = {r[0] for r in root_sql("SELECT DISTINCT status FROM shipments")}
    assert statuses == {"Pending", "In Transit", "Delivered", "Delayed", "Failed Delivery", "Under Investigation"}


def test_03_decoy_secrets_are_marked_fake_by_construction():
    assert root_sql("SELECT COUNT(*) FROM api_credentials WHERE api_key NOT LIKE 'tnk\\_TEST\\_%'")[0][0] == 0
    assert root_sql("SELECT COUNT(*) FROM backup_credentials WHERE secret_value NOT LIKE 'TEST-only-%'")[0][0] == 0
    assert root_sql("SELECT COUNT(*) FROM employees WHERE email NOT LIKE '%.example'")[0][0] == 0
    assert root_sql("SELECT COUNT(*) FROM internal_network_assets WHERE ip_address NOT LIKE '198.18.%'")[0][0] == 0


# ---- 4. decoy login -----------------------------------------------------------------
def test_04_decoy_user_connects_with_a_genuine_client():
    result = sh("SELECT CURRENT_USER(), DATABASE()")
    assert result.returncode == 0 and "decoy_user@%" in result.stdout and DB in result.stdout


# ---- 5. attacker privileges ---------------------------------------------------------
def test_05_grants_are_exactly_select_on_the_23_visible_tables():
    grants = granted()
    assert set(grants) == VISIBLE and set(grants.values()) == {"Select"}
    assert root_sql("SELECT COUNT(*) FROM mysql.db WHERE User='decoy_user'")[0][0] == 0
    assert root_sql("SELECT COUNT(*) FROM mysql.columns_priv WHERE User='decoy_user'")[0][0] == 0
    assert root_sql("SELECT COUNT(*) FROM mysql.procs_priv WHERE User='decoy_user'")[0][0] == 0
    assert root_sql("SELECT COUNT(*) FROM mysql.roles_mapping WHERE User='decoy_user'")[0][0] == 0
    doc = json.loads(root_sql("SELECT Priv FROM mysql.global_priv WHERE User='decoy_user'")[0][0])
    assert doc["access"] == 0  # no global privilege of any kind
    assert doc["max_user_connections"] == 10 and float(doc["max_statement_time"]) == 5


@pytest.mark.parametrize("sql", [
    "INSERT INTO customers (account_no) VALUES ('AUDIT')", "UPDATE shipments SET weight_kg=1", "DELETE FROM shipments",
    "DROP TABLE shipments", "TRUNCATE TABLE shipments", "ALTER TABLE shipments ADD c INT", "CREATE TABLE audit_x (i INT)",
    "CREATE VIEW audit_v AS SELECT 1", "CREATE DATABASE audit_db", "CREATE USER 'audit'@'%'", "GRANT SELECT ON *.* TO 'decoy_user'@'%'",
    "SET GLOBAL general_log=0", "SET GLOBAL server_audit_logging=0", "SHUTDOWN", "KILL 1", "SELECT 1 INTO OUTFILE 'a.txt'",
    "CREATE PROCEDURE audit_p() SELECT 1", "CREATE FUNCTION sys_exec RETURNS INT SONAME 'x.dll'", "INSTALL SONAME 'server_audit'",
    "UNINSTALL PLUGIN server_audit",
])
def test_05_write_admin_and_os_paths_are_refused(sql):
    assert "ERROR" in sh(sql).stderr


def test_05_logging_was_not_disabled_and_data_is_unchanged():
    assert root_sql("SELECT @@general_log, @@server_audit_logging")[0] == (1, 1)
    assert root_sql("SELECT COUNT(*) FROM shipments")[0][0] == 380
    assert root_sql("SELECT COUNT(*) FROM customers WHERE account_no='AUDIT'")[0][0] == 0


def test_05_resource_limits_really_apply():
    started = time.time()
    result = sh("SELECT COUNT(*) FROM tracking_events a, tracking_events b, tracking_events c, tracking_events d")
    assert "ERROR 1969" in result.stderr and time.time() - started < 15
    held, refused = [], 0
    try:
        for _ in range(12):
            try:
                held.append(pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, bind_address=OTHER))
            except pymysql.MySQLError:
                refused += 1
    finally:
        for conn in held:
            conn.close()
    assert len(held) == 10 and refused == 2


# ---- 6. controller ------------------------------------------------------------------
def test_06_controller_cannot_log_in_from_any_other_address():
    result = sh("SELECT 1", ip=ATTACKER, user="deception_ctrl", password=CTRL_PW)
    assert "ERROR 1045" in result.stderr


def test_06_controller_has_only_the_narrow_grants():
    rows = root_sql("SELECT Db, Table_name, Table_priv FROM mysql.tables_priv WHERE User='deception_ctrl'")
    assert {(r[0], r[1]) for r in rows} == {(DB, t) for t in HIDDEN} | {("mysql", "tables_priv")}
    for db, table, priv in rows:
        assert str(priv) == ("Select" if db == "mysql" else "Select,Grant"), table
    assert json.loads(root_sql("SELECT Priv FROM mysql.global_priv WHERE User='deception_ctrl'")[0][0])["access"] == 0
    assert root_sql("SELECT COUNT(*) FROM mysql.db WHERE User='deception_ctrl'")[0][0] == 0


@pytest.mark.parametrize("sql", [
    "SELECT * FROM api_credentials", "DROP TABLE shipment_archive", "UPDATE shipment_archive SET storage_ref='x'",
    "CREATE USER 'z'@'%'", "GRANT SELECT ON transnova_logistics.api_credentials TO 'decoy_user'@'%'",
    "GRANT UPDATE ON transnova_logistics.shipment_archive TO 'decoy_user'@'%'", "GRANT ALL ON *.* TO 'deception_ctrl'@'127.0.0.1'",
    "SELECT * FROM mysql.global_priv", "SET GLOBAL server_audit_logging=0",
])
def test_06_controller_cannot_exceed_its_job(sql):
    conn = pymysql.connect(host=HOST, port=PORT, user="deception_ctrl", password=CTRL_PW, database=DB, autocommit=True)
    with conn, conn.cursor() as cur, pytest.raises(pymysql.MySQLError):
        cur.execute(sql)


def test_06_decoy_account_cannot_see_the_controller():
    assert "deception_ctrl" not in sh("SELECT * FROM information_schema.user_privileges").stdout
    assert "ERROR" in sh("SHOW GRANTS FOR 'deception_ctrl'@'127.0.0.1'").stderr
    assert "ERROR" in sh("SELECT * FROM mysql.tables_priv").stderr


def test_06_credentials_do_not_appear_in_any_telemetry():
    settle()
    blob = json.dumps(all_events())
    assert CTRL_PW not in blob and DECOY_PW not in blob
    assert CTRL_PW not in "\n".join(raw_lines())
    assert not list(Path(ROOT, "services/database").rglob("*.env"))


# ---- 7. genuine capture -------------------------------------------------------------
def test_07_a_unique_marker_appears_in_mariadb_own_logs():
    marker = f"audit_marker_{int(time.time())}"
    sh(f"SELECT '{marker}' FROM shipments LIMIT 1")
    assert wait_for(lambda: any(marker in ln for ln in raw_lines()), 5)
    general = AUDIT_LOG.with_name("general.log").read_text(encoding="utf-8", errors="replace")
    assert marker in general
    # 8. the same marker reaches the SOC
    event = event_with(marker)
    assert event and marker in event["raw_evidence_redacted"]["raw_event"]


def test_07_failed_login_is_in_the_raw_log_and_the_error_log():
    sh("SELECT 1", ip=OTHER, password="audit-wrong")
    assert wait_for(lambda: any("FAILED_CONNECT" in ln and OTHER in ln for ln in raw_lines()), 5)
    assert "Access denied for user 'decoy_user'@'127.0.0.3'" in AUDIT_LOG.with_name("error.log").read_text(encoding="utf-8", errors="replace")


# ---- 13. restricted start state (before anything triggers) ----------------------------
def test_13_all_eight_decoys_start_restricted():
    assert not (set(granted()) & HIDDEN)
    assert revealed() == {}
    listing = sh("SHOW TABLES").stdout
    assert not [t for t in HIDDEN if t in listing]
    for table in HIDDEN:
        assert "ERROR 1142" in sh(f"SELECT * FROM {table} LIMIT 1").stderr
        assert "ERROR 1142" in sh(f"DESCRIBE {table}").stderr


def test_13_no_metadata_view_leaks_a_hidden_table_name():
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB, bind_address=OTHER)
    with conn, conn.cursor() as cur:
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='information_schema'")
        views = [r[0] for r in cur.fetchall()]
        assert len(views) > 70
        for view in views:
            try:
                cur.execute(f"SELECT * FROM information_schema.`{view}` LIMIT 20000")
            except pymysql.MySQLError:
                continue
            text = repr(cur.fetchall()).lower()
            assert not [t for t in HIDDEN if t in text], view
        for sql in ("SHOW TABLE STATUS", "SHOW FULL TABLES", "SHOW OPEN TABLES", "SHOW CREATE TABLE shipments",
                    "SHOW CREATE TABLE customers", "SHOW CREATE TABLE warehouses"):
            cur.execute(sql)
            text = repr(cur.fetchall()).lower()
            assert not [t for t in HIDDEN if t in text], sql


def test_13_denied_reads_do_not_trigger_anything():
    settle()
    assert revealed() == {}


# ---- 14, 15. triggers reveal the right tables, and they really work --------------------
def test_14a_below_threshold_reveals_nothing():
    sh("SELECT * FROM shipments LIMIT 1")
    sh("SELECT * FROM shipments LIMIT 2")
    settle()
    assert revealed() == {}, "2 reads of 1 table is under rule A"


def test_14a_rule_a_reveals_exactly_its_two_tables():
    sh("SELECT * FROM tracking_events LIMIT 1")
    got = wait_for(lambda: len(revealed()) >= 2 and revealed())
    assert set(got) == {"shipment_archive", "premium_customer_records"}
    assert {r["rule_id"] for r in got.values()} == {"A-SHIPMENT-EXPLORATION"}
    assert set(granted()) - VISIBLE == set(got)


def test_15a_revealed_tables_are_visible_and_readable():
    listing = sh("SHOW TABLES").stdout
    assert "shipment_archive" in listing and "backup_credentials" not in listing
    assert len(sh("SELECT * FROM shipment_archive").stdout.splitlines()) == 61
    assert len(sh("SELECT * FROM premium_customer_records").stdout.splitlines()) > 1


def test_15a_an_already_open_session_sees_the_reveal_without_reconnecting():
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB, bind_address=ATTACKER)
    with conn, conn.cursor() as cur:
        with pytest.raises(pymysql.MySQLError):
            cur.execute("SELECT * FROM backup_credentials LIMIT 1")
        cur.execute("SELECT * FROM api_integrations LIMIT 1")
        cur.execute("SELECT * FROM api_credentials LIMIT 1")
        wait_for(lambda: "backup_credentials" in revealed())
        cur.execute("SELECT * FROM backup_credentials LIMIT 1")
        assert cur.fetchone()


def test_14b_rule_b_reveals_exactly_backup_credentials():
    assert revealed()["backup_credentials"]["rule_id"] == "B-CREDENTIAL-EXPLORATION"
    assert set(revealed()) == {"shipment_archive", "premium_customer_records", "backup_credentials"}


def test_14c_rule_c_needs_two_tables_and_reveals_exactly_two():
    sh("SELECT * FROM warehouse_access LIMIT 1")
    sh("SELECT * FROM warehouse_access LIMIT 2")
    settle()
    assert "warehouse_security_logs" not in revealed()
    sh("SELECT * FROM internal_network_assets LIMIT 1")
    assert wait_for(lambda: {"warehouse_security_logs", "internal_transfer_records"} <= set(revealed()))
    assert len(sh("SELECT * FROM warehouse_security_logs").stdout.splitlines()) > 1
    assert len(sh("SELECT * FROM internal_transfer_records").stdout.splitlines()) > 1


def test_14d_rule_d_reveals_stage_two_and_everything_is_reachable():
    # Rule D counts sensitive reads, so the reads above may already have met its threshold.
    sh("SELECT * FROM partner_contracts LIMIT 1")
    final = wait_for(lambda: len(revealed()) == 8 and revealed())
    assert set(final) == HIDDEN
    for table in ("executive_shipments", "restricted_routes", "disaster_recovery_backup"):
        assert final[table]["rule_id"] == "D-HIGH-VALUE-TARGETING" and final[table]["stage"] == 2
        assert len(sh(f"SELECT * FROM {table}").stdout.splitlines()) > 1
    assert set(granted()) == VISIBLE | HIDDEN and set(granted().values()) == {"Select"}


def test_15_revealed_tables_stay_read_only():
    for sql in ("UPDATE backup_credentials SET account='x'", "DELETE FROM shipment_archive", "DROP TABLE executive_shipments"):
        assert "ERROR 1142" in sh(sql).stderr


def test_14_every_reveal_links_to_a_real_trigger_event():
    settle()
    ids = {e["event_id"]: e for e in all_events()}
    for record in revealed().values():
        trigger = ids[record["trigger_event_id"]]
        assert trigger["event_type"] == "sql_query" and trigger["outcome"] == "succeeded"
        assert record["privilege_before"] is False and record["privilege_after"] is True
        assert "threshold" in record["trigger_reason"]


# ---- 16. no duplicate or uncontrolled privilege changes ---------------------------------
def test_16_repeating_every_trigger_changes_nothing():
    before = len(api("/api/adaptations"))
    grants_before = granted()
    for _ in range(3):
        for sql in ("SELECT * FROM shipments LIMIT 1", "SELECT * FROM tracking_events LIMIT 1", "SELECT * FROM api_credentials LIMIT 1",
                    "SELECT * FROM warehouse_access LIMIT 1", "SELECT * FROM internal_network_assets LIMIT 1"):
            sh(sql)
    settle()
    assert len(api("/api/adaptations")) == before and granted() == grants_before


def test_16_a_second_source_does_not_issue_a_second_grant():
    for sql in ("SELECT * FROM api_integrations LIMIT 1", "SELECT * FROM api_credentials LIMIT 1"):
        sh(sql, ip=OTHER)
    wait_for(lambda: [r for r in api("/api/adaptations") if r["source_ip"] == OTHER])
    second = [r for r in api("/api/adaptations") if r["source_ip"] == OTHER]
    assert second and {r["status"] for r in second} == {"already_present"} and not [r for r in second if r["statement"]]


def test_16_raw_log_shows_exactly_one_grant_per_table():
    # Retcode 0 only: check 6 provokes GRANTs that the server refuses.
    grants = [ln for ln in raw_statements("deception_ctrl") if "GRANT SELECT" in ln and ln.endswith(",0")]
    assert len(grants) == 8
    assert {re.search(r"`\.`(\w+)`", ln).group(1) for ln in grants} == HIDDEN
    assert not [ln for ln in raw_statements("deception_ctrl")
                if re.search(r"'(UPDATE|DROP|CREATE|REVOKE|INSERT|DELETE)", ln) and ln.endswith(",0")]


# ---- 17. controller activity is not attributed to the attacker ---------------------------
def test_17_controller_queries_exist_in_the_log_but_never_as_events():
    assert raw_statements("deception_ctrl")
    settle()
    events = all_events()
    assert not [e for e in events if e["username"] == "deception_ctrl" and e["source_ip"] == HOST]
    assert not [e for e in events if "GRANT SELECT" in (e["command"] or "") and "decoy_user" in (e["command"] or "")
                and e["outcome"] == "succeeded"]
    assert not [e for e in events if "tables_priv" in (e["command"] or "") and e["source_ip"] == HOST]


def test_17_someone_guessing_the_controller_login_is_reported():
    sh("SELECT 1", ip=ATTACKER, user="deception_ctrl", password="guess")
    found = wait_for(lambda: [e for e in all_events() if e["username"] == "deception_ctrl" and e["outcome"] == "failed"])
    assert found and found[0]["source_ip"] == ATTACKER


# ---- 9, 10, 11, 12. classification, outcomes, risk, ATT&CK --------------------------------
def test_09_real_statements_classify_correctly():
    cases = [("SHOW DATABASES", "reconnaissance", "succeeded"), ("DESCRIBE shipments", "reconnaissance", "succeeded"),
             ("SELECT * FROM routes LIMIT 3", "data_exploration", "succeeded"),
             ("SELECT * FROM admin_accounts LIMIT 3", "sensitive_access", "succeeded"),
             ("SELECT * FROM backup_credentials LIMIT 3", "adaptive_decoy_access", "succeeded"),
             ("SELECT * FROM mysql.user LIMIT 3", "restricted_access", "blocked"),
             ("UPDATE routes SET active=0", "modification_attempt", "blocked"),
             ("DROP TABLE routes", "schema_change_attempt", "blocked"),
             ("GRANT ALL ON *.* TO 'x'@'%'", "privilege_attempt", "blocked"),
             ("SELEC broken", "unknown", "failed")]
    for sql, category, outcome in cases:
        sh(f"{sql} /* audit09 */")
    for sql, category, outcome in cases:
        event = event_with(f"{sql} /* audit09 */")
        assert (event["action"], event["outcome"]) == (category, outcome), sql


@pytest.mark.parametrize("sql", [
    "(SELECT * FROM api_credentials LIMIT 1)", "/*!50000 SELECT * FROM api_credentials LIMIT 1 */",
    "/*M!100100 SELECT * FROM api_credentials LIMIT 1 */", "/*!SELECT*/ * FROM api_credentials LIMIT 1",
    "SELECT/**/*/**/FROM/**/api_credentials/**/LIMIT/**/1", "SELECT * FROM api_credentials PROCEDURE ANALYSE()",
    "SET STATEMENT max_statement_time=2 FOR SELECT * FROM api_credentials LIMIT 1", "ANALYZE SELECT * FROM api_credentials LIMIT 1",
    "EXPLAIN SELECT * FROM api_credentials", "CHECKSUM TABLE api_credentials", "DO (SELECT COUNT(*) FROM api_credentials)",
])
def test_09_disguised_reads_that_the_server_ran_are_caught(sql):
    tagged = sql.replace("LIMIT 1", f"LIMIT {abs(hash(sql)) % 900 + 2}") if "LIMIT 1" in sql else sql
    assert "ERROR" not in sh(tagged, ip=HOSTILE).stderr
    # The client may re-space comments before sending, so compare without whitespace.
    compact = re.sub(r"\s", "", tagged)
    event = wait_for(lambda: next((e for e in all_events() if re.sub(r"\s", "", e["command"] or "") == compact), None))
    assert event, tagged
    assert event["action"] == "sensitive_access" and "api_credentials" in event["table_names"]
    assert event["raw_evidence_redacted"]["severity"] in ("HIGH", "CRITICAL")


def test_09_inner_statements_of_prepare_handler_and_multi_statement_are_seen():
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB, bind_address=HOSTILE,
                           client_flag=CLIENT.MULTI_STATEMENTS, autocommit=True)
    with conn, conn.cursor() as cur:
        cur.execute("SET @q = CONCAT('SELECT tracking_no, 7001 FROM ship', 'ments, api_cred', 'entials LIMIT 1')")
        cur.execute("PREPARE p FROM @q")
        cur.execute("EXECUTE p")
        cur.execute("EXECUTE IMMEDIATE 'SELECT 7002 FROM api_credentials LIMIT 1'")
        cur.execute("HANDLER api_credentials OPEN AS audit_h")
        cur.execute("HANDLER audit_h READ FIRST")
        cur.execute("HANDLER audit_h CLOSE")
        cur.execute("SELECT 7003; SELECT 7004 FROM api_credentials LIMIT 1")
    for marker in ("7001 FROM shipments, api_credentials", "7002 FROM api_credentials", "7004 FROM api_credentials"):
        assert wait_for(lambda: [e for e in all_events() if marker in (e["command"] or "")
                                 and e["action"] == "sensitive_access"]), marker
    handler = event_with("HANDLER audit_h READ FIRST")
    assert handler and handler["action"] == "sensitive_access" and handler["table_names"] == ["api_credentials"]


def test_09_dynamic_sql_is_resolved_from_what_the_server_opened():
    # The statement text never contains the table name, so no parser could find it.
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB,
                           bind_address=HOSTILE, autocommit=True)
    with conn, conn.cursor() as cur:
        cur.execute("EXECUTE IMMEDIATE CONCAT('SELECT 7101 FROM api_', 'credentials LIMIT 1')")
        cur.execute("SET @audit_q = CONCAT('SELECT 7102 FROM admin_', 'accounts LIMIT 1')")
        cur.execute("EXECUTE IMMEDIATE @audit_q")
    concat = event_with("EXECUTE IMMEDIATE CONCAT('SELECT 7101")
    assert concat["action"] == "sensitive_access" and "api_credentials" in concat["table_names"]
    assert "db:server_resolved_tables" in concat["tags"]
    assert concat["raw_evidence_redacted"]["mitre"][0]["technique"] == "T1552"
    variable = event_with("EXECUTE IMMEDIATE @audit_q")
    assert variable["action"] == "sensitive_access" and "admin_accounts" in variable["table_names"]


def test_09_optimizer_statistics_are_not_attributed_to_the_attacker():
    settle()
    assert not [e for e in all_events() if any(t.startswith("mysql.") and t.endswith("_stats") for t in e["table_names"])]


def test_09_binary_protocol_prepared_statement_is_logged():
    conn = pymysql.connect(host=HOST, port=PORT, user="decoy_user", password=DECOY_PW, database=DB, bind_address=HOSTILE)
    with conn:
        conn._execute_command(22, b"SELECT 7005 FROM api_credentials LIMIT 1")  # COM_STMT_PREPARE
        first = conn._read_packet()
        statement_id = int.from_bytes(first.get_all_data()[1:5], "little")
        columns = int.from_bytes(first.get_all_data()[5:7], "little")
        for _ in range(columns + 1):
            conn._read_packet()
        payload = statement_id.to_bytes(4, "little") + b"\x00" + (1).to_bytes(4, "little")
        conn._execute_command(23, payload)  # COM_STMT_EXECUTE
        conn._read_packet()
    event = wait_for(lambda: next((e for e in all_events() if "7005" in (e["command"] or "") and e["action"] == "sensitive_access"), None))
    assert event


def test_10_no_event_claims_success_when_the_server_refused():
    sh("DELETE FROM routes")
    settle()
    checked = 0
    for line in raw_statements():
        retcode = int(line.rsplit(",", 1)[1])
        if retcode:
            checked += 1
    events = [e for e in all_events() if e["event_type"] == "sql_query"]
    denied = [e for e in events if e["raw_evidence_redacted"]["server_retcode"]]
    assert checked >= 40 and len(denied) == checked
    assert not [e for e in denied if e["outcome"] == "succeeded"]
    for event in denied:
        logged = int(event["raw_evidence_redacted"]["raw_event"].rsplit(",", 1)[1])
        assert logged == event["raw_evidence_redacted"]["server_retcode"]


def test_10_failed_logins_are_never_reported_as_logins():
    settle()
    raw_failed = len([ln for ln in raw_lines() if ",FAILED_CONNECT," in ln])
    events = [e for e in all_events() if e["action"] == "db_login" and e["outcome"] == "failed"]
    assert raw_failed == len(events) and raw_failed >= 2


def test_11_every_score_equals_its_stated_reasons_and_band():
    settle()
    bands = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]
    checked = 0
    for event in all_events():
        ev = event["raw_evidence_redacted"]
        if ev.get("audit_operation") == "DISCONNECT":
            continue
        points = sum(int(m.group(1)) for r in ev["risk_reasons"] for m in [re.match(r"\+(\d+)", r)] if m)
        assert min(points, 100) == ev["risk_score"] or "log_injection" in ev["classification"], ev["risk_reasons"]
        assert ev["severity"] == next(name for floor, name in bands if ev["risk_score"] >= floor)
        checked += 1
    assert checked > 100


def test_11_ordinary_reads_stay_low_however_often_they_run():
    for _ in range(8):
        sh("SELECT * FROM routes LIMIT 5", ip="127.0.0.5")
    settle()
    events = [e for e in all_events() if e["source_ip"] == "127.0.0.5" and e["action"] == "data_exploration"]
    assert len(events) == 8 and {e["raw_evidence_redacted"]["severity"] for e in events} == {"LOW"}


def test_12_every_technique_is_backed_by_the_event_itself():
    settle()
    table_map = json.loads((ROOT / "services/database/sensor/config/rules.json").read_text(encoding="utf-8"))["mitre_table_map"]
    seen = set()
    for event in all_events():
        ev = event["raw_evidence_redacted"]
        for item in ev.get("mitre") or []:
            tid = item["technique"]
            seen.add(tid)
            assert item["name"] and item["tactic"] and item["rationale"]
            if tid.startswith("T1110"):
                assert event["action"] == "db_login" and event["outcome"] == "failed"
                continue
            mapped = [t for t in event["table_names"] if table_map.get(t) == tid]
            assert mapped or (tid == "T1213" and "distinct tables" in item["rationale"]), (tid, event["table_names"])
            assert item["status"] == ("observed" if event["outcome"] == "succeeded" else "attempted")
    assert {"T1213", "T1087", "T1552"} <= seen


def test_12_routine_and_denied_write_activity_has_no_technique():
    settle()
    for event in all_events():
        if event["action"] in ("modification_attempt", "schema_change_attempt", "privilege_attempt", "client_noise",
                               "session_control", "db_disconnect"):
            assert not event["raw_evidence_redacted"].get("mitre"), event["command"]


# ---- 18. schema ----------------------------------------------------------------------
def test_18_every_event_validates_against_both_schema_copies():
    from collector.schema import CanonicalEvent as Collector

    spec = importlib.util.spec_from_file_location("web_schema_copy", ROOT / "services/web/web_decoy/telemetry/schema.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["web_schema_copy"] = module
    spec.loader.exec_module(module)
    settle()
    events = all_events()
    assert len(events) > 100
    for event in events:
        Collector.model_validate(event)
        module.CanonicalEvent.model_validate(event)
        assert event["service"] == "database" and event["sensor_id"] == "db-01"
        assert event["timestamp"].endswith("Z") and event["source_port"] is None


def test_18_detections_use_the_shape_the_web_decoy_uses():
    keys = {"rule", "category", "label", "field", "confidence", "rationale", "attack"}
    found = [d for e in all_events() for d in e["raw_evidence_redacted"].get("detections") or []]
    assert found and all(keys <= set(d) for d in found)


# ---- 19. delivery ---------------------------------------------------------------------
def test_19_every_logged_statement_became_exactly_one_event():
    settle()
    events = [e for e in all_events() if e["event_type"] == "sql_query" and e["username"] == "decoy_user"]
    assert len(events) == len(raw_statements()) and len(events) > 100
    assert len({e["event_id"] for e in events}) == len(events)
    assert not [e for e in all_events() if e["action"] == "unparsed_audit_line"]


def test_19_collector_outage_delays_but_loses_nothing(stack):
    stack["collector"].terminate()
    stack["collector"].wait(timeout=10)
    assert not healthy()
    sh("SELECT 'during_outage_1' FROM routes LIMIT 1")
    sh("SELECT 'during_outage_2' FROM routes LIMIT 1")
    spool = Path(stack["sensor_env"]["SENSOR_DATA_DIR"]) / "db-spool.jsonl"
    assert wait_for(lambda: spool.exists() and "during_outage_2" in spool.read_text(encoding="ascii"), 10)
    stack["collector"] = start_collector(stack["work"])
    assert event_with("during_outage_1", 40) and event_with("during_outage_2", 5)
    assert wait_for(lambda: spool.read_text(encoding="ascii") == "", 10)


def test_19_sensor_restart_after_a_crash_neither_loses_nor_duplicates(stack):
    stack["sensor"].kill()
    stack["sensor"].wait(timeout=10)
    sh("SELECT 'during_sensor_down' FROM routes LIMIT 1")
    stack["sensor"] = subprocess.Popen([sys.executable, "-m", "db_sensor.main"], cwd=ROOT, env=stack["sensor_env"])
    assert event_with("during_sensor_down", 15)
    test_19_every_logged_statement_became_exactly_one_event()


def test_19_log_rotation_during_activity_loses_nothing():
    sh("SELECT 'before_rotation' FROM routes LIMIT 1")
    # Windows refuses the rename while the sensor has the file open for a read, and MariaDB
    # then keeps writing to the same file. Nothing is lost, so simply ask again.
    def rotated():
        root_sql("SET GLOBAL server_audit_file_rotate_now=ON")
        return AUDIT_LOG.with_name(AUDIT_LOG.name + ".1").exists()
    assert wait_for(rotated, 10)
    sh("SELECT 'after_rotation' FROM routes LIMIT 1")
    assert event_with("before_rotation") and event_with("after_rotation")


def test_19_mariadb_restart_keeps_grants_and_new_connection_ids_do_not_collide():
    lab = [sys.executable, str(ROOT / "services/database/scripts/native_lab.py")]
    args = ["--mariadb-home", os.environ["LIVE_MARIADB_HOME"], "--workdir", os.environ["LIVE_WORKDIR"]]
    subprocess.run(lab + ["stop"] + args, check=True, capture_output=True)
    time.sleep(2)
    subprocess.run(lab + ["start"] + args, check=True, capture_output=True, timeout=60)
    time.sleep(1)
    assert len(sh("SELECT * FROM backup_credentials").stdout.splitlines()) > 1, "reveal must survive a restart"
    sh("SELECT 'after_db_restart' FROM routes LIMIT 1")
    event = event_with("after_db_restart", 15)
    assert event and event["outcome"] == "succeeded" and event["action"] == "data_exploration"
    assert not [e for e in all_events() if e["action"] == "log_tampering"]


# ---- 20. SOC views ---------------------------------------------------------------------
def test_20_collector_views_agree_with_mariadb():
    settle()
    summary = api("/api/database/summary")
    assert summary["queries_captured"] == len([e for e in all_events() if e["event_type"] == "sql_query"])
    assert summary["connections_failed"] == len([ln for ln in raw_lines() if ",FAILED_CONNECT," in ln])
    rules = {a["rule"] for a in api("/api/alerts")}
    assert {"D-SENS-01", "D-ADAPT-01", "D-RESTR-01", "D-MOD-01", "D-DDL-01", "D-PRIV-01"} <= rules
    assert ATTACKER in {s["source_ip"] for s in api("/api/attackers")}
    followed = [r for r in api("/api/adaptations") if r["followup_event_ids"]]
    assert len({r["asset_revealed"] for r in followed}) == 8


def test_20_sensor_reports_healthy_with_real_sessions():
    # internal_ignored counts since the last sensor start, and check 19 restarts the sensor,
    # so wait for a heartbeat sent after it has seen our own traffic again.
    def beat():
        return next((s for s in api("/api/sensors") if s["sensor_id"] == "db-01"), None)
    sensor = wait_for(lambda: (b := beat()) and b["details"]["internal_ignored"] > 0 and b, 30)
    assert sensor and sensor["details"]["sessions"]
    assert sensor["details"]["spool_pending"] == 0
    assert len(sensor["details"]["revealed_assets"]) == 8
