"""Regressions from the readiness audit. Each form returned rows from a real MariaDB 11.4.9
while being reported as LOW, so an attacker could read secrets and never trip a rule."""

from __future__ import annotations

import pytest
from db_sensor.classify import classify
from db_sensor.config import DEFAULT_RULES, load_rules

RULES = load_rules(str(DEFAULT_RULES))
DB = "transnova_logistics"
READS = [
    "(SELECT * FROM api_credentials LIMIT 1)",
    "((SELECT * FROM api_credentials LIMIT 1))",
    "/*!50000 SELECT * FROM api_credentials LIMIT 1 */",
    "/*M!100100 SELECT * FROM api_credentials LIMIT 1 */",
    "/*!SELECT*/ * FROM api_credentials LIMIT 1",
    "SELECT /*!* FROM*/ api_credentials LIMIT 1",
    "HANDLER api_credentials READ FIRST",
    "SELECT * FROM api_credentials PROCEDURE ANALYSE()",
    "SELECT * FROM api_credentials LIMIT 1 INTO @x, @y, @z",
    "SET STATEMENT max_statement_time=1 FOR SELECT * FROM api_credentials LIMIT 1",
    "ANALYZE SELECT * FROM api_credentials",
    "ANALYZE FORMAT=JSON SELECT * FROM api_credentials",
    "DO (SELECT COUNT(*) FROM api_credentials)",
    "CHECKSUM TABLE api_credentials",
    "SHOW COLUMNS IN api_credentials",
    "SHOW FULL FIELDS FROM api_credentials",
]


@pytest.mark.parametrize("sql", READS)
def test_disguised_read_is_still_a_sensitive_read(sql):
    c = classify(sql, 0, DB, RULES)
    assert c.category == "sensitive_access", (c.category, c.tables)
    assert c.tables == ["api_credentials"]


@pytest.mark.parametrize("sql", ["(SELECT * FROM backup_credentials)", "/*!SELECT * FROM backup_credentials*/"])
def test_disguised_hidden_table_read_when_denied_is_restricted(sql):
    assert classify(sql, 1142, DB, RULES).category == "restricted_access"


def test_handler_open_and_close_return_no_rows():
    assert classify("HANDLER api_credentials OPEN", 0, DB, RULES).category == "session_control"
    assert classify("HANDLER api_credentials CLOSE", 0, DB, RULES).category == "session_control"
    assert classify("HANDLER backup_credentials OPEN", 1142, DB, RULES).category == "restricted_access"


def test_parenthesised_select_reports_its_real_type():
    assert classify("(SELECT 1 FROM shipments)", 0, DB, RULES).query_type == "SELECT"


def test_junk_names_are_not_recorded_as_tables():
    assert classify("SHOW COLUMNS FROM shipments", 0, DB, RULES).tables == ["shipments"]
    assert classify("SELECT 1 FROM DUAL", 0, DB, RULES).tables == []
    assert classify("SHOW TABLES FROM transnova_logistics", 0, DB, RULES).tables == []
    assert classify("SELECT 1 INTO OUTFILE 'x.txt'", 1045, DB, RULES).tables == []


def test_string_literals_are_never_tables():
    c = classify("PREPARE p FROM 'SELECT * FROM api_credentials'", 0, DB, RULES)
    assert c.tables == [] and c.category == "unknown"
    assert classify("SELECT 'FROM api_credentials'", 0, DB, RULES).tables == []


def test_failed_syntax_is_not_a_read():
    assert classify("SELEC * FROM api_credentials", 1064, DB, RULES).category == "unknown"
