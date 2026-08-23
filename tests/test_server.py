"""Integration tests for the MCP tool layer, against the same local
pgguard_test database used by test_db.py."""

import os

import psycopg
import pytest

TEST_DSN = os.environ.get(
    "PG_GUARD_TEST_DSN",
    "host=127.0.0.1 dbname=pgguard_test user=pgguard_readonly password=pgguard_readonly_dev_pw",
)


def _connectable() -> bool:
    try:
        with psycopg.connect(TEST_DSN, connect_timeout=3):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _connectable(),
    reason="no local pgguard_test database reachable — set PG_GUARD_TEST_DSN or run the dev setup script",
)


@pytest.fixture(autouse=True)
def _configure_dsn(monkeypatch):
    monkeypatch.setenv("PG_GUARD_DSN", TEST_DSN)
    yield


class TestPgRunQuery:
    def test_returns_rows_for_a_plain_select(self):
        from pg_guard_mcp.server import pg_run_query

        result = pg_run_query("SELECT id, email FROM users ORDER BY id")
        assert result["row_count"] == 2
        assert result["rows"][0]["email"] == "a@example.com"

    def test_returns_a_typed_error_instead_of_raising_for_unsafe_query(self):
        from pg_guard_mcp.server import pg_run_query

        result = pg_run_query("DROP TABLE users")
        assert result["error"] == "UnsafeQuery"
        assert "DROP" in result["message"]

    def test_returns_a_typed_error_for_the_datadog_exploit(self):
        from pg_guard_mcp.server import pg_run_query

        result = pg_run_query("SELECT 1; COMMIT; DROP TABLE users;")
        assert "error" in result

        # and the table really is untouched
        followup = pg_run_query("SELECT count(*) AS n FROM users")
        assert followup["rows"][0]["n"] == 2


class TestPgListTables:
    def test_finds_the_users_table(self):
        from pg_guard_mcp.server import pg_list_tables

        result = pg_list_tables()
        names = [row["table_name"] for row in result["rows"]]
        assert "users" in names


class TestPgDescribeTable:
    def test_lists_columns_of_users(self):
        from pg_guard_mcp.server import pg_describe_table

        result = pg_describe_table("users")
        names = [row["column_name"] for row in result["rows"]]
        assert "id" in names
        assert "email" in names


class TestPgExplainQuery:
    def test_returns_a_plan_without_error(self):
        from pg_guard_mcp.server import pg_explain_query

        result = pg_explain_query("SELECT * FROM users")
        assert "error" not in result
        assert result["row_count"] > 0

    def test_rejects_a_write_statement_instead_of_explaining_it(self):
        from pg_guard_mcp.server import pg_explain_query

        # EXPLAIN ANALYZE of a write statement actually *runs* the write
        # in real Postgres — this must never reach the database at all.
        result = pg_explain_query("ANALYZE DELETE FROM users")
        assert result.get("error") == "UnsafeQuery"

    def test_table_is_untouched_after_a_rejected_explain_analyze_write(self):
        from pg_guard_mcp.server import pg_explain_query, pg_run_query

        pg_explain_query("ANALYZE DELETE FROM users")
        followup = pg_run_query("SELECT count(*) AS n FROM users")
        assert followup["rows"][0]["n"] == 2


class TestPgCheckPrivileges:
    def test_readonly_role_has_no_write_grants(self):
        from pg_guard_mcp.server import pg_check_privileges

        result = pg_check_privileges()
        assert result["rows"] == []
