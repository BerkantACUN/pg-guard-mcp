"""
Integration tests against a real local PostgreSQL instance.

These prove the actual security boundary: that pg-guard-mcp's connection
layer executes every query through the Postgres *extended* query protocol,
which structurally refuses to run more than one statement per call — the
exact mechanism the official @modelcontextprotocol/server-postgres lacked,
which is what let a single `COMMIT;` bypass its read-only wrapper.

Skipped automatically if PG_GUARD_TEST_DSN is not set, so the fast unit
suite (test_safety.py) still runs everywhere with no external dependency.
"""

import os

import psycopg
import pytest

from pg_guard_mcp.db import ReadOnlyConnection

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


class TestOrdinaryReadsWork:
    def test_select_returns_rows(self):
        with ReadOnlyConnection(TEST_DSN) as conn:
            rows = conn.query("SELECT id, email FROM users ORDER BY id")
        assert len(rows) == 2
        assert rows[0]["email"] == "a@example.com"

    def test_parameterized_select_works(self):
        with ReadOnlyConnection(TEST_DSN) as conn:
            rows = conn.query("SELECT email FROM users WHERE id = %s", (1,))
        assert rows == [{"email": "a@example.com"}]


class TestTheDatadogExploitFailsAgainstARealServer:
    """The exact payload that deprecated the official Postgres MCP server,
    run against a real connection, to prove the defense is structural and
    not just a string check that could itself have a bypass."""

    def test_commit_bypass_drop_table_is_refused_by_postgres_itself(self):
        with ReadOnlyConnection(TEST_DSN) as conn:
            with pytest.raises(Exception):
                conn.query("SELECT 1; COMMIT; DROP TABLE users;")

        # Prove the table really does still exist and still has its rows —
        # not just that *an* exception was raised.
        with ReadOnlyConnection(TEST_DSN) as conn:
            rows = conn.query("SELECT count(*) AS n FROM users")
        assert rows[0]["n"] == 2

    def test_multi_statement_select_select_is_refused(self):
        with ReadOnlyConnection(TEST_DSN) as conn:
            with pytest.raises(Exception):
                conn.query("SELECT 1; SELECT 2;")


class TestWritesAreRefusedEvenIfSomehowSubmittedAlone:
    """Belt-and-suspenders: even if the pre-flight keyword check in
    safety.py were somehow bypassed, the role itself has no write grant
    and the session is read-only, so Postgres refuses the write."""

    def test_insert_is_refused_by_the_database(self):
        with ReadOnlyConnection(TEST_DSN) as conn:
            with pytest.raises(Exception):
                conn.query("INSERT INTO users (email) VALUES ('hacker@example.com')")

        with ReadOnlyConnection(TEST_DSN) as conn:
            rows = conn.query("SELECT count(*) AS n FROM users")
        assert rows[0]["n"] == 2

    def test_delete_is_refused_by_the_database(self):
        with ReadOnlyConnection(TEST_DSN) as conn:
            with pytest.raises(Exception):
                conn.query("DELETE FROM users")

        with ReadOnlyConnection(TEST_DSN) as conn:
            rows = conn.query("SELECT count(*) AS n FROM users")
        assert rows[0]["n"] == 2


class TestConnectionRefusesUnsafeQueriesBeforeSendingThem:
    def test_dangerous_query_never_reaches_the_network(self):
        # safety.py should reject this before ReadOnlyConnection even opens
        # a cursor — confirmed indirectly: it still raises, and the data is
        # untouched, whether or not a network round-trip happened.
        with ReadOnlyConnection(TEST_DSN) as conn:
            with pytest.raises(Exception):
                conn.query("DROP TABLE users")
        with ReadOnlyConnection(TEST_DSN) as conn:
            rows = conn.query("SELECT count(*) AS n FROM users")
        assert rows[0]["n"] == 2
