"""
MCP tool surface for pg-guard-mcp.

Every tool here goes through ReadOnlyConnection (db.py), so every query —
no matter which tool calls it — passes through the same three-layer
defense (protocol / session / pre-flight) described there. There is
deliberately no "run arbitrary write SQL" escape hatch and no shell-out to
the `psql` binary: the only way this server talks to Postgres is through
psycopg's extended query protocol.
"""

from __future__ import annotations

import os
import sys

try:
    # SDK >= 2.0: FastMCP was renamed to MCPServer, same .tool()/.run() API.
    from mcp.server import MCPServer as _MCPServerImpl
except ImportError:  # SDK < 2.0
    from mcp.server.fastmcp import FastMCP as _MCPServerImpl  # type: ignore[no-redef]

from .db import DEFAULT_ROW_LIMIT, DEFAULT_STATEMENT_TIMEOUT_MS, ReadOnlyConnection
from .safety import UnsafeQueryError, validate_readonly_query

mcp = _MCPServerImpl("pg-guard-mcp")


def _dsn() -> str:
    dsn = os.environ.get("PG_GUARD_DSN")
    if dsn:
        return dsn
    # Fall back to standard libpq environment variables (PGHOST, PGPORT,
    # PGDATABASE, PGUSER, PGPASSWORD, ...) — psycopg reads these itself
    # when given an empty DSN, so this just documents the expectation.
    return ""


def _row_limit() -> int:
    raw = os.environ.get("PG_GUARD_ROW_LIMIT")
    return int(raw) if raw else DEFAULT_ROW_LIMIT


def _statement_timeout_ms() -> int:
    raw = os.environ.get("PG_GUARD_STATEMENT_TIMEOUT_MS")
    return int(raw) if raw else DEFAULT_STATEMENT_TIMEOUT_MS


def _connect() -> ReadOnlyConnection:
    return ReadOnlyConnection(
        _dsn(),
        statement_timeout_ms=_statement_timeout_ms(),
        row_limit=_row_limit(),
    )


def _run(sql: str, params: tuple | list | None = None) -> dict:
    try:
        with _connect() as conn:
            rows = conn.query(sql, params)
        return {"rows": rows, "row_count": len(rows)}
    except UnsafeQueryError as e:
        return {"error": "UnsafeQuery", "message": str(e)}
    except Exception as e:  # psycopg errors, connection failures, etc.
        return {"error": type(e).__name__, "message": str(e)}


@mcp.tool()
def pg_run_query(sql: str) -> dict:
    """Run a single read-only SQL statement (SELECT / WITH / EXPLAIN / SHOW)
    against the configured PostgreSQL database and return the rows.

    Rejects anything that isn't exactly one plain read-only statement —
    multiple statements, transaction-control keywords (COMMIT, ROLLBACK,
    BEGIN, ...), and any write/DDL/admin keyword anywhere in the query are
    all refused before the query is sent to the database. Results are
    capped at PG_GUARD_ROW_LIMIT rows (default 1000).
    """
    return _run(sql)


@mcp.tool()
def pg_explain_query(sql: str) -> dict:
    """Return the PostgreSQL query plan for a read-only SELECT/WITH
    statement, without running it. Useful for checking whether a query
    will be slow before running it for real."""
    # Validate the user's actual input *before* wrapping it in EXPLAIN.
    # This is deliberate: wrapping first and validating the composed
    # string would still catch anything on the dangerous-keyword
    # blocklist, but it makes the error about what the caller typed, and
    # it means a change to that composition logic can never quietly
    # start validating something other than the real input.
    try:
        validate_readonly_query(sql)
    except UnsafeQueryError as e:
        return {"error": "UnsafeQuery", "message": str(e)}

    stripped = sql.strip().rstrip(";")
    return _run(f"EXPLAIN {stripped}")


@mcp.tool()
def pg_list_tables(schema: str = "public") -> dict:
    """List the tables and views visible to the connected role in the
    given schema (default: public)."""
    return _run(
        "SELECT table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = %s ORDER BY table_name",
        (schema,),
    )


@mcp.tool()
def pg_check_privileges() -> dict:
    """Report any write privilege (INSERT/UPDATE/DELETE/TRUNCATE) the
    connected role actually holds on any table. An empty list is the
    expected, safe result — anything else means the privilege layer of
    defense is missing and the role should be locked down (see README.md),
    even though the protocol and session layers still hold on their own."""
    return _run(
        "SELECT table_schema, table_name, privilege_type "
        "FROM information_schema.role_table_grants "
        "WHERE grantee = current_user "
        "AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE') "
        "ORDER BY table_schema, table_name, privilege_type"
    )


@mcp.tool()
def pg_describe_table(table_name: str, schema: str = "public") -> dict:
    """List the columns of a table: name, data type, nullability, and
    default, in column order."""
    return _run(
        "SELECT column_name, data_type, is_nullable, column_default "
        "FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = %s "
        "ORDER BY ordinal_position",
        (schema, table_name),
    )


def _warn_if_role_can_write() -> None:
    """Best-effort startup check: if the connected role holds any write
    privilege, say so loudly. Never fails startup — this is advisory."""
    try:
        result = pg_check_privileges()
    except Exception:
        return
    grants = result.get("rows") or []
    if grants:
        print(
            f"pg-guard-mcp: WARNING — the connected role has {len(grants)} write "
            "grant(s) (see pg_check_privileges). The protocol and session layers "
            "still block writes, but a role with write access revoked is the "
            "recommended setup. See README.md.",
            file=sys.stderr,
        )


def main() -> None:
    if not os.environ.get("PG_GUARD_DSN") and not os.environ.get("PGDATABASE"):
        print(
            "pg-guard-mcp: no PG_GUARD_DSN or PGDATABASE set — connections will fail "
            "until one is configured. See README.md for setup.",
            file=sys.stderr,
        )
    else:
        _warn_if_role_can_write()
    mcp.run()


if __name__ == "__main__":
    main()
