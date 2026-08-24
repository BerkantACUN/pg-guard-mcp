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
from pathlib import Path

try:
    # SDK >= 2.0: FastMCP was renamed to MCPServer, same .tool()/.run() API.
    from mcp.server import MCPServer as _MCPServerImpl
except ImportError:  # SDK < 2.0
    from mcp.server.fastmcp import FastMCP as _MCPServerImpl  # type: ignore[no-redef]

from .db import DEFAULT_ROW_LIMIT, DEFAULT_STATEMENT_TIMEOUT_MS, ReadOnlyConnection
from .migration_safety import check_migration_safety
from .safety import UnsafeQueryError, validate_readonly_query

mcp = _MCPServerImpl("pg-guard-mcp")

# Real migration files are a few KB. Generous ceiling, not a tight budget —
# rejects an oversized input with a clear typed error before it's ever
# handed to the regex-based rule engine, as defense in depth.
_MAX_MIGRATION_BYTES = 2 * 1024 * 1024  # 2 MiB


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


def _too_large_error(size: int) -> dict:
    return {
        "error": "MigrationTooLarge",
        "message": f"{size} bytes exceeds the {_MAX_MIGRATION_BYTES}-byte limit for a migration.",
    }


def _check_migration_sql(sql: str) -> dict:
    """Shared by both migration tools below. Wraps the rule-engine call
    itself in the same catch-all shape every other tool in this file gets
    from _run() — a future bug in the regex engine should surface as a
    typed {"error": ...} response at the MCP boundary, not an unhandled
    exception, even though this path never touches ReadOnlyConnection."""
    try:
        findings = check_migration_safety(sql)
    except Exception as e:  # pragma: no cover - defense in depth, see docstring
        return {"error": type(e).__name__, "message": str(e)}
    return {
        "findings": [f.to_dict() for f in findings],
        "finding_count": len(findings),
    }


@mcp.tool()
def pg_check_migration_safety(sql: str) -> dict:
    """Statically check DDL (CREATE INDEX, ALTER TABLE ADD/RENAME/ALTER
    COLUMN TYPE, ADD CONSTRAINT) for lock/downtime/breakage patterns that
    cause real production incidents on a table that already has traffic —
    a missing CONCURRENTLY, a FOREIGN KEY added without NOT VALID, a
    NOT NULL column added with no DEFAULT, an in-place RENAME, and similar.
    Pure text analysis — never connects to the database, never runs
    anything. An empty findings list means no known-unsafe pattern was
    found, not a guarantee the migration is safe; see the rule engine's
    module docstring for what this does and doesn't cover."""
    size = len(sql.encode("utf-8"))
    if size > _MAX_MIGRATION_BYTES:
        return _too_large_error(size)
    return _check_migration_sql(sql)


def _migrations_dir() -> Path | None:
    """Optional containment root for pg_check_migration_file, set via
    PG_GUARD_MIGRATIONS_DIR. Unset by default: this tool reads whatever
    path it's given, same as every other MCP filesystem-read tool in this
    session's "guard" family (actions-guard-mcp's scan_workflow_file has
    the identical shape). But that's a real, separate capability from
    "read-only Postgres access" — the one thing this whole project exists
    to guarantee elsewhere — so a user who wants this tool confined to a
    known migrations folder can set this and get it, without changing the
    permissive default anyone upgrading from an earlier version relies on.
    """
    raw = os.environ.get("PG_GUARD_MIGRATIONS_DIR")
    return Path(raw).resolve() if raw else None


def _looks_like_unc_path(path: str) -> bool:
    """True for a UNC network path (\\\\host\\share\\...), including the
    \\\\?\\UNC\\ extended-length form and its forward-slash spelling
    (//host/share/...). A stat()/is_file()/resolve() call on one of these
    can force an outbound SMB/NTLM authentication attempt to whatever
    host the string names — independent of anything this function does,
    a well-known Windows "forced authentication" primitive — and a
    real security review measured ~21s hung against a single
    unreachable address before returning. Rejected outright, before any
    Path method ever touches the string, rather than after. A genuine
    single leading backslash (a drive-relative local path) is unaffected
    — this only matches a *double* leading separator."""
    return path.replace("/", "\\").startswith("\\\\")


@mcp.tool()
def pg_check_migration_file(path: str) -> dict:
    """Same as pg_check_migration_safety, reading the SQL from a file on
    disk instead of inline content. Confined to PG_GUARD_MIGRATIONS_DIR
    when that's set; otherwise reads any local path this process can
    access — see _migrations_dir()'s docstring. UNC network paths are
    always rejected, configured or not."""
    if _looks_like_unc_path(path):
        return {
            "error": "UnsupportedPath",
            "message": f"UNC network paths are not supported: {path}",
        }

    try:
        file_path = Path(path)
        migrations_dir = _migrations_dir()
        if migrations_dir is not None:
            resolved = file_path.resolve()
            if not resolved.is_relative_to(migrations_dir):
                return {
                    "error": "PathOutsideMigrationsDir",
                    "message": (
                        f"{path} resolves outside PG_GUARD_MIGRATIONS_DIR ({migrations_dir})."
                    ),
                }
            file_path = resolved

        if not file_path.is_file():
            return {"error": "FileNotFoundError", "message": f"No such file: {path}"}

        size = file_path.stat().st_size
        if size > _MAX_MIGRATION_BYTES:
            return _too_large_error(size)
        sql = file_path.read_text(encoding="utf-8")
    except OSError as e:
        # Deliberately one try/except spanning every filesystem call in
        # this function, is_file() included: is_file() only swallows a
        # narrow set of OSError codes internally (ENOENT/ENOTDIR/EBADF
        # and their Windows equivalents) and re-raises the rest —
        # PermissionError ("Access is denied") is one of the ones that
        # gets re-raised. A real security review confirmed that with
        # is_file() outside this block, a permission-denied path crashed
        # this tool with an unhandled exception instead of returning the
        # same typed {"error": ...} shape every other failure here does.
        return {"error": type(e).__name__, "message": str(e)}
    except UnicodeDecodeError as e:
        return {"error": "UnicodeDecodeError", "message": str(e)}
    return _check_migration_sql(sql)


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
