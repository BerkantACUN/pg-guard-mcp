# pg-guard-mcp

[![PyPI](https://img.shields.io/pypi/v/pg-guard-mcp.svg)](https://pypi.org/project/pg-guard-mcp/)

A PostgreSQL MCP server that enforces read-only access at the **protocol and privilege level** — not by parsing the query string and hoping.

## Install

```bash
pip install pg-guard-mcp
# or, without installing anything permanently:
uvx pg-guard-mcp
```

## Why this exists

The official `@modelcontextprotocol/server-postgres` shipped a read-only mode that a single `COMMIT;` could bypass: it wrapped the agent's query in `BEGIN TRANSACTION READ ONLY` and sent the whole thing as one string. Postgres accepts semicolon-separated multiple statements in that mode, so `SELECT 1; COMMIT; DROP SCHEMA public CASCADE;` closed the read-only transaction early and ran the drop as an ordinary write. The package was deprecated over it. ([Datadog Security Labs writeup](https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/))

pg-guard-mcp exists because that bug class — "read-only" enforced only by string inspection — is still common across the MCP ecosystem. It defends in three independent layers, so no single mistake is fatal:

1. **Protocol layer (the real boundary).** Every query runs through Postgres's *extended* query protocol (`Parse`/`Bind`/`Execute`), never the simple query protocol. The extended protocol structurally rejects more than one statement per `Parse` message — Postgres itself refuses it, before any of our code runs. This is why the Datadog exploit cannot work here regardless of what string is submitted.
2. **Session layer.** Every connection sets `default_transaction_read_only = on` at the session level, so even a query that somehow reached the database as a write is rejected by Postgres.
3. **Pre-flight layer.** Before a query is even sent, it's checked for multiple statements and transaction-control keywords (`COMMIT`, `ROLLBACK`, `BEGIN`, `SAVEPOINT`, ...) and rejected with a clear error. This exists to fail fast and loud, not as the primary defense.

On top of that, connecting with a database role that has had write privileges `REVOKE`d is the recommended (and startup-checked) setup — belt and suspenders at the privilege layer too.

## Tools

| Tool | Does |
|---|---|
| `pg_run_query(sql)` | Run one read-only statement, return rows |
| `pg_explain_query(sql)` | Return the query plan without running it |
| `pg_list_tables(schema="public")` | List tables/views in a schema |
| `pg_describe_table(table_name, schema="public")` | List a table's columns |
| `pg_check_privileges()` | Report any write grant the connected role actually holds — should always come back empty |
| `pg_check_migration_safety(sql)` | Static-check DDL for lock/downtime/breakage patterns *before* anyone runs it — never touches the database |
| `pg_check_migration_file(path)` | Same check, reading the SQL from a file on disk |

### Migration safety linting

An agent asked to "add this migration and run it" is exactly the moment a
`CREATE INDEX` without `CONCURRENTLY` locks writes on a busy table for the
next ten minutes, or an `ADD COLUMN ... NOT NULL` with no default fails
outright the instant it hits a populated table. `pg_check_migration_safety`
and `pg_check_migration_file` catch these *before* they run — pure text
analysis, no database connection involved, so they work with no `PG_GUARD_DSN`
configured at all.

This is the same rule class as [Squawk](https://squawkhq.com) and
[strong_migrations](https://github.com/ankane/strong_migrations), which
exist as standalone linters but not, as far as a deliberate search turned
up, as an MCP tool an agent can call mid-conversation:

| Rule | Catches |
|---|---|
| `PGGUARD-M01` | `CREATE INDEX` without `CONCURRENTLY` — locks writes for the whole build |
| `PGGUARD-M02` | `ADD CONSTRAINT ... FOREIGN KEY` without `NOT VALID` — scans + locks both tables |
| `PGGUARD-M03` | `ADD CONSTRAINT ... UNIQUE`/`PRIMARY KEY` without `USING INDEX` — locks while building the index in place |
| `PGGUARD-M04` | `ALTER COLUMN ... TYPE` — usually rewrites the whole table under an exclusive lock |
| `PGGUARD-M05` | `ADD COLUMN ... NOT NULL` with no `DEFAULT` — fails outright on a populated table |
| `PGGUARD-M06` | `RENAME COLUMN`/`RENAME TABLE` — breaks in-flight app code from a rolling deploy |
| `PGGUARD-M07` | `ADD CONSTRAINT ... CHECK` without `NOT VALID` — scans + locks the table |

This is regex-based pattern matching over one statement at a time, not a
real SQL parser — see `migration_safety.py`'s module docstring for the
exact scope limitation (a single hand-written statement combining several
actions in one comma-separated `ALTER TABLE` is checked as a whole, not
action-by-action; every common migration tool generates one action per
statement by default, so this covers the overwhelming majority of
real-world migrations). An empty findings list means no known-unsafe
pattern was found, not a guarantee.

## Setup

```bash
pip install pg-guard-mcp
export PG_GUARD_DSN="host=127.0.0.1 dbname=mydb user=myapp_readonly password=..."
pg-guard-mcp
```

Point your MCP client at the `pg-guard-mcp` command (or `uvx pg-guard-mcp` to skip a permanent install) with `PG_GUARD_DSN` set in its env config.

See `.env.example` for all supported environment variables, and `scripts/setup_dev_db.sh` for a working example of setting up a properly-restricted read-only role (the setup this project's own tests run against).

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

`tests/test_safety.py` is pure-Python and needs no database. `tests/test_db.py` and `tests/test_server.py` run against a real local PostgreSQL instance — including the exact exploit payload that deprecated the official Postgres MCP server — and skip automatically if `pgguard_test` isn't reachable. Run `scripts/setup_dev_db.sh` once to create it.

## Status

v0.2.0. 99 passing tests (unit + live-Postgres integration, including the exact exploit that deprecated the official server-postgres, run against a fresh `pip install` of the published package) plus 16 DB-dependent tests that skip automatically without a local `pgguard_test` database.

## License

MIT
