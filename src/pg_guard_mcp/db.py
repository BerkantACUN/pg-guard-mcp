"""
The real security boundary.

Every query is executed through psycopg's *extended* query protocol
(Parse/Bind/Execute), never the simple query protocol. Postgres's extended
protocol structurally refuses to run more than one statement inside a
single Parse message — that is a server-side wire-protocol rule, enforced
by Postgres itself, not a client-side check that a cleverly-crafted string
could talk its way around.

psycopg only falls back to the simple protocol when `execute()` is called
with `params=None`. `ReadOnlyConnection.query()` always passes params
(defaulting to an empty tuple), which forces the extended-protocol path
even for queries that bind no parameters at all. This is the mechanism
that makes the Datadog-documented exploit against the official
`@modelcontextprotocol/server-postgres` — smuggling `COMMIT;` plus a write
past a `BEGIN TRANSACTION READ ONLY` wrapper — structurally impossible
here: Postgres rejects the multi-statement string before any of it runs.

This is layered with two more independent defenses, so no single mistake
in this file is fatal:
- session layer: `default_transaction_read_only = on` is set right after
  connecting, so even a write that somehow reached Postgres is refused;
- pre-flight layer: `validate_readonly_query()` (safety.py) rejects an
  obviously dangerous query before it's sent at all, with a clear error.

The privilege layer — connecting as a role with write grants revoked — is
enforced by Postgres itself and is the caller's responsibility to set up;
see README.md.
"""

from __future__ import annotations

from types import TracebackType

import psycopg
from psycopg.rows import dict_row

from .safety import validate_readonly_query

DEFAULT_STATEMENT_TIMEOUT_MS = 10_000
DEFAULT_ROW_LIMIT = 1_000


class ReadOnlyConnection:
    """A single-use, read-only-enforced Postgres connection. Use as a
    context manager: `with ReadOnlyConnection(dsn) as conn: conn.query(...)`."""

    def __init__(
        self,
        dsn: str,
        *,
        statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
        row_limit: int = DEFAULT_ROW_LIMIT,
    ) -> None:
        self._dsn = dsn
        self._statement_timeout_ms = statement_timeout_ms
        self._row_limit = row_limit
        self._conn: psycopg.Connection | None = None

    def __enter__(self) -> "ReadOnlyConnection":
        self._conn = psycopg.connect(self._dsn, row_factory=dict_row, autocommit=True)
        with self._conn.cursor() as cur:
            # Session layer: belt-and-suspenders even if a write somehow
            # reached Postgres despite the protocol and pre-flight layers.
            cur.execute("SET default_transaction_read_only = on", ())
            # SET does not accept a bind parameter for this value (it's a
            # utility statement, not a regular query) — coerce through
            # int() first so there's nothing to inject even though this
            # particular string is built with an f-string.
            cur.execute(f"SET statement_timeout = {int(self._statement_timeout_ms)}", ())
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def query(self, sql: str, params: tuple | list | None = None) -> list[dict]:
        if self._conn is None:
            raise RuntimeError("ReadOnlyConnection must be used as a context manager")

        # Pre-flight layer: reject obviously dangerous input with a clear,
        # specific error before it ever reaches the network.
        validate_readonly_query(sql)

        with self._conn.cursor() as cur:
            # Protocol layer — the real boundary. Passing params, even an
            # empty tuple, forces psycopg's extended query protocol, which
            # Postgres refuses to run more than one statement through.
            cur.execute(sql, params if params is not None else ())
            return cur.fetchmany(self._row_limit)
