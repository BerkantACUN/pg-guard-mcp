"""
Pre-flight read-only query validation.

IMPORTANT: this module is the *second* line of defense, not the first. The
real boundary is that db.py always executes queries through Postgres's
extended query protocol, which cannot run more than one statement per call
no matter what string is submitted — see db.py's module docstring. This
module exists to reject an obviously dangerous query early, with a clear
error, instead of relying on protocol behaviour alone.

It works by masking out everything that cannot affect statement structure —
string literals, quoted identifiers, dollar-quoted bodies, and comments —
before looking for statement-separating semicolons or dangerous keywords.
This is what lets `WHERE message = 'a; DROP TABLE users;'` pass (the
semicolons are just data) while `SELECT 1; DROP TABLE users;` is rejected
(that semicolon is a real statement boundary).
"""

from __future__ import annotations

import re

__all__ = ["UnsafeQueryError", "validate_readonly_query"]


class UnsafeQueryError(ValueError):
    """Raised when a query is not a single, plain read-only statement."""


# A statement is only accepted if it opens with one of these. This alone
# rejects every bare write/DDL/admin statement (INSERT, DROP, GRANT, ...)
# without needing to name each one individually.
_ALLOWED_START_KEYWORDS = {"SELECT", "WITH", "EXPLAIN", "SHOW"}

# Extra defense for dangerous keywords that can appear *inside* an
# otherwise SELECT/WITH-shaped statement: transaction control smuggled
# past the outer wrapper, data-modifying CTEs (`WITH d AS (DELETE ...)`),
# and admin functions callable from a plain SELECT list.
_DANGEROUS_KEYWORDS = [
    "COMMIT", "ROLLBACK", "BEGIN", "SAVEPOINT", "RELEASE",
    "SET", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
    "ALTER", "CREATE", "GRANT", "REVOKE", "VACUUM", "CALL",
    "COPY", "MERGE", "REINDEX", "CLUSTER", "LOCK", "DO",
    "EXECUTE", "PREPARE", "DEALLOCATE", "LISTEN", "NOTIFY",
    "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND", "PG_RELOAD_CONF",
]

_DOLLAR_TAG_RE = re.compile(r"\$[A-Za-z_]*\$")
_LEADING_WORD_RE = re.compile(r"\s*([A-Za-z_][A-Za-z_0-9]*)")
_KEYWORD_RE_CACHE = {
    kw: re.compile(rf"(?<![A-Za-z0-9_]){re.escape(kw)}(?![A-Za-z0-9_])", re.IGNORECASE)
    for kw in _DANGEROUS_KEYWORDS
}


def _mask(sql: str) -> str:
    """Return a string the same length as `sql` with the contents of every
    string literal, quoted identifier, dollar-quoted body, and comment
    replaced by spaces. Everything else is left untouched."""
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]

        if ch == "'":
            # An E'...' / e'...' string uses backslash escapes (\' , \\, ...)
            # in addition to the standard '' doubling. A plain '...' string
            # does not treat backslash specially at all under
            # standard_conforming_strings=on, which has been Postgres's
            # default since 9.1 — so backslash is ignored for those, and a
            # lone "'" always closes them, exactly like Postgres parses it.
            prev = sql[i - 1] if i > 0 else ""
            prev_prev = sql[i - 2] if i > 1 else ""
            is_e_string = prev in ("E", "e") and not (prev_prev.isalnum() or prev_prev == "_")

            out.append(" ")
            i += 1
            while i < n:
                if is_e_string and sql[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                if sql[i] == "'" and i + 1 < n and sql[i + 1] == "'":
                    out.append("  ")
                    i += 2
                    continue
                is_closing = sql[i] == "'"
                out.append(" ")
                i += 1
                if is_closing:
                    break
            continue

        if ch == '"':
            out.append(" ")
            i += 1
            while i < n and sql[i] != '"':
                out.append(" ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue

        if sql[i:i + 2] == "--":
            while i < n and sql[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if sql[i:i + 2] == "/*":
            out.append("  ")
            i += 2
            while i < n and sql[i:i + 2] != "*/":
                out.append(" ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue

        if ch == "$":
            tag_match = _DOLLAR_TAG_RE.match(sql, i)
            if tag_match:
                tag = tag_match.group(0)
                out.append(" " * len(tag))
                i += len(tag)
                end = sql.find(tag, i)
                if end == -1:
                    out.append(" " * (n - i))
                    i = n
                else:
                    out.append(" " * (end - i))
                    out.append(" " * len(tag))
                    i = end + len(tag)
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def _split_statements(sql: str, masked: str) -> list[tuple[str, str]]:
    """Split on semicolons that survived masking (i.e. real statement
    separators), returning (original_text, masked_text) pairs so keyword
    checks can run on the masked text while errors can quote the original."""
    pairs: list[tuple[str, str]] = []
    start = 0
    for i, ch in enumerate(masked):
        if ch == ";":
            pairs.append((sql[start:i], masked[start:i]))
            start = i + 1
    pairs.append((sql[start:], masked[start:]))
    return pairs


def validate_readonly_query(sql: str) -> None:
    """Raise UnsafeQueryError unless `sql` is exactly one plain read-only
    statement (SELECT / WITH / EXPLAIN / SHOW) with no transaction-control
    or write/DDL/admin keywords anywhere in it. Returns None if it's fine."""
    if not sql or not sql.strip():
        raise UnsafeQueryError("Empty query.")

    masked = _mask(sql)
    statements = [
        (orig, masked_stmt)
        for orig, masked_stmt in _split_statements(sql, masked)
        if masked_stmt.strip()
    ]

    if not statements:
        raise UnsafeQueryError("Empty query.")

    if len(statements) > 1:
        raise UnsafeQueryError(
            f"Multiple statements are not allowed (found {len(statements)}). "
            "Submit exactly one read-only statement per call."
        )

    original, masked_stmt = statements[0]

    leading = _LEADING_WORD_RE.match(masked_stmt)
    first_word = leading.group(1).upper() if leading else ""
    if first_word not in _ALLOWED_START_KEYWORDS:
        raise UnsafeQueryError(
            f"Statement must start with SELECT, WITH, EXPLAIN, or SHOW — "
            f"found '{first_word or original.strip()[:30]}'."
        )

    for keyword, pattern in _KEYWORD_RE_CACHE.items():
        if pattern.search(masked_stmt):
            raise UnsafeQueryError(
                f"Query contains a disallowed keyword: {keyword}. "
                "Only plain read-only SELECT/WITH/EXPLAIN/SHOW statements are permitted."
            )
