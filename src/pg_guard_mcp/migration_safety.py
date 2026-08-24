"""
Migration safety linting: static analysis of DDL statements for the
lock/downtime/breakage patterns that cause real production incidents when
run against a table that already has traffic. This is the same rule class
as Squawk (https://squawkhq.com), strong_migrations (the Rails/Ruby gem),
and Braintree's "Safe Operations For High Volume PostgreSQL" guide — none
of which exist as an MCP tool an agent can call while it's drafting or
about to run a migration, which is the gap this closes.

This module never touches a database connection — it's pure text analysis
of the SQL, reusing the same literal/comment-masking and statement-
splitting logic safety.py already hardened (see mask_sql/split_sql_statements
there), so `ALTER TABLE users ADD COLUMN note text DEFAULT 'NOT NULL'`
doesn't false-positive on the word "NOT NULL" sitting inside a string
literal, and `ALTER TABLE users ADD CONSTRAINT "fk_user" FOREIGN KEY ...`
(a quoted identifier, masked to blank the same way a string literal is)
doesn't silently fail to match either — every identifier placeholder below
degrades to "zero or more non-space characters," not "one or more," for
exactly this reason: a masked-blank quoted name still needs the surrounding
keyword structure to match.

A multi-action ALTER TABLE (`ADD COLUMN a int NOT NULL DEFAULT 0,
ADD COLUMN b text NOT NULL`) is split on its top-level commas — depth-
tracked, so a comma inside `CHECK (a > 0, b > 0)` isn't mistaken for an
action separator — and each action is checked independently. This matters
for correctness, not just precision: without it, a DEFAULT on one action
or a NOT VALID on a sibling FOREIGN KEY would satisfy that rule's "is the
safety keyword present anywhere in the statement" check and silently hide
a genuinely unsafe action right next to it.

Known limitation: this is regex-based pattern matching, not a real SQL
parser. It reasons about lexical shape, not semantics — e.g. PGGUARD-M04
can't tell a rewrite-triggering type change from a binary-coercible one
that skips the rewrite, so it flags ALTER COLUMN TYPE generally and says
so in the finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .safety import mask_sql, split_sql_statements

__all__ = ["MigrationFinding", "check_migration_safety"]


@dataclass(frozen=True)
class MigrationFinding:
    rule_id: str
    severity: str
    message: str
    statement: str  # the original (unmasked) SQL text that triggered it

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "statement": self.statement.strip(),
        }


# An identifier placeholder that tolerates being masked to all-blank (a
# quoted identifier — `"fk_user"` — is masked exactly like a string
# literal: quotes and contents alike become spaces, same length). \S*
# (zero or more), not \S+ (one or more): a real unquoted identifier still
# matches as before, but a masked-blank one degrades to matching zero
# characters instead of failing the whole pattern outright.
_ID = r"\S*"

# --- CREATE INDEX without CONCURRENTLY -------------------------------------
#
# A plain CREATE INDEX takes a SHARE lock on the table for the entire index
# build — reads still work, but every INSERT/UPDATE/DELETE blocks until it
# finishes, which can be minutes on a large table. CONCURRENTLY builds the
# index without that lock (PostgreSQL's own CREATE INDEX docs describe this
# trade-off directly); Squawk's require-concurrent-index-creation rule
# exists for exactly this pattern.
_CREATE_INDEX_RE = re.compile(
    r"^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?", re.IGNORECASE
)

# --- ALTER TABLE and its sub-clauses ----------------------------------------
_ALTER_TABLE_RE = re.compile(
    r"^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?[\w.\"]+", re.IGNORECASE
)

# Adding a FOREIGN KEY constraint validates every existing row in both
# tables by default, under a lock that blocks writes on both, for however
# long that scan takes. `ADD CONSTRAINT ... NOT VALID` skips the scan (the
# constraint just isn't enforced yet), and a follow-up `VALIDATE CONSTRAINT`
# does the same scan later under a much lighter lock. PostgreSQL's own
# ALTER TABLE docs document this pattern directly.
_ADD_FK_RE = re.compile(
    rf"\bADD\s+(?:CONSTRAINT\s+{_ID}\s+)?FOREIGN\s+KEY\b", re.IGNORECASE
)
_NOT_VALID_RE = re.compile(r"\bNOT\s+VALID\b", re.IGNORECASE)

# Same story for CHECK constraints: they also validate every existing row
# under lock by default, and also support NOT VALID + a later VALIDATE
# CONSTRAINT to split that cost out from under the lock. (EXCLUDE
# constraints are deliberately not covered here — unlike CHECK and FOREIGN
# KEY, NOT VALID's applicability to EXCLUDE constraints isn't something
# this project has verified confidently enough to recommend.)
_ADD_CHECK_RE = re.compile(
    rf"\bADD\s+(?:CONSTRAINT\s+{_ID}\s+)?CHECK\s*\(", re.IGNORECASE
)

# Adding a UNIQUE or PRIMARY KEY constraint directly builds a unique index
# while holding a lock that blocks writes — the safe sequence is
# `CREATE UNIQUE INDEX CONCURRENTLY` first, then
# `ALTER TABLE ... ADD CONSTRAINT ... UNIQUE USING INDEX <name>`, which
# attaches the already-built index near-instantly. PostgreSQL's ALTER TABLE
# docs list `USING INDEX index_name` for exactly this purpose.
_ADD_UNIQUE_OR_PK_RE = re.compile(
    rf"\bADD\s+(?:CONSTRAINT\s+{_ID}\s+)?(?:UNIQUE|PRIMARY\s+KEY)\b", re.IGNORECASE
)
_USING_INDEX_RE = re.compile(r"\bUSING\s+INDEX\b", re.IGNORECASE)

# Changing a column's type generally rewrites the entire table (and
# rebuilds every index on it) under an ACCESS EXCLUSIVE lock — the small
# set of binary-coercible exceptions (e.g. widening a varchar's length)
# don't, but telling those apart from the general case needs real type
# semantics, not a regex, so this flags ALTER COLUMN TYPE generally and
# says so.
_ALTER_COLUMN_TYPE_RE = re.compile(
    rf"\bALTER\s+COLUMN\s+{_ID}\s+(?:SET\s+DATA\s+)?TYPE\b", re.IGNORECASE
)

# ADD COLUMN ... NOT NULL with no DEFAULT doesn't just lock — it fails
# outright the moment the table has any existing rows, since Postgres has
# no value to backfill them with.
#
# This only needs to answer "is this action an ADD of a column, as opposed
# to an ADD CONSTRAINT/UNIQUE/PRIMARY KEY/FOREIGN KEY/CHECK/EXCLUDE" — it
# never needs to actually capture the column's name, so unlike the other
# rules there's nothing here for a masked-blank quoted name to break: the
# negative lookahead is a zero-width assertion, satisfied or not
# regardless of what (if anything) follows it.
_ADD_COLUMN_RE = re.compile(
    r"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?!CONSTRAINT\b|UNIQUE\b|PRIMARY\b|FOREIGN\b|CHECK\b|EXCLUDE\b)",
    re.IGNORECASE,
)
_NOT_NULL_RE = re.compile(r"\bNOT\s+NULL\b", re.IGNORECASE)
_DEFAULT_RE = re.compile(r"\bDEFAULT\b", re.IGNORECASE)

# RENAME (column or table) isn't a locking/performance problem — it's a
# backward-compatibility break. Application code from the previous deploy
# that's still running (a rolling deploy, a long-lived connection pool)
# references the old name and starts failing the instant this commits.
_RENAME_RE = re.compile(rf"\bRENAME\s+(?:COLUMN\s+{_ID}\s+TO\s+{_ID}|TO\s+{_ID})", re.IGNORECASE)


def _split_top_level_commas(masked: str) -> list[tuple[int, int]]:
    """Return (start, end) index spans for each top-level, paren-depth-0
    comma-separated segment of `masked` — the individual actions of a
    multi-action ALTER TABLE. A comma inside parens (`CHECK (a > 0, b >
    0)`, a column list) is depth > 0 and not a split point. Masking has
    already blanked out commas inside string/identifier literals, so
    those never reach here as real commas either."""
    spans: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for i, ch in enumerate(masked):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
    spans.append((start, len(masked)))
    return spans


def _check_create_index(original: str, masked: str) -> MigrationFinding | None:
    match = _CREATE_INDEX_RE.match(masked)
    if match is None:
        return None
    if match.group(1):  # CONCURRENTLY was present
        return None
    return MigrationFinding(
        rule_id="PGGUARD-M01",
        severity="high",
        message=(
            "CREATE INDEX without CONCURRENTLY holds a lock that blocks writes to "
            "this table for the entire index build — minutes or more on a large "
            "table. Use CREATE INDEX CONCURRENTLY instead (note: it can't run "
            "inside a transaction block, and a failed run leaves an invalid index "
            "behind that needs a manual DROP INDEX)."
        ),
        statement=original,
    )


def _check_alter_table_action(
    statement_original: str, action_original: str, action_masked: str
) -> list[MigrationFinding]:
    """Check a single action of an ALTER TABLE statement — one element of
    its top-level comma-separated list, or the whole statement when it
    only has one action. `statement_original` (the full statement) is
    what's quoted back in the finding, since that's what someone would
    actually need to find and fix; `action_original`/`action_masked` are
    what the rule logic reads, so a safety keyword on a different action
    in the same statement can't satisfy this one's check."""
    findings: list[MigrationFinding] = []
    action_snippet = action_original.strip()

    if _ADD_FK_RE.search(action_masked) and not _NOT_VALID_RE.search(action_masked):
        findings.append(
            MigrationFinding(
                rule_id="PGGUARD-M02",
                severity="high",
                message=(
                    f"ADD CONSTRAINT ... FOREIGN KEY (in `{action_snippet}`) validates "
                    "every existing row in both tables under a lock that blocks writes "
                    "on both, for the duration of that scan. Add it with NOT VALID, "
                    "then validate separately with ALTER TABLE ... VALIDATE CONSTRAINT "
                    "... (a much lighter lock) once the constraint is in place."
                ),
                statement=statement_original,
            )
        )

    if _ADD_CHECK_RE.search(action_masked) and not _NOT_VALID_RE.search(action_masked):
        findings.append(
            MigrationFinding(
                rule_id="PGGUARD-M07",
                severity="high",
                message=(
                    f"ADD CONSTRAINT ... CHECK (in `{action_snippet}`) validates every "
                    "existing row under a lock that blocks writes, for the duration of "
                    "that scan. Add it with NOT VALID, then validate separately with "
                    "ALTER TABLE ... VALIDATE CONSTRAINT ... (a much lighter lock) once "
                    "the constraint is in place."
                ),
                statement=statement_original,
            )
        )

    if _ADD_UNIQUE_OR_PK_RE.search(action_masked) and not _USING_INDEX_RE.search(action_masked):
        findings.append(
            MigrationFinding(
                rule_id="PGGUARD-M03",
                severity="high",
                message=(
                    f"ADD CONSTRAINT ... UNIQUE/PRIMARY KEY (in `{action_snippet}`) builds "
                    "a unique index while holding a lock that blocks writes. Build the "
                    "index first with CREATE UNIQUE INDEX CONCURRENTLY, then attach it "
                    "near-instantly with ALTER TABLE ... ADD CONSTRAINT ... UNIQUE USING "
                    "INDEX <name>."
                ),
                statement=statement_original,
            )
        )

    if _ALTER_COLUMN_TYPE_RE.search(action_masked):
        findings.append(
            MigrationFinding(
                rule_id="PGGUARD-M04",
                severity="medium",
                message=(
                    f"ALTER COLUMN ... TYPE (in `{action_snippet}`) generally rewrites "
                    "the entire table (and rebuilds every index on it) under a lock "
                    "that blocks reads and writes both. A handful of type changes are "
                    "binary-coercible and skip the rewrite (e.g. widening a varchar's "
                    "length) — verify this specific change is one of those before "
                    "assuming it's cheap."
                ),
                statement=statement_original,
            )
        )

    if (
        _ADD_COLUMN_RE.search(action_masked)
        and _NOT_NULL_RE.search(action_masked)
        and not _DEFAULT_RE.search(action_masked)
    ):
        findings.append(
            MigrationFinding(
                rule_id="PGGUARD-M05",
                severity="critical",
                message=(
                    f"ADD COLUMN ... NOT NULL with no DEFAULT (in `{action_snippet}`) "
                    "will fail outright the moment this table has any existing rows — "
                    "Postgres has no value to backfill them with. Add a DEFAULT, or add "
                    "the column nullable and backfill it before a separate migration "
                    "adds the NOT NULL constraint."
                ),
                statement=statement_original,
            )
        )

    if _RENAME_RE.search(action_masked):
        findings.append(
            MigrationFinding(
                rule_id="PGGUARD-M06",
                severity="high",
                message=(
                    f"RENAME (in `{action_snippet}`) breaks any application code from "
                    "the previous deploy that's still running and references the old "
                    "name — not a locking issue, a rolling-deploy correctness issue. "
                    "Prefer add-new / dual-write / drop-old over an in-place rename."
                ),
                statement=statement_original,
            )
        )

    return findings


def _check_alter_table(original: str, masked: str) -> list[MigrationFinding]:
    if _ALTER_TABLE_RE.match(masked) is None:
        return []

    findings: list[MigrationFinding] = []
    for start, end in _split_top_level_commas(masked):
        findings.extend(
            _check_alter_table_action(original, original[start:end], masked[start:end])
        )
    return findings


def check_migration_safety(sql: str) -> list[MigrationFinding]:
    """Run every migration-safety rule against each statement in `sql` and
    return every finding, in the order the statements appear. An empty
    list means no known-unsafe pattern was found — see this module's
    docstring for what "known" does and doesn't cover."""
    if not sql or not sql.strip():
        return []

    masked = mask_sql(sql)
    findings: list[MigrationFinding] = []
    for original, masked_stmt in split_sql_statements(sql, masked):
        if not masked_stmt.strip():
            continue

        index_finding = _check_create_index(original, masked_stmt)
        if index_finding is not None:
            findings.append(index_finding)

        findings.extend(_check_alter_table(original, masked_stmt))

    return findings
