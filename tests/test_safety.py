"""
Tests for the pre-execution query safety check.

This is deliberately layer 2 of the defense, not layer 1. Layer 1 (the real
boundary) is that every query is executed through the Postgres *extended*
query protocol, which structurally cannot run more than one statement per
call — see db.py and test_db.py for that proof. This module exists so a
dangerous query is rejected with a clear error *before* it ever reaches the
network, and so an obviously-malicious payload never depends on protocol
subtlety alone to be stopped.

The exact exploit these tests are written against is the one that got the
official @modelcontextprotocol/server-postgres deprecated: wrap the query in
`BEGIN TRANSACTION READ ONLY`, then let the attacker's string smuggle a
`COMMIT;` followed by a write statement, closing the read-only transaction
early. See: https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/
"""

import pytest

from pg_guard_mcp.safety import UnsafeQueryError, validate_readonly_query


class TestObviouslySafeQueries:
    def test_simple_select_is_allowed(self):
        validate_readonly_query("SELECT * FROM users")

    def test_select_with_where_clause_is_allowed(self):
        validate_readonly_query("SELECT id, email FROM users WHERE active = true")

    def test_select_with_join_is_allowed(self):
        validate_readonly_query(
            "SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id"
        )

    def test_select_with_trailing_semicolon_is_allowed(self):
        validate_readonly_query("SELECT * FROM users;")

    def test_select_with_trailing_semicolon_and_whitespace_is_allowed(self):
        validate_readonly_query("SELECT * FROM users;   \n")

    def test_cte_select_is_allowed(self):
        validate_readonly_query(
            "WITH recent AS (SELECT * FROM orders WHERE created_at > now() - interval '1 day') "
            "SELECT * FROM recent"
        )

    def test_explain_select_is_allowed(self):
        validate_readonly_query("EXPLAIN SELECT * FROM users")


class TestTheDatadogExploit:
    """The exact real-world attack that deprecated the official Postgres MCP server."""

    def test_commit_bypass_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SELECT 1; COMMIT; DROP TABLE users;")

    def test_commit_bypass_with_schema_drop_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SELECT 1; COMMIT; DROP SCHEMA public CASCADE;")

    def test_commit_alone_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("COMMIT;")

    def test_rollback_alone_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("ROLLBACK;")

    def test_begin_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("BEGIN; SELECT * FROM users;")

    def test_savepoint_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SAVEPOINT sp1; SELECT * FROM users;")

    def test_release_savepoint_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("RELEASE SAVEPOINT sp1;")

    def test_set_transaction_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SET TRANSACTION READ WRITE; SELECT 1;")


class TestMultiStatementPayloads:
    """Even without transaction-control keywords, a second statement is refused."""

    def test_two_selects_are_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SELECT 1; SELECT 2;")

    def test_select_then_insert_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SELECT * FROM users; INSERT INTO users (id) VALUES (1);")

    def test_select_then_delete_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SELECT * FROM users; DELETE FROM users;")

    def test_semicolon_inside_a_string_literal_is_still_allowed(self):
        # A literal semicolon inside quotes is not a statement boundary.
        validate_readonly_query("SELECT * FROM logs WHERE message = 'a; b; c'")

    def test_semicolon_inside_a_string_literal_followed_by_real_second_statement_is_rejected(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query(
                "SELECT * FROM logs WHERE message = 'a; b'; DROP TABLE logs;"
            )


class TestWriteStatementsAreRejectedEvenAsTheOnlyStatement:
    @pytest.mark.parametrize(
        "sql",
        [
            "INSERT INTO users (id) VALUES (1)",
            "UPDATE users SET active = false",
            "DELETE FROM users",
            "DROP TABLE users",
            "DROP SCHEMA public CASCADE",
            "TRUNCATE users",
            "ALTER TABLE users ADD COLUMN x int",
            "CREATE TABLE evil (id int)",
            "GRANT ALL ON users TO public",
            "REVOKE ALL ON users FROM public",
            "VACUUM users",
            "CALL some_procedure()",
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity",
        ],
    )
    def test_write_or_admin_statement_is_rejected(self, sql):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query(sql)


class TestEscapeStringEdgeCases:
    """Postgres has two incompatible quoting dialects live at once:
    standard '...' strings (backslash is NOT special — the default since
    PG 9.1, standard_conforming_strings=on) and E'...' strings (backslash
    IS an escape character). Getting this wrong in either direction is
    the classic SQL-parser-mismatch bug class. These pin down that the
    masker matches Postgres's real behavior for both."""

    def test_standard_string_backslash_is_not_an_escape(self):
        # Under standard_conforming_strings=on (the default), '...' ends
        # at the first single quote no matter what precedes it — a
        # trailing backslash does NOT protect it. This mirrors real
        # Postgres parsing, so a payload relying on backslash-escaping a
        # standard string is correctly seen as closing early, exposing
        # the rest as real (and here, dangerous) SQL.
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("SELECT * FROM t WHERE x = 'abc\\'; DROP TABLE users; --'")

    def test_e_string_backslash_escaped_quote_stays_inside_the_string(self):
        # E'...' DOES treat backslash as an escape. \' must not be read
        # as the closing quote, or a real semicolon later in the same
        # E-string would be wrongly treated as data by Postgres but as a
        # statement boundary by an unaware masker (a false positive, not
        # a bypass — but still wrong).
        validate_readonly_query(r"SELECT * FROM logs WHERE msg = E'it\'s fine; still one row'")

    def test_e_string_is_case_insensitive(self):
        validate_readonly_query(r"SELECT * FROM logs WHERE msg = e'it\'s fine too'")

    def test_e_string_does_not_falsely_trigger_on_a_column_named_ending_in_e(self):
        # The "is this an E-string" check must not fire just because some
        # unrelated identifier happens to end in e/E right before a
        # genuinely standard string starts.
        validate_readonly_query("SELECT * FROM t WHERE name = 'value'")

    def test_dollar_quoted_body_is_masked(self):
        validate_readonly_query("SELECT $tag$anything; DROP TABLE users;$tag$ AS literal")

    def test_dollar_quoted_body_does_not_end_on_a_different_tag(self):
        validate_readonly_query("SELECT $a$ text with $b$ inside $a$ AS literal")


class TestErrorMessageQuality:
    def test_error_names_the_offending_keyword(self):
        with pytest.raises(UnsafeQueryError, match="DROP"):
            validate_readonly_query("DROP TABLE users")

    def test_error_on_empty_query_is_clear(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("")

    def test_error_on_whitespace_only_query_is_clear(self):
        with pytest.raises(UnsafeQueryError):
            validate_readonly_query("   \n\t  ")
