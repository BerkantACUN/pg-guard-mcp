"""
Tests for migration_safety.py, written directly against the real
production-incident shapes these rules exist to catch: a CREATE INDEX
that locks writes for the whole build, a FOREIGN KEY add that scans both
tables under lock, a NOT NULL column add that fails outright on a
populated table, and similar — the same rule class as Squawk and
strong_migrations.
"""

from pg_guard_mcp.migration_safety import check_migration_safety


def _rule_ids(findings):
    return {f.rule_id for f in findings}


class TestCreateIndexConcurrently_PGGUARDM01:
    def test_plain_create_index_is_flagged(self):
        findings = check_migration_safety("CREATE INDEX idx_users_email ON users (email);")
        assert "PGGUARD-M01" in _rule_ids(findings)

    def test_unique_index_without_concurrently_is_flagged(self):
        findings = check_migration_safety(
            "CREATE UNIQUE INDEX idx_users_email ON users (email);"
        )
        assert "PGGUARD-M01" in _rule_ids(findings)

    def test_concurrently_is_not_flagged(self):
        findings = check_migration_safety(
            "CREATE INDEX CONCURRENTLY idx_users_email ON users (email);"
        )
        assert "PGGUARD-M01" not in _rule_ids(findings)

    def test_unique_concurrently_is_not_flagged(self):
        findings = check_migration_safety(
            "CREATE UNIQUE INDEX CONCURRENTLY idx_users_email ON users (email);"
        )
        assert "PGGUARD-M01" not in _rule_ids(findings)


class TestForeignKeyNotValid_PGGUARDM02:
    def test_add_foreign_key_without_not_valid_is_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id);"
        )
        assert "PGGUARD-M02" in _rule_ids(findings)

    def test_unnamed_foreign_key_is_also_flagged(self):
        # PostgreSQL allows omitting the constraint name entirely.
        findings = check_migration_safety(
            "ALTER TABLE orders ADD FOREIGN KEY (user_id) REFERENCES users (id);"
        )
        assert "PGGUARD-M02" in _rule_ids(findings)

    def test_add_foreign_key_with_not_valid_is_not_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) "
            "REFERENCES users (id) NOT VALID;"
        )
        assert "PGGUARD-M02" not in _rule_ids(findings)


class TestUniqueOrPrimaryKeyUsingIndex_PGGUARDM03:
    def test_add_unique_constraint_without_using_index_is_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE users ADD CONSTRAINT uq_email UNIQUE (email);"
        )
        assert "PGGUARD-M03" in _rule_ids(findings)

    def test_add_primary_key_without_using_index_is_flagged(self):
        findings = check_migration_safety("ALTER TABLE users ADD PRIMARY KEY (id);")
        assert "PGGUARD-M03" in _rule_ids(findings)

    def test_add_unique_constraint_using_a_pre_built_index_is_not_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE users ADD CONSTRAINT uq_email UNIQUE USING INDEX idx_users_email;"
        )
        assert "PGGUARD-M03" not in _rule_ids(findings)


class TestAlterColumnType_PGGUARDM04:
    def test_alter_column_type_is_flagged(self):
        findings = check_migration_safety("ALTER TABLE users ALTER COLUMN age TYPE bigint;")
        assert "PGGUARD-M04" in _rule_ids(findings)

    def test_alter_column_set_data_type_form_is_also_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE users ALTER COLUMN age SET DATA TYPE bigint;"
        )
        assert "PGGUARD-M04" in _rule_ids(findings)

    def test_statement_with_no_alter_column_type_is_not_flagged(self):
        findings = check_migration_safety("ALTER TABLE users ADD COLUMN nickname text;")
        assert "PGGUARD-M04" not in _rule_ids(findings)


class TestAddNotNullColumnWithoutDefault_PGGUARDM05:
    def test_add_not_null_column_without_default_is_flagged(self):
        findings = check_migration_safety("ALTER TABLE users ADD COLUMN age int NOT NULL;")
        assert "PGGUARD-M05" in _rule_ids(findings)

    def test_add_not_null_column_with_default_is_not_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE users ADD COLUMN age int NOT NULL DEFAULT 0;"
        )
        assert "PGGUARD-M05" not in _rule_ids(findings)

    def test_add_nullable_column_is_not_flagged(self):
        findings = check_migration_safety("ALTER TABLE users ADD COLUMN nickname text;")
        assert "PGGUARD-M05" not in _rule_ids(findings)

    def test_add_column_without_explicit_column_keyword_is_still_caught(self):
        # PostgreSQL allows omitting the COLUMN keyword entirely.
        findings = check_migration_safety("ALTER TABLE users ADD age int NOT NULL;")
        assert "PGGUARD-M05" in _rule_ids(findings)

    def test_the_string_literal_not_null_does_not_false_positive(self):
        # The literal text "NOT NULL" inside a string value must not be
        # mistaken for the constraint keyword — this is exactly what
        # mask_sql exists to prevent.
        findings = check_migration_safety(
            "ALTER TABLE users ADD COLUMN status text DEFAULT 'NOT NULL';"
        )
        assert "PGGUARD-M05" not in _rule_ids(findings)


class TestRename_PGGUARDM06:
    def test_rename_column_is_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE users RENAME COLUMN email TO email_address;"
        )
        assert "PGGUARD-M06" in _rule_ids(findings)

    def test_rename_table_is_flagged(self):
        findings = check_migration_safety("ALTER TABLE users RENAME TO app_users;")
        assert "PGGUARD-M06" in _rule_ids(findings)

    def test_statement_with_no_rename_is_not_flagged(self):
        findings = check_migration_safety("ALTER TABLE users ADD COLUMN nickname text;")
        assert "PGGUARD-M06" not in _rule_ids(findings)


class TestQuotedIdentifiers:
    """Regression coverage for a real bug: quoted identifiers are masked
    to blank exactly like string literals, and every rule that needed to
    skip over an identifier token originally used \\S+ (one-or-more) —
    which fails to match anything at all against a masked-blank run,
    silently suppressing the finding entirely. Every one of Rails,
    Django, and Prisma double-quotes identifiers in generated DDL by
    default, so this isn't an edge case."""

    def test_quoted_foreign_key_constraint_name_is_still_flagged(self):
        findings = check_migration_safety(
            'ALTER TABLE orders ADD CONSTRAINT "fk_user" FOREIGN KEY (user_id) '
            "REFERENCES users (id);"
        )
        assert "PGGUARD-M02" in _rule_ids(findings)

    def test_quoted_unique_constraint_name_is_still_flagged(self):
        findings = check_migration_safety(
            'ALTER TABLE users ADD CONSTRAINT "uq_email" UNIQUE (email);'
        )
        assert "PGGUARD-M03" in _rule_ids(findings)

    def test_quoted_column_name_in_alter_column_type_is_still_flagged(self):
        findings = check_migration_safety('ALTER TABLE t ALTER COLUMN "age" TYPE bigint;')
        assert "PGGUARD-M04" in _rule_ids(findings)

    def test_quoted_column_name_in_add_not_null_is_still_flagged(self):
        findings = check_migration_safety('ALTER TABLE t ADD COLUMN "age" int NOT NULL;')
        assert "PGGUARD-M05" in _rule_ids(findings)

    def test_quoted_names_in_rename_column_are_still_flagged(self):
        findings = check_migration_safety(
            'ALTER TABLE users RENAME COLUMN "email" TO "email_address";'
        )
        assert "PGGUARD-M06" in _rule_ids(findings)

    def test_quoted_table_name_in_rename_table_is_still_flagged(self):
        findings = check_migration_safety('ALTER TABLE "users" RENAME TO "app_users";')
        assert "PGGUARD-M06" in _rule_ids(findings)


class TestCheckConstraintNotValid_PGGUARDM07:
    def test_add_check_constraint_without_not_valid_is_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE orders ADD CONSTRAINT chk_amount CHECK (amount > 0);"
        )
        assert "PGGUARD-M07" in _rule_ids(findings)

    def test_add_check_constraint_with_not_valid_is_not_flagged(self):
        findings = check_migration_safety(
            "ALTER TABLE orders ADD CONSTRAINT chk_amount CHECK (amount > 0) NOT VALID;"
        )
        assert "PGGUARD-M07" not in _rule_ids(findings)


class TestMultiActionAlterTableDoesNotMaskSiblingActions:
    """Regression coverage for a real bug: each rule originally searched
    the *entire* statement for its safety keyword, so a DEFAULT on one
    comma-separated action, or a NOT VALID on one sibling constraint,
    satisfied the check for a completely different, genuinely unsafe
    action in the same statement — full suppression, not just imprecise
    location reporting."""

    def test_default_on_one_column_does_not_mask_not_null_on_another(self):
        findings = check_migration_safety(
            "ALTER TABLE t ADD COLUMN a int NOT NULL DEFAULT 0, "
            "ADD COLUMN b text NOT NULL;"
        )
        assert "PGGUARD-M05" in _rule_ids(findings)

    def test_not_valid_on_one_fk_does_not_mask_another_fk_missing_it(self):
        findings = check_migration_safety(
            "ALTER TABLE t ADD CONSTRAINT fk1 FOREIGN KEY (a) REFERENCES t2 (id), "
            "ADD CONSTRAINT fk2 FOREIGN KEY (b) REFERENCES t3 (id) NOT VALID;"
        )
        assert "PGGUARD-M02" in _rule_ids(findings)

    def test_using_index_on_one_constraint_does_not_mask_another_missing_it(self):
        findings = check_migration_safety(
            "ALTER TABLE t ADD CONSTRAINT uq1 UNIQUE (a), "
            "ADD CONSTRAINT pk1 PRIMARY KEY (b) USING INDEX idx_b;"
        )
        assert "PGGUARD-M03" in _rule_ids(findings)

    def test_a_comma_inside_a_check_expression_is_not_a_split_point(self):
        # Must not be treated as two actions — the comma is inside the
        # CHECK's own parens, part of one action's expression.
        findings = check_migration_safety(
            "ALTER TABLE t ADD CONSTRAINT chk CHECK (a > 0 AND (b > 0 OR c > 0)) NOT VALID;"
        )
        assert "PGGUARD-M07" not in _rule_ids(findings)

    def test_fully_safe_multi_action_statement_has_no_findings(self):
        findings = check_migration_safety(
            "ALTER TABLE t ADD COLUMN a int NOT NULL DEFAULT 0, "
            "ADD CONSTRAINT fk1 FOREIGN KEY (a) REFERENCES t2 (id) NOT VALID;"
        )
        assert findings == []


class TestMultipleStatementsAndFindingQuality:
    def test_each_statement_in_a_multi_statement_migration_is_checked(self):
        sql = """
CREATE INDEX idx_users_email ON users (email);
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id);
ALTER TABLE users ADD COLUMN age int NOT NULL;
"""
        findings = check_migration_safety(sql)
        assert _rule_ids(findings) == {"PGGUARD-M01", "PGGUARD-M02", "PGGUARD-M05"}

    def test_a_safe_migration_produces_no_findings(self):
        sql = """
CREATE INDEX CONCURRENTLY idx_users_email ON users (email);
ALTER TABLE users ADD COLUMN nickname text;
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id) NOT VALID;
"""
        assert check_migration_safety(sql) == []

    def test_empty_input_produces_no_findings(self):
        assert check_migration_safety("") == []
        assert check_migration_safety("   ") == []

    def test_a_finding_quotes_the_triggering_statement(self):
        findings = check_migration_safety("CREATE INDEX idx_x ON users (email);")
        assert "idx_x" in findings[0].statement

    def test_to_dict_produces_a_serializable_shape(self):
        findings = check_migration_safety("CREATE INDEX idx_x ON users (email);")
        as_dict = findings[0].to_dict()
        assert set(as_dict) == {"rule_id", "severity", "message", "statement"}
