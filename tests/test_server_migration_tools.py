"""Integration tests for the migration-safety MCP tools specifically.

Deliberately a separate file from test_server.py: those tests need a live
Postgres connection and are skipped without one, but pg_check_migration_safety
and pg_check_migration_file never touch the database at all — they should
run (and be meaningful) even with no database configured anywhere."""

import time
from pathlib import Path

import pg_guard_mcp.server as server_module


class TestPgCheckMigrationSafety:
    def test_flags_a_real_unsafe_migration(self):
        result = server_module.pg_check_migration_safety(
            "CREATE INDEX idx_users_email ON users (email);"
        )
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "PGGUARD-M01" in rule_ids
        assert result["finding_count"] == len(result["findings"])

    def test_safe_migration_has_no_findings(self):
        result = server_module.pg_check_migration_safety(
            "CREATE INDEX CONCURRENTLY idx_users_email ON users (email);"
        )
        assert result["findings"] == []
        assert result["finding_count"] == 0

    def test_never_touches_a_database_connection(self, monkeypatch):
        # No PG_GUARD_DSN, no PGDATABASE, nothing — if this tool touched
        # the database it would raise a connection error, not return
        # findings.
        monkeypatch.delenv("PG_GUARD_DSN", raising=False)
        monkeypatch.delenv("PGDATABASE", raising=False)
        result = server_module.pg_check_migration_safety(
            "ALTER TABLE users ADD COLUMN age int NOT NULL;"
        )
        assert "PGGUARD-M05" in {f["rule_id"] for f in result["findings"]}

    def test_oversized_content_is_a_typed_error(self):
        oversized = "-- " + ("x" * (server_module._MAX_MIGRATION_BYTES + 1))
        result = server_module.pg_check_migration_safety(oversized)
        assert result["error"] == "MigrationTooLarge"


class TestPgCheckMigrationFile:
    def test_reads_and_checks_a_real_file(self, tmp_path):
        migration_file = tmp_path / "001_add_index.sql"
        migration_file.write_text(
            "CREATE INDEX idx_users_email ON users (email);", encoding="utf-8"
        )
        result = server_module.pg_check_migration_file(str(migration_file))
        assert result["finding_count"] > 0

    def test_missing_file_is_a_typed_error(self):
        result = server_module.pg_check_migration_file("does-not-exist.sql")
        assert result["error"] == "FileNotFoundError"

    def test_oversized_file_is_rejected_before_being_read(self, tmp_path):
        migration_file = tmp_path / "huge.sql"
        migration_file.write_bytes(b"-- " + b"x" * server_module._MAX_MIGRATION_BYTES)
        result = server_module.pg_check_migration_file(str(migration_file))
        assert result["error"] == "MigrationTooLarge"

    def test_non_utf8_file_is_a_typed_error_not_a_crash(self, tmp_path):
        migration_file = tmp_path / "binary.sql"
        migration_file.write_bytes(b"\xff\xfe\x00\x01not utf-8")
        result = server_module.pg_check_migration_file(str(migration_file))
        assert result["error"] == "UnicodeDecodeError"

    def test_no_containment_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PG_GUARD_MIGRATIONS_DIR", raising=False)
        migration_file = tmp_path / "outside.sql"
        migration_file.write_text("CREATE INDEX idx ON t (c);", encoding="utf-8")
        result = server_module.pg_check_migration_file(str(migration_file))
        assert "error" not in result

    def test_path_inside_configured_migrations_dir_is_allowed(self, tmp_path, monkeypatch):
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        migration_file = migrations_dir / "001_add_index.sql"
        migration_file.write_text("CREATE INDEX idx ON t (c);", encoding="utf-8")
        monkeypatch.setenv("PG_GUARD_MIGRATIONS_DIR", str(migrations_dir))
        result = server_module.pg_check_migration_file(str(migration_file))
        assert "error" not in result
        assert result["finding_count"] > 0

    def test_path_outside_configured_migrations_dir_is_rejected(self, tmp_path, monkeypatch):
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        outside_file = tmp_path / "outside.sql"
        outside_file.write_text("CREATE INDEX idx ON t (c);", encoding="utf-8")
        monkeypatch.setenv("PG_GUARD_MIGRATIONS_DIR", str(migrations_dir))
        result = server_module.pg_check_migration_file(str(outside_file))
        assert result["error"] == "PathOutsideMigrationsDir"

    def test_traversal_out_of_the_migrations_dir_is_rejected(self, tmp_path, monkeypatch):
        migrations_dir = tmp_path / "migrations"
        migrations_dir.mkdir()
        secret_file = tmp_path / "secret.sql"
        secret_file.write_text("CREATE INDEX idx ON t (c);", encoding="utf-8")
        monkeypatch.setenv("PG_GUARD_MIGRATIONS_DIR", str(migrations_dir))
        traversal_path = str(migrations_dir / ".." / "secret.sql")
        result = server_module.pg_check_migration_file(traversal_path)
        assert result["error"] == "PathOutsideMigrationsDir"


class TestUncPathRejection:
    """Regression coverage for a real finding: a UNC path can force an
    outbound SMB/NTLM authentication attempt merely from a stat()/
    is_file() call — a well-known Windows "forced authentication"
    primitive — and a security review measured ~21s hung against a
    single unreachable address before returning. These must be rejected
    before any Path method ever touches the string, not just eventually
    time out."""

    def test_backslash_unc_path_is_rejected_immediately(self):
        start = time.monotonic()
        result = server_module.pg_check_migration_file(r"\\192.0.2.2\share\migration.sql")
        elapsed = time.monotonic() - start
        assert result["error"] == "UnsupportedPath"
        assert elapsed < 1.0, f"took {elapsed:.2f}s — may have touched the filesystem/network"

    def test_forward_slash_unc_path_is_also_rejected(self):
        result = server_module.pg_check_migration_file("//192.0.2.2/share/migration.sql")
        assert result["error"] == "UnsupportedPath"

    def test_extended_length_unc_prefix_is_rejected(self):
        result = server_module.pg_check_migration_file(
            r"\\?\UNC\192.0.2.2\share\migration.sql"
        )
        assert result["error"] == "UnsupportedPath"

    def test_single_leading_backslash_is_not_mistaken_for_unc(self):
        from pg_guard_mcp.server import _looks_like_unc_path

        assert not _looks_like_unc_path(r"\folder\file.sql")

    def test_ordinary_local_path_is_not_mistaken_for_unc(self):
        from pg_guard_mcp.server import _looks_like_unc_path

        assert not _looks_like_unc_path(r"C:\migrations\001_add_index.sql")


class TestPermissionDeniedFileIsATypedError:
    """Regression coverage for a real finding: is_file() only swallows a
    narrow set of OSError codes internally and re-raises the rest —
    PermissionError included. A security review confirmed a permission-
    denied path crashed this tool with an unhandled exception when
    is_file() sat outside the try/except block. Simulated via monkeypatch
    rather than real ACLs so this test is reliable regardless of which
    account/privilege level runs the suite."""

    def test_permission_error_from_is_file_is_a_typed_error_not_a_crash(
        self, tmp_path, monkeypatch
    ):
        migration_file = tmp_path / "denied.sql"
        migration_file.write_text("CREATE INDEX idx ON t (c);", encoding="utf-8")
        real_is_file = Path.is_file

        def _is_file_denies_this_one_path(self):
            if self == migration_file:
                raise PermissionError(13, "Access is denied")
            return real_is_file(self)

        monkeypatch.setattr(Path, "is_file", _is_file_denies_this_one_path)
        result = server_module.pg_check_migration_file(str(migration_file))
        assert result["error"] == "PermissionError"
