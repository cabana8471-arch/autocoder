#!/usr/bin/env python3
"""
Unit tests for detach.py module.

Tests cover:
- File detection patterns
- Backup creation and manifest
- Restore functionality
- Edge cases (locked projects, missing backups, etc.)
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import detach


class TestGetAutocoderFiles(unittest.TestCase):
    """Tests for get_autocoder_files function."""

    def setUp(self):
        """Create temporary project directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_detects_autocoder_directory(self):
        """Should detect .autocoder directory."""
        (self.project_dir / ".autocoder").mkdir()
        files = detach.get_autocoder_files(self.project_dir)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, ".autocoder")

    def test_detects_prompts_directory(self):
        """Should detect prompts directory."""
        (self.project_dir / "prompts").mkdir()
        files = detach.get_autocoder_files(self.project_dir)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "prompts")

    def test_detects_features_db(self):
        """Should detect features.db file."""
        (self.project_dir / "features.db").touch()
        files = detach.get_autocoder_files(self.project_dir)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "features.db")

    def test_detects_claude_md(self):
        """Should detect CLAUDE.md file."""
        (self.project_dir / "CLAUDE.md").touch()
        files = detach.get_autocoder_files(self.project_dir)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "CLAUDE.md")

    def test_detects_glob_patterns(self):
        """Should detect files matching glob patterns."""
        (self.project_dir / "test-login.json").touch()
        (self.project_dir / "test-api.py").touch()
        (self.project_dir / "generate-data.py").touch()
        files = detach.get_autocoder_files(self.project_dir)
        self.assertEqual(len(files), 3)
        names = {f.name for f in files}
        self.assertIn("test-login.json", names)
        self.assertIn("test-api.py", names)
        self.assertIn("generate-data.py", names)

    def test_detects_sqlite_wal_files(self):
        """Should detect SQLite WAL companion files."""
        (self.project_dir / "features.db").touch()
        (self.project_dir / "features.db-shm").write_bytes(b"\x00" * 32768)
        (self.project_dir / "features.db-wal").touch()
        (self.project_dir / "assistant.db").touch()
        (self.project_dir / "assistant.db-shm").write_bytes(b"\x00" * 32768)
        (self.project_dir / "assistant.db-wal").touch()
        files = detach.get_autocoder_files(self.project_dir)
        names = {f.name for f in files}
        self.assertIn("features.db", names)
        self.assertIn("features.db-shm", names)
        self.assertIn("features.db-wal", names)
        self.assertIn("assistant.db", names)
        self.assertIn("assistant.db-shm", names)
        self.assertIn("assistant.db-wal", names)
        self.assertEqual(len(files), 6)

    def test_detects_sql_test_files(self):
        """Should detect test-*.sql files."""
        (self.project_dir / "test-feature153-create-page.sql").touch()
        (self.project_dir / "test-database-migration.sql").touch()
        files = detach.get_autocoder_files(self.project_dir)
        names = {f.name for f in files}
        self.assertIn("test-feature153-create-page.sql", names)
        self.assertIn("test-database-migration.sql", names)
        self.assertEqual(len(files), 2)

    def test_detects_php_test_files(self):
        """Should detect test-*.php files."""
        (self.project_dir / "test-feature28-create-page.php").touch()
        (self.project_dir / "test-api-endpoint.php").touch()
        files = detach.get_autocoder_files(self.project_dir)
        names = {f.name for f in files}
        self.assertIn("test-feature28-create-page.php", names)
        self.assertIn("test-api-endpoint.php", names)
        self.assertEqual(len(files), 2)

    def test_detects_test_helper_php_files(self):
        """Should detect create-*-test*.php helper scripts."""
        (self.project_dir / "create-xss-direct-test.php").touch()
        (self.project_dir / "create-xss-test-page.php").touch()
        (self.project_dir / "create-csrf-test.php").touch()
        files = detach.get_autocoder_files(self.project_dir)
        names = {f.name for f in files}
        self.assertIn("create-xss-direct-test.php", names)
        self.assertIn("create-xss-test-page.php", names)
        self.assertIn("create-csrf-test.php", names)
        self.assertEqual(len(files), 3)

    def test_detects_rollback_json_files(self):
        """Should detect rollback-*.json files."""
        (self.project_dir / "rollback-test-translated.json").touch()
        (self.project_dir / "rollback-migration-v2.json").touch()
        files = detach.get_autocoder_files(self.project_dir)
        names = {f.name for f in files}
        self.assertIn("rollback-test-translated.json", names)
        self.assertIn("rollback-migration-v2.json", names)
        self.assertEqual(len(files), 2)

    def test_excludes_artifacts_when_disabled(self):
        """Should exclude .playwright-mcp when include_artifacts=False."""
        (self.project_dir / ".playwright-mcp").mkdir()
        (self.project_dir / "features.db").touch()

        # With artifacts
        files_with = detach.get_autocoder_files(self.project_dir, include_artifacts=True)
        names_with = {f.name for f in files_with}
        self.assertIn(".playwright-mcp", names_with)

        # Without artifacts
        files_without = detach.get_autocoder_files(self.project_dir, include_artifacts=False)
        names_without = {f.name for f in files_without}
        self.assertNotIn(".playwright-mcp", names_without)
        self.assertIn("features.db", names_without)

    def test_returns_empty_for_non_autocoder_project(self):
        """Should return empty list for projects without Autocoder files."""
        (self.project_dir / "src").mkdir()
        (self.project_dir / "package.json").touch()
        files = detach.get_autocoder_files(self.project_dir)
        self.assertEqual(len(files), 0)

    def test_returns_sorted_results(self):
        """Should return files sorted by name."""
        (self.project_dir / "prompts").mkdir()
        (self.project_dir / ".autocoder").mkdir()
        (self.project_dir / "features.db").touch()
        files = detach.get_autocoder_files(self.project_dir)
        names = [f.name for f in files]
        self.assertEqual(names, sorted(names))


class TestBackupCreation(unittest.TestCase):
    """Tests for create_backup function."""

    def setUp(self):
        """Create temporary project with Autocoder files."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

        # Create Autocoder files
        (self.project_dir / ".autocoder").mkdir()
        (self.project_dir / ".autocoder" / "config.yaml").write_text("test: true")
        (self.project_dir / "prompts").mkdir()
        (self.project_dir / "prompts" / "app_spec.txt").write_text("spec content")
        (self.project_dir / "features.db").write_bytes(b"SQLite database")

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_creates_backup_directory(self):
        """Should create .autocoder-backup directory."""
        files = detach.get_autocoder_files(self.project_dir)
        detach.create_backup(self.project_dir, "test-project", files)

        backup_dir = self.project_dir / detach.BACKUP_DIR
        self.assertTrue(backup_dir.exists())

    def test_moves_files_to_backup(self):
        """Should move all files to backup directory."""
        files = detach.get_autocoder_files(self.project_dir)
        detach.create_backup(self.project_dir, "test-project", files)

        backup_dir = self.project_dir / detach.BACKUP_DIR

        # Original locations should be gone
        self.assertFalse((self.project_dir / ".autocoder").exists())
        self.assertFalse((self.project_dir / "prompts").exists())
        self.assertFalse((self.project_dir / "features.db").exists())

        # Backup locations should exist
        self.assertTrue((backup_dir / ".autocoder").exists())
        self.assertTrue((backup_dir / "prompts").exists())
        self.assertTrue((backup_dir / "features.db").exists())

    def test_creates_manifest(self):
        """Should create manifest.json with correct structure."""
        files = detach.get_autocoder_files(self.project_dir)
        manifest = detach.create_backup(self.project_dir, "test-project", files)

        # Check manifest structure
        self.assertEqual(manifest["version"], detach.MANIFEST_VERSION)
        self.assertEqual(manifest["project_name"], "test-project")
        self.assertIn("detached_at", manifest)
        self.assertIn("files", manifest)
        self.assertIn("total_size_bytes", manifest)
        self.assertIn("file_count", manifest)

        # Check manifest file exists
        manifest_path = self.project_dir / detach.BACKUP_DIR / detach.MANIFEST_FILE
        self.assertTrue(manifest_path.exists())

    def test_manifest_contains_checksums(self):
        """Should include checksums for files."""
        files = detach.get_autocoder_files(self.project_dir)
        manifest = detach.create_backup(self.project_dir, "test-project", files)

        for entry in manifest["files"]:
            if entry["type"] == "file":
                self.assertIsNotNone(entry["checksum"])
            else:
                self.assertIsNone(entry["checksum"])

    def test_dry_run_does_not_move_files(self):
        """Dry run should not move files or create backup."""
        files = detach.get_autocoder_files(self.project_dir)
        manifest = detach.create_backup(self.project_dir, "test-project", files, dry_run=True)

        # Original files should still exist
        self.assertTrue((self.project_dir / ".autocoder").exists())
        self.assertTrue((self.project_dir / "prompts").exists())
        self.assertTrue((self.project_dir / "features.db").exists())

        # Backup should not exist
        backup_dir = self.project_dir / detach.BACKUP_DIR
        self.assertFalse(backup_dir.exists())

        # Manifest should still be returned
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest["project_name"], "test-project")


class TestBackupRestore(unittest.TestCase):
    """Tests for restore_backup function."""

    def setUp(self):
        """Create temporary project with backup."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

        # Create Autocoder files and backup them
        (self.project_dir / ".autocoder").mkdir()
        (self.project_dir / ".autocoder" / "config.yaml").write_text("test: true")
        (self.project_dir / "prompts").mkdir()
        (self.project_dir / "prompts" / "app_spec.txt").write_text("spec content")
        (self.project_dir / "features.db").write_bytes(b"SQLite database")

        files = detach.get_autocoder_files(self.project_dir)
        detach.create_backup(self.project_dir, "test-project", files)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_restores_files_from_backup(self):
        """Should restore all files from backup."""
        success, files_restored = detach.restore_backup(self.project_dir)

        self.assertTrue(success)
        self.assertEqual(files_restored, 3)  # .autocoder, prompts, features.db

        # Files should be restored
        self.assertTrue((self.project_dir / ".autocoder").exists())
        self.assertTrue((self.project_dir / "prompts").exists())
        self.assertTrue((self.project_dir / "features.db").exists())

    def test_removes_backup_after_restore(self):
        """Should remove backup directory after successful restore."""
        detach.restore_backup(self.project_dir)

        backup_dir = self.project_dir / detach.BACKUP_DIR
        self.assertFalse(backup_dir.exists())

    def test_restores_file_contents(self):
        """Should restore correct file contents."""
        detach.restore_backup(self.project_dir)

        config_content = (self.project_dir / ".autocoder" / "config.yaml").read_text()
        self.assertEqual(config_content, "test: true")

        spec_content = (self.project_dir / "prompts" / "app_spec.txt").read_text()
        self.assertEqual(spec_content, "spec content")

    def test_fails_without_backup(self):
        """Should fail gracefully if no backup exists."""
        # Remove backup
        shutil.rmtree(self.project_dir / detach.BACKUP_DIR)

        success, files_restored = detach.restore_backup(self.project_dir)
        self.assertFalse(success)
        self.assertEqual(files_restored, 0)


class TestDetachStatus(unittest.TestCase):
    """Tests for status checking functions."""

    def setUp(self):
        """Create temporary project directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_is_project_detached_false(self):
        """Should return False for non-detached project."""
        (self.project_dir / "features.db").touch()
        self.assertFalse(detach.is_project_detached(self.project_dir))

    def test_is_project_detached_true(self):
        """Should return True for detached project."""
        backup_dir = self.project_dir / detach.BACKUP_DIR
        backup_dir.mkdir()
        (backup_dir / detach.MANIFEST_FILE).write_text("{}")
        self.assertTrue(detach.is_project_detached(self.project_dir))

    def test_has_backup(self):
        """Should correctly detect backup existence."""
        self.assertFalse(detach.has_backup(self.project_dir))

        backup_dir = self.project_dir / detach.BACKUP_DIR
        backup_dir.mkdir()
        (backup_dir / detach.MANIFEST_FILE).write_text("{}")

        self.assertTrue(detach.has_backup(self.project_dir))

    def test_get_backup_info(self):
        """Should return manifest info when backup exists."""
        backup_dir = self.project_dir / detach.BACKUP_DIR
        backup_dir.mkdir()

        manifest = {
            "version": 1,
            "project_name": "test",
            "total_size_bytes": 1000,
            "file_count": 5,
        }
        (backup_dir / detach.MANIFEST_FILE).write_text(json.dumps(manifest))

        info = detach.get_backup_info(self.project_dir)
        self.assertIsNotNone(info)
        self.assertEqual(info["project_name"], "test")
        self.assertEqual(info["total_size_bytes"], 1000)

    def test_get_backup_info_returns_none_without_backup(self):
        """Should return None when no backup exists."""
        info = detach.get_backup_info(self.project_dir)
        self.assertIsNone(info)


class TestDetachProject(unittest.TestCase):
    """Tests for detach_project function."""

    def setUp(self):
        """Create temporary project with Autocoder files."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

        # Create Autocoder files
        (self.project_dir / ".autocoder").mkdir()
        (self.project_dir / "features.db").touch()
        (self.project_dir / "prompts").mkdir()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    @patch('detach.get_project_path')
    def test_detach_by_path(self, mock_get_path):
        """Should detach project by path."""
        mock_get_path.return_value = None

        success, message, manifest = detach.detach_project(str(self.project_dir))

        self.assertTrue(success)
        self.assertIn("files", message)
        self.assertIsNotNone(manifest)

    @patch('detach.get_project_path')
    def test_detach_by_name(self, mock_get_path):
        """Should detach project by registry name."""
        mock_get_path.return_value = self.project_dir

        success, message, manifest = detach.detach_project("test-project")

        self.assertTrue(success)
        self.assertIsNotNone(manifest)

    @patch('detach.get_project_path')
    def test_fails_if_already_detached(self, mock_get_path):
        """Should fail if project is already detached."""
        mock_get_path.return_value = self.project_dir

        # Create backup
        backup_dir = self.project_dir / detach.BACKUP_DIR
        backup_dir.mkdir()
        (backup_dir / detach.MANIFEST_FILE).write_text("{}")

        success, message, manifest = detach.detach_project("test-project")

        self.assertFalse(success)
        self.assertIn("already detached", message)

    @patch('detach.get_project_path')
    def test_fails_if_agent_running(self, mock_get_path):
        """Should fail if agent is running (lock file exists)."""
        mock_get_path.return_value = self.project_dir

        # Create agent lock
        (self.project_dir / ".agent.lock").touch()

        success, message, manifest = detach.detach_project("test-project")

        self.assertFalse(success)
        self.assertIn("Agent is currently running", message)

    @patch('detach.get_project_path')
    def test_force_bypasses_agent_check(self, mock_get_path):
        """Should bypass agent check with force=True."""
        mock_get_path.return_value = self.project_dir

        # Create agent lock
        (self.project_dir / ".agent.lock").touch()

        success, message, manifest = detach.detach_project("test-project", force=True)

        self.assertTrue(success)

    @patch('detach.get_project_path')
    def test_fails_if_no_autocoder_files(self, mock_get_path):
        """Should fail if no Autocoder files found."""
        # Remove Autocoder files
        shutil.rmtree(self.project_dir / ".autocoder")
        (self.project_dir / "features.db").unlink()
        shutil.rmtree(self.project_dir / "prompts")

        mock_get_path.return_value = self.project_dir

        success, message, manifest = detach.detach_project("test-project")

        self.assertFalse(success)
        self.assertIn("No Autocoder files found", message)


class TestReattachProject(unittest.TestCase):
    """Tests for reattach_project function."""

    def setUp(self):
        """Create temporary project with backup."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

        # Create and backup Autocoder files
        (self.project_dir / ".autocoder").mkdir()
        (self.project_dir / "features.db").write_bytes(b"test")

        files = detach.get_autocoder_files(self.project_dir)
        detach.create_backup(self.project_dir, "test-project", files)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    @patch('detach.get_project_path')
    def test_reattach_restores_files(self, mock_get_path):
        """Should restore files from backup."""
        mock_get_path.return_value = self.project_dir

        success, message, files_restored = detach.reattach_project("test-project")

        self.assertTrue(success)
        self.assertGreater(files_restored, 0)
        self.assertTrue((self.project_dir / ".autocoder").exists())
        self.assertTrue((self.project_dir / "features.db").exists())

    @patch('detach.get_project_path')
    def test_reattach_fails_without_backup(self, mock_get_path):
        """Should fail if no backup exists."""
        mock_get_path.return_value = self.project_dir

        # Remove backup
        shutil.rmtree(self.project_dir / detach.BACKUP_DIR)

        success, message, files_restored = detach.reattach_project("test-project")

        self.assertFalse(success)
        self.assertIn("No backup found", message)


class TestGitignoreUpdate(unittest.TestCase):
    """Tests for update_gitignore function."""

    def setUp(self):
        """Create temporary project directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_creates_gitignore_if_missing(self):
        """Should create .gitignore if it doesn't exist."""
        detach.update_gitignore(self.project_dir)

        gitignore = self.project_dir / ".gitignore"
        self.assertTrue(gitignore.exists())
        content = gitignore.read_text()
        self.assertIn(detach.BACKUP_DIR, content)

    def test_appends_to_existing_gitignore(self):
        """Should append to existing .gitignore."""
        gitignore = self.project_dir / ".gitignore"
        gitignore.write_text("node_modules/\n")

        detach.update_gitignore(self.project_dir)

        content = gitignore.read_text()
        self.assertIn("node_modules/", content)
        self.assertIn(detach.BACKUP_DIR, content)

    def test_does_not_duplicate_entry(self):
        """Should not add duplicate entry."""
        gitignore = self.project_dir / ".gitignore"
        gitignore.write_text(f"{detach.BACKUP_DIR}/\n")

        detach.update_gitignore(self.project_dir)

        content = gitignore.read_text()
        # Should only appear once
        self.assertEqual(content.count(detach.BACKUP_DIR), 1)


class TestDetachLock(unittest.TestCase):
    """Tests for detach lock functions."""

    def setUp(self):
        """Create temporary project directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_acquire_lock(self):
        """Should acquire lock successfully."""
        result = detach.acquire_detach_lock(self.project_dir)
        self.assertTrue(result)
        self.assertTrue((self.project_dir / detach.DETACH_LOCK).exists())

    def test_acquire_lock_writes_pid_and_timestamp(self):
        """Should write PID and timestamp to lock file."""
        import os
        detach.acquire_detach_lock(self.project_dir)
        lock_content = json.loads((self.project_dir / detach.DETACH_LOCK).read_text())
        self.assertEqual(lock_content["pid"], os.getpid())
        self.assertIn("timestamp", lock_content)

    def test_acquire_lock_fails_if_locked_by_live_process(self):
        """Should fail to acquire lock if already locked by live process."""
        import os
        # Create lock with current process PID (which is alive)
        lock_data = {"pid": os.getpid(), "timestamp": 9999999999}
        (self.project_dir / detach.DETACH_LOCK).write_text(json.dumps(lock_data))
        result = detach.acquire_detach_lock(self.project_dir)
        self.assertFalse(result)

    def test_acquire_lock_removes_stale_lock_dead_process(self):
        """Should remove stale lock from dead process."""
        # Create lock with non-existent PID
        lock_data = {"pid": 999999999, "timestamp": 9999999999}
        (self.project_dir / detach.DETACH_LOCK).write_text(json.dumps(lock_data))
        result = detach.acquire_detach_lock(self.project_dir)
        self.assertTrue(result)  # Should succeed after removing stale lock

    def test_acquire_lock_removes_corrupted_lock(self):
        """Should remove corrupted lock file."""
        (self.project_dir / detach.DETACH_LOCK).write_text("not valid json")
        result = detach.acquire_detach_lock(self.project_dir)
        self.assertTrue(result)

    def test_release_lock(self):
        """Should release lock successfully."""
        (self.project_dir / detach.DETACH_LOCK).write_text("{}")
        detach.release_detach_lock(self.project_dir)
        self.assertFalse((self.project_dir / detach.DETACH_LOCK).exists())

    def test_release_lock_handles_missing_file(self):
        """Should handle missing lock file gracefully."""
        # Should not raise
        detach.release_detach_lock(self.project_dir)


class TestSecurityPathTraversal(unittest.TestCase):
    """Security tests for path traversal protection."""

    def setUp(self):
        """Create temporary project with backup."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

        # Create backup directory
        backup_dir = self.project_dir / detach.BACKUP_DIR
        backup_dir.mkdir()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_restore_blocks_path_traversal(self):
        """Should reject manifest with path traversal attempt."""
        backup_dir = self.project_dir / detach.BACKUP_DIR

        # Create malicious manifest with path traversal
        manifest = {
            "version": 1,
            "detached_at": "2024-01-01T00:00:00Z",
            "project_name": "malicious",
            "autocoder_version": "1.0.0",
            "files": [
                {
                    "path": "../../../etc/passwd",  # Path traversal attempt
                    "type": "file",
                    "size": 100,
                    "checksum": None,
                    "file_count": None,
                }
            ],
            "total_size_bytes": 100,
            "file_count": 1,
        }
        (backup_dir / detach.MANIFEST_FILE).write_text(json.dumps(manifest))

        # Note: We don't need to create the actual malicious file - the validation
        # catches it during path resolution before attempting to access the source file

        success, _ = detach.restore_backup(self.project_dir)
        self.assertFalse(success)

    def test_restore_blocks_absolute_path(self):
        """Should reject manifest with absolute path."""
        backup_dir = self.project_dir / detach.BACKUP_DIR

        manifest = {
            "version": 1,
            "detached_at": "2024-01-01T00:00:00Z",
            "project_name": "malicious",
            "autocoder_version": "1.0.0",
            "files": [
                {
                    "path": "/etc/passwd",  # Absolute path
                    "type": "file",
                    "size": 100,
                    "checksum": None,
                    "file_count": None,
                }
            ],
            "total_size_bytes": 100,
            "file_count": 1,
        }
        (backup_dir / detach.MANIFEST_FILE).write_text(json.dumps(manifest))

        success, _ = detach.restore_backup(self.project_dir)
        self.assertFalse(success)

    def test_restore_rejects_unsupported_manifest_version(self):
        """Should reject manifest with unsupported version."""
        backup_dir = self.project_dir / detach.BACKUP_DIR

        manifest = {
            "version": 999,  # Future version
            "detached_at": "2024-01-01T00:00:00Z",
            "files": [],
            "total_size_bytes": 0,
            "file_count": 0,
        }
        (backup_dir / detach.MANIFEST_FILE).write_text(json.dumps(manifest))

        success, _ = detach.restore_backup(self.project_dir)
        self.assertFalse(success)

    def test_restore_rejects_invalid_manifest_structure(self):
        """Should reject manifest with missing required keys."""
        backup_dir = self.project_dir / detach.BACKUP_DIR

        # Missing required keys
        manifest = {
            "version": 1,
            # missing "files" and "detached_at"
        }
        (backup_dir / detach.MANIFEST_FILE).write_text(json.dumps(manifest))

        success, _ = detach.restore_backup(self.project_dir)
        self.assertFalse(success)


class TestGitignoreLineMatching(unittest.TestCase):
    """Tests for gitignore line-based matching."""

    def setUp(self):
        """Create temporary project directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_does_not_match_comment(self):
        """Should not match backup dir name in comment."""
        gitignore = self.project_dir / ".gitignore"
        gitignore.write_text(f"# Ignore {detach.BACKUP_DIR} directory\nnode_modules/\n")

        detach.update_gitignore(self.project_dir)

        content = gitignore.read_text()
        # Should have added the actual entry
        lines = [line.strip() for line in content.splitlines()]
        self.assertIn(f"{detach.BACKUP_DIR}/", lines)

    def test_does_not_match_path_substring(self):
        """Should not match backup dir name as substring of path."""
        gitignore = self.project_dir / ".gitignore"
        gitignore.write_text(f"some/path/{detach.BACKUP_DIR}/other\n")

        detach.update_gitignore(self.project_dir)

        content = gitignore.read_text()
        # Should have added the standalone entry
        lines = [line.strip() for line in content.splitlines()]
        self.assertIn(f"{detach.BACKUP_DIR}/", lines)

    def test_matches_exact_entry(self):
        """Should match exact entry and not duplicate."""
        gitignore = self.project_dir / ".gitignore"
        gitignore.write_text(f"{detach.BACKUP_DIR}/\n")

        detach.update_gitignore(self.project_dir)

        content = gitignore.read_text()
        # Should only appear once
        self.assertEqual(content.count(f"{detach.BACKUP_DIR}/"), 1)


class TestBackupAtomicity(unittest.TestCase):
    """Tests for atomic backup operations (copy-then-delete)."""

    def setUp(self):
        """Create temporary project with files."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir)

        # Create Autocoder files (only regular files to test copy2)
        (self.project_dir / "features.db").write_bytes(b"database content")
        (self.project_dir / "CLAUDE.md").write_text("# Test")

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)

    def test_backup_preserves_originals_on_copy_failure(self):
        """Should preserve originals if copy fails."""
        files = detach.get_autocoder_files(self.project_dir)

        # Mock shutil.copy2 to fail on second file
        original_copy2 = shutil.copy2
        call_count = [0]

        def failing_copy2(src, dst):
            call_count[0] += 1
            if call_count[0] > 1:
                raise OSError("Simulated copy failure")
            return original_copy2(src, dst)

        with patch('detach.shutil.copy2', side_effect=failing_copy2):
            with self.assertRaises(OSError):
                detach.create_backup(self.project_dir, "test", files)

        # Original files should still exist
        self.assertTrue((self.project_dir / "CLAUDE.md").exists())
        self.assertTrue((self.project_dir / "features.db").exists())

        # Backup directory should be cleaned up
        self.assertFalse((self.project_dir / detach.BACKUP_DIR).exists())


if __name__ == "__main__":
    unittest.main()
