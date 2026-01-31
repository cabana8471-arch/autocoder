#!/usr/bin/env python3
"""
Project Detach/Reattach Module
==============================

Manages the separation of Autocoder files from project directories,
allowing Claude Code to run without restrictions on completed projects.

Features:
- Detach: Moves Autocoder files to .autocoder-backup/
- Reattach: Restores files from backup
- Status: Checks detach state and backup info
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from registry import get_project_path, list_registered_projects

# Module logger
logger = logging.getLogger(__name__)

# Backup directory name
BACKUP_DIR = ".autocoder-backup"
PRE_REATTACH_BACKUP_DIR = ".pre-reattach-backup"
MANIFEST_FILE = "manifest.json"
DETACH_LOCK = ".autocoder-detach.lock"

# Version for manifest format
MANIFEST_VERSION = 1

# Lock file timeout in seconds (5 minutes)
LOCK_TIMEOUT_SECONDS = 300


def get_autocoder_version() -> str:
    """Get autocoder version from pyproject.toml, with fallback."""
    try:
        pyproject_path = Path(__file__).parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
                version = data.get("project", {}).get("version", "1.0.0")
                return str(version) if version is not None else "1.0.0"
    except Exception:
        pass
    return "1.0.0"  # Fallback


# Autocoder file patterns to detect and move
# Directories (will be moved recursively)
AUTOCODER_DIRECTORIES = {
    ".autocoder",
    "prompts",
    ".playwright-mcp",
}

# Files with exact names
AUTOCODER_FILES = {
    "features.db",
    "features.db-shm",  # SQLite shared memory file
    "features.db-wal",  # SQLite write-ahead log
    "assistant.db",
    "assistant.db-shm",  # SQLite shared memory file
    "assistant.db-wal",  # SQLite write-ahead log
    "CLAUDE.md",
    ".claude_settings.json",
    ".claude_assistant_settings.json",
    ".agent.lock",
    "claude-progress.txt",
}

# Glob patterns for generated files
AUTOCODER_PATTERNS = [
    "test-*.json",
    "test-*.py",
    "test-*.html",
    "test-*.sql",  # SQL test files
    "test-*.php",  # PHP test files
    "create-*-test*.php",  # Test helper scripts (e.g., create-xss-test.php)
    "rollback-*.json",  # Rollback test data
    "generate-*.py",
    "mark_feature*.py",
    ".claude_settings.expand.*.json",
]


class FileEntry(TypedDict):
    """Type for manifest file entry."""
    path: str
    type: str  # "file" or "directory"
    size: int
    checksum: str | None  # MD5 for files, None for directories
    file_count: int | None  # Number of files for directories


class Manifest(TypedDict):
    """Type for manifest.json structure."""
    version: int
    detached_at: str
    project_name: str
    autocoder_version: str
    files: list[FileEntry]
    total_size_bytes: int
    file_count: int


def compute_file_checksum(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute checksum for a file using specified algorithm.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ("sha256" or "md5")

    Returns:
        Hex digest of the file checksum
    """
    if algorithm == "md5":
        hasher = hashlib.md5()
    else:
        hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_checksum(file_path: Path, expected: str) -> bool:
    """Verify file checksum with algorithm auto-detection (SHA-256 vs MD5).

    Detects algorithm by checksum length: MD5=32 hex chars, SHA-256=64 hex chars.
    This provides backward compatibility with older backups using MD5.

    Args:
        file_path: Path to the file to verify
        expected: Expected checksum value

    Returns:
        True if checksum matches, False otherwise
    """
    # Detect algorithm by checksum length: MD5=32 hex chars, SHA-256=64 hex chars
    if len(expected) == 32:
        actual = compute_file_checksum(file_path, algorithm="md5")
    else:
        actual = compute_file_checksum(file_path, algorithm="sha256")
    return actual == expected


def get_directory_info(dir_path: Path) -> tuple[int, int]:
    """Get total size and file count for a directory."""
    total_size = 0
    file_count = 0
    for item in dir_path.rglob("*"):
        if item.is_file():
            total_size += item.stat().st_size
            file_count += 1
    return total_size, file_count


def get_autocoder_files(project_dir: Path, include_artifacts: bool = True) -> list[Path]:
    """
    Detect all Autocoder files in a project directory.

    Args:
        project_dir: Path to the project directory
        include_artifacts: Whether to include .playwright-mcp and other artifacts

    Returns:
        List of Path objects for Autocoder files/directories
    """
    files = []

    # Check directories
    for dir_name in AUTOCODER_DIRECTORIES:
        if not include_artifacts and dir_name == ".playwright-mcp":
            continue
        dir_path = project_dir / dir_name
        if dir_path.exists():
            files.append(dir_path)

    # Check exact files
    for file_name in AUTOCODER_FILES:
        file_path = project_dir / file_name
        if file_path.exists():
            files.append(file_path)

    # Check glob patterns
    for pattern in AUTOCODER_PATTERNS:
        for match in project_dir.glob(pattern):
            if match.exists() and match not in files:
                files.append(match)

    return sorted(files, key=lambda p: p.name)


def is_project_detached(project_dir: Path) -> bool:
    """Check if a project is currently detached."""
    manifest_path = project_dir / BACKUP_DIR / MANIFEST_FILE
    return manifest_path.exists()


def has_backup(project_dir: Path) -> bool:
    """Check if a backup exists for a project."""
    return is_project_detached(project_dir)


def get_backup_info(project_dir: Path) -> Manifest | None:
    """
    Get manifest info from backup if it exists.

    Returns:
        Manifest dict or None if no backup exists
    """
    manifest_path = project_dir / BACKUP_DIR / MANIFEST_FILE
    if not manifest_path.exists():
        return None

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data: Manifest = json.load(f)
            return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read manifest: %s", e)
        return None


def acquire_detach_lock(project_dir: Path) -> bool:
    """
    Acquire lock for detach operations using atomic file creation.

    Uses O_CREAT|O_EXCL for atomic lock creation to prevent TOCTOU race conditions.
    Writes PID and timestamp to lock file for stale lock detection.

    Returns:
        True if lock acquired, False if already locked
    """
    lock_file = project_dir / DETACH_LOCK

    def try_atomic_create() -> bool:
        """Attempt atomic lock file creation. Returns True if successful."""
        try:
            fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                lock_data = {
                    "pid": os.getpid(),
                    "timestamp": datetime.now(timezone.utc).timestamp(),
                }
                os.write(fd, json.dumps(lock_data).encode("utf-8"))
            finally:
                os.close(fd)
            return True
        except FileExistsError:
            return False
        except OSError as e:
            logger.error("Failed to create lock file: %s", e)
            return False

    # First attempt
    if try_atomic_create():
        return True

    # Lock exists - check if stale/corrupted
    try:
        lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
        lock_pid = lock_data.get("pid")
        lock_time = lock_data.get("timestamp", 0)

        if lock_pid is not None:
            try:
                os.kill(lock_pid, 0)  # Check if process exists
                # Process exists, check timeout
                elapsed = datetime.now(timezone.utc).timestamp() - lock_time
                if elapsed < LOCK_TIMEOUT_SECONDS:
                    return False  # Valid lock held by another process
                logger.warning("Removing stale lock (timeout): pid=%s", lock_pid)
            except OSError:
                # Process doesn't exist - stale lock
                logger.warning("Removing stale lock (dead process): pid=%s", lock_pid)
    except (json.JSONDecodeError, OSError, KeyError):
        logger.warning("Removing corrupted lock file")

    # Remove stale/corrupted lock and retry once
    try:
        lock_file.unlink()
    except OSError:
        pass

    return try_atomic_create()


def release_detach_lock(project_dir: Path) -> None:
    """Release detach operation lock."""
    lock_file = project_dir / DETACH_LOCK
    lock_file.unlink(missing_ok=True)


def create_backup(
    project_dir: Path,
    project_name: str,
    files: list[Path],
    dry_run: bool = False
) -> Manifest:
    """
    Create backup of Autocoder files.

    Uses copy-then-delete approach to prevent data loss on partial failures.

    Args:
        project_dir: Path to project directory
        project_name: Name of the project
        files: List of files/directories to backup
        dry_run: If True, only simulate the operation

    Returns:
        Manifest describing the backup
    """
    backup_dir = project_dir / BACKUP_DIR

    # Build manifest
    manifest_files: list[FileEntry] = []
    total_size = 0
    total_file_count = 0

    for file_path in files:
        relative_path = file_path.relative_to(project_dir)

        if file_path.is_dir():
            size, count = get_directory_info(file_path)
            manifest_files.append({
                "path": str(relative_path),
                "type": "directory",
                "size": size,
                "checksum": None,
                "file_count": count,
            })
            total_size += size
            total_file_count += count
        else:
            size = file_path.stat().st_size
            checksum = compute_file_checksum(file_path) if not dry_run else "dry-run"
            manifest_files.append({
                "path": str(relative_path),
                "type": "file",
                "size": size,
                "checksum": checksum,
                "file_count": None,
            })
            total_size += size
            total_file_count += 1

    manifest: Manifest = {
        "version": MANIFEST_VERSION,
        "detached_at": datetime.now(timezone.utc).isoformat(),
        "project_name": project_name,
        "autocoder_version": get_autocoder_version(),
        "files": manifest_files,
        "total_size_bytes": total_size,
        "file_count": total_file_count,
    }

    if dry_run:
        return manifest

    # Create backup directory
    backup_dir.mkdir(parents=True, exist_ok=True)
    copied_files: list[Path] = []

    try:
        # Phase 1: Copy files to backup (preserves originals on failure)
        for file_path in files:
            relative_path = file_path.relative_to(project_dir)
            dest_path = backup_dir / relative_path

            # Ensure parent directory exists
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            # Copy file/directory (handle symlinks explicitly)
            if file_path.is_symlink():
                # Preserve symlinks as symlinks
                link_target = os.readlink(file_path)
                dest_path.symlink_to(link_target)
            elif file_path.is_dir():
                shutil.copytree(file_path, dest_path, symlinks=True)
            else:
                shutil.copy2(file_path, dest_path)

            copied_files.append(file_path)
            logger.debug("Copied %s to backup", relative_path)

        # Phase 2: Write manifest (before deleting originals)
        manifest_path = backup_dir / MANIFEST_FILE
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Phase 3: Delete originals (only after successful copy + manifest)
        for file_path in files:
            if file_path.is_dir() and not file_path.is_symlink():
                shutil.rmtree(file_path)
            else:
                file_path.unlink()
            logger.debug("Removed original: %s", file_path.relative_to(project_dir))

    except Exception as e:
        # Cleanup partial backup on failure
        logger.error("Backup failed: %s - cleaning up partial backup", e)
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        raise

    return manifest


def restore_backup(project_dir: Path, verify_checksums: bool = False) -> tuple[bool, int, list[str]]:
    """
    Restore files from backup.

    Uses copy-then-delete approach to prevent data loss on partial failures.
    Detects and backs up conflicting user files before restore.

    Args:
        project_dir: Path to project directory
        verify_checksums: If True, verify file checksums after restore

    Returns:
        Tuple of (success, files_restored, conflicts_backed_up)
    """
    backup_dir = project_dir / BACKUP_DIR
    manifest_path = backup_dir / MANIFEST_FILE
    project_dir_resolved = project_dir.resolve()

    if not manifest_path.exists():
        logger.error("No backup manifest found")
        return False, 0, []

    # Read manifest
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest: Manifest = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read manifest: %s", e)
        return False, 0, []

    # Validate manifest structure
    required_keys = {"version", "files", "detached_at"}
    if not required_keys.issubset(manifest.keys()):
        logger.error("Invalid manifest structure: missing required keys")
        return False, 0, []

    # Check manifest version compatibility
    manifest_version = manifest.get("version", 1)
    if manifest_version > MANIFEST_VERSION:
        logger.error(
            "Manifest version %d not supported (max: %d)",
            manifest_version, MANIFEST_VERSION
        )
        return False, 0, []

    # Detect and backup user files that would be overwritten
    conflicts = detect_conflicts(project_dir, manifest)
    if conflicts:
        backup_conflicts(project_dir, conflicts)
        logger.info("Backed up %d user files to %s", len(conflicts), PRE_REATTACH_BACKUP_DIR)

    # Restore files
    files_restored = 0
    restored_entries: list[FileEntry] = []

    for entry in manifest["files"]:
        src_path = backup_dir / entry["path"]
        dest_path = project_dir / entry["path"]

        # SECURITY: Validate path to prevent path traversal attacks
        try:
            dest_resolved = dest_path.resolve()
            # Ensure the resolved path is within the project directory
            dest_resolved.relative_to(project_dir_resolved)
        except ValueError:
            logger.error("Path traversal detected: %s", entry["path"])
            return False, 0, []

        if not src_path.exists():
            logger.warning("Backup file missing: %s", entry["path"])
            continue

        # Ensure parent directory exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic copy-then-replace: copy to temp, then atomically replace destination
        temp_path: Path | None = None
        try:
            if src_path.is_symlink():
                # Symlinks can be created atomically - remove existing first
                if dest_path.exists() or dest_path.is_symlink():
                    dest_path.unlink()
                link_target = os.readlink(src_path)
                dest_path.symlink_to(link_target)
            elif src_path.is_dir():
                # Directories: copy to temp location, then replace
                temp_fd, temp_path_str = tempfile.mkstemp(
                    dir=dest_path.parent,
                    prefix=f".{dest_path.name}.",
                    suffix=".tmp"
                )
                temp_path = Path(temp_path_str)
                os.close(temp_fd)
                # mkstemp creates a file, but we need a directory
                temp_path.unlink()
                shutil.copytree(src_path, temp_path, symlinks=True)

                # Remove existing destination if needed
                if dest_path.exists():
                    if dest_path.is_dir() and not dest_path.is_symlink():
                        shutil.rmtree(dest_path)
                    else:
                        dest_path.unlink()

                os.replace(temp_path, dest_path)
                temp_path = None  # Successfully moved, no cleanup needed
            else:
                # Files: copy to temp location, then atomically replace
                temp_fd, temp_path_str = tempfile.mkstemp(
                    dir=dest_path.parent,
                    prefix=f".{dest_path.name}.",
                    suffix=".tmp"
                )
                temp_path = Path(temp_path_str)
                os.close(temp_fd)
                shutil.copy2(src_path, temp_path)

                # Atomic replace (removes existing destination automatically for files)
                os.replace(temp_path, dest_path)
                temp_path = None  # Successfully moved, no cleanup needed

        except OSError as e:
            logger.error("Failed to restore %s: %s", entry["path"], e)
            # Clean up temp file/directory on failure
            if temp_path and temp_path.exists():
                try:
                    if temp_path.is_dir():
                        shutil.rmtree(temp_path)
                    else:
                        temp_path.unlink()
                except OSError:
                    pass
            return False, files_restored, conflicts

        # Verify checksum if requested and available
        entry_checksum = entry.get("checksum")
        if verify_checksums and entry_checksum and entry["type"] == "file":
            if not verify_checksum(dest_path, entry_checksum):
                logger.error(
                    "Checksum mismatch for %s: expected %s",
                    entry["path"], entry["checksum"]
                )
                return False, files_restored, conflicts

        if entry["type"] == "directory":
            files_restored += entry.get("file_count") or 0
        else:
            files_restored += 1

        restored_entries.append(entry)
        logger.debug("Restored %s", entry["path"])

    # Only remove backup directory if ALL files were restored
    expected_count = len(manifest["files"])
    restored_count = len(restored_entries)

    if restored_count == expected_count:
        shutil.rmtree(backup_dir)
        logger.info("Backup directory removed after successful restore")
    else:
        logger.warning(
            "Partial restore: %d/%d files - backup preserved",
            restored_count, expected_count
        )

    return True, files_restored, conflicts


def update_gitignore(project_dir: Path) -> None:
    """Add backup directories to .gitignore if not already present."""
    gitignore_path = project_dir / ".gitignore"

    patterns = [
        (f"{BACKUP_DIR}/", "Autocoder backup (for reattach)"),
        (f"{PRE_REATTACH_BACKUP_DIR}/", "User files backup (for detach)"),
    ]

    if gitignore_path.exists():
        content = gitignore_path.read_text(encoding="utf-8")
        lines = content.splitlines()

        for pattern, comment in patterns:
            if not any(line.strip() == pattern for line in lines):
                with open(gitignore_path, "a", encoding="utf-8") as f:
                    f.write(f"\n# {comment}\n{pattern}\n")
                logger.info("Added %s to .gitignore", pattern)
    else:
        entries = "\n".join(f"# {comment}\n{pattern}" for pattern, comment in patterns)
        gitignore_path.write_text(entries + "\n", encoding="utf-8")
        logger.info("Created .gitignore with backup entries")


def detect_conflicts(project_dir: Path, manifest: Manifest) -> list[str]:
    """Return list of relative paths that exist in both backup and project.

    These are files the user created/modified after detaching that would
    be overwritten by restoring autocoder files.

    Args:
        project_dir: Path to the project directory
        manifest: The backup manifest containing file entries

    Returns:
        List of relative path strings for conflicting files
    """
    conflicts = []
    for entry in manifest["files"]:
        dest = project_dir / entry["path"]
        if dest.exists():
            conflicts.append(entry["path"])
    return conflicts


def backup_conflicts(project_dir: Path, conflicts: list[str]) -> Path:
    """Backup conflicting user files to .pre-reattach-backup/ before restore.

    If backup dir already exists, merges new conflicts (doesn't overwrite).

    Args:
        project_dir: Path to the project directory
        conflicts: List of relative paths to backup

    Returns:
        Path to the backup directory
    """
    backup_dir = project_dir / PRE_REATTACH_BACKUP_DIR
    backup_dir.mkdir(parents=True, exist_ok=True)

    for rel_path in conflicts:
        src = project_dir / rel_path
        dest = backup_dir / rel_path

        # Don't overwrite existing backups (merge mode)
        if dest.exists():
            logger.debug("Skipping existing backup: %s", rel_path)
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)

        if src.is_dir():
            shutil.copytree(src, dest, symlinks=True)
        else:
            shutil.copy2(src, dest)

        logger.debug("Backed up user file: %s", rel_path)

    return backup_dir


def restore_pre_reattach_backup(project_dir: Path) -> int:
    """Restore user files from .pre-reattach-backup/ after detaching.

    Includes path traversal protection.

    Args:
        project_dir: Path to the project directory

    Returns:
        Number of files restored
    """
    backup_dir = project_dir / PRE_REATTACH_BACKUP_DIR
    if not backup_dir.exists():
        return 0

    project_dir_resolved = project_dir.resolve()
    files_restored = 0

    for item in backup_dir.rglob("*"):
        if item.is_file():
            rel_path = item.relative_to(backup_dir)
            dest = project_dir / rel_path

            # SECURITY: Path traversal protection
            try:
                dest.resolve().relative_to(project_dir_resolved)
            except ValueError:
                logger.error("Path traversal detected in pre-reattach backup: %s", rel_path)
                continue  # Skip malicious path

            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest)
            files_restored += 1
            logger.debug("Restored user file: %s", rel_path)

    # Clean up backup directory after successful restore
    shutil.rmtree(backup_dir)
    logger.info("Removed %s after restoring %d files", PRE_REATTACH_BACKUP_DIR, files_restored)

    return files_restored


def detach_project(
    name_or_path: str,
    force: bool = False,
    include_artifacts: bool = True,
    dry_run: bool = False
) -> tuple[bool, str, Manifest | None, int]:
    """
    Detach a project by moving Autocoder files to backup.

    Args:
        name_or_path: Project name (from registry) or absolute path
        force: Skip confirmations
        include_artifacts: Include .playwright-mcp and other artifacts
        dry_run: Only simulate, don't actually move files

    Returns:
        Tuple of (success, message, manifest, user_files_restored)
    """
    # Resolve project path
    project_dir = get_project_path(name_or_path)
    if project_dir is None:
        # Try as path
        project_dir = Path(name_or_path)
        if not project_dir.exists():
            return False, f"Project '{name_or_path}' not found in registry and path doesn't exist", None, 0

    project_dir = Path(project_dir).resolve()
    project_name = name_or_path

    # Check if already detached
    if is_project_detached(project_dir):
        return False, "Project is already detached. Use --reattach to restore.", None, 0

    # Check for agent lock
    agent_lock = project_dir / ".agent.lock"
    if agent_lock.exists() and not force:
        return False, "Agent is currently running. Stop the agent first or use --force.", None, 0

    # Acquire detach lock
    if not dry_run and not acquire_detach_lock(project_dir):
        return False, "Another detach operation is in progress.", None, 0

    try:
        # Get files to move
        files = get_autocoder_files(project_dir, include_artifacts)
        if not files:
            return False, "No Autocoder files found in project.", None, 0

        # Create backup
        manifest = create_backup(project_dir, project_name, files, dry_run)

        # Update .gitignore
        if not dry_run:
            update_gitignore(project_dir)

        # Restore user files from pre-reattach backup if exists
        user_files_restored = 0
        if not dry_run:
            user_files_restored = restore_pre_reattach_backup(project_dir)

        action = "Would move" if dry_run else "Moved"
        message = f"{action} {manifest['file_count']} files ({manifest['total_size_bytes'] / 1024 / 1024:.1f} MB) to backup"
        if user_files_restored > 0:
            message += f", restored {user_files_restored} user files"

        return True, message, manifest, user_files_restored

    finally:
        if not dry_run:
            release_detach_lock(project_dir)


def reattach_project(name_or_path: str) -> tuple[bool, str, int, list[str]]:
    """
    Reattach a project by restoring Autocoder files from backup.

    Args:
        name_or_path: Project name (from registry) or absolute path

    Returns:
        Tuple of (success, message, files_restored, conflicts_backed_up)
    """
    # Resolve project path
    project_dir = get_project_path(name_or_path)
    if project_dir is None:
        project_dir = Path(name_or_path)
        if not project_dir.exists():
            return False, f"Project '{name_or_path}' not found in registry and path doesn't exist", 0, []

    project_dir = Path(project_dir).resolve()

    # Check for agent lock - don't reattach while agent is running
    agent_lock = project_dir / ".agent.lock"
    if agent_lock.exists():
        return False, "Agent is currently running. Stop the agent first.", 0, []

    # Check if backup exists
    if not has_backup(project_dir):
        return False, "No backup found. Project is not detached.", 0, []

    # Acquire detach lock
    if not acquire_detach_lock(project_dir):
        return False, "Another detach operation is in progress.", 0, []

    try:
        success, files_restored, conflicts = restore_backup(project_dir)
        if success:
            if conflicts:
                return True, f"Restored {files_restored} files. {len(conflicts)} user files saved to {PRE_REATTACH_BACKUP_DIR}/", files_restored, conflicts
            return True, f"Restored {files_restored} files from backup", files_restored, []
        else:
            return False, "Failed to restore backup", 0, []
    finally:
        release_detach_lock(project_dir)


def get_detach_status(name_or_path: str) -> dict:
    """
    Get detach status for a project.

    Args:
        name_or_path: Project name (from registry) or absolute path

    Returns:
        Dict with status information
    """
    project_dir = get_project_path(name_or_path)
    if project_dir is None:
        project_dir = Path(name_or_path)
        if not project_dir.exists():
            return {
                "is_detached": False,
                "backup_exists": False,
                "error": f"Project '{name_or_path}' not found",
            }

    project_dir = Path(project_dir).resolve()
    is_detached = is_project_detached(project_dir)
    manifest = get_backup_info(project_dir) if is_detached else None

    return {
        "is_detached": is_detached,
        "backup_exists": is_detached,
        "backup_size": manifest["total_size_bytes"] if manifest else None,
        "detached_at": manifest["detached_at"] if manifest else None,
        "file_count": manifest["file_count"] if manifest else None,
    }


def list_projects_with_status() -> list[dict]:
    """
    List all registered projects with their detach status.

    Returns:
        List of project dicts with name, path, and is_detached
    """
    projects = list_registered_projects()
    result = []

    for name, info in projects.items():
        project_dir = Path(info["path"])
        if project_dir.exists():
            result.append({
                "name": name,
                "path": info["path"],
                "is_detached": is_project_detached(project_dir),
            })

    return sorted(result, key=lambda p: p["name"])


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Detach/Reattach Autocoder files from projects",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detach.py my-project              # Detach project
  python detach.py --reattach my-project   # Reattach project
  python detach.py --status my-project     # Check status
  python detach.py --list                  # List all projects with status
  python detach.py --dry-run my-project    # Preview detach operation
        """,
    )

    parser.add_argument(
        "project",
        nargs="?",
        help="Project name (from registry) or path",
    )
    parser.add_argument(
        "--reattach",
        action="store_true",
        help="Reattach project (restore files from backup)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show detach status for project",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all projects with detach status",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would happen without making changes",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmations and safety checks",
    )

    # Mutually exclusive artifact options
    artifact_group = parser.add_mutually_exclusive_group()
    artifact_group.add_argument(
        "--include-artifacts",
        dest="include_artifacts",
        action="store_true",
        default=True,
        help="Include artifacts (.playwright-mcp, screenshots) in backup (default)",
    )
    artifact_group.add_argument(
        "--no-artifacts",
        dest="include_artifacts",
        action="store_false",
        help="Exclude artifacts from backup",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    try:
        args = parser.parse_args()
    except SystemExit:
        return 1

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        # Handle --list
        if args.list:
            projects = list_projects_with_status()
            if not projects:
                print("No projects registered.")
                return 0

            print("\nRegistered Projects:")
            print("-" * 60)
            for p in projects:
                status_text = "DETACHED" if p["is_detached"] else "attached"
                print(f"  [{status_text:8}] {p['name']}")
                print(f"            {p['path']}")
            print()
            return 0

        # All other commands require a project
        if not args.project:
            parser.print_help()
            return 1

        # Handle --status
        if args.status:
            status_info = get_detach_status(args.project)
            if "error" in status_info:
                print(f"Error: {status_info['error']}")
                return 1

            print(f"\nProject: {args.project}")
            print("-" * 40)
            if status_info["is_detached"]:
                print("  Status: DETACHED")
                print(f"  Detached at: {status_info['detached_at']}")
                backup_size = status_info['backup_size']
                if backup_size is not None:
                    print(f"  Backup size: {backup_size / 1024 / 1024:.1f} MB")
                print(f"  Files in backup: {status_info['file_count']}")
            else:
                print("  Status: attached (Autocoder files present)")
            print()
            return 0

        # Handle --reattach
        if args.reattach:
            print(f"\nReattaching project: {args.project}")
            success, message, files_restored, conflicts = reattach_project(args.project)
            print(f"  {message}")
            if conflicts:
                print(f"  ⚠ {len(conflicts)} user files backed up to {PRE_REATTACH_BACKUP_DIR}/")
                for f in conflicts[:5]:
                    print(f"      - {f}")
                if len(conflicts) > 5:
                    print(f"      ... and {len(conflicts) - 5} more")
            return 0 if success else 1

        # Handle detach (default)
        if args.dry_run:
            print(f"\nDRY RUN - Previewing detach for: {args.project}")
        else:
            print(f"\nDetaching project: {args.project}")

        success, message, manifest, user_files_restored = detach_project(
            args.project,
            force=args.force,
            include_artifacts=args.include_artifacts,
            dry_run=args.dry_run,
        )

        print(f"  {message}")
        if user_files_restored > 0:
            print(f"  ✓ Restored {user_files_restored} user files from previous session")

        if manifest and args.dry_run:
            print("\n  Files to be moved:")
            for entry in manifest["files"]:
                size_str = f"{entry['size'] / 1024:.1f} KB"
                if entry["type"] == "directory":
                    print(f"    [DIR] {entry['path']} ({entry['file_count']} files, {size_str})")
                else:
                    print(f"    [FILE] {entry['path']} ({size_str})")

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n\nOperation cancelled.")
        return 130  # Standard exit code for Ctrl+C


if __name__ == "__main__":
    sys.exit(main())
