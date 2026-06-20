#!/usr/bin/env python3
"""Safe storage statistics, archival, and retention cleanup primitives."""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


CATEGORIES = ("logs", "pcaps", "sessions", "iocs")
PROTECTED_FILES = {"iocs": {"blocked_ips.json", "watchlist.json"}}
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
_CLEANUP_LOCK = threading.Lock()


class StorageError(Exception):
    """Base error for storage management operations."""


class StorageValidationError(StorageError):
    """Raised when a cleanup request is invalid."""


class StorageBusyError(StorageError):
    """Raised when another cleanup operation is already running."""


class StorageConsistencyError(StorageError):
    """Raised when a filesystem/Supabase transaction cannot be completed."""


def human_size(value: int) -> str:
    """Return an IEC-style human-readable byte count."""
    size = float(max(value, 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if size < 1024.0 or unit == "PiB":
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PiB"


@dataclass(frozen=True)
class StorageFile:
    category: str
    root: Path
    path: Path
    relative_path: Path
    size: int
    modified_at: float


@dataclass
class CleanupSelection:
    categories: Tuple[str, ...]
    older_than_days: Optional[int]
    files: List[StorageFile]

    @property
    def total_size(self) -> int:
        return sum(item.size for item in self.files)

    @property
    def folders(self) -> List[str]:
        return sorted({str(item.path.parent) for item in self.files})

    def by_category(self) -> Dict[str, List[StorageFile]]:
        grouped = {category: [] for category in self.categories}
        for item in self.files:
            grouped[item.category].append(item)
        return grouped


@dataclass
class StagedFile:
    source: StorageFile
    staged_path: Path


@dataclass
class CleanupResult:
    files_deleted: int = 0
    folders_cleaned: int = 0
    bytes_freed: int = 0
    duration: float = 0.0
    supabase_rows_deleted: int = 0
    archive_created: bool = False
    archive_path: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_deleted": self.files_deleted,
            "folders_cleaned": self.folders_cleaned,
            "bytes_freed": self.bytes_freed,
            "freed_human": human_size(self.bytes_freed),
            "duration": round(self.duration, 3),
            "supabase_rows_deleted": self.supabase_rows_deleted,
            "archive_created": self.archive_created,
            "archive_path": self.archive_path,
            "errors": self.errors,
        }


class SupabaseCleanup:
    """Delete matching datastore rows with snapshots for compensation."""

    TABLES = {
        "sessions": "honeypot_sessions",
        "iocs": "honeypot_iocs",
    }

    def __init__(self, client: Any, chunk_size: int = 200):
        self.client = client
        self.chunk_size = chunk_size

    @classmethod
    def from_environment(cls) -> Optional["SupabaseCleanup"]:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        if not url or not key:
            return None
        from supabase import create_client

        return cls(create_client(url, key))

    @staticmethod
    def _chunks(values: Sequence[str], size: int) -> Iterable[Sequence[str]]:
        for index in range(0, len(values), size):
            yield values[index : index + size]

    def delete_matching(
        self, files_by_category: Mapping[str, Sequence[StorageFile]]
    ) -> Tuple[int, List[Tuple[str, List[dict]]]]:
        deleted = 0
        snapshots: List[Tuple[str, List[dict]]] = []
        try:
            for category, table in self.TABLES.items():
                names = sorted({item.path.name for item in files_by_category.get(category, [])})
                for chunk in self._chunks(names, self.chunk_size):
                    rows = (
                        self.client.table(table)
                        .select("*")
                        .in_("file_name", list(chunk))
                        .execute()
                    ).data or []
                    snapshots.append((table, list(rows)))
                    if not rows:
                        continue
                    response = (
                        self.client.table(table)
                        .delete()
                        .in_("file_name", list(chunk))
                        .execute()
                    )
                    deleted += len(response.data or rows)
        except Exception as exc:
            self.restore(snapshots)
            raise StorageConsistencyError(
                f"Supabase cleanup failed; remote rows were restored: {exc}"
            ) from exc
        return deleted, snapshots

    def restore(self, snapshots: Sequence[Tuple[str, Sequence[dict]]]) -> None:
        errors = []
        for table, rows in reversed(snapshots):
            if not rows:
                continue
            try:
                self.client.table(table).upsert(list(rows), on_conflict="file_name").execute()
            except Exception as exc:  # pragma: no cover - depends on remote failure mode
                errors.append(f"{table}: {exc}")
        if errors:
            raise StorageConsistencyError(
                "Could not restore Supabase snapshot: " + "; ".join(errors)
            )


class StorageManager:
    """Manage only explicitly approved honeypot storage directories."""

    def __init__(
        self,
        category_roots: Optional[Mapping[str, Sequence[Path]]] = None,
        archive_dir: Optional[Path] = None,
        supabase_cleanup: Optional[SupabaseCleanup] = None,
        audit_logger: Optional[logging.Logger] = None,
    ):
        data_dir = Path(os.getenv("DATA_DIR", str(DEFAULT_DATA_DIR)))
        configured = category_roots or {
            "logs": (Path(os.getenv("LOGS_DIR", "/logs")), data_dir / "logs"),
            "pcaps": (Path(os.getenv("PCAPS_DIR", "/pcaps")), data_dir / "pcaps"),
            "sessions": (
                Path(os.getenv("SESSIONS_DIR", "/sessions")),
                data_dir / "sessions",
            ),
            "iocs": (Path(os.getenv("IOCS_DIR", "/iocs")), data_dir / "iocs"),
        }
        self.category_roots = {
            category: self._deduplicate_roots(configured.get(category, ()))
            for category in CATEGORIES
        }
        self.archive_dir = Path(
            archive_dir or os.getenv("ARCHIVE_DIR", str(data_dir / "archive"))
        )
        self.supabase_cleanup = (
            supabase_cleanup
            if supabase_cleanup is not None
            else SupabaseCleanup.from_environment()
        )
        self.audit_logger = audit_logger or configure_audit_logger(self.archive_dir)

    @staticmethod
    def _deduplicate_roots(roots: Sequence[Path]) -> Tuple[Path, ...]:
        result: List[Path] = []
        seen = set()
        for raw_root in roots:
            root = Path(raw_root).expanduser()
            resolved = root.resolve(strict=False)
            key = os.path.normcase(str(resolved))
            if key not in seen:
                result.append(root)
                seen.add(key)
        return tuple(result)

    @staticmethod
    def _validate_root(root: Path) -> Path:
        if root.is_symlink():
            raise StorageError(f"Storage root may not be a symlink: {root}")
        return root.resolve(strict=False)

    @classmethod
    def _is_within_root(cls, path: Path, root: Path) -> bool:
        try:
            path.resolve(strict=False).relative_to(cls._validate_root(root))
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    def _iter_files(self, category: str) -> Iterable[StorageFile]:
        protected = PROTECTED_FILES.get(category, set())
        for root in self.category_roots[category]:
            if not root.exists():
                continue
            resolved_root = self._validate_root(root)
            if not resolved_root.is_dir():
                continue
            try:
                paths = root.rglob("*")
                for path in paths:
                    try:
                        relative = path.relative_to(root)
                        if any(part.startswith(".cleanup-trash-") for part in relative.parts):
                            continue
                        if path.name in protected:
                            continue
                        if path.is_symlink():
                            # Symlinks are never followed or removed by storage cleanup.
                            continue
                        if not path.is_file() or not self._is_within_root(path, root):
                            continue
                        stat = path.stat()
                        yield StorageFile(
                            category=category,
                            root=root,
                            path=path,
                            relative_path=relative,
                            size=stat.st_size,
                            modified_at=stat.st_mtime,
                        )
                    except (OSError, RuntimeError, ValueError) as exc:
                        self.audit_logger.warning(
                            "storage_scan_skipped path=%s error=%s", path, exc
                        )
            except OSError as exc:
                self.audit_logger.warning(
                    "storage_root_scan_failed root=%s error=%s", root, exc
                )

    @staticmethod
    def parse_categories(categories: Any) -> Tuple[str, ...]:
        if categories is None:
            return CATEGORIES
        if isinstance(categories, str):
            categories = [categories]
        if not isinstance(categories, (list, tuple)) or not categories:
            raise StorageValidationError("categories must be a non-empty list")
        normalized = []
        for category in categories:
            value = str(category).strip().lower()
            if value not in CATEGORIES:
                raise StorageValidationError(f"Unsupported storage category: {value}")
            if value not in normalized:
                normalized.append(value)
        return tuple(normalized)

    @staticmethod
    def parse_older_than_days(value: Any) -> Optional[int]:
        if value is None or (isinstance(value, str) and value.lower() == "all"):
            return None
        if isinstance(value, bool):
            raise StorageValidationError("older_than_days must be a positive integer or 'all'")
        try:
            days = int(value)
        except (TypeError, ValueError) as exc:
            raise StorageValidationError(
                "older_than_days must be a positive integer or 'all'"
            ) from exc
        if days < 1:
            raise StorageValidationError("older_than_days must be at least 1")
        return days

    def select(self, categories: Any, older_than_days: Any) -> CleanupSelection:
        selected_categories = self.parse_categories(categories)
        days = self.parse_older_than_days(older_than_days)
        cutoff = None if days is None else time.time() - (days * 86400)
        files = [
            item
            for category in selected_categories
            for item in self._iter_files(category)
            if cutoff is None or item.modified_at < cutoff
        ]
        return CleanupSelection(selected_categories, days, files)

    def storage_stats(self) -> Dict[str, Any]:
        disk_anchor = next(
            (
                root
                for category in CATEGORIES
                for root in self.category_roots[category]
                if root.exists()
            ),
            self.archive_dir.parent,
        )
        while not disk_anchor.exists() and disk_anchor != disk_anchor.parent:
            disk_anchor = disk_anchor.parent
        usage = shutil.disk_usage(disk_anchor)
        categories = {}
        for category in CATEGORIES:
            files = list(self._iter_files(category))
            size = sum(item.size for item in files)
            categories[category] = {
                "file_count": len(files),
                "size_bytes": size,
                "size_human": human_size(size),
            }
        return {
            "disk": {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_percent": round((usage.used / usage.total) * 100, 2)
                if usage.total
                else 0.0,
                "total_human": human_size(usage.total),
                "used_human": human_size(usage.used),
                "free_human": human_size(usage.free),
            },
            "categories": categories,
            **categories,
        }

    def preview(
        self, categories: Any, older_than_days: Any, archive: bool = False
    ) -> Dict[str, Any]:
        selection = self.select(categories, older_than_days)
        by_category = {
            category: {
                "files": len(files),
                "size_bytes": sum(item.size for item in files),
                "size_human": human_size(sum(item.size for item in files)),
            }
            for category, files in selection.by_category().items()
        }
        return {
            "categories": list(selection.categories),
            "older_than_days": selection.older_than_days
            if selection.older_than_days is not None
            else "all",
            "archive": bool(archive),
            "files_to_delete": len(selection.files),
            "folders_affected": selection.folders,
            "folders_affected_count": len(selection.folders),
            "total_size": selection.total_size,
            "total_size_human": human_size(selection.total_size),
            "estimated_freed_space": selection.total_size,
            "estimated_freed_human": human_size(selection.total_size),
            "by_category": by_category,
        }

    def _create_archive(self, selection: CleanupSelection) -> Path:
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        if self.archive_dir.is_symlink():
            raise StorageError("Archive directory may not be a symlink")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        final_path = self.archive_dir / f"honeypot_{timestamp}.zip"
        if final_path.exists():
            final_path = self.archive_dir / f"honeypot_{timestamp}_{uuid.uuid4().hex[:8]}.zip"
        temporary_path = final_path.with_suffix(".zip.tmp")
        try:
            with zipfile.ZipFile(
                temporary_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
            ) as archive_file:
                root_indexes: Dict[Tuple[str, Path], int] = {}
                for item in selection.files:
                    key = (item.category, item.root)
                    if key not in root_indexes:
                        root_indexes[key] = 1 + sum(
                            1
                            for category, _root in root_indexes
                            if category == item.category
                        )
                    prefix = (
                        item.category
                        if len(self.category_roots[item.category]) == 1
                        else f"{item.category}/root_{root_indexes[key]}"
                    )
                    archive_file.write(
                        item.path, arcname=str(Path(prefix) / item.relative_path)
                    )
            with zipfile.ZipFile(temporary_path, "r") as archive_file:
                bad_file = archive_file.testzip()
                if bad_file is not None:
                    raise StorageError(f"Archive integrity check failed at {bad_file}")
                if len(archive_file.infolist()) != len(selection.files):
                    raise StorageError("Archive integrity check found a file-count mismatch")
            temporary_path.replace(final_path)
            return final_path
        except Exception:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _stage(self, selection: CleanupSelection) -> List[StagedFile]:
        transaction_id = uuid.uuid4().hex
        staged: List[StagedFile] = []
        try:
            for item in selection.files:
                if not self._is_within_root(item.path, item.root):
                    raise StorageError(f"Refusing to stage path outside approved root: {item.path}")
                trash_root = item.root / f".cleanup-trash-{transaction_id}"
                staged_path = trash_root / item.relative_path
                staged_path.parent.mkdir(parents=True, exist_ok=True)
                item.path.replace(staged_path)
                staged.append(StagedFile(item, staged_path))
            return staged
        except Exception as exc:
            self._restore_staged(staged)
            raise StorageConsistencyError(f"Could not stage cleanup files: {exc}") from exc

    @staticmethod
    def _restore_staged(staged: Sequence[StagedFile]) -> None:
        errors = []
        for item in reversed(staged):
            try:
                item.source.path.parent.mkdir(parents=True, exist_ok=True)
                item.staged_path.replace(item.source.path)
            except OSError as exc:
                errors.append(f"{item.source.path}: {exc}")
        if errors:
            raise StorageConsistencyError(
                "Could not restore staged files: " + "; ".join(errors)
            )

    def _purge_staged(self, staged: Sequence[StagedFile]) -> Tuple[int, int, List[str]]:
        deleted = 0
        bytes_freed = 0
        errors = []
        trash_roots = set()
        for item in staged:
            trash_root = next(
                parent
                for parent in item.staged_path.parents
                if parent.name.startswith(".cleanup-trash-")
            )
            trash_roots.add(trash_root)
            try:
                item.staged_path.unlink()
                deleted += 1
                bytes_freed += item.source.size
            except OSError as exc:
                errors.append(f"{item.source.path}: {exc}")
        for trash_root in trash_roots:
            folders = sorted(
                (path for path in trash_root.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            )
            for folder in [*folders, trash_root]:
                try:
                    folder.rmdir()
                except OSError:
                    # A failed file deletion intentionally leaves quarantine in place.
                    pass
        return deleted, bytes_freed, errors

    def _remove_empty_folders(self, selection: CleanupSelection) -> int:
        removed = 0
        parents = sorted(
            {
                parent
                for item in selection.files
                for parent in item.path.parents
                if parent != item.root and self._is_within_root(parent, item.root)
            },
            key=lambda path: len(path.parts),
            reverse=True,
        )
        for folder in parents:
            try:
                folder.rmdir()
                removed += 1
            except OSError:
                pass
        return removed

    def cleanup(
        self,
        categories: Any,
        older_than_days: Any = "all",
        archive: bool = False,
        initiated_by: str = "system",
    ) -> CleanupResult:
        if not _CLEANUP_LOCK.acquire(blocking=False):
            raise StorageBusyError("Another cleanup operation is already running")
        started = time.monotonic()
        result = CleanupResult()
        selected_categories: Tuple[str, ...] = ()
        try:
            selection = self.select(categories, older_than_days)
            selected_categories = selection.categories
            if archive and selection.files:
                archive_path = self._create_archive(selection)
                result.archive_created = True
                result.archive_path = str(archive_path)

            staged = self._stage(selection)
            try:
                if self.supabase_cleanup:
                    result.supabase_rows_deleted, _snapshots = (
                        self.supabase_cleanup.delete_matching(selection.by_category())
                    )
            except Exception:
                self._restore_staged(staged)
                raise

            deleted, bytes_freed, purge_errors = self._purge_staged(staged)
            result.files_deleted = deleted
            result.bytes_freed = bytes_freed
            result.folders_cleaned = self._remove_empty_folders(selection)
            result.errors.extend(purge_errors)
            if purge_errors:
                raise StorageConsistencyError(
                    "Some quarantined files could not be purged; active storage and "
                    "Supabase remain consistent"
                )
            return result
        except Exception as exc:
            result.errors.append(str(exc))
            raise
        finally:
            result.duration = time.monotonic() - started
            self.audit_logger.info(
                "storage_cleanup actor=%s timestamp=%s categories=%s "
                "files_deleted=%s bytes_deleted=%s archive=%s duration=%.3f errors=%s",
                initiated_by,
                datetime.now(timezone.utc).isoformat(),
                ",".join(selected_categories),
                result.files_deleted,
                result.bytes_freed,
                result.archive_path or "",
                result.duration,
                json.dumps(result.errors),
            )
            _CLEANUP_LOCK.release()


def configure_audit_logger(archive_dir: Path) -> logging.Logger:
    """Create a dedicated rotating audit log without duplicating handlers."""
    logger = logging.getLogger("honeypot.storage_cleanup")
    logger.setLevel(logging.INFO)
    logger.propagate = True
    if any(isinstance(handler, RotatingFileHandler) for handler in logger.handlers):
        return logger
    log_path = Path(
        os.getenv("CLEANUP_AUDIT_LOG", str(Path(archive_dir) / "storage_cleanup.log"))
    )
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=int(os.getenv("CLEANUP_AUDIT_MAX_BYTES", str(5 * 1024 * 1024))),
            backupCount=int(os.getenv("CLEANUP_AUDIT_BACKUP_COUNT", "5")),
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)
    except OSError as exc:
        logger.warning("Could not configure cleanup audit file %s: %s", log_path, exc)
    return logger


def cleanup_old_logs(keep_days: int, **kwargs: Any) -> Dict[str, Any]:
    return StorageManager().cleanup(["logs"], keep_days, **kwargs).to_dict()


def cleanup_old_pcaps(keep_days: int, **kwargs: Any) -> Dict[str, Any]:
    return StorageManager().cleanup(["pcaps"], keep_days, **kwargs).to_dict()


def cleanup_old_sessions(keep_days: int, **kwargs: Any) -> Dict[str, Any]:
    return StorageManager().cleanup(["sessions"], keep_days, **kwargs).to_dict()


def cleanup_old_iocs(keep_days: int, **kwargs: Any) -> Dict[str, Any]:
    return StorageManager().cleanup(["iocs"], keep_days, **kwargs).to_dict()
