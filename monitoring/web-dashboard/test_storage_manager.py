import importlib.util
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("storage_manager.py")
SPEC = importlib.util.spec_from_file_location("storage_manager_under_test", MODULE_PATH)
storage = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = storage
SPEC.loader.exec_module(storage)


class FailingSupabaseCleanup:
    def delete_matching(self, files_by_category):
        raise storage.StorageConsistencyError("simulated remote failure")


class StorageManagerTests(unittest.TestCase):
    def setUp(self):
        Path(r"C:\tmp").mkdir(parents=True, exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=r"C:\tmp")
        self.base = Path(self.temp_dir.name)
        self.roots = {
            category: (self.base / category,) for category in storage.CATEGORIES
        }
        for roots in self.roots.values():
            roots[0].mkdir()
        self.archive_dir = self.base / "archive"
        self.manager = storage.StorageManager(
            category_roots=self.roots,
            archive_dir=self.archive_dir,
            supabase_cleanup=None,
        )
        # Explicitly disable environment-created Supabase clients for unit tests.
        self.manager.supabase_cleanup = None

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_stats_and_preview_apply_age_filter(self):
        old_file = self.roots["logs"][0] / "old.log"
        new_file = self.roots["logs"][0] / "new.log"
        old_file.write_bytes(b"old")
        new_file.write_bytes(b"new-data")
        old_timestamp = storage.time.time() - (10 * 86400)
        os.utime(old_file, (old_timestamp, old_timestamp))

        stats = self.manager.storage_stats()
        preview = self.manager.preview(["logs"], 7)

        self.assertEqual(stats["logs"]["file_count"], 2)
        self.assertEqual(stats["logs"]["size_bytes"], 11)
        self.assertEqual(preview["files_to_delete"], 1)
        self.assertEqual(preview["total_size"], 3)
        self.assertTrue(old_file.exists())

    def test_archive_is_verified_before_files_are_deleted(self):
        session_file = self.roots["sessions"][0] / "session.json"
        session_file.write_text('{"id": 1}', encoding="utf-8")

        result = self.manager.cleanup(["sessions"], "all", archive=True)

        self.assertFalse(session_file.exists())
        self.assertEqual(result.files_deleted, 1)
        self.assertTrue(result.archive_created)
        with zipfile.ZipFile(result.archive_path) as archive_file:
            self.assertIsNone(archive_file.testzip())
            self.assertEqual(archive_file.namelist(), ["sessions/session.json"])

    def test_ioc_user_settings_are_never_selected(self):
        protected = self.roots["iocs"][0] / "blocked_ips.json"
        removable = self.roots["iocs"][0] / "ioc_1.json"
        protected.write_text("[]", encoding="utf-8")
        removable.write_text("{}", encoding="utf-8")

        result = self.manager.cleanup(["iocs"], "all")

        self.assertTrue(protected.exists())
        self.assertFalse(removable.exists())
        self.assertEqual(result.files_deleted, 1)

    def test_remote_failure_restores_staged_files(self):
        session_file = self.roots["sessions"][0] / "session.json"
        session_file.write_text("{}", encoding="utf-8")
        self.manager.supabase_cleanup = FailingSupabaseCleanup()

        with self.assertRaises(storage.StorageConsistencyError):
            self.manager.cleanup(["sessions"], "all")

        self.assertTrue(session_file.exists())
        self.assertFalse(any(self.roots["sessions"][0].glob(".cleanup-trash-*")))

    def test_symlink_is_not_followed_or_deleted(self):
        outside = self.base / "outside.txt"
        outside.write_text("keep", encoding="utf-8")
        link = self.roots["logs"][0] / "outside-link"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable")

        preview = self.manager.preview(["logs"], "all")
        result = self.manager.cleanup(["logs"], "all")

        self.assertEqual(preview["files_to_delete"], 0)
        self.assertEqual(result.files_deleted, 0)
        self.assertTrue(link.exists())
        self.assertTrue(outside.exists())

    def test_invalid_category_is_rejected(self):
        with self.assertRaises(storage.StorageValidationError):
            self.manager.preview(["source-code"], "all")


if __name__ == "__main__":
    unittest.main()
