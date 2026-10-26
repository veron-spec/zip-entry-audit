import tempfile
import unittest
import zipfile
from pathlib import Path

from zip_entry_audit import inspect_archive


class ZipEntryAuditTests(unittest.TestCase):
    def test_clean_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "clean.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("docs/readme.txt", "hello")
            self.assertEqual(inspect_archive(path), [])

    def test_detects_traversal_and_duplicate_names(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "risky.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../outside.txt", "a")
                archive.writestr("Docs/Readme.txt", "a")
                archive.writestr("docs/readme.TXT", "b")
            issues = [finding["issue"] for finding in inspect_archive(path)]
            self.assertIn("unsafe-path", issues)
            self.assertIn("duplicate-path", issues)

    def test_detects_symlink_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "link.zip"
            info = zipfile.ZipInfo("shortcut")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(info, "target")
            self.assertIn("symbolic-link", [f["issue"] for f in inspect_archive(path)])


if __name__ == "__main__":
    unittest.main()
