import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import installer_store


class InstallerStoreTests(unittest.TestCase):
    def test_load_catalog_requires_core_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "catalog.json"
            path.write_text(json.dumps({"repository": "owner/repo"}), encoding="utf-8")
            with self.assertRaises(installer_store.InstallerStoreError):
                installer_store.load_catalog(path)

    def test_prepare_downloads_and_verifies_asset(self):
        content = b"test installer"
        expected = hashlib.sha256(content).hexdigest()
        catalog = {
            "repository": "owner/repo",
            "release_tag": "installers-v1",
            "installers": [{"name": "Test", "asset": "test.exe", "silent_args": "/S"}],
        }

        def fake_download(url, destination):
            if destination.name == "SHA256SUMS":
                destination.write_text(f"{expected}  test.exe\n", encoding="utf-8")
            else:
                destination.write_bytes(content)

        with tempfile.TemporaryDirectory() as folder, patch.object(installer_store, "_download", fake_download):
            result = installer_store.prepare_installers(catalog, folder)
            self.assertEqual(Path(result[0]["local_path"]).read_bytes(), content)

    def test_prepare_rejects_unlisted_asset(self):
        catalog = {
            "repository": "owner/repo",
            "release_tag": "installers-v1",
            "installers": [{"name": "Test", "asset": "test.exe"}],
        }

        def fake_download(url, destination):
            destination.write_text("", encoding="utf-8")

        with tempfile.TemporaryDirectory() as folder, patch.object(installer_store, "_download", fake_download):
            with self.assertRaises(installer_store.InstallerStoreError):
                installer_store.prepare_installers(catalog, folder)


if __name__ == "__main__":
    unittest.main()
