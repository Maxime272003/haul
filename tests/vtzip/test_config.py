"""Tests du stockage de la cle API (chiffree avec DPAPI sous Windows)."""

from __future__ import annotations

import json
import os
import unittest
from tempfile import TemporaryDirectory
from unittest import mock

from vtzip import config

KEY = "a1" * 32


class ApiKeyStorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        env = {k: v for k, v in os.environ.items() if k not in config.ENV_KEYS}
        env["APPDATA"] = self.tmp.name
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def stored(self) -> dict:
        return json.loads(config.config_path().read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "nt", "DPAPI : Windows uniquement")
    def test_key_is_encrypted_on_windows(self):
        config.store_api_key(KEY)
        data = self.stored()
        self.assertNotIn("api_key", data)
        self.assertNotIn(KEY, json.dumps(data))
        self.assertEqual(config.resolve_api_key(), KEY)

    @unittest.skipUnless(os.name == "nt", "DPAPI : Windows uniquement")
    def test_plaintext_key_is_migrated(self):
        config.save_config({"api_key": KEY, "autre": 1})
        self.assertEqual(config.resolve_api_key(), KEY)
        data = self.stored()
        self.assertNotIn("api_key", data)
        self.assertEqual(data["autre"], 1)
        self.assertEqual(config.resolve_api_key(), KEY)

    def test_environment_variable_wins(self):
        config.store_api_key(KEY)
        with mock.patch.dict(os.environ, {"VT_API_KEY": "env" * 20}):
            self.assertEqual(config.resolve_api_key(), "env" * 20)

    def test_unreadable_encrypted_key_is_ignored(self):
        config.save_config({"api_key_dpapi": "pas du base64 !"})
        self.assertIsNone(config.resolve_api_key())


if __name__ == "__main__":
    unittest.main()
