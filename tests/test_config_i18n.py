import json
import os
import tempfile
import unittest
from pathlib import Path

from nextguard.config import DEFAULT, atomic_json, load
from nextguard.i18n import STRINGS


class ConfigTests(unittest.TestCase):
    def test_translation_keys_match(self):
        self.assertEqual(set(STRINGS["ru"]), set(STRINGS["en"]))

    def test_atomic_config_and_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            atomic_json(path, {"language": "en", "interval_minutes": 30})
            cfg = load(path)
            self.assertEqual(cfg["language"], "en")
            self.assertEqual(cfg["interval_minutes"], 30)
            self.assertEqual(cfg["modules"], DEFAULT["modules"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
