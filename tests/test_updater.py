import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nextguard import updater


class Headers(dict):
    def get(self, key, default=None): return super().get(key, default)


class Response:
    def __init__(self, data): self.data, self.offset, self.headers = data, 0, Headers()
    def read(self, size):
        result = self.data[self.offset:self.offset+size]; self.offset += len(result); return result
    def __enter__(self): return self
    def __exit__(self, *args): pass


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name)
        self.source = {"id":"one", "module":"attackers", "url":"https://example.invalid/list", "adapter":"lines", "allow_empty":False}
        self.paths = patch.multiple(updater, CACHE=self.cache)
        self.paths.start()

    def tearDown(self): self.paths.stop(); self.tmp.cleanup()

    def test_failed_update_preserves_good_copy(self):
        updater.update_source(self.source, opener=lambda *a, **k: Response(b"192.0.2.1\n"))
        raw = (self.cache / "one/raw").read_bytes()
        meta = updater.update_source(self.source, opener=lambda *a, **k: Response(b"<html>bad</html>"))
        self.assertEqual((self.cache / "one/raw").read_bytes(), raw)
        self.assertIn("HTML", meta["error"])

    def test_one_source_old_other_source_new(self):
        one = self.source
        two = {**one, "id":"two"}
        updater.update_source(one, opener=lambda *a, **k: Response(b"192.0.2.1\n"))
        updater.update_source(two, opener=lambda *a, **k: Response(b"198.51.100.1\n"))
        updater.update_source(one, opener=lambda *a, **k: Response(b"bad\n"))
        updater.update_source(two, opener=lambda *a, **k: Response(b"198.51.100.2\n"))
        cfg={"modules":{"attackers":True},"interfaces":[],"logging":{"attackers":True}}
        generation=updater.build_generation(cfg,[one,two])
        self.assertEqual(set(generation["networks"]), {"192.0.2.1/32","198.51.100.2/32"})


if __name__ == "__main__": unittest.main()
