"""StreamEncrypt regression tests: python -m unittest -v test_stream_encrypt.py"""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import stream_encrypt


class StreamEncryptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.data = self.base / "input"
        self.data.mkdir()
        (self.data / "hello.txt").write_text("测试 FCS4 data!\n" * 12000, encoding="utf-8")
        (self.data / "empty.bin").write_bytes(b"")
        for user in ("a", "b", "c"):
            with patch.object(fcs4.getpass, "getpass", side_effect=["long-test-password-123", "long-test-password-123"]):
                fcs4.keygen(self.base / f"{user}.pem", self.base / f"{user}.pub")

    def private(self, user, action, *args, **kwargs):
        with patch.object(fcs4.getpass, "getpass", return_value="long-test-password-123"):
            return action(*args, **kwargs)

    def roundtrip(self, algorithm):
        encrypted = self.base / f"{algorithm}.fcs4"
        fcs4.encrypt([self.data], encrypted, [self.base / "a.pub", self.base / "b.pub"], compression=algorithm)
        restored = self.base / f"{algorithm}_restored"
        self.private("b", fcs4.decrypt, encrypted, restored, self.base / "b.pem")
        self.assertEqual((restored / "input" / "hello.txt").read_bytes(), (self.data / "hello.txt").read_bytes())
        self.assertEqual((restored / "input" / "empty.bin").read_bytes(), b"")
        rotated = self.base / f"{algorithm}_rotated.fcs4"
        self.private("a", fcs4.rotate, encrypted, rotated, self.base / "a.pem", [self.base / "c.pub"], replace=True)
        self.private("c", fcs4.decrypt, rotated, self.base / f"{algorithm}_new", self.base / "c.pem")
        with self.assertRaises(ValueError):
            self.private("a", fcs4.decrypt, rotated, self.base / f"{algorithm}_old", self.base / "a.pem")
        with encrypted.open("rb") as original, rotated.open("rb") as new:
            fcs4.read_envelope(original)
            fcs4.read_envelope(new)
            self.assertEqual(original.read(), new.read())
        # Alter the final authenticated record; must reject the file.
        modified = bytearray(encrypted.read_bytes())
        modified[-1] ^= 1
        corrupt = self.base / f"{algorithm}_corrupt.fcs4"
        corrupt.write_bytes(modified)
        with self.assertRaises(Exception):
            self.private("a", fcs4.decrypt, corrupt, self.base / f"{algorithm}_corrupt_out", self.base / "a.pem")
        self.assertFalse((self.base / f"{algorithm}_corrupt_out").exists())

    def test_gzip(self):
        self.roundtrip("gzip")

    def test_none(self):
        self.roundtrip("none")

    @unittest.skipUnless(importlib.util.find_spec("zstandard"), "zstandard not installed")
    def test_zstd(self):
        self.roundtrip("zstd")

    def test_invalid_levels(self):
        with self.assertRaises(ValueError):
            fcs4.encrypt([self.data], self.base / "bad.fcs4", [self.base / "a.pub"], compression="gzip", compression_level=10)


if __name__ == "__main__":
    unittest.main()
