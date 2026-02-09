#!/usr/bin/env python3
"""Live test suite for n3ds_smb against a real 3DS.

Usage:
    N3DS_NAME=3DS-XXXX python3 -m unittest tests.test_3ds -v

Set N3DS_IP and N3DS_NAME to match your 3DS.
"""

import io, os, unittest
from n3ds_smb import N3DSClient

IP = os.environ.get("N3DS_IP", "")
NAME = os.environ.get("N3DS_NAME", "")
if not IP or not NAME:
    raise RuntimeError("Set N3DS_IP and N3DS_NAME environment variables")
TEST_DIR = "\\__test__"


class TestN3DS(unittest.TestCase):
    c: N3DSClient

    @classmethod
    def setUpClass(cls):
        cls.c = N3DSClient(IP, NAME)
        cls.c.connect()
        # clean up stale test dir if present
        try:
            cls._nuke(cls, TEST_DIR)
        except Exception:
            pass
        cls.c.mkdir(TEST_DIR)

    @classmethod
    def tearDownClass(cls):
        try:
            cls._nuke(cls, TEST_DIR)
        except Exception:
            pass
        cls.c.close()

    def _nuke(self, path):
        """Recursively remove a directory."""
        for e in self.c.listdir(path):
            if e["name"] in (".", ".."):
                continue
            full = path.rstrip("\\") + "\\" + e["name"]
            if e["is_dir"]:
                self._nuke(full)
                self.c.rmdir(full)
            else:
                self.c.delete(full)
        try:
            self.c.rmdir(path)
        except Exception:
            pass

    def _tp(self, name):
        """Return full test path."""
        return TEST_DIR + "\\" + name

    # -- discovery & connection --

    def test_reconnect(self):
        """Disconnect and reconnect with the same name."""
        c2 = N3DSClient(IP, NAME)
        self.__class__.c.close()
        try:
            c2.connect()
            self.assertEqual(c2.name, NAME)
            self.assertNotEqual(c2.tid, 0)
        finally:
            c2.close()
            self.__class__.c = N3DSClient(IP, NAME)
            self.__class__.c.connect()

    # -- directory listing --

    def test_listdir_root(self):
        """Root listing returns entries with expected keys."""
        entries = self.c.listdir("\\")
        self.assertGreater(len(entries), 0)
        for e in entries:
            self.assertIn("name", e)
            self.assertIn("size", e)
            self.assertIn("attr", e)
            self.assertIn("is_dir", e)

    def test_listdir_subdir(self):
        """Listing the test directory shows . and .. at minimum."""
        entries = self.c.listdir(TEST_DIR)
        names = [e["name"] for e in entries]
        self.assertIn(".", names)
        self.assertIn("..", names)

    # -- mkdir / rmdir --

    def test_mkdir_rmdir(self):
        """Create and remove a directory."""
        d = self._tp("subdir")
        self.c.mkdir(d)
        names = [e["name"] for e in self.c.listdir(TEST_DIR)]
        self.assertIn("subdir", names)
        self.c.rmdir(d)
        names = [e["name"] for e in self.c.listdir(TEST_DIR)]
        self.assertNotIn("subdir", names)

    # -- file operations --

    def test_put_get_small(self):
        """Upload 5 bytes, download, compare."""
        data = b"hello"
        self.c.put_file(self._tp("small.bin"), io.BytesIO(data))
        out = io.BytesIO()
        self.c.get_file(self._tp("small.bin"), out)
        self.assertEqual(out.getvalue(), data)
        self.c.delete(self._tp("small.bin"))

    def test_put_get_large(self):
        """Upload ~64 KB, download, compare."""
        data = os.urandom(65536)
        self.c.put_file(self._tp("large.bin"), io.BytesIO(data))
        out = io.BytesIO()
        self.c.get_file(self._tp("large.bin"), out)
        self.assertEqual(out.getvalue(), data)
        self.c.delete(self._tp("large.bin"))

    def test_put_overwrite(self):
        """Upload twice to the same path; second write wins."""
        p = self._tp("overwrite.bin")
        self.c.put_file(p, io.BytesIO(b"first"))
        self.c.put_file(p, io.BytesIO(b"second"))
        out = io.BytesIO()
        self.c.get_file(p, out)
        self.assertEqual(out.getvalue(), b"second")
        self.c.delete(p)

    def test_delete(self):
        """Upload, delete, verify gone."""
        p = self._tp("del.bin")
        self.c.put_file(p, io.BytesIO(b"x"))
        self.c.delete(p)
        names = [e["name"] for e in self.c.listdir(TEST_DIR)]
        self.assertNotIn("del.bin", names)

    def test_rename(self):
        """Upload, rename, verify new name exists and old is gone."""
        old = self._tp("before.bin")
        new = self._tp("after.bin")
        self.c.put_file(old, io.BytesIO(b"mv"))
        self.c.rename(old, new)
        names = [e["name"] for e in self.c.listdir(TEST_DIR)]
        self.assertNotIn("before.bin", names)
        self.assertIn("after.bin", names)
        # verify content survived
        out = io.BytesIO()
        self.c.get_file(new, out)
        self.assertEqual(out.getvalue(), b"mv")
        self.c.delete(new)


if __name__ == "__main__":
    unittest.main()
