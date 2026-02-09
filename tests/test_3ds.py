#!/usr/bin/env python3
"""Live test suite for n3ds_smb against a real 3DS.

Usage:
    N3DS_NAME=3DS-XXXX python3 -m unittest tests.test_3ds -v

Set N3DS_IP and N3DS_NAME to match your 3DS.
"""

import io
import os
import random
import time
import unittest
from n3ds_smb import N3DSClient, discover_3ds

TEST_DIR = "\\__test__"


class TestN3DS(unittest.TestCase):
    c: N3DSClient

    @classmethod
    def setUpClass(cls):
        env_ip = os.environ.get("N3DS_IP", "")
        env_name = os.environ.get("N3DS_NAME", "")

        target = None
        if env_ip and env_name:
            target = (env_ip, env_name)
        else:
            target = discover_3ds()

        cls.ip, cls.name = target
        cls.c = N3DSClient(cls.ip, cls.name)
        try:
            cls.c.connect()
        except Exception:
            if env_ip and env_name:
                cls.c.close()
                cls.ip, cls.name = discover_3ds()
                cls.c = N3DSClient(cls.ip, cls.name)
                cls.c.connect()
            else:
                raise
        # clean up stale test dir if present
        try:
            cls._nuke(TEST_DIR)
        except Exception:
            pass
        cls.c.mkdir(TEST_DIR)

    @classmethod
    def tearDownClass(cls):
        try:
            cls._nuke(TEST_DIR)
        except Exception:
            pass
        cls.c.close()

    @classmethod
    def _nuke(cls, path):
        """Recursively remove a directory."""
        for e in cls.c.listdir(path):
            if e["name"] in (".", ".."):
                continue
            full = path.rstrip("\\") + "\\" + e["name"]
            if e["is_dir"]:
                cls._nuke(full)
                cls.c.rmdir(full)
            else:
                cls.c.delete(full)
        try:
            cls.c.rmdir(path)
        except Exception:
            pass

    def _tp(self, name):
        """Return full test path."""
        return TEST_DIR + "\\" + name

    # -- discovery & connection --

    def test_reconnect(self):
        """Disconnect and reconnect with the same name."""
        c2 = N3DSClient(self.ip, self.name)
        self.__class__.c.close()
        try:
            c2.connect()
            self.assertEqual(c2.name, self.name)
            self.assertNotEqual(c2.tid, 0)
        finally:
            c2.close()
            self.__class__.c = N3DSClient(self.ip, self.name)
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

    def test_listdir_default_path(self):
        """Calling listdir() without args lists the root."""
        entries = self.c.listdir()
        self.assertGreater(len(entries), 0)

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
        written = self.c.put_file(self._tp("small.bin"), io.BytesIO(data))
        self.assertEqual(written, len(data))
        out = io.BytesIO()
        read = self.c.get_file(self._tp("small.bin"), out)
        self.assertEqual(read, len(data))
        self.assertEqual(out.getvalue(), data)
        self.c.delete(self._tp("small.bin"))

    def test_put_get_large(self):
        """Upload ~64 KB, download, compare."""
        data = os.urandom(65536)
        written = self.c.put_file(self._tp("large.bin"), io.BytesIO(data))
        self.assertEqual(written, len(data))
        out = io.BytesIO()
        read = self.c.get_file(self._tp("large.bin"), out)
        self.assertEqual(read, len(data))
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

    def test_rename_directory(self):
        """Create dir, rename dir, verify target exists."""
        old = self._tp("dir_before")
        new = self._tp("dir_after")
        self.c.mkdir(old)
        try:
            self.c.rename(old, new)
            names = [e["name"] for e in self.c.listdir(TEST_DIR)]
            self.assertNotIn("dir_before", names)
            self.assertIn("dir_after", names)
        finally:
            try:
                self.c.rmdir(new)
            except Exception:
                pass
            try:
                self.c.rmdir(old)
            except Exception:
                pass

    def test_ping_echo(self):
        """SMB echo returns alive status."""
        self.assertTrue(self.c.echo())

    def test_df_disk_info(self):
        """disk_info returns sane total/free values."""
        info = self.c.disk_info()
        self.assertIsNotNone(info)
        assert info is not None
        self.assertIn("total_bytes", info)
        self.assertIn("free_bytes", info)
        self.assertGreater(info["total_bytes"], 0)
        self.assertGreaterEqual(info["free_bytes"], 0)
        self.assertLessEqual(info["free_bytes"], info["total_bytes"])

    def test_open_read_write_close_low_level(self):
        """Use low-level open/read/write/close methods directly."""
        suffix = f"{int(time.time())}_{random.randint(1000, 9999)}"
        path = self._tp(f"lowlevel_{suffix}.bin")
        data = b"hello low-level io"
        fid = self.c.open_file(path, access=0x1F01BF, disp=5, share=0)
        try:
            n = self.c.write(fid, data, 0)
            self.assertEqual(n, len(data))
        finally:
            self.c.close_file(fid)

        fid = self.c.open_file(path)
        try:
            out = self.c.read(fid, 0, len(data) + 32)
            self.assertEqual(out, data)
        finally:
            self.c.close_file(fid)
        self.c.delete(path)


if __name__ == "__main__":
    unittest.main()
