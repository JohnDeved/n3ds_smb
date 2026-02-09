#!/usr/bin/env python3
"""Live end-to-end WebDAV tests against a real 3DS.

Usage:
    N3DS_IP=<ip> N3DS_NAME=<name> python3 -m unittest tests.test_webdav_e2e -v
"""

import http.client
import os
import random
import socket
import threading
import time
import unittest

from n3ds_smb import N3DSClient, discover_3ds


def _pick_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return int(port)


class TestWebDAVE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env_ip = os.environ.get("N3DS_IP", "")
        env_name = os.environ.get("N3DS_NAME", "")

        try:
            from n3ds_smb.webdav import build_webdav_server
        except ModuleNotFoundError as exc:
            raise unittest.SkipTest(f"Missing optional dependency: {exc}")

        cls._build_webdav_server = staticmethod(build_webdav_server)

        target = None
        if env_ip and env_name:
            target = (env_ip, env_name)
        else:
            try:
                target = discover_3ds()
            except Exception as exc:
                raise unittest.SkipTest(
                    f"Could not resolve 3DS target (set N3DS_IP/N3DS_NAME): {exc}"
                )

        cls.client = N3DSClient(*target)
        try:
            cls.client.connect()
        except Exception:
            # If env target failed, try one discovery fallback before skipping.
            if env_ip and env_name:
                try:
                    cls.client.close()
                except Exception:
                    pass
                try:
                    target = discover_3ds()
                    cls.client = N3DSClient(*target)
                    cls.client.connect()
                except Exception as exc:
                    raise unittest.SkipTest(
                        f"Could not connect to 3DS for WebDAV tests: {exc}"
                    )
            else:
                raise
        cls.port = _pick_free_port()
        _, cls.server = cls._build_webdav_server(
            cls.client,
            host="127.0.0.1",
            port=cls.port,
            readonly=False,
            numthreads=1,
            verbose=1,
        )
        cls.thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.thread.start()
        cls._wait_until_ready(timeout=8.0)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server", None) is not None:
            cls.server.stop()
        if getattr(cls, "thread", None) is not None:
            cls.thread.join(timeout=2.0)
        if getattr(cls, "client", None) is not None:
            cls.client.close()

    @classmethod
    def _wait_until_ready(cls, timeout: float):
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=2)
                conn.request("OPTIONS", "/")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                return
            except Exception as exc:
                last_err = exc
                time.sleep(0.1)
        raise RuntimeError(f"WebDAV server did not become ready: {last_err}")

    def _request(self, method, path, body=b"", headers=None):
        if headers is None:
            headers = {}
        last_err = None
        for _ in range(2):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                conn.close()
                return status, payload, resp_headers
            except TimeoutError as exc:
                last_err = exc
                time.sleep(0.2)
        if last_err is not None:
            raise last_err
        raise RuntimeError("request failed without timeout error")

    def test_options_root(self):
        status, _, headers = self._request("OPTIONS", "/")
        self.assertEqual(status, 200)
        self.assertIn("dav", headers)
        self.assertIn("allow", headers)
        allow = headers["allow"].upper()
        for method in ("OPTIONS", "PROPFIND", "GET", "DELETE", "MOVE", "COPY"):
            self.assertIn(method, allow)

    def _delete_expect_removed(self, path: str):
        status, _, _ = self._request("DELETE", path)
        if status in (200, 204, 404):
            return
        status, _, _ = self._request("GET", path)
        self.assertEqual(status, 404)

    def _ensure_mkcol(self, path: str):
        for _ in range(3):
            status, _, _ = self._request("MKCOL", path)
            if status in (201, 405):
                return
            if status == 403:
                body = (
                    b'<?xml version="1.0" encoding="utf-8"?>'
                    b"<D:propfind xmlns:D='DAV:'><D:allprop/></D:propfind>"
                )
                pstatus, _, _ = self._request(
                    "PROPFIND",
                    path,
                    body=body,
                    headers={"Depth": "0", "Content-Type": "application/xml"},
                )
                if pstatus == 207:
                    return
            time.sleep(0.2)
        self.fail(f"MKCOL failed for {path}")

    def test_propfind_root(self):
        body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b"<D:propfind xmlns:D='DAV:'><D:allprop/></D:propfind>"
        )
        status, payload, _ = self._request(
            "PROPFIND",
            "/",
            body=body,
            headers={
                "Depth": "1",
                "Content-Type": "application/xml",
            },
        )
        self.assertEqual(status, 207)
        self.assertIn(b"multistatus", payload.lower())

    def test_file_roundtrip_via_webdav(self):
        suffix = f"{int(time.time())}_{random.randint(1000, 9999)}"
        test_dir = f"/__webdav_test_{suffix}"
        src = f"{test_dir}/hello.bin"
        dst = f"{test_dir}/hello_moved.bin"
        content = b"hello via webdav\n"

        try:
            status, _, _ = self._request("MKCOL", test_dir)
            self.assertIn(status, (201, 405))

            status, _, _ = self._request(
                "PUT",
                src,
                body=content,
                headers={"Content-Type": "application/octet-stream"},
            )
            self.assertIn(status, (200, 201, 204))

            status, payload, _ = self._request("GET", src)
            self.assertEqual(status, 200)
            self.assertEqual(payload, content)

            status, payload, headers = self._request("HEAD", src)
            self.assertEqual(status, 200)
            self.assertEqual(payload, b"")
            self.assertIn("content-length", headers)
            self.assertEqual(int(headers["content-length"]), len(content))

            copied = f"{test_dir}/hello_copy.bin"
            status, _, _ = self._request(
                "COPY",
                src,
                headers={
                    "Destination": f"http://127.0.0.1:{self.port}{copied}",
                    "Overwrite": "T",
                },
            )
            self.assertIn(status, (201, 204))

            status, payload, _ = self._request("GET", copied)
            self.assertEqual(status, 200)
            self.assertEqual(payload, content)

            status, _, _ = self._request(
                "MOVE",
                src,
                headers={
                    "Destination": f"http://127.0.0.1:{self.port}{dst}",
                    "Overwrite": "T",
                },
            )
            self.assertIn(status, (201, 204))

            status, payload, _ = self._request("GET", dst)
            self.assertEqual(status, 200)
            self.assertEqual(payload, content)

            self._delete_expect_removed(copied)
            self._delete_expect_removed(dst)
            status, _, _ = self._request("DELETE", test_dir)
            self.assertIn(status, (200, 204, 404))
        finally:
            self._request("DELETE", f"{test_dir}/hello_copy.bin")
            self._request("DELETE", dst)
            self._request("DELETE", src)
            self._request("DELETE", test_dir)

    def test_directory_move_recursive(self):
        suffix = f"{int(time.time())}_{random.randint(1000, 9999)}"
        root = f"/__webdav_dirmv_{suffix}"
        src_dir = f"{root}/from"
        nested = f"{src_dir}/nested"
        src_file = f"{nested}/x.txt"
        dst_dir = f"{root}/to"
        dst_file = f"{dst_dir}/nested/x.txt"
        content = b"recursive move"

        try:
            self._request("DELETE", root)
            for path in (root, src_dir, nested):
                self._ensure_mkcol(path)

            status, _, _ = self._request("PUT", src_file, body=content)
            self.assertIn(status, (200, 201, 204))

            status, _, _ = self._request(
                "MOVE",
                src_dir,
                headers={
                    "Destination": f"http://127.0.0.1:{self.port}{dst_dir}",
                    "Overwrite": "T",
                },
            )
            self.assertIn(status, (201, 204))

            status, payload, _ = self._request("GET", dst_file)
            self.assertEqual(status, 200)
            self.assertEqual(payload, content)

            status, _, _ = self._request("GET", src_file)
            self.assertEqual(status, 404)
        finally:
            self._request("DELETE", dst_file)
            self._request("DELETE", f"{dst_dir}/nested")
            self._request("DELETE", dst_dir)
            self._request("DELETE", src_file)
            self._request("DELETE", nested)
            self._request("DELETE", src_dir)
            self._request("DELETE", root)


if __name__ == "__main__":
    unittest.main()
