"""Expose n3ds_smb over WebDAV using WsgiDAV."""

from __future__ import annotations

import io
import posixpath
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple

from cheroot import wsgi
from wsgidav import util
from wsgidav.dav_error import (
    DAVError,
    HTTP_BAD_REQUEST,
    HTTP_FORBIDDEN,
    HTTP_INTERNAL_ERROR,
    HTTP_NOT_FOUND,
)
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider
from wsgidav.wsgidav_app import WsgiDAVApp

from .client import N3DSClient


def _norm_dav_path(path: str) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    path = posixpath.normpath(path)
    return "/" if path == "." else path


def _dav_parent(path: str) -> str:
    path = _norm_dav_path(path)
    if path == "/":
        return "/"
    parent = posixpath.dirname(path.rstrip("/"))
    return parent if parent else "/"


def _dav_name(path: str) -> str:
    path = _norm_dav_path(path)
    if path == "/":
        return ""
    return posixpath.basename(path.rstrip("/"))


def _dav_join(parent: str, name: str) -> str:
    parent = _norm_dav_path(parent)
    if parent == "/":
        return "/" + name
    return parent.rstrip("/") + "/" + name


def _to_remote_smb_path(dav_path: str) -> str:
    dav_path = _norm_dav_path(dav_path)
    if dav_path == "/":
        return "\\"
    return "\\" + dav_path.lstrip("/").replace("/", "\\")


def _as_dav_error(exc: Exception) -> DAVError:
    if isinstance(exc, DAVError):
        return exc
    if isinstance(exc, FileNotFoundError):
        return DAVError(HTTP_NOT_FOUND)
    if isinstance(exc, PermissionError):
        return DAVError(HTTP_FORBIDDEN)
    if isinstance(exc, OSError):
        return DAVError(HTTP_FORBIDDEN)
    return DAVError(HTTP_INTERNAL_ERROR)


class _SMBReadStream(io.RawIOBase):
    def __init__(self, provider: "N3DSSMBProvider", remote_path: str):
        self._p = provider
        self._remote = remote_path
        self._fid: Optional[int] = None
        self._pos = 0
        self._closed = False

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if self._closed:
            return b""
        if n == 0:
            return b""
        want = 32768 if n < 0 else n
        with self._p._lock:
            self._p._ensure_connected()
            if self._fid is None:
                self._fid = self._p.client.open_file(_to_remote_smb_path(self._remote))
            chunk = self._p.client.read(self._fid, self._pos, want)
            if chunk:
                self._pos += len(chunk)
            return chunk

    def close(self) -> None:
        if self._closed:
            return
        with self._p._lock:
            try:
                if self._fid is not None and self._p.client.t is not None:
                    self._p.client.close_file(self._fid)
            finally:
                self._fid = None
                self._closed = True
        super().close()


class _SMBWriteStream(io.RawIOBase):
    def __init__(self, provider: "N3DSSMBProvider", remote_path: str):
        self._p = provider
        self._remote = remote_path
        self._fid: Optional[int] = None
        self._pos = 0
        self._closed = False

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        if self._closed:
            raise ValueError("I/O operation on closed stream")
        if not b:
            return 0
        with self._p._lock:
            self._p._ensure_connected()
            if self._fid is None:
                self._fid = self._p.client.open_file(
                    _to_remote_smb_path(self._remote),
                    access=0x1F01BF,
                    disp=5,
                    share=0,
                )
            self._p.client.write(self._fid, b, self._pos)
            self._pos += len(b)
            return len(b)

    def close(self) -> None:
        if self._closed:
            return
        with self._p._lock:
            try:
                if self._fid is not None and self._p.client.t is not None:
                    self._p.client.close_file(self._fid)
            finally:
                self._fid = None
                self._closed = True
        super().close()


@dataclass
class _Entry:
    name: str
    size: int
    is_dir: bool


class N3DSSMBProvider(DAVProvider):
    def __init__(self, client: N3DSClient, *, readonly: bool = False):
        super().__init__()
        self.client = client
        self._readonly = readonly
        self._lock = threading.RLock()

    def is_readonly(self):
        return self._readonly

    def _ensure_connected(self) -> None:
        if self.client.t is None:
            self.client.connect()
            return
        try:
            ok = self.client.echo()
        except Exception:
            ok = False
        if not ok:
            try:
                self.client.close()
            except Exception:
                pass
            self.client.connect()

    def _listdir_entries(self, dav_path: str, environ: dict) -> List[_Entry]:
        dav_path = _norm_dav_path(dav_path)
        with self._lock:
            self._ensure_connected()
            raw = self.client.listdir(_to_remote_smb_path(dav_path))

        entries = [
            _Entry(e["name"], int(e["size"]), bool(e["is_dir"]))
            for e in raw
            if e["name"] not in (".", "..")
        ]
        return entries

    def _stat(self, dav_path: str, environ: dict) -> Optional[_Entry]:
        dav_path = _norm_dav_path(dav_path)
        if dav_path == "/":
            return _Entry("", 0, True)
        parent = _dav_parent(dav_path)
        name = _dav_name(dav_path)
        for entry in self._listdir_entries(parent, environ):
            if entry.name.lower() == name.lower():
                return entry
        return None

    def get_resource_inst(self, path: str, environ: dict):
        path = _norm_dav_path(path)
        if path == "/":
            return _N3DSDir(path, environ, self, _Entry("", 0, True))
        ent = self._stat(path, environ)
        if ent is None:
            return None
        if ent.is_dir:
            return _N3DSDir(path, environ, self, ent)
        return _N3DSFile(path, environ, self, ent)


class _N3DSBase:
    def __init__(self, provider: N3DSSMBProvider, entry: _Entry):
        self._p = provider
        self._e = entry

    def support_etag(self):
        return False

    def get_etag(self):
        return None

    def support_modified(self):
        return False

    def get_last_modified(self):
        return None


class _N3DSDir(_N3DSBase, DAVCollection):
    def __init__(
        self, path: str, environ: dict, provider: N3DSSMBProvider, entry: _Entry
    ):
        DAVCollection.__init__(self, path, environ)
        _N3DSBase.__init__(self, provider, entry)

    def get_member_names(self):
        try:
            return [e.name for e in self._p._listdir_entries(self.path, self.environ)]
        except Exception as exc:
            raise _as_dav_error(exc)

    def get_member(self, name):
        return self._p.get_resource_inst(_dav_join(self.path, name), self.environ)

    def get_member_list(self):
        out = []
        try:
            for e in self._p._listdir_entries(self.path, self.environ):
                child_path = _dav_join(self.path, e.name)
                out.append(
                    _N3DSDir(child_path, self.environ, self._p, e)
                    if e.is_dir
                    else _N3DSFile(child_path, self.environ, self._p, e)
                )
            return out
        except Exception as exc:
            raise _as_dav_error(exc)

    def get_available_bytes(self):
        with self._p._lock:
            self._p._ensure_connected()
            info = self._p.client.disk_info()
        if not info:
            return None
        return int(info["free_bytes"])

    def get_used_bytes(self):
        with self._p._lock:
            self._p._ensure_connected()
            info = self._p.client.disk_info()
        if not info:
            return None
        return int(info["total_bytes"] - info["free_bytes"])

    def create_collection(self, name):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)
        if not name:
            raise DAVError(HTTP_BAD_REQUEST)
        try:
            with self._p._lock:
                self._p._ensure_connected()
                self._p.client.mkdir(_to_remote_smb_path(_dav_join(self.path, name)))
        except Exception as exc:
            raise _as_dav_error(exc)
        return self._p.get_resource_inst(_dav_join(self.path, name), self.environ)

    def create_empty_resource(self, name):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)
        if not name:
            raise DAVError(HTTP_BAD_REQUEST)
        dav_path = _dav_join(self.path, name)
        try:
            with self._p._lock:
                self._p._ensure_connected()
                fid = self._p.client.open_file(
                    _to_remote_smb_path(dav_path), access=0x1F01BF, disp=5, share=0
                )
                self._p.client.close_file(fid)
        except Exception as exc:
            raise _as_dav_error(exc)
        return _N3DSFile(dav_path, self.environ, self._p, _Entry(name, 0, False))

    def support_recursive_delete(self):
        return True

    def delete(self):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)
        errors: List[Tuple[str, DAVError]] = []
        try:
            for child in self.get_member_list():
                try:
                    child.delete()
                except Exception as exc:
                    errors.append((child.get_ref_url(), _as_dav_error(exc)))
        except Exception as exc:
            raise _as_dav_error(exc)

        try:
            with self._p._lock:
                self._p._ensure_connected()
                if self.path != "/":
                    self._p.client.rmdir(_to_remote_smb_path(self.path))
        except Exception as exc:
            errors.append((self.get_ref_url(), _as_dav_error(exc)))

        return errors

    def support_recursive_move(self, dest_path):
        return True

    def move_recursive(self, dest_path):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)

        src_remote = _to_remote_smb_path(self.path)
        dst_remote = _to_remote_smb_path(dest_path)
        try:
            with self._p._lock:
                self._p._ensure_connected()
                self._p.client.rename(src_remote, dst_remote)
            return []
        except Exception:
            errors: List[Tuple[str, DAVError]] = []
            try:
                parent = _dav_parent(dest_path)
                name = _dav_name(dest_path)
                parent_res = self._p.get_resource_inst(parent, self.environ)
                if parent_res is None or not isinstance(parent_res, DAVCollection):
                    raise DAVError(HTTP_BAD_REQUEST)
                parent_res.create_collection(name)
            except Exception as exc:
                raise _as_dav_error(exc)

            for child in self.get_member_list():
                child_dst = _dav_join(dest_path, child.get_display_name())
                try:
                    if child.is_collection:
                        child.move_recursive(child_dst)
                    else:
                        child.copy_move_single(child_dst, is_move=True)
                except Exception as exc:
                    errors.append((child.get_ref_url(), _as_dav_error(exc)))

            try:
                self.delete()
            except Exception as exc:
                errors.append((self.get_ref_url(), _as_dav_error(exc)))

            return errors


class _N3DSFile(_N3DSBase, DAVNonCollection):
    def __init__(
        self, path: str, environ: dict, provider: N3DSSMBProvider, entry: _Entry
    ):
        DAVNonCollection.__init__(self, path, environ)
        _N3DSBase.__init__(self, provider, entry)

    def get_content_length(self):
        return int(self._e.size)

    def get_content(self):
        try:
            return _SMBReadStream(self._p, self.path)
        except Exception as exc:
            raise _as_dav_error(exc)

    def support_recursive_move(self, dest_path):
        return False

    def handle_move(self, dest_path):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)
        try:
            with self._p._lock:
                self._p._ensure_connected()
                self._p.client.rename(
                    _to_remote_smb_path(self.path), _to_remote_smb_path(dest_path)
                )
            return True
        except Exception as exc:
            raise _as_dav_error(exc)

    def begin_write(self, *, content_type=None):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)
        return _SMBWriteStream(self._p, self.path)

    def delete(self):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)
        try:
            with self._p._lock:
                self._p._ensure_connected()
                self._p.client.delete(_to_remote_smb_path(self.path))
        except Exception as exc:
            raise _as_dav_error(exc)
        return []

    def copy_move_single(self, dest_path, *, is_move):
        if self._p.is_readonly():
            raise DAVError(HTTP_FORBIDDEN)

        src_remote = _to_remote_smb_path(self.path)
        dst_remote = _to_remote_smb_path(dest_path)
        try:
            with self._p._lock:
                self._p._ensure_connected()
                if is_move:
                    self._p.client.rename(src_remote, dst_remote)
                    return []

                src_fid = self._p.client.open_file(src_remote)
                dst_fid = self._p.client.open_file(
                    dst_remote, access=0x1F01BF, disp=5, share=0
                )
                try:
                    off = 0
                    while True:
                        chunk = self._p.client.read(src_fid, off, 32768)
                        if not chunk:
                            break
                        self._p.client.write(dst_fid, chunk, off)
                        off += len(chunk)
                finally:
                    self._p.client.close_file(src_fid)
                    self._p.client.close_file(dst_fid)
            return []
        except Exception as exc:
            raise _as_dav_error(exc)


def serve_webdav(
    client: N3DSClient,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    readonly: bool = False,
    user: Optional[str] = None,
    password: Optional[str] = None,
    numthreads: int = 4,
    verbose: int = 3,
):
    app, server = build_webdav_server(
        client,
        host=host,
        port=port,
        readonly=readonly,
        user=user,
        password=password,
        numthreads=numthreads,
        verbose=verbose,
    )

    app.logger.info(
        "Serving WebDAV on http://%s:%s/ (readonly=%s)", host, int(port), readonly
    )
    try:
        server.start()
    except KeyboardInterrupt:
        app.logger.info("Stopping...")
    finally:
        server.stop()
        try:
            client.close()
        except Exception:
            pass


def build_webdav_server(
    client: N3DSClient,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    readonly: bool = False,
    user: Optional[str] = None,
    password: Optional[str] = None,
    numthreads: int = 4,
    verbose: int = 3,
):
    provider = N3DSSMBProvider(client, readonly=readonly)

    if user:
        user_mapping = {"*": {user: {"password": password or ""}}}
    else:
        user_mapping = {"*": True}

    config = {
        "host": host,
        "port": int(port),
        "provider_mapping": {"/": provider},
        "http_authenticator": {"domain_controller": None},
        "simple_dc": {"user_mapping": user_mapping},
        "property_manager": True,
        "lock_storage": True,
        "verbose": int(verbose),
        "logging": {"enable": True, "enable_loggers": []},
    }

    app = WsgiDAVApp(config)
    version = (
        f"{util.public_wsgidav_info} {wsgi.Server.version} {util.public_python_info}"
    )
    server = wsgi.Server(
        bind_addr=(host, int(port)),
        wsgi_app=app,
        server_name=version,
        numthreads=int(numthreads),
    )

    return app, server
