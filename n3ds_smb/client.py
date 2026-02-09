"""N3DSClient — SMB1 file operations for the New Nintendo 3DS microSD share."""

import io, socket, struct

from n3ds_smb.transport import (
    AUTH_BLOB,
    SMBTransport,
    nb_name,
    recv_bytes,
    smb_header,
)


class N3DSClient:
    """Connect to a 3DS microSD Management SMB1 share and perform file operations."""

    def __init__(self, ip, name, share="microSD", port=139, timeout=10):
        self.ip, self.name, self.share = ip, name, share
        self.port, self.timeout = port, timeout
        self.t, self.uid, self.tid = None, 0, 0

    # -- connection lifecycle -----------------------------------------------

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.ip, self.port))
        self._nb_session(sock)
        self.t = SMBTransport(sock)
        self._negotiate()
        self._auth()
        self._tree_connect()

    def close(self):
        if self.t:
            self.t.sock.close()
            self.t = None

    def _nb_session(self, sock):
        called = b"\x20" + nb_name(self.name, 0x20) + b"\x00"
        calling = b"\x20" + nb_name("3DSCLIENT", 0x20) + b"\x00"
        pl = called + calling
        sock.sendall(bytes([0x81, 0, len(pl) >> 8, len(pl) & 0xFF]) + pl)
        if recv_bytes(sock, 4)[0] != 0x82:
            raise RuntimeError("NetBIOS session refused")

    def _negotiate(self):
        body = b"\x00" + struct.pack("<H", 14) + b"\x02NT LM 0.12\x00"
        h, data = self.t.exchange(smb_header(0x72, mid=self.t.mid()) + body)
        if h["status"]:
            raise RuntimeError(f"negotiate failed: 0x{h['status']:08X}")
        self._max_buf = struct.unpack_from("<I", data, 40)[0]
        self._sess_key = struct.unpack_from("<I", data, 48)[0]

    def _auth(self):
        words = struct.pack(
            "<3BH H H H I H I I",
            12,
            0xFF,
            0,
            0,
            min(self._max_buf, 4356),
            2,
            1,
            self._sess_key,
            len(AUTH_BLOB),
            0,
            0x80000004,
        )
        h, _ = self.t.cmd(0x73, words, AUTH_BLOB + b"Unix\x00Samba\x00")
        if h["status"]:
            raise RuntimeError(f"auth failed: 0x{h['status']:08X}")
        self.uid = h["uid"]

    def _tree_connect(self):
        unc = f"\\\\{self.name.upper()}\\{self.share}"
        words = struct.pack("<BBH H H", 0xFF, 0, 0, 0x0C, 1)
        bdata = b"\x00" + unc.encode("utf-16le") + b"\x00\x00" + b"?????\x00"
        h, _ = self.t.cmd(0x75, words, bdata, uid=self.uid)
        if h["status"]:
            raise RuntimeError(f"tree connect failed: 0x{h['status']:08X}")
        self.tid = h["tid"]

    # -- file handle operations ---------------------------------------------

    def open_file(self, path, access=0x20089, disp=1, opts=0x40, share=1, attrs=0):
        name = path.encode("utf-16le") + b"\x00\x00"
        words = struct.pack(
            "<BBH B H I I I Q I I I I I B",
            0xFF,
            0,
            0,
            0,
            len(name),
            0x16,
            0,
            access,
            0,
            attrs,
            share,
            disp,
            opts,
            2,
            0,
        )
        pad = b"\x00" if ((32 + 1 + len(words) + 2) % 2) else b""
        h, resp = self.t.cmd(0xA2, words, pad + name, tid=self.tid, uid=self.uid)
        if h["status"]:
            raise OSError(f"open failed: 0x{h['status']:08X}")
        return struct.unpack_from("<H", resp, 38)[0]

    def read(self, fid, offset=0, count=4096):
        words = struct.pack(
            "<BBH H I H H I H I",
            0xFF,
            0,
            0,
            fid,
            offset,
            count,
            0,
            0xFFFFFFFF,
            0,
            0,
        )
        h, resp = self.t.cmd(0x2E, words, tid=self.tid, uid=self.uid)
        if h["status"]:
            return b""
        dlen, doff = struct.unpack_from("<2H", resp, 43)
        return resp[doff : doff + dlen]

    def write(self, fid, data, offset=0):
        doff = 64  # hdr(32) + wc(1) + words(28) + bc(2) + pad(1)
        words = struct.pack(
            "<BBH H I I H H H H H I",
            0xFF,
            0,
            0,
            fid,
            offset,
            0,
            0,
            0,
            0,
            len(data),
            doff,
            0,
        )
        h, resp = self.t.cmd(0x2F, words, b"\x00" + data, tid=self.tid, uid=self.uid)
        if h["status"]:
            raise OSError(f"write failed: 0x{h['status']:08X}")
        return struct.unpack_from("<H", resp, 37)[0]

    def close_file(self, fid):
        self.t.cmd(
            0x04, struct.pack("<HI", fid, 0xFFFFFFFF), tid=self.tid, uid=self.uid
        )

    # -- high-level file operations -----------------------------------------

    def listdir(self, path="\\"):
        pattern = (path.rstrip("\\") + "\\*\x00").encode("utf-16le")
        params = struct.pack("<HHHHI", 0x16, 1024, 0x06, 0x0104, 0) + pattern
        st, pp, dd = self._trans2(0x0001, params)
        if len(pp) < 8:
            return []
        return self._parse_dir(dd, struct.unpack_from("<H", pp, 2)[0])

    def get_file(self, remote, fobj):
        fid, total = self.open_file(remote), 0
        try:
            while True:
                chunk = self.read(fid, total, min(self._max_buf - 64, 32768))
                if not chunk:
                    break
                fobj.write(chunk)
                total += len(chunk)
        finally:
            self.close_file(fid)
        return total

    def put_file(self, remote, fobj):
        fid, total = self.open_file(remote, access=0x1F01BF, disp=5, share=0), 0
        try:
            while True:
                chunk = fobj.read(min(self._max_buf - 128, 16384))
                if not chunk:
                    break
                self.write(fid, chunk, total)
                total += len(chunk)
        finally:
            self.close_file(fid)
        return total

    def mkdir(self, path):
        self.close_file(self.open_file(path, access=0x1F01FF, disp=2, opts=1, attrs=0))

    def delete(self, path):
        self.close_file(self.open_file(path, access=0x10000, disp=1, opts=0x1000))

    def rename(self, old, new):
        """SMB_COM_RENAME is broken on 3DS; emulate via copy + delete."""
        buf = io.BytesIO()
        self.get_file(old, buf)
        buf.seek(0)
        self.put_file(new, buf)
        self.delete(old)

    def rmdir(self, path):
        h, _ = self.t.cmd(
            0x01,
            b"",
            b"\x00" + path.encode("utf-16le") + b"\x00\x00",
            tid=self.tid,
            uid=self.uid,
        )
        if h["status"]:
            raise OSError(f"rmdir failed: 0x{h['status']:08X}")

    # -- TRANS2 internals ---------------------------------------------------

    def _trans2(self, subcmd, params, data=b""):
        fixed = 32 + 1 + 30 + 2
        pad_p = (-fixed) & 3
        p_off = fixed + pad_p
        pad_d = (-(p_off + len(params))) & 3
        d_off = p_off + len(params) + pad_d
        words = struct.pack(
            "<HHHHBBHIHHHHH BB",
            len(params),
            len(data),
            10,
            16644,
            0,
            0,
            0,
            0,
            0,
            len(params),
            p_off,
            len(data),
            d_off,
            1,
            0,
        ) + struct.pack("<H", subcmd)
        h, resp = self.t.cmd(
            0x32,
            words,
            b"\x00" * pad_p + params + b"\x00" * pad_d + data,
            tid=self.tid,
            uid=self.uid,
        )
        if h["status"] or resp[32] < 10:
            return h["status"], b"", b""
        _, _, _, pc, po, _, dc, do_ = struct.unpack_from("<8H", resp, 33)
        return h["status"], resp[po : po + pc], resp[do_ : do_ + dc]

    @staticmethod
    def _parse_dir(data, count):
        entries, off = [], 0
        for _ in range(count):
            if off + 94 > len(data):
                break
            (nxt,) = struct.unpack_from("<I", data, off)
            (size,) = struct.unpack_from("<Q", data, off + 40)
            attr, nlen = struct.unpack_from("<II", data, off + 56)
            raw = data[off + 94 : off + 94 + nlen]
            if raw.endswith(b"\x00\x00"):
                raw = raw[:-2]
            try:
                name = raw.decode("utf-16le")
            except Exception:
                name = raw.hex()
            entries.append(
                {"name": name, "size": size, "attr": attr, "is_dir": bool(attr & 0x10)}
            )
            if nxt == 0:
                break
            off += nxt
        return entries
