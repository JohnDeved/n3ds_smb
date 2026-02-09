"""SMB1 wire protocol: NetBIOS session framing, header building, and transport."""

import os, socket, struct

FLAGS2 = 0xC841

# SPNEGO+NTLM Type1 - 3DS accepts immediately without credentials
AUTH_BLOB = bytes.fromhex(
    "604006062b0601050502a0363034a00e300c060a2b0601040182370202"
    "0aa22204204e544c4d5353500001000000050208a00000000000000000"
    "0000000000000000"
)


def nb_name(name, suffix=0x20):
    """Encode a NetBIOS name (first-level encoding)."""
    p = name.upper()[:15].ljust(15) + chr(suffix)
    return bytes(b for c in p for b in ((ord(c) >> 4) + 0x41, (ord(c) & 0xF) + 0x41))


def recv_bytes(sock, n):
    """Read exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def smb_header(cmd, *, tid=0, uid=0, mid=1):
    """Build a 32-byte SMB1 header."""
    return (
        b"\xffSMB"
        + struct.pack("<B", cmd)
        + b"\x00" * 4
        + struct.pack("<BH", 0x18, FLAGS2)
        + b"\x00" * 12
        + struct.pack("<4H", tid, os.getpid() & 0xFFFF, uid, mid)
    )


def parse_header(data):
    """Parse an SMB1 response header. Returns dict or None."""
    if len(data) < 32 or data[:4] != b"\xffSMB":
        return None
    return {
        "cmd": data[4],
        "status": struct.unpack_from("<I", data, 5)[0],
        "tid": struct.unpack_from("<H", data, 24)[0],
        "uid": struct.unpack_from("<H", data, 28)[0],
    }


class SMBTransport:
    """NetBIOS session framing and SMB1 request/response transport."""

    def __init__(self, sock):
        self.sock = sock
        self._mid = 0

    def mid(self):
        self._mid = (self._mid % 0xFFFF) + 1
        return self._mid

    def send(self, payload):
        n = len(payload)
        self.sock.sendall(
            bytes([0, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + payload
        )

    def recv(self):
        h = recv_bytes(self.sock, 4)
        return recv_bytes(self.sock, (h[1] << 16) | (h[2] << 8) | h[3])

    def exchange(self, payload):
        self.send(payload)
        data = self.recv()
        h = parse_header(data)
        if not h:
            raise RuntimeError("invalid SMB response")
        return h, data

    def cmd(self, cmd_id, words, bdata=b"", *, tid=0, uid=0):
        pkt = (
            smb_header(cmd_id, tid=tid, uid=uid, mid=self.mid())
            + struct.pack("<B", len(words) // 2)
            + words
            + struct.pack("<H", len(bdata))
            + bdata
        )
        return self.exchange(pkt)
