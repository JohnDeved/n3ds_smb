"""Network discovery: find 3DS IP and name via WS-Discovery."""

import ipaddress, pathlib, re, socket, sys, time, uuid
import xml.etree.ElementTree as ET

from n3ds_smb.transport import nb_name, recv_bytes

_CACHE_FILE = pathlib.Path.home() / ".n3ds_smb_cache"

# ---------------------------------------------------------------------------
# WS-Discovery constants
# ---------------------------------------------------------------------------

_WSD_MCAST = "239.255.255.250"
_WSD_PORT = 3702
_DPWS_PORT = 5357

_NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsdp": "http://schemas.xmlsoap.org/ws/2006/02/devprof",
    "pub": "http://schemas.microsoft.com/windows/pub/2005/07",
    "wsx": "http://schemas.xmlsoap.org/ws/2004/09/mex",
}

_PROBE_XML = """\
<?xml version="1.0" encoding="utf-8"?>\
<soap:Envelope\
 xmlns:soap="http://www.w3.org/2003/05/soap-envelope"\
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"\
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"\
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"\
 xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">\
<soap:Header>\
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\
<wsa:MessageID>urn:uuid:{mid}</wsa:MessageID>\
</soap:Header>\
<soap:Body>\
<wsd:Probe>\
<wsd:Types>wsdp:Device pub:Computer</wsd:Types>\
</wsd:Probe>\
</soap:Body>\
</soap:Envelope>"""

_GET_XML = """\
<?xml version="1.0" encoding="utf-8"?>\
<soap:Envelope\
 xmlns:soap="http://www.w3.org/2003/05/soap-envelope"\
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">\
<soap:Header>\
<wsa:To>{endpoint}</wsa:To>\
<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>\
<wsa:MessageID>urn:uuid:{mid}</wsa:MessageID>\
<wsa:ReplyTo>\
<wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>\
</wsa:ReplyTo>\
</soap:Header>\
<soap:Body/>\
</soap:Envelope>"""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _nb_probe(ip, name, port=139, timeout=0.15):
    """Return True if *ip* accepts a NetBIOS session for *name*."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        called = b"\x20" + nb_name(name, 0x20) + b"\x00"
        calling = b"\x20" + nb_name("P", 0x20) + b"\x00"
        pl = called + calling
        sock.sendall(bytes([0x81, 0, len(pl) >> 8, len(pl) & 0xFF]) + pl)
        resp = recv_bytes(sock, 4)
        if resp[0] == 0x83:
            elen = (resp[1] << 16) | (resp[2] << 8) | resp[3]
            if elen:
                recv_bytes(sock, elen)
        return resp[0] == 0x82
    except OSError:
        return False
    finally:
        sock.close()


def _port_open(ip, port=139, timeout=0.15):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# WS-Discovery
# ---------------------------------------------------------------------------


def _wsd_probe(timeout=1.5):
    """Send a WS-Discovery Probe multicast; yield (ip, endpoint, xaddrs)."""
    probe = _PROBE_XML.format(mid=uuid.uuid4()).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    sock.sendto(probe, (_WSD_MCAST, _WSD_PORT))

    deadline = time.monotonic() + timeout
    seen = set()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            break
        if addr[0] in seen:
            continue
        try:
            root = ET.fromstring(data)
            action = root.find(".//wsa:Action", _NS)
            if action is None or not action.text or "ProbeMatches" not in action.text:
                continue
            for pm in root.findall(".//wsd:ProbeMatch", _NS):
                ep = pm.find("wsa:EndpointReference/wsa:Address", _NS)
                xa = pm.find("wsd:XAddrs", _NS)
                if ep is not None and ep.text and xa is not None and xa.text:
                    seen.add(addr[0])
                    yield addr[0], ep.text, xa.text.strip()
        except ET.ParseError:
            continue
    sock.close()


def _wsd_get_metadata(ip, xaddrs, endpoint, timeout=3.0):
    """HTTP GET device metadata from *xaddrs*; return (name, is_3ds) or (None, False)."""
    m = re.match(r"https?://([^:/]+):?(\d+)?(/.*)?$", xaddrs)
    if not m:
        return None, False
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else _DPWS_PORT
    path = m.group(3) or "/"

    body = _GET_XML.format(endpoint=endpoint, mid=uuid.uuid4()).encode("utf-8")
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8") + body

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.sendall(req)
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
    except OSError:
        return None, False
    finally:
        sock.close()

    text = resp.decode("utf-8", errors="replace")
    xml_start = text.find("<?xml")
    if xml_start < 0:
        return None, False
    try:
        root = ET.fromstring(text[xml_start:])
    except ET.ParseError:
        return None, False

    # Check if this is a Nintendo 3DS
    is_3ds = False
    mfr = root.find(".//{%s}Manufacturer" % _NS["wsdp"])
    if mfr is not None and mfr.text and "Nintendo" in mfr.text:
        is_3ds = True
    fn = root.find(".//{%s}FriendlyName" % _NS["wsdp"])
    if fn is not None and fn.text and "3DS" in fn.text:
        is_3ds = True

    # Extract name from <pub:Computer>NAME/Workgroup:WG</pub:Computer>
    comp = root.find(".//{%s}Computer" % _NS["pub"])
    if comp is not None and comp.text:
        return comp.text.split("/")[0], is_3ds

    return None, is_3ds


def _wsd_discover(timeout=1.5):
    """Discover 3DS via WS-Discovery. Returns (ip, name) or (None, None).

    Sends a multicast Probe, then queries each responder's metadata.
    Stops as soon as a Nintendo 3DS is found.
    """
    for ip, endpoint, xaddrs in _wsd_probe(timeout=timeout):
        name, is_3ds = _wsd_get_metadata(ip, xaddrs, endpoint, timeout=2.0)
        if name and is_3ds:
            return ip, name
    return None, None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _load_cache():
    """Return (ip, name) or (None, None)."""
    try:
        parts = _CACHE_FILE.read_text().strip().split(None, 1)
        ipaddress.IPv4Address(parts[0])
        return parts[0], parts[1] if len(parts) > 1 else None
    except Exception:
        return None, None


def _save_cache(ip, name):
    try:
        _CACHE_FILE.write_text(f"{ip} {name}")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _ask_name(ip):
    """Prompt until the user gives a name the 3DS accepts."""
    while True:
        name = input("3DS name: ").strip()
        if not name:
            raise RuntimeError("no name provided")
        if _nb_probe(ip, name, timeout=2):
            return name
        sys.stderr.write(f"  '{name}' rejected — check the name on the 3DS screen\n")


def discover_3ds():
    """Find the 3DS IP and name. Returns (ip, name).

    Discovery order:
      1. Cache — validate cached (ip, name) with a quick NetBIOS probe
      2. WS-Discovery — multicast Probe + HTTP Get for name (~200ms)
      3. User prompt — ask the user to type the name shown on the 3DS
    """
    t0 = time.monotonic()
    sys.stderr.write("Scanning for 3DS...")
    sys.stderr.flush()

    def _done(ip, name, method):
        dt = (time.monotonic() - t0) * 1000
        sys.stderr.write(f" {name} at {ip} ({method}) [{dt:.0f}ms]\n")
        _save_cache(ip, name)
        return ip, name

    # 1. Cache — instant if still valid
    cached_ip, cached_name = _load_cache()
    if cached_ip and cached_name and _nb_probe(cached_ip, cached_name):
        return _done(cached_ip, cached_name, "cached")

    # 2. WS-Discovery — active multicast probe
    ip, name = _wsd_discover(timeout=3.0)
    if ip and name:
        return _done(ip, name, "WS-Discovery")

    # 3. Fallback — user prompt
    # If we found the IP via cache but name changed, reuse the IP
    if cached_ip and _port_open(cached_ip):
        ip = cached_ip
    if ip:
        sys.stderr.write(f" found {ip}, but could not auto-detect name.\n")
    else:
        sys.stderr.write(" could not find 3DS on the network.\n")
        raise RuntimeError(
            "3DS not found. Ensure microSD Management is running "
            "and your device is on the same network."
        )
    name = _ask_name(ip)
    return _done(ip, name, "manual")
