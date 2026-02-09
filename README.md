# n3ds_smb

Zero-dependency Python SMB1 client for the New Nintendo 3DS **microSD Management** feature.

Automatically discovers the 3DS on your local network via WS-Discovery, connects to the microSD share over WiFi, and provides an interactive file browser shell - no configuration needed.

## Quick Start

```
python3 n3ds_smb
```

That's it. The tool discovers your 3DS automatically and drops you into a shell:

```
Scanning for 3DS... 3DS-MYNAME at 192.168.1.42 (WS-Discovery) [194ms]
Connected to 3DS-MYNAME (192.168.1.42)
Type 'help' for commands.
3ds> ls
         <DIR>  Nintendo 3DS
         <DIR>  DCIM
3ds> cd "Nintendo 3DS"
3ds> tree
...
3ds> get somefile.bin
  1,234 bytes -> somefile.bin
3ds> quit
```

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)
- New Nintendo 3DS / 3DS XL / 2DS XL with **microSD Management** enabled
  (System Settings → Data Management → microSD Management)
- Both devices on the same WiFi network

## Usage

### Interactive Shell

```bash
# Auto-discover (recommended)
python3 n3ds_smb

# Explicit IP and name
python3 n3ds_smb 192.168.1.42 3DS-MYNAME
```

Shell commands:

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory contents |
| `cd [path]` | Change directory (no arg = root) |
| `pwd` | Print working directory |
| `get <remote> [local]` | Download a file |
| `put <local> [remote]` | Upload a file |
| `mkdir <path>` | Create a directory |
| `rm <file>` | Delete a file |
| `rmdir <path>` | Remove an empty directory |
| `mv <old> <new>` | Rename/move a file |
| `ping` | Send SMB echo request |
| `df` | Show total/used/free space |
| `tree [path]` | Recursive directory listing |
| `quit` | Exit |

### Python API

```python
from n3ds_smb import N3DSClient, discover_3ds

# Auto-discover
ip, name = discover_3ds()

# Connect
client = N3DSClient(ip, name)
client.connect()

# List files
for entry in client.listdir("\\"):
    print(entry["name"], entry["size"], entry["is_dir"])

# Download
with open("backup.bin", "wb") as f:
    client.get_file("\\Nintendo 3DS\\somefile", f)

# Upload
with open("local.bin", "rb") as f:
    client.put_file("\\upload.bin", f)

# Other operations
client.mkdir("\\new_folder")
client.delete("\\old_file.bin")
client.rename("\\old_name.bin", "\\new_name.bin")
client.rmdir("\\empty_folder")

client.close()
```

## How Discovery Works

The tool discovers the 3DS using **WS-Discovery** (the same protocol Windows uses):

1. **Cache check** (~10ms) - If we've connected before, validate the cached IP+name
2. **WS-Discovery Probe** (~200-700ms) - Send a UDP multicast probe to `239.255.255.250:3702`. The 3DS responds with its endpoint URL
3. **HTTP metadata fetch** (~30ms) - GET device metadata from the 3DS's DPWS HTTP endpoint (port 5357) which contains the NetBIOS name
4. **Fallback** - If multicast doesn't work (e.g. network restrictions), prompt the user for the name shown on the 3DS screen

The cache is stored at `~/.n3ds_smb_cache` for instant reconnection on subsequent runs.

## How It Works (Protocol)

The 3DS microSD Management exposes an **SMB1** file server on TCP port 139. This client implements the minimum SMB1 protocol needed:

- **NetBIOS Session Service** - Session setup with the 3DS's name
- **SMB_COM_NEGOTIATE** - Dialect negotiation (`NT LM 0.12`)
- **SPNEGO/NTLM Auth** - The 3DS accepts any NTLM Type 1 blob without verifying credentials
- **Tree Connect** - Connects to the `microSD` share
- **File operations** - TRANS2 directory listing, NT_CREATE_ANDX, read, write, close

Notable quirks of the 3DS SMB implementation:
- `SMB_COM_DELETE` and `SMB_COM_RENAME` work, but require strict Unicode alignment around `BufferFormat` bytes
- Single TCP connection at a time - the 3DS only handles one client
- Auth bypass - no credentials are ever verified

## Security Research

See [exploits.md](exploits.md) for detailed findings from reverse-engineering the 3DS SMB server, including:

- SPNEGO authentication bypass
- DELETE/RENAME Unicode alignment gotchas (and the now-correct native implementation)
- Tree Connect name oracle
- NetBIOS session handler bugs (including a remote DoS)
- Dual NTLM code paths and patched overflow analysis
- Three broadcast discovery protocols (NBNS, Browser, WS-Discovery)
- Active name discovery via WS-Discovery + DPWS metadata

## Running Tests

Tests run against a live 3DS:

```bash
N3DS_IP=<your_3ds_ip> N3DS_NAME=<your_3ds_name> python3 -m unittest tests.test_3ds -v
```

## Project Structure

```
n3ds_smb/
  __init__.py    - Public API: N3DSClient, discover_3ds
  __main__.py    - Entry point: python3 n3ds_smb [ip name]
  transport.py   - SMB1 wire protocol: NBSS framing, headers, SMBTransport
  client.py      - N3DSClient: connect, auth, file operations
  discovery.py   - WS-Discovery based auto-discovery
  shell.py       - Interactive cmd.Cmd shell
tests/
  test_3ds.py    - 9 live integration tests
exploits.md      - Security research findings (11 discoveries)
```

## License

MIT
