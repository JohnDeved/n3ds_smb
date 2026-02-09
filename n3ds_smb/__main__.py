"""Entry point: python3 n3ds_smb [ip] [name]"""

import os, sys

# When run as `python3 n3ds_smb`, Python sets __path__ to the package dir
# but doesn't add the parent to sys.path — fix that for absolute imports.
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_pkg_dir)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from n3ds_smb.client import N3DSClient
from n3ds_smb.discovery import discover_3ds
from n3ds_smb.shell import Shell


def main():
    if len(sys.argv) not in (1, 3):
        print("Usage: python3 -m n3ds_smb [ip name]", file=sys.stderr)
        return 2

    try:
        if len(sys.argv) == 3:
            ip, name = sys.argv[1], sys.argv[2]
        else:
            ip, name = discover_3ds()
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"\nError: {e}", file=sys.stderr)
        print(
            "Tip: You can also connect manually with: python3 -m n3ds_smb <ip> <name>",
            file=sys.stderr,
        )
        return 1

    c = N3DSClient(ip, name)
    try:
        c.connect()
        print(f"Connected to {c.name} ({c.ip})")
        Shell(c).cmdloop()
    except KeyboardInterrupt:
        print()
        return 130
    except OSError as e:
        print(f"Error: could not connect to {ip} ({name}): {e}", file=sys.stderr)
        print(
            "Make sure microSD Management is open on the 3DS and both devices are on the same WiFi.",
            file=sys.stderr,
        )
        return 1
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
