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
    if len(sys.argv) >= 3:
        ip, name = sys.argv[1], sys.argv[2]
    else:
        ip, name = discover_3ds()
    c = N3DSClient(ip, name)
    try:
        c.connect()
        print(f"Connected to {c.name} ({c.ip})")
        Shell(c).cmdloop()
    except KeyboardInterrupt:
        print()
    finally:
        c.close()


if __name__ == "__main__":
    main()
