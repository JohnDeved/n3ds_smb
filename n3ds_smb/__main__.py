"""Entry point: python3 n3ds_smb [ip] [name]"""

import argparse
import importlib
import os
import subprocess
import sys

# When run as `python3 n3ds_smb`, Python sets __path__ to the package dir
# but doesn't add the parent to sys.path - fix that for absolute imports.
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_pkg_dir)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from n3ds_smb.client import N3DSClient
from n3ds_smb.discovery import clear_discovery_cache, discover_3ds
from n3ds_smb.shell import Shell


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m n3ds_smb",
        description="3DS microSD SMB shell, with optional WebDAV hosting",
    )
    parser.add_argument("ip", nargs="?", help="3DS IP address")
    parser.add_argument("name", nargs="?", help="3DS NetBIOS name shown on the console")
    parser.add_argument(
        "--webdav",
        action="store_true",
        help="serve the 3DS share through a local WebDAV endpoint",
    )
    parser.add_argument("--host", default="127.0.0.1", help="WebDAV bind host")
    parser.add_argument("--port", type=int, default=8080, help="WebDAV bind port")
    parser.add_argument(
        "--readonly", action="store_true", help="start WebDAV in read-only mode"
    )
    parser.add_argument("--user", help="WebDAV basic auth username")
    parser.add_argument("--password", help="WebDAV basic auth password")
    parser.add_argument(
        "--threads", type=int, default=4, help="WebDAV worker thread count"
    )
    parser.add_argument(
        "--no-auto-install",
        action="store_true",
        help="do not auto-install optional WebDAV dependencies",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="clear cached 3DS discovery entry and exit",
    )
    return parser


def _confirm_install() -> bool:
    try:
        answer = input("Install now? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return False
    return answer in ("", "y", "yes")


def _ensure_webdav_dependencies(auto_install: bool) -> bool:
    missing = []
    for module in ("cheroot", "wsgidav"):
        try:
            importlib.import_module(module)
        except ModuleNotFoundError:
            missing.append(module)

    if not missing:
        return True

    print(
        "WebDAV mode requires optional dependencies that are not installed:",
        ", ".join(missing),
        file=sys.stderr,
    )

    install_cmd = [sys.executable, "-m", "pip", "install", "wsgidav", "cheroot"]
    cmd_text = " ".join(install_cmd)

    if not auto_install:
        print(f"Install them manually with: {cmd_text}", file=sys.stderr)
        return False

    print("To continue, n3ds_smb can install them using:", file=sys.stderr)
    print(f"  {cmd_text}", file=sys.stderr)
    if not _confirm_install():
        print("Skipped installation. WebDAV mode was not started.", file=sys.stderr)
        print(f"Install manually with: {cmd_text}", file=sys.stderr)
        return False

    print("Installing optional WebDAV dependencies...", file=sys.stderr)
    try:
        subprocess.run(install_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(
            f"Failed to install dependencies (exit {exc.returncode}).", file=sys.stderr
        )
        print(f"Try manually: {cmd_text}", file=sys.stderr)
        return False

    return _ensure_webdav_dependencies(auto_install=False)


def _resolve_target(args: argparse.Namespace):
    if (args.ip and not args.name) or (args.name and not args.ip):
        raise ValueError("Both ip and name are required when connecting manually.")
    if args.ip and args.name:
        return args.ip, args.name
    return discover_3ds()


def main():
    parser = _make_parser()
    args = parser.parse_args()

    if args.clear_cache:
        removed = clear_discovery_cache()
        if removed:
            print("Cleared discovery cache (~/.n3ds_smb_cache).")
        else:
            print("Discovery cache was already empty.")
        return 0

    try:
        ip, name = _resolve_target(args)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"\nError: {e}", file=sys.stderr)
        print(
            "Tip: You can also connect manually with: python3 -m n3ds_smb <ip> <name>",
            file=sys.stderr,
        )
        return 1

    c = N3DSClient(ip, name)
    try:
        if args.webdav:
            if not _ensure_webdav_dependencies(auto_install=not args.no_auto_install):
                return 1
            from n3ds_smb.webdav import serve_webdav

            serve_webdav(
                c,
                host=args.host,
                port=args.port,
                readonly=args.readonly,
                user=args.user,
                password=args.password,
                numthreads=args.threads,
            )
            return 0

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
