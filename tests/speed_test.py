#!/usr/bin/env python3
"""Live SMB speed test against a real 3DS.

Usage:
    python3 tests/speed_test.py
    N3DS_IP=<ip> N3DS_NAME=<name> python3 tests/speed_test.py --sizes 1,8,32 --repeats 2
"""

from __future__ import annotations

import argparse
import io
import os
import random
import sys
import time

# Allow running directly from repo root: python3 tests/speed_test.py
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_THIS_DIR)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from n3ds_smb import N3DSClient, discover_3ds


def _parse_sizes(text: str) -> list[tuple[str, int]]:
    """Parse sizes like: 64kb,256kb,1mb (or 64k,1m)."""
    out = []
    for part in text.split(","):
        part = part.strip().lower()
        if not part:
            continue
        mult = None
        if part.endswith("kb"):
            mult = 1024
            num = part[:-2]
        elif part.endswith("k"):
            mult = 1024
            num = part[:-1]
        elif part.endswith("mb"):
            mult = 1024 * 1024
            num = part[:-2]
        elif part.endswith("m"):
            mult = 1024 * 1024
            num = part[:-1]
        else:
            # Backward-compatible default: treat bare numbers as MB.
            mult = 1024 * 1024
            num = part
        value = int(num)
        if value <= 0:
            raise ValueError("sizes must be positive")
        byte_count = value * mult
        label = f"{value}KB" if mult == 1024 else f"{value}MB"
        out.append((label, byte_count))
    if not out:
        raise ValueError("at least one test size is required")
    return out


def _mbps(byte_count: int, elapsed: float) -> float:
    if elapsed <= 0:
        return 0.0
    return byte_count / (1024 * 1024) / elapsed


def _progress(prefix: str, done: int, total: int) -> None:
    pct = (done / total * 100.0) if total else 100.0
    width = 30
    filled = int(width * (pct / 100.0))
    bar = "#" * filled + "-" * (width - filled)
    mb_done = done / (1024 * 1024)
    mb_total = total / (1024 * 1024)
    print(
        f"\r{prefix} [{bar}] {pct:6.2f}% ({mb_done:6.2f}/{mb_total:6.2f} MB)",
        end="",
        flush=True,
    )


def _put_with_progress(
    client: N3DSClient, remote_file: str, data: bytes, show_progress: bool
) -> None:
    fid = client.open_file(remote_file, access=0x1F01BF, disp=5, share=0)
    try:
        total = len(data)
        off = 0
        chunk = int(getattr(client, "_write_chunk", 16384))
        while off < total:
            part = data[off : off + chunk]
            client.write(fid, part, off)
            off += len(part)
            if show_progress:
                _progress("  upload", off, total)
    finally:
        client.close_file(fid)
    if show_progress:
        print()


def _get_with_progress(
    client: N3DSClient, remote_file: str, total: int, show_progress: bool
) -> bytes:
    out = io.BytesIO()
    fid = client.open_file(remote_file)
    try:
        off = 0
        chunk = int(getattr(client, "_read_chunk", 8192))
        while True:
            data = client.read(fid, off, chunk)
            if not data:
                break
            out.write(data)
            off += len(data)
            if show_progress:
                _progress("download", off, total)
    finally:
        client.close_file(fid)
    if show_progress:
        print()
    return out.getvalue()


def _fmt_row(
    size_label: str, w_mbps: float, r_mbps: float, sec_w: float, sec_r: float
) -> str:
    return (
        f"{size_label:>7} | {w_mbps:>12.2f} | {r_mbps:>11.2f}"
        f" | {sec_w:>9.3f} | {sec_r:>8.3f}"
    )


def _resolve_target(args: argparse.Namespace) -> tuple[str, str]:
    if args.ip and args.name:
        return args.ip, args.name
    env_ip = os.environ.get("N3DS_IP", "")
    env_name = os.environ.get("N3DS_NAME", "")
    if env_ip and env_name:
        return env_ip, env_name
    return discover_3ds()


def _cleanup_dir(client: N3DSClient, path: str) -> None:
    try:
        entries = client.listdir(path)
    except Exception:
        return
    for e in entries:
        name = e["name"]
        if name in (".", ".."):
            continue
        child = path.rstrip("\\") + "\\" + name
        if e["is_dir"]:
            _cleanup_dir(client, child)
            try:
                client.rmdir(child)
            except Exception:
                pass
        else:
            try:
                client.delete(child)
            except Exception:
                pass
    try:
        client.rmdir(path)
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Measure SMB read/write throughput to a 3DS"
    )
    ap.add_argument("ip", nargs="?", help="3DS IP address")
    ap.add_argument("name", nargs="?", help="3DS NetBIOS name")
    ap.add_argument(
        "--sizes",
        default="64kb,256kb,1mb",
        help="comma-separated sizes (kb/mb), default: 64kb,256kb,1mb",
    )
    ap.add_argument(
        "--repeats", type=int, default=2, help="repeats per size (default: 2)"
    )
    ap.add_argument("--seed", type=int, default=1337, help="RNG seed for test data")
    ap.add_argument("--keep", action="store_true", help="keep remote test files")
    ap.add_argument(
        "--no-progress",
        action="store_true",
        help="disable per-transfer progress updates",
    )
    args = ap.parse_args()

    if args.repeats <= 0:
        print("Error: --repeats must be >= 1")
        return 2

    try:
        sizes = _parse_sizes(args.sizes)
    except Exception as exc:
        print(f"Error: invalid --sizes value: {exc}")
        return 2

    try:
        ip, name = _resolve_target(args)
    except Exception as exc:
        print(f"Error: could not resolve 3DS target: {exc}")
        return 1

    print(f"Target: {name} ({ip})")
    print(f"Sizes: {[label for label, _ in sizes]}, repeats: {args.repeats}")
    show_progress = not args.no_progress

    rng = random.Random(args.seed)
    client = N3DSClient(ip, name)
    run_id = f"{int(time.time())}_{rng.randint(1000, 9999)}"
    remote_dir = f"\\__speedtest__{run_id}"

    rows = []
    total_w_bytes = 0
    total_r_bytes = 0
    total_w_sec = 0.0
    total_r_sec = 0.0

    try:
        client.connect()
        client.mkdir(remote_dir)

        for size_label, size_bytes in sizes:
            data = rng.randbytes(size_bytes)
            file_name = f"speed_{size_label.lower()}.bin"
            remote_file = remote_dir + "\\" + file_name

            write_rates = []
            read_rates = []
            write_secs = []
            read_secs = []

            for _ in range(args.repeats):
                if show_progress:
                    print(f"\nTesting {size_label} ...")
                t0 = time.perf_counter()
                _put_with_progress(client, remote_file, data, show_progress)
                dt_w = time.perf_counter() - t0

                t1 = time.perf_counter()
                got = _get_with_progress(client, remote_file, len(data), show_progress)
                dt_r = time.perf_counter() - t1

                if got != data:
                    raise RuntimeError(f"data mismatch for {file_name}")

                write_secs.append(dt_w)
                read_secs.append(dt_r)
                write_rates.append(_mbps(len(data), dt_w))
                read_rates.append(_mbps(len(data), dt_r))

            avg_w = sum(write_rates) / len(write_rates)
            avg_r = sum(read_rates) / len(read_rates)
            avg_sw = sum(write_secs) / len(write_secs)
            avg_sr = sum(read_secs) / len(read_secs)

            rows.append((size_label, avg_w, avg_r, avg_sw, avg_sr))
            total_w_bytes += len(data) * args.repeats
            total_r_bytes += len(data) * args.repeats
            total_w_sec += sum(write_secs)
            total_r_sec += sum(read_secs)

        print()
        print("Size    | Write MB/s   | Read MB/s   | Write sec | Read sec")
        print("--------+--------------+-------------+-----------+---------")
        for row in rows:
            print(_fmt_row(*row))

        print()
        print(
            f"Overall write throughput: {_mbps(total_w_bytes, total_w_sec):.2f} MB/s"
            f" over {total_w_sec:.2f}s"
        )
        print(
            f"Overall read throughput:  {_mbps(total_r_bytes, total_r_sec):.2f} MB/s"
            f" over {total_r_sec:.2f}s"
        )
        print(f"Remote test dir: {remote_dir}")
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        if not args.keep:
            _cleanup_dir(client, remote_dir)
        client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
