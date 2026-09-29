#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import time
import uuid


def wait_for_stable_size(path: pathlib.Path, timeout_s: float = 2.0) -> int:
    deadline = time.monotonic() + timeout_s
    previous = -1
    stable = 0
    while True:
        size = path.stat().st_size
        if size == previous:
            stable += 1
            if stable >= 3:
                return size
        else:
            stable = 0
            previous = size
        if time.monotonic() >= deadline:
            return size
        time.sleep(0.05)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Atomically rotate a live sccache Rust shadow JSONL and zstd-compress it."
    )
    ap.add_argument("active", type=pathlib.Path)
    ap.add_argument("archive_dir", type=pathlib.Path)
    ap.add_argument("--min-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--level", type=int, default=3)
    args = ap.parse_args()

    try:
        size = args.active.stat().st_size
    except FileNotFoundError:
        print(json.dumps({"rotated": False, "reason": "missing"}))
        return

    if size == 0:
        print(json.dumps({"rotated": False, "reason": "empty"}))
        return
    if size < args.min_bytes and not args.force:
        print(json.dumps({"rotated": False, "reason": "below-threshold", "bytes": size}))
        return

    args.archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    token = uuid.uuid4().hex[:8]
    staging = args.active.with_name(f".{args.active.name}.{stamp}.{token}.rotating")
    archive = args.archive_dir / f"rust-shadow-{stamp}-{token}.jsonl.zst"
    tmp_archive = archive.with_suffix(archive.suffix + ".tmp")

    # rename(2) is atomic within tmpfs. The daemon opens the active path for
    # each append, so new records immediately go to a new active file.
    os.replace(args.active, staging)

    try:
        stable_size = wait_for_stable_size(staging)
        subprocess.run(
            [
                "zstd",
                "-q",
                f"-{args.level}",
                "-T1",
                "-f",
                str(staging),
                "-o",
                str(tmp_archive),
            ],
            check=True,
        )
        subprocess.run(["zstd", "-q", "-t", str(tmp_archive)], check=True)
        os.replace(tmp_archive, archive)
        staging.unlink()
    except BaseException:
        if tmp_archive.exists():
            tmp_archive.unlink()
        # Do not merge back over a new active file. Keep the renamed JSONL
        # beside it for a later retry/manual recovery.
        raise

    print(
        json.dumps(
            {
                "rotated": True,
                "input_bytes": stable_size,
                "archive": str(archive),
                "archive_bytes": archive.stat().st_size,
            }
        )
    )


if __name__ == "__main__":
    main()
