#!/usr/bin/env python3
"""Fail if a Cargo.lock change introduces crates.io releases younger than the quarantine."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path

CRATES_IO_MARKERS = ("crates.io-index", "index.crates.io")
_cache: dict[str, dict[str, dict]] = {}


def git_show(ref: str, path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{ref}:{path}"])


def load_lock(raw: bytes) -> list[dict]:
    return tomllib.loads(raw.decode()).get("package", [])


def key(pkg: dict) -> tuple[str, str, str | None]:
    return pkg["name"], pkg["version"], pkg.get("source")


def is_crates_io(pkg: dict) -> bool:
    source = pkg.get("source") or ""
    return source.startswith("registry+") and any(marker in source for marker in CRATES_IO_MARKERS)


def crate_versions(name: str) -> dict[str, dict]:
    if name in _cache:
        return _cache[name]
    req = urllib.request.Request(
        "https://crates.io/api/v1/crates/" + urllib.parse.quote(name, safe=""),
        headers={"Accept": "application/json", "User-Agent": "codeandsolder-renovate-quarantine/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.load(response)
    versions = {item["num"]: item for item in payload.get("versions", [])}
    _cache[name] = versions
    return versions


def publication_time(pkg: dict) -> dt.datetime | None:
    info = crate_versions(pkg["name"]).get(pkg["version"])
    value = info.get("created_at") if info else None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--hours", type=int, default=72)
    args = parser.parse_args()

    try:
        before = {key(pkg) for pkg in load_lock(git_show(args.base_ref, "Cargo.lock"))}
    except subprocess.CalledProcessError:
        before = set()

    after = load_lock(Path("Cargo.lock").read_bytes())
    changed = [pkg for pkg in after if key(pkg) not in before and is_crates_io(pkg)]
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.hours)

    blocked: list[str] = []
    for pkg in changed:
        when = publication_time(pkg)
        if when is None:
            blocked.append(f"{pkg['name']} {pkg['version']}: missing authoritative crates.io publication time")
        elif when > cutoff:
            blocked.append(
                f"{pkg['name']} {pkg['version']}: published {when.isoformat()}, "
                f"younger than {args.hours}h"
            )

    if blocked:
        print("Cargo release-age quarantine is still active:", file=sys.stderr)
        for item in blocked:
            print(f"- {item}", file=sys.stderr)
        return 1

    print(f"Cargo release-age quarantine passed for {len(changed)} newly introduced crates.io package versions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
