#!/usr/bin/env python3
"""Fail if Cargo.lock introduces crates.io releases younger than the quarantine."""

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
from typing import TypedDict, cast

CRATES_IO_MARKERS = ("crates.io-index", "index.crates.io")


class LockPackage(TypedDict, total=False):
    name: str
    version: str
    source: str


class CrateVersion(TypedDict, total=False):
    num: str
    created_at: str


_cache: dict[str, dict[str, CrateVersion]] = {}


def git_show(ref: str, path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{ref}:{path}"])


def load_lock(raw: bytes) -> list[LockPackage]:
    packages = tomllib.loads(raw.decode()).get("package", [])
    if not isinstance(packages, list):
        return []
    return [
        cast(LockPackage, package) for package in packages if isinstance(package, dict)
    ]


def key(pkg: LockPackage) -> tuple[str, str, str | None]:
    return pkg["name"], pkg["version"], pkg.get("source")


def is_crates_io(pkg: LockPackage) -> bool:
    source = pkg.get("source", "")
    return source.startswith("registry+") and any(
        marker in source for marker in CRATES_IO_MARKERS
    )


def crate_versions(name: str) -> dict[str, CrateVersion]:
    if name in _cache:
        return _cache[name]
    request = urllib.request.Request(
        "https://crates.io/api/v1/crates/" + urllib.parse.quote(name, safe=""),
        headers={
            "Accept": "application/json",
            "User-Agent": "codeandsolder-renovate-quarantine/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("crates.io returned a non-object response")
    raw_versions = payload.get("versions", [])
    if not isinstance(raw_versions, list):
        raise ValueError("crates.io response has a non-list versions field")

    versions: dict[str, CrateVersion] = {}
    for raw_version in raw_versions:
        if not isinstance(raw_version, dict):
            continue
        num = raw_version.get("num")
        if isinstance(num, str):
            versions[num] = cast(CrateVersion, raw_version)
    _cache[name] = versions
    return versions


def publication_time(pkg: LockPackage) -> dt.datetime | None:
    info = crate_versions(pkg["name"]).get(pkg["version"])
    value = info.get("created_at") if info else None
    return dt.datetime.fromisoformat(value) if value else None


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
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(hours=args.hours)

    blocked: list[str] = []
    for pkg in changed:
        when = publication_time(pkg)
        if when is None:
            blocked.append(
                f"{pkg['name']} {pkg['version']}: missing authoritative crates.io publication time"
            )
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

    print(
        "Cargo release-age quarantine passed for "
        f"{len(changed)} newly introduced crates.io package versions."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
