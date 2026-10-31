#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import sys
import zipfile
from collections.abc import Iterable, Iterator, Sequence
from typing import Literal, TypedDict, cast

type InputField = Literal[
    "source_inputs",
    "extern_inputs",
    "staticlib_inputs",
    "target_json_inputs",
]
type EnvField = Literal["dep_env", "cargo_env"]
type MemberDigests = tuple[tuple[str, str], ...]


class InputItem(TypedDict):
    digest: str
    raw_path: str
    key_path: str


class EnvValue(TypedDict):
    raw_blake3: str
    key_blake3: str
    raw_text: str | None
    key_text: str | None


class EnvItem(TypedDict):
    name: str
    value: EnvValue


class Record(TypedDict, total=False):
    schema: int
    cache_key: str
    crate_name: str
    crate_types: list[str]
    host: str
    target: str
    compiler_version: str
    compiler_shlibs_digests: list[str]
    arguments_hashed_blob: str
    source_inputs: list[InputItem]
    extern_inputs: list[InputItem]
    staticlib_inputs: list[InputItem]
    target_json_inputs: list[InputItem]
    dep_env: list[EnvItem]
    cargo_env: list[EnvItem]
    cwd_raw: str
    cwd_key: str
    resolved_native_profile: object
    normalization_policy: object
    canonical_enabled: bool


class CacheFingerprint(TypedDict, total=False):
    whole_members: MemberDigests
    compiled_members: MemberDigests
    error: str


class CandidateExample(TypedDict):
    verdict: str
    keys: list[str]
    crate_names: list[str]


class CandidateResult(TypedDict):
    candidate: str
    drops: list[str]
    collision_groups: int
    groups_equal_compiled: int
    groups_different_compiled: int
    groups_missing_cache: int
    examples: list[CandidateExample]


def cache_path(cache_dir: pathlib.Path, key: str) -> pathlib.Path:
    return cache_dir / key[0] / key[1] / key


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint_zip(zf: zipfile.ZipFile) -> CacheFingerprint:
    members: dict[str, str] = {}
    compiled: dict[str, str] = {}
    for info in zf.infolist():
        if info.is_dir():
            continue
        data = zf.read(info)
        digest = digest_bytes(data)
        members[info.filename] = digest
        name = info.filename
        if (
            name.endswith((".rlib", ".rmeta", ".o", ".so", ".a", ".dll", ".dylib"))
            or ".rcgu.o" in name
        ):
            compiled[name] = digest
    return {
        "whole_members": tuple(sorted(members.items())),
        "compiled_members": tuple(sorted(compiled.items())),
    }


def cache_fingerprint(path: pathlib.Path) -> CacheFingerprint | None:
    if not path.is_file():
        return None
    try:
        with zipfile.ZipFile(path) as zf:
            return _fingerprint_zip(zf)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"error": str(exc)}


def env_map(record: Record, field: EnvField) -> dict[str, str]:
    return {item["name"]: item["value"]["key_blake3"] for item in record.get(field, [])}


def input_digests(record: Record, field: InputField) -> tuple[str, ...]:
    if field == "source_inputs":
        items = record.get("source_inputs", [])
    elif field == "extern_inputs":
        items = record.get("extern_inputs", [])
    elif field == "staticlib_inputs":
        items = record.get("staticlib_inputs", [])
    else:
        items = record.get("target_json_inputs", [])
    return tuple(sorted(item["digest"] for item in items))


def signature(record: Record, drops: Iterable[str] = ()) -> str:
    drop_set = set(drops)
    dep_env = env_map(record, "dep_env")
    cargo_env = env_map(record, "cargo_env")

    for drop in drop_set:
        if drop.startswith("dep_env:"):
            dep_env.pop(drop.split(":", 1)[1], None)
        elif drop.startswith("cargo_env:"):
            cargo_env.pop(drop.split(":", 1)[1], None)

    parts: dict[str, object] = {
        "crate_name": record.get("crate_name"),
        "crate_types": record.get("crate_types"),
        "host": record.get("host"),
        "target": record.get("target"),
        "compiler_version": record.get("compiler_version"),
        "compiler_shlibs_digests": tuple(record.get("compiler_shlibs_digests", [])),
        "arguments_hashed_blob": record.get("arguments_hashed_blob"),
        "source": input_digests(record, "source_inputs"),
        "extern": input_digests(record, "extern_inputs"),
        "staticlib": input_digests(record, "staticlib_inputs"),
        "target_json": input_digests(record, "target_json_inputs"),
        "dep_env": tuple(sorted(dep_env.items())),
        "cargo_env": tuple(sorted(cargo_env.items())),
        "cwd_key": record.get("cwd_key"),
        "native": record.get("resolved_native_profile"),
        "normalization_policy": record.get("normalization_policy"),
    }

    drop_map = {
        "cwd": "cwd_key",
        "arguments": "arguments_hashed_blob",
        "native_profile": "native",
        "compiler_shlibs": "compiler_shlibs_digests",
    }
    for drop in drop_set:
        if drop in drop_map:
            parts.pop(drop_map[drop], None)

    return json.dumps(parts, sort_keys=True, separators=(",", ":"), default=list)


def iter_log_lines(path: pathlib.Path) -> Iterator[str]:
    if path.suffix == ".zst":
        proc = subprocess.Popen(
            ["zstd", "-q", "-dc", str(path)],
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        try:
            yield from proc.stdout
        finally:
            proc.stdout.close()
            if proc.wait() != 0:
                raise RuntimeError(f"zstd failed while reading {path}")
    else:
        with path.open("r", encoding="utf-8") as fh:
            yield from fh


def recover_embedded_records(line: str) -> list[Record]:
    decoder = json.JSONDecoder()
    recovered: list[Record] = []
    marker = '{"schema":'
    start = 0
    while True:
        start = line.find(marker, start)
        if start < 0:
            return recovered
        try:
            record, _ = decoder.raw_decode(line[start:])
        except json.JSONDecodeError:
            start += len(marker)
            continue
        if (
            isinstance(record, dict)
            and record.get("schema") == 1
            and "cache_key" in record
        ):
            recovered.append(cast(Record, record))
        start += len(marker)


def load_records(paths: Iterable[pathlib.Path]) -> tuple[list[Record], int, int]:
    records: list[Record] = []
    bad = 0
    recovered = 0
    for path in paths:
        for lineno, raw_line in enumerate(iter_log_lines(path), 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError as exc:
                salvaged = recover_embedded_records(line)
                if salvaged:
                    records.extend(salvaged)
                    recovered += len(salvaged)
                    print(
                        f"{path}:{lineno}: recovered {len(salvaged)} embedded record(s) from invalid JSON: {exc}",
                        file=sys.stderr,
                    )
                    continue
                bad += 1
                print(f"{path}:{lineno}: invalid JSON: {exc}", file=sys.stderr)
                continue
            if (
                not isinstance(candidate, dict)
                or candidate.get("schema") != 1
                or "cache_key" not in candidate
            ):
                bad += 1
                continue
            records.append(cast(Record, candidate))
    return records, bad, recovered


def normalization_summary(
    records: Sequence[Record],
) -> tuple[collections.Counter[str], dict[str, list[tuple[str | None, str | None]]]]:
    counts: collections.Counter[str] = collections.Counter()
    examples: collections.defaultdict[str, list[tuple[str | None, str | None]]] = (
        collections.defaultdict(list)
    )
    for record in records:
        if record.get("cwd_raw") != record.get("cwd_key"):
            counts["cwd"] += 1
            if len(examples["cwd"]) < 3:
                examples["cwd"].append((record.get("cwd_raw"), record.get("cwd_key")))
        for field in (
            "source_inputs",
            "extern_inputs",
            "staticlib_inputs",
            "target_json_inputs",
        ):
            for item in record.get(field, []):
                if item.get("raw_path") != item.get("key_path"):
                    counts[field] += 1
                    if len(examples[field]) < 3:
                        examples[field].append(
                            (item.get("raw_path"), item.get("key_path"))
                        )
        for field in ("dep_env", "cargo_env"):
            for item in record.get(field, []):
                value = item["value"]
                if value.get("raw_blake3") != value.get("key_blake3"):
                    key = f"{field}:{item['name']}"
                    counts[key] += 1
                    if len(examples[key]) < 3:
                        examples[key].append(
                            (value.get("raw_text"), value.get("key_text"))
                        )
    return counts, examples


def compare_candidate(
    records: Sequence[Record],
    cache_dir: pathlib.Path,
    drops: Iterable[str],
) -> CandidateResult:
    drop_tuple = tuple(drops)
    groups: collections.defaultdict[str, list[Record]] = collections.defaultdict(list)
    for record in records:
        groups[signature(record, drop_tuple)].append(record)

    collision_groups: list[tuple[list[str], list[Record]]] = []
    for group_records in groups.values():
        keys = sorted({record["cache_key"] for record in group_records})
        if len(keys) > 1:
            collision_groups.append((keys, group_records))

    result: CandidateResult = {
        "candidate": drop_tuple[0] if len(drop_tuple) == 1 else "+".join(drop_tuple),
        "drops": list(drop_tuple),
        "collision_groups": len(collision_groups),
        "groups_equal_compiled": 0,
        "groups_different_compiled": 0,
        "groups_missing_cache": 0,
        "examples": [],
    }

    fingerprint_cache: dict[str, CacheFingerprint | None] = {}
    for keys, group_records in collision_groups:
        compiled_fingerprints: set[MemberDigests] = set()
        missing = False
        for key in keys:
            if key not in fingerprint_cache:
                fingerprint_cache[key] = cache_fingerprint(cache_path(cache_dir, key))
            fingerprint = fingerprint_cache[key]
            if (
                fingerprint is None
                or "error" in fingerprint
                or "compiled_members" not in fingerprint
            ):
                missing = True
            else:
                compiled_fingerprints.add(fingerprint["compiled_members"])

        if missing:
            result["groups_missing_cache"] += 1
            verdict = "missing-cache"
        elif len(compiled_fingerprints) == 1:
            result["groups_equal_compiled"] += 1
            verdict = "compiled-equal"
        else:
            result["groups_different_compiled"] += 1
            verdict = "compiled-different"

        if len(result["examples"]) < 5:
            result["examples"].append(
                {
                    "verdict": verdict,
                    "keys": keys,
                    "crate_names": sorted(
                        {
                            name
                            for record in group_records
                            if (name := record.get("crate_name")) is not None
                        }
                    ),
                }
            )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="+", type=pathlib.Path)
    parser.add_argument("--cache-dir", type=pathlib.Path, required=True)
    parser.add_argument("--json-out", type=pathlib.Path)
    parser.add_argument(
        "--canonical-only",
        action="store_true",
        help="analyze only records produced with canonical Rust mode enabled",
    )
    parser.add_argument(
        "--drop-set",
        action="append",
        default=[],
        metavar="A,B,...",
        help="also analyze a combined candidate that drops the comma-separated dimensions",
    )
    args = parser.parse_args()

    logs = cast(list[pathlib.Path], args.logs)
    cache_dir = cast(pathlib.Path, args.cache_dir)
    json_out = cast(pathlib.Path | None, args.json_out)
    canonical_only = cast(bool, args.canonical_only)
    drop_sets = cast(list[str], args.drop_set)

    records, bad, recovered = load_records(logs)
    loaded_records = len(records)
    if canonical_only:
        records = [
            record for record in records if record.get("canonical_enabled") is True
        ]
    if not records:
        raise SystemExit("no valid telemetry records after filtering")

    dep_names = sorted(
        {item["name"] for record in records for item in record.get("dep_env", [])}
    )
    cargo_names = sorted(
        {item["name"] for record in records for item in record.get("cargo_env", [])}
    )
    candidates = ["cwd", "arguments", "native_profile", "compiler_shlibs"]
    candidates += [f"dep_env:{name}" for name in dep_names]
    candidates += [f"cargo_env:{name}" for name in cargo_names]

    combined: list[tuple[str, ...]] = []
    for spec in drop_sets:
        drops = tuple(part.strip() for part in spec.split(",") if part.strip())
        if len(drops) < 2:
            raise SystemExit(f"--drop-set requires at least two dimensions: {spec!r}")
        unknown = [drop for drop in drops if drop not in candidates]
        if unknown:
            raise SystemExit(
                f"--drop-set contains unknown dimension(s): {', '.join(unknown)}"
            )
        if drops not in combined:
            combined.append(drops)

    counts, examples = normalization_summary(records)
    analyses = [
        compare_candidate(records, cache_dir, (candidate,)) for candidate in candidates
    ]
    combined_analyses = [
        compare_candidate(records, cache_dir, drops) for drops in combined
    ]

    report = {
        "loaded_records": loaded_records,
        "canonical_only": canonical_only,
        "records": len(records),
        "invalid_records": bad,
        "recovered_records": recovered,
        "distinct_cache_keys": len({record["cache_key"] for record in records}),
        "normalization_changes": dict(counts),
        "normalization_examples": dict(examples),
        "candidate_analysis": analyses,
        "combined_candidate_analysis": combined_analyses,
    }

    text = json.dumps(report, indent=2, sort_keys=True)
    if json_out:
        json_out.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
