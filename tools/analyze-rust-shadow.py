#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import sys
import zipfile


def cache_path(cache_dir: pathlib.Path, key: str) -> pathlib.Path:
    return cache_dir / key[0] / key[1] / key


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cache_fingerprint(path: pathlib.Path):
    if not path.is_file():
        return None
    try:
        with zipfile.ZipFile(path) as zf:
            members = {}
            compiled = {}
            for info in zf.infolist():
                if info.is_dir():
                    continue
                data = zf.read(info)
                h = digest_bytes(data)
                members[info.filename] = h
                name = info.filename
                if (
                    name.endswith((".rlib", ".rmeta", ".o", ".so", ".a", ".dll", ".dylib"))
                    or ".rcgu.o" in name
                ):
                    compiled[name] = h
            return {
                "whole_members": tuple(sorted(members.items())),
                "compiled_members": tuple(sorted(compiled.items())),
            }
    except (OSError, zipfile.BadZipFile) as exc:
        return {"error": str(exc)}


def env_map(record, field):
    return {
        item["name"]: item["value"]["key_blake3"]
        for item in record.get(field, [])
    }


def input_digests(record, field):
    return tuple(sorted(item["digest"] for item in record.get(field, [])))


def signature(record, drop=None):
    dep_env = env_map(record, "dep_env")
    cargo_env = env_map(record, "cargo_env")

    if drop and drop.startswith("dep_env:"):
        dep_env.pop(drop.split(":", 1)[1], None)
    if drop and drop.startswith("cargo_env:"):
        cargo_env.pop(drop.split(":", 1)[1], None)

    parts = {
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
    if drop in drop_map:
        parts.pop(drop_map[drop], None)

    return json.dumps(parts, sort_keys=True, separators=(",", ":"), default=list)


def iter_log_lines(path):
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


def recover_embedded_records(line):
    decoder = json.JSONDecoder()
    recovered = []
    marker = '{"schema":'
    start = 0
    while True:
        start = line.find(marker, start)
        if start < 0:
            return recovered
        try:
            rec, _ = decoder.raw_decode(line[start:])
        except json.JSONDecodeError:
            start += len(marker)
            continue
        if isinstance(rec, dict) and rec.get("schema") == 1 and "cache_key" in rec:
            recovered.append(rec)
        start += len(marker)


def load_records(paths):
    records = []
    bad = 0
    recovered = 0
    for path in paths:
        for lineno, line in enumerate(iter_log_lines(path), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
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
            if rec.get("schema") != 1 or "cache_key" not in rec:
                bad += 1
                continue
            records.append(rec)
    return records, bad, recovered


def normalization_summary(records):
    counts = collections.Counter()
    examples = collections.defaultdict(list)
    for rec in records:
        if rec.get("cwd_raw") != rec.get("cwd_key"):
            counts["cwd"] += 1
            if len(examples["cwd"]) < 3:
                examples["cwd"].append((rec.get("cwd_raw"), rec.get("cwd_key")))
        for field in ("source_inputs", "extern_inputs", "staticlib_inputs", "target_json_inputs"):
            for item in rec.get(field, []):
                if item.get("raw_path") != item.get("key_path"):
                    counts[field] += 1
                    if len(examples[field]) < 3:
                        examples[field].append((item.get("raw_path"), item.get("key_path")))
        for field in ("dep_env", "cargo_env"):
            for item in rec.get(field, []):
                value = item.get("value", {})
                if value.get("raw_blake3") != value.get("key_blake3"):
                    key = f"{field}:{item.get('name')}"
                    counts[key] += 1
                    if len(examples[key]) < 3:
                        examples[key].append((value.get("raw_text"), value.get("key_text")))
    return counts, examples


def compare_candidate(records, cache_dir, drop):
    groups = collections.defaultdict(list)
    for rec in records:
        groups[signature(rec, drop)].append(rec)

    collision_groups = []
    for recs in groups.values():
        keys = sorted({r["cache_key"] for r in recs})
        if len(keys) > 1:
            collision_groups.append((keys, recs))

    result = {
        "candidate": drop,
        "collision_groups": len(collision_groups),
        "groups_equal_compiled": 0,
        "groups_different_compiled": 0,
        "groups_missing_cache": 0,
        "examples": [],
    }

    fp_cache = {}
    for keys, recs in collision_groups:
        fps = []
        missing = False
        for key in keys:
            if key not in fp_cache:
                fp_cache[key] = cache_fingerprint(cache_path(cache_dir, key))
            fp = fp_cache[key]
            if not fp or "error" in fp:
                missing = True
            fps.append(fp)

        if missing:
            result["groups_missing_cache"] += 1
            verdict = "missing-cache"
        else:
            compiled = {fp["compiled_members"] for fp in fps}
            if len(compiled) == 1:
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
                    "crate_names": sorted({r.get("crate_name") for r in recs}),
                }
            )
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+", type=pathlib.Path)
    ap.add_argument("--cache-dir", type=pathlib.Path, required=True)
    ap.add_argument("--json-out", type=pathlib.Path)
    args = ap.parse_args()

    records, bad, recovered = load_records(args.logs)
    if not records:
        raise SystemExit("no valid telemetry records")

    dep_names = sorted({item["name"] for r in records for item in r.get("dep_env", [])})
    cargo_names = sorted({item["name"] for r in records for item in r.get("cargo_env", [])})
    candidates = ["cwd", "arguments", "native_profile", "compiler_shlibs"]
    candidates += [f"dep_env:{name}" for name in dep_names]
    candidates += [f"cargo_env:{name}" for name in cargo_names]

    counts, examples = normalization_summary(records)
    analyses = [compare_candidate(records, args.cache_dir, c) for c in candidates]

    report = {
        "records": len(records),
        "invalid_records": bad,
        "recovered_records": recovered,
        "distinct_cache_keys": len({r["cache_key"] for r in records}),
        "normalization_changes": dict(counts),
        "normalization_examples": dict(examples),
        "candidate_analysis": analyses,
    }

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out:
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
