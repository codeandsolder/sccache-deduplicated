#!/usr/bin/env bash
set -euo pipefail

BASE=/srv/scratch/projects/sccache
ARCHIVE=$BASE/telemetry/archive
REPORTS=$BASE/telemetry/reports
ANALYZER=$BASE/maintenance/analyze-rust-shadow.py
CURRENT=/dev/shm/sccache-rust-shadow/current.jsonl
STATS_CURRENT=/dev/shm/sccache-rust-shadow/stats.jsonl
ERROR_CURRENT=/dev/shm/sccache-rust-shadow/error.log
CACHE=/var/cache/sccache

mkdir -p "$REPORTS"

logs=()
while IFS= read -r -d '' f; do
    logs+=("$f")
done < <(find "$ARCHIVE" -maxdepth 1 -type f -name '*.jsonl.zst' -print0 2>/dev/null | sort -z)

if [[ -s "$CURRENT" ]]; then
    logs+=("$CURRENT")
fi

if (( ${#logs[@]} == 0 )); then
    echo "no telemetry logs available"
    exit 0
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
mixed_tmp="$REPORTS/.report-$stamp.json.tmp"
mixed_out="$REPORTS/report-$stamp.json"
canon_tmp="$REPORTS/.report-$stamp-canonical.json.tmp"
canon_out="$REPORTS/report-$stamp-canonical.json"

common_drop_sets=(
  --drop-set cargo_env:CARGO_EPHEMERAL_REGISTRY_SRC,cargo_env:CARGO_RUSTC_CURRENT_DIR
  --drop-set cargo_env:CARGO_EPHEMERAL_REGISTRY_SRC,cargo_env:CARGO_RUSTC_CURRENT_DIR,cargo_env:CARGO_NET_OFFLINE
)

/usr/local/bin/uv run --no-project python "$ANALYZER" \
    "${logs[@]}" --cache-dir "$CACHE" --json-out "$mixed_tmp" >/dev/null

/usr/local/bin/uv run --no-project python "$ANALYZER" \
    "${logs[@]}" --cache-dir "$CACHE" --canonical-only \
    "${common_drop_sets[@]}" --json-out "$canon_tmp" >/dev/null

mv "$mixed_tmp" "$mixed_out"
mv "$canon_tmp" "$canon_out"
ln -sfn "$(basename "$mixed_out")" "$REPORTS/latest.json"
ln -sfn "$(basename "$canon_out")" "$REPORTS/latest-canonical.json"

if [[ -s "$STATS_CURRENT" ]]; then
    stats_out="$REPORTS/stats-$stamp.jsonl.zst"
    stats_tmp="$REPORTS/.stats-$stamp.jsonl.zst.tmp"
    zstd -q -3 -T1 -c "$STATS_CURRENT" >"$stats_tmp"
    zstd -q -t "$stats_tmp"
    mv "$stats_tmp" "$stats_out"
    ln -sfn "$(basename "$stats_out")" "$REPORTS/latest-stats.jsonl.zst"
fi

if [[ -s "$ERROR_CURRENT" ]]; then
    error_out="$REPORTS/error-$stamp.log.zst"
    error_tmp="$REPORTS/.error-$stamp.log.zst.tmp"
    zstd -q -3 -T1 -c "$ERROR_CURRENT" >"$error_tmp"
    zstd -q -t "$error_tmp"
    mv "$error_tmp" "$error_out"
    ln -sfn "$(basename "$error_out")" "$REPORTS/latest-error.log.zst"
fi

summary=$(
  /usr/local/bin/uv run --no-project python - "$mixed_out" "$canon_out" <<'PY'
import json,sys
mixed=json.load(open(sys.argv[1]))
canon=json.load(open(sys.argv[2]))
parts=[
    f"mixed_records={mixed['records']}",
    f"canonical_records={canon['records']}",
    f"canonical_keys={canon['distinct_cache_keys']}",
    f"invalid={canon['invalid_records']}",
    f"recovered={canon.get('recovered_records',0)}",
]
singles=[]
for x in canon['candidate_analysis']:
    if x['groups_equal_compiled'] and not x['groups_different_compiled']:
        singles.append(
            f"{x['candidate']}:{x['groups_equal_compiled']}/{x['collision_groups']}"
        )
if singles:
    parts.append("clean_singles="+",".join(singles))
combined=[]
for x in canon.get('combined_candidate_analysis', []):
    if x['collision_groups']:
        combined.append(
            f"{x['candidate']}:{x['groups_equal_compiled']}eq/"
            f"{x['groups_different_compiled']}diff/{x['groups_missing_cache']}missing"
        )
if combined:
    parts.append("combined="+";".join(combined))
print(" ".join(parts))
PY
)

echo "$summary"
logger -t sccache-rust-shadow-analysis -- "$summary"
