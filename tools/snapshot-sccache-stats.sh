#!/usr/bin/env bash
set -euo pipefail

BASE=/dev/shm/sccache-rust-shadow
OUT=$BASE/stats.jsonl
SCCACHE=/usr/local/bin/sccache
UV=/usr/local/bin/uv

mkdir -p "$BASE"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp_stats=$(mktemp -p "$BASE" .stats.XXXXXX)
tmp_dist=$(mktemp -p "$BASE" .dist.XXXXXX)
tmp_line=$(mktemp -p "$BASE" .line.XXXXXX)
trap 'rm -f "$tmp_stats" "$tmp_dist" "$tmp_line"' EXIT

/usr/bin/timeout 5s "$SCCACHE" --show-stats --stats-format json >"$tmp_stats"
if ! /usr/bin/timeout 5s "$SCCACHE" --dist-status >"$tmp_dist"; then
    printf '%s\n' 'null' >"$tmp_dist"
fi

"$UV" run --no-project python - "$stamp" "$tmp_stats" "$tmp_dist" "$tmp_line" <<'PY'
import json, pathlib, sys
stamp, stats_path, dist_path, out_path = sys.argv[1:]
payload = {
    "timestamp_utc": stamp,
    "stats": json.load(open(stats_path)),
    "dist_status": json.load(open(dist_path)),
}
pathlib.Path(out_path).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
PY

cat "$tmp_line" >>"$OUT"
tail -n 1 "$OUT"
