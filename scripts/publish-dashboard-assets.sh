#!/usr/bin/env bash
# Publish a fully prepared asset directory, never unlink the live generation.
set -euo pipefail
(( $# == 2 )) || { echo "usage: $0 <staged directory> <destination directory>" >&2; exit 2; }
stage=$1
destination=$2
# The staging directory must be a sibling, guaranteeing a same-filesystem rename.
[[ "$(realpath "$(dirname "$stage")")" == "$(realpath "$(dirname "$destination")")" ]]
[[ -d "$stage" && ! -L "$stage" && -s "$stage/SHA256SUMS" ]]
(cd "$stage" && sha256sum --strict -c SHA256SUMS)
if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -d "$destination" && ! -L "$destination" ]]
    # GNU coreutils rename-exchange uses renameat2 on Linux. No fallback to
    # a destructive remove/copy sequence if the filesystem cannot exchange.
    mv --exchange --no-copy -T -- "$stage" "$destination"
else
    # Older release builders only need the initial atomic rename.
    mv -T -- "$stage" "$destination"
fi
