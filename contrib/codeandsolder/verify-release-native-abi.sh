#!/usr/bin/env bash
# Enforce native DSO compatibility with all managed sccache workers.
# A GLIBC symbol ceiling alone does not detect libssl.so.4 vs libssl.so.3.
set -euo pipefail

if (($# == 0)); then
    echo "usage: $0 release-binary..." >&2
    exit 2
fi

for binary in "$@"; do
    header="$(readelf -W --file-header "$binary")"
    if ! rg -q 'Machine:.*Advanced Micro Devices X86-64' <<<"$header" ||
       ! rg -q 'Type:.*(EXEC|DYN)' <<<"$header"; then
        echo "::error::$binary is not an x86-64 executable ELF file" >&2
        exit 1
    fi

    # Capture readelf's exit code (a process-substitution failure is ignored).
    dynamic="$(readelf -W --dynamic "$binary")"
    needed="$(sed -nE 's/^.*\(NEEDED\).*Shared library: \[([^]]+)\].*$/\1/p' <<<"$dynamic")"
    if [[ -z "$needed" ]]; then
        if readelf -W --program-headers "$binary" | rg -q 'INTERP'; then
            echo "::error::$binary has a dynamic interpreter but no DT_NEEDED entries" >&2
            exit 1
        fi
        echo "$binary: static ELF with no native DSO dependencies"
        continue
    fi

    while IFS= read -r library; do
        # All names must be supported across the fleet, not merely on the build
        # machine. A new SONAME requires an explicit fleet compatibility review.
        case "$library" in
            libc.so.6|libm.so.6|libgcc_s.so.1|\
            libpthread.so.0|libdl.so.2|librt.so.1|\
            libssl.so.3|libcrypto.so.3)
                ;;
            *)
                echo "::error::$binary requires unsupported fleet DSO $library" >&2
                exit 1
                ;;
        esac
    done <<<"$needed"
    printf '%s: verified native DSOs:\n%s\n' "$binary" "$needed"
done
