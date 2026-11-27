#!/usr/bin/env bash
# Enforce native DSO compatibility with all managed sccache workers.
# Check the native TLS/C++ runtime and libc floor on the actual linked ELF.
set -euo pipefail
export LC_ALL=C
# shellcheck source=contrib/codeandsolder/release-protocol.env
source "$(dirname "$0")/release-protocol.env"
[[ "$glibc_abi_max" =~ ^[0-9]+\.[0-9]+$ ]]
max_supported="GLIBC_$glibc_abi_max"

if (($# == 0)); then
    echo "usage: $0 release-binary..." >&2
    exit 2
fi

for binary in "$@"; do
    header="$(readelf -W --file-header "$binary")"
    if [[ ! "$header" =~ Class:[[:space:]]+ELF64 ||
          ! "$header" =~ Data:.*little\ endian ||
          ! "$header" =~ Machine:.*Advanced\ Micro\ Devices\ X86-64 ||
          ! "$header" =~ Type:[[:space:]]+(EXEC|DYN) ||
          ! "$header" =~ Entry\ point\ address:[[:space:]]+0x[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]* ]]; then
        echo "::error::$binary is not an x86-64 executable ELF file" >&2
        exit 1
    fi

    # Capture readelf's exit code (a process-substitution failure is ignored).
    dynamic="$(readelf -W --dynamic "$binary")"
    program_headers="$(readelf -W --program-headers "$binary")"
    interpreter="$(sed -nE 's/^.*Requesting program interpreter: ([^]]+)\].*$/\1/p' <<<"$program_headers")"
    if [[ -n "$interpreter" && "$interpreter" != /lib64/ld-linux-x86-64.so.2 ]]; then
        echo "::error::$binary has unsupported interpreter $interpreter" >&2
        exit 1
    fi
    if [[ "$dynamic" =~ \((RPATH|RUNPATH|AUDIT|DEPAUDIT|FILTER|AUXILIARY)\) ]]; then
        echo "::error::$binary embeds a runtime library search or injection directive" >&2
        exit 1
    fi
    versions="$(readelf -W --version-info "$binary")"
    labels="$(sed -nE 's/^.*Name: ([^[:space:]]+).*$/\1/p' <<<"$versions" | sort -u)"
    while IFS= read -r version; do
        case "$version" in
            GLIBC_ABI_DT_RELR) required="GLIBC_2.36" ;;
            GLIBC_[0-9]*)
                if [[ ! "$version" =~ ^GLIBC_[0-9]+(\.[0-9]+)+$ ]]; then
                    echo "::error::$binary requires unknown libc ABI $version" >&2
                    exit 1
                fi
                required="$version"
                ;;
            # Exact public libgcc_s version definitions common to all four
            # managed x86-64 hosts. Numeric ordering is insufficient because
            # version nodes are sparse (e.g. there is no GCC_11.0.0).
            GCC_3.0|GCC_3.3|GCC_3.3.1|GCC_3.4|GCC_3.4.2|GCC_3.4.4|\
            GCC_4.0.0|GCC_4.2.0|GCC_4.3.0|GCC_4.7.0|GCC_4.8.0|\
            GCC_7.0.0|GCC_12.0.0|GCC_13.0.0|GCC_14.0.0)
                continue
                ;;
            GLIBC_*|GLIBCXX_*|CXXABI_*|GCC_*)
                echo "::error::$binary requires unsupported versioned ABI $version" >&2
                exit 1
                ;;
            *) continue ;;
        esac
        if [[ "$(printf '%s\n%s\n' "$max_supported" "$required" | sort -V | tail -n 1)" != "$max_supported" ]]; then
            echo "::error::$binary requires $required, newer than $max_supported" >&2
            exit 1
        fi
    done <<<"$labels"
    echo "$binary: verified libc ABI ceiling $max_supported"
    needed="$(sed -nE 's/^.*\(NEEDED\).*Shared library: \[([^]]+)\].*$/\1/p' <<<"$dynamic")"
    if [[ "$dynamic" =~ \(NEEDED\) && -z "$needed" ]]; then
        echo "::error::$binary contains unreadable DT_NEEDED entries" >&2
        exit 1
    fi
    if [[ -z "$needed" ]]; then
        if [[ -n "$interpreter" ]]; then
            echo "::error::$binary has a dynamic interpreter but no DT_NEEDED entries" >&2
            exit 1
        fi
        echo "$binary: static ELF with no native DSO dependencies"
        continue
    fi

    if [[ "$interpreter" != /lib64/ld-linux-x86-64.so.2 ]]; then
        echo "::error::$binary has native DSO dependencies without the fleet interpreter" >&2
        exit 1
    fi
    while IFS= read -r library; do
        # All names must be supported across the fleet, not merely on the build
        # machine. A new SONAME requires an explicit fleet compatibility review.
        case "$library" in
            libc.so.6|libm.so.6|libgcc_s.so.1|\
            libpthread.so.0|libdl.so.2|librt.so.1|ld-linux-x86-64.so.2)
                # The loader is already mandatory as PT_INTERP. Its explicit
                # DT_NEEDED entry may be emitted by the static C++ runtime.
                # All versioned imports, including loader imports, are checked
                # above; GLIBC_PRIVATE is forbidden.
                ;;
            *)
                echo "::error::$binary requires unsupported fleet DSO $library" >&2
                exit 1
                ;;
        esac
    done <<<"$needed"
    printf '%s: verified native DSOs:\n%s\n' "$binary" "$needed"
done
