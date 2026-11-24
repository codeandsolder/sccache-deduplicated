# Native CAS real-compiler and ARC locality benchmark

This Linux benchmark compares direct host Clang compilation with the actual
native-CAS Bubblewrap executor on ZFS and non-ZFS backends. It is implemented
in `crates/build-runtime/examples/native_realbuild_arc.rs`.

Run with explicit working directories on different filesystems:

```bash
cargo +stable run -p sccache-build --example native_realbuild_arc \
  --release --locked -- \
  /path/on/zfs /path/on/nonzfs /usr/bin/clang /usr/bin/bwrap
```

The two working directories should be on the intended backing filesystems.
Each store and its scratch share one filesystem, so ZFS block cloning stays
within the same dataset. The example creates and removes isolated temporary
CAS roots and never changes ARC limits, ZFS settings, or production services.

## Workload

The benchmark captures the **real installed Clang ELF executable and 15+
dynamic loader/library dependencies**, then compiles a generated C
translation unit including 384 separate headers with
`clang -cc1 -O2 -emit-obj`. Every native output object is verified
byte-for-byte against direct host Clang.

It measures seven identical-root executions per backend and seven distinct
source variants differing only by a trailing comment. The changed source
preserves the output bytes but changes the input-tree identity, exposing
cache-reuse behavior on real action misses.

Three source layouts are compared in rotated order:

1. One newly composed root containing compiler, libraries, all headers and
   the changed source file. This matches the current compiler frontend's
   `TreeRecipe::union` and empty `ExecutionSpec.mounts`.
2. A stable compiler/library root with a changing source mount that still
   contains all 384 unchanged headers.
3. A stable compiler/library/header root with only one changing source file
   mounted separately. The explicit `-I /src` include path preserves
   header resolution and the generated object remains byte-identical.

Output includes wall time, CAS import time, source identity, and per-run
global ARC hit/miss and memory counters. The benchmark deliberately does
not include scheduler/network transfer latency.

## Interpretation

Warm identical-root timing does not predict normal cache misses because
an unchanged action should already be a cache hit. A source-only change can
invalidate the current immutable-view cache, which is keyed by complete
`TreeId`. Global ARC counters do not attribute demand to the
individual job, and non-ZFS tmpfs/FUSE measurements do not generalize to
disk-backed ext4/XFS. First execution is subject to dynamic loader cold
pages, ZFS TXG work, and competing host activity.

A true ARC-pressure comparison needs controlled residency on isolated
datasets/test hosts; never globally flush ARC on an active worker.

See merged [PR #416](https://github.com/codeandsolder/sccache-deduplicated/pull/416)
for the storage policy, [issue #432](https://github.com/codeandsolder/sccache-deduplicated/issues/432)
for general immutable subtree reuse, and the
[Notion experiment log](https://app.notion.com/p/422f74be9020815ca210d49c64a216ed)
for current measurements and methods.
