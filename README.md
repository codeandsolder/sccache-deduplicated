# sccache-deduplicated

Native distributed compiler caching for managed Linux builds. The scheduler
owns the content-addressed store and dispatches cache misses to isolated
workers. Results are restored from verified CAS manifests; compilation never
falls back to the local machine. This fork uses native compilation and linking
actions rather than the upstream archive protocol or storage plugins.

Configure the scheduler, workers, and client before invoking the wrapper:

```sh
sccache gcc -o foo.o -c foo.c
```

For Cargo, configure the installed managed wrapper as `build.rustc-wrapper`.
The fleet tooling provisions the pinned compiler and runtime inputs.

## Documentation

- [Distributed quickstart](docs/DistributedQuickstart.md)
- [Native CAS](docs/NativeCache.md)
- [Configuration](docs/Configuration.md)
- [Architecture](docs/Architecture.md)
- [Rust](docs/Rust.md)
- [Response files](docs/ResponseFiles.md)
- [Request traces](docs/RequestTraces.md)
- [Release and deployment](docs/Releasing.md)

## Storage

There is no backend selector, local result cache, multi-level fallback, ZIP
cache format, or separate preprocessor cache. The native CAS owns result
identity, content verification, retention, and eviction. Use the existing
managed fleet storage and provisioning configuration; do not create a second
compiler cache.

Licensed under the Apache License, Version 2.0.
