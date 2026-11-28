# Distributed compilation quickstart

Use the [native scheduler cache configuration](NativeCache.md#configuration)
and [ordinary compiler client setup](NativeCache.md#ordinary-compiler-client).
For cluster enrollment, authentication, and maintenance, see
[Distributed.md](Distributed.md).

Build the pinned fleet binaries with the distributed client and server
features enabled. Configure a scheduler with a native store, enroll Linux
workers, and configure the client to use that scheduler. Workers require
bubblewrap and the native runtime prerequisites described in NativeCache.md.
Compilation is remote-only; an unavailable worker or unsupported action is
an explicit error. The legacy archive transport, Docker/overlay/pot
builders, and FreeBSD worker support have been removed.
