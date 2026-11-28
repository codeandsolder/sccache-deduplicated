# Resolve only concrete packages from the trusted base distribution's signed
# repositories. Publish the exact image and inventory, never re-resolve on clients.
ARG BASE=local/sccache-runtime-base:build-required
FROM ${BASE}
ARG BASE_ID
ARG REQUEST_DIGEST
LABEL org.codeandsolder.sccache-runtime.profile-base="${BASE_ID}"
LABEL org.codeandsolder.sccache-runtime.profile-request="${REQUEST_DIGEST}"
COPY request /usr/share/sccache-runtime/profile-request.txt
RUN set -eu; \
    inventory() { dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}=${Version}\n' | awk '$1 == "ii" {print $2}' | LC_ALL=C sort; }; \
    inventory > /tmp/runtime-base-packages; \
    set --; \
    while IFS= read -r package; do set -- "$@" "$package"; done < /usr/share/sccache-runtime/profile-request.txt; \
    test "$#" -gt 0; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-remove -- "$@"; \
    for package do test "$(dpkg-query -W -f='${db:Status-Abbrev}' -- "$package")" = 'ii '; done; \
    inventory > /usr/share/sccache-runtime/packages.txt; \
    LC_ALL=C comm -23 /tmp/runtime-base-packages /usr/share/sccache-runtime/packages.txt > /usr/share/sccache-runtime/profile-replaced-packages.txt; \
    LC_ALL=C comm -13 /tmp/runtime-base-packages /usr/share/sccache-runtime/packages.txt > /usr/share/sccache-runtime/profile-packages.txt; \
    if test -s /usr/share/sccache-runtime/profile-replaced-packages.txt; then echo 'Base package versions replaced in this derived image:'; cat /usr/share/sccache-runtime/profile-replaced-packages.txt; fi; \
    cut -d= -f1 /tmp/runtime-base-packages | LC_ALL=C sort > /tmp/runtime-base-names; \
    cut -d= -f1 /usr/share/sccache-runtime/packages.txt | LC_ALL=C sort > /tmp/runtime-current-names; \
    test -z "$(LC_ALL=C comm -23 /tmp/runtime-base-names /tmp/runtime-current-names)"; \
    rm -f /tmp/runtime-base-packages /tmp/runtime-base-names /tmp/runtime-current-names; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
