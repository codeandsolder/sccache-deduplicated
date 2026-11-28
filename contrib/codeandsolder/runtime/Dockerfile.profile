# Resolve only concrete packages from the trusted base distribution's signed
# repositories. Publish the exact image and inventory, never re-resolve on clients.
ARG BASE=local/sccache-runtime-base:build-required
FROM ${BASE}
ARG BASE_ID
ARG REQUEST_DIGEST
LABEL org.codeandsolder.sccache-runtime.profile-base="${BASE_ID}"
LABEL org.codeandsolder.sccache-runtime.profile-request="${REQUEST_DIGEST}"
COPY request /usr/share/sccache-runtime/profile-request.txt
RUN --mount=type=bind,source=debs,target=/tmp/runtime-debs,readonly set -eu; \
    inventory() { dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}=${Version}\n' | awk '$1 == "ii" {print $2}' | LC_ALL=C sort; }; \
    inventory > /tmp/runtime-base-packages; \
    set --; \
    while read -r package digest url; do \
        if test -n "$digest"; then \
            archive="/tmp/runtime-debs/$package.deb"; \
            printf '%s  %s\n' "${digest#sha256:}" "$archive" | sha256sum -c -; \
            test "$(dpkg-deb -f "$archive" Package)" = "$package"; \
            set -- "$@" "$archive"; \
        else set -- "$@" "$package"; fi; \
    done < /usr/share/sccache-runtime/profile-request.txt; \
    test "$#" -gt 0; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-remove -- "$@"; \
    while read -r package digest url; do \
        test "$(dpkg-query -W -f='${db:Status-Abbrev}' -- "$package")" = 'ii '; \
        if test -n "$digest"; then \
            test "$(dpkg-query -W -f='${Version}' -- "$package")" = "$(dpkg-deb -f "/tmp/runtime-debs/$package.deb" Version)"; \
        fi; \
    done < /usr/share/sccache-runtime/profile-request.txt; \
    inventory > /usr/share/sccache-runtime/packages.txt; \
    LC_ALL=C comm -23 /tmp/runtime-base-packages /usr/share/sccache-runtime/packages.txt > /usr/share/sccache-runtime/profile-replaced-packages.txt; \
    LC_ALL=C comm -13 /tmp/runtime-base-packages /usr/share/sccache-runtime/packages.txt > /usr/share/sccache-runtime/profile-packages.txt; \
    if test -s /usr/share/sccache-runtime/profile-replaced-packages.txt; then echo 'Base package versions replaced in this derived image:'; cat /usr/share/sccache-runtime/profile-replaced-packages.txt; fi; \
    cut -d= -f1 /tmp/runtime-base-packages | LC_ALL=C sort > /tmp/runtime-base-names; \
    cut -d= -f1 /usr/share/sccache-runtime/packages.txt | LC_ALL=C sort > /tmp/runtime-current-names; \
    test -z "$(LC_ALL=C comm -23 /tmp/runtime-base-names /tmp/runtime-current-names)"; \
    rm -f /tmp/runtime-base-packages /tmp/runtime-base-names /tmp/runtime-current-names; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
