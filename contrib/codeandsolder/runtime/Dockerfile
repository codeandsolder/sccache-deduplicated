# The build context is one complete, verified Rust installation, not a checkout.
# BASE is the immutable runtime image produced by Dockerfile.base.
ARG BASE=local/sccache-runtime-base:build-required
FROM ${BASE}
ARG TOOLCHAIN
ENV RUSTUP_HOME=/opt/sccache-rustup
LABEL org.codeandsolder.sccache-runtime.version="1"
LABEL org.codeandsolder.sccache-runtime.toolchain="${TOOLCHAIN}"
COPY --link . /opt/sccache-rustup/toolchains/${TOOLCHAIN}/
RUN test -n "${TOOLCHAIN}" \
 && printf 'version = "12"\ndefault_toolchain = "%s"\n\n[overrides]\n' "${TOOLCHAIN}" > "$RUSTUP_HOME/settings.toml" \
 && rustup run "${TOOLCHAIN}" rustc -vV \
 && rustup run "${TOOLCHAIN}" cargo -V
