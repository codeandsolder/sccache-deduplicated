#!/usr/bin/env bash
# Prepare only disposable CI runners for the native namespace tests.
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends gcc clang bubblewrap ripgrep fuse3
# Canonical Rust integration tests execute the bundled compiler through
# bwrap, just like the managed Linux hosts.
command -v bwrap
[[ "$(bwrap --help)" == *--overlay-src* ]]
# This disposable test VM must permit nested mount namespaces: the
# networkless caller creates its own overlay for Rust's local link.
# Ubuntu 26.04's bwrap-userns-restrict profile denies nested namespace
# creation independently of the global unprivileged-userns sysctl.
# Do not change this policy on managed production hosts.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
profile=/etc/apparmor.d/bwrap-userns-restrict
if [ -f "$profile" ]; then
  sudo apparmor_parser -R "$profile"
fi
bwrap --unshare-net --ro-bind / / --proc /proc --dev-bind /dev /dev -- \
  bwrap --ro-bind / / --dev-bind /dev /dev -- /usr/bin/true
