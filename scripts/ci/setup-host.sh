#!/usr/bin/env bash
# Prepares a throwaway CI runner for root integration tests. It changes
# host settings (IP forwarding, the iptables FORWARD policy) and installs
# gVisor: never run it on a machine you care about.
set -euo pipefail

if [ "${CI:-}" != "true" ]; then
  echo "refusing to run outside CI (set CI=true on a throwaway machine)" >&2
  exit 1
fi

GVISOR_RELEASE=${GVISOR_RELEASE:-20261019.0}
arch=$(uname -m)

# gVisor: runsc plus its helper binaries, checksum-verified.
work=$(mktemp -d)
base="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${arch}"
curl -fsSL -o "$work/gvisor.tar.zstd" "$base/gvisor.tar.zstd"
curl -fsSL -o "$work/gvisor.tar.zstd.sha512" "$base/gvisor.tar.zstd.sha512"
(cd "$work" && sha512sum -c gvisor.tar.zstd.sha512)
sudo mkdir -p /usr/local/lib/gvisor
sudo tar --zstd -xf "$work/gvisor.tar.zstd" -C /usr/local/lib/gvisor
sudo ln -sf /usr/local/lib/gvisor/runsc /usr/local/bin/runsc
runsc --version

# The allowlist network forwards packets from the veth to the uplink.
sudo sysctl -q -w net.ipv4.ip_forward=1
# Docker on the runner sets the iptables FORWARD policy to DROP, which would
# drop forwarded packets our own nftables table accepts.
if command -v iptables >/dev/null; then
  sudo iptables -P FORWARD ACCEPT
fi
nft --version || sudo apt-get install -y -qq nftables
