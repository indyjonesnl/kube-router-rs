#!/usr/bin/env bash
# Populate e2e/k0s/gobgp-bin/{gobgp,gobgpd} from the pinned gobgp release.
# These are gitignored build artifacts that Dockerfile.deploy COPYs into the image.
set -euo pipefail
GOBGP_VERSION="${GOBGP_VERSION:-4.5.0}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gobgp-bin"
mkdir -p "$DIR"
if [ -x "$DIR/gobgpd" ] && [ -x "$DIR/gobgp" ]; then
  echo "gobgp binaries already present in $DIR"; exit 0
fi
url="https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz"
echo "fetching $url"
tmp="$(mktemp -d)"
curl -sSLf "$url" -o "$tmp/gobgp.tgz"
tar -xzf "$tmp/gobgp.tgz" -C "$tmp" gobgp gobgpd
install -m 0755 "$tmp/gobgp" "$tmp/gobgpd" "$DIR/"
rm -rf "$tmp"
echo "installed gobgp v${GOBGP_VERSION} into $DIR"
