#!/usr/bin/env sh
# Installs the cloud-posture binary from GitHub releases (or builds from source when Go is present).
set -eu
VERSION="${1:-latest}"
REPO="DreadpiratePickles/nimbus"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; esac
DEST="${DEST:-/usr/local/bin}"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/cloud-posture_${OS}_${ARCH}"
else
  URL="https://github.com/$REPO/releases/download/$VERSION/cloud-posture_${OS}_${ARCH}"
fi
if curl -fsSL "$URL" -o /tmp/cloud-posture 2>/dev/null; then
  chmod +x /tmp/cloud-posture && (mv /tmp/cloud-posture "$DEST/cloud-posture" 2>/dev/null || sudo mv /tmp/cloud-posture "$DEST/cloud-posture")
  echo "installed $("$DEST"/cloud-posture version)"
elif command -v go >/dev/null 2>&1; then
  echo "no release asset for $OS/$ARCH; building from source"
  GOBIN="$DEST" go install "github.com/$REPO/cmd/cloud-posture@${VERSION}"
else
  echo "could not download $URL and Go is not installed" >&2; exit 1
fi
