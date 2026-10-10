#!/bin/sh
# Install a *tagged, verified* cloud-posture release.
#
#   curl -fsSLO https://raw.githubusercontent.com/DreadpiratePickles/nimbus/v0.2.0/install.sh
#   less install.sh                      # read it first
#   VERSION=v0.2.0 sh install.sh --require-signature
#
# What it does, in order, and it refuses (exit non-zero) at the first failure:
#   1. resolves a release tag (VERSION, or the latest published release) - never a branch
#   2. downloads the archive for this OS/arch, checksums.txt and checksums.txt.sigstore.json
#   3. verifies the cosign keyless signature on checksums.txt against this repo's release workflow
#      identity (mandatory with --require-signature / REQUIRE_SIGNATURE=1; otherwise skipped with a
#      warning when cosign is not installed)
#   4. verifies the archive's SHA-256 against checksums.txt
#   5. extracts and installs the binary into INSTALL_DIR (no sudo; it tells you if it cannot write)
# It never pipes anything else into a shell.
#
# Options / environment:
#   --version <tag>        | VERSION=v0.2.0        release tag (default: latest published release)
#   --install-dir <dir>    | INSTALL_DIR=/path     default /usr/local/bin if writable, else ~/.local/bin
#   --require-signature    | REQUIRE_SIGNATURE=1   fail unless cosign verifies the signature
#   BASE_URL=<url>         directory holding the release assets (mirrors / local testing;
#                          plain http is accepted only for localhost)
set -eu

REPO="DreadpiratePickles/nimbus"
PROJECT="cloud-posture"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

VERSION="${VERSION:-}"
INSTALL_DIR="${INSTALL_DIR:-}"
REQUIRE_SIGNATURE="${REQUIRE_SIGNATURE:-0}"
BASE_URL="${BASE_URL:-}"

say() { printf 'install.sh: %s\n' "$*" >&2; }
die() { printf 'install.sh: ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --install-dir) [ $# -ge 2 ] || die "--install-dir needs a value"; INSTALL_DIR="$2"; shift 2 ;;
    --install-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
    --require-signature) REQUIRE_SIGNATURE=1; shift ;;
    -h|--help) sed -n '2,27p' "$0" 2>/dev/null || true; exit 0 ;;
    -*) die "unknown option: $1" ;;
    *) VERSION="$1"; shift ;;   # positional version, for compatibility
  esac
done

case "$REQUIRE_SIGNATURE" in 1|true|yes) REQUIRE_SIGNATURE=1 ;; *) REQUIRE_SIGNATURE=0 ;; esac

# --- transport ---------------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then DL=curl
elif command -v wget >/dev/null 2>&1; then DL=wget
else die "need curl or wget"; fi

case "$BASE_URL" in
  ""|https://*) PROTO_HTTPS=1 ;;
  http://127.0.0.1[:/]*|http://localhost[:/]*|http://\[::1\][:/]*) PROTO_HTTPS=0 ;;
  *) die "BASE_URL must be https:// (plain http only for localhost): $BASE_URL" ;;
esac

fetch() { # fetch <url> <dest>
  if [ "$DL" = curl ]; then
    if [ "$PROTO_HTTPS" = 1 ]; then curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
    else curl -fsSL -o "$2" "$1"; fi
  else
    if [ "$PROTO_HTTPS" = 1 ]; then wget --https-only -q -O "$2" "$1"
    else wget -q -O "$2" "$1"; fi
  fi
}

# --- platform ----------------------------------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux|darwin) ;;
  mingw*|msys*|cygwin*) die "Windows: download ${PROJECT}_<version>_windows_<arch>.zip and checksums.txt from https://github.com/$REPO/releases and verify them as described in SECURITY.md" ;;
  *) die "unsupported OS: $OS" ;;
esac
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

# --- version -----------------------------------------------------------------------------------
if [ -z "$VERSION" ] || [ "$VERSION" = latest ]; then
  [ -z "$BASE_URL" ] || die "set VERSION explicitly when BASE_URL is used"
  TMPJSON="$(mktemp)"
  fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMPJSON" || { rm -f "$TMPJSON"; die "could not resolve the latest release; set VERSION=vX.Y.Z"; }
  VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMPJSON" | head -n 1)"
  rm -f "$TMPJSON"
  [ -n "$VERSION" ] || die "could not resolve the latest release; set VERSION=vX.Y.Z"
  say "latest release is $VERSION"
fi
VER="${VERSION#v}"
TAG="v$VER"
# Tags only: refuse branch names such as main/master/HEAD and anything that is not semver-shaped.
printf '%s' "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$' \
  || die "VERSION must be a release tag like v0.2.0 (got '$VERSION'); branches are never installed"

[ -n "$BASE_URL" ] || BASE_URL="https://github.com/$REPO/releases/download/$TAG"
BASE_URL="${BASE_URL%/}"

ARCHIVE="${PROJECT}_${VER}_${OS}_${ARCH}.tar.gz"
SIG_IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t cloud-posture)"
trap 'rm -rf "$WORK"' EXIT INT TERM

say "downloading $ARCHIVE ($TAG) from $BASE_URL"
fetch "$BASE_URL/$ARCHIVE" "$WORK/$ARCHIVE" || die "download failed: $BASE_URL/$ARCHIVE"
fetch "$BASE_URL/checksums.txt" "$WORK/checksums.txt" || die "download failed: $BASE_URL/checksums.txt"

# --- signature ---------------------------------------------------------------------------------
if command -v cosign >/dev/null 2>&1; then
  fetch "$BASE_URL/checksums.txt.sigstore.json" "$WORK/checksums.txt.sigstore.json" \
    || die "signature bundle checksums.txt.sigstore.json is missing; refusing to install"
  say "verifying cosign signature (identity $SIG_IDENTITY)"
  cosign verify-blob \
    --bundle "$WORK/checksums.txt.sigstore.json" \
    --certificate-identity "$SIG_IDENTITY" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$WORK/checksums.txt" >/dev/null 2>"$WORK/cosign.err" \
    || { cat "$WORK/cosign.err" >&2; die "signature verification FAILED; refusing to install"; }
  say "signature OK"
elif [ "$REQUIRE_SIGNATURE" = 1 ]; then
  die "--require-signature given but cosign is not installed (brew install cosign, or https://docs.sigstore.dev/cosign/system_config/installation/)"
else
  say "WARNING: cosign not found; the signature was NOT verified (only the checksum will be)."
  say "         install cosign (brew install cosign, or https://docs.sigstore.dev/cosign/system_config/installation/)"
  say "         and re-run with --require-signature to make this mandatory."
fi

# --- checksum ----------------------------------------------------------------------------------
EXPECTED="$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1; exit }' "$WORK/checksums.txt")"
[ -n "$EXPECTED" ] || die "$ARCHIVE is not listed in checksums.txt; refusing to install"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$WORK/$ARCHIVE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$WORK/$ARCHIVE" | awk '{print $1}')"
else
  die "need sha256sum or shasum to verify the download"
fi
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum MISMATCH for $ARCHIVE (expected $EXPECTED, got $ACTUAL); refusing to install"
say "checksum OK ($ACTUAL)"

# --- install -----------------------------------------------------------------------------------
tar -xzf "$WORK/$ARCHIVE" -C "$WORK" "$PROJECT" || die "could not extract $PROJECT from $ARCHIVE"
if [ -z "$INSTALL_DIR" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then INSTALL_DIR=/usr/local/bin
  else INSTALL_DIR="$HOME/.local/bin"; fi
fi
mkdir -p "$INSTALL_DIR" 2>/dev/null || true
[ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable; re-run with INSTALL_DIR=\$HOME/.local/bin (this script never uses sudo)"
chmod 0755 "$WORK/$PROJECT"
mv -f "$WORK/$PROJECT" "$INSTALL_DIR/$PROJECT"
say "installed $INSTALL_DIR/$PROJECT: $("$INSTALL_DIR/$PROJECT" version 2>/dev/null || echo '?')"
case ":$PATH:" in *":$INSTALL_DIR:"*) ;; *) say "note: $INSTALL_DIR is not on your PATH" ;; esac
