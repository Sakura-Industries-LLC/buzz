#!/usr/bin/env bash
# Place dntls-demo-buzz next to the other Tauri sidecars as
# desktop/src-tauri/binaries/dntls-demo-buzz-<target-triple>.
#
# Preference:
#   1. DNTLS_DEMO_BUZZ_LOCAL=/path/to/dntls-demo-buzz  — copy a locally built binary.
#   2. Otherwise download the GitHub release archive for the target OS/arch from
#      Sakura-Industries-LLC/dntls-demo-buzz. DNTLS_DEMO_BUZZ_VERSION pins the
#      release (with or without the leading "v"); unset means the latest one.
#      Release builds must pin it so a rebuild of a tag ships the same connector.
set -euo pipefail

HOST=$(rustc -vV | sed -n 's|host: ||p')
TARGET=${1:-$HOST}
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BINARIES_DIR=$(cd "$SCRIPT_DIR/../src-tauri" && pwd)/binaries

if [[ "$TARGET" == *windows* ]]; then
  EXE=".exe"
else
  EXE=""
fi

DEST="$BINARIES_DIR/dntls-demo-buzz-${TARGET}${EXE}"
mkdir -p "$BINARIES_DIR"

if [[ -n "${DNTLS_DEMO_BUZZ_LOCAL:-}" ]]; then
  if [[ ! -f "$DNTLS_DEMO_BUZZ_LOCAL" ]]; then
    echo "Error: DNTLS_DEMO_BUZZ_LOCAL is not a file: $DNTLS_DEMO_BUZZ_LOCAL" >&2
    exit 1
  fi
  cp "$DNTLS_DEMO_BUZZ_LOCAL" "$DEST"
  if [[ -z "$EXE" ]]; then
    chmod 755 "$DEST"
  fi
  echo "Copied local connector to $DEST"
  exit 0
fi

case "$TARGET" in
  aarch64-apple-darwin) ARCHIVE_SUFFIX="darwin_arm64.tar.gz" ;;
  x86_64-apple-darwin) ARCHIVE_SUFFIX="darwin_amd64.tar.gz" ;;
  aarch64-unknown-linux-gnu | aarch64-unknown-linux-musl) ARCHIVE_SUFFIX="linux_arm64.tar.gz" ;;
  x86_64-unknown-linux-gnu | x86_64-unknown-linux-musl) ARCHIVE_SUFFIX="linux_amd64.tar.gz" ;;
  aarch64-pc-windows-msvc) ARCHIVE_SUFFIX="windows_arm64.zip" ;;
  x86_64-pc-windows-msvc) ARCHIVE_SUFFIX="windows_amd64.zip" ;;
  *)
    echo "Error: unsupported target triple $TARGET" >&2
    echo "Build dntls-demo-buzz locally and set DNTLS_DEMO_BUZZ_LOCAL." >&2
    exit 1
    ;;
esac

REPO="Sakura-Industries-LLC/dntls-demo-buzz"
if [[ -n "${DNTLS_DEMO_BUZZ_VERSION:-}" ]]; then
  TAG="v${DNTLS_DEMO_BUZZ_VERSION#v}"
elif ! TAG=$(gh release view -R "$REPO" --json tagName --jq .tagName 2>/dev/null); then
  echo "Error: no GitHub release for $REPO yet." >&2
  echo "Build dntls-demo-buzz locally and rerun with DNTLS_DEMO_BUZZ_LOCAL=/path/to/dntls-demo-buzz." >&2
  exit 1
fi
VERSION="${TAG#v}"
ARCHIVE="dntls-demo-buzz_${VERSION}_${ARCHIVE_SUFFIX}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
gh release download "$TAG" -R "$REPO" --pattern "$ARCHIVE" --dir "$WORKDIR"

mkdir -p "$WORKDIR/out"
if [[ "$ARCHIVE" == *.zip ]]; then
  # Git Bash on Windows runners ships neither unzip nor a zip-capable tar,
  # so fall back to 7-Zip, which those images do carry.
  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$WORKDIR/$ARCHIVE" -d "$WORKDIR/out"
  elif command -v 7z >/dev/null 2>&1; then
    7z x -bso0 -bsp0 -o"$WORKDIR/out" "$WORKDIR/$ARCHIVE"
  else
    echo "Error: extracting $ARCHIVE needs unzip or 7z on PATH." >&2
    exit 1
  fi
else
  tar -xzf "$WORKDIR/$ARCHIVE" -C "$WORKDIR/out"
fi

SOURCE=$(find "$WORKDIR/out" -type f -name "dntls-demo-buzz${EXE}" | head -n 1)
if [[ -z "$SOURCE" ]]; then
  echo "Error: archive $ARCHIVE did not contain dntls-demo-buzz${EXE}" >&2
  exit 1
fi
cp "$SOURCE" "$DEST"
if [[ -z "$EXE" ]]; then
  chmod 755 "$DEST"
fi
echo "Fetched $TAG connector to $DEST"
