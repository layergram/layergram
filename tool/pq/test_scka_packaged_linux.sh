#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
PACKAGE_ROOT=${LAYERGRAM_SCKA_LINUX_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/linux}
TARGET_DIR="$PACKAGE_ROOT/target"
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
BUNDLE=${LAYERGRAM_LINUX_BUNDLE:-$REPO_ROOT/build/linux/x64/release/bundle}
BUNDLE_BACKUP_DIR=
BUNDLE_EXISTED=false

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [ -n "$BUNDLE_BACKUP_DIR" ]; then
    rm -rf "$BUNDLE"
    if [ "$BUNDLE_EXISTED" = true ]; then
      mkdir -p "$(dirname "$BUNDLE")"
      mv "$BUNDLE_BACKUP_DIR/bundle" "$BUNDLE"
    fi
    rmdir "$BUNDLE_BACKUP_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(uname -s)" = Linux ] || fail 'Linux packaging requires Linux'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA packaging requires Rust 1.87.0'
mkdir -p "$PACKAGE_ROOT"
BUNDLE_BACKUP_DIR=$(mktemp -d "$PACKAGE_ROOT/bundle-backup.XXXXXX")
if [ -d "$BUNDLE" ]; then
  mv "$BUNDLE" "$BUNDLE_BACKUP_DIR/bundle"
  BUNDLE_EXISTED=true
fi
RUSTFLAGS='-C link-arg=-Wl,-z,relro -C link-arg=-Wl,-z,now' \
  cargo build --release --locked --offline --features candidate-ffi \
  --manifest-path "$CRATE_DIR/Cargo.toml" --target-dir "$TARGET_DIR"
flutter build linux --release -t tool/pq/scka_packaged_scope_smoke.dart

LIBRARY="$BUNDLE/lib/liblayergram_scka.so"
install -m 755 "$TARGET_DIR/release/liblayergram_scka.so" "$LIBRARY"
actual="$PACKAGE_ROOT/symbols.txt"
mkdir -p "$PACKAGE_ROOT"
nm -D --defined-only "$LIBRARY" |
  awk '{ name = $NF; sub(/@@.*/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
  sort -u >"$actual"
cmp -s "$SYMBOLS" "$actual" || {
  diff -u "$SYMBOLS" "$actual" >&2 || true
  fail 'Unexpected packaged Linux SCKA export surface'
}
readelf -d "$LIBRARY" | grep -q 'BIND_NOW'
readelf -lW "$LIBRARY" | grep -q 'GNU_RELRO'

if command -v xvfb-run >/dev/null 2>&1; then
  output=$(xvfb-run -a "$BUNDLE/layergram" 2>&1)
else
  output=$($BUNDLE/layergram 2>&1)
fi
printf '%s\n' "$output"
printf '%s\n' "$output" | grep -Fx 'LAYERGRAM_SCKA_PACKAGED_SCOPE_OK' >/dev/null ||
  fail 'Packaged Linux SCKA scope smoke did not complete'

printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_LINUX_OK'
