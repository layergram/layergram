#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
TARGET_DIR=${LAYERGRAM_SCKA_TARGET_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-rust}
BUILD_DIR="$TARGET_DIR/release"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required'
command -v rustc >/dev/null 2>&1 || fail 'Rust compiler is required'
command -v cc >/dev/null 2>&1 || fail 'A C11 compiler is required'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA scaffold requires the pinned Rust 1.87.0 toolchain'

cargo test --locked --offline --manifest-path "$CRATE_DIR/Cargo.toml" \
  --target-dir "$TARGET_DIR"
cargo build --release --locked --offline \
  --manifest-path "$CRATE_DIR/Cargo.toml" --target-dir "$TARGET_DIR"

case "$(uname -s)" in
  Darwin)
    LIBRARY="$BUILD_DIR/liblayergram_scka.dylib"
    RPATH_FLAG="-Wl,-rpath,$BUILD_DIR"
    ;;
  Linux)
    LIBRARY="$BUILD_DIR/liblayergram_scka.so"
    RPATH_FLAG="-Wl,-rpath,$BUILD_DIR"
    ;;
  *)
    fail 'Use test_scka_scaffold_windows.ps1 on Windows'
    ;;
esac

[ -f "$LIBRARY" ] || fail "Missing SCKA scaffold library: $LIBRARY"

EXPECTED="$TARGET_DIR/expected-scka-symbols.txt"
ACTUAL="$TARGET_DIR/actual-scka-symbols.txt"
printf '%s\n' \
  lg_scka_v1_abi_version \
  lg_scka_v1_epoch_secret_bytes \
  lg_scka_v1_implementation_id \
  lg_scka_v1_initialize \
  lg_scka_v1_max_message_bytes \
  lg_scka_v1_max_state_bytes \
  lg_scka_v1_min_state_bytes \
  lg_scka_v1_protocol_revision \
  lg_scka_v1_receive \
  lg_scka_v1_self_test \
  lg_scka_v1_send \
  lg_scka_v1_session_id_bytes \
  lg_scka_v1_state_format_version \
  lg_scka_v1_state_header_bytes \
  lg_scka_v1_state_key_bytes \
  lg_scka_v1_state_tag_bytes \
  lg_scka_v1_state_validate | sort -u >"$EXPECTED"

case "$(uname -s)" in
  Darwin)
    xcrun nm -gU "$LIBRARY" |
      awk '{ name = $NF; sub(/^_/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
      sort -u >"$ACTUAL"
    ;;
  Linux)
    nm -D --defined-only "$LIBRARY" |
      awk '{ name = $NF; if (name ~ /^lg_scka_v1_/) print name }' |
      sort -u >"$ACTUAL"
    ;;
esac
cmp -s "$EXPECTED" "$ACTUAL" || {
  diff -u "$EXPECTED" "$ACTUAL" >&2 || true
  fail 'Unexpected Layergram SCKA export surface'
}

SMOKE="$TARGET_DIR/layergram_scka_abi_smoke"
cc -std=c11 -Wall -Wextra -Werror -Wpedantic \
  -I"$CRATE_DIR/include" "$CRATE_DIR/layergram_scka_abi_smoke.c" \
  -L"$BUILD_DIR" -llayergram_scka "$RPATH_FLAG" -o "$SMOKE"
"$SMOKE"

printf '%s\n' 'LAYERGRAM_SCKA_SCAFFOLD_POSIX_OK'
