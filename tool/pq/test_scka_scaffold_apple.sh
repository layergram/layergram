#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
TARGET_DIR=${LAYERGRAM_SCKA_APPLE_TARGET_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-rust-apple}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[ "$(uname -s)" = Darwin ] || fail 'Apple SCKA checks require macOS'
command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
command -v xcrun >/dev/null 2>&1 || fail 'Xcode command-line tools are required'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA scaffold requires the pinned Rust 1.87.0 toolchain'

EXPECTED="$TARGET_DIR/expected-scka-symbols.txt"
mkdir -p "$TARGET_DIR"
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

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  rustup target list --installed | grep -Fx "$target" >/dev/null ||
    fail "Missing Rust target: $target"
  cargo build --release --locked --offline \
    --manifest-path "$CRATE_DIR/Cargo.toml" --target-dir "$TARGET_DIR" \
    --target "$target"
  library="$TARGET_DIR/$target/release/liblayergram_scka.a"
  [ -f "$library" ] || fail "Missing Apple static library: $library"
  case "$target" in
    x86_64-apple-ios) expected_architecture=x86_64 ;;
    *) expected_architecture=arm64 ;;
  esac
  [ "$(xcrun lipo -archs "$library")" = "$expected_architecture" ] ||
    fail "Unexpected architecture for $target"
  actual="$TARGET_DIR/$target-symbols.txt"
  xcrun nm -gU "$library" 2>/dev/null |
    awk '{ name = $NF; sub(/^_/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
    sort -u >"$actual"
  cmp -s "$EXPECTED" "$actual" || {
    diff -u "$EXPECTED" "$actual" >&2 || true
    fail "Unexpected SCKA exports for $target"
  }
done

IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
SIM_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun --sdk iphoneos clang -arch arm64 -isysroot "$IOS_SDK" \
  -miphoneos-version-min=15.5 -std=c11 -Wall -Wextra -Werror -Wpedantic \
  -I"$CRATE_DIR/include" -fsyntax-only "$CRATE_DIR/layergram_scka_abi_smoke.c"
xcrun --sdk iphonesimulator clang -arch arm64 -isysroot "$SIM_SDK" \
  -mios-simulator-version-min=15.5 -std=c11 -Wall -Wextra -Werror -Wpedantic \
  -I"$CRATE_DIR/include" -fsyntax-only "$CRATE_DIR/layergram_scka_abi_smoke.c"
xcrun --sdk iphonesimulator clang -arch x86_64 -isysroot "$SIM_SDK" \
  -mios-simulator-version-min=15.5 -std=c11 -Wall -Wextra -Werror -Wpedantic \
  -I"$CRATE_DIR/include" -fsyntax-only "$CRATE_DIR/layergram_scka_abi_smoke.c"

printf '%s\n' 'LAYERGRAM_SCKA_SCAFFOLD_APPLE_OK'
