#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
OUTPUT_ROOT=${LAYERGRAM_SCKA_APPLE_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/apple}
TARGET_DIR="$OUTPUT_ROOT/target"
FRAMEWORK="$OUTPUT_ROOT/LayergramScka.xcframework"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[ "$(uname -s)" = Darwin ] || fail 'Apple packaging requires macOS'
command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
command -v xcrun >/dev/null 2>&1 || fail 'Xcode tools are required'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA packaging requires Rust 1.87.0'
"$SCRIPT_DIR/verify_scka_export_contract.sh"

build_target() {
  target=$1
  rustup target list --installed | grep -Fx "$target" >/dev/null ||
    fail "Missing Rust target: $target"
  cargo build --release --locked --offline --features candidate-ffi \
    --manifest-path "$CRATE_DIR/Cargo.toml" \
    --target-dir "$TARGET_DIR" --target "$target"
  "$SCRIPT_DIR/verify_scka_export_contract.sh" namespace xcrun \
    "$TARGET_DIR/$target/release/liblayergram_scka.a"
}

for target in \
  aarch64-apple-ios \
  aarch64-apple-ios-sim \
  x86_64-apple-ios \
  aarch64-apple-darwin \
  x86_64-apple-darwin; do
  build_target "$target"
done

mkdir -p "$OUTPUT_ROOT/ios-device" "$OUTPUT_ROOT/ios-simulator" \
  "$OUTPUT_ROOT/macos"
cp "$TARGET_DIR/aarch64-apple-ios/release/liblayergram_scka.a" \
  "$OUTPUT_ROOT/ios-device/liblayergram_scka.a"
xcrun lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/liblayergram_scka.a" \
  "$TARGET_DIR/x86_64-apple-ios/release/liblayergram_scka.a" \
  -output "$OUTPUT_ROOT/ios-simulator/liblayergram_scka.a"
xcrun lipo -create \
  "$TARGET_DIR/aarch64-apple-darwin/release/liblayergram_scka.a" \
  "$TARGET_DIR/x86_64-apple-darwin/release/liblayergram_scka.a" \
  -output "$OUTPUT_ROOT/macos/liblayergram_scka.a"

rm -rf "$FRAMEWORK"
xcodebuild -create-xcframework \
  -library "$OUTPUT_ROOT/ios-device/liblayergram_scka.a" \
  -headers "$CRATE_DIR/include" \
  -library "$OUTPUT_ROOT/ios-simulator/liblayergram_scka.a" \
  -headers "$CRATE_DIR/include" \
  -library "$OUTPUT_ROOT/macos/liblayergram_scka.a" \
  -headers "$CRATE_DIR/include" \
  -output "$FRAMEWORK"

printf '%s\n' "$FRAMEWORK"
printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_APPLE_BUILT'
