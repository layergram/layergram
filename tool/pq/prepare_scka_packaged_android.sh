#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
OUTPUT_ROOT=${LAYERGRAM_SCKA_ANDROID_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/android}
TARGET_DIR="$OUTPUT_ROOT/target"
JNI_DIR="$OUTPUT_ROOT/jniLibs"
ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[ -n "$ANDROID_SDK" ] || fail 'Set ANDROID_HOME or ANDROID_SDK_ROOT'
command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA packaging requires Rust 1.87.0'

REFERENCE_LINKER=$(find "$ANDROID_SDK/ndk" -type f \
  -path '*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang' \
  -print | sort | tail -1)
TOOLCHAIN=${REFERENCE_LINKER%/*}
[ -n "$TOOLCHAIN" ] || fail 'Android NDK LLVM toolchain was not found'

build_abi() {
  abi=$1
  target=$2
  linker_name=$3
  linker_env=$4
  linker="$TOOLCHAIN/$linker_name"
  [ -x "$linker" ] || fail "Missing Android linker: $linker"
  rustup target list --installed | grep -Fx "$target" >/dev/null ||
    fail "Missing Rust target: $target"
  env "$linker_env=$linker" cargo build --release --locked --offline \
    --features candidate-ffi --manifest-path "$CRATE_DIR/Cargo.toml" \
    --target-dir "$TARGET_DIR" --target "$target"
  mkdir -p "$JNI_DIR/$abi"
  cp "$TARGET_DIR/$target/release/liblayergram_scka.so" \
    "$JNI_DIR/$abi/liblayergram_scka.so"
  "$SCRIPT_DIR/verify_scka_export_contract.sh" dynamic \
    "$TOOLCHAIN/llvm-nm" "$JNI_DIR/$abi/liblayergram_scka.so"
}

build_abi arm64-v8a aarch64-linux-android aarch64-linux-android21-clang \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER
build_abi armeabi-v7a armv7-linux-androideabi armv7a-linux-androideabi21-clang \
  CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER
build_abi x86_64 x86_64-linux-android x86_64-linux-android21-clang \
  CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER

printf '%s\n' "$JNI_DIR"
printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_ANDROID_PREPARED'
