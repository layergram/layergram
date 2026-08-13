#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
NATIVE_DIR="$REPO_ROOT/native/layergram_mlkem"
UPSTREAM_DIR="$REPO_ROOT/third_party/mlkem-native/mlkem"
UPSTREAM_TEST_DIR="$REPO_ROOT/third_party/mlkem-native/test"
BUILD_DIR=${LAYERGRAM_MLKEM_LINUX_BUILD_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/linux-native}
CC=${CC:-cc}
SANITIZE=${LAYERGRAM_MLKEM_SANITIZE:-0}

mkdir -p "$BUILD_DIR"

set -- \
  -std=c99 -fPIC -fvisibility=hidden \
  -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion \
  -Wshadow -Wpointer-arith -Wmissing-prototypes \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -I"$NATIVE_DIR" -I"$UPSTREAM_DIR" -I"$UPSTREAM_TEST_DIR" \
  -DLG_MLKEM_BUILD=1

if [ "$SANITIZE" = 1 ]; then
  set -- "$@" -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
else
  set -- "$@" -O3
fi

"$CC" "$@" -DLG_MLKEM_TESTING=1 -shared \
  "$NATIVE_DIR/layergram_mlkem.c" \
  -Wl,-soname,liblayergram_mlkem_test.so \
  -Wl,--no-undefined -Wl,-z,defs -Wl,-z,relro -Wl,-z,now \
  -o "$BUILD_DIR/liblayergram_mlkem_test.so"

"$CC" "$@" -DLG_MLKEM_TESTING=1 \
  "$NATIVE_DIR/layergram_mlkem_abi_test.c" \
  -L"$BUILD_DIR" -llayergram_mlkem_test -Wl,-rpath,'$ORIGIN' \
  -Wl,-z,relro -Wl,-z,now \
  -o "$BUILD_DIR/layergram_mlkem_abi_test"

"$BUILD_DIR/layergram_mlkem_abi_test"

"$CC" "$@" -shared "$NATIVE_DIR/layergram_mlkem.c" \
  -Wl,-soname,liblayergram_mlkem.so \
  -Wl,--version-script="$REPO_ROOT/linux/mlkem/layergram_mlkem.exports.map" \
  -Wl,--no-undefined -Wl,-z,defs -Wl,-z,relro -Wl,-z,now \
  -o "$BUILD_DIR/liblayergram_mlkem.so"

if [ "$SANITIZE" != 1 ] && command -v flutter >/dev/null 2>&1; then
  LAYERGRAM_MLKEM_TEST_LIBRARY="$BUILD_DIR/liblayergram_mlkem_test.so" \
  LAYERGRAM_MLKEM_PRODUCTION_LIBRARY="$BUILD_DIR/liblayergram_mlkem.so" \
    flutter test \
      "$REPO_ROOT/test/core/crypto/v3/ml_kem_768_ffi_integration_test.dart" \
      -r expanded
fi

printf '%s\n' 'LAYERGRAM_MLKEM_NATIVE_LINUX_OK'
