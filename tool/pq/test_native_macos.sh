#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
NATIVE_DIR="$REPO_ROOT/native/layergram_mlkem"
LIBRARY="$REPO_ROOT/.dart_tool/layergram_pq/macos/liblayergram_mlkem_test.dylib"
PRODUCTION_LIBRARY="$REPO_ROOT/.dart_tool/layergram_pq/macos/liblayergram_mlkem.dylib"

make -C "$NATIVE_DIR" TESTING=1 test
make -C "$NATIVE_DIR" TESTING=0 build
LAYERGRAM_MLKEM_TEST_LIBRARY="$LIBRARY" \
  LAYERGRAM_MLKEM_PRODUCTION_LIBRARY="$PRODUCTION_LIBRARY" \
  flutter test "$REPO_ROOT/test/core/crypto/v3/ml_kem_768_ffi_integration_test.dart" -r expanded
