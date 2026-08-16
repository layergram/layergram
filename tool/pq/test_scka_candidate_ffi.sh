#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
TARGET_ROOT=${LAYERGRAM_SCKA_CANDIDATE_TARGET_DIR:-$REPO_ROOT/.dart_tool/layergram_pq}

case "$(uname -s)" in
  Darwin)
    LIBRARY_NAME=liblayergram_scka.dylib
    ;;
  Linux)
    LIBRARY_NAME=liblayergram_scka.so
    ;;
  *)
    echo 'Layergram SCKA candidate FFI script supports macOS and Linux' >&2
    exit 1
    ;;
esac

cd "$CRATE_DIR"
cargo test --locked --offline
cargo test --locked --offline --features candidate-ffi
cargo clippy --locked --offline --all-targets -- -D warnings
cargo clippy --locked --offline --all-targets --features candidate-ffi -- -D warnings
cargo build --locked --offline --release --target-dir "$TARGET_ROOT/scka-scaffold"
cargo build --locked --offline --release --features candidate-ffi \
  --target-dir "$TARGET_ROOT/scka-candidate"

cd "$REPO_ROOT"
flutter analyze \
  lib/core/crypto/v3/scka_candidate_ffi.dart \
  test/core/crypto/v3/scka_candidate_ffi_integration_test.dart
LAYERGRAM_SCKA_SCAFFOLD_LIBRARY="$TARGET_ROOT/scka-scaffold/release/$LIBRARY_NAME" \
LAYERGRAM_SCKA_CANDIDATE_LIBRARY="$TARGET_ROOT/scka-candidate/release/$LIBRARY_NAME" \
  flutter test test/core/crypto/v3/scka_candidate_ffi_integration_test.dart

echo 'LAYERGRAM_SCKA_CANDIDATE_FFI_OK'
