#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate_dir="$repo_root/native/layergram_scka"
toolchain="${LAYERGRAM_SCKA_SANITIZER_TOOLCHAIN:-nightly-2026-08-16}"

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required for the pinned SCKA sanitizer toolchain" >&2
  exit 1
fi

if ! rustup run "$toolchain" rustc --version >/dev/null 2>&1; then
  echo "missing Rust toolchain $toolchain" >&2
  echo "install it with: rustup toolchain install $toolchain --profile minimal" >&2
  exit 1
fi

host_target="$(rustup run "$toolchain" rustc -vV | sed -n 's/^host: //p')"
case "$host_target" in
  aarch64-apple-darwin|x86_64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu)
    ;;
  *)
    echo "AddressSanitizer checkpoint is not frozen for host target: $host_target" >&2
    exit 1
    ;;
esac

target_dir="${LAYERGRAM_SCKA_SANITIZER_TARGET_DIR:-$repo_root/.dart_tool/layergram_pq/scka-asan-$host_target}"
asan_options="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:abort_on_error=1}"

echo "SCKA hardening toolchain: $(rustup run "$toolchain" rustc --version)"
echo "SCKA hardening target: $host_target"
echo "SCKA hardening target dir: $target_dir"

env \
  ASAN_OPTIONS="$asan_options" \
  CARGO_INCREMENTAL=0 \
  RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes" \
  RUSTDOCFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes" \
  cargo "+$toolchain" test \
    --manifest-path "$crate_dir/Cargo.toml" \
    --locked \
    --offline \
    --features candidate-ffi \
    --target "$host_target" \
    --target-dir "$target_dir"

echo "Layergram SCKA candidate AddressSanitizer and hostile-corpus checks passed."
