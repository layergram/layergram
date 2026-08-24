#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fuzz_dir="$repo_root/native/layergram_scka/fuzz"
toolchain="${LAYERGRAM_SCKA_FUZZ_TOOLCHAIN:-nightly-2026-08-16}"
seconds="${LAYERGRAM_SCKA_FUZZ_SECONDS:-20}"

case "$seconds" in
  ''|*[!0-9]*|0)
    echo "LAYERGRAM_SCKA_FUZZ_SECONDS must be a positive integer" >&2
    exit 1
    ;;
esac

if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required for the pinned SCKA fuzzing toolchain" >&2
  exit 1
fi

if ! rustup run "$toolchain" rustc --version >/dev/null 2>&1; then
  echo "missing Rust toolchain $toolchain" >&2
  echo "install it with: rustup toolchain install $toolchain --profile minimal" >&2
  exit 1
fi

fuzz_version="$(cargo +"$toolchain" fuzz --version 2>/dev/null || true)"
if [[ "$fuzz_version" != "cargo-fuzz 0.13.2" ]]; then
  echo "cargo-fuzz 0.13.2 is required; found: ${fuzz_version:-not installed}" >&2
  echo "install it with: cargo +$toolchain install cargo-fuzz --version 0.13.2 --locked" >&2
  exit 1
fi

host_target="$(rustup run "$toolchain" rustc -vV | sed -n 's/^host: //p')"
case "$host_target" in
  aarch64-apple-darwin|x86_64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu)
    ;;
  *)
    echo "SCKA fuzzing checkpoint is not frozen for host target: $host_target" >&2
    exit 1
    ;;
esac

target_dir="${LAYERGRAM_SCKA_FUZZ_TARGET_DIR:-$repo_root/.dart_tool/layergram_pq/scka-fuzz-$host_target}"
runtime_dir="${LAYERGRAM_SCKA_FUZZ_RUNTIME_DIR:-$repo_root/.dart_tool/layergram_pq/scka-fuzz-runtime-$host_target}"
mkdir -p "$target_dir" "$runtime_dir"

echo "SCKA fuzz toolchain: $(rustup run "$toolchain" rustc --version)"
echo "SCKA fuzz driver: $fuzz_version"
echo "SCKA fuzz target: $host_target"
echo "SCKA fuzz duration per harness: ${seconds}s"

cargo +"$toolchain" metadata \
  --manifest-path "$fuzz_dir/Cargo.toml" \
  --locked \
  --offline \
  --format-version 1 >/dev/null

lock_hash_before="$(shasum -a 256 "$fuzz_dir/Cargo.lock" | awk '{print $1}')"

run_target() {
  local target="$1"
  local max_len="$2"
  local corpus_dir="$runtime_dir/corpus/$target"
  local artifact_dir="$runtime_dir/artifacts/$target"
  mkdir -p "$corpus_dir" "$artifact_dir"

  CARGO_INCREMENTAL=0 \
  CARGO_NET_OFFLINE=true \
    cargo +"$toolchain" fuzz run \
      --fuzz-dir "$fuzz_dir" \
      --target-dir "$target_dir" \
      --sanitizer address \
      "$target" \
      "$corpus_dir" \
      -- \
      "-artifact_prefix=$artifact_dir/" \
      "-max_len=$max_len" \
      "-max_total_time=$seconds" \
      -timeout=10 \
      -rss_limit_mb=2048 \
      -print_final_stats=1
}

run_target ffi_state_validate 4096
run_target ffi_send 4096
run_target ffi_receive 513

lock_hash_after="$(shasum -a 256 "$fuzz_dir/Cargo.lock" | awk '{print $1}')"
if [[ "$lock_hash_before" != "$lock_hash_after" ]]; then
  echo "fuzz Cargo.lock changed during an offline checkpoint" >&2
  exit 1
fi

echo "Layergram SCKA bounded coverage-guided fuzzing checkpoint passed."
