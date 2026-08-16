#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PACKAGE_ROOT=${LAYERGRAM_SCKA_ANDROID_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/android}
APK=${LAYERGRAM_SCKA_ANDROID_APK:-$REPO_ROOT/build/app/outputs/flutter-apk/app-release.apk}
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

"$SCRIPT_DIR/prepare_scka_packaged_android.sh"
ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true \
  flutter build apk --release -t tool/pq/scka_packaged_scope_smoke.dart
[ -f "$APK" ] || fail "Missing packaged APK: $APK"

NDK_NM=$(find "$ANDROID_SDK/ndk" -type f \
  -path '*/toolchains/llvm/prebuilt/*/bin/llvm-nm' -print | sort | tail -1)
[ -n "$NDK_NM" ] || fail 'Android NDK llvm-nm was not found'
EXTRACT_ROOT="$PACKAGE_ROOT/apk"
rm -rf "$EXTRACT_ROOT"
mkdir -p "$EXTRACT_ROOT"
for abi in arm64-v8a armeabi-v7a x86_64; do
  archive_path="lib/$abi/liblayergram_scka.so"
  unzip -q "$APK" "$archive_path" -d "$EXTRACT_ROOT"
  actual="$PACKAGE_ROOT/$abi-symbols.txt"
  "$NDK_NM" -D --defined-only "$EXTRACT_ROOT/$archive_path" |
    awk '{ name = $NF; sub(/@@.*/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
    sort -u >"$actual"
  cmp -s "$SYMBOLS" "$actual" || {
    diff -u "$SYMBOLS" "$actual" >&2 || true
    fail "Unexpected packaged Android SCKA exports for $abi"
  }
done

printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_ANDROID_OK'
