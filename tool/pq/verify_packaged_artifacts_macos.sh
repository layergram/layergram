#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
TEMP_ROOT=${TMPDIR:-/tmp}
TEMP_DIR=$(mktemp -d "$TEMP_ROOT/layergram-pq-artifacts.XXXXXX")

cleanup() {
  case "$TEMP_DIR" in
    "$TEMP_ROOT"/layergram-pq-artifacts.*) rm -rf -- "$TEMP_DIR" ;;
    *) printf '%s\n' "Refusing to remove unexpected path: $TEMP_DIR" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "Missing packaged artifact: $1"
}

EXPECTED_SYMBOLS="$TEMP_DIR/expected-symbols.txt"
printf '%s\n' \
  lg_mlkem768_abi_version \
  lg_mlkem768_ciphertext_bytes \
  lg_mlkem768_decapsulate \
  lg_mlkem768_encaps_seed_bytes \
  lg_mlkem768_encapsulate \
  lg_mlkem768_implementation_id \
  lg_mlkem768_keygen_seed_bytes \
  lg_mlkem768_keypair_from_seed \
  lg_mlkem768_private_key_bytes \
  lg_mlkem768_private_key_destroy \
  lg_mlkem768_public_key_bytes \
  lg_mlkem768_self_test \
  lg_mlkem768_shared_secret_bytes \
  lg_mlkem768_validate_public_key >"$EXPECTED_SYMBOLS"

check_macho_symbols() {
  macho_binary=$1
  macho_label=$2
  actual="$TEMP_DIR/$macho_label-symbols.txt"
  xcrun nm -gU "$macho_binary" |
    awk '{ name = $NF; if (name ~ /^_lg_mlkem768_/) { sub(/^_/, "", name); print name } }' |
    sort -u >"$actual"
  if ! cmp -s "$EXPECTED_SYMBOLS" "$actual"; then
    printf '%s\n' "Unexpected ML-KEM export surface for $macho_label" >&2
    diff -u "$EXPECTED_SYMBOLS" "$actual" >&2 || true
    exit 1
  fi
}

check_universal_macho() {
  universal_binary=$1
  universal_label=$2
  for architecture in arm64 x86_64; do
    thin="$TEMP_DIR/$universal_label-$architecture"
    xcrun lipo "$universal_binary" -extract "$architecture" -output "$thin"
    check_macho_symbols "$thin" "$universal_label-$architecture"
  done
}

check_elf_symbols() {
  elf_binary=$1
  elf_label=$2
  actual="$TEMP_DIR/$elf_label-symbols.txt"
  "$NDK_NM" -D --defined-only "$elf_binary" |
    awk '{ name = $NF; sub(/@@.*/, "", name); if (name ~ /^lg_mlkem768_/) print name }' |
    sort -u >"$actual"
  if ! cmp -s "$EXPECTED_SYMBOLS" "$actual"; then
    printf '%s\n' "Unexpected ML-KEM export surface for $elf_label" >&2
    diff -u "$EXPECTED_SYMBOLS" "$actual" >&2 || true
    exit 1
  fi
}

ANDROID_APK=${LAYERGRAM_ANDROID_APK:-$REPO_ROOT/build/app/outputs/flutter-apk/app-release.apk}
IOS_SIM_APP=${LAYERGRAM_IOS_SIM_APP:-$REPO_ROOT/build/ios/iphonesimulator/Runner.app}
IOS_DEVICE_APP=${LAYERGRAM_IOS_DEVICE_APP:-$REPO_ROOT/build/ios/iphoneos/Runner.app}
MACOS_APP=${LAYERGRAM_MACOS_APP:-$REPO_ROOT/build/macos/UnsignedDerivedData/Build/Products/Release/Layergram.app}

require_file "$ANDROID_APK"
require_file "$IOS_SIM_APP/Runner"
require_file "$IOS_DEVICE_APP/Runner"
require_file "$MACOS_APP/Contents/Frameworks/LayergramMlKem.framework/Versions/A/LayergramMlKem"

ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[ -n "$ANDROID_SDK" ] || fail 'Set ANDROID_HOME or ANDROID_SDK_ROOT'
NDK_NM=$(find "$ANDROID_SDK/ndk" -type f \
  -path '*/toolchains/llvm/prebuilt/*/bin/llvm-nm' -print | sort | tail -1)
[ -n "$NDK_NM" ] || fail 'Android NDK llvm-nm was not found'

mkdir -p "$TEMP_DIR/android"
for android_abi in armeabi-v7a arm64-v8a x86_64; do
  archive_path="lib/$android_abi/liblayergram_mlkem.so"
  unzip -q "$ANDROID_APK" "$archive_path" -d "$TEMP_DIR/android"
  check_elf_symbols "$TEMP_DIR/android/$archive_path" "android-$android_abi"
done

IOS_SIM_SYMBOL_BINARY="$IOS_SIM_APP/Runner"
if [ -f "$IOS_SIM_APP/Runner.debug.dylib" ]; then
  IOS_SIM_SYMBOL_BINARY="$IOS_SIM_APP/Runner.debug.dylib"
fi
check_universal_macho "$IOS_SIM_SYMBOL_BINARY" ios-simulator
check_macho_symbols "$IOS_DEVICE_APP/Runner" ios-device-release
check_universal_macho \
  "$MACOS_APP/Contents/Frameworks/LayergramMlKem.framework/Versions/A/LayergramMlKem" \
  macos-framework

printf '%s\n' 'LAYERGRAM_MLKEM_PACKAGED_ARTIFACTS_OK'
