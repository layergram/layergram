#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PACKAGE_ROOT=${LAYERGRAM_SCKA_APPLE_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/apple}
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
SIM_DERIVED=${LAYERGRAM_SCKA_IOS_SIM_DERIVED_DATA:-$REPO_ROOT/build/ios/SckaPackagedSimulatorDerivedData}
DEVICE_DERIVED=${LAYERGRAM_SCKA_IOS_DEVICE_DERIVED_DATA:-$REPO_ROOT/build/ios/SckaPackagedDeviceDerivedData}
GENERATED_CONFIG="$REPO_ROOT/ios/Flutter/Generated.xcconfig"
GENERATED_ENV="$REPO_ROOT/ios/Flutter/flutter_export_environment.sh"
CONFIG_BACKUP_DIR=
GENERATED_CONFIG_EXISTED=false
GENERATED_ENV_EXISTED=false

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [ -z "$CONFIG_BACKUP_DIR" ]; then
    return
  fi
  rm -f "$GENERATED_CONFIG" "$GENERATED_ENV"
  if [ "$GENERATED_CONFIG_EXISTED" = true ]; then
    mkdir -p "$(dirname "$GENERATED_CONFIG")"
    mv "$CONFIG_BACKUP_DIR/Generated.xcconfig" "$GENERATED_CONFIG"
  fi
  if [ "$GENERATED_ENV_EXISTED" = true ]; then
    mkdir -p "$(dirname "$GENERATED_ENV")"
    mv "$CONFIG_BACKUP_DIR/flutter_export_environment.sh" "$GENERATED_ENV"
  fi
  rmdir "$CONFIG_BACKUP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

linker_flags() {
  library=$1
  flags="\$(inherited) -Wl,-force_load,$library"
  while IFS= read -r symbol; do
    [ -n "$symbol" ] || continue
    flags="$flags -Wl,-u,_$symbol"
  done <"$SYMBOLS"
  printf '%s\n' "$flags"
}

check_symbols() {
  binary=$1
  label=$2
  "$SCRIPT_DIR/verify_scka_export_contract.sh" namespace xcrun "$binary" ||
    fail "Unexpected packaged iOS SCKA namespace surface for $label"
}

"$SCRIPT_DIR/build_scka_packaged_apple.sh"
mkdir -p "$PACKAGE_ROOT"
CONFIG_BACKUP_DIR=$(mktemp -d "$PACKAGE_ROOT/ios-config-backup.XXXXXX")
if [ -f "$GENERATED_CONFIG" ]; then
  cp -p "$GENERATED_CONFIG" "$CONFIG_BACKUP_DIR/Generated.xcconfig"
  GENERATED_CONFIG_EXISTED=true
fi
if [ -f "$GENERATED_ENV" ]; then
  cp -p "$GENERATED_ENV" "$CONFIG_BACKUP_DIR/flutter_export_environment.sh"
  GENERATED_ENV_EXISTED=true
fi
flutter build ios --simulator --debug --config-only \
  -t tool/pq/scka_packaged_scope_smoke.dart

sim_library="$PACKAGE_ROOT/ios-simulator/liblayergram_scka.a"
sim_flags=$(linker_flags "$sim_library")
xcodebuild -quiet -workspace ios/Runner.xcworkspace -scheme Runner \
  -configuration Debug -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$SIM_DERIVED" CODE_SIGNING_ALLOWED=NO \
  ARCHS=x86_64 ONLY_ACTIVE_ARCH=YES OTHER_LDFLAGS="$sim_flags" build
sim_app="$SIM_DERIVED/Build/Products/Debug-iphonesimulator/Runner.app"
sim_binary="$sim_app/Runner"
if [ -f "$sim_app/Runner.debug.dylib" ]; then
  sim_binary="$sim_app/Runner.debug.dylib"
fi
[ -f "$sim_binary" ] || fail "Missing iOS simulator binary: $sim_binary"
[ "$(xcrun lipo -archs "$sim_binary")" = x86_64 ] ||
  fail 'Unexpected iOS simulator architecture'
check_symbols "$sim_binary" ios-simulator

device_library="$PACKAGE_ROOT/ios-device/liblayergram_scka.a"
device_flags=$(linker_flags "$device_library")
flutter build ios --release --config-only --no-codesign \
  -t tool/pq/scka_packaged_scope_smoke.dart
xcodebuild -quiet -workspace ios/Runner.xcworkspace -scheme Runner \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath "$DEVICE_DERIVED" CODE_SIGNING_ALLOWED=NO \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=YES OTHER_LDFLAGS="$device_flags" build
device_binary="$DEVICE_DERIVED/Build/Products/Release-iphoneos/Runner.app/Runner"
[ -f "$device_binary" ] || fail "Missing iOS device binary: $device_binary"
[ "$(xcrun lipo -archs "$device_binary")" = arm64 ] ||
  fail 'Unexpected iOS device architecture'
check_symbols "$device_binary" ios-device

printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_IOS_OK'
