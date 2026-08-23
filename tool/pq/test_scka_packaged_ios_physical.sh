#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CRATE_DIR="$REPO_ROOT/native/layergram_scka"
DEVICE_ID=${LAYERGRAM_SCKA_IOS_PHYSICAL_DEVICE_ID:-}
TARGET_DIR=${LAYERGRAM_SCKA_IOS_PHYSICAL_TARGET_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-physical-ios/target}
DERIVED_DATA=${LAYERGRAM_SCKA_IOS_PHYSICAL_DERIVED_DATA:-$REPO_ROOT/.dart_tool/layergram_pq/scka-physical-ios/DerivedData}
CONFIG_BACKUP_ROOT=${LAYERGRAM_SCKA_IOS_PHYSICAL_CONFIG_BACKUP_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-physical-ios}
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
BUNDLE_ID=app.layergram.app
LAUNCH_TIMEOUT=${LAYERGRAM_SCKA_IOS_PHYSICAL_TIMEOUT_SECONDS:-60}
INSTALLED_BY_SCRIPT=false
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
  if [ "$INSTALLED_BY_SCRIPT" = true ]; then
    xcrun devicectl device uninstall app --device "$DEVICE_ID" \
      "$BUNDLE_ID" >/dev/null 2>&1 || true
  fi
  if [ -n "$CONFIG_BACKUP_DIR" ]; then
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
  fi
}
trap cleanup EXIT

check_symbols() {
  binary=$1
  actual="$DERIVED_DATA/actual-ios-physical-symbols.txt"
  xcrun nm -gU "$binary" |
    awk '{ name = $NF; sub(/^_/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
    sort -u >"$actual"
  cmp -s "$SYMBOLS" "$actual" || {
    diff -u "$SYMBOLS" "$actual" >&2 || true
    fail 'Unexpected packaged physical-iOS SCKA export surface'
  }
}

record_apps() {
  output=$1
  xcrun devicectl device info apps --device "$DEVICE_ID" \
    --json-output "$output" >/dev/null
}

contains_layergram() {
  input=$1
  jq -e --arg bundle "$BUNDLE_ID" \
    '.result.apps[]? | select(.bundleIdentifier == $bundle)' \
    "$input" >/dev/null
}

[ "$(uname -s)" = Darwin ] || fail 'Physical iOS testing requires macOS'
[ -n "$DEVICE_ID" ] ||
  fail 'Set LAYERGRAM_SCKA_IOS_PHYSICAL_DEVICE_ID to a paired physical device'
command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required'
command -v flutter >/dev/null 2>&1 || fail 'Flutter is required'
command -v jq >/dev/null 2>&1 || fail 'jq is required'
command -v xcrun >/dev/null 2>&1 || fail 'Xcode tools are required'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA packaging requires Rust 1.87.0'

mkdir -p "$TARGET_DIR" "$DERIVED_DATA" "$CONFIG_BACKUP_ROOT"
CONFIG_BACKUP_DIR=$(mktemp -d "$CONFIG_BACKUP_ROOT/ios-config-backup.XXXXXX")
if [ -f "$GENERATED_CONFIG" ]; then
  cp -p "$GENERATED_CONFIG" "$CONFIG_BACKUP_DIR/Generated.xcconfig"
  GENERATED_CONFIG_EXISTED=true
fi
if [ -f "$GENERATED_ENV" ]; then
  cp -p "$GENERATED_ENV" "$CONFIG_BACKUP_DIR/flutter_export_environment.sh"
  GENERATED_ENV_EXISTED=true
fi
apps_before="$DERIVED_DATA/apps-before.json"
record_apps "$apps_before"
if contains_layergram "$apps_before"; then
  fail 'Refusing to replace an existing app.layergram.app installation'
fi

cargo build --release --locked --offline --features candidate-ffi \
  --manifest-path "$CRATE_DIR/Cargo.toml" \
  --target-dir "$TARGET_DIR" --target aarch64-apple-ios
library="$TARGET_DIR/aarch64-apple-ios/release/liblayergram_scka.a"
[ -f "$library" ] || fail "Missing physical-iOS SCKA library: $library"
[ "$(xcrun lipo -archs "$library")" = arm64 ] ||
  fail 'Unexpected physical-iOS SCKA library architecture'

flutter build ios --release --config-only --no-codesign \
  -t tool/pq/scka_packaged_scope_smoke.dart

linker_flags="\$(inherited) -Wl,-force_load,$library"
while IFS= read -r symbol; do
  [ -n "$symbol" ] || continue
  linker_flags="$linker_flags -Wl,-u,_$symbol"
done <"$SYMBOLS"

xcodebuild -quiet -workspace ios/Runner.xcworkspace -scheme Runner \
  -configuration Release -sdk iphoneos -destination "id=$DEVICE_ID" \
  -derivedDataPath "$DERIVED_DATA" ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
  OTHER_LDFLAGS="$linker_flags" clean build

app="$DERIVED_DATA/Build/Products/Release-iphoneos/Runner.app"
binary="$app/Runner"
[ -f "$binary" ] || fail "Missing physical-iOS app binary: $binary"
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
  "$app/Info.plist")" = "$BUNDLE_ID" ] ||
  fail 'Unexpected physical-iOS smoke bundle identifier'
codesign --verify --deep --strict --verbose=2 "$app"
check_symbols "$binary"

apps_before_install="$DERIVED_DATA/apps-before-install.json"
record_apps "$apps_before_install"
if contains_layergram "$apps_before_install"; then
  fail 'Refusing to replace app.layergram.app installed during the build'
fi

xcrun devicectl device install app --device "$DEVICE_ID" "$app"
INSTALLED_BY_SCRIPT=true

set +e
launch_output=$(xcrun devicectl device process launch \
  --device "$DEVICE_ID" --console --terminate-existing \
  --timeout "$LAUNCH_TIMEOUT" "$BUNDLE_ID" 2>&1)
launch_status=$?
set -e
printf '%s\n' "$launch_output"
[ "$launch_status" -eq 0 ] ||
  fail "Physical-iOS SCKA scope smoke exited with $launch_status"
printf '%s\n' "$launch_output" | tr -d '\r' |
  grep -Fx 'LAYERGRAM_SCKA_PACKAGED_SCOPE_OK' >/dev/null ||
  fail 'Physical-iOS SCKA scope smoke did not complete'

xcrun devicectl device uninstall app --device "$DEVICE_ID" "$BUNDLE_ID"
INSTALLED_BY_SCRIPT=false
apps_after="$DERIVED_DATA/apps-after.json"
record_apps "$apps_after"
if contains_layergram "$apps_after"; then
  fail 'Physical-iOS SCKA smoke app remains installed after cleanup'
fi

printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_IOS_PHYSICAL_OK'
