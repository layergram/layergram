#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PACKAGE_ROOT=${LAYERGRAM_SCKA_APPLE_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/apple}
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
DERIVED_DATA=${LAYERGRAM_SCKA_MACOS_DERIVED_DATA:-$REPO_ROOT/build/macos/SckaPackagedDerivedData}
SIGN_IDENTITY=${LAYERGRAM_SCKA_MACOS_SIGN_IDENTITY:-}
APP="$DERIVED_DATA/Build/Products/Release/Layergram.app"
EXECUTABLE="$APP/Contents/MacOS/Layergram"
LIBRARY="$PACKAGE_ROOT/macos/liblayergram_scka.a"
GENERATED_CONFIG="$REPO_ROOT/macos/Flutter/ephemeral/Flutter-Generated.xcconfig"
GENERATED_ENV="$REPO_ROOT/macos/Flutter/ephemeral/flutter_export_environment.sh"
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
    mv "$CONFIG_BACKUP_DIR/Flutter-Generated.xcconfig" "$GENERATED_CONFIG"
  fi
  if [ "$GENERATED_ENV_EXISTED" = true ]; then
    mkdir -p "$(dirname "$GENERATED_ENV")"
    mv "$CONFIG_BACKUP_DIR/flutter_export_environment.sh" "$GENERATED_ENV"
  fi
  rmdir "$CONFIG_BACKUP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

"$SCRIPT_DIR/build_scka_packaged_apple.sh"
[ -f "$LIBRARY" ] || fail "Missing packaged static library: $LIBRARY"

mkdir -p "$PACKAGE_ROOT"
CONFIG_BACKUP_DIR=$(mktemp -d "$PACKAGE_ROOT/macos-config-backup.XXXXXX")
if [ -f "$GENERATED_CONFIG" ]; then
  cp -p "$GENERATED_CONFIG" "$CONFIG_BACKUP_DIR/Flutter-Generated.xcconfig"
  GENERATED_CONFIG_EXISTED=true
fi
if [ -f "$GENERATED_ENV" ]; then
  cp -p "$GENERATED_ENV" "$CONFIG_BACKUP_DIR/flutter_export_environment.sh"
  GENERATED_ENV_EXISTED=true
fi

linker_flags="\$(inherited) -Wl,-force_load,$LIBRARY"
while IFS= read -r symbol; do
  [ -n "$symbol" ] || continue
  linker_flags="$linker_flags -Wl,-u,_$symbol"
done <"$SYMBOLS"

flutter build macos --release --config-only \
  -t tool/pq/scka_packaged_scope_smoke.dart
xcodebuild -quiet -workspace macos/Runner.xcworkspace -scheme Runner \
  -configuration Release -derivedDataPath "$DERIVED_DATA" \
  CODE_SIGNING_ALLOWED=NO OTHER_LDFLAGS="$linker_flags" build

[ -x "$EXECUTABLE" ] || fail "Missing packaged executable: $EXECUTABLE"
if [ -n "$SIGN_IDENTITY" ]; then
  # Local artifact proof only. Distribution archives must sign nested code
  # explicitly through the release pipeline and complete notarization.
  if [ "$SIGN_IDENTITY" = - ]; then
    # Ad-hoc signatures have no Team ID. Enabling Hardened Runtime here would
    # make dyld reject the pre-signed Flutter engine and does not model a real
    # distribution identity, so keep this smoke local and non-hardened.
    codesign --force --deep --timestamp=none --sign - "$APP"
  else
    codesign --force --deep --options runtime --timestamp=none \
      --sign "$SIGN_IDENTITY" "$APP"
  fi
  codesign --verify --deep --strict --verbose=2 "$APP"
fi
actual="$PACKAGE_ROOT/macos-process-symbols.txt"
xcrun nm -gU "$EXECUTABLE" |
  awk '{ name = $NF; sub(/^_/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
  sort -u >"$actual"
cmp -s "$SYMBOLS" "$actual" || {
  diff -u "$SYMBOLS" "$actual" >&2 || true
  fail 'Unexpected packaged macOS SCKA export surface'
}

output=$($EXECUTABLE 2>&1)
printf '%s\n' "$output"
printf '%s\n' "$output" | grep -Fx 'LAYERGRAM_SCKA_PACKAGED_SCOPE_OK' >/dev/null ||
  fail 'Packaged macOS SCKA scope smoke did not complete'

printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_APPLE_OK'
