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

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

"$SCRIPT_DIR/build_scka_packaged_apple.sh"
[ -f "$LIBRARY" ] || fail "Missing packaged static library: $LIBRARY"

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
