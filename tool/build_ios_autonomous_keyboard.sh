#!/bin/bash
# Build the experimental autonomous keyboard for an iOS device or simulator.
# Does not install, publish, or change the default keyboard build mode.
set -euo pipefail
keyboard_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$keyboard_root"
keyboard_fixture="${LAYERGRAM_KEYBOARD_FIXTURE:-NO}"
keyboard_simulator="${LAYERGRAM_KEYBOARD_SIMULATOR:-NO}"
keyboard_release="${LAYERGRAM_KEYBOARD_RELEASE:-NO}"
if [ "$keyboard_release" != YES ] && [ "$keyboard_release" != NO ]; then
  echo 'LAYERGRAM_KEYBOARD_RELEASE must be YES or NO.' >&2
  exit 1
fi
if [ "$keyboard_release" = YES ] && [ "$keyboard_simulator" = YES ]; then
  echo 'Release keyboard validation requires a physical device.' >&2
  exit 1
fi
keyboard_isolated_qa="${LAYERGRAM_KEYBOARD_ISOLATED_QA:-NO}"
keyboard_isolated_full_app="${LAYERGRAM_KEYBOARD_ISOLATED_FULL_APP:-NO}"
keyboard_reuse_fixture="${LAYERGRAM_KEYBOARD_REUSE_VALIDATION_APP:-NO}"
case "$keyboard_isolated_full_app" in YES|NO) ;; *) echo 'Invalid isolated full-app selection.' >&2; exit 1 ;; esac
if [ "$keyboard_isolated_full_app" = YES ] &&
   { [ "$keyboard_isolated_qa" != YES ] || [ "$keyboard_reuse_fixture" != NO ]; }; then
  echo 'A full-app reinstall test requires a separate isolated QA identifier.' >&2
  exit 1
fi
if [ "$keyboard_reuse_fixture" != YES ] && [ "$keyboard_reuse_fixture" != NO ]; then
  echo 'LAYERGRAM_KEYBOARD_REUSE_VALIDATION_APP must be YES or NO.' >&2
  exit 1
fi
if [ "$keyboard_reuse_fixture" = YES ] && [ "$keyboard_isolated_qa" != YES ]; then
  echo 'Reusing the validation app is available only for isolated QA.' >&2
  exit 1
fi
if [ "$keyboard_reuse_fixture" = YES ] &&
   [ "${LAYERGRAM_KEYBOARD_REPLACE_FULL_APP_WITH_FIXTURE:-NO}" != YES ]; then
  echo 'This build would replace the full validation app with the diagnostic fixture.' >&2
  echo 'Set LAYERGRAM_KEYBOARD_REPLACE_FULL_APP_WITH_FIXTURE=YES only for that explicit, temporary QA operation.' >&2
  exit 1
fi
if [ "$keyboard_isolated_qa" != YES ] && [ "$keyboard_isolated_qa" != NO ]; then
  echo 'LAYERGRAM_KEYBOARD_ISOLATED_QA must be YES or NO.' >&2
  exit 1
fi
if [ "$keyboard_isolated_qa" = YES ] && [ "$keyboard_fixture" != YES ]; then
  echo 'Isolated QA requires LAYERGRAM_KEYBOARD_FIXTURE=YES.' >&2
  exit 1
fi
if [ "$keyboard_fixture" != YES ] && [ "$keyboard_fixture" != NO ]; then
  echo 'LAYERGRAM_KEYBOARD_FIXTURE must be YES or NO.' >&2
  exit 1
fi
if [ "$keyboard_simulator" != YES ] && [ "$keyboard_simulator" != NO ]; then
  echo 'LAYERGRAM_KEYBOARD_SIMULATOR must be YES or NO.' >&2
  exit 1
fi
keyboard_entry="$keyboard_root/lib/main.dart"
keyboard_fixture_id=app.layergram.keyboardvalidation
if [ "$keyboard_isolated_qa" = YES ]; then
  # A device QA run must never replace the fixture containing user test chats.
  keyboard_fixture_id=app.layergram.keyboardvalidation.qa
  keyboard_entry="$keyboard_root/tool/qa/ios_keyboard_fixture.dart"
  if [ "$keyboard_isolated_full_app" = YES ]; then
    keyboard_entry="$keyboard_root/lib/main.dart"
  fi
  if [ "$keyboard_reuse_fixture" = YES ]; then
    # Explicit opt-in for a disposable installed validation app whose existing
    # provisioning profiles can be reused. Tests still use unique storage.
    keyboard_fixture_id=app.layergram.keyboardvalidation
  fi
fi
keyboard_simulator_setup="${LAYERGRAM_KEYBOARD_SIMULATOR_SETUP:-NO}"
case "$keyboard_simulator_setup" in YES|NO) ;; *) echo 'Invalid simulator setup selection.' >&2; exit 1 ;; esac
if [ "$keyboard_simulator_setup" = YES ]; then
  if [ "$keyboard_simulator" != YES ] || [ "$keyboard_fixture" != YES ] ||
     [ "$keyboard_isolated_qa" != NO ] || [ "${LAYERGRAM_KEYBOARD_DISPOSABLE_SIMULATOR:-NO}" != YES ]; then
    echo 'UI preparation is only for a disposable full-app QA simulator.' >&2; exit 1
  fi
  : "${LAYERGRAM_KEYBOARD_DEVICE_ID:?Select the exact booted QA simulator}"
  xcrun simctl list devices available --json | python3 -c '
import json,sys
rows=[d for group in json.load(sys.stdin)["devices"].values() for d in group if d["udid"]==sys.argv[1]]
if len(rows)!=1 or rows[0]["state"]!="Booted" or not rows[0]["name"].startswith("Layergram "):
    raise SystemExit("Select exactly one booted Layergram QA simulator")
' "$LAYERGRAM_KEYBOARD_DEVICE_ID"
  keyboard_entry="$keyboard_root/tool/qa/ios_simulator_setup.dart"
fi
keyboard_sdk_name=iphoneos
keyboard_rust_target=aarch64-apple-ios
keyboard_configuration=Profile
keyboard_flutter_mode=--profile
keyboard_product_directory=Profile-iphoneos
keyboard_package_kind=ios-device
keyboard_destination='generic/platform=iOS'
if [ "$keyboard_release" = YES ]; then
  keyboard_configuration=Release
  keyboard_flutter_mode=--release
  keyboard_product_directory=Release-iphoneos
fi
if [ "$keyboard_simulator" = YES ]; then
  keyboard_sdk_name=iphonesimulator
  keyboard_rust_target=aarch64-apple-ios-sim
  keyboard_configuration=Debug
  keyboard_flutter_mode=--debug
  keyboard_product_directory=Debug-iphonesimulator
  keyboard_package_kind=ios-simulator
  keyboard_destination='generic/platform=iOS Simulator'
fi
keyboard_sdk="$(xcrun --sdk "$keyboard_sdk_name" --show-sdk-version)"
if [ "${keyboard_sdk%%.*}" -lt 26 ]; then
  echo 'The experimental keyboard requires the iOS 26 SDK or later.' >&2
  exit 1
fi
keyboard_workspace="${LAYERGRAM_KEYBOARD_IOS_WORKSPACE:-$keyboard_root/ios/Runner.xcworkspace}"
keyboard_output_name=ios-autonomous-keyboard
if [ "$keyboard_fixture" = YES ]; then
  keyboard_output_name=ios-autonomous-keyboard-fixture
fi
if [ "$keyboard_isolated_qa" = YES ]; then
  keyboard_output_name=ios-autonomous-keyboard-isolated-qa
fi
keyboard_extension_flags='-D LAYERGRAM_AUTONOMOUS_KEYBOARD'
keyboard_runner_flags=''
if [ "$keyboard_fixture" = YES ]; then
  keyboard_extension_flags="$keyboard_extension_flags -D LAYERGRAM_KEYBOARD_TRACE"
  keyboard_runner_flags='-D LAYERGRAM_KEYBOARD_TRACE'
fi
if [ "$keyboard_simulator" = YES ]; then
  keyboard_output_name="$keyboard_output_name-simulator"
fi
keyboard_derived="${LAYERGRAM_KEYBOARD_DERIVED_DATA:-$keyboard_root/build/$keyboard_output_name}"
keyboard_target="${LAYERGRAM_SCKA_TARGET_DIR:-$keyboard_root/build/ios-keyboard-scka}"
keyboard_logs="$keyboard_root/build/$keyboard_output_name-logs"
mkdir -p "$keyboard_logs"
# A failed configuration step must not leave an older installable app at the
# documented output path. Only remove the generated app for the default build
# directory; a caller-supplied derived-data path is not ours to erase.
keyboard_app="$keyboard_derived/Build/Products/$keyboard_product_directory/Runner.app"
if [ -z "${LAYERGRAM_KEYBOARD_DERIVED_DATA:-}" ]; then
  rm -rf -- "$keyboard_app"
fi
rustup run 1.87.0 cargo build --release --locked --offline --features candidate-ffi \
  --manifest-path "$keyboard_root/native/layergram_scka/Cargo.toml" \
  --target-dir "$keyboard_target" --target "$keyboard_rust_target" \
  > "$keyboard_logs/scka.log" 2>&1
keyboard_library="$keyboard_target/$keyboard_rust_target/release/liblayergram_scka.a"
"$keyboard_root/tool/pq/verify_scka_export_contract.sh" namespace xcrun "$keyboard_library"
keyboard_packaged_library="$keyboard_root/.dart_tool/layergram_pq/scka-package/apple/$keyboard_package_kind/liblayergram_scka.a"
mkdir -p "$(dirname "$keyboard_packaged_library")"
ln -sfn "$keyboard_library" "$keyboard_packaged_library"
keyboard_flags="-Wl,-force_load,\"$keyboard_library\""
while IFS= read -r keyboard_symbol; do
  keyboard_flags="$keyboard_flags -Wl,-u,_$keyboard_symbol"
done < "$keyboard_root/tool/pq/scka_expected_symbols.txt"

keyboard_flutter_args=(--config-only "$keyboard_flutter_mode" --no-pub)
if [ "$keyboard_fixture" = YES ]; then
  keyboard_flutter_args+=(--dart-define=LAYERGRAM_KEYBOARD_DIAGNOSTICS=true)
fi
if [ "$keyboard_simulator" = YES ]; then
  keyboard_flutter_args+=(--simulator)
fi
if [ "$keyboard_simulator_setup" = YES ]; then
  keyboard_flutter_args+=(--dart-define="LAYERGRAM_QA_SIMULATOR_ID=$LAYERGRAM_KEYBOARD_DEVICE_ID")
fi
flutter build ios "${keyboard_flutter_args[@]}" \
  --target "$keyboard_entry" \
  --dart-define=LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true \
  --dart-define=LAYERGRAM_AUTONOMOUS_SYSTEM_KEYBOARD=true \
  > "$keyboard_logs/flutter-config.log" 2>&1
keyboard_defines="$(sed -n 's/^DART_DEFINES=//p' ios/Flutter/Generated.xcconfig)"
if [ -n "${LAYERGRAM_KEYBOARD_DEVICE_ID:-}" ]; then
  keyboard_destination="id=$LAYERGRAM_KEYBOARD_DEVICE_ID"
fi
keyboard_args=(-workspace "$keyboard_workspace" -configuration "$keyboard_configuration" -sdk "$keyboard_sdk_name"
  -destination "$keyboard_destination" -derivedDataPath "$keyboard_derived"
  -jobs 2 ARCHS=arm64 ONLY_ACTIVE_ARCH=YES ENABLE_TESTABILITY=YES
  COMPILER_INDEX_STORE_ENABLE=NO
  "FLUTTER_TARGET=$keyboard_entry" "DART_DEFINES=$keyboard_defines"
  "LAYERGRAM_SCKA_LDFLAGS=$keyboard_flags"
  "LAYERGRAM_RUNNER_SWIFT_FLAGS=$keyboard_runner_flags")
if [ "$keyboard_simulator" = YES ]; then
  keyboard_args+=(CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES)
else
  keyboard_args+=(REGISTER_APP_GROUPS=YES)
fi
if [ "$keyboard_fixture" = YES ]; then
  # All three products use separately registered validation identifiers. A
  # target-specific setting is essential: a global PRODUCT_BUNDLE_IDENTIFIER
  # override would give the app and both extensions the same identifier.
  keyboard_args+=(
    "LAYERGRAM_RUNNER_BUNDLE_ID=$keyboard_fixture_id"
    "LAYERGRAM_KEYBOARD_BUNDLE_ID=$keyboard_fixture_id.keyboard"
    "LAYERGRAM_SHARE_BUNDLE_ID=$keyboard_fixture_id.share"
    "CUSTOM_GROUP_ID=group.$keyboard_fixture_id"
    "CUSTOM_KEYBOARD_GROUP_ID=group.$keyboard_fixture_id.keyboard")
fi
if [ -n "${LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM:-}" ]; then
  keyboard_args+=("DEVELOPMENT_TEAM=$LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM")
fi
if [ "${LAYERGRAM_ALLOW_PROVISIONING_UPDATES:-NO}" = YES ]; then
  keyboard_args+=(-allowProvisioningUpdates)
fi

# Produce the containing app's AOT snapshot and Flutter framework first. The
# extension shares those binaries, without a Flutter view or plugin registrant.
xcodebuild "${keyboard_args[@]}" -scheme Runner LAYERGRAM_KEYBOARD_EMBED=NO \
  LAYERGRAM_RUNNER_ENTITLEMENTS=Runner/RunnerKeyboard.entitlements \
  build > "$keyboard_logs/runner.log" 2>&1
mlkem_archive="$keyboard_derived/Build/Products/$keyboard_product_directory/LayergramMlKem/LayergramMlKem.framework/LayergramMlKem"
test -f "$mlkem_archive" || { echo 'ML-KEM archive for keyboard is missing.' >&2; exit 1; }
keyboard_flags="$keyboard_flags -Wl,-force_load,\"$mlkem_archive\""
while IFS= read -r keyboard_symbol; do
  keyboard_flags="$keyboard_flags -Wl,-u,_$keyboard_symbol"
done < "$keyboard_root/tool/pq/mlkem_expected_symbols.txt"
xcodebuild "${keyboard_args[@]}" -scheme LayergramKeyboard \
  APPLICATION_EXTENSION_API_ONLY=YES \
  "LAYERGRAM_KEYBOARD_LDFLAGS=-framework Flutter $keyboard_flags" \
  "LAYERGRAM_KEYBOARD_SWIFT_FLAGS=$keyboard_extension_flags" \
  build > "$keyboard_logs/extension.log" 2>&1
keyboard_action=build
if [ "${LAYERGRAM_KEYBOARD_BUILD_FOR_TESTING:-NO}" = YES ]; then
  keyboard_action=build-for-testing
fi
xcodebuild "${keyboard_args[@]}" -scheme Runner LAYERGRAM_KEYBOARD_EMBED=YES \
  LAYERGRAM_RUNNER_ENTITLEMENTS=Runner/RunnerKeyboard.entitlements \
  "LAYERGRAM_KEYBOARD_LDFLAGS=-framework Flutter $keyboard_flags" \
  "LAYERGRAM_KEYBOARD_SWIFT_FLAGS=$keyboard_extension_flags" \
  "$keyboard_action" > "$keyboard_logs/embedded-app.log" 2>&1
keyboard_binary="$keyboard_app/PlugIns/LayergramKeyboard.appex/LayergramKeyboard"
keyboard_runner_binary="$keyboard_app/Runner"
if [ "$keyboard_simulator" = YES ]; then
  # Xcode Debug uses a launcher executable; compiled extension code and FFI
  # exports live in its adjacent debug dylib.
  keyboard_binary="$keyboard_binary.debug.dylib"
  if [ -f "$keyboard_runner_binary.debug.dylib" ]; then
    keyboard_runner_binary="$keyboard_runner_binary.debug.dylib"
  fi
fi
/usr/bin/python3 - "$keyboard_root" "$keyboard_binary" <<'PY'
import pathlib
import sys

root, binary = map(pathlib.Path, sys.argv[1:])
sources = list((root / 'ios/LayergramKeyboard').glob('*.swift'))
sources += list((root / 'ios/SystemKeyboardCore/Sources/SystemKeyboardCore').glob('*.swift'))
if not binary.is_file() or any(binary.stat().st_mtime_ns <= source.stat().st_mtime_ns for source in sources):
    raise SystemExit(f'Keyboard binary is missing or stale: {binary}')
PY
"$keyboard_root/tool/pq/verify_scka_export_contract.sh" namespace xcrun "$keyboard_binary"
"$keyboard_root/tool/pq/verify_scka_export_contract.sh" namespace xcrun "$keyboard_runner_binary"
mlkem_actual="$keyboard_logs/keyboard-mlkem-symbols.txt"
xcrun nm -gU "$keyboard_binary" | awk '/ _lg_mlkem768_/ { sub(/^_/, "", $NF); print $NF }' | sort -u > "$mlkem_actual"
diff -u "$keyboard_root/tool/pq/mlkem_expected_symbols.txt" "$mlkem_actual"
mlkem_runner_actual="$keyboard_logs/runner-mlkem-symbols.txt"
xcrun nm -gU "$keyboard_runner_binary" | awk '/ _lg_mlkem768_/ { sub(/^_/, "", $NF); print $NF }' | sort -u > "$mlkem_runner_actual"
diff -u "$keyboard_root/tool/pq/mlkem_expected_symbols.txt" "$mlkem_runner_actual"
otool -L "$keyboard_binary" | awk '/Flutter.framework\/Flutter/ { found=1 } END { exit !found }'
codesign --verify --deep --strict "$keyboard_app"
if [ "$keyboard_fixture" = YES ]; then
  /usr/bin/python3 - "$keyboard_app" "$keyboard_simulator" "$keyboard_derived" "$keyboard_fixture_id" <<'PY'
import pathlib
import plistlib
import subprocess
import sys

app = pathlib.Path(sys.argv[1])
simulator = sys.argv[2] == 'YES'
derived = pathlib.Path(sys.argv[3])
identifier = sys.argv[4]
expected = {
    app: (identifier, {
        f'group.{identifier}',
        f'group.{identifier}.keyboard',
    }),
    app / 'PlugIns/LayergramKeyboard.appex': (
        f'{identifier}.keyboard',
        {f'group.{identifier}.keyboard'},
    ),
    app / 'PlugIns/Share Extension.appex': (
        f'{identifier}.share',
        {f'group.{identifier}'},
    ),
}
for bundle, (identifier, groups) in expected.items():
    actual_identifier = plistlib.loads((bundle / 'Info.plist').read_bytes())['CFBundleIdentifier']
    if simulator:
        # Xcode signs Debug simulator bundles with an empty device entitlement
        # blob and uses the generated Simulated.xcent at simulator runtime.
        target, product = (
            ('Runner', 'Runner.app') if bundle == app else
            ('LayergramKeyboard', 'LayergramKeyboard.appex')
            if bundle.name == 'LayergramKeyboard.appex' else
            ('Share Extension', 'Share Extension.appex')
        )
        simulated = (derived / 'Build/Intermediates.noindex/Runner.build/'
                     'Debug-iphonesimulator' / f'{target}.build' /
                     f'{product}-Simulated.xcent')
        signed = plistlib.loads(simulated.read_bytes())
    else:
        signed = plistlib.loads(subprocess.check_output(
            ['/usr/bin/codesign', '-d', '--entitlements', ':-', str(bundle)],
            stderr=subprocess.DEVNULL,
        ))
    actual_groups = set(signed.get('com.apple.security.application-groups', []))
    if actual_identifier != identifier or actual_groups != groups:
        raise SystemExit(
            f'Fixture identity mismatch in {bundle}: '
            f'id={actual_identifier!r}, groups={sorted(actual_groups)!r}'
        )
print('Validation app, keyboard and share extension identities verified.')
PY
fi
if [ "$keyboard_simulator" = NO ] && [ "$keyboard_fixture" = YES ]; then
  keyboard_signing_args=(--app "$keyboard_app" --identifier "$keyboard_fixture_id")
  if [ -n "${LAYERGRAM_KEYBOARD_DEVICE_ID:-}" ]; then
    keyboard_signing_args+=(--device "$LAYERGRAM_KEYBOARD_DEVICE_ID")
  fi
  /usr/bin/python3 "$keyboard_root/tool/qa/verify_ios_keyboard_signing.py" "${keyboard_signing_args[@]}"
fi
printf 'App: %s\nBuild logs: %s\n' "$keyboard_app" "$keyboard_logs"
