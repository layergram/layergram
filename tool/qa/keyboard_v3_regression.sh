#!/usr/bin/env bash
# Re-run the V3 and system-keyboard contracts after protocol, custody or UI changes.
set -euo pipefail

qa_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$qa_root"
qa_stage="${1:-dart}"

run_dart() {
  python3 -m unittest discover -s tool/qa -p test_verify_ios_keyboard_signing.py
  flutter test \
    test/core/crypto/v3 \
    test/features/system_keyboard \
    test/core/storage/aux_record_lifecycle_test.dart \
    test/features/contact_verification/contact_verification_actions_test.dart \
    test/security/system_keyboard_ios_surface_test.dart \
    test/security/system_keyboard_surface_test.dart \
    test/stego_roundtrip_test.dart \
    test/ui/fs_security_ux_test.dart \
    test/ui/keyboard_dark_palette_contract_test.dart
}

run_swift() {
  swift test --package-path ios/SystemKeyboardCore
}

run_android() {
  (cd "$qa_root/android" && ./gradlew :app:testDebugUnitTest)
}

require_android_fixture_device() {
  local qa_serial="${LAYERGRAM_KEYBOARD_ANDROID_SERIAL:-}"
  test -n "$qa_serial" || { echo 'Select LAYERGRAM_KEYBOARD_ANDROID_SERIAL.' >&2; exit 2; }
  case "$qa_serial" in
    emulator-*) ;;
    *)
      if [ "${LAYERGRAM_KEYBOARD_DISPOSABLE_DEVICE:-NO}" != YES ]; then
        echo 'Physical QA requires LAYERGRAM_KEYBOARD_DISPOSABLE_DEVICE=YES.' >&2
        exit 2
      fi
      ;;
  esac
  local qa_adb="${ANDROID_HOME:?Set ANDROID_HOME}/platform-tools/adb"
  test "$("$qa_adb" -s "$qa_serial" get-state)" = device || {
    echo 'The selected QA device is not connected and authorized.' >&2; exit 2;
  }
}

run_android_ui() {
  local qa_serial="${LAYERGRAM_KEYBOARD_ANDROID_SERIAL:-}"
  local qa_adb="${ANDROID_HOME:?Set ANDROID_HOME}/platform-tools/adb"
  require_android_fixture_device
  local qa_mode=debug qa_task=:app:assembleDebug
  case "$qa_serial" in emulator-*) ;; *) qa_mode=profile; qa_task=:app:assembleProfile ;; esac
  (cd "$qa_root/android" && ./gradlew "$qa_task" :app:assembleDebugAndroidTest \
    -PlayergramKeyboardValidation=true "-Ptarget=$qa_root/tool/qa/android_keyboard_fixture.dart")
  "$qa_adb" -s "$qa_serial" install -r "$qa_root/build/app/outputs/apk/$qa_mode/app-$qa_mode.apk"
  "$qa_adb" -s "$qa_serial" install -r "$qa_root/build/app/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
  local qa_result
  qa_result="$(mktemp)"
  "$qa_adb" -s "$qa_serial" shell am instrument -w \
    -e class app.layergram.KeyboardSurfaceInstrumentedTest \
    app.layergram.keyboardvalidation.test/androidx.test.runner.AndroidJUnitRunner | tee "$qa_result"
  if ! rg -q '^OK \([0-9]+ tests?\)' "$qa_result" || rg -q 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' "$qa_result"; then
    rm -f "$qa_result"; exit 1
  fi
  rm -f "$qa_result"
}

run_android_autonomous() {
  # Destructive lifecycle tests are confined to this fixed fixture package and
  # an explicitly selected disposable test device. Never uninstall a user's app.
  local qa_serial="${LAYERGRAM_KEYBOARD_ANDROID_SERIAL:-}"
  local qa_adb="${ANDROID_HOME:?Set ANDROID_HOME}/platform-tools/adb"
  local qa_package=app.layergram.keyboardvalidation
  require_android_fixture_device
  ./tool/pq/prepare_scka_packaged_android.sh
  # Physical devices use AOT, as shipped. Debug JIT work can block Flutter's
  # merged platform/UI thread past the independently enforced short lease.
  local qa_mode=debug qa_task=:app:assembleDebug
  case "$qa_serial" in emulator-*) ;; *) qa_mode=profile; qa_task=:app:assembleProfile ;; esac
  (cd "$qa_root/android" && ./gradlew :app:testDebugUnitTest "$qa_task" :app:assembleDebugAndroidTest \
    -PlayergramKeyboardValidation=true -PlayergramSckaCandidatePackage=true \
    "-Ptarget=$qa_root/tool/qa/android_keyboard_fixture.dart")
  local qa_app="$qa_root/build/app/outputs/apk/$qa_mode/app-$qa_mode.apk"
  local qa_test="$qa_root/build/app/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
  "$qa_adb" -s "$qa_serial" install -r "$qa_app"
  "$qa_adb" -s "$qa_serial" install -r "$qa_test"
  # Each gate starts from a clean disposable fixture, including after an
  # interrupted run. Lifecycle continuity is then tested explicitly below.
  "$qa_adb" -s "$qa_serial" shell pm clear "$qa_package"
  local qa_result
  qa_result="$(mktemp)"
  qa_instrument() {
    "$qa_adb" -s "$qa_serial" shell am instrument -w "$@" "$qa_package.test/androidx.test.runner.AndroidJUnitRunner" | tee "$qa_result"
    if ! rg -q '^OK \([0-9]+ tests?\)' "$qa_result" || rg -q 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' "$qa_result"; then
      rm -f "$qa_result"; exit 1
    fi
  }
  qa_instrument -e class app.layergram.KeyboardCustodyInstrumentedTest,app.layergram.KeyboardAutonomousInstrumentedTest
  qa_instrument -e class app.layergram.KeyboardLifecycleInstrumentedTest -e lifecycleStage seed
  "$qa_adb" -s "$qa_serial" install -r "$qa_app"
  qa_instrument -e class app.layergram.KeyboardLifecycleInstrumentedTest -e lifecycleStage upgrade
  "$qa_adb" -s "$qa_serial" uninstall "$qa_package"
  "$qa_adb" -s "$qa_serial" install "$qa_app"
  qa_instrument -e class app.layergram.KeyboardLifecycleInstrumentedTest -e lifecycleStage fresh
  rm -f "$qa_result"
}

run_ios_ui() {
  if [ "$(uname -s)" != Darwin ]; then
    echo 'iOS UI tests require macOS.' >&2
    exit 2
  fi
  if [ -z "${LAYERGRAM_KEYBOARD_SIMULATOR_ID:-}" ]; then
    echo 'Set LAYERGRAM_KEYBOARD_SIMULATOR_ID to an available iOS Simulator UUID.' >&2
    exit 2
  fi
  LAYERGRAM_KEYBOARD_FIXTURE=YES \
    LAYERGRAM_KEYBOARD_SIMULATOR=YES \
    LAYERGRAM_KEYBOARD_BUILD_FOR_TESTING=YES \
    ./tool/build_ios_autonomous_keyboard.sh
  qa_xctestrun="$qa_root/build/ios-autonomous-keyboard-fixture-simulator/Build/Products/Runner_iphonesimulator$(xcrun --sdk iphonesimulator --show-sdk-version)-arm64.xctestrun"
  if [ ! -f "$qa_xctestrun" ]; then
    echo "The keyboard fixture did not produce $qa_xctestrun" >&2
    exit 1
  fi
  xcodebuild test-without-building \
    -xctestrun "$qa_xctestrun" \
    -destination "platform=iOS Simulator,id=$LAYERGRAM_KEYBOARD_SIMULATOR_ID" \
    -parallel-testing-enabled NO \
    '-only-testing:RunnerTests/KeyboardViewControllerTests' \
    '-only-testing:RunnerTests/SystemKeyboardHostTests'
}

run_ios_device() {
  : "${LAYERGRAM_KEYBOARD_DEVICE_ID:?Select a physical test iPhone}"
  : "${LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM:?Select its signing team}"
  python3 -m unittest discover -s tool/qa -p test_verify_ios_keyboard_signing.py
  LAYERGRAM_KEYBOARD_FIXTURE=YES LAYERGRAM_KEYBOARD_ISOLATED_QA=YES \
    LAYERGRAM_KEYBOARD_BUILD_FOR_TESTING=YES ./tool/build_ios_autonomous_keyboard.sh
  local qa_sdk
  qa_sdk="$(xcrun --sdk iphoneos --show-sdk-version)"
  local qa_tests="$qa_root/build/ios-autonomous-keyboard-isolated-qa/Build/Products/Runner_iphoneos$qa_sdk-arm64.xctestrun"
  test -f "$qa_tests" || { echo 'Physical fixture test bundle is missing.' >&2; exit 1; }
  xcodebuild test-without-building -xctestrun "$qa_tests" \
    -destination "platform=iOS,id=$LAYERGRAM_KEYBOARD_DEVICE_ID" \
    -parallel-testing-enabled NO \
    '-only-testing:RunnerTests/KeyboardViewControllerTests' \
    '-only-testing:RunnerTests/SystemKeyboardHostTests' \
    '-only-testing:RunnerTests/KeyboardAutonomousRuntimeTests'
}

run_ios_device_update() {
  : "${LAYERGRAM_KEYBOARD_DEVICE_ID:?Select a physical test iPhone}"
  : "${LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM:?Select its signing team}"
  LAYERGRAM_KEYBOARD_FIXTURE=YES LAYERGRAM_KEYBOARD_ISOLATED_QA=YES \
    LAYERGRAM_KEYBOARD_BUILD_FOR_TESTING=YES ./tool/build_ios_autonomous_keyboard.sh
  local qa_products="$qa_root/build/ios-autonomous-keyboard-isolated-qa/Build/Products"
  local qa_tests="$qa_products/Runner_iphoneos$(xcrun --sdk iphoneos --show-sdk-version)-arm64.xctestrun"
  local qa_stage
  for qa_stage in seed upgrade; do
    python3 - "$qa_tests" "$qa_stage" <<'PY'
import pathlib, plistlib, sys
source = pathlib.Path(sys.argv[1])
data = plistlib.loads(source.read_bytes())
target = data['RunnerTests']
target.setdefault('EnvironmentVariables', {})['LAYERGRAM_V3_UPDATE_STAGE'] = sys.argv[2]
target['OnlyTestIdentifiers'] = ['KeyboardAutonomousRuntimeTests/testGreenFsSurvivesInPlaceUpdate']
source.with_name('V3UpdateStage.xctestrun').write_bytes(plistlib.dumps(data))
PY
    # This in-place install between staged processes is the update boundary.
    xcrun devicectl device install app --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" \
      "$qa_products/Profile-iphoneos/Runner.app"
    xcodebuild test-without-building -xctestrun "$qa_products/V3UpdateStage.xctestrun" \
      -destination "platform=iOS,id=$LAYERGRAM_KEYBOARD_DEVICE_ID" -parallel-testing-enabled NO
  done
}

run_ios_lifecycle() {
  : "${LAYERGRAM_KEYBOARD_DEVICE_ID:?Select a physical test iPhone}"
  : "${LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM:?Select its signing team}"
  command -v xcodegen >/dev/null || { echo 'Install XcodeGen for the isolated lifecycle fixture.' >&2; exit 2; }
  # This fixed QA identifier is disposable. Never remove a user's app or the
  # validation app containing manual test conversations.
  local qa_package=app.layergram.keyboardvalidation.qa
  local qa_derived="$qa_root/build/ios-custody-installation"
  xcodegen generate --spec "$qa_root/tool/qa/ios_custody_fixture/project.yml"
  local qa_build=(-project "$qa_root/tool/qa/ios_custody_fixture/KeyboardCustodyFixture.xcodeproj"
    -scheme CustodyFixture -destination "platform=iOS,id=$LAYERGRAM_KEYBOARD_DEVICE_ID"
    -derivedDataPath "$qa_derived" -parallel-testing-enabled NO
    "DEVELOPMENT_TEAM=$LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM")
  if [ "${LAYERGRAM_ALLOW_PROVISIONING_UPDATES:-NO}" = YES ]; then
    qa_build+=(-allowProvisioningUpdates)
  fi
  xcodebuild "${qa_build[@]}" build-for-testing
  local qa_app="$qa_derived/Build/Products/Debug-iphoneos/CustodyFixture.app"
  python3 tool/qa/verify_ios_keyboard_signing.py --kind custody --app "$qa_app" \
    --identifier "$qa_package" --device "$LAYERGRAM_KEYBOARD_DEVICE_ID"
  # devicectl uninstall is repeatable even when the package is absent.
  xcrun devicectl device uninstall app --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" "$qa_package"
  local qa_stage qa_tests
  qa_tests="$qa_derived/Build/Products/CustodyFixture_iphoneos$(xcrun --sdk iphoneos --show-sdk-version)-arm64.xctestrun"
  for qa_stage in seed upgrade fresh; do
    if [ "$qa_stage" = fresh ]; then
      xcrun devicectl device uninstall app --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" "$qa_package"
    fi
    # Explicit installation between stages is the OS update/reinstall boundary.
    xcrun devicectl device install app --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" "$qa_app"
    python3 - "$qa_tests" "$qa_stage" <<'PY'
import pathlib, plistlib, sys
source = pathlib.Path(sys.argv[1])
data = plistlib.loads(source.read_bytes())
target = data['CustodyFixtureTests']
target.setdefault('EnvironmentVariables', {})['LAYERGRAM_CUSTODY_STAGE'] = sys.argv[2]
if sys.argv[2] != 'seed':
    target['OnlyTestIdentifiers'] = ['CustodyInstallationTests/testInstallationStage']
source.with_name('LifecycleStage.xctestrun').write_bytes(plistlib.dumps(data))
PY
    xcodebuild test-without-building -xctestrun "$(dirname "$qa_tests")/LifecycleStage.xctestrun" \
      -destination "platform=iOS,id=$LAYERGRAM_KEYBOARD_DEVICE_ID" -parallel-testing-enabled NO
  done
  xcrun devicectl device uninstall app --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" "$qa_package"
}

case "$qa_stage" in
  dart) run_dart ;;
  swift) run_swift ;;
  android) run_android ;;
  android-ui) run_android_ui ;;
  android-autonomous) run_android_autonomous ;;
  ios-ui) run_ios_ui ;;
  ios-device) run_ios_device ;;
  ios-device-update) run_ios_device_update ;;
  ios-lifecycle) run_ios_lifecycle ;;
  ios-transport-export) bash tool/qa/ios_transport_fixture/run.sh export ;;
  ios-transport-decode) bash tool/qa/ios_transport_fixture/run.sh decode ;;
  all) run_dart; run_swift; run_android; run_ios_ui ;;
  *) echo 'Usage: keyboard_v3_regression.sh [dart|swift|ios-ui|ios-device|ios-device-update|ios-lifecycle|ios-transport-export|ios-transport-decode|android|android-ui|android-autonomous|all]' >&2; exit 2 ;;
esac
