#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
: "${LAYERGRAM_KEYBOARD_DEVICE_ID:?Select the exact disposable test iPhone or simulator}"
case "${LAYERGRAM_KEYBOARD_SIMULATOR:-NO}" in YES|NO) ;; *) echo 'Invalid simulator selection.' >&2; exit 2 ;; esac
mode="${1:-export}"
case "$mode" in authorization|simulator-onboarding|simulator-coordinate-entry|simulator-public-seed-onboarding|simulator-restored-identity-readback|simulator-identity-name-exact|simulator-identity-name-readback|simulator-keyboard-settings-inventory|simulator-keyboard-settings-path|simulator-keyboard-availability|simulator-keyboard-add|simulator-keyboard-access-page|simulator-keyboard-full-access|simulator-keyboard-access-probe|simulator-keyboard-host-inventory|simulator-keyboard-launch|simulator-app-keyboard-settings|simulator-app-keyboard-enable|simulator-keyboard-session|simulator-keyboard-session-inventory|simulator-public-contact-inventory|simulator-public-contact-save|simulator-public-contact-readback|simulator-biometric|simulator-biometric-unavailable|simulator-biometric-retry|simulator-biometric-cancel|export|decode|history|lifecycle|handoff-stability|biometrics|privacy|recording|paste-confirmation) ;; *) echo 'Unknown transport fixture mode.' >&2; exit 2 ;; esac
case "$mode" in simulator-biometric*|simulator-onboarding|simulator-coordinate-entry|simulator-public-seed-onboarding|simulator-restored-identity-readback|simulator-identity-name-exact|simulator-identity-name-readback|simulator-keyboard-settings-inventory|simulator-keyboard-settings-path|simulator-keyboard-availability|simulator-keyboard-add|simulator-keyboard-access-page|simulator-keyboard-full-access|simulator-keyboard-access-probe|simulator-keyboard-host-inventory|simulator-keyboard-launch|simulator-app-keyboard-settings|simulator-app-keyboard-enable|simulator-keyboard-session|simulator-keyboard-session-inventory|simulator-public-contact-inventory|simulator-public-contact-save|simulator-public-contact-readback)
  test "${LAYERGRAM_KEYBOARD_SIMULATOR:-NO}" = YES || {
    echo 'Sensor simulation is refused on physical devices.' >&2; exit 2;
  } ;;
esac
if [ "$mode" = recording ] || [ "$mode" = handoff-stability ]; then
  : "${LAYERGRAM_QA_RECORDING_TRACE:?Supply the current device-scoped code-only trace for the lifecycle gate}"
fi
output="${LAYERGRAM_QA_TRANSPORT_OUTPUT:-${TMPDIR:-/tmp}/layergram-ios-transport}"
mkdir -p "$output/source"
destination="platform=iOS,id=$LAYERGRAM_KEYBOARD_DEVICE_ID"
signing=()
if [ "${LAYERGRAM_KEYBOARD_SIMULATOR:-NO}" = YES ]; then
  test "${LAYERGRAM_KEYBOARD_DISPOSABLE_SIMULATOR:-NO}" = YES || {
    echo 'Select a disposable QA simulator explicitly.' >&2; exit 2;
  }
  test "$mode" != paste-confirmation || { echo 'Paste Settings routing gate is physical-only.' >&2; exit 2; }
  xcrun simctl list devices available --json > "$output/simulator-selection.json"
  python3 - "$output/simulator-selection.json" "$LAYERGRAM_KEYBOARD_DEVICE_ID" <<'PY'
import json, sys
rows = [d for group in json.load(open(sys.argv[1]))['devices'].values() for d in group
        if d['udid'] == sys.argv[2]]
if len(rows) != 1 or rows[0]['state'] != 'Booted' or not rows[0]['name'].startswith('Layergram '):
    raise SystemExit('Select exactly one booted Layergram QA simulator')
PY
  destination="platform=iOS Simulator,id=$LAYERGRAM_KEYBOARD_DEVICE_ID"
  signing=(CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES)
  if { [ "$mode" = simulator-coordinate-entry ] || [ "$mode" = simulator-public-seed-onboarding ] || [ "$mode" = simulator-restored-identity-readback ] || [ "$mode" = simulator-identity-name-exact ] || [ "$mode" = simulator-identity-name-readback ] || [ "$mode" = simulator-keyboard-settings-inventory ] || [ "$mode" = simulator-keyboard-settings-path ] || [ "$mode" = simulator-keyboard-availability ] || [ "$mode" = simulator-keyboard-add ] || [ "$mode" = simulator-keyboard-access-page ] || [ "$mode" = simulator-keyboard-full-access ] || [ "$mode" = simulator-keyboard-access-probe ] || [ "$mode" = simulator-keyboard-host-inventory ] || [ "$mode" = simulator-keyboard-launch ] || [ "$mode" = simulator-app-keyboard-settings ] || [ "$mode" = simulator-app-keyboard-enable ] || [ "$mode" = simulator-keyboard-session ] || [ "$mode" = simulator-keyboard-session-inventory ] || [ "$mode" = simulator-public-contact-inventory ] || [ "$mode" = simulator-public-contact-save ] || [ "$mode" = simulator-public-contact-readback ]; } &&
     [ "$LAYERGRAM_KEYBOARD_DEVICE_ID" != 1D3A51F4-34CC-41F9-9AE7-BEF5687EF6C3 ]; then
    echo 'Coordinate diagnostic requires the exact inspected disposable QA simulator.' >&2
    exit 2
  fi
else
  : "${LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM:?Select the physical iPhone signing team}"
  test "${LAYERGRAM_KEYBOARD_DISPOSABLE_DEVICE:-NO}" = YES || {
    echo 'Select a disposable QA device explicitly.' >&2; exit 2;
  }
  signing=("DEVELOPMENT_TEAM=$LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM" -allowProvisioningUpdates)
fi
if [ "$mode" = paste-confirmation ]; then
  xcrun devicectl device info apps --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" \
    --json-output "$output/installed-app-routing.json" > "$output/installed-app-routing.log"
  python3 - "$output/installed-app-routing.json" <<'PY'
import json
import sys
apps = json.load(open(sys.argv[1]))['result']['apps']
matches = [app for app in apps if app.get('name') == 'Layergram']
if len(matches) != 1 or matches[0].get('bundleIdentifier') != 'app.layergram.keyboardvalidation':
    raise SystemExit('The app Settings entry must uniquely identify the disposable validation bundle')
PY
fi
cp "$root/App.swift" "$root/SimulatorBiometricProbe.swift" "$root/TransportUITests.swift" "$root/project.yml" "$output/source/"
(cd "$output/source" && xcodegen generate --spec project.yml)
xcodebuild -project "$output/source/KeyboardTransportFixture.xcodeproj" -scheme Transport \
  -destination "$destination" \
  -derivedDataPath "$output/DerivedData" -parallel-testing-enabled NO \
  "${signing[@]}" build-for-testing
export LAYERGRAM_QA_TRANSPORT_OUTPUT="$output"
python3 "$root/test_environment.py" "$mode"
if [ "$mode" = authorization ]; then method=testUIAutomationAuthorizationPreflight
elif [ "$mode" = simulator-onboarding ]; then method=testSimulatorLayergramOnboardingAccessibility
elif [ "$mode" = simulator-coordinate-entry ]; then method=testSimulatorCoordinateNameEntry
elif [ "$mode" = simulator-public-seed-onboarding ]; then method=testSimulatorPublicSeedOnboarding
elif [ "$mode" = simulator-restored-identity-readback ]; then method=testSimulatorRestoredIdentityReadback
elif [ "$mode" = simulator-identity-name-exact ]; then method=testSimulatorIdentityNameExactAfterUpdate
elif [ "$mode" = simulator-identity-name-readback ]; then method=testSimulatorIdentityNameExactReadback
elif [ "$mode" = simulator-keyboard-settings-inventory ]; then method=testSimulatorKeyboardSettingsInventory
elif [ "$mode" = simulator-keyboard-settings-path ]; then method=testSimulatorKeyboardSettingsPath
elif [ "$mode" = simulator-keyboard-availability ]; then method=testSimulatorKeyboardAvailability
elif [ "$mode" = simulator-keyboard-add ]; then method=testSimulatorKeyboardAdd
elif [ "$mode" = simulator-keyboard-access-page ]; then method=testSimulatorKeyboardAccessPage
elif [ "$mode" = simulator-keyboard-full-access ]; then method=testSimulatorKeyboardFullAccess
elif [ "$mode" = simulator-keyboard-access-probe ]; then method=testSimulatorKeyboardFullAccessTapProbe
elif [ "$mode" = simulator-keyboard-host-inventory ]; then method=testSimulatorKeyboardHostInventory
elif [ "$mode" = simulator-keyboard-launch ]; then method=testSimulatorKeyboardLaunch
elif [ "$mode" = simulator-app-keyboard-settings ]; then method=testSimulatorAppKeyboardSettingsInventory
elif [ "$mode" = simulator-app-keyboard-enable ]; then method=testSimulatorAppKeyboardEnable
elif [ "$mode" = simulator-keyboard-session ]; then method=testSimulatorKeyboardSessionAdmission
elif [ "$mode" = simulator-keyboard-session-inventory ]; then method=testSimulatorKeyboardSessionInventory
elif [ "$mode" = simulator-public-contact-inventory ]; then method=testSimulatorPublicContactImportInventory
elif [ "$mode" = simulator-public-contact-save ]; then method=testSimulatorPublicContactSave
elif [ "$mode" = simulator-public-contact-readback ]; then method=testSimulatorPublicContactReadback
elif [ "$mode" = simulator-biometric ]; then method=testSimulatorBiometricSensorMatch
elif [ "$mode" = simulator-biometric-unavailable ]; then method=testSimulatorBiometricSensorUnavailable
elif [ "$mode" = simulator-biometric-retry ]; then method=testSimulatorBiometricSensorRejectAndRetry
elif [ "$mode" = simulator-biometric-cancel ]; then method=testSimulatorBiometricSensorCancellation
elif [ "$mode" = paste-confirmation ]; then method=testRestoreCrossAppPasteConfirmation
elif [ "$mode" = privacy ]; then method=testRestoreCaptureProtectionAndVerifyProtectedScreenshot
elif [ "$mode" = recording ]; then method=testRecordingBlocksAndFreshAppReturnRecovers
elif [ "$mode" = handoff-stability ]; then method=testRepeatedProtectedHostHandoffs
elif [ "$mode" = biometrics ]; then method=testEnableKeyboardBiometricResume
elif [ "$mode" = lifecycle ]; then method=testIdleExpiryAndColdHandoffPreserveActiveFS
elif [ "$mode" = history ]; then method=testKeyboardChatArchiveContainsExactMessage
elif [ "$mode" = decode ]; then method=testIncomingCarrierDisplaysPlaintextAfterOnePaste
else method=testContactCountdownAndConsecutiveExports; fi
result="$output/transport-$(date +%Y%m%d-%H%M%S).xcresult"
# XCTest requests the OS automation authorization during initialization. Never
# loop that request, alter passcode/biometrics, or mistake pre-touch denial for
# a Layergram test result. Keep the exact failure log for a safe later resume.
test_log="${result%.xcresult}.log"
if ! xcodebuild test-without-building -xctestrun "$output/DerivedData/Build/Products/transport.xctestrun" \
  -destination "$destination" -parallel-testing-enabled NO \
  "-only-testing:TransportUITests/TransportUITests/$method" -resultBundlePath "$result" \
  > "$test_log" 2>&1; then
  python3 "$root/classify_xctest_failure.py" --log "$test_log"
  exit 1
fi
if [ "$mode" = recording ]; then
  python3 "$root/verify_recording_recovery.py" --trace "$LAYERGRAM_QA_RECORDING_TRACE" \
    --xctest-log "$test_log"
fi
if [ "$mode" = handoff-stability ]; then
  python3 "$root/verify_handoff_stability.py" --trace "$LAYERGRAM_QA_RECORDING_TRACE" \
    --xctest-log "$test_log"
fi
if [ "${LAYERGRAM_KEYBOARD_SIMULATOR:-NO}" = YES ]; then
  printf 'Simulator transport result (not physical authentication): %s\n' "$result"
else
  printf 'Physical transport result: %s\n' "$result"
fi
