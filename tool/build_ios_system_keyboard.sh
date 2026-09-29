#!/bin/bash
# Build the local experimental keyboard preview for the current Mac's simulator.
# Ordinary `flutter build ios` / Runner builds do not embed the extension.
set -euo pipefail
keyboard_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$keyboard_root"
keyboard_sdk="$(xcrun --sdk iphonesimulator --show-sdk-version)"
if [ "${keyboard_sdk%%.*}" -lt 26 ]; then
  echo 'The experimental iOS keyboard requires Xcode with the iOS 26 SDK or later.' >&2
  exit 1
fi
flutter build ios --config-only --simulator --debug \
  --dart-define=LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true
keyboard_arch="$(uname -m)"
keyboard_derived="$keyboard_root/build/ios-system-keyboard"
keyboard_build_args=(-workspace ios/Runner.xcworkspace -configuration Debug
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator'
  -derivedDataPath "$keyboard_derived" "ARCHS=$keyboard_arch"
  ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=-)
xcodebuild "${keyboard_build_args[@]}" -scheme LayergramKeyboard build
xcodebuild "${keyboard_build_args[@]}" -scheme Runner LAYERGRAM_KEYBOARD_EMBED=YES \
  LAYERGRAM_RUNNER_ENTITLEMENTS=Runner/RunnerKeyboard.entitlements build
printf 'Simulator app: %s/Build/Products/Debug-iphonesimulator/Runner.app\n' "$keyboard_derived"
