#!/usr/bin/env bash
set -euo pipefail

# Build the real QA application. Never substitute a diagnostic Dart entrypoint:
# an app start with the keyboard feature compiled out disables the native IME.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
target=${1:-}
case "$target" in
  lib/main.dart) ;;
  *)
    printf '%s\n' 'Pass the public full-app entrypoint: lib/main.dart' >&2
    exit 2
    ;;
esac
test -f "$repo_root/$target" || {
  printf 'Missing full-app entrypoint: %s\n' "$target" >&2
  exit 2
}
test -f "$repo_root/.dart_tool/layergram_pq/scka-package/android/jniLibs/arm64-v8a/liblayergram_scka.so" || {
  printf '%s\n' 'Prepare the packaged SCKA Android library before the QA build.' >&2
  exit 2
}

cd "$repo_root"
export ORG_GRADLE_PROJECT_layergramKeyboardValidation=true
export ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true
flutter build apk --profile --no-pub -t "$target" \
  --dart-define=LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true \
  --dart-define=LAYERGRAM_AUTONOMOUS_SYSTEM_KEYBOARD=true \
  --dart-define=LAYERGRAM_KEYBOARD_DIAGNOSTICS=true

aapt=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}/build-tools/35.0.0/aapt
package_line=$("$aapt" dump badging build/app/outputs/apk/profile/app-profile.apk | rg '^package: ')
case "$package_line" in
  *"name='app.layergram.keyboardvalidation'"*) ;;
  *)
    printf '%s\n' 'Refusing APK with a non-QA package id.' >&2
    exit 3
    ;;
esac
printf '%s\n' 'Full keyboard QA APK built with both keyboard feature flags.'
