#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
DEVICE_ID=${LAYERGRAM_SCKA_ANDROID_PHYSICAL_DEVICE_ID:-}
PACKAGE_ROOT=${LAYERGRAM_SCKA_ANDROID_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/android}
APK=$REPO_ROOT/build/app/outputs/flutter-apk/app-release.apk
PACKAGE_ID=app.layergram.sckasmoke
ACTIVITY=app.layergram.MainActivity
MARKER=LAYERGRAM_SCKA_PACKAGED_SCOPE_OK
LAUNCH_TIMEOUT=${LAYERGRAM_SCKA_ANDROID_PHYSICAL_TIMEOUT_SECONDS:-60}
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
LOGCAT_PID=

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [ -n "$LOGCAT_PID" ]; then
    kill "$LOGCAT_PID" >/dev/null 2>&1 || true
    wait "$LOGCAT_PID" 2>/dev/null || true
  fi
  if [ -n "$DEVICE_ID" ]; then
    adb -s "$DEVICE_ID" uninstall "$PACKAGE_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

package_installed() {
  adb -s "$DEVICE_ID" shell pm path "$1" 2>/dev/null | grep -q '^package:'
}

[ "$(uname -s)" = Darwin ] || fail 'Physical Android testing currently requires the macOS host'
[ -n "$ANDROID_SDK" ] || fail 'Set ANDROID_HOME or ANDROID_SDK_ROOT'
[ -n "$DEVICE_ID" ] ||
  fail 'Set LAYERGRAM_SCKA_ANDROID_PHYSICAL_DEVICE_ID to one authorized device'
command -v adb >/dev/null 2>&1 || fail 'Android platform-tools adb is required'
command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required'
command -v flutter >/dev/null 2>&1 || fail 'Flutter is required'
command -v unzip >/dev/null 2>&1 || fail 'unzip is required'
[ "$(rustc --version | awk '{ print $2 }')" = 1.87.0 ] ||
  fail 'Layergram SCKA packaging requires Rust 1.87.0'

# Android SDK command-line tools require Java 17 or later. Use the JDK pinned
# by Flutter instead of inheriting an older interactive-shell JAVA_HOME.
FLUTTER_JDK=$(flutter config --list 2>/dev/null |
  sed -n 's/^  jdk-dir: //p' | tail -1)
if [ -n "$FLUTTER_JDK" ] && [ -x "$FLUTTER_JDK/bin/java" ]; then
  # Some Android SDK launchers mishandle spaces in JAVA_HOME. Point them at a
  # task-local symlink rather than the usual "Android Studio.app" path.
  mkdir -p "$PACKAGE_ROOT"
  JDK_LINK=$PACKAGE_ROOT/flutter-jdk
  ln -sfn "$FLUTTER_JDK" "$JDK_LINK"
  JAVA_HOME=$JDK_LINK
  PATH=$JAVA_HOME/bin:$PATH
  export JAVA_HOME PATH
fi
java_major=$(java -version 2>&1 | awk -F '[".]' 'NR == 1 { print ($2 == 1 ? $3 : $2) }')
[ "$java_major" -ge 17 ] 2>/dev/null ||
  fail 'Android SDK command-line tools require Java 17 or later'
[ "$(adb -s "$DEVICE_ID" get-state 2>/dev/null)" = device ] ||
  fail 'The selected Android device is not authorized and online'
[ "$(adb -s "$DEVICE_ID" shell getprop ro.kernel.qemu | tr -d '\r')" != 1 ] ||
  fail 'The selected target is an emulator, not a physical Android device'

APKANALYZER=$(find "$ANDROID_SDK/cmdline-tools" -type f \
  -path '*/bin/apkanalyzer' -perm -111 -print | sort -V | tail -1)
APKSIGNER=$(find "$ANDROID_SDK/build-tools" -type f \
  -name apksigner -perm -111 -print | sort -V | tail -1)
NDK_NM=$(find "$ANDROID_SDK/ndk" -type f \
  -path '*/toolchains/llvm/prebuilt/*/bin/llvm-nm' -print | sort | tail -1)
[ -x "$APKANALYZER" ] || fail 'Android SDK apkanalyzer was not found'
[ -x "$APKSIGNER" ] || fail 'Android SDK apksigner was not found'
[ -x "$NDK_NM" ] || fail 'Android NDK llvm-nm was not found'

if package_installed "$PACKAGE_ID"; then
  adb -s "$DEVICE_ID" uninstall "$PACKAGE_ID" >/dev/null ||
    fail 'Could not remove a stale Layergram SCKA smoke package'
fi

"$SCRIPT_DIR/prepare_scka_packaged_android.sh"
ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true \
ORG_GRADLE_PROJECT_layergramSckaPhysicalSmoke=true \
  flutter build apk --release -t tool/pq/scka_packaged_scope_smoke.dart
[ -f "$APK" ] || fail "Missing physical-Android SCKA APK: $APK"
[ "$("$APKANALYZER" manifest application-id "$APK")" = "$PACKAGE_ID" ] ||
  fail 'Physical-Android smoke APK has the production package identifier'
"$APKSIGNER" verify --verbose --print-certs "$APK"

EXTRACT_ROOT="$PACKAGE_ROOT/physical-apk"
mkdir -p "$EXTRACT_ROOT"
for abi in arm64-v8a armeabi-v7a x86_64; do
  archive_path="lib/$abi/liblayergram_scka.so"
  unzip -oq "$APK" "$archive_path" -d "$EXTRACT_ROOT"
  actual="$PACKAGE_ROOT/$abi-physical-symbols.txt"
  "$NDK_NM" -D --defined-only "$EXTRACT_ROOT/$archive_path" |
    awk '{ name = $NF; sub(/@@.*/, "", name); if (name ~ /^lg_scka_v1_/) print name }' |
    sort -u >"$actual"
  cmp -s "$SYMBOLS" "$actual" || {
    diff -u "$SYMBOLS" "$actual" >&2 || true
    fail "Unexpected physical-Android SCKA exports for $abi"
  }
done

device_abis=$(adb -s "$DEVICE_ID" shell getprop ro.product.cpu.abilist | tr -d '\r')
printf '%s\n' "$device_abis" | tr ',' '\n' |
  grep -E '^(arm64-v8a|armeabi-v7a|x86_64)$' >/dev/null ||
  fail "Unsupported physical Android ABI list: $device_abis"

adb -s "$DEVICE_ID" install --no-streaming "$APK" >/dev/null
package_installed "$PACKAGE_ID" || fail 'Physical-Android smoke package was not installed'

log_file="$PACKAGE_ROOT/physical-device.log"
adb -s "$DEVICE_ID" logcat -T 1 -v brief >"$log_file" &
LOGCAT_PID=$!
adb -s "$DEVICE_ID" shell am force-stop "$PACKAGE_ID"
adb -s "$DEVICE_ID" shell am start -W \
  -n "$PACKAGE_ID/$ACTIVITY" >/dev/null

started_at=$(date +%s)
while adb -s "$DEVICE_ID" shell pidof "$PACKAGE_ID" 2>/dev/null |
    grep -q '[0-9]'; do
  now=$(date +%s)
  [ $((now - started_at)) -lt "$LAUNCH_TIMEOUT" ] ||
    fail 'Physical-Android SCKA scope smoke did not terminate'
  sleep 1
done

sleep 1
kill "$LOGCAT_PID" >/dev/null 2>&1 || true
wait "$LOGCAT_PID" 2>/dev/null || true
LOGCAT_PID=
app_pid=$(sed -n \
  "s/.*Start proc \([0-9][0-9]*\):$PACKAGE_ID.*/\1/p" "$log_file" | tail -1)
[ -n "$app_pid" ] || fail 'Physical-Android smoke process was not observed'
grep -E "^I/flutter[[:space:]]+\\([[:space:]]*$app_pid\\): $MARKER$" \
  "$log_file" >/dev/null ||
  fail 'Physical-Android SCKA scope smoke did not complete'

adb -s "$DEVICE_ID" uninstall "$PACKAGE_ID" >/dev/null
package_installed "$PACKAGE_ID" &&
  fail 'Physical-Android SCKA smoke package remains installed after cleanup'

model=$(adb -s "$DEVICE_ID" shell getprop ro.product.model | tr -d '\r')
release=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.release | tr -d '\r')
printf '%s\n' "Physical Android: $model (Android $release; $device_abis)"
printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_ANDROID_PHYSICAL_OK'
