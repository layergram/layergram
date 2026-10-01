#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
sdk="${ANDROID_HOME:?Set ANDROID_HOME to the installed Android SDK}"
build_tools="${LAYERGRAM_QA_BUILD_TOOLS:-35.0.0}"
platform="${LAYERGRAM_QA_ANDROID_PLATFORM:-android-35}"
output="${LAYERGRAM_QA_TRANSPORT_OUTPUT:-${TMPDIR:-/tmp}/layergram-android-transport}"
mkdir -p "$output/classes" "$output/dex"
"${JAVA_HOME:?Set JAVA_HOME to a JDK}/bin/javac" -source 8 -target 8 -classpath "$sdk/platforms/$platform/android.jar" -d "$output/classes" "$root"/*.java
"$JAVA_HOME/bin/jar" cf "$output/classes.jar" -C "$output/classes" .
"$sdk/build-tools/$build_tools/d8" --min-api 23 --lib "$sdk/platforms/$platform/android.jar" --output "$output/dex" "$output/classes.jar"
"$sdk/build-tools/$build_tools/aapt" package -f -M "$root/AndroidManifest.xml" -I "$sdk/platforms/$platform/android.jar" -F "$output/transport-unsigned.apk"
(cd "$output/dex" && zip -q "$output/transport-unsigned.apk" classes.dex)
"$sdk/build-tools/$build_tools/zipalign" -f 4 "$output/transport-unsigned.apk" "$output/transport-aligned.apk"
"$sdk/build-tools/$build_tools/apksigner" sign --ks "${LAYERGRAM_QA_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}" --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out "$output/transport.apk" "$output/transport-aligned.apk"
printf 'Offline transport APK: %s\n' "$output/transport.apk"
