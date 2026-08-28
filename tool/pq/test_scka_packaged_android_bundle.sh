#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
PACKAGE_ROOT=${LAYERGRAM_SCKA_ANDROID_PACKAGE_DIR:-$REPO_ROOT/.dart_tool/layergram_pq/scka-package/android}
AAB=$REPO_ROOT/build/app/outputs/bundle/release/app-release.aab
PACKAGE_ID=app.layergram.sckasmoke
SYMBOLS="$SCRIPT_DIR/scka_expected_symbols.txt"
ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
GRADLE_CACHE=${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1
BUNDLETOOL_RUNTIME=
ARTIFACT_BACKUP_DIR=
AAB_EXISTED=false

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [ -n "$BUNDLETOOL_RUNTIME" ] && [ -d "$BUNDLETOOL_RUNTIME" ]; then
    find "$BUNDLETOOL_RUNTIME" -type l -delete 2>/dev/null || true
    rmdir "$BUNDLETOOL_RUNTIME" 2>/dev/null || true
  fi
  if [ -n "$ARTIFACT_BACKUP_DIR" ]; then
    rm -f "$AAB"
    if [ "$AAB_EXISTED" = true ]; then
      mkdir -p "$(dirname "$AAB")"
      mv "$ARTIFACT_BACKUP_DIR/app-release.aab" "$AAB"
    fi
    rmdir "$ARTIFACT_BACKUP_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ -n "$ANDROID_SDK" ] || fail 'Set ANDROID_HOME or ANDROID_SDK_ROOT'
command -v flutter >/dev/null 2>&1 || fail 'Flutter is required'
command -v unzip >/dev/null 2>&1 || fail 'unzip is required'
command -v zipinfo >/dev/null 2>&1 || fail 'zipinfo is required'

mkdir -p "$PACKAGE_ROOT"
FLUTTER_JDK=$(flutter config --list 2>/dev/null |
  sed -n 's/^  jdk-dir: //p' | tail -1)
if [ -n "$FLUTTER_JDK" ] && [ -x "$FLUTTER_JDK/bin/java" ]; then
  JDK_LINK=$PACKAGE_ROOT/flutter-jdk
  ln -sfn "$FLUTTER_JDK" "$JDK_LINK"
  JAVA_HOME=$JDK_LINK
  PATH=$JAVA_HOME/bin:$PATH
  export JAVA_HOME PATH
fi
java_major=$(java -version 2>&1 |
  awk -F '[".]' 'NR == 1 { print ($2 == 1 ? $3 : $2) }')
[ "$java_major" -ge 17 ] 2>/dev/null ||
  fail 'Android bundle verification requires Java 17 or later'
command -v jarsigner >/dev/null 2>&1 || fail 'JDK jarsigner is required'

ARTIFACT_BACKUP_DIR=$(mktemp -d "$PACKAGE_ROOT/aab-backup.XXXXXX")
if [ -f "$AAB" ]; then
  mv "$AAB" "$ARTIFACT_BACKUP_DIR/app-release.aab"
  AAB_EXISTED=true
fi
"$SCRIPT_DIR/prepare_scka_packaged_android.sh"
ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true \
ORG_GRADLE_PROJECT_layergramSckaPhysicalSmoke=true \
  flutter build appbundle --release -t tool/pq/scka_packaged_scope_smoke.dart
[ -f "$AAB" ] || fail "Missing packaged Android App Bundle: $AAB"

JARSIGNER_LOG=$PACKAGE_ROOT/app-bundle-jarsigner.txt
LC_ALL=C jarsigner -verify -verbose -certs "$AAB" >"$JARSIGNER_LOG" 2>&1 ||
  fail 'Android App Bundle signature verification failed'
grep -F 'jar verified.' "$JARSIGNER_LOG" >/dev/null ||
  fail 'Android App Bundle is not JAR-signed'
zipinfo -1 "$AAB" | grep -E '^META-INF/[^/]+\.(SF|RSA|DSA|EC)$' >/dev/null ||
  fail 'Android App Bundle does not contain signature metadata'

BUNDLETOOL_ROOT=$GRADLE_CACHE/com.android.tools.build/bundletool
[ -d "$BUNDLETOOL_ROOT" ] || fail 'Gradle bundletool cache was not found'
BUNDLETOOL=$(find "$BUNDLETOOL_ROOT" -type f \
  -name 'bundletool-*.jar' -print | sort -V | tail -1)
[ -f "$BUNDLETOOL" ] || fail 'Gradle bundletool JAR was not found'

BUNDLETOOL_RUNTIME=$(mktemp -d "$PACKAGE_ROOT/bundletool-runtime.XXXXXX")
BUNDLETOOL_CLASSPATH=$(unzip -p "$BUNDLETOOL" META-INF/MANIFEST.MF |
  tr -d '\r' | awk '
    /^Class-Path:/ { value = substr($0, 13); active = 1; next }
    active && /^ / { value = value substr($0, 2); next }
    active { print value; exit }
    END { if (active) print value }
  ' | head -1)
[ -n "$BUNDLETOOL_CLASSPATH" ] ||
  fail 'Gradle bundletool dependency manifest was not found'

printf '%s\n' "$BUNDLETOOL_CLASSPATH" | tr ' ' '\n' |
  while IFS= read -r jar_name; do
    [ -n "$jar_name" ] || continue
    dependency=$(find "$GRADLE_CACHE" -type f -name "$jar_name" -print |
      head -1)
    if [ -z "$dependency" ] &&
      printf '%s' "$jar_name" | grep -q '^aapt2-proto-'; then
      aapt2_proto_root=$GRADLE_CACHE/com.android.tools.build/aapt2-proto
      [ -d "$aapt2_proto_root" ] ||
        fail 'Gradle aapt2-proto cache was not found'
      # Bundletool's JAR manifest names an older schema artifact. The Android
      # Gradle Plugin resolves a newer wire-compatible aapt2 proto at build
      # time, so use that already-cached tool artifact for offline validation.
      dependency=$(find "$aapt2_proto_root" -type f \
        -name 'aapt2-proto-*.jar' -print | sort -V | tail -1)
    fi
    [ -f "$dependency" ] ||
      fail "Missing cached bundletool dependency: $jar_name"
    ln -s "$dependency" "$BUNDLETOOL_RUNTIME/$jar_name"
  done

BUNDLETOOL_MAIN=com.android.tools.build.bundletool.BundleToolMain
BUNDLETOOL_CP=$BUNDLETOOL:$BUNDLETOOL_RUNTIME/'*'
BUNDLETOOL_LOG=$PACKAGE_ROOT/app-bundle-validate.txt
java -cp "$BUNDLETOOL_CP" "$BUNDLETOOL_MAIN" validate \
  --bundle "$AAB" >"$BUNDLETOOL_LOG"

MANIFEST_XML=$PACKAGE_ROOT/app-bundle-manifest.xml
java -cp "$BUNDLETOOL_CP" "$BUNDLETOOL_MAIN" dump manifest \
  --bundle "$AAB" --module base >"$MANIFEST_XML"
grep -F "package=\"$PACKAGE_ID\"" "$MANIFEST_XML" >/dev/null ||
  fail 'Android App Bundle has the production package identifier'

NDK_NM=$(find "$ANDROID_SDK/ndk" -type f \
  -path '*/toolchains/llvm/prebuilt/*/bin/llvm-nm' -print | sort | tail -1)
[ -x "$NDK_NM" ] || fail 'Android NDK llvm-nm was not found'
EXTRACT_ROOT=$PACKAGE_ROOT/aab
mkdir -p "$EXTRACT_ROOT"
for abi in arm64-v8a armeabi-v7a x86_64; do
  archive_path="base/lib/$abi/liblayergram_scka.so"
  [ "$(zipinfo -1 "$AAB" | grep -Fxc "$archive_path")" -eq 1 ] ||
    fail "Android App Bundle must contain exactly one SCKA library for $abi"
  unzip -oq "$AAB" "$archive_path" -d "$EXTRACT_ROOT"
  "$SCRIPT_DIR/verify_scka_export_contract.sh" dynamic "$NDK_NM" \
    "$EXTRACT_ROOT/$archive_path"
done

bundletool_version=$(java -cp "$BUNDLETOOL_CP" "$BUNDLETOOL_MAIN" version)
printf '%s\n' "Android App Bundle verified with bundletool $bundletool_version"
printf '%s\n' 'LAYERGRAM_SCKA_PACKAGED_ANDROID_BUNDLE_OK'
