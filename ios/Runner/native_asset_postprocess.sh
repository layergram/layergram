#!/bin/bash
set -euo pipefail

if [[ "${PLATFORM_NAME:-}" != "iphoneos" ]]; then
  exit 0
fi

framework_dir="${TARGET_BUILD_DIR}/${WRAPPER_NAME}/Frameworks/objective_c.framework"
binary_path="${framework_dir}/objective_c"
info_plist_path="${framework_dir}/Info.plist"

if [[ ! -f "$binary_path" ]]; then
  exit 0
fi

needs_resign=false
binary_minos=""

if command -v lipo >/dev/null 2>&1; then
  arch_info="$(lipo -info "$binary_path" 2>/dev/null || true)"
  for arch in i386 x86_64 arm64e; do
    if [[ "$arch_info" == *"$arch"* ]]; then
      lipo -remove "$arch" "$binary_path" -output "$binary_path"
      needs_resign=true
    fi
  done
fi

if command -v xcrun >/dev/null 2>&1; then
  build_info="$(xcrun vtool -show-build -arch arm64 "$binary_path" 2>/dev/null || true)"
  binary_minos="$(printf '%s\n' "$build_info" | awk '/minos / {print $2; exit}')"
  if [[ "$build_info" == *"platform IOSSIMULATOR"* ]]; then
    minos="$(printf '%s\n' "$build_info" | awk '/minos / {print $2; exit}')"
    sdk="$(printf '%s\n' "$build_info" | awk '/sdk / {print $2; exit}')"
    ld_version="$(printf '%s\n' "$build_info" | awk '$1 == "version" {print $2; exit}')"
    patched_binary_path="${binary_path}.patched"

    if [[ -z "$minos" || -z "$sdk" ]]; then
      exit 1
    fi

    if [[ -n "$ld_version" ]]; then
      xcrun vtool \
        -arch arm64 \
        -set-build-version ios "$minos" "$sdk" \
        -tool ld "$ld_version" \
        -replace \
        -output "$patched_binary_path" \
        "$binary_path"
    else
      xcrun vtool \
        -arch arm64 \
        -set-build-version ios "$minos" "$sdk" \
        -replace \
        -output "$patched_binary_path" \
        "$binary_path"
    fi

    mv "$patched_binary_path" "$binary_path"
    chmod +x "$binary_path"
    needs_resign=true

    updated_build_info="$(xcrun vtool -show-build -arch arm64 "$binary_path" 2>/dev/null || true)"
    binary_minos="$(printf '%s\n' "$updated_build_info" | awk '/minos / {print $2; exit}')"
    if [[ "$updated_build_info" == *"platform IOSSIMULATOR"* ]]; then
      exit 1
    fi
  fi
fi

if [[ -f "$info_plist_path" && -n "$binary_minos" ]]; then
  plist_minos="$(/usr/libexec/PlistBuddy -c 'Print :MinimumOSVersion' "$info_plist_path" 2>/dev/null || true)"
  if [[ "$plist_minos" != "$binary_minos" ]]; then
    /usr/libexec/PlistBuddy -c "Set :MinimumOSVersion $binary_minos" "$info_plist_path"
    needs_resign=true
  fi
fi

if [[ "$needs_resign" == "true" && "${CODE_SIGNING_ALLOWED:-NO}" == "YES" ]]; then
  sign_identity="${EXPANDED_CODE_SIGN_IDENTITY:-}"
  if [[ -z "$sign_identity" ]]; then
    sign_identity="-"
  fi
  /usr/bin/codesign --force --sign "$sign_identity" --preserve-metadata=identifier,requirements,flags "$framework_dir"
fi

if [[ -n "${DWARF_DSYM_FOLDER_PATH:-}" ]]; then
  dsym_path="${DWARF_DSYM_FOLDER_PATH}/objective_c.framework.dSYM"
  rm -rf "$dsym_path"
  xcrun dsymutil "$binary_path" -o "$dsym_path"
fi
