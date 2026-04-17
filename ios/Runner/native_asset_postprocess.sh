#!/bin/bash
set -euo pipefail

platform_name="${PLATFORM_NAME:-}"
expected_platform=""

case "$platform_name" in
  iphoneos)
    expected_platform="ios"
    ;;
  iphonesimulator)
    expected_platform="iossim"
    ;;
  xros|xrsimulator)
    # visionOS (Apple Vision Pro) - skip processing as it may not need these modifications
    exit 0
    ;;
  *)
    ;;
esac

if [[ -z "$expected_platform" ]]; then
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
primary_arch="${ARCHS%% *}"

if [[ -z "$primary_arch" ]]; then
  if [[ "$platform_name" == "iphonesimulator" ]]; then
    primary_arch="arm64"
  else
    primary_arch="arm64"
  fi
fi

if command -v lipo >/dev/null 2>&1; then
  arch_info="$(lipo -info "$binary_path" 2>/dev/null || true)"
  removable_arches=(i386 arm64e)
  if [[ "$platform_name" == "iphoneos" ]]; then
    removable_arches+=(x86_64)
  fi
  for arch in "${removable_arches[@]}"; do
    if [[ "$arch_info" == *"$arch"* ]]; then
      lipo -remove "$arch" "$binary_path" -output "$binary_path"
      needs_resign=true
    fi
  done
fi

if command -v xcrun >/dev/null 2>&1; then
  build_info="$(xcrun vtool -show-build -arch "$primary_arch" "$binary_path" 2>/dev/null || true)"
  if [[ -z "$build_info" && "$primary_arch" != "arm64" ]]; then
    primary_arch="arm64"
    build_info="$(xcrun vtool -show-build -arch "$primary_arch" "$binary_path" 2>/dev/null || true)"
  fi
  binary_minos="$(printf '%s\n' "$build_info" | awk '/minos / {print $2; exit}')"
  # Determine the exact platform keyword expected by vtool output.
  # Use awk to match the exact word to avoid 'IOS' matching 'IOSSIMULATOR'.
  if [[ "$expected_platform" == "iossim" ]]; then
    expected_platform_keyword="IOSSIMULATOR"
  else
    expected_platform_keyword="IOS"
  fi
  actual_platform_keyword="$(printf '%s\n' "$build_info" | awk '/platform / {print $2; exit}')"
  if [[ "$actual_platform_keyword" != "$expected_platform_keyword" ]]; then
    minos="$(printf '%s\n' "$build_info" | awk '/minos / {print $2; exit}')"
    sdk="$(printf '%s\n' "$build_info" | awk '/sdk / {print $2; exit}')"
    ld_version="$(printf '%s\n' "$build_info" | awk '$1 == "version" {print $2; exit}')"
    patched_binary_path="${binary_path}.patched"

    if [[ -z "$minos" || -z "$sdk" ]]; then
      exit 1
    fi

    if [[ -n "$ld_version" ]]; then
      xcrun vtool \
        -arch "$primary_arch" \
        -set-build-version "$expected_platform" "$minos" "$sdk" \
        -tool ld "$ld_version" \
        -replace \
        -output "$patched_binary_path" \
        "$binary_path"
    else
      xcrun vtool \
        -arch "$primary_arch" \
        -set-build-version "$expected_platform" "$minos" "$sdk" \
        -replace \
        -output "$patched_binary_path" \
        "$binary_path"
    fi

    mv "$patched_binary_path" "$binary_path"
    chmod +x "$binary_path"
    needs_resign=true

    updated_build_info="$(xcrun vtool -show-build -arch "$primary_arch" "$binary_path" 2>/dev/null || true)"
    binary_minos="$(printf '%s\n' "$updated_build_info" | awk '/minos / {print $2; exit}')"
    updated_platform_keyword="$(printf '%s\n' "$updated_build_info" | awk '/platform / {print $2; exit}')"
    if [[ "$updated_platform_keyword" != "$expected_platform_keyword" ]]; then
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
