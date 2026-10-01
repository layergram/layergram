#!/bin/sh
# This optional product is built separately, never an implicit Runner dependency.
set -eu
keyboard_destination="${TARGET_BUILD_DIR}/${PLUGINS_FOLDER_PATH}/LayergramKeyboard.appex"
if [ "${LAYERGRAM_KEYBOARD_EMBED:-NO}" != YES ]; then
  # Prevent an incremental ordinary build retaining a prior experimental product.
  if [ -d "$keyboard_destination" ]; then rm -rf "$keyboard_destination"; fi
  exit 0
fi
# A separately built extension can live outside Xcode's archive products,
# which Xcode may recreate before running this phase.
keyboard_source="${LAYERGRAM_KEYBOARD_PRODUCT_PATH:-${BUILT_PRODUCTS_DIR}/LayergramKeyboard.appex}"
if [ ! -f "$keyboard_source/Info.plist" ]; then
  echo 'error: Build the LayergramKeyboard scheme before embedding the extension.' >&2
  exit 1
fi
mkdir -p "${TARGET_BUILD_DIR}/${PLUGINS_FOLDER_PATH}"
if [ -d "$keyboard_destination" ]; then rm -rf "$keyboard_destination"; fi
/usr/bin/ditto "$keyboard_source" "$keyboard_destination"
