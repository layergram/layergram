#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
EXPECTED="$SCRIPT_DIR/scka_expected_symbols.txt"
SOURCE="$REPO_ROOT/native/layergram_scka/src/lib.rs"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/layergram-scka-exports.XXXXXX")
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

source_exports="$tmp_root/source.txt"
sed -n '/#\[no_mangle\]/{
  n
  s/.* fn \([A-Za-z0-9_]*\).*/\1/p
}' "$SOURCE" | sort -u >"$source_exports"
if grep -Eq '#\[(unsafe\()?export_name' "$SOURCE"; then
  fail 'Layergram SCKA source contains an unreviewed export_name attribute'
fi
cmp -s "$EXPECTED" "$source_exports" || {
  diff -u "$EXPECTED" "$source_exports" >&2 || true
  fail 'Layergram SCKA source export contract changed'
}

[ "$#" -eq 0 ] && exit 0
[ "$#" -eq 3 ] || fail 'Usage: verify_scka_export_contract.sh [dynamic|namespace] <nm> <library>'
mode=$1
nm_tool=$2
library=$3
[ -f "$library" ] || fail "Missing Layergram SCKA library: $library"

actual="$tmp_root/actual.txt"
case "$mode" in
  dynamic)
    "$nm_tool" -D --defined-only "$library" |
      awk '{ name = $NF; sub(/@@.*/, "", name); if (name != "") print name }' |
      sort -u >"$actual"
    ;;
  namespace)
    if [ "$nm_tool" = xcrun ]; then
      xcrun nm -gU "$library"
    else
      "$nm_tool" -gU "$library"
    fi |
      awk '{ name = $NF; sub(/^_/, "", name); if (name ~ /^lg_scka_/) print name }' |
      sort -u >"$actual"
    ;;
  *) fail "Unknown Layergram SCKA export verification mode: $mode" ;;
esac

cmp -s "$EXPECTED" "$actual" || {
  diff -u "$EXPECTED" "$actual" >&2 || true
  fail "Unexpected Layergram SCKA $mode export contract: $library"
}
