#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BUNDLE=${LAYERGRAM_LINUX_BUNDLE:-$REPO_ROOT/build/linux/x64/release/bundle}
LIBRARY="$BUNDLE/lib/liblayergram_mlkem.so"
EXECUTABLE="$BUNDLE/layergram"

[ -x "$EXECUTABLE" ] || {
  printf '%s\n' "Missing Linux executable: $EXECUTABLE" >&2
  exit 1
}
[ -f "$LIBRARY" ] || {
  printf '%s\n' "Missing packaged ML-KEM library: $LIBRARY" >&2
  exit 1
}

machine=$(readelf -h "$LIBRARY" | awk -F: '/Machine:/ {gsub(/^[[:space:]]+/, "", $2); print $2}')
[ "$machine" = 'Advanced Micro Devices X86-64' ] || {
  printf '%s\n' "Unexpected Linux library machine: $machine" >&2
  exit 1
}

TEMP_ROOT=${TMPDIR:-/tmp}
TEMP_DIR=$(mktemp -d "$TEMP_ROOT/layergram-pq-linux.XXXXXX")
cleanup() {
  case "$TEMP_DIR" in
    "$TEMP_ROOT"/layergram-pq-linux.*) rm -rf -- "$TEMP_DIR" ;;
    *) printf '%s\n' "Refusing to remove unexpected path: $TEMP_DIR" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' \
  lg_mlkem768_abi_version \
  lg_mlkem768_ciphertext_bytes \
  lg_mlkem768_decapsulate \
  lg_mlkem768_encaps_seed_bytes \
  lg_mlkem768_encapsulate \
  lg_mlkem768_implementation_id \
  lg_mlkem768_keygen_seed_bytes \
  lg_mlkem768_keypair_from_seed \
  lg_mlkem768_private_key_bytes \
  lg_mlkem768_private_key_destroy \
  lg_mlkem768_public_key_bytes \
  lg_mlkem768_self_test \
  lg_mlkem768_shared_secret_bytes \
  lg_mlkem768_validate_public_key >"$TEMP_DIR/expected.txt"

nm -D --defined-only "$LIBRARY" |
  awk '{ name = $NF; sub(/@@.*/, "", name); if (name ~ /^lg_mlkem768_/) print name }' |
  sort -u >"$TEMP_DIR/actual.txt"

if ! cmp -s "$TEMP_DIR/expected.txt" "$TEMP_DIR/actual.txt"; then
  printf '%s\n' 'Unexpected Linux ML-KEM export surface' >&2
  diff -u "$TEMP_DIR/expected.txt" "$TEMP_DIR/actual.txt" >&2 || true
  exit 1
fi

readelf -d "$LIBRARY" | grep -q 'BIND_NOW'
readelf -lW "$LIBRARY" | grep -q 'GNU_RELRO'
ldd "$LIBRARY" | grep -q 'libc.so.6'

printf '%s\n' 'LAYERGRAM_MLKEM_PACKAGED_LINUX_OK'
