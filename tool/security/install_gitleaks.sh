#!/usr/bin/env bash
set -euo pipefail

readonly LAYERGRAM_GITLEAKS_VERSION='8.30.1'
readonly LAYERGRAM_GITLEAKS_RELEASE_BASE="https://github.com/gitleaks/gitleaks/releases/download/v${LAYERGRAM_GITLEAKS_VERSION}"

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
install_root="${LAYERGRAM_GITLEAKS_INSTALL_DIR:-${repository_root}/.dart_tool/security/gitleaks/${LAYERGRAM_GITLEAKS_VERSION}}"
binary_path="${install_root}/gitleaks"

if [[ -x "$binary_path" ]] &&
    "$binary_path" version 2>/dev/null | grep -Fq "$LAYERGRAM_GITLEAKS_VERSION"; then
  printf '%s\n' "$binary_path"
  exit 0
fi

case "$(uname -s)" in
  Darwin) operating_system='darwin' ;;
  Linux) operating_system='linux' ;;
  *)
    printf 'Unsupported operating system for the Gitleaks bootstrap.\n' >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64|aarch64) architecture='arm64' ;;
  x86_64|amd64) architecture='x64' ;;
  *)
    printf 'Unsupported CPU architecture for the Gitleaks bootstrap.\n' >&2
    exit 1
    ;;
esac

archive_name="gitleaks_${LAYERGRAM_GITLEAKS_VERSION}_${operating_system}_${architecture}.tar.gz"
case "${operating_system}_${architecture}" in
  darwin_arm64)
    expected_sha256='b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'
    ;;
  darwin_x64)
    expected_sha256='dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'
    ;;
  linux_arm64)
    expected_sha256='e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'
    ;;
  linux_x64)
    expected_sha256='551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
    ;;
esac

download_root="$(mktemp -d "${TMPDIR:-/tmp}/layergram-gitleaks.XXXXXX")"
trap 'rm -r -- "$download_root"' EXIT
archive_path="${download_root}/${archive_name}"

curl --fail --location --silent --show-error \
  "${LAYERGRAM_GITLEAKS_RELEASE_BASE}/${archive_name}" \
  --output "$archive_path"

if command -v shasum >/dev/null 2>&1; then
  actual_sha256="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$archive_path" | awk '{print $1}')"
else
  printf 'A SHA-256 utility is required to verify Gitleaks.\n' >&2
  exit 1
fi

if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  printf 'Gitleaks archive checksum mismatch; refusing installation.\n' >&2
  exit 1
fi

tar -xzf "$archive_path" -C "$download_root" gitleaks
mkdir -p "$install_root"
install -m 0755 "${download_root}/gitleaks" "$binary_path"
printf '%s\n' "$binary_path"
