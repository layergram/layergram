#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gitleaks_binary="$("${repository_root}/tool/security/install_gitleaks.sh")"
scan_mode="${1:-working-tree}"
cd "$repository_root"

common_arguments=(
  --config "${repository_root}/.gitleaks.toml"
  --redact=100
  --no-banner
  --no-color
)

case "$scan_mode" in
  staged)
    exec "$gitleaks_binary" git \
      "${common_arguments[@]}" \
      --pre-commit \
      --staged \
      .
    ;;
  history)
    exec "$gitleaks_binary" git \
      "${common_arguments[@]}" \
      .
    ;;
  working-tree)
    exec "$gitleaks_binary" dir \
      "${common_arguments[@]}" \
      .
    ;;
  *)
    printf 'Usage: %s [staged|history|working-tree]\n' "$0" >&2
    exit 64
    ;;
esac
