#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository_root"

existing_hooks_path="$(git config --local --get core.hooksPath || true)"
if [[ -n "$existing_hooks_path" && "$existing_hooks_path" != '.githooks' ]]; then
  printf 'Refusing to replace existing core.hooksPath: %s\n' \
    "$existing_hooks_path" >&2
  exit 1
fi

git config --local core.hooksPath .githooks
printf 'Layergram Git hooks enabled from .githooks.\n'
