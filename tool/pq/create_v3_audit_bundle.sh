#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  fail 'Refusing to create a Layergram v3 audit bundle from a dirty tree'
fi

commit="$(git rev-parse --verify HEAD)"
tree="$(git rev-parse --verify HEAD^{tree})"
short_commit="${commit:0:12}"
output_dir="${LAYERGRAM_V3_AUDIT_OUTPUT_DIR:-$repo_root/.dart_tool/layergram_pq/audit}"
bundle_name="layergram-v3-oss-audit-$short_commit"
bundle_path="$output_dir/$bundle_name.tar.gz"
bundle_digest_path="$bundle_path.sha256"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/layergram-v3-audit.XXXXXX")"
snapshot_root="$temporary_root/$bundle_name"

cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup EXIT

for required in \
  LICENSE \
  SECURITY.md \
  THREAT_MODEL.md \
  pubspec.yaml \
  pubspec.lock \
  android/gradlew \
  android/gradlew.bat \
  android/gradle/wrapper/gradle-wrapper.jar \
  android/gradle/wrapper/gradle-wrapper.properties \
  android/gradle/verification-metadata.xml \
  android/app/gradle.lockfile \
  third_party/mlkem-native/LICENSE \
  native/layergram_scka/Cargo.toml \
  native/layergram_scka/Cargo.lock \
  native/layergram_scka/THIRD_PARTY_NOTICES.md \
  native/layergram_scka/fuzz/Cargo.toml \
  native/layergram_scka/fuzz/Cargo.lock \
  native/layergram_scka/fuzz/THIRD_PARTY_NOTICES.md \
  specs/PROTOCOL_V3_AUDIT_PACKAGE.md; do
  [[ -f "$required" ]] || fail "Missing required audit input: $required"
done

expected_gradle_wrapper_jar_sha256='7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172'
actual_gradle_wrapper_jar_sha256="$({
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum android/gradle/wrapper/gradle-wrapper.jar
  else
    shasum -a 256 android/gradle/wrapper/gradle-wrapper.jar
  fi
} | awk '{print $1}')"
[[ "$actual_gradle_wrapper_jar_sha256" == "$expected_gradle_wrapper_jar_sha256" ]] ||
  fail 'Android Gradle wrapper JAR does not match the official Gradle 8.14 checksum'
grep -Fxq \
  'distributionSha256Sum=efe9a3d147d948d7528a9887fa35abcf24ca1a43ad06439996490f77569b02d1' \
  android/gradle/wrapper/gradle-wrapper.properties ||
  fail 'Android Gradle 8.14 distribution checksum is missing or changed'
grep -q '<verification-metadata ' android/gradle/verification-metadata.xml ||
  fail 'Android strict dependency-verification metadata is empty'
grep -q '^empty=' android/app/gradle.lockfile ||
  fail 'Android application dependency lock state is incomplete'

if git ls-files 'specs/private/**' | grep -q .; then
  fail 'Private specifications must not be tracked in the OSS audit snapshot'
fi

grep -Eq 'identitySharing[[:space:]]*=[[:space:]]*true' \
  lib/core/crypto/v3/protocol_v3_activation.dart ||
  fail 'Protocol v3 identity sharing is not active'
grep -Eq 'messaging[[:space:]]*=[[:space:]]*true' \
  lib/core/crypto/v3/protocol_v3_activation.dart ||
  fail 'Protocol v3 messaging is not active'
grep -Eq 'productionApproved[[:space:]]*=[[:space:]]*true' \
  lib/core/crypto/v3/protocol_v3_activation.dart ||
  fail 'Protocol v3 production approval is not active'

python3 - <<'PY'
import json
from pathlib import Path

receipt = json.loads(Path('tool/pq/scka_native_candidate.json').read_text())
if receipt.get('selectedImplementationPath', {}).get('productionRegistered') is not True:
    raise SystemExit('SCKA production registration is not true')
if receipt.get('checkpointEffects', {}).get('protocolV3Activated') is not True:
    raise SystemExit('Protocol v3 receipt activation is not true')
if not receipt.get('continuousReleaseRequirements'):
    raise SystemExit('Protocol v3 receipt has no continuous release requirements')
PY

mkdir -p "$snapshot_root" "$output_dir"
git archive --format=tar "$commit" | tar -xf - -C "$snapshot_root"

cat >"$snapshot_root/AUDIT_SNAPSHOT.txt" <<EOF
Layergram protocol v3 OSS audit snapshot
commit=$commit
tree=$tree
source_repository=layergram-public
premium_repository_included=false
protocol_v3_activated=true
scka_production_registered=true
generated_artifacts_included=false
local_credentials_included=false
review_instructions=specs/PROTOCOL_V3_AUDIT_PACKAGE.md
EOF

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

(
  cd "$snapshot_root"
  find . -type f \
    ! -name SOURCE_SHA256SUMS.txt \
    -print | LC_ALL=C sort | while IFS= read -r path; do
    printf '%s  %s\n' "$(hash_file "$path")" "${path#./}"
  done >SOURCE_SHA256SUMS.txt
)

COPYFILE_DISABLE=1 tar -czf "$bundle_path" -C "$temporary_root" "$bundle_name"
printf '%s  %s\n' "$(hash_file "$bundle_path")" "$(basename "$bundle_path")" \
  >"$bundle_digest_path"

printf 'LAYERGRAM_V3_AUDIT_BUNDLE_OK\n'
printf 'commit=%s\n' "$commit"
printf 'bundle=%s\n' "$bundle_path"
printf 'sha256=%s\n' "$(hash_file "$bundle_path")"
