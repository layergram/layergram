# Post-quantum backend and release verification

Create a clean, commit-bound OSS source package for independent protocol and
implementation review (without including the downstream Premium repository):

```sh
tool/pq/create_v3_audit_bundle.sh
```

The archive and its SHA-256 file are written below the ignored
`.dart_tool/layergram_pq/audit/` directory. See
`specs/PROTOCOL_V3_AUDIT_PACKAGE.md` for the mandatory review scope and the
active-release boundary.

This directory records reproducible implementation decisions and platform
verification commands. The pinned source is vendored under
`third_party/mlkem-native`. Android, iOS, macOS, Windows x64, and Linux x64
builds package the backend. Layergram 2.0 loads it only through the complete
fail-closed activation policy; earlier releases remain protocol v2.

## Current production selection

`mlkem_native_candidate.json` records the exact upstream release and commit
tested on the development host. On 2026-08-22, upstream `make build` and
`make test` completed successfully on macOS ARM64, including the upstream KAT,
ACVP, Wycheproof, unit, allocation, RNG-failure, and ABI checks.

Layergram now also has a narrow C ABI and Dart FFI implementation. On macOS
ARM64, `test_native_macos.sh` traverses upstream known-answer vectors through
the actual wrapper, verifies opaque-handle lifecycle and zeroization, checks
implicit rejection and invalid inputs, and confirms that the production ABI
uses the OS CSPRNG while excluding deterministic test hooks. The opaque
private-key registry rejects forged, stale, and repeated handles before
dereference and serializes concurrent decapsulation and destruction.

`scka_native_candidate.json` records the separate ML-KEM Braid/SCKA backend
decision. The official Signal SPQR implementation is explicitly rejected for
embedding because it is AGPL-3.0-only; no code from it is imported. The receipt
selects a specification-first Layergram-owned Apache-2.0 implementation path.
The exact commercially compatible `libcrux-ml-kem` dependency is pinned only
inside the native crate. Official release scripts link it into generated,
ignored platform artifacts and the application admits only the exact build.

`native/layergram_scka` is an Apache-2.0 Rust backend with exact pinned
permissive dependencies and notices. Its default build deliberately returns
`NOT_READY`. An explicit exact-build-allowlisted `candidate-ffi` build exposes the
outer `LS3` AES-256-GCM-SIV composition through the frozen C ABI and an
exact-build-allowlisted Dart FFI loader. Reproducible opt-in packaging scripts
exercise the production build through a scope-owned loader, while the default
build remains disconnected. The crate also contains
Layergram-owned erasure-code and incremental-ML-KEM boundary modules specified
by `specs/SCKA_ERASURE_CODE.md` and `specs/SCKA_INCREMENTAL_MLKEM.md`. Its
internal transition engine uses both modules. Only the allowlisted build
connects them to the C ABI; production registration is owned by the v3
lifecycle. The internal
`LB3` codec freezes
the canonical plaintext representation for all 11 revision-1 states as
specified by `specs/SCKA_STATE_PAYLOAD.md`, and the transition engine persists
its candidates through that representation. The private authenticator module
freezes the Layergram protocol domain, revision-1 KDFs, and HMAC behavior
specified by `specs/SCKA_AUTHENTICATOR.md` and is used by authenticated private
state transitions. The private `BM3` codec freezes all seven logical
public-message types, their internal Braid epoch, and exact 24/58-byte canonical
encodings as specified by `specs/SCKA_PUBLIC_MESSAGE.md`; it is likewise used by
the private transition engine but excluded from the public ABI and application
packaging. The private initial transition slice implements
initialization, `KeysUnsampled.Send`, its operating-system entropy boundary,
the matching receive no-op, continued Header/`Ek`/`EkCt1Ack` symbols, no-data
output while receiving `Ct2` or an authenticated Header, transition-7 Ct1
sampling with a native epoch key, continued Ct1 output, transition-8
acknowledgement with incomplete public-key reconstruction, transition-9
public-key validation plus authenticated `Ct2Sampled` construction, and
transition-10 validated `EkReceivedCt1Sampled` construction with continued
persisted Ct1 output, and transition-11 `Ct1Acknowledged` completion with
full-key validation, deterministic `Encaps2`, and exact ciphertext
authentication, and transitions 2-13 as specified by
`specs/SCKA_TRANSITION_ENGINE.md`, including transition-12 completion from the
validated `EkReceivedCt1Sampled` state after a delayed or lost Ct1 carrier
export. Transition 13 now continues exact authenticated Ct2 symbols across
loss/restart and switches roles only on the immediately following authenticated
Braid epoch. All revision-1 transitions 1-13 are implemented privately. The
explicit candidate build connects them to the frozen C ABI for integration
tests and official application packages, while the default ABI remains
disconnected.
The private composition specified by
`specs/SCKA_AUTHENTICATED_COMPOSITION.md` now opens and semantically validates
exact LS3/LB3 state, dispatches canonical BM3, checks revision-plus-one
successors, derives injective role-and-revision state nonces, uses RFC 8452
nonce-misuse-resistant state sealing, and returns immutable exact sealed
candidates. The allowlisted implementation is callable through an explicit
library path or deterministic generated package location from Dart and is
exercised with the durable session journals, TR3, LMF, and the encrypted Aux
store. The packaged smoke and official lifecycle construct it through
`V3SessionPersistenceScope.openPackagedScka`; the default ABI remains
`NOT_READY` so unsupported builds fail closed.

## Reproducible checks

### Static identity QR physical and print gate

The physical camera harness displays the maximum 1,270-byte canonical v3
identity and scans any complete canonical v3 identity. It uses the same QR
renderer and native scanner dependency as the app, continues automatically
after an incomplete/non-canonical read, and emits a byte-counted
`LAYERGRAM_QR_CAMERA_PASS` line only after canonical decoding succeeds. Its
display mode also exercises the temporary brightness floor; scan mode restores
the prior window value.

Build and install the isolated Android harness without replacing the normal app:

```sh
ORG_GRADLE_PROJECT_layergramSckaPhysicalSmoke=true \
  flutter build apk --debug -t tool/pq/identity_qr_camera_harness.dart

adb -s <serial> install -r -d build/app/outputs/flutter-apk/app-debug.apk
adb -s <serial> shell am force-stop app.layergram.sckasmoke
adb -s <serial> shell monkey -p app.layergram.sckasmoke \
  -c android.intent.category.LAUNCHER 1
```

Confirm the APK manifest says `app.layergram.sckasmoke` before installing it.
Use **Mostra QR** for Android-display-to-iPhone-camera tests. Use **Scansiona**
for iPhone-display-to-Android-camera tests: open a complete v3 identity in the
iOS candidate app and scan it with the harness. Test the normal preview and the
enlarged preview separately. A successful screen test requires the complete
expected byte length and no `LAYERGRAM_QR_CAMERA_RETRY` result left as the final
state. Record device models, OS versions, payload length, elapsed time,
lighting, orientation, and whether either phone had to be tilted.

On Android, the display-mode window must report `sbrt=0.6` when the system
brightness is below 60%; scan mode must have no window brightness override, and
the global system setting must remain unchanged. The equivalent iOS check uses
the candidate app: opening the enlarged QR raises the app display to at least
60%, and closing/backgrounding it restores the previous brightness. The QR
itself remains version 30, ECC M, with a four-module quiet zone and a 20% logo;
brightness presentation must never change those encoding parameters.

Create the one-page A4 print gate from the real 1,024-pixel app export:

```sh
flutter run -d macos -t tool/pq/export_qr_print_test_png.dart
# Copy the `created=...` file reported by the sandboxed runner:
mkdir -p tmp/pdfs output/pdf
cp <created-path> tmp/pdfs/layergram-v3-max-identity-export-1024.png
python3 -m pip install --disable-pip-version-check --no-input \
  --target tmp/pdfs/python-deps -r tool/pq/requirements-print.txt
PYTHONPATH=tmp/pdfs/python-deps \
  python3 tool/pq/create_qr_print_test_pdf.py
```

The PDF places the same PNG at 50, 45, 40, 35, 30, and 25 mm on one A4 page;
the 50 mm example is inside an 85.60 x 53.98 mm card outline. Print at 100%
with page fitting disabled, measure the 50 x 10 mm calibration rectangle, and
scan every numbered size three times with representative iPhone and Android
devices. The supported minimum is the smallest size read immediately and
without error by both physical devices, not the smallest size decoded from a
digital 300-DPI render. The QR payload is synthetic and must not be added as a
real contact.

The 2026-08-24 release print measured the nominal 50 mm sample at 48 mm, so the
page was scaled to approximately 96%. The Huawei SNE-LX1 decoded nominal sizes
from 30 mm upward (about 28.8 mm measured); the iPhone 14 Pro Max also decoded
the nominal 25 mm sample (about 24 mm measured). The published recommendation
therefore remains a conservative **35 mm measured side or larger**, including
the complete quiet zone, rather than treating the smallest successful sample as
a universal promise.

The print-only Python packages are permissively licensed and are not linked,
packaged, or distributed with Layergram.

Regenerate and compare the independent revision-1 conformance vector with the
Python 3 standard-library oracle:

```sh
python3 tool/pq/generate_scka_cross_implementation_vector.py \
  --check native/layergram_scka/testdata/braid_r1_cross_impl_vector.txt
cargo test --manifest-path native/layergram_scka/Cargo.toml \
  full_epoch_matches_independent_public_domain_cross_implementation_vector
cargo test --manifest-path native/layergram_scka/Cargo.toml \
  independent_lb3_bm3_and_continuation_binding_vectors_are_frozen
```

The oracle uses only the public-domain specification and the already vendored,
permissively licensed `mlkem-native` ML-KEM-768 KAT. It does not import or run
the production Rust module or Signal's AGPL implementation. The Rust test
compares a complete two-party epoch at all 174 transcript records. Vector
format v3 also uses an independent Python GF(2^16) receive decoder to recover
Header, public-key vector, Ct1, and `Ct2 || MAC` from reordered mixtures of
systematic and parity symbols. It verifies header MAC, public-key binding, and
ciphertext MAC after recovery, including negative tag checks. Rust recreates
the same mixed chunk-set digests and authenticates the recovered bytes. Format
v3 also constructs all 11 canonical `LB3` variants and all seven canonical
`BM3` types in Python. Rust compares their independent digests or exact bytes,
decodes them, and checks that the opaque 2,080-byte continuation remains tied
to LB3 payload format 1 and `libcrux-ml-kem = 0.0.10`. This strengthens the
independent-vector checkpoint but does not complete the external independent
review, activate, or register v3.

Run the host-native wrapper, vector, production-ABI, and sanitizer checks:

```sh
tool/pq/test_native_macos.sh
make -C native/layergram_mlkem TESTING=1 SANITIZE=1 \
  BUILD_DIR="$PWD/.dart_tool/layergram_pq/macos-sanitized" test
tool/pq/test_native_linux.sh
LAYERGRAM_MLKEM_SANITIZE=1 \
  LAYERGRAM_MLKEM_LINUX_BUILD_DIR="$PWD/.dart_tool/layergram_pq/linux-sanitized" \
  tool/pq/test_native_linux.sh
```

Run the SCKA default/production contract on POSIX hosts, all Apple compilation
targets, or Windows x64 respectively:

```sh
tool/pq/test_scka_scaffold_posix.sh
tool/pq/test_scka_scaffold_apple.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File `
  tool\pq\test_scka_scaffold_windows.ps1
```

Run the explicit-path candidate bridge on macOS/Linux or Windows respectively:

```sh
tool/pq/test_scka_candidate_ffi.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File `
  tool\pq\test_scka_candidate_ffi_windows.ps1
```

The Windows candidate check selects the Rust release target from the actual
Dart runtime architecture. This matters on Windows 11 ARM, where the current
Flutter/Dart toolchain may run as x64 under emulation and cannot load an ARM64
DLL into that process.

Run the opt-in packaged-scope candidate checks with generated artifacts:

```sh
tool/pq/test_scka_packaged_apple.sh
tool/pq/test_scka_packaged_ios.sh
tool/pq/test_scka_packaged_android.sh
tool/pq/test_scka_packaged_linux.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File `
  tool\pq\test_scka_packaged_windows.ps1
```

`test_scka_packaged_apple.sh` creates an XCFramework and a macOS scope smoke.
Set `LAYERGRAM_SCKA_MACOS_SIGN_IDENTITY` to a local signing identity to verify
the generated macOS app with hardened runtime. This is not archive,
notarization, or store-distribution evidence. The iOS script executes the x64
simulator smoke when a compatible simulator is booted and also compiles the
device ARM64 candidate without signing. A separate opt-in physical-iOS gate
builds a development-signed Release runner, verifies the exact ABI, executes
the packaged scope on a paired device, and removes the test app:

```sh
LAYERGRAM_SCKA_IOS_PHYSICAL_DEVICE_ID=<device-udid> \
  tool/pq/test_scka_packaged_ios_physical.sh
```

The physical script fails before building if `app.layergram.app` is already
installed, so it cannot replace a real Layergram installation or its data. It
requires an unlocked signing keychain and an existing development profile that
contains the selected device. Its development signature is device-runtime
evidence, not App Store distribution approval. The corresponding Android gate
builds a Release APK with a dedicated `app.layergram.sckasmoke` identifier,
verifies its signature and exact native exports, executes it on an authorized
non-emulator device, and removes it after the result:

```sh
LAYERGRAM_SCKA_ANDROID_PHYSICAL_DEVICE_ID=<adb-serial> \
  tool/pq/test_scka_packaged_android_physical.sh
```

It never installs, uninstalls, or clears `app.layergram`; local APK signing is
physical-runtime evidence, not Play Store signing approval. Linux retains
RELRO/BIND_NOW; Windows uses an executable-relative absolute DLL path. All generated native
artifacts live below ignored `.dart_tool` or Flutter build directories and are
not committed. Android additionally requires the explicit
`layergramSckaCandidatePackage` Gradle property set by its verification script,
so stale generated libraries cannot enter a later ordinary build.

The separate App Bundle gate exercises the Play Store-shaped `.aab` container
without uploading or publishing it:

```sh
tool/pq/test_scka_packaged_android_bundle.sh
```

It builds only the isolated `app.layergram.sckasmoke` application, validates
the bundle with the bundletool already resolved by the Android Gradle Plugin,
verifies the local JAR signature, reads the protobuf manifest, and checks the
exact SCKA export allowlist for all three Android ABIs. This is local bundle
structure evidence, not Play App Signing or store review evidence.

The Apple check builds separate static libraries for iOS device ARM64 and iOS
simulator ARM64/x86_64. This is target-specific compilation evidence, not a
simulator runtime test or App Store distribution evidence.

Build the packaged Android, Apple, and Windows artifacts on their respective
hosts:

```sh
flutter build apk --debug
flutter build apk --release
flutter build ios --simulator --debug
flutter build ios --release --no-codesign
flutter build macos --release
flutter build windows --release
flutter build linux --release
```

On macOS, verify all three Android ABIs, both iOS simulator architectures, the
iOS arm64 release binary, the universal macOS framework, and their exact
production export surfaces after the builds:

```sh
tool/pq/verify_packaged_artifacts_macos.sh
```

The ordinary macOS command requires a working local signing identity. For a
deterministic packaging-only build when diagnosing local keychain failures:

```sh
flutter build macos --release --config-only -t lib/main.dart
xcodebuild -quiet -workspace macos/Runner.xcworkspace -scheme Runner \
  -configuration Release -derivedDataPath build/macos/UnsignedDerivedData \
  CODE_SIGNING_ALLOWED=NO build
```

This unsigned build does not count as distribution-signing evidence.

Run the common packaged-library traversal on a booted Android or iOS target:

```sh
flutter test integration_test/ml_kem_768_packaging_test.dart \
  -d DEVICE_ID -r expanded
```

For a physical iOS device connected wirelessly, use the integration driver so
Flutter can publish the VM service port over mDNS:

```sh
flutter drive \
  --driver=test_driver/integration_test.dart \
  --target=integration_test/ml_kem_768_packaging_test.dart \
  -d DEVICE_ID --publish-port
```

For the macOS embedded framework, the unit/integration traversal accepts its
absolute binary path:

```sh
LAYERGRAM_MLKEM_PACKAGED_MACOS_LIBRARY=\
build/macos/UnsignedDerivedData/Build/Products/Release/\
Layergram.app/Contents/Frameworks/\
LayergramMlKem.framework/Versions/A/LayergramMlKem \
flutter test test/core/crypto/v3/ml_kem_768_ffi_integration_test.dart
```

`mlkem_packaged_process_smoke.dart` is also a minimal Flutter entry point for
an unsigned macOS app packaging smoke test:

```sh
flutter build macos --debug --config-only \
  -t tool/pq/mlkem_packaged_process_smoke.dart
xcodebuild -quiet -workspace macos/Runner.xcworkspace -scheme Runner \
  -configuration Debug \
  -derivedDataPath build/macos/PackagedSmokeDerivedData \
  CODE_SIGNING_ALLOWED=NO build
build/macos/PackagedSmokeDerivedData/Build/Products/Debug/\
Layergram.app/Contents/MacOS/Layergram
```

Its success marker is `LAYERGRAM_MLKEM_PACKAGED_SMOKE_OK`. Run the release
`--config-only -t lib/main.dart` command again before a subsequent normal Xcode
build so the generated ephemeral configuration targets the application.

On Windows, run the native warning-as-error ABI suite, verify the x64 PE export
table, and traverse the packaged DLL inside a real Flutter integration-test
process:

```powershell
powershell -ExecutionPolicy Bypass -File tool\pq\test_native_windows.ps1
flutter build windows --release
powershell -ExecutionPolicy Bypass -File tool\pq\verify_packaged_windows.ps1
flutter test integration_test\ml_kem_768_packaging_test.dart `
  -d windows -r expanded
flutter build windows --release `
  -t tool\pq\mlkem_packaged_process_smoke.dart
build\windows\x64\runner\Release\layergram.exe
flutter build windows --release -t lib\main.dart
dart run msix:create
powershell -ExecutionPolicy Bypass -File tool\pq\verify_packaged_windows.ps1
```

The PowerShell invocations use a process-scoped execution-policy override;
they do not change the machine or user execution policy. The expected smoke
marker is `LAYERGRAM_MLKEM_PACKAGED_SMOKE_OK`, and the artifact verifier emits
`LAYERGRAM_MLKEM_PACKAGED_WINDOWS_OK`. If `layergram.msix` exists, the verifier
also requires that it contain the production DLL.

On Linux x64, build and inspect the release bundle, traverse the production ABI
inside a Flutter desktop integration-test process, and run the release-process
smoke entry point under a display server (or `xvfb-run` on a headless host):

```sh
tool/pq/test_native_linux.sh
flutter build linux --release -t lib/main.dart
tool/pq/verify_packaged_linux.sh
xvfb-run -a flutter test \
  integration_test/ml_kem_768_packaging_test.dart -d linux -r expanded
flutter build linux --release \
  -t tool/pq/mlkem_packaged_process_smoke.dart
xvfb-run -a build/linux/x64/release/bundle/layergram
flutter build linux --release -t lib/main.dart
tool/pq/verify_packaged_linux.sh
```

The expected artifact marker is `LAYERGRAM_MLKEM_PACKAGED_LINUX_OK`; the
process marker remains `LAYERGRAM_MLKEM_PACKAGED_SMOKE_OK`.

## SCKA native hostile corpus and AddressSanitizer

The Rust ABI has a dependency-free deterministic hostile-input corpus covering
authenticated-state mutations, bounded random state/message shapes, output
scrubbing, guard bytes, pointer overlap, and scalar alignment. Run that corpus
together with the complete candidate suite under AddressSanitizer with:

```sh
rustup toolchain install nightly-2026-08-16 --profile minimal
tool/pq/test_scka_hardening.sh
```

The same corpus now includes a fixed-schedule stateful campaign across four
concurrent independent sessions. Each session performs 128 sends per endpoint,
persists and reopens exact sealed-state bytes between calls, rejects a stale
state against the current revision, and exercises bounded carrier loss,
delayed/out-of-order delivery, duplicate replay, monotonic epoch high-water
values, and cross-participant epoch-key agreement. At most nine messages per
direction are retained by the test schedule. The campaign uses only the
existing production crate graph and never enables the candidate in the app.
It passes natively on macOS arm64, Linux x64, and Windows x64 running under
Windows 11 ARM64; the macOS and Linux runs also execute under AddressSanitizer.

The pinned nightly is only a test instrument. It does not alter the crate's
Rust 1.87 production baseline, `Cargo.lock`, application packaging, or the
commercially usable dependency graph. Supported hosts are macOS arm64/x64 and
glibc Linux arm64/x64.

Run the separate locked coverage-guided fuzz package with:

```sh
LAYERGRAM_SCKA_FUZZ_SECONDS=60 tool/pq/test_scka_fuzz.sh
```

The runner pins `cargo-fuzz` 0.13.2 and `nightly-2026-08-16`, keeps its build,
corpus, and crash artifacts under ignored `.dart_tool` paths, and exercises
state validation, send, and receive through the candidate C ABI with
AddressSanitizer. Its separate dependencies are test-only, permissively
licensed, and recorded in `native/layergram_scka/fuzz/THIRD_PARTY_NOTICES.md`;
they never enter the production crate lockfile or application packages. This
local checkpoint is bounded and repeatable.

`.github/workflows/scka-fuzz.yml` configures a daily Linux x64 campaign on the
official repository. It uses a read-only token, immutable commits for the
official GitHub Actions, a 600-second default per target, a 900-second manual
ceiling, a one-hour job limit, an evolving cache containing only fuzz corpus
inputs, and 30-day failure-reproducer retention. Pull requests and pushes do
not execute the workflow. A hosted green run has not yet been collected from
this branch, so recurring-run monitoring and failure triage remain release
tasks before production registration.

For the macOS packaged-scope smoke, `LAYERGRAM_SCKA_MACOS_SIGN_IDENTITY=-`
applies an ad-hoc signature without Hardened Runtime because an ad-hoc identity
has no Team ID. A real signing identity keeps Hardened Runtime enabled. The
ad-hoc path proves local code integrity only; release signing, nested-code Team
ID consistency, notarization, and store verification remain separate gates.

On Windows, set `LAYERGRAM_SCKA_WINDOWS_TARGET_DIR` to an NTFS-local directory
when the repository is exposed through a Parallels shared folder. Cargo's
temporary archive rename operations are not reliable on that shared filesystem;
the generated DLL is still copied into and verified from the Flutter bundle.

The common `ml_kem_768_packaging_test.dart` traversal also checks the complete
24-word v3 identity vector and the imported ML-KEM public-key validation
boundary. Run the same file on every shipped target; matching only the native
primitive KAT is not sufficient to establish cross-platform identity
derivation.

This is cross-platform packaging evidence, not production approval. The
backend still requires any Linux ARM64 or native Windows ARM64 build that is
actually distributed, physical-device and signed-distribution validation,
equivalent validation on every shipped ABI, full ACVP/Wycheproof traversal
through the wrapper, supply-chain review, and explicit release approval. See
`specs/ML_KEM_BACKEND.md`.
