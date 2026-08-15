# Post-quantum backend spikes

This directory records reproducible candidate decisions and platform
verification commands. The pinned source is vendored under
`third_party/mlkem-native`. Android, iOS, macOS, Windows x64, and Linux x64
builds package the backend, but normal application code never loads or
activates it and protocol v2 remains unchanged.

## Current candidate

`mlkem_native_candidate.json` records the exact upstream release and commit
tested on the development host. On 2026-08-13, upstream `make build` and
`make test` completed successfully on macOS ARM64, including the upstream KAT,
ACVP, Wycheproof, unit, allocation, RNG-failure, and ABI checks.

Layergram now also has a narrow C ABI and Dart FFI implementation. On macOS
ARM64, `test_native_macos.sh` traverses upstream known-answer vectors through
the actual wrapper, verifies opaque-handle lifecycle and zeroization, checks
implicit rejection and invalid inputs, and confirms that the production ABI
uses the OS CSPRNG while excluding deterministic test hooks.

`scka_native_candidate.json` records the separate ML-KEM Braid/SCKA backend
decision. The official Signal SPQR implementation is explicitly rejected for
embedding because it is AGPL-3.0-only; no code from it is imported. The receipt
selects a specification-first Layergram-owned Apache-2.0 implementation path.
The exact commercially compatible `libcrux-ml-kem` candidate is now pinned only
inside the inactive native crate; it is not linked into the application.

`native/layergram_scka` is an Apache-2.0 Rust scaffold with exact pinned
permissive dependencies and notices. It implements the outer `LS3` AES-256-GCM
envelope behind an internal module but deliberately returns `NOT_READY`; it is
not referenced by application packaging or Dart FFI. The crate also contains
disconnected Layergram-owned erasure-code and incremental-ML-KEM boundary
modules specified by `specs/SCKA_ERASURE_CODE.md` and
`specs/SCKA_INCREMENTAL_MLKEM.md`. Its disconnected `LB3` codec freezes the
canonical plaintext representation for all 11 revision-1 states as specified
by `specs/SCKA_STATE_PAYLOAD.md`. The private authenticator module freezes the
Layergram protocol domain, revision-1 KDFs, and HMAC behavior specified by
`specs/SCKA_AUTHENTICATOR.md`. The disconnected private `BM3` codec freezes all
seven logical public-message types, their internal Braid epoch, and exact
24/58-byte canonical encodings as specified by
`specs/SCKA_PUBLIC_MESSAGE.md`. The private initial transition slice implements
initialization, `KeysUnsampled.Send`, its operating-system entropy boundary,
the matching receive no-op, continued Header/`Ek`/`EkCt1Ack` symbols, and transitions 2-4 as specified by
`specs/SCKA_TRANSITION_ENGINE.md`; it remains disconnected from the ABI and
every application package.

## Reproducible checks

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

Run the inactive SCKA scaffold contract on POSIX hosts, all Apple compilation
targets, or Windows x64 respectively:

```sh
tool/pq/test_scka_scaffold_posix.sh
tool/pq/test_scka_scaffold_apple.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File `
  tool\pq\test_scka_scaffold_windows.ps1
```

The Apple check builds separate static libraries for iOS device ARM64 and iOS
simulator ARM64/x86_64. This is target-specific compilation evidence, not a
simulator runtime test, physical-device test, or packaged-app integration.

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

The common `ml_kem_768_packaging_test.dart` traversal also checks the complete
24-word v3 identity vector and the imported ML-KEM public-key validation
boundary. Run the same file on every shipped target; matching only the native
primitive KAT is not sufficient to establish cross-platform identity
derivation.

This is cross-platform packaging evidence, not production approval. The
backend still requires any Linux ARM64 or native Windows ARM64 build that is
actually distributed, physical-device and signed-distribution validation,
equivalent validation on every shipped ABI, full ACVP/Wycheproof traversal
through the wrapper, supply-chain review, and an independent audit. See
`specs/ML_KEM_BACKEND.md`.
