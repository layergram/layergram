# Post-quantum backend spikes

This directory records reproducible candidate decisions and platform
verification commands. The pinned source is vendored under
`third_party/mlkem-native`. Android, iOS, and macOS builds package the backend,
but normal application code never loads or activates it and protocol v2 remains
unchanged.

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

## Reproducible checks

Run the host-native wrapper, vector, production-ABI, and sanitizer checks:

```sh
tool/pq/test_native_macos.sh
make -C native/layergram_mlkem TESTING=1 SANITIZE=1 \
  BUILD_DIR="$PWD/.dart_tool/layergram_pq/macos-sanitized" test
```

Build the packaged Android and Apple artifacts:

```sh
flutter build apk --debug
flutter build apk --release
flutter build ios --simulator --debug
flutter build ios --release --no-codesign
flutter build macos --release
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

This is cross-platform packaging evidence, not production approval. The
backend still requires Windows/Linux packaging, physical-device and signed
distribution validation, equivalent validation on every shipped ABI, full
ACVP/Wycheproof traversal through the wrapper, supply-chain review, and an
independent audit. See `specs/ML_KEM_BACKEND.md`.
