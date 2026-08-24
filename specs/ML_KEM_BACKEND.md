# ML-KEM-768 native backend

Status: **active Android/Apple/Windows/Linux production packaging boundary**

Layergram protocol v3 uses a narrow C ABI around the pinned `mlkem-native`
v2.0.0 implementation. Android, iOS, macOS, Windows x64, and Linux x64 builds
package the production ABI. Layergram 2.0 loads it through the exact allowlisted
v3 lifecycle; the defensive default build remains fail-closed.

## Security boundary

- Only ML-KEM-768 is compiled.
- Upstream symbols have hidden visibility; the dynamic library exports only
  `lg_mlkem768_*` ABI functions.
- The 2,400-byte decapsulation key is allocated in native memory and is exposed
  to Dart only as an opaque handle.
- Manual close and `NativeFinalizer` both call the same native destructor. The
  destructor performs volatile-byte zeroization before `free`.
- Public keys receive the FIPS 203 modulus check before encapsulation.
- Private keys receive the FIPS 203 hash check after deterministic keygen and
  again inside upstream decapsulation.
- Decapsulation preserves FIPS 203 implicit rejection. Ciphertext validity is
  not returned to Dart.
- Production encapsulation obtains 32 fresh bytes directly from the operating
  system CSPRNG. Dart cannot inject encapsulation entropy.
- Deterministic encapsulation is exported only when `LG_MLKEM_TESTING` is set.
- The packaged Dart loader admits only the exact pinned implementation ID and
  ABI sizes, and rejects any production library exposing even a partial set of
  test-only symbols.
- Desktop packaged libraries are resolved from executable-owned absolute
  locations; the generic explicit-path loader remains available only for
  native engineering and known-answer tests.

The BIP39-derived 64-byte `d || z` key-generation seed necessarily crosses the
FFI boundary during identity restoration. Its native copy is wiped after the
call, but managed-memory zeroization remains best effort. The expanded private
key never crosses back into Dart.

## Native-wrapper verification

On macOS ARM64, `tool/pq/test_native_macos.sh` performs:

1. warning-as-error build of the test ABI;
2. native ABI, length, invalid-key, implicit-rejection, lifecycle, OS-CSPRNG,
   and zeroization-observation tests;
3. warning-as-error production build without deterministic/test symbols;
4. Dart FFI self-test and upstream known-answer-vector traversal;
5. production-library Dart traversal using native OS entropy.

The native test executable also passes AddressSanitizer and UndefinedBehavior
Sanitizer. Loading an ASan-instrumented library into the signed Flutter test
runner is blocked by macOS platform policy, so the sanitizer evidence covers
the native executable while the ordinary library covers the Dart FFI path.

On Ubuntu 22.04 x86_64, `tool/pq/test_native_linux.sh` performs the equivalent
warning-as-error native and Dart FFI traversal. Its optional
`LAYERGRAM_MLKEM_SANITIZE=1` mode passes AddressSanitizer and UndefinedBehavior
Sanitizer, and production encapsulation traverses the Linux `getrandom` branch.

## Packaged-platform verification

The production ABI is included without `LG_MLKEM_TESTING` and has
been checked as follows:

- Android debug and release APKs contain `liblayergram_mlkem.so` for
  `armeabi-v7a`, `arm64-v8a`, and `x86_64`. Each library exports only the 14
  `lg_mlkem768_*` production functions. The packaged round trip and self-test
  pass in an Android 14 arm64 emulator.
- The iOS simulator debug app is universal `arm64`/`x86_64`; its effective
  executable exports the same 14 production functions and no test hooks. The
  packaged round trip and self-test pass in an arm64 iOS simulator.
- The unsigned iOS device release build is arm64, retains the 14 production
  functions after dead stripping, excludes test hooks, and links the Security
  framework. Physical-device execution has also passed on the supported iPhone
  test scope; distribution signing remains part of the official store pipeline.
- The embedded macOS `LayergramMlKem.framework` is universal
  `arm64`/`x86_64`, exports only the 14 production functions, and is loaded by
  an absolute path derived from the application bundle. The packaged round
  trip and self-test pass in an unsigned Flutter app build.
- The Windows release bundle contains an x64 `layergram_mlkem.dll` linked to
  BCrypt and exporting exactly the 14 production functions. The loader derives
  its absolute path from the running executable rather than using the ambient
  DLL search order. On Windows 11 ARM64 under Parallels, Windows' x64 execution
  layer passes the packaged Flutter integration traversal, a release-process
  smoke test, and the native ABI, negative, implicit-rejection, CSPRNG,
  lifecycle, and zeroization tests. The generated Store-mode MSIX also contains
  the production DLL.
- The Linux release bundle contains an x86-64 `liblayergram_mlkem.so` linked to
  glibc and exporting exactly the 14 versioned production functions. On Ubuntu
  22.04, the packaged Flutter integration traversal and a release-process smoke
  test pass under a virtual X display. The library is loaded from the bundle's
  `lib` directory using an absolute path derived from the app executable and is
  linked with full RELRO and immediate binding.

Official signed distribution remains a per-release pipeline responsibility;
local unsigned packages are used only for deterministic engineering traversal.

`integration_test/ml_kem_768_packaging_test.dart` is the common device,
simulator, and desktop FFI traversal. `tool/pq/mlkem_packaged_process_smoke.dart`
provides a minimal app/process smoke test for macOS, Windows, and Linux
packaging.

The common packaged traversal also restores one public test identity from a
24-word BIP39 vector, checks the X25519 public key, ML-KEM public-key digest,
complete identity ID and fingerprint, then reimports the canonical bundle
through the native ML-KEM public-key validator. The vector is byte-identical on
macOS arm64, Android 14 arm64, iOS arm64 simulator, Linux x64, and Windows x64.
This establishes deterministic identity assembly across the tested ABIs; it is
not evidence for the future handshake or ratchet.

## Commercial distribution and dependency gate

The open-source Layergram repository is the shared protocol and security base
for optional downstream capability distributions. Every dependency added to
this base or to a future native SCKA backend therefore requires an exact
versioned license review before adoption. The recorded terms must permit:

- commercial use and paid distribution;
- distribution through desktop and mobile application stores;
- linking, embedding, and combination with a commercial downstream binary
  without forcing disclosure of unrelated downstream source code;
- preservation of the public Layergram source under its existing license; and
- production redistribution of every transitive runtime artifact.

The review must record the exact source/version, SPDX expression, transitive
runtime dependencies, binary redistribution obligations, attribution, NOTICE,
and source-offer duties. Non-commercial, field-of-use, unknown, or custom terms,
and copyleft terms whose distribution obligations conflict with the downstream
distribution model, fail this engineering gate unless a specific legal review approves the
exact use. Required license and notice material must ship with every affected
artifact. This is a release-engineering rule, not legal advice.

The currently vendored `mlkem-native` v2.0.0 library sources are offered by
upstream under Apache-2.0 OR ISC OR MIT; Layergram records Apache-2.0 as its
selected choice in `third_party/mlkem-native/SOURCE.json` and
`README.layergram.md`. This checkpoint adds no new package or native dependency.
The SCKA implementation path is now selected in `SCKA_BACKEND.md`: the
AGPL-only Signal reference implementation is excluded, while an independent
Layergram-owned Apache-2.0 implementation from the public-domain specification
is the approved direction. `libcrux-ml-kem` 0.0.10 is the pinned permissively
licensed incremental primitive inside the Layergram-owned SCKA implementation.
Exact transitive license review and packaging verification remain mandatory for
every release.

## Continuous release requirements

- Package and test the backend on Linux ARM64 and native Windows ARM64 if
  Layergram distributes those targets.
- Repeat full wrapper KAT, ACVP, Wycheproof, negative, sanitizer, lifecycle,
  physical-device, release-signing, and packaging tests for every shipped ABI.
- Verify iOS background/extension and Android process-lifecycle behavior on
  physical devices.
- Complete Apple distribution signing/notarization and Android store-signing
  validation.
- Maintain the supply-chain inventory and seek independent implementation
  review as a priority post-release objective.
- Re-approve the exact native SCKA dependency and its full transitive license
  inventory for both public and commercial downstream distribution.
- Keep the authenticated hybrid handshake and sparse PQ ratchet specifications
  synchronized with the implementation.

Only official packages containing the exact allowlisted backend satisfy the
Layergram 2.0 post-quantum claim. Any missing artifact or failed gate blocks the
affected release.
