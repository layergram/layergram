# ML-KEM-768 native backend

Status: **inactive first-platform implementation; not production approved**

Layergram protocol v3 uses a narrow C ABI around the pinned `mlkem-native`
v2.0.0 implementation. The current app remains on protocol v2 and does not
load or package this library in normal application builds.

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

The BIP39-derived 64-byte `d || z` key-generation seed necessarily crosses the
FFI boundary during identity restoration. Its native copy is wiped after the
call, but managed-memory zeroization remains best effort. The expanded private
key never crosses back into Dart.

## Current verification

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

## Remaining activation gates

- Integrate static/shared packaging into every supported Flutter target.
- Repeat wrapper KAT, ACVP, Wycheproof, negative, sanitizer, lifecycle, device,
  simulator, architecture, release-signing, and packaging tests for each ABI.
- Verify iOS background/extension and Android process-lifecycle behavior.
- Verify Windows and Linux CSPRNG and toolchain branches.
- Complete supply-chain inventory and independent implementation audit.
- Specify and review the authenticated hybrid handshake and sparse PQ ratchet.

Until all gates pass, the backend must not be described to users as active or
as making Layergram quantum-resistant.
