# Post-quantum backend spikes

This directory records reproducible candidate decisions and first-platform
verification commands. The pinned source is now vendored under
`third_party/mlkem-native`, but the backend is not packaged, loaded, or
activated during normal application builds.

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

This is first-platform implementation evidence, not production approval. The
backend still requires packaging and equivalent validation on every supported
ABI, full ACVP/Wycheproof traversal through the wrapper, supply-chain review,
and independent audit. See `specs/ML_KEM_BACKEND.md`.
