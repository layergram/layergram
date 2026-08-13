# Post-quantum backend spikes

This directory records reproducible candidate decisions. It does not vendor,
download, or activate a cryptographic backend during normal application builds.

## Current candidate

`mlkem_native_candidate.json` records the exact upstream release and commit
tested on the development host. On 2026-08-13, upstream `make build` and
`make test` completed successfully on macOS ARM64, including the upstream KAT,
ACVP, Wycheproof, unit, allocation, RNG-failure, and ABI checks.

That result proves only that the pinned upstream candidate works in its own test
harness on one platform. It does not prove that a future Layergram FFI wrapper,
other ABIs, packaging, secret ownership, or the final protocol are correct.

The next backend work package must create a minimal Layergram-owned C ABI around
only ML-KEM-768, keep decapsulation keys behind opaque native handles, and run
the same vectors through the shipped wrapper on every supported platform.
