# ML-KEM Braid / SCKA backend decision

Status: **inactive ABI scaffold frozen; no production backend; protocol v3 inactive**

Layergram needs an ML-KEM Braid revision-1 backend to provide the Sparse
Continuous Key Agreement input to its inactive Triple Ratchet. This component
belongs to the public Apache-2.0 protocol base, which is also merged into a
separately distributed paid Premium application. Commercial redistribution and
the public-to-Premium merge boundary are therefore mandatory selection gates.

This document records an engineering dependency decision, not legal advice.
The machine-readable receipt is `tool/pq/scka_native_candidate.json`.

## Primary protocol source

The normative design source is Signal's [ML-KEM Braid revision-1
specification](https://signal.org/docs/specifications/mlkembraid/), last updated
2025-09-26. Its IPR section places the document in the public domain. Layergram
targets that published protocol revision and must freeze independent
interoperability vectors before activation.

## Reference implementation decision

Signal's official `signalapp/sparsepostquantumratchet` release v1.5.3,
commit `fd320484dcec89004021e6fdc7481825f5f261fa`, declares
`AGPL-3.0-only` in both its root license and Cargo package metadata.

Layergram rejects that implementation for linking, embedding, adaptation, or
vendoring in this codebase. The paid proprietary Premium binary cannot rely on
an AGPL-only component under Layergram's current distribution model. This
decision may be revisited only if the relevant rights holder supplies a
separate compatible license and the exact use receives specific legal and
engineering approval.

No source from that implementation may be copied or used as implementation
material. Its repository was inspected only to establish identity, version,
declared license, and dependency posture.

## Selected implementation path

Layergram will build an independent Apache-2.0 implementation from the
public-domain specification. The backend remains native and must expose only a
narrow Layergram-owned ABI. The implementation must:

- implement ML-KEM Braid revision 1 exactly;
- keep mutable SCKA secrets out of ordinary Dart objects;
- return immutable candidate transitions and never mutate committed input;
- version and authenticate every opaque state export to the stable session ID
  and role;
- validate state semantics before and after every transition;
- produce at most 512 public payload bytes per Layergram SK3 message;
- pass immutable self-tests before initialization, send, or receive;
- export only the reviewed production ABI and no deterministic test hooks;
- remain unregistered until all activation gates pass.

The public Dart boundary now requires a canonical diagnostic implementation
ID, exact protocol revision `1`, and a successful backend self-test before each
SCKA operation. Those checks reject malformed metadata, stale revisions, and a
failed backend; the future provider registration must separately allowlist the
exact approved implementation ID. None of these controls replaces
cryptographic review.

The Layergram-owned Rust crate under `native/layergram_scka` now freezes the
minimal ABI and outer authenticated state envelope described in
`SCKA_NATIVE_ABI.md`. It has no dependency and is not linked into any app. Its
self-test and every correctly shaped state operation return `NOT_READY`, so the
scaffold cannot satisfy the Dart admission gate or activate protocol v3.

## Incremental ML-KEM primitive candidate

The only primitive selected for further prototyping is
`libcrux-ml-kem` 0.0.10 with default features disabled and only
`incremental,mlkem768` enabled. The crate declares Apache-2.0 and has crates.io
checksum
`1d8160f7d64fd2716b4fd05cc886a042f8dcda18d9206c0d506e2c67bdf97daa`.

A clean Cargo resolution and selected-feature dependency tree on 2026-08-15
showed only Apache-2.0, MIT, and Unicode-3.0 choices in the applicable build and
runtime graph. No GPL, AGPL, LGPL, non-commercial, or field-of-use term appeared
in that selected feature graph. The exact observed package list is recorded in
the machine receipt.

This is a candidate approval only. The dependency-free Layergram scaffold adds
no third-party Cargo package and is not linked into an application binary.
Before adopting the primitive, Layergram must update the pinned Cargo.lock,
store all required license and notice texts, verify the resolved target-specific
graph for every release ABI, and repeat the license review. Store distribution,
commercial use, source/notice obligations, and proprietary Premium combination
must all remain acceptable.

## Packaging direction

The future backend remains a Layergram-owned Rust static library behind the
frozen C ABI. Once implemented and approved, it will be embedded into the same
platform artifacts already used by the ML-KEM primitive wrapper:

- iOS: statically linked into the signed application process;
- macOS: signed embedded framework or static library with no loader search-path
  ambiguity;
- Android: one shared library for every shipped ABI;
- Windows: one DLL for every shipped architecture;
- Linux: one hardened shared library per shipped architecture.

Only exact absolute or platform loader paths may be used. Production exports
must be allowlisted and test hooks must be absent. The Rust toolchain, panic
policy, allocator behavior, symbol stripping, reproducibility, notices, and
store packaging are separate release gates.

The scaffold is currently compiled independently and is not referenced by
CocoaPods, Gradle, CMake, the Windows runner, or Flutter FFI.

## Remaining security gates

- derive and persist the separate state-sealing key, then bind its native state
  revision atomically to the exact outer TR3 revision;
- freeze the encrypted state-machine payload after the erasure-code and
  incremental ML-KEM representations have been independently reviewed;
- implement revision-1 state transitions independently from the specification;
- generate independent public vectors and compare with a separately executed
  conforming implementation without linking its code;
- verify erasure-code behavior, epoch uniqueness, output-key agreement,
  reordering, loss, duplication, and offline recovery;
- test state corruption, replay, crash windows, rollback, allocation limits,
  panic containment, wiping, and concurrent calls;
- pass native sanitizers, fuzzing, static analysis, platform packaging, and
  physical-device tests;
- obtain independent cryptographic and implementation review.

Until all gates pass, no provider may register this backend and Layergram must
not claim that protocol v3 or the released app is quantum-resistant.
