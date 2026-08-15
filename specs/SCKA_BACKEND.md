# ML-KEM Braid / SCKA backend decision

Status: **inactive ABI; outer state envelope and canonical inner payload
implemented; erasure representation and incremental primitive boundary frozen;
no transition engine or production backend; protocol v3 inactive**

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
SCKA operation. It also supplies a separately derived state-sealing key and the
exact expected TR3 revision, then rejects a candidate unless its authenticated
state reports the immediately next revision. Those checks reject malformed
metadata, wrong keys, stale/rolled-back revisions, and a failed backend; the
future provider registration must separately allowlist the exact approved
implementation ID. None of these controls replaces cryptographic review.

The Layergram-owned Rust crate under `native/layergram_scka` now freezes the
minimal ABI and outer authenticated state envelope described in
`SCKA_NATIVE_ABI.md`. It is not linked into any app. Its self-test and every
correctly shaped state operation return `NOT_READY`, so the scaffold cannot
satisfy the Dart admission gate or activate protocol v3.

The same crate now contains a Layergram-owned, dependency-free systematic
Reed-Solomon encoder/decoder for the exact revision-1 public payload classes.
`SCKA_ERASURE_CODE.md` freezes its GF(2^16) field, generator matrix, 34-byte
chunk representation, duplicate policy, and resource limits. The module is not
connected to the C ABI or state machine, so this progress does not change the
backend's inactive status.

The exact incremental ML-KEM candidate is now adopted only behind the internal,
non-ABI wrapper frozen in `SCKA_INCREMENTAL_MLKEM.md`. The wrapper enforces
exact lengths and complete `pk1 + pk2` validation before the second
encapsulation step, and binds the opaque continuation state to its exact
part-one public-key header. Its transient `Encaps1` result exposes the shared
secret once, as required by revision-1 transition 7, then consumption into the
pending completion owner drops that raw secret. Its FIPS output matches the
separately implemented `mlkem-native` known-answer vector. It remains unused by
every exported SCKA operation; self-test and all shaped state operations still
return `NOT_READY`.

The same inactive crate now implements the frozen outer `LS3` AES-256-GCM
container behind an internal module. It validates exact header fields, lengths,
role/session/revision bindings, signed-63 counters, AAD, ciphertext, and tag,
and returns decrypted bytes only through a zeroizing owner. The caller must
supply a fresh OS-generated nonce; the module does not generate randomness and
is not connected to any C ABI operation. The disconnected canonical plaintext
payload is now frozen separately in `SCKA_STATE_PAYLOAD.md`.

The `LB3` codec represents all 11 revision-1 states, duplicates and
cross-checks the authenticated `LS3` role/session/revision/epoch metadata,
validates sender/receiver parity and ML-KEM key relationships, bounds canonical
encoder/decoder progress, and zeroizes its owned plaintext. It does not yet
implement any state transition, KDF, MAC, entropy call, or public-message codec,
and it has no C ABI callsite.

## Incremental ML-KEM primitive, inactive internal adoption

The primitive selected for internal prototyping is
`libcrux-ml-kem` 0.0.10 with default features disabled and only
`incremental,mlkem768` enabled. The crate declares Apache-2.0 and has crates.io
checksum
`1d8160f7d64fd2716b4fd05cc886a042f8dcda18d9206c0d506e2c67bdf97daa`.

A clean Cargo resolution and selected-feature dependency tree on 2026-08-15
showed only Apache-2.0, MIT, and Unicode-3.0 choices in the applicable build and
runtime graph. No GPL, AGPL, LGPL, non-commercial, or field-of-use term appeared
in that selected feature graph. The exact observed package list is recorded in
the machine receipt.

An isolated Rust 1.87.0 probe also compiled and executed the exact serialized
incremental ML-KEM-768 flow with these features. It confirmed the expected
sizes: 64-byte `pk1`, 1,152-byte public-key vector, 960-byte `ct1`, 128-byte
`ct2`, 2,080-byte encapsulation state, and matching 32-byte shared secrets.
Upstream explicitly labels this incremental API non-standard and warns that
misuse may be insecure. The successful probe therefore establishes API and
toolchain feasibility only; it is not production approval or cryptographic
validation.

The dependency is pinned in the inactive native crate together with `zeroize`
1.8.1. `sha2` 0.10.9 is test-only. The exact applicable dependency graph and
notices are recorded in `native/layergram_scka/THIRD_PARTY_NOTICES.md` and the
machine-readable receipt. The crate is still not linked into an application
binary.

Before any packaged use, Layergram must regenerate and verify the resolved
target-specific graph for every release ABI and repeat the license/notice
review. Store distribution, commercial use, source/notice obligations, and the
proprietary Premium combination must all remain acceptable.

## Authenticated state-envelope primitive, inactive internal adoption

The `LS3` implementation pins `aes-gcm` 0.10.3 with default features disabled
and only `aes,zeroize` enabled. It also pins `aes` 0.8.4 with its `zeroize`
feature so the software and hardware-specific AES key schedules implement
best-effort cleanup on drop. Both crates offer an Apache-2.0 licensing path.

The applicable graph adds only Apache-2.0/MIT-compatible packages plus
`subtle` 2.6.1 under BSD-3-Clause. The exact BSD text is retained at
`native/layergram_scka/licenses/BSD-3-Clause-subtle.txt`; the package inventory
and checksums are recorded in `Cargo.lock`, the third-party notice, and the
machine receipt. These terms permit paid commercial distribution when their
notice requirements are preserved, but this remains an engineering review and
not legal advice.

The internal envelope API deliberately accepts a caller-supplied nonce rather
than adding an RNG dependency or silently choosing an entropy source. A future
ABI implementation must obtain a fresh nonce from the approved OS CSPRNG,
ensure one seal per candidate revision, and persist the exact sealed bytes.

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
