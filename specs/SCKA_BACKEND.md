# ML-KEM Braid / SCKA backend decision

Status: **engineering-only candidate ABI connected behind an explicit Cargo
feature and exact Dart build allowlist; default ABI `NOT_READY`, opt-in
generated candidate packages tested but no registered production backend,
protocol v3 inactive**

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

The inactive encrypted session scope additionally requires one backend at
open, admits it before touching storage, and pins that exact object across
checkpoint restore, initial-session handoff, durable send, and its owned
receive resolver. Low-level crypto tests may still construct unbound
controllers directly, but the scope intended for eventual application wiring
rejects a different per-call backend before transition or persistence. This
does not register the Rust scaffold or make its `NOT_READY` ABI callable.

The Layergram-owned Rust crate under `native/layergram_scka` freezes the minimal
ABI and authenticated composition described in `SCKA_NATIVE_ABI.md`. Its
default build returns `NOT_READY`. An explicit `candidate-ffi` build is usable
through `V3SckaCandidateFfiBackend`, which rejects any mismatch in
implementation ID, ABI, protocol, state format, or fixed size. Reproducible
opt-in scripts now package that exact candidate for Apple, Android, Linux, and
Windows verification. The application-facing smoke constructs it only through
`V3SessionPersistenceScope.openPackagedScka`; ordinary `lib/main.dart` does not
import or call the packaged loader. This engineering bridge does not activate
protocol v3.

The same crate now contains a Layergram-owned, dependency-free systematic
Reed-Solomon encoder/decoder for the exact revision-1 public payload classes.
`SCKA_ERASURE_CODE.md` freezes its GF(2^16) field, generator matrix, 34-byte
chunk representation, duplicate policy, and resource limits. The private
transition engine uses this module. The explicit `candidate-ffi` build connects
it to the frozen C ABI, while the default ABI and ordinary application
bootstrap remain disconnected, so opt-in candidate packaging does not change
the backend's inactive product status.

The exact incremental ML-KEM candidate is now adopted only behind the internal,
non-ABI wrapper frozen in `SCKA_INCREMENTAL_MLKEM.md`. The wrapper enforces
exact lengths and complete `pk1 + pk2` validation before the second
encapsulation step, and binds the opaque continuation state to its exact
part-one public-key header. Its transient `Encaps1` result exposes the shared
secret once, as required by revision-1 transition 7, then consumption into the
pending completion owner drops that raw secret. Its FIPS output matches the
separately implemented `mlkem-native` known-answer vector. It is used by
exported SCKA operations only in the explicit `candidate-ffi` build. The
default self-test and all default shaped state operations still return
`NOT_READY`.

The same inactive crate implements the frozen outer `LS3` AES-256-GCM-SIV container
behind an internal module. It validates exact header fields, lengths,
role/session/revision bindings, signed-63 counters, AAD, ciphertext, and tag,
and returns decrypted bytes only through a zeroizing owner. The lower-level
envelope still accepts an exact caller-supplied nonce. The private composition
specified by `SCKA_AUTHENTICATED_COMPOSITION.md` derives an injective
`"LN3" || role || revision` nonce and connects LS3 to canonical LB3/BM3
transitions. Only the explicit `candidate-ffi` build connects that composition
to the C ABI; the default build remains `NOT_READY`.

The `LB3` codec represents all 11 revision-1 states, duplicates and
cross-checks the authenticated `LS3` role/session/revision/epoch metadata,
validates sender/receiver parity and ML-KEM key relationships, bounds canonical
encoder/decoder progress, and zeroizes its owned plaintext.

The private module frozen in `SCKA_AUTHENTICATOR.md` now implements the exact
Layergram revision-1 protocol domain, `KDF_AUTH`, `KDF_OK`, full-length
HMAC-SHA-256 header/ciphertext tags, constant-time verification, detached
authenticator successors, and zeroizing epoch-key ownership.

The application-disconnected `BM3` codec frozen in `SCKA_PUBLIC_MESSAGE.md` represents all
seven revision-1 logical public-message types, preserves their internal Braid
epoch, binds each data-bearing type to the exact erasure payload class, and
accepts only canonical 24-byte or 58-byte records.

The private initial transition slice frozen in `SCKA_TRANSITION_ENGINE.md` now
implements `InitAlice`, `InitBob`, `KeysUnsampled.Send`, and the
`KeysUnsampled.Receive` no-op, continues authenticated Header erasure symbols
in `KeysSampled.Send`, implements transition 2 from current-epoch `Ct1` to
`HeaderSent`, emits persisted `Ek` symbols in `HeaderSent.Send`, and implements
transition 3 after any sufficient unique `Ct1` set reconstructs the exact
ciphertext part, continues `Ek` with a `Ct1` acknowledgement in
`Ct1Received.Send`, and implements transition 4 by initializing the `Ct2`
decoder from the first current-epoch symbol. `EkSentCt1Received.Send` emits the
canonical no-data record, while `EkSentCt1Received.Receive` implements
transition 5: it reconstructs `ct2 || mac`, decapsulates ML-KEM, derives the
zeroizing native epoch key, ratchets the authenticator, verifies the ciphertext
MAC with that successor authenticator, and only then advances to the next-epoch
`NoHeaderReceived` state. `NoHeaderReceived.Send` emits the canonical
no-data record and catches up the send high-water. `NoHeaderReceived.Receive`
implements transition 6: it reconstructs `header || mac`, verifies the
current-epoch header MAC, and only then creates `HeaderReceived` with the
authenticated `pk1` and an empty `pk2` decoder. `HeaderReceived.Send`
implements transition 7: it obtains one fresh 32-byte encapsulation seed,
runs `Encaps1`, derives the zeroizing epoch key, ratchets the authenticator,
emits Ct1 symbol zero, and creates the exact pending `Ct1Sampled` candidate.
`HeaderReceived.Receive` is the revision-1 semantic no-op. `Ct1Sampled.Send`
continues exact Ct1 symbols from persisted progress. `Ct1Sampled.Receive`
retains incomplete `pk2` symbols canonically and implements transition 8 when
`EkCt1Ack` arrives before completion: it discards the acknowledged Ct1 encoder
and creates `Ct1Acknowledged` with the exact pending continuation and partial
decoder. Transition 9 handles completing `EkCt1Ack`: it validates the full
public key, completes `Encaps2`, authenticates exact `ct1 || ct2`, and creates
the initial `Ct2Sampled` encoder without entropy or a second epoch-key output.
Transition 10 handles completing plain `Ek`: it validates the same full public
key and creates `EkReceivedCt1Sampled` while preserving the pending
encapsulation, exact `ct1`, and persisted `ct1` encoder until acknowledgement.
That state continues deterministic `Ct1` output without entropy or a second
epoch-key output. `Ct1Acknowledged.Send` emits the canonical no-data record
while preserving the pending continuation and partial decoder. Transition 11 is
`Ct1Acknowledged.Receive`: it reconstructs and validates the complete public
key from current-epoch `EkCt1Ack` symbols, completes `Encaps2`, authenticates
the exact persisted `ct1 || ct2`, and only then creates `Ct2Sampled`. It
requests no entropy and emits no second epoch key. Transition 12 is
`EkReceivedCt1Sampled.Receive`: a current-epoch `EkCt1Ack`
revalidates the already-complete public key, restores the exact pending
`Encaps1` state, completes `Encaps2`, authenticates persisted `ct1 || ct2`,
and creates the same canonical `Ct2Sampled` shape. It requests no entropy,
emits no second epoch key, and unrelated or wrong-epoch input remains a
semantic no-op. `Ct2Sampled.Send` continues the exact authenticated `ct2`
encoder across dropped carrier exports and restart. Transition 13 accepts only
the immediately following Braid epoch, preserves the already-ratcheted
authenticator, switches roles to `KeysUnsampled`, and emits neither entropy nor
an epoch key. Earlier or later canonical epochs are semantic no-ops. The first send
obtains its exact 64-byte ML-KEM key-generation seed from a private
`getrandom` 0.4.3 operating-system entropy boundary; transition 7 obtains a
separate 32-byte seed from the same boundary, while continued Header and `Ek`
symbols use persisted encoder progress without requesting new entropy.
Every opt-in `getrandom` backend is rejected at compile time. The complete
transition engine is now connected privately to LS3, LB3, BM3, and OS
transition entropy by `authenticated_braid.rs`; LS3 state nonces are derived
deterministically from role and revision. It remains deliberately disconnected
from Flutter packaging. The Dart durable scope freezes the backend-selection
seam and can select the explicit-path, exact-build-allowlisted `candidate-ffi`
implementation in engineering tests; the default exports still return
`NOT_READY`.

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
1.8.1. The exact applicable dependency graph and notices are recorded in
`native/layergram_scka/THIRD_PARTY_NOTICES.md` and the machine-readable receipt.
The candidate crate is linked only into generated, ignored verification
artifacts; no native binary is committed and the normal application target
does not reference the packaged loader.

Before any packaged use, Layergram must regenerate and verify the resolved
target-specific graph for every release ABI and repeat the license/notice
review. Store distribution, commercial use, source/notice obligations, and the
proprietary Premium combination must all remain acceptable.

## Authenticated state-envelope primitive, inactive internal adoption

The `LS3` implementation pins `aes-gcm-siv` 0.11.1 with default features
disabled and only `aes,alloc` enabled. It additionally pins `aes` 0.8.4 with
its `zeroize` feature so Cargo feature unification enables best-effort erasure
of expanded AES round keys when the envelope cipher is dropped. RustCrypto's
applicable key and owned buffer types use the pinned `zeroize` graph for
best-effort cleanup. Both crates offer an Apache-2.0 licensing path.

The applicable graph adds only Apache-2.0/MIT-compatible packages plus
`subtle` 2.6.1 under BSD-3-Clause. The exact BSD text is retained at
`native/layergram_scka/licenses/BSD-3-Clause-subtle.txt`; the package inventory
and checksums are recorded in `Cargo.lock`, the third-party notice, and the
machine receipt. These terms permit paid commercial distribution when their
notice requirements are preserved, but this remains an engineering review and
not legal advice.

The internal envelope API still accepts a caller-supplied nonce. The private
composition derives an injective 96-bit nonce as
`"LN3" || role_u8 || state_revision_u64_be`; the shared state key therefore has
disjoint initiator/responder nonce spaces and no random-collision budget.
RFC 8452 AES-GCM-SIV prevents a divergent same-revision recomputation from
causing AES-GCM's catastrophic nonce-reuse failure. The future durable
authority must still ensure one logical candidate per role/revision, persist
the exact candidate before advancing, and re-export those bytes without
rerunning a randomized transition.

## Ratcheted-authenticator primitives, inactive internal adoption

The implementation pins RustCrypto `hkdf` 0.12.4, `hmac` 0.12.1, and `sha2`
0.10.9 with default features disabled. Each offers an Apache-2.0 licensing path.
Their applicable graph is already composed of the permissive packages recorded
in the notice, plus the two newly locked `hkdf` and `hmac` packages. No GPL,
AGPL, LGPL, non-commercial, or field-of-use term is selected.

`SCKA_AUTHENTICATOR.md` freezes the exact ASCII Layergram protocol domain and
independent golden outputs. RustCrypto HMAC verification supplies the
constant-time tag comparison. This is an inactive primitive checkpoint, not an
independent cryptographic audit or approval of the eventual state machine.

## Independent revision-1 conformance vector

`tool/pq/generate_scka_cross_implementation_vector.py` is a separately
executed Layergram-owned Python 3 oracle. It uses only the standard library,
the public-domain ML-KEM Braid revision-1 specification, and the already
vendored permissive `mlkem-native` ML-KEM-768 KAT. It neither imports nor
executes the Rust SCKA implementation and does not use Signal's AGPL source.

The frozen vector at
`native/layergram_scka/testdata/braid_r1_cross_impl_vector.txt` covers the
standard ML-KEM public key, ciphertext and shared secret, the Layergram
authenticator KDF/MAC values, systematic and parity erasure symbols, and one
complete two-party epoch. The Rust test compares every one of the 174 ordered
send/receive transcript records and the final participant states. The
independent transcript digest is
`fdee3ec45793c14a7317076ebd914690a98c49408a02330046b7189882768275`.
`test_scka_hardening.sh` first regenerates and compares this vector before its
sanitizer run.

Vector format v3 retains the Python-owned GF(2^16) receive decoder. For
each of Header, public-key vector, Ct1, and `Ct2 || MAC`, it drops source
symbols, mixes systematic and parity indexes, reverses their order, reconstructs
the exact payload, treats exact duplicates idempotently, rejects conflicting
duplicates, and freezes the encoded-chunk-set digest. The oracle then
authenticates the reconstructed header, binds the reconstructed public-key
vector to its header digest, and authenticates the reconstructed ciphertext.
Negative tag mutations must be rejected. The Rust conformance test independently
recreates the same mixed chunk sets, decodes them, and verifies the MACs over
the recovered bytes.

Format v3 additionally freezes the complete canonical `LB3` encoding of all
11 revision-1 state variants and the complete canonical `BM3` encoding of all
seven public-message types. Python constructs the headers, bodies, decoder
progress, role/epoch metadata, and exact byte lengths without calling Rust;
Rust reconstructs the same semantic fixtures, compares every per-state digest
and every full BM3 record, decodes them, and checks aggregate bundle digests.
The three pending variants carry one deterministic 2,080-byte opaque
continuation whose digest is frozen together with payload format 1 and the
exact `libcrux-ml-kem = 0.0.10` dependency. A different payload format or
continuation length is rejected. Same-length continuation integrity still
comes from authenticated `LS3`, as required by the protocol boundary.

This strengthens the implementation-independent revision-1 vector gate. It is
not the required external independent review, proof of the protocol,
production registration, or cross-platform packaging approval.

## Candidate packaging and release direction

The backend remains a Layergram-owned Rust library behind the frozen C ABI.
The opt-in verification scripts embed the exact candidate as follows:

- iOS: statically linked into the signed application process;
- macOS: signed embedded framework or static library with no loader search-path
  ambiguity;
- Android: one shared library for every shipped ABI;
- Windows: one DLL for every shipped architecture;
- Linux: one hardened shared library per shipped architecture.

Only exact absolute or platform-defined process loader paths may be used.
Production exports must be allowlisted and test hooks must be absent. The
candidate loader accepts either an explicit engineering path or the
deterministic packaged location, plus an exact compile-time identity/ABI tuple.
The ordinary application now contains a fail-closed lifecycle reference to the
packaged factory, but its selector returns before constructing the owner or
loading the library while the production activation policy is false. The Rust
toolchain, panic policy, allocator behavior, symbol stripping, reproducibility,
notices, and store packaging are separate release gates.

Generated artifacts are connected only by the opt-in smoke scripts. The
Android Gradle source set is enabled only by an explicit candidate property and
then points at an ignored generated directory; Apple link flags, Linux bundle
copying, and Windows DLL copying are supplied by verification scripts rather
than production project registration.

The Android bundle checkpoint also produces an isolated Release `.aab`,
validates it with the Gradle-resolved bundletool, verifies its local JAR
signature and protobuf manifest application ID, and rechecks the exact SCKA
exports for every packaged ABI. It is store-shaped packaging evidence only;
Play App Signing, upload, review, and production registration remain open.

## Remaining security gates

- independently review the now-complete private revision-1 transition engine
  together with its frozen authenticator, payload, and public-message codecs;
- verify erasure-code behavior, epoch uniqueness, output-key agreement,
  reordering, loss, duplication, and offline recovery;
- test state corruption, replay, crash windows, rollback, allocation limits,
  panic containment, wiping, and concurrent calls;
- retain the bounded deterministic hostile corpus and fixed-schedule stateful
  ABI campaign across concurrent sessions, carrier loss/reordering/replay,
  exact-state restart, stale-revision rejection, and epoch-key agreement;
  retain the macOS/Linux
  AddressSanitizer checkpoint, and locked state-validation/send/receive
  coverage-guided fuzz harnesses; collect and monitor recurring green runs from
  the configured scheduled workflow, retain and triage any reproducer, and
  extend static analysis, crash/resource campaigns, signed distribution/store
  packaging, and per-release physical-device regression testing;
- obtain independent cryptographic and implementation review.

Until all gates pass, no enabled production provider may return this backend
and Layergram must not claim that protocol v3 or the released app is
quantum-resistant.
