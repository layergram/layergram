# Layergram SCKA native ABI and state envelope v1

Status: **default build is a frozen `NOT_READY` scaffold; an explicit
engineering-only Cargo feature connects the authenticated composition to the
frozen ABI; opt-in generated candidate artifacts are packaged for verification,
while ordinary application bootstrap, production registration, and protocol v3
activation remain disconnected**

This document freezes the first Layergram-owned C ABI and authenticated state
envelope for an eventual independent implementation of ML-KEM Braid revision 1.
The current Rust crate implements and tests the outer `LS3` envelope, inner
`LB3` payload, revision-1 authenticator primitives, and canonical `BM3` public
message behind internal modules. The private engine implements initialization
and transitions 1-13 as specified by `SCKA_TRANSITION_ENGINE.md`; the private
composition in `SCKA_AUTHENTICATED_COMPOSITION.md` now authenticates and
semantically validates LS3/LB3, dispatches canonical BM3, seals each detached
successor once with an injective role-and-revision nonce, and preserves exact
candidate bytes. With default features the crate deliberately returns
`LG_SCKA_V1_ERR_NOT_READY` from its self-test and every correctly shaped state
operation. Cargo feature `candidate-ffi` connects those exact ABI shapes to the
private authenticated composition for laboratory integration tests. That
feature changes the implementation ID. Opt-in scripts package it into
generated, ignored platform artifacts and exercise the scope-owned loader; it
is not referenced by ordinary `lib/main.dart`, is not registered for
production, and does not make Layergram quantum-resistant.

The crate is Apache-2.0, pins Rust 1.87.0, and is suitable for the public
repository that is merged into the separately distributed paid Premium
application. Its inactive incremental primitive uses exact-version permissive
dependencies recorded in `native/layergram_scka/THIRD_PARTY_NOTICES.md` and the
machine receipt. Every dependency change requires a new checksum, feature,
transitive-license, notice, and target-specific review.

## 1. Stable constants and ownership

The authoritative public header is
`native/layergram_scka/include/layergram_scka.h`.

The default implementation ID is `layergram-scka-scaffold-r1-abi1`. The
engineering feature identifies itself as
`layergram-scka-private-r1-abi1-state2-build1`. The Dart candidate loader
hard-codes that second identity together with every table value below. This
allowlist is compiled into the signed Dart binary rather than read from a
carrier message or mutable storage. It is necessary but not sufficient for
production approval.

| Constant | Value |
|---|---:|
| ABI version | 1 |
| ML-KEM Braid protocol revision | 1 |
| state format | 2 |
| suite | Layergram v3 suite 1 / ML-KEM-768 |
| session ID | 16 bytes |
| state-sealing key | 32 bytes |
| handshake SCKA seed | 32 bytes |
| emitted epoch secret | 32 bytes |
| maximum public native message | 512 bytes |
| minimum state export | 97 bytes |
| maximum state export | 196,608 bytes |
| state header | 80 bytes |
| AES-256-GCM-SIV tag | 16 bytes |

The initiator is ML-KEM Braid's initial sending participant (`InitAlice` in the
public specification); the responder is its initial receiving participant
(`InitBob`). The Braid internal epoch begins at 1, so the first reported
`sending_epoch`/`receiving_epoch` high-water value is 0.

The private transition result does not change this public ABI contract. It is
reachable through the header and Dart only in an explicitly built engineering
candidate. Generated candidate smoke packages may reach it only through the
scope-owned loader; released application packages remain outside this path.

Every transition is candidate-only:

- input state is immutable and caller-owned;
- output state, public message, and optional epoch secret are caller-owned;
- the caller must wipe every fixed-capacity output buffer after copying an
  accepted result;
- the backend must clear all supplied output buffers before returning any
  non-`OK` result after it has accepted their pointers and exact capacities;
- an optional epoch secret is valid only when `has_epoch_secret_out == 1`;
- a returned state becomes authoritative only in the same atomic application
  effect and TR3 revision that consumes it.

No ABI function allocates memory across the FFI boundary and no opaque native
handle survives a call. Every length is explicit `uint64_t`; values are bounded
before conversion to a platform `size_t`. A non-null pointer must reference the
declared readable or writable range. `message_in` is the only optional buffer
and may be null exactly when its length is zero.

Candidate operations additionally reject naturally misaligned scalar outputs,
overlapping writable outputs, and every overlap between a readable input and a
writable output before constructing Rust slices. Deterministic hostile-state
and message corpora exercise those rules with guard bytes and assert that every
accepted non-`OK` path scrubs the fixed-capacity outputs. The pinned
`tool/pq/test_scka_hardening.sh` reruns the complete candidate Rust suite under
AddressSanitizer on the explicitly supported macOS/Linux host targets. The
separate locked `native/layergram_scka/fuzz` package additionally drives state
validation, send, and receive through this exact ABI under libFuzzer plus
AddressSanitizer on macOS/Linux. This bounded engineering checkpoint is not a
substitute for scheduled continuous campaigns, physical-device testing, or an
independent audit.

## 2. Stable state-sealing key

The state export is not self-authenticating merely because it contains a MAC
key. The 32-byte state-sealing key is therefore supplied separately to every
native operation and MUST NOT occur inside the state export.

Before provider registration, `V3KeySchedule.deriveSession` must derive one
stable key with a new domain-separated label:

```text
info = "layergram/v3/session/scka-state-seal\0"
L = 32
```

The key must be stored as separately named secret session material, copied only
for one native call, wiped afterward, and committed under the same encrypted
identity/passphrase scope as TR3. It is stable for the session lifetime and is
not the mutable PQ root. The native AEAD additionally binds the stable session
ID and role, so the same session key cannot authorize another role or session.

The Dart key schedule now derives this key, and TR3 format 2 persists it as a
separately named secret beside the opaque native export under the encrypted
identity/passphrase scope. The defensive Dart adapter supplies temporary copies
of the key and exact expected TR3 revision to every backend operation, wipes
them afterward, and rejects a candidate unless it reports the immediately next
revision. The scaffold self-test remains `NOT_READY`; provider registration is
still forbidden until the remaining implementation and audit gates pass.

## 3. Canonical `LS3` authenticated state export

All integers use unsigned big-endian encoding. Epochs and revisions are limited
to `0..2^63-1`. The exact 80-byte header is AES-256-GCM-SIV additional authenticated
data. The encrypted payload is the canonical backend state-machine encoding;
the 16-byte authentication tag is appended after its ciphertext.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `LS3` |
| 3 | 1 | state format `0x02` |
| 4 | 1 | suite `0x01` |
| 5 | 1 | stable role: initiator `0x01`, responder `0x02` |
| 6 | 2 | flags, zero |
| 8 | 2 | header length, exactly `80` |
| 10 | 2 | ML-KEM Braid revision, exactly `1` |
| 12 | 4 | exact total export length, `97..196608` |
| 16 | 4 | ciphertext length, exactly `total_length - 96` |
| 20 | 16 | stable non-zero session ID |
| 36 | 8 | native state revision |
| 44 | 8 | sending-epoch high-water value |
| 52 | 8 | receiving-epoch high-water value |
| 60 | 12 | state-sealing nonce |
| 72 | 8 | reserved zeros |
| 80 | N | AES-256-GCM-SIV ciphertext, `1..196512` bytes |
| 80+N | 16 | AES-256-GCM-SIV authentication tag |

The private composition derives the nonce as the exact 12 bytes
`"LN3" || role_u8 || state_revision_u64_be`. Both roles share the state-sealing
key, so the role byte creates disjoint nonce spaces and the signed-63 revision
is injective within each space. The lower-level `state_envelope` module accepts
that exact caller-owned nonce, uses the full 80-byte header as AES-256-GCM-SIV
AAD, authenticates before returning a zeroizing plaintext owner, and enforces
every fixed field and size bound. AES-GCM-SIV is the RFC 8452 nonce-misuse-
resistant construction: divergent plaintext at the same role and revision
cannot trigger AES-GCM's catastrophic nonce-reuse failure. It may still reveal
whether candidate plaintexts are equal, so a candidate must be sealed once,
persisted exactly, and retried from its stored bytes. It is not called by the
ABI and does not generate randomness. The complete implementation must reject
malformed length arithmetic,
unsupported values, non-zero reserved fields, wrong session/role, an
authentication failure, counter exhaustion, and any mismatch between header
and decrypted state semantics.

Initialization emits revision 0. Each accepted `Send` or `Receive` candidate
emits exactly `expected_state_revision + 1`; revision exhaustion fails closed.
The caller supplies `expected_state_revision`, and the backend must authenticate
that the input header and plaintext both carry that exact revision. The outer
serialized session authority must also require the input native revision to
equal the current TR3 revision and the candidate revision to equal the proposed
TR3 revision. This prevents a valid older state export from silently rolling a
session backward.

The encrypted payload is the canonical `LB3` representation frozen in
`SCKA_STATE_PAYLOAD.md`. It carries the exact state-machine variant, Braid
internal epoch, ratcheted authenticator roots, incremental ML-KEM secrets, and
minimal erasure encoder/decoder progress. Its decoder accepts at most 4,434
bytes, duplicates and cross-checks all authenticated outer metadata, validates
role/epoch direction, private/public ML-KEM key relationships, canonical chunk
ordering, and state-specific progress, and wipes its owned plaintext on drop.
Changing a field layout or the opaque incremental continuation representation
requires a new payload-format migration decision; it cannot reinterpret an
existing `LB3` payload or weaken `LS3` bindings.

The root and MAC keys stored inside `LB3` are interpreted only through the
exact `KDF_AUTH`, `KDF_OK`, and HMAC domains frozen in
`SCKA_AUTHENTICATOR.md`. The implementation derives immutable successor state
and zeroizing output-key owners. It is used by the private transition engine
and the explicit candidate ABI, but remains disconnected from default ABI
behavior and application packaging.

The standalone public-message erasure representation is frozen in
`SCKA_ERASURE_CODE.md`; the canonical logical message that carries one such
chunk is frozen in `SCKA_PUBLIC_MESSAGE.md`. A `BM3` record is exactly 24 bytes
for `None`/`Ct1Ack` or 58 bytes for a chunk-bearing type, and always preserves
the non-zero internal Braid epoch. The version-locked incremental primitive boundary and
its exact 2,080-byte opaque continuation state are frozen in
`SCKA_INCREMENTAL_MLKEM.md`. These components and the complete encrypted
payload representation are tested inside the Rust crate. The private composition
now joins them as specified by `SCKA_AUTHENTICATED_COMPOSITION.md`, including
transition 13, exact revision-plus-one checks, and one injective LS3 nonce per
role/revision. The engineering feature connects these operations to the
candidate ABI and the scope-owned Dart dispatcher. Production packaging and
independent review remain unimplemented.

## 4. ABI operations

All operations below remain `NOT_READY` in the default build. They are
operational only when the crate is deliberately built with `candidate-ffi`.
The candidate clears full fixed-capacity output buffers before validation,
maps typed authentication/format/revision/entropy failures to the frozen status
domain, copies outputs only from a complete detached candidate, and rejects an
empty or non-canonical revision-1 BM3 input.

`lg_scka_v1_state_validate` authenticates and semantically validates one exact
state against role, session ID, state-sealing key, and expected revision.

`lg_scka_v1_initialize` consumes the transcript-derived 32-byte SCKA seed and
produces revision-zero state. It emits no public message or epoch secret.

`lg_scka_v1_send` produces a new state, one `0..512` byte canonical Braid
message, the high-water sending epoch, and at most one `(epoch, 32-byte secret)`
output. It must not accept or choose the Layergram PQ message counter.

For the admitted revision-1 implementation, a non-empty result is one exact
24-byte or 58-byte `BM3` record. An empty native message remains representable
by the generic frozen ABI but is not a canonical revision-1 `BM3` message and
MUST NOT be emitted or accepted by that implementation.

`lg_scka_v1_receive` consumes one `0..512` byte native Braid message and
produces a new state, the matching receiving epoch, and at most one epoch
secret. Dart separately verifies that this receiving epoch equals the visible
SK3 sending epoch before committing the candidate.

Status values are stable. `INVALID_ARGUMENT` denotes an ABI shape failure;
`AUTHENTICATION`, `STATE_FORMAT`, and `STATE_REVISION` distinguish durable-state
rejection; `BACKEND`, `ENTROPY`, `SELF_TEST`, and `ALLOCATION` are fail-closed
local failures. `NOT_READY` is reserved for this scaffold and any deliberately
disabled build. No non-`OK` result may be interpreted as an empty/no-op SCKA
transition.

## 5. Candidate packaging and platform proof

The crate emits `staticlib`, `cdylib`, and `rlib` artifacts. Opt-in scripts link
or copy generated candidate artifacts into disposable Flutter smoke builds;
normal application builds contain no generated library and do not call the
packaged loader. Exact export tests allow only `lg_scka_v1_*` symbols.

Current candidate proof is:

- macOS ARM64: Rust unit tests, release dylib, C-header ABI smoke, exact exports;
- iOS device ARM64: release static library, header compile against the iPhoneOS
  SDK, exact exports;
- iOS simulator ARM64 and x86_64: release static libraries, header compile
  against the simulator SDK, exact exports;
- Linux x64: Rust unit tests, release shared library, C-header ABI smoke, exact
  exports;
- Windows x64: Rust unit tests, release DLL, exact PE exports;
- Android arm64-v8a, armeabi-v7a, and x86_64: release APK contains the exact
  allowlisted library for every tested ABI;
- Android App Bundle: the isolated Release `.aab` passes bundletool validation,
  has a locally valid JAR signature and `app.layergram.sckasmoke` manifest, and
  contains the exact allowlisted library for all three Android ABIs;
- macOS ARM64/x86_64: universal candidate linked into a locally signed smoke
  app and exercised through the persistence scope;
- iOS simulator x86_64: packaged scope smoke executed; device ARM64 and
  simulator ARM64 artifacts compile with exact symbols;
- iOS physical ARM64: a development-signed Release scope smoke executed on an
  iPhone 14 Pro Max running iOS 27.0, returned the exact success marker and
  exit code zero, and was removed after the test;
- Android physical ARM64: an isolated Release scope smoke executed on a Huawei
  SNE-LX1 running Android 10, returned the exact success marker and exit code
  zero, and was removed after the test;
- Linux x64 and Windows x64: packaged scope smoke executed from the final
  bundle location with exact exports; Linux also verifies RELRO/BIND_NOW.

The macOS signature and Android App Bundle signature are local developer
verification, not notarized or Play-signed releases. Store archives,
notarization, and every actually shipped ABI remain mandatory release gates.
The physical iOS and Android results are device-runtime evidence and do not
replace distribution signing.

When real native transitions exist, these compile-time checks are insufficient.
Every shipped ABI must then run identical primitive/state-machine vectors,
corruption, replay, rollback, loss/reorder/duplicate, concurrency, panic,
allocation, wiping, sanitizer, fuzzing, restart, and packaged-app traversal.
At least one physical iOS device and one physical Android device are mandatory;
both device checkpoints are now satisfied. macOS success never substitutes for
iOS evidence, and an Android cross-build never substitutes for Android-device
execution.

## 6. Activation gates

The backend remains unregistrable until all of the following are complete:

- independent review of the frozen erasure representation and a complete
  state-payload format;
- pinned permissively licensed dependencies and notices in `Cargo.lock`;
- independent ML-KEM Braid revision-1 implementation and conformance vectors;
- production self-tests that return `OK` only for the approved implementation;
- per-platform production linking with an exact implementation-ID allowlist;
- full security testing and an independent cryptographic/implementation audit.

Changing a frozen function signature, status meaning, header field, algorithm,
or authenticated binding after this inactive state-format-v2 checkpoint
requires a new ABI/state format. Until activation, the only safe
runtime outcome from this crate is `LG_SCKA_V1_ERR_NOT_READY`.
