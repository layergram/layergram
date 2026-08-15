# Layergram SCKA native ABI and state envelope v1

Status: **frozen inactive scaffold, implemented internal outer envelope,
canonical inner payload, ratcheted authenticator, and canonical public-message
codec; erasure representation and incremental primitive boundary frozen; no
public transitions; private initialization and transitions 1-11 implemented;
protocol v3 inactive**

This document freezes the first Layergram-owned C ABI and authenticated state
envelope for an eventual independent implementation of ML-KEM Braid revision 1.
The current Rust crate implements and tests the outer `LS3` envelope, inner
`LB3` payload, revision-1 authenticator primitives, and canonical `BM3` public
message behind internal modules. The private engine now implements
initialization and transitions 1-11 as specified by `SCKA_TRANSITION_ENGINE.md`,
while deliberately returning
`LG_SCKA_V1_ERR_NOT_READY`
from its self-test and every correctly shaped state operation. It cannot be
registered as a `V3SckaBackend` and does not make Layergram quantum-resistant.

The crate is Apache-2.0, pins Rust 1.87.0, and is suitable for the public
repository that is merged into the separately distributed paid Premium
application. Its inactive incremental primitive uses exact-version permissive
dependencies recorded in `native/layergram_scka/THIRD_PARTY_NOTICES.md` and the
machine receipt. Every dependency change requires a new checksum, feature,
transitive-license, notice, and target-specific review.

## 1. Stable constants and ownership

The authoritative public header is
`native/layergram_scka/include/layergram_scka.h`.

| Constant | Value |
|---|---:|
| ABI version | 1 |
| ML-KEM Braid protocol revision | 1 |
| state format | 1 |
| suite | Layergram v3 suite 1 / ML-KEM-768 |
| session ID | 16 bytes |
| state-sealing key | 32 bytes |
| handshake SCKA seed | 32 bytes |
| emitted epoch secret | 32 bytes |
| maximum public native message | 512 bytes |
| minimum state export | 97 bytes |
| maximum state export | 196,608 bytes |
| state header | 80 bytes |
| AES-256-GCM tag | 16 bytes |

The initiator is ML-KEM Braid's initial sending participant (`InitAlice` in the
public specification); the responder is its initial receiving participant
(`InitBob`). The Braid internal epoch begins at 1, so the first reported
`sending_epoch`/`receiving_epoch` high-water value is 0.

The private transition result does not change this public ABI contract: it
cannot be called through the header, Dart, Flutter, or a packaged application.

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
to `0..2^63-1`. The exact 80-byte header is AES-256-GCM additional authenticated
data. The encrypted payload is the canonical backend state-machine encoding;
the 16-byte authentication tag is appended after its ciphertext.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `LS3` |
| 3 | 1 | state format `0x01` |
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
| 60 | 12 | fresh state-sealing nonce |
| 72 | 8 | reserved zeros |
| 80 | N | AES-256-GCM ciphertext, `1..196512` bytes |
| 80+N | 16 | AES-256-GCM authentication tag |

The nonce comes from the approved operating-system CSPRNG. The internal
`state_envelope` module accepts that exact caller-owned nonce, uses the full
80-byte header as AES-256-GCM AAD, authenticates before returning a
zeroizing plaintext owner, and enforces every fixed field and size bound. It is
not called by the ABI and does not generate randomness. A candidate must be
sealed once and its exact bytes persisted; retry never reseals the same logical
revision. The complete implementation must reject malformed length arithmetic,
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
but remains disconnected from the public C ABI and application packaging.

The standalone public-message erasure representation is frozen in
`SCKA_ERASURE_CODE.md`; the canonical logical message that carries one such
chunk is frozen in `SCKA_PUBLIC_MESSAGE.md`. A `BM3` record is exactly 24 bytes
for `None`/`Ct1Ack` or 58 bytes for a chunk-bearing type, and always preserves
the non-zero internal Braid epoch. The version-locked incremental primitive boundary and
its exact 2,080-byte opaque continuation state are frozen in
`SCKA_INCREMENTAL_MLKEM.md`. These components and the complete encrypted
payload representation are tested inside the Rust crate and remain disconnected
from all ABI operations. Braid scheduling, authenticated reconstruction,
remaining scheduling, recovery behavior, and transitions 12-13 remain
unimplemented and require separate review.

## 4. ABI operations

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

## 5. Packaging and platform proof

The crate emits `staticlib`, `cdylib`, and `rlib` artifacts but is not linked by
Flutter, CocoaPods, CMake, Gradle, or the Windows runner. Exact export tests
allow only `lg_scka_v1_*` symbols.

Required scaffold proof is:

- macOS ARM64: Rust unit tests, release dylib, C-header ABI smoke, exact exports;
- iOS device ARM64: release static library, header compile against the iPhoneOS
  SDK, exact exports;
- iOS simulator ARM64 and x86_64: release static libraries, header compile
  against the simulator SDK, exact exports;
- Linux x64: Rust unit tests, release shared library, C-header ABI smoke, exact
  exports;
- Windows x64: Rust unit tests, release DLL, exact PE exports;
- Android and any shipped ARM64 Linux/Windows target: required before the crate
  is packaged, but not implied by the current host-only scaffold.

When real native transitions exist, these compile-time checks are insufficient.
Every shipped ABI must then run identical primitive/state-machine vectors,
corruption, replay, rollback, loss/reorder/duplicate, concurrency, panic,
allocation, wiping, sanitizer, fuzzing, restart, and packaged-app traversal.
At least one physical iOS device and one physical Android device are mandatory;
macOS success never substitutes for iOS evidence.

## 6. Activation gates

The backend remains unregistrable until all of the following are complete:

- independent review of the frozen erasure representation and a complete
  state-payload format;
- pinned permissively licensed dependencies and notices in `Cargo.lock`;
- independent ML-KEM Braid revision-1 implementation and conformance vectors;
- production self-tests that return `OK` only for the approved implementation;
- per-platform production linking with an exact implementation-ID allowlist;
- full security testing and an independent cryptographic/implementation audit.

Changing a frozen function signature, status meaning, header field, or
authenticated binding requires ABI/state format v2. Until then, the only safe
runtime outcome from this crate is `LG_SCKA_V1_ERR_NOT_READY`.
