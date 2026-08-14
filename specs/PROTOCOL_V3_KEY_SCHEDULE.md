# Layergram Protocol v3 — Key Schedule and Durable State Draft

Status: **normative research draft; inactive; not externally reviewed**

This document freezes the first testable Layergram-v3 key-expansion boundary,
hybrid message-key combination, fragment nonce derivation, acknowledgement
schedule, committed application/control record, and Triple Ratchet snapshot
envelope. The separate `PROTOCOL_V3_HANDSHAKE.md` defines the inactive
candidate that supplies its authenticated inputs. The EC Double Ratchet engine,
ML-KEM Braid/SCKA backend boundary, exact HR3-to-LMF authentication, and an
inactive receive-commit session controller now exist. No production SCKA
backend or active send/receive integration exists, and protocol v3 remains
disabled.

`PROTOCOL_V3_SECURITY_GOALS.md` remains authoritative. This draft and its code
must change if later transcript design, ML-KEM Braid integration, persistence
review, or independent cryptographic review finds an unsafe construction.

The design follows the hybrid composition in Signal's Triple Ratchet: the
elliptic-curve Double Ratchet and Sparse Post-Quantum Ratchet produce separate
32-byte message keys, which are combined by an extract-then-expand KDF. The
selected primitive is HKDF-SHA-256 as specified by RFC 5869.

Primary references:

- <https://signal.org/docs/specifications/doubleratchet/>
- <https://signal.org/docs/specifications/mlkembraid/>
- <https://www.rfc-editor.org/rfc/rfc5869>

## 1. Scope and activation boundary

This checkpoint provides:

- transcript-bound expansion of already-authenticated classical and
  post-quantum handshake secrets;
- independent EC-ratchet, PQ-ratchet, directional ACK, routing, and session-ID
  outputs;
- a non-mutating X25519 Double Ratchet transition engine initialized from the
  authenticated handshake, including canonical `(DH, PN, N)` headers;
- mandatory hybrid combination of one EC and one PQ message key;
- deterministic, domain-separated message IDs, AES-256-GCM keys, and fragment
  nonces;
- directional ACK keys and nonces derived from visible canonical header fields;
- a strict 192-byte-header application/control record;
- a strict bounded Triple Ratchet snapshot containing EC state, at most two PQ
  epochs, bounded skipped keys, and an opaque native SCKA-state export;
- a strict public `SK3` SCKA envelope, a canonical `HR3` EC+SCKA container,
  and a non-mutating backend contract for authenticated native state exports;
- exact first-fragment HR3 carriage, digest-bound continuation fragments, and
  portable adaptive fragmentation;
- one inactive identity/passphrase-scoped receive-commit controller that owns
  its atomic journal, reconstructs contiguous per-session TR3 revisions,
  validates AR3/LMF/session bindings, and applies serialized revision CAS;
- golden, negative, framing, reassembly, and atomic-commit tests.

It deliberately does not provide:

- an independently approved handshake or deniability claim (the separate
  candidate remains externally unreviewed);
- a production ML-KEM Braid/SCKA implementation or reviewed native state
  exporter;
- an active send controller, deferred continuation-key resolver, handshake
  bootstrap, or real application-repository materializer;
- checkpoint compaction, replay-window retirement, or journal garbage
  collection;
- activation in contacts, messaging, UI, backup, migration, or Premium paths.

All code remains isolated under `lib/core/crypto/v3/`. Protocol v2 remains the
only active messaging protocol.

## 2. Canonical notation

- All multi-byte integers are unsigned big endian.
- `||` means byte concatenation.
- `U16`, `U32`, and `U64` mean fixed-width big-endian encodings.
- Every counter represented as `U64` is limited to `0..2^63-1` so all shipped
  Dart runtimes have the same accepted range.
- `HKDF(salt, IKM, info, L)` means RFC-5869 HKDF-SHA-256 producing `L` bytes.
- Every label below is exact UTF-8 and includes the final NUL byte shown as
  `\0`.
- The only registered suite is LMF suite `0x01`.
- All-zero secret inputs, all-zero transcript digests, malformed lengths,
  unknown roles/directions/kinds, and exhausted counters fail closed.

Participant roles are stable for the life of a session:

| ID | Role |
|---:|---|
| `0x01` | initiator |
| `0x02` | responder |

Traffic directions do not depend on which endpoint is currently local:

| ID | Direction |
|---:|---|
| `0x01` | initiator to responder |
| `0x02` | responder to initiator |

## 3. Post-handshake session expansion

The future authenticated handshake must provide:

- `CS`: exactly 32 bytes of authenticated classical handshake secret;
- `PS`: exactly 32 bytes of authenticated post-quantum handshake secret;
- `TH`: exactly 48 bytes, the SHA-384 digest of the complete canonical
  transcript.

This schedule does not authorize a classical-only or PQ-only handshake. Both
inputs are mandatory and must already bind both complete identities, devices,
roles, suite, mode, capabilities, and handshake frames through `TH`.

First isolate the input branches:

```text
CSEED = HKDF(
  salt = TH,
  IKM  = CS,
  info = "layergram/v3/session/classical-extract\0",
  L    = 32)

PQSEED = HKDF(
  salt = TH,
  IKM  = PS,
  info = "layergram/v3/session/post-quantum-extract\0",
  L    = 32)
```

Every session output uses the Signal Triple-Ratchet hybrid ordering, with the
post-quantum seed as HKDF salt and the classical seed as IKM:

```text
D(label, L) = HKDF(
  salt = PQSEED,
  IKM  = CSEED,
  info = UTF8(label) || TH,
  L    = L)
```

Outputs:

| Output | Bytes | Exact label |
|---|---:|---|
| session ID | 16 | `layergram/v3/session/id\0` |
| initiator routing binding | 32 | `layergram/v3/session/routing/initiator\0` |
| responder routing binding | 32 | `layergram/v3/session/routing/responder\0` |
| initial EC ratchet root | 32 | `layergram/v3/session/ec-ratchet-root\0` |
| initial PQ ratchet root | 32 | `layergram/v3/session/pq-ratchet-root\0` |
| initiator-to-responder ACK root | 32 | `layergram/v3/session/ack/initiator-to-responder\0` |
| responder-to-initiator ACK root | 32 | `layergram/v3/session/ack/responder-to-initiator\0` |

The two routing bindings are opaque session values, not identity IDs. A normal
frame uses the sender role's binding first and the recipient role's binding
second. A reply or ACK reverses them. The session ID and routing values are
public once placed in an authenticated LMF header; the ratchet and ACK roots
remain secret.

## 4. EC Double Ratchet transition schedule

This checkpoint follows the Signal Double Ratchet state machine with X25519.
It produces only the EC message-key branch. It does not authorize sealing an
LMF application/control frame until the future sparse-PQ transition produces a
matching `PQMK` and the composite EC+SCKA header is authenticated.

Let `SID` be the 16-byte session ID and `RK0` the 32-byte initial EC root from
Section 3. The authenticated handshake also supplies fresh initial X25519
ratchet pairs `RKA` and `RKB` for the initiator and responder. Define:

```text
KDF_RK(RK, DHOUT) = HKDF(
  salt = RK,
  IKM  = DHOUT,
  info = "layergram/v3/ec-double-ratchet/root\0" || SID,
  L    = 64)

KDF_RK output = next_RK || CK

MK      = HMAC-SHA-256(CK, "layergram/v3/ec-double-ratchet/message-key\0")
next_CK = HMAC-SHA-256(CK, "layergram/v3/ec-double-ratchet/next-chain-key\0")
```

The initiator initializes as:

```text
(RK1, CKs_A) = KDF_RK(RK0, X25519(RKA_priv, RKB_pub))
DHs_A = RKA
DHr_A = RKB_pub
CKr_A = absent
Ns_A = Nr_A = PN_A = 0
```

The responder may precompute the standard first receive/send DH step because
the completed authenticated handshake already binds `RKA_pub`. This permits a
responder to send immediately after confirmation without creating a second
ad-hoc bootstrap chain:

```text
(RK1, CKr_B) = KDF_RK(RK0, X25519(RKB_priv, RKA_pub))
RKB2 = fresh X25519 ratchet pair
(RK2, CKs_B) = KDF_RK(RK1, X25519(RKB2_priv, RKA_pub))
DHs_B = RKB2
DHr_B = RKA_pub
Ns_B = Nr_B = PN_B = 0
```

Thus `CKs_A == CKr_B`. The responder's first header advertises `RKB2_pub`, so
the initiator performs the corresponding receive/send DH step and obtains
`CKr_A == CKs_B`. Every later changed remote DH public key performs the normal
two-stage Signal DH ratchet: retain skipped keys through the authenticated
`PN`, derive the new receiving chain, generate a fresh local pair, then derive
the new sending chain.

The canonical standalone EC header is exactly 56 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `DR3` |
| 3 | 1 | format version `0x01` |
| 4 | 1 | suite `0x01` |
| 5 | 1 | flags, zero |
| 6 | 2 | encoded length `56` |
| 8 | 32 | current sender X25519 ratchet public key |
| 40 | 8 | previous sending-chain length `PN` |
| 48 | 8 | message number `N` |

LMF carries this record only inside the canonical `HR3` container described
below. Fragment zero authenticates the exact HR3 bytes as associated data;
continuations authenticate the same HR3 length and digest. The record alone
still cannot authorize a state transition.

Send and receive operations never mutate committed state. They return a
candidate message key and complete next EC state. Authentication failure wipes
the candidate and leaves the original state usable. A successful candidate
must replace the EC fields in a `TR3` snapshot whose prior revision matches
exactly; the new snapshot revision is prior revision plus one. This prevents a
candidate derived from stale state from being attached to a newer snapshot.

Out-of-order keys are indexed by `(ratchet_public_key, N)`. The total retained
EC dictionary is capped at 50 entries; a single jump or aggregate insertion
beyond that cap fails before advancing committed state. Expiry uses only a
caller-supplied local time policy. Expired, duplicate, stale, backwards-`PN`,
all-zero-DH, malformed, or exhausted-counter inputs fail closed. Restore
derives the X25519 public key from the stored private seed and compares it to
the stored public key before allowing a live transition.

Frozen portable vectors:

- `SHA-256(DR3(_bytes(32, 0x21), PN=7, N=9))` =
  `c4da6a0f0645f7a935960c9e810a6e76cdf935dc26e1a1c87e9a7f82656d2091`;
- for `CK = c1c2...dfe0`, the first `MK` =
  `0e65a0e3dd2f7133beb2590eda9f3245107bc4f6c71425c2ff6afc3de34c80cd`;
- for the same `CK`, `next_CK` =
  `5dd4c244b5069d2fad5374abcbcc3ee2643a3cfabdb46a35beb9bfd14a733b34`.

### 4.1 Sparse-PQ backend and hybrid-header boundary

The Dart boundary models the ML-KEM Braid SCKA operations `Init`, `Send`, and
`Receive` without implementing them. A conforming native backend MUST leave its
input export unchanged, return a distinct candidate export, bind the export to
the session ID and stable role, validate it before and after every transition,
and internally version and authenticate it. The export MUST NOT be an expanded
ML-KEM private key copied into Dart. No production backend is registered in
this checkpoint.

The public SCKA message uses a canonical `SK3` envelope:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `SK3` |
| 3 | 1 | format version `0x01` |
| 4 | 1 | suite `0x01` |
| 5 | 1 | flags, zero |
| 6 | 2 | exact total length, 24–536 |
| 8 | 8 | SCKA sending epoch |
| 16 | 8 | PQ message counter within that epoch |
| 24 | N | canonical backend SCKA public message, 0–512 bytes |

The epoch and counter are limited to `0..2^63-1`. The backend message is public
and may be empty for an SCKA no-op, but it is length-bounded before copying.
The native backend remains responsible for semantic parsing and for the SCKA's
own message authentication before its transition can be accepted.

The standalone hybrid container is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `HR3` |
| 3 | 1 | format version `0x01` |
| 4 | 1 | suite `0x01` |
| 5 | 1 | flags, zero |
| 6 | 2 | fixed header length `16` |
| 8 | 2 | exact total length |
| 10 | 2 | EC header length, exactly `56` |
| 12 | 2 | SCKA envelope length, 24–536 |
| 14 | 2 | reserved zeros |
| 16 | 56 | exact canonical `DR3` header |
| 72 | N | exact canonical `SK3` envelope |

An `HR3` is at most 608 bytes. Decoding validates outer lengths before nested
parsing, and both nested records must be canonical. LMF application and PQ
control frames require the exact HR3 on fragment zero. Every frame authenticates
its total length and `SHA-256("layergram/v3/lmf/hybrid-ratchet-header\0" || HR3)`;
the SCKA epoch/counter must equal the visible LMF coordinates. HR3 still cannot
authorize a ratchet transition by itself.

SCKA send and receive results are candidates: each owns a new authenticated
native export and an optional 32-byte epoch secret. The source export is never
mutated. A non-ACK commit uses `replaceHybridState` to replace EC and PQ state
in one `TR3` revision; no EC-only or PQ-only durable intermediate is allowed.

## 5. Hybrid application/control message schedule

For every non-ACK logical message the two ratchets must independently produce:

- `ECMK`: one 32-byte EC Double Ratchet message key;
- `PQMK`: one 32-byte Sparse Post-Quantum Ratchet message key.

Missing, malformed, all-zero, stale, or ambiguous input from either ratchet is
an error. No v3 frame may be sealed from only one branch.

The canonical 36-byte message context `M` is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | protocol version `0x03` |
| 1 | 1 | suite `0x01` |
| 2 | 1 | traffic direction |
| 3 | 1 | non-ACK frame kind |
| 4 | 8 | PQ epoch |
| 12 | 8 | message counter |
| 20 | 16 | session ID |

Define:

```text
H(label, L) = HKDF(
  salt = PQMK,
  IKM  = ECMK,
  info = UTF8(label) || M,
  L    = L)
```

Then derive:

```text
message_id = H("layergram/v3/triple-ratchet/message-id\0", 16)
aead_key   = H("layergram/v3/triple-ratchet/aead-key\0", 32)
nonce_seed = H("layergram/v3/triple-ratchet/nonce-seed\0", 32)
```

The derived message ID must exactly match the authenticated LMF header. The
message key is used for all canonical fragments of this one logical message.

For fragment `i` of `count`, final assembled plaintext length `length`, exact
HR3 length `hr3_length`, and domain-separated 32-byte digest `hr3_digest`, let:

```text
SHAPE = U16(i) || U16(count) || U32(length)
        || U16(hr3_length) || hr3_digest

nonce_i = HKDF(
  salt = 32 zero bytes,
  IKM  = nonce_seed,
  info = "layergram/v3/triple-ratchet/fragment-nonce\0"
         || M || message_id || SHAPE,
  L    = 12)
```

Application and PQ-control messages require a non-zero canonical HR3 length and
digest; headerless kinds use zero length and 32 zero bytes. `SHAPE` must describe
the exact canonical LMF fragmentation. The receiver must
derive and compare both `message_id` and `nonce_i` before accepting the frame's
ratchet transition. Distinct fragment indexes produce distinct nonces under the
same message key.

Crashes and retries do not authorize resealing changed content under the same
ratchet coordinates. The durable outbox must persist the complete sealed frame
set before first export and every resend must reuse those exact bytes.

## 6. ACK key and nonce schedule

ACKs are not Triple-Ratchet application messages and never consume an EC or PQ
message key. They use a direction-specific ACK root retained in the session
snapshot. The ACK frame must have a fresh, non-zero 16-byte message ID whenever
a new cumulative ACK is sealed. An ACK resend reuses the already-sealed bytes.

The canonical 128-byte visible ACK context `A` is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | protocol version `0x03` |
| 1 | 1 | suite `0x01` |
| 2 | 1 | ACK traffic direction |
| 3 | 1 | frame kind `0x04` |
| 4 | 32 | sender routing binding |
| 36 | 32 | recipient routing binding |
| 68 | 16 | ACK message ID |
| 84 | 16 | session ID |
| 100 | 8 | ACK-envelope epoch |
| 108 | 8 | ACK-envelope message counter |
| 116 | 4 | sender-declared expiry |
| 120 | 2 | fragment index `0` |
| 122 | 2 | fragment count `1` |
| 124 | 4 | final plaintext length `52` |

For the directional root `ACKROOT`:

```text
ack_key = HKDF(
  salt = session_id,
  IKM  = ACKROOT,
  info = "layergram/v3/ack/aead-key\0" || A,
  L    = 32)

ack_nonce = HKDF(
  salt = session_id,
  IKM  = ACKROOT,
  info = "layergram/v3/ack/nonce\0" || A,
  L    = 12)
```

Only header-visible values enter this derivation, so the receiver can derive
the key before opening the 52-byte ACK plaintext. Session ID, direction, and
both routing bindings must match the committed session exactly.

## 7. Canonical committed application/control record

The atomic journal's application byte string is the exact binary `AR3` record.
It has a fixed 192-byte header followed by 1–16,384 content bytes:

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 3 | magic | ASCII `AR3` |
| 3 | 1 | format version | `0x02` |
| 4 | 1 | suite | `0x01` |
| 5 | 1 | record kind | application `1`, handshake control `2`, PQ control `3` |
| 6 | 1 | flags | zero |
| 7 | 1 | header length | `192` |
| 8 | 4 | total record length | exact |
| 12 | 32 | assembly digest | exact LMF assembly-ID digest bytes |
| 44 | 16 | session ID | non-zero |
| 60 | 16 | message ID | non-zero |
| 76 | 32 | sender routing binding | non-zero |
| 108 | 32 | recipient routing binding | non-zero |
| 140 | 8 | epoch | authenticated target epoch |
| 148 | 8 | message counter | authenticated target counter |
| 156 | 4 | content length | 1–16,384 |
| 160 | 32 | content digest | rule below |
| 192 | N | content | exact complete delivered plaintext |

The record kind maps one-to-one to the source LMF frame kind; ACK has no mapping
and cannot create an atomic effect. The assembly digest is recomputed using the
same domain and fields as `V3LmfFrameCodec.assemblyId`.

```text
content_digest = SHA-256(
  "layergram/v3/committed-record/content\0"
  || assembly_digest || U64(epoch) || U64(message_counter) || content)
```

The maximum encoded record is 16,576 bytes. The atomic journal therefore
allows 17 KiB for this field so the full 16 KiB LMF plaintext remains
representable. The stable external record ID remains
`v3:<base64url(assembly_digest)>`.

## 8. Canonical Triple Ratchet snapshot

The journal's ratchet byte string is the exact binary `TR3` snapshot. It is a
complete post-effect state, never a delta. The fixed header is 496 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `TR3` |
| 3 | 1 | format version `0x01` |
| 4 | 1 | suite `0x01` |
| 5 | 1 | session role |
| 6 | 1 | lifecycle: active `1`, suspended `2`, rekey-required `3`, broken `4` |
| 7 | 1 | bit 0: remote EC DH public key present; bit 1: EC receiving chain present; all other bits zero |
| 8 | 2 | header length `496` |
| 10 | 4 | exact total length |
| 14 | 8 | monotonic snapshot revision |
| 22 | 16 | session ID |
| 38 | 48 | canonical transcript digest |
| 86 | 32 | initiator routing binding |
| 118 | 32 | responder routing binding |
| 150 | 32 | initiator-to-responder ACK root |
| 182 | 32 | responder-to-initiator ACK root |
| 214 | 32 | EC root key |
| 246 | 32 | EC sending-chain key |
| 278 | 32 | EC receiving-chain key, or canonical zeros when absent |
| 310 | 32 | EC local DH private seed |
| 342 | 32 | EC local DH public key |
| 374 | 32 | remote EC DH public key or canonical zeros |
| 406 | 8 | EC send counter |
| 414 | 8 | EC receive counter |
| 422 | 8 | EC previous sending-chain length |
| 430 | 32 | PQ root key |
| 462 | 8 | current PQ epoch |
| 470 | 8 | PQ sending epoch |
| 478 | 8 | PQ receiving epoch |
| 486 | 1 | retained PQ epoch count, 1–2 |
| 487 | 1 | retained EC skipped-key count, 0–50 |
| 488 | 1 | retained PQ skipped-key count, 0–50 |
| 489 | 3 | reserved zeros |
| 492 | 4 | opaque native SCKA-state length, 1–196,608 |

The variable sections follow in this exact order:

1. PQ epoch records, ascending and consecutive by epoch;
2. EC skipped keys, ordered by ratchet public key then counter;
3. PQ skipped keys, ordered by epoch then counter;
4. the opaque native SCKA-state export.

Each PQ epoch record is 96 bytes:

```text
U64(epoch) || U8(chain_flags) || 7 zero bytes
|| U64(send_counter) || U64(receive_counter)
|| 32-byte send key-or-zeros || 32-byte receive key-or-zeros
```

At least one chain flag must be set. A sealed chain has a zero counter and 32
zero bytes. The newest retained epoch equals the current epoch; two retained
epochs must be consecutive. The declared sending and receiving epochs must
exist and retain their respective chain.

Each EC skipped-key record is 80 bytes:

```text
32-byte ratchet public key || U64(counter) || 32-byte message key
|| U64(local expiry seconds)
```

Each PQ skipped-key record is 56 bytes:

```text
U64(epoch) || U64(counter) || 32-byte message key
|| U64(local expiry seconds)
```

Skipped-key identities must be unique. PQ skipped keys may reference only a
retained epoch. Count limits are enforced before allocation. Time expiry is
local policy and never trusts a peer clock.

An absent EC receiving chain is valid only for the initial initiator state. Its
presence flag is zero, its 32-byte field is all zero, and its receive counter is
zero. The sending chain is always present in this Layergram initialization.

The opaque SCKA bytes are consumed through the candidate-only backend boundary
in Section 4.1. They must be a backend-authenticated export and must not be a
raw expanded ML-KEM private key copied into Dart. The Dart envelope cannot
establish that property by itself; a production native implementation,
semantic export/import validation, and independent review remain activation
gates.

The synchronous envelope codec alone cannot prove that the stored local EC
private seed corresponds to the stored local public key. The EC transition
import boundary therefore derives and compares that public key before it
restores a live ratchet; independent cryptographic review remains required.

The maximum snapshot is 256 KiB, while the native SCKA section is capped at
192 KiB. Encoding, decode, corruption, conflicting order, unknown values,
zero required secrets, duplicate skipped keys, retired epochs, trailing bytes,
and over-limit input fail closed. Secret buffers are copied on construction and
best-effort overwritten when the state is discarded; perfect managed-runtime
zeroization is not claimed.

## 9. Persistence and crash rules

For every complete non-ACK delivery:

1. derive and authenticate both ratchet message keys and every fragment nonce;
2. build one canonical `AR3` record from the complete plaintext;
3. apply the EC and PQ transitions in private temporary state;
4. encode the complete post-transition `TR3` snapshot;
5. persist `AR3` and `TR3` together in one atomic journal effect;
6. only then bind that effect digest into the inbox replay tombstone;
7. expose or idempotently materialize the application record under its stable
   assembly-derived record ID.

A restored durable effect bypasses record/ratchet construction. A missing,
unbound, mismatched, malformed, or divergent effect/tombstone pair fails closed.
No effect may be collected until a separately durable ratchet checkpoint,
application record, and replay window prove it safe.

The inactive `V3SessionCommitController` claims its journal before restore, so
direct journal lifecycle or commit calls cannot race the coordinator after the
claim. Passing a journal to the controller transfers exclusive ownership;
production wiring must not retain or expose it for concurrent use while restore
begins. The controller requires a unique active checkpoint for every session in
the encrypted identity/passphrase scope and accepts only application or
PQ-control receive deliveries with the exact local session/routing bindings.
Restore sorts durable effects by session and revision and requires a contiguous
`checkpoint.revision + 1` chain. A new transition builder runs only after its
caller-supplied expected revision matches the current committed revision. The
controller updates its in-memory snapshot only after both the effect and bound
replay tombstone succeed. Once a prepared effect could have become durable, any
error makes that controller fail stopped until a fresh inbox, journal, and
controller restore storage.

The controller validates the canonical TR3 envelope and derives the stored
X25519 public key from its private seed before accepting a checkpoint or
candidate. Its optional backend validator is mandatory for future activation:
without a reviewed implementation authenticating and semantically validating
the opaque native SCKA export, the controller remains research-only. It does not
prove that a caller-supplied hybrid candidate is cryptographically correct by
revision shape alone; the reviewed EC/SCKA transition engines and validator
must supply that proof.

## 10. Remaining activation gates

Before this schedule can carry user messages, Layergram still requires:

- independent cryptographic review of the authenticated hybrid handshake and
  EC Double Ratchet construction;
- a reviewed ML-KEM Braid backend implementing authenticated state
  export/import behind the frozen boundary;
- completion of the current serialized receive-commit controller with exact
  EC/SCKA candidate construction, a send controller, deferred continuation-key
  resolution, and reviewed native-state validation;
- skipped-key expiry, checkpoint, compaction, replay-window, and garbage-
  collection rules;
- idempotent external application materialization;
- full packaging, crash, migration, multi-device, passphrase, Maximum-mode,
  text, link, QR, and steganography tests;
- independent protocol and implementation audit with no unresolved high or
  critical findings.

Until those gates pass, this is a developer-only research implementation and
must not be described to users as active quantum-resistant messaging.
