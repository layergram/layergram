# Layergram Protocol v3 — Key Schedule and Durable State Draft

Status: **normative research draft; inactive; not externally reviewed**

This document freezes the first testable Layergram-v3 key-expansion boundary,
hybrid message-key combination, fragment nonce derivation, acknowledgement
schedule, committed application/control record, and Triple Ratchet snapshot
envelope. The separate `PROTOCOL_V3_HANDSHAKE.md` defines the inactive
candidate that supplies its authenticated inputs. The EC Double Ratchet engine,
ML-KEM Braid/SCKA backend boundary, Sparse-PQ message chains, exact HR3-to-LMF
authentication, candidate-only hybrid send/receive orchestration,
deferred-fragment key resolution, and an inactive crash-consistent send/receive
session coordinator, encrypted stable-ID AR3 materializer, and monotonic TR3
checkpoint repository now exist. A scope-pinned owner also connects those
components and a bounded crash-consistent hybrid-handshake pending repository
to Layergram's real encrypted Aux/Hive storage. A fail-closed application
lifecycle owner now selects the exact primary/passphrase scope, drains the old
runtime before its identity handle is destroyed, and can open the packaged SCKA
candidate only after the single production activation policy becomes true.
That policy remains false, so normal application startup neither constructs the
owner nor loads the native backend. Protocol v3 remains disabled.

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
- deterministic directional Sparse-PQ epoch chains, bounded expired skipped
  keys, and candidate-only EC+PQ send/receive transitions;
- exact first-fragment HR3 carriage, digest-bound continuation fragments, and
  portable adaptive fragmentation;
- durable retention and later exact-key resolution when continuation fragments
  arrive before fragment zero;
- one inactive identity/passphrase-scoped send/receive coordinator that owns
  its journals and outbox, reconstructs a unified contiguous per-session TR3
  revision chain, validates AR3/LMF/session bindings, and applies serialized
  revision CAS;
- encrypted, bounded, idempotent AR3 materialization under the stable
  assembly-derived record ID, plus write-new-before-delete TR3 checkpoints with
  cumulative direction/revision/state receipts;
- checkpoint-backed restore, explicit journal collection, and write-before-
  delete replacement of incoming tombstones with durable replay-window proofs;
- one inactive scope-pinned Aux/Hive owner that privately constructs the full
  handshake/journal/outbox/checkpoint topology, restores sealed frames and
  pending handshakes before session keys are requested, and destroys its copied
  storage key on close;
- one inactive application lifecycle owner that serializes primary,
  passphrase, and multi-identity context changes, closes the complete session
  scope before its private identity handle is replaced or expelled, and leaves
  the packaged native loader unreachable while the activation selector is
  false;
- encrypted, bounded HP3 persistence with persist-before-export exact
  offer/reply retry, single-controller authority, per-identity capacity
  preflight, fail-stop ambiguous-write recovery, and write-before-delete
  completion tombstones retaining the initiator's exact confirmation;
- an encrypted, bounded initial-session preparation journal that commits the
  exact confirmation and revision-zero TR3 before checkpoint materialization,
  resumes every ambiguous boundary without rerunning cryptography, validates
  the deterministic checkpoint digest, retires HP3 before collection, and
  uses one unexposed scope-created identity capability to reject direct or
  competing child-controller registration/completion calls;
- frozen local Normal/Maximum retention horizons plus a non-destructive,
  explainable eligibility check for future replay/completion-proof retirement;
- an encrypted, bounded, fail-stop `v3_session_retirement_v1` journal whose
  `prepared` record freezes the exact compact proof, cumulative receipt, local
  proof age, and source checkpoint, and whose write-new-before-delete
  `checkpointReplaced` and `finalCheckpointWritten` revisions bind the exact
  pending and self-contained final checkpoint digests;
- single-authority ownership and scope-pinned Aux/Hive restore of that journal,
  with fail-closed reconciliation against the exact durable checkpoint,
  direction-bound receipt state, incoming/outgoing compact proof, exact
  proof/plan deletion, and bounded rolling receipt retirement;
- golden, negative, framing, reassembly, atomic-commit, exact-byte retry,
  capacity-preflight, ambiguous-write, restart, and ACK-ordering tests.

It deliberately does not provide:

- an independently approved handshake or deniability claim (the separate
  candidate remains externally unreviewed);
- a production ML-KEM Braid/SCKA implementation or reviewed native state
  exporter;
- active contact/device bootstrap policy, an active durable send controller,
  or projection from the durable AR3 source into the current message/UI
  repository;
- registration in providers or activation in contacts, messaging, UI, backup,
  migration, or Premium paths.

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
`Receive`. A conforming native backend MUST leave its
input export unchanged, return a distinct candidate export, bind the export to
the session ID and stable role, validate it before and after every transition,
and internally version and authenticate it. The export MUST NOT be an expanded
ML-KEM private key copied into Dart. No production backend is registered in
this checkpoint. `SCKA_BACKEND.md` records the commercially compatible
implementation path and rejects embedding the AGPL-only reference code.
Initialization, send, receive, and durable-state restore validation MUST pass
through `V3SparsePqRatchet`, which checks the canonical diagnostic
implementation ID, exact revision `1`, and self-test before invoking native
state semantics. Future provider registration must separately allowlist the
exact approved implementation ID.

The engineering-only `V3SckaCandidateFfiBackend` implements that exact build
admission for Cargo feature `candidate-ffi`: implementation ID, ABI, protocol
revision, state format, and every fixed size are compared against constants
compiled into Dart before self-test or state use. It exposes no packaged-loader
factory. The normal Rust build retains a different scaffold ID and returns
`NOT_READY`, so it is rejected by the candidate loader. This closes the
candidate integration proof only; production code signing, packaged-path
verification, and registration remain gates.

The inactive encrypted session scope MUST pin one admitted backend instance
for its lifetime. Checkpoint restore, HP3-to-TR3 handoff, durable send, and the
scope-owned receive resolver use that same instance; a divergent per-call
backend fails before SCKA transition work or a durable write. This process-local
binding is not encoded on the wire and does not replace the future signed build
allowlist or packaged native implementation check.

The scope-owned receive path MUST also pin that resolver to the exact durable
controller at construction. The scope, not an external transport caller,
resolves frame keys, handles AEAD candidate rejection, resumes sealed
continuations after fragment zero, and commits the exact authenticated
delivery. The scope API accepts neither a caller-selected resolver nor a
caller-selected commit controller. Continuations may still arrive first and
remain durably sealed across restart; they do not advance TR3 until fragment
zero authenticates and the complete delivery commits atomically. Automatic
resume after one fragment zero is restricted to that exact assembly so another
session's ready delivery cannot be consumed without notification; the explicit
all-assembly resume returns every delivery it completes.

`SCKA_NATIVE_ABI.md` freezes the inactive Layergram-owned C ABI and outer `LS3`
state envelope. The session expansion derives a separate stable 32-byte
state-sealing key with label `"layergram/v3/session/scka-state-seal\0"`. TR3
format 2 persists that key beside, never inside, the opaque native state under
the existing encrypted identity/passphrase scope. Every Dart backend call gets
a temporary copy plus the exact expected TR3 revision; initialization must
validate native revision 0 and every candidate must report exactly
`expected_revision + 1` before it can enter the atomic TR3 effect. The Rust
scaffold still returns `NOT_READY` and is not registered. Generated opt-in
candidate packages exercise only the scope-owned loader; ordinary application
bootstrap does not link or load it.

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
and the generic inactive Dart boundary permits an empty SCKA no-op so test
doubles and future revisions remain representable; it is length-bounded before
copying. The admitted ML-KEM Braid revision-1 backend instead MUST emit and
accept one canonical non-empty `BM3` record: 24 bytes for `None`/`Ct1Ack` or 58
bytes for a data-bearing type, as frozen in `SCKA_PUBLIC_MESSAGE.md`. `BM3`
preserves the internal Braid message epoch, which is distinct from this `SK3`
sending-epoch high-water field. The native backend remains responsible for
semantic parsing, complete erasure reconstruction, and the SCKA's own message
authentication before its transition can be accepted.

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
in one `TR3` revision. Both candidates are bound to a domain-separated SHA-256
digest of the exact canonical prior `TR3`, preventing same-session,
same-revision forks from being mixed; no EC-only or PQ-only durable intermediate
is allowed.

The epoch used by the public SCKA message and the epoch attached to an optional
new output secret are independent SCKA results. The backend MUST NOT rewrite
the Layergram PQ message counter. Dart selects that counter only after it has
selected the retained directional chain.

### 4.2 Sparse-PQ epoch and message chains

Let `PQROOT` be the current 32-byte Sparse-PQ root and `S` be either the
handshake-derived PQ root seed for epoch zero or one new 32-byte SCKA output
secret. Define the exact 96-byte expansion:

```text
PQ_MATERIAL = HKDF(
  salt = (session_id for epoch zero, otherwise PQROOT),
  IKM  = S,
  info = "layergram/v3/sparse-pq/root\0" || session_id || U64(epoch),
  L    = 96)

next_PQROOT = PQ_MATERIAL[0..31]
CK_i2r      = PQ_MATERIAL[32..63]
CK_r2i      = PQ_MATERIAL[64..95]
```

The initiator sends with `CK_i2r` and receives with `CK_r2i`; the responder
uses the reverse assignment. An SCKA output secret MUST advance the current
epoch by exactly one. Its directional chains are installed even when the
current SCKA message still uses the previous epoch.

For chain counter `N`, derive independently:

```text
PQMK    = HMAC-SHA-256(CK,
          "layergram/v3/sparse-pq/message-key\0" || U64(N))
next_CK = HMAC-SHA-256(CK,
          "layergram/v3/sparse-pq/next-chain-key\0" || U64(N))
```

Counters start at zero. Sending consumes the selected sending chain. Receiving
derives and retains each missing key before the target, indexed by
`(epoch, counter)`, then consumes the target key. At most 50 PQ skipped keys and
two epochs are retained. Expiry uses caller-supplied local time. Moving an SCKA
direction's committed high-water mark backward, skipping an epoch, exceeding a
counter or skipped-key bound, or pruning an epoch still used by either
direction fails closed. A delayed message may still consume a retained chain or
skipped key from an older epoch without lowering that high-water mark. The
committed `TR3` remains unchanged until the complete LMF plaintext and its
candidate snapshot are atomically committed.

Retention uses only locally recorded UTC wall-clock values. The Normal profile
retains newly skipped EC/PQ message keys for 180 days and requires compact
replay/completion proofs to remain for at least 365 days. The Maximum profile
uses 30 and 90 days respectively. Clock rollback blocks retirement; the exact
target also remains ineligible while an unexpired PQ skipped key exists or a
retained PQ receiving chain can still derive it. Sender-declared LMF expiry is
never an authority for deleting local state. Pending sealed inbox frames and
unacknowledged exact-byte outbox entries are bounded but never silently
time-purged. The current evaluator is deliberately non-destructive: only a
future serialized, crash-consistent journal may act on an eligible decision.

Frozen epoch-zero vector for `session_id = 1112...1f20` and
`S = 3132...4f50`:

- `next_PQROOT` =
  `10b41e054ec17f83eae13159a803b5f701da201b4ddec3f64a6061cd8b5c2f21`;
- `CK_i2r` =
  `dbda34bc9dc4e2c1d267fbe402eb2874ae611b68d6e258af16428b1bb217500c`;
- `CK_r2i` =
  `29d77d7b0bb350e7514fb9108cff9bb9e3be604dff1fc5ee5d21a33ea5685073`.

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
complete post-effect state, never a delta. Format 2 intentionally rejects the
never-activated developer-only format 1 snapshot. The fixed header is 528
bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `TR3` |
| 3 | 1 | format version `0x02` |
| 4 | 1 | suite `0x01` |
| 5 | 1 | session role |
| 6 | 1 | lifecycle: active `1`, suspended `2`, rekey-required `3`, broken `4` |
| 7 | 1 | bit 0: remote EC DH public key present; bit 1: EC receiving chain present; all other bits zero |
| 8 | 2 | header length `528` |
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
| 462 | 32 | stable SCKA state-sealing key |
| 494 | 8 | current PQ epoch |
| 502 | 8 | PQ sending epoch |
| 510 | 8 | PQ receiving epoch |
| 518 | 1 | retained PQ epoch count, 1–2 |
| 519 | 1 | retained EC skipped-key count, 0–50 |
| 520 | 1 | retained PQ skipped-key count, 0–50 |
| 521 | 3 | reserved zeros |
| 524 | 4 | opaque native SCKA-state length, 1–196,608 |

The variable sections follow in this exact order:

1. PQ epoch records, ascending and consecutive by epoch;
2. EC skipped keys, ordered by ratchet public key then counter;
3. PQ skipped keys, ordered by epoch then counter;
4. the opaque native SCKA-state export.

The state-sealing key is stable for the session lineage. Session restore and
every candidate transition pass the outer TR3 revision as the backend's exact
expected native revision. A valid older native export therefore cannot be
paired with a newer canonical TR3, and an EC-only diagnostic candidate cannot
be committed by the durable session controller without native validation.

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
retained epoch. Count limits are enforced before allocation. Time expiry uses
the frozen local profile in Section 4.2 and never trusts a peer clock.

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

For every outgoing application or PQ-control message, the same serialized
session coordinator MUST:

1. apply revision compare-and-swap before invoking EC or SCKA state;
2. derive one non-mutating hybrid send candidate and every canonical fragment
   nonce;
3. seal the complete canonical LMF frame set and build the matching AR3 and
   complete post-send TR3 records;
4. persist AR3, TR3, and the exact ordered sealed frame bytes together in one
   encrypted send-journal effect;
5. only after that journal record is durable, materialize those exact bytes in
   the outbox and make them available for export;
6. on retry or restart, return the stored bytes and never rerun the ratchet,
   derive a replacement nonce, or reseal the logical message.

The send-journal record is the outgoing commit point. A crash before its write
leaves the prior ratchet checkpoint authoritative. A crash after that write but
before outbox materialization restores the post-send TR3 and reconstructs the
outbox from the exact stored frame bytes. An ambiguous journal or outbox write
forces controller reconstruction and restore before another transition.

Complete ACK handling uses the reverse durability order: authenticate and merge
the ACK, persist the send effect's completed revision, then update or remove the
outbox materialization. A crash after the completed journal revision cannot
re-export the acknowledged frame set even if an older outbox record is still
present. Partial or unauthenticated ACKs never alter the send journal.

The inactive `V3SessionCommitController` claims its receive journal and, when
durable sending is configured, its send journal and outbox before restore, so
direct lifecycle, mutation, effect/frame-read, or export calls cannot race the
coordinator after the claim. Passing these objects to the controller transfers
exclusive ownership;
production wiring must not retain or expose them for concurrent use while
restore begins. The controller requires a unique active checkpoint for every
session in the encrypted identity/passphrase scope and accepts only application
or PQ-control transitions with the exact local session/routing bindings.
Restore merges incoming and outgoing effects by session revision and requires
one contiguous `checkpoint.revision + 1` chain. A new transition runs only after
its caller-supplied expected revision matches the current committed revision.
The controller updates its in-memory snapshot only after the applicable durable
commit and replay/outbox reconciliation succeed. Once a prepared effect could
have become durable, any error makes that controller fail stopped until fresh
transport stores, journals, and controller restore storage.

The controller validates the canonical TR3 envelope and derives the stored
X25519 public key from its private seed before accepting a checkpoint or
candidate. Its optional backend validator is mandatory for future activation:
without a reviewed implementation authenticating and semantically validating
the opaque native SCKA export, the controller remains research-only. It does not
prove that a caller-supplied hybrid candidate is cryptographically correct by
revision shape alone; the reviewed EC/SCKA transition engines and validator
must supply that proof.

When configured, the same serialized controller also restores the encrypted
AR3 materializer and checkpoint repository before journal replay. After replay,
and after every new incoming or outgoing transition, it:

1. materializes each exact canonical AR3 byte string under `v3:<assembly-id>`;
2. rejects a different AR3 byte string for an already materialized stable ID;
3. derives a direction-bound receipt over the exact AR3 and TR3 byte strings;
4. persists the complete current TR3 plus the cumulative sorted receipt set;
5. exposes the commit/send result only after those writes complete.

Materializer and checkpoint writes have ambiguous outcomes on error and force
fresh controller reconstruction. Restore makes partial progress idempotent: an
already materialized exact AR3 is reused, and the checkpoint repository accepts
only the same revision or a higher snapshot that preserves every prior receipt
and the stable session lineage.

The highest encrypted checkpoint is the durable restore anchor. It may advance
an older caller bootstrap snapshot, or restore a known session without a caller
snapshot, only when its stable lineage and canonical snapshot validate. Journal
effects above that revision still form one contiguous chain. Effects at or
below it are not replayed: their exact direction-bound receipt and independently
materialized AR3 bytes MUST match before they are treated as covered.

Compaction is explicit and serialized by the same coordinator. For an incoming
effect it MUST verify the materialized AR3, exact cumulative receipt, and
current checkpoint, then write a `v3_lmf_replay_v1` entry before deleting the
full inbox tombstone or journal effect. The replay entry retains the complete
ACK/target binding, higher-level effect digest, stable AR3 ID, session, ratchet
revision, and checkpoint digest. Restore prefers it over an exact older
tombstone; a missing journal effect is valid only for such an entry. Malformed
compact replay state is retained and fails closed.
If the compact proof was written but deletion failed, a later cumulative
checkpoint MAY be used to retry collection when it still contains the exact
same direction, assembly, stable record ID, session, ratchet revision, and
state receipt. The proof keeps its original checkpoint digest as evidence of
the earlier write-before-delete boundary.

An outgoing effect is collectable only after its authenticated complete ACK is
durable in the send journal, its outbox entry is absent, and the same AR3/TR3
coverage checks pass. The coordinator MUST write a
`v3_send_completion_v1` proof binding the effect digest, stable record ID,
session, ratchet revision, and checkpoint digest before deleting the full send
effect. On restore every cumulative incoming or outgoing receipt MUST retain
either its exact full journal effect or its corresponding compact proof; losing
both fails closed. Deletion errors with ambiguous durable outcomes force a fresh
restore; that restore uses the checkpoint and never reruns ratchet or AEAD work.
An already durable completion proof remains valid when a later cumulative
checkpoint retains the same immutable receipt.
Direct tombstone/replay purging is rejected after coordinator ownership.
The retention profile and non-destructive eligibility rules are frozen. The
bounded encrypted `v3_session_retirement_v1` journal provides the durable
retirement boundary: `prepared` binds direction,
assembly, proof digest, stable record ID, session, ratchet revision, exact state
receipt, source checkpoint digest, locally recorded proof/preparation times, and
the minimum lifetime used; `checkpointReplaced` is a write-new-before-delete
revision that additionally binds one different canonical replacement checkpoint
digest; `finalCheckpointWritten` binds a self-contained final checkpoint whose
canonical transition also binds the pending checkpoint digest, proof digest,
plan ID, original source digest, and removed receipt. Ambiguous writes and
deletes fail stopped until fresh restore, equal-stage divergence fails closed,
and every restored higher stage must exactly extend its predecessors. Deletion
is authority-gated and accepts only the exact finalized binding.
The single session authority claims and restores this journal from the same
scope-pinned encrypted store. It evaluates the frozen local policy, writes the
prepared plan, then writes a same-revision checkpoint containing a canonical
transition over the exact source checkpoint digest and the one removed receipt,
advances the plan, writes the finalized checkpoint, and advances the final stage
before deleting the exact compact proof and then the exact plan. Restore retains
an interrupted predecessor chain, selects only its unique exact tip, reconciles
any already durable stage, accepts a missing proof only after the final
checkpoint is present, and resumes deletion idempotently. Source cleanup runs
oldest-to-newest and stops on failure, preventing a disconnected surviving
ancestor. One plan may be pending per session during an intermediate boundary;
successful or recovered finalization removes it, so another receipt can be
retired at the same stable ratchet revision with fixed-size latest-transition
metadata. Divergence fails closed at every boundary.

## 10. Remaining activation gates

Before this schedule can carry user messages, Layergram still requires:

- independent cryptographic review of the authenticated hybrid handshake and
  EC Double Ratchet construction;
- a reviewed ML-KEM Braid backend implementing authenticated state
  export/import behind the frozen boundary;
- independent review and production wiring of the inactive crash-consistent
  send/receive coordinator, including the reviewed native-state validator;
- production wiring that preserves the implemented scope-owned initial-session
  and receive-dispatch capability topology and supplies its reviewed native
  SCKA validator/backend;
- active message/UI repository projection from the idempotent durable AR3
  source and fail-closed provider lifecycle ownership are implemented at the
  inactive runtime boundary, but chat send/receive/display routing and reviewed
  deletion/retention UX still require application wiring;
- full packaging, crash, migration, multi-device, passphrase, Maximum-mode,
  text, link, QR, and steganography tests;
- independent protocol and implementation audit with no unresolved high or
  critical findings.

Until those gates pass, this is a developer-only research implementation and
must not be described to users as active quantum-resistant messaging.
