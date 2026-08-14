# Layergram Message Format v3 — Canonical Framing Draft

Status: **normative research draft; inactive; not externally reviewed**

This document freezes the first testable candidate for Layergram protocol-v3
binary framing, text/link armor, steganographic carriage, bounded fragment
reassembly, cumulative acknowledgements, and crash-consistent sealed-frame
storage. It does not enable protocol v3, define the handshake or ratchet key
schedule, or establish a quantum-resistant product claim.

`PROTOCOL_V3_SECURITY_GOALS.md` remains authoritative. This draft must change if
the later handshake, ratchet, persistence design, or external review finds that
the layout cannot meet those goals.

## 1. Scope and non-goals

This checkpoint provides:

- one canonical binary frame;
- AES-256-GCM authentication of every header field and encrypted fragment;
- strict unpadded Base64URL text armor;
- a deep link that prefixes the exact same text token;
- steganographic transport of the exact same binary frame;
- HR3-authenticated, bounded fragmentation and duplicate-aware reassembly;
- a canonical cumulative ACK payload with no ACK-of-ACK loops;
- inactive encrypted inbox/outbox persistence with write-before-delete recovery;
- an inactive atomic-effect journal binding one application/control record and
  its matching ratchet snapshot to the inbox replay tombstone;
- an inactive transcript-bound session expansion, mandatory hybrid EC/PQ
  message schedule, deterministic fragment nonces, and directional ACK
  schedule;
- canonical committed application/control and Triple Ratchet snapshot codecs;
- exact carriage of the canonical EC+SCKA `HR3` on fragment zero, with its
  length and digest authenticated on every continuation fragment;
- public golden and adversarial parser tests.

It deliberately does not provide:

- the authenticated handshake transcript or sender proof;
- a production ML-KEM Braid transition engine;
- sender proof of possession or contact authentication;
- reviewed native ML-KEM Braid state export/import;
- atomicity for side effects written outside the v3 effect journal;
- resend scheduling, erasure coding, notification, or progress UI;
- erasure coding;
- activation in identity, contact, messaging, UI, storage, or Premium paths.

## 2. Integer and canonicalization rules

- All multi-byte integers use unsigned network byte order (big endian).
- The base header has fixed length. Application/control fragment zero appends
  exactly one canonical length-prefixed `HR3`; continuation fragments bind it
  by the same declared length and digest without repeating it.
- Empty ciphertexts, all-zero routing bindings/IDs, unknown values, non-zero
  flags, trailing bytes, shortened bytes, and alternative fragmentation fail
  closed.
- A decoder must validate the outer length and fixed header before copying large
  fields or invoking cryptography.
- Re-encoding a decoded binary, token, or link must reproduce the exact input.

## 3. Registry

### 3.1 Suite

| ID | Candidate suite |
|---:|---|
| `0x01` | hybrid X25519 + ML-KEM-768 session, AES-256-GCM frame protection |

The suite ID reserves framing semantics only. The hybrid KDF and ratchet are not
defined by this document.

### 3.2 Frame kind

| ID | Kind |
|---:|---|
| `0x01` | handshake |
| `0x02` | application |
| `0x03` | sparse PQ-ratchet material |
| `0x04` | acknowledgement |

Registering a kind does not enable its state transition.

### 3.3 Flags

No flag is assigned. The flags byte must be zero.

## 4. Canonical binary frame

The fixed base header is exactly 180 bytes:

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 3 | magic | ASCII `LM3` |
| 3 | 1 | protocol version | `0x03` |
| 4 | 1 | suite | registered value |
| 5 | 1 | frame kind | registered value |
| 6 | 1 | flags | zero |
| 7 | 1 | header length | `0xB4` (180) |
| 8 | 2 | ciphertext length | 1–16,384 |
| 10 | 32 | sender binding | non-zero opaque context binding |
| 42 | 32 | recipient binding | non-zero opaque context binding |
| 74 | 16 | message ID | non-zero, unique in its context |
| 90 | 16 | session ID | non-zero |
| 106 | 8 | epoch | authenticated value, 0–2^63−1 |
| 114 | 8 | message counter | 0–2^63−1 in this candidate |
| 122 | 4 | expiry | Unix seconds; zero means no sender-declared expiry |
| 126 | 2 | fragment index | zero based |
| 128 | 2 | fragment count | 1–64 |
| 130 | 4 | final plaintext length | 1–16,384 |
| 134 | 12 | AES-GCM nonce | unique for the session key |
| 146 | 2 | total HR3 length | `0` or canonical `96–608` |
| 148 | 32 | HR3 digest | zero iff length is zero |
| 180 | H | canonical HR3 | exact bytes only on fragment zero |
| 180+H | N | ciphertext fragment | length declared at offset 8 |
| 180+H+N | 16 | AES-GCM tag | full, untruncated tag |

The minimum frame is 197 bytes. A headerless single frame can be at most 16,580
bytes. A canonical application/control frame carrying the maximum 608-byte HR3
is capped at 828 bytes so its minimum-cover steganographic encoding stays below
the 4,000-character portable target.

Application and sparse-PQ control frames require one HR3. Its SCKA epoch and
message counter must exactly match the LMF epoch and message counter. Handshake
and ACK frames require zero HR3 length and an all-zero HR3 digest.

The 32-byte sender and recipient values are routing/context bindings, not public
identity IDs and not proof of an owner's identity. Their derivation must be
defined by the reviewed handshake and must bind the complete identities in the
session transcript. This draft does not authorize using truncated public keys
or treating these fields as contact verification.

The authenticated expiry is sender policy input, not a trusted timestamp.
Layergram has no shared trusted clock. Parsing alone must not discard a message
because of clock interpretation.

## 5. AEAD boundary

Each fragment uses AES-256-GCM with:

- a 32-byte key supplied by the future handshake/ratchet layer;
- the exact 180-byte canonical base header as associated authenticated data;
- on fragment zero, the exact canonical HR3 bytes appended to that data;
- the 12-byte nonce from the header;
- the encrypted fragment as ciphertext;
- the final 16 bytes as the authentication tag.

This binds the suite, kind, flags, routing bindings, message/session IDs, epoch,
message counter, expiry, fragment index/count, final assembled length, nonce,
fragment length, HR3 length, and domain-separated HR3 digest. Fragment zero
also authenticates the exact HR3 bytes. Header, HR3, ciphertext, and tag
tampering must fail before any partial application content is exposed.

`PROTOCOL_V3_KEY_SCHEDULE.md` now derives one hybrid message key from mandatory
EC and sparse-PQ message keys, plus a distinct deterministic nonce for every
canonical fragment shape. The receiver must rederive and compare the message ID
and nonce before committing the ratchet transition. The framing API still
requires the nonce explicitly and rejects duplicates within one locally sealed
fragment set; callers outside the v3 schedule receive no session-wide safety
claim.

The implemented EC transition engine and SCKA boundary produce the canonical
`HR3` container holding the 56-byte `DR3` header and bounded `SK3` message.
This draft carries and authenticates that exact container. Activation still
requires a reviewed native SCKA engine and one serialized controller that binds
the accepted ratchet candidate to the atomic application effect.

## 6. Canonical fragmentation

Single-frame messages use:

- fragment index `0`;
- fragment count `1`;
- ciphertext length equal to final plaintext length.

Headerless multi-frame messages use a 256-byte plaintext fragment size.
Application/control messages use an adaptive first fragment:

```text
firstCapacity = min(256, 828 - 180 - HR3_length - 16)
fragment[0] = min(finalPlaintextLength, firstCapacity)
fragment[n>0] = min(remaining, 256)
```

The maximum 608-byte HR3 leaves 24 plaintext bytes in fragment zero; later
fragments remain 256 bytes. That layout permits at most 16,152 assembled bytes
with 64 fragments. A shorter HR3 may retain the full 16,384-byte global limit.
Alternative splits, gaps, overlaps, empty fragments, counts above 64, or lengths
outside the derived layout are non-canonical and rejected.

Every fragment is authenticated independently. The receiver authenticates a
frame before placing its plaintext into the private reassembly buffer. It
returns no fragment plaintext to the caller. Only a complete, gap-free set
returns the assembled plaintext.

Reassembly is keyed by suite, kind, both routing bindings, message ID, and
session ID. All other authenticated metadata must match the first accepted
fragment, including HR3 length and digest. An exact duplicate is ignored. An authenticated duplicate with
different content, or contradictory authenticated metadata, wipes and rejects
the pending assembly.

The reference implementation defaults to at most 8 pending assemblies and
64 KiB of buffered fragment plaintext, refuses new work instead of silently
evicting valid state, allocates the final buffer only after every fragment is
present, and best-effort wipes discarded managed buffers.

Retention cleanup is explicit rather than time-assumed: legitimate manual
transport can take days or weeks, and Layergram has no trusted shared clock.
The durable inbox stores the exact sealed frame through the encrypted auxiliary
record repository before authenticating or passing it to this in-memory
reassembler. A caller that uses the reassembler directly has no persistence
guarantee.

A continuation fragment may arrive before fragment zero. The durable inbox
retains its exact sealed bytes, while the inactive session key resolver returns
no guessed key until it has the HR3 and corresponding EC+Sparse-PQ candidate.
It then resumes deferred records and verifies every deterministic nonce and HR3
binding. If AEAD rejects a deferred fragment zero, the inbox notifies the
resolver so its uncommitted session candidate is wiped; a continuation failure
does not discard a candidate whose authenticated fragment zero remains valid.
No plaintext or ratchet transition is committed before the complete set
authenticates and the atomic effect is durable.

This candidate uses retransmission, not erasure coding. Loss therefore leaves
an assembly incomplete until the missing authenticated frame is supplied.

## 7. Cumulative ACK and durable delivery candidate

### 7.1 Canonical ACK plaintext

An acknowledgement is exactly 52 plaintext bytes carried inside a separately
authenticated, single-fragment LMF frame of kind `0x04`:

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 3 | magic | ASCII `AK3` |
| 3 | 1 | ACK format version | `0x02` |
| 4 | 1 | target suite | registered value |
| 5 | 1 | target kind | handshake, application, or PQ-ratchet; never ACK |
| 6 | 1 | flags | zero |
| 7 | 1 | target fragment count | 1–64 |
| 8 | 16 | target message ID | non-zero |
| 24 | 8 | target epoch | exact authenticated target value |
| 32 | 8 | target message counter | 0–2^63−1 |
| 40 | 4 | target final plaintext length | 1–16,384 |
| 44 | 8 | received bitmap | bit `n` acknowledges fragment `n` |

The bitmap is cumulative, non-empty, and has no set bits beyond the target
fragment count. The ACK envelope MUST use the target suite and session ID and
MUST reverse the target sender/recipient routing bindings. Its key and nonce
come from the direction-specific ACK root and exact visible header context in
`PROTOCOL_V3_KEY_SCHEDULE.md`; every newly sealed cumulative ACK requires a
fresh message ID. ACK frames are never acknowledged; loss of an ACK can
therefore cause a safe exact-byte duplicate resend but cannot create an
ACK-of-ACK loop.

`AK3` deliberately omits the target HR3 length and digest to preserve this
single compact fixed-size payload. A fragmented handshake target is headerless,
so its fragment count is derived and checked directly from the final plaintext
length; a canonical headerless single frame may instead carry the full bounded
plaintext. For application and PQ-ratchet targets, the adaptive fragment count
is accepted only from an already canonical set of authenticated LMF frames. On
receipt, an authenticated ACK can update durable state only when suite, kind,
message ID, epoch, message counter, final length, fragment count, session, and
reversed routing bindings exactly match one local outbox entry. An ACK therefore
does not independently prove the target HR3 or honest receipt by a malicious
peer.

### 7.2 Inbox commit order

The inactive durable inbox performs these steps in order:

1. persist the exact still-sealed canonical frame in an outer-encrypted local
   auxiliary record;
2. authenticate it and privately reassemble only a complete set;
3. return a complete delivery at least once;
4. invoke the higher-level effect builder only if no effect for the assembly ID
   is already durable;
5. persist one outer-encrypted journal record containing both the canonical
   application/control record and its matching complete ratchet snapshot;
6. persist an encrypted complete-ACK replay tombstone bound to the journal
   effect digest;
7. delete obsolete sealed-frame records.

The journal record in step 5 is the higher-level commit point. A crash before it
can redeliver the complete plaintext. A crash after it but before step 6 restores
the already-built effect, does not advance the ratchet again, and finishes only
the bound tombstone. A crash after step 6 suppresses redelivery even if frame
cleanup did not finish. On restore, a tombstone with an effect digest but no
matching journal record, a journal effect paired with an unbound tombstone, or
any digest mismatch is a fail-closed persistence conflict.

Within this inactive boundary, the stable application record ID is derived from
the assembly ID, so replay cannot allocate a second record. Exactly-once effects
outside the journal are still not claimed: future message/UI repositories must
read the journal as their source of truth or materialize its record idempotently
under that stable ID. The inactive canonical `AR3` and `TR3` codecs now provide
the exact journal byte strings. The inactive receive-commit controller claims
the journal before restore, validates AR3/TR3/session/routing bindings, and
applies revision CAS before its candidate builder runs. The inactive resolver
now binds an exact candidate snapshot into that controller after complete LMF
authentication. A clean commit failure is retryable only while the controller
still exposes the candidate's expected revision; a concurrently superseded
candidate is wiped instead of being requeued. Reviewed native SCKA semantics,
durable sending, crash-window reconciliation, and external materialization
remain activation gates.

Commit-tombstone retention is local and explicit. A tombstone may be purged only
after the durable ratchet/application replay window will independently reject
the corresponding old message; a peer-supplied timestamp never authorizes it.

No partial fragment plaintext is returned or persisted. Competing
unauthenticated bytes are removed alone. Two different authenticated fragments
for the same assembly index wipe and reject the pending assembly.

### 7.3 Outbox and resend order

The inactive durable outbox persists a complete canonical set of exact sealed
frames before first export. When attached to the session coordinator it is a
materialized view of the send journal, whose single effect binds the exact
sealed frame set, canonical outgoing AR3 record, prior ratchet revision, and
complete post-send TR3 snapshot. Restore selects the highest valid revision,
rejects conflicting copies at the same revision, merges incoming and outgoing
transitions into one contiguous per-session revision chain, and recreates a
missing outbox entry from the journal without resealing. A resend returns the
same sealed bytes; it never re-encrypts a fragment or derives policy from a
remote clock.

The outbox and send journal transfer exclusive ownership to the coordinator
before restore. Direct lifecycle, mutation, or frame-read calls are rejected
after the claim. A complete authenticated ACK is first committed as the send
journal's next local record revision and only then may its outbox materialization
be removed. Restart suppresses and cleans a stale outbox copy when that durable
completed revision already exists. Unauthenticated ACK rejection happens before
any persistence attempt and therefore does not poison a clean retry.

The reference defaults bound the inbox to 256 sealed frame records, 128 KiB of
sealed frame bytes, 4,096 commit tombstones, and 8,192 relevant physical
records. The atomic-effect journal is bounded to 4,096 effects, 17 KiB per
encoded application record (including its 192-byte header), 256 KiB per ratchet
snapshot, 16 MiB total decoded state,
and 8,192 relevant physical records. The outbox is bounded to 64 logical
entries, 512 KiB of sealed frame bytes, and 256 physical revisions. The send
journal is bounded to 4,096 effects, 17 KiB per AR3 record, 256 KiB per TR3
snapshot, 512 KiB of sealed frames per effect, 32 MiB total retained state, and
8,192 relevant physical records. Reassembly retains its separate limits of 8
pending assemblies and 64 KiB of authenticated plaintext. Limit breaches fail
closed without silently evicting valid state.

All records use Layergram's existing padded, outer-encrypted auxiliary-record
storage under the active identity/passphrase scope. The record kind, assembly
ID, ACK state, effect digest, application state, ratchet snapshot, frame bytes,
and timestamps are not global cleartext markers.

### 7.4 Atomic-effect record invariants

The journal record is keyed logically by the assembly ID and binds:

- a domain-separated digest of the complete ordered sealed-frame set;
- the exact representative target frame;
- independently versioned application/control and ratchet-state byte strings;
- their lengths and a domain-separated effect digest;
- the local persistence time.

The builder receives a temporary copy of the complete plaintext. The copy is
wiped after the builder returns or throws. A restored effect bypasses the
builder entirely. ACK frames never create journal effects. Malformed or
conflicting effect records are retained and fail closed; only byte-identical
duplicates may be cleaned. If the effect-store API reports an error after the
durable outcome has become ambiguous, that journal instance fails stopped: a
new instance must restore storage before any builder may run again. Once a
journal is attached to an inbox, transport-only tombstones are rejected; a
pre-existing unbound tombstone also rejects journal commit before the builder
can observe the already-consumed delivery.

Effect-journal garbage collection is deliberately not defined yet. Activation
requires a ratchet checkpoint/compaction rule that proves both application
history and the replay window remain durable before an effect or its bound
tombstone can be removed.

### 7.5 Session-controller restore and commit invariants

One inactive controller owns one journal for an encrypted identity/passphrase
scope. It claims an unforgeable in-memory journal authority before journal
restore; after that claim, direct `restore`, `commit`, `resume`, or `close`
calls without the exact authority fail before reading plaintext or changing
state. Passing a journal to the controller transfers its ownership: callers
MUST NOT retain it for concurrent direct use while controller restore begins,
and production wiring MUST keep that journal private to the controller. The
caller supplies a unique active checkpoint for every session represented by
the journal.

For each durable effect, the controller decodes canonical AR3 and TR3 bytes,
requires the exact target assembly/session/message/routing/epoch/counter and
content length, and reconstructs a strictly contiguous TR3 revision chain from
the registered checkpoint. Stable role, transcript, routing bindings, ACK
roots, active lifecycle, and X25519 private/public consistency cannot change.
Application and PQ-control deliveries must use the inbound routing direction
for the local role and carry HR3 on fragment zero.

New commits are serialized and compare the caller's expected revision before
the transition builder runs. The builder sees only temporary plaintext and a
detached current snapshot. Its candidate must advance exactly one revision and
pass the same stable-session and snapshot validation. In-memory state advances
only after the journal effect and bound inbox tombstone both complete. If an
error occurs after a complete candidate is prepared, the controller fails
stopped even when the exact persistence outcome is unknown. A fresh restore
selects the durable truth and may resume only the missing tombstone without
running the builder or advancing the ratchet again.

The optional semantic snapshot validator is required at activation to invoke
the reviewed native SCKA backend. The current controller alone does not prove
that arbitrary caller-supplied EC/PQ candidate fields implement the specified
cryptographic transition, and it does not define sending or external
application materialization.

### 7.6 ACK golden vector

For target suite `0x01`, kind `0x01`, five fragments, message ID `81 82 ...
90`, epoch `7`, counter `9`, final length `1,088`, and received indexes `0, 2,
4`, the canonical 52-byte ACK plaintext is:

```text
414b3302010100058182838485868788898a8b8c8d8e8f9000000000000000070000000000000009000004401500000000000000
```

## 8. Three transports, one binary meaning

### 8.1 Direct text

```text
m3.<unpadded Base64URL(canonical binary frame)>
```

Only ASCII letters, digits, `-`, and `_` are valid after `m3.`. Padding `=`,
whitespace, alternate alphabets, and non-round-tripping forms are rejected.

### 8.2 Deep link

```text
layergram://m/m3.<same text token>
```

User info, ports, queries, fragments, extra path segments, and alternate
serialization are rejected. The link adds a prefix; it is not a different
protocol. Total link length is capped before URI parsing.

### 8.3 Steganography

The existing hardened Layergram payload alphabet maps the exact binary frame to
four zero-width payload runes per byte and may interleave only the documented
noise runes. The v3 decoder caps input before collecting payload runes, rejects
forbidden U+200E/U+200F, requires a whole number of bytes, and then invokes the
same strict binary parser.

The current conservative portable-share target is 4,000 total characters.
Channel-specific adapters may impose a smaller limit and must preflight the
final frame, not an estimate of the user's plaintext.

For a headerless 256-byte encrypted fragment:

- canonical frame: 452 bytes;
- minimum visible steganographic cover: 177 carrier-safe ASCII characters;
- minimum encoded steganographic length under current noise rules: 2,211
  characters.

For a maximum 608-byte HR3, fragment zero carries 24 plaintext bytes and is 828
binary bytes. It needs at least 271 visible carrier-safe characters and encodes
to 3,997 characters under the current minimum-cover rules. Continuations carry
only the authenticated HR3 length/digest and use the normal 452-byte bound.

For a headerless ML-KEM-768 ciphertext of 1,088 bytes, canonical fragmentation
produces four 452-byte frames and one 260-byte frame. All five fit the 4,000-character
candidate target in text, link, and minimum-cover steganographic form. This is a
codec result, not proof that WhatsApp, Telegram, Signal, or iMessage preserves
the payload; real transport tests remain an activation gate.

## 9. Frame golden vector

Inputs:

- suite `0x01`, kind `0x01`, flags `0`;
- sender binding `01 02 ... 20`;
- recipient binding `41 42 ... 60`;
- message ID `81 82 ... 90`;
- session ID `a1 a2 ... b0`;
- epoch `7`, counter `9`, expiry `2000000000`;
- fragment index `0`, count `1`, final length `25`;
- nonce `a0 a1 ... ab`;
- AES key `00 01 ... 1f`;
- plaintext UTF-8 `Layergram v3 golden frame`.

Canonical binary hex:

```text
4c4d3303010100b400190102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f204142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f608182838485868788898a8b8c8d8e8f90a1a2a3a4a5a6a7a8a9aaabacadaeafb000000000000000070000000000000009773594000000000100000019a0a1a2a3a4a5a6a7a8a9aaab00000000000000000000000000000000000000000000000000000000000000000000aa79054837ac70de0f45f1e0271dafb214c93730f4c52301f9cd648176ad87cc84dc532cbecb164569
```

Canonical direct token:

```text
m3.TE0zAwEBALQAGQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2CBgoOEhYaHiImKi4yNjo-QoaKjpKWmp6ipqqusra6vsAAAAAAAAAAHAAAAAAAAAAl3NZQAAAAAAQAAABmgoaKjpKWmp6ipqqsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqnkFSDescN4PRfHgJx2vshTJNzD0xSMB-c1kgXath8yE3FMsvssWRWk
```

## 10. Activation boundary

The implementation lives only under `lib/core/crypto/v3/`. Protocol v2 remains
active. Nothing in this draft or codec changes identity import, message send,
message decode, contact state, backups, migration, QR, UI, or Premium capability
contracts.

Before activation, the native ML-KEM Braid engine must produce and consume the
frozen message/state formats and validate every opaque export; the inactive
crash-consistent send/receive coordinator and its recovery paths must pass
independent review and production wiring; the application repository must use
the atomic journals as its source of truth; checkpoint and garbage-collection
rules must be frozen;
resend/progress UX and real loss recovery must pass; all three transports must
pass real cross-app tests; and the complete design and implementation must pass
independent review.
