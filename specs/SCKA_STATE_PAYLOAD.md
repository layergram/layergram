# Layergram ML-KEM Braid state payload revision 1

Status: **canonical internal payload frozen and used by private transitions
1-13; engineering candidate ABI connected, default ABI `NOT_READY`, no
production application registration; protocol v3 inactive**

This document freezes the plaintext state-machine representation carried inside
the authenticated `LS3` envelope defined by `SCKA_NATIVE_ABI.md`. The Apache-2.0
implementation is `native/layergram_scka/src/braid_state_payload.rs`.

The state names and required values follow Signal's public-domain [ML-KEM Braid
revision-1 specification](https://signal.org/docs/specifications/mlkembraid/).
No source from Signal's AGPL implementation was copied, adapted, linked, or
embedded. The codec introduces no dependency and is suitable for the public
Layergram base that is merged into the separately distributed paid Premium
application.

The private authenticated composition implements `Send` and `Receive` across
transitions 1-13 and uses the private OS-entropy boundary where required. The
explicit `candidate-ffi` build connects those operations to the frozen C ABI
for exact-build-allowlisted Dart integration tests. The default build continues
to return `NOT_READY`. The candidate build is packaged only by opt-in generated
smoke scripts and loaded through the persistence scope; neither build is
registered or loaded by ordinary application bootstrap.

## 1. Authenticated composition

`LB3` is not independently authenticated. It may be decoded only after `LS3`
has authenticated successfully. The decoder receives the authenticated outer
metadata and requires exact equality with the duplicate inner role, session
ID, state revision, sending-epoch high-water value, and receiving-epoch
high-water value.

The duplication is deliberate. A future transition must:

1. authenticate and open `LS3`;
2. decode `LB3` against the metadata returned by that exact open operation;
3. build one immutable candidate state;
4. seal that candidate once with nonce-misuse-resistant AES-256-GCM-SIV and the injective
   `"LN3" || role_u8 || state_revision_u64_be` nonce; and
5. atomically commit it with the matching TR3 revision and application effect.

Parsing raw `LB3` bytes without the authenticated outer envelope provides no
integrity guarantee.

## 2. Canonical common header

All integers are unsigned big-endian. Revisions and epochs use the signed-63
domain `0..2^63-1`. The internal Braid epoch is `1..2^63-1`. Revision-1
outputs make each persisted high-water value either `epoch - 2` or `epoch - 1`
(with zero as the floor), with stricter variant rules below.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `LB3` |
| 3 | 1 | payload format `0x01` |
| 4 | 1 | suite `0x01` / ML-KEM-768 |
| 5 | 1 | stable role: initiator `0x01`, responder `0x02` |
| 6 | 1 | state variant `1..11` |
| 7 | 1 | flags, zero |
| 8 | 2 | header length, exactly `136` |
| 10 | 2 | ML-KEM Braid revision, exactly `1` |
| 12 | 4 | exact total payload length |
| 16 | 16 | exact non-zero stable session ID from `LS3` |
| 32 | 8 | exact native state revision from `LS3` |
| 40 | 8 | current internal Braid epoch, non-zero |
| 48 | 8 | exact sending-epoch high-water from `LS3` |
| 56 | 8 | exact receiving-epoch high-water from `LS3` |
| 64 | 32 | ratcheted authenticator root key |
| 96 | 32 | ratcheted authenticator MAC key |
| 128 | 4 | exact variant-body length |
| 132 | 4 | reserved zeros |
| 136 | N | exact variant body |

The shortest payload is 136 bytes. The largest valid revision-1 payload is
4,434 bytes. The broader 196,512-byte `LS3` plaintext ceiling remains an ABI
envelope bound, but this decoder rejects any `LB3` value above its exact,
smaller bound before parsing.

The initiator is the encapsulation-key sender in odd epochs and the receiver in
even epochs. The responder has the inverse role. A variant on the wrong side of
the state machine is rejected.

High-water values represent the most recent values returned by local `Send`
and `Receive` operations. Let `high = epoch - 1` and
`low = max(0, epoch - 2)`. `KeysUnsampled` requires `(sending, receiving) =
(low, high)`. `NoHeaderReceived` permits each value independently in
`{low, high}` because no-data sends or receives can catch up either side.
`HeaderReceived` requires receiving `high` and permits sending `low` or `high`.
Every other variant requires both values to be `high`. At epoch 1, `low` and
`high` are both zero.

## 3. Primitive blocks

The following sizes are frozen by `SCKA_INCREMENTAL_MLKEM.md`:

| Name | Bytes | Contents |
|---|---:|---|
| `private_key` | 2,400 | compressed ML-KEM-768 decapsulation key, including its bound public key |
| `pk1` | 64 | encapsulation-key seed and full-key hash |
| `pk2` | 1,152 | encapsulation-key vector |
| `encaps_state` | 2,080 | version-locked libcrux incremental continuation |
| `ct1` | 960 | ciphertext part one |
| `ct2` | 128 | ciphertext part two |
| `mac` | 32 | HMAC-SHA256 result selected for Layergram revision 1 |

Every stored private key passes the primitive's private-key hash validation and
the embedded `pk1`/`pk2` public-key validation before acceptance. Whenever a
body contains both a pending `pk1` and received `pk2`, their full public-key
relationship is also validated.

`pending` is the exact concatenation `pk1 || encaps_state || ct1` (3,104
bytes). It deliberately excludes the raw `Encaps1` shared secret: transition 7
must derive the epoch key and update the authenticator before converting the
transient primitive result into this persisted form.

The opaque `encaps_state` is tied to libcrux-ml-kem 0.0.10 and payload format 1.
The primitive does not expose a semantic validator for those opaque bytes.
Their integrity therefore relies on creation through the typed incremental
API and authentication by `LS3`; a dependency or serialized-continuation
change requires a new payload-format migration decision.

## 4. Encoder and decoder progress

An encoder is persisted only as a two-byte `next_index`, because its complete
source value is already present elsewhere in the variant body. Values
`0..65534` identify the next wire symbol. `65535` is never emitted and is the
sole canonical exhausted marker. Variants created by a send that already
emitted their first symbol require `next_index >= 1`.

A decoder is encoded as:

| Bytes | Field |
|---:|---|
| 2 | distinct chunk count `c` |
| `34*c` | canonical chunks from `SCKA_ERASURE_CODE.md` |

Chunks are strictly sorted by encoding index, unique, and bounded to
`0..65534`. A persisted decoder is always incomplete, so `c < k` for its exact
payload class. State-specific transitions that necessarily consumed a first
chunk require `c >= 1`. No allocation occurs before count, exact length,
ordering, index, and state-specific bounds are checked.

## 5. Exact state variants

Fields are concatenated in the order shown. `decoder(X)` uses the exact source
chunk count of payload class `X`.

| ID | Variant | Exact body |
|---:|---|---|
| 1 | `KeysUnsampled` | empty |
| 2 | `KeysSampled` | `private_key || header_mac || header_next_index` |
| 3 | `HeaderSent` | `private_key || ek_next_index || decoder(ct1)` |
| 4 | `Ct1Received` | `private_key || ct1 || ek_next_index` |
| 5 | `EkSentCt1Received` | `private_key || ct1 || decoder(ct2 || mac)` |
| 6 | `NoHeaderReceived` | `decoder(header || mac)` |
| 7 | `HeaderReceived` | `pk1 || empty decoder(pk2)` |
| 8 | `Ct1Sampled` | `pending || ct1_next_index || decoder(pk2)` |
| 9 | `EkReceivedCt1Sampled` | `pending || pk2 || ct1_next_index` |
| 10 | `Ct1Acknowledged` | `pending || decoder(pk2)` |
| 11 | `Ct2Sampled` | `ct2 || mac || ct2_next_index` |

`KeysSampled`, `Ct1Sampled`, and `EkReceivedCt1Sampled` require an encoder
index of at least 1. `HeaderSent` and `EkSentCt1Received` require at least one
decoder chunk. `Ct1Acknowledged` also requires at least one `pk2` chunk.
`HeaderReceived` requires its prepared `pk2` decoder to be empty.

Every field has one position and one exact length; unknown variants, flags,
padding, trailing bytes, alternate chunk order, complete decoder states, and
reserved values fail closed.

## 6. Secret lifetime and remaining gates

The owned decoded payload implements neither `Clone` nor `Debug` and wipes its
complete byte buffer on drop. Temporary private-key validation owners and
rejected private keys are also wiped on ordinary Rust error paths. This is
best-effort native hygiene, not a guarantee about registers, allocator history,
crash dumps, or upstream temporaries.

Tests cover all 11 variants, exact round trips, metadata mismatch, role/epoch
parity, signed-63 boundaries, private/public-key corruption, malformed lengths,
reserved fields, decoder ordering/duplication/completion, impossible progress,
and the explicit wipe path.

Activation still requires the complete revision-1 transition engine,
integration and review of the ratcheted authenticator and KDF frozen in
`SCKA_AUTHENTICATOR.md` and the public-message codec frozen in
`SCKA_PUBLIC_MESSAGE.md`, approved OS entropy, authenticated reconstruction,
cross-implementation vectors, fuzzing and sanitizers,
panic containment, crash/restart/rollback/concurrency tests, packaged physical
device traversal, and independent cryptographic and implementation review.
