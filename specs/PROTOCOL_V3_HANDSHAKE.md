# Layergram Protocol v3 — Authenticated Hybrid Handshake Draft

Status: **normative research draft; inactive; not externally reviewed**

This document freezes a falsifiable three-message handshake candidate for the
inactive Layergram protocol v3. It does not enable protocol v3 and it is not a
claim that the construction has passed independent cryptographic review.

`PROTOCOL_V3_SECURITY_GOALS.md` remains authoritative. This construction must
change, or remain disabled, if external review finds that its authentication,
deniability, key-compromise, KEM, transcript, or state-machine properties are
insufficient.

Primary references:

- [NIST FIPS 203, ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [RFC 7748, X25519](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 5869, HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/)
- [Signal Double Ratchet and Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/)

PQXDH is an important design reference, but it assumes asynchronously
published prekeys and a server. Layergram has neither. The candidate below is
therefore an interactive, no-server protocol and must not be described as a
PQXDH implementation.

## 1. Scope and activation boundary

This checkpoint defines and implements:

- stable initiator and responder roles;
- complete identity, device, mode, capability, record, and message binding;
- fresh X25519 and ML-KEM contributions from both participants;
- responder and initiator key confirmation derived from both branches;
- a final SHA-384 transcript accepted identically by both participants;
- handoff to the mandatory hybrid session key schedule;
- fixed canonical `offer`, `reply`, and `confirmation` records;
- canonical pending-state records for encrypted restart persistence;
- an inactive, bounded Aux-backed pending repository and single-authority
  controller with persist-before-export retry and completion tombstones;
- deterministic resolution of simultaneous crossed offers;
- fixed size bounds, public codec vectors, negative tests, and native-backend
  integration tests.

It deliberately does not define or enable:

- the outer bootstrap encryption and LMF key-resolution mechanism;
- the active contact/device coordinator, expiry, acknowledgement UI, or
  garbage collection;
- Maximum-mode device-pin policy or Normal-mode device caps;
- a production/reviewed ML-KEM Braid transition backend;
- application-content activation, migration, backup, Premium wiring, or UI;
- a third-party-verifiable signature or a non-repudiation claim.

All implementation remains isolated under `lib/core/crypto/v3/`. The inactive
session-persistence scope constructs the repository, but no active v2 provider,
identity, contact, message, UI, backup, or Premium seam imports it.

## 2. Participants and keys

The stable roles are:

- `A`: initiator;
- `B`: responder.

Each participant has:

- `IK`: the 32-byte X25519 identity key in the complete v3 public identity;
- `PQIK`: the 1,184-byte ML-KEM-768 encapsulation key in that identity;
- `DK`: a fresh-per-installation 32-byte X25519 device key;
- `DID`: the 16-byte deterministic device identifier below;
- `EK`: one fresh 32-byte X25519 handshake-ephemeral key;
- `RK`: one fresh 32-byte X25519 initial Double Ratchet key.

The device key is not derived from BIP39. A second device or reinstall must
create a new random device seed. Future integration must store that seed only
inside the same identity/passphrase-scoped encrypted local boundary as other
secret state.

```text
DID = first16(SHA-256(
  "layergram/v3/device/id\0" || Encode(DK)))
```

Every local handshake first recomputes `IK_pub` from the retained private seed
and compares it with the complete local public identity. A mismatch, a closed
private handle, an ML-KEM backend self-test failure, or an invalid ML-KEM
public key fails closed before encapsulation or decapsulation.

## 3. Modes and capabilities

Modes are fixed for the complete run:

| Wire ID | Mode |
|---:|---|
| `0x01` | Normal, future independently authenticated per-device sessions |
| `0x02` | Maximum, future explicitly pinned device pair |

The first candidate accepts exactly capability mask `0x0000001f`:

| Bit | Required capability |
|---:|---|
| 0 | canonical fragmented transport |
| 1 | cumulative authenticated acknowledgement |
| 2 | EC Double Ratchet |
| 3 | ML-KEM Braid / sparse PQ ratchet |
| 4 | independently authenticated multi-device session model |

There is no negotiation to a smaller set. Unknown, missing, or changed bits
fail closed. Future extensions require a separately reviewed versioning rule.

## 4. Canonical notation

- Integers are unsigned big endian.
- `U32(x)` is a four-byte encoding.
- `H384(x)` is SHA-384.
- `HKDF(salt, IKM, info, L)` is RFC 5869 HKDF-SHA-256.
- `HMAC(k, x)` is HMAC-SHA-256.
- Every literal label includes the final NUL byte shown as `\0`.
- `ID_A` and `ID_B` are the complete canonical identity binding bytes, not
  only a fingerprint or display label.
- `SS_AB` is the result of A encapsulating to `PQIK_B` and B decapsulating.
- `SS_BA` is the result of B encapsulating to `PQIK_A` and A decapsulating.
- An all-zero, missing, malformed, ambiguous, or wrong-length secret fails.

The transcript base is:

```text
BASE = "layergram/v3/handshake/transcript\0"
       || U32(len(ID_A)) || ID_A
       || U32(len(ID_B)) || ID_B
```

Each appended record is encoded as `U32(length) || canonical_record`.

## 5. Three-message flow

### 5.1 Offer: A to B

A generates `EK_A`, encapsulates to `PQIK_B`, and retains `EK_A_priv` and
`SS_AB` in encrypted pending state. The offer contains both complete-identity
digests, A's device material, `EK_A_pub`, and the 1,088-byte ML-KEM ciphertext.

The handshake and offer message identifiers are deterministic hashes of all
fresh offer material, identities, mode, and capabilities. They are collision
bindings, not secret authentication tags.

B applies the strict codec, identity/mode/capability checks, ML-KEM public-key
validation, resource limits, and simultaneous-offer policy before expensive
processing. The offer alone does not authenticate A and never activates or
displays user content.

### 5.2 Reply: B to A

B decapsulates `SS_AB`, generates `EK_B` and `RK_B`, encapsulates to `PQIK_A`
to obtain `(CT_BA, SS_BA)`, and builds the reply body without its final proof.

```text
T1 = H384(BASE
     || U32(len(OFFER)) || OFFER
     || U32(len(REPLY_BODY)) || REPLY_BODY)
```

The five ordered classical outputs are:

```text
DH1 = X25519(IK_A, DK_B)
DH2 = X25519(DK_A, IK_B)
DH3 = X25519(EK_A, DK_B)
DH4 = X25519(DK_A, EK_B)
DH5 = X25519(EK_A, EK_B)
```

Both sides must compute exactly this role-stable order. Any all-zero X25519
output is rejected.

```text
CS = HKDF(
  salt = T1,
  IKM  = DH1 || DH2 || DH3 || DH4 || DH5,
  info = "layergram/v3/handshake/classical-secret\0",
  L    = 32)

PS = HKDF(
  salt = T1,
  IKM  = SS_AB || SS_BA,
  info = "layergram/v3/handshake/post-quantum-secret\0",
  L    = 32)
```

The responder proof is computed by the hybrid proof schedule in section 6
using `T1`. It proves to A that the responder produced all required classical
and ML-KEM contributions, including decapsulation under B's imported PQ
identity. A accepts no session material before this proof verifies.

### 5.3 Confirmation: A to B

A decapsulates `SS_BA`, independently computes `CS`, `PS`, and `T1`, and
verifies the responder proof. A then generates `RK_A`, constructs the
confirmation body, and echoes `T1` explicitly.

```text
T2 = H384(BASE
     || U32(len(OFFER)) || OFFER
     || U32(len(REPLY)) || REPLY
     || U32(len(CONFIRM_BODY)) || CONFIRM_BODY)
```

The initiator proof uses the same hybrid schedule with role-separated labels
and `T2`. It proves to B that A also produced the required classical values and
decapsulated under A's imported PQ identity.

The final transcript is:

```text
TH = H384(BASE
     || U32(len(OFFER)) || OFFER
     || U32(len(REPLY)) || REPLY
     || U32(len(CONFIRM)) || CONFIRM)
```

Only after the appropriate proof verifies may each side call the mandatory
hybrid `V3KeySchedule.deriveSession(CS, PS, TH)`. The result is still only an
authenticated handoff to future ratchet initializers, not an active Layergram
application session.

## 6. Symmetric hybrid proof schedule

For proof transcript `T` (`T1` for B, `T2` for A):

```text
CSEED = HKDF(
  salt = T,
  IKM  = CS,
  info = "layergram/v3/handshake/proof/classical-extract\0",
  L    = 32)

PQSEED = HKDF(
  salt = T,
  IKM  = PS,
  info = "layergram/v3/handshake/proof/post-quantum-extract\0",
  L    = 32)

PROOF_KEY(role) = HKDF(
  salt = PQSEED,
  IKM  = CSEED,
  info = role_key_label || T,
  L    = 32)

PROOF(role) = HMAC(PROOF_KEY(role), role_data_label || T)
```

Exact responder labels:

- key: `layergram/v3/handshake/proof/responder-key\0`
- data: `layergram/v3/handshake/proof/responder\0`

Exact initiator labels:

- key: `layergram/v3/handshake/proof/initiator-key\0`
- data: `layergram/v3/handshake/proof/initiator\0`

Both participants know `CS` and `PS` after a valid run and can therefore
construct the symmetric proof tags. The records are not signatures and do not
give a third party cryptographic proof of authorship. This supports a limited
transcript-deniability goal; its exact claim remains an external-review gate.

## 7. Fixed handshake records

Every record begins with:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `HH3` |
| 3 | 1 | format version `1` |
| 4 | 1 | protocol version `3` |
| 5 | 1 | suite `1` |
| 6 | 1 | kind: offer `1`, reply `2`, confirm `3` |
| 7 | 1 | mode |
| 8 | 1 | flags, zero |
| 9 | 1 | reserved, zero |
| 10 | 2 | common header length, `20` |
| 12 | 4 | exact total record length |
| 16 | 4 | exact capabilities `0x0000001f` |

### 7.1 Offer, 1,316 bytes

| Offset | Bytes | Field |
|---:|---:|---|
| 20 | 16 | handshake ID |
| 36 | 16 | offer message ID |
| 52 | 48 | initiator complete-identity digest |
| 100 | 48 | responder complete-identity digest |
| 148 | 16 | initiator device ID |
| 164 | 32 | initiator device public key |
| 196 | 32 | initiator ephemeral public key |
| 228 | 1,088 | `CT_AB` |

### 7.2 Reply, 1,412 bytes

| Offset | Bytes | Field |
|---:|---:|---|
| 20 | 16 | handshake ID |
| 36 | 16 | reply message ID |
| 52 | 16 | offer message ID |
| 68 | 48 | initiator complete-identity digest |
| 116 | 48 | responder complete-identity digest |
| 164 | 16 | initiator device ID |
| 180 | 16 | responder device ID |
| 196 | 32 | responder device public key |
| 228 | 32 | responder ephemeral public key |
| 260 | 32 | responder initial ratchet public key |
| 292 | 1,088 | `CT_BA` |
| 1,380 | 32 | responder proof |

`REPLY_BODY` is bytes `0..1379`; its total-length header field still commits to
the full canonical length 1,412.

### 7.3 Confirmation, 324 bytes

| Offset | Bytes | Field |
|---:|---:|---|
| 20 | 16 | handshake ID |
| 36 | 16 | confirmation message ID |
| 52 | 16 | offer message ID |
| 68 | 16 | reply message ID |
| 84 | 48 | initiator complete-identity digest |
| 132 | 48 | responder complete-identity digest |
| 180 | 16 | initiator device ID |
| 196 | 16 | responder device ID |
| 212 | 32 | initiator initial ratchet public key |
| 244 | 48 | exact `T1` |
| 292 | 32 | initiator proof |

`CONFIRM_BODY` is bytes `0..291`; its total-length header field commits to the
full canonical length 324.

All decoders require exact lengths, exact known fields, non-zero fixed-size
values, derived device/message/handshake identifiers, and byte-identical
canonical re-encoding. No trailing data or unknown downgrade is accepted.

## 8. Simultaneous offers and replay

Two crossed offers are simultaneous candidates only if their complete identity
digests are exact role reversals and their mode/capabilities match. Both peers
retain the lexicographically smaller complete canonical offer. Arrival order
and wall-clock time do not participate.

An exact duplicate is not a second handshake. The inactive persistence
controller keys pending state by handshake ID, retains the exact canonical
offer or reply bytes for resend, and enforces a global and per-remote-identity
pending cap before expensive handshake cryptography. The active contact/device
coordinator must still apply the crossed-offer tie-break and Normal/Maximum
device policy before activation.

Old offer/reply/confirmation tuples cannot be relabelled into a new run because
the derived identifiers, ordered roles, complete records, KEM ciphertexts,
device keys, and proofs are bound into `T1`, `T2`, and `TH`.

## 9. Pending restart state

The `HP3` codec stores only the canonical plaintext that a future encrypted,
padded auxiliary repository needs:

- initiator: exact offer, `EK_A_priv`, `SS_AB`;
- responder: exact offer, exact reply, `CS`, `PS`, `RK_B_priv`.

The 60-byte header binds role, mode, capabilities, total length, component
lengths, and a SHA-256 corruption digest. Exact record sizes are:

- initiator: 1,440 bytes;
- responder: 2,884 bytes.

These bytes contain secrets. They must never be stored, logged, backed up, or
exported outside an identity/passphrase-scoped encrypted and padded auxiliary
record. The SHA-256 field is only an inner canonical-corruption check; outer
AEAD authentication is mandatory.

The codec is bounded to 4,096 bytes and rejects truncation, corruption, role
confusion, zero secrets, non-canonical embedded records, and inconsistent
offer/reply links. Managed-memory wiping is best effort, not guaranteed.

The inactive `V3HandshakePendingRepository` now stores HP3 plus the exact
canonical public offer/reply in the same encrypted, padded Aux namespace as the
session scope. It is bounded to 64 pending handshakes, 4 per remote identity,
4 MiB of retained pending bytes, 4,096 completion tombstones, and 8,192
physical handshake records. Capacity is checked before X25519/ML-KEM work. A
single controller authority must restore it before reads or writes; after the
claim, direct repository access is rejected.

First export occurs only after the pending record write succeeds. An ambiguous
write fails stopped until a fresh restore, which recovers the exact offer/reply
without rerunning cryptography. After the initial session checkpoint is
independently durable, the controller writes a completion tombstone binding the
handshake, pending-state digest, identities/devices, exact confirmation,
session ID, and checkpoint digest before deleting HP3. An ambiguous write or
delete likewise requires restore. For an initiator, the tombstone retains the
exact confirmation for loss recovery without retaining HP3 secrets.

This is durable handshake-state infrastructure, not the active bootstrap
handoff: the future session initializer must still prove that the supplied
checkpoint is the exact TR3 state derived from that confirmation before it may
request completion.

## 10. Manual transport sizing

With canonical 256-byte LMF plaintext fragments:

| Record | Plain bytes | LMF fragments | Approx. combined Base64URL frame bytes |
|---|---:|---:|---:|
| offer | 1,316 | 6 | about 3,020 characters before delimiters |
| reply | 1,412 | 6 | about 3,147 characters before delimiters |
| confirmation | 324 | 2 | about 854 characters before delimiters |

The candidate therefore remains compatible with the existing 4,000-character
portable text target if one logical record's fragments are exported together
with a compact bounded delimiter. This is a size calculation, not completed
WhatsApp, Telegram, Signal, iMessage, deep-link, or steganographic UX proof.

The outer bootstrap wrapper, exact armor, loss/retry UX, and carrier-text cost
must be tested before activation. No implementation may silently omit either
ML-KEM ciphertext to make the handshake shorter.

## 11. State transitions

| Local state | Permitted action | User content |
|---|---|---|
| `INIT` | create/receive canonical offer | pending only |
| `REPLY` | create/verify responder reply | pending only |
| `CONFIRM` | create/verify initiator confirmation | pending only |
| authenticated handoff | persist initial checkpoint, then tombstone HP3 | still blocked |
| `ACTIVE` | only after ratchet/controller commit | allowed |

Proof verification does not by itself make the application active. Future
integration must atomically bind the final transcript, initial EC state,
initial PQ state, device policy, and replay state before releasing content.

## 12. Remaining security gates

Before this candidate can be enabled:

- independent cryptographic review must assess the custom interactive KEM
  possession proof, deniability, KCI, active-quantum, reflection, replay, and
  transcript construction;
- the bootstrap encryption and LMF key-resolution design must prevent a
  classical-only application fallback and bind exact outer records;
- Normal and Maximum device policy must be enforced by the controller;
- the implemented EC Double Ratchet initializer and the future ML-KEM Braid
  initializer must be composed into one atomic initial `TR3` checkpoint;
- the active handoff must validate that the completion tombstone's session ID
  and checkpoint digest identify exactly that initialized `TR3` state;
- loss, reorder, duplicate, resend, text, link, steganography, QR-independent
  identity, passphrase, multi-identity Premium, backup, and cross-platform
  packaging tests must pass;
- the complete protocol and implementation must pass the activation gate in
  `PROTOCOL_V3_SECURITY_GOALS.md`.
