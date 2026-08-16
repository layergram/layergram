# Layergram authenticated SCKA composition v1

Status: **implemented privately; the inactive Dart durable scope pins one
admitted backend, while the Rust composition, public ABI, application
packaging, and protocol v3 activation remain disconnected**

This document freezes the internal composition implemented by
`native/layergram_scka/src/authenticated_braid.rs`. It joins the already frozen
Layergram-owned `LS3`, `LB3`, `BM3`, entropy, and ML-KEM Braid revision-1
transition modules without exposing a C ABI or registering a Flutter backend.

## 1. Boundary and ownership

Every operation is candidate-only. Its authenticated input state remains
immutable and caller-owned. A successful send owns exactly one newly sealed
`LS3` state, one canonical 24-byte or 58-byte `BM3` record, the reported
sending-epoch high-water value, and at most one zeroizing epoch output. A
successful receive owns exactly one newly sealed state, the reported matching
receiving epoch, and at most one zeroizing epoch output.

Candidate types implement neither `Clone` nor `Debug`. Re-export borrows their
exact bytes and never repeats a transition or reseals a logical revision. The
sealed state is not authoritative merely because it was generated: the future
single per-session authority must commit it with the matching TR3 revision,
optional epoch output, and exact durable outbox/application effect before any
message becomes visible to a share sheet or external carrier.

## 2. Initialization and validation

Initialization performs `InitAlice` or `InitBob`, derives the exact 12-byte
state nonce `"LN3" || role_u8 || state_revision_u64_be`, and seals the canonical
revision-zero `LB3` payload as state-format-v2 `LS3` under the separately
derived 32-byte state key with AES-256-GCM-SIV. It emits no public message or
epoch output.

Validation performs this exact order:

1. bound the encoded state and authenticate its complete `LS3` header,
   ciphertext, and tag against the expected stable role, non-zero session ID,
   state key, and exact revision;
2. decode the authenticated plaintext as canonical `LB3`;
3. require every duplicated role, session, revision, epoch high-water, state
   variant, key relationship, and encoder/decoder field to agree;
4. wipe both owned plaintext copies on every success or error exit.

A valid outer tag over a non-canonical or semantically mismatched inner payload
is rejected.

## 3. Send

One private send operation:

1. opens and validates the exact expected `LS3` revision;
2. invokes the complete immutable transition engine, using only its private OS
   entropy boundary when that transition requires randomness;
3. requires the successor to preserve stable role/session and advance the
   signed-63 state revision by exactly one;
4. canonically encodes the transition's exact `BM3` record;
5. derives the injective 12-byte role-and-revision nonce and seals the canonical
   successor once as `LS3`;
6. returns one detached exact candidate.

If transition entropy fails, no candidate or partial output is returned. The
prior stays valid and immutable. A transition that succeeded internally but
could not be sealed is dropped and its plaintext and epoch-key owners are
wiped. LS3 nonce derivation consumes no entropy.

## 4. Receive and outer authentication precondition

Raw `BM3` is public protocol material and is not a Layergram authentication
boundary. The private receive composition may be invoked only after the future
LMF/HR3 path has authenticated and session-bound the complete message. It then:

1. decodes one exact canonical non-empty `BM3` record;
2. opens and semantically validates the exact expected `LS3` revision;
3. derives one immutable receive candidate;
4. requires stable role/session and an exact revision-plus-one successor;
5. seals that successor exactly once with its injective role-and-revision nonce.

This checkpoint cannot enforce the outer-caller precondition because no public
ABI or application caller is connected. Activating the C ABI before the
authenticated LMF/HR3 dispatcher owns the call would be a security error.

## 5. Epoch domains

Three epoch values remain intentionally distinct:

- the non-zero internal Braid epoch carried by `BM3`;
- the sending/receiving high-water value reported for the surrounding `SK3`;
- the epoch attached to an optional newly derived 32-byte output key.

An output key can complete the current internal Braid epoch while the carrier
message still reports the prior high-water. The authenticated successor can
advance its stored high-water at the same transition. The composition therefore
preserves the engine's typed values independently; it never equates the BM3
epoch, SK3 high-water, and output-key epoch.

## 6. Unreliable carrier and recovery contract

Layergram has no delivery server. A generated text, link, QR-derived exchange,
or steganographic carrier message may never be sent, or may be lost, delayed,
duplicated, or reordered. Generation never proves delivery. Retry must reuse
the exact durable candidate bytes. A later transition may generate a new
erasure symbol only from the previously committed successor state.

Both participants use the same session state-sealing key. The stable role byte
separates their nonce spaces, while the signed-63 revision is injective within
each role. AES-256-GCM-SIV prevents a divergent same-revision recomputation from
causing AES-GCM's catastrophic nonce-reuse failure. It does not make repeated
candidate generation desirable: the future serialized durable authority MUST
persist the exact candidate before another transition can observe that prior
revision. Retry re-exports those exact bytes and never invokes the transition
again.

The inactive Dart v3 persistence scope now admits one backend before opening
storage and pins that exact instance across checkpoint restore validation,
initial HP3-to-TR3 handoff, durable send, and its scope-owned receive resolver.
A different per-call backend is rejected before SCKA transition work or a
durable write. The controller still commits the resulting opaque native state
inside the exact TR3/outbox or TR3/application effect.

This is an authority-side integration seam, not a connection to the private
Rust composition: the native ABI still returns `NOT_READY`, is unregistered,
and is not packaged. Authenticated outer dispatch through the real application
and the native ABI connection remain activation gates.

## 7. Verification and commercial boundary

Rust tests cover outer/inner binding, wrong key/session/role/revision, tag and
payload tampering, canonical BM3 rejection, exact candidate re-export,
restart validation, deterministic role-and-revision nonce separation,
transition-entropy failure before candidate exposure, and a two-party run
through sealed states that reaches matching epoch outputs.

This checkpoint pins RustCrypto `aes-gcm-siv` 0.11.1 and `aes` 0.8.4 with its
`zeroize` feature under their Apache-2.0 licensing alternatives. The crate and
Layergram-owned source remain Apache-2.0.
All pinned dependencies use the permissive commercial paths
recorded in `native/layergram_scka/THIRD_PARTY_NOTICES.md` and
`tool/pq/scka_native_candidate.json`. Signal's AGPL implementation remains
excluded; this is an independent implementation of the public-domain protocol
specification.

Protocol v3 remains inactive and Layergram must not claim post-quantum
readiness from this checkpoint.
