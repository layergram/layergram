# Layergram authenticated SCKA composition v1

Status: **implemented behind an engineering-only candidate FFI feature; the
default ABI remains `NOT_READY`, application packaging and registration remain
disconnected, and protocol v3 remains inactive**

This document freezes the internal composition implemented by
`native/layergram_scka/src/authenticated_braid.rs`. It joins the already frozen
Layergram-owned `LS3`, `LB3`, `BM3`, entropy, and ML-KEM Braid revision-1
transition modules. Cargo feature `candidate-ffi` now connects that composition
to the frozen C shapes strictly for engineering verification. The default
feature set still returns `NOT_READY`; no Flutter package or application
bootstrap loads either build.

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
boundary. The scope-owned LMF/HR3 path may invoke the private receive
composition speculatively to derive the message key needed for LMF
authentication. The returned candidate is non-authoritative: AEAD failure must
discard it, and only a complete authenticated LMF delivery may commit it. The
composition:

1. decodes one exact canonical non-empty `BM3` record;
2. opens and semantically validates the exact expected `LS3` revision;
3. derives one immutable receive candidate;
4. requires stable role/session and an exact revision-plus-one successor;
5. seals that successor exactly once with its injective role-and-revision nonce.

The engineering candidate is invoked through
`V3SckaCandidateFfiBackend` only from the scope-owned authenticated LMF/HR3
dispatcher in integration tests. Direct raw C calls remain possible in a
manually built candidate library and therefore are not an application security
boundary. Packaging or registering that candidate before the scope owns every
receive call would be a security error.

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

The same scope now hides its inbox, resolver, and durable controller, constructs
the resolver with that exact controller once, and owns frame receive, deferred replay,
authentication-failure cleanup, and delivery commit. Continuations received
before fragment zero remain sealed and durable. When fragment zero later
arrives, the scope derives one non-authoritative ratchet candidate, persists
and authenticates the frame, resumes only continuations for that exact
assembly, and can commit only through the resolver/controller pair it created.
It never consumes another session's completed delivery notification during
that automatic retry; the explicit all-assembly resume returns every delivery
it completes. A caller cannot inject a different resolver,
authentication-failure handler, or commit controller into this scope path.
Scope-owned wrappers preserve durable send, exact re-export, ACK processing,
compaction, and retention operations without exposing the controller itself.

The candidate-only bridge now exercises the private Rust composition through
the authority-side integration seam. Its Dart loader accepts only an explicit
path and checks the exact implementation ID, ABI, protocol revision, state
format, and every fixed size before admission. The normal Rust feature set
still returns `NOT_READY`; the candidate is unregistered and absent from every
app package. Authenticated dispatch from the active application remains an
activation gate.

## 7. Verification and commercial boundary

Rust tests cover outer/inner binding, wrong key/session/role/revision, tag and
payload tampering, canonical BM3 rejection, exact candidate re-export,
restart validation, deterministic role-and-revision nonce separation,
transition-entropy failure before candidate exposure, and a two-party run
through sealed states that reaches matching epoch outputs.

Dart real-Aux tests additionally cover continuation-before-fragment-zero,
process restart, scope-owned candidate derivation, exact plaintext recovery,
atomic AR3/TR3 commit, replay cleanup, and a second restart at the committed
ratchet revision without caller-supplied resolver or controller objects. A
two-session regression proves automatic fragment-zero replay cannot consume an
unrelated ready delivery and that explicit replay returns it separately.

The candidate FFI integration builds the default and `candidate-ffi` libraries
separately. It proves that the default implementation ID is rejected by the
candidate allowlist, then uses real LS3 states for an outgoing journal/outbox
commit, exact retry after restart, delayed and duplicated continuation,
receive-side restart, atomic incoming commit, backend validation at TR3
revision one, and committed replay suppression. No transition is rerun to
produce retry bytes.

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
