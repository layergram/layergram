# Layergram ML-KEM Braid transition engine revision 1

Status: **initialization and transitions 1-8 implemented privately; remaining
transitions and public ABI not connected; protocol v3 inactive**

This document freezes the initial bounded slice of Layergram's independent
Apache-2.0 implementation of the public-domain [ML-KEM Braid revision-1
specification](https://signal.org/docs/specifications/mlkembraid/). The code is
`native/layergram_scka/src/braid_transition.rs` and remains private to the
inactive native crate.

No source from Signal's AGPL implementation was inspected, copied, adapted,
linked, or embedded. The normative inputs for this slice are only the published
public-domain specification and the already frozen Layergram-owned `LB3`,
`BM3`, erasure, authenticator, and incremental-ML-KEM boundaries.

## 1. Implemented state-machine slice

`initialize` implements `InitAlice` and `InitBob` at internal Braid epoch 1:

- the stable Layergram initiator begins as `KeysUnsampled`;
- the stable Layergram responder begins as `NoHeaderReceived` with an empty
  `header || mac` decoder;
- both derive the same revision-1 authenticator from the exact 32-byte
  transcript-derived SCKA seed;
- state revision and both reported epoch high-water values begin at zero;
- initialization emits neither a public message nor an epoch secret.

The first send transition implements `KeysUnsampled.Send`:

1. reject any state other than canonical `KeysUnsampled` and reject an
   exhausted state revision before requesting entropy;
2. obtain exactly 64 bytes from the operating-system CSPRNG;
3. generate the ML-KEM-768 keypair and compute the authenticated 64-byte
   public-key header;
4. erasure-encode `header || mac`, emit canonical symbol zero, and wrap it as
   an exact 58-byte `BM3 Header` record;
5. construct a detached revision-plus-one `KeysSampled` `LB3` successor with
   the private key, header MAC, and next encoder index one;
6. report `sending_epoch = epoch - 1` and no output epoch key.

`KeysUnsampled.Receive` is also frozen: every canonical incoming Braid message
is ignored semantically, the authenticated prior remains immutable, and
`receiving_epoch = epoch - 1`. Layergram still emits an otherwise identical
revision-plus-one successor so the durable authority records each accepted
`Receive` exactly as required by the frozen ABI. This is the revision-1
behavior for delayed, duplicated, or reordered messages while the participant
is in that state.

`KeysSampled.Send` emits the next canonical `Header` erasure symbol from the
persisted private key and encoder index. Before carrying the state forward it
reconstructs the public header and verifies the persisted header MAC. It then
advances only the detached encoder index and Layergram state revision. It does
not generate another ML-KEM keypair or request more entropy.

`KeysSampled.Receive` implements transition 2. A canonical `Ct1` symbol for
the current internal Braid epoch creates a detached `HeaderSent` successor,
preserving the private key, initializing the `Ek` encoder at index zero, and
initializing the `Ct1` decoder with the exact received symbol. Other canonical
messages or epochs are ignored semantically while the accepted operation still
advances the Layergram state revision.

`HeaderSent.Send` emits the next canonical `Ek` erasure symbol from the
public-key vector embedded in the validated private key and the persisted
encoder index. It preserves the exact partial `Ct1` decoder and advances only
the detached encoder index and Layergram state revision.

`HeaderSent.Receive` implements transition 3. Current-epoch `Ct1` symbols are
retained in canonical sorted order; exact duplicates are idempotent and
conflicting duplicates fail before a candidate is returned. Once any 30 unique
symbols reconstruct the exact 960-byte `Ct1`, the detached successor becomes
`Ct1Received` and retains the current `Ek` encoder index. Wrong types or epochs
are ignored semantically while the accepted wrapper revision advances. Other
canonical messages are ignored semantically while the accepted wrapper
revision advances.

`Ct1Received.Send` continues the same persisted `Ek` encoder and marks the
canonical public message as `EkCt1Ack`. A lost exported copy does not roll back
the encoder and a later committed send emits the next distinct erasure symbol.

`Ct1Received.Receive` implements transition 4. The first current-epoch `Ct2`
symbol initializes a sorted one-symbol decoder for `ct2 || mac`, discards the
now-acknowledged `Ek` encoder, preserves the private key and exact reconstructed
`Ct1`, and produces `EkSentCt1Received`. Wrong types or epochs are ignored
semantically while the accepted wrapper revision advances.

`EkSentCt1Received.Send` emits the canonical current-epoch no-data `BM3`
message. It preserves the exact incomplete `ct2 || mac` decoder and advances
only the detached Layergram state revision.

`EkSentCt1Received.Receive` implements transition 5. Current-epoch `Ct2`
symbols are retained in sorted canonical order; exact duplicates are
idempotent and conflicting same-index symbols fail before a candidate is
returned. Any five unique symbols reconstruct the exact 128-byte `ct2` and
32-byte MAC. The engine then:

1. reconstructs and validates the persisted ML-KEM keypair;
2. decapsulates the exact persisted `ct1` and reconstructed `ct2`;
3. applies revision-1 `KDF_OK` and keeps the epoch key in a native zeroizing
   owner;
4. derives the detached successor authenticator from that key;
5. verifies the ciphertext MAC with the successor authenticator;
6. only after successful authentication creates an empty header decoder and a
   next-epoch `NoHeaderReceived` successor.

The receive result binds the exact successor to the emitted epoch number and
key. State-only extraction refuses key-emitting candidates, preventing helper
code from silently advancing while discarding the key. A wrong MAC returns a
typed authentication error and no successor; the future durable session
authority must treat it as terminal for that candidate/session. Wrong message
types or epochs preserve semantic state while advancing only the wrapper
revision.

`NoHeaderReceived.Send` emits the canonical current-epoch no-data `BM3`
message, preserves the exact incomplete `header || mac` decoder and
authenticator, catches the sending high-water up to `epoch - 1`, and advances
only the detached Layergram state revision.

`NoHeaderReceived.Receive` implements transition 6. Current-epoch `Header`
symbols are retained in sorted canonical order; exact duplicates are
idempotent and conflicting same-index symbols fail before a candidate is
returned. Any three unique symbols reconstruct the exact 64-byte `pk1` header
and 32-byte MAC. The engine verifies that MAC with the current authenticator
before it can create a `HeaderReceived` successor containing the
authenticated `pk1` and an empty `pk2` decoder. A wrong MAC returns the typed
authentication error, produces no successor, and leaves the authenticated
prior immutable. Wrong message types or epochs preserve semantic state while
the receive high-water catches up and the wrapper revision advances.

`HeaderReceived.Send` implements transition 7:

1. it rejects exhausted revision state before requesting entropy;
2. it obtains exactly 32 fresh bytes from the operating-system CSPRNG;
3. it runs incremental ML-KEM `Encaps1` against the authenticated header;
4. it applies revision-1 `KDF_OK` to the raw shared secret and immediately
   consumes the encapsulation result into a pending owner that contains no raw
   shared secret;
5. it ratchets the authenticator with the zeroizing epoch key;
6. it erasure-encodes Ct1, emits canonical symbol zero in an exact `BM3 Ct1`
   record, and creates `Ct1Sampled` with pending ML-KEM continuation, next Ct1
   encoder index one, and the still-empty `pk2` decoder;
7. it returns the exact state, message, epoch number, and native zeroizing key
   as one detached candidate.

The random seed and raw shared secret are never serialized. Entropy failure or
any later construction failure exposes no candidate and leaves the prior
immutable. `HeaderReceived.Receive` is the revision-1 semantic no-op: it
preserves the header, authenticator, and high-water values while advancing only
the detached Layergram wrapper revision.

`Ct1Sampled.Send` emits the next canonical current-epoch `Ct1` symbol from the
persisted ciphertext and encoder index. It preserves the exact incomplete
`pk2` decoder, requests no new entropy, emits no second epoch key, and advances
only the detached encoder index and Layergram state revision.

`Ct1Sampled.Receive` now implements its incomplete-decoder behavior and
transition 8. Current-epoch `Ek` and `EkCt1Ack` symbols are retained in
canonical sorted order; exact duplicates are idempotent and conflicting
same-index symbols fail before a candidate exists. While `pk2` is incomplete,
a plain `Ek` remains in `Ct1Sampled`. An `EkCt1Ack` proves that the peer has
reconstructed `Ct1`, discards the no-longer-needed `Ct1` encoder index, and
creates `Ct1Acknowledged` with the exact pending ML-KEM continuation and
partial decoder. The authenticator and already-emitted epoch key do not change.
A symbol that would complete `pk2` returns the typed
`TransitionUnavailable` error with no candidate until transitions 9 and 10 are
implemented; it is never misinterpreted as transition 8. Later state variants
remain outside this private slice.

## 2. Immutable candidate and unreliable transport contract

Layergram does not send through a server of its own. Users export text, links,
or steganographic payloads through unrelated applications, which may never be
sent or may be dropped, delayed, duplicated, or reordered.

Therefore a native `Send` result means only **generated**, never **delivered**:

- the authenticated prior remains immutable during derivation;
- one result owns the exact successor, exact BM3 record, and any emitted native
  epoch key and implements neither `Clone` nor `Debug`;
- the future per-session durable coordinator MUST seal the plaintext successor
  as exact `LS3`, then commit that sealed state, any transition-7 epoch key,
  and the exact outbound record/outbox entry atomically before any share sheet,
  copy, link, or steganographic export becomes visible;
- retry or re-export MUST reuse those exact stored bytes and MUST NOT rerun the
  randomized transition;
- losing or not sending an exported copy does not authorize rollback or entropy
  reuse; subsequent `KeysSampled.Send`, `HeaderSent.Send`,
  `Ct1Received.Send`, or `Ct1Sampled.Send` operations provide distinct erasure
  symbols from persisted encoder progress and eventual reconstruction succeeds
  once enough symbols actually reach the peer;
- a Layergram authenticated ACK proves that the peer processed the bound
  Layergram message. It is not an acknowledgement from WhatsApp, Telegram,
  Signal, iMessage, or another carrier, and the ACK message can itself be lost.

This checkpoint tests stable re-export, candidate reconstruction after a
simulated restart, discarded exported copies, continuation after a lost header
symbol, transition 2, `Ek` continuation, exact/conflicting `Ct1` duplicates,
loss and reordering across a simulated decoder restart, `EkCt1Ack`
continuation, transition 4, and canonical `Ct2` decoder restart. It
also tests no-data send behavior, transition 5 reconstruction with loss,
reverse ordering, exact duplicates and restart, output-key/authenticator
agreement, next-epoch metadata, conflicting chunks, MAC failure, and revision
and epoch exhaustion. It additionally tests transition 6 no-data send, header
reconstruction after loss/reordering/duplicate/restart, deterministic
`HeaderReceived` state, conflicting chunks, header-MAC failure, high-water
catch-up, and revision exhaustion. Transition 7 additionally freezes the exact
32-byte entropy request, Ct1 symbol zero, pending-state layout, native epoch-key
and successor-authenticator agreement, deterministic successor digest,
semantic receive no-op, entropy failure, revision exhaustion, and production OS
entropy path. Transition 8 additionally freezes continued `Ct1` output,
stable re-export, exact pending-continuation preservation, sorted and
idempotent `pk2` progress, conflicting-duplicate rejection, the precise
`Ct1Acknowledged` layout and deterministic digest, completion fail-closed until
transitions 9/10, encoder/revision exhaustion, and canonical reconstruction
after restart. It does not yet connect native candidates
to the existing durable send/receive journals; that atomic composition remains
activation-blocking.

## 3. Entropy and licensing boundary

The first key-generating transition and transition 7 call the private
`OsEntropy` boundary in
`native/layergram_scka/src/entropy.rs`. It pins `getrandom` 0.4.3 with default
features disabled, rejects every documented opt-in backend at compile time, and
maps every OS-source failure to a fail-closed entropy error. Partially filled
seed storage is zeroized before return and no candidate is exposed on failure.
The first transition requests exactly 64 bytes for ML-KEM key generation;
transition 7 requests exactly 32 distinct bytes for encapsulation. A lost or
unexported transition-7 candidate must be retried from its durable exact bytes,
never recomputed with reused or replacement entropy. `KeysSampled.Send`,
`HeaderSent.Send`, `Ct1Received.Send`, `Ct1Sampled.Send`, transitions 5, 6,
and 8 do not request new entropy.
Deterministic entropy exists only as a private unit-test trait implementation
and is not exported through the C ABI. The complete application and native
entropy policy is frozen in `ENTROPY_SOURCES.md`.

`getrandom` is available under MIT or Apache-2.0; Layergram selects its
Apache-2.0 path. Its applicable `cfg-if`, `libc`, `r-efi`, and `rand_core`
dependencies also provide an Apache-2.0-compatible path. Exact versions and
notices are frozen in `Cargo.lock`, `THIRD_PARTY_NOTICES.md`, and the machine
receipt. These terms are compatible with both the public Layergram base and the
separately distributed paid Premium application, subject to preserving the
recorded notices.

## 4. Verification and remaining gates

Unit tests cover both roles, revision-zero invariants, the independent FIPS
ML-KEM key-generation vector, detached transition semantics, exact symbol-zero
output, one entropy request, error-before-entropy behavior, OS entropy, stable
re-export, reconstruction, loss of an intermediate header symbol, recovery
from later symbols without new entropy, transitions 2-3, `Ek` continuation,
`Ct1` loss/reordering/duplicate/conflict behavior, simulated decoder restart,
`EkCt1Ack` continuation after a lost export, transition 4 with wrong-epoch
filtering and `Ct2` decoder restart, MAC/state corruption, encoder/revision
exhaustion, revisioned ignored inputs, no-data send, transition 5 recovery with
loss/reordering/duplicate/restart, exact epoch-key and authenticator agreement,
typed MAC failure, epoch exhaustion, transition-7 Ct1/output/authenticator
agreement and failure paths, transition-8 loss/reordering/duplicate/conflict
and completion-gate behavior, and frozen deterministic digests for Header/`Ek`
continuation and transitions 2-8.

Activation still requires transitions 9 through 13, durable terminal
MAC-failure and transition-unavailable handling, remaining encoder/decoder
completion, LS3 sealing with a unique OS nonce, the public C ABI and panic
containment, atomic TR3/journal composition, cross-implementation vectors,
fuzzing/sanitizers, every shipped target, and an independent cryptographic and
implementation audit.
