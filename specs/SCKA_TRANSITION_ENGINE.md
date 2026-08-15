# Layergram ML-KEM Braid transition engine revision 1

Status: **initialization and transition 1 implemented privately; remaining
transitions and public ABI not connected; protocol v3 inactive**

This document freezes the first bounded slice of Layergram's independent
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
is in that state. Other receive and send variants remain unimplemented and fail
outside this private slice.

## 2. Immutable candidate and unreliable transport contract

Layergram does not send through a server of its own. Users export text, links,
or steganographic payloads through unrelated applications, which may never be
sent or may be dropped, delayed, duplicated, or reordered.

Therefore a native `Send` result means only **generated**, never **delivered**:

- the authenticated prior remains immutable during derivation;
- one result owns the exact successor and exact BM3 record and implements
  neither `Clone` nor `Debug`;
- the future per-session durable coordinator MUST seal the plaintext successor
  as exact `LS3`, then commit that sealed state and the exact outbound
  record/outbox entry atomically before any share sheet, copy, link, or
  steganographic export becomes visible;
- retry or re-export MUST reuse those exact stored bytes and MUST NOT rerun the
  randomized transition;
- losing or not sending an exported copy does not authorize rollback or entropy
  reuse; subsequent Braid messages provide new erasure symbols and eventual
  progress depends on fresh messages actually reaching the peer;
- a Layergram authenticated ACK proves that the peer processed the bound
  Layergram message. It is not an acknowledgement from WhatsApp, Telegram,
  Signal, iMessage, or another carrier, and the ACK message can itself be lost.

This checkpoint tests stable re-export, candidate reconstruction after a
simulated restart, discarded exported copies, and duplicate/reordered no-op
receives. It does not yet connect native candidates to the existing durable
send/receive journals; that atomic composition remains activation-blocking.

## 3. Entropy and licensing boundary

Production transition entry points call the private `OsEntropy` boundary in
`native/layergram_scka/src/entropy.rs`. It pins `getrandom` 0.4.3 with default
features disabled and maps every OS-source failure to a fail-closed entropy
error. Partially filled seed storage is zeroized before return and no candidate
is exposed on failure. Deterministic entropy exists only as a private unit-test
trait implementation and is not exported through the C ABI.

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
re-export, reconstruction, and revisioned ignored duplicates/reordering.

Activation still requires transitions 2 through 13, authenticated receive
reconstruction and terminal MAC-failure behavior, encoder/decoder continuation,
epoch-key emission and authenticator ratcheting, LS3 sealing with a unique OS
nonce, the public C ABI and panic containment, atomic TR3/journal composition,
cross-implementation vectors, fuzzing/sanitizers, every shipped target, and an
independent cryptographic and implementation audit.
