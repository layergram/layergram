# Layergram Protocol v3 — Security Goals

Status: **normative research baseline; protocol v3 is not enabled**

This document defines the properties that a Layergram protocol-v3 design must
demonstrate before it can replace protocol v2. If a later handshake, ratchet,
transport, or storage choice cannot satisfy these properties, the choice must
change. The application must not weaken a property silently or describe a
partial result as quantum-resistant.

Normative terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are interpreted as in
RFC 2119.

## Scope and trust boundaries

Protocol v3 assumes:

- the user controls an uncompromised Layergram process while it is unlocked;
- the platform CSPRNG, X25519 implementation, SHA-2, HKDF, AES-256-GCM, and the
  pinned ML-KEM-768 implementation behave according to their specifications;
- users verify a contact's complete v3 fingerprint or SAS through an
  independent channel before treating the contact as authenticated;
- every external transport may inspect, delay, drop, duplicate, reorder,
  replay, normalize, or replace Layergram payloads;
- Layergram has no server, account directory, transparency log, push channel,
  or trusted clock shared between peers.

Compromise of an unlocked endpoint, screen or keyboard capture, malicious
operating-system code, physical side channels, and coercion are outside the
cryptographic protocol guarantee. Steganography does not guarantee that the
existence of ciphertext is undetectable.

## Adversaries

The design MUST address at least:

1. a passive store-now/decrypt-later observer, including one with a future
   cryptographically relevant quantum computer;
2. an active classical or quantum-capable man-in-the-middle during identity and
   message exchange;
3. a malicious transport that replays, reflects, reorders, duplicates,
   truncates, splices, or selectively suppresses whole frames;
4. an attacker attempting version, suite, capability, or security-mode
   downgrade;
5. unknown-key-share, identity-misbinding, key-compromise-impersonation, and
   unexpected-device attacks;
6. a peer or unauthenticated sender attempting CPU, memory, storage, skipped-key,
   fragment, or session-state exhaustion;
7. later compromise of identity or ratchet state, with the limits stated below;
8. local inspection when a passphrase-scoped identity is not active.

## Identity properties

- A v3 public identity MUST contain the complete X25519 and ML-KEM-768 public
  keys. Neither key may be truncated, replaced by an online lookup, or reduced
  to a verification digest.
- The same valid BIP39 mnemonic and optional BIP39 passphrase MUST reproduce the
  same complete v3 cryptographic identity on every supported platform.
- Primary and passphrase-scoped identities MUST use distinct domain-separated
  derivation labels. Each separately saved Premium identity MUST use its own
  recovery material and the same public protocol contract.
- The identity ID, fingerprint, and future SAS MUST bind the protocol version,
  suite, flags, X25519 key, and ML-KEM key. Mutable display text MUST NOT affect
  the cryptographic identity.
- Decoders MUST reject unknown suites or flags, non-canonical encodings,
  malformed lengths, invalid UTF-8, checksum failures, all-zero keys, trailing
  data, and invalid ML-KEM public keys before the identity becomes usable.
- Importing a QR, token, or link does not authenticate its owner. Verification
  MUST be explicit and MUST cover the complete v3 identity.
- Reusing the current 24 words MUST NOT be described as retaining the old
  identity: v3 has a different public bundle, ID, fingerprint, contacts, and
  sessions, all of which require a new exchange and verification.

## Handshake properties

`PROTOCOL_V3_HANDSHAKE.md` freezes the current inactive research candidate.
It is not approved for activation and any candidate MUST:

- bind both complete identities, both device identifiers and device keys,
  initiator/responder roles, protocol version, suite, capabilities, security
  mode, message/session identifiers, and every canonical handshake frame into
  one transcript;
- require fresh contributions from both peers and prove possession of the
  private material corresponding to the imported identities;
- derive no application key from X25519 alone and accept no path where an
  invalid or missing ML-KEM contribution is masked by the classical branch;
- prevent replay, reflection, unknown-key-share, identity misbinding, and silent
  downgrade, including across simultaneous handshakes;
- keep user content pending and undisplayed until the authentication state
  required by the selected mode has committed atomically;
- fail closed on backend self-test failure, unsupported suite, malformed
  transcript, expired state, unexpected device, or resource-limit breach.
- persist the complete secret HP3 state and exact public offer/reply inside the
  identity/passphrase-scoped encrypted Aux store before first export; retries
  after restart MUST return byte-identical public records without rerunning
  X25519 or ML-KEM;
- enforce global and per-remote-identity pending limits before expensive
  handshake cryptography, and require one controller authority for restore,
  reads, writes, resend, and retirement;
- retain HP3 until the exact initial session checkpoint is independently
  durable. Retirement MUST write a canonical completion binding the pending
  digest, identities/devices, exact confirmation, session ID, and checkpoint
  digest before deleting HP3. Ambiguous writes or deletes MUST fail stopped
  until restore, and initiator confirmation loss recovery MUST reuse exact
  retained bytes.
- persist an encrypted preparation containing the exact confirmation and
  revision-zero TR3 before the initial checkpoint; restore MUST finish the
  same checkpoint/tombstone transition without rerunning handshake, SCKA, or
  ratchet-key generation, and no confirmation may be exported first;

The proposed KEM-based proof of possession is a research candidate, not an
approved primitive. It MUST NOT be enabled until an external cryptographic
review accepts the construction. If it fails review, Layergram must use a
reviewed standard alternative or narrow its product claim explicitly.

## Ratchet and key-schedule properties

- Every v3 application message MUST derive its key from both a current
  classical Double Ratchet contribution and the required sparse post-quantum
  ratchet context through domain-separated extract-then-expand processing.
- Every fragment nonce MUST be derived in a domain separate from the message
  key, bind the complete canonical message/fragment context, and be verified by
  the receiver before a ratchet transition commits.
- Application and PQ-control fragment zero MUST authenticate the exact canonical
  EC+SCKA header. Every continuation MUST authenticate the same header length and
  digest; contradictory bindings MUST poison the candidate assembly.
- ACK keys and nonces MUST use a direction-specific session root and the exact
  visible canonical ACK header context. A newly sealed cumulative ACK MUST have
  a fresh message ID; a resend MUST reuse the exact sealed bytes.
- Missing, invalid, stale, or ambiguous post-quantum state MUST NOT be replaced
  by a classical-only key while the result is labelled v3.
- The design MUST define forward secrecy and post-compromise recovery separately
  for the classical and post-quantum components, including exact epoch and
  deletion boundaries.
- Skipped message keys, prior epochs, incomplete exchanges, and retired device
  sessions MUST have strict count, byte, and time limits and deterministic
  deletion rules.
- A crash MUST leave either the old committed state or the new committed state,
  never visible plaintext paired with an uncommitted ratchet transition.
- An outgoing manual-transport message MUST durably retain the exact sealed
  bytes before first export. Retransmission MUST NOT re-encrypt an old logical
  frame under reused key/nonce state.
- The outgoing commit point MUST bind the canonical application/control record,
  complete post-send ratchet snapshot, prior revision, and exact ordered sealed
  frame set. Restart MUST advance from that record and materialize only those
  bytes, without invoking the ratchet or AEAD again.
- A complete authenticated ACK MUST become durable in the send journal before
  the outbox copy may be deleted. A journal-completed frame set MUST NOT become
  exportable again after crash recovery.
- An incoming frame MUST be durably stored while still sealed before it can
  advance ratchet or application state. Complete delivery MAY be at least once,
  but replay suppression MUST be committed only after the higher-level effect is
  idempotent or transactionally durable under a stable message identifier.
- The durable higher-level effect MUST bind one application/control record and
  its matching complete ratchet snapshot to the exact authenticated frame set.
  Its digest MUST be bound into replay suppression. Restore MUST fail closed if
  either side is missing, unbound, malformed, or divergent.
- No effect-journal entry may be removed until a separately durable ratchet
  checkpoint, application record, and replay window make that removal safe.
- Durable AR3 materialization MUST use the assembly-derived stable record ID,
  reuse exact bytes idempotently, and reject divergent bytes for the same ID.
  A TR3 checkpoint MUST bind one stable session lineage and cumulative receipts
  over the exact covered AR3/TR3 transitions. An incoming tombstone MUST be
  replaced write-before-delete by an exact durable replay-window proof before
  its effect is collected. A completed outgoing effect MUST be collected only
  after its outbox copy is absent and a durable completion proof has been
  written. Every checkpoint receipt MUST retain its full effect or the exact
  compact proof; loss of both MUST fail restore closed. A compact proof already
  written before an interrupted deletion MUST remain usable under a later
  checkpoint that cumulatively retains the same receipt. Replay-window expiry
  MUST remain disabled until skipped-key retirement independently rejects the
  corresponding input. Retention MUST use only locally recorded time, fail
  closed on clock rollback, and MUST NOT silently time-purge incomplete inbox
  assemblies or unacknowledged exact-byte outbox entries.
- A retirement intent MUST be encrypted in the same identity/passphrase scope,
  bounded, canonical, and written before any compact proof or cumulative receipt
  disappears. Its prepared state MUST bind the exact proof, direction-bound
  receipt, source checkpoint, locally measured age, and configured minimum
  lifetime. Later durable stages MUST bind one exact pending replacement and one
  self-contained final checkpoint without weakening the prepared binding. The
  final checkpoint MUST bind the pending checkpoint, proof digest, plan ID,
  source checkpoint, and exactly one removed receipt. Ambiguous writes or
  deletes MUST fail stopped until restore. No generic proof-deletion API may be
  exposed; only the single authority may delete an exact proof after the final
  checkpoint is durable.
- The single authority MUST claim and restore the retirement journal from the
  same encrypted scope. At most one retirement plan may be pending per session;
  restore MUST reject duplicate plans for one session or assembly and
  MUST revalidate the exact current checkpoint stage, direction-bound receipt
  state, compact proof digest/bindings, and locally recorded proof time before
  accepting any non-final plan. If a replacement or final write completed
  before a crash, restore MUST validate that exact transition and idempotently
  advance the journal. A missing compact proof is valid only with the exact
  final stage. The coordinator MUST delete the proof before the plan, resume
  either ambiguous deletion after restore, and clean retained checkpoint
  ancestors without disconnecting a surviving older record. A pending plan MUST
  block ratchet advance; successful finalization MUST remove it and allow
  bounded rolling retirement at the same stable revision.
- One identity/passphrase-scoped authority MUST own journal mutation before
  session restore. Direct journal lifecycle calls and writes MUST be rejected
  after ownership; production wiring MUST neither retain nor expose the owned
  journal for concurrent direct use. Every session transition MUST be
  serialized under revision compare-and-swap before its builder can observe
  plaintext or candidate state.
- Restore MUST accept only a contiguous effect chain above a unique registered
  checkpoint and MUST verify canonical AR3/TR3, session, routing, stable ACK
  roots, active lifecycle, and EC private/public consistency. A prepared effect
  with an ambiguous persistence result MUST force controller reconstruction and
  restore before any further transition.

## Asynchronous and multi-device properties

- Loss, duplication, and reordering are normal operating conditions because
  users manually transport messages. They MUST NOT cause silent state rollback,
  permanent key reuse, or acceptance of replayed application content.
- Normal mode MUST maintain an independently authenticated session for every
  accepted recipient device and MUST enforce a device cap. Adding a device is
  never a silent replacement.
- Maximum mode MUST pin the authenticated device pair and block user content on
  an unexpected device until the user explicitly repairs or changes mode.
- A content key MAY be wrapped for several authenticated device sessions in
  Normal mode, but one device's compromise MUST NOT reveal another device's
  private ratchet state.

## Transport properties

- Binary message semantics MUST be identical before text armor, deep-link
  prefixing, or steganographic embedding.
- Every parser and reassembler MUST be canonical, size-bounded, duplicate-aware,
  and fail closed before large allocation or cryptographic work.
- Fragment authentication MUST bind the message, session, epoch, fragment index,
  total count, and final assembled length. Partial content MUST NOT be exposed.
- Text, links, and steganography MUST tolerate documented loss/reorder scenarios
  without a server. Transport normalization may produce a clear local error but
  never a weakened cryptographic fallback.
- Fragment acknowledgements MUST be authenticated in the same session context,
  bind the exact target message metadata, accumulate monotonically, and reverse
  the routing roles. Acknowledgements MUST NOT acknowledge acknowledgements.
- Resend and retention policy MUST NOT trust a peer-supplied clock. A lost ACK
  may cause an exact-byte duplicate resend, never state rollback or nonce reuse.
- The single static identity QR MUST carry the entire public identity. Reliability
  on representative screens, printers, cameras, reductions, and photocopies is
  a physical test gate, not implied by theoretical QR capacity.

## Deniability and local state

- Protocol payloads SHOULD avoid stable sender or recipient identifiers where
  routing does not require them; the precise transcript-deniability claim must
  be reviewed together with the chosen sender-authentication construction.
- Passphrase-derived identity and ratchet state MUST remain unavailable when the
  passphrase context is inactive and MUST NOT create a global cleartext marker.
- Logs, analytics, crash reports, backups, and diagnostic exports MUST NOT
  contain mnemonics, passphrases, private seeds, shared secrets, message keys,
  private handles, or unredacted plaintext.
- Managed-runtime overwrites are best effort and MUST NOT be described as
  guaranteed zeroization. Expanded ML-KEM private keys MUST remain behind native
  opaque handles and be destroyed explicitly.

## State semantics

The eventual protocol state machine MUST distinguish at least:

| State | User content | Required property |
|---|---|---|
| `INIT` | pending only | canonical offer created, no authenticated session |
| `REPLY` | pending only | responder contribution bound to transcript |
| `CONFIRM` | pending only | mutual proof verified, commit not yet complete |
| `ACTIVE` | allowed | authenticated hybrid session committed atomically |
| `SUSPENDED` | blocked | recoverable loss/reorder/timeout or user action needed |
| `REKEY_REQUIRED` | blocked | identity/device/epoch transition cannot continue safely |
| `BROKEN` | blocked | invalid state, downgrade, corruption, or invariant failure |

No state transition may reinterpret v2 bytes as v3 or automatically downgrade a
contact from v3 to v2.

## Activation and claim gate

Protocol v3 may be called quantum-resistant only after all of the following:

- normative wire, transcript, state-machine, KDF, ratchet, persistence, and
  migration specifications are frozen with public vectors;
- every shipped ABI passes the primitive, parser, model, crash, transport, and
  cross-platform suites;
- real QR, text, link, and steganographic tests pass on the supported matrix;
- the public protocol and private Premium implementation pass compatibility
  tests without a protocol fork;
- every runtime and native dependency has a versioned license inventory that
  permits both open-source and paid proprietary Premium distribution;
- an independent audit has no unresolved critical or high-severity finding.

Until then, all v3 code and UI must remain developer-only, inactive, and labelled
as research implementation.

## Primary references

- [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [Signal Double Ratchet Algorithm, including the Triple Ratchet integration](https://signal.org/docs/specifications/doubleratchet/)
- [Signal ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/)
