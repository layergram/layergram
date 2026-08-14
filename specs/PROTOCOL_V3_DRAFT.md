# Layergram Protocol v3 — Security and Identity Draft

Status: **research implementation; not enabled for users; not a security claim**

This document defines the first falsifiable invariants for the intentionally
incompatible Layergram protocol v3. It does not declare the protocol complete
or independently reviewed.

The normative threat boundary and activation properties are defined in
`PROTOCOL_V3_SECURITY_GOALS.md`. If this draft conflicts with those goals, the
security-goals document wins and this draft must be corrected before code is
enabled.

## Recovery, public identity, and session proof are different operations

1. A user restores their own local identity only from the 24-word BIP39 phrase
   plus an optional passphrase.
2. QR, direct text, and deep link carry only the complete public identity used
   to import a contact. They never carry a mnemonic or private key.
3. A later session handshake proves possession of private material matching the
   imported public identity. That proof is not an account login.

Layergram still has no account, key directory, or Layergram-operated server.

## Selected hybrid identity suite

The first experimental suite is:

- X25519 public key: exactly 32 bytes;
- ML-KEM-768 encapsulation key: exactly 1,184 bytes;
- protocol identity digest: SHA-384 over the complete canonical cryptographic
  public material;
- optional display label: at most 32 UTF-8 bytes and excluded from the stable
  cryptographic identity digest.

The ML-KEM key is the full FIPS 203 value. No key, ciphertext, shared secret,
digest input, or security parameter may be truncated to make a QR, link, or
steganographic payload smaller.

## Compact public-identity encoding

The public identity uses a fixed binary layout:

| Field | Bytes |
|---|---:|
| Magic `LG3` | 3 |
| Suite | 1 |
| Flags | 1 |
| Display-name byte length | 1 |
| X25519 public key | 32 |
| ML-KEM-768 public key | 1,184 |
| Display name | 0–32 |
| SHA-384 checksum prefix | 16 |

Maximum binary size is 1,270 bytes. The checksum detects corrupt imports; it is
not a substitute for SAS/fingerprint verification.

The QR stores these binary bytes directly. The text token and deep link use
Base64URL armor around the exact same binary payload. Compactness therefore
comes from eliminating redundant JSON field names and duplicated ID/fingerprint
values, not from reducing cryptographic material.

The maximum 1,270-byte binary identity can be constructed as one static QR at
error-correction level H, where it occupies QR version 40 (177 x 177 modules).
That is a codec/capacity result only: reliable scanning at realistic printed
sizes, displays, cameras, quiet zones, and with the current logo overlay remains
an activation-gate test rather than an established UX claim.

## Required identity invariants

- A bit change in either public key changes the identity ID and fingerprint.
- Changing only the display label does not change the identity ID.
- Unknown suites, flags, non-canonical lengths, all-zero keys, invalid UTF-8,
  and checksum mismatches fail closed.
- The decoder derives identity ID and fingerprint locally; transmitted values
  are never trusted.
- A backend-specific ML-KEM public-key validity check remains mandatory before
  the identity becomes usable for encapsulation.

## Protocol v3 activation gate

The current application remains on protocol v2. Version v3 must not become the
preferred derivation or appear as quantum-resistant until all of these pass:

- production native ML-KEM backend on every release ABI;
- NIST KAT/ACVP and Wycheproof validation through the shipped wrapper;
- reviewed sender proof/handshake and Triple Ratchet specification;
- complete text, link, QR, and steganographic transport tests;
- migration, passphrase, multi-device, Maximum mode, backup, and crash tests;
- independent protocol and implementation audit with no unresolved high or
  critical findings.

The native wrapper and inactive packaging now traverse the production ABI on
an Android arm64 emulator, an iOS arm64 simulator, a macOS arm64 app, and a
Windows x64 app running on Windows 11 ARM64, plus a Linux x64 app on Ubuntu
22.04; the packaged Android libraries and Apple binaries also cover their
release architectures. This is an engineering checkpoint, not the
production-native-backend gate: physical devices, distribution signing, any
distributed Linux ARM64 or native Windows ARM64 build, complete per-ABI
vectors, and independent review remain. See `ML_KEM_BACKEND.md`.

## Inactive complete local-identity checkpoint

`V3LocalIdentityFactory` now restores a complete hybrid public identity from a
valid mnemonic using the explicit v3 X25519 and ML-KEM derivation labels. It
requires the native backend self-test, validates the generated ML-KEM public
key, keeps the expanded ML-KEM private key behind an opaque native handle, and
wipes temporary seed buffers on both success and failure. Passphrase-scoped
restoration uses both the BIP39 passphrase and the separate v3 passphrase
derivation namespace.

The factory is intentionally absent from `IdentityManager`, providers, storage,
backup, UI, contact import, and messaging. It is not a migration or activation:
v2 remains preferred. Its private fields are now consumed only by the inactive
handshake library part described below; no active application seam can reach
that code.

Imported identities have a distinct `V3PublicIdentityValidator` boundary. It
first applies the strict canonical codec, then requires the native backend
self-test and the FIPS 203 public-key validity check. Its validated wrapper means
only “structurally usable”; it never substitutes owner authentication or the
future fingerprint/SAS ceremony.

## Initial transport limitation

An ML-KEM-768 ciphertext is 1,088 bytes and does not fit the current 800-byte
forward-secrecy control budget. It must be fragmented for steganographic
bootstrap. The steady-state sparse PQ ratchet will use bounded smaller chunks.
Neither issue may be hidden through a classical-only fallback labelled as v3.

`LMF_V3_DRAFT.md` now defines an inactive framing candidate with a fixed
180-byte authenticated base header, a full 16-byte AES-GCM tag, canonical
adaptive first-fragment sizing, at most 64 fragments, and a 16,384-byte global
final-length limit. The exact canonical `HR3` EC+SCKA header is appended to
fragment zero and authenticated directly; every continuation authenticates its
length and domain-separated digest. Headerless 1,088-byte ML-KEM bootstrap data
becomes five frames with encrypted fragment sizes 256, 256, 256, 256, and 64
bytes.

A headerless full fragment is 452 binary bytes and uses at least 177 visible
carrier-safe ASCII characters; the final 64-byte fragment is 260 bytes. With a
maximum 608-byte HR3, fragment zero carries 24 plaintext bytes in an 828-byte
frame and its minimum-cover steganographic encoding is 3,997 characters. These
are frozen codec vectors, not cross-app reliability proof.

The framing implementation is still isolated from active messaging and exposes
no authenticated handshake. Its bounded durable inbox stores sealed frames
before authentication, withholds partial plaintext, restores after restart, and
writes a replay tombstone before cleanup. Its durable outbox retains the exact
sealed bytes and applies authenticated cumulative ACKs using write-new-before-
delete revisions. An inactive atomic-effect journal now makes the application or
control record and its matching opaque ratchet snapshot durable in one encrypted
record before binding that effect digest into the inbox tombstone. A crash in
between restores the effect without running its builder or advancing the ratchet
twice. Missing or mismatched effect/tombstone pairs fail closed.

An inactive identity/passphrase-scoped receive-commit controller now claims the
atomic journal before restore, reconstructs each registered session through a
contiguous TR3 revision chain, validates canonical AR3/LMF/routing bindings, and
serializes revision compare-and-swap before invoking a candidate builder. It
advances the in-memory snapshot only after the durable effect and replay
tombstone both succeed; an ambiguous post-candidate failure requires a fresh
restore. This is the persistence authority boundary, not an active or complete
Triple Ratchet integration.

`PROTOCOL_V3_KEY_SCHEDULE.md` now freezes the next inactive boundary: mandatory
hybrid EC/PQ message-key combination, transcript-bound session/routing/ACK
expansion, deterministic fragment nonces, a canonical committed record, and a
bounded complete Triple Ratchet snapshot envelope. The key schedule has public
golden vectors and the concrete codecs pass through the atomic journal.

`PROTOCOL_V3_HANDSHAKE.md` now freezes an inactive three-message authenticated
hybrid candidate. Both peers contribute an ephemeral X25519 key and an
ML-KEM-768 encapsulation; five ordered X25519 outputs and both ordered ML-KEM
secrets produce symmetric responder and initiator confirmation tags. Complete
identities, installation devices, roles, mode, capabilities, record IDs, and
every canonical handshake record are bound into the final SHA-384 transcript.
The tags are deliberately symmetric rather than transferable signatures, so
the candidate preserves a limited deniability design. Canonical pending-state
records now live in the real identity/passphrase-scoped encrypted Aux store:
the exact offer/reply is persisted before first export, survives restart
without repeating ML-KEM, and is replaced only after a checkpoint-bound
completion tombstone is durable. Crossed offers use a clock-free deterministic
tie-break, which the future active contact/device coordinator must enforce.

The handshake is still a research candidate and is not wired to bootstrap
transport, contacts, messages, UI, backup, or Premium. The v3 EC
transition engine and HR3 transport are now implemented as inactive components.
The receive-commit controller still depends on a reviewed native ML-KEM Braid
transition/state validator and trusted candidate construction. A complete send
and receive persistence authority, deferred continuation-key resolution,
checkpointing, replay retirement, pending-handshake persistence, and the exact
prepare/checkpoint/tombstone initial-TR3 handoff exist only behind the inactive
v3 boundary. Controller-level device policy, a reviewed production SCKA
backend, active projection, resend/progress UX, real cross-app loss tests, and
erasure coding remain activation gates.
