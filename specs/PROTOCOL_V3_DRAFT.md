# Layergram Protocol v3 — Security and Identity Draft

Status: **integrated implementation candidate; inactive; not a security claim**

This document defines the falsifiable invariants for the intentionally
incompatible Layergram protocol v3 candidate. The application integration is
complete behind a fail-closed selector, but the protocol is not activated or
independently approved.

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

The maximum 1,270-byte binary identity is encoded as one static QR at
error-correction level M, where it occupies QR version 30 (137 x 137 data
modules). The branded renderer reserves a four-module quiet zone, for 145 x 145
modules overall, and centers a Layergram logo whose side is 20% of the complete
symbol side. The preview and normal exported PNG use this same renderer; the
export is 1,024 x 1,024 pixels.

Native decoders return the original binary payload byte-for-byte at the
1,024-pixel export size. Bidirectional physical-camera checks also pass between
an iPhone 14 Pro Max and a Huawei SNE-LX1: the iPhone app scanner reads the
maximum 1,270-byte Android test identity, and the Android native scanner harness
reads the complete 1,243-byte iPhone identity. The enlarged presentation uses a
uniform light surface and raises only the app window to a 60% brightness floor,
restoring the previous value when it closes; a dark surround was rejected after
it caused glare and materially slower Android recognition. A 300-DPI render of
the production 1,024-pixel PNG decodes exactly at each 50, 45, 40, 35, 30, and
25 mm test size. Actual printed-media, damage, compression, lighting, and broader
device coverage remain release tests rather than implied by codec capacity.

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
- documented security review with no unresolved high or critical findings.

The native wrapper and inactive packaging now traverse the production ABI on
an Android arm64 emulator, an iOS arm64 simulator, a macOS arm64 app, and a
Windows x64 app running on Windows 11 ARM64, plus a Linux x64 app on Ubuntu
22.04; the packaged Android libraries and Apple binaries also cover their
release architectures. This is an engineering checkpoint, not the
production-native-backend gate: physical devices, distribution signing, any
distributed Linux ARM64 or native Windows ARM64 build, complete per-ABI
vectors, and representative physical QR/carrier tests remain. See
`ML_KEM_BACKEND.md`.

## Inactive complete local-identity checkpoint

`V3LocalIdentityFactory` now restores a complete hybrid public identity from a
valid mnemonic using the explicit v3 X25519 and ML-KEM derivation labels. It
requires the native backend self-test, validates the generated ML-KEM public
key, keeps the expanded ML-KEM private key behind an opaque native handle, and
wipes temporary seed buffers on both success and failure. Passphrase-scoped
restoration uses both the BIP39 passphrase and the separate v3 passphrase
derivation namespace.

The factory is reachable only through the inactive v3 lifecycle and provider
seams. It is not an activation: v2 remains preferred and no active application
path can construct the v3 runtime while the selector is false.

Imported identities have a distinct `V3PublicIdentityValidator` boundary. It
first applies the strict canonical codec, then requires the native backend
self-test and the FIPS 203 public-key validity check. Its validated wrapper means
only “structurally usable”; it never substitutes owner authentication or the
v3 fingerprint/SAS ceremony.

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
tie-break, which the gated contact/device coordinator enforces after activation.

The handshake and application runtime remain implementation candidates behind the
inactive v3 boundary. They now compose canonical identity import, durable
offer/reply/confirmation bootstrap, the exact initial-TR3 handoff, complete
send/receive persistence authority, deferred continuation-key resolution,
checkpointing, replay retirement, AP3 application plaintext, Normal-mode
multi-device send groups, Maximum-mode exclusivity, exact receiver-ACK retry,
and per-frame text/link/steganography carriage. `APPLICATION_MESSAGE_V3.md`
freezes that application boundary.

This is application/runtime integration, not product activation. Contact and
message repositories, chat UI, migration, passphrase-scoped lifecycle, and
downstream capability seams are connected only behind the false activation
selector. The controller depends on an approved native SCKA candidate and
trusted construction. Its initial registration/completion API is protected by
one unexposed scope-created identity capability, including concurrent forged-
claim rejection. Hosted CI, current physical devices, real cross-application
loss/preservation tests, signed distribution-artifact verification, and
independent review remain activation gates. The user consequences are defined
in [Protocol v3 Migration](PROTOCOL_V3_MIGRATION.md).
