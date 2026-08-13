# Layergram Message Format v3 — Canonical Framing Draft

Status: **normative research draft; inactive; not externally reviewed**

This document freezes the first testable candidate for Layergram protocol-v3
binary framing, text/link armor, steganographic carriage, and bounded fragment
reassembly. It does not enable protocol v3, define the handshake or ratchet key
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
- fixed, bounded fragmentation and duplicate-aware reassembly;
- public golden and adversarial parser tests.

It deliberately does not provide:

- handshake or Triple Ratchet key derivation;
- sender proof of possession or contact authentication;
- nonce derivation across a session;
- durable fragment persistence, acknowledgements, resend UI, or crash recovery;
- erasure coding;
- activation in identity, contact, messaging, UI, storage, or Premium paths.

## 2. Integer and canonicalization rules

- All multi-byte integers use unsigned network byte order (big endian).
- No optional or variable-length header fields exist in this draft.
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

The fixed header is exactly 142 bytes:

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 3 | magic | ASCII `LM3` |
| 3 | 1 | protocol version | `0x03` |
| 4 | 1 | suite | registered value |
| 5 | 1 | frame kind | registered value |
| 6 | 1 | flags | zero |
| 7 | 1 | header length | `0x8e` (142) |
| 8 | 2 | ciphertext length | 1–16,384 |
| 10 | 32 | sender binding | non-zero opaque context binding |
| 42 | 32 | recipient binding | non-zero opaque context binding |
| 74 | 16 | message ID | non-zero, unique in its context |
| 90 | 16 | session ID | non-zero |
| 106 | 4 | epoch | authenticated unsigned value |
| 110 | 8 | message counter | 0–2^63−1 in this candidate |
| 118 | 4 | expiry | Unix seconds; zero means no sender-declared expiry |
| 122 | 2 | fragment index | zero based |
| 124 | 2 | fragment count | 1–64 |
| 126 | 4 | final plaintext length | 1–16,384 |
| 130 | 12 | AES-GCM nonce | unique for the session key |
| 142 | N | ciphertext fragment | length declared at offset 8 |
| 142+N | 16 | AES-GCM tag | full, untruncated tag |

The minimum frame is 159 bytes. The maximum syntactically valid single frame is
16,542 bytes.

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
- the exact 142-byte canonical header as associated authenticated data;
- the 12-byte nonce from the header;
- the encrypted fragment as ciphertext;
- the final 16 bytes as the authentication tag.

This binds the suite, kind, flags, routing bindings, message/session IDs, epoch,
message counter, expiry, fragment index/count, final assembled length, nonce,
and fragment length. Header, ciphertext, and tag tampering must fail before any
partial application content is exposed.

The future key schedule must guarantee nonce uniqueness for every use of the
same key. The framing API requires the nonce explicitly and rejects duplicate
nonces within one locally sealed fragment set; that local check is not a
substitute for a reviewed session-wide construction.

## 6. Canonical fragmentation

Single-frame messages use:

- fragment index `0`;
- fragment count `1`;
- ciphertext length equal to final plaintext length.

Multi-frame messages use a fixed 256-byte plaintext fragment size:

```text
fragmentCount = ceil(finalPlaintextLength / 256)
fragmentOffset = fragmentIndex * 256
```

Every non-final fragment is exactly 256 bytes. The final fragment is exactly the
remaining length. Alternative splits, gaps, overlaps, empty fragments, counts
above 64, and final lengths above 16,384 bytes are non-canonical and rejected.

Every fragment is authenticated independently. The receiver authenticates a
frame before placing its plaintext into the private reassembly buffer. It
returns no fragment plaintext to the caller. Only a complete, gap-free set
returns the assembled plaintext.

Reassembly is keyed by suite, kind, both routing bindings, message ID, and
session ID. All other authenticated metadata must match the first accepted
fragment. An exact duplicate is ignored. An authenticated duplicate with
different content, or contradictory authenticated metadata, wipes and rejects
the pending assembly.

The reference implementation defaults to at most 8 pending assemblies and
64 KiB of buffered fragment plaintext, refuses new work instead of silently
evicting valid state, allocates the final buffer only after every fragment is
present, and best-effort wipes discarded managed buffers.

Retention cleanup is explicit rather than time-assumed: legitimate manual
transport can take days or weeks, and Layergram has no trusted shared clock.
The future persistence layer must store sealed frames transactionally before
ratchet state changes. The current in-memory reassembler does not yet satisfy
the crash/restart part of WP-5.

This candidate uses retransmission, not erasure coding. Loss therefore leaves
an assembly incomplete until the missing authenticated frame is supplied. Ack,
progress, resend, and durable recovery remain later WP-5 work.

## 7. Three transports, one binary meaning

### 7.1 Direct text

```text
m3.<unpadded Base64URL(canonical binary frame)>
```

Only ASCII letters, digits, `-`, and `_` are valid after `m3.`. Padding `=`,
whitespace, alternate alphabets, and non-round-tripping forms are rejected.

### 7.2 Deep link

```text
layergram://m/m3.<same text token>
```

User info, ports, queries, fragments, extra path segments, and alternate
serialization are rejected. The link adds a prefix; it is not a different
protocol.

### 7.3 Steganography

The existing hardened Layergram payload alphabet maps the exact binary frame to
four zero-width payload runes per byte and may interleave only the documented
noise runes. The v3 decoder caps input before collecting payload runes, rejects
forbidden U+200E/U+200F, requires a whole number of bytes, and then invokes the
same strict binary parser.

The current conservative portable-share target is 4,000 total characters.
Channel-specific adapters may impose a smaller limit and must preflight the
final frame, not an estimate of the user's plaintext.

For a 256-byte encrypted fragment:

- canonical frame: 414 bytes;
- direct token: 555 characters;
- deep link: 569 characters;
- minimum visible steganographic cover: 168 carrier-safe ASCII characters;
- minimum encoded steganographic length under current noise rules: 2,032
  characters.

For an ML-KEM-768 ciphertext of 1,088 bytes, canonical fragmentation produces
four 414-byte frames and one 222-byte frame. All five fit the 4,000-character
candidate target in text, link, and minimum-cover steganographic form. This is a
codec result, not proof that WhatsApp, Telegram, Signal, or iMessage preserves
the payload; real transport tests remain an activation gate.

## 8. Golden vector

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
4c4d33030101008e00190102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f204142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f608182838485868788898a8b8c8d8e8f90a1a2a3a4a5a6a7a8a9aaabacadaeafb0000000070000000000000009773594000000000100000019a0a1a2a3a4a5a6a7a8a9aaabaa79054837ac70de0f45f1e0271dafb214c93730f4c52301f987ccf30812a75a51aea46274d3f1ac72
```

Canonical direct token:

```text
m3.TE0zAwEBAI4AGQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2CBgoOEhYaHiImKi4yNjo-QoaKjpKWmp6ipqqusra6vsAAAAAcAAAAAAAAACXc1lAAAAAABAAAAGaChoqOkpaanqKmqq6p5BUg3rHDeD0Xx4Ccdr7IUyTcw9MUjAfmHzPMIEqdaUa6kYnTT8axy
```

## 9. Activation boundary

The implementation lives only under `lib/core/crypto/v3/`. Protocol v2 remains
active. Nothing in this draft or codec changes identity import, message send,
message decode, contact state, backups, migration, QR, UI, or Premium capability
contracts.

Before activation, the handshake/ratchet must define routing-binding and nonce
derivation; fragment persistence and resend behavior must survive crashes; all
three transports must pass real cross-app tests; and the complete design and
implementation must pass independent review.
