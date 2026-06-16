# Layergram Message Format (LMF) Specification

**Version:** 2.1
**Status:** Forward Secrecy branch draft; LMF v2 base format stable

This document defines the **Layergram Message Format (LMF)**, the protocol used by Layergram to embed end-to-end encrypted messages within standard, visually innocuous text messages.

## Version History

- **LMF v2.1 (Forward Secrecy branch draft)**: Adds optional Forward Secrecy envelope fields and `x.fs` control extensions while preserving the raw-binary outer transport.
- **LMF v2.0 (Stable base)**: Introduces structured inner container, gzip compression, hardened Unicode alphabet. Always encode with v2; decode supports v2 then v1 fallback.
- **LMF v1.1 (Legacy)**: Original format with raw JSON encryption. Decode-only support for backward compatibility.

The stable LMF v2.0 base format is implemented by the public Layergram application and by
official Layergram builds released through the project's official channels. The v2.1 Forward
Secrecy additions are implemented in the FS branch until they are promoted into an official
release.

---

## 1. Why

Traditional end-to-end encrypted (E2EE) messaging apps require both parties to use the same proprietary platform.

The **Layergram Message Format (LMF)** decouples the encryption layer from the transport layer. By encoding the ciphertext into Unicode zero-width characters (steganography) and interleaving them within normal visible text ("cover message"), LMF allows encrypted payloads to travel over **any** text-based channel.

This approach provides:

1. **Transport Agnosticism:** Messages can be sent over WhatsApp, Telegram, Signal, iMessage, email — any channel that preserves Unicode. For channels that strip or normalize invisible characters, a **direct message link** format (`layergram://m/<payload>`) is available as a fallback (see Section 4.3).
2. **Visual Deniability:** To an outside observer, automated filter, or platform moderator, the message looks like an ordinary conversation. The encrypted data does not contain any recognizable signature or prefix.
3. **Resilience:** The encoding and distribution strategy is specifically designed to survive platform-specific character truncation.

---

## 2. Encryption

LMF uses the following cryptographic primitives:

| Component | Algorithm |
|---|---|
| Key Agreement | X25519 (Elliptic Curve Diffie-Hellman) |
| Key Derivation | HKDF-SHA256 (info: `msg-encryption`, salt: `layergram-v1`) |
| Symmetric Encryption | AES-GCM-256 |

### 2.1 Plaintext Structure

Before encryption, the secret message is serialized as a JSON object:

The JSON serialization is encoded as UTF-8 before encryption. Any valid Unicode content is permitted in `text` and `senderDisplayName`, including accented letters, combining-mark sequences, emoji, and mixed-script text.

```json
{
  "v": 1,
  "senderId": "<full sender identity ID>",
  "recipientId": "<full recipient identity ID>",
  "timestamp": 1700000000,
  "text": "The actual secret message",
  "senderDisplayName": "Alice",
  "expireAfter": null,
  "deleteAfterRead": false
}
```

| Field | Type | Description |
|---|---|---|
| `v` | int | Format version (`2` for LMF v2) |
| `senderId` | string | Full sender identity ID |
| `recipientId` | string | Full recipient identity ID |
| `timestamp` | int | Unix timestamp (milliseconds since epoch) |
| `text` | string | The secret message content |
| `senderDisplayName` | string? | Optional sender display name |
| `expireAfter` | int? | Optional TTL in seconds |
| `deleteAfterRead` | bool | Whether the message self-destructs after reading |

### 2.1.1 Forward Secrecy Envelope Fields

When a confirmed FS session is available, the JSON envelope remains encrypted inside the same
LMF v2 raw binary payload, but the secret message text is not stored directly in `text`.
Instead, the envelope carries FS metadata and an inner ratchet ciphertext:

| Field | Type | Description |
|---|---|---|
| `fs_v` | int | FS envelope version (`1`) |
| `fs_session` | string | Opaque FS session identifier used to select the ratchet state |
| `fs_ratchet_pub` | string | Sender ratchet public key, canonical FS key encoding |
| `fs_counter` | int | Message counter within the sender ratchet chain |
| `fs_cipher` | string | Base64-encoded FS ciphertext plus MAC |
| `fs_nonce` | string | Base64-encoded derived AES-GCM nonce |

The FS ciphertext decrypts to the message `text`. The identity-encrypted outer LMF envelope is
still authenticated first; then the receiver checks replay state for `(fs_session, fs_counter)`
before advancing the Double Ratchet.

FS control negotiation messages are carried in an optional extension:

```json
{
  "x": {
    "fs": {
      "type": "fs_init | fs_reply | fs_confirm | fs_ack | fs_suspend | fs_reset",
      "...": "type-specific fields"
    }
  }
}
```

Older clients that do not understand `x.fs` ignore it and keep using the base model.

### 2.1.2 Multi-Envelope FS

When a contact has more than one active device session, the sender may encrypt the plaintext
once with a fresh content key and wrap that key separately for each device ratchet:

| Field | Type | Description |
|---|---|---|
| `fs_multi` | int | Multi-envelope marker (`1`) |
| `mc_cipher` | string | Base64-encoded content ciphertext plus MAC |
| `mc_nonce` | string | Base64-encoded content nonce |
| `fs_wraps` | array | Per-session FS wraps for the content key |
| `mc_fallback_key` | string? | Optional legacy fallback content key; forbidden in Strict/Maximum FS |

Each `fs_wraps[]` entry uses the same FS fields as a single-envelope message
(`fs_session`, `fs_ratchet_pub`, `fs_counter`, `fs_cipher`, `fs_nonce`), but its plaintext is
the content key rather than the user message. The receiver selects the wrap matching one of its
known sessions and advances only that ratchet.

`mc_fallback_key` is off by default because it weakens Forward Secrecy. If present, the message
classification is `fs_with_fallback`; Strict/Maximum FS messages must not include it.

### 2.2 Raw Binary Ciphertext

To maximize deniability, the encrypted payload does **not** contain any plaintext prefix, marker, or metadata (such as "LAYERGRAM|" or sender/recipient IDs). The payload is a pure sequence of raw bytes resulting from AES-GCM-256 encryption.

```
rawPayloadBytes = 12-byte AES-GCM nonce || AES-GCM-ciphertext || 16-byte MAC
```

### 2.3 LMF v2 Inner Container (LMFv2Inner)

LMF v2 wraps the plaintext before encryption. This enables compression and future extensibility:

```
LMFv2Inner =
    1 byte  formatVersion    (0x02)
    1 byte  flags            (bitmask)
    2 bytes reserved         (0x0000)
    N bytes payloadBytes
```

**Field values:**

| Field | Value | Description |
|---|---|---|
| `formatVersion` | `0x02` | LMF v2 format identifier |
| `flags` | bitmask | bit 0 = 1 if payloadBytes is gzip-compressed |
| `reserved` | `0x0000` | Must be zero (enables future extensions) |
| `payloadBytes` | bytes | UTF-8 JSON (plain or gzip-compressed) |

**Processing order for encoding:**
1. Build v2 JSON envelope
2. UTF-8 encode the JSON
3. Optionally compress with gzip (see section 2.4)
4. Construct LMFv2Inner container
5. Encrypt LMFv2Inner with AES-GCM-256

**Processing order for decoding:**
1. Decrypt with AES-GCM-256
2. Parse LMFv2Inner header (validate formatVersion, reserved, flags)
3. Decompress if compression flag is set
4. Decode UTF-8 JSON
5. Validate `json.v == 2`

### 2.4 Compression (LMF v2)

LMF v2 uses **gzip** compression (via pure Dart `archive` package) to reduce payload size for long messages. Using gzip instead of zstd avoids native FFI dependencies that cause code signing issues on macOS, while still providing good compression ratios.

**Policy:**
- Compression level: 6 (gzip default)
- Compression threshold: do not compress if plaintext < 96 bytes
- Minimum savings: only use compressed form if it saves at least 4 bytes
- If compression fails: fall back to uncompressed (set compression flag to 0)

```
if plaintextLen < 96:
    use uncompressed
else:
    compressed = gzip(plaintext, level=6)
    if compressedLen + 4 < plaintextLen:
        use compressed, set compression flag = 1
    else:
        use uncompressed, set compression flag = 0
```

---

## 3. Steganographic Encoding

Layergram primarily uses a single steganographic standard: the raw-binary zero-width format described in this section. Older logical-payload steganography formats are not part of the supported protocol.

**Note:** Steganographic embedding requires the transport to preserve zero-width Unicode characters. For transports that strip these characters (or when the user prefers explicit sharing), LMF supports an alternative **direct message link** format (see Section 4.3). Deep links make the presence of encryption visibly obvious, unlike steganographic embedding which requires instrumental analysis to detect.

### 3.1 Base-4 Symbol Alphabet

The `rawPayloadBytes` are converted to bits (each byte → 8 bits) and encoded at **2 bits per rune** using four specific zero-width Unicode characters that survive filtering on major platforms (like WhatsApp):

| Bit pair | Symbol | Unicode Name |
|---|---|---|
| `00` | `U+200B` | Zero Width Space |
| `01` | `U+200C` | Zero Width Non-Joiner |
| `10` | `U+200D` | Zero Width Joiner |
| `11` | `U+2061` | Function Application |

**LMF v2 vs v1 Alphabet Differences:**

- **LMF v2 (current):** Uses exact alphabet only. Decoders accept only `U+200B`, `U+200C`, `U+200D`, `U+2061`.
- **LMF v1 (legacy):** For backward compatibility, legacy decoders may accept `U+2060` and `U+2062` as aliases for `11`. These aliases are **not** valid in v2.

Encoders **MUST NOT** emit aliases (`U+2060`, `U+2062`) or forbidden characters (`U+200E`, `U+200F`).

### 3.2 Noise Injection for Deniability

To prevent the encoded message from presenting a predictable statistical pattern, **noise characters** are randomly injected into the hidden blocks during encoding.

**LMF v2 Noise Alphabet:**

| Noise Symbol | Unicode Name |
|---|---|
| `U+2063` | INVISIBLE SEPARATOR |
| `U+2064` | INVISIBLE PLUS |
| `U+FEFF` | ZERO WIDTH NO-BREAK SPACE (BOM) |

**Forbidden Characters (LMF v2):**

These characters must **never** appear in LMF v2 steganographic output:

| Forbidden Symbol | Unicode Name | Reason |
|---|---|---|
| `U+200E` | LEFT-TO-RIGHT MARK | Normalizes to U+200C on some platforms (Telegram) |
| `U+200F` | RIGHT-TO-LEFT MARK | Normalizes to U+200C on some platforms (Telegram) |

**Important rules:**
- `U+200C` is **payload-only** in v2. Never use it as noise, separator, filler, or alias.
- The decoder ignores noise characters entirely because they are not part of the payload alphabet.
- Within each hidden block, payload symbols and noise characters are **interleaved at random positions**.
- The relative order of payload symbols is preserved.

### 3.3 Distribution Across Cover Text

The hidden runes are distributed **between the visible characters** of the cover text, but **not from the very beginning**. Layergram reserves a clean visible prefix so that messaging apps can render a normal-looking chat preview before any invisible data appears.

#### 3.3.1 Block Construction

Each slot receives a **block** of hidden runes with the following properties:

- **Minimum block size:** 8 runes (or the number of payload symbols assigned to the slot plus the minimum mixed-slot noise requirement, whichever is larger).
- **Maximum mixed-slot block size:** 22 runes.
- **Maximum noise-only decoy block size:** 12 runes.
- **Actual mixed-slot block size:** chosen randomly between the minimum and `min(22, payloadSymbolsInSlot + 6)` for each slot independently.
- **Content:** the payload symbols assigned to the slot are placed at **random positions** within the block (preserving their relative order), and all remaining positions are filled with random noise characters.

The 22 rune limit applies to the **total** runes in a mixed block (payload + noise combined). The public Layergram implementation additionally caps payload density so that a carrier slot never receives more than 16 payload symbols. This intentionally spreads the ciphertext across more visible boundaries instead of concentrating a very large hidden cluster between two letters.

In addition to mixed payload+noise blocks, some eligible suffix slots may receive **noise-only decoy blocks**, while other eligible slots may remain completely clean. This avoids a rigid "hidden block after every letter" pattern.

#### 3.3.2 Preview-Safe Clean Prefix

Before any hidden rune is inserted, Layergram reserves a clean prefix of visible characters:

- **Minimum clean prefix:** 64 visible characters.
- **Preferred randomized clean prefix:** between 64 and 96 visible characters, whenever the cover text is long enough.

This means that the earliest hidden block starts only **after** the clean prefix. The exact start position is randomized per message, so that messages do not all begin embedding at a fixed offset.

#### 3.3.3 Eligible Slots

Only the inter-character slots in the **suffix after the clean prefix** are candidates for embedding.

The public Layergram implementation further restricts embedding to **carrier-safe** slots: boundaries where both adjacent visible grapheme clusters are composed entirely of printable ASCII code points (`U+0020`-`U+007E`). Boundaries touching non-ASCII or otherwise complex grapheme clusters are left clean to avoid transport-layer rendering corruption around accented characters, combining sequences, emoji, or script-shaping controls.

If the cover text has `N` visible characters and the chosen clean prefix has length `P`, then the candidate suffix-slot count is:

```
candidateSlots = N - P
```

The actual number of eligible slots is the carrier-safe subset of those candidate suffix slots.

No hidden runes are placed before the first visible character or after the final visible character.

#### 3.3.4 Payload Distribution

Payload symbols are distributed across a **randomized subset** of the eligible suffix slots, not evenly across all slots.

The encoder:

1. Chooses a randomized clean prefix length in the allowed range.
2. Computes the eligible suffix slots.
3. Selects a randomized set of **carrier slots** large enough for the payload.
4. Optionally selects additional **noise-only decoy slots**.
5. Leaves the remaining eligible suffix slots clean.

Payload symbols are then assigned to carrier slots using **bounded random chunking**:

```
carrierSlots = randomized subset of eligible suffix slots
payloadPerSlot = randomized positive chunk sizes
sum(payloadPerSlot) = payloadSymbols
payloadPerSlot[i] <= 16
```

This preserves global payload order while avoiding a rigid left-to-right even split that could become recognizable.

#### 3.3.5 Minimum Cover Text Length

To ensure all payload symbols fit while preserving the clean preview-safe prefix, the minimum cover text length is calculated conservatively using the **maximum payload capacity per carrier slot**:

```
payloadSymbols = rawPayloadBytes.length * 4
maxPayloadPerCarrierSlot = 16
requiredCarrierSlots = ceil(payloadSymbols / 16)
minCoverLength = 64 + requiredCarrierSlots
```

For exact user-facing validation, `rawPayloadBytes` means the final byte array
that will be embedded after the complete message has been constructed and
encrypted. This includes all optional protocol fields and envelopes, including
forward-secrecy metadata such as `fs_*` fields, `x.fs`, `fs_multi`, `fs_wraps`,
and `mc_fallback_key` when present. A pre-encryption estimate based only on the
secret text length is therefore only a UI estimate; send/copy/share actions MUST
re-check cover capacity against the final `rawPayloadBytes.length`.

The actual clean prefix may be longer than 64 (up to 96) when cover length allows it. The formula above guarantees the minimum safe case.

In addition to satisfying the minimum visible length, the cover text must contain at least `requiredCarrierSlots` carrier-safe eligible slots after filtering. Covers with many accented, emoji, or other non-ASCII grapheme clusters may therefore require additional visible text even when the simple length formula is met.

When reporting how much text the user must add, implementations SHOULD compute
the minimal number of plain visible ASCII characters that must be appended to
the normalized current cover text until both conditions are true: visible length
is at least `minCoverLength`, and carrier-safe eligible slot count is at least
`requiredCarrierSlots`.

Before this length is checked, the cover text is normalized with trailing-whitespace trimming. In other words, spaces, tabs, or line breaks after the user's last non-whitespace character do **not** count as usable cover capacity.

If the normalized cover text is too short, encoding must fail and the UI must require a longer visible cover message rather than appending any visible or invisible data after the user's final character.

### 3.4 No Leading or Trailing Hidden Runes

The encoding strictly avoids placing any invisible characters before the first or after the final visible character of the normalized cover text. Any trailing whitespace present in the user input is removed before embedding, so the resulting message never gains extra spaces or zero-width characters after the user's final non-whitespace character.

---

## 4. Decoding and Multi-Key Trial

Because the steganographic payload is purely binary and lacks any unencrypted sender/recipient identifiers, the receiving client must attempt decryption to find out if the message is addressed to the user.

### 4.1 Steganographic Decoding
1. The client scans the text and collects only the runes matching the Base-4 alphabet, automatically ignoring injected noise characters.
2. The sequence of 2-bit symbols is converted back into raw bits.
3. Because platforms sometimes truncate leading characters, the decoder generates **up to 8 byte alignment candidates** by shifting the start bit from offset `0` to `7`. Each alignment yields a candidate byte array `rawPayloadBytes`.

### 4.2 Multi-Key Trial Decryption
For every candidate byte array, the client attempts AES-GCM decryption using derived symmetric keys from the local user's contacts.

To minimize decryption time, the client tries the keys in priority order:
1. **Self Key:** Decrypting a message sent to oneself.
2. **Hint Contact Key:** The key of the currently open chat (if the user pasted the text inside a specific conversation).
3. **Frequent Contacts:** Contacts sorted by the number of messages exchanged in the past.
4. **All Other Contacts.**

If AES-GCM decryption succeeds (the MAC validates), the payload is parsed as JSON and displayed.

### 4.3 Direct Message Link (No Steganography)

As an alternative to steganographic embedding, LMF supports sharing the encrypted raw binary payload as a **direct deep link**:

```
layergram://m/<base64url_raw_bytes>
```

The `<base64url_raw_bytes>` is the entire `rawPayloadBytes` array, encoded in base64url without padding (`+`→`-`, `/`→`_`, `=` stripped).

**Decoding:**
1. Strip the `layergram://m/` prefix.
2. base64url-decode the remainder to get `rawPayloadBytes`.
3. Proceed with the Multi-Key Trial Decryption (Section 4.2).

#### Trade-Off and When to Use

Direct message links sacrifice **visual deniability**: the link is clearly identifiable as a Layergram encrypted message, making the presence of encrypted communication obvious to anyone who sees the link.

**When to use deep links instead of steganography:**
- Transport platforms that strip or normalize zero-width Unicode characters (some email gateways, certain web forms)
- Situations where the recipient needs an obvious, clickable entry point to the message
- When the user prefers explicit sharing over hidden embedding

**Important:** Unlike steganographic embedding, deep links do not hide the existence of encrypted communication — they advertise it. Use steganography when you want the message to look like an ordinary conversation; use deep links when transport compatibility or usability is more important than hiding the message's existence.

---

## 5. Encoder and Decoder Behavior

### 5.1 Encoding Policy (LMF v2 Only)

**All newly encoded messages MUST use LMF v2.**

The encoder:
1. Constructs a v2 JSON envelope with `v: 2`
2. UTF-8 encodes the JSON
3. Applies gzip compression if beneficial (see section 2.4)
4. Wraps in LMFv2Inner container with `formatVersion: 0x02`
5. Encrypts with AES-GCM-256
6. Maps bytes to v2 payload alphabet (U+200B, U+200C, U+200D, U+2061)
7. Injects noise using v2 noise alphabet only (U+2063, U+2064, U+FEFF)
8. Distributes hidden runes into cover text

**Forbidden in v2 output:**
- `U+200E` and `U+200F` (LRM/RLM)
- `U+200C` used as noise
- `U+2060` and `U+2062` (v1 aliases)

### 5.2 Decoding Strategy (v2 then v1)

When receiving a message, the decoder attempts:

1. **LMF v2 decode first:**
   - Extract only v2 payload runes (U+200B, U+200C, U+200D, U+2061)
   - Ignore v2 noise runes (U+2063, U+2064, U+FEFF)
   - Convert to bytes, decrypt, parse LMFv2Inner
   - Validate header (formatVersion == 0x02, reserved == 0, flags valid)
   - Decompress if compression flag set
   - Validate JSON `v == 2`

2. **If v2 fails: LMF v1 legacy decode:**
   - Accept v1 payload alphabet plus aliases (U+2060, U+2062)
   - Decrypt and parse as raw JSON (no LMFv2Inner container)
   - Accept JSON without `v` field or with `v == 1`

3. **If both fail:** Message does not contain a valid Layergram payload.

### 5.3 Backward Compatibility

- **Encode:** Always LMF v2 (never emit v1)
- **Decode:** Try v2 first, fall back to v1 for legacy messages
- Legacy v1 support is **decode-only** and isolated in the codebase

---

## 6. Examples

### Raw Binary Ciphertext
```
[12 bytes nonce] [145 bytes AES-GCM ciphertext] [16 bytes MAC] = 173 bytes
```

### Encoded Message (Conceptual)
Given a sufficiently long cover text and 400 payload symbols:

```
maxPayloadPerCarrierSlot = 16
requiredCarrierSlots = ceil(400 / 16) = 25
minCoverLength = 64 + 25 = 89
```

Suppose the chosen clean prefix for this message is 71 visible characters.

Then embedding starts only after character 71, and only the suffix slots are eligible. A randomized subset of those suffix slots becomes carrier slots, while some additional eligible slots may become noise-only decoys.

Each used mixed slot's block is independently sized between 8 and 22 runes total:

```
[clean visible prefix...71 chars...] c [11 runes] o [0] m [18 runes] e [0]   [12 runes] s [9 runes] t [0] a [16 runes] i
```

Within each block, the payload symbols are scattered at random positions (in order) and the remaining positions are filled with noise. Noise-only decoy slots contain only noise characters from the deniability alphabet.

The recipient sees the original visible message with no leading/trailing spaces or hidden characters. The early preview-visible portion remains clean, while the suffix carries the steganographic payload.  
The Layergram app extracts all zero-width runes, discards the noise characters, decodes the remaining payload symbols to candidate byte arrays, performs multi-key trial decryption, and reconstructs the plaintext JSON.

---

## Appendix A: Deep Link Policy

### A.1 Default Policy

The custom URI scheme `layergram://` is **strictly reserved for the official Layergram applications**.

If you create a fork, derivative work, or independent client based on the official public Layergram repository, you **MUST** use your own distinct URI scheme (e.g., `yourapp://`).

### A.2 Third-Party Interoperability

Third-party developers who wish to build interoperable clients that use the official `layergram://` deep link scheme must obtain explicit permission from **Simone Riccetti**. See https://layergram.app/legal for legal and trademark guidance and use the official channels published there to request interoperability approval.

---

## Appendix B: Identity Deep Link Format

Layergram uses deep links to share public identities between users. An identity deep link allows a user to import another user's public key by clicking a link or scanning a QR code.

### B.1 URI Structure

```
layergram://i/<base64url_data>.<base64url_checksum>
```

| Component | Description |
|---|---|
| Scheme | `layergram` |
| Host | `i` (identifies this as an identity link) |
| Path | Single segment: `<data>.<checksum>` |

### B.2 Data Payload

The `<data>` portion is a base64url-encoded (no padding) JSON object:

```json
{
  "v": 1,
  "id": "<identityId>",
  "pk": "<publicKeyBase64>",
  "fp": "<fingerprint>",
  "n": "<displayName>"
}
```

| Field | Description |
|---|---|
| `v` | Link format version (currently `1`) |
| `id` | The user's unique identity ID |
| `pk` | X25519 public key, standard base64 encoded |
| `fp` | Public key fingerprint (human-readable hash) |
| `n` | User's display name |

### B.3 Checksum

The `<checksum>` portion provides integrity verification:

1. Compute SHA-256 of the raw UTF-8 JSON bytes (before base64url encoding).
2. Take the **first 6 bytes** of the hash.
3. Encode them as base64url **without padding**.

### B.4 Decoding and Validation

1. Parse the URI; verify scheme is `layergram` and host is `i`.
2. Split the path segment at the last `.` to separate data and checksum.
3. base64url-decode the data portion.
4. Recompute the checksum from the decoded bytes and compare with the provided checksum.
5. Parse the JSON; verify `v` is a supported version.
6. Reject if `id` or `pk` are empty.

---

## Appendix C: Identity Text Block

For manual sharing (e.g., via email or a text file), Layergram can export an identity as a human-readable text block:

```
[Layergram Identity]
Protocol: layergram/1
Name: Alice
Identity ID: abc123...
Fingerprint: A1B2:C3D4:E5F6:...
Public Key (Base64):
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
[/Layergram Identity]
```

The block is delimited by `[Layergram Identity]` and `[/Layergram Identity]` markers. Each field is on its own line in `Key: Value` format, with the public key on the line following its label.
