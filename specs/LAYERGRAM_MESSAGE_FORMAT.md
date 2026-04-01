# Layergram Message Format (LMF) Specification

**Version:** 1.0  
**Status:** Stable  

This document defines the **Layergram Message Format (LMF)**, the protocol used by Layergram to embed end-to-end encrypted messages within standard, visually innocuous text messages.

The specification in this document is implemented by the public Layergram application and by official Layergram builds released through the project's official channels.

---

## 1. Why

Traditional end-to-end encrypted (E2EE) messaging apps require both parties to use the same proprietary platform.

The **Layergram Message Format (LMF)** decouples the encryption layer from the transport layer. By encoding the ciphertext into Unicode zero-width characters (steganography) and interleaving them within normal visible text ("cover message"), LMF allows encrypted payloads to travel over **any** text-based channel.

This approach provides:

1. **Transport Agnosticism:** Messages can be sent over WhatsApp, Telegram, Signal, iMessage, email, or even standard SMS — any channel that preserves Unicode.
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
| `v` | int | Format version (currently `1`) |
| `senderId` | string | Full sender identity ID |
| `recipientId` | string | Full recipient identity ID |
| `timestamp` | int | Unix timestamp (milliseconds) |
| `text` | string | The secret message content |
| `senderDisplayName` | string? | Optional sender display name |
| `expireAfter` | int? | Optional TTL in seconds |
| `deleteAfterRead` | bool | Whether the message self-destructs after reading |

### 2.2 Raw Binary Ciphertext

To maximize deniability, the encrypted payload does **not** contain any plaintext prefix, marker, or metadata (such as "LAYERGRAM|" or sender/recipient IDs). The payload is a pure sequence of raw bytes resulting from AES-GCM-256 encryption.

```
rawPayloadBytes = 12-byte AES-GCM nonce || AES-GCM-ciphertext || 16-byte MAC
```

---

## 3. Steganographic Encoding

Layergram currently supports a single steganographic standard: the raw-binary zero-width format described in this section. Older logical-payload steganography formats are not part of the supported protocol.

### 3.1 Base-4 Symbol Alphabet

The `rawPayloadBytes` are converted to bits (each byte → 8 bits) and encoded at **2 bits per rune** using four specific zero-width Unicode characters that survive filtering on major platforms (like WhatsApp):

| Bit pair | Symbol | Unicode Name |
|---|---|---|
| `00` | `U+200B` | Zero Width Space |
| `01` | `U+200C` | Zero Width Non-Joiner |
| `10` | `U+200D` | Zero Width Joiner |
| `11` | `U+2061` | Function Application |

For robustness, decoders **MAY** additionally accept `U+2060` and `U+2062` as aliases for `11` if these characters appear after transport-layer normalization. Encoders **MUST NOT** emit them as primary payload symbols.

### 3.2 Noise Injection for Deniability

To prevent the encoded message from presenting a predictable statistical pattern, **noise characters** are randomly injected into the hidden blocks during encoding.

| Noise Symbol | Unicode Name |
|---|---|
| `U+200E` | LEFT-TO-RIGHT MARK |
| `U+200F` | RIGHT-TO-LEFT MARK |
| `U+2063` | INVISIBLE SEPARATOR |
| `U+2064` | INVISIBLE PLUS |
| `U+FEFF` | ZERO WIDTH NO-BREAK SPACE (BOM) |

Within each hidden block (see section 3.3), payload symbols and noise characters are **interleaved at random positions**. The relative order of payload symbols is preserved, but noise characters are placed at randomly chosen positions throughout the block. The decoder ignores noise characters entirely because they are not part of the core Base-4 alphabet.

### 3.3 Distribution Across Cover Text

The hidden runes are distributed **between the visible characters** of the cover text, but **not from the very beginning**. Layergram reserves a clean visible prefix so that messaging apps can render a normal-looking chat preview before any invisible data appears.

#### 3.3.1 Block Construction

Each slot receives a **block** of hidden runes with the following properties:

- **Minimum block size:** 8 runes (or the number of payload symbols assigned to the slot plus the minimum mixed-slot noise requirement, whichever is larger).
- **Maximum block size:** 48 runes.
- **Actual block size:** chosen randomly between the minimum and 48 for each slot independently.
- **Content:** the payload symbols assigned to the slot are placed at **random positions** within the block (preserving their relative order), and all remaining positions are filled with random noise characters.

The 48 rune limit applies to the **total** runes in the block (payload + noise combined).

In addition to mixed payload+noise blocks, some eligible suffix slots may receive **noise-only decoy blocks**, while other eligible slots may remain completely clean. This avoids a rigid "hidden block after every letter" pattern.

#### 3.3.2 Preview-Safe Clean Prefix

Before any hidden rune is inserted, Layergram reserves a clean prefix of visible characters:

- **Minimum clean prefix:** 64 visible characters.
- **Preferred randomized clean prefix:** between 64 and 96 visible characters, whenever the cover text is long enough.

This means that the earliest hidden block starts only **after** the clean prefix. The exact start position is randomized per message, so that messages do not all begin embedding at a fixed offset.

#### 3.3.3 Eligible Slots

Only the inter-character slots in the **suffix after the clean prefix** are eligible for embedding.

If the cover text has `N` visible characters and the chosen clean prefix has length `P`, then the number of eligible slots is:

```
eligibleSlots = N - P
```

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
payloadPerSlot[i] <= maxPayloadPerCarrierSlot
```

This preserves global payload order while avoiding a rigid left-to-right even split that could become recognizable.

#### 3.3.5 Minimum Cover Text Length

To ensure all payload symbols fit while preserving the clean preview-safe prefix, the minimum cover text length is calculated conservatively using the **maximum payload capacity per carrier slot**:

```
maxPayloadPerCarrierSlot = 48 - 2 = 46
requiredCarrierSlots = ceil(payloadSymbols / 46)
minCoverLength = 64 + requiredCarrierSlots
```

The actual clean prefix may be longer than 64 (up to 96) when cover length allows it. The formula above guarantees the minimum safe case.

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

#### Trade-Off

Direct message links sacrifice **visual deniability**: the link is clearly identifiable as a Layergram encrypted message. Use this method only on platforms that aggressively sanitize zero-width Unicode characters.

---

## 5. Examples

### Raw Binary Ciphertext
```
[12 bytes nonce] [145 bytes AES-GCM ciphertext] [16 bytes MAC] = 173 bytes
```

### Encoded Message (Conceptual)
Given a sufficiently long cover text and 400 payload symbols:

```
maxPayloadPerCarrierSlot = 46
requiredCarrierSlots = ceil(400 / 46) = 9
minCoverLength = 64 + 9 = 73
```

Suppose the chosen clean prefix for this message is 71 visible characters.

Then embedding starts only after character 71, and only the suffix slots are eligible. A randomized subset of those suffix slots becomes carrier slots, while some additional eligible slots may become noise-only decoys.

Each used slot's block is independently sized between 8 and 48 runes total:

```
[clean visible prefix...71 chars...] c [11 runes] o [0] m [23 runes] e [0]   [14 runes] s [9 runes] t [0] a [17 runes] i
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