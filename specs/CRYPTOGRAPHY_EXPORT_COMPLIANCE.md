# Layergram - Cryptography Export Compliance Notes

**App name:** Layergram

**Bundle ID:** `app.layergram.app`

**Developer:** Simone Riccetti

**Contact:** dev@layergram.app

These notes are a technical inventory for release and store-review workflows.
They are not legal advice or a final export-classification determination. The
developer must review the rules, destinations, declarations, and store forms
applicable to each release.

## 1. Product scope

Layergram is an end-to-end encrypted messaging application. Encryption and
decryption happen locally, and opaque message text is transferred through an
external communication channel chosen by the user. Layergram does not provide
a VPN, proxy, telecommunications interception function, cryptographic API
service, account server, key directory, or message relay.

Layergram 2.0 and later use active protocol v3 behind a fail-closed activation
selector. Earlier releases use protocol v2 and are not post-quantum protected.

## 2. Cryptographic inventory

| Use | Algorithm | Parameters/reference | Runtime status |
|---|---|---|---|
| Identity and key agreement | X25519 | RFC 7748, 32-byte keys | Active v3 classical branch; legacy v2 |
| Post-quantum KEM | ML-KEM-768 | NIST FIPS 203; 1,184-byte encapsulation key, 1,088-byte ciphertext | Active v3 |
| Message AEAD | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag; FIPS 197 and SP 800-38D | Active v3 framing; legacy v2 |
| Native-state AEAD | AES-256-GCM-SIV | RFC 8452 | Active v3 |
| Key derivation and authentication | HKDF/HMAC-SHA-256 | RFC 5869 and FIPS 180-4 | Active as specified |
| Identity/transcript digest | SHA-384 | FIPS 180-4 | Active v3 |
| Other integrity/fingerprints | SHA-256 | FIPS 180-4 | Active as specified |

The Flutter/Dart layer uses the open-source `package:cryptography` dependency
for its documented primitives. The v3 native components are independent Rust
code using pinned, permissively licensed dependencies. ML-KEM-768 is provided
through the pinned native backend and validated against the repository's public
FIPS 203 vectors and self-tests. Exact versions, hashes, license choices, and
notices are recorded in the lockfiles, native manifests,
`THIRD_PARTY_NOTICES.md`, and the protocol-v3 audit receipt.

No cryptographic key, ciphertext, shared secret, or security parameter is
truncated to make a v3 identity QR code or message carrier smaller.

## 3. Key generation, storage, and use

1. A user's BIP39 recovery phrase is generated locally from the platform CSPRNG
   and produces deterministic, versioned identity material. The optional BIP39
   passphrase selects a separate domain-separated context.
2. Protocol v2 derives an X25519 identity. Active protocol v3 derives
   separate X25519 and ML-KEM-768 identity material from the same recovery
   secret; it does not reuse the v2 cryptographic identity.
3. Fresh device, handshake, nonce, and ratchet entropy comes from the supported
   operating system's cryptographically secure random source. Entropy failure
   fails closed.
4. Recovery secrets and private state remain local. OS secure storage protects
   wrapping/storage secrets where supported; encrypted local repositories hold
   bounded protocol state. Expanded v3 ML-KEM private material is kept behind an
   opaque native handle, not serialized into a public identity, QR, link, or
   message.
5. Public identity carriers contain public material only. Importing a public
   identity does not authenticate its owner; users must verify the complete
   fingerprint or SAS through an independent channel.

## 4. Source and licensing

Layergram's public cryptographic source is available in this repository.
Third-party notices are preserved in the applicable source and packaged notice
files. The v3 dependency policy excludes incompatible copyleft implementation
code and records license paths suitable for Apache-2.0 and commercial
downstream distribution.

The protocols use published standards or openly published protocol
specifications. Layergram's framing, persistence, orchestration, and
domain-separation rules are publicly documented application protocol logic;
they are not proprietary secret ciphers.

## 5. Release checklist

Before activating or distributing protocol v3, the release owner must:

- refresh this inventory and the machine-readable dependency/license receipts;
- verify native hashes, self-tests, supported ABIs, and signed distribution
  artifacts through the established Android, Apple, and Microsoft Store flows;
- complete the independent security-review gate;
- answer current store/export questions based on the exact activated artifact,
  destinations, and applicable law;
- keep required notices and source-access information with the release.

Historically Layergram has been treated as mass-market encryption software, but
that description is not a substitute for release-specific classification or
filing advice. Store metadata such as Apple's encryption declarations must be
reviewed for the exact release rather than copied mechanically from this file.

## 6. Contact

For compliance questions, contact **dev@layergram.app**.
