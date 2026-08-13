# Layergram Protocol v3 — Security and Identity Draft

Status: **research implementation; not enabled for users; not a security claim**

This document defines the first falsifiable invariants for the intentionally
incompatible Layergram protocol v3. It does not declare the protocol complete
or independently reviewed.

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

## Initial transport limitation

An ML-KEM-768 ciphertext is 1,088 bytes and does not fit the current 800-byte
forward-secrecy control budget. It must be fragmented for steganographic
bootstrap. The steady-state sparse PQ ratchet will use bounded smaller chunks.
Neither issue may be hidden through a classical-only fallback labelled as v3.

With the current steganographic alphabet, the raw ciphertext alone would need
272 carrier slots and at least 336 visible cover characters. A research-only
256-byte raw-fragment cap yields five fragments (256, 256, 256, 256, 64) and at
least 128 visible cover characters for each full fragment. These numbers exclude
the authenticated fragment header, routing fields, and AEAD overhead; 256 bytes
is a measurement point, not yet a protocol constant.
