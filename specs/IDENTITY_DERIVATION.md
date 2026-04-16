# Identity Derivation Model

## Overview

Layergram derives the local X25519 identity private key from BIP39 seed material. This derivation is versioned so the application can preserve legacy identities exactly while introducing stronger, domain-separated derivation for newly created identities.

## Versions

### v1

- Input: BIP39 seed bytes
- Derivation: `sha256(seed)`
- Output: 32-byte X25519 private key seed
- Status: legacy compatibility mode

`v1` remains supported for existing identities and for legacy restore flows. It must remain byte-for-byte reproducible forever.

### v2

- Input: BIP39 seed bytes
- KDF: HKDF-SHA256
- Salt/context: `layergram`
- Output length: 32 bytes
- Status: current preferred derivation

For `v2`, Layergram uses explicit domain separation:

- Identity derivation label: `layergram-identity-x25519-v2`
- Passphrase-derived identity label: `layergram-passphrase-identity-x25519-v2`

This keeps identity derivation isolated from future key uses and from the passphrase-derived identity namespace.

## Storage Metadata

Stored local identity material persists derivation metadata:

- `derivationVersion`
- `derivationAlgorithm`

The application must never infer derivation version heuristically when metadata is present. When reading older stored identities that predate this metadata, Layergram treats them as legacy `v1` identities for backward compatibility.

## Product Rules

### New identity creation

Newly created identities default to `v2`.

### Restore from raw mnemonic

Restore from raw mnemonic without external metadata defaults to `v1` so old users can recover the historical identity they originally created.

### Stored local identities

Stored local identities are always restored using their saved derivation version. If an older stored identity has no derivation metadata, it is treated as `v1`.

### Passphrase-derived identities

Passphrase-derived identities use the same explicit versioning model. New passphrase-derived identities default to `v2` unless a legacy `v1` flow is explicitly requested.

## No Silent Migration

Layergram does not automatically migrate existing identities from `v1` to `v2`.

Changing derivation version changes:

- private key
- public key
- identity ID
- fingerprint
- decryption compatibility for messages addressed to the previous identity
- trust relationships bound to the old public key

Any future migration from `v1` to `v2` must be explicit, user-driven, and designed as a separate product flow.
