# Identity Derivation Model

## Overview

Layergram derives local identity key material from BIP39 seed material. This
derivation is versioned so the application can preserve legacy identities
exactly while introducing stronger, domain-separated derivation for new
protocol generations.

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
- Status: legacy protocol-v2 derivation

For `v2`, Layergram uses explicit domain separation:

- Identity derivation label: `layergram-identity-x25519-v2`
- Passphrase-derived identity label: `layergram-passphrase-identity-x25519-v2`

This keeps identity derivation isolated from future key uses and from the passphrase-derived identity namespace.

### v3 (active in Layergram 2.0 and later)

- Input: BIP39 seed bytes
- KDF: HKDF-SHA256
- Salt/context: `layergram/protocol-v3/identity-derivation`
- X25519 seed output: 32 bytes
- ML-KEM-768 key-generation seed output: 64 bytes (`d || z`)
- Status: preferred production derivation, connected to the fail-closed
  protocol-v3 application seams

The labels are purpose- and algorithm-specific:

- `layergram/v3/identity/x25519-seed`
- `layergram/v3/identity/ml-kem-768-keygen-seed`
- `layergram/v3/passphrase-identity/x25519-seed`
- `layergram/v3/passphrase-identity/ml-kem-768-keygen-seed`

The active `V3LocalIdentityFactory` is the only complete v3 assembly path. It
requires a successful native ML-KEM self-test, derives both key components,
validates the resulting ML-KEM public key, and returns a non-serializable local
handle. Temporary BIP39 and algorithm seed buffers are overwritten as a best
effort after construction. The expanded 2,400-byte ML-KEM private key remains
inside the native opaque handle and is destroyed when the local handle closes.

For passphrase-scoped identities, the passphrase first participates in the
standard BIP39 seed derivation and the result then uses Layergram's separate v3
passphrase labels. The passphrase and expanded local handle are not persisted
as a discoverable identity record; the handle exists only while that context is
active.

Public identities received from text, links, or QR must cross the separate
`V3PublicIdentityValidator` boundary before use. A checksum-valid identity is
not sufficient: the native backend self-test and ML-KEM public-key validity
check must also pass. This validation still does not authenticate the owner.

The 64-byte ML-KEM seed is never truncated for QR or link compactness. The
allowlisted native backend expands it into the complete FIPS 203 keypair. In
Layergram 2.0 and later, v3 is the preferred application derivation.

## Storage Metadata

Stored local identity material persists derivation metadata:

- `derivationVersion`
- `derivationAlgorithm`

The application must never infer derivation version heuristically when metadata is present. When reading older stored identities that predate this metadata, Layergram treats them as legacy `v1` identities for backward compatibility.

## Product Rules

### New identity creation

In Layergram 2.0 and later, newly created identities default to `v3`. The
application derives the v3 identity for the active recovery context without
silently treating its v2 contact state as v3.

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

The same rule applies to v3. Reusing the same 24 words produces deterministic
but different v3 key material, identity ID, fingerprint, contact bindings, and
sessions. A v3 migration therefore requires a new public-identity exchange and
contact verification; it is never silent.

The complete user-facing contract is defined in
[Protocol v3 Migration](PROTOCOL_V3_MIGRATION.md).
