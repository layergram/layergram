# Protocol v3 optional-capability compatibility

Layergram maintains one public protocol. Optional builds may add product
capabilities, but must not fork identity, message, handshake, ratchet, or
migration semantics.

## Compatibility rules

- Protocol-changing code and specifications land in the public repository
  first.
- Optional capability implementations consume the public v3 types and codecs.
- `IdentityProfile` evolves additively: legacy `publicKeyBase64` remains
  available while `protocolVersion` and `publicIdentityBase64` expose a complete
  versioned identity bundle when implemented.
- Existing implementations that construct an `IdentityProfile` without v3
  fields remain source-compatible.
- Every saved local identity, including additional selectable identities, uses
  its own BIP39 recovery material and deterministically recreates its own v3
  bundle.
- Switching identities switches the complete identity, device-session router,
  contact state, ratchets, and encrypted storage context atomically.
- Passphrase-derived identities remain ephemeral and do not become enumerable
  saved profiles.
- Backup implementations must treat the v3 bundle as public metadata but keep
  mnemonic, ML-KEM key-generation seed, private-key handle state, ratchets, and
  passphrase-derived material inside their existing protected boundaries.

## Release gate

Before v3 is enabled publicly, the downstream optional build must compile
against the public branch and pass its existing capability, multi-identity,
backup, cover-generation, folder, media, secure-keyboard, and entrypoint tests.
This verification occurs in the private repository without copying private
implementation details into the public tree.
