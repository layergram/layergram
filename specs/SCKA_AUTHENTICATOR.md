# Layergram ML-KEM Braid authenticator revision 1

Status: **canonical KDF and ratcheted authenticator implemented internally;
initialization, header MAC, output-key derivation, ratcheting, and ciphertext
verification connected only to private transitions 1-7; public
ABI connection not implemented; protocol v3 inactive**

This document freezes Layergram's implementation-defined domain and the
ratcheted-authenticator primitives required by the public-domain [ML-KEM Braid
revision-1 specification](https://signal.org/docs/specifications/mlkembraid/).
The Apache-2.0 implementation is
`native/layergram_scka/src/braid_authenticator.rs`.

No source from Signal's AGPL implementation was inspected, copied, adapted,
linked, or embedded. This checkpoint uses the permissively licensed RustCrypto
`hkdf`, `hmac`, and `sha2` crates and remains suitable for the public Layergram
base that is merged into the separately distributed paid Premium application.

The private transition slice now uses authenticator initialization, restore,
header-MAC generation, persisted-header verification, `KDF_OK`, detached
ratcheting, and successor-key ciphertext verification as frozen in
`SCKA_TRANSITION_ENGINE.md`. Transition 5 returns the derived epoch key only
through the native zeroizing candidate owner and produces no successor on MAC
failure. Transition 6 verifies the reconstructed current-epoch header MAC
before a `HeaderReceived` successor can exist and likewise returns no
successor on authentication failure. Transition 7 applies `KDF_OK` to the
fresh `Encaps1` shared secret, binds the zeroizing epoch key to the exact send
candidate, and ratchets the authenticator before `Ct1Sampled` can exist.
Remaining Braid transitions, state-envelope persistence, and every C ABI
operation are still disconnected.
Native self-test and every correctly shaped public operation continue to return
`NOT_READY`.

## 1. Frozen parameters

Layergram selects the following revision-1 parameters:

| Parameter | Exact value |
|---|---|
| KEM | ML-KEM-768 incremental interface |
| Hash | SHA-256 |
| HKDF | RFC 5869 HKDF-SHA-256 |
| MAC | HMAC-SHA-256, complete 32-byte output |
| Epoch encoding | unsigned 64-bit big-endian, accepted domain `1..2^63-1` |
| Authenticator root key | 32 bytes |
| Authenticator MAC key | 32 bytes |
| SCKA output key | 32 bytes |

The exact ASCII `PROTOCOL_INFO` byte string is:

```text
LayergramV3_MLKEM768_HMAC-SHA256
```

It has no length prefix, NUL terminator, case conversion, or Unicode
normalization. Changing any byte requires a new protocol-suite decision and
cannot be treated as a compatible implementation detail.

## 2. KDF definitions

`epoch_be64` is the exact eight-byte big-endian epoch representation. `||`
means byte concatenation.

The authenticator update derives 64 bytes and splits them in order:

```text
auth_material = HKDF-SHA256(
  salt = current_root_key,
  IKM  = update_key,
  info = PROTOCOL_INFO || ":Authenticator Update" || epoch_be64,
  L    = 64
)

next_root_key = auth_material[0..32]
next_mac_key  = auth_material[32..64]
```

Initialization is exactly one update with a 32-byte all-zero root key:

```text
Authenticator.Init(epoch, initial_key) =
  KDF_AUTH(zero32, initial_key, epoch)
```

The SCKA output-key KDF is:

```text
output_key = HKDF-SHA256(
  salt = zero32,
  IKM  = shared_secret,
  info = PROTOCOL_INFO || ":SCKA Key" || epoch_be64,
  L    = 32
)
```

With RFC 5869, an absent SHA-256 salt is equivalent to the exact 32-byte zero
salt above. The Rust implementation deliberately uses that standard `None`
salt representation.

The raw incremental ML-KEM shared secret is transient. Transition 5 now
derives `output_key`, ratchets the authenticator with that same `output_key`,
returns the output only through its zeroizing owner, and persists neither the raw
shared secret nor an extra copy of the derived output.

## 3. MAC definitions

The header MAC authenticates exactly the 64-byte ML-KEM-768 `pk1` header:

```text
header_mac = HMAC-SHA256(
  mac_key,
  PROTOCOL_INFO || ":ekheader" || epoch_be64 || header64
)
```

The ciphertext MAC authenticates exactly `ct1 || ct2`, or 960 + 128 = 1,088
bytes. The private API receives the two exact-length components as separate
arguments and concatenates them only through sequential HMAC updates:

```text
ciphertext_mac = HMAC-SHA256(
  mac_key,
  PROTOCOL_INFO || ":ciphertext" || epoch_be64 || ct1_960 || ct2_128
)
```

The full 32-byte tag is transmitted. Verification uses the constant-time
verification operation supplied by the RustCrypto `hmac` crate. Wrong tag
length, value length, epoch, domain, data, or tag fails closed. A MAC failure is
a terminal Braid-session error: the future caller must not continue from the
candidate state and must negotiate a new Braid session.

## 4. Ownership and atomicity

`BraidAuthenticator` and `BraidOutputKey` implement neither `Clone` nor `Debug`
and zeroize their owned arrays on drop. `ratchet` derives a detached successor
without mutating the prior state and accepts only a typed `BraidOutputKey`, not
an arbitrary byte slice. This prevents a future transition from accidentally
ratcheting the authenticator with the raw ML-KEM secret. The API permits the
future transition engine to retain the authenticated durable prior until one
immutable successor is sealed and atomically committed with the matching TR3
revision.

The detached API does not itself prevent two callers from deriving competing
successors from one prior. Before activation, one serialized per-session
authority and revision compare-and-swap must select and commit exactly one
candidate.

RustCrypto HKDF/HMAC and SHA-256 may retain internal stack/register copies that
are outside Layergram's explicit zeroizing owners. The same best-effort native
zeroization limitation already recorded in the threat model applies; this
checkpoint does not claim perfect erasure from allocator history, crash dumps,
registers, or upstream primitive temporaries.

## 5. Verification and remaining gates

Tests freeze the exact protocol domain and independent golden bytes for
initialization, header MAC, ciphertext MAC, `KDF_OK`, and a subsequent
authenticator update. The expected bytes were generated independently with
Python's standard `hashlib` and `hmac` RFC-5869/HMAC-SHA-256 implementation;
the production Rust code uses RustCrypto. Tests also cover constant-time verify
success/failure behavior, domain separation, exact input sizes, signed-63 epoch
bounds, detached successor semantics, restore length checks, and explicit wipe
paths.

Activation still requires the complete revision-1 transition engine, approved
OS entropy, integration and review of the canonical `BM3` codec, authenticated
reconstruction, LS3/LB3 composition, atomic LS3/TR3 revision binding,
independent cross-implementation vectors,
fuzzing and sanitizers, panic containment, crash/restart/rollback/concurrency
tests, packaged physical-device traversal, and independent cryptographic and
implementation review.
