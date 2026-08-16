# Layergram incremental ML-KEM-768 boundary revision 1

Status: **internal primitive adopted; key generation, keypair restoration,
public-vector access, validation, decapsulation, and two-part encapsulation
connected to the private engine, whose transitions 1-13 are implemented;
engineering candidate ABI connected, default ABI `NOT_READY`, no application
packaging; protocol v3 inactive**

This document freezes the Layergram-owned boundary around the incremental
ML-KEM-768 primitive needed by ML-KEM Braid revision 1. The implementation is
`native/layergram_scka/src/incremental_mlkem.rs`.

The private initial-transition slice calls deterministic key generation with
an OS-supplied seed, reconstructs the exact keypair from persisted private
state before continuing Header symbols or accepting transition 2, and derives
`Ek` erasure symbols from that validated keypair during transitions 3-4. The
same private engine now uses exact-length decapsulation during transition 5;
the resulting raw shared secret remains in a zeroizing native owner and is
immediately consumed by `KDF_OK` and the ratcheted authenticator. Transition 7
starts two-part encapsulation and serializes only the secret-free pending
continuation; transition 9 first validates the complete public key and only
then completes `Encaps2`. Transition 10 applies that same complete public-key
validation before persisting `pk2` beside the still-pending encapsulation and
`ct1` encoder; it deliberately does not call `Encaps2` until the peer later
acknowledges `ct1`. The transition-11 path performs that deferred full-key
validation again before it restores the pending continuation and calls
`Encaps2`; transition 12 applies that same fail-closed sequence to the complete
key already stored by transition 10 when its delayed `ct1` acknowledgement
arrives. Transition 13 invokes no ML-KEM primitive: it only continues exact
persisted `ct2` output or advances roles after an authenticated next-epoch
message. No candidate survives a key-integrity or primitive failure. The
explicit `candidate-ffi` build reaches the module through
`lg_scka_v1_self_test`, `lg_scka_v1_initialize`, `lg_scka_v1_send`,
`lg_scka_v1_receive`, and `lg_scka_v1_state_validate`. The default build
remains `NOT_READY`; the native backend is unregistered, unlinked from
application packages, and unavailable to production code.

## 1. Dependency and licensing boundary

The exact primitive dependency is:

```toml
libcrux-ml-kem = { version = "=0.0.10", default-features = false,
  features = ["incremental", "mlkem768"] }
```

The crate declares Apache-2.0. Its selected normal/build dependency graph is
recorded in `tool/pq/scka_native_candidate.json`; every applicable package has
an Apache-2.0-compatible licensing path. Layergram selects the Apache-2.0
alternative where packages are dual licensed. `unicode-ident` additionally
requires Unicode-3.0, whose notice is retained under
`native/layergram_scka/licenses/`.

`zeroize` 1.8.1 is pinned for best-effort cleanup of Layergram-owned secret
buffers. `sha2` 0.10.9 is a test-only dependency used to compare incremental
output against a separately implemented `mlkem-native` known-answer vector.
None of these packages is currently linked into a Layergram app.

The upstream incremental API explicitly describes itself as non-standard and
requires caution. Adoption inside this inactive crate is not production or
cryptographic approval and does not relax any activation gate.

## 2. Exact primitive representation

| Value | Bytes | Meaning |
|---|---:|---|
| key-generation seed | 64 | FIPS 203 `d || z`; deterministic test/import seam only |
| public-key header (`pk1`) | 64 | `rho || H(ek)` |
| public-key vector (`pk2`) | 1,152 | serialized ML-KEM-768 `t` |
| compressed private key | 2,400 | standard ML-KEM-768 decapsulation key |
| encapsulation seed | 32 | FIPS 203 encapsulation randomness |
| ciphertext part 1 | 960 | compressed `u` vector |
| encapsulation continuation state | 2,080 | version-locked opaque libcrux state |
| ciphertext part 2 | 128 | compressed `v` |
| shared secret | 32 | ML-KEM shared secret |

The 2,080-byte continuation state is not a wire format. A future encrypted SCKA
payload may carry it only as an opaque, version-bound value. Changing the
libcrux version or its serialized continuation representation requires a new
state payload version and migration decision before any persisted state exists.

## 3. Mandatory call order

Layergram's wrapper enforces exact lengths at every entry point:

1. derive `pk1`, `pk2`, and the compressed private key from an exact 64-byte
   seed;
2. receive `pk1` and create ciphertext part 1 plus continuation state from exact
   32-byte encapsulation randomness;
3. expose the 32-byte `Encaps1` shared secret only through a transient,
   non-clonable owner so the Braid state machine can derive the epoch key and
   update its authenticator at revision-1 transition 7;
4. consume that transient result into a pending completion owner, which drops
   and zeroizes the raw shared secret while retaining the exact `pk1` and opaque
   continuation state;
5. after `pk2` arrives, validate the complete `pk1 + pk2` relationship;
6. only after successful validation, create ciphertext part 2;
7. decapsulate only exact 960-byte and 128-byte ciphertext parts.

The part-one owner retains the exact `pk1` that created its opaque continuation
state. The part-two API accepts that owner rather than a caller-supplied raw
state/header pair, so a continuation generated for key A cannot be combined
with an independently valid key-B pair. The transient `EncapsulationStarted`
type mirrors the public-domain Braid `Encaps1` result and exposes the raw shared
secret exactly while transition 7 is being built. Converting it to
`EncapsulationPartOne` drops that secret; the pending state has no secret getter
and cannot be completed without full `pk1 + pk2` validation. A completion
failure drops and zeroizes the retained continuation state.

The wrapper intentionally does not expose a function that completes
encapsulation without validating both public-key parts. Production randomness
must eventually come from an approved OS CSPRNG inside the native backend; the
current deterministic seams are internal and test-only.

## 4. Secret lifetime

Layergram-owned compressed private-key, continuation-state, shared-secret, and
temporary seed buffers are zeroized on their normal Rust lifetime/error paths.
Both `Encaps1` and decapsulation return shared secrets only through a
non-clonable Layergram-owned object that zeroizes its 32-byte buffer on drop;
the wrapper never returns a bare shared-secret array to its future caller. The
raw `Encaps1` secret is deliberately absent from the pending continuation state,
matching the revision-1 state machine after it derives `KDF_OK` and updates the
ratcheted authenticator.
This is best-effort compiler/runtime hygiene, not a guarantee that registers,
stack copies, allocator history, crash dumps, or upstream internal temporaries
are erased. Those remain native implementation audit and platform-hardening
gates.

## 5. Verification and activation boundary

Tests freeze all sizes, exact-length rejection, full public-key validation
before part 2, malformed-key rejection, shared-secret agreement, transition-9
completion through the restored pending owner, and exact public-key/ciphertext
SHA-256 values from the existing independent `mlkem-native` FIPS vector.

This primitive boundary alone does not provide Braid epochs, erasure
scheduling, MACs, authenticated state payloads, recovery, rollback protection,
or OS entropy. It does not make Layergram quantum-resistant. Activation still
requires integration and independent review of the complete private state
machine, cross-implementation Braid vectors, fuzzing/sanitizers, packaged
physical-device tests, and independent cryptographic review.
