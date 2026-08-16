# Layergram SCKA erasure code revision 1

Status: **internal representation frozen; engineering candidate ABI connected,
default ABI `NOT_READY`, no application packaging; protocol v3 inactive**

This document freezes the Layergram-owned erasure-code representation for the
public messages used by ML-KEM Braid revision 1. The implementation is
Apache-2.0 code in `native/layergram_scka/src/erasure.rs`; it has no third-party
dependency and is suitable for the public base that is merged into the paid,
proprietary Premium application.

The explicit `candidate-ffi` build reaches this module through
`lg_scka_v1_initialize`, `lg_scka_v1_send`, `lg_scka_v1_receive`, and the
native self-test. The default build remains `NOT_READY`; the SCKA backend is
still unregistered, unlinked from application packages, and non-production.

## 1. Sources and scope

Signal's public-domain [ML-KEM Braid revision-1
specification](https://signal.org/docs/specifications/mlkembraid/) recommends a
systematic Reed-Solomon erasure code over GF(2^16) with 32-byte chunks. The
field representation and systematic generator below follow [RFC
5510](https://www.rfc-editor.org/rfc/rfc5510), Sections 8.1 and 8.2.

The erasure code provides availability under loss. It provides **no**
authentication and does not correct adversarial errors. The Braid state machine
must authenticate the fully reconstructed message and reject it before any
state transition if its MAC is invalid.

## 2. Exact payload classes

The enclosing Braid message type selects one exact payload class. Length is not
encoded again inside an erasure chunk.

| Payload | Exact bytes | Source chunks `k` |
|---|---:|---:|
| 64-byte header + 32-byte MAC | 96 | 3 |
| ML-KEM-768 public-key vector | 1,152 | 36 |
| ML-KEM-768 ciphertext part 1 | 960 | 30 |
| ML-KEM-768 ciphertext part 2 + 32-byte MAC | 160 | 5 |

Every payload length is an exact multiple of 32. Generic or padded lengths are
not accepted by this revision.

## 3. Field and generator matrix

Each 32-byte source chunk is sixteen GF(2^16) elements in unsigned big-endian
order. RFC 5510's primitive polynomial for `m = 16` defines the field:

```text
p(x) = x^16 + x^12 + x^3 + x + 1
binary = 11010000000010001
reduction constant = 0x100B
```

Let `alpha` be the polynomial element `x` (`0x0002`). For a payload with `k`
source chunks, build the `k × 65535` Vandermonde matrix

```text
V[i,j] = alpha^(i*j), 0 <= i < k, 0 <= j < 65535.
```

Let `Vkk` be its first `k` columns. The systematic generator is

```text
GM = inverse(Vkk) * V.
```

The first `k` columns of `GM` are therefore the identity matrix. Encoding index
`j` is column `j`; index values are limited to `0..65534`. The all-ones 16-bit
value `65535` is reserved because powers of `alpha` repeat after 65535.

The same generator coefficients are applied independently to all sixteen field
elements in a chunk. Matrix arithmetic is exact GF(2^16) arithmetic; no
floating-point operation is permitted.

## 4. Canonical encoded chunk

One encoded chunk is exactly 34 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 2 | unsigned big-endian encoding index, `0..65534` |
| 2 | 32 | encoded symbol |

Indexes `0..k-1` carry the corresponding 32 source bytes unchanged. No flags,
payload length, message type, checksum, or MAC is embedded in this structure;
those belong to the enclosing canonical Braid message.

## 5. Recovery and limits

Any `k` distinct valid indexes reconstruct the original payload. The decoder:

- accepts at most 72 supplied chunks in one call;
- treats an exact repeated `(index, symbol)` as idempotent;
- rejects two different symbols with the same index;
- requires at least `k` distinct chunks;
- sorts by index and deterministically selects the lowest `k` if more are
  supplied;
- allocates matrices only after count, index, duplicate, and exact payload-class
  checks;
- returns reconstructed bytes only; the caller must still authenticate the
  complete Braid message before changing state.

The future state machine should retain at most `k` distinct chunks for one
in-progress payload and handle repeated transport delivery idempotently. A MAC
failure must discard the unauthenticated reconstruction candidate and must not
advance epochs or native-state revision.

## 6. Verification and activation boundary

Rust tests freeze the field polynomial, one independently calculated parity
vector, exact systematic bytes, maximum index, all four Braid payload sizes,
random deterministic any-`k` recovery, loss, reordering, duplicates,
conflicting duplicates, malformed lengths, and allocation limits.

This is not an independent cryptographic review or a cross-implementation Braid
vector. Before activation, Layergram still requires a separately reviewed
incremental ML-KEM representation, authenticated state-machine encoding,
complete Braid conformance vectors, fuzzing/sanitizers, physical-device tests,
and independent cryptographic and implementation audit.
