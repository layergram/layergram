# Layergram ML-KEM Braid public message revision 1

Status: **canonical private codec frozen; Header/Ek/Ct1 output and
Header/Ek/EkCt1Ack/Ct1 input connected only to private transitions 1-9;
public ABI not connected; protocol v3 inactive**

This document freezes Layergram's `BM3` representation of one logical public
message from the public-domain [ML-KEM Braid revision-1
specification](https://signal.org/docs/specifications/mlkembraid/). The
Layergram-owned Apache-2.0 implementation is
`native/layergram_scka/src/braid_message.rs`.

No source from Signal's AGPL implementation was copied, adapted, linked, or
embedded. This codec adds no dependency and is suitable for the public
Layergram base that is merged into the separately distributed paid Premium
application.

`BM3` is currently a private Rust module. Its Header, `Ek`, `EkCt1Ack`, `Ct1`,
`Ct2`, and no-data constructors/accessors are used by the private transition
slice. Transitions 8-9 distinguish `Ek` from `EkCt1Ack` only after canonical
BM3 parsing; a completing authenticated acknowledgement creates the exact
private `Ct2Sampled` state, but it
is not called by the C ABI, cannot be packaged through Flutter, and does not
change the scaffold's `NOT_READY` result.

## 1. Logical message and epoch ownership

Revision 1 defines a message as an internal Braid `epoch`, a `type`, and an
optional erasure-coded `data` chunk. The seven types are represented in their
normative order:

| Value | Type | Data class | Reconstructed bytes |
|---:|---|---|---:|
| 0 | `None` | absent | 0 |
| 1 | `Hdr` | header plus MAC | 96 |
| 2 | `Ek` | ML-KEM-768 public-key vector | 1,152 |
| 3 | `EkCt1Ack` | ML-KEM-768 public-key vector | 1,152 |
| 4 | `Ct1Ack` | absent | 0 |
| 5 | `Ct1` | ML-KEM-768 ciphertext part one | 960 |
| 6 | `Ct2` | ML-KEM-768 ciphertext part two plus MAC | 160 |

`None` and `Ct1Ack` still carry the Braid message's own non-zero epoch. They
are therefore encoded as 24-byte `BM3` records, never as an empty native
buffer. This internal message epoch is distinct from the outer `SK3` sending
epoch high-water mark: either may be needed by a future transition without
implying that the other advances.

## 2. Canonical binary representation

All multi-byte integers are unsigned big-endian. A message is exactly 24 bytes
without data or 58 bytes with one canonical 34-byte erasure chunk.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 3 | magic `BM3` |
| 3 | 1 | format version `0x01` |
| 4 | 1 | suite `0x01` / ML-KEM-768 |
| 5 | 1 | message type `0x00..0x06` |
| 6 | 1 | flags, zero |
| 7 | 1 | header length, exactly `24` |
| 8 | 2 | exact total length, `24` or `58` |
| 10 | 2 | ML-KEM Braid revision, exactly `1` |
| 12 | 8 | internal Braid epoch, `1..2^63-1` |
| 20 | 4 | reserved zeros |
| 24 | 0 or 34 | canonical encoded erasure chunk |

Types `None` and `Ct1Ack` require total length 24 and no chunk. Every other
type requires total length 58 and exactly one chunk. The message type selects
the one permissible reconstructed payload class; callers cannot reinterpret a
chunk as another class merely because the 34-byte chunk shape is identical.

Decoding first requires one of the two exact total sizes, then validates every
fixed field, type, epoch, type/length relationship, and erasure index. It
re-encodes the accepted value and requires byte equality. Unknown types,
non-zero flags or reserved bytes, zero/high-bit epochs, reserved erasure index
`65535`, alternate lengths, missing chunks, extra chunks, and trailing bytes
fail closed.

Both encodings fit inside the existing 512-byte native-message bound and the
536-byte maximum `SK3` envelope.

## 3. Authentication and state-advance rule

The 34-byte erasure chunk is public transport data, not independently
authenticated by this codec. A future transition engine may retain bounded,
canonical candidates, but MUST NOT advance committed Braid state merely because
a chunk parses.

After enough unique chunks are present, reconstruction uses the payload class
selected by the message type. Revision-1 authentication and relationship
checks then apply to the complete logical value: the header carries its MAC,
`Ct2` carries the ciphertext MAC, and the completed public-key vector is bound
through the authenticated header relationship. Failure discards the candidate
and leaves the committed prior unchanged.

The outer Layergram LMF/HR3 authentication protects the exported transport
frame and exact `SK3` bytes when integrated, but it does not replace the
Braid-internal reconstruction and authentication rules.

## 4. Frozen vectors and remaining gates

Tests freeze independent byte vectors for no-data, data, and maximum-epoch
records, canonical round trips for all seven types, exact erasure
encode/wrap/decode/reconstruct behavior for every data class, signed-63 and
wire-size boundaries, and hostile fixed-field/type/shape/chunk inputs. The
golden bytes were generated independently with Python standard-library integer
and byte encoding, not by the Rust codec under test.

Activation still requires the complete immutable revision-1 transition engine,
approved OS entropy, authenticated reconstruction integration, LS3/LB3/TR3
atomic revision binding, independent cross-implementation vectors, fuzzing and
sanitizers, panic containment, crash/restart/rollback/concurrency tests,
packaged physical-device traversal, and independent cryptographic and
implementation review.
