# Layergram Protocol v3 — Application Message

Status: **inactive implementation candidate; not enabled for users**

This document freezes the canonical user-message plaintext and its unreliable
carrier behavior. It does not activate protocol v3 or make a production
post-quantum claim.

## AP3 canonical plaintext

An application message is encoded once as `AP3` and then sealed independently
through each selected device session. All per-device copies therefore share one
logical message ID and plaintext, while every session keeps independent EC,
Sparse-PQ, nonce, message-key, and acknowledgement state.

The fixed header is 144 bytes:

| Offset | Bytes | Field | Rule |
|---:|---:|---|---|
| 0 | 3 | magic | ASCII `AP3` |
| 3 | 1 | format | `0x01` |
| 4 | 1 | flags | bit 0 delete-after-read; bit 1 backup-excluded |
| 5 | 1 | display-name length | 0–32 UTF-8 bytes |
| 6 | 2 | reserved | zero |
| 8 | 4 | total length | exact encoded length |
| 12 | 16 | logical message ID | non-zero, shared across target devices |
| 28 | 48 | sender identity digest | exact non-zero SHA-384 identity digest |
| 76 | 48 | recipient identity digest | exact non-zero SHA-384 identity digest |
| 124 | 8 | creation time | unsigned encoding, protocol range 0–2^63−1 |
| 132 | 8 | expiry time | zero or strictly later than creation time |
| 140 | 4 | text length | 1–16,240 bytes, subject to final length |
| 144 | variable | display name, then text | canonical UTF-8 |

The complete payload is limited by the 16,384-byte LMF assembled-plaintext
bound. Unknown flags, reserved bytes, malformed UTF-8, zero identifiers,
non-canonical lengths, invalid time relationships, and alternate encodings fail
closed before application display.

The identity digests are application-level recipient/sender bindings in
addition to the authenticated session and routing bindings. A correctly
authenticated payload for a different local identity is committed to advance
the ratchet safely but is never exposed as user content.

## Multi-device delivery policy

- Normal mode selects every currently accepted installation for the recipient,
  up to the frozen device cap. One durable all-or-none send group stores the AP3
  bytes and expected revision for every target before any frame is exported.
- Each target transition is independently committed. Export is withheld until
  all selected targets have exact durable assembly IDs, preventing a crash from
  silently reducing the selected device set.
- Maximum mode requires exactly one exclusive authenticated device session. It
  does not silently fall back to Normal mode or replace a pinned peer.
- An all-device group is complete only after every target session has accepted
  an authenticated complete acknowledgement. A partial result remains pending
  and can be re-exported exactly.

## Carrier and acknowledgement rules

Each exported item is one complete canonical LMF frame represented as:

- text armor beginning with `m3`;
- the same text armor after the `layergram://m/` deep-link prefix; or
- steganographic carriage of the same binary frame.

No bundle, server, carrier receipt, or ordering assumption is required. Parts
may be lost, delayed, duplicated, pasted into a different application, or
arrive in any order. Every individual export is capped at 4,000 characters for
the portable carrier profile. If a logical message uses several frames, the UI
must present each as an independently shareable part and keep the exact pending
set available for retry.

The receiver creates a cumulative complete ACK only after the entire message
has authenticated and its AR3/TR3 effect and replay tombstone are durable. The
ACK itself is persisted as exact sealed bytes before export. Replaying the
message or restarting returns that exact ACK frame; it never allocates a new
message ID, derives a replacement nonce, or reseals. ACK loss may therefore
cause harmless duplicate message/ACK transport but cannot cause state rollback.

## Chat projection and presentation state

The encrypted canonical AR3 materializer is the plaintext source of truth. A
chat projection stores only deterministic metadata under
`v3m:<logical-message-id>`; it does not copy AP3 text into `MessageRecord.text`.
Normal-mode AR3 copies with the same exact AP3 payload collapse to that one
metadata record. A conflicting payload or pre-existing incompatible metadata
fails closed instead of overwriting the chat.

Read and delete state is a separate encrypted, monotonic, write-new-before-
delete journal. Projection consults that journal on every reconciliation, so a
retained AR3 replay proof cannot resurrect a user-deleted message or lose a
delete-after-read decision. Plaintext lookup also requires current visible
metadata and rejects a durable deletion tombstone.

## Activation boundary

The AP3 codec, durable multi-device group, exact-byte ACK outbox, chat metadata
projection, presentation journal, and text/link/steganography transport are
integrated only through the inactive v3 runtime. Provider/UI bootstrap,
passphrase-scoped lifecycle, migration UX, and Normal/Maximum policy are wired
behind the same fail-closed selector. Supported physical-device and real-
carrier tests, hosted CI, established signed distribution-artifact checks, and
independent audit remain mandatory before
`ProtocolV3Activation.messaging` can become true.
