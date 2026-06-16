# Forward Secrecy

This document describes the Forward Secrecy (FS) model implemented in Layergram, how it
preserves Layergram's existing properties (no server, no account, no public-key
redistribution, plausible deniability), and the hardening notes required by the FS
specification v1.18 — in particular the **secure memory handling limitations** (§20.2) and
the **implementation review gate** (§20.4).

It complements [../THREAT_MODEL.md](../THREAT_MODEL.md) (user-facing threat wording) and the
message/identity specs under [./](.).

## Overview

Layergram's Base model encrypts each message with a static–static X25519 shared secret
between identity keys. This is simple and old-client compatible, but a future compromise of a
long-term identity key exposes all past messages encrypted for that key.

Forward Secrecy adds an **opportunistic, in-band** upgrade: peers negotiate an ephemeral
session and, once it is confirmed, switch to a Double Ratchet whose per-message keys cannot be
reconstructed from the long-term identity key. The negotiation travels inside ordinary
Layergram messages, so:

- no server or key directory is involved;
- users do **not** redistribute public contact keys;
- clients that do not understand FS simply ignore the extension and keep using the Base model.

## Core principle

> Forward Secrecy must improve Layergram without changing what makes Layergram different.

That means: no server, no account, no public-key redistribution, no persistent hidden
identity list, no plaintext message database, no externally recognizable passphrase settings,
no externally recognizable FS state, and no breakage for old clients.

## Negotiation and state machine

FS is negotiated with three control messages carried as opaque extensions inside normal
encrypted messages: `fs_init` → `fs_reply` → `fs_confirm`
(see `lib/core/crypto/fs_control_messages.dart`).

The `fs_confirm` message is verified against both the locally stored transcript hash and the
wire `transcriptHash` field. A confirm whose MAC is valid for the stored transcript but whose
declared transcript differs is rejected, so the final handshake message cannot carry an
inconsistent transcript.

The per-contact handshake is driven by `FsOpportunisticController`
(`lib/core/crypto/fs_opportunistic_controller.dart`), which tracks the session state
(`legacyOnly`, `fsInitSent/Seen`, `fsReplySent/Seen`, `fsConfirmSent`, `fsConfirmed`,
`fsActive`, `strictRequested`, `strictFsActive`, `fsSuspended`, `fsBroken`). The UI maps these
states to a colored shield (grey → orange while negotiating → green when active → green with a
gold rim for Strict; red for broken) and to per-message classifications.

Simultaneous `fs_init` collisions are resolved with the canonical tie-break
`EncodeKey(IK) ‖ EncodeKey(DK) ‖ initId` (spec §8.3.4).

## Double Ratchet and per-device sessions

Once confirmed, message keys are derived by a Double Ratchet session
(`lib/core/crypto/fs_session_manager.dart`). Each remote **device** gets its own independent
session via `FsDeviceSessionRouter` (`lib/core/crypto/fs_device_session_router.dart`): when a
second device of the same identity starts a new handshake, the existing session is **archived**
(its ratchet state preserved) rather than destroyed, so messages from both devices keep
decrypting. Inbound messages are routed to the correct ratchet by the `fs_session` value in the
envelope.

## Multi-envelope messages (§9.6)

When a contact has **two or more active device sessions**, a single outgoing message is encoded
as a multi-envelope (`lib/core/crypto/encryption_service.dart`, `encryptMultiEnvelope`): the
payload is encrypted **once** with a fresh per-message content key (`mc_cipher`), and that
content key is then wrapped (ratchet-encrypted) once per device session (`fs_wraps[]`, each
keyed by `fs_session`). Each of the contact's devices recovers the content key with its own
ratchet, so one sent payload is readable in FS by all of them. Decryption picks the wrap
matching one of the recipient's sessions, unwraps the content key (advancing only that device's
ratchet), then decrypts the single ciphertext.

A legacy fallback (`mc_fallback_key`, the content key carried in the identity-encrypted outer
layer) is **optional and off by default**, so multi-envelope messages stay full FS
(`fs_only`/`strict_fs`). When included, the message is classified `fs_with_fallback` and is no
longer full FS; **Strict mode must never include it**. Conversations with a single active
session keep using the single-envelope path unchanged.

## Security modes

Each contact has a per-contact security mode (`lib/core/crypto/fs_security_mode.dart`):

- **Base** — FS negotiation is suppressed entirely; legacy model only.
- **Advanced** — opportunistic FS with compatibility fallback allowed. While FS is active the
  contact card shows an amber fallback warning, because some messages may still use the legacy
  model (spec §14.6.4).
- **Strict (Maximum FS)** — single confirmed device per side, no legacy fallback. Requires
  explicit mutual consent; while requested but not yet confirmed the UI shows a distinct
  "Maximum FS requested" pending state, not active Strict (spec §14.6.3).
  If a new device/session appears after Strict is active, sending is paused until the session
  is repaired or Maximum FS is explicitly disabled; the implementation must not silently fall
  back to legacy encryption in this state.

## Per-message classification

Every message carries one of eight opaque classifications
(`lib/core/crypto/fs_message_classification.dart`): `legacy`, `pre_fs`, `fs_negotiation`,
`fs_with_fallback`, `fs_only`, `strict_fs`, `fs_failed`, `unknown`. The chat shows only a small
icon; the message-details panel explains the classification.

## Storage and plausible deniability

Layergram never stores FS plaintext in `MessageRecord.text`. All FS-related state is persisted
as **encrypted, padded auxiliary records** that are externally shaped like any other archive
record; their semantic `kind` is only visible after decryption in the correct identity context:

| Record kind | Purpose | Source |
|-------------|---------|--------|
| `fs_state_v1` | per-device session / ratchet state | `fs_device_session_router.dart` |
| `fs_pt_v1` | decrypted FS plaintext (for re-display after restart) | `fs_plaintext_persistence_service.dart` |
| `fs_mode_v1` | per-contact security mode | `fs_security_mode.dart` |
| `fs_pp_v1` | passphrase-context security preferences | `fs_passphrase_preferences.dart` |

Modern auxiliary records are stored as:

```text
m|{scopeToken}|{randomStorageId} -> { encryptedRecord: "<base64url blob>" }
```

The blob embeds a random 128-bit record identifier before the derived nonce, ciphertext, and
authentication tag. That record identifier is random-looking and is used only to rederive the
per-record key/nonce pair; it is not stored as separate cleartext metadata. Legacy development
records that still contain `_rid` or an aux marker are accepted for migration, but new writes
must not emit those fields.

Cleanup of undecryptable local records is conservative: legacy records that carry the old
cleartext aux marker can be deleted when malformed or undecryptable, while modern unmarked
records are preserved unless they decrypt successfully and match the intended record kind.
This avoids deleting ordinary message records or future opaque archive formats by mistake.

Decrypted plaintext for display lives in an in-memory cache
(`fs_plaintext_cache.dart`) and is cleared on lock, timeout, passphrase expulsion, and app
lifecycle events (`fs_passphrase_timeout_controller.dart`). On identity reset, all auxiliary
plaintext records are removed; only the legacy archive (re-derivable from the identity key)
survives.

Passphrase-derived contexts are never persisted as profile entries; their settings live only
inside `fs_pp_v1` records and are visible only while the passphrase is active.

## Local DoS resistance (§20.3)

Malformed, duplicated, stale, replayed, or excessive FS control messages are tolerated without
corrupting state or exhausting storage (`lib/core/crypto/fs_dos_resistance.dart`,
`lib/core/crypto/fs_replay_cache.dart`). Bounds enforced:

- max pending handshakes per contact/device: **4** (spec recommended: 4);
- max orphan auxiliary control records: **16** (spec recommended: 8 — see "Divergences").

Corrupted handshakes cannot block future valid handshakes after cleanup.

Message replay checks happen after the identity-encrypted outer envelope is authenticated and
parsed, but before the FS ratchet is advanced. A replayed `(fs_session, fs_counter)` is rejected
without consuming skipped keys, persisting plaintext, or mutating ratchet state. Skipped message
keys are bounded, TTL-pruned, and wiped best-effort before removal or after successful use.

## Secure memory handling limitations (§20.2)

Layergram wipes ephemeral secrets, passphrase-derived keys, ratchet temporary values,
`chainSeed_0`, `confirmKey`, DH outputs, and decrypted caches as soon as they are no longer
needed. However, **managed runtimes such as Dart/Flutter cannot guarantee reliable
zeroization** of all memory because of garbage collection, value copies, string immutability,
compiler optimizations, and platform-level memory behavior.

Implementation requirements:

- keep cryptographic secrets in mutable byte buffers (`Uint8List`) whenever possible;
- avoid storing secrets in immutable `String`s;
- avoid logging, debugging, serializing, or formatting secret material;
- isolate cryptographic operations in reviewed primitives where reliable zeroization is
  possible;
- use platform facilities such as secure storage, hardware-backed keystores, memory locking,
  or zeroization APIs where available;
- document any limitation where guaranteed memory wiping is not possible.

Layergram **must not** claim perfect memory erasure on all platforms. The correct claim is:

> Layergram minimizes the lifetime of sensitive material in memory and uses best-effort
> zeroization within platform limits.

Required tests / review checks:

- no logs contain key material, plaintext messages, passphrase-derived identifiers, DH
  outputs, ratchet state, or confirm keys;
- the decrypted UI cache is cleared on lock, timeout, passphrase expulsion, and app lifecycle
  events defined by policy;
- secret material is not converted into immutable strings for convenience;
- platform-specific secure memory limitations are documented (this section).

**Known platform limitation.** On Dart/Flutter, even after a secret buffer is overwritten,
copies produced by the garbage collector or by intermediate APIs may persist until reclaimed.
Layergram therefore treats memory zeroization as best-effort and relies on minimizing secret
lifetime plus OS-level protections, not on guaranteed erasure.

## Implementation review gate (§20.4)

Before enabling FS for normal users, the implementation must pass a security review covering the
items below. This checklist is the release gate; any divergence from the specification must be
documented (see "Divergences") before release.

- [x] handshake transcript construction;
- [x] DH computation order;
- [x] public-key validation;
- [x] AES-GCM nonce uniqueness;
- [x] Double Ratchet initialization;
- [x] skipped-key and replay-cache pruning;
- [x] auxiliary record opacity and padding;
- [x] passphrase-context UI invisibility when passphrase is not active;
- [x] manual-transport assumptions;
- [x] Maximum FS consent and pending/active state separation;
- [x] atomic state transitions;
- [x] memory-wipe best effort and documented limitations;
- [x] local DoS behavior.

The checklist above reflects the dedicated review performed on this branch. It does not imply
that FS is already present in public store builds or in the official public release
description.

## Divergences from the specification

Per §20.4, divergences are documented here:

- **Orphan control record bound.** The spec recommends a max of 8 orphan replies/confirms per
  contact; the implementation currently uses 16 (`FsDosResistance.maxOrphanAuxRecords`). The
  recommended limits are explicitly "unless changed after testing"; 16 was retained to reduce
  spurious pruning during multi-device negotiation. Revisit if storage growth is observed.
- **Decrypted FS plaintext persistence.** To survive app restarts without re-running the
  handshake, decrypted FS plaintext is persisted as an encrypted, padded `fs_pt_v1` auxiliary
  record (not in `MessageRecord.text`). This is a deliberate, documented choice consistent with
  established clients (Signal/Matrix store decrypted history locally) and preserves plausible
  deniability because the record is opaque and removed on identity reset.

## References

- FS specification v1.18 (source of §-numbered requirements above)
- [../THREAT_MODEL.md](../THREAT_MODEL.md) — user-facing threat model, "Forward Secrecy" section
- `lib/core/crypto/fs_*.dart` — implementation
- `test/core/crypto/`, `test/ui/` — FS test suites
