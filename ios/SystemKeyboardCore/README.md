# SystemKeyboardCore

Bounded, encrypted, single-client mailbox that lets the iOS keyboard extension
talk to the **live** Layergram app process through a dedicated App Group
subdirectory.

This package contains the transport and editor policy without UIKit or Flutter
dependencies. The app host and keyboard extension link it as a local Swift
package. See `../../SYSTEM_KEYBOARD.md` for the experimental build procedure.

## What it does and does not do

* The mailbox carries **existing MethodChannel JSON maps** (`begin`, `heartbeat`,
  `contacts`, `select`, `prepare`, `authorize`, `ack`, `decode`, `end`) as opaque
  `Data` payloads. There is **no custom Layergram message cryptography** here: the
  payload is whatever the live Dart service already produces or consumes.
* No identity, vault, V3 session key or keyTag material is shared. No long-lived
  secret is written anywhere. The key agreement is the platform built-in **hybrid
  post-quantum KEM `XWingMLKEM768X25519`** (ML-KEM-768 + X25519): the owner
  generates one hybrid key pair per window and the client performs **one
  encapsulation** per session against the owner's public key. Only public data
  (the 1216-byte owner public key, the 1120-byte encapsulation) is written in the
  shared documents; the 32-byte resulting secret never leaves the process.
  Persisted encrypted mailbox payloads therefore keep the same post-quantum
  protection from a hybrid post-quantum key agreement instead of relying only
  on classical key agreement. This does not extend V3 identity authentication
  into the extension; admission still relies on the dedicated App Group.
* The hybrid KEM ships in CryptoKit from **iOS 26 / macOS 26**, while this package
  still deploys to iOS 15 / macOS 11. Hosts and the keyboard extension gate the
  mailbox on the public constant
  `MailboxCryptoAvailability.isSupported`; `MailboxOwner.openWindow()` and
  `MailboxClient.attach()` additionally fail closed with `unavailable` when it is
  false. **There is no classical fallback and no downgrade path.**
* Plaintext exists only inside the two processes, in memory, during the bounded
  session. It is never intentionally persisted by the transport. Keys are dropped on revoke/close; **no zeroization is promised**.

## Shared container

App Group: `group.app.layergram.app.keyboard` (dedicated to the keyboard). Dedicated
subdirectory: `SystemKeyboardMailbox/`. Fixed leaf names only:

| file | writer | content |
| --- | --- | --- |
| `rendezvous.json` | owner | public: version, session id, hybrid ML-KEM-768+X25519 owner public key (1216 bytes), created/deadline/window millis |
| `client.request` | client | encrypted request envelope, with the public KEM encapsulation (1120 bytes) in `k` |
| `owner.response` | owner | encrypted response envelope |
| `mailbox.lock` | both | advisory `flock` target, empty |

No plaintext file names, no contact ids, no payload-derived names. The dedicated
directory is opened once at initialisation and every leaf operation goes through
that pinned descriptor (`openat`, `unlinkat`, `renameat`, `fstatat`), so a
symlink or directory replacement after initialisation can never redirect a read
or a write. Every open uses `O_NOFOLLOW | O_NONBLOCK` and every descriptor is
checked with `fstat` for a regular file, so a FIFO or device node can neither
block nor be read; reads are size-bounded with `fstat` before allocation; writes
are exclusive temp file + `renameat` (atomic). Three fixed staging leaves
are cleaned under the directory lock, so process crashes cannot accumulate an
unbounded number of temporary files. Leftover documents are purged when
expired or older than 5 minutes. On iOS the directory, every temporary file and
the lock file are set to `FileProtectionType.complete` and read back before any
content is written (including device-lock restrictions); a mailbox that cannot be
protected fails closed. The directory is excluded from backup and that exclusion
is verified, so it is mandatory rather than best-effort. On macOS and iOS Simulator, `FileProtection` is not implemented by the
host filesystem; that compile-time branch checks backup exclusion but cannot
attest device-lock protection. Real-device builds require and verify complete
protection before writing.

## Protocol (version 2)

1. Owner opens a window: generates one ephemeral `XWingMLKEM768X25519` hybrid key
   pair and an unpredictable 16-byte session id, writes `rendezvous.json` with a
   deadline of `created + windowMillis` where `windowMillis <= 20_000`. The
   document carries the 1216-byte hybrid public key; the private key and its
   decapsulation closure stay in the owner process.
2. Client attaches: reads the rendezvous, rejects it when the wall deadline has
   passed or the version/length is not exactly version 2 with a 1216-byte key,
   then encapsulates **once** against the owner public key. It keeps the 32-byte
   resulting secret in RAM and sends only the 1120-byte public encapsulation. The
   shared deadline is converted to a local monotonic deadline clamped to the
   window.
3. Client seals a request with AES-GCM using the **request** key, a fresh random
   12-byte nonce, and AAD =
   `layergram.system-keyboard.mailbox|v2|request|<session>|<requestId>|<seq>`.
   The envelope carries the KEM encapsulation in the clear as `k`.
4. Owner decapsulates with its hybrid private key, decrypts with the request key,
   **pins the first client that presents a valid AEAD tag for the whole window**
   (the pin is the exact 1120-byte encapsulation), and answers with the
   **response** key, AAD direction `response`, the same request id and its own
   increasing sequence.
5. Client decrypts only when the response matches its exact pending request id,
   the live session, an increasing response sequence and the pending lease.

A **version 1** document (the superseded classical 32-byte X25519 format) is
rejected outright: `badVersion`/`unsupportedVersion` when the version number is
wrong, `badLength` when a 32-byte key appears in a version 2 document. No
classical or fallback code path exists.

Keys: `HKDF-SHA256(KEM sharedSecret, salt = sessionId || encapsulation ||
ownerPublicKey, info = .../v2/request | .../v2/response)`, 32 bytes each. Request
and response keys are separate; direction, version and session are also
authenticated as AAD, so a document sealed for one direction, version or session
cannot be replayed in another.

## Bounds and timing

| bound | value |
| --- | --- |
| window | `<= 20_000 ms`, non-renewable |
| freshness lease for a fresh operation response | `<= 1_000 ms` |
| client pending wait | `1 ... 1_000 ms` (default 900) |
| serialized envelope / file | `<= 2 MiB` |
| plaintext payload | `<= 1 MiB` |
| rendezvous document | `<= 4 KiB` (1216-byte hybrid key base64) |
| hybrid owner public key | exactly 1216 bytes |
| hybrid KEM encapsulation | exactly 1120 bytes |
| KEM session secret / derived AEAD keys | 32 bytes each |
| replay memory per window | 128 request ids + strictly increasing sequences |
| advisory lock wait | 250 ms, then `unavailable` |

## Public API

```swift
import SystemKeyboardCore

// The mailbox is post-quantum only: gate the UI on this on every OS.
func openMailbox() async throws {
    guard MailboxCryptoAvailability.isSupported else { return }   // iOS 26 / macOS 26+

// Owner (app process)
let storage = try MailboxStorage()                 // group.app.layergram.app.keyboard
let owner = MailboxOwner(storage: storage)         // clock injectable for tests

let window: MailboxWindowInfo = try owner.openWindow()   // <= 20 s, once
let deadline = window.deadlineMonotonicMillis            // host can schedule cleanup

switch try owner.pollRequest() {
case .idle:
    break
case .request(let pending):
    // pending.payload is the decrypted MethodChannel JSON map. Hand it to the
    // already-running Dart service, then serialize its reply.
    let reply: Data = try await dartService.handle(pending.payload)
    try owner.respond(to: pending, payload: reply)   // re-checks session + lease
}

try owner.closeWindow()                                  // drops keys, clears files
}
```

```swift
// Client (keyboard extension process)
let storage = try MailboxStorage()                       // same group/directory
let client = MailboxClient(storage: storage)

guard MailboxCryptoAvailability.isSupported, client.hasLiveWindow() else { return }
let session = try client.attach()                        // one hybrid encapsulation

_ = try session.send(payload: beginJSON)                 // one outstanding request
while session.isWaitingForResponse, Date() < deadline {
    switch try session.pollResponse() {
    case .idle:
        continue
    case .response(let reply):
        handle(reply)
    }
}
session.revoke()                                         // drop key references
```

Errors: `MailboxError` exposes only `kind == .unavailable` or `.malformed`.
Admission, deadline, storage, lock and peer-state problems collapse to
`unavailable`; parse, bound, authentication, replay and mismatch problems collapse
to `malformed`. No identity, lock or key metadata is surfaced, and nothing is
logged.

Owner polling contract for the host:

* `pollRequest()` returns at most one request, deletes the document after a
  successful accept, and returns `.idle` when nothing is waiting. While a pending
  handle's 1 s lease is still live it refuses a competing document with
  `unavailable` instead of silently replacing the handle, and leaves that document
  in place.
* Deadlines are exclusive: a reading exactly at the window deadline or at the
  pending lease is already expired. A negative or rolled-back clock reading fails
  closed instead of moving a window.
* `respond(to:payload:)` fails closed with `unavailable` if the window closed or
  the 1 s freshness lease elapsed, and with `malformed` if the handle is stale
  (duplicate or out-of-order reply). Publish only after the Dart service returned.
* A second `openWindow()` while a window is open fails; windows are never renewed.
* The window is hard-capped and monotonic-clock enforced: a wall-clock change
  cannot extend it.

## Tests

`swift test` in this directory (macOS 26+; no App Group needed, tests use an
explicit temporary directory and an injected clock). On an older OS the mailbox
tests skip rather than fail, because the hybrid KEM does not exist there.

* round trip across two storage handles, sequential requests, carrier-sized
  payloads, no plaintext/op names/KEM secret/derived key bytes anywhere on disk,
  rendezvous field set, atomicity/no temp leftovers, backup exclusion, purge;
* hybrid post-quantum (`MailboxPostQuantumTests`): real encapsulation and
  decapsulation agree on the same secret and differ per encapsulation, full
  encrypted round trip, 1216/1120-byte wire lengths, changed encapsulation and
  changed AEAD tag rejected without replacing the pinned client, version 1 and
  32-byte classical documents rejected by version and length, per-window
  unlinkability of session/nonce/ciphertext/encapsulation, directional key
  separation, revoke clearing the private-key wrapper and session secret;
* tampering (ciphertext, nonce, request id, sequence), cross-direction documents,
  wrong session, wrong/absent pending request, response mismatch, request and
  response replay, non-increasing response sequence, second-client rejection with
  the pinned client still working, stale response handle;
* bounds: oversized files, non-JSON, empty file, wrong version, extra/missing
  field, fractional/zero/boolean numbers, non-canonical base64, wrong base64
  length, payload over the plaintext bound, rendezvous window over the ceiling,
  deadline mismatch, wrong field types, symlinked leaf and directory, unsafe path
  components, out-of-range timeouts;
* lifecycle: window expiry for owner and client, wall-clock jumps in both
  directions, late owner response, bounded client pending timeout, single
  outstanding request, revoke, missing rendezvous, closed window, second open,
  cross-session rejection after reopen, stale purge.

Transport regressions retain real hybrid fixtures, with separate post-quantum
and editor-policy suites. Runtime host tests in `RunnerTests` additionally
exercise the UIKit owner and method-channel codec on iOS.

## Honest limitations

* Simulator compilation and macOS package tests do not establish physical-device
  protection or extension lifecycle behavior. Verify `FileProtectionType.complete`,
  actual lock/suspension and Full Access on devices before any distribution.
* Only the app and keyboard are entitled to the dedicated App Group, but any process in that group
  can read the directory. The design assumes a hostile *host application*, not a
  hostile team-signed binary; a team-level attacker can always replace inputs.
* Complete file protection is enforced on real devices. macOS and iOS Simulator
  do not provide it; those tests verify encrypted IPC and backup exclusion only.
* Keys are held in memory as Swift values; dropping references is not a
  guarantee that key bytes are erased from the process.
* The hybrid KEM exists only on iOS 26 / macOS 26 and later. On older systems the
  mailbox is simply unavailable; there is deliberately no classical fallback.
* The mailbox is opt-in and default-off in the app; this package only implements
  the bounded transport once a window is explicitly opened.
