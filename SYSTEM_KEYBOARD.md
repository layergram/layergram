# Experimental system keyboard

Status: **experimental, local increment, not release-ready.** The capability is
disabled in ordinary builds: the gate is a compile-time flag that defaults to
off, and it stays off until the user both consents in the app and selects the
keyboard in system settings. The iOS extension is embedded only by the explicit
experimental build procedure below.

## What it does

The system keyboard lets a user compose and preview Layergram messages while
another application is in the foreground, without handing plaintext or key
material to that other application's editor. Outbound text is encrypted by the
already running Layergram app: the *outbound result* the keyboard holds is only
an opaque pending id and, after an explicit authorization, the encrypted
carrier. Composing and previewing happen inside Layergram's own keyboard window,
which is drawn by Layergram's native keyboard component; plaintext is never inserted into the
host application's editor. The native side also receives approved contact names
and fingerprints for the explicit chooser, and, for an authenticated ordinary
inbound message, a transient plaintext preview that the app authenticates.

Non-negotiable properties of the current increment:

* Ordinary V3 contacts only. The host application never supplies a recipient;
  the user picks one explicitly and sees its saved fingerprint. Each successful
  insertion clears the selection, so the next send needs a new confirmation.
* One carrier part, text only, no expiry and no read-once previews. Anything
  with a deletion schedule must be viewed in the full app instead.
* The keyboard is available only while the Layergram process is alive and its
  ordinary (non-passphrase) identity is unlocked. Backgrounding under an enabled
  app lock applies the same lock deadline; the keyboard can never unlock the app
  and never receives a biometric or PIN prompt.
* The outbound result crossing the channel is only the opaque pending id and
  the final ciphertext; contacts are private display references and an inbound
  preview is transient authenticated plaintext for Layergram's own window. No
  clipboard export, no send-button automation, and the host editor is never
  touched with plaintext.

## Enabling it locally

```
flutter run --dart-define=LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true
```

Then, in the app: open Settings, enable the experimental system keyboard entry,
accept the consent dialog, and use the provided button to open the Android input
method settings and select the Layergram keyboard.

The iOS keyboard requires iOS 26 or later for native hybrid post-quantum IPC.
The containing app retains its existing minimum OS version. For a simulator
preview on macOS with Flutter, CocoaPods and Xcode 26 or later installed:

```sh
./tool/build_ios_system_keyboard.sh
```

The script builds the standalone `LayergramKeyboard` scheme, then Runner with
`LAYERGRAM_KEYBOARD_EMBED=YES` and the Dart feature flag enabled. Ordinary Runner
builds do not depend on or embed the keyboard target; an incremental ordinary
build also removes a previously embedded experimental keyboard. Device builds
need signing/provisioning for `app.layergram.app.keyboard` and the dedicated
`group.app.layergram.app.keyboard` App Group. Experimental Runner builds select
`LAYERGRAM_RUNNER_ENTITLEMENTS=Runner/RunnerKeyboard.entitlements`; ordinary
builds retain the existing entitlements. The existing share extension has no
access to the keyboard group. Simulator builds use local ad-hoc signing and do not prove provisioning.
The Simulator filesystem does not implement iOS complete file protection; that
protection is mandatory in real-device builds and needs physical-device tests.

Enable the switch in Layergram, then add Layergram in iOS keyboard settings and
allow Full Access. Full Access is required for the local App Group channel; it
also grants network capability at OS level, but the extension uses no network.
Return to Layergram, unlock if required, and switch to the transport app. A
session lasts **at most 20 seconds after leaving Layergram**, or less if the
existing app-lock deadline or iOS background execution expires. Requests and
heartbeats never renew that window. Hiding or switching the keyboard ends the
session immediately, including its transport keys. A window admits one keyboard
appearance; return to Layergram to start another one.

### iOS owner and extension boundary

The extension never opens the vault or V3 runtime. A finite background task in
the containing app services the existing Dart owner. There is no attempt to
wake a suspended app, keep it alive indefinitely, or move its identity/session
keys into an extension. Owner revocation invalidates pending replies. The
extension clears its draft, preview and contact selection when its short live
grant expires, capture is detected, its editor changes, or its view disappears.

The dedicated App Group admits only the app and keyboard extension; its OS
entitlement is the peer admission boundary. Ephemeral public keys alone do not
authenticate a binary independently of that boundary. The mailbox contains only public ephemeral rendezvous data
and encrypted request/response envelopes. Ephemeral transport keys exist only
in memory. CryptoKit X-Wing (ML-KEM-768 + X25519), HKDF-SHA256 and AES-GCM-256 protect
this local transport, with no classical-only fallback; all
Layergram message cryptography remains in the existing app owner. Session,
direction, request and sequence binding reject stale or substituted envelopes.
File size bounds, complete file protection and backup exclusion limit storage.
Dropping key references and clearing UI values do not promise memory zeroization.

The keyboard only reads the clipboard following an explicit paste action. It
does not read host surrounding text or infer a chat recipient. iOS insertion
uses `textDocumentProxy.insertText`, which returns no acceptance result: history
already contains the prepared message. The best-effort `ack` marks an export
attempt only while the same editor is still authorized. If an editor callback,
lock or suspension prevents the acknowledgement, the prepared export stays
recoverable as pending; no delivery or transport-app acceptance is inferred.
Own-insertion callbacks are not suppressed to make acknowledgement appear reliable.

Native host tests use a synthetic Dart peer and real protected App Group
storage. On a physical device they check the directory and every final mailbox
leaf for complete file protection, plus backup exclusion and removal of staging
files. A real-clock test keeps sending heartbeats and verifies that the finite
window closes and is purged without renewal. Notification tests explicitly
simulate protection-loss and capture events; they do not prove behavior during
an actual device lock or screen recording.

For native host tests on a physical device, use the Profile configuration with
`ENABLE_TESTABILITY=YES`, build the keyboard first, and explicitly enable its
embedding and experimental Runner entitlements. Profile avoids the Flutter
Debug engine's debugger/JIT requirement. Use separately provisioned test bundle
identifiers and App Groups when testing on a personal device. Runner's Profile
configuration is separate from the project defaults; the test bundle carries no
App Group entitlement, and the native keyboard does not inherit Flutter linker
flags.

The experiment is not ready for distribution. Physical-device validation must
cover Full Access, data protection on lock, suspension/termination, app-lock and
identity changes, capture, extension memory pressure and real V3 exchanges.
Apple's keyboard guidelines also require useful operation without Full Access;
the encrypted live-owner feature depends on it, so store eligibility remains an
unresolved release gate. No insecure plaintext fallback is added to satisfy it.

## Design

* `system_keyboard_controller.dart` — pure Dart, backend-agnostic core. Owns the
  input session, admission sampling, replay memory, the single pending export and
  the generic failure taxonomy. It never touches keys, storage or the wire
  format.
* `system_keyboard_app_service.dart` — the app-owner integration. It evaluates the
  compile-time feature gate, loads the independent opt-in from existing secure storage,
  configures the native component once, answers the native `request` channel,
  and builds the admission snapshot (lock readiness, unlock state, synchronous
  lock request, ordinary identity plus its keyTag, passphrase state, background
  deadline).
* `system_keyboard_app_backend.dart` — the real backend. Reads saved contacts,
  opens the existing V3 session runtime plus a repository context lease, prepares
  and acknowledges the durable export and authenticates inbound carriers.
* `system_keyboard_settings.dart` — the settings tile with local Italian and
  English copy. It is only rendered when the gate is active.

Admission is re-sampled before every operation, after every `await` and again
before a reply is serialized. Any admission-relevant owner change (identity,
identity reload, passphrase, keyTag, lock readiness, unlock state, lock enabled
or timeout, opt-in) bumps a monotonic generation and immediately revokes the core
session and the native editor state. A change away and back to the same value
still invalidates, so a revoked session can never be revived by a later event.

### Independent background deadline

The app lock's own idle controller only checks its timeout when the app resumes.
The integration therefore keeps its own monotonic record: the first transition
away from `resumed` records the background instant once, later `paused` events
never extend it, and with an enabled app lock the deadline is
`backgroundAt + timeout` (a zero timeout denies immediately). The lock
configuration that already exists before the integration starts is seeded, so an
enabled lock with a zero or positive timeout is enforced even if no provider ever
changes again. Reducing the timeout can only narrow an existing deadline.
Heartbeats validate the live session but never renew this deadline, and Dart
timers being suspended while the process is backgrounded cannot widen it because
every check compares absolute instants. The integration guard used by the backend
re-evaluates the full admission set and the absolute deadline before every
provider access and after every `await`, so a lapsed grant suppresses an in-flight
backend operation even when no provider event fires.

### Native channel

The channel contract is strict: every request must carry a well-formed operation,
the live editor nonce and a bounded request id. A request bound to an older editor
is rejected, and an `end` from an older editor can never close a newer one. Replies
carry a monotonic `processingMillis` measured from handler entry to completion
(`0..30000`, always `0` for heartbeats) and a `leaseMillis` capped at 1000 ms and
never larger than the remaining app background grant. Every lock, passphrase,
opt-in, context or engine denial collapses into the single generic `unavailable`
status; no reason, identity or lock metadata reaches the native layer.

### Scramble hook

A neutral, optional preference seam defaults to `false` and is only *added* to the
existing secure-keyboard capability check before a presentation hint is sent with
the session start. It changes nothing about encryption or admission, is not
persisted by this increment, and is intended purely so a downstream preference can
ask for scrambled layout if it already supports it.

## Tests

```
flutter test test/features/system_keyboard/ test/security/
swift test --package-path ios/SystemKeyboardCore
```

The Swift package tests the hybrid IPC and editor policy. The iOS
`SystemKeyboardHostTests` suite runs in the experimental embedded Runner build:
it verifies live forwarding through the Flutter channel codec, disable/resume
revocation and suppression of a delayed response. Its Dart peer is synthetic;
it does not prove a complete keyboard interaction with real V3 peers.
The existing Runner screen-shield tests remain part of that native suite.

The app-service suite drives an injected backend, monotonic clock and native
channel. It covers: feature-disabled and unsupported-platform denial with native
configuration off; missing and failed consent; lock-not-ready, locked, passphrase
and missing-keyTag denial with no backend read; the full begin → contacts →
explicit select → prepare → authorize → ack path; stale editor callbacks and a
stale `end` not closing a newer editor; inactive-then-paused not extending the
deadline; zero-timeout denial; a clock advance with a suspended timer; heartbeat
not renewing the deadline; in-flight lock request, identity away-and-back and
full-lock-timeout-mid-await suppression; delayed enable versus newer disable
races on the preference store and native configure, including disposal during
startup; out-of-order preference completions; failed secure opt-out remaining
disabled after restart through native/store agreement; seeded zero/positive lock timeouts
with unchanged providers; the real backend aborting before any storage access
once the deadline lapses; and provider-driven generation bumps with a Riverpod
container.

The backend integration tests use the actual V3 runtime, message bridge, Hive
repositories and projection layer with synthetic cryptographic test adapters.
They verify established-session ciphertext export, authenticated reply preview,
exactly-once history, replay suppression, saved fingerprint revalidation, and a
revoked export handle refusing acknowledgement in another identity context. The
adapters test flow wiring, not cryptographic algorithm correctness.

## Honest limitations

* This is a local experimental branch. Physical two-application and security
  acceptance testing on real devices has not been performed. Automated tests
  exercise the app service and repository boundaries. An Android 15 emulator
  fixture exercises the native editor, explicit contact confirmation, ciphertext
  insertion and password-field denial; that synthetic fixture does not prove
  end-to-end cryptographic interoperability on physical devices.
* Protection against a hostile host application is best effort. Screenshot
  blocking, overlay hiding and obscuring-gesture rejection are platform
  conveniences, not a claim of universal protection against privileged malware,
  a compromised operating system or a kernel-level attacker that can observe
  another app's input pipeline.
* Previewed and composed text is visible in Layergram's own keyboard window
  while another application is in the foreground. It is not inserted into the
  host application's editor, but it is on screen outside Layergram's main UI for
  the duration of the interaction; this trade-off is stated in the consent
  dialog.
* The keyboard requires the Layergram process to be alive. If the process is
  killed, carriers cannot be prepared or authenticated until the app runs again.
* iOS uses a separate extension process and a bounded live owner. A suspended
  or terminated containing app cannot serve the keyboard. iOS or the host app
  may replace or reject custom keyboards, including in secure text fields.
  Screenshots cannot be reliably prevented in the extension.
* Identity reloads, passphrase activation and app-lock changes intentionally
  revoke the current keyboard session and require a fresh explicit selection.
  Contact list changes are not subscribed as a revocation trigger: the selected
  contact, its saved fingerprint and its eligibility policy are freshly
  revalidated inside `prepare`, so a contact removed or changed in the meantime
  fails closed.
