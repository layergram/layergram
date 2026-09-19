# Experimental system keyboard

Status: **experimental, local increment, not release-ready.** The capability is
disabled in ordinary builds: the gate is a compile-time flag that defaults to
off, and it stays off until the user both consents in the app and selects the
keyboard in Android input-method settings.

## What it does

The system keyboard lets a user compose and preview Layergram messages while
another application is in the foreground, without handing plaintext or key
material to that other application's editor. Outbound text is encrypted by the
already running Layergram app: the *outbound result* the keyboard holds is only
an opaque pending id and, after an explicit authorization, the encrypted
carrier. Composing and previewing happen inside Layergram's own keyboard window,
which is drawn by the Layergram process; plaintext is never inserted into the
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
  the final ciphertext; contacts are non-secret display references and an inbound
  preview is transient authenticated plaintext for Layergram's own window. No
  clipboard export, no send-button automation, and the host editor is never
  touched with plaintext.

## Enabling it locally

```
flutter run --dart-define=LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true
```

Then, in the app: open Settings, enable the experimental system keyboard entry,
accept the consent dialog, and use the provided button to open the Android input
method settings and select the Layergram keyboard. Android only. iOS has no
keyboard extension in this increment.

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
flutter test test/features/system_keyboard/
```

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
* iOS is not supported in this increment. A keyboard extension runs in a separate
  process and the host application can be suspended, so there is no safe
  suspended-process key owner. No shared key store, app-group secret or duplicate
  database workaround is used or planned here; iOS needs a different design before
  any crypto work is attempted.
* Identity reloads, passphrase activation and app-lock changes intentionally
  revoke the current keyboard session and require a fresh explicit selection.
  Contact list changes are not subscribed as a revocation trigger: the selected
  contact, its saved fingerprint and its eligibility policy are freshly
  revalidated inside `prepare`, so a contact removed or changed in the meantime
  fails closed.
