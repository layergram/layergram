# Layergram system keyboard for Android and iOS

The keyboard brings Layergram's encrypted messaging into the apps you already
use. You can write a private message, insert its encrypted carrier into the
conversation, and preview a received message from the keyboard. This reduces
switching between applications while keeping private text inside Layergram's
keyboard window.

Status: **opt-in experimental feature on Android and iOS.** The capability is
disabled in ordinary builds: the gate is a compile-time flag that defaults to
off, and it stays off until the user both consents in the app and selects the
keyboard in system settings. The iOS extension is embedded only by the explicit
experimental build procedure below.

## What it does

The system keyboard lets a user compose and preview Layergram messages while
another application is in the foreground. Plaintext is drawn only in
Layergram's keyboard window, never inserted into the host application's editor.
There are two experimental modes: the original finite preview forwards
operations to the running Layergram app; the autonomous V3 candidate transfers
exclusive encrypted protocol custody to a headless keyboard runtime after an
app-authorized grant. The latter is the build used to investigate immediate
“Sesión caducada” on a physical iPhone.

Shared properties:

* V3 contacts, including saved Maximum contacts, appear in the picker. Maximum
  keeps its handshake and session requirements: visibility is not permission to
  send an identity-only first message. The host application never supplies a recipient;
  the user picks one explicitly and sees its saved fingerprint. A successful
  insertion consumes the one-use selection. The same live editor can reselect
  that previously confirmed contact after the owner checks its current
  fingerprint again; a host editor change or
  session end requires a new explicit choice.
* One carrier part, text only, no expiry and no read-once previews. Anything
  with a deletion schedule must be viewed in the full app instead.
* The ordinary (non-passphrase) identity must be unlocked when the app grants
access. The keyboard cannot unlock the identity. In the autonomous build,
  the separate opt-in biometric shortcut can create a fresh keyboard session
  after idle expiry while the same exclusive FS custody and editor remain valid;
  it never unlocks the app or accepts a PIN fallback. Manual lock, device lock
  and revocation end the grant.
* No clipboard export or send-button automation is performed. The host editor
  receives only the encrypted carrier after the user explicitly inserts it.
* The setting to save keyboard conversations in Layergram chats is on by
  default. Turning it off suppresses new keyboard messages from those chats;
  the encrypted protocol state remains available for FS and replay protection.

## Enabling it locally

```
ORG_GRADLE_PROJECT_layergramSckaCandidatePackage=true \
  flutter run --dart-define=LAYERGRAM_EXPERIMENTAL_SYSTEM_KEYBOARD=true \
  --dart-define=LAYERGRAM_AUTONOMOUS_SYSTEM_KEYBOARD=true
```

On Android, first complete the Rust and native-library preparation in the
[source build instructions](README.md#build-a-functional-android-app). A Flutter
feature flag alone does not package the active protocol backend. On iOS, use
the explicit autonomous extension build procedure below instead of this
Android command.

Then, in the app: open Settings, enable the experimental system keyboard entry,
accept the consent dialog, and use the provided button to open the Android input
method settings and select the Layergram keyboard.

### Android composer

The native Android surface uses the same compact composer as the iOS candidate:
a contacts circle, a two-line local secret-message viewport with a caret and
clear control, and a contextual paste/decrypt or locked-send circle. The
recipient name and live V3 shield appear above it, without the fingerprint;
the explicit confirmation still shows the fingerprint. Maximum status uses a
gold rim. An unknown status never appears as active FS.

The contact chooser filters names as the user types using the keyboard's own
keys. Results scroll in a fixed viewport, so reducing the result count cannot
move the keys upward. Accents are available by holding letters; holding space
moves the local cursor horizontally or vertically and keeps it in view. Emoji
insertion and deletion preserve complete Unicode sequences. The layout follows
the device language for Spanish, Portuguese, French, German and Nordic layouts,
with QWERTY as the fallback. Function controls use the app's green light palette
and blue dark palette, and haptics respect Android's feedback setting.

Real, unobscured touch input renews the configured keyboard inactivity window
(60 seconds by default). Heartbeats, drawing and background work do not renew
it. App admission and a nonzero app-lock timeout bound the grant. The autonomous
Android build uses `LAYERGRAM_AUTONOMOUS_SYSTEM_KEYBOARD=true` in addition to
the feature flag, with real packaged ML-KEM and SCKA. A plugin-free headless
engine receives exclusive FS custody; it does not initialize the app archive,
plugins or a network client. `AtomicFile` stores one authenticated AES-GCM leaf
in `noBackupFilesDir`, binding phase, epoch and revision. Every write compares
the current revision, and app recovery takes the latest state before finishing
custody. Missing or altered state fails closed without resetting FS.

The separate biometric preference wraps a revocable capability with an
authentication-per-use Android Keystore key. Reopening requires a fresh strong
biometric `CryptoObject`; there is no device-PIN fallback. A new version-2
capability remains available after long inactivity during the same device boot;
already-issued version-1 capabilities retain their ten-minute limit. Reboot,
revocation or invalid custody denies reopening. Enrollment invalidates the key;
only a new app-authorized delegation can replace it. The native owner and Dart
runtime independently enforce inactivity. Editor rebinding clears recipient,
draft and pending requests while preserving the FS owner and original idle
deadline. Bounded request bookkeeping rotates before a safe operation; exports
and acknowledgements are never retried after an uncertain result.

The keyboard's own Android window uses `FLAG_SECURE` when the app's screen
protection setting is enabled. Overlay and password-field admission checks
remain active independently. The host application's window is unaffected.

Run `tool/qa/keyboard_v3_regression.sh android` with JDK 17 or later for the native
policy/editor suite. Run its `android-ui` stage on a disposable emulator for
real layout, language, palette, contact-viewport and caret-scrolling checks.
Keep live transport, background termination, biometric, update and reinstall
validation separate from these layout checks. Uninstall tests must use a
disposable identity; an in-place update must preserve the FS, identity and chat
records and must never silently start a new FS.

Run the `android-autonomous` stage with `ANDROID_HOME`, JDK 17+, and
`LAYERGRAM_KEYBOARD_ANDROID_SERIAL=emulator-…`. It builds a fixed, separate
validation package, exchanges real V3 data to green through the native owner,
restarts from custody, exercises prolonged broker use, and performs in-place
replacement followed by uninstall/reinstall on that fixture alone. Its fixture
identities are public test vectors. This does not certify biometric system UI,
OEM behavior or a physical transport app; perform those checks at the device gate.

At a keyboard release candidate or after changing custody, persistence or
authorization, repeat this lifecycle matrix on disposable installations:

| Transition | Required result |
| --- | --- |
| Update while app is stopped, foregrounded, or keyboard is active | Identity, contacts, history and the latest committed FS state survive; no silent new device key and no duplicate insertion. |
| Process death before preparation, after preparation, during insert or before acknowledgement | One recoverable transaction; no state rollback, plaintext host insertion or duplicate export. |
| Uninstall then reinstall without restoration | Fresh onboarding; orphaned credentials or biometric tickets cannot reopen an old session. |
| Reinstall then restore the same identity from a supported backup | Contacts/history follow the backup contract; a fresh installation negotiates its own FS instead of adopting a stale ratchet. |
| Interrupted reset, storage denial/corruption, device lock or authorization revocation | Fail closed; preserve identity/contacts/history and never treat a failed reset as success. |

These are milestone tests, not a requirement for every cosmetic change. They
must not uninstall a personal device's app or clear its data to produce a pass.

### Finite iOS preview

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
Return to Layergram, unlock if required, and switch to the transport app. The
finite preview's owner window lasts **at most 20 seconds after leaving
Layergram**, or less if the app-lock deadline or iOS background execution
expires. The autonomous candidate below uses that short window only to transfer
one grant; its separate idle countdown begins after the keyboard takes custody.
Hiding or switching the keyboard ends either session immediately. A fresh
appearance requires a fresh handoff from Layergram. If iOS retains the same
keyboard view after a session expires, it also recognizes the next new
app-owned handoff; the already-consumed window cannot be reused.

The iOS composer uses conventional letter, number and symbol rows, with
backspace on the right and a wide space key. It reads only the host field's
input-language tag through `documentInputMode` and selects a Latin key layout
for Spanish (including a visible `ñ`), Portuguese (`ç`), French AZERTY,
German QWERTZ, Swedish, Norwegian and Danish. English, Italian and other
unrecognized modes use QWERTY. When iOS reports only this extension's declared
`en-US` tag, the layout follows the device locale, keeping labels such as
`espacio` consistent with the visible Spanish `ñ`. iOS exposes a language tag,
not the previous Apple keyboard's full geometry, so this does not claim parity
with every international layout or detect a previous keyboard choice that iOS
does not report. Holding a vowel or supported consonant opens its
accented variants; holding space moves the cursor in the local draft. The draft scrolls
to keep the cursor visible after movement or a newline. The return key uses
the ↵ symbol. The function buttons share deep Layergram green in light mode
and the app's dark-theme blue in dark mode, including Encrypt and Decrypt.
Backspace matches Shift; the
emoji key matches `123`. The
input view requests only the height needed for its key rows, leaving more of the
host app visible. A two-line local message field shares one row with circular
Contacts and contextual action buttons. When the field is empty, the right
button pastes and decrypts with the Layergram mark; once text is entered, it
becomes a locked send icon for encrypting and inserting. An X inside the field
clears the whole local message and restores the paste action. Tapping the field
moves its local cursor without activating the host editor. The contact picker expands the keyboard view, supports scrolling
and searches saved names or fingerprints locally. On Face ID iPhones iOS already
provides a globe below the keyboard; an in-keyboard switch key appears only if
`needsInputModeSwitchKey` requires it. The icon-only emoji key sits between
`123` and space; it swaps the letter rows for a categorized, scrollable picker
without detaching the bottom row. Choosing an emoji inserts it only into the
local draft. Keys and commands request a haptic pulse on supported iPhones. A selected
recipient's name stays visible above the draft without repeating the
fingerprint after confirmation. Its small shield replaces the repeated person
icon: orange means V3 FS is still negotiating, green means Normal FS active,
green with a gold rim means Maximum active, and red means recovery is needed.
Maximum setup has an orange shield with a gold rim. If the FS phase is still
unknown during contact confirmation, the name appears without a shield rather
than suggesting that FS is absent. This phase is
read from the delegated V3 runtime on contact confirmation and refreshed when
the same contact is revalidated after the keyboard's own insertion. It is a
status display, not authorization to send. Choose a recipient, compose locally,
then use **Encrypt & insert** and the transport app's own send control.
The session status and its inactivity countdown share one row, with the
countdown on the right. In the autonomous build, a completed insertion clears
the local draft and one-use selection, then starts a fresh editor generation
within the same live grant. Only the previously confirmed recipient may be
reselected after fresh validation in the same OS document. It does not extend
the inactivity deadline.
**Paste & decrypt** opens a reading panel with the authenticated sender and a
scrollable message. Decoding does not choose a recipient. Tapping **Reply to**
explicitly selects that sender after the app validates the selection; **Compose**
returns to typing without choosing anyone. The globe remains available on each
panel. English, Italian and Spanish labels are included.

The finite preview retains this 20-second limitation. The autonomous candidate
below implements a separate keyboard-owned inactivity window.

### Finite preview owner and extension boundary

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
does not read host surrounding text or infer a chat recipient. The host's
`documentInputMode.primaryLanguage` supplies only a language tag for the local
key layout. iOS insertion
uses `textDocumentProxy.insertText`, which returns no acceptance result: history
contains the prepared message only when its chat-saving preference is on. The
best-effort `ack` marks an export
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

The finite preview is not ready for distribution. Physical-device validation must
cover Full Access, data protection on lock, suspension/termination, app-lock and
identity changes, capture, extension memory pressure and real V3 exchanges.
Apple's keyboard guidelines also require useful operation without Full Access;
the encrypted live-owner feature depends on it, so store eligibility remains an
unresolved release gate. No insecure plaintext fallback is added to satisfy it.

### Autonomous V3 candidate

The separate build below embeds the headless V3 runtime in the iOS keyboard
extension. A short, at-most-20-second app background window exists only to
authenticate and transfer one encrypted grant. After that handoff the extension
owns the V3 protocol scope; keeping the containing app executable is unnecessary.
Its default session expires after **60 seconds without intentional keyboard
touches**. The user can select a supported idle duration in settings, subject
to the app-lock ceiling. Polling and message requests never renew it. Lock,
capture, a different OS document, Full Access loss and explicit revocation
remain terminal. A callback for the same document can start a fresh editor
generation while retaining the still-live grant, with no retained draft or
recipient and no deadline renewal. The recipient exception above applies only
to the keyboard's own successful insertion, never to a host callback.
The countdown is shown as soon as the delegated runtime is ready, even before
the first protocol response. Waiting more than the short app-to-keyboard
handoff window before selecting Layergram can still prevent a grant from being
transferred; that is distinct from the post-handoff idle countdown.

The grant contains a one-use X25519/ML-KEM identity capability and an encrypted
V3 working set, including the installation device key and pending handshake
state. It contains neither the recovery phrase nor the app's Aux storage root.
The keyboard restores the approved identity, shares the app's V3 conversation
state through exclusive custody, and can put a readable message in the first
text carrier while negotiation proceeds. One carrier remains the maximum for
one user message; the keyboard currently offers text mode only.

Build a separately identified validation app for a simulator or signed device:

```sh
LAYERGRAM_KEYBOARD_SIMULATOR=YES LAYERGRAM_KEYBOARD_FIXTURE=YES \
  ./tool/build_ios_autonomous_keyboard.sh

LAYERGRAM_KEYBOARD_FIXTURE=YES LAYERGRAM_ALLOW_PROVISIONING_UPDATES=YES \
  ./tool/build_ios_autonomous_keyboard.sh
```

The build verifies exact SCKA and ML-KEM exports in the extension, the bundled
app/keyboard/share identifiers and App Groups, and code signing. Simulator
signing is only a packaging check; it does not prove physical iOS file
protection, keyboard permission behavior or an exchange in a transport app.
The physical validation fixture remains a local candidate until a complete
real-device exchange passes.

### Physical iPhone smoke test (after keyboard, custody or insertion changes)

Use the separately identified validation app and update it **in place** so its
identity, contacts and enabled keyboard survive. Confirm Full Access in iOS
keyboard settings. Do not run XCUITest, screen recording, mirroring or a device
screenshot during the handoff: iOS reports the screen as captured during
XCUITest, and Layergram correctly revokes the keyboard grant. This is a manual
test with read-only device process or App Group metadata checks when needed.
Before a routine fixture update, close the keyboard and reopen the containing
app so it can reclaim the latest FS state. Check the native cleanup receipt,
then keep the keyboard closed throughout installation. Do not assume that
opening the app once prevents a later keyboard delegation. Stop if ownership
changes or recovery fails and preserve the disposable installation for
diagnosis. A reset is not a normal QA step. Test updates while the keyboard
owns the ratchet only in the separate candidate-gate update scenario with
disposable identities.
Leaving the app alone does not prepare or transfer V3 custody. Preparation
starts only when an eligible keyboard editor requests delegation; the first
request may receive `busy` while preparation finishes, then retry for its
grant. On iOS a missed initial delivery lease may be replaced only inside the
original bootstrap window. The owner keeps the single consumed grant in memory
until ACK, revocation or that fixed deadline, and can seal the same grant for
the exact pinned mailbox client and editor nonce under a new request ID and
fresh exclusive lease. It neither activates custody again nor renews the
window; expired responses and application-operation retries remain forbidden.
This avoids creating a native custody snapshot just because the app is
being updated. If an interrupted preparation left its marker but never removed
the original private records, startup verifies their exact marker digest,
preserves any later authenticated private V3 writes, and clears the abandoned
marker. A missing original record or a keyboard-authoritative snapshot that
cannot be reclaimed still fails closed unless the narrow pre-FS proof below
applies. An update during active keyboard custody needs its separate test.
For new delegations the keyboard mirrors every AES-GCM sealed custody revision
in a device-only shared Keychain item before confirming the App Group file
write. The recovery key remains only in the app-private encrypted marker; the
mirror by itself is neither a keyboard session nor plaintext. If an update
replaces the App Group directory, the app can authenticate and reclaim the
latest mirrored revision. A mirror that is absent, behind the file, from a
different epoch, or unavailable due to device lock fails closed. The mirror is
removed only after the app has durably imported that revision. Existing
delegations made by older builds cannot acquire a mirror retroactively, so an
update test must distinguish a newly mirrored disposable delegation from an
older delegation and fail closed when authenticated recovery evidence is
insufficient.
The v3 encrypted custody marker records a narrow pre-FS abort proof. When the
native snapshot is missing before keyboard activation, one replaced pending
manifest can be accepted only if every other original protocol record matches
its marker digest and the replacement revision advances. Older v1 markers still
need the authenticated deleted Hive frame for that proof; if it has been
compacted away, leave the installation untouched and fail closed. Never infer
the missing record type from the replacement alone.

New v4 delegations write an exact, app-private encrypted abort snapshot before
native preparation. After deleting the private sources, they flush a separate
activation-intent receipt and erase the abort snapshot before calling native
activation. If native preparation disappears before that intent, recovery
verifies the snapshot digest and source IDs, rejects concurrent protocol writes,
and restores only missing exact records through an idempotent repair receipt.
Once activation intent exists, the abort snapshot is never authoritative:
recovery must reclaim the current native/Keychain revision or fail closed. The
v4 abort snapshot is absent during normal keyboard use, so old ratchet secrets
are not kept in app-private storage for an active session.

1. Open and unlock the validation app to the chat list (no individual contact
   chat needs to be opened), then switch manually
   to a transport app and focus its ordinary message field. Select the
   Layergram keyboard. It must show **Session active**, without requiring the
   first message to be a key-only exchange.
2. Open Contacts, tap the local search field and type a few characters with the
   Layergram keys. Filtering must update after each key, keep the typing rows
   at the bottom with a visible gap below the results, keep the session active,
   and must not change
   the transport app's editor or activate another keyboard. Each result shows
   its name and fingerprint without a document icon. Select an already
   approved Layergram contact, confirm its fingerprint, type
   a disposable test message in the keyboard and tap **Encrypt & insert** once.
   The countdown must stay visible to the right of the status after confirming
   the contact and throughout typing, not only after insertion.
   Do not use the host's contextual **Paste** action: it inserts the existing
   system clipboard, which is unrelated to the keyboard's `insertText` call.
   Before pressing the host's send button, check that its editor contains one
   long V3 carrier, at most 4,000 characters. During Normal pre-FS setup it can
   begin with `p1.` (encrypted application message) followed by `m3.` control
   frames. No message-part fraction or empty key-only user message is expected.
   After insertion, the keyboard must return to an active session without
   reopening Layergram. The previously confirmed contact's name and refreshed
   FS shield must remain visible in this same transport editor after a fresh
   fingerprint check;
   changing the host editor or the contact key requires a new explicit choice.
   Prepare a second message while the inactivity countdown still has time
   remaining; host editor callbacks from the first insertion must not close
   that session. Check the device log
   for an extension memory-limit termination during **Encrypt & insert**:
   iOS must not replace Layergram with the system keyboard at that step.
3. Repeat **Encrypt & insert** and the host's own **Send** for at least three
   consecutive disposable messages without returning to Layergram. Each
   inserted carrier must contain a readable application message, and the
   keyboard must remain active while touches keep its idle grant alive. Monitor
   extension memory-limit terminations and remaining memory after each send;
   a pass on the first send alone is insufficient. Only with a controlled peer,
   deliver those carriers through the chosen
   transport. After the host's own **Send** action, the Layergram keyboard must
   still admit another message while its idle grant remains valid. If iOS
   dismisses the keyboard, open and unlock Layergram to the chat list, then
   reselect the keyboard; a fresh session must open without resetting FS.
   Import the carrier on the peer and verify the original message is readable
   immediately. Continue until the FS indicator turns green; verify subsequent
   replies, replay handling and a second device for the same identity in Normal
   mode. This step is required before claiming full physical interoperability.
4. Repeat with touches spaced below the configured inactivity timeout and then
   with no keyboard touch beyond it. Touches should renew the autonomous grant;
   genuine inactivity should expire it. Lock, screen recording and mirroring
   should revoke it immediately. With screen protection enabled, a still
   screenshot should hide the entire keyboard surface. If iOS dismisses the
   keyboard while showing the screenshot preview, the old draft must be empty;
   a deliberate tap may reopen a new session with Face ID when that separate
   option is enabled and native FS custody is still valid. Confirm that the
   reopened keyboard can encrypt and insert another message without resetting
   FS. Do not infer host delivery from the keyboard's exported
   status: iOS `insertText` has no host-acceptance result. If iOS sends a memory
   warning while the keyboard is visible, the native grant should remain
   usable after transient UI resources are trimmed; verify another contact
   selection and local draft before the idle deadline.
5. Tap outside the transport field to dismiss the keyboard, then open and
   unlock Layergram to its chat list and select the keyboard again in the same
   transport field. A new session must become active without resetting FS.
   Repeat this once after a successful **Encrypt & insert** operation; the
   keyboard must also remain active immediately after that insertion.
6. After expiry, open and unlock Layergram, return to the same transport field
   and select its keyboard again. A fresh session should become active without
   reinstalling or toggling the keyboard. Type a multiline local draft: `↵`
   and a vertical space-key drag must keep the cursor line visible in both
   directions. Check green function buttons in light appearance and the same
   blue as the app's dark buttons in dark appearance,
   the clipboard icon for paste/decrypt, neutral emoji and `123` keys, and
   Backspace matching Shift. In light appearance, check that the keyboard
   background joins the system's rounded container without a contrasting band
   in both light and dark appearance.
   The status and countdown should have a small, even inset below the curved
   upper edge; a selected
   contact should appear as a small FS shield and name on the neutral background,
   with the shield aligned to the session-status dot. Before confirmation,
   an unknown FS phase should show only the name, never a document placeholder
   or a misleading gray shield;
   while a decoded sender has the same compact visible heading. The lower key
   row should leave only a narrow gap above the separate iOS input-mode area.

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

The system keyboard has its own optional, persisted key-scramble setting,
independent of the in-app keyboard capability. The preference is read before
a session starts and only changes the key presentation hint. It changes
nothing about encryption or admission.

## Tests

```
bash tool/qa/keyboard_v3_regression.sh dart
bash tool/qa/keyboard_v3_regression.sh swift
LAYERGRAM_KEYBOARD_SIMULATOR_ID=<simulator-uuid> \
  bash tool/qa/keyboard_v3_regression.sh ios-ui
```

The Dart and Swift stages run automatically for changes proposed to `main`.
The iOS UI stage is a local simulator gate after keyboard layout, editor-rebind
or native insertion changes. It also exercises the actual shared Keychain
custody mirror after replacing the App Group directory in a disposable test
fixture. The physical procedure above is required after
custody, memory, signing or transport-interaction changes, before claiming
device compatibility; it is not part of every code-only test run. A simulator
cannot prove iOS extension memory limits, secure storage on lock, or how a
transport app treats the inserted carrier.

The Swift package tests the hybrid IPC and editor policy. The iOS
`SystemKeyboardHostTests` suite runs in the experimental embedded Runner build:
it verifies live forwarding through the Flutter channel codec, disable/resume
revocation and suppression of a delayed response. Its Dart peer is synthetic;
it does not prove a complete keyboard interaction with real V3 peers.
The existing Runner screen-shield tests remain part of that native suite.

Physical native regression stages are available separately:

```sh
LAYERGRAM_KEYBOARD_DEVICE_ID=<device-udid> \
LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM=<signing-team> \
LAYERGRAM_ALLOW_PROVISIONING_UPDATES=YES \
  bash tool/qa/keyboard_v3_regression.sh ios-device
LAYERGRAM_KEYBOARD_DEVICE_ID=<device-udid> \
LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM=<signing-team> \
LAYERGRAM_ALLOW_PROVISIONING_UPDATES=YES \
  bash tool/qa/keyboard_v3_regression.sh ios-device-update
LAYERGRAM_KEYBOARD_DEVICE_ID=<device-udid> \
LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM=<signing-team> \
LAYERGRAM_ALLOW_PROVISIONING_UPDATES=YES \
  bash tool/qa/keyboard_v3_regression.sh ios-lifecycle
```

`ios-device` packages the real ML-KEM/SCKA backends, checks device provisioning
for all three products, and exercises first-readable-message negotiation,
green FS, repeated insertions, engine restart and capture revocation through
the native bridge. Its editor snapshots are synthetic. The default fixture
uses a separate QA identifier; `LAYERGRAM_KEYBOARD_REUSE_VALIDATION_APP=YES`
selects the installed validation identifier, but replacing the full app with
the diagnostic entrypoint also requires
`LAYERGRAM_KEYBOARD_REPLACE_FULL_APP_WITH_FIXTURE=YES`. Use both only when that
copy is disposable, then restore the full `lib/main.dart` application build.

`ios-device-update` negotiates green FS with real ML-KEM/SCKA peers, saves the
latest authenticated working state and performs an actual in-place install
between two test processes. The next process must recover the same native
custody revision and decrypt a new message in both directions before advancing
that revision. It uses a protected, test-only recovery journal, removes it after
success, and never treats a new FS as update continuity.

`ios-lifecycle` runs the Swift core suite on the device and reinstalls only
`app.layergram.keyboardvalidation.qa`. It preserves a synthetic advanced
snapshot across an actual in-place installation, then uninstalls/reinstalls
that isolated app and verifies that the private recovery key is gone and old
Keychain ciphertext cannot authorize or decrypt a fresh installation. This
is a custody-storage test, not a full application onboarding or restored-chat
test. It never removes the ordinary app or the manual validation copy.

Run these stages after custody, packaging or engine-lifecycle changes and at
the candidate gate. Keep actual keyboard touches, transport clipboard prompts,
Face ID success/cancellation and screenshot/recording pixels as separate
physical acceptance cases. An OS refusal to authorize UI automation is
`BLOCKED`, even if every native test passes.

For physical touch automation, enable **Settings → Developer → Enable UI
Automation** on the test iPhone first. Use XCTest UI with a signed, offline
UIKit transport fixture; simulator-only automation tools do not control a
physical iPhone. Confirm that Layergram is present in the iOS enabled-keyboard
list and has Full Access before diagnosing a runtime or FS failure. Screen
capture protection can hide the accessibility hierarchy during automated
inspection: disable it only on the disposable test copy, then restore it for
the separate screenshot and recording acceptance checks. Device authentication
and real biometric success remain physical checks; never collect the passcode.

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

When the clipboard contains another person's public identity link, V3 identity
token, or Layergram identity block, the keyboard treats it as a contact import,
not as ciphertext. It leaves the clipboard unchanged and directs the user to
open Layergram and tap Incolla; the app then shows the parsed name and
fingerprint before saving. A person can also use the transport app's Share
action to send the identity to Layergram's existing share extension. iOS does
not provide a supported way for a custom keyboard to launch its containing app
directly, so this flow never claims an automatic handoff.

## Keyboard setup and iOS privacy

After onboarding, and once after an update, the app introduces the system
keyboard. The guide remains available from keyboard settings. On iOS the app
opens its own Settings page through Apple's public URL; users then follow
Settings → General → Keyboard → Keyboards → Add New Keyboard → Layergram and
enable Allow Full Access. Android opens the system input-method settings.

On iOS, biometric resume is a separate, off-by-default keyboard preference.
With current-device Face ID or Touch ID enrollment, a revocable capability is
kept in a device-only, biometric-protected shared Keychain group. New version-2
capabilities do not expire merely because the containing app has been suspended
for ten minutes; already-issued version-1 capabilities retain their original
ten-minute limit. The app removes the item when it reclaims keyboard custody.
An idle session still ends and wipes its runtime. A deliberate key tap can
prompt for biometrics and construct a new session only after current native FS
custody, visible editor, Full Access and capture state are checked. iOS can
assign a new document identifier after a screenshot, so the
biometric check may authorize a fresh editor; it never restores the old draft,
recipient or runtime. Opening the app, losing Full Access, screen recording or
mirroring, access while the device is locked, or changed biometric enrollment
denies the shortcut.
The ordinary app path remains available when the shortcut is unavailable.

The keyboard revokes its session and clears visible secret text when it detects
screen recording or mirroring. When app screen protection is enabled, the
keyboard renders inside a secure-text-entry canvas as a best-effort still-
screenshot mitigation. The screenshot notification arrives **after** capture:
the draft remains only if that canvas, the bound editor and the authorized
session are still live. Otherwise it is cleared, and a new keyboard instance
may offer the optional biometric path. This canvas behavior is not a documented
screenshot-protection API; the host application's content remains outside the
keyboard's control and the behavior must be revalidated on every supported iOS
release and device class.

## Honest limitations

* Physical two-application delivery, decryption and security acceptance remain
  release gates. Automated tests exercise the app service and repository
  boundaries. An Android emulator fixture exercises the native editor, explicit
  contact confirmation, ciphertext insertion and password-field denial; that
  synthetic fixture does not prove end-to-end cryptographic interoperability on
  physical devices.
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
* iOS uses a separate extension process and a bounded authorization. iOS or
  the host app may replace or reject custom keyboards, including in secure text
  fields. The secure canvas is a best-effort screenshot mitigation whose
  behavior must be rechecked on new iOS releases and device classes.
* Identity reloads, passphrase activation and app-lock changes intentionally
  revoke the current keyboard session and require a fresh explicit selection.
  Contact list changes are not subscribed as a revocation trigger: the selected
  contact, its saved fingerprint and its eligibility policy are freshly
  revalidated inside `prepare`, so a contact removed or changed in the meantime
  fails closed.
