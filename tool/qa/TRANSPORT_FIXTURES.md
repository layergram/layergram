# Physical system-keyboard transport

The offline transport app is retained in `ios_transport_fixture` and
`android_transport_fixture`. Both install as `app.layergram.keyboardprobe`.
They provide a real editable host field, Copy and/or Send controls, and no
network transport or cryptography. The Android fixture also contains guarded
UI-only helpers for transport observation and the separate full-app reinstall
test described below.
Encryption and decryption
run in the installed Layergram system keyboard, with actual system lifecycle
callbacks and real injected touches.

Use a disposable Layergram validation installation with an unlocked identity,
an explicitly named contact and the system keyboard enabled. On iOS enable
Developer → UI Automation (re-authorize when iOS requests it), then use XCTest for device gestures. Do not
substitute simulator coordinates, screen mirroring or simulated biometrics for
physical device results. Screenshot protection may be disabled on this QA copy
while inspecting UI; restore and test it separately at the end.

If XCTest times out while enabling automation mode before the first test
action, report an infrastructure failure, not a Layergram failure or pass.
Check the device's actual lock state and Developer UI Automation setting.
Do not reset FS or change conversation data to troubleshoot that condition.
XCTest already requests activation of automation mode automatically when its
runner initializes. The installed Xcode 27 `devicectl` command help exposes no
UI Automation authorization command. Apple's
[Xcode 13 release notes](https://developer.apple.com/documentation/xcode-release-notes/xcode-13-release-notes)
describe required authentication on passcode-protected devices and an
eight-hour authorization cache; do not assume that historical duration is a
guarantee for later OS versions. A requested device authentication remains an
interactive boundary. Never collect/type/store the passcode or disable it.
The retained wrapper attempts once and emits an infrastructure code with exit
75 for a runner-initialization automation timeout with no test actions. It
does not retry that condition until a confirmed external change or user retry.
Its classifier refuses to label a timeout after test actions as this pre-touch
block. Successful initialization or a warm runner is not a crypto/capture pass.

Before a period of unattended physical testing, run `run.sh authorization`
with the normal disposable-device and signing variables. This initializes
XCTest and checks that SpringBoard exists, without activating Layergram,
opening a host field, taking screenshots, typing or touching FS state. If iOS
requests UI Automation authentication, its owner must complete it on the phone.
A pass certifies authorization at that instant, not that it will remain valid
throughout an unattended run. Keep this preflight separate from product tests.

## iOS

### Isolated full-app removal and reinstall

Build the complete app with `LAYERGRAM_KEYBOARD_ISOLATED_FULL_APP=YES`,
`LAYERGRAM_KEYBOARD_ISOLATED_QA=YES`, `LAYERGRAM_KEYBOARD_FIXTURE=YES` and
`LAYERGRAM_KEYBOARD_REUSE_VALIDATION_APP=NO`. The builder uses `lib/main.dart`
and the separate `app.layergram.keyboardvalidation.qa` identifier and App
Groups. Invalid combinations are refused before building. Supply the normal
exact device/signing selection and a task-owned derived-data directory; use
`LAYERGRAM_KEYBOARD_RELEASE=YES` for the complete Release candidate.

Inventory the installed bundles first. Create a throwaway identity in this
isolated copy through normal onboarding and record its display name and public
fingerprint. Reinstall the same complete app in-place, launch only that copy,
and require the same name and fingerprint in its actual identity screen.
Then remove only the isolated `.qa` app, verify that it is absent, reinstall it
and check the real fresh-onboarding state. Keep the existing validation app,
its FS state and the Probe installed throughout. Do not clear shared or global
Keychain data, retain recovery words, or claim that this gate restores an old
FS conversation after uninstall. Installation success alone is not an
identity-continuity or fresh-onboarding pass.

### Autonomous simulator biometrics

For tests that do not require a person's face, select a booted disposable
simulator whose name starts with `Layergram `. The transport wrapper accepts
`LAYERGRAM_KEYBOARD_SIMULATOR=YES` and
`LAYERGRAM_KEYBOARD_DISPOSABLE_SIMULATOR=YES` with its exact UUID; no device
signing team is needed. `run.sh authorization` checks XCTest initialization
before the product tests. A missing simulator testmanagerd socket is an
infrastructure failure before touches, distinct from device authentication.

Install `@appium/coresim@1.9.0` in a temporary tools directory, outside the app
repository, and set `LAYERGRAM_QA_CORESIM_MODULE` to its absolute
`lib/src/index.js` path. Run:

```sh
node tool/qa/ios_transport_fixture/simulator_biometrics.mjs enrolled "$LAYERGRAM_KEYBOARD_DEVICE_ID"
node tool/qa/ios_transport_fixture/simulator_biometrics.mjs match "$LAYERGRAM_KEYBOARD_DEVICE_ID"
```

The helper also supports `status`, `unenrolled` and `nonmatch`. It verifies the
exact booted QA target, refuses physical identifiers and requires explicit
disposable-simulator consent. Enrollment is read back; a match never silently
enrolls a sensor. Sensor injection uses the
[Appium biometric API](https://appium.github.io/appium-xcuitest-driver/12.10/guides/biometric-auth/).
Run its guards with `node --test tool/qa/ios_transport_fixture/test_simulator_biometrics.mjs`.

An injected match is not a test pass: require the actual authentication
callback and fresh keyboard admission, and exact decoded content for a Paste
case. Record cancellation, nonmatch, missing enrollment, ticket expiry and
changed editor separately. Simulator Keychain or capture limitations must not
be hidden by a production authentication mock. Simulated success does not
certify physical Face ID, Secure Enclave or hardware screenshot behavior.

For full-app onboarding in the disposable simulator, the complete Debug build
can use `LAYERGRAM_KEYBOARD_SIMULATOR_SETUP=YES` together with the simulator,
fixture, exact UUID and disposable-simulator flags above. The guarded
`tool/qa/ios_simulator_setup.dart` entry uses the real Layergram app and
changes only that simulator's screenshot-protection preference to make UI
inspection possible. It refuses physical targets and other simulator names.
Re-enable protection before testing capture behavior; no result from this
preparation certifies screenshot safety. Use `run.sh simulator-onboarding` to
check whether the real onboarding controls are exposed to XCTest before trying
unattended identity creation. A rendered screenshot alone is insufficient:
this check currently fails on iOS 26.5 because the Flutter controls are not
present in the accessibility tree, despite the preference reading `false`.
On the exact disposable QA simulator used for layout inspection, the separate
`run.sh simulator-coordinate-entry` diagnostic checks the screenshot size and
Italian onboarding text with Vision before tapping the observed name field.
It types only `QA Touch A` and verifies those characters in a second screenshot;
it refuses an already-filled QA name and never creates an identity. This can
establish that XCTest coordinates reach
the real Flutter input even when accessibility children are absent. It is not
a physical-device, biometric, cryptographic or end-to-end keyboard pass, and
must be recalibrated from a fresh screenshot if the layout changes.
`run.sh simulator-public-seed-onboarding` is a separate, one-use QA gate for
that exact disposable simulator. It checks the live screenshot with OCR before
each tap, then restores a throwaway identity through the real Flutter form
using a published BIP39 test vector. It refuses an app that has already left
onboarding and never reads or supplies a personal recovery phrase. A passing
restore establishes only simulator onboarding and real identity derivation;
keyboard communication, FS, physical Face ID and capture protection require
their own gates. Keep screenshot protection disabled only for this disposable
UI-inspection run and restore it before capture testing.
After a one-use restore, `run.sh simulator-restored-identity-readback` checks
the real identity screen and the disposable name without reentering the test
vector. This is a separate check if the initial runner stopped after the app
completed its restore but before its own final assertion.
The guarded
`run.sh simulator-identity-name-exact` mode edits only the known public-seed
identity's display name. It requires the previously observed doubled name,
checks the exact replacement in the real editor, saves it, cold-relaunches the
app and checks exact on-screen text plus the identity fingerprint label. This
one-use check is not a keyboard or physical-device test; a substring match is
insufficient because it would miss a duplicated final word.
The repeatable `run.sh simulator-identity-name-readback` only checks the exact
persisted name and original fingerprint after a cold launch. A failed one-use
edit can leave an unsaved draft; do not rerun it until read-back establishes the
stored state. The observed duplicate came from placing the fixture caret in
the middle of the name and deleting only its prefix, not from product typing.
Before trying to enable the installed QA keyboard on this simulator,
`run.sh simulator-keyboard-settings-inventory` makes a read-only inventory of
the native Settings navigation. It is restricted to the exact disposable QA
simulator and does not grant Full Access or select an input method.
`run.sh simulator-keyboard-settings-path` follows the accessible native
General → Keyboard → Keyboards path and verifies that Add New Keyboard appears;
it still makes no permission change.
From that verified list, `run.sh simulator-keyboard-availability` opens the
native Add Keyboard chooser and checks that the installed Layergram extension
is offered. It does not enable the keyboard or grant Full Access.
With the native chooser still open, `run.sh simulator-keyboard-add` selects
only the observed Layergram QA extension, then requires it on the installed
keyboard list. It is one-use on this disposable simulator. Full Access and
actual keyboard launch need separate read-back gates.
`run.sh simulator-keyboard-access-page` opens the installed Layergram keyboard
entry and checks that native Full Access is offered, without toggling it.
With that page still open, `run.sh simulator-keyboard-full-access` enables the
throwaway keyboard's Full Access, accepts only an observed keyboard warning,
and requires the real iOS switch to read back on. It is restricted to the exact
disposable QA simulator and says nothing about the physical iPhone.
`run.sh simulator-keyboard-host-inventory` opens the offline Probe text field
and records the selected system keyboard without changing it. The separate
`run.sh simulator-keyboard-launch` selects Layergram from the native keyboard
menu and requires its status to render in Probe. That proves iOS launches the
extension, not an active session, custody, FS, or a message exchange.
On the exact disposable simulator, `simulator-public-contact-inventory` follows
an already opened, checksum-validated QA public identity link through the
observed iOS open-in-app prompt and dismisses only the observed V3 identity
notice. It stops at the import preview. The one-use
`simulator-public-contact-save` checks the QA name and fingerprint prefix
before the save tap; `simulator-public-contact-readback` independently opens
the real Contacts list and verifies the saved name. Do not rerun the save mode
after a successful readback or treat a preview alone as an imported contact.
`run.sh simulator-app-keyboard-settings` inspects the real app Settings after
dismissing the one-time V3 notice. `run.sh simulator-app-keyboard-enable` is
one-use on that same QA identity: it accepts the app's own opt-in dialog and
requires the inactivity setting to appear. `run.sh simulator-keyboard-session`
prepares the Probe and its keyboard selector before the app's finite departure
window, closes an observed V3 identity notice on cold app launch, then requires
an active status and visible countdown after an ordinary app to Probe handoff.
Prepare and verify a real disposable remote contact before treating this as an
end-to-end session gate; the local QA identity alone is insufficient. If it
fails, `simulator-keyboard-session-inventory` records the
settled keyboard and AX state without calling absence of AX an admission
failure. A simulator keyboard launch or app opt-in is not a physical biometric
or message-exchange result.
Do not report a subsequent end-to-end simulator keyboard test as passed until
the real app controls can be operated and the actual keyboard callback checked.

The separate `SimulatorBiometricProbe` in the transport app has passed a real
simulated Face ID match and a sensor-not-enrolled rejection through
`LAContext`. A single simulated nonmatch did not produce a rejection callback
within the test window, and XCTest could not locate the system Cancel control
on this runtime. Those modes remain diagnostic failures, not Layergram failures
or successes. Do not loop sensor events to manufacture a pass.

### Physical transport

Build the complete containing app and extension with
`tool/build_ios_autonomous_keyboard.sh` before installation. Building only the
Runner scheme may copy an older extension product; the complete helper rebuilds
the extension, verifies source freshness, packaged crypto and signing. Never
count a test against a stale installed keyboard as validation of new code.
For production memory validation on a physical device, build with
`LAYERGRAM_KEYBOARD_RELEASE=YES` and install `Release-iphoneos/Runner.app` from
the printed products directory. The default Profile build is useful for
diagnostics; simulator validation remains Debug. A Profile result does not
replace the Release memory/lifecycle gate.

Set `LAYERGRAM_KEYBOARD_DEVICE_ID`, `LAYERGRAM_KEYBOARD_DEVELOPMENT_TEAM`, and
`LAYERGRAM_KEYBOARD_DISPOSABLE_DEVICE=YES`. Run:

```sh
bash tool/qa/ios_transport_fixture/run.sh export
```

The test opens Layergram, switches to the offline host, confirms the exact
`LAYERGRAM_QA_CONTACT_NAME` (default `QA Android`), checks countdown visibility,
types repeated letters, clears the draft, inserts `prova`, presses the host's
Send, then inserts `altra`. Recipient and session must remain available. The
first carrier is a retained XCTest attachment, never a source file.

After a passed exchange, set `LAYERGRAM_QA_HISTORY_PLAINTEXT` to a unique test
phrase sent or received by the keyboard and run `run.sh history`. This opens
the named conversation in Layergram and asserts the exact visible body. A
keyboard preview alone does not attest persistence in the app's chat archive.

For the reverse direction set `LAYERGRAM_QA_INCOMING_FILE` to the other device's
new carrier and `LAYERGRAM_QA_EXPECTED_PLAINTEXT` to the test phrase, then run:

```sh
bash tool/qa/ios_transport_fixture/run.sh decode
```

The host's Copy incoming control first places the supplied ciphertext in the
clipboard after the keyboard has opened, avoiding app-handoff clipboard cleanup.
The test waits for the system paste control to be enabled, then the real keyboard
receives one Paste tap. Do not take diagnostic screenshots during this operation;
they can exercise the capture-protection lifecycle instead of the paste flow.
The preview must display the exact
authenticated plaintext, a sender Reply control and a running countdown.
Set `LAYERGRAM_QA_REPLY_TEXT` to a lowercase phrase supported by the selected
layout to continue through Reply, confirm the authenticated sender, and insert
the response. The outgoing carrier is another retained XCTest attachment;
`QA_TRANSPORT_FS=active|pending` reports the actual recipient shield. Transfer
that attachment to Android and repeat with new messages until both shields
report active. A pending shield is not a completed FS test.
On the final iOS exchange set `LAYERGRAM_QA_EXPECT_FS=active`; on Android pass
`-e qaExpectedFs active`. These make a pending shield fail the final test instead
of relying on reading progress output. Earlier setup exchanges can explicitly
expect `pending`. Unknown or recovery shield states are failures.
Use `ios_transport_fixture/collect_carrier.py --result /temporary/run.xcresult
--output /temporary/reply.txt` to collect the reply without printing ciphertext.
For the initial export add `--attachment qa-first-v3-carrier`. This helper
refuses failed/skipped results, ambiguous attachments, oversized carriers and
partial/fractional text. It does not certify the FS phase by itself.
The harness accepts all current text carriers: `p1.` identity-first messages,
`m3.` frames and `b3.` combined V3 frames. A live FS message can switch to
`b3.`; rejecting that prefix would falsely report a successful insertion as
absent. Every format still has to decrypt through the actual installed keyboard.
An absent input is a configuration failure; a skipped decode test is not a
passed cross-device run. Generated projects, results and carriers stay outside
the repository. The installed transport app remains available for future runs.

The `run.sh lifecycle` gate uses the real idle timeout with biometrics temporarily
disabled: it verifies that inactivity ends the grant and wipes a harmless draft,
hides the keyboard, terminates and relaunches the root app, then requires a new
physical export with the existing FS still active. Its `qa-cold-return-v3-carrier`
attachment must also decrypt on the other device. Restore biometric and capture
preferences after these inspection gates.

`run.sh privacy` restores the screenshot-protection preference through the app
and checks the physical screen compositor. When controls remain accessible,
it types a known harmless draft and requires uniform pixels where its glyphs
were visible. If secure rendering hides all keyboard children from XCTest,
it locates the actual secure keyboard canvas through its observed on-screen
bounds and requires uniform pixels across that canvas. That branch does not
attest draft typing or session admission; the output states this explicitly.
This verifies capture rendering. It does not replace the independent hardware
screenshot-preview, screen-recording and real Face ID recovery gates.

Run `run.sh paste-confirmation` to restore the iOS app's cross-app paste choice
to Ask after inspection tests. This navigates Settings → Apps → Layergram;
first verify that the disposable phone has exactly one installed app with
that display name and that it is the validation bundle. Ambiguous app entries
fail the test. A following `decode` run must still tap Paste
only once; accepting the OS consent prompt is a separate action. For a real
biometric recovery test, use a new unconsumed carrier and set
`LAYERGRAM_QA_START_AFTER_IDLE=YES`. The test waits for the existing grant to
expire before tapping Paste; a person must complete the physical Face ID
prompt. Do not count biometric preference enablement as authentication.

When capture protection hides the keyboard's accessibility controls, prepare a
manual test without disabling that protection. First bring the containing app
to the foreground and wait for its normal custody handoff to become ready, then:

```sh
python3 tool/qa/ios_transport_fixture/prepare_manual_carrier.py \
  --device "$LAYERGRAM_KEYBOARD_DEVICE_ID" --disposable-device YES \
  --input /temporary/fresh-unconsumed-carrier.txt
```

This restarts only the offline host with the bounded carrier in its child
environment. It neither copies the carrier nor authenticates or decrypts it.
In the host, show Layergram's keyboard, let the session expire, tap Copy incoming
test carrier, then tap the keyboard's Paste exactly once and complete real Face
ID and any OS paste consent. Check the exact preview and FS shield manually.
Preparing a carrier alone is never a delivery or a passed biometric test.

For a protected physical keyboard that XCTest cannot inspect, the owner can
confirm a contact, type a unique test phrase and use **Encrypt & insert** in
the already open Probe field. Leave the resulting carrier in that host field;
do not press Probe's offline Send control, which clears it. The read-only
`run.sh readback-carrier` test attaches that existing host text without opening
Layergram or touching the keyboard. Collect it with `collect_carrier.py
--attachment 'QA existing physical carrier'` only after the test passes, then
decode it on the other device. The readback proves insertion into the host,
not the recipient's ability to decrypt or the FS phase; verify those separately.

For the recording lifecycle gate, start with an admitted keyboard and a harmless
draft. Start real screen recording, reopen the keyboard, and require a cleared
draft and denied admission throughout capture. Stop recording, make one fresh
return through the unlocked containing app, and reopen the keyboard. Ending
capture alone must not unlock it, and a delayed stop notification must not revoke
the new app-authorized session. Keep capture protection enabled throughout.
The retained `run.sh recording` mode operates the actual Control Center
recording icon and reads Probe's live `scene.screen.isCaptured` sensor before
and after stopping. Select the Favorites page containing Screen Recording
before running it. The fixture resolves the localized accessibility icon;
it never guesses coordinates among personal Home controls. Supply
`LAYERGRAM_QA_RECORDING_TRACE` with the device-scoped code-only trace covering
this cycle. Both XCTest and the independent trace verifier must pass.
Collect only native lifecycle codes from the explicitly selected device into a
private trace covering this cycle, then check admission ordering with:

```sh
python3 tool/qa/ios_transport_fixture/verify_recording_recovery.py \
  --trace /temporary/device-scoped-recording-cycle.log \
  --xctest-log /temporary/single-completed-recording-test.log
```

The verifier requires an admitted keyboard before capture, no grant until capture stops, and fresh
app preparation, departure, delegation and keyboard admission in order. It
accepts only real root/extension process routes, excluding simulated UIKit
test-host capture events. The protected canvas alone does not prove admission;
neither this automated gate nor its verifier certifies physical draft clearing,
Face ID or FS color. If XCTest fails before its
first touch with `Timed out while enabling automation mode`, record an
infrastructure block and wait for UI Automation to be re-authorized; do not
repeat the run unchanged or label it a Layergram failure.
The wrapper bounds native observation by the single successful XCTest's actual
start/end timestamps. XCTest can hide the host after reporting completion;
the subsequent native hidden-editor revocation is required behavior, outside
the tested visible interval. Revocation inside that interval still fails,
and a missing, failed or ambiguous completion cannot supply a cutoff.

`run.sh handoff-stability` performs six protected iOS root-to-host handoffs,
alternating warm foregrounding and cold containing-app launches. Each visible
cycle has a 20-second observation, followed by explicit host keyboard dismissal.
Keep protection ON and supply `LAYERGRAM_QA_RECORDING_TRACE` as a fresh,
device-scoped native lifecycle trace. The independent
`verify_handoff_stability.py --trace ... --xctest-log ...` requires a fresh root
preparation and admission in every cycle, at least 15 seconds of admitted
observation, and actual hidden-editor revocation after dismissal. Missing AX
controls cannot stand in for revocation. Resigning a host field can invalidate
the document before UIKit delivers disappearance; that route requires observed
document denial, runtime closure, runtime clearing and `viewWillDisappear` in
order. Shared millisecond timestamps between adjacent cycles are allowed only
when the cycle phases remain ordered and observation intervals do not overlap.
Missing AX secret controls do not prove admission. This bounded lifecycle gate does not
attest plaintext, FS color, physical biometrics, or long-term memory stability;
it neither consumes a carrier nor resets FS. Re-run for custody/lifecycle changes,
not cosmetic edits.

## Android

Set `JAVA_HOME` to the installed JDK and `ANDROID_HOME` to the SDK. Build and
install the transport on the explicitly selected disposable device:

```sh
bash tool/qa/android_transport_fixture/build.sh
adb -s "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" install -r "$LAYERGRAM_QA_TRANSPORT_OUTPUT/transport.apk"
```

### Host-owned transport observation

For a cold app-to-keyboard handoff, start a fresh code-only QA trace, stop only
the disposable containing app, and run the host helper with `qaStage=handoff`.
It requires the QA IME to be enabled and selected, waits for the ordinary
unlocked navigation, then returns to Probe without an extra warm-up delay. It
requires the real active status and countdown to remain visible for 20 seconds.
It never copies or pastes a carrier. Count a pass only with
`QA_PHYSICAL_HANDOFF=visibleActiveSessionAndCountdown20s`,
`INSTRUMENTATION_CODE: -1` and no process crash/ANR in that cycle's trace.
Repeat distinct cold and warm cycles with fresh timestamps; do not retry an
unchanged failure or instrument the IME owner's process. This bounded gate does
not certify FS, hardware biometrics or long-term memory stability.

The `KeyboardTransportInstrumentation` helper runs in the offline Probe host;
it does not instrument or restart the process that owns Layergram's IME. It
accepts only the validation package and explicit disposable-device consent.
`qaStage=inspect` reads fixed status categories and whether a declared harmless
QA phrase is visible; it neither touches the UI nor pastes a carrier:

```sh
adb -s "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" shell am instrument -w \
  -e qaTarget app.layergram.keyboardvalidation -e disposableDevice YES \
  -e qaStage inspect -e qaLocale it -e qaExpectedPlaintext risposta \
  app.layergram.keyboardprobe/.KeyboardTransportInstrumentation
```

The diagnostic `qaStage=decode` requires the existing QA IME to be enabled and
selected before any touch. It never enables a component, changes opt-in or
authenticates on the owner's behalf. A disabled component, missing biometric
interaction or unavailable visible control is a failed stage, not a crypto or
FS verdict. It observes only focused app windows and the visible IME; controls
from a previous app window cannot authorize touches in a new window.

Prepare the complete incoming carrier with `load_carrier.py --host-instrumentation`
and the normal `--adb`, `--serial`, and `--input` arguments. This writes only
the Probe's fixed `no_backup/qa-transport-incoming.carrier` input over stdin;
no ciphertext is printed or embedded in a shell command. Then supply its
canonical SHA-256 as `qaCarrierSha256`, the exact harmless lowercase test phrase
as `qaExpectedPlaintext`, and the sender's public label as `qaExpectedContact`:

```sh
adb -s "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" shell am instrument -w \
  -e qaTarget app.layergram.keyboardvalidation -e disposableDevice YES \
  -e qaStage decode -e qaLocale it -e qaExpectedPlaintext risposta \
  -e qaExpectedContact "$QA_PUBLIC_CONTACT" -e qaCarrierSha256 "$QA_CARRIER_SHA256" \
  app.layergram.keyboardprobe/.KeyboardTransportInstrumentation
```

The helper makes an ordinary app-to-Probe handoff, checks visible readiness,
uses the host's explicit incoming-copy control, and issues at most one real
keyboard Paste tap for that carrier. A retained attempt marker prevents retries
after a paste was attempted. Do not delete it to force a test result; an already
visible exact decoded preview can be inspected without another Paste. A pass
requires `QA_PHYSICAL_DECODE=exactPlaintextAndActiveFS` together with
`INSTRUMENTATION_CODE: -1`, exact decoded text, confirmed authenticated sender,
active FS and a running countdown. Shell exit zero or progress markers alone
are insufficient. Bound the driver externally and stop only the Probe on a
timeout, preserving Layergram and its custody. Keep this diagnostic fixture's
validation separate from physical biometrics, cold-start stability and release
qualification.

### Separate complete-app reinstall copy

Build the complete app (`lib/main.dart`, packaged cryptography) with the existing
Gradle `layergramSckaPhysicalSmoke=true` and `layergramSckaCandidatePackage=true`
properties. Verify the APK package with `aapt dump badging`: this gate accepts
only `app.layergram.sckasmoke`. Confirm that package is absent before the initial
install. Never uninstall the validation pair or a personal app for this gate.

On this isolated copy create `QA_Reinstall_Isolated` through onboarding and
legal consent. For API 26+ with Italian UI, the retained helper completes the
generated recovery-word confirmation using the actual accessibility field
hint, which the old `uiautomator dump` XML omits. The generated disposable seed
is read and used only in memory, never exported, logged or stored; screenshots
of the recovery dialog are prohibited. This is UI confirmation, not injection
of identity or custody records.

```sh
adb -s "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" shell am instrument -w \
  -e qaTarget app.layergram.sckasmoke -e disposableDevice YES \
  -e qaStage confirmGeneratedIdentity \
  app.layergram.keyboardprobe/.FullAppLifecycleInstrumentation
```

Dismiss the creation confirmation and record only the new PUBLIC fingerprint.
The helper requires explicit isolated-target and disposable-device arguments,
refuses other packages before reading UI, and returns only fixed result/error
categories. Once the unlocked identity page is visible, assert its public name
and fingerprint:

```sh
adb -s "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" shell am instrument -w \
  -e qaTarget app.layergram.sckasmoke -e disposableDevice YES \
  -e qaStage assertIdentity -e qaExpectedName QA_Reinstall_Isolated \
  -e qaExpectedFingerprint "$QA_PUBLIC_FINGERPRINT" \
  app.layergram.keyboardprobe/.FullAppLifecycleInstrumentation
```

This gate dismisses only the observed V3 migration notice and navigates the
actual identity tab when needed. Install the same complete APK with `adb install
-r`, launch the root normally, wait for the actual rendered UI and repeat the
identity assertion. A same-binary install verifies reinstall-in-place, not a
change between version numbers or active-FS migration. Archive the install log,
APK hash and successful assertions outside the repository.

Then uninstall **only** `app.layergram.sckasmoke`, verify `pm path` is empty,
install the complete APK afresh and launch it. `qaStage assertFreshSetup` must
observe both Create and Restore controls and no old QA identity. Count a pass
only with the specific result marker AND `INSTRUMENTATION_CODE: -1`; shell exit
zero alone is insufficient. This checks destructive removal followed by fresh
setup. It does not claim restoration of the old identity or continuation of an
FS negotiated before removal. Those are independent recovery/exchange gates.
Remove the isolated copy afterward, restore the original default IME, and retain
the offline transport fixture for subsequent tests.

Build the complete validation Profile/AOT app with
`tool/qa/build_android_full_keyboard_validation.sh lib/main.dart`. The builder
requires the QA package, packaged SCKA, and both keyboard Dart defines. A
full-app build without those defines starts with the keyboard feature compiled
out and disables the native IME component on app launch. Install with `adb
install -r` to preserve the QA identity, chats and FS; never replace this app
with the isolated crypto fixture for the UI round trip. Install its
instrumentation APK separately.
Enable its IME through Android input-method settings. Run the retained test:

```sh
adb -s "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" shell am instrument -w \
  -e class app.layergram.KeyboardTransportInstrumentedTest \
  -e qaAction export -e qaContact prova -e qaPlaintext risposta \
  app.layergram.keyboardvalidation.test/androidx.test.runner.AndroidJUnitRunner
```

Only `OK (1 test)` with no crashes or failed assertions passes. Read
`cache/qa-transport-export.txt` from the fixed validation package with `run-as`
into a temporary file, without printing it. For decode supply the other device's
bounded V3 carrier through the retained loader, then run the test with
`qaAction=decode` and the exact `qaPlaintext`:

```sh
python3 tool/qa/android_transport_fixture/load_carrier.py \
  --adb "$ANDROID_HOME/platform-tools/adb" \
  --serial "$LAYERGRAM_KEYBOARD_ANDROID_SERIAL" \
  --input /temporary/ios-reply.txt
```

The loader preserves all carrier lines in one `qa_carrier` intent extra.
Plain argument lists passed to `adb shell` do not preserve literal newlines;
never interpolate the carrier directly into a shell command. Stop if loading
fails, rather than decoding an older clipboard value.
Add `-e qaReplyText risposta -e qaContact prova` to decode, confirm Reply and
export the next carrier in the same physical test. The test reports only its
length and the native shield category, never the carrier or key material.

Use `qaAction=continuity`, `qaPlaintext` and `qaSecondPlaintext` for two real
exports separated by the host app's Send. The test requires exact secret drafts,
a running countdown, preserved recipient and active FS on the second export.
It also checks that host Send and nonce rebind did not extend the native idle
deadline before another keyboard touch.
Only collect the final carrier if the complete test passes.
Android may report a same-field `onStartInput(restarting=true)` after the host
clears a sent carrier, followed by a separate cursor-to-zero callback. This
must preserve the confirmed recipient and active custody only for that visible
OS editor after a successful insertion. Test a different field, hidden window,
expired grant and changed OS binding separately: those must revoke old callbacks
and sensitive UI. A host Send must not renew keyboard inactivity.

`qaAction=privacy` restores screenshot protection in the real app, types a
harmless draft in the offline host, checks the actual IME window's `FLAG_SECURE`
and requires either a refused capture or a uniform protected draft region in
the physical screenshot. Keep a privacy pass separate from export/decode: it
does not attest cross-device delivery or biometric authentication.

After a passed exchange, run the same instrumentation with `qaAction=history`,
`qaContact` and `qaPlaintext` set to a unique sent or received phrase. It opens
the actual Layergram conversation and requires the exact visible message body.
Run it for both directions. Navigation must remain scoped to the validation
package: Android's system Back control is not the app's chat Back button.

The transport fixtures remain installed. Keep their source and these commands
for subsequent regression runs; do not reconstruct an ad hoc transport or try
screen mirroring as a replacement for XCTest/ADB automation.

## Candidate protocol

Run at protocol/custody/lifecycle changes and before a release candidate,
not for every cosmetic edit. Check first-message plaintext in both directions,
continue exchanging new messages until both FS shields are green, and verify
the corresponding Layergram chats after returning to the app. Repeat a host
Send, hide/show, idle expiry, cold app start, in-place update while each side
owns custody, and disposable uninstall/reinstall. No empty technical carrier,
fraction, duplicate plaintext or automatic FS reset is accepted as continuity.

For an opt-in biometric build, keep a separate long-idle gate: after a fresh
app-authorized delegation, leave the same host editor idle for longer than the
legacy ten-minute ticket, then make one deliberate keyboard tap. Require the
real biometric prompt, successful fresh session admission, a new encrypted
message, and preserved FS custody. Cancel, changed biometric enrollment,
recording, loss of Full Access, app reclaim and Android reboot must deny
reopening; a prompt without a successful custody check is not a pass. Existing
version-1 tickets keep their ten-minute expiry until the app issues a new
capability. Simulator sensor injection can check platform callbacks and native
policy, but only the physical device verifies Face ID or Touch ID hardware.

Keep explicit fresh-setup/reset runs separate from continuity. If a reused QA
identity still has an unanswered negotiation addressed to an earlier device,
inspect device bindings before attributing an orange shield to the current
pair. A disposable contact-policy reset must also retire its queued keyboard
transport parts; retaining an old reply in the outbox can otherwise append it
to the new readable message. The integration regression exercises this across
a snapshot reopen without discarding identity/device keys or conversation
records.

For bootstrap/custody changes, run the native mailbox lifecycle regressions
before the device suite. They hold the shared file lock across client/owner
polls and an initial unpublished request. Brief contention must preserve the
unread request and original deadlines; expired leases, closed windows and
revocation must still refuse admission. Waiting for bootstrap never retries a
message operation or accepts a late response.

Keep synthetic native custody tests in the separate isolated `.qa` package and
App Group. Do not run those fixtures in the installation holding the real UI
conversation. Record successful checks, failed stages and missing capabilities
separately; a cryptographic fixture pass does not certify physical UI behavior.
