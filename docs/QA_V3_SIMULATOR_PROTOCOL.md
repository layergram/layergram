# Protocol v3 simulator acceptance

This is a manual end-to-end gate for the user-visible message path. Unit and
integration tests remain the normal check for each code change. Run this gate
only when one of these conditions applies:

- A change affects v3 handshake, ratchet, identity or device routing, message
  framing, carrier capacity, steganography, clipboard import/export, or the
  composer, its embedded keyboard, or a packaged system keyboard.
- The Flutter, Xcode, iOS Simulator, Android Emulator, native crypto backend,
  or platform clipboard implementation changes.
- A release candidate is selected, after automated checks pass and before
  publishing. Run it again only if the candidate changes in one of the areas
  above.
- A reported regression concerns a real send/receive path. Reproduce the
  affected case first, then run the related cases below after the fix.

Do not run the full matrix for unrelated copy, layout, or documentation edits.
For a narrow change, run the affected cases plus one ordinary text exchange.
Record skipped cases and the reason; a build or unit test is not a substitute
for a required simulator case.

For physical keyboard tests, use the retained offline transport apps and
the XCTest/ADB procedures in
[`TRANSPORT_FIXTURES.md`](../tool/qa/TRANSPORT_FIXTURES.md). Keep the actual
conversation installation separate from synthetic custody fixtures.

## Preparation

1. Record the repository commit or working-tree diff, app version, Flutter,
   Xcode, simulator OS, emulator image, and native crypto package versions.
   Use the same candidate build on every participant. Check that the packaged
   v3 crypto backend is functional; a launch alone does not prove this. Record
   separately whether an iOS keyboard extension or Android input method is
   actually packaged and enabled; source files alone do not establish this.
2. Run `flutter analyze` and `flutter test`; resolve failures before the manual
   gate. Keep their result separate from the simulator verdict.
3. Start three isolated app installations: **A1** on macOS, **B** on iOS
   Simulator, and **A2** on Android Emulator. A1 and A2 restore the same
   identity; B has a different identity. Preserve app data for the duration
   of the run. Use separate fresh test sets for the first-text and
   first-steganographic cases so each really exercises a first message.
4. Exchange the identity links in the UI, add contacts, and complete mutual
   verification. Record which device is verified and whether the UI offers a
   new verification ceremony for A2. Do not infer device verification solely
   from an already verified identity.
5. Establish a working copy/paste path **in each direction** using a harmless
   marker before exchanging encrypted carriers. If host-to-iOS clipboard sync
   is broken, the local
   [`ios_simulator_clipboard_bridge.py`](../tool/qa/ios_simulator_clipboard_bridge.py)
   can place the exact carrier on the simulator pasteboard. For example,
   `python3 tool/qa/ios_simulator_clipboard_bridge.py UDID < carrier.txt`.
   Compare its SHA-256 with the sender's carrier, then tap **Paste and decode**
   in Layergram. Record the host-sync failure separately as an environment
   limitation. Do not replace the receiving app's UI import with a direct
   protocol call.

## Acceptance cases

For each row, compose a unique, recognizable secret in the sending app, use
its **Copy** control once, transfer that exact carrier, and use the receiving
app's **Paste and decode** control once. Check the plaintext in both chat UIs.
Keep the carrier or its SHA-256 and character count as evidence; avoid storing
private identity keys or the user's real conversations.

| Case | Action | Required observation |
| --- | --- | --- |
| First text | A1 sends to B before FS becomes active; B replies in text mode. | Both plaintexts appear immediately. Each new send is one carrier within the configured limit, with no empty bubble, `1/2`, `2/2`, or any other fraction. |
| First steganographic | On a fresh test set, repeat the first-message exchange with cover text. Include a cover close to the indicated minimum and a valid encoded carrier near the configured maximum. | Copy is enabled only for valid capacity, succeeds, and one paste reveals the secret. The visible cover and hidden payload survive clipboard transfer. |
| Link carrier | Exchange one link-mode carrier in each direction. | One paste reveals each plaintext; no technical-only message is shown as a chat message. |
| FS progression | Continue ordinary text and steganographic exchanges in alternating directions until both shields turn green. | Every exchange has readable plaintext, no fraction, and the shields progress to green without an empty initiation message. Record the number of user messages, rather than assuming a fixed count. |
| Second device after green | With A1↔B green, send A2→B, B→A1, B→A2, and A1→B, alternating text and steganography. | A2's first plaintext is readable; its own FS can begin, while the A1 session remains usable and green in Normal mode. Verify device-specific routing and verification UI. |
| Second device before green | On a fresh test set, start A1↔B negotiation, then send A2→B before either session is green. Interleave replies to A1 and A2 until both can progress. | Both devices' first and later plaintexts remain readable. Pending negotiation for one device neither replaces nor corrupts the other. |
| Copy and import resilience | Repeat a carrier paste, restart one app, then exchange one more message in both modes. | No duplicate plaintext on repeated import, no lost session after restart, and no preference reset caused by relaunch. |
| Composer boundary | Try generated and manually edited cover text around its indicated minimum and maximum; extend and shorten a text-mode secret. | Character estimate updates with edits; over-limit Copy/Share stay disabled; returning within the limit enables them; Copy succeeds and yields a decodable carrier. |
| System keyboard, when packaged | Enable the Layergram system keyboard in the OS and opt in within the app. In another app's text field, select a verified contact and send a first Normal-mode secret before FS is green. Import the inserted carrier on the receiver, then continue from the in-app composer and repeat with an active session. Check the saved Maximum policy separately. | The host receives exactly one text carrier, the receiver sees the plaintext after one import, and the system keyboard shares the contact's FS state with the app. No empty negotiation message, fraction, or silent relaxation of Maximum is accepted. Record steganography and link as unavailable if the keyboard still exposes text only. |
| System keyboard custody, when packaged | Once FS is green, leave Layergram and use its system keyboard in another app beyond the old 20-second parent window. Send and receive through the keyboard, return to Layergram, and send once more from the in-app composer. Repeat after hiding the keyboard and after locking the device. | The keyboard can use the established session without losing or forking ratchet state. History and shield remain consistent on return; expiry or lock revokes access without exposing plaintext. Record the actual supported inactivity limit and mark this case failed if the keyboard only works while the parent app remains live. |
| Android biometric reopening, at device gate | On a disposable device with strong biometrics enrolled, enable the separate keyboard option. Let idle expire and tap Incolla once on a new incoming carrier; authenticate. Repeat with cancellation, hiding the window, changing host fields, and an expired ticket. Disable the option and change biometric enrollment in separate runs. | The first explicit action executes once after authentication. No PIN fallback, old draft restoration, stale callback reopening, or FS reset is accepted. Missing enrollment must not prevent normal app-authorized use. Test actual system prompt and host behavior on a device; pure policy tests do not certify them. |
| Android screen protection, at device gate | With app screen protection on, type a harmless secret draft in the IME and capture/record the screen. Repeat after turning protection off; never use private conversations in the fixture. | The IME window is protected according to the setting; the host window is unaffected. On returning, the selected recipient and draft must follow the session's visibility/idle rules. |
| System keyboard repeated handoff, when packaged | In another app, encrypt and insert a carrier, then return to Layergram, unlock, and reopen the keyboard. Repeat the export, return, and reopening twice with the same identity and contact. On the last reopening, type continuously across the former 20-second limit and pause for less than the configured idle duration. | Each reopening becomes active, keeps the contact available, and inserts one decodable carrier. Typing renews the inactivity window; a session must not close during active typing or get stuck asking to open Layergram after an export. |
| System keyboard app update, at candidate gate | With an established FS session, let the keyboard advance it, close the keyboard, reopen Layergram to reclaim custody, then update the containing app **in place** without removing its App Groups. Check that app departure alone did not start delegation, then reopen Layergram and exchange a message in each direction before and after reopening the keyboard. Separately repeat an update while the keyboard has custody. Use disposable test identities for that second timing and run it only before a release candidate, not after every UI edit. | The latest ratchet revision survives both update timings. No recovery reset, missing native snapshot, old-key fallback, duplicate plaintext or renewed FS negotiation is accepted. An interrupted preparation with all original private records intact may recover its exact authenticated baseline; active keyboard custody may not be inferred from that case. Inspect only state/revision categories, never keys or message bodies, in diagnostic logs. |
| Contact-policy reset with queued keyboard replies, at candidate gate | On disposable identities, receive an initial setup-bearing message and leave its reply queued. Explicitly reset that contact's session on both sides, then reopen custody and exchange new readable messages until both shields are green. Preserve identity/device keys and history. | Excluded handshake and acknowledgement parts never reappear beside the new messages. The fresh negotiation progresses without another reset, blank carrier, lost recipient or closed keyboard session. This is a reset test, not evidence of continuity for the retired session. |

Inspect the shield **per device and per message**: gray means the message has
no FS, orange means negotiation is still in progress, and green means FS is
active for that device. A readable gray bootstrap message does not prove
post-quantum FS. Confirm the protocol version and the crypto classification
from the candidate's test evidence or local diagnostics without exposing keys.
Strict FS, if tested, is a separate run with its own expected reset behavior;
do not apply the Normal-mode multi-device expectation to it.

## Verdict and record

Use `PASS`, `FAIL`, `BLOCKED`, or `NOT RUN` per case and platform direction.
`PASS` requires visible plaintext on the receiver after one real UI import,
plus the applicable shield and single-carrier assertions. Mark a bridge-assisted
case `PASS (clipboard bridge)` only when the pasteboard SHA-256 matches the
sender's carrier; keep the broken host-sync check `BLOCKED` separately. A
screenshot of the sender or a successful codec test alone is insufficient. For a failure, record
the step, device, time, non-secret carrier metadata, exact visible error, and
whether the clipboard marker passed. For `BLOCKED`, name the environmental
condition and rerun that direction when it is fixed. The release gate passes
only when all cases required by its triggers pass; do not relabel a blocked
case as passed because an automated test covers the same logic.

Keep a dated report with build identities, the case matrix, screenshots of
the resulting chat and shield states, test commands/results, and unresolved
limits. Reuse this protocol at the next trigger rather than repeating manual
simulator work on every code edit.

## Physical iOS automated companion

After custody, native packaging, or runtime lifecycle changes, run the
`ios-device`, `ios-device-update` and `ios-lifecycle` stages documented in
`SYSTEM_KEYBOARD.md`.
The former drives the production native bridge with real packaged V3 crypto
and synthetic editor observations. The latter runs the shared native core on
the phone plus a real install/update/uninstall/reinstall cycle of a separate
fixed QA app, using synthetic encrypted state.
The update stage additionally preserves real green FS through an in-place
installation and decrypts fresh messages in both directions after recovery.
Report these results separately from visible keyboard acceptance. They cannot
substitute for screenshot pixels,
Face ID system prompts, a transport app's paste confirmation or visible
single-touch delivery. Always restore the intended test application build if
the installed validation app was explicitly reused for the crypto fixture.
