import SystemKeyboardCore
import UIKit
import XCTest

/// Native UI regression tests for the Layergram keyboard.
///
/// These tests use a real, unattached `UIInputViewController`, and therefore a
/// real unbound `UITextDocumentProxy`. They never fabricate an owner session,
/// never read host text and never weaken admission: the only extra state they
/// touch is display-only (local draft, surface, decoded-sender display). None of
/// those grants a lease, a recipient or an insertion permit.
///
/// Locale-independent by construction: assertions compare against
/// `Copy.string(_:in: Locale.current)` or against the explicit en/it/es locales
/// instead of assuming an English device.
final class KeyboardViewControllerTests: XCTestCase {
  private let keyHeightFloor: CGFloat = 44
  private let english = KeyboardViewController.Language.english
  private let italian = KeyboardViewController.Language.italian
  private let spanish = KeyboardViewController.Language.spanish

  func testPublicIdentityPasteIsDistinctFromEncryptedMessage() {
    XCTAssertTrue(KeyboardViewController.looksLikePublicIdentity(
      "  layergram://i/v3.public-identity  \n"))
    XCTAssertTrue(KeyboardViewController.looksLikePublicIdentity(
      "layergram://i/legacy.identity"))
    XCTAssertTrue(KeyboardViewController.looksLikePublicIdentity(
      "[Layergram Identity]\nProtocol: layergram/3\n[/Layergram Identity]"))
    XCTAssertTrue(KeyboardViewController.looksLikePublicIdentity(
      "v3.public-identity-token"))
    XCTAssertFalse(KeyboardViewController.looksLikePublicIdentity(
      "layergram://m/encrypted-message"))
    XCTAssertFalse(KeyboardViewController.looksLikePublicIdentity(
      "m3.encrypted-message"))
    XCTAssertFalse(KeyboardViewController.looksLikePublicIdentity(
      "layergram://i/" + String(repeating: "x", count: 4096)))
    for language in [english, italian, spanish] {
      XCTAssertFalse(KeyboardViewController.Copy.string(.identityImport, in: language).isEmpty)
    }
  }

  // MARK: - Harness

  private func makeKeyboard(width: CGFloat = 390, height: CGFloat = 370) -> KeyboardViewController {
    let keyboard = KeyboardViewController()
    keyboard.loadViewIfNeeded()
    keyboard.view.frame = CGRect(x: 0, y: 0, width: width, height: height)
    keyboard.view.layoutIfNeeded()
    return keyboard
  }

  private func keyButton(_ action: String, in view: UIView) -> UIButton? {
    if let button = view as? UIButton,
       button.accessibilityIdentifier == "layergram.key.\(action)" {
      return button
    }
    return view.subviews.lazy.compactMap { self.keyButton(action, in: $0) }.first
  }

  private func actionButton(_ suffix: String, in view: UIView) -> UIButton? {
    if let button = view as? UIButton,
       button.accessibilityIdentifier == "layergram.action.\(suffix)" {
      return button
    }
    return view.subviews.lazy.compactMap { self.actionButton(suffix, in: $0) }.first
  }

  private func pasteAction(in view: UIView) -> UIView? {
    descendantViews(view).first {
      $0.accessibilityIdentifier == "layergram.action.paste"
    }
  }

  private func allButtons(in view: UIView) -> [UIButton] {
    let nested = view.subviews.flatMap { allButtons(in: $0) }
    if let button = view as? UIButton { return [button] + nested }
    return nested
  }

  private func descendantViews(_ view: UIView) -> [UIView] {
    [view] + view.subviews.flatMap { descendantViews($0) }
  }

  private func keyButtons(in keyboard: KeyboardViewController) -> [UIButton] {
    allButtons(in: keyboard.view).filter {
      $0.accessibilityIdentifier?.hasPrefix("layergram.key.") == true
    }
  }

  /// Effective visibility: a view is only visible when neither it nor any
  /// ancestor is hidden, so a globe inside `keysContainer` cannot count as
  /// available while that container is hidden.
  private func effectivelyVisible(_ view: UIView, in root: UIView) -> Bool {
    var current: UIView? = view
    while let node = current {
      if node.isHidden || node.alpha <= 0.01 { return false }
      if node === root { return true }
      current = node.superview
    }
    return false
  }

  private func isDescendant(_ view: UIView, of ancestor: UIView) -> Bool {
    var current = view.superview
    while let node = current {
      if node === ancestor { return true }
      current = node.superview
    }
    return false
  }

  private func textKeys(_ keys: [KeyboardViewController.KeyboardKey]) -> [String] {
    keys.compactMap { key in
      if case .text(let character) = key.kind { return character }
      return nil
    }
  }

  private func actions(
    _ keys: [KeyboardViewController.KeyboardKey]
  ) -> [KeyboardViewController.KeyAction] {
    keys.compactMap(\.action)
  }

  private func middle(_ row: [KeyboardViewController.KeyboardKey])
    -> ArraySlice<KeyboardViewController.KeyboardKey> {
    row.dropFirst().dropLast()
  }

  private func layout(
    _ layer: KeyboardViewController.Layer,
    shift: KeyboardViewController.ShiftState = .off,
    permutation: [Int: [Int]]? = nil
  ) -> [[KeyboardViewController.KeyboardKey]] {
    KeyboardViewController.renderedLayout(
      layer: layer, shift: shift, permutation: permutation, language: english
    )
  }

  // MARK: - Startup

  func testLayoutAndCallbacksBeforeDocumentBindingRemainInert() {
    let keyboard = makeKeyboard()

    // A real, unattached UIKit proxy reproduces the startup state. Reading its
    // nonnull-annotated UUID directly from Swift would trap on a physical device.
    XCTAssertNil(LGKeyboardDocumentIdentifier(keyboard.textDocumentProxy))
    let table = UITableView()
    XCTAssertEqual(keyboard.tableView(table, numberOfRowsInSection: 0), 0)
    keyboard.textWillChange(nil)
    keyboard.textDidChange(nil)
    keyboard.selectionWillChange(nil)
    keyboard.selectionDidChange(nil)
    XCTAssertEqual(keyboard.tableView(table, numberOfRowsInSection: 0), 0)
  }

  func testScreenshotNotificationClearsKeyboardDraftEvenWithoutOwnerSession() {
    let keyboard = makeKeyboard()
    keyboard.setLocalDraft("sensitive draft")
    XCTAssertEqual(keyboard.draft, "sensitive draft")
    NotificationCenter.default.post(name: UIApplication.userDidTakeScreenshotNotification,
                                    object: nil)
    XCTAssertEqual(keyboard.draft, "")
  }

  func testMemoryWarningClearsKeyboardDraftWithoutOwnerSession() {
    let keyboard = makeKeyboard()
    keyboard.setLocalDraft("sensitive draft")
    keyboard.didReceiveMemoryWarning()
    XCTAssertEqual(keyboard.draft, "")
  }

  func testStoppedCaptureNotificationDoesNotRevokeFreshEditorState() {
    let keyboard = makeKeyboard()
    keyboard.setLocalDraft("fresh harmless draft")
    let status = keyboard.status
    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification,
                                    object: nil)
    XCTAssertEqual(keyboard.draft, "fresh harmless draft")
    XCTAssertEqual(keyboard.status, status)
  }

  func testRecordingRevokesDraftAndStoppingCannotRestoreIt() {
    let keyboard = makeKeyboard()
    keyboard.setLocalDraft("harmless recording draft")
    keyboard.handleCaptureChange(captured: true)
    XCTAssertEqual(keyboard.draft, "")
    let deniedStatus = keyboard.status
    keyboard.handleCaptureChange(captured: false)
    XCTAssertEqual(keyboard.draft, "")
    XCTAssertEqual(keyboard.status, deniedStatus)
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection)
  }

  func testNewUnboundControllerCallbackWipesDraftBeforeDocumentReady() {
    let keyboard = makeKeyboard()
    keyboard.viewDidAppear(false)
    keyboard.setLocalDraft("sensitive draft")
    keyboard.textDidChange(nil)
    XCTAssertEqual(keyboard.draft, "")
    keyboard.viewWillDisappear(false)
  }

  func testPendingBootstrapCallbackRequiresSameLiveVisibleUncapturedEditor() {
    func permitted(pending: Bool = true, document: String? = "editor",
                   visible: Bool = true, fullAccess: Bool = true,
                   captured: Bool = false, current: String? = "editor",
                   now: Int64 = 99) -> Bool {
      KeyboardViewController.canContinuePendingDelegation(
        pending: pending, document: document, deadline: 100,
        snapshot: KeyboardEditorSnapshot(isViewVisible: visible, hasFullAccess: fullAccess,
          isCaptured: captured, documentIdentifier: current, monotonicMillis: now))
    }
    XCTAssertTrue(permitted())
    XCTAssertFalse(permitted(pending: false))
    XCTAssertFalse(permitted(document: nil, current: nil))
    XCTAssertFalse(permitted(document: "", current: ""))
    XCTAssertFalse(permitted(visible: false))
    XCTAssertFalse(permitted(fullAccess: false))
    XCTAssertFalse(permitted(captured: true))
    XCTAssertFalse(permitted(current: "different-editor"))
    XCTAssertFalse(permitted(current: nil))
    XCTAssertFalse(permitted(now: 100))
    XCTAssertFalse(permitted(now: 101))
  }

  func testStillScreenshotRetainsDraftOnlyWithProtectedActiveSession() {
    let permitted = KeyboardViewController.canRetainDraftAfterStillScreenshot(
      protectionEnabled: true,
      secureHostReady: true,
      sessionActive: true,
      viewVisible: true,
      recordingActive: false
    )
    XCTAssertTrue(permitted)

    for (protected, host, session, visible, recording) in [
      (false, true, true, true, false),
      (true, false, true, true, false),
      (true, true, false, true, false),
      (true, true, true, false, false),
      (true, true, true, true, true)
    ] {
      XCTAssertFalse(KeyboardViewController.canRetainDraftAfterStillScreenshot(
        protectionEnabled: protected,
        secureHostReady: host,
        sessionActive: session,
        viewVisible: visible,
        recordingActive: recording
      ))
    }
  }

  // MARK: - Conventional iPhone QWERTY geometry

  func testDocumentLanguageSelectsInternationalLatinLayout() {
    typealias InputLayout = KeyboardViewController.InputLayout
    XCTAssertEqual(InputLayout.resolve("es-ES", fallback: Locale(identifier: "en_US")), .spanish)
    XCTAssertEqual(InputLayout.resolve("pt-BR", fallback: Locale(identifier: "en_US")), .portuguese)
    XCTAssertEqual(InputLayout.resolve("fr-CA", fallback: Locale(identifier: "en_US")), .french)
    XCTAssertEqual(InputLayout.resolve("de-DE", fallback: Locale(identifier: "en_US")), .german)
    XCTAssertEqual(InputLayout.resolve("sv-SE", fallback: Locale(identifier: "en_US")), .swedish)
    XCTAssertEqual(InputLayout.resolve("nb-NO", fallback: Locale(identifier: "en_US")), .norwegian)
    XCTAssertEqual(InputLayout.resolve("da-DK", fallback: Locale(identifier: "en_US")), .danish)
    XCTAssertEqual(InputLayout.resolve(nil, fallback: Locale(identifier: "es_ES")), .spanish)
    XCTAssertEqual(InputLayout.resolve("en-US", fallback: Locale(identifier: "es_ES")), .qwerty)
    XCTAssertEqual(InputLayout.resolve("en-US", fallback: Locale(identifier: "es_ES"),
                                       advertisedLanguage: "en-US"), .spanish)
    XCTAssertEqual(InputLayout.resolve("es-ES", fallback: Locale(identifier: "en_US"),
                                       advertisedLanguage: "en-US"), .spanish)

    let english = KeyboardViewController.layout(layer: .letters, shift: .off,
                                                permutation: nil, inputLayout: .qwerty)
    let spanish = KeyboardViewController.layout(layer: .letters, shift: .off,
                                                permutation: nil, inputLayout: .spanish)
    XCTAssertFalse(english[1].keys.contains { $0.label == "ñ" })
    XCTAssertEqual(spanish[1].keys.count, 10)
    XCTAssertFalse(spanish[1].inset,
                   "ten Spanish keys need the full row width so edge keys such as a stay tappable")
    XCTAssertEqual(spanish[1].keys.last?.label, "ñ")
    let spanishUpper = KeyboardViewController.layout(layer: .letters, shift: .on,
                                                     permutation: nil, inputLayout: .spanish)
    XCTAssertEqual(spanishUpper[1].keys.last?.label, "Ñ")
    XCTAssertEqual(InputLayout.portuguese.letterRows[1].last, "ç")
    XCTAssertEqual(Array(InputLayout.french.letterRows[0].prefix(2)), ["a", "z"])
    XCTAssertEqual(InputLayout.german.letterRows[0][5], "z")
    XCTAssertEqual(InputLayout.swedish.letterRows[0].last, "å")
    XCTAssertEqual(Array(InputLayout.norwegian.letterRows[1].suffix(2)), ["ø", "æ"])
    XCTAssertEqual(Array(InputLayout.danish.letterRows[1].suffix(2)), ["æ", "ø"])
    XCTAssertFalse(KeyboardViewController.layout(layer: .letters, shift: .off,
                                                 permutation: nil, inputLayout: .german)[1].inset)
  }

  func testTwoLineComposerHasCircularContextualActionsAndClearControl() throws {
    let keyboard = makeKeyboard()
    let composer = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.compose.row"
    })
    let recipient = try XCTUnwrap(actionButton("recipient", in: keyboard.view))
    let paste = try XCTUnwrap(pasteAction(in: keyboard.view))
    let clear = try XCTUnwrap(actionButton("clearDraft", in: keyboard.view))
    let draft = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.draft"
    })
    XCTAssertEqual(composer.bounds.height, 58, accuracy: 1)
    XCTAssertEqual(draft.bounds.height, 58, accuracy: 1)
    XCTAssertTrue(effectivelyVisible(composer, in: keyboard.view))
    XCTAssertEqual(recipient.bounds.size, CGSize(width: 40, height: 40))
    XCTAssertEqual(paste.bounds.size, recipient.bounds.size)
    let recipientFrame = keyboard.view.convert(recipient.bounds, from: recipient)
    let pasteFrame = keyboard.view.convert(paste.bounds, from: paste)
    let draftFrame = keyboard.view.convert(draft.bounds, from: draft)
    XCTAssertEqual(recipientFrame.midY, pasteFrame.midY, accuracy: 1)
    XCTAssertLessThan(recipientFrame.maxX, draftFrame.minX)
    XCTAssertGreaterThan(pasteFrame.minX, draftFrame.maxX)
    XCTAssertNil(recipient.title(for: .normal))
    XCTAssertNil((paste as? UIButton)?.title(for: .normal))
    XCTAssertEqual(recipient.accessibilityLabel,
                   KeyboardViewController.Copy.string(.contacts, in: Locale.current))
    if #available(iOS 16.0, *) {
      let control = try XCTUnwrap(paste as? UIPasteControl)
      XCTAssertTrue(control.target === keyboard,
                    "UIKit must deliver the user-approved paste directly to this keyboard")
      XCTAssertEqual(control.configuration.displayMode, .iconOnly)
      XCTAssertNotNil(keyboard.pasteConfiguration)
      XCTAssertEqual(control.accessibilityLabel,
                     KeyboardViewController.Copy.string(.pasteDecrypt, in: Locale.current))
      XCTAssertEqual(control.accessibilityHint,
                     KeyboardViewController.Copy.string(.pasteDecrypt, in: Locale.current))
    } else {
      XCTAssertEqual(paste.accessibilityLabel,
                     KeyboardViewController.Copy.string(.pasteDecrypt, in: Locale.current))
      XCTAssertEqual((paste as? UIButton)?.configuration?.image?.size,
                     UIImage(systemName: "doc.on.clipboard")?.size)
    }
    XCTAssertTrue(clear.isHidden)
    XCTAssertNil(actionButton("primary", in: keyboard.view))

    keyboard.setLocalDraft("ciao")
    keyboard.view.layoutIfNeeded()
    let send = try XCTUnwrap(actionButton("primary", in: keyboard.view))
    if #available(iOS 16.0, *) {
      XCTAssertTrue(paste.isHidden, "system paste control leaves the send slot")
      XCTAssertFalse(send.isHidden)
    } else {
      XCTAssertTrue(send === paste, "iOS 15 keeps its contextual action")
    }
    XCTAssertEqual(send.configuration?.image?.size, CGSize(width: 26, height: 26))
    XCTAssertEqual(send.accessibilityLabel,
                   KeyboardViewController.Copy.string(.encryptInsert, in: Locale.current))
    XCTAssertFalse(clear.isHidden)
    XCTAssertTrue(isDescendant(clear, of: draft.superview!))
    clear.sendActions(for: .touchUpInside)
    XCTAssertEqual(keyboard.draft, "")
    XCTAssertTrue(clear.isHidden)
    XCTAssertFalse(try XCTUnwrap(pasteAction(in: keyboard.view)).isHidden)
    XCTAssertNil(actionButton("primary", in: keyboard.view))
  }

  func testSessionCountdownSharesStatusRowAndStaysRightAligned() throws {
    let keyboard = makeKeyboard()
    let status = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.status"
    })
    let countdown = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.window"
    })
    XCTAssertTrue(status.superview === countdown.superview)
    XCTAssertLessThan(status.frame.minX, countdown.frame.minX)
    XCTAssertEqual(status.frame.midY, countdown.frame.midY, accuracy: 1)
    let statusFrame = keyboard.view.convert(status.bounds, from: status)
    let countdownFrame = keyboard.view.convert(countdown.bounds, from: countdown)
    XCTAssertEqual(statusFrame.minY, 2, accuracy: 1,
                   "the status row has minimal clearance below the curved iOS edge")
    XCTAssertGreaterThanOrEqual(statusFrame.minX, 15,
                                "the left label remains inside the rounded edge")
    XCTAssertLessThanOrEqual(countdownFrame.maxX, keyboard.view.bounds.maxX - 15,
                             "the countdown remains inside the rounded edge")
  }

  func testCountdownKeepsItsWidthWhenStatusNeedsMoreRoom() throws {
    let keyboard = makeKeyboard()
    let status = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.status"
    } as? UILabel)
    let countdown = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.window"
    } as? UILabel)
    status.text = String(repeating: "Destinatario ", count: 12)
    countdown.text = "60s"
    keyboard.view.setNeedsLayout()
    keyboard.view.layoutIfNeeded()
    XCTAssertGreaterThanOrEqual(countdown.bounds.width,
                                countdown.intrinsicContentSize.width - 1,
                                "a long status may truncate, but not hide the idle countdown")
  }

  func testOwnInsertionCallbacksCannotCloseTheLiveReboundSession() {
    let route = KeyboardViewController.hostCallbackAction
    XCTAssertEqual(route(true, false, true), .deferOwnExport,
                   "host callbacks during insertText and the export ACK are ours")
    XCTAssertEqual(route(false, true, false), .deferOwnExport,
                   "callbacks during native rebind must not revoke the fresh editor")
    XCTAssertEqual(route(false, true, true), .deferOwnExport,
                   "the rebind guard must remain set until its begin reply arrives")
    XCTAssertEqual(route(false, false, false), .rebind,
                   "an ordinary host editor callback still clears old local state")
    XCTAssertEqual(route(false, false, true), .invalidate,
                   "a changed editor during an unrelated request still fails closed")
  }

  func testRecipientReuseRequiresOwnExportAndExactDocument() {
    let recipient = KeyboardContact(id: "a", name: "Ana", fingerprint: "fingerprint")
    let eligible = KeyboardViewController.canRestoreRecipientAfterOwnExport
    XCTAssertTrue(eligible(recipient, "document-1", "document-1"))
    XCTAssertFalse(eligible(nil, "document-1", "document-1"))
    XCTAssertFalse(eligible(recipient, nil, "document-1"))
    XCTAssertFalse(eligible(recipient, "document-1", "document-2"))
    XCTAssertFalse(eligible(recipient, "document-1", nil))

    let match = KeyboardViewController.matchesRecipientAfterOwnExport
    XCTAssertTrue(match(recipient, KeyboardContact(id: "a", name: "Ana renamed",
                                                       fingerprint: "fingerprint")))
    XCTAssertFalse(match(recipient, KeyboardContact(id: "b", name: "Ana",
                                                        fingerprint: "fingerprint")),
                   "a different contact must require an explicit choice")
    XCTAssertFalse(match(recipient, KeyboardContact(id: "a", name: "Ana",
                                                        fingerprint: "changed")),
                   "a replaced identity key must not inherit the earlier selection")
  }

  func testNativeRebindDoesNotPollTheIntentionallyEndedEditor() {
    XCTAssertFalse(KeyboardViewController.needsEditorPolicyRevalidation(
      runtimeReady: true, rebindInProgress: true),
      "native custody remains checked while Dart binds the next editor")
    XCTAssertTrue(KeyboardViewController.needsEditorPolicyRevalidation(
      runtimeReady: true, rebindInProgress: false),
      "the new editor resumes full policy admission once rebind completes")
    XCTAssertFalse(KeyboardViewController.needsEditorPolicyRevalidation(
      runtimeReady: false, rebindInProgress: false))
  }

  func testTwoLineDraftKeepsBeginningAndEndVisibleAtNarrowWidth() throws {
    let keyboard = makeKeyboard(width: 320, height: 306)
    keyboard.setLocalDraft("Messaggio segreto di prova")
    keyboard.view.layoutIfNeeded()
    let draft = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.draft"
    } as? UITextView)
    let first = draft.caretRect(for: draft.beginningOfDocument)
    let last = draft.caretRect(for: draft.endOfDocument)
    XCTAssertGreaterThanOrEqual(first.minY, draft.contentOffset.y - 1)
    XCTAssertLessThanOrEqual(last.maxY, draft.contentOffset.y + draft.bounds.height + 1)
    XCTAssertGreaterThan(last.minY, first.minY, "text should occupy two lines")
    let stableOffset = draft.contentOffset.y
    for _ in 0..<5 {
      keyboard.setLocalDraftCursorForDisplay(0)
      keyboard.setLocalDraftCursorForDisplay(keyboard.draft.count)
      XCTAssertEqual(draft.contentOffset.y, stableOffset, accuracy: 0.5,
                     "moving inside a fully visible draft must not oscillate the scroll position")
    }
  }

  func testLetterLayoutKeepsConventionalIPhoneRows() {
    let rows = layout(.letters)

    XCTAssertEqual(rows.count, 4)
    XCTAssertEqual(rows[0].count, 10, "row 1 is the full ten-letter run")
    XCTAssertEqual(rows[1].count, 9, "row 2 is the inset nine-letter run")
    XCTAssertEqual(rows[2].count, 9, "row 3 is shift + seven letters + backspace")
    XCTAssertEqual(textKeys(rows[2]).count, 7)
    XCTAssertEqual(rows[3].count, 5, "bottom row is 123, globe, emoji, wide space, return")

    XCTAssertEqual(textKeys(rows[0]), ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"])
    XCTAssertEqual(textKeys(rows[1]), ["a", "s", "d", "f", "g", "h", "j", "k", "l"])
    XCTAssertEqual(textKeys(rows[2]), ["z", "x", "c", "v", "b", "n", "m"])

    // Shift is leftmost on row 3 and backspace rightmost: the actions are never
    // reordered and never sit inside the letter run.
    XCTAssertEqual(actions([rows[2][0]]), [.shift])
    XCTAssertEqual(actions([rows[2][rows[2].count - 1]]), [.backspace])
    XCTAssertEqual(actions(Array(middle(rows[2]))).isEmpty, true)

    // Rows 2 and 3 are inset under the full-width top row.
    XCTAssertEqual(
      KeyboardViewController.layout(layer: .letters, shift: .off, permutation: nil).map(\.inset),
      [false, true, true]
    )
    XCTAssertGreaterThan(KeyboardViewController.insetRowInset, 0)

    // The bottom row is positional: layer, globe, emoji, wide space, return.
    XCTAssertEqual(actions(rows[3]), [.layer, .globe, .emoji, .space, .newline])
    XCTAssertEqual(rows[3].first?.label, "123")
    XCTAssertEqual(rows[3].last?.label, "↵")

    // Shift changes the typed label, never the action layout.
    let shifted = layout(.letters, shift: .on)
    XCTAssertEqual(textKeys(shifted[0]), ["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"])
    XCTAssertEqual(actions([shifted[2][0]]), [.shift])
    XCTAssertEqual(KeyboardViewController.shiftGlyph(for: .locked), "⇪")
  }

  func testEveryLayerUsesPredictableActionsAndKeepsEveryKeyReachable() {
    // Bottom-left layer key: letters offer 123, both non-letter pages return
    // straight to letters with ABC.
    XCTAssertEqual(KeyboardViewController.layerPresentation(for: .letters).title, "123")
    XCTAssertEqual(KeyboardViewController.layerPresentation(for: .letters).action, .layer)
    XCTAssertEqual(KeyboardViewController.layerPresentation(for: .numbers).title, "ABC")
    XCTAssertEqual(KeyboardViewController.layerPresentation(for: .numbers).action, .layer)
    XCTAssertEqual(KeyboardViewController.layerPresentation(for: .symbols).title, "ABC")
    XCTAssertEqual(KeyboardViewController.layerPresentation(for: .symbols).action, .layer)

    // Third-row leading key: Shift on letters, the #+= / 123 page toggle on the
    // numeric and symbol pages (never a useless Shift key).
    XCTAssertEqual(
      KeyboardViewController.thirdRowLeadingPresentation(for: .letters, shift: .off).action,
      .shift
    )
    XCTAssertEqual(
      KeyboardViewController.thirdRowLeadingPresentation(for: .numbers, shift: .off).title,
      "#+="
    )
    XCTAssertEqual(
      KeyboardViewController.thirdRowLeadingPresentation(for: .numbers, shift: .off).action,
      .symbols
    )
    XCTAssertEqual(
      KeyboardViewController.thirdRowLeadingPresentation(for: .symbols, shift: .off).title,
      "123"
    )
    XCTAssertEqual(
      KeyboardViewController.thirdRowLeadingPresentation(for: .symbols, shift: .off).action,
      .symbols
    )

    // Reachable transitions: letters -> numbers -> symbols -> numbers, and both
    // non-letter pages go directly back to letters.
    XCTAssertEqual(KeyboardViewController.layerAfter(.letters, tapped: .layer), .numbers)
    XCTAssertEqual(KeyboardViewController.layerAfter(.numbers, tapped: .layer), .letters)
    XCTAssertEqual(KeyboardViewController.layerAfter(.symbols, tapped: .layer), .letters)
    XCTAssertEqual(KeyboardViewController.layerAfter(.numbers, tapped: .symbols), .symbols)
    XCTAssertEqual(KeyboardViewController.layerAfter(.symbols, tapped: .symbols), .numbers)
    XCTAssertEqual(KeyboardViewController.layerAfter(.letters, tapped: .symbols), .letters)

    // Geometry per layer: 10 / (9 or 10) / toggle + 7 + backspace / 5.
    for layer in [KeyboardViewController.Layer.letters, .numbers, .symbols] {
      let rows = layout(layer)
      XCTAssertEqual(rows.count, 4)
      XCTAssertEqual(rows[0].count, 10, "\(layer) row 1")
      XCTAssertEqual(rows[1].count, layer == .letters ? 9 : 10, "\(layer) row 2")
      XCTAssertEqual(rows[2].count, 9, "\(layer) row 3 keeps the shared action geometry")
      XCTAssertEqual(textKeys(rows[2]).count, 7, "\(layer) row 3 text run")
      XCTAssertEqual(
        actions([rows[2][0]]),
        [layer == .letters ? .shift : .symbols],
        "\(layer) third-row leading action"
      )
      XCTAssertEqual(actions([rows[2][rows[2].count - 1]]), [.backspace], "backspace stays rightmost")
      XCTAssertEqual(actions(Array(middle(rows[2]))).isEmpty, true, "no action inside the text run")
      XCTAssertEqual(actions(rows[3]), [.layer, .globe, .emoji, .space, .newline])
      XCTAssertEqual(rows[3].first?.label, layer == .letters ? "123" : "ABC")
    }

    // No numeric or operator key is silently dropped to fit the geometry.
    let numberKeys = Set(layout(.numbers).dropLast().flatMap(textKeys))
    for key in [
      "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
      "-", "/", ":", ";", "(", ")", "$", "&", "@", "\"",
      ".", ",", "?", "!", "'", "#", "%"
    ] {
      XCTAssertTrue(numberKeys.contains(key), "numbers page keeps \(key)")
    }
    XCTAssertEqual(numberKeys.count, 27, "the numeric page exposes its whole keyset")
    // + = * are reachable on the symbols page, not trimmed away.
    let symbolKeys = Set(layout(.symbols).dropLast().flatMap(textKeys))
    for key in ["+", "=", "*", "#", "%", "[", "]", "{", "}", "€", "£", "¥"] {
      XCTAssertTrue(symbolKeys.contains(key), "symbols page keeps \(key)")
    }
    XCTAssertEqual(symbolKeys.count, 27, "the symbols page exposes its whole keyset")
  }

  func testScramblePermutesOnlyTextSlots() {
    // An explicit permutation exercises the real scrambled branch without any
    // production bypass of the owner-reported capability flag.
    let permutation: [Int: [Int]] = [
      0: Array(Array(0..<10).reversed()),
      1: Array(Array(0..<9).reversed()),
      2: Array(Array(0..<7).reversed())
    ]
    let scrambled = layout(.letters, permutation: permutation)

    XCTAssertEqual(textKeys(scrambled[0]), ["p", "o", "i", "u", "y", "t", "r", "e", "w", "q"])
    XCTAssertEqual(textKeys(scrambled[1]), ["l", "k", "j", "h", "g", "f", "d", "s", "a"])
    XCTAssertEqual(textKeys(scrambled[2]), ["m", "n", "b", "v", "c", "x", "z"])

    // Every action keeps its exact position and identity.
    XCTAssertEqual(scrambled[2].count, 9)
    XCTAssertEqual(actions([scrambled[2][0]]), [.shift], "shift stays leftmost")
    XCTAssertEqual(
      actions([scrambled[2][scrambled[2].count - 1]]), [.backspace],
      "backspace stays rightmost"
    )
    XCTAssertEqual(actions(Array(middle(scrambled[2]))).isEmpty, true, "no action inside the run")
    XCTAssertEqual(actions(scrambled[3]), [.layer, .globe, .emoji, .space, .newline])

    // The identity case is the conventional iPhone order.
    let plain = layout(.letters)
    XCTAssertEqual(textKeys(plain[0]), ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"])

    // A malformed order is ignored, never a silent key re-map.
    XCTAssertEqual(KeyboardViewController.permuted(["a", "b", "c"], order: [0, 0, 1]), ["a", "b", "c"])
    XCTAssertEqual(KeyboardViewController.permuted(["a", "b", "c"], order: nil), ["a", "b", "c"])
  }

  // MARK: - On-screen frames

  func testRenderedKeyFramesStayTappableContainedAndNonOverlapping() {
    for size in [CGSize(width: 390, height: 370), CGSize(width: 320, height: 370)] {
      let keyboard = makeKeyboard(width: size.width, height: size.height)
      keyboard.view.layoutIfNeeded()

      let buttons = keyButtons(in: keyboard)
      XCTAssertEqual(buttons.count, keyboard.showsEmbeddedInputSwitcher ? 32 : 31, "globe exists only when UIKit requires it at \(size)")
      let bounds = keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5)

      for button in buttons {
        let identifier = button.accessibilityIdentifier ?? "?"
        XCTAssertGreaterThan(button.bounds.height, 0, "\(identifier) has a nonzero height at \(size)")
        XCTAssertGreaterThanOrEqual(
          button.bounds.height, keyHeightFloor - 0.5,
          "\(identifier) stays reasonably tappable at \(size)"
        )
        XCTAssertGreaterThan(button.bounds.width, 0, "\(identifier) has a nonzero width at \(size)")
        XCTAssertTrue(
          effectivelyVisible(button, in: keyboard.view),
          "\(identifier) is effectively visible at \(size)"
        )
        let frame = keyboard.view.convert(button.bounds, from: button)
        XCTAssertTrue(
          bounds.contains(frame),
          "\(identifier) frame \(frame) stays inside the input view \(keyboard.view.bounds) at \(size)"
        )
      }

      // Visible key frames never overlap each other.
      let frames = buttons.map { keyboard.view.convert($0.bounds, from: $0) }
      for first in frames.indices {
        for second in frames.indices where second > first {
          XCTAssertFalse(
            frames[first].intersects(frames[second]),
            "keys \(first) and \(second) overlap at \(size)"
          )
        }
      }

      // Backspace is in the same row as shift and strictly to its right.
      guard let shift = keyButton("shift", in: keyboard.view),
            let backspace = keyButton("backspace", in: keyboard.view) else {
        return XCTFail("shift and backspace must both exist at \(size)")
      }
      XCTAssertTrue(shift.superview === backspace.superview)
      XCTAssertGreaterThan(backspace.frame.minX, shift.frame.minX)

      // Face ID phones get the switcher below the input view. UIKit only asks
      // the extension to draw another globe when that system control is absent.
      guard let space = keyButton("space", in: keyboard.view) else {
        return XCTFail("space must exist at \(size)")
      }
      if keyboard.showsEmbeddedInputSwitcher {
        guard let globe = keyButton("globe", in: keyboard.view) else {
          return XCTFail("UIKit required the globe at \(size)")
        }
        XCTAssertTrue(globe.superview === space.superview)
        XCTAssertLessThan(globe.frame.minX, space.frame.minX)
        XCTAssertGreaterThan(space.frame.width, globe.frame.width)
      } else {
        XCTAssertNil(keyButton("globe", in: keyboard.view))
      }
      guard let emoji = actionButton("emoji", in: keyboard.view),
            let layer = keyButton("layer", in: keyboard.view) else {
        return XCTFail("emoji and 123 keys must exist at \(size)")
      }
      let emojiFrame = keyboard.view.convert(emoji.bounds, from: emoji)
      let layerFrame = keyboard.view.convert(layer.bounds, from: layer)
      let spaceFrame = keyboard.view.convert(space.bounds, from: space)
      XCTAssertNil(emoji.title(for: .normal), "emoji button is icon-only")
      XCTAssertNotNil(emoji.image(for: .normal))
      XCTAssertGreaterThan(emojiFrame.minX, layerFrame.maxX)
      XCTAssertLessThan(emojiFrame.maxX, spaceFrame.minX)
      XCTAssertGreaterThan(space.frame.width, keyButton("newline", in: keyboard.view)!.frame.width)
      XCTAssertEqual(keyButton("newline", in: keyboard.view)?.title(for: .normal), "↵")
      XCTAssertEqual(emoji.backgroundColor?.resolvedColor(with: keyboard.traitCollection),
                     layer.backgroundColor?.resolvedColor(with: keyboard.traitCollection))
      XCTAssertNotNil(space.gestureRecognizers?.compactMap { $0 as? UILongPressGestureRecognizer }.first)
      XCTAssertNil(backspace.title(for: .normal))
      XCTAssertNotNil(backspace.image(for: .normal))
    }
  }

  func testLongStatusAndDraftDoNotSqueezeKeysOffTheInputView() {
    // A real unattached proxy produces a genuine, long admission status; the
    // draft is display-only state, and neither is a forged grant.
    for size in [CGSize(width: 390, height: 370), CGSize(width: 320, height: 370)] {
      let keyboard = makeKeyboard(width: size.width, height: size.height)
      keyboard.viewDidAppear(false)
      defer { keyboard.viewWillDisappear(false) }
      XCTAssertFalse(keyboard.status.isEmpty, "startup always states a real status at \(size)")

      keyboard.setLocalDraft(String(repeating: "mensaje ", count: 40))
      // Also render the preview + sender display through the display-only seam:
      // a generic long decoded message, never a forged grant.
      keyboard.applyDecodedPreview(
        KeyboardViewController.DecodedPreviewDisplay(
          contactId: "c9",
          contactName: "Nombre Largo",
          fingerprint: "AA BB CC",
          text: String(repeating: "texto largo ", count: 40)
        )
      )
      keyboard.view.layoutIfNeeded()

      let bounds = keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5)
      XCTAssertEqual(keyboard.surface, .preview)
      XCTAssertTrue(keyboard.keysContainerView.isHidden)
      for button in keyButtons(in: keyboard).filter({ effectivelyVisible($0, in: keyboard.view) }) {
        XCTAssertGreaterThanOrEqual(
          button.bounds.height, keyHeightFloor - 0.5,
          "keys stay tappable under a long status/draft/preview at \(size)"
        )
        XCTAssertTrue(
          bounds.contains(keyboard.view.convert(button.bounds, from: button)),
          "keys stay inside the input view under a long status/draft/preview at \(size)"
        )
      }
      // The persistent actions must survive, including the reply shortcut.
      for suffix in ["back", "sender"] + (keyboard.showsEmbeddedInputSwitcher ? ["globe"] : []) {
        guard let button = actionButton(suffix, in: keyboard.view) else {
          return XCTFail("action \(suffix) is missing at \(size)")
        }
        XCTAssertTrue(effectivelyVisible(button, in: keyboard.view), "\(suffix) visible at \(size)")
        let minimumHeight = suffix == "sender" || suffix == "globe"
          ? keyHeightFloor : KeyboardViewController.actionBarMinimumHeight
        XCTAssertGreaterThanOrEqual(button.bounds.height, minimumHeight,
                                    "\(suffix) must remain tappable")
        XCTAssertTrue(
          bounds.contains(keyboard.view.convert(button.bounds, from: button)),
          "\(suffix) stays inside the input view at \(size)"
        )
      }
      let preview = keyboard.view.subviews.flatMap { descendantViews($0) }
        .first { $0.accessibilityIdentifier == "layergram.preview" }
      XCTAssertGreaterThanOrEqual(preview?.bounds.height ?? 0, 46)
      let status = keyboard.view.subviews.flatMap { descendantViews($0) }
        .first { $0.accessibilityIdentifier == "layergram.status" }
      XCTAssertGreaterThan(status?.bounds.height ?? 0, 12)
    }
  }

  // MARK: - Discoverable message workflow

  func testComposingStatusDraftAndActionsKeepReadableFrames() {
    for width: CGFloat in [320, 390] {
      let keyboard = makeKeyboard(width: width, height: 306)
      keyboard.viewDidAppear(false)
      defer { keyboard.viewWillDisappear(false) }
      keyboard.setLocalDraft("PROVA")
      keyboard.view.layoutIfNeeded()
      let status = descendantViews(keyboard.view).first {
        $0.accessibilityIdentifier == "layergram.status"
      }
      XCTAssertGreaterThan(status?.bounds.height ?? 0, 12)
      for suffix in ["primary", "recipient", "clearDraft"] {
        let button = actionButton(suffix, in: keyboard.view)!
        XCTAssertGreaterThanOrEqual(button.bounds.height,
                                    KeyboardViewController.actionBarMinimumHeight)
        XCTAssertTrue(keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(
          keyboard.view.convert(button.bounds, from: button)))
      }
      for button in keyButtons(in: keyboard) {
        XCTAssertTrue(keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(
          keyboard.view.convert(button.bounds, from: button)))
      }
      let recipientName = descendantViews(keyboard.view).first {
        $0.accessibilityIdentifier == "layergram.recipient.name"
      } as? UILabel
      recipientName?.text = "A: Destinatario di prova"
      recipientName?.isHidden = false
      keyboard.view.layoutIfNeeded()
      for button in keyButtons(in: keyboard) {
        XCTAssertTrue(keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(
          keyboard.view.convert(button.bounds, from: button)),
          "keys remain visible with a recipient name at \(width) pt")
      }
    }
  }

  func testContextualActionShowsPasteBeforeWritingAndSendAfterWriting() {
    let keyboard = makeKeyboard()
    XCTAssertNil(keyboard.pendingSelection)

    let primary = actionButton("primary", in: keyboard.view)
    let paste = pasteAction(in: keyboard.view)
    let recipient = actionButton("recipient", in: keyboard.view)
    XCTAssertNil(primary, "send appears only after writing")
    XCTAssertNotNil(paste, "the paste & decrypt action exists before any selection")
    XCTAssertNotNil(recipient, "recipient selection is directly discoverable")
    XCTAssertEqual(paste?.isHidden, false)
    XCTAssertEqual(recipient?.isHidden, false)
    XCTAssertEqual((paste as? UIControl)?.isEnabled, true)
    if #available(iOS 16.0, *) {
      XCTAssertTrue(paste is UIPasteControl,
                    "iOS must authorize the paste through the system control")
    } else {
      XCTAssertNotNil((paste as? UIButton)?.configuration?.image)
    }

    // Icon-only controls keep the toolbar compact; full localized action
    // names remain available to VoiceOver.
    if #available(iOS 16.0, *) {
      XCTAssertEqual(paste?.accessibilityHint,
                     KeyboardViewController.Copy.string(.pasteDecrypt, in: Locale.current))
    } else {
      XCTAssertEqual(paste?.accessibilityLabel,
                     KeyboardViewController.Copy.string(.pasteDecrypt, in: Locale.current))
    }
    XCTAssertNil(recipient?.title(for: .normal))
    XCTAssertEqual(recipient?.accessibilityLabel,
                   KeyboardViewController.Copy.string(.contacts, in: Locale.current))
    keyboard.setLocalDraft("ciao")
    let send = actionButton("primary", in: keyboard.view)
    if #available(iOS 16.0, *) {
      XCTAssertEqual(paste?.isHidden, true)
      XCTAssertEqual(send?.isHidden, false)
    } else {
      XCTAssertTrue(send === paste)
    }
    XCTAssertEqual(send?.accessibilityLabel,
                   KeyboardViewController.Copy.string(.encryptInsert, in: Locale.current))
  }

  func testPasteResultCannotCrossEditorOrDocumentRebind() {
    let matches = KeyboardViewController.matchesPasteDelivery
    XCTAssertTrue(matches("nonce-1", "nonce-1", "document-1", "document-1"))
    XCTAssertFalse(matches("nonce-1", "nonce-2", "document-1", "document-1"))
    XCTAssertFalse(matches("nonce-1", "nonce-1", "document-1", "document-2"))
    XCTAssertFalse(matches(nil, "nonce-1", "document-1", "document-1"))
    XCTAssertFalse(matches("nonce-1", "nonce-1", nil, "document-1"))
  }

  func testDeferredPasteRequiresSameDocumentGenerationAndFreshGrant() {
    let matches = KeyboardViewController.matchesDeferredPaste
    XCTAssertTrue(matches("editor-1", "editor-1", 7, 7, 1000, 61000))
    XCTAssertFalse(matches("editor-1", "editor-2", 7, 7, 1000, 1001))
    XCTAssertFalse(matches("editor-1", "editor-1", 7, 8, 1000, 1001))
    XCTAssertFalse(matches("editor-1", "editor-1", 7, 7, 1000, 61001))
    XCTAssertFalse(matches("editor-1", "editor-1", 7, 7, 1000, 999))
    XCTAssertFalse(matches(nil, nil, 7, 7, 1000, 1001))
  }

  func testContactSearchMatchesNameAndFingerprintWithoutSelectingAnyone() {
    let contacts = [
      KeyboardContact(id: "one", name: "Álvaro", fingerprint: "0074-FB6A-FA27"),
      KeyboardContact(id: "two", name: "Beatrice", fingerprint: "AABB-1122")
    ]
    XCTAssertEqual(KeyboardViewController.matchingContacts(contacts, query: "alvaro").map(\.id), ["one"])
    XCTAssertEqual(KeyboardViewController.matchingContacts(contacts, query: "0074FB6A").map(\.id), ["one"])
    XCTAssertEqual(KeyboardViewController.matchingContacts(contacts, query: "BEA").map(\.id), ["two"])
    XCTAssertEqual(KeyboardViewController.matchingContacts(contacts, query: " ").map(\.id), ["one", "two"])
    let keyboard = makeKeyboard()
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection)
  }

  func testContactSearchCannotTakeFocusFromHostEditor() {
    let keyboard = makeKeyboard()
    guard let search = descendantViews(keyboard.view).first(where: {
      $0 is UISearchTextField
    }) as? UISearchTextField else { return XCTFail("contact search display missing") }
    XCTAssertFalse(search.canBecomeFirstResponder)
    XCTAssertFalse(search.isUserInteractionEnabled)
    XCTAssertNotNil(actionButton("recipient", in: keyboard.view))
  }

  func testContactSearchKeepsTypingRowsAtBottomAndListScrollAreaAbove() {
    let keyboard = makeKeyboard(width: 390, height: 740)
    keyboard.setContactSearchForDisplay()
    keyboard.view.layoutIfNeeded()
    guard let table = descendantViews(keyboard.view).first(where: {
      $0.accessibilityIdentifier == "layergram.contacts.list"
    }), let search = descendantViews(keyboard.view).first(where: {
      $0 is UISearchTextField
    }), let space = keyButton("space", in: keyboard.view) else {
      return XCTFail("search, contacts list and typing rows must all be present")
    }
    let tableFrame = keyboard.view.convert(table.bounds, from: table)
    let searchFrame = keyboard.view.convert(search.bounds, from: search)
    let spaceFrame = keyboard.view.convert(space.bounds, from: space)
    let topKeyY = keyButtons(in: keyboard).map {
      keyboard.view.convert($0.bounds, from: $0).minY
    }.min() ?? 0
    XCTAssertGreaterThan(tableFrame.height, 150)
    XCTAssertLessThan(searchFrame.maxY, tableFrame.minY)
    XCTAssertLessThan(tableFrame.maxY, spaceFrame.minY)
    XCTAssertGreaterThanOrEqual(topKeyY - tableFrame.maxY, 9,
                                "contact results need breathing room before the first key row")
    XCTAssertLessThanOrEqual(keyboard.view.bounds.maxY - spaceFrame.maxY, 5,
                             "only a narrow pad stays below the typing row")
  }

  func testContactActionsUseCompactHorizontalButtons() throws {
    let keyboard = makeKeyboard()
    for surface in [KeyboardViewController.Surface.contacts, .confirmation] {
      keyboard.setSurfaceForDisplay(surface)
      keyboard.view.layoutIfNeeded()
      let names = surface == .confirmation ? ["cancel", "confirm"] : ["back"]
      for name in names {
        let button = try XCTUnwrap(actionButton(name, in: keyboard.view))
        let config = try XCTUnwrap(button.configuration)
        XCTAssertEqual(config.imagePlacement, .leading)
        XCTAssertEqual(config.imagePadding, 7)
        XCTAssertEqual(config.contentInsets.top, 6)
        XCTAssertEqual(config.contentInsets.bottom, 6)
        XCTAssertEqual(button.bounds.height, 40)
      }
    }
    keyboard.setContactSearchForDisplay()
    keyboard.view.layoutIfNeeded()
    let done = try XCTUnwrap(actionButton("doneSearch", in: keyboard.view))
    XCTAssertEqual(done.configuration?.imagePlacement, .leading)
    XCTAssertEqual(done.configuration?.contentInsets.leading, 12)
  }

  func testKeyboardRequestsReducedOverallHeightWithNarrowBottomPad() {
    let keyboard = makeKeyboard(width: 390, height: 296)
    let requestedHeight = keyboard.view.constraints.first {
      $0.firstItem === keyboard.view && $0.firstAttribute == .height &&
        $0.secondItem == nil
    }
    XCTAssertEqual(requestedHeight?.constant, 296,
                   "removing bottom padding must shorten the whole input view")
    let space = keyButton("space", in: keyboard.view)
    XCTAssertNotNil(space)
    if let space {
      let frame = keyboard.view.convert(space.bounds, from: space)
      XCTAssertLessThanOrEqual(keyboard.view.bounds.maxY - frame.maxY, 5)
    }
  }

  func testContactHeadingUsesSmallIconAndNeutralRecipientBackground() throws {
    let heading = KeyboardViewController.contactHeading("Ana", font: .systemFont(ofSize: 14))
    XCTAssertTrue(heading.string.hasSuffix("  Ana"))
    let neutralIcon = try XCTUnwrap(heading.attribute(.attachment, at: 0,
                                                     effectiveRange: nil) as? NSTextAttachment)
    XCTAssertNotNil(neutralIcon.image, "a nil attachment appears as a document in iOS")
    let unknownAtConfirmation = KeyboardViewController.contactHeading(
      "Ana", font: .systemFont(ofSize: 14), showUnknownShield: false)
    XCTAssertEqual(unknownAtConfirmation.string, "Ana")
    XCTAssertNil(unknownAtConfirmation.attribute(.attachment, at: 0, effectiveRange: nil),
                 "an unknown FS state must not look like the gray no-FS shield")
    XCTAssertFalse(heading.string.contains("Para:"))
    XCTAssertFalse(heading.string.contains("Da:"))
    XCTAssertEqual(KeyboardViewController.securityPhaseLabel(.setupPending,
                   language: .italian), "FS in negoziazione")
    XCTAssertEqual(KeyboardViewController.securityPhaseLabel(.normalActive,
                   language: .italian), "FS attiva")
    XCTAssertEqual(KeyboardViewController.securityPhaseLabel(.maximumActive,
                   language: .italian), "FS Maximum attiva")
    XCTAssertEqual(KeyboardViewController.securityPhaseLabel(.maximumSetupPending,
                   language: .italian), "FS Maximum in negoziazione")
    let appearance = KeyboardViewController.securityShieldAppearance
    XCTAssertTrue(appearance(.setupPending).color.isEqual(UIColor.systemOrange))
    XCTAssertTrue(appearance(.normalActive).color.isEqual(UIColor.systemGreen))
    XCTAssertTrue(appearance(.recoveryRequired).color.isEqual(UIColor.systemRed))
    XCTAssertFalse(appearance(.normalActive).goldRim)
    XCTAssertTrue(appearance(.maximumSetupPending).goldRim)
    XCTAssertTrue(appearance(.maximumActive).goldRim)
    XCTAssertEqual(appearance(nil).symbol, "shield.fill")
    for phase in [KeyboardSecurityPhase.setupRequired, .setupPending, .normalActive,
                  .maximumSetupRequired, .maximumSetupPending, .maximumActive,
                  .recoveryRequired, .maximumRecoveryRequired] {
      let shield = KeyboardViewController.contactHeading(
        "Ana", font: .systemFont(ofSize: 14), securityPhase: phase)
      let attachment = try XCTUnwrap(shield.attribute(.attachment, at: 0,
                                                     effectiveRange: nil) as? NSTextAttachment)
      XCTAssertNotNil(attachment.image, "every V3 phase needs a real shield image")
      XCTAssertTrue(shield.string.hasSuffix("  Ana"))
    }

    let keyboard = makeKeyboard()
    let recipient = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.recipient.name"
    } as? UILabel)
    XCTAssertEqual(recipient.backgroundColor, UIColor.clear)
    keyboard.applyDecodedPreview(decodedSender)
    let preview = try XCTUnwrap(descendantViews(keyboard.view).compactMap { $0 as? UILabel }
      .first { $0.text?.hasSuffix("\nhola") == true })
    XCTAssertNotNil(preview.attributedText?.attribute(.attachment, at: 0, effectiveRange: nil))
    XCTAssertTrue(preview.text?.contains("Ana\nhola") == true)
    XCTAssertEqual(preview.accessibilityLabel,
                   "\(KeyboardViewController.Copy.string(.from, in: Locale.current)): Ana\nhola")
  }

  func testContactListNeverShowsAReusedDocumentIcon() {
    let contact = KeyboardContact(id: "a", name: "Ana", fingerprint: "AB-CD")
    let content = KeyboardViewController.contactCellContent(contact, language: .spanish)
    XCTAssertNil(content.image)
    XCTAssertEqual(content.text, "Ana")
    XCTAssertEqual(content.secondaryText, "Huella: AB-CD")
    let cleared = KeyboardViewController.contactCellContent(nil, language: .spanish)
    XCTAssertNil(cleared.image)
    XCTAssertNil(cleared.text)
    XCTAssertNil(cleared.secondaryText)
  }

  func testCountdownRemainsInsideKeyboardAfterContactConfirmation() throws {
    let keyboard = makeKeyboard(width: 375, height: 326)
    keyboard.setConfirmedHeaderForDisplay("Ana", seconds: "58s")
    keyboard.view.layoutIfNeeded()

    let timer = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.window"
    })
    let status = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.status"
    })
    let recipient = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.recipient.name"
    })
    let compose = try XCTUnwrap(descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.compose.row"
    })
    let frame = timer.convert(timer.bounds, to: keyboard.view)
    let statusFrame = status.convert(status.bounds, to: keyboard.view)
    let recipientFrame = recipient.convert(recipient.bounds, to: keyboard.view)
    let composeFrame = compose.convert(compose.bounds, to: keyboard.view)
    XCTAssertGreaterThanOrEqual(frame.minY, 0)
    XCTAssertLessThanOrEqual(frame.maxY, keyboard.view.bounds.height)
    XCTAssertGreaterThanOrEqual(frame.minX, 0)
    XCTAssertLessThanOrEqual(frame.maxX, keyboard.view.bounds.width)
    XCTAssertEqual(recipientFrame.minX, statusFrame.minX, accuracy: 1,
                   "the recipient shield must align with the status dot")
    XCTAssertGreaterThanOrEqual(recipientFrame.height, (recipient as? UILabel)?.font.lineHeight ?? 0,
                                "the selected recipient must not be vertically clipped")
    XCTAssertGreaterThanOrEqual(recipientFrame.minY, 0)
    XCTAssertLessThanOrEqual(recipientFrame.maxY, keyboard.view.bounds.height)
    XCTAssertGreaterThanOrEqual(recipientFrame.minY - frame.maxY, 4)
    XCTAssertGreaterThanOrEqual(composeFrame.minY - recipientFrame.maxY, 8)
  }

  func testSelectingRecipientRequestsEnoughInputViewHeightImmediately() throws {
    let keyboard = makeKeyboard(width: 375, height: 296)
    let height = try XCTUnwrap(keyboard.view.constraints.first {
      $0.firstItem === keyboard.view && $0.firstAttribute == .height &&
        $0.secondItem == nil && $0.priority.rawValue == 999
    })
    XCTAssertEqual(height.constant, 296)
    keyboard.setConfirmedHeaderForDisplay("Ana", seconds: "58s")
    XCTAssertGreaterThanOrEqual(height.constant, 326,
      "confirming a contact must expand the real input view, not only the label")
  }

  func testKeyboardBackgroundBlendsWithSystemContainerInLightAppearance() {
    let keyboard = makeKeyboard()
    let light = UITraitCollection(userInterfaceStyle: .light)
    let color = keyboard.view.backgroundColor?.resolvedColor(with: light)
    var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0, alpha: CGFloat = 0
    XCTAssertTrue(color?.getRed(&red, green: &green, blue: &blue, alpha: &alpha) == true)
    XCTAssertEqual(red, 223/255, accuracy: 0.001)
    XCTAssertEqual(green, 225/255, accuracy: 0.001)
    XCTAssertEqual(blue, 228/255, accuracy: 0.001)
    XCTAssertEqual(alpha, 1, accuracy: 0.001)
  }

  func testKeyboardBackgroundBlendsWithSystemContainerInDarkAppearance() {
    let keyboard = makeKeyboard()
    let dark = UITraitCollection(userInterfaceStyle: .dark)
    let color = keyboard.view.backgroundColor?.resolvedColor(with: dark)
    var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0, alpha: CGFloat = 0
    XCTAssertTrue(color?.getRed(&red, green: &green, blue: &blue, alpha: &alpha) == true)
    XCTAssertEqual(red, 33/255, accuracy: 0.001)
    XCTAssertEqual(green, 33/255, accuracy: 0.001)
    XCTAssertEqual(blue, 33/255, accuracy: 0.001)
    XCTAssertEqual(alpha, 1, accuracy: 0.001)
  }

  func testDraftLooksEditableButCannotBecomeAHostTextResponder() {
    let keyboard = makeKeyboard()
    XCTAssertTrue(descendantViews(keyboard.view).contains {
      ($0 as? UILabel)?.text == KeyboardViewController.Copy.string(.secretMessage, in: Locale.current)
    })
    keyboard.setLocalDraft("prova da iPhone")
    keyboard.view.layoutIfNeeded()
    guard let draft = descendantViews(keyboard.view).first(where: {
      $0.accessibilityIdentifier == "layergram.draft"
    }) as? UITextView else {
      return XCTFail("local draft view missing")
    }
    XCTAssertEqual(draft.text, "prova da iPhone")
    XCTAssertFalse(draft.canBecomeFirstResponder)
    XCTAssertFalse(draft.isEditable)
    XCTAssertFalse(draft.isAccessibilityElement)
    XCTAssertNotNil(draft.closestPosition(to: CGPoint(x: 30, y: 20)),
                    "a tap can resolve a cursor position without activating text input")
    let send = actionButton("primary", in: keyboard.view)!
    XCTAssertEqual(keyboard.view.convert(send.bounds, from: send).midY,
                   keyboard.view.convert(draft.bounds, from: draft).midY, accuracy: 1)
    let letterKey = keyButtons(in: keyboard).first!
    XCTAssertGreaterThan(keyboard.view.convert(letterKey.bounds, from: letterKey).minY,
                         keyboard.view.convert(draft.bounds, from: draft).minY)
  }

  func testLocalDraftScrollsToKeepTrailingNewlineVisible() {
    let keyboard = makeKeyboard()
    keyboard.setLocalDraft(String(repeating: "riga\n", count: 12))
    keyboard.view.layoutIfNeeded()
    guard let draft = descendantViews(keyboard.view).first(where: {
      $0.accessibilityIdentifier == "layergram.draft"
    }) as? UITextView else { return XCTFail("local draft view missing") }
    guard let end = draft.endOfDocument as UITextPosition? else {
      return XCTFail("local draft end missing")
    }
    let caret = draft.caretRect(for: end)
    XCTAssertGreaterThan(draft.contentSize.height, draft.bounds.height)
    XCTAssertGreaterThan(draft.contentOffset.y, 0, "newlines must move the local viewport")
    if #available(iOS 26.0, *) {
      XCTAssertTrue(draft.topEdgeEffect.isHidden,
                    "the scroll edge must not blur the first visible line")
      XCTAssertTrue(draft.bottomEdgeEffect.isHidden,
                    "the scroll edge must not blur the last visible line")
    }
    XCTAssertGreaterThanOrEqual(caret.minY, draft.contentOffset.y - 1)
    XCTAssertLessThanOrEqual(caret.maxY, draft.contentOffset.y + draft.bounds.height + 1,
                             "the trailing newline cursor must remain visible")

    keyboard.setLocalDraftCursorForDisplay(0)
    let first = draft.caretRect(for: draft.beginningOfDocument)
    XCTAssertGreaterThanOrEqual(first.minY, draft.contentOffset.y - 1)
    XCTAssertLessThanOrEqual(first.maxY, draft.contentOffset.y + draft.bounds.height + 1,
                             "moving to the first line must reveal it again")
    keyboard.setLocalDraftCursorForDisplay(draft.text.count)
    XCTAssertGreaterThan(draft.contentOffset.y, 0,
                         "moving back down must reveal the last line")
  }

  func testEmojiPickerHasScrollableCategoriesAndKeepsTheHostEditorOutOfTheFlow() {
    XCTAssertEqual(KeyboardViewController.emojiCatalog.count, 5)
    XCTAssertTrue(KeyboardViewController.emojiCatalog.allSatisfy { $0.count >= 30 })
    XCTAssertTrue(KeyboardViewController.emojiCatalog.flatMap { $0 }.contains("❤️"))
    let keyboard = makeKeyboard()
    let picker = descendantViews(keyboard.view).first {
      $0.accessibilityIdentifier == "layergram.emoji.grid"
    } as? UICollectionView
    XCTAssertNotNil(picker)
    XCTAssertTrue(picker?.alwaysBounceVertical == true)
    XCTAssertNotNil(actionButton("emoji", in: keyboard.view))
    XCTAssertTrue(isDescendant(picker!, of: keyboard.keysContainerView),
                  "emoji grid stays inside the same input view as the keys")
    keyboard.setEmojiPickerForDisplay(true)
    keyboard.view.layoutIfNeeded()
    XCTAssertGreaterThan(keyboard.collectionView(picker!, numberOfItemsInSection: 0), 30,
                         "the local catalog renders without reading the host editor")
    XCTAssertFalse(keyboard.keysContainerView.isHidden,
                   "switching to emoji cannot detach the keyboard surface")
    XCTAssertTrue(effectivelyVisible(picker!, in: keyboard.view))
    XCTAssertTrue(effectivelyVisible(actionButton("emoji", in: keyboard.view)!, in: keyboard.view),
                  "the icon remains available to return to letters")
    XCTAssertTrue(effectivelyVisible(keyButton("space", in: keyboard.view)!, in: keyboard.view))
    XCTAssertNil(keyboard.view.subviews.flatMap { descendantViews($0) }
      .compactMap { $0 as? UITextField }.first(where: { $0.isFirstResponder }))
    keyboard.setEmojiPickerForDisplay(false)
    XCTAssertFalse(keyboard.keysContainerView.isHidden)
    XCTAssertTrue(keyButtons(in: keyboard).first?.actions(
      forTarget: keyboard, forControlEvent: .touchDown)?.contains("hapticKey") == true)
    XCTAssertTrue(actionButton("emoji", in: keyboard.view)?.actions(
      forTarget: keyboard, forControlEvent: .touchDown)?.contains("hapticButton") == true)
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection)
  }

  func testEmptyDraftPrimaryTapKeepsAdmissionStatusAndRevokesNothing() {
    let keyboard = makeKeyboard()
    keyboard.viewDidAppear(false)
    defer { keyboard.viewWillDisappear(false) }
    let admissionStatus = keyboard.status
    XCTAssertFalse(admissionStatus.isEmpty, "the keyboard states why it cannot work yet")

    keyboard.tapPrimary()

    XCTAssertEqual(
      keyboard.status, admissionStatus,
      "an empty draft never hides the need-Full-Access / open-the-app message"
    )
    XCTAssertEqual(keyboard.draft, "")
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertNil(keyboard.displayedSender)
    XCTAssertNil(actionButton("primary", in: keyboard.view))
    XCTAssertEqual(pasteAction(in: keyboard.view)?.isHidden, false)
  }

  func testPrimaryIntentCoversAdmissionEmptyDraftAndMissingRecipient() {
    let keyboard = makeKeyboard()

    XCTAssertEqual(
      keyboard.primaryIntent(admitted: false, draft: "hola", recipient: true, candidate: true),
      .blockedByAdmission,
      "no admission means the admission message is kept"
    )
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "", recipient: false, candidate: false),
      .promptEmptyDraft
    )
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "   \n", recipient: true, candidate: true),
      .promptEmptyDraft,
      "a whitespace-only draft is empty"
    )
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "hola", recipient: false, candidate: false),
      .openRecipientSelection
    )
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "hola", recipient: false, candidate: true),
      .openRecipientSelection,
      "a local candidate without the owner-confirmed selection is not a recipient"
    )
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "hola", recipient: true, candidate: false),
      .openRecipientSelection
    )
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "hola", recipient: true, candidate: true),
      .send,
      "only a usable recipient plus a valid draft is the explicit send tap"
    )
  }

  func testPrimaryTapWithDraftAndNoRecipientNeverQueuesAnAutomaticSend() {
    let keyboard = makeKeyboard()
    keyboard.viewDidAppear(false)
    defer { keyboard.viewWillDisappear(false) }
    keyboard.setLocalDraft("hola")
    let statusBefore = keyboard.status

    // The pure decision opens recipient selection when admission is available...
    XCTAssertEqual(
      keyboard.primaryIntent(admitted: true, draft: "hola", recipient: false, candidate: false),
      .openRecipientSelection
    )
    // ...and the real tap never clears the draft on the way there.
    keyboard.tapPrimary()

    XCTAssertEqual(keyboard.draft, "hola", "the draft is never cleared to reach a recipient")
    XCTAssertNil(keyboard.pendingSelection, "no recipient is invented")
    XCTAssertNotEqual(
      keyboard.status,
      KeyboardViewController.Copy.string(.waiting, in: Locale.current)
    )
    XCTAssertEqual(keyboard.status, statusBefore)
    XCTAssertEqual(actionButton("primary", in: keyboard.view)?.isHidden, false)
  }

  func testConfirmationRequiresAnExplicitRecipientAndExplicitConfirm() {
    let keyboard = makeKeyboard()

    // Confirming with no candidate must not queue a selection request and must
    // not resolve into a send.
    keyboard.confirmSelection()
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertNotEqual(
      keyboard.status,
      KeyboardViewController.Copy.string(.waiting, in: Locale.current)
    )
    XCTAssertEqual(keyboard.surface, .keys)

    // Selecting a contact without a live session is refused: nothing is
    // auto-confirmed and the editor is not silently kept alive.
    let contact = KeyboardContact(id: "c1", name: "Ana", fingerprint: "AB CD")
    keyboard.selectContact(contact)
    XCTAssertNil(keyboard.pendingSelection, "no contact is selected without a live session")
  }

  // MARK: - Decoded sender shortcut

  private let decodedSender = KeyboardViewController.DecodedPreviewDisplay(
    contactId: "c1",
    contactName: "Ana",
    fingerprint: "AB CD",
    text: "hola"
  )

  func testDecodedSenderIsDisplayOnlyAndNeverPreselectsARecipient() {
    let keyboard = makeKeyboard()
    keyboard.applyDecodedPreview(decodedSender)

    // Decode alone: the sender is shown, but nothing is selected.
    XCTAssertEqual(keyboard.displayedSender?.id, "c1")
    XCTAssertEqual(keyboard.displayedSender?.name, "Ana")
    XCTAssertNil(keyboard.pendingSelection, "decode alone never selects a recipient")
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection, "decode alone never confirms a selection")
    XCTAssertEqual(keyboard.surface, .preview)

    // The affordance names the sender and says what it does.
    let button = actionButton("sender", in: keyboard.view)
    XCTAssertNotNil(button, "the decoded sender is tappable")
    XCTAssertEqual(button?.isHidden, false)
    XCTAssertEqual(
      button?.title(for: .normal),
      "\(KeyboardViewController.Copy.string(.replyTo, in: Locale.current)) Ana"
    )
    XCTAssertEqual(
      button?.accessibilityHint,
      KeyboardViewController.Copy.string(.senderTapHint, in: Locale.current)
    )

    // No `To:` recipient is displayed before the owner accepts: the confirmed
    // selection is still empty and no candidate is held.
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection)
    XCTAssertNil(keyboard.pendingSelection)

    // Sending with a draft but no selection opens the contact list: the visible
    // sender is never consulted as an implicit recipient.
    XCTAssertEqual(
      keyboard.primaryIntent(
        admitted: true,
        draft: "ciao",
        recipient: keyboard.hasConfirmedOwnerSelection,
        candidate: keyboard.pendingSelection != nil
      ),
      .openRecipientSelection,
      "typing a reply never implicitly chooses the displayed sender"
    )
  }

  func testSenderTapRoutesExactSelectConfirmWithoutPrepareAuthorizeOrInsertion() {
    let keyboard = makeKeyboard()
    keyboard.applyDecodedPreview(decodedSender)
    let sender = KeyboardContact(id: "c1", name: "Ana", fingerprint: "AB CD")

    // The shortcut is exactly the explicit select/confirm request.
    let payload = keyboard.senderSelectPayload(for: sender)
    XCTAssertEqual(payload, ["contactId": .string("c1"), "confirm": .bool(true)])
    XCTAssertEqual(Set(payload.keys), ["contactId", "confirm"])
    XCTAssertFalse(payload.keys.contains("text"), "the sender shortcut never prepares a message")
    XCTAssertFalse(payload.keys.contains("pendingId"), "the sender shortcut never authorizes or acks")

    // Without a live session the explicit tap is refused and claims nothing.
    keyboard.tapSender()
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection)
    XCTAssertNotEqual(
      keyboard.status,
      KeyboardViewController.Copy.string(.waiting, in: Locale.current)
    )
  }

  func testSenderShortcutIsClearedByNewDecodeFailureInvalidationAndNewMessage() {
    let keyboard = makeKeyboard()
    keyboard.viewDidAppear(false)
    defer { keyboard.viewWillDisappear(false) }

    keyboard.applyDecodedPreview(decodedSender)
    XCTAssertNotNil(keyboard.displayedSender)

    // A rejected/malformed/expired decode must not retain the old shortcut.
    keyboard.applyDecodedPreview(nil)
    XCTAssertNil(keyboard.displayedSender)
    XCTAssertNil(actionButton("sender", in: keyboard.view)?.title(for: .normal))
    XCTAssertEqual(actionButton("sender", in: keyboard.view)?.isHidden, true)

    // A fresh decode replaces, never appends.
    keyboard.applyDecodedPreview(decodedSender)
    keyboard.applyDecodedPreview(
      KeyboardViewController.DecodedPreviewDisplay(
        contactId: "c2", contactName: "Bea", fingerprint: "EF 01", text: "ciao"
      )
    )
    XCTAssertEqual(keyboard.displayedSender?.id, "c2")

    // A host editor change invalidates everything, including the shortcut.
    keyboard.textDidChange(nil)
    XCTAssertNil(keyboard.displayedSender)
    XCTAssertFalse(keyboard.hasConfirmedOwnerSelection)
    XCTAssertNil(keyboard.pendingSelection)
    XCTAssertEqual(actionButton("sender", in: keyboard.view)?.isHidden, true)

    // Render paths (including the primary tap) never restore it.
    keyboard.tapPrimary()
    XCTAssertNil(keyboard.displayedSender)
    XCTAssertNil(actionButton("sender", in: keyboard.view)?.title(for: .normal))
  }

  // MARK: - Persistent globe

  func testGlobeStaysEffectivelyVisibleOnEverySurface() {
    let keyboard = makeKeyboard()
    keyboard.viewDidAppear(false)
    defer { keyboard.viewWillDisappear(false) }

    // The fallback globe must not live inside the container that render hides
    // off the key surface.
    guard let fallback = actionButton("globe", in: keyboard.view) else {
      return XCTFail("the persistent fallback globe must exist")
    }
    XCTAssertFalse(
      isDescendant(fallback, of: keyboard.keysContainerView),
      "the fallback globe must sit outside the hidden key container"
    )
    XCTAssertEqual(keyButton("globe", in: keyboard.view) != nil,
                   keyboard.showsEmbeddedInputSwitcher)

    for surface in [KeyboardViewController.Surface.keys, .contacts, .confirmation, .preview] {
      keyboard.setSurfaceForDisplay(surface)
      keyboard.view.layoutIfNeeded()
      let globes = allButtons(in: keyboard.view).filter {
        $0.accessibilityIdentifier == "layergram.key.globe"
          || $0.accessibilityIdentifier == "layergram.action.globe"
      }
      XCTAssertEqual(globes.count, keyboard.showsEmbeddedInputSwitcher ? 2 : 1)
      let visible = globes.filter { effectivelyVisible($0, in: keyboard.view) }
      XCTAssertEqual(
        visible.count, keyboard.showsEmbeddedInputSwitcher ? 1 : 0,
        "the extension draws a globe only when UIKit requires one"
      )
    }

    // Off the key surface the key container really is hidden, so only the
    // fallback can be the visible globe.
    keyboard.setSurfaceForDisplay(.contacts)
    keyboard.view.layoutIfNeeded()
    XCTAssertTrue(keyboard.keysContainerView.isHidden)
    XCTAssertEqual(effectivelyVisible(fallback, in: keyboard.view),
                   keyboard.showsEmbeddedInputSwitcher)
    if let inRow = keyButton("globe", in: keyboard.view) {
      XCTAssertFalse(effectivelyVisible(inRow, in: keyboard.view))
    }
  }

  // MARK: - Copy

  func testActionIdentifiersStayStableAcrossLayers() {
    let keyboard = makeKeyboard()
    XCTAssertEqual(keyboard.resolveKeyAction("layergram.key.globe"), .globe)
    XCTAssertEqual(keyboard.resolveKeyAction("layergram.key.backspace"), .backspace)
    XCTAssertEqual(keyboard.resolveKeyAction("not-a-key"), nil)
    XCTAssertEqual(keyboard.resolveKeyAction(nil), nil)
    XCTAssertEqual(
      KeyboardViewController.KeyAction.allCases.map(\.identifier),
      [
        "layergram.key.shift", "layergram.key.backspace", "layergram.key.space",
        "layergram.key.newline", "layergram.key.globe", "layergram.key.layer",
        "layergram.key.symbols", "layergram.key.emoji"
      ]
    )
  }

  func testAccentAlternativesAndSpaceTrackpadUseCharacterBoundaries() {
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "a"),
                   ["à", "á", "â", "ä", "ã", "å", "æ"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "E").map { Array($0.prefix(2)) }, ["È", "É"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "n"), ["ñ", "ń", "ň"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "N"), ["Ñ", "Ń", "Ň"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "c"), ["ç", "ć", "č"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "g"), ["ğ"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "s"), ["ß", "ś", "š", "ş", "ș"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "S"), ["ẞ", "Ś", "Š", "Ş", "Ș"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "d"), ["ď", "đ", "ð"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "l"), ["ł", "ľ", "ĺ"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "r"), ["ř", "ŕ"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "t"), ["ť", "ț", "þ"])
    XCTAssertEqual(KeyboardViewController.accentOptions(for: "z"), ["ź", "ż", "ž"])
    XCTAssertNil(KeyboardViewController.accentOptions(for: "b"))
    XCTAssertEqual(KeyboardViewController.cursorAfterSpaceDrag(start: 2, deltaX: -100, count: 5), 0)
    XCTAssertEqual(KeyboardViewController.cursorAfterSpaceDrag(start: 2, deltaX: 25, count: 5), 4)
    XCTAssertEqual(KeyboardViewController.cursorAfterSpaceDrag(start: 2, deltaX: 100, count: 5), 5)
    XCTAssertEqual(KeyboardViewController.characterCursor(in: "A👩🏽‍💻B", utf16Offset: 1), 1)
    XCTAssertEqual(KeyboardViewController.characterCursor(in: "A👩🏽‍💻B", utf16Offset: 3), 1,
                   "trackpad may only stop at a grapheme boundary")

    let keyboard = makeKeyboard()
    let vowels = allButtons(in: keyboard.view).filter { ["a", "e", "i", "o", "u"].contains($0.title(for: .normal) ?? "") }
    XCTAssertEqual(vowels.count, 5)
    XCTAssertTrue(vowels.allSatisfy {
      $0.gestureRecognizers?.contains(where: { $0 is UILongPressGestureRecognizer }) == true
    })
  }

  func testFunctionButtonsShareOnePaletteInLightAndDarkMode() {
    let keyboard = makeKeyboard()
    for style in [UIUserInterfaceStyle.light, .dark] {
      keyboard.overrideUserInterfaceStyle = style
      let traits = UITraitCollection(userInterfaceStyle: style)
      let recipient = actionButton("recipient", in: keyboard.view)
      let paste = pasteAction(in: keyboard.view)
      XCTAssertNotNil(recipient)
      XCTAssertNotNil(paste)
      let pasteBackground: UIColor?
      let pasteForeground: UIColor?
      if #available(iOS 16.0, *), let control = paste as? UIPasteControl {
        pasteBackground = control.configuration.baseBackgroundColor
        pasteForeground = control.configuration.baseForegroundColor
      } else {
        pasteBackground = (paste as? UIButton)?.configuration?.baseBackgroundColor
        pasteForeground = (paste as? UIButton)?.configuration?.baseForegroundColor
      }
      let backgrounds = [recipient?.configuration?.baseBackgroundColor, pasteBackground]
        .compactMap { $0?.resolvedColor(with: traits) }
      let foregrounds = [recipient?.configuration?.baseForegroundColor, pasteForeground]
        .compactMap { $0?.resolvedColor(with: traits) }
      XCTAssertEqual(backgrounds.count, 2)
      XCTAssertEqual(foregrounds.count, 2)
      XCTAssertEqual(Set(backgrounds).count, 1)
      XCTAssertEqual(Set(foregrounds).count, 1)
      let expectedBackground = style == .dark
        ? UIColor(red: 154/255, green: 203/255, blue: 250/255, alpha: 1)
        : UIColor(red: 11/255, green: 82/255, blue: 69/255, alpha: 1)
      let expectedForeground = style == .dark
        ? UIColor(red: 0, green: 51/255, blue: 82/255, alpha: 1)
        : UIColor.white
      XCTAssertEqual(backgrounds[0], expectedBackground)
      XCTAssertEqual(foregrounds[0], expectedForeground)
      keyboard.setLocalDraft("ciao")
      XCTAssertEqual(actionButton("primary", in: keyboard.view)?.configuration?.baseBackgroundColor?.resolvedColor(with: traits),
                     backgrounds[0])
      XCTAssertEqual(actionButton("primary", in: keyboard.view)?.configuration?.baseForegroundColor?.resolvedColor(with: traits),
                     expectedForeground)
      actionButton("clearDraft", in: keyboard.view)?.sendActions(for: .touchUpInside)
    }
    guard let shift = keyButton("shift", in: keyboard.view),
          let backspace = keyButton("backspace", in: keyboard.view) else {
      return XCTFail("shift and backspace must exist")
    }
    XCTAssertEqual(backspace.tintColor?.resolvedColor(with: keyboard.traitCollection),
                   shift.titleColor(for: .normal)?.resolvedColor(with: keyboard.traitCollection),
                   "the backspace symbol must match Shift instead of the system blue")
  }

  func testLocalCopyCoversEnglishItalianAndSpanishWithoutAssumingLocale() {
    for key in KeyboardViewController.StringKey.allCases {
      for language in [english, italian, spanish] {
        XCTAssertFalse(
          KeyboardViewController.Copy.string(key, in: language).isEmpty,
          "\(key) is localized"
        )
      }
    }

    // Space and return must not fall back to English on a Spanish device.
    XCTAssertEqual(KeyboardViewController.Copy.string(.space, in: english), "space")
    XCTAssertEqual(KeyboardViewController.Copy.string(.space, in: italian), "spazio")
    XCTAssertEqual(KeyboardViewController.Copy.string(.space, in: spanish), "espacio")
    XCTAssertEqual(KeyboardViewController.Copy.string(.returnKey, in: spanish), "salto de línea")
    XCTAssertEqual(KeyboardViewController.Copy.string(.returnKey, in: italian), "a capo")
    XCTAssertEqual(KeyboardViewController.Copy.string(.secretMessage, in: english), "Secret message")
    XCTAssertEqual(KeyboardViewController.Copy.string(.secretMessage, in: italian), "Messaggio segreto")
    XCTAssertEqual(KeyboardViewController.Copy.string(.secretMessage, in: spanish), "Texto secreto")

    XCTAssertEqual(
      KeyboardViewController.Copy.string(.encryptInsert, in: english), "Encrypt & insert"
    )
    XCTAssertEqual(
      KeyboardViewController.Copy.string(.encryptInsert, in: italian), "Cifra e inserisci"
    )
    XCTAssertEqual(
      KeyboardViewController.Copy.string(.encryptInsert, in: spanish), "Cifrar e insertar"
    )
    XCTAssertEqual(
      KeyboardViewController.Copy.string(.pasteDecrypt, in: english), "Paste & decrypt"
    )
    XCTAssertEqual(
      KeyboardViewController.Copy.string(.pasteDecrypt, in: spanish), "Pegar y descifrar"
    )
    XCTAssertEqual(KeyboardViewController.Copy.string(.from, in: spanish), "De")
    XCTAssertEqual(KeyboardViewController.Copy.string(.to, in: italian), "A")
    XCTAssertEqual(KeyboardViewController.Copy.string(.replyTo, in: spanish), "Responder a")
    XCTAssertEqual(
      KeyboardViewController.Copy.string(.globeSwitch, in: spanish), "Cambiar teclado"
    )

    // The hand-off copy says the encrypted text was passed to the app and asks
    // the user to press send; it never claims insertion, acceptance or delivery.
    let exported: [(KeyboardViewController.Language, String)] = [
      (english, KeyboardViewController.Copy.string(.exported, in: english)),
      (italian, KeyboardViewController.Copy.string(.exported, in: italian)),
      (spanish, KeyboardViewController.Copy.string(.exported, in: spanish))
    ]
    XCTAssertTrue(exported[0].1.lowercased().contains("passed"))
    XCTAssertTrue(exported[1].1.lowercased().contains("passato"))
    XCTAssertTrue(exported[2].1.lowercased().contains("pasado"))
    // The copy only says the encrypted text was passed to the host and
    // instructs the user to use the host's Send control.
    XCTAssertTrue(exported[0].1.lowercased().contains("tap send"))
    XCTAssertTrue(exported[1].1.lowercased().contains("tocca invia"))
    XCTAssertTrue(exported[2].1.lowercased().contains("pulsa enviar"))
    for (language, text) in exported {
      let lowered = text.lowercased()
      XCTAssertFalse(lowered.contains("insert"), "\(language) export copy claims insertion")
      XCTAssertFalse(lowered.contains("accepted"), "\(language) export copy claims acceptance")
      XCTAssertFalse(lowered.contains("delivered"), "\(language) export copy claims delivery")
      XCTAssertFalse(lowered.contains("consegnato"), "\(language) export copy claims delivery")
      XCTAssertFalse(lowered.contains("entregado"), "\(language) export copy claims delivery")
    }
  }

  // MARK: - Neutral layout attachments

  func testNeutralLayoutScreenshotAttachmentsAtBothSizes() {
    for size in [CGSize(width: 390, height: 306), CGSize(width: 320, height: 306)] {
      let keyboard = makeKeyboard(width: size.width, height: size.height)
      keyboard.view.layoutIfNeeded()
      let renderer = UIGraphicsImageRenderer(bounds: keyboard.view.bounds)
      let image = renderer.image { context in
        keyboard.view.layer.render(in: context.cgContext)
      }
      let attachment = XCTAttachment(image: image)
      attachment.name = "layergram-keyboard-\(Int(size.width))x\(Int(size.height))"
      attachment.lifetime = .keepAlways
      add(attachment)
      keyboard.overrideUserInterfaceStyle = .dark
      keyboard.view.layoutIfNeeded()
      let darkImage = renderer.image { context in
        keyboard.view.layer.render(in: context.cgContext)
      }
      let darkAttachment = XCTAttachment(image: darkImage)
      darkAttachment.name = "layergram-keyboard-dark-\(Int(size.width))x\(Int(size.height))"
      darkAttachment.lifetime = .keepAlways
      add(darkAttachment)
      keyboard.overrideUserInterfaceStyle = .light
      keyboard.setLocalDraft("Messaggio segreto di prova")
      keyboard.view.layoutIfNeeded()
      let filledImage = renderer.image { context in
        keyboard.view.layer.render(in: context.cgContext)
      }
      let filledAttachment = XCTAttachment(image: filledImage)
      filledAttachment.name = "layergram-keyboard-filled-\(Int(size.width))x\(Int(size.height))"
      filledAttachment.lifetime = .keepAlways
      add(filledAttachment)
      keyboard.setEmojiPickerForDisplay(true)
      keyboard.view.layoutIfNeeded()
      let emojiImage = renderer.image { context in
        keyboard.view.layer.render(in: context.cgContext)
      }
      let emojiAttachment = XCTAttachment(image: emojiImage)
      emojiAttachment.name = "layergram-emoji-\(Int(size.width))x\(Int(size.height))"
      emojiAttachment.lifetime = .keepAlways
      add(emojiAttachment)
      keyboard.setEmojiPickerForDisplay(false)
      keyboard.applyDecodedPreview(decodedSender)
      keyboard.view.layoutIfNeeded()
      let previewImage = renderer.image { context in
        keyboard.view.layer.render(in: context.cgContext)
      }
      let previewAttachment = XCTAttachment(image: previewImage)
      previewAttachment.name = "layergram-preview-\(Int(size.width))x\(Int(size.height))"
      previewAttachment.lifetime = .keepAlways
      add(previewAttachment)
    }
  }
}
