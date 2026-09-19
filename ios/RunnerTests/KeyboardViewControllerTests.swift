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

  // MARK: - Harness

  private func makeKeyboard(width: CGFloat = 390, height: CGFloat = 320) -> KeyboardViewController {
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

  // MARK: - Conventional iPhone QWERTY geometry

  func testLetterLayoutKeepsConventionalIPhoneRows() {
    let rows = layout(.letters)

    XCTAssertEqual(rows.count, 4)
    XCTAssertEqual(rows[0].count, 10, "row 1 is the full ten-letter run")
    XCTAssertEqual(rows[1].count, 9, "row 2 is the inset nine-letter run")
    XCTAssertEqual(rows[2].count, 9, "row 3 is shift + seven letters + backspace")
    XCTAssertEqual(textKeys(rows[2]).count, 7)
    XCTAssertEqual(rows[3].count, 4, "bottom row is 123, globe, wide space, return")

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

    // The bottom row is positional: layer, globe, wide space, return.
    XCTAssertEqual(actions(rows[3]), [.layer, .globe, .space, .newline])
    XCTAssertEqual(rows[3].first?.label, "123")

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

    // Geometry per layer: 10 / (9 or 10) / toggle + 7 + backspace / 4.
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
      XCTAssertEqual(actions(rows[3]), [.layer, .globe, .space, .newline])
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
    XCTAssertEqual(actions(scrambled[3]), [.layer, .globe, .space, .newline])

    // The identity case is the conventional iPhone order.
    let plain = layout(.letters)
    XCTAssertEqual(textKeys(plain[0]), ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"])

    // A malformed order is ignored, never a silent key re-map.
    XCTAssertEqual(KeyboardViewController.permuted(["a", "b", "c"], order: [0, 0, 1]), ["a", "b", "c"])
    XCTAssertEqual(KeyboardViewController.permuted(["a", "b", "c"], order: nil), ["a", "b", "c"])
  }

  // MARK: - On-screen frames

  func testRenderedKeyFramesStayTappableContainedAndNonOverlapping() {
    for size in [CGSize(width: 390, height: 320), CGSize(width: 320, height: 320)] {
      let keyboard = makeKeyboard(width: size.width, height: size.height)
      keyboard.view.layoutIfNeeded()

      let buttons = keyButtons(in: keyboard)
      XCTAssertEqual(buttons.count, 32, "10 + 9 + 7 + shift + backspace + 4 at \(size)")
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

      // The globe is always available in the bottom row, before the wide space.
      guard let globe = keyButton("globe", in: keyboard.view),
            let space = keyButton("space", in: keyboard.view) else {
        return XCTFail("globe and space must both exist at \(size)")
      }
      XCTAssertTrue(globe.superview === space.superview)
      XCTAssertLessThan(globe.frame.minX, space.frame.minX)
      XCTAssertGreaterThan(space.frame.width, globe.frame.width)
      XCTAssertGreaterThan(space.frame.width, keyButton("newline", in: keyboard.view)!.frame.width)
      XCTAssertNil(backspace.title(for: .normal))
      XCTAssertNotNil(backspace.image(for: .normal))
      XCTAssertEqual(globe.isHidden, false)
    }
  }

  func testLongStatusAndDraftDoNotSqueezeKeysOffTheInputView() {
    // A real unattached proxy produces a genuine, long admission status; the
    // draft is display-only state, and neither is a forged grant.
    for size in [CGSize(width: 390, height: 320), CGSize(width: 320, height: 320)] {
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
      for suffix in ["back", "globe", "sender"] {
        guard let button = actionButton(suffix, in: keyboard.view) else {
          return XCTFail("action \(suffix) is missing at \(size)")
        }
        XCTAssertTrue(effectivelyVisible(button, in: keyboard.view), "\(suffix) visible at \(size)")
        XCTAssertGreaterThanOrEqual(button.bounds.height, 44, "\(suffix) must remain tappable")
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
      let keyboard = makeKeyboard(width: width)
      keyboard.viewDidAppear(false)
      defer { keyboard.viewWillDisappear(false) }
      keyboard.setLocalDraft("PROVA")
      keyboard.view.layoutIfNeeded()
      let status = descendantViews(keyboard.view).first {
        $0.accessibilityIdentifier == "layergram.status"
      }
      XCTAssertGreaterThan(status?.bounds.height ?? 0, 12)
      for suffix in ["primary", "paste", "recipient", "new"] {
        let button = actionButton(suffix, in: keyboard.view)!
        XCTAssertGreaterThanOrEqual(button.bounds.height, 44)
        XCTAssertTrue(keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(
          keyboard.view.convert(button.bounds, from: button)))
      }
      for button in keyButtons(in: keyboard) {
        XCTAssertTrue(keyboard.view.bounds.insetBy(dx: -0.5, dy: -0.5).contains(
          keyboard.view.convert(button.bounds, from: button)))
      }
    }
  }

  func testPrimaryEncryptAndPasteActionsRemainVisibleWithoutSelection() {
    let keyboard = makeKeyboard()
    XCTAssertNil(keyboard.pendingSelection)

    let primary = actionButton("primary", in: keyboard.view)
    let paste = actionButton("paste", in: keyboard.view)
    let recipient = actionButton("recipient", in: keyboard.view)
    XCTAssertNotNil(primary, "the primary encrypt action exists before any selection")
    XCTAssertNotNil(paste, "the paste & decrypt action exists before any selection")
    XCTAssertNotNil(recipient, "recipient selection is directly discoverable")
    XCTAssertEqual(primary?.isHidden, false)
    XCTAssertEqual(paste?.isHidden, false)
    XCTAssertEqual(recipient?.isHidden, false)
    XCTAssertEqual(primary?.isEnabled, true)
    XCTAssertEqual(paste?.isEnabled, true)

    // Titles are localized through the live locale: no English assumption here.
    XCTAssertEqual(
      primary?.title(for: .normal),
      KeyboardViewController.Copy.string(.encryptInsert, in: Locale.current)
    )
    XCTAssertEqual(
      paste?.title(for: .normal),
      KeyboardViewController.Copy.string(.pasteDecrypt, in: Locale.current)
    )
    XCTAssertEqual(
      recipient?.title(for: .normal),
      KeyboardViewController.Copy.string(.contacts, in: Locale.current)
    )
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
    XCTAssertEqual(actionButton("primary", in: keyboard.view)?.isHidden, false)
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
    XCTAssertNotNil(keyButton("globe", in: keyboard.view), "the bottom key row keeps its globe")

    for surface in [KeyboardViewController.Surface.keys, .contacts, .confirmation, .preview] {
      keyboard.setSurfaceForDisplay(surface)
      keyboard.view.layoutIfNeeded()
      let globes = allButtons(in: keyboard.view).filter {
        $0.accessibilityIdentifier == "layergram.key.globe"
          || $0.accessibilityIdentifier == "layergram.action.globe"
      }
      XCTAssertEqual(globes.count, 2, "both globe controls exist on \(surface)")
      let visible = globes.filter { effectivelyVisible($0, in: keyboard.view) }
      XCTAssertEqual(
        visible.count, 1,
        "exactly one globe is effectively visible on \(surface) (hidden ancestors count)"
      )
    }

    // Off the key surface the key container really is hidden, so only the
    // fallback can be the visible globe.
    keyboard.setSurfaceForDisplay(.contacts)
    keyboard.view.layoutIfNeeded()
    XCTAssertTrue(keyboard.keysContainerView.isHidden)
    XCTAssertTrue(effectivelyVisible(fallback, in: keyboard.view))
    XCTAssertFalse(
      effectivelyVisible(keyButton("globe", in: keyboard.view)!, in: keyboard.view),
      "the in-row globe is genuinely unreachable while its container is hidden"
    )
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
        "layergram.key.symbols"
      ]
    )
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
    XCTAssertEqual(KeyboardViewController.Copy.string(.returnKey, in: spanish), "intro")
    XCTAssertEqual(KeyboardViewController.Copy.string(.returnKey, in: italian), "invio")

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
    // The copy disclaims delivery instead of claiming it.
    XCTAssertTrue(exported[0].1.lowercased().contains("no delivery confirmation"))
    XCTAssertTrue(exported[1].1.lowercased().contains("nessuna conferma di consegna"))
    XCTAssertTrue(exported[2].1.lowercased().contains("sin confirmación de entrega"))
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
    for size in [CGSize(width: 390, height: 320), CGSize(width: 320, height: 320)] {
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
