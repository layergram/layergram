import UIKit
import XCTest

final class KeyboardViewControllerTests: XCTestCase {
  func testLayoutAndCallbacksBeforeDocumentBindingRemainInert() {
    let keyboard = KeyboardViewController()
    keyboard.loadViewIfNeeded()
    keyboard.view.frame = CGRect(x: 0, y: 0, width: 390, height: 320)
    keyboard.view.layoutIfNeeded()

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

  func testUnavailableKeyboardKeepsNextKeyboardControlVisible() {
    let keyboard = KeyboardViewController()
    keyboard.loadViewIfNeeded()
    keyboard.viewDidAppear(false)
    defer { keyboard.viewWillDisappear(false) }

    func nextKeyboardButton(in view: UIView) -> UIView? {
      if view.accessibilityIdentifier == "layergram.key.globe" { return view }
      return view.subviews.lazy.compactMap { nextKeyboardButton(in: $0) }.first
    }
    let globe = nextKeyboardButton(in: keyboard.view)
    XCTAssertNotNil(globe)
    XCTAssertEqual(globe?.isHidden, false)
    XCTAssertEqual(keyboard.tableView(UITableView(), numberOfRowsInSection: 0), 0)
  }
}
