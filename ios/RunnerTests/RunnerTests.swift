import UIKit
import XCTest
@testable import Runner

class RunnerTests: XCTestCase {

  func testVisibilityPolicyCoversInactiveAndCapturedStates() {
    let cases: [(enabled: Bool, captured: Bool, foreground: Bool, expected: Bool)] = [
      (false, false, false, false),
      (false, false, true, false),
      (false, true, false, false),
      (false, true, true, false),
      (true, false, false, true),
      (true, false, true, false),
      (true, true, false, true),
      (true, true, true, true),
    ]

    for testCase in cases {
      XCTAssertEqual(
        ScreenPrivacyShield.shouldBeVisible(
          protectionEnabled: testCase.enabled,
          isCaptured: testCase.captured,
          isForegroundActive: testCase.foreground
        ),
        testCase.expected,
        "Unexpected policy for enabled=\(testCase.enabled), captured=\(testCase.captured), foreground=\(testCase.foreground)"
      )
    }
  }

  func testShieldHidesContentBlocksSemanticsAndRestoresExistingState() {
    let window = makeWindow()
    let rootView = try! XCTUnwrap(window.rootViewController?.view)
    rootView.isHidden = false
    rootView.isUserInteractionEnabled = true
    rootView.accessibilityElementsHidden = false
    let shield = ScreenPrivacyShield()

    shield.setVisible(true, in: window)

    XCTAssertTrue(rootView.isHidden)
    XCTAssertFalse(rootView.isUserInteractionEnabled)
    XCTAssertTrue(rootView.accessibilityElementsHidden)
    let shieldView = try! XCTUnwrap(shield.shieldView)
    XCTAssertEqual(shieldView.superview, window)
    XCTAssertEqual(shieldView.backgroundColor, .black)
    XCTAssertTrue(shieldView.isOpaque)
    XCTAssertTrue(shieldView.isUserInteractionEnabled)
    XCTAssertTrue(shieldView.isAccessibilityElement)
    XCTAssertEqual(shieldView.accessibilityLabel, "Layergram")
    XCTAssertTrue(shieldView.accessibilityViewIsModal)

    shield.setVisible(false, in: window)

    XCTAssertFalse(rootView.isHidden)
    XCTAssertTrue(rootView.isUserInteractionEnabled)
    XCTAssertFalse(rootView.accessibilityElementsHidden)
  }

  func testShieldRestoresPreexistingContentState() {
    let window = makeWindow()
    let rootView = try! XCTUnwrap(window.rootViewController?.view)
    rootView.isHidden = true
    rootView.isUserInteractionEnabled = false
    rootView.accessibilityElementsHidden = true
    let shield = ScreenPrivacyShield()

    shield.setVisible(true, in: window)
    shield.setVisible(false, in: window)

    XCTAssertTrue(rootView.isHidden)
    XCTAssertFalse(rootView.isUserInteractionEnabled)
    XCTAssertTrue(rootView.accessibilityElementsHidden)
  }

  func testRepeatedVisibilityCallsDoNotDuplicateShieldOrLoseState() {
    let window = makeWindow()
    let rootView = try! XCTUnwrap(window.rootViewController?.view)
    let shield = ScreenPrivacyShield()

    shield.setVisible(true, in: window)
    let shieldView = try! XCTUnwrap(shield.shieldView)
    shield.setVisible(true, in: window)

    XCTAssertEqual(window.subviews.filter { $0 === shieldView }.count, 1)
    XCTAssertTrue(rootView.isHidden)

    shield.setVisible(false, in: window)
    shield.setVisible(false, in: window)

    XCTAssertFalse(rootView.isHidden)
    XCTAssertTrue(rootView.isUserInteractionEnabled)
    XCTAssertFalse(rootView.accessibilityElementsHidden)
    XCTAssertNil(shieldView.superview)
  }

  func testReplacingRootOrWindowRestoresPreviousContent() {
    let firstWindow = makeWindow()
    let firstRootView = try! XCTUnwrap(firstWindow.rootViewController?.view)
    firstRootView.isUserInteractionEnabled = false
    firstRootView.accessibilityElementsHidden = true
    let shield = ScreenPrivacyShield()

    shield.setVisible(true, in: firstWindow)
    let replacementRoot = UIViewController()
    firstWindow.rootViewController = replacementRoot
    let replacementRootView = replacementRoot.view!
    shield.setVisible(true, in: firstWindow)

    XCTAssertFalse(firstRootView.isHidden)
    XCTAssertFalse(firstRootView.isUserInteractionEnabled)
    XCTAssertTrue(firstRootView.accessibilityElementsHidden)
    XCTAssertTrue(replacementRootView.isHidden)

    let secondWindow = makeWindow()
    let secondRootView = try! XCTUnwrap(secondWindow.rootViewController?.view)
    shield.setVisible(true, in: secondWindow)

    XCTAssertFalse(replacementRootView.isHidden)
    XCTAssertTrue(secondRootView.isHidden)
    XCTAssertEqual(shield.shieldView?.superview, secondWindow)

    shield.setVisible(false, in: secondWindow)
    XCTAssertFalse(secondRootView.isHidden)
  }

  private func makeWindow() -> UIWindow {
    let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 320, height: 640))
    window.rootViewController = UIViewController()
    return window
  }

}
