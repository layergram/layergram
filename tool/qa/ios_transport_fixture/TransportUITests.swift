import XCTest
import UIKit
import LocalAuthentication
import Vision

/// Real keyboard touches in an offline transport. Prepare an unlocked disposable
/// Layergram identity and its named QA contact before running this suite.
/// Failures are assertions: a denied session must never be reported as a pass.
final class TransportUITests: XCTestCase {
    private let rootBundle = ProcessInfo.processInfo.environment[
        "LAYERGRAM_QA_ROOT_BUNDLE"
    ] ?? "app.layergram.keyboardvalidation"
    private let contactName = ProcessInfo.processInfo.environment[
        "LAYERGRAM_QA_CONTACT_NAME"
    ] ?? "QA Android"

    override func setUpWithError() throws {
        continueAfterFailure = false
        XCTAssertEqual(rootBundle, "app.layergram.keyboardvalidation",
                       "Run transport QA only against the disposable validation app")
    }

    /// Let XCTest request normal OS authorization before unattended work.
    /// No host/app activation, screenshot, typing or cryptographic operation.
    func testUIAutomationAuthorizationPreflight() throws {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        XCTAssertTrue(springboard.waitForExistence(timeout: 5))
        print("QA_UI_AUTOMATION=runnerInitialized;noPhoneGestures")
    }

    /// Collect an already inserted encrypted carrier without opening Layergram,
    /// touching the keyboard or changing the offline host field.
    func testExistingProbeCarrierReadback() throws {
        let host = XCUIApplication(bundleIdentifier: "app.layergram.keyboardprobe")
        XCTAssertTrue(host.waitForExistence(timeout: 5), "Leave the offline Probe in front")
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "The Probe host field must remain visible")
        let carrier = field.value as? String ?? ""
        XCTAssertFalse(carrier.isEmpty, "Insert one new keyboard carrier before readback")
        XCTAssertLessThanOrEqual(carrier.utf16.count, 4_000)
        let lines = carrier.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.count, 1, "A single new message must have one carrier")
        XCTAssertTrue(carrier.range(
            of: #"^(?:p1|m3|b3)\.[A-Za-z0-9_-]+$"#, options: .regularExpression
        ) != nil, "The host field must contain only a complete V3 carrier")
        let attachment = XCTAttachment(string: carrier)
        attachment.name = "QA existing physical carrier"
        attachment.lifetime = .keepAlways
        add(attachment)
        print("QA_EXISTING_CARRIER_READBACK=complete;units=\(carrier.utf16.count)")
    }

    /// Inventory the actual full-app onboarding in a disposable simulator.
    /// This only checks accessibility; it never creates or prints an identity.
    func testSimulatorLayergramOnboardingAccessibility() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        let welcome = root.staticTexts["Benvenuto in Layergram"]
        let name = root.textFields["Nome visibile ai contatti"]
        XCTAssertTrue(welcome.waitForExistence(timeout: 8),
                      "The actual onboarding must be exposed to XCTest")
        XCTAssertTrue(name.waitForExistence(timeout: 3),
                      "The QA identity name field must be exposed to XCTest")
        print("QA_SIM_ONBOARDING=accessible;identityUnchanged")
#else
        throw XCTSkip("Disposable simulator-only onboarding inventory")
#endif
    }

    /// A guarded diagnostic for Flutter screens that render but expose no AX
    /// children on this disposable simulator. It edits only the QA name field;
    /// no identity is created and no product/physical-device result is claimed.
    func testSimulatorCoordinateNameEntry() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        let before = root.screenshot()
        guard let pixels = before.image.cgImage else {
            XCTFail("Cannot inspect simulator onboarding image"); return
        }
        XCTAssertEqual(pixels.width, 1206, "Coordinate diagnostic requires the inspected QA layout")
        XCTAssertEqual(pixels.height, 2622, "Coordinate diagnostic requires the inspected QA layout")
        func words(in image: CGImage) throws -> String {
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }
                .joined(separator: " ")
        }
        let baseline = try words(in: pixels)
        XCTAssertTrue(baseline.contains("Benvenuto in Layergram") &&
                      baseline.contains("Nome visibile ai contatti"),
                      "Tap only the observed QA onboarding layout")
        XCTAssertFalse(baseline.contains("QA Touch A"),
                       "Diagnostic needs an empty QA name field; do not append to an earlier run")
        root.coordinate(withNormalizedOffset: CGVector(dx: 0.45, dy: 0.928)).tap()
        root.typeText("QA Touch A")
        let after = root.screenshot()
        let attachment = XCTAttachment(screenshot: after)
        attachment.name = "qa-coordinate-name-entry"
        attachment.lifetime = .keepAlways
        add(attachment)
        guard let finalPixels = after.image.cgImage else {
            XCTFail("Cannot inspect typed QA name"); return
        }
        XCTAssertTrue(try words(in: finalPixels).contains("QA Touch A"),
                      "XCTest input must visibly reach the real Flutter field")
        print("QA_SIM_COORDINATE=nameEntered;identityUnchanged;simulatorOnly")
#else
        throw XCTSkip("Disposable simulator-only coordinate diagnostic")
#endif
    }

    /// Restore a throwaway identity using the public BIP39 test vector through
    /// the actual Flutter onboarding. No secret seed or production identity is
    /// supplied, and every coordinate is preceded by a current OCR check.
    func testSimulatorPublicSeedOnboarding() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        func observations() throws -> [(String, CGPoint)] {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QAOnboarding", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT", "en-US"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        func tapObserved(_ needle: String, exact: Bool = false,
                         swipes: Int = 4) throws {
            for attempt in 0...swipes {
                let lines = try observations()
                if let line = lines.first(where: {
                    exact ? $0.0.caseInsensitiveCompare(needle) == .orderedSame
                          : $0.0.localizedCaseInsensitiveContains(needle)
                }) {
                    root.coordinate(withNormalizedOffset: CGVector(dx: line.1.x,
                                                                  dy: line.1.y)).tap()
                    return
                }
                if attempt < swipes { root.swipeUp() }
            }
            XCTFail("Expected QA onboarding control was not observed: \(needle)")
            throw NSError(domain: "QAOnboarding", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Missing observed control"])
        }
        var welcomeVisible = false
        for _ in 0..<12 {
            welcomeVisible = try observations().contains {
                $0.0.localizedCaseInsensitiveContains("Benvenuto in Layergram")
            }
            if welcomeVisible { break }
            sleep(2)
        }
        guard welcomeVisible else {
            let attachment = XCTAttachment(screenshot: root.screenshot())
            attachment.name = "qa-onboarding-unexpected-baseline"
            attachment.lifetime = .keepAlways
            add(attachment)
            XCTFail("Only an unconfigured disposable Layergram app may run this test")
            return
        }
        try tapObserved("Ripristina", exact: true, swipes: 0)
        try tapObserved("Nome visibile ai contatti")
        // A prior diagnostic may have left a draft in the same field. Clearing
        // via the actual focused editor makes the fixture deterministic.
        root.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 40))
        root.typeText("QA Simulator Seed")
        // The app bar is outside the onboarding GestureDetector. The narrow
        // body gutter receives its unfocus tap without activating a form row.
        root.coordinate(withNormalizedOffset: CGVector(dx: 0.98, dy: 0.30)).tap()
        try tapObserved("Inserisci 12 o 24 parole")
        let publicVector = (Array(repeating: "abandon", count: 11) + ["about"])
            .joined(separator: " ")
        root.typeText(publicVector)
        root.coordinate(withNormalizedOffset: CGVector(dx: 0.98, dy: 0.30)).tap()
        var consentLine: (String, CGPoint)?
        for attempt in 0...5 {
            consentLine = try observations().first {
                $0.0.localizedCaseInsensitiveContains("Ho letto")
            }
            if consentLine != nil { break }
            if attempt < 5 { root.swipeUp() }
        }
        guard let consentLine else {
            XCTFail("Legal consent must be visible before restoring QA identity"); return
        }
        root.coordinate(withNormalizedOffset: CGVector(dx: 0.09,
                                                      dy: consentLine.1.y)).tap()
        try tapObserved("Ripristina ora")
        var confirmed = false
        for _ in 0..<30 {
            let lines = try observations().map(\.0)
            if lines.contains(where: { $0.contains("La tua nuova identità") }) &&
               !lines.contains(where: { $0.contains("Benvenuto in Layergram") }) {
                confirmed = true; break
            }
            sleep(2)
        }
        XCTAssertTrue(confirmed, "Real QA identity restore must show the v3 identity dialog")
        print("QA_SIM_ONBOARDING=publicTestSeedRestored;realCrypto;simulatorOnly")
#else
        throw XCTSkip("Disposable simulator-only public test-vector onboarding")
#endif
    }

    /// Read back the actual identity after the one-use restore. This does not
    /// reenter a seed or manufacture an identity when the restore has failed.
    func testSimulatorRestoredIdentityReadback() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        func observed(_ needle: String) throws -> CGPoint? {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QAOnboarding", code: 3,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).first(where: {
                $0.topCandidates(1).first?.string.localizedCaseInsensitiveContains(needle) == true
            }).map {
                CGPoint(x: $0.boundingBox.midX, y: 1 - $0.boundingBox.midY)
            }
        }
        guard try observed("Benvenuto in Layergram") == nil else {
            XCTFail("QA identity has not left onboarding"); return
        }
        if let later = try observed("Più tardi") {
            root.coordinate(withNormalizedOffset: CGVector(dx: later.x, dy: later.y)).tap()
        }
        guard let identityTab = try observed("La mia identità") else {
            XCTFail("Real identity tab is not visible after restore"); return
        }
        root.coordinate(withNormalizedOffset: CGVector(dx: identityTab.x,
                                                       dy: identityTab.y - 0.035)).tap()
        var nameVisible = false
        for _ in 0..<8 {
            nameVisible = try observed("QA Simulator Seed") != nil
            if nameVisible { break }
            sleep(2)
        }
        XCTAssertTrue(nameVisible, "Restored QA identity name must be visible in its real screen")
        print("QA_SIM_IDENTITY=restoredNameReadBack;realApp;simulatorOnly")
#else
        throw XCTSkip("Disposable simulator-only restored identity read-back")
#endif
    }

    /// Check the updated full app's identity-name editor on the public-seed
    /// simulator. This changes only that disposable display name, not keys.
    func testSimulatorIdentityNameExactAfterUpdate() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        // A failed earlier name-edit attempt can leave an unsaved field draft
        // in memory. Relaunch the app to inspect the persisted identity only.
        if root.state != .notRunning { root.terminate() }
        root.activate()
        func lines() throws -> [(String, CGPoint)] {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QAIdentityName", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        func point(_ needle: String) throws -> CGPoint? {
            try lines().first(where: {
                $0.0.localizedCaseInsensitiveContains(needle)
            })?.1
        }
        // Flutter's first frame can lag behind app activation; the migration
        // notice is shown on cold launch and blocks taps on the tab behind it.
        for _ in 0..<12 {
            let visible = try lines()
            let modal = visible.contains { $0.0.localizedCaseInsensitiveContains("La tua nuova identità") }
            if modal, let later = visible.first(where: {
                $0.0.localizedCaseInsensitiveContains("Più tardi")
            })?.1 {
                root.coordinate(withNormalizedOffset: CGVector(dx: later.x,
                                                               dy: later.y)).tap()
                break
            }
            if !modal && visible.contains(where: { $0.0.localizedCaseInsensitiveContains("Impronta:") }) { break }
            if !modal && visible.contains(where: { $0.0.localizedCaseInsensitiveContains("La mia identità") }) { break }
            sleep(1)
        }
        if try point("QA Simulator Seed Seed") == nil {
            guard let tab = try point("La mia identità") else {
                XCTFail("Identity tab is not visible in disposable simulator"); return
            }
            root.coordinate(withNormalizedOffset: CGVector(dx: tab.x,
                                                           dy: tab.y - 0.035)).tap()
        }
        var previous: CGPoint?
        for _ in 0..<8 {
            previous = try point("QA Simulator Seed Seed")
            if previous != nil { break }
            sleep(1)
        }
        guard let previous, try point("Impronta:") != nil else {
            XCTFail("Expected the previously restored disposable identity"); return
        }
        // Tap beyond the visible name to place the insertion caret at its
        // end. Backspace clears only text before the caret; tapping the OCR
        // midpoint would leave a suffix and create a false duplicate.
        root.coordinate(withNormalizedOffset: CGVector(dx: 0.75,
                                                       dy: previous.y)).tap()
        root.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 60))
        guard try point("QA Simulator Seed") == nil else {
            XCTFail("QA name was not fully cleared before replacement"); return
        }
        root.typeText("QA Name Fixed")
        guard try lines().contains(where: { $0.0 == "QA Name Fixed" }) else {
            XCTFail("The editor must show the exact new disposable name before save"); return
        }
        root.coordinate(withNormalizedOffset: CGVector(dx: 0.85,
                                                       dy: previous.y)).tap()
        root.terminate()
        root.activate()
        for _ in 0..<12 {
            let visible = try lines()
            let modal = visible.contains { $0.0.localizedCaseInsensitiveContains("La tua nuova identità") }
            if modal, let later = visible.first(where: {
                $0.0.localizedCaseInsensitiveContains("Più tardi")
            })?.1 {
                root.coordinate(withNormalizedOffset: CGVector(dx: later.x, dy: later.y)).tap()
                break
            }
            if !modal && visible.contains(where: { $0.0.localizedCaseInsensitiveContains("La mia identità") }) { break }
            sleep(1)
        }
        if try point("QA Name Fixed") == nil {
            guard let tab = try point("La mia identità") else {
                XCTFail("Identity tab missing after a cold relaunch"); return
            }
            root.coordinate(withNormalizedOffset: CGVector(dx: tab.x,
                                                           dy: tab.y - 0.035)).tap()
        }
        var exact = false
        for _ in 0..<8 {
            let visible = try lines()
            exact = visible.contains(where: { $0.0 == "QA Name Fixed" }) &&
                visible.contains(where: { $0.0.localizedCaseInsensitiveContains("Impronta:") })
            if exact { break }
            sleep(2)
        }
        XCTAssertTrue(exact, "Saved identity name must remain exact after a cold relaunch")
        print("QA_SIM_NAME=exactAfterSaveAndRelaunch;simulatorOnly")
#else
        throw XCTSkip("Disposable simulator-only identity-name check")
#endif
    }

    /// Read only the persisted disposable name after an earlier one-use edit.
    /// This mode is safe to rerun and never changes the identity or its keys.
    func testSimulatorIdentityNameExactReadback() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        if root.state != .notRunning { root.terminate() }
        root.activate()
        func observations() throws -> [(String, CGPoint)] {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QAIdentityName", code: 4,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        for _ in 0..<12 {
            let visible = try observations()
            let modal = visible.contains { $0.0.localizedCaseInsensitiveContains("La tua nuova identità") }
            if modal, let later = visible.first(where: {
                $0.0.localizedCaseInsensitiveContains("Più tardi")
            })?.1 {
                root.coordinate(withNormalizedOffset: CGVector(dx: later.x, dy: later.y)).tap()
                break
            }
            if !modal && visible.contains(where: {
                $0.0.localizedCaseInsensitiveContains("La mia identità")
            }) { break }
            sleep(1)
        }
        guard let tab = try observations().first(where: {
            $0.0.localizedCaseInsensitiveContains("La mia identità")
        })?.1 else {
            XCTFail("Identity tab not visible after cold launch"); return
        }
        root.coordinate(withNormalizedOffset: CGVector(dx: tab.x,
                                                       dy: tab.y - 0.035)).tap()
        var exact = false
        for _ in 0..<8 {
            let visible = try observations()
            exact = visible.contains(where: { $0.0 == "QA Name Fixed" }) &&
                visible.contains(where: { $0.0.localizedCaseInsensitiveContains("Impronta:") }) &&
                visible.contains(where: { $0.0.contains("7562-8DFE-BB5C") })
            if exact { break }
            sleep(2)
        }
        XCTAssertTrue(exact, "Persisted QA name and fingerprint must match after cold launch")
        print("QA_SIM_NAME=exactPersistedReadback;simulatorOnly")
#else
        throw XCTSkip("Disposable simulator-only identity-name read-back")
#endif
    }

    /// Read-only inventory of native simulator Settings before enabling the
    /// QA keyboard. This gate never changes an OS permission or IME selection.
    func testSimulatorKeyboardSettingsInventory() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        XCTAssertTrue(settings.waitForExistence(timeout: 8))
        let labels = settings.descendants(matching: .any).allElementsBoundByIndex
            .compactMap { element -> String? in
                let label = element.label.trimmingCharacters(in: .whitespacesAndNewlines)
                return label.isEmpty ? nil : label
            }
        let generalVisible = labels.contains {
            ["General", "Generali", "General Settings"].contains($0)
        }
        let keyboardVisible = labels.contains {
            ["Keyboard", "Tastiera", "Teclado"].contains($0)
        }
        print("QA_SIM_SETTINGS=general:\(generalVisible);keyboard:\(keyboardVisible);readOnly")
        XCTAssertTrue(generalVisible || keyboardVisible,
                      "Native Settings navigation labels must be visible before touching permissions")
#else
        throw XCTSkip("Disposable simulator-only Settings inventory")
#endif
    }

    /// Verify the native path to available keyboards on the disposable
    /// simulator. Navigation is read-only; do not grant Full Access here.
    func testSimulatorKeyboardSettingsPath() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        let general = settings.staticTexts["Generali"]
        if general.waitForExistence(timeout: 3) { general.tap() }
        let keyboard = settings.staticTexts["Tastiera"]
        let keyboardRows = settings.staticTexts.matching(NSPredicate(
            format: "label == %@", "Tastiere"
        ))
        let keyboards = keyboardRows.firstMatch
        let add = settings.descendants(matching: .any).matching(NSPredicate(
            format: "label CONTAINS %@", "Aggiungi nuova tastiera"
        )).firstMatch
        if !keyboards.exists && !add.exists {
            for _ in 0..<4 where !keyboard.exists { settings.swipeUp() }
            XCTAssertTrue(keyboard.waitForExistence(timeout: 3),
                          "Native keyboard settings row must be accessible")
            keyboard.tap()
        }
        let onInstalledList = settings.staticTexts["Italiano"].exists &&
            settings.buttons["Modifica"].exists
        if !add.exists && !onInstalledList {
            let candidates = keyboardRows.allElementsBoundByIndex
            guard let row = candidates.max(by: { $0.frame.midY < $1.frame.midY }) else {
                XCTFail("Installed-keyboards row must be accessible"); return
            }
            row.tap()
        }
        for _ in 0..<12 where !add.exists { settings.swipeUp() }
        XCTAssertTrue(add.waitForExistence(timeout: 4),
                      "Add-keyboard entry must be visible before QA permission setup")
        print("QA_SIM_KEYBOARD_SETTINGS=addEntryVisible;readOnly")
#else
        throw XCTSkip("Disposable simulator-only keyboard Settings path")
#endif
    }

    /// The installed QA extension must appear in the native Add Keyboard
    /// chooser before any Full Access permission is changed.
    func testSimulatorKeyboardAvailability() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        let add = settings.descendants(matching: .any).matching(NSPredicate(
            format: "label CONTAINS %@", "Aggiungi nuova tastiera"
        )).firstMatch
        XCTAssertTrue(add.waitForExistence(timeout: 5),
                      "Start from the inspected disposable keyboard list")
        add.tap()
        let candidate = settings.staticTexts.matching(NSPredicate(
            format: "label CONTAINS %@", "Layergram"
        )).firstMatch
        for _ in 0..<6 where !candidate.exists { settings.swipeUp() }
        XCTAssertTrue(candidate.waitForExistence(timeout: 4),
                      "Installed QA extension must be offered by native Settings")
        print("QA_SIM_KEYBOARD=availableInNativeChooser;notEnabled")
#else
        throw XCTSkip("Disposable simulator-only keyboard availability")
#endif
    }

    /// Enable only the uniquely installed Layergram QA extension in the
    /// disposable simulator. Full Access is checked in a separate gate.
    func testSimulatorKeyboardAdd() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        let chooser = settings.staticTexts["Aggiungi nuova tastiera"]
        XCTAssertTrue(chooser.waitForExistence(timeout: 5),
                      "Start from the previously inspected native chooser")
        let candidate = settings.staticTexts.matching(NSPredicate(
            format: "label == %@", "Layergram"
        )).firstMatch
        for _ in 0..<24 where !candidate.isHittable { settings.swipeUp() }
        XCTAssertTrue(candidate.isHittable,
                      "The unique QA keyboard must be visible before selection")
        candidate.tap()
        XCTAssertTrue(settings.buttons["Modifica"].waitForExistence(timeout: 6),
                      "Add Keyboard chooser must close onto installed list")
        XCTAssertTrue(settings.staticTexts["Layergram"].exists,
                      "Installed-keyboard list must contain Layergram")
        print("QA_SIM_KEYBOARD=addedToInstalledList;fullAccessUnverified")
#else
        throw XCTSkip("Disposable simulator-only keyboard addition")
#endif
    }

    /// Open the added QA keyboard's access page without changing its switch.
    func testSimulatorKeyboardAccessPage() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        let layergram = settings.staticTexts["Layergram"]
        XCTAssertTrue(layergram.waitForExistence(timeout: 5) && layergram.isHittable,
                      "Start from the inspected installed-keyboards list")
        layergram.tap()
        let access = settings.descendants(matching: .any).matching(NSPredicate(
            format: "label CONTAINS[cd] %@", "accesso completo"
        )).firstMatch
        XCTAssertTrue(access.waitForExistence(timeout: 5),
                      "Native Full Access preference must be visible")
        print("QA_SIM_KEYBOARD=fullAccessPreferenceVisible;unchanged")
#else
        throw XCTSkip("Disposable simulator-only keyboard access inventory")
#endif
    }

    /// Grant the already-added throwaway extension Full Access and read back
    /// the real OS switch. Never run this against a physical or personal app.
    func testSimulatorKeyboardFullAccess() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        let title = settings.descendants(matching: .any).matching(NSPredicate(
            format: "label CONTAINS[cd] %@", "Consenti accesso completo"
        )).firstMatch
        XCTAssertTrue(title.waitForExistence(timeout: 5),
                      "Start from the inspected QA keyboard access page")
        let toggle = settings.switches["Consenti accesso completo"]
        XCTAssertTrue(toggle.exists, "Expected exactly one keyboard access switch")
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let appWarning = settings.alerts.firstMatch
        let systemWarning = springboard.alerts.firstMatch
        if !appWarning.exists && !systemWarning.exists && (toggle.value as? String) != "1" {
            // The native switch AX frame covers its entire row. Tap the actual
            // switch at the right, not the row center, which leaves it unchanged.
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.88, dy: 0.5)).tap()
        }
        if appWarning.waitForExistence(timeout: 3) || systemWarning.exists {
            let warning = appWarning.exists ? appWarning : systemWarning
            let description = ([warning.label] + warning.staticTexts.allElementsBoundByIndex.map(\.label))
                .joined(separator: " ").localizedLowercase
            XCTAssertTrue(description.contains("layergram") &&
                          (description.contains("accesso completo") ||
                           description.contains("full access")),
                          "Only the Layergram Full Access warning may be accepted")
            let allow = warning.buttons.matching(NSPredicate(
                format: "label IN %@", ["Consenti", "Allow"]
            )).firstMatch
            XCTAssertTrue(allow.exists, "Full Access warning must have an explicit allow action")
            allow.tap()
        }
        let enabled = XCTNSPredicateExpectation(predicate: NSPredicate(
            format: "value == %@", "1"
        ), object: toggle)
        XCTAssertEqual(XCTWaiter.wait(for: [enabled], timeout: 6), .completed,
                       "OS must confirm Full Access after selection")
        print("QA_SIM_KEYBOARD=fullAccessOn;nativeReadback")
#else
        throw XCTSkip("Disposable simulator-only keyboard Full Access")
#endif
    }

    /// Inspect the real transport host and OS keyboard selector after the
    /// disposable simulator extension has been enabled in Settings.
    func testSimulatorKeyboardHostInventory() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8), "Offline transport field must exist")
        field.tap()
        let capture = XCTAttachment(screenshot: host.screenshot())
        capture.name = "qa-keyboard-host-inventory"
        capture.lifetime = .keepAlways
        add(capture)
        print("QA_SIM_HOST_KEYBOARD_AX=\(host.keyboards.debugDescription)")
        print("QA_SIM_HOST_KEYBOARD=inTransportField;selectionUnchanged")
#else
        throw XCTSkip("Disposable simulator-only keyboard host inventory")
#endif
    }

    /// Select the installed extension in the real native keyboard menu.
    /// This proves launch only; a session, identity or FS exchange needs its
    /// own authenticated gate.
    func testSimulatorKeyboardLaunch() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        field.tap()
        selectKeyboard(in: host)
        let status = host.staticTexts["layergram.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 10),
                      "The installed Layergram extension must render in the offline host")
        let capture = XCTAttachment(screenshot: host.screenshot())
        capture.name = "qa-layergram-keyboard-first-launch"
        capture.lifetime = .keepAlways
        add(capture)
        print("QA_SIM_KEYBOARD_LAUNCH=rendered;sessionUnverified;fsUnverified")
#else
        throw XCTSkip("Disposable simulator-only keyboard launch")
#endif
    }

    /// Inspect the real app's system-keyboard settings after its one-time V3
    /// notice. Flutter controls are not exposed in this simulator's AX tree,
    /// so each coordinate is resolved from fresh OCR of the visible screen.
    func testSimulatorAppKeyboardSettingsInventory() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        func observed() throws -> [(String, CGPoint)] {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QAKeyboardSettings", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT", "en-US"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        func tap(_ label: String) throws {
            let lines = try observed()
            guard let row = lines.first(where: { $0.0.localizedCaseInsensitiveContains(label) }) else {
                XCTFail("Missing observed QA control: \(label)")
                throw NSError(domain: "QAKeyboardSettings", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "Missing visible control"])
            }
            root.coordinate(withNormalizedOffset: CGVector(dx: row.1.x, dy: row.1.y)).tap()
        }
        let before = try observed().map(\.0)
        if before.contains(where: { $0.localizedCaseInsensitiveContains("La tua nuova identità") }) {
            try tap("Più tardi")
        }
        XCTAssertTrue(try observed().contains {
            $0.0.localizedCaseInsensitiveContains("Messaggi")
        }, "Actual chat list must be visible before opening app settings")
        try tap("Impostazioni")
        let lines = try observed().map(\.0)
        let capture = XCTAttachment(screenshot: root.screenshot())
        capture.name = "qa-app-keyboard-settings-inventory"
        capture.lifetime = .keepAlways
        add(capture)
        print("QA_SIM_APP_SETTINGS_OCR=\(lines.joined(separator: " | "))")
        XCTAssertTrue(lines.contains { $0.localizedCaseInsensitiveContains("Tastiera") },
                      "Actual app settings must offer system keyboard configuration")
        print("QA_SIM_APP_KEYBOARD_SETTINGS=visible;unchanged")
#else
        throw XCTSkip("Disposable simulator-only app settings inventory")
#endif
    }

    /// Enable the app-side opt-in only on the inspected throwaway simulator.
    /// The settings page and exact confirmation are checked on screen before
    /// every tap; newly revealed idle controls provide a UI read-back.
    func testSimulatorAppKeyboardEnable() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        func observed() throws -> [(String, CGPoint)] {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QAKeyboardEnable", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        func tapExact(_ label: String) throws {
            guard let row = try observed().first(where: {
                $0.0.caseInsensitiveCompare(label) == .orderedSame
            }) else {
                XCTFail("Missing exact observed control: \(label)")
                throw NSError(domain: "QAKeyboardEnable", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "Missing visible control"])
            }
            root.coordinate(withNormalizedOffset: CGVector(dx: row.1.x, dy: row.1.y)).tap()
        }
        let baseline = try observed().map(\.0)
        XCTAssertTrue(baseline.contains("Tastiera di sistema"),
                      "Start only on the inspected app Settings page")
        XCTAssertFalse(baseline.contains("Blocco per inattività della tastiera"),
                       "Do not toggle an already enabled keyboard off")
        try tapExact("Tastiera di sistema")
        XCTAssertTrue(try observed().contains {
            $0.0.localizedCaseInsensitiveContains("Attivare la tastiera")
        }, "App must present the keyboard opt-in explanation")
        try tapExact("Attiva")
        let appeared = XCTNSPredicateExpectation(predicate: NSPredicate(
            block: { _, _ in
                (try? observed().contains {
                    $0.0.localizedCaseInsensitiveContains("Blocco per inattività")
                }) ?? false
            }
        ), object: root)
        XCTAssertEqual(XCTWaiter.wait(for: [appeared], timeout: 8), .completed,
                       "Enabled app keyboard must reveal inactivity setting")
        let capture = XCTAttachment(screenshot: root.screenshot())
        capture.name = "qa-app-keyboard-opt-in-readback"
        capture.lifetime = .keepAlways
        add(capture)
        print("QA_SIM_APP_KEYBOARD=enabled;idleSettingVisible;simulatorOnly")
#else
        throw XCTSkip("Disposable simulator-only app keyboard opt-in")
#endif
    }

    /// Attempt an ordinary app-to-host handoff on the disposable simulator.
    /// A real status plus visible countdown are required; this test cannot
    /// stand in for hardware Face ID or an authenticated FS exchange.
    func testSimulatorKeyboardSessionAdmission() throws {
#if targetEnvironment(simulator)
        // Launch and select the transport before the app departure. XCTest can
        // spend most of the nonrenewable 20-second bootstrap window launching
        // a fresh host and opening the keyboard picker otherwise.
        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        field.tap()
        selectKeyboard(in: host)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        try dismissSimulatorIdentityNotice(in: root)
        // The autonomous bridge starts after Flutter restores the identity.
        // Give that asynchronous initialization a bounded ordinary foreground
        // window before switching to the transport app.
        sleep(8)
        host.activate()
        field.tap()
        selectKeyboard(in: host)
        let capture = XCTAttachment(screenshot: host.screenshot())
        capture.name = "qa-simulator-keyboard-session"
        capture.lifetime = .keepAlways
        add(capture)
        assertActive(in: host)
        print("QA_SIM_KEYBOARD_SESSION=activeCountdown;fsUnverified;biometricUnverified")
#else
        throw XCTSkip("Disposable simulator-only keyboard session admission")
#endif
    }

    /// Read the keyboard state after app opt-in without equating AX absence
    /// with denial: iOS can hide protected controls from accessibility.
    func testSimulatorKeyboardSessionInventory() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        field.tap()
        selectKeyboard(in: host)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        try dismissSimulatorIdentityNotice(in: root)
        sleep(8)
        host.activate()
        field.tap()
        selectKeyboard(in: host)
        // The OS keyboard picker can remain on screen during its dismissal
        // animation. Inspect the settled host, not the selection overlay.
        sleep(3)
        let capture = XCTAttachment(screenshot: host.screenshot())
        capture.name = "qa-simulator-session-inventory"
        capture.lifetime = .keepAlways
        add(capture)
        let status = host.staticTexts["layergram.status"]
        print("QA_SIM_SESSION_INVENTORY=statusPresent:\(status.exists);label:\(status.exists ? status.label : "AX-hidden");secureFields:\(host.secureTextFields.count)")
#else
        throw XCTSkip("Disposable simulator-only keyboard session inventory")
#endif
    }

    /// Follow an already opened, checksum-validated public QA identity link.
    /// Stop at the real import screen: this diagnostic never saves a contact
    /// or mistakes a displayed link for an accepted identity.
    func testSimulatorPublicContactImportInventory() throws {
#if targetEnvironment(simulator)
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let alert = springboard.alerts.firstMatch
        if alert.waitForExistence(timeout: 2) {
            XCTAssertTrue(alert.label.localizedCaseInsensitiveContains("Layergram"),
                          "Do not accept an unrelated system prompt")
            let open = alert.buttons["Apri"]
            XCTAssertTrue(open.exists, "The observed system prompt needs an Apri action")
            open.tap()
        }
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        XCTAssertTrue(root.waitForExistence(timeout: 8))
        func words(_ image: CGImage) throws -> [(String, CGPoint)] {
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT", "en-US"]
            try VNImageRequestHandler(cgImage: image).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        let initial = root.screenshot()
        guard let initialPixels = initial.image.cgImage,
              initialPixels.width == 1206, initialPixels.height == 2622 else {
            XCTFail("Public-contact diagnostic requires the exact QA simulator layout")
            return
        }
        if let later = try words(initialPixels).first(where: {
            $0.0.localizedCaseInsensitiveContains("Più tardi")
        })?.1 {
            root.coordinate(withNormalizedOffset: CGVector(dx: later.x, dy: later.y)).tap()
        }
        let shot = root.screenshot()
        let attachment = XCTAttachment(screenshot: shot)
        attachment.name = "qa-public-contact-import-inventory"
        attachment.lifetime = .keepAlways
        add(attachment)
        guard let pixels = shot.image.cgImage,
              pixels.width == 1206, pixels.height == 2622 else {
            XCTFail("Public-contact diagnostic requires the exact QA simulator layout")
            return
        }
        let visible = try words(pixels).map(\.0)
        XCTAssertTrue(visible.contains { $0.localizedCaseInsensitiveContains("Aggiungi contatto") },
                      "The real identity import form must be visible")
        print("QA_SIM_PUBLIC_CONTACT=importFormVisible;notAnalyzed;notSaved")
#else
        throw XCTSkip("Disposable simulator-only public contact inventory")
#endif
    }

    /// Save the observed public QA Android contact once on the disposable
    /// simulator. The fingerprint guard binds this tap to the physical QA
    /// Android public identity without changing that device.
    func testSimulatorPublicContactSave() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        func words() throws -> [(String, CGPoint)] {
            guard let pixels = root.screenshot().image.cgImage,
                  pixels.width == 1206, pixels.height == 2622 else {
                throw NSError(domain: "QAContact", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected QA layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT", "en-US"]
            try VNImageRequestHandler(cgImage: pixels).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        let before = try words()
        XCTAssertTrue(before.contains { $0.0 == "QA Android" },
                      "The import preview must name the exact QA contact")
        // Vision may split a fingerprint across OCR observations. The full
        // checksum and fingerprint of this public link were verified before
        // opening it; require its distinctive visible prefix here.
        XCTAssertTrue(before.contains { $0.0.contains("2DB4-BDE5") },
                      "The displayed public fingerprint must match QA Android")
        XCTAssertTrue(before.contains { $0.0.localizedCaseInsensitiveContains("Aggiungi contatto") } &&
                      before.contains { $0.0.localizedCaseInsensitiveContains("Impronta") },
                      "The QA import preview must be uncovered before its Save tap")
        // Vision reads the fingerprint but can omit the compact Save label.
        // This coordinate is bound to the exact 1206x2622 preview just checked.
        let save = before.first(where: { $0.0 == "Salva" })?.1 ??
            CGPoint(x: 0.79, y: 0.72)
        root.coordinate(withNormalizedOffset: CGVector(dx: save.x, dy: save.y)).tap()
        sleep(2)
        let after = try words().map(\.0)
        let attachment = XCTAttachment(screenshot: root.screenshot())
        attachment.name = "qa-public-contact-save-readback"
        attachment.lifetime = .keepAlways
        add(attachment)
        XCTAssertTrue(after.contains("Messaggi") && !after.contains("Salva"),
                      "Saving the contact must leave the import preview")
        print("QA_SIM_PUBLIC_CONTACT=saveRouteCompleted;readbackRequired")
#else
        throw XCTSkip("Disposable simulator-only public contact save")
#endif
    }

    /// Independent readback after the one-use import. Navigation is allowed;
    /// the fixture never imports the same contact twice just to get a pass.
    func testSimulatorPublicContactReadback() throws {
#if targetEnvironment(simulator)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        func words() throws -> [(String, CGPoint)] {
            guard let pixels = root.screenshot().image.cgImage,
                  pixels.width == 1206, pixels.height == 2622 else {
                throw NSError(domain: "QAContact", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected QA layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["it-IT", "en-US"]
            try VNImageRequestHandler(cgImage: pixels).perform([request])
            return (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
        }
        let before = try words()
        guard let contacts = before.last(where: { $0.0 == "Contatti" })?.1 else {
            XCTFail("The observed app has no Contacts tab")
            return
        }
        root.coordinate(withNormalizedOffset: CGVector(dx: contacts.x, dy: contacts.y)).tap()
        sleep(1)
        let after = try words().map(\.0)
        let attachment = XCTAttachment(screenshot: root.screenshot())
        attachment.name = "qa-public-contact-saved-readback"
        attachment.lifetime = .keepAlways
        add(attachment)
        XCTAssertTrue(after.contains { $0.localizedCaseInsensitiveContains("QA Android") },
                      "The QA Android contact must be in the real saved list")
        print("QA_SIM_PUBLIC_CONTACT=savedReadback;sessionUnverified")
#else
        throw XCTSkip("Disposable simulator-only public contact readback")
#endif
    }

    /// A cold launch of the disposable restored identity can display the V3
    /// identity notice again. Close only that observed notice before measuring
    /// an app-to-keyboard handoff; a covered app is not a prepared QA owner.
    private func dismissSimulatorIdentityNotice(in root: XCUIApplication) throws {
#if targetEnvironment(simulator)
        for _ in 0..<12 {
            guard let image = root.screenshot().image.cgImage,
                  image.width == 1206, image.height == 2622 else {
                throw NSError(domain: "QASimulatorNotice", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unexpected simulator layout"])
            }
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            try VNImageRequestHandler(cgImage: image).perform([request])
            let visible: [(String, CGPoint)] = (request.results ?? []).compactMap { result in
                guard let text = result.topCandidates(1).first?.string else { return nil }
                return (text, CGPoint(x: result.boundingBox.midX,
                                      y: 1 - result.boundingBox.midY))
            }
            let hasNotice = visible.contains {
                $0.0.localizedCaseInsensitiveContains("La tua nuova identità")
            }
            if hasNotice {
                guard let later = visible.first(where: {
                    $0.0.localizedCaseInsensitiveContains("Più tardi")
                })?.1 else {
                    XCTFail("V3 identity notice visible without its dismiss action")
                    return
                }
                root.coordinate(withNormalizedOffset: CGVector(dx: later.x, dy: later.y)).tap()
                continue
            }
            if visible.contains(where: { $0.0 == "Messaggi" }) { return }
            sleep(1)
        }
        XCTFail("QA app did not reach the uncovered message list")
#endif
    }

    /// Diagnose native switch activation without claiming Full Access. This
    /// captures the immediate OS result before XCTest can end the session.
    func testSimulatorKeyboardFullAccessTapProbe() throws {
#if targetEnvironment(simulator)
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        let toggle = settings.switches["Consenti accesso completo"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 5))
        let before = String(describing: toggle.value)
        let frame = toggle.frame
        toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.88, dy: 0.5)).tap()
        let capture = XCTAttachment(screenshot: settings.screenshot())
        capture.name = "qa-full-access-immediate-native-result"
        capture.lifetime = .keepAlways
        add(capture)
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let appAlert = settings.alerts.firstMatch.exists
        let systemAlert = springboard.alerts.firstMatch.exists
        print("QA_SIM_FULL_ACCESS_PROBE=before:\(before);after:\(String(describing: toggle.value));frame:\(frame);appAlert:\(appAlert);systemAlert:\(systemAlert)")
#else
        throw XCTSkip("Disposable simulator-only Full Access tap probe")
#endif
    }

    /// Baseline OS authentication only; not a keyboard/custody/Face ID device pass.
    func testSimulatorBiometricSensorMatch() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launchEnvironment["LAYERGRAM_QA_SIMULATOR_BIOMETRIC_PROBE"] = "YES"
        host.launch()
        let authenticate = host.buttons["probe.biometric.authenticate"]
        XCTAssertTrue(authenticate.waitForExistence(timeout: 8))
        authenticate.tap()
        let board = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let consent = board.alerts.buttons.matching(NSPredicate(format: "label IN %@",
            ["OK", "Allow", "Consenti", "Permitir"])).firstMatch
        if consent.waitForExistence(timeout: 2) { consent.tap() }
        let state = host.staticTexts["probe.biometric.state"]
        let pending = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", "pending"), object: state)
        XCTAssertEqual(XCTWaiter.wait(for: [pending], timeout: 5), .completed)
        print("QA_SIM_AUTH=awaitingMatch;platformControlOnly")
        let accepted = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", "authenticated"), object: state)
        XCTAssertEqual(XCTWaiter.wait(for: [accepted], timeout: 90), .completed,
                       "Inject a matching simulated sensor event; never bypass the callback")
        print("QA_SIM_AUTH=authenticated;platformControlOnly")
#else
        throw XCTSkip("Simulator-only biometric control")
#endif
    }

    func testSimulatorBiometricSensorUnavailable() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launchEnvironment["LAYERGRAM_QA_SIMULATOR_BIOMETRIC_PROBE"] = "YES"
        host.launch()
        let authenticate = host.buttons["probe.biometric.authenticate"]
        XCTAssertTrue(authenticate.waitForExistence(timeout: 8))
        authenticate.tap()
        let state = host.staticTexts["probe.biometric.state"]
        let expected = "unavailable:\(LAError.Code.biometryNotEnrolled.rawValue)"
        let denied = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", expected), object: state)
        XCTAssertEqual(XCTWaiter.wait(for: [denied], timeout: 8), .completed)
        print("QA_SIM_AUTH=notEnrolled;platformControlOnly")
#else
        throw XCTSkip("Simulator-only biometric control")
#endif
    }

    func testSimulatorBiometricSensorRejectAndRetry() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launchEnvironment["LAYERGRAM_QA_SIMULATOR_BIOMETRIC_PROBE"] = "YES"
        host.launch()
        let authenticate = host.buttons["probe.biometric.authenticate"]
        XCTAssertTrue(authenticate.waitForExistence(timeout: 8))
        let state = host.staticTexts["probe.biometric.state"]
        func wait(_ predicate: NSPredicate, timeout: TimeInterval) -> Bool {
            let expected = XCTNSPredicateExpectation(predicate: predicate, object: state)
            return XCTWaiter.wait(for: [expected], timeout: timeout) == .completed
        }
        authenticate.tap()
        XCTAssertTrue(wait(NSPredicate(format: "label == %@", "pending"), timeout: 8))
        print("QA_SIM_AUTH=awaitingNonMatch;platformControlOnly")
        XCTAssertTrue(wait(NSPredicate(format: "label BEGINSWITH %@", "rejected:"), timeout: 60))
        print("QA_SIM_AUTH=rejected;platformControlOnly")
        authenticate.tap()
        XCTAssertTrue(wait(NSPredicate(format: "label == %@", "pending"), timeout: 8))
        print("QA_SIM_AUTH=awaitingMatch;platformControlOnly")
        XCTAssertTrue(wait(NSPredicate(format: "label == %@", "authenticated"), timeout: 90))
        print("QA_SIM_AUTH=retryAuthenticated;platformControlOnly")
#else
        throw XCTSkip("Simulator-only biometric control")
#endif
    }

    func testSimulatorBiometricSensorCancellation() throws {
#if targetEnvironment(simulator)
        let host = XCUIApplication()
        host.launchEnvironment["LAYERGRAM_QA_SIMULATOR_BIOMETRIC_PROBE"] = "YES"
        host.launch()
        let authenticate = host.buttons["probe.biometric.authenticate"]
        XCTAssertTrue(authenticate.waitForExistence(timeout: 8))
        authenticate.tap()
        let board = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let cancel = board.buttons.matching(NSPredicate(format: "label IN %@",
            ["Cancel", "Annulla", "Cancelar"])).firstMatch
        XCTAssertTrue(cancel.waitForExistence(timeout: 8), "Cancel the observed system prompt; do not mock authentication")
        cancel.tap()
        let state = host.staticTexts["probe.biometric.state"]
        let expected = "rejected:\(LAError.Code.userCancel.rawValue)"
        let rejected = XCTNSPredicateExpectation(predicate: NSPredicate(format: "label == %@", expected), object: state)
        XCTAssertEqual(XCTWaiter.wait(for: [rejected], timeout: 8), .completed)
        print("QA_SIM_AUTH=userCanceled;platformControlOnly")
#else
        throw XCTSkip("Simulator-only biometric control")
#endif
    }

    func testRestoreCaptureProtectionAndVerifyProtectedScreenshot() throws {
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        let settings = root.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Ajustes")).firstMatch
        if settings.waitForExistence(timeout: 3) {
            settings.tap()
            let protection = root.switches.matching(NSPredicate(format: "label CONTAINS %@", "Protección de captura de pantalla")).firstMatch
            for _ in 0..<8 {
                if protection.exists && protection.isHittable { break }
                root.swipeDown()
            }
            XCTAssertTrue(protection.exists && protection.isHittable)
            if protection.value as? String == "0" { protection.tap() }
            // Enabling the app's secure canvas can remove Flutter's controls
            // from XCTest snapshots. The keyboard's physical pixel assertion
            // below is the authoritative protection gate, not a vanished switch.
        }
        sleep(4)
        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8)); field.tap()
        selectKeyboard(in: host)
        let draft = host.textViews["layergram.draft"]
        let protectedDraftFrame: CGRect
        if draft.waitForExistence(timeout: 2) {
            assertActive(in: host)
            for letter in "captura" { tapKey(String(letter), in: host) }
            XCTAssertEqual(draft.value as? String, "captura")
            protectedDraftFrame = draft.frame.insetBy(dx: 8, dy: 8)
            print("QA_CAPTURE_DRAFT_INPUT=observed")
        } else {
            // Secure rendering may intentionally expose only the secure
            // text-field leaf to XCTest. Verify the entire observed keyboard
            // canvas in that case; this branch does not attest draft typing
            // or session admission. Those remain independent physical gates.
            XCTAssertEqual(host.secureTextFields.count, 1)
            let canvasSize = host.secureTextFields.firstMatch.frame.size
            XCTAssertEqual(canvasSize.width, host.frame.width, accuracy: 1)
            XCTAssertGreaterThan(canvasSize.height, 150)
            let candidates = host.descendants(matching: .other).allElementsBoundByIndex.map(\.frame).filter {
                abs($0.width - canvasSize.width) < 1 && abs($0.height - canvasSize.height) < 1 &&
                    $0.minY > field.frame.maxY && host.frame.contains($0)
            }
            let canvas = try XCTUnwrap(candidates.first, "Expected the observed on-screen keyboard canvas")
            XCTAssertTrue(candidates.allSatisfy { $0 == canvas }, "The protected canvas position must be unambiguous")
            protectedDraftFrame = canvas.insetBy(dx: 8, dy: 8)
            print("QA_CAPTURE_DRAFT_INPUT=notObserved;protectedCanvas=observed")
        }
        let screenFrame = host.frame
        XCTAssertGreaterThan(protectedDraftFrame.width, 0)
        XCTAssertGreaterThan(protectedDraftFrame.height, 0)
        XCTAssertTrue(screenFrame.contains(protectedDraftFrame))
        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "QA protected keyboard capture"; attachment.lifetime = .keepAlways; add(attachment)
        // Check the exact area that displayed the known harmless draft before
        // capture. Normal visible glyphs/cursor have contrast; protected pixels
        // must form a uniform canvas. This is an actual physical capture, not a
        // simulated didTakeScreenshot notification or a screenshot API claim.
        let image = screenshot.image
        let imageRef = try XCTUnwrap(image.cgImage)
        // XCTest images may use scale=1 while carrying physical pixels.
        // Map the observed screen coordinates, rather than cropping an
        // unrelated uniform area using UIImage's presentation scale.
        let rect = protectedDraftFrame.applying(CGAffineTransform(
            scaleX: CGFloat(imageRef.width) / screenFrame.width,
            y: CGFloat(imageRef.height) / screenFrame.height))
        let region = try XCTUnwrap(imageRef.cropping(to: rect))
        var rgba = [UInt8](repeating: 0, count: region.width * region.height * 4)
        let bitmap = try XCTUnwrap(CGContext(data: &rgba, width: region.width, height: region.height,
            bitsPerComponent: 8, bytesPerRow: region.width * 4, space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        bitmap.draw(region, in: CGRect(x: 0, y: 0, width: region.width, height: region.height))
        for channel in 0..<3 {
            let samples = stride(from: channel, to: rgba.count, by: 4).map { Int(rgba[$0]) }
            XCTAssertLessThanOrEqual(try XCTUnwrap(samples.max()) - XCTUnwrap(samples.min()), 5,
                                    "Secret draft pixels must be hidden in the physical capture")
        }
        print("QA_PHYSICAL_CAPTURE=uniformProtectedCanvas")
    }

    /// Real Control Center recording. Secret keyboard controls remain hidden
    /// by capture protection; admission is checked separately from native trace.
    func testRecordingBlocksAndFreshAppReturnRecovers() throws {
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        let host = XCUIApplication()
        let board = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let capture = host.staticTexts["probe.capture.state"]
        func waitForCapture(_ value: String) -> Bool {
            XCTWaiter.wait(for: [XCTNSPredicateExpectation(
                predicate: NSPredicate(format: "label == %@", value), object: capture)], timeout: 10) == .completed
        }
        func recordingControl() -> XCUIElement {
            let start = host.coordinate(withNormalizedOffset: CGVector(dx: 0.99, dy: 0.001))
            start.press(forDuration: 0.1, thenDragTo:
                host.coordinate(withNormalizedOffset: CGVector(dx: 0.99, dy: 0.25)))
            let control = board.icons.matching(NSPredicate(format: "identifier IN %@",
                ["Grabación de pantalla", "Screen Recording", "Registrazione schermo"])).firstMatch
            // Require the recording control on the selected Control Center
            // page. Never guess a coordinate among personal Home controls.
            _ = control.waitForExistence(timeout: 5)
            return control
        }
        func stopIfCaptured() {
            host.activate()
            guard waitForCapture("captured") else { return }
            let control = recordingControl()
            if control.exists && control.isHittable { control.tap() }
            let stop = board.alerts.buttons.matching(NSPredicate(format: "label IN %@",
                ["Detener", "Stop", "Interrompi"])).firstMatch
            if stop.waitForExistence(timeout: 1) { stop.tap() }
            host.activate()
            _ = waitForCapture("notCaptured")
        }
        root.activate()
        sleep(10)
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        XCTAssertTrue(waitForCapture("notCaptured"), "Do not toggle a recording already started by somebody else")
        field.tap()
        selectKeyboard(in: host)
        XCTAssertEqual(host.secureTextFields.count, 1)
        // Allow the real app-owned delegation to finish. The independent
        // native verifier still requires runtimeReady + beginResponseGranted
        // before recording: elapsed time or a secure canvas never proves it.
        sleep(20)
        let control = recordingControl()
        XCTAssertTrue(control.exists && control.isHittable,
                      "Select Control Center Favorites with its Screen Recording control before this gate")
        var mustStop = true
        defer { if mustStop { stopIfCaptured() } }
        control.tap()
        sleep(5)
        host.activate()
        XCTAssertTrue(waitForCapture("captured"), "The actual host screen must be recorded")
        print("QA_RECORDING_HOST_SENSOR=captured")
        host.buttons["probe.transport.showKeyboard"].tap()
        XCTAssertEqual(host.secureTextFields.count, 1)
        sleep(3)
        XCTAssertEqual(capture.label, "captured")
        stopIfCaptured()
        XCTAssertTrue(waitForCapture("notCaptured"), "Recording must be stopped before app authorization")
        mustStop = false
        print("QA_RECORDING_HOST_SENSOR=notCaptured")
        root.activate()
        sleep(10)
        host.activate()
        field.tap()
        selectKeyboard(in: host)
        XCTAssertEqual(host.secureTextFields.count, 1)
        sleep(20)
        XCTAssertEqual(capture.label, "notCaptured")
        print("QA_RECORDING_UI=realStartStop;protectedCanvas;admissionRequiresNativeTrace")
    }

    /// Repeated warm/cold root handoffs with protection ON. The secure canvas
    /// conceals secret controls; admission and retirement require native trace.
    /// This is a bounded lifecycle observation, not a plaintext or memory pass.
    func testRepeatedProtectedHostHandoffs() {
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        let host = XCUIApplication()
        let clock = DateFormatter()
        clock.locale = Locale(identifier: "en_US_POSIX")
        clock.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        func mark(_ cycle: Int, _ phase: String) {
            print("QA_HANDOFF_CYCLE=\(cycle);phase=\(phase);time=\(clock.string(from: Date()))")
        }
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        let capture = host.staticTexts["probe.capture.state"]
        let stopped = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "label == %@", "notCaptured"), object: capture)
        XCTAssertEqual(XCTWaiter.wait(for: [stopped], timeout: 5), .completed)
        for cycle in 1...6 {
            mark(cycle, "started")
            // Alternate ordinary foregrounding with an actual cold app start.
            if cycle.isMultiple(of: 2) { root.terminate(); root.launch() }
            else { root.activate() }
            sleep(10)
            host.activate()
            field.tap()
            selectKeyboard(in: host)
            XCTAssertEqual(host.secureTextFields.count, 1,
                           "Keep capture protection ON throughout this gate")
            sleep(20)
            XCTAssertEqual(capture.label, "notCaptured")
            mark(cycle, "observed")
            let hide = host.buttons["probe.transport.hideKeyboard"]
            XCTAssertTrue(hide.isHittable); hide.tap()
            sleep(3)
            mark(cycle, "retired")
        }
        print("QA_HANDOFF_UI=6;warmAndCold;admissionAndRetirementRequireNativeTrace")
    }

    func testRestoreCrossAppPasteConfirmation() {
        let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
        settings.activate()
        // The app's protected canvas is intentionally not readable by XCTest.
        // Navigate the real Settings UI. This QA phone must have exactly one
        // installed app named Layergram; verify the bundle inventory first.
        let apps = settings.buttons["com.apple.settings.apps"]
        for _ in 0..<5 {
            if apps.exists { break }
            let back = settings.buttons["BackButton"]
            if !back.exists { break }
            back.tap()
        }
        for _ in 0..<12 {
            if apps.exists && apps.isHittable { break }
            settings.swipeUp()
        }
        XCTAssertTrue(apps.exists && apps.isHittable); apps.tap()
        let candidates = settings.buttons.matching(NSPredicate(format: "label == %@", "Layergram"))
        for _ in 0..<30 {
            if candidates.count == 1 && candidates.firstMatch.isHittable { break }
            settings.swipeUp()
        }
        XCTAssertEqual(candidates.count, 1, "Never select an ambiguous app Settings entry")
        XCTAssertTrue(candidates.firstMatch.isHittable); candidates.firstMatch.tap()
        let paste = settings.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Pegar desde otras apps")).firstMatch
        XCTAssertTrue(paste.waitForExistence(timeout: 15)); paste.tap()
        let ask = settings.descendants(matching: .any).matching(NSPredicate(format: "label == %@", "Preguntar")).firstMatch
        XCTAssertTrue(ask.waitForExistence(timeout: 5)); ask.tap()
        let selected = settings.cells.matching(NSPredicate(format: "label == %@", "Preguntar")).firstMatch
        XCTAssertTrue(selected.isSelected, "Restore the OS confirmation instead of relying on permanent paste permission")
        print("QA_CROSS_APP_PASTE_PREFERENCE=ask")
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
    }

    private func selectKeyboard(in host: XCUIApplication) {
        if host.textViews["layergram.draft"].exists || host.secureTextFields.count == 1 { return }
        let globe = host.buttons["Next keyboard"]
        XCTAssertTrue(globe.waitForExistence(timeout: 8),
                      "Enable the Layergram system keyboard on the QA device")
        globe.press(forDuration: 1)
        let row = host.cells.matching(NSPredicate(
            format: "label CONTAINS[c] %@", "Layergram"
        )).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.tap()
    }

    private func tapKey(_ character: String, in host: XCUIApplication) {
        let key = host.buttons.matching(NSPredicate(
            format: "identifier BEGINSWITH %@ AND label == %@",
            "layergram.key.text.", character
        )).firstMatch
        XCTAssertTrue(key.waitForExistence(timeout: 3),
                      "Missing visible keyboard key: \(character)")
        key.tap()
    }

    private func leavePreparedChat(in root: XCUIApplication) throws {
        // The Flutter app bar Back has no label on this physical iOS build.
        // Select its observed leading position, never the unlabeled banner X.
        let back = try XCTUnwrap(root.buttons.allElementsBoundByIndex.first {
            let frame = $0.frame
            return frame.minX < 20 && frame.minY < 120 && frame.width >= 40 && frame.height >= 40
        }, "Expected the app bar Back in the prepared contact chat")
        XCTAssertTrue(back.isHittable)
        back.tap()
    }

    private func assertActive(in host: XCUIApplication) {
        let status = host.staticTexts["layergram.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 8))
        print("QA_SESSION_STATUS=" + status.label)
        let live = NSPredicate { _, _ in
            ["activa", "attiva", "active", "Destinatario", "Recipient", "Cifrado pasado", "Encrypted text passed"].contains { status.label.contains($0) }
        }
        XCTAssertEqual(XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: live, object: nil)], timeout: 12), .completed,
                       "A visible draft alone does not prove an authorized session")
        assertCountdown(in: host)
    }

    private func assertCountdown(in host: XCUIApplication) {
        let countdown = host.staticTexts["layergram.window"]
        XCTAssertTrue(countdown.waitForExistence(timeout: 5))
        XCTAssertTrue(countdown.isHittable,
                      "Countdown must remain visible after contact confirmation")
        XCTAssertNotNil(countdown.label.range(of: #"[0-9]+s"#, options: .regularExpression),
                        "Only a running lease proves an active session")
    }

    private func assertCarrier(in field: XCUIElement) -> String {
        let present = NSPredicate { _, _ in
            let value = field.value as? String ?? ""
            return value.hasPrefix("p1.") || value.hasPrefix("m3.") || value.hasPrefix("b3.")
        }
        let insertion = XCTWaiter.wait(for: [XCTNSPredicateExpectation(
            predicate: present, object: nil)], timeout: 8)
        if insertion != .completed {
            let host = XCUIApplication()
            let status = host.staticTexts["layergram.status"]
            let value = field.value as? String ?? ""
            print("QA_INSERT_FAILURE_FIELD_UNITS=\(value.utf16.count);v3=\(value.contains("m3."));p1=\(value.contains("p1."));hittable=\(field.isHittable)")
            let draft = host.textViews["layergram.draft"]
            print("QA_INSERT_FAILURE_DRAFT_UNITS=\((draft.value as? String ?? "").utf16.count)")
            print("QA_INSERT_FAILURE_STATUS=" + (status.exists ? status.label : "absent"))
            print("QA_INSERT_FAILURE_STAGES=" + (status.exists ? status.value as? String ?? "none" : "absent"))
        }
        XCTAssertEqual(insertion, .completed,
            "Wait for the actual asynchronous insertion")
        let carrier = field.value as? String ?? ""
        XCTAssertFalse(carrier.isEmpty,
                       "Cifra e inserisci must insert an actual carrier")
        XCTAssertLessThanOrEqual(carrier.utf16.count, 4_000)
        XCTAssertTrue(carrier.contains("m3.") || carrier.hasPrefix("p1.") || carrier.hasPrefix("b3."),
                      "Expected a complete Layergram V3 text carrier")
        XCTAssertNil(carrier.range(of: #"\b[0-9]+/[0-9]+\b"#, options: .regularExpression))
        return carrier
    }

    func testContactCountdownAndConsecutiveExports() throws {
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        XCTAssertTrue(root.buttons.matching(NSPredicate(
            format: "label BEGINSWITH %@", "Mensajes"
        )).firstMatch.waitForExistence(timeout: 10),
                      "Prepare the unlocked disposable validation identity")

        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        field.tap()
        selectKeyboard(in: host)

        let draft = host.textViews["layergram.draft"]
        XCTAssertTrue(draft.waitForExistence(timeout: 8),
                      "A denied keyboard grant is a test failure")
        assertActive(in: host)
        host.buttons["layergram.action.recipient"].tap()
        let list = host.tables["layergram.contacts.list"]
        XCTAssertTrue(list.waitForExistence(timeout: 5))
        let contact = list.cells.containing(.staticText,
                                            identifier: contactName).firstMatch
        XCTAssertTrue(contact.waitForExistence(timeout: 5),
                      "Prepare the exact named QA contact; never pick another")
        contact.tap()
        let confirm = host.buttons["layergram.action.confirm"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 5))
        confirm.tap()

        let recipient = host.staticTexts["layergram.recipient.name"]
        XCTAssertTrue(recipient.waitForExistence(timeout: 5))
        XCTAssertTrue(recipient.label.contains(contactName))
        assertCountdown(in: host)

        for _ in 0..<8 { tapKey("a", in: host) }
        XCTAssertEqual(draft.value as? String, "aaaaaaaa")
        assertCountdown(in: host)
        host.buttons["layergram.action.clearDraft"].tap()
        XCTAssertTrue((draft.value as? String ?? "").isEmpty
                      || draft.value as? String == "Texto secreto")

        for key in ["p", "r", "o", "v", "a"] { tapKey(key, in: host) }
        XCTAssertEqual(draft.value as? String, "prova", "Every physical key must reach the secret field")
        XCTAssertTrue(host.buttons["layergram.action.primary"].isEnabled)
        host.buttons["layergram.action.primary"].tap()
        let first = assertCarrier(in: field)
        let carrierAttachment = XCTAttachment(string: first)
        carrierAttachment.name = "qa-first-v3-carrier"
        carrierAttachment.lifetime = .keepAlways
        add(carrierAttachment)
        assertActive(in: host)
        XCTAssertTrue(recipient.waitForExistence(timeout: 10))
        XCTAssertTrue(recipient.label.contains(contactName),
                      "Recipient must survive Cifra e inserisci")
        assertCountdown(in: host)

        let send = host.buttons["probe.transport.send"]
        XCTAssertTrue(send.exists)
        send.tap()
        XCTAssertTrue((field.value as? String ?? "").isEmpty)
        XCTAssertTrue(draft.waitForExistence(timeout: 5),
                      "Host send must not revoke the keyboard session")
        XCTAssertTrue(recipient.waitForExistence(timeout: 10))
        XCTAssertTrue(recipient.label.contains(contactName))

        for key in ["a", "l", "t", "r", "a"] { tapKey(key, in: host) }
        XCTAssertEqual(draft.value as? String, "altra", "The second draft must survive the host Send")
        XCTAssertTrue(host.buttons["layergram.action.primary"].isEnabled)
        host.buttons["layergram.action.primary"].tap()
        let second = assertCarrier(in: field)
        XCTAssertNotEqual(first, second)
        assertActive(in: host)
        assertCountdown(in: host)
        let label = recipient.label
        let active = label.contains("FS activa") || label.contains("FS attiva") || label.contains("FS active")
        let pending = label.contains("negocia") || label.contains("negozia") || label.contains("negotiat")
        XCTAssertTrue(active || pending, "The actual recipient shield must report FS state")
        print("QA_TRANSPORT_FS=" + (active ? "active" : "pending"))
        if let expected = ProcessInfo.processInfo.environment["LAYERGRAM_QA_EXPECT_FS"] {
            XCTAssertTrue(["active", "pending"].contains(expected))
            XCTAssertEqual(active ? "active" : "pending", expected)
        }
    }

    func testKeyboardChatArchiveContainsExactMessage() throws {
        guard let plaintext = ProcessInfo.processInfo.environment["LAYERGRAM_QA_HISTORY_PLAINTEXT"],
              !plaintext.isEmpty else {
            throw XCTSkip("Supply a unique plaintext from a passed keyboard exchange")
        }
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        let messages = root.buttons.matching(NSPredicate(
            format: "label BEGINSWITH %@", "Mensajes"
        )).firstMatch
        if !messages.waitForExistence(timeout: 3) {
            let header = root.descendants(matching: .any).matching(NSPredicate(
                format: "label BEGINSWITH %@", contactName + "\n"
            )).firstMatch
            XCTAssertTrue(header.exists, "Expected the prepared contact chat before navigating back")
            try leavePreparedChat(in: root)
        }
        XCTAssertTrue(messages.waitForExistence(timeout: 10))
        messages.tap()
        let row = root.descendants(matching: .any).matching(NSPredicate(
            format: "label BEGINSWITH %@", contactName + "\n"
        )).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10),
                      "The keyboard exchange must populate the correct app chat")
        row.tap()
        // Flutter message semantics are exposed as Other on physical iOS,
        // rather than StaticText. Still require the exact visible body.
        let message = root.descendants(matching: .any).matching(NSPredicate(
            format: "label == %@ OR label BEGINSWITH %@", plaintext, plaintext + "\n"
        )).firstMatch
        XCTAssertTrue(message.waitForExistence(timeout: 10),
                      "A keyboard preview is not proof of saved app history")
        XCTAssertTrue(message.isHittable, "The saved message must be visible in its chat")
        XCTAssertEqual(message.label.components(separatedBy: "\n").first, plaintext)
        print("QA_CHAT_ARCHIVE_EXACT_PLAINTEXT=present")
        try leavePreparedChat(in: root)
        XCTAssertTrue(messages.waitForExistence(timeout: 5))
    }

    func testIdleExpiryAndColdHandoffPreserveActiveFS() throws {
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        let messages = root.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Mensajes")).firstMatch
        XCTAssertTrue(messages.waitForExistence(timeout: 10))
        sleep(4)
        let host = XCUIApplication()
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        field.tap()
        selectKeyboard(in: host)
        assertActive(in: host)
        for character in "bozza" { tapKey(String(character), in: host) }
        let draft = host.textViews["layergram.draft"]
        XCTAssertEqual(draft.value as? String, "bozza")
        let countdown = host.staticTexts["layergram.window"]
        let expired = NSPredicate { _, _ in
            let remaining = countdown.exists ? countdown.label : ""
            let value = draft.exists ? draft.value as? String ?? "" : ""
            return remaining.range(of: #"[1-9][0-9]*s"#, options: .regularExpression) == nil && !value.contains("bozza")
        }
        XCTAssertEqual(XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: expired, object: nil)], timeout: 75), .completed,
                       "Idle expiry must end the grant and erase the draft")
        let hide = host.buttons["probe.transport.hideKeyboard"]
        XCTAssertTrue(hide.isHittable)
        hide.tap()
        root.terminate()
        root.launch()
        XCTAssertTrue(messages.waitForExistence(timeout: 15))
        sleep(4)
        host.activate()
        host.buttons["probe.transport.showKeyboard"].tap()
        selectKeyboard(in: host)
        assertActive(in: host)
        XCTAssertFalse((draft.value as? String ?? "").contains("bozza"))
        host.buttons["layergram.action.recipient"].tap()
        let list = host.tables["layergram.contacts.list"]
        XCTAssertTrue(list.waitForExistence(timeout: 5))
        let contact = list.cells.containing(.staticText, identifier: contactName).firstMatch
        XCTAssertTrue(contact.waitForExistence(timeout: 8))
        contact.tap()
        host.buttons["layergram.action.confirm"].tap()
        let recipient = host.staticTexts["layergram.recipient.name"]
        XCTAssertTrue(recipient.waitForExistence(timeout: 8))
        let phrase = "riaperturaverde"
        for character in phrase { tapKey(String(character), in: host) }
        XCTAssertEqual(draft.value as? String, phrase)
        host.buttons["layergram.action.primary"].tap()
        let carrier = assertCarrier(in: field)
        assertActive(in: host)
        XCTAssertTrue(recipient.label.contains(contactName))
        XCTAssertTrue(["FS activa", "FS attiva", "FS active"].contains { recipient.label.contains($0) },
                      "Idle expiry and a cold app start must preserve this active FS")
        let attachment = XCTAttachment(string: carrier)
        attachment.name = "qa-cold-return-v3-carrier"
        attachment.lifetime = .keepAlways
        add(attachment)
        print("QA_IDLE_COLD_HANDOFF=passed;FS=active")
    }

    func testEnableKeyboardBiometricResume() {
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        let settings = root.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Ajustes")).firstMatch
        XCTAssertTrue(settings.waitForExistence(timeout: 10))
        settings.tap()
        let toggle = root.switches.matching(NSPredicate(format: "label CONTAINS %@", "Reopen keyboard with biometrics")).firstMatch
        for _ in 0..<8 {
            if toggle.exists && toggle.isHittable { break }
            root.swipeUp()
        }
        XCTAssertTrue(toggle.exists && toggle.isHittable)
        if toggle.value as? String == "0" { toggle.tap() }
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let consent = springboard.alerts.matching(NSPredicate(format: "label CONTAINS[c] %@", "Face ID")).firstMatch
        if consent.waitForExistence(timeout: 2) {
            consent.buttons.matching(NSPredicate(format: "label IN %@", ["Allow", "Permitir", "Consenti"])).firstMatch.tap()
        }
        let on = NSPredicate { _, _ in toggle.value as? String == "1" }
        XCTAssertEqual(XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: on, object: nil)], timeout: 8), .completed)
        root.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Mensajes")).firstMatch.tap()
        print("QA_KEYBOARD_BIOMETRIC_PREFERENCE=enabled")
    }

    func testIncomingCarrierDisplaysPlaintextAfterOnePaste() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let carrier = environment["LAYERGRAM_QA_INCOMING_CARRIER"],
              let plaintext = environment["LAYERGRAM_QA_EXPECTED_PLAINTEXT"] else {
            throw XCTSkip("Supply a new carrier from the other disposable device")
        }
        XCTAssertLessThanOrEqual(carrier.utf16.count, 4_000)
        XCTAssertTrue(carrier.hasPrefix("p1.") || carrier.hasPrefix("m3.") || carrier.hasPrefix("b3."))
        XCTAssertFalse(plaintext.isEmpty)
        let root = XCUIApplication(bundleIdentifier: rootBundle)
        root.activate()
        XCTAssertTrue(root.buttons.matching(NSPredicate(
            format: "label BEGINSWITH %@", "Mensajes"
        )).firstMatch.waitForExistence(timeout: 10))
        let host = XCUIApplication()
        host.launchEnvironment["LAYERGRAM_QA_INCOMING_CARRIER"] = carrier
        host.launch()
        let field = host.textViews["probe.transport.field"]
        XCTAssertTrue(field.waitForExistence(timeout: 8))
        field.tap()
        selectKeyboard(in: host)
        assertActive(in: host)
        let copy = host.buttons["probe.transport.copyIncoming"]
        XCTAssertTrue(copy.waitForExistence(timeout: 5))
        XCTAssertTrue(copy.isEnabled, "Supply the bounded incoming test carrier")
        if environment["LAYERGRAM_QA_START_AFTER_IDLE"] == "YES" {
            let countdown = host.staticTexts["layergram.window"]
            let expired = NSPredicate { _, _ in
                !countdown.exists || countdown.label.range(of: #"[1-9][0-9]*s"#, options: .regularExpression) == nil
            }
            XCTAssertEqual(XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: expired, object: nil)], timeout: 75), .completed)
            print("QA_SINGLE_PASTE_STARTS_AFTER_IDLE=expired")
        }
        copy.tap()
        // Deliberately one paste only: retrying could hide the lost-action bug.
        let paste = host.descendants(matching: .any)["layergram.action.paste"].firstMatch
        XCTAssertTrue(paste.waitForExistence(timeout: 8))
        let enabled = NSPredicate { _, _ in paste.isEnabled }
        XCTAssertEqual(XCTWaiter.wait(for: [XCTNSPredicateExpectation(
            predicate: enabled, object: nil)], timeout: 5), .completed,
            "The system paste control must have a readable incoming carrier")
        paste.tap()
        // iOS can ask for cross-app paste even for a UIPasteControl inside an
        // extension. Consent is a separate OS action, never a second Paste tap.
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let allow = springboard.buttons.matching(NSPredicate(
            format: "label IN %@", ["Permitir pegar", "Allow Paste", "Consenti di incollare"]
        )).firstMatch
        if allow.waitForExistence(timeout: 2) { allow.tap() }
        let message = host.staticTexts.matching(NSPredicate(
            format: "label ENDSWITH %@", contactName + "\n" + plaintext
        )).firstMatch
        XCTAssertTrue(message.waitForExistence(timeout: environment["LAYERGRAM_QA_START_AFTER_IDLE"] == "YES" ? 45 : 15),
                      "A success status must include the authenticated preview")
        // One accessible label contains the sender heading, a newline, then
        // the message body. Compare the entire body, including its newlines.
        let lines = message.label.components(separatedBy: "\n")
        XCTAssertEqual(lines.dropFirst().joined(separator: "\n"), plaintext,
                       "The exact authenticated plaintext must be visible")
        XCTAssertTrue(lines.first?.hasSuffix(contactName) == true,
                      "The preview must belong to the prepared QA sender")
        XCTAssertTrue(host.buttons["layergram.action.sender"].exists,
                      "Reply must bind the authenticated sender")
        assertCountdown(in: host)
        if let replyText = environment["LAYERGRAM_QA_REPLY_TEXT"], !replyText.isEmpty {
            host.buttons["layergram.action.sender"].tap()
            // Reply is already an explicit confirmation of the authenticated
            // sender; the owner still has to return its accepted selection.
            let selected = host.staticTexts["layergram.recipient.name"]
            let selectedReady = selected.waitForExistence(timeout: 8)
            if !selectedReady {
                let status = host.staticTexts["layergram.status"]
                print("QA_AFTER_REPLY_STATUS=" + (status.exists ? status.label : "absent"))
                print("QA_AFTER_REPLY_STAGES=" + (status.exists ? status.value as? String ?? "none" : "absent"))
            }
            XCTAssertTrue(selectedReady,
                          "Reply must retain the authenticated recipient and session")
            XCTAssertTrue(selected.label.contains(contactName))
            assertCountdown(in: host)
            let draft = host.textViews["layergram.draft"]
            XCTAssertTrue(draft.waitForExistence(timeout: 5))
            for character in replyText { tapKey(String(character), in: host) }
            XCTAssertEqual(draft.value as? String, replyText, "Every physical reply key must reach the secret field")
            XCTAssertTrue(host.buttons["layergram.action.primary"].isEnabled)
            host.buttons["layergram.action.primary"].tap()
            let reply = assertCarrier(in: field)
            let attachment = XCTAttachment(string: reply)
            attachment.name = "QA outgoing reply carrier"
            attachment.lifetime = .keepAlways
            add(attachment)
            assertCountdown(in: host)
            let recipient = host.staticTexts["layergram.recipient.name"]
            XCTAssertTrue(recipient.waitForExistence(timeout: 10))
            let label = recipient.label
            let active = label.contains("FS activa") || label.contains("FS attiva") || label.contains("FS active")
            let pending = label.contains("negocia") || label.contains("negozia") || label.contains("negotiat")
            XCTAssertTrue(active || pending, "The actual recipient shield must report FS state")
            print("QA_TRANSPORT_FS=" + (active ? "active" : "pending"))
            if let expected = environment["LAYERGRAM_QA_EXPECT_FS"] {
                XCTAssertTrue(["active", "pending"].contains(expected))
                XCTAssertEqual(active ? "active" : "pending", expected,
                               "The final exchange must reach the requested real FS shield")
            }
        }
    }
}
