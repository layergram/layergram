import UIKit

@main
final class ClipboardBridge: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let documents = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        )[0]
        let payloadFile = documents.appendingPathComponent("carrier.txt")
        if let payload = try? String(contentsOf: payloadFile, encoding: .utf8) {
            UIPasteboard.general.string = payload
            try? FileManager.default.removeItem(at: payloadFile)
        }

        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = UIViewController()
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}
