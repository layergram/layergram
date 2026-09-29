#if LAYERGRAM_AUTONOMOUS_KEYBOARD
import CoreFoundation
import Darwin
import Flutter
import SystemKeyboardCore
import UIKit
import os.log
import QuartzCore

/// Authority is already revoked before this bounded resource-only handshake.
/// Give Dart a chance to dispose its native handles before destroying its VM
/// context. A stalled isolate must not retain the engine indefinitely.
enum KeyboardRuntimeTeardown {
    static func begin(requestClose: (@escaping () -> Void) -> Void,
                      scheduleTimeout: (@escaping () -> Void) -> Void,
                      destroy: @escaping () -> Void) {
        var completed = false
        let finish = {
            guard !completed else { return }
            completed = true
            destroy()
        }
        scheduleTimeout(finish)
        requestClose(finish)
    }
}

/// One headless engine and one live custody grant. Confined to the main thread.
/// No plugin registrant, app launch, network, identity vault or host text access.
final class KeyboardRuntimeBridge {
    private let snapshot: () -> KeyboardEditorSnapshot
    private let custody: KeyboardCustodyStore
    private let authorization: KeyboardAutonomousSession
    private var configuration: [String: Any]?
    private var engine: FlutterEngine?
    private var channel: FlutterMethodChannel?
    private var timer: Timer?
    private var startCompletion: ((Bool) -> Void)?
    private var started = false
    private var ready = false
    private var closed = false
    private var generation: UInt64 = 0
    private var activityCount = 0
    private(set) var lastClosureWasIdle = false
    var onClosed: (() -> Void)?

    private func trace(_ code: String) {
        #if LAYERGRAM_KEYBOARD_TRACE
        os_log("LayergramKeyboardTrace %{public}@", log: .default, type: .info, code)
        #endif
    }

    private func traceMemory(_ phase: String) {
        #if LAYERGRAM_KEYBOARD_TRACE
        trace("memory_\(phase)_available\(os_proc_available_memory() / 1_048_576)MB")
        #endif
    }

    #if LAYERGRAM_KEYBOARD_TRACE
    private func traceSlow(_ phase: String, since start: CFTimeInterval) {
        let millis = Int((CACurrentMediaTime() - start) * 1_000)
        if millis >= 16 { trace("slow_\(phase)_\(millis)ms") }
    }
    #endif

    init(groupIdentifier: String, epoch: Data, key: Data,
         configuration: [String: Any], snapshot: @escaping () -> KeyboardEditorSnapshot,
         custodyDirectoryName: String = KeyboardCustodyStore.directoryName,
         mirrorAccount: String = "v3-working-state") throws {
        guard let duration = Self.integer(configuration["idleMillis"]), duration > 0,
              duration <= 300_000,
              let configEpoch = configuration["epoch"] as? FlutterStandardTypedData,
              configEpoch.data == epoch,
              let authorization = KeyboardAutonomousSession(snapshot: snapshot(), authorizedIdleMillis: duration)
        else { throw KeyboardCustodyStore.Failure.invalidInput }
        let storage = try MailboxStorage(appGroupIdentifier: groupIdentifier,
                                        directoryName: custodyDirectoryName)
        custody = try KeyboardCustodyStore(
            storage: storage, epoch: epoch, key: key,
            mirror: KeyboardKeychainCustodyMirror(group: groupIdentifier,
                                                  epoch: epoch, account: mirrorAccount))
        self.authorization = authorization
        self.configuration = configuration
        self.snapshot = snapshot
        guard custody.isKeyboardCustodian() else {
            custody.close()
            throw KeyboardCustodyStore.Failure.revoked
        }
    }

    var deadlineMonotonicMillis: Int64 { authorization.deadlineMonotonicMillis }
    var isReady: Bool { ready && !closed }

    /// Polls prove native admission only. They NEVER renew inactivity.
    @discardableResult func validate() -> Bool {
        #if LAYERGRAM_KEYBOARD_TRACE
        let startedAt = CACurrentMediaTime()
        defer { traceSlow("validate", since: startedAt) }
        #endif
        guard !closed else { return false }
        guard authorization.validate(snapshot(), hasCustody: custody.isKeyboardCustodian()) else {
            trace("authorization_\(authorization.lastValidationFailure?.rawValue ?? "unknown")")
            lastClosureWasIdle = authorization.lastValidationFailure == .idleExpired
            close(); return false
        }
        return true
    }

    func start(completion: @escaping (Bool) -> Void) {
        guard !started, validate(), let bundle = Self.dartBundle() else {
            completion(false); close(); return
        }
        started = true
        startCompletion = completion
        traceMemory("beforeEngine")
        let engine = FlutterEngine(name: "layergram.keyboard.runtime",
                                   project: FlutterDartProject(precompiledDartBundle: bundle),
                                   allowHeadlessExecution: true)
        self.engine = engine
        guard engine.run(withEntrypoint: "layergramKeyboardMain") else {
            close(); return
        }
        traceMemory("afterEngine")
        // Flutter requires run() before installing a platform message handler.
        let channel = FlutterMethodChannel(name: "layergram/keyboard_runtime", binaryMessenger: engine.binaryMessenger)
        self.channel = channel
        channel.setMethodCallHandler { [weak self] call, result in
            guard let self else { result(FlutterError(code: "unavailable", message: nil, details: nil)); return }
            self.handle(call, result: result)
        }
        let timer = Timer(timeInterval: 0.25, repeats: true) { [weak self] _ in _ = self?.validate() }
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    /// Invoke only for an actual physical touch on this keyboard. A request,
    /// heartbeat, timer, rendering callback or programmatic edit must not call it.
    @discardableResult func recordUserInteraction() -> Bool {
        #if LAYERGRAM_KEYBOARD_TRACE
        let startedAt = CACurrentMediaTime()
        defer { traceSlow("touch", since: startedAt) }
        #endif
        guard isReady, validate(),
              authorization.recordUserInteraction(snapshot(), hasCustody: custody.isKeyboardCustodian()) else {
            trace("activityRejected")
            return false
        }
        activityCount += 1
        if activityCount == 1 || activityCount % 10 == 0 { trace("activityAccepted") }
        let captured = generation
        channel?.invokeMethod("activity", arguments: nil) { [weak self] result in
            guard let self, !self.closed, self.generation == captured else { return }
            guard result as? Bool == true else { self.trace("activityReplyRejected"); self.close(); return }
            guard self.validate() else { return }
        }
        return true
    }

    func request(_ bytes: Data, completion: @escaping (Data?) -> Void) {
        guard isReady, validate(), bytes.count <= MailboxConstants.maxPlaintextBytes,
              let arguments = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let channel else { completion(nil); return }
        traceMemory("beforeRequest")
        let captured = generation
        channel.invokeMethod("request", arguments: arguments) { [weak self] raw in
            self?.traceMemory("afterRequest")
            guard let self, !self.closed, self.generation == captured,
                  self.validate(), let reply = raw as? [String: Any],
                  JSONSerialization.isValidJSONObject(reply),
                  let bytes = try? JSONSerialization.data(withJSONObject: reply),
                  bytes.count <= MailboxConstants.maxPlaintextBytes else { completion(nil); return }
            completion(bytes)
        }
    }

    /// The host editor changed while the keyboard remains visible. The native
    /// custody/idle grant is checked but never renewed; Dart discards the old
    /// selection and pending editor state before a fresh `begin`.
    func rebind(editorNonce: String, completion: @escaping (Bool) -> Void) {
        guard isReady, validate(), !editorNonce.isEmpty,
              editorNonce.utf16.count <= 128, let channel else {
            completion(false); return
        }
        let captured = generation
        channel.invokeMethod("rebind", arguments: ["editorNonce": editorNonce]) { [weak self] raw in
            guard let self, !self.closed, self.generation == captured,
                  raw as? Bool == true, self.validate() else {
                completion(false); return
            }
            completion(true)
        }
    }

    /// Drop authorization synchronously before waiting for any Dart cleanup.
    /// The encrypted working state remains for the app's crash-safe reclaim.
    func close() {
        guard !closed else { return }
        trace("runtimeClose")
        closed = true
        ready = false
        generation &+= 1
        authorization.revoke()
        custody.close()
        configuration = nil
        timer?.invalidate()
        timer = nil
        let completion = startCompletion
        startCompletion = nil
        completion?(false)
        let previousChannel = channel
        channel = nil
        // Cleanup may still send a native check/closed callback. Deny every
        // operation immediately; this handler owns no key, custody or grant.
        previousChannel?.setMethodCallHandler { _, result in
            result(FlutterError(code: "unavailable", message: nil, details: nil))
        }
        let previousEngine = engine
        engine = nil
        // Do not destroy the messenger in the middle of its own inbound call.
        DispatchQueue.main.async {
            Self.disposeEngine(previousEngine, channel: previousChannel)
        }
        onClosed?()
        onClosed = nil
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        if call.method == "closed" {
            trace("dartClosed")
            if !authorization.validate(snapshot(), hasCustody: custody.isKeyboardCustodian()) {
                lastClosureWasIdle = authorization.lastValidationFailure == .idleExpired
            }
            result(nil); close(); return
        }
        guard validate() else { result(FlutterError(code: "unavailable", message: nil, details: nil)); return }
        do {
            switch call.method {
            case "diagnosticStage":
                #if LAYERGRAM_KEYBOARD_TRACE
                let allowed: Set<String> = ["fragmentAccepted", "fragmentDuplicate", "committedReplay",
                    "responsePrepared", "sessionEstablished", "addressedElsewhere", "initiatorProofRejected",
                    "responderProofRejected", "transcriptMismatch", "deviceMismatch", "resetRejected", "malformed"]
                if let stage = call.arguments as? String, allowed.contains(stage) {
                    trace("protocol_\(stage)")
                }
                #endif
                result(nil)
            case "ready":
                guard !ready, let configuration, let channel else {
                    throw KeyboardCustodyStore.Failure.conflict
                }
                self.configuration = nil
                result(nil)
                let captured = generation
                channel.invokeMethod("start", arguments: configuration) { [weak self] accepted in
                    guard let self, !self.closed, self.generation == captured else { return }
                    guard accepted as? Bool == true, self.validate() else { self.close(); return }
                    self.ready = true
                    self.traceMemory("ready")
                    let completion = self.startCompletion
                    self.startCompletion = nil
                    completion?(true)
                }
            case "check": result(validate())
            case "load":
                let loaded = try custody.loadForKeyboard()
                guard validate() else { throw KeyboardCustodyStore.Failure.revoked }
                result(["revision": loaded.revision, "snapshot": FlutterStandardTypedData(bytes: loaded.plaintext)])
            case "commit":
                guard let args = call.arguments as? [String: Any], args.count == 2,
                      let bytes = args["snapshot"] as? FlutterStandardTypedData,
                      let revision = Self.integer(args["revision"]), revision >= 0 else {
                    throw KeyboardCustodyStore.Failure.invalidInput
                }
                let next = try custody.commitForKeyboard(bytes.data, expectedRevision: UInt64(revision))
                guard validate() else { throw KeyboardCustodyStore.Failure.revoked }
                result(next)
            default: throw KeyboardCustodyStore.Failure.invalidInput
            }
        } catch {
            result(FlutterError(code: "unavailable", message: nil, details: nil))
            close()
        }
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue >= 0,
              number.doubleValue <= 9_007_199_254_740_991,
              number.doubleValue == Double(number.int64Value) else { return nil }
        return number.int64Value
    }

    private static func dartBundle() -> Bundle? {
        // In the extension the shared AOT bundle belongs to its containing app.
        // Native integration tests load this same bridge inside that app.
        let main = Bundle.main.bundleURL
        let app = main.pathExtension == "appex"
            ? main.deletingLastPathComponent().deletingLastPathComponent() : main
        guard let bundle = Bundle(url: app.appendingPathComponent("Frameworks/App.framework")),
              bundle.bundleIdentifier == "io.flutter.flutter.app" else { return nil }
        return bundle
    }

    private static func disposeEngine(_ engine: FlutterEngine?, channel: FlutterMethodChannel?) {
        guard let engine else { return }
        KeyboardRuntimeTeardown.begin(requestClose: { completed in
            guard let channel else { completed(); return }
            channel.invokeMethod("close", arguments: nil) { _ in completed() }
        }, scheduleTimeout: { completed in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: completed)
        }, destroy: {
            channel?.setMethodCallHandler(nil)
            engine.destroyContext()
            #if LAYERGRAM_KEYBOARD_TRACE
            os_log("LayergramKeyboardTrace engineContextDestroyed_available%{public}lluMB", log: .default,
                   type: .info, UInt64(os_proc_available_memory() / 1_048_576))
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak engine] in
                os_log("LayergramKeyboardTrace %{public}@", log: .default, type: .info,
                       engine == nil ? "engineWrapperReleased" : "engineWrapperRetained")
            }
            #endif
        })
    }

    deinit {
        trace("runtimeBridgeDeinit")
        timer?.invalidate()
        custody.close()
        channel?.setMethodCallHandler { _, result in
            result(FlutterError(code: "unavailable", message: nil, details: nil))
        }
        let previousEngine = engine
        let previousChannel = channel
        DispatchQueue.main.async {
            Self.disposeEngine(previousEngine, channel: previousChannel)
        }
    }
}
#endif
