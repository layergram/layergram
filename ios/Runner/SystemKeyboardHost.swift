import CoreFoundation
import Flutter
import SystemKeyboardCore
import UIKit
import os.log

/// Sole native bridge to the existing Flutter owner. No engine, vault or identity
/// is created here. The extension cannot start or renew this finite window.
final class SystemKeyboardHost {
  private func traceHost(_ code: String) {
    os_log("LayergramHostTrace %{public}@", log: .default, type: .info, code)
    #if LAYERGRAM_KEYBOARD_TRACE
    if let groupIdentifier, let traceDefaults = UserDefaults(suiteName: groupIdentifier) {
      var stages = traceDefaults.stringArray(forKey: "fixtureHostStages") ?? []
      stages.append(code)
      traceDefaults.set(Array(stages.suffix(20)), forKey: "fixtureHostStages")
    }
    #endif
  }
  private let channel: FlutterMethodChannel
  private var custodyChannel: SystemKeyboardCustodyChannel?
  private let defaults: UserDefaults
  private let groupIdentifier: String?
  private let isEmbedded: Bool
  private let mailboxDirectoryName: String
  private let captureActive: () -> Bool
  private var configured = false
  private var departed = false
  private var departureDenied = true
  private var autonomousHandoffNonce: String?
  // Volatile delivery of the single already-consumed grant. Only the pinned
  // mailbox client and exact editor nonce may obtain it through a fresh lease;
  // no second custody activation occurs. ACK, expiry or revocation drops it.
  private var autonomousHandoffReply: [String: Any]?
  private var epoch: UInt64 = 0
  private var owner: MailboxOwner?
  private var timer: Timer?
  // A stalled merged Flutter/platform thread must not make an otherwise valid
  // bootstrap look revoked. The worker can answer only busy/unavailable; all
  // grants, custody admission and lifecycle decisions remain on the main thread.
  private let mailboxLock = NSRecursiveLock()
  private let busyQueue = DispatchQueue(label: "layergram.keyboard.bootstrap.busy")
  private var busyTimer: DispatchSourceTimer?
  private var lastMainPollMillis: Int64 = 0
  private var autonomousBootstrapAttempted = false
  private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
  private var waiting = false
  private var observers: [NSObjectProtocol] = []
  private static let enabledKey = "system_keyboard_enabled"
  init(messenger: FlutterBinaryMessenger, bundle: Bundle = .main,
       defaults: UserDefaults = .standard,
       mailboxDirectoryName: String = MailboxConstants.directoryName,
       custodyDirectoryName: String = KeyboardCustodyStore.directoryName,
       captureActive: @escaping () -> Bool = { UIScreen.main.isCaptured }) {
    self.defaults = defaults
    self.mailboxDirectoryName = mailboxDirectoryName
    self.captureActive = captureActive
    groupIdentifier = bundle.object(forInfoDictionaryKey: "KeyboardAppGroupId") as? String
    isEmbedded = bundle.builtInPlugInsURL.map {
      FileManager.default.fileExists(atPath:
        $0.appendingPathComponent("LayergramKeyboard.appex/Info.plist").path)
    } ?? false
    channel = FlutterMethodChannel(name: "layergram/system_keyboard", binaryMessenger: messenger)
    channel.setMethodCallHandler { [weak self] call, result in
      guard let self else { result(false); return }
      self.mailboxLock.lock()
      defer { self.mailboxLock.unlock() }
      switch call.method {
      case "readEnabled":
        result(MailboxCryptoAvailability.isSupported && self.isEmbedded && self.defaults.bool(forKey: Self.enabledKey))
      case "configure":
        guard let args = call.arguments as? [String: Any],
              let enabled = args["enabled"] as? Bool else { result(false); return }
        self.revoke()
        let accepted = !enabled || (MailboxCryptoAvailability.isSupported && self.isEmbedded && self.groupIdentifier != nil)
        self.configured = enabled && accepted
        self.traceHost(self.configured ? "configuredOn" : "configuredOff")
        self.defaults.set(self.configured, forKey: Self.enabledKey)
        result(accepted)
      case "revoke":
        self.revoke()
        result(nil)
      #if LAYERGRAM_KEYBOARD_TRACE
      case "diagnosticStage":
        let allowed: Set<String> = [
          "prepareUnavailableOrAttempted", "prepareAdmissionDenied", "prepareStarted",
          "prepareCompleted", "prepareFailed", "prepareFailedState", "prepareFailedFormat",
          "prepareFailedPlatform", "prepareFailedOther", "closureAdmissionDenied", "closureNoIdentity",
          "closureRuntimeLoad", "closureRuntimeUnavailable", "closureRuntimeReady",
          "closureContactContextStart", "closureContactContextReady", "closureContactReadStart", "closureContactReadReady",
          "closureContactsAdmissionDenied", "closureContactsChanged", "closureNoUsableContacts",
          "closureContactsReady", "closureNoContext", "closureContextAdmissionDenied",
          "closureCustodyPrepare", "closureCustodyReady", "delegateNoCoordinator",
          "delegateNoIdentity", "delegateAdmissionDenied", "delegateGranted",
          "delegatePipelinePreparing", "delegateGrantMissing",
          "delegateClockUnavailable", "delegateServiceDisposed",
          "delegateServiceNotStarted", "delegateInvalidRequest",
          "runtimeProviderBegin", "runtimeIdentityLoadStart",
          "runtimeIdentityLoadReady", "runtimeContextStart",
          "runtimeContextReady", "runtimeProjectionKeyStart",
          "runtimeProjectionKeyReady", "runtimeHistoryContextStart",
          "runtimeHistoryContextReady", "runtimeHistoryLeaseStart",
          "runtimeHistoryLeaseReady", "runtimeOwnerOpenStart",
          "runtimeOwnerOpenReady", "runtimeMaintainStart",
          "runtimeMaintainReady", "runtimeHistoryKeyStart",
          "runtimeHistoryKeyReady", "runtimeHistoryRestoreStart",
          "runtimeHistoryRestoreReady", "runtimeHistoryReconcileStart",
          "runtimeHistoryReconcileReady", "runtimeProviderReady",
          "runtimeOwnerQueued", "runtimeOwnerEntered",
          "runtimeOwnerReused", "runtimeOwnerCloseStart",
          "runtimeOwnerCloseReady", "runtimeOwnerIdentityStart",
          "runtimeOwnerIdentityReady", "runtimeOwnerFactoryStart",
          "runtimeOwnerFactoryReady", "runtimeOwnerFactoryFailed",
          "runtimeOwnerSuperseded", "runtimeFactoryCustodyStart",
          "runtimeFactoryCustodyReady", "runtimeFactorySessionStart",
          "runtimeFactorySessionReady", "custodyGateEntered",
          "custodyKeyStart", "custodyKeyReady", "custodyRecoverStart",
          "custodyRecoverReady", "custodyMissingFailure",
          "custodyFormatFailure", "custodyStateFailure",
          "custodyOtherFailure", "custodyReadStart", "custodyReadReady",
          "custodyResetReceipt", "custodyNoJournal",
          "custodyImportReceipt", "custodyAmbiguousJournal",
          "custodyMarkerPresent", "custodyMarkerParsed",
          "custodyNativeReclaimStart", "custodyNativeReclaimReady",
          "custodyNativeMissing", "custodyReplacedManifestRecovered",
          "custodyUnpreparedRecovered", "custodyDelegateMarkerReady",
          "custodyDelegateKeyStart", "custodyDelegateKeyReady", "custodyDelegateIdentityReady",
          "custodyDelegateRuntimeClosed", "custodyDelegateEntered", "custodyDelegateNativePending",
          "custodyDelegateJournalPresent", "custodyDelegateWorkingSetEmpty",
          "custodyLegacyFramesRecovered",
          "custodyDelegateNativePrepareStart", "custodyDelegateNativePrepareReady",
          "custodyDelegateReceiptReady", "custodyDelegateSourcesRemoved",
          "custodyDelegateActivateStart", "custodyDelegateActivateReady",
          "custodyReplacedManifestUnproven", "custodyBaselineRecovered",
          "custodyIntactBaselineWithManifest",
          "custodyManifestReady", "custodyManifestApplied",
          "custodyCleanupReady", "custodyHistoryUnavailable",
          "custodyAbsentShapeMismatch", "custodyOneAbsentRecord",
          "custodyRetainedNone", "custodyRetainedOne", "custodyRetainedMultiple",
          "custodyAbsentDeviceKey", "custodyAbsentCheckpoint",
          "custodyAbsentManifest", "custodyAbsentHandshake",
          "custodyAbsentHistoryMissing", "custodyAbsentOther",
          "custodyAbsentCompletion", "custodyAbsentFrame",
          "custodyAbsentFrameDone", "custodyAbsentHandoff",
          "custodyAbsentLmfEffect", "custodyAbsentLmfOut",
          "custodyAbsentLmfIn", "custodyAbsentLmfDone",
          "custodyAbsentLmfReplay", "custodyAbsentSendGroup",
          "custodyAbsentApplicationRecord", "custodyAbsentAckOutbox",
          "custodyAbsentSendEffect", "custodyAbsentSendCompletion",
          "custodyAbsentKeyboardHistory", "custodyAbsentControlOutbox",
          "custodyDeletedManifestUnavailable", "custodyDeletedManifestReady",
          "custodyOldRevisionInvalid", "custodyOriginalDigestMismatch",
          "custodyNewManifestShapeMismatch", "custodyNewRevisionInvalid",
          "custodyExtraNone", "custodyExtraMultiple",
          "custodyExtraCheckpoint", "custodyExtraHandshake",
          "custodyExtraHistory", "custodyExtraManifestInvalid",
          "custodyExtraOther",
          "custodyFinalReceiptChanged", "historyScopeUnavailable",
          "resetActionEntered", "resetActionRuntimeClosed",
          "resetActionKeyReady", "resetActionProbeStart",
          "resetActionLossConfirmed", "resetActionLossNotConfirmed",
          "resetActionCommitStart", "resetActionCommitReady",
          "resetActionReopenStart", "resetActionReopenReady",
          "resetActionReopenFailed",
          "resetProbeReadStart", "resetProbeJournalNotEligible",
          "resetProbeBaselineLost", "resetProbeBaselineIntact",
          "resetCommitReadStart", "resetCommitRepairBlocked",
          "resetCommitResumeReceipt", "resetCommitJournalBlocked",
          "resetCommitPreparedBlocked", "resetCommitNativeCheck",
          "resetCommitNativeRecoverable", "resetCommitBaselineRecoverable",
          "resetCommitOtherProtocolBlocked", "resetCommitReceiptStart",
          "resetCommitReceiptReady", "resetCommitFinished",
          "resetCandidateNoExtra", "resetCandidateOneManifest",
          "resetCandidateMultipleExtras", "resetCandidateOtherExtra",
          "resetCandidateUnknown", "resetCandidateHasCheckpoint",
          "resetCandidateOnlyPending", "resetCandidateHasOtherWorkingState",
          "historyRecordStillPresent", "historyPathUnavailable",
          "historyFileOversize", "historyFrameInvalid",
          "historyDeletedFrameFound", "historyDeletedFrameAbsent",
          "historyReadError", "historyDecryptFailed",
          "historyDecryptReady", "historyRepositoryError"
        ]
        guard let stage = call.arguments as? String, allowed.contains(stage) else {
          result(false); return
        }
        self.traceHost("service_\(stage)")
        result(true)
      #endif
      case "openSettings":
        guard let url = URL(string: UIApplication.openSettingsURLString) else {
          result(false); return
        }
        UIApplication.shared.open(url, options: [:]) { result($0) }
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    custodyChannel = SystemKeyboardCustodyChannel(
      messenger: messenger, groupIdentifier: groupIdentifier, embedded: isEmbedded,
      directoryName: custodyDirectoryName,
      canDelegate: { [weak self] in self?.canDelegateCustody == true })
    custodyChannel?.revoke()
    observers.append(NotificationCenter.default.addObserver(
      forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
      object: nil, queue: .main
    ) { [weak self] _ in self?.revoke() })
    observers.append(NotificationCenter.default.addObserver(
      forName: UIScreen.capturedDidChangeNotification,
      object: nil, queue: .main
    ) { [weak self] _ in
      guard let self else { return }
      // The notification also fires when recording stops. A late "stopped"
      // event must not revoke a fresh, uncaptured departure window.
      if self.captureActive() { self.revoke() }
    })
  }

  private var canDelegateCustody: Bool {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    guard let info = owner?.windowInfo,
          MailboxClock.system().monotonicMillis < info.deadlineMonotonicMillis else { return false }
    let screens = UIApplication.shared.connectedScenes.compactMap { ($0 as? UIWindowScene)?.screen }
    return configured && departed && !departureDenied && autonomousHandoffNonce == nil &&
      !captureActive() &&
      !screens.isEmpty && screens.allSatisfy { !$0.isCaptured }
  }

  /// Called before the scene leaves the foreground. Repeated inactive/background
  /// notifications cannot extend or reopen this departure's window.
  func willResignActive() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    traceHost("willResignActive")
    guard !departed else { traceHost("alreadyDeparted"); return }
    departed = true
    guard configured else { traceHost("notConfigured"); return }
    guard isEmbedded else { traceHost("notEmbedded"); return }
    guard UIApplication.shared.isProtectedDataAvailable else { traceHost("protectedDataUnavailable"); return }
    guard !captureActive() else { traceHost("screenCaptured"); return }
    guard let groupIdentifier else { traceHost("noAppGroup"); return }
    revoke()
    backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "Keyboard session") {
      [weak self] in self?.bootstrapExpired()
    }
    guard backgroundTask != .invalid else { traceHost("backgroundTaskUnavailable"); return }
    do {
      let storage = try MailboxStorage(appGroupIdentifier: groupIdentifier, directoryName: mailboxDirectoryName)
      let mailbox = MailboxOwner(storage: storage)
      try mailbox.openWindow()
      owner = mailbox
      traceHost("windowOpened")
      departureDenied = false
      autonomousHandoffNonce = nil
      let poll = Timer(timeInterval: 0.05, repeats: true) { [weak self] _ in self?.poll() }
      timer = poll
      RunLoop.main.add(poll, forMode: .common)
      lastMainPollMillis = MailboxClock.system().monotonicMillis
      let busyPoll = DispatchSource.makeTimerSource(queue: busyQueue)
      busyPoll.schedule(deadline: .now() + .milliseconds(50), repeating: .milliseconds(50))
      busyPoll.setEventHandler { [weak self] in self?.pollBusyWhileMainStalled() }
      busyTimer = busyPoll
      busyPoll.resume()
    } catch {
      traceHost("windowOpenFailed")
      revoke()
    }
  }

  func didBecomeActive() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    traceHost("didBecomeActive")
    revoke()
    departed = false
  }

  func disconnect() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    departed = true
    configured = false
    revoke()
    channel.setMethodCallHandler(nil)
  }

  private func poll() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    lastMainPollMillis = MailboxClock.system().monotonicMillis
    guard let owner, let info = owner.windowInfo else { bootstrapExpired(); return }
    guard configured, departed,
          UIApplication.shared.isProtectedDataAvailable,
          !captureActive() else { revoke(); return }
    guard MailboxClock.system().monotonicMillis < info.deadlineMonotonicMillis else {
      bootstrapExpired(); return
    }
    guard !waiting, !owner.hasLivePendingRequest else { return }
    do {
      guard case .request(let pending) = try owner.pollRequest() else { return }
      guard let request = try JSONSerialization.jsonObject(with: pending.payload) as? [String: Any]
      else { revoke(); return }
      if request["operation"] as? String == "delegateAck",
         let nonce = autonomousHandoffNonce, request["editorNonce"] as? String == nonce {
        closeBootstrap()
        return
      }
      if request["operation"] as? String == "delegate", let cached = autonomousHandoffReply {
        guard request["editorNonce"] as? String == autonomousHandoffNonce else { revoke(); return }
        let delivered = try owner.respondIfFresh(to: pending, payload: JSONSerialization.data(withJSONObject: cached))
        traceHost(delivered ? "delegateRedeliveredFreshLease" : "delegateDeliveryLeaseMissed")
        return
      }
      let capturedEpoch = epoch
      waiting = true
      if request["operation"] as? String == "delegate" {
        autonomousBootstrapAttempted = true
        traceHost("delegateForwarded")
      }
      channel.invokeMethod("request", arguments: request) { [weak self, weak owner] raw in
        guard let self, let owner else { return }
        self.mailboxLock.lock()
        defer { self.mailboxLock.unlock() }
        guard
              self.epoch == capturedEpoch, self.owner === owner else { return }
        self.waiting = false
        guard self.configured, self.departed,
              UIApplication.shared.isProtectedDataAvailable,
              !self.captureActive(),
              let info = owner.windowInfo,
              MailboxClock.system().monotonicMillis < info.deadlineMonotonicMillis,
              let reply = raw as? [String: Any], reply["status"] is String,
              JSONSerialization.isValidJSONObject(reply) else {
          self.traceHost("replyAborted")
          self.revoke(); return
        }
        if request["operation"] as? String == "delegate" {
          #if LAYERGRAM_KEYBOARD_TRACE
          let stages: Set<String> = [
            "delegateClockUnavailable", "delegateServiceDisposed",
            "delegateServiceNotStarted", "delegateInvalidRequest",
            "delegateNoCoordinator", "delegateNoIdentity",
            "delegateAdmissionDenied", "delegatePipelinePreparing",
            "delegateGrantMissing"
          ]
          if let stage = reply["diagnosticStage"] as? String, stages.contains(stage) {
            self.traceHost("delegateReason_\(stage)")
          }
          #endif
          switch reply["status"] as? String {
          case "ok": self.traceHost("delegateReplyOk")
          case "busy": self.traceHost("delegateReplyBusy")
          default: self.traceHost("delegateReplyDenied")
          }
        }
        do {
          if request["operation"] as? String == "delegate", reply["status"] as? String == "ok",
             reply["mode"] as? String == "autonomous-v1", reply["key"] is String,
             reply["configuration"] is [String: Any], let nonce = request["editorNonce"] as? String {
            self.autonomousHandoffNonce = nonce
            self.autonomousHandoffReply = reply
          }
          let bytes = try JSONSerialization.data(withJSONObject: reply)
          if request["operation"] as? String == "delegate" {
            if try !owner.respondIfFresh(to: pending, payload: bytes) {
              self.traceHost("delegateDeliveryLeaseMissed")
            }
          } else {
            try owner.respond(to: pending, payload: bytes)
          }
        } catch {
          // A known missed delivery lease is not a lifecycle revocation.
          // The next authenticated request still needs a new exclusive lease.
          if request["operation"] as? String == "delegate",
             let error = error as? MailboxError, error.kind == .unavailable,
             MailboxClock.system().monotonicMillis >= pending.respondByMonotonicMillis {
            self.traceHost("delegateDeliveryLeaseMissed")
          } else { self.revoke() }
        }
      }
    } catch { revoke() }
  }

  private func pollBusyWhileMainStalled() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    let now = MailboxClock.system().monotonicMillis
    guard configured, departed, !departureDenied, !waiting, autonomousBootstrapAttempted,
          autonomousHandoffNonce == nil, now - lastMainPollMillis >= 200,
          let owner, let info = owner.windowInfo,
          now < info.deadlineMonotonicMillis, !owner.hasLivePendingRequest else { return }
    do {
      guard case .request(let pending) = try owner.pollRequest() else { return }
      let request = try JSONSerialization.jsonObject(with: pending.payload) as? [String: Any]
      let reply = ["status": request?["operation"] as? String == "delegate" ? "busy" : "unavailable"]
      _ = try owner.respondIfFresh(to: pending, payload: JSONSerialization.data(withJSONObject: reply))
      // No key, configuration, plaintext, identity or renewed deadline is ever
      // produced on this queue, even if a lifecycle notification is pending.
      os_log("LayergramHostTrace bootstrapMainStalledBusy", log: .default, type: .info)
    } catch {
      // A malformed/expired request is never retried or granted by this worker.
      // Revoke on the lifecycle thread, only if this is still the same window.
      let capturedEpoch = epoch
      DispatchQueue.main.async { [weak self] in
        guard let self else { return }
        self.mailboxLock.lock()
        defer { self.mailboxLock.unlock() }
        if self.epoch == capturedEpoch { self.revoke() }
      }
    }
  }

  private func bootstrapExpired() {
    if autonomousHandoffNonce != nil { closeBootstrap() } else { revoke() }
  }

  private func revoke() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    departureDenied = true
    autonomousHandoffNonce = nil
    if let groupIdentifier {
      KeyboardBiometricResumeStore.remove(group: groupIdentifier)
    }
    custodyChannel?.revoke()
    closeBootstrap()
  }

  /// A completed handoff outlives only the parent execution window. Real app,
  /// lock, capture and opt-in revocations always pass through revoke() above.
  private func closeBootstrap() {
    mailboxLock.lock()
    defer { mailboxLock.unlock() }
    epoch &+= 1
    timer?.invalidate()
    timer = nil
    busyTimer?.cancel()
    busyTimer = nil
    autonomousBootstrapAttempted = false
    autonomousHandoffReply = nil
    let previous = owner
    owner = nil
    waiting = false
    try? previous?.closeWindow()
    let task = backgroundTask
    backgroundTask = .invalid
    if task != .invalid { UIApplication.shared.endBackgroundTask(task) }
  }

  deinit {
    busyTimer?.cancel()
    timer?.invalidate()
    try? owner?.closeWindow()
    if backgroundTask != .invalid { UIApplication.shared.endBackgroundTask(backgroundTask) }
    observers.forEach { NotificationCenter.default.removeObserver($0) }
  }
}


/// App-side persistence seam only. Keys arrive from the unlocked ordinary
/// identity's private recovery journal; they are never stored by this channel.
/// All calls are confined to Flutter's main-thread platform handler.
private final class SystemKeyboardCustodyChannel {
  private let channel: FlutterMethodChannel
  private let groupIdentifier: String?
  private let embedded: Bool
  private let canDelegate: () -> Bool
  private let directoryName: String

  #if LAYERGRAM_KEYBOARD_TRACE
  private func traceState(_ stage: String, storage: MailboxStorage,
                          group: String) {
    let file = (try? storage.readCustodyState()) != nil
    let control = (try? storage.readCustodyControl()) != nil
    let mirror = (try? KeyboardKeychainCustodyMirror.hasAny(group: group)) == true
    let container = storage.directoryURL.deletingLastPathComponent().lastPathComponent
    os_log("LayergramCustodyTrace %{public}@", log: .default, type: .info,
           "\(stage) file=\(file) control=\(control) mirror=\(mirror) container=\(container)")
  }

  private func probeSharedKeychain(group: String) {
    let epoch = Data(repeating: 0, count: 16)
    let probe = KeyboardKeychainCustodyMirror(
      group: group, epoch: epoch, account: "fixture-keychain-probe-v1")
    var sealed = Data([1])
    sealed.append(epoch)
    sealed.append(Data(repeating: 0, count: 36))
    var updated = sealed
    updated[updated.count - 1] = 1
    do {
      if let previous = try probe.load() {
        if previous == sealed {
          try probe.save(updated)
          let valid = try probe.load() == updated
          os_log("LayergramCustodyTrace %{public}@", log: .default, type: .info,
                 valid ? "keychainProbeUpdated" : "keychainProbeUpdateMismatch")
        } else {
          try probe.remove()
          os_log("LayergramCustodyTrace %{public}@", log: .default, type: .info,
                 previous == updated ? "keychainProbeUpdateSurvived" : "keychainProbeChanged")
        }
        return
      }
      try probe.save(sealed)
      let readable = try probe.load() == sealed
      os_log("LayergramCustodyTrace %{public}@", log: .default, type: .info,
             readable ? "keychainProbeCreated" : "keychainProbeMismatch")
    } catch {
      os_log("LayergramCustodyTrace keychainProbeFailed", log: .default,
             type: .info)
    }
  }
  #endif

  init(messenger: FlutterBinaryMessenger, groupIdentifier: String?, embedded: Bool,
       directoryName: String, canDelegate: @escaping () -> Bool) {
    self.groupIdentifier = groupIdentifier
    self.directoryName = directoryName
    self.embedded = embedded
    self.canDelegate = canDelegate
    channel = FlutterMethodChannel(name: "layergram/keyboard_custody", binaryMessenger: messenger)
    channel.setMethodCallHandler { [weak self] call, result in
      self?.handle(call, result: result)
    }
    #if LAYERGRAM_KEYBOARD_TRACE
    if embedded, let groupIdentifier,
       let storage = try? MailboxStorage(appGroupIdentifier: groupIdentifier,
                                         directoryName: directoryName) {
      traceState("hostInit", storage: storage, group: groupIdentifier)
      probeSharedKeychain(group: groupIdentifier)
    }
    #endif
  }

  func revoke() {
    guard embedded, let groupIdentifier else { return }
    do {
      let storage = try MailboxStorage(appGroupIdentifier: groupIdentifier,
                                      directoryName: directoryName)
      try KeyboardCustodyStore.revoke(storage: storage)
    } catch {
      // Complete protection can deny I/O while locked. Extension lifecycle and
      // observation-gap invalidation independently destroy live authorization.
    }
  }

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    if call.method == "hasPending" {
      guard embedded else { result(false); return }
      guard let groupIdentifier, UIApplication.shared.isProtectedDataAvailable else {
        result(FlutterError(code: "custodyUnavailable", message: nil, details: nil)); return
      }
      do {
        let storage = try MailboxStorage(appGroupIdentifier: groupIdentifier,
                                        directoryName: directoryName)
        let pending = try storage.withExclusiveLock {
          try storage.readCustodyState() != nil ||
              storage.readCustodyControl() != nil ||
              KeyboardKeychainCustodyMirror.hasAny(group: groupIdentifier)
        }
        result(pending)
      } catch { result(FlutterError(code: "custodyUnavailable", message: nil, details: nil)) }
      return
    }
    guard embedded, let groupIdentifier, UIApplication.shared.isProtectedDataAvailable,
          let args = call.arguments as? [String: Any],
          let epoch = args["epoch"] as? FlutterStandardTypedData,
          let key = args["key"] as? FlutterStandardTypedData,
          epoch.data.count == 16, key.data.count == 32 else {
      result(FlutterError(code: "unavailable", message: nil, details: nil)); return
    }
    do {
      let storage = try MailboxStorage(appGroupIdentifier: groupIdentifier,
                                      directoryName: directoryName)
      let mirror = KeyboardKeychainCustodyMirror(group: groupIdentifier,
                                                 epoch: epoch.data)
      let store = try KeyboardCustodyStore(storage: storage, epoch: epoch.data,
                                           key: key.data, mirror: mirror)
      defer { store.close() }
      switch call.method {
      case "prepare":
        guard canDelegate(),
              let bytes = args["snapshot"] as? FlutterStandardTypedData else {
          throw KeyboardCustodyStore.Failure.revoked
        }
        try store.prepare(bytes.data)
        #if LAYERGRAM_KEYBOARD_TRACE
        traceState("prepared", storage: storage, group: groupIdentifier)
        #endif
        result(nil)
      case "activate":
        guard canDelegate() else { throw KeyboardCustodyStore.Failure.revoked }
        try store.activate()
        #if LAYERGRAM_KEYBOARD_TRACE
        traceState("activated", storage: storage, group: groupIdentifier)
        #endif
        result(nil)
      case "reclaim":
        let snapshot: KeyboardCustodyStore.Snapshot? = try storage.withExclusiveLock {
          if try storage.readCustodyState() == nil &&
              storage.readCustodyControl() == nil && mirror.load() == nil { return nil }
          return try store.reclaimForApp()
        }
        guard let snapshot else {
          #if LAYERGRAM_KEYBOARD_TRACE
          traceState("reclaimMissing", storage: storage, group: groupIdentifier)
          #endif
          result(FlutterError(code: "custodyMissing", message: nil, details: nil)); return
        }
        #if LAYERGRAM_KEYBOARD_TRACE
        traceState("reclaimed", storage: storage, group: groupIdentifier)
        #endif
        result(["revision": snapshot.revision, "snapshot": FlutterStandardTypedData(bytes: snapshot.plaintext)])
      case "finish":
        guard let revision = args["revision"] as? NSNumber,
              CFGetTypeID(revision) != CFBooleanGetTypeID(),
              revision.doubleValue.isFinite,
              revision.doubleValue == Double(revision.uint64Value),
              revision.uint64Value <= KeyboardCustodyStore.maxRevision else {
          throw KeyboardCustodyStore.Failure.invalidInput
        }
        try store.removeAfterImport(expectedRevision: revision.uint64Value)
        result(nil)
      default: result(FlutterMethodNotImplemented)
      }
    } catch { result(FlutterError(code: "custodyUnavailable", message: nil, details: nil)) }
  }

  deinit { channel.setMethodCallHandler(nil) }
}
