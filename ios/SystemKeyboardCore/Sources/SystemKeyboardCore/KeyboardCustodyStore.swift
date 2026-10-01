import CryptoKit
import Foundation

/// An encrypted working snapshot for one keyboard delegation. Instances must
/// remain confined to one serial executor, including close(). Callers MUST use
/// a dedicated directory, distinct from the ephemeral IPC mailbox, and persist
/// the recovery key in the app's existing encrypted ordinary-identity store
/// before deleting private baselines or authorizing the keyboard.
///
/// This primitive is NOT authorization: an unlocked parent grant and an active
/// in-memory inactivity session are required separately. No key is persisted
/// here. Closing an extension must discard its key; only the app may recover
/// data from its private wrapper after a fresh ordinary-identity unlock.
public final class KeyboardCustodyStore {
    public static let directoryName = "keyboard-custody-v1"
    public static let maxPlaintextBytes = 2 * 1024 * 1024
    public static let maxRevision: UInt64 = 9_007_199_254_740_991

    public struct Snapshot {
        public let revision: UInt64
        public let plaintext: Data
    }

    public enum Failure: Error, Equatable {
        case invalidInput, unavailable, conflict, revoked, authentication
    }

    private enum Custodian: UInt8 { case prepared = 0, keyboard = 1, app = 2 }
    private let storage: MailboxStorage
    private let epoch: Data
    private let mirror: KeyboardCustodyMirror?
    private var key: SymmetricKey?

    public init(storage: MailboxStorage, epoch: Data, key: Data,
                mirror: KeyboardCustodyMirror? = nil) throws {
        guard epoch.count == 16, key.count == 32 else { throw Failure.invalidInput }
        self.storage = storage
        self.epoch = epoch
        self.mirror = mirror
        self.key = SymmetricKey(data: key)
    }

    /// Makes the initial state durable, but does not grant keyboard custody.
    /// Existing or partial state is never overwritten. An interrupted prepare
    /// must be recovered by the app using its durable recovery marker.
    public func prepare(_ plaintext: Data) throws {
        try storage.withExclusiveLock {
            guard try storage.readCustodyState() == nil,
                  try storage.readCustodyControl() == nil,
                  try mirror?.load() == nil else { throw Failure.conflict }
            try write(plaintext, revision: 0)
            try setCustodian(.prepared)
        }
    }

    /// The parent calls this only after its recovery marker and removal of
    /// private baselines are durable. Activation is one-way and never retried
    /// to revive a returned/revoked session.
    public func activate() throws {
        try storage.withExclusiveLock {
            guard try custodian() == .prepared else { throw Failure.conflict }
            _ = try read()
            try setCustodian(.keyboard)
        }
    }

    public func isKeyboardCustodian() -> Bool {
        guard key != nil else { return false }
        return (try? storage.withExclusiveLock { try custodian() == .keyboard }) == true
    }

    public func loadForKeyboard() throws -> Snapshot {
        try storage.withExclusiveLock {
            guard try custodian() == .keyboard else { throw Failure.revoked }
            return try read()
        }
    }

    /// Compare-and-swap prevents a second in-memory runtime from overwriting a
    /// newer durable revision. The caller must suppress plaintext/ciphertext
    /// output until this call succeeds and its live grant is checked again.
    /// Any failure, including an uncertain sync, requires closing the runtime;
    /// retrying the computation or using its pre-write state is forbidden.
    @discardableResult
    public func commitForKeyboard(_ plaintext: Data, expectedRevision: UInt64) throws -> UInt64 {
        try storage.withExclusiveLock {
            guard try custodian() == .keyboard else { throw Failure.revoked }
            let current = try read()
            guard current.revision == expectedRevision,
                  expectedRevision < Self.maxRevision else { throw Failure.conflict }
            let next = expectedRevision + 1
            try write(plaintext, revision: next)
            return next
        }
    }

    /// Revoke before loading. This is repeatable during crash recovery; it
    /// never grants the keyboard or rolls a snapshot back. Missing control
    /// after an interrupted prepare is recoverable only by the app with key.
    public func reclaimForApp() throws -> Snapshot {
        try storage.withExclusiveLock {
            if try storage.readCustodyControl() != nil { _ = try custodian() }
            let snapshot = try read()
            try setCustodian(.app)
            return snapshot
        }
    }

    /// Key-free revocation supports the containing app's earliest lifecycle
    /// callback, before Dart/identity restoration. Only existing well-formed
    /// control is modified; it cannot create or reactivate a delegation.
    public static func revoke(storage: MailboxStorage) throws {
        try storage.withExclusiveLock {
            guard let control = try storage.readCustodyControl() else { return }
            guard control.count == 18, (control[0] == 1 || control[0] == 2),
                  Custodian(rawValue: control[1]) != nil else { throw Failure.unavailable }
            var revoked = control
            revoked[1] = Custodian.app.rawValue
            try storage.writeCustodyControl(revoked)
        }
    }

    /// Cleanup is allowed only after an idempotent private import has committed
    /// and flushed its import receipt. Recovery markers are removed only after
    /// this cleanup succeeds. The revision binding avoids deleting
    /// a different or newer delegation after stale asynchronous callbacks.
    public func removeAfterImport(expectedRevision: UInt64) throws {
        try storage.withExclusiveLock {
            // The app's durable import manifest authorizes repeating cleanup.
            // A crash may have removed the state but not yet its control leaf.
            let hasState = try storage.readCustodyState() != nil
            let hasControl = try storage.readCustodyControl() != nil
            let hasMirror = try mirror?.load() != nil
            if !hasState && !hasControl && !hasMirror { return }
            if hasControl {
                guard try custodian() == .app else { throw Failure.conflict }
            } else if hasState {
                throw Failure.conflict
            }
            if hasState || hasMirror {
                guard try read().revision == expectedRevision else { throw Failure.conflict }
            }
            try storage.removeCustodyFiles()
            try mirror?.remove()
        }
        close()
    }

    /// Best-effort lifetime boundary; no perfect managed-memory erasure claim.
    public func close() { key = nil }

    private func custodian() throws -> Custodian {
        guard let control = try storage.readCustodyControl(), control.count == 18,
              (control[0] == 1 || control[0] == 2),
              Data(control.suffix(16)) == epoch,
              let owner = Custodian(rawValue: control[1]) else { throw Failure.unavailable }
        return owner
    }

    private func setCustodian(_ value: Custodian) throws {
        // Version 2 requires the independent mirror. Preserve version 1 while
        // importing a delegation created by an older installed build.
        let previous = try storage.readCustodyControl()
        let version = previous?.first ?? (mirror == nil ? UInt8(1) : UInt8(2))
        var control = Data([version, value.rawValue])
        control.append(epoch)
        try storage.writeCustodyControl(control)
    }

    private func header(revision: UInt64) -> Data {
        var data = Data([1])
        data.append(epoch)
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8(truncatingIfNeeded: revision >> shift))
        }
        return data
    }

    private func write(_ plaintext: Data, revision: UInt64) throws {
        guard let key else { throw Failure.revoked }
        guard plaintext.count <= Self.maxPlaintextBytes,
              revision <= Self.maxRevision else { throw Failure.invalidInput }
        let aad = header(revision: revision)
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        guard let combined = sealed.combined else { throw Failure.authentication }
        var stored = aad
        stored.append(combined)
        // The independent copy commits first. If the App Group write is
        // interrupted, recovery uses this higher authenticated revision.
        try mirror?.save(stored)
        try storage.writeCustodyState(stored)
    }

    private func read() throws -> Snapshot {
        guard let key else { throw Failure.revoked }
        let file = try storage.readCustodyState()
        let mirrored = try mirror?.load()
        if mirror != nil && mirrored == nil {
            // A version-2 control proves that every successful commit had a
            // mirror. Its disappearance must never expose an older file.
            if try storage.readCustodyControl()?.first == 2 || file == nil {
                throw Failure.unavailable
            }
        }
        let fileSnapshot = try file.map { try decode($0, key: key) }
        let mirrorSnapshot = try mirrored.map { try decode($0, key: key) }
        if let fileSnapshot, let mirrorSnapshot,
           fileSnapshot.revision > mirrorSnapshot.revision ||
           (fileSnapshot.revision == mirrorSnapshot.revision && file != mirrored) {
            throw Failure.conflict
        }
        guard let chosen = mirrorSnapshot ?? fileSnapshot else { throw Failure.unavailable }
        return chosen
    }

    private func decode(_ stored: Data, key: SymmetricKey) throws -> Snapshot {
        guard stored.count >= 53, stored[0] == 1,
              Data(stored[1..<17]) == epoch else { throw Failure.unavailable }
        let revision = stored[17..<25].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard revision <= Self.maxRevision else { throw Failure.invalidInput }
        let clear: Data
        do {
            let box = try AES.GCM.SealedBox(combined: stored.suffix(from: 25))
            clear = try AES.GCM.open(box, using: key, authenticating: stored.prefix(25))
        } catch { throw Failure.authentication }
        guard clear.count <= Self.maxPlaintextBytes else { throw Failure.invalidInput }
        return Snapshot(revision: revision, plaintext: clear)
    }
}
