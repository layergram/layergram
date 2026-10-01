import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Fixed leaf names inside the dedicated shared subdirectory.
enum MailboxLeaf: String, CaseIterable {
    case rendezvous = "rendezvous.json"
    case request = "client.request"
    case response = "owner.response"
    case lock = "mailbox.lock"
    // Used only in a separate custody directory, never by mailbox cleanup.
    case custodyState = "custody.state"
    case custodyControl = "custody.control"

    var maxBytes: Int {
        switch self {
        case .rendezvous: return MailboxConstants.maxRendezvousBytes
        case .request, .response: return MailboxConstants.maxEnvelopeBytes
        case .lock: return 0
        case .custodyState: return 2 * 1024 * 1024 + 64
        case .custodyControl: return 64
        }
    }
}

/// iOS data protection is applied **and read back** on the dedicated directory,
/// on every temporary file before its first content byte, and on the lock file
/// before it is used. A failure to apply or verify it fails closed before any
/// content is written. On macOS, where the tests run, the attribute does not
/// exist and this is a no-op.
private func applyCompleteProtection(at url: URL) throws {
    #if (os(iOS) || os(tvOS) || os(watchOS)) && !targetEnvironment(simulator)
    do {
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
    } catch {
        throw MailboxError.unavailable(.storageUnavailable)
    }
    let attributes: [FileAttributeKey: Any]
    do {
        attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    } catch {
        throw MailboxError.unavailable(.storageUnavailable)
    }
    guard let raw = attributes[.protectionKey],
          let value = (raw as? FileProtectionType)?.rawValue ?? (raw as? String),
          value == FileProtectionType.complete.rawValue else {
        throw MailboxError.unavailable(.storageUnavailable)
    }
    #else
    // Simulator files live on the Mac filesystem and do not expose iOS data
    // protection attributes. This build-time branch never applies to a device.
    // Transport tests here cannot attest device-lock encryption.
    _ = url
    #endif
}

/// Serialises access to the shared directory with an advisory `flock`, so the
/// owner process and the extension process cannot interleave a write with a
/// read. Re-entrant in one process: nested calls reuse the held lock instead of
/// self-deadlocking.
///
/// The wait is measured on the monotonic clock (`ProcessInfo.systemUptime`), so
/// a wall-clock change can neither shorten nor extend it, and it is always
/// bounded by `timeoutMillis`.
final class MailboxLockCoordinator {
    private let mutex = NSRecursiveLock()
    private var depth = 0
    private var descriptor: Int32 = -1

    func withLock<T>(
        directoryDescriptor: Int32,
        directoryURL: URL,
        fileName: String,
        timeoutMillis: Int64,
        _ body: () throws -> T
    ) throws -> T {
        mutex.lock()
        defer { mutex.unlock() }

        if depth > 0 {
            depth += 1
            defer { depth -= 1 }
            return try body()
        }

        let fd = openat(
            directoryDescriptor,
            fileName,
            O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
            0o600
        )
        guard fd >= 0 else { throw MailboxError.unavailable(.storageUnavailable) }

        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            close(fd)
            throw MailboxError.unavailable(.storageUnavailable)
        }
        do {
            try applyCompleteProtection(at: directoryURL.appendingPathComponent(fileName, isDirectory: false))
        } catch {
            close(fd)
            throw error
        }

        var acquired = false
        let deadline = ProcessInfo.processInfo.systemUptime + (Double(max(timeoutMillis, 0)) / 1000.0)
        while true {
            if flock(fd, LOCK_EX | LOCK_NB) == 0 {
                acquired = true
                break
            }
            if errno != EWOULDBLOCK && errno != EINTR { break }
            if ProcessInfo.processInfo.systemUptime >= deadline { break }
            usleep(2_000)
        }
        guard acquired else {
            close(fd)
            throw MailboxError.unavailable(.locked)
        }

        descriptor = fd
        depth = 1
        defer {
            depth = 0
            if descriptor >= 0 {
                flock(descriptor, LOCK_UN)
                close(descriptor)
                descriptor = -1
            }
        }
        return try body()
    }
}

/// Safe storage for the mailbox inside one dedicated App Group subdirectory.
///
/// Properties:
/// * only fixed leaf file names are ever touched, and every operation goes
///   through a directory descriptor pinned at initialisation (`openat`), so a
///   symlink or directory replacement after initialisation cannot redirect a
///   read or a write outside the originally opened directory;
/// * every open uses `O_NOFOLLOW | O_NONBLOCK` and every descriptor is checked
///   with `fstat` for a regular file, so a FIFO or device node can neither block
///   nor be read;
/// * reads are size-bounded using `fstat` before allocation;
/// * writes are exclusive temp file + `renameat`, so a reader never observes a
///   partial document;
/// * on iOS the directory, every temporary file and the lock file use
///   `FileProtectionType.complete`, applied and verified before any content is
///   written, and a mailbox that cannot be protected fails to initialise;
/// * the directory is excluded from backup, and that exclusion is verified; a
///   directory that cannot be excluded fails to initialise.
///
/// No logging of file contents happens anywhere in this package.
public final class MailboxStorage {
    public static let defaultAppGroupIdentifier = MailboxConstants.appGroupIdentifier

    public let directoryURL: URL

    /// Verified result of the mandatory backup-exclusion request on the
    /// dedicated directory: always `true` for a mailbox that finished
    /// initialising.
    public private(set) var isBackupExcluded = false

    private let lockCoordinator = MailboxLockCoordinator()
    private var directoryDescriptor: Int32 = -1

    /// Production initialiser: resolves the existing Layergram App Group and uses
    /// the dedicated mailbox subdirectory inside it.
    public convenience init(
        appGroupIdentifier: String = MailboxStorage.defaultAppGroupIdentifier,
        directoryName: String = MailboxConstants.directoryName
    ) throws {
        guard MailboxStorage.isSafePathComponent(directoryName) else {
            throw MailboxError.malformed(.unsafePath)
        }
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) else {
            throw MailboxError.unavailable(.noApplicationGroup)
        }
        try self.init(directoryURL: container.appendingPathComponent(directoryName, isDirectory: true))
    }

    /// Explicit-directory initialiser: used by extension targets that resolve the
    /// container themselves, and by tests on macOS where no App Group exists.
    public init(directoryURL: URL) throws {
        self.directoryURL = directoryURL.standardizedFileURL
        try prepareDirectory()
    }

    deinit {
        if directoryDescriptor >= 0 {
            close(directoryDescriptor)
        }
    }

    // MARK: - Rendezvous

    public func writeRendezvous(_ data: Data) throws {
        try writeAtomic(data, to: .rendezvous)
    }

    public func readRendezvous() throws -> Data? {
        try readBounded(.rendezvous)
    }

    public func removeRendezvous() throws {
        try removeLeaf(.rendezvous)
    }

    // MARK: - Requests and responses

    public func writeRequest(_ data: Data) throws {
        try writeAtomic(data, to: .request)
    }

    public func readRequest() throws -> Data? {
        try readBounded(.request)
    }

    public func removeRequest() throws {
        try removeLeaf(.request)
    }

    public func writeResponse(_ data: Data) throws {
        try writeAtomic(data, to: .response)
    }

    public func readResponse() throws -> Data? {
        try readBounded(.response)
    }

    public func removeResponse() throws {
        try removeLeaf(.response)
    }

    // Custody state is durable protocol state, unlike transient IPC. A failed
    // sync is an uncertain commit and must be reported to the caller. These
    // files are deliberately excluded from mailbox expiration/cleanup.
    public func readCustodyState() throws -> Data? { try readBounded(.custodyState) }
    public func readCustodyControl() throws -> Data? { try readBounded(.custodyControl) }
    public func writeCustodyState(_ data: Data) throws {
        try withExclusiveLock { try writeAtomicLocked(data, to: .custodyState, durable: true) }
    }
    public func writeCustodyControl(_ data: Data) throws {
        try withExclusiveLock { try writeAtomicLocked(data, to: .custodyControl, durable: true) }
    }
    public func removeCustodyFiles() throws {
        try withExclusiveLock {
            try removeLeaf(.custodyState)
            try syncDirectory()
            try removeLeaf(.custodyControl)
            try syncDirectory()
        }
    }

    /// Remove every mailbox document but keep the directory itself.
    public func removeAll() throws {
        try lockCoordinator.withLock(
            directoryDescriptor: directoryDescriptor,
            directoryURL: directoryURL,
            fileName: MailboxLeaf.lock.rawValue,
            timeoutMillis: MailboxConstants.lockTimeoutMillis
        ) {
            try removeLeaf(.request)
            try removeLeaf(.response)
            try removeLeaf(.rendezvous)
            try removeTemporaryFiles()
        }
    }

    /// Remove documents belonging to an expired rendezvous and any document that
    /// is older than `maxAgeMillis` (or dated in the future).
    public func purgeStaleFiles(
        nowEpochMillis: Int64,
        maxAgeMillis: Int64 = MailboxConstants.defaultStaleMillis
    ) throws {
        try lockCoordinator.withLock(
            directoryDescriptor: directoryDescriptor,
            directoryURL: directoryURL,
            fileName: MailboxLeaf.lock.rawValue,
            timeoutMillis: MailboxConstants.lockTimeoutMillis
        ) {
            try removeTemporaryFiles()
            if let rendezvousData = try readBounded(.rendezvous) {
                let expired: Bool
                if let rendezvous = try? MailboxRendezvous.decode(rendezvousData) {
                    expired = nowEpochMillis > rendezvous.deadlineEpochMillis
                } else {
                    expired = true
                }
                if expired {
                    try removeLeaf(.request)
                    try removeLeaf(.response)
                    try removeLeaf(.rendezvous)
                    return
                }
            }
            for leaf in [MailboxLeaf.request, .response, .rendezvous] {
                guard let modified = modificationMillis(leaf) else { continue }
                let age = nowEpochMillis - modified
                if age > maxAgeMillis || age < -maxAgeMillis {
                    try removeLeaf(leaf)
                }
            }
        }
    }

    // MARK: - Locking

    public func withExclusiveLock<T>(
        timeoutMillis: Int64 = MailboxConstants.lockTimeoutMillis,
        _ body: () throws -> T
    ) throws -> T {
        try lockCoordinator.withLock(
            directoryDescriptor: directoryDescriptor,
            directoryURL: directoryURL,
            fileName: MailboxLeaf.lock.rawValue,
            timeoutMillis: timeoutMillis,
            body
        )
    }

    // MARK: - Internals

    static func isSafePathComponent(_ name: String) -> Bool {
        guard !name.isEmpty, name != ".", name != ".." else { return false }
        guard !name.contains("/"), !name.contains("\\"), !name.contains("\0") else { return false }
        return true
    }

    private static let directoryOpenFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC

    private func prepareDirectory() throws {
        var descriptor = open(directoryURL.path, MailboxStorage.directoryOpenFlags)
        if descriptor < 0 {
            let code = errno
            if code == ELOOP || code == ENOTDIR {
                throw MailboxError.malformed(.unsafePath)
            }
            guard code == ENOENT else { throw MailboxError.unavailable(.storageUnavailable) }
            do {
                try FileManager.default.createDirectory(
                    at: directoryURL,
                    withIntermediateDirectories: true,
                    attributes: MailboxStorage.protectionAttributes()
                )
            } catch {
                throw MailboxError.unavailable(.storageUnavailable)
            }
            descriptor = open(directoryURL.path, MailboxStorage.directoryOpenFlags)
            guard descriptor >= 0 else {
                if errno == ELOOP || errno == ENOTDIR {
                    throw MailboxError.malformed(.unsafePath)
                }
                throw MailboxError.unavailable(.storageUnavailable)
            }
        }

        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else {
            close(descriptor)
            throw MailboxError.malformed(.unsafePath)
        }
        directoryDescriptor = descriptor

        do {
            try applyCompleteProtection(at: directoryURL)
            try excludeFromBackup(directoryURL)
        } catch {
            close(directoryDescriptor)
            directoryDescriptor = -1
            throw error
        }
        isBackupExcluded = true
    }

    private static func protectionAttributes() -> [FileAttributeKey: Any] {
        #if (os(iOS) || os(tvOS) || os(watchOS)) && !targetEnvironment(simulator)
        return [.protectionKey: FileProtectionType.complete]
        #else
        return [:]
        #endif
    }

    /// Backup exclusion is mandatory on the dedicated directory and is verified
    /// by reading the value back. A directory that cannot be excluded fails
    /// closed: the mailbox never carries a payload it cannot protect. Excluding
    /// the directory also excludes everything written inside it, so the rename
    /// target keeps the exclusion.
    private func excludeFromBackup(_ url: URL) throws {
        var mutable = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        do {
            try mutable.setResourceValues(values)
        } catch {
            throw MailboxError.unavailable(.storageUnavailable)
        }
        let readBack = url
        guard let current = try? readBack.resourceValues(forKeys: [.isExcludedFromBackupKey]),
              current.isExcludedFromBackup == true else {
            throw MailboxError.unavailable(.storageUnavailable)
        }
    }

    private func modificationMillis(_ leaf: MailboxLeaf) -> Int64? {
        var info = stat()
        guard fstatat(directoryDescriptor, leaf.rawValue, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
            return nil
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        let seconds = Int64(info.st_mtimespec.tv_sec)
        let nanos = Int64(info.st_mtimespec.tv_nsec)
        return seconds * 1000 + nanos / 1_000_000
    }

    private func readBounded(_ leaf: MailboxLeaf) throws -> Data? {
        let fd = openat(
            directoryDescriptor,
            leaf.rawValue,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            // `O_NOFOLLOW` refuses a symlink final component: ELOOP on Darwin,
            // with ENOTDIR/EMLINK accepted as equivalent fail-closed answers.
            if errno == ELOOP || errno == ENOTDIR || errno == EMLINK {
                throw MailboxError.malformed(.unsafePath)
            }
            throw MailboxError.unavailable(.storageUnavailable)
        }
        defer { close(fd) }

        var info = stat()
        guard fstat(fd, &info) == 0 else { throw MailboxError.unavailable(.storageUnavailable) }
        // A FIFO, socket or device node is never a mailbox document. Checking the
        // type after a non-blocking open means such a leaf cannot hang the caller.
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw MailboxError.malformed(.unsafePath) }
        let size = Int(info.st_size)
        guard size >= 0, size <= leaf.maxBytes else { throw MailboxError.malformed(.tooLarge) }
        if size == 0 { return Data() }

        var data = Data(count: size)
        var total = 0
        while total < size {
            let bytesRead = data.withUnsafeMutableBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return -1 }
                return Darwin.read(fd, base.advanced(by: total), size - total)
            }
            if bytesRead < 0 {
                if errno == EINTR { continue }
                throw MailboxError.unavailable(.storageUnavailable)
            }
            if bytesRead == 0 { break }
            total += bytesRead
        }
        guard total == size else { throw MailboxError.unavailable(.storageUnavailable) }
        return data
    }

    // Fixed staging leaves bound crash leftovers independently of the
    // number of launches. The same directory lock covers cleanup and writing.
    private func removeTemporaryFiles() throws {
        for leaf in [MailboxLeaf.request, .response, .rendezvous, .custodyState, .custodyControl] {
            let name = ".\(leaf.rawValue).tmp"
            guard unlinkat(directoryDescriptor, name, 0) == 0 || errno == ENOENT else {
                throw MailboxError.unavailable(.storageUnavailable)
            }
        }
    }

    private func writeAtomic(_ data: Data, to leaf: MailboxLeaf) throws {
        try withExclusiveLock { try writeAtomicLocked(data, to: leaf) }
    }

    private func writeAtomicLocked(_ data: Data, to leaf: MailboxLeaf, durable: Bool = false) throws {
        guard data.count <= leaf.maxBytes else { throw MailboxError.malformed(.tooLarge) }

        let tempName = ".\(leaf.rawValue).tmp"
        try removeTemporaryFiles()
        guard MailboxStorage.isSafePathComponent(tempName) else {
            throw MailboxError.malformed(.unsafePath)
        }
        let tempURL = directoryURL.appendingPathComponent(tempName, isDirectory: false)

        let fd = openat(
            directoryDescriptor,
            tempName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
            0o600
        )
        guard fd >= 0 else { throw MailboxError.unavailable(.storageUnavailable) }

        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            close(fd)
            unlinkat(directoryDescriptor, tempName, 0)
            throw MailboxError.unavailable(.storageUnavailable)
        }

        do {
            // Protection must be in place before the first content byte.
            try applyCompleteProtection(at: tempURL)
            try writeAll(data, to: fd)
            let synced = fsync(fd)
            if durable && synced != 0 {
                throw MailboxError.unavailable(.storageUnavailable)
            }
        } catch {
            close(fd)
            unlinkat(directoryDescriptor, tempName, 0)
            throw error
        }
        close(fd)

        guard renameat(directoryDescriptor, tempName, directoryDescriptor, leaf.rawValue) == 0 else {
            unlinkat(directoryDescriptor, tempName, 0)
            throw MailboxError.unavailable(.storageUnavailable)
        }
        if durable { try syncDirectory() }
    }

    private func syncDirectory() throws {
        guard fsync(directoryDescriptor) == 0 else {
            throw MailboxError.unavailable(.storageUnavailable)
        }
    }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        var total = 0
        while total < data.count {
            let written = data.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: total), data.count - total)
            }
            if written < 0 {
                if errno == EINTR { continue }
                throw MailboxError.unavailable(.storageUnavailable)
            }
            if written == 0 { throw MailboxError.unavailable(.storageUnavailable) }
            total += written
        }
    }

    private func removeLeaf(_ leaf: MailboxLeaf) throws {
        // unlinkat never follows a symlink, so removing a link is safe, and it is
        // confined to the pinned directory descriptor.
        if unlinkat(directoryDescriptor, leaf.rawValue, 0) != 0, errno != ENOENT {
            throw MailboxError.unavailable(.storageUnavailable)
        }
    }
}
