import Foundation

/// Caller-supplied time.
///
/// `epochMillis` is used only where a value must survive in shared storage
/// (rendezvous creation and deadline). `monotonicMillis` is used for every local
/// deadline decision, so a wall-clock change cannot widen a window. On Darwin
/// `ProcessInfo.systemUptime` is mach-uptime based and therefore consistent
/// across processes of the same boot, which is what the owner and the extension
/// rely on when they each convert the shared deadline once.
public struct MailboxClock: Equatable {
    public let monotonicMillis: Int64
    public let epochMillis: Int64

    public init(monotonicMillis: Int64, epochMillis: Int64) {
        self.monotonicMillis = monotonicMillis
        self.epochMillis = epochMillis
    }

    public static func system() -> MailboxClock {
        let uptime = ProcessInfo.processInfo.systemUptime
        let epoch = Date().timeIntervalSince1970
        return MailboxClock(
            monotonicMillis: Int64((uptime * 1000).rounded(.down)),
            epochMillis: Int64((epoch * 1000).rounded(.down))
        )
    }

    /// A negative reading is never trusted. Every service checks this before it
    /// derives or compares a deadline, so a broken clock fails closed instead of
    /// moving a window.
    var isSane: Bool { monotonicMillis >= 0 && epochMillis >= 0 }

    /// Test/integration helper: advance both readings by the same delta.
    ///
    /// Throws instead of trapping when either reading would overflow or fall
    /// below zero, so a hostile or broken clock cannot crash the process.
    public func advanced(byMillis delta: Int64) throws -> MailboxClock {
        let (monotonic, monotonicOverflow) = monotonicMillis.addingReportingOverflow(delta)
        let (epoch, epochOverflow) = epochMillis.addingReportingOverflow(delta)
        guard !monotonicOverflow, !epochOverflow, monotonic >= 0, epoch >= 0 else {
            throw MailboxError.malformed(.badNumber)
        }
        return MailboxClock(monotonicMillis: monotonic, epochMillis: epoch)
    }
}

enum MailboxRandom {
    /// Cryptographically secure random bytes from the system generator.
    static func bytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        var data = Data()
        data.reserveCapacity(count)
        for _ in 0..<count {
            data.append(UInt8.random(in: UInt8.min...UInt8.max, using: &generator))
        }
        return data
    }
}
