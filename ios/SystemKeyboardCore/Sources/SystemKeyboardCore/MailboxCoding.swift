import CoreFoundation
import Foundation

/// Strict, bounded parsing helpers.
///
/// Every shared file is untrusted input: it may have been truncated, replaced or
/// crafted by another process in the App Group. Parsing therefore validates the
/// byte budget before allocation, requires the exact field set, requires integer
/// JSON numbers, and requires canonical base64.
enum StrictJSON {
    static func dictionary(_ data: Data, maxBytes: Int) throws -> [String: Any] {
        guard data.count <= maxBytes else { throw MailboxError.malformed(.tooLarge) }
        guard !data.isEmpty else { throw MailboxError.malformed(.badJSON) }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw MailboxError.malformed(.badJSON)
        }
        guard let dictionary = object as? [String: Any] else {
            throw MailboxError.malformed(.badJSON)
        }
        return dictionary
    }

    /// JSON booleans are `__NSCFBoolean`, and `NSNumber` also bridges to `Bool`.
    /// `value is Bool` is therefore true for the legitimate numbers `0` and `1`
    /// as well, which rejected every version/sequence/epoch field. The
    /// CoreFoundation type id distinguishes a real boolean from a real number
    /// exactly.
    private static func isBoolean(_ value: Any) -> Bool {
        guard let number = value as? NSNumber else { return false }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    private static let integerTypeEncodings: Set<String> = [
        "c", "i", "s", "l", "q", "C", "I", "S", "L", "Q"
    ]

    /// Numeric fields must be integers: booleans, fractional numbers and
    /// non-numeric values are rejected before any conversion.
    private static func number(_ value: Any?) throws -> NSNumber {
        guard let value = value else { throw MailboxError.malformed(.badFields) }
        guard !isBoolean(value) else { throw MailboxError.malformed(.badNumber) }
        guard let number = value as? NSNumber else { throw MailboxError.malformed(.badFields) }
        let encoding = String(cString: number.objCType)
        guard integerTypeEncodings.contains(encoding) else {
            throw MailboxError.malformed(.badNumber)
        }
        return number
    }

    /// Exact signed-integer conversion: the decimal value must fall inside the
    /// closed range and must be exactly the converted value, so a value that
    /// only looks like an integer after truncation is rejected.
    static func integer(_ value: Any?, minimum: Int64, maximum: Int64) throws -> Int64 {
        let number = try number(value)
        let decimal = number.decimalValue
        guard decimal >= Decimal(minimum), decimal <= Decimal(maximum) else {
            throw MailboxError.malformed(.badNumber)
        }
        let result = number.int64Value
        guard decimal == Decimal(result) else { throw MailboxError.malformed(.badNumber) }
        return result
    }

    /// Exact unsigned-integer conversion with the same closed-range and
    /// exactness rules. Values above `Int64.max` are handled through the
    /// decimal value instead of a lossy signed conversion.
    static func unsignedInteger(_ value: Any?, minimum: UInt64, maximum: UInt64) throws -> UInt64 {
        let number = try number(value)
        let decimal = number.decimalValue
        guard decimal >= Decimal(minimum), decimal <= Decimal(maximum) else {
            throw MailboxError.malformed(.badNumber)
        }
        let result = number.uint64Value
        guard decimal == Decimal(result) else { throw MailboxError.malformed(.badNumber) }
        return result
    }

    static func string(_ value: Any?) throws -> String {
        guard let string = value as? String else { throw MailboxError.malformed(.badFields) }
        return string
    }

    /// Canonical standard base64 only: valid alphabet, valid padding, and a
    /// round-trip that reproduces the input exactly.
    static func base64(
        _ value: Any?,
        exactBytes: Int? = nil,
        minBytes: Int? = nil,
        maxBytes: Int? = nil
    ) throws -> Data {
        let string = try self.string(value)
        guard string.utf8.count % 4 == 0 else { throw MailboxError.malformed(.badBase64) }
        guard let data = Data(base64Encoded: string, options: []), data.base64EncodedString() == string else {
            throw MailboxError.malformed(.badBase64)
        }
        if let exactBytes = exactBytes, data.count != exactBytes {
            throw MailboxError.malformed(.badLength)
        }
        if let minBytes = minBytes, data.count < minBytes {
            throw MailboxError.malformed(.badLength)
        }
        if let maxBytes = maxBytes, data.count > maxBytes {
            throw MailboxError.malformed(.badLength)
        }
        return data
    }
}
