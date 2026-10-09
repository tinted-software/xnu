import Foundation

/// Errors from trust cache operations.
public enum TrustCacheError: Error, LocalizedError, Sendable {
    case invalidFormat
    case noCodeSignature
    case noCodeDirectory
    case unsupportedHashType(UInt8)
    case fileNotFound(String)
    case notMachO(String)
    case truncated
    case unexpectedVersion(UInt32)

    public var errorDescription: String? {
        switch self {
        case .invalidFormat:
            "Invalid trust cache format"
        case .truncated:
            "Trust cache data is truncated"
        case .unexpectedVersion(let v):
            "Unexpected trust cache version \(v)"
        case .noCodeSignature:
            "Mach-O binary has no code signature"
        case .noCodeDirectory:
            "Code signature has no code directory"
        case .unsupportedHashType(let raw):
            "Unsupported hash type: \(raw)"
        case .fileNotFound(let path):
            "File not found: \(path)"
        case .notMachO(let path):
            "Not a valid Mach-O binary: \(path)"
        }
    }
}
