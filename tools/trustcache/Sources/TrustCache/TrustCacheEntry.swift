import Foundation

// MARK: - Constants

/// CDHash length in bytes (defined in XNU: osfmk/kern/trustcache.h)
public let kCDHashLength = 20

// MARK: - Hash Type

/// Code directory hash type, matching CS_HASHTYPE_* from codesign.
public enum CDHashType: UInt8, Sendable {
    case sha1 = 1
    case sha256 = 2
    case sha256Truncated = 3
    case sha384 = 4
}

// MARK: - Entry Flags

/// Trust cache entry flags.
public struct TrustCacheEntryFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Valid cdhash for amfid (CS_TRUST_CACHE_AMFID).
    public static let amfid = TrustCacheEntryFlags(rawValue: 0x1)
}

// MARK: - Trust Cache Entry (v1)

/// A single trust cache entry containing a CDHash and metadata.
///
/// Layout (22 bytes, packed):
/// ```
/// uint8_t  cdhash[20]
/// uint8_t  hash_type
/// uint8_t  flags
/// ```
public struct TrustCacheEntry: Sendable, Hashable {
    /// The 20-byte code directory hash.
    public var cdhash: Data

    /// Hash algorithm used to compute the CDHash.
    public var hashType: CDHashType

    /// Entry flags.
    public var flags: TrustCacheEntryFlags

    public init(cdhash: Data, hashType: CDHashType, flags: TrustCacheEntryFlags = []) {
        precondition(cdhash.count == kCDHashLength, "CDHash must be \(kCDHashLength) bytes")
        self.cdhash = cdhash
        self.hashType = hashType
        self.flags = flags
    }
}

extension TrustCacheEntry: Comparable {
    /// Entries are sorted by cdhash (memcmp order) as required by trustcache v1.
    public static func < (lhs: TrustCacheEntry, rhs: TrustCacheEntry) -> Bool {
        let l = lhs.cdhash
        let r = rhs.cdhash
        for i in 0 ..< kCDHashLength {
            if l[l.startIndex + i] != r[r.startIndex + i] {
                return l[l.startIndex + i] < r[r.startIndex + i]
            }
        }
        return false
    }
}

// MARK: - Serialization

extension TrustCacheEntry {
    /// Packed size in bytes.
    public static let packedSize = kCDHashLength + 2

    /// Deserialize from packed bytes.
    public init?(from data: Data) {
        guard data.count >= Self.packedSize else { return nil }
        let base = data.startIndex
        let hash = data[base ..< base + kCDHashLength]
        guard let ht = CDHashType(rawValue: data[base + kCDHashLength]) else { return nil }
        let fl = TrustCacheEntryFlags(rawValue: data[base + kCDHashLength + 1])
        self.init(cdhash: Data(hash), hashType: ht, flags: fl)
    }

    /// Serialize to packed bytes.
    public func serialize() -> Data {
        var out = Data(capacity: Self.packedSize)
        out.append(cdhash)
        out.append(hashType.rawValue)
        out.append(flags.rawValue)
        return out
    }
}
