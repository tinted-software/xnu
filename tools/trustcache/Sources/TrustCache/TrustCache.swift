import Foundation

// MARK: - Trust Cache Module (v1)

/// A version 1 Apple trust cache.
///
/// Layout (packed):
/// ```
/// uint32_t version        // always 1
/// uuid_t   uuid           // 16 bytes
/// uint32_t num_entries
/// trust_cache_entry1 entries[]
/// ```
///
/// Entries must be sorted by cdhash for binary search at runtime.
public struct TrustCache: Sendable {
    /// Trust cache format version.
    public let version: UInt32

    /// Unique identifier for this trust cache.
    public var uuid: UUID

    /// Sorted trust cache entries.
    public private(set) var entries: [TrustCacheEntry]

    /// Create an empty trust cache with a random UUID.
    public init(uuid: UUID = UUID()) {
        self.version = 1
        self.uuid = uuid
        self.entries = []
    }

    /// Create a trust cache with pre-built entries.
    /// Entries will be sorted by cdhash automatically.
    public init(uuid: UUID = UUID(), entries: [TrustCacheEntry]) {
        self.version = 1
        self.uuid = uuid
        self.entries = entries.sorted()
    }

    // MARK: - Mutating

    /// Add an entry. Duplicates (by cdhash) are skipped.
    @discardableResult
    public mutating func addEntry(_ entry: TrustCacheEntry) -> Bool {
        if entries.contains(where: { $0.cdhash == entry.cdhash }) {
            return false
        }
        entries.append(entry)
        entries.sort()
        return true
    }

    /// Add multiple entries. Returns the count of newly added entries.
    @discardableResult
    public mutating func addEntries(_ newEntries: [TrustCacheEntry]) -> Int {
        let existing = Set(entries.map(\.cdhash))
        let unique = newEntries.filter { !existing.contains($0.cdhash) }
        entries.append(contentsOf: unique)
        entries.sort()
        return unique.count
    }
}

// MARK: - Serialization

extension TrustCache {
    /// Header size: version(4) + uuid(16) + num_entries(4) = 24 bytes.
    public static let headerSize = 24

    /// Total serialized size in bytes.
    public var serializedSize: Int {
        Self.headerSize + entries.count * TrustCacheEntry.packedSize
    }

    /// Deserialize a trust cache from raw data.
    public init?(from data: Data) {
        guard data.count >= Self.headerSize else { return nil }

        let base = data.startIndex
        let ver = data.withUnsafeBytes { buf in
            buf.loadUnaligned(fromByteOffset: base, as: UInt32.self)
        }
        guard ver == 1 else { return nil }
        self.version = ver

        // uuid (16 bytes at offset 4)
        let uuidBytes = data[base + 4 ..< base + 20]
        let u = uuidBytes.withUnsafeBytes { $0.load(as: uuid_t.self) }
        self.uuid = UUID(uuid: u)

        // num_entries (4 bytes at offset 20)
        let numEntries: UInt32 = data.withUnsafeBytes { buf in
            buf.loadUnaligned(fromByteOffset: base + 20, as: UInt32.self)
        }

        let expectedSize = Self.headerSize + Int(numEntries) * TrustCacheEntry.packedSize
        guard data.count >= expectedSize else { return nil }

        var parsed: [TrustCacheEntry] = []
        parsed.reserveCapacity(Int(numEntries))
        for i in 0 ..< Int(numEntries) {
            let offset = base + Self.headerSize + i * TrustCacheEntry.packedSize
            let slice = data[offset ..< offset + TrustCacheEntry.packedSize]
            guard let entry = TrustCacheEntry(from: slice) else { return nil }
            parsed.append(entry)
        }

        self.entries = parsed
    }

    /// Serialize the trust cache to raw bytes (little-endian, packed).
    public func serialize() -> Data {
        var out = Data(capacity: serializedSize)

        // version (uint32, LE)
        var ver = version.littleEndian
        out.append(Data(bytes: &ver, count: 4))

        // uuid (16 bytes, raw)
        var u = uuid.uuid
        out.append(Data(bytes: &u, count: 16))

        // num_entries (uint32, LE)
        var count = UInt32(entries.count).littleEndian
        out.append(Data(bytes: &count, count: 4))

        // entries (sorted)
        for entry in entries {
            out.append(entry.serialize())
        }

        return out
    }
}

// MARK: - File I/O

extension TrustCache {
    /// Load a trust cache from a file.
    public static func load(from url: URL) throws -> TrustCache {
        let data = try Data(contentsOf: url)
        guard let tc = TrustCache(from: data) else {
            throw TrustCacheError.invalidFormat
        }
        return tc
    }

    /// Write the trust cache to a file.
    public func write(to url: URL) throws {
        try serialize().write(to: url)
    }
}
