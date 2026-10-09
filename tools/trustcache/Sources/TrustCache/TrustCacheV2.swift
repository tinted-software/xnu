import Foundation

// MARK: - Trust Cache Module (v2)
//
// Layout (packed, little-endian), from EXTERNAL_HEADERS/TrustCache/RawTypes.h:
//   uint32_t version        // always 2
//   uuid_t   uuid           // 16 bytes
//   uint32_t numEntries
//   TrustCacheEntry2 entries[numEntries]   // 24 bytes each
// Entry: cdhash[20], hashType, flags, constraintCategory, reserved0

public struct TrustCacheEntry2: Sendable, Equatable {
    public static let size = 24
    public var cdhash: Data
    public var hashType: UInt8
    public var flags: UInt8
    public var constraintCategory: UInt8
}

public struct TrustCacheModule2: Sendable {
    public static let headerSize = 24
    public let uuid: UUID
    public let entries: [TrustCacheEntry2]

    public init(data: Data) throws {
        guard data.count >= Self.headerSize else {
            throw TrustCacheError.truncated
        }
        let version = Self.u32(data, 0)
        guard version == 2 else {
            throw TrustCacheError.unexpectedVersion(version)
        }
        let uuidBytes = data.subdata(in: 4..<20)
        let uuidTuple = uuidBytes.withUnsafeBytes { raw -> uuid_t in
            raw.load(as: uuid_t.self)
        }
        self.uuid = UUID(uuid: uuidTuple)
        let count = Int(Self.u32(data, 20))
        let needed = Self.headerSize + count * TrustCacheEntry2.size
        guard data.count >= needed else {
            throw TrustCacheError.truncated
        }
        var out: [TrustCacheEntry2] = []
        out.reserveCapacity(count)
        for i in 0..<count {
            let base = Self.headerSize + i * TrustCacheEntry2.size
            out.append(TrustCacheEntry2(
                cdhash: data.subdata(in: base..<(base + 20)),
                hashType: data[base + 20],
                flags: data[base + 21],
                constraintCategory: data[base + 22]
            ))
        }
        self.entries = out
    }

    public func lookup(cdhash: Data) -> TrustCacheEntry2? {
        entries.first { $0.cdhash == cdhash }
    }

    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
        }
    }
}
