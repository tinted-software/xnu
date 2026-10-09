import Foundation
import MachOKit

// MARK: - CDHash Extraction

/// Extracts CDHash entries from Mach-O binaries for trust cache construction.
public enum CDHashExtractor {
    /// Extract CDHash from a single Mach-O file at a given offset.
    ///
    /// Selects the best available code directory (preferring SHA256 over SHA1)
    /// and computes its hash, truncated to 20 bytes for trust cache entry.
    ///
    /// - Parameters:
    ///   - url: Path to the Mach-O binary.
    ///   - offset: Byte offset into the file where the Mach-O header starts (for FAT slices).
    /// - Returns: A trust cache entry, or `nil` if the binary is unsigned.
    public static func extractCDHash(from url: URL, headerOffset: Int = 0) throws -> TrustCacheEntry? {
        let machO: MachOFile
        do {
            machO = try MachOFile(url: url, headerStartOffset: headerOffset)
        } catch {
            return nil
        }

        return extractCDHash(from: machO)
    }

    /// Extract CDHash from a parsed MachOFile.
    public static func extractCDHash(from machO: MachOFile) -> TrustCacheEntry? {
        guard let codeSign = machO.codeSign else {
            return nil
        }

        let codeDirectories = codeSign.codeDirectories
        guard !codeDirectories.isEmpty else {
            return nil
        }

        // Prefer SHA256 > SHA384 > SHA1 (matching Apple's priority)
        let best = codeDirectories.max { a, b in
            priority(of: a.hashType) < priority(of: b.hashType)
        }!

        guard let hashData = best.hash(in: codeSign) else {
            return nil
        }

        // Trust cache CDHash is always 20 bytes — truncate if longer
        let cdhash: Data
        if hashData.count >= kCDHashLength {
            cdhash = hashData.prefix(kCDHashLength)
        } else {
            var padded = hashData
            padded.append(contentsOf: repeatElement(UInt8(0), count: kCDHashLength - hashData.count))
            cdhash = padded
        }

        let hashType = mapHashType(best.hashType)
        return TrustCacheEntry(
            cdhash: cdhash,
            hashType: hashType,
            flags: .amfid
        )
    }

    /// Extract CDHashes from a file, handling both thin Mach-O and FAT/universal binaries.
    /// Each architecture slice in a FAT binary gets its own entry.
    public static func extractCDHashes(from url: URL) throws -> [TrustCacheEntry] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { handle.closeFile() }

        guard let headerData = try? handle.read(upToCount: 8), headerData.count >= 4 else {
            return []
        }

        let magic = headerData.withUnsafeBytes { $0.load(as: UInt32.self) }

        // FAT binary (big-endian magic)
        if magic == 0xBEBAFECA /* FAT_MAGIC */ || magic == 0xBFBAFECA /* FAT_MAGIC_64 */ {
            return try extractFromFat(url: url, data: headerData, is64: magic == 0xBFBAFECA)
        }

        // Thin Mach-O
        if let entry = try extractCDHash(from: url) {
            return [entry]
        }
        return []
    }
}

// MARK: - FAT Binary Parsing

extension CDHashExtractor {
    /// Parse FAT header and extract CDHash from each slice.
    private static func extractFromFat(url: URL, data: Data, is64: Bool) throws -> [TrustCacheEntry] {
        let fileData = try Data(contentsOf: url)
        guard fileData.count >= 8 else { return [] }

        // FAT header: magic(4) + nfat_arch(4), all big-endian
        let nfat = UInt32(bigEndian: fileData.withUnsafeBytes {
            $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
        })

        var entries: [TrustCacheEntry] = []
        let archHeaderSize = is64 ? 32 : 20 // fat_arch_64 vs fat_arch

        for i in 0 ..< Int(nfat) {
            let archOffset = 8 + i * archHeaderSize
            guard archOffset + archHeaderSize <= fileData.count else { break }

            // Read slice offset (big-endian)
            let sliceOffset: Int
            if is64 {
                // fat_arch_64: cputype(4) + cpusubtype(4) + offset(8)
                sliceOffset = Int(UInt64(bigEndian: fileData.withUnsafeBytes {
                    $0.loadUnaligned(fromByteOffset: archOffset + 8, as: UInt64.self)
                }))
            } else {
                // fat_arch: cputype(4) + cpusubtype(4) + offset(4)
                sliceOffset = Int(UInt32(bigEndian: fileData.withUnsafeBytes {
                    $0.loadUnaligned(fromByteOffset: archOffset + 8, as: UInt32.self)
                }))
            }

            if let entry = try extractCDHash(from: url, headerOffset: sliceOffset) {
                entries.append(entry)
            }
        }

        return entries
    }
}

// MARK: - Helpers

extension CDHashExtractor {
    /// Map MachOKit hash type to our CDHashType.
    private static func mapHashType(_ machOHashType: CodeSignHashType?) -> CDHashType {
        guard let ht = machOHashType else { return .sha256 }
        switch ht {
        case .sha1: return .sha1
        case .sha256: return .sha256
        case .sha256_truncated: return .sha256Truncated
        case .sha384: return .sha384
        @unknown default: return .sha256
        }
    }

    /// Hash type priority for selecting best code directory.
    private static func priority(of hashType: CodeSignHashType?) -> Int {
        guard let ht = hashType else { return -1 }
        switch ht {
        case .sha1: return 0
        case .sha256_truncated: return 1
        case .sha256: return 2
        case .sha384: return 3
        @unknown default: return -1
        }
    }
}
