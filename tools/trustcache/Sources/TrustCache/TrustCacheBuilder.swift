import Foundation

// MARK: - Trust Cache Builder

/// Scans directories and files for Mach-O binaries and builds a trust cache.
///
/// This replicates the behavior of `trustcache create <outfile> <path...>`:
/// recursively scan paths for Mach-O binaries, extract CDHashes, and produce
/// a sorted v1 trust cache.
public struct TrustCacheBuilder: Sendable {
    /// The trust cache being built.
    public private(set) var trustCache: TrustCache

    /// Paths that were skipped (not Mach-O, unsigned, or malformed).
    public private(set) var skippedPaths: [String] = []

    /// Paths that were successfully added.
    public private(set) var addedPaths: [String] = []

    public init(uuid: UUID = UUID()) {
        self.trustCache = TrustCache(uuid: uuid)
    }

    // MARK: - Scanning

    /// Scan a file or directory and add all found Mach-O CDHashes.
    ///
    /// - Parameter url: A file or directory to scan.
    /// - Returns: Number of new entries added.
    @discardableResult
    public mutating func scan(_ url: URL) throws -> Int {
        let fm = FileManager.default
        var isDir: ObjCBool = false

        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else {
            throw TrustCacheError.fileNotFound(url.path)
        }

        if isDir.boolValue {
            return try scanDirectory(url)
        } else {
            return try scanFile(url)
        }
    }

    /// Scan multiple paths.
    @discardableResult
    public mutating func scan(_ urls: [URL]) throws -> Int {
        var total = 0
        for url in urls {
            total += try scan(url)
        }
        return total
    }

    // MARK: - Output

    /// Serialize the built trust cache.
    public func serialize() -> Data {
        trustCache.serialize()
    }

    /// Write the built trust cache to a file.
    public func write(to url: URL) throws {
        try trustCache.write(to: url)
    }
}

// MARK: - Private

extension TrustCacheBuilder {
    private mutating func scanDirectory(_ url: URL) throws -> Int {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey, .isExecutableKey],
            options: [.skipsHiddenFiles]
        ) else {
            return 0
        }

        var count = 0
        for case let fileURL as URL in enumerator {
            guard let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey]),
                  values.isRegularFile == true
            else { continue }

            count += (try? scanFile(fileURL)) ?? 0
        }
        return count
    }

    private mutating func scanFile(_ url: URL) throws -> Int {
        // Quick magic check before attempting MachO parse
        guard isMachOOrFat(url) else {
            skippedPaths.append(url.path)
            return 0
        }

        do {
            let entries = try CDHashExtractor.extractCDHashes(from: url)
            if entries.isEmpty {
                skippedPaths.append(url.path)
                return 0
            }
            let added = trustCache.addEntries(entries)
            if added > 0 {
                addedPaths.append(url.path)
            }
            return added
        } catch {
            skippedPaths.append(url.path)
            return 0
        }
    }

    /// Check if file starts with a Mach-O or FAT magic number.
    private func isMachOOrFat(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { handle.closeFile() }

        guard let data = try? handle.read(upToCount: 4), data.count == 4 else { return false }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }

        // Mach-O magics (LE and BE)
        let machOMagics: Set<UInt32> = [
            0xFEEDFACE, 0xCEFAEDFE, // 32-bit
            0xFEEDFACF, 0xCFFAEDFE, // 64-bit
        ]
        // FAT magics
        let fatMagics: Set<UInt32> = [
            0xCAFEBABE, 0xBEBAFECA, // FAT 32-bit offsets
            0xCAFEBABF, 0xBFBAFECA, // FAT 64-bit offsets
        ]

        return machOMagics.contains(magic) || fatMagics.contains(magic)
    }
}
