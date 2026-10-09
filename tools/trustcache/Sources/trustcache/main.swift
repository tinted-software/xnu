import Foundation
import Crypto
import MachOKit
import TrustCache

// Host-side trust cache tool.
//   trustcache unwrap  <im4p>         <payload-out>   IM4P DER -> raw trust cache module
//   trustcache wrap    <blob-out> <payload>...        raw modules -> trust_cache_offsets_t blob (module order kept)
//   trustcache inspect <payload>                      print version/uuid/entry count
//   trustcache cdhash  <macho>                        20-byte SHA-256 cdhash (as AMFI computes it)
//   trustcache lookup  <payload> <macho>              exit 0 if the binary's cdhash is in the cache

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func readFile(_ path: String) -> Data {
    guard let d = FileManager.default.contents(atPath: path) else {
        fail("cannot read \(path)")
    }
    return d
}

func writeFile(_ data: Data, _ path: String) {
    do {
        try data.write(to: URL(fileURLWithPath: path))
    } catch {
        fail("cannot write \(path): \(error)")
    }
}

// Minimal DER reader: returns (tag, content range) for the TLV at offset.
func readTLV(_ d: Data, _ offset: Int) -> (tag: UInt8, start: Int, end: Int) {
    let tag = d[offset]
    var len = Int(d[offset + 1])
    var pos = offset + 2
    if len & 0x80 != 0 {
        let n = len & 0x7f
        len = 0
        for i in 0..<n {
            len = (len << 8) | Int(d[pos + i])
        }
        pos += n
    }
    return (tag, pos, pos + len)
}

// IM4P: SEQUENCE { IA5 "IM4P", IA5 type, IA5 description, OCTET STRING payload }.
func unwrapIM4P(_ d: Data) -> Data {
    let outer = readTLV(d, 0)
    guard outer.tag == 0x30 else { fail("not a DER SEQUENCE") }
    var cur = outer.start
    var fields: [Data] = []
    for _ in 0..<4 {
        let t = readTLV(d, cur)
        fields.append(d.subdata(in: t.start..<t.end))
        cur = t.end
    }
    guard String(data: fields[0], encoding: .ascii) == "IM4P" else {
        fail("not an IM4P container")
    }
    return fields[3]
}

// trust_cache_offsets_t: uint32 num_caches; uint32 offsets[num_caches] (relative to struct start).
func wrapOffsets(_ payloads: [Data]) -> Data {
    var out = Data()
    func put(_ v: UInt32) {
        var v = v.littleEndian
        withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
    }
    put(UInt32(payloads.count))
    var off = UInt32(4 + 4 * payloads.count)
    for p in payloads {
        put(off)
        off += UInt32(p.count)
    }
    for p in payloads {
        out.append(p)
    }
    return out
}

// Code directory blob for slot 0 (CSSLOT_CODEDIRECTORY), whole blob including header.
func codeDirectoryBlob(_ path: String) -> Data {
    let url = URL(fileURLWithPath: path)
    guard let file = try? MachOFile(url: url) else {
        fail("not a Mach-O: \(path)")
    }
    guard let sig = file.codeSign, let superBlob = sig.superBlob else {
        fail("no code signature in \(path)")
    }
    guard let index = sig.blobIndices(of: superBlob).first(where: { $0.type == .codedirectory }) else {
        fail("no code directory in \(path)")
    }
    guard let blob = sig.blobData(in: superBlob, at: index, includesGenericInfo: true) else {
        fail("cannot read code directory in \(path)")
    }
    return blob
}

func cdhash(_ path: String) -> Data {
    Data(SHA256.hash(data: codeDirectoryBlob(path)).prefix(20))
}

func hex(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    fail("usage: trustcache unwrap|wrap|inspect|cdhash|lookup ...")
}

switch args[1] {
case "unwrap":
    guard args.count == 4 else { fail("usage: trustcache unwrap <im4p> <out>") }
    writeFile(unwrapIM4P(readFile(args[2])), args[3])

case "wrap":
    guard args.count >= 4 else { fail("usage: trustcache wrap <out> <payload>...") }
    writeFile(wrapOffsets(args[3...].map(readFile)), args[2])

case "inspect":
    guard args.count == 3 else { fail("usage: trustcache inspect <payload>") }
    do {
        let m = try TrustCacheModule2(data: readFile(args[2]))
        print("version 2, uuid \(m.uuid), entries \(m.entries.count)")
    } catch {
        fail("inspect failed: \(error)")
    }

case "cdhash":
    guard args.count == 3 else { fail("usage: trustcache cdhash <macho>") }
    print(hex(cdhash(args[2])))

case "lookup":
    guard args.count == 4 else { fail("usage: trustcache lookup <payload> <macho>") }
    do {
        let m = try TrustCacheModule2(data: readFile(args[2]))
        let h = cdhash(args[3])
        if let e = m.lookup(cdhash: h) {
            print("found hashType=\(e.hashType) flags=\(e.flags) constraintCategory=\(e.constraintCategory)")
        } else {
            fail("not in trust cache: \(hex(h))")
        }
    } catch {
        fail("lookup failed: \(error)")
    }

default:
    fail("unknown command \(args[1])")
}
