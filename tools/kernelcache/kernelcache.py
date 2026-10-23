"""Kernel collection assembler: wraps the kernel and its kexts in an MH_FILESET.

Vendored from the buck2 port (tools/buck/kernelcache.py) and used by the make
build: build-kernelcache.sh passes the layout that makedefs/MakeInc.def links
the kernel with when KERNELCACHE=1.

A stock kernelcache is an MH_FILESET: an outer mach header whose segments span
every member, one LC_FILESET_ENTRY per member (`com.apple.kernel` first, then
the kexts), an LC_DYLD_CHAINED_FIXUPS that the kernel applies to the whole image
at boot (osfmk/mach/dyld_kernel_fixups.h kernel_collection_slide; that is where
an arm64e kernelcache gets its pointers signed), and a __PRELINK_INFO plist that
describes the kexts to libsa/bootstrap.cpp. This tool builds that.

  * The kernel's mach header gets MH_DYLIB_IN_CACHE, file offsets equal to
    `vmaddr - base` (the layout kernel_collection_adjust_mh_addrs expects) and
    the empty __PRELINK_*/__PLK_* segments the kernel looks for. Its own
    __TEXT,__thread_starts rebase chains become kernel-cache chain fixups.
  * A kext is an MH_KEXT_BUNDLE linked, with mold, at its final addresses in a
    slot of the regions the kernel link reserves for kexts. The tool places its
    segments, binds its imports against the kernel's symbols, turns its
    relocations into chain fixups (keeping the pointer-auth schema mold left in
    the slot), and records it in the prelink plist.

The address layout is defined once, in xnu/kernel.bzl KC_LAYOUT, and passed in on
the command line (kc_layout_args()).
"""

import argparse
import os
import plistlib
import secrets
import struct
import uuid
from dataclasses import dataclass, field

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_KEXT_BUNDLE = 0xB
MH_FILESET = 0xC
MH_DYLIB_IN_CACHE = 0x80000000
CPU_TYPE_ARM64 = 0x0100000C

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_UNIXTHREAD = 0x5
LC_UUID = 0x1B
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FILESET_ENTRY = 0x80000035
LC_DYLD_CHAINED_FIXUPS = 0x80000034
# linkedit_data_command: dataoff at 8, datasize at 12.
LINKEDIT_DATA_CMDS = {0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x36, 0x80000033, 0x80000034}

VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE = 1, 2, 4
SG_NORELOC = 0x4
S_ATTR_PURE_INSTRUCTIONS_SOME = 0x80000400
N_EXT = 0x01
N_TYPE = 0x0E
N_SECT = 0x0E
N_UNDF = 0x00

HEADER_SIZE = 32
SEG_CMD_SIZE = 72
SECT_SIZE = 80
PAGE = 0x4000  # outer segments and chain pages; fine for 4 KiB kernels too

DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8
DYLD_CHAINED_PTR_START_NONE = 0xFFFF
DYLD_CHAINED_IMPORT = 1

# OSKext's marker for a kext with no executable: an interface (KPI) pseudo-kext.
CODELESS_LOAD_ADDR = 0x7FFFFFFFFFFFFFFF
# The KPI pseudo-kexts a kext's OSBundleLibraries may name (id suffix: executable).
KPI_KEXTS = {
    "bsd": "BSDKernel",
    "dsep": "DSEP",
    "iokit": "IOKit",
    "libkern": "Libkern",
    "mach": "Mach",
    "private": "Private",
    "unsupported": "Unsupported",
}
# The kernel version the KPI pseudo-kexts must match ('osrelease').
OSRELEASE = "27.0.0"


def align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def cstr(b: bytes) -> str:
    return bytes(b).split(b"\x00")[0].decode("ascii", errors="replace")


def s64(v: int) -> int:
    """An unsigned address as the signed integer the prelink plist stores."""
    return v - (1 << 64) if v >= 1 << 63 else v


# ---------------------------------------------------------------------------
# Mach-O access
# ---------------------------------------------------------------------------


@dataclass
class Section:
    name: str
    segname: str
    addr: int
    size: int
    offset: int
    off: int  # offset of the section_64 inside the header buffer


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    flags: int
    sections: list[Section]
    off: int  # offset of the segment_command_64 inside the header buffer


@dataclass
class Macho:
    """A mach header plus load commands, kept mutable in `hdr`."""

    hdr: bytearray
    data: bytes  # the whole file the header was parsed from
    filetype: int
    ncmds: int
    sizeofcmds: int
    cmds: list[tuple[int, int, int]] = field(default_factory=list)  # cmd,off,size

    @classmethod
    def parse(cls, data: bytes, base: int = 0) -> "Macho":
        magic, cputype, _, filetype, ncmds, sizeofcmds, _, _ = struct.unpack_from(
            "<IIIIIIII", data, base
        )
        if magic != MH_MAGIC_64:
            raise ValueError(f"not a 64-bit Mach-O: magic 0x{magic:x}")
        if cputype != CPU_TYPE_ARM64:
            raise ValueError(f"unexpected cputype 0x{cputype:x}")
        hdr = bytearray(data[base : base + HEADER_SIZE + sizeofcmds])
        m = cls(hdr, data, filetype, ncmds, sizeofcmds)
        off = HEADER_SIZE
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", hdr, off)
            if size < 8:
                raise ValueError("malformed load command")
            m.cmds.append((cmd, off, size))
            off += size
        return m

    @property
    def flags(self) -> int:
        return struct.unpack_from("<I", self.hdr, 24)[0]

    @flags.setter
    def flags(self, v: int) -> None:
        struct.pack_into("<I", self.hdr, 24, v)

    def segments(self) -> list[Segment]:
        out = []
        for cmd, off, _size in self.cmds:
            if cmd != LC_SEGMENT_64:
                continue
            name = cstr(self.hdr[off + 8 : off + 24])
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = (
                struct.unpack_from("<QQQQIIII", self.hdr, off + 24)
            )
            sects = []
            so = off + SEG_CMD_SIZE
            for _ in range(nsects):
                sname = cstr(self.hdr[so : so + 16])
                sg = cstr(self.hdr[so + 16 : so + 32])
                addr, size, offset = struct.unpack_from("<QQI", self.hdr, so + 32)
                sects.append(Section(sname, sg, addr, size, offset, so))
                so += SECT_SIZE
            out.append(
                Segment(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, flags, sects, off)
            )
        return out

    def find_section(self, segname: str | None, name: str) -> Section | None:
        for seg in self.segments():
            for s in seg.sections:
                if s.name == name and (segname is None or s.segname == segname):
                    return s
        return None

    def command(self, cmd: int) -> tuple[int, int] | None:
        for c, off, size in self.cmds:
            if c == cmd:
                return off, size
        return None

    def uuid(self) -> bytes:
        cmd = self.command(LC_UUID)
        if cmd is None:
            return b""
        return bytes(self.hdr[cmd[0] + 8 : cmd[0] + 24])

    def symbols(self) -> list[tuple[str, int, int]]:
        """(name, n_type, n_value) of every symbol, from the file it was parsed from."""
        cmd = self.command(LC_SYMTAB)
        if cmd is None:
            return []
        symoff, nsyms, stroff, _strsize = struct.unpack_from("<IIII", self.hdr, cmd[0] + 8)
        out = []
        for i in range(nsyms):
            strx, ntype, _sect, _desc, value = struct.unpack_from(
                "<IBBHQ", self.data, symoff + i * 16
            )
            end = self.data.index(b"\x00", stroff + strx)
            out.append((self.data[stroff + strx : end].decode("ascii", "replace"), ntype, value))
        return out


def set_segment(hdr: bytearray, seg: Segment, **fields: int) -> None:
    """Rewrites fields of `seg`'s command in `hdr`."""
    layout = {
        "vmaddr": (24, "<Q"),
        "vmsize": (32, "<Q"),
        "fileoff": (40, "<Q"),
        "filesize": (48, "<Q"),
        "maxprot": (56, "<I"),
        "initprot": (60, "<I"),
        "flags": (68, "<I"),
    }
    for k, v in fields.items():
        o, f = layout[k]
        struct.pack_into(f, hdr, seg.off + o, v)


def shift_linkedit_offsets(m: Macho, delta: int) -> None:
    """Moves every file offset into __LINKEDIT in `m`'s load commands."""

    def bump(off: int) -> None:
        v = struct.unpack_from("<I", m.hdr, off)[0]
        if v:
            struct.pack_into("<I", m.hdr, off, v + delta)

    for cmd, off, _size in m.cmds:
        if cmd == LC_SYMTAB:
            bump(off + 8)
            bump(off + 16)
        elif cmd == LC_DYSYMTAB:
            for o in (32, 40, 48, 56, 64, 72):
                bump(off + o)
        elif cmd in LINKEDIT_DATA_CMDS:
            bump(off + 8)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            for o in (8, 16, 24, 32, 40):
                bump(off + o)


def relocate_to_cache(m: Macho, base: int, linkedit_vm: int | None) -> None:
    """Rewrites a member's header for its place in the collection: flagged as in
    the cache, file offsets `vmaddr - base`, __LINKEDIT at `linkedit_vm`."""
    m.flags = m.flags | MH_DYLIB_IN_CACHE
    old_linkedit = None
    for seg in m.segments():
        if seg.name == "__LINKEDIT":
            old_linkedit = seg
            assert linkedit_vm is not None
            set_segment(
                m.hdr, seg,
                vmaddr=linkedit_vm,
                fileoff=linkedit_vm - base,
                vmsize=align(seg.filesize, PAGE),
            )
        else:
            set_segment(m.hdr, seg, fileoff=seg.vmaddr - base)
        for s in seg.sections:
            if s.offset:
                struct.pack_into("<I", m.hdr, s.off + 48, s.addr - base)
    if old_linkedit is not None:
        shift_linkedit_offsets(m, (linkedit_vm - base) - old_linkedit.fileoff)


# ---------------------------------------------------------------------------
# Rebase chains
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Fixup:
    """One pointer of the image: where, what it points at, how it is signed."""

    loc: int  # vm address of the pointer
    target: int  # vm address it points at
    auth: bool = False
    diversity: int = 0
    addr_div: bool = False
    key: int = 0


def decode_threaded_starts(
    kernel: Macho, kernel_vm: int, image: bytes, base: int
) -> list[Fixup]:
    """Fixups listed by the kernel's __thread_starts (the arm64e static-kernelcache
    rebase format, osfmk/mach/dyld_kernel_fixups.h rebase_chain).

    `image` holds the kernel at file offset `vmaddr - base`; its pointers are
    still in the threaded encoding. The chain starts are offsets from the
    kernel's mach header; an authenticated rebase stores its target as one too.
    """
    sect = kernel.find_section(None, "__thread_starts")
    if sect is None or sect.size == 0:
        return []
    raw = image[sect.addr - base : sect.addr - base + sect.size]
    if not raw:
        return []
    words = struct.unpack(f"<{len(raw) // 4}I", raw)
    step = 8 if words[0] & 1 else 4
    fixups: list[Fixup] = []
    for start in words[1:]:
        if start == 0xFFFFFFFF:
            break
        loc = kernel_vm + start
        while True:
            value = struct.unpack_from("<Q", image, loc - base)[0]
            if value >> 62 & 1:
                raise ValueError(f"bind in kernel rebase chain at 0x{loc:x}")
            if value >> 63 & 1:
                fixups.append(
                    Fixup(
                        loc,
                        kernel_vm + (value & 0xFFFFFFFF),
                        True,
                        value >> 32 & 0xFFFF,
                        bool(value >> 48 & 1),
                        value >> 49 & 3,
                    )
                )
            else:
                # A plain pointer: 8 high bits and a sign-extended 43-bit
                # address packed into 51 bits.
                top8 = value & 0x0007F80000000000
                bottom43 = value & 0x000007FFFFFFFFFF
                if bottom43 >> 42:
                    bottom43 |= 0xFFFFFFFFFFFFFFFF & ~0x7FFFFFFFFFF
                target = (top8 << 13) | (bottom43 & 0x00FFFFFFFFFFFFFF)
                fixups.append(Fixup(loc, target & 0xFFFFFFFFFFFFFFFF))
            delta = (value & ~(1 << 62) & 0x3FF8000000000000) >> 51
            if delta == 0:
                break
            loc += delta * step
    return fixups


def encode_chain_fixups(
    fixups: list[Fixup],
    base: int,
    segments: list[tuple[str, int, int]],
    image: bytearray,
) -> bytes:
    """Writes the chains into `image` (file offset = vmaddr - base) and returns the
    dyld_chained_fixups blob describing them.

    `segments` are the outer segments in load-command order, as
    (name, vmaddr, vmsize). Each pointer becomes a
    dyld_chained_ptr_64_kernel_cache_rebase: a 30-bit target relative to `base`,
    the pointer-auth schema, and a 4-byte-stride `next` that ends at the page.
    """
    per_page: dict[tuple[int, int], list[Fixup]] = {}
    seen: set[int] = set()
    for f in fixups:
        if f.loc in seen:
            raise ValueError(f"two fixups for the pointer at 0x{f.loc:x}")
        seen.add(f.loc)
        for idx, (_name, vm, size) in enumerate(segments):
            if vm <= f.loc < vm + size:
                per_page.setdefault((idx, (f.loc - vm) // PAGE), []).append(f)
                break
        else:
            raise ValueError(f"pointer at 0x{f.loc:x} is outside every segment")

    page_starts: dict[int, dict[int, int]] = {}
    for (idx, page), items in per_page.items():
        items.sort(key=lambda f: f.loc)
        for i, f in enumerate(items):
            offset = f.target - base
            if not 0 <= offset < 1 << 30:
                raise ValueError(
                    f"pointer at 0x{f.loc:x} targets 0x{f.target:x}, outside the "
                    "30-bit range of a kernel-cache fixup"
                )
            if f.loc % 4:
                raise ValueError(f"pointer at 0x{f.loc:x} is not 4-byte aligned")
            nxt = (items[i + 1].loc - f.loc) // 4 if i + 1 < len(items) else 0
            word = (
                offset
                | f.diversity << 32
                | int(f.addr_div) << 48
                | f.key << 49
                | nxt << 51
                | int(f.auth) << 63
            )
            struct.pack_into("<Q", image, f.loc - base, word)
        page_starts.setdefault(idx, {})[page] = (items[0].loc - segments[idx][1]) % PAGE

    # starts_in_segment blobs.
    seg_blobs: dict[int, bytes] = {}
    for idx, pages in page_starts.items():
        _name, vm, size = segments[idx]
        count = (size + PAGE - 1) // PAGE
        starts = [pages.get(p, DYLD_CHAINED_PTR_START_NONE) for p in range(count)]
        blob = struct.pack(
            "<IHHQIH", 22 + 2 * count, PAGE, DYLD_CHAINED_PTR_64_KERNEL_CACHE, vm - base, 0, count
        ) + struct.pack(f"<{count}H", *starts)
        seg_blobs[idx] = blob + b"\x00" * (align(len(blob), 8) - len(blob))

    seg_count = len(segments)
    starts_off = 32
    cursor = align(4 + 4 * seg_count, 8)
    offsets = [0] * seg_count
    body = bytearray()
    for idx in range(seg_count):
        if idx in seg_blobs:
            offsets[idx] = cursor + len(body)
            body += seg_blobs[idx]
    starts = struct.pack(f"<I{seg_count}I", seg_count, *offsets).ljust(cursor, b"\x00") + bytes(body)
    imports_off = starts_off + len(starts)
    header = struct.pack(
        "<7I", 0, starts_off, imports_off, imports_off, 0, DYLD_CHAINED_IMPORT, 0
    )
    return header.ljust(starts_off, b"\x00") + starts


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


@dataclass
class Layout:
    """KC_LAYOUT from xnu/kernel.bzl: offsets from `base`, regions as (start, end)."""

    base: int
    kernel_offset: int
    kext_text: tuple[int, int]
    data_const: int
    lastdata_const: int
    kext_data_const: tuple[int, int]
    kext_text_exec: tuple[int, int]
    text_exec: int
    kld_data: int
    kext_data: tuple[int, int]

    def at(self, offset: int) -> int:
        return self.base + offset

    def region(self, r: tuple[int, int]) -> tuple[int, int]:
        return self.base + r[0], self.base + r[1]


def pair(s: str) -> tuple[int, int]:
    a, b = s.split(",")
    return int(a, 0), int(b, 0)


# ---------------------------------------------------------------------------
# Kexts
# ---------------------------------------------------------------------------


@dataclass
class Kext:
    bundle_id: str
    path: str
    macho: Macho
    data: bytes
    text: Segment
    segments: dict[str, Segment]
    kmod_info: int
    info: dict
    linkedit_vm: int = 0


def load_kext(bundle_id: str, path: str, layout: Layout) -> Kext:
    with open(path, "rb") as f:
        data = f.read()
    m = Macho.parse(data)
    if m.filetype != MH_KEXT_BUNDLE:
        raise ValueError(f"{path}: not an MH_KEXT_BUNDLE (filetype 0x{m.filetype:x})")
    segs = {s.name: s for s in m.segments()}
    regions = {
        "__TEXT": layout.region(layout.kext_text),
        "__DATA_CONST": layout.region(layout.kext_data_const),
        "__TEXT_EXEC": layout.region(layout.kext_text_exec),
        "__DATA": layout.region(layout.kext_data),
    }
    for name, (lo, hi) in regions.items():
        seg = segs.get(name)
        if seg is None:
            continue
        if seg.vmsize and (seg.vmaddr < lo or seg.vmaddr + seg.vmsize > hi):
            raise ValueError(
                f"{path}: {name} at 0x{seg.vmaddr:x}+0x{seg.vmsize:x} is outside its region "
                f"0x{lo:x}-0x{hi:x}; link it with kext_ldflags()"
            )
    if "__TEXT" not in segs or "__LINKEDIT" not in segs:
        raise ValueError(f"{path}: needs __TEXT and __LINKEDIT")
    kmod = [v for n, t, v in m.symbols() if n == "_kmod_info" and t & N_TYPE == N_SECT]
    if not kmod:
        raise ValueError(f"{path}: no _kmod_info symbol (KMOD_DECL)")
    info_sect = m.find_section("__TEXT", "__info")
    if info_sect is None:
        raise ValueError(f"{path}: no __TEXT,__info Info.plist")
    info = plistlib.loads(data[info_sect.offset : info_sect.offset + info_sect.size].rstrip(b"\x00"))
    if info.get("CFBundleIdentifier") != bundle_id:
        raise ValueError(
            f"{path}: Info.plist says {info.get('CFBundleIdentifier')!r}, not {bundle_id!r}"
        )
    return Kext(bundle_id, path, m, data, segs["__TEXT"], segs, kmod[0], info)


def kext_fixups(k: Kext, image: bytes, base: int, ksyms: dict[str, int]) -> list[Fixup]:
    """A kext's relocations as chain fixups.

    mold leaves a kext's pointers as the object file's: a local relocation per
    pointer (its slot already holds the final address, or, for a signed pointer,
    the schema above the low 32 bits of it) and an external one per import (a
    GOT slot kmutil fills in; an arm64e kext calls imports through plain stubs,
    so those are unsigned). The addresses are offsets from the first segment.
    """
    cmd = k.macho.command(LC_DYSYMTAB)
    if cmd is None:
        return []
    fields = struct.unpack_from("<18I", k.macho.hdr, cmd[0] + 8)
    extreloff, nextrel, locreloff, nlocrel = fields[14:18]
    first_vm = min(s.vmaddr for s in k.segments.values())
    upper = base & ~0xFFFFFFFF
    names = [n for n, _t, _v in k.macho.symbols()]
    out: list[Fixup] = []

    def reloc(off: int) -> tuple[int, int, bool, int, int]:
        addr, word = struct.unpack_from("<iI", k.data, off)
        return (
            first_vm + addr,
            word & 0xFFFFFF,
            bool(word >> 27 & 1),
            word >> 25 & 3,
            word >> 28 & 0xF,
        )

    for i in range(nextrel):
        loc, symnum, ext, length, rtype = reloc(extreloff + i * 8)
        if not (ext and length == 3 and rtype == 0):
            raise ValueError(f"{k.path}: unsupported external relocation at 0x{loc:x}")
        name = names[symnum]
        if name not in ksyms:
            raise ValueError(f"{k.path} imports {name}, which the kernel does not define")
        out.append(Fixup(loc, ksyms[name]))
    for i in range(nlocrel):
        loc, _sym, ext, length, rtype = reloc(locreloff + i * 8)
        if ext or length != 3 or rtype != 0:
            raise ValueError(f"{k.path}: unsupported local relocation at 0x{loc:x}")
        value = struct.unpack_from("<Q", image, loc - base)[0]
        # mold's signed-pointer slot is 1<<63 | key | address diversity |
        # diversity above the low 32 bits of the target, with bits 51-62 clear.
        # A plain pointer is a kernel address, whose bits 51-62 are all set (and
        # bit 63 too), so bit 63 alone cannot tell the two apart.
        if value >> 63 and not value >> 51 & 0xFFF:
            # The cache's addresses share their upper word.
            out.append(
                Fixup(
                    loc, upper | (value & 0xFFFFFFFF), True,
                    value >> 32 & 0xFFFF, bool(value >> 48 & 1), value >> 49 & 3,
                )
            )
        else:
            if value & ~0xFFFFFFFF != upper:
                raise ValueError(
                    f"{k.path}: pointer at 0x{loc:x} holds 0x{value:x}, which is neither "
                    "a signed-pointer slot nor an address in the cache"
                )
            out.append(Fixup(loc, value))
    return out


def prelink_info(
    kexts: list[Kext], raw_uuid: bytes, kernel_vm: int
) -> bytes:
    """The __PRELINK_INFO plist libsa/bootstrap.cpp readPrelinkedExtensions() reads."""
    entries: list[dict] = []
    for suffix, exe in KPI_KEXTS.items():
        bundle_id = f"com.apple.kpi.{suffix}"
        entries.append({
            "CFBundleDevelopmentRegion": "English",
            "CFBundleExecutable": exe,
            "CFBundleGetInfoString": f"{exe} Pseudoextension, {OSRELEASE}",
            "CFBundleIdentifier": bundle_id,
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": f"{exe} Pseudoextension",
            "CFBundlePackageType": "KEXT",
            "CFBundleShortVersionString": OSRELEASE,
            "CFBundleSignature": "????",
            "CFBundleVersion": OSRELEASE,
            "OSBundleAllowUserLoad": True,
            "OSBundleCompatibleVersion": "8.0.0b1",
            "OSBundleRequired": "Root",
            "OSBundleUUID": uuid.uuid5(uuid.NAMESPACE_DNS, bundle_id).bytes,
            "OSKernelResource": True,
            "_PrelinkBundlePath": f"/System/Library/Extensions/System.kext/PlugIns/{exe}.kext",
            "_PrelinkExecutableLoadAddr": CODELESS_LOAD_ADDR,
            "_PrelinkExecutableSourceAddr": CODELESS_LOAD_ADDR,
        })
    for k in kexts:
        info = dict(k.info)
        exe = info.get("CFBundleExecutable", k.bundle_id)
        info.update({
            "OSBundleUUID": k.macho.uuid(),
            "_PrelinkBundlePath": f"/System/Library/Extensions/{exe}.kext",
            "_PrelinkExecutableRelativePath": exe,
            "_PrelinkExecutableLoadAddr": s64(k.text.vmaddr),
            "_PrelinkExecutableSourceAddr": s64(k.text.vmaddr),
            "_PrelinkExecutableSize": k.text.vmsize,
            "_PrelinkKmodInfo": s64(k.kmod_info),
        })
        entries.append(info)
    root = {
        "KMBuildVersion": "xnu-kernelcache.py",
        "ManagerVersion": 1,
        "OSPrelinkInfoContainsUUIDs": True,
        "_PrelinkInfoDictionary": entries,
        "_PrelinkKCID": raw_uuid,
    }
    return plistlib.dumps(root, fmt=plistlib.FMT_XML)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def pack_section(name: str, segname: str, addr: int, size: int, offset: int, flags: int = 0) -> bytes:
    buf = bytearray(SECT_SIZE)
    buf[0 : len(name)] = name.encode("ascii")
    buf[16 : 16 + len(segname)] = segname.encode("ascii")
    struct.pack_into("<QQIIIII", buf, 32, addr, size, offset, 0, 0, 0, flags)
    return bytes(buf)


def pack_segment(
    name: str,
    vmaddr: int,
    vmsize: int,
    fileoff: int,
    filesize: int,
    prot: int,
    sections: list[bytes],
    flags: int = 0,
) -> bytes:
    cmdsize = SEG_CMD_SIZE + SECT_SIZE * len(sections)
    buf = bytearray(SEG_CMD_SIZE)
    struct.pack_into("<II", buf, 0, LC_SEGMENT_64, cmdsize)
    buf[8 : 8 + len(name)] = name.encode("ascii")
    struct.pack_into("<QQQQIIII", buf, 24, vmaddr, vmsize, fileoff, filesize, prot, prot, len(sections), flags)
    return bytes(buf) + b"".join(sections)


def fileset_entry(name: str, vmaddr: int, fileoff: int) -> bytes:
    raw = name.encode("ascii") + b"\x00"
    size = align(32 + len(raw), 8)
    buf = bytearray(size)
    struct.pack_into("<IIQQII", buf, 0, LC_FILESET_ENTRY, size, vmaddr, fileoff, 32, 0)
    buf[32 : 32 + len(raw)] = raw
    return bytes(buf)


R, RW, RX = VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_EXECUTE


def build_kernelcache(
    kernel_path: str,
    output_path: str,
    layout: Layout,
    raw_uuid: bytes,
    kext_args: list[tuple[str, str]],
) -> None:
    with open(kernel_path, "rb") as f:
        kdata = f.read()
    kernel = Macho.parse(kdata)
    if kernel.filetype != MH_EXECUTE:
        raise ValueError(f"kernel is not MH_EXECUTE: 0x{kernel.filetype:x}")
    # Prelinked kexts bind against the kernel's whole symbol table, exported or
    # not (in a kernel collection they share the kernel's image); prefer a
    # global definition over a local one of the same name.
    ksyms = {}
    for n, t, v in kernel.symbols():
        if t & N_TYPE == N_SECT and not t & N_EXT:
            ksyms.setdefault(n, v)
    for n, t, v in kernel.symbols():
        if t & N_TYPE == N_SECT and t & N_EXT:
            ksyms[n] = v
    kexts = [load_kext(bid, path, layout) for bid, path in kext_args]

    base = layout.base
    ksegs = {s.name: s for s in kernel.segments()}
    kernel_vm = layout.at(layout.kernel_offset)
    if ksegs["__TEXT"].vmaddr != kernel_vm:
        raise ValueError(
            f"kernel __TEXT is at 0x{ksegs['__TEXT'].vmaddr:x}, KC_LAYOUT puts it at 0x{kernel_vm:x}"
        )
    for need in ("__LASTDATA_CONST", "__LAST", "__KLDDATA", "__DATA", "__BOOTDATA", "__LINKEDIT"):
        if need not in ksegs:
            raise ValueError(f"kernel has no {need} segment (a fileset entry needs it)")

    # Where each region of the collection ends, from what the kernel linked.
    text_group_end = align(
        max(ksegs[n].vmaddr + ksegs[n].vmsize for n in ("__TEXT_EXEC", "__KLD", "__LAST")), PAGE
    )
    data_end = align(
        max(ksegs[n].vmaddr + ksegs[n].vmsize for n in ("__KLDDATA", "__DATA", "__BOOTDATA")), PAGE
    )
    prelink_data, kc_data_end = layout.region(layout.kext_data)
    linkedit_vm = kc_data_end

    def check(cond: bool, what: str) -> None:
        if not cond:
            raise ValueError(f"layout overflow: {what}")

    check(ksegs["__TEXT"].vmaddr + ksegs["__TEXT"].vmsize <= layout.at(layout.kext_text[0]), "kernel __TEXT")
    check(ksegs["__DATA_CONST"].vmaddr + ksegs["__DATA_CONST"].vmsize <= layout.at(layout.lastdata_const), "kernel __DATA_CONST")
    check(ksegs["__TEXT_EXEC"].vmaddr + ksegs["__TEXT_EXEC"].vmsize <= text_group_end, "kernel __TEXT_EXEC")
    check(text_group_end <= layout.at(layout.kld_data), "kernel text group")
    check(data_end <= prelink_data, "kernel data group")

    # Members of the collection: no two kext segments may overlap.
    taken: list[tuple[int, int, str]] = []
    for k in kexts:
        for seg in k.segments.values():
            if seg.name == "__LINKEDIT" or not seg.vmsize:
                continue
            for lo, hi, who in taken:
                if seg.vmaddr < hi and lo < seg.vmaddr + seg.vmsize:
                    raise ValueError(f"{k.bundle_id} {seg.name} overlaps {who}")
            taken.append((seg.vmaddr, seg.vmaddr + seg.vmsize, f"{k.bundle_id} {seg.name}"))

    # __LINKEDIT: the outer chained-fixups blob, then each member's tables.
    kernel_linkedit = ksegs["__LINKEDIT"]
    chained_blob_pad = PAGE
    cursor = linkedit_vm + chained_blob_pad
    inner_linkedit_vm = cursor
    cursor = align(cursor + kernel_linkedit.filesize, PAGE)
    for k in kexts:
        k.linkedit_vm = cursor
        cursor = align(cursor + k.segments["__LINKEDIT"].filesize, PAGE)
    linkedit_end = cursor
    image = bytearray(linkedit_end - base)

    # The linked members in their final layout: file offset == vmaddr - base.
    for seg in ksegs.values():
        if seg.name == "__LINKEDIT" or seg.filesize == 0:
            continue
        image[seg.vmaddr - base : seg.vmaddr - base + seg.filesize] = kdata[
            seg.fileoff : seg.fileoff + seg.filesize
        ]
    image[inner_linkedit_vm - base : inner_linkedit_vm - base + kernel_linkedit.filesize] = kdata[
        kernel_linkedit.fileoff : kernel_linkedit.fileoff + kernel_linkedit.filesize
    ]
    for k in kexts:
        for seg in k.segments.values():
            if seg.filesize == 0:
                continue
            dst = k.linkedit_vm if seg.name == "__LINKEDIT" else seg.vmaddr
            image[dst - base : dst - base + seg.filesize] = k.data[seg.fileoff : seg.fileoff + seg.filesize]

    # Fixups, collected while the pointers are still in their linked encodings.
    fixups = decode_threaded_starts(kernel, kernel_vm, bytes(image), base)
    for k in kexts:
        fixups += kext_fixups(k, image, base, ksyms)

    # Inner (com.apple.kernel) header.
    relocate_to_cache(kernel, base, inner_linkedit_vm)
    hdr = kernel.hdr

    # The segments a fileset entry kernel carries empty, at the addresses the
    # kernel computes the kexts' regions from (osfmk/arm64/arm_vm_init.c).
    empties = [
        ("__PRELINK_TEXT", layout.at(layout.kext_text[0]), RX, "__text"),
        ("__PRELINK_INFO", text_group_end, RW, "__info"),
        ("__PLK_TEXT_EXEC", layout.at(layout.kext_text_exec[0]), RW, "__text"),
        ("__PRELINK_DATA", prelink_data, RW, "__data"),
        ("__PLK_DATA_CONST", layout.at(layout.kext_data_const[0]), RW, "__data"),
        ("__PLK_LINKEDIT", linkedit_vm, RW, "__data"),
    ]
    extra = b"".join(
        pack_segment(
            name, vm, 0, vm - base, 0, prot,
            [pack_section(sect, name, vm, 0, vm - base)], SG_NORELOC,
        )
        for name, vm, prot, sect in empties
    )
    # The extra commands go in the header's slack (-headerpad): up to the first
    # section the kernel's __TEXT keeps content in.
    need = HEADER_SIZE + kernel.sizeofcmds + len(extra)
    room = min(s.addr for s in ksegs["__TEXT"].sections if s.offset) - kernel_vm
    if need > room:
        raise ValueError(
            f"no room in the kernel header for the {len(empties)} empty prelink "
            f"segments: {need} bytes needed, {room} available; raise -headerpad"
        )
    hdr += extra
    struct.pack_into("<I", hdr, 16, kernel.ncmds + len(empties))
    struct.pack_into("<I", hdr, 20, kernel.sizeofcmds + len(extra))
    image[kernel_vm - base : kernel_vm - base + len(hdr)] = hdr

    # Kext headers: in the cache, with their relocations consumed (they are in
    # the outer fixups now).
    for k in kexts:
        relocate_to_cache(k.macho, base, k.linkedit_vm)
        dysym = k.macho.command(LC_DYSYMTAB)
        if dysym is not None:
            struct.pack_into("<4I", k.macho.hdr, dysym[0] + 64, 0, 0, 0, 0)
        text_off = k.text.vmaddr - base
        image[text_off : text_off + len(k.macho.hdr)] = k.macho.hdr

    # The prelink plist, in the __PRELINK_INFO region.
    plist = prelink_info(kexts, raw_uuid, kernel_vm) + b"\x00"
    info_vm = text_group_end
    info_size = layout.at(layout.kld_data) - info_vm
    if len(plist) > info_size:
        raise ValueError(f"prelink plist ({len(plist)} bytes) overflows its {info_size}-byte region")
    image[info_vm - base : info_vm - base + len(plist)] = plist

    # Outer segments, in load-command order.
    kext_dc_end = layout.at(layout.kext_data_const[1])
    kext_te_start = layout.at(layout.kext_text_exec[0])
    outer = [
        ("__TEXT", base, layout.kernel_offset, R, [], 0),
        ("__PRELINK_TEXT", kernel_vm, layout.at(layout.kext_text[1]) - kernel_vm, R, ["__text"], 0),
        ("__DATA_CONST", layout.at(layout.data_const), kext_dc_end - layout.at(layout.data_const), R, [], 0),
        ("__TEXT_EXEC", kext_te_start, text_group_end - kext_te_start, RX, [], 0),
        ("__PRELINK_INFO", info_vm, info_size, RW, ["__info"], len(plist)),
        ("__DATA", layout.at(layout.kld_data), kc_data_end - layout.at(layout.kld_data), RW, [], 0),
        ("__LINKEDIT", linkedit_vm, linkedit_end - linkedit_vm, R, [], 0),
    ]
    seg_table = [(n, vm, size) for n, vm, size, *_ in outer]
    blob = encode_chain_fixups(fixups, base, seg_table, image)
    if len(blob) > chained_blob_pad:
        raise ValueError(f"chained fixups ({len(blob)} bytes) overflow their {chained_blob_pad}-byte slot")
    image[linkedit_vm - base : linkedit_vm - base + len(blob)] = blob

    # Outer header.
    thread = kernel.command(LC_UNIXTHREAD)
    if thread is None:
        raise ValueError("kernel has no LC_UNIXTHREAD")
    cmds = bytearray()
    cmds += struct.pack("<II16s", LC_UUID, 24, raw_uuid)
    cmds += bytes(kernel.hdr[thread[0] : thread[0] + thread[1]])
    cmds += struct.pack("<IIII", LC_DYLD_CHAINED_FIXUPS, 16, linkedit_vm - base, len(blob))
    for name, vm, size, prot, sects, sect_size in outer:
        sections = [
            pack_section(
                s, name, vm, sect_size or size, vm - base,
                S_ATTR_PURE_INSTRUCTIONS_SOME if name == "__PRELINK_TEXT" else 0,
            )
            for s in sects
        ]
        cmds += pack_segment(name, vm, size, vm - base, size, prot, sections)
    cmds += fileset_entry("com.apple.kernel", kernel_vm, kernel_vm - base)
    for k in kexts:
        cmds += fileset_entry(k.bundle_id, k.text.vmaddr, k.text.vmaddr - base)
    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64, CPU_TYPE_ARM64, struct.unpack_from("<I", kernel.hdr, 8)[0], MH_FILESET,
        len(outer) + 3 + 1 + len(kexts), len(cmds), 0, 0,
    )
    if len(header) + len(cmds) > layout.kernel_offset:
        raise ValueError("outer header does not fit before the kernel")
    image[0 : len(header) + len(cmds)] = header + bytes(cmds)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(image)
    print(
        f"kernelcache: {output_path} uuid={uuid.UUID(bytes=raw_uuid)} bytes={len(image)} "
        f"fixups={len(fixups)} kexts={[k.bundle_id for k in kexts]}"
    )


def main() -> None:
    p = argparse.ArgumentParser(description="Assembles an MH_FILESET kernelcache")
    p.add_argument("kernel", help="linked kernel (MH_EXECUTE)")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--uuid", help="kernelcache UUID (default: random)")
    p.add_argument(
        "--kext", action="append", default=[], metavar="BUNDLE_ID=PATH",
        help="a kext (MH_KEXT_BUNDLE linked with kext_ldflags()); repeatable",
    )
    p.add_argument("--kc-base", required=True, type=lambda s: int(s, 0))
    # KC_LAYOUT (xnu/kernel.bzl): offsets from --kc-base, regions as start,end.
    p.add_argument("--kernel-offset", required=True, type=lambda s: int(s, 0))
    p.add_argument("--kext-text", required=True, type=pair)
    p.add_argument("--data-const", required=True, type=lambda s: int(s, 0))
    p.add_argument("--lastdata-const", required=True, type=lambda s: int(s, 0))
    p.add_argument("--kext-data-const", required=True, type=pair)
    p.add_argument("--kext-text-exec", required=True, type=pair)
    p.add_argument("--text-exec", required=True, type=lambda s: int(s, 0))
    p.add_argument("--kld-data", required=True, type=lambda s: int(s, 0))
    p.add_argument("--kext-data", required=True, type=pair)
    a = p.parse_args()

    layout = Layout(
        a.kc_base, a.kernel_offset, a.kext_text, a.data_const, a.lastdata_const,
        a.kext_data_const, a.kext_text_exec, a.text_exec, a.kld_data, a.kext_data,
    )
    raw_uuid = bytes.fromhex(a.uuid.replace("-", "")) if a.uuid else secrets.token_bytes(16)
    kexts = []
    for spec in a.kext:
        bundle_id, _, path = spec.partition("=")
        if not path:
            p.error(f"--kext expects BUNDLE_ID=PATH, got {spec!r}")
        kexts.append((bundle_id, path))
    build_kernelcache(a.kernel, a.output, layout, raw_uuid, kexts)


if __name__ == "__main__":
    main()
