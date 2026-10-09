use crate::println;
use object::macho;
use object::read::macho::MachHeader;
use object::Endianness;

pub struct MachOLoadInfo {
    pub base: u64,
    pub entry: u64,
    pub end: u64,
}

#[inline(always)]
pub unsafe fn copy_mem(dst: u64, src: u64, len: usize) {
    let mut d = dst as *mut u64;
    let mut s = src as *const u64;
    let words = len / 8;
    for _ in 0..words {
        core::ptr::write_unaligned(d, core::ptr::read_unaligned(s));
        d = d.add(1);
        s = s.add(1);
    }
    let mut d_byte = d as *mut u8;
    let mut s_byte = s as *const u8;
    for _ in 0..(len % 8) {
        *d_byte = *s_byte;
        d_byte = d_byte.add(1);
        s_byte = s_byte.add(1);
    }
}

#[inline(always)]
pub unsafe fn zero_mem(dst: u64, len: usize) {
    let mut d = dst as *mut u64;
    let words = len / 8;
    for _ in 0..words {
        core::ptr::write_unaligned(d, 0);
        d = d.add(1);
    }
    let mut d_byte = d as *mut u8;
    for _ in 0..(len % 8) {
        *d_byte = 0;
        d_byte = d_byte.add(1);
    }
}

pub unsafe fn load_macho_image(
    image_addr: u64,
    xnu_load_addr: u64,
) -> Result<MachOLoadInfo, &'static str> {
    let data = core::slice::from_raw_parts(image_addr as *const u8, 64 * 1024 * 1024);

    let header = macho::MachHeader64::<Endianness>::parse(data, 0)
        .map_err(|_| "failed to parse mach-o header")?;

    let endian = header.endian().map_err(|_| "failed to get endianness")?;
    let magic = header.magic();
    let filetype = header.filetype(endian);
    let ncmds = header.ncmds(endian);

    println!(
        "  macho header: magic=0x{:x} file_type=0x{:x} commands_nb={}",
        magic, filetype, ncmds
    );

    // A kernelcache is an MH_FILESET: its outer header lists every segment of
    // the collection and the entry point, so it loads like the bare kernel did.
    let loadable = filetype == macho::MH_EXECUTE || filetype == macho::MH_FILESET;
    if (magic != macho::MH_MAGIC_64 && magic != macho::MH_CIGAM_64) || !loadable {
        return Err("invalid mach-o magic or file type");
    }

    // Pass 1: compute base and end
    let mut base = u64::MAX;
    let mut end = 0u64;

    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|_| "failed to iterate load commands")?;

    while let Ok(Some(command)) = commands.next() {
        if command.cmd() == macho::LC_SEGMENT_64 {
            if let Ok(Some((seg, _))) = command.segment_64() {
                let vmaddr = seg.vmaddr.get(endian);
                let vmsize = seg.vmsize.get(endian);
                if vmaddr + vmsize > end {
                    end = vmaddr + vmsize;
                }
                if vmaddr < base {
                    base = vmaddr;
                }
            }
        }
    }

    if base > end {
        return Err("no segments found in mach-o image");
    }

    println!("  pass 1 done: base=0x{:x} end=0x{:x}", base, end);

    // Pass 2: load segments and extract entry point
    let mut entry = 0u64;
    let mut commands = header
        .load_commands(endian, data, 0)
        .map_err(|_| "failed to iterate load commands")?;

    while let Ok(Some(command)) = commands.next() {
        let cmd = command.cmd();
        if cmd == macho::LC_SEGMENT_64 {
            if let Ok(Some((seg, _))) = command.segment_64() {
                let seg_name_bytes = &seg.segname;
                let seg_name_len = seg_name_bytes
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(seg_name_bytes.len());
                let seg_name =
                    core::str::from_utf8(&seg_name_bytes[..seg_name_len]).unwrap_or("<invalid>");

                let vmaddr = seg.vmaddr.get(endian);
                let vmsize = seg.vmsize.get(endian);
                let fileoff = seg.fileoff.get(endian);
                let filesize = seg.filesize.get(endian);

                let dst = vmaddr - base + xnu_load_addr;
                let src = image_addr + fileoff;

                println!(
                    "    seg {}: dst=0x{:x} src=0x{:x} src_len=0x{:x} dst_len=0x{:x}",
                    seg_name, dst, src, filesize, vmsize
                );

                if filesize != 0 && vmsize != 0 {
                    let copy_len = filesize.min(vmsize) as usize;
                    core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, copy_len);
                }
                if filesize < vmsize && vmsize != 0 {
                    core::ptr::write_bytes(
                        (dst + filesize) as *mut u8,
                        0,
                        (vmsize - filesize) as usize,
                    );
                }
            }
        } else if cmd == macho::LC_UNIXTHREAD {
            let raw_data = command.raw_data();
            if raw_data.len() >= 280 {
                let pc_bytes: [u8; 8] = raw_data[272..280].try_into().unwrap();
                entry = match endian {
                    Endianness::Little => u64::from_le_bytes(pc_bytes),
                    Endianness::Big => u64::from_be_bytes(pc_bytes),
                };
            }
        }
    }

    Ok(MachOLoadInfo { base, entry, end })
}
