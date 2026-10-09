#![no_std]
#![no_main]

pub mod afdt;
pub mod allocator;
pub mod bootargs;
pub mod macho;
pub mod uart;

pub mod main_defs {
    pub const RAM_BASE: u64 = 0x40000000;
    /// The kernel's boot page tables map with L2 block entries, so virtual and
    /// physical bases must agree modulo the L2 block size: 32 MB with 16K
    /// granules (a multiple of the 2 MB used by 4K granules).
    pub const L2_BLOCK: u64 = 0x2000000;
    pub const XNU_LOAD_REGION: u64 = 0x42000000;
    pub const MACHO_SRC_ADDR: u64 = 0x48000000;
    pub const MEM_SIZE: u64 = 1024 * 1024 * 1024;
    pub const PANIC_LOG_SIZE: u32 = 0x80000;
    pub const PANIC_LOG_PHYS: u64 = RAM_BASE + MEM_SIZE - PANIC_LOG_SIZE as u64;

    pub const PL011_BASE: usize = 0x09000000;
    pub const GICD_BASE: u64 = 0x08000000;
    pub const GICC_BASE: u64 = 0x08010000;
    pub const PL031_BASE: u64 = 0x09010000;
    pub const RAMDISK_PHYS: u64 = 0x50000000;
    pub const RAMDISK_SIZE: u64 = 0x01000000; // 16 MB max window
    /// Where tools/qemu.py --bootargs loads extra boot-args (below the ramdisk
    /// window, above the kernelcache at 0x48000000).
    pub const EXTRA_ARGS_PHYS: u64 = 0x4ff00000;
    /// Where tools/qemu.py --trustcache loads a trust_cache_offsets_t blob: a
    /// 1 MiB window between the kernelcache (0x48000000) and boot-args.
    pub const TRUST_CACHE_PHYS: u64 = 0x4fe00000;
    pub const TRUST_CACHE_WINDOW: u64 = 0x100000;
}

use bootargs::XnuBootArguments;
use core::arch::global_asm;
use core::panic::PanicInfo;
use main_defs::*;

global_asm!(
    r#"
    .section .text._start, "ax", @progbits
    .global _start
_start:
    // Enable FP/SIMD (CPACR_EL1.FPEN = 0b11)
    mrs x0, cpacr_el1
    orr x0, x0, #(0x3 << 20)
    msr cpacr_el1, x0
    isb

    // Set up stack pointer
    ldr x0, =__stack_top
    mov sp, x0

    // Zero BSS
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:
    cmp x0, x1
    b.ge 2f
    str xzr, [x0], #8
    b 1b
2:
    // Jump to Rust main
    bl rust_main

    // If rust_main returns, halt
3:  wfe
    b 3b
"#
);

/// The NUL-terminated extra boot-args at `EXTRA_ARGS_PHYS`, or empty when
/// the `XNUARGS\0` magic is absent.
unsafe fn extra_boot_args() -> &'static [u8] {
    const MAGIC: &[u8; 8] = b"XNUARGS\0";
    const MAX: usize = 512;
    let p = EXTRA_ARGS_PHYS as *const u8;
    for (i, &m) in MAGIC.iter().enumerate() {
        if p.add(i).read_volatile() != m {
            return &[];
        }
    }
    let s = p.add(MAGIC.len());
    let mut len = 0;
    while len < MAX && s.add(len).read_volatile() != 0 {
        len += 1;
    }
    core::slice::from_raw_parts(s, len)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[inline(always)]
fn round_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

#[inline(never)]
unsafe fn jump_to_kernel(entry: u64, boot_args: u64) -> ! {
    core::arch::asm!(
        // Disable MMU & Caches before entering XNU
        "mrs x2, sctlr_el1",
        "bic x2, x2, #1",      // M: MMU disable (bit 0)
        "bic x2, x2, #4",      // C: Data cache disable (bit 2)
        "bic x2, x2, #4096",   // I: Instruction cache disable (bit 12)
        "msr sctlr_el1, x2",
        "isb",

        // Invalidate instruction cache
        "ic iallu",
        "isb",
        "dsb sy",

        // Branch to XNU kernel entry with x0 = boot_args
        "br x1",
        in("x1") entry,
        in("x0") boot_args,
        options(noreturn)
    );
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    println!("xnu-qemu-boot (Rust): starting bootloader");

    let xnu_load_addr = XNU_LOAD_REGION + (0xfffffff007004000 % L2_BLOCK);

    let load_info = match unsafe { macho::load_macho_image(MACHO_SRC_ADDR, xnu_load_addr) } {
        Ok(info) => info,
        Err(e) => {
            println!("xnu-qemu-boot: fatal error loading Mach-O: {}", e);
            loop {
                core::hint::spin_loop();
            }
        }
    };

    let xnu_entry = load_info.entry - load_info.base + xnu_load_addr;
    let xnu_end = load_info.end - load_info.base + xnu_load_addr;

    println!(
        "  mach-o base=0x{:x} entry=0x{:x} end=0x{:x}",
        load_info.base, load_info.entry, load_info.end
    );
    println!("  xnu entry=0x{:x} xnu_end=0x{:x}", xnu_entry, xnu_end);

    let boot_args_addr = xnu_end;
    let boot_args_size = core::mem::size_of::<XnuBootArguments>() as u64;

    unsafe {
        let p = boot_args_addr as *mut u8;
        for i in 0..(boot_args_size as usize) {
            *p.add(i) = 0;
        }

        let boot_args = &mut *(boot_args_addr as *mut XnuBootArguments);

        boot_args.revision = 2;
        boot_args.version = 2;
        boot_args.virt_base = load_info.base;
        boot_args.phys_base = xnu_load_addr;
        boot_args.mem_size = MEM_SIZE - PANIC_LOG_SIZE as u64;
        boot_args.top_of_kernel_data = boot_args_addr + boot_args_size;

        // kdp_match_name=none: on arm64, kdp_init() configures *serial* KDP by
        // default, which shares the console UART. On panic the kernel then emits
        // KDP packet framing over that port (appearing as garbled text) and blocks
        // forever waiting for a remote debugger to attach -- which looks exactly
        // like a boot hang and destroys the panic message. Requesting a non-serial
        // debugger name makes kdp_init() bail out early, so panics print normally.
        let base = "serial=3 serial-device-name=uart0 debug=0xa -v -noprogress fips_mode=8 amfi_allow_any_signature=1 kdp_match_name=none";

        // Extra boot-args: tools/qemu.py --bootargs loads "XNUARGS\0" followed by
        // a NUL-terminated string at EXTRA_ARGS_PHYS. Guest RAM starts zeroed,
        // so without it the magic is absent. A root device given there as
        // `rd=` replaces the default ramdisk root.
        let extra = extra_boot_args();
        let cmd = &mut boot_args.command_line;
        let mut n = 0;
        for part in [base.as_bytes(), b" ", extra] {
            for &b in part {
                if n < cmd.len() - 1 {
                    cmd[n] = b;
                    n += 1;
                }
            }
        }
        if !contains(extra, b"rd=") {
            for &b in b" rd=md0" {
                if n < cmd.len() - 1 {
                    cmd[n] = b;
                    n += 1;
                }
            }
        }
        let cmdline = match core::str::from_utf8(&boot_args.command_line[..n]) {
            Ok(s) => s,
            Err(_) => base,
        };
        println!("  boot-args: {}", cmdline);

        // A zero num_caches means tools/qemu.py --trustcache did not load a
        // blob; the kernel panics on a non-zero segment with zero caches, so
        // the TrustCache range is only advertised when a blob is present.
        //
        // The loader stages the blob at TRUST_CACHE_PHYS, which is ordinary
        // free RAM to the kernel: the static trust cache is used in place for
        // the life of the system, so it is copied behind the device tree,
        // inside top_of_kernel_data, where the kernel never allocates.
        const DT_WINDOW: u64 = 0x10000;
        let afdt_phys = boot_args.top_of_kernel_data;
        let tc_num_caches = unsafe { core::ptr::read_volatile(TRUST_CACHE_PHYS as *const u32) };
        let (trust_cache, tc_end) = if tc_num_caches != 0 {
            let dst = afdt_phys + DT_WINDOW;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    TRUST_CACHE_PHYS as *const u8,
                    dst as *mut u8,
                    TRUST_CACHE_WINDOW as usize,
                );
            }
            println!("  trust cache: {} module(s) copied to 0x{:x}", tc_num_caches, dst);
            (Some((dst, TRUST_CACHE_WINDOW)), dst + TRUST_CACHE_WINDOW)
        } else {
            (None, afdt_phys + DT_WINDOW)
        };

        let afdt_len = afdt::build_afdt(
            afdt_phys,
            RAM_BASE,
            MEM_SIZE,
            PANIC_LOG_PHYS,
            PANIC_LOG_SIZE,
            RAMDISK_PHYS,
            RAMDISK_SIZE,
            trust_cache,
            cmdline,
        );
        assert!(afdt_len as u64 <= DT_WINDOW);

        boot_args.device_tree_p = afdt_phys - xnu_load_addr + load_info.base;
        boot_args.device_tree_length = afdt_len;
        boot_args.top_of_kernel_data = round_up(tc_end, 0x10000);

        println!(
            "  boot_args=0x{:x} afdt=0x{:x} afdt_len={}",
            boot_args_addr, boot_args.device_tree_p, afdt_len
        );
        println!("  jumping into XNU kernel now...");

        jump_to_kernel(xnu_entry, boot_args_addr);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("PANIC: {:?}", info);
    loop {
        core::hint::spin_loop();
    }
}
