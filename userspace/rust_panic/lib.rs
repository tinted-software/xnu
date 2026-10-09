//! Single `#[panic_handler]` for the freestanding Rust crates linked into
//! userspace images (ccrng, ccsha2). A final link may contain exactly one.
//! A panic here means an internal invariant broke; trap rather than unwind.

#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        // SAFETY: `brk` raises a debug exception and does not touch memory.
        unsafe { core::arch::asm!("brk #0x1", options(nomem, nostack)) };
    }
}

/// The prebuilt `core` references the unwinding personality routine even
/// though nothing here unwinds. Never called: panics trap above.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
