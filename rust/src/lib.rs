//! Kernel-side Rust shims: crypto primitives and the read-only APFS root
//! filesystem reader. `no_std`, `panic = "abort"`; `alloc` is backed by the
//! kernel heap (see `kalloc`) and is used only by the APFS reader, mounted from
//! thread context. Buck2's crate fixups select scalar software backends,
//! avoiding SIMD and userland CPU-detection dependencies in freestanding
//! kernel code.
#![no_std]

extern crate alloc;

mod aead;
mod apfs;
mod block_modes;
mod digest;
mod kalloc;
mod ptrauth;
mod rng;
mod rsa;

/// Signs every function-pointer table handed to C, once (see `ptrauth`). Each
/// accessor that returns such a table calls this first.
pub(crate) fn ensure_tables_signed() {
    ptrauth::sign_once(|| {
        aead::sign_tables();
        block_modes::sign_tables();
        rng::sign_tables();
    });
}

use core::panic::PanicInfo;

extern "C" {
    /// Kernel `panic()` (osfmk/kern/debug.c, declared in osfmk/kern/panic_call.h).
    /// Never returns.
    #[link_name = "panic"]
    fn kernel_panic(fmt: *const u8, ...) -> !;
}

/// libSystem `memset_pattern16`, emitted by LLVM for repeating 16-byte fills.
/// Writes are volatile so LLVM cannot turn this loop back into a call to itself.
#[no_mangle]
pub unsafe extern "C" fn memset_pattern16(b: *mut u8, pattern: *const u8, len: usize) {
    let mut i = 0;
    while i < len {
        core::ptr::write_volatile(b.add(i), core::ptr::read(pattern.add(i % 16)));
        i += 1;
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Rust panic messages are not NUL-terminated and cannot be formatted
    // without an allocator, so report the source location and let the kernel
    // panic path (debugger trap, panic log) handle the rest.
    unsafe {
        match info.location() {
            Some(loc) => kernel_panic(
                b"rust panic at %.*s:%u\0".as_ptr(),
                loc.file().len() as i32,
                loc.file().as_ptr(),
                loc.line(),
            ),
            None => kernel_panic(b"rust panic (no location)\0".as_ptr()),
        }
    }
}

/// `compiler_builtins` (prebuilt Apple target) calls `__assert_rtn` from its
/// C `int_util` code. The kernel has no libSystem, so forward to kernel panic.
///
/// # Safety
/// All pointers must be NUL-terminated C strings, as passed by C `assert()`.
#[no_mangle]
pub unsafe extern "C" fn __assert_rtn(
    func: *const u8,
    file: *const u8,
    line: i32,
    expr: *const u8,
) -> ! {
    kernel_panic(
        b"assertion failed: '%s' at %s:%d in %s\0".as_ptr(),
        expr,
        file,
        line,
        func,
    )
}

// Referenced by libcore's unwinding machinery; unreachable with panic=abort.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// The prebuilt `alloc` crate carries landing pads that reference
/// `_Unwind_Resume`. Our code is `panic = "abort"`, so nothing unwinds into
/// them; reaching this symbol is a kernel bug.
#[no_mangle]
pub unsafe extern "C" fn _Unwind_Resume(_exception: *mut u8) -> ! {
    kernel_panic(b"rust: unwind reached _Unwind_Resume\0".as_ptr())
}
