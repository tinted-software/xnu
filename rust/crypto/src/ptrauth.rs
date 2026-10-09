// SPDX-License-Identifier: MIT OR Apache-2.0
//! Function-pointer ABI bridge for arm64e.
//!
//! On arm64e the C side (clang with `-fptrauth-calls`) signs every function
//! pointer it creates (key IA, zero discriminator) and authenticates every
//! indirect call. `rustc` does neither: Rust function pointers are raw. At the
//! boundary this crate therefore
//!
//! * authenticates pointers it receives from C before calling them (`auth`), and
//! * signs the pointers in the tables it hands to C (`sign`), in place and once
//!   (`Mutable`, `sign_once`).
//!
//! Everything is the identity unless built with `--cfg xnu_arm64e` (set by the
//! toolchain for the arm64e board), so the plain aarch64 kernel is unaffected.

use core::cell::UnsafeCell;
use core::mem;
use core::sync::atomic::{AtomicU8, Ordering};

/// A table that is written once, during `sign_once`, before C uses it.
#[repr(transparent)]
pub struct Mutable<T>(UnsafeCell<T>);

// SAFETY: written only inside `sign_once`'s exclusive window; afterwards
// shared and read-only.
unsafe impl<T> Sync for Mutable<T> {}

impl<T> Mutable<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

#[cfg(xnu_arm64e)]
#[inline(always)]
fn pac(raw: usize, auth: bool) -> usize {
    let mut p = raw;
    // SAFETY: `paciza`/`autiza` only transform the register.
    unsafe {
        if auth {
            core::arch::asm!(
                ".arch_extension pauth",
                "autiza {0}",
                inout(reg) p,
                options(pure, nomem, nostack, preserves_flags)
            );
        } else {
            core::arch::asm!(
                ".arch_extension pauth",
                "paciza {0}",
                inout(reg) p,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
    }
    p
}

#[cfg(not(xnu_arm64e))]
#[inline(always)]
fn pac(raw: usize, _auth: bool) -> usize {
    raw
}

#[inline(always)]
fn convert<F: Copy>(f: F, auth: bool) -> F {
    const { assert!(mem::size_of::<F>() == mem::size_of::<usize>()) };
    // SAFETY: `F` is a function pointer (checked to be pointer-sized).
    unsafe { mem::transmute_copy(&pac(mem::transmute_copy(&f), auth)) }
}

/// Signs a Rust function pointer as C expects it (IA key, zero discriminator).
#[inline(always)]
pub fn sign<F: Copy>(f: F) -> F {
    convert(f, false)
}

/// Authenticates a function pointer received from C so it can be called.
#[inline(always)]
pub fn auth<F: Copy>(f: F) -> F {
    convert(f, true)
}

/// Runs `sign_tables` exactly once; every caller returns after it completed.
/// Idempotent signing is not possible (signing twice corrupts), hence the gate.
pub fn sign_once(sign_tables: impl FnOnce()) {
    static STATE: AtomicU8 = AtomicU8::new(0);
    if STATE.load(Ordering::Acquire) == 2 {
        return;
    }
    if STATE
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
        .is_ok()
    {
        sign_tables();
        STATE.store(2, Ordering::Release);
    } else {
        while STATE.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
    }
}
