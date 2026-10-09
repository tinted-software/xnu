//! ChaCha20 keystream primitive backing libc's corecrypto/ccrng shim.
//!
//! Stateless on purpose: the C layer (ccrng.c) owns the key, the nonce counter
//! and the reseed policy, so this crate needs no global state and no lock.

#![no_std]

// Provides the single #[panic_handler]; must be linked explicitly.
extern crate rust_panic;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use core::ffi::{c_int, c_void};

extern "C" {
    fn getentropy(buf: *mut c_void, buflen: usize) -> c_int;
}

/// Fills `len` bytes at `buf` from the kernel entropy source.
/// `len` must be at most 256 (getentropy(2)'s limit; the caller chunks).
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ccrng_rs_entropy(buf: *mut u8, len: usize) -> c_int {
    if getentropy(buf as *mut c_void, len) == 0 {
        0
    } else {
        -1
    }
}

/// Writes `len` keystream bytes under `key`, at nonce `counter`.
///
/// The 12-byte IETF nonce is the 64-bit `counter` (little endian) padded with
/// zeros. Callers must never reuse a (key, counter) pair.
///
/// # Safety
/// `key` must be valid for reads of 32 bytes; `out` valid for writes of `len`.
#[no_mangle]
pub unsafe extern "C" fn ccrng_rs_keystream(
    key: *const u8,
    counter: u64,
    out: *mut u8,
    len: usize,
) -> c_int {
    let key = match <&[u8; 32]>::try_from(core::slice::from_raw_parts(key, 32)) {
        Ok(k) => k,
        Err(_) => return -1,
    };
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());

    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    let out = core::slice::from_raw_parts_mut(out, len);
    out.fill(0);
    cipher.apply_keystream(out);
    0
}
