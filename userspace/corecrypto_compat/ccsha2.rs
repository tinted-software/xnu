//! Streaming digest primitives backing the corecrypto/ccdigest shim:
//! SHA-1, SHA-256 and SHA-384 (RustCrypto `sha1` / `sha2`).
//!
//! The C side (ccsha2.c) owns a fixed-size context buffer and passes it in.
//! Each call operates on the hasher placed in that buffer, so there is no
//! allocation and no global state.

#![no_std]

// Provides the single #[panic_handler]; must be linked explicitly.
extern crate rust_panic;

use core::mem::{align_of, size_of};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

/// Bytes reserved by the C side for one hash context (CCDIGEST_MAX_CTX_BYTES).
pub const CTX_BYTES: usize = 256;
/// The C context is declared with 16-byte alignment.
pub const CTX_ALIGN: usize = 16;

const _: () = assert!(size_of::<Sha1>() <= CTX_BYTES && align_of::<Sha1>() <= CTX_ALIGN);
const _: () = assert!(size_of::<Sha256>() <= CTX_BYTES && align_of::<Sha256>() <= CTX_ALIGN);
const _: () = assert!(size_of::<Sha384>() <= CTX_BYTES && align_of::<Sha384>() <= CTX_ALIGN);

macro_rules! digest_ffi {
    ($ty:ty, $init:ident, $update:ident, $fin:ident, $out:expr) => {
        /// # Safety
        /// `ctx` must be valid for writes of `CTX_BYTES`, 16-byte aligned.
        #[no_mangle]
        pub unsafe extern "C" fn $init(ctx: *mut u8) {
            (ctx as *mut $ty).write(<$ty>::new());
        }

        /// # Safety
        /// `ctx` holds an initialized context; `data` is valid for `len` bytes.
        #[no_mangle]
        pub unsafe extern "C" fn $update(ctx: *mut u8, data: *const u8, len: usize) {
            let h = &mut *(ctx as *mut $ty);
            h.update(core::slice::from_raw_parts(data, len));
        }

        /// Writes the digest to `out` and consumes the context.
        ///
        /// # Safety
        /// `ctx` holds an initialized context not reused until re-initialized;
        /// `out` is valid for the digest size.
        #[no_mangle]
        pub unsafe extern "C" fn $fin(ctx: *mut u8, out: *mut u8) {
            let digest = (ctx as *mut $ty).read().finalize();
            core::ptr::copy_nonoverlapping(digest.as_ptr(), out, $out);
        }
    };
}

digest_ffi!(Sha1, ccsha1_rs_init, ccsha1_rs_update, ccsha1_rs_final, 20);
digest_ffi!(Sha256, ccsha256_rs_init, ccsha256_rs_update, ccsha256_rs_final, 32);
digest_ffi!(Sha384, ccsha384_rs_init, ccsha384_rs_update, ccsha384_rs_final, 48);
