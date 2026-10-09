//! Scalar RustCrypto compression primitives for the kernel digest ABI.
//! Padding and legacy context conversion are implemented in ccdigest_rc.c.

/// # Safety
/// `state` is aligned and writable for eight u32 words. When `nblocks` is
/// nonzero, `data` is readable for `nblocks * 64` bytes.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_sha256_compress(state: *mut u32, nblocks: usize, data: *const u8) {
    if nblocks == 0 {
        return;
    }
    let state = &mut *state.cast::<[u32; 8]>();
    let blocks = core::slice::from_raw_parts(data.cast::<[u8; 64]>(), nblocks);
    sha2::block_api::compress256(state, blocks);
}

/// # Safety
/// `state` is aligned and writable for five u32 words. When `nblocks` is
/// nonzero, `data` is readable for `nblocks * 64` bytes.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_sha1_compress(state: *mut u32, nblocks: usize, data: *const u8) {
    if nblocks == 0 {
        return;
    }
    let state = &mut *state.cast::<[u32; 5]>();
    let blocks = core::slice::from_raw_parts(data.cast::<[u8; 64]>(), nblocks);
    sha1::block_api::compress(state, blocks);
}

/// # Safety
/// `state` is aligned and writable for four u32 words. When `nblocks` is
/// nonzero, `data` is readable for `nblocks * 64` bytes.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_md5_compress(state: *mut u32, nblocks: usize, data: *const u8) {
    if nblocks == 0 {
        return;
    }
    let state = &mut *state.cast::<[u32; 4]>();
    let blocks = core::slice::from_raw_parts(data.cast::<[u8; 64]>(), nblocks);
    md5::block_api::compress(state, blocks);
}

/// # Safety
/// `state` is aligned and writable for eight u64 words. When `nblocks` is
/// nonzero, `data` is readable for `nblocks * 128` bytes.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_sha512_compress(state: *mut u64, nblocks: usize, data: *const u8) {
    if nblocks == 0 {
        return;
    }
    let state = &mut *state.cast::<[u64; 8]>();
    let blocks = core::slice::from_raw_parts(data.cast::<[u8; 128]>(), nblocks);
    sha2::block_api::compress512(state, blocks);
}
