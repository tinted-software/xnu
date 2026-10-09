//! Allocation-free multipart AEAD. Only incomplete authentication and cipher
//! blocks are retained; callers own plaintext until authentication succeeds.
use aes::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use chacha20::{cipher::consts::U16, ChaCha20};
use core::{mem, ptr, slice};
use ghash::{universal_hash::UniversalHash, GHash};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

use crate::ptrauth::{self, Mutable};

const INVALID: i32 = -67; // CCMODE_INVALID_INPUT
const SEQUENCE: i32 = -68; // CCMODE_INVALID_CALL_SEQUENCE
const AUTH_FAILED: i32 = -69; // CCMODE_INTEGRITY_FAILURE
const GCM_MAGIC: u64 = 0x584e5547434d3031;
const CHACHA_MAGIC: u64 = 0x584e554348413031;
const READY: u8 = 0;
const AAD: u8 = 1;
const DATA: u8 = 2;
const FINAL: u8 = 3;
const GCM_MAX_DATA: u64 = (1u64 << 36) - 32;
const CHACHA_MAX_DATA: u64 = (u32::MAX as u64) * 64;

unsafe fn erase(p: *mut u8, n: usize) {
    for i in 0..n {
        ptr::write_volatile(p.add(i), 0);
    }
}
fn valid_input(p: *const u8, n: usize) -> bool {
    n <= isize::MAX as usize && (n == 0 || !p.is_null())
}
fn valid_io(input: *const u8, output: *mut u8, n: usize) -> bool {
    if !valid_input(input, n) || !valid_input(output, n) {
        return false;
    }
    if n == 0 || input == output as *const u8 {
        return true;
    }
    match (
        (input as usize).checked_add(n),
        (output as usize).checked_add(n),
    ) {
        (Some(a), Some(b)) => a <= output as usize || b <= input as usize,
        _ => false,
    }
}
unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        slice::from_raw_parts(p, n)
    }
}
fn increment_be64(iv: &mut [u8; 12]) -> bool {
    let n = u64::from_be_bytes(iv[4..].try_into().unwrap());
    if n == u64::MAX {
        return false;
    }
    iv[4..].copy_from_slice(&(n + 1).to_be_bytes());
    true
}

struct Auth<H: UniversalHash<BlockSize = U16>> {
    hash: H,
    partial: [u8; 16],
    used: usize,
}
impl<H: UniversalHash<BlockSize = U16>> Auth<H> {
    fn new(hash: H) -> Self {
        Self {
            hash,
            partial: [0; 16],
            used: 0,
        }
    }
    fn feed(&mut self, mut input: &[u8]) {
        if self.used != 0 {
            let n = (16 - self.used).min(input.len());
            self.partial[self.used..self.used + n].copy_from_slice(&input[..n]);
            self.used += n;
            input = &input[n..];
            if self.used == 16 {
                self.hash.update(&[self.partial.into()]);
                self.partial = [0; 16];
                self.used = 0;
            }
        }
        while input.len() >= 16 {
            let block = <&ghash::Block>::try_from(&input[..16]).expect("16-byte block");
            self.hash.update(&[*block]);
            input = &input[16..];
        }
        if !input.is_empty() {
            self.partial[..input.len()].copy_from_slice(input);
            self.used = input.len();
        }
    }
    fn pad(&mut self) {
        if self.used != 0 {
            self.hash.update(&[self.partial.into()]);
            self.partial = [0; 16];
            self.used = 0;
        }
    }
}

enum AesKey {
    K128(Aes128),
    K192(Aes192),
    K256(Aes256),
}
impl AesKey {
    fn new(key: &[u8]) -> Option<Self> {
        Some(match key.len() {
            16 => Self::K128(Aes128::new_from_slice(key).ok()?),
            24 => Self::K192(Aes192::new_from_slice(key).ok()?),
            32 => Self::K256(Aes256::new_from_slice(key).ok()?),
            _ => return None,
        })
    }
    fn encrypt(&self, block: &mut [u8; 16]) {
        let b: &mut aes::cipher::Block<Aes128> = block.into();
        match self {
            Self::K128(k) => k.encrypt_block(b),
            Self::K192(k) => k.encrypt_block(b),
            Self::K256(k) => k.encrypt_block(b),
        }
    }
}
#[repr(C, align(16))]
struct Gcm {
    magic: u64,
    key: AesKey,
    h: [u8; 16],
    auth: Auth<GHash>,
    counter: [u8; 16],
    mask: [u8; 16],
    stream: [u8; 16],
    stream_used: usize,
    aad_len: u64,
    data_len: u64,
    nonce: [u8; 12],
    managed: bool,
    decrypt: bool,
    state: u8,
}
#[repr(C)]
pub struct GcmMode {
    size: usize,
    block_size: usize,
    init: unsafe extern "C" fn(*const GcmMode, *mut u8, usize, *const u8) -> i32,
    set_iv: unsafe extern "C" fn(*mut u8, usize, *const u8) -> i32,
    gmac: unsafe extern "C" fn(*mut u8, usize, *const u8) -> i32,
    gcm: unsafe extern "C" fn(*mut u8, usize, *const u8, *mut u8) -> i32,
    finalize: unsafe extern "C" fn(*mut u8, usize, *mut u8) -> i32,
    reset: unsafe extern "C" fn(*mut u8) -> i32,
}
static GCM_ENCRYPT: Mutable<GcmMode> = Mutable::new(GcmMode {
    size: mem::size_of::<Gcm>(),
    block_size: 1,
    init: gcm_init,
    set_iv: gcm_set_iv,
    gmac: gcm_aad,
    gcm: gcm_update,
    finalize: gcm_finalize,
    reset: gcm_reset,
});
static GCM_DECRYPT: Mutable<GcmMode> = Mutable::new(GcmMode {
    size: mem::size_of::<Gcm>(),
    block_size: 1,
    init: gcm_init,
    set_iv: gcm_set_iv,
    gmac: gcm_aad,
    gcm: gcm_update,
    finalize: gcm_finalize,
    reset: gcm_reset,
});
fn sign_gcm(mode: &mut GcmMode) {
    mode.init = ptrauth::sign(mode.init);
    mode.set_iv = ptrauth::sign(mode.set_iv);
    mode.gmac = ptrauth::sign(mode.gmac);
    mode.gcm = ptrauth::sign(mode.gcm);
    mode.finalize = ptrauth::sign(mode.finalize);
    mode.reset = ptrauth::sign(mode.reset);
}
/// Signs this module's tables for C (see `ptrauth`).
pub(crate) fn sign_tables() {
    // SAFETY: called once from `ensure_tables_signed`, before C sees the tables.
    unsafe {
        sign_gcm(&mut *GCM_ENCRYPT.get());
        sign_gcm(&mut *GCM_DECRYPT.get());
        let fns = &mut *CHACHA_FNS.get();
        fns.info = ptrauth::sign(fns.info);
        fns.init = ptrauth::sign(fns.init);
        fns.reset = ptrauth::sign(fns.reset);
        fns.setnonce = ptrauth::sign(fns.setnonce);
        fns.incnonce = ptrauth::sign(fns.incnonce);
        fns.aad = ptrauth::sign(fns.aad);
        fns.encrypt = ptrauth::sign(fns.encrypt);
        fns.finalize = ptrauth::sign(fns.finalize);
        fns.decrypt = ptrauth::sign(fns.decrypt);
        fns.verify = ptrauth::sign(fns.verify);
    }
}
#[no_mangle]
pub extern "C" fn xnu_rc_aes_gcm_encrypt_mode() -> *const GcmMode {
    crate::ensure_tables_signed();
    GCM_ENCRYPT.get()
}
#[no_mangle]
pub extern "C" fn xnu_rc_aes_gcm_decrypt_mode() -> *const GcmMode {
    crate::ensure_tables_signed();
    GCM_DECRYPT.get()
}
fn mode_direction(mode: *const GcmMode) -> Option<bool> {
    if ptr::eq(mode, GCM_ENCRYPT.get()) {
        Some(false)
    } else if ptr::eq(mode, GCM_DECRYPT.get()) {
        Some(true)
    } else {
        None
    }
}
unsafe fn gcm_ctx<'a>(p: *mut u8) -> Option<&'a mut Gcm> {
    if p.is_null()
        || (p as usize) % mem::align_of::<Gcm>() != 0
        || ptr::read(p as *const u64) != GCM_MAGIC
    {
        None
    } else {
        Some(&mut *(p as *mut Gcm))
    }
}
unsafe fn checked_gcm<'a>(mode: *const GcmMode, p: *mut u8) -> Option<&'a mut Gcm> {
    let direction = mode_direction(mode)?;
    let c = gcm_ctx(p)?;
    if c.decrypt == direction {
        Some(c)
    } else {
        None
    }
}
unsafe extern "C" fn gcm_init(mode: *const GcmMode, p: *mut u8, n: usize, key: *const u8) -> i32 {
    let decrypt = match mode_direction(mode) {
        Some(v) => v,
        None => return INVALID,
    };
    if p.is_null() || p as usize % mem::align_of::<Gcm>() != 0 || !valid_input(key, n) {
        return INVALID;
    }
    let key = match AesKey::new(bytes(key, n)) {
        Some(k) => k,
        None => return INVALID,
    };
    let mut h = [0; 16];
    key.encrypt(&mut h);
    ptr::write(
        p as *mut Gcm,
        Gcm {
            magic: GCM_MAGIC,
            key,
            h,
            auth: Auth::new(GHash::new(&h.into())),
            counter: [0; 16],
            mask: [0; 16],
            stream: [0; 16],
            stream_used: 16,
            aad_len: 0,
            data_len: 0,
            nonce: [0; 12],
            managed: false,
            decrypt,
            state: READY,
        },
    );
    0
}
unsafe extern "C" fn gcm_set_iv(p: *mut u8, n: usize, iv: *const u8) -> i32 {
    if n == 0 || n as u64 > u64::MAX / 8 || !valid_input(iv, n) {
        return INVALID;
    }
    let c = match gcm_ctx(p) {
        Some(c) if c.state == READY => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    let iv = bytes(iv, n);
    let mut j0 = [0; 16];
    if n == 12 {
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
    } else {
        let mut hash = Auth::new(GHash::new(&c.h.into()));
        hash.feed(iv);
        hash.pad();
        let mut lengths = [0; 16];
        lengths[8..].copy_from_slice(&((n as u64) * 8).to_be_bytes());
        hash.feed(&lengths);
        j0.copy_from_slice(&hash.hash.finalize());
    }
    c.auth = Auth::new(GHash::new(&c.h.into()));
    c.counter = j0;
    c.mask = j0;
    c.key.encrypt(&mut c.mask);
    c.stream_used = 16;
    c.aad_len = 0;
    c.data_len = 0;
    c.state = AAD;
    0
}
unsafe extern "C" fn gcm_aad(p: *mut u8, n: usize, input: *const u8) -> i32 {
    if !valid_input(input, n) {
        return INVALID;
    }
    let c = match gcm_ctx(p) {
        Some(c) if c.state == AAD => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    let total = match c.aad_len.checked_add(n as u64) {
        Some(v) if v <= u64::MAX / 8 => v,
        _ => return INVALID,
    };
    c.auth.feed(bytes(input, n));
    c.aad_len = total;
    0
}
unsafe extern "C" fn gcm_update(p: *mut u8, n: usize, input: *const u8, output: *mut u8) -> i32 {
    if !valid_io(input, output, n) {
        return INVALID;
    }
    let c = match gcm_ctx(p) {
        Some(c) if c.state == AAD || c.state == DATA => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    let total = match c.data_len.checked_add(n as u64) {
        Some(v) if v <= GCM_MAX_DATA => v,
        _ => return INVALID,
    };
    if c.state == AAD {
        c.auth.pad();
        c.state = DATA;
    }
    let mut offset = 0;
    while offset < n {
        if c.stream_used == 16 {
            let ctr = u32::from_be_bytes(c.counter[12..].try_into().unwrap()).wrapping_add(1);
            c.counter[12..].copy_from_slice(&ctr.to_be_bytes());
            c.stream = c.counter;
            c.key.encrypt(&mut c.stream);
            c.stream_used = 0;
        }
        let take = (16 - c.stream_used).min(n - offset);
        let mut ciphertext = [0u8; 16];
        for i in 0..take {
            let src = ptr::read(input.add(offset + i));
            let dst = src ^ c.stream[c.stream_used + i];
            ciphertext[i] = if c.decrypt { src } else { dst };
            ptr::write(output.add(offset + i), dst);
        }
        c.auth.feed(&ciphertext[..take]);
        c.stream_used += take;
        offset += take;
    }
    c.data_len = total;
    0
}
unsafe extern "C" fn gcm_finalize(p: *mut u8, n: usize, tag: *mut u8) -> i32 {
    // NIST SP 800-38D supported tag widths (in bytes).
    if !matches!(n, 4 | 8 | 12 | 13 | 14 | 15 | 16) || tag.is_null() {
        return INVALID;
    }
    let c = match gcm_ctx(p) {
        Some(c) if c.state == AAD || c.state == DATA => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    c.auth.pad();
    let mut lengths = [0; 16];
    lengths[..8].copy_from_slice(&(c.aad_len * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&(c.data_len * 8).to_be_bytes());
    c.auth.feed(&lengths);
    let mut expected = c.auth.hash.clone().finalize();
    for i in 0..16 {
        expected[i] ^= c.mask[i];
    }
    c.state = FINAL;
    let result = if c.decrypt {
        if bool::from(expected[..n].ct_eq(bytes(tag, n))) {
            0
        } else {
            AUTH_FAILED
        }
    } else {
        ptr::copy_nonoverlapping(expected.as_ptr(), tag, n);
        0
    };
    erase(expected.as_mut_ptr(), 16);
    result
}
unsafe extern "C" fn gcm_reset(p: *mut u8) -> i32 {
    let c = match gcm_ctx(p) {
        Some(c) => c,
        None => return INVALID,
    };
    c.auth = Auth::new(GHash::new(&c.h.into()));
    c.counter = [0; 16];
    c.mask = [0; 16];
    c.stream = [0; 16];
    c.stream_used = 16;
    c.aad_len = 0;
    c.data_len = 0;
    c.state = READY;
    0
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_init(m: *const GcmMode, p: *mut u8, n: usize, k: *const u8) -> i32 {
    if mode_direction(m).is_none() {
        INVALID
    } else {
        (ptrauth::auth((*m).init))(m, p, n, k)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_set_iv(
    m: *const GcmMode,
    p: *mut u8,
    n: usize,
    v: *const u8,
) -> i32 {
    if checked_gcm(m, p).is_none() {
        INVALID
    } else {
        (ptrauth::auth((*m).set_iv))(p, n, v)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_aad(m: *const GcmMode, p: *mut u8, n: usize, v: *const u8) -> i32 {
    if checked_gcm(m, p).is_none() {
        INVALID
    } else {
        (ptrauth::auth((*m).gmac))(p, n, v)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_update(
    m: *const GcmMode,
    p: *mut u8,
    n: usize,
    v: *const u8,
    o: *mut u8,
) -> i32 {
    if checked_gcm(m, p).is_none() {
        INVALID
    } else {
        (ptrauth::auth((*m).gcm))(p, n, v, o)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_finalize(
    m: *const GcmMode,
    p: *mut u8,
    n: usize,
    t: *mut u8,
) -> i32 {
    if checked_gcm(m, p).is_none() {
        INVALID
    } else {
        (ptrauth::auth((*m).finalize))(p, n, t)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_reset(m: *const GcmMode, p: *mut u8) -> i32 {
    if checked_gcm(m, p).is_none() {
        INVALID
    } else {
        (ptrauth::auth((*m).reset))(p)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_init_with_iv(
    m: *const GcmMode,
    p: *mut u8,
    n: usize,
    k: *const u8,
    iv: *const u8,
) -> i32 {
    if iv.is_null() {
        return INVALID;
    }
    let mut nonce = [0; 12];
    ptr::copy_nonoverlapping(iv, nonce.as_mut_ptr(), 12);
    let rc = ccgcm_init(m, p, n, k);
    if rc != 0 {
        return rc;
    }
    let c = gcm_ctx(p).unwrap();
    c.nonce = nonce;
    c.managed = true;
    gcm_set_iv(p, 12, nonce.as_ptr())
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_inc_iv(m: *const GcmMode, p: *mut u8, out: *mut u8) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    let c = match checked_gcm(m, p) {
        Some(c) if c.state == READY && c.managed => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    if !increment_be64(&mut c.nonce) {
        return INVALID;
    }
    let nonce = c.nonce;
    let rc = gcm_set_iv(p, 12, nonce.as_ptr());
    if rc == 0 {
        ptr::copy_nonoverlapping(nonce.as_ptr(), out, 12);
    }
    rc
}
#[no_mangle]
pub unsafe extern "C" fn ccgcm_one_shot(
    m: *const GcmMode,
    kn: usize,
    k: *const u8,
    vn: usize,
    v: *const u8,
    an: usize,
    a: *const u8,
    n: usize,
    input: *const u8,
    output: *mut u8,
    tn: usize,
    tag: *mut u8,
) -> i32 {
    let mut storage = mem::MaybeUninit::<Gcm>::uninit();
    let p = storage.as_mut_ptr() as *mut u8;
    let result = (|| {
        let rc = ccgcm_init(m, p, kn, k);
        if rc != 0 {
            return rc;
        }
        let rc = ccgcm_set_iv(m, p, vn, v);
        if rc != 0 {
            return rc;
        }
        let rc = ccgcm_aad(m, p, an, a);
        if rc != 0 {
            return rc;
        }
        let rc = ccgcm_update(m, p, n, input, output);
        if rc != 0 {
            return rc;
        }
        ccgcm_finalize(m, p, tn, tag)
    })();
    if result == AUTH_FAILED && valid_io(input, output, n) {
        erase(output, n);
    }
    erase(p, mem::size_of::<Gcm>());
    result
}

// The stream core is advanced one block at a time, guarded by the RFC 8439
// byte limit. This permits counter 0xffffffff without wrapping into block 0.
type ChaCha = ChaCha20;
#[repr(C, align(8))]
struct ChaCtx {
    magic: u64,
    key: [u8; 32],
    nonce: [u8; 12],
    nonce_valid: bool,
    cipher: ChaCha,
    auth: Auth<Poly1305>,
    stream: [u8; 64],
    stream_used: usize,
    aad_len: u64,
    data_len: u64,
    direction: u8,
    state: u8,
}
// Scalar RustCrypto backends are required by the kernel's register policy.
// Cargo host harnesses need the same poly1305_force_soft/chacha20_force_soft
// cfg flags as the dependency-specific Buck fixups; the AVX2 Poly1305 backend
// deliberately cannot fit this alignment-8 C ABI.
const _: () = assert!(mem::size_of::<ChaCtx>() <= 1024 && mem::align_of::<ChaCtx>() <= 8);
#[repr(C)]
pub struct ChaInfo {
    size: usize,
}
static CHACHA_INFO: ChaInfo = ChaInfo { size: 1024 };
#[no_mangle]
pub extern "C" fn ccchacha20poly1305_info() -> *const ChaInfo {
    &CHACHA_INFO
}
unsafe fn cha_ctx<'a>(info: *const ChaInfo, p: *mut u8) -> Option<&'a mut ChaCtx> {
    if !ptr::eq(info, &CHACHA_INFO)
        || p.is_null()
        || p as usize % mem::align_of::<ChaCtx>() != 0
        || ptr::read(p as *const u64) != CHACHA_MAGIC
    {
        None
    } else {
        Some(&mut *(p as *mut ChaCtx))
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_init(
    info: *const ChaInfo,
    p: *mut u8,
    key: *const u8,
) -> i32 {
    if !ptr::eq(info, &CHACHA_INFO)
        || p.is_null()
        || p as usize % mem::align_of::<ChaCtx>() != 0
        || key.is_null()
    {
        return INVALID;
    }
    let mut k = [0; 32];
    ptr::copy_nonoverlapping(key, k.as_mut_ptr(), 32);
    ptr::write(
        p as *mut ChaCtx,
        ChaCtx {
            magic: CHACHA_MAGIC,
            key: k,
            nonce: [0; 12],
            nonce_valid: false,
            cipher: ChaCha::new(&k.into(), &[0; 12].into()),
            auth: Auth::new(Poly1305::new(&[0; 32].into())),
            stream: [0; 64],
            stream_used: 64,
            aad_len: 0,
            data_len: 0,
            direction: 0,
            state: READY,
        },
    );
    erase(k.as_mut_ptr(), 32);
    0
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_reset(info: *const ChaInfo, p: *mut u8) -> i32 {
    let c = match cha_ctx(info, p) {
        Some(c) => c,
        None => return INVALID,
    };
    c.cipher = ChaCha::new(&c.key.into(), &[0; 12].into());
    c.auth = Auth::new(Poly1305::new(&[0; 32].into()));
    c.stream = [0; 64];
    c.stream_used = 64;
    c.aad_len = 0;
    c.data_len = 0;
    c.direction = 0;
    c.state = READY;
    0
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_setnonce(
    info: *const ChaInfo,
    p: *mut u8,
    nonce: *const u8,
) -> i32 {
    if nonce.is_null() {
        return INVALID;
    }
    let c = match cha_ctx(info, p) {
        Some(c) if c.state == READY => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    ptr::copy(nonce, c.nonce.as_mut_ptr(), 12);
    c.nonce_valid = true;
    c.cipher = ChaCha::new(&c.key.into(), &c.nonce.into());
    let mut first = [0u8; 64];
    c.cipher.apply_keystream(&mut first);
    let poly_key = <&poly1305::Key>::try_from(&first[..32]).expect("32-byte key");
    c.auth = Auth::new(Poly1305::new(poly_key));
    erase(first.as_mut_ptr(), 64);
    c.stream_used = 64;
    c.aad_len = 0;
    c.data_len = 0;
    c.direction = 0;
    c.state = AAD;
    0
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_incnonce(
    info: *const ChaInfo,
    p: *mut u8,
    out: *mut u8,
) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    let c = match cha_ctx(info, p) {
        Some(c) if c.state == READY && c.nonce_valid => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    // Treat the entire nonce as a little-endian integer, matching RFC stream convention.
    if c.nonce.iter().all(|b| *b == 255) {
        return INVALID;
    }
    for b in &mut c.nonce {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            break;
        }
    }
    let nonce = c.nonce;
    let rc = ccchacha20poly1305_setnonce(info, p, nonce.as_ptr());
    if rc == 0 {
        ptr::copy_nonoverlapping(nonce.as_ptr(), out, 12);
    }
    rc
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_aad(
    info: *const ChaInfo,
    p: *mut u8,
    n: usize,
    input: *const u8,
) -> i32 {
    if !valid_input(input, n) {
        return INVALID;
    }
    let c = match cha_ctx(info, p) {
        Some(c) if c.state == AAD => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    let total = match c.aad_len.checked_add(n as u64) {
        Some(v) => v,
        None => return INVALID,
    };
    c.auth.feed(bytes(input, n));
    c.aad_len = total;
    0
}
unsafe fn cha_update(
    info: *const ChaInfo,
    p: *mut u8,
    n: usize,
    input: *const u8,
    output: *mut u8,
    decrypt: bool,
) -> i32 {
    if !valid_io(input, output, n) {
        return INVALID;
    }
    let c = match cha_ctx(info, p) {
        Some(c) if c.state == AAD || c.state == DATA => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    let direction = if decrypt { 2 } else { 1 };
    if c.direction != 0 && c.direction != direction {
        return SEQUENCE;
    }
    let total = match c.data_len.checked_add(n as u64) {
        Some(v) if v <= CHACHA_MAX_DATA => v,
        _ => return INVALID,
    };
    if c.state == AAD {
        c.auth.pad();
        c.state = DATA;
    }
    c.direction = direction;
    let mut offset = 0;
    while offset < n {
        if c.stream_used == 64 {
            c.stream = [0u8; 64];
            c.cipher.apply_keystream(&mut c.stream);
            c.stream_used = 0;
        }
        let take = (64 - c.stream_used).min(n - offset);
        let mut ciphertext = [0u8; 64];
        for i in 0..take {
            let src = ptr::read(input.add(offset + i));
            let dst = src ^ c.stream[c.stream_used + i];
            ciphertext[i] = if decrypt { src } else { dst };
            ptr::write(output.add(offset + i), dst);
        }
        c.auth.feed(&ciphertext[..take]);
        c.stream_used += take;
        offset += take;
    }
    c.data_len = total;
    0
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_encrypt(
    info: *const ChaInfo,
    p: *mut u8,
    n: usize,
    input: *const u8,
    out: *mut u8,
) -> i32 {
    cha_update(info, p, n, input, out, false)
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_decrypt(
    info: *const ChaInfo,
    p: *mut u8,
    n: usize,
    input: *const u8,
    out: *mut u8,
) -> i32 {
    cha_update(info, p, n, input, out, true)
}
unsafe fn cha_tag(info: *const ChaInfo, p: *mut u8, tag: *mut u8, verify: bool) -> i32 {
    if tag.is_null() {
        return INVALID;
    }
    let c = match cha_ctx(info, p) {
        Some(c) if c.state == AAD || c.state == DATA => c,
        Some(_) => return SEQUENCE,
        None => return INVALID,
    };
    if c.direction != 0 && c.direction != if verify { 2 } else { 1 } {
        return SEQUENCE;
    }
    c.auth.pad();
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&c.aad_len.to_le_bytes());
    lengths[8..].copy_from_slice(&c.data_len.to_le_bytes());
    c.auth.feed(&lengths);
    let mut expected = c.auth.hash.clone().finalize();
    c.state = FINAL;
    let rc = if verify {
        if bool::from(expected.as_slice().ct_eq(bytes(tag, 16))) {
            0
        } else {
            AUTH_FAILED
        }
    } else {
        ptr::copy_nonoverlapping(expected.as_ptr(), tag, 16);
        0
    };
    erase(expected.as_mut_ptr(), 16);
    rc
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_finalize(
    info: *const ChaInfo,
    p: *mut u8,
    tag: *mut u8,
) -> i32 {
    cha_tag(info, p, tag, false)
}
#[no_mangle]
pub unsafe extern "C" fn ccchacha20poly1305_verify(
    info: *const ChaInfo,
    p: *mut u8,
    tag: *const u8,
) -> i32 {
    cha_tag(info, p, tag as *mut u8, true)
}
#[repr(C)]
pub struct ChaFns {
    info: extern "C" fn() -> *const ChaInfo,
    init: unsafe extern "C" fn(*const ChaInfo, *mut u8, *const u8) -> i32,
    reset: unsafe extern "C" fn(*const ChaInfo, *mut u8) -> i32,
    setnonce: unsafe extern "C" fn(*const ChaInfo, *mut u8, *const u8) -> i32,
    incnonce: unsafe extern "C" fn(*const ChaInfo, *mut u8, *mut u8) -> i32,
    aad: unsafe extern "C" fn(*const ChaInfo, *mut u8, usize, *const u8) -> i32,
    encrypt: unsafe extern "C" fn(*const ChaInfo, *mut u8, usize, *const u8, *mut u8) -> i32,
    finalize: unsafe extern "C" fn(*const ChaInfo, *mut u8, *mut u8) -> i32,
    decrypt: unsafe extern "C" fn(*const ChaInfo, *mut u8, usize, *const u8, *mut u8) -> i32,
    verify: unsafe extern "C" fn(*const ChaInfo, *mut u8, *const u8) -> i32,
}
static CHACHA_FNS: Mutable<ChaFns> = Mutable::new(ChaFns {
    info: ccchacha20poly1305_info,
    init: ccchacha20poly1305_init,
    reset: ccchacha20poly1305_reset,
    setnonce: ccchacha20poly1305_setnonce,
    incnonce: ccchacha20poly1305_incnonce,
    aad: ccchacha20poly1305_aad,
    encrypt: ccchacha20poly1305_encrypt,
    finalize: ccchacha20poly1305_finalize,
    decrypt: ccchacha20poly1305_decrypt,
    verify: ccchacha20poly1305_verify,
});
#[no_mangle]
pub extern "C" fn xnu_rc_chacha20poly1305_fns() -> *const ChaFns {
    crate::ensure_tables_signed();
    CHACHA_FNS.get()
}
