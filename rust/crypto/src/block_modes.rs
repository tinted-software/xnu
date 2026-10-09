//! Allocation-free block-cipher KPI, implemented with RustCrypto primitives.
//! AES keeps a compact key because the legacy CBC storage cannot hold the
//! software backend's expanded schedule. A schedule is expanded once per call,
//! not once per block. DES schedules fit and are retained in their C contexts.
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use core::ffi::{c_int, c_ulong, c_void};
use core::mem::{align_of, size_of};
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use des::{Des, TdesEde3};

use crate::ptrauth::{self, Mutable};

const INVALID: c_int = -67;
const MAGIC: u32 = 0x584e5542;
const AES: u8 = 1;
const DES: u8 = 2;
const TDES: u8 = 3;
const XTS_LIMIT: usize = 1 << 20;

unsafe fn erase(p: *mut u8, n: usize) {
    for i in 0..n {
        ptr::write_volatile(p.add(i), 0);
    }
    compiler_fence(Ordering::SeqCst);
}
struct Secret<const N: usize>([u8; N]);
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        unsafe { erase(self.0.as_mut_ptr(), N) }
    }
}

#[repr(C)]
struct Header {
    magic: u32,
    kind: u8,
    decrypt: u8,
    key_len: u8,
    reserved: u8,
}
#[repr(C, align(16))]
struct KeyCtx {
    header: Header,
    key: [u8; 32],
}
#[repr(C, align(16))]
struct DesCtx {
    header: Header,
    cipher: Des,
}
#[repr(C, align(16))]
struct TdesCtx {
    header: Header,
    cipher: TdesEde3,
}
#[repr(C, align(16))]
struct CtrCtx {
    key: KeyCtx,
    counter: [u8; 16],
    stream: [u8; 16],
    used: u8,
    exhausted: u8,
}
#[repr(C, align(16))]
struct XtsCtx {
    data: KeyCtx,
    tweak_key: [u8; 32],
}
#[repr(C, align(16))]
struct XtsTweak {
    value: [u8; 16],
    blocks: usize,
}

// These constants are published in ccmode_abi.h and fit the fixed C ABI.
const _: () = assert!(size_of::<KeyCtx>() == 48 && size_of::<KeyCtx>() <= 280);
const _: () = assert!(size_of::<DesCtx>() == 144 && size_of::<DesCtx>() <= 256);
const _: () = assert!(size_of::<TdesCtx>() == 400 && size_of::<TdesCtx>() <= 768);
const _: () = assert!(size_of::<CtrCtx>() == 96);
const _: () = assert!(size_of::<XtsCtx>() == 80 && size_of::<XtsCtx>() <= 1064);
const _: () = assert!(size_of::<XtsTweak>() == 32);

#[repr(C)]
pub struct Ecb {
    size: usize,
    block_size: usize,
    init: unsafe extern "C" fn(*const Ecb, *mut c_void, usize, *const c_void) -> c_int,
    ecb: unsafe extern "C" fn(*const c_void, usize, *const c_void, *mut c_void) -> c_int,
    reserved_roundkey: usize,
    implementation: u32,
}
#[repr(C)]
pub struct Cbc {
    size: usize,
    block_size: usize,
    init: unsafe extern "C" fn(*const Cbc, *mut c_void, usize, *const c_void) -> c_int,
    cbc: unsafe extern "C" fn(
        *const c_void,
        *mut c_void,
        usize,
        *const c_void,
        *mut c_void,
    ) -> c_int,
    custom: *const c_void,
}
#[repr(C)]
pub struct Ctr {
    size: usize,
    block_size: usize,
    ecb_block_size: usize,
    init:
        unsafe extern "C" fn(*const Ctr, *mut c_void, usize, *const c_void, *const c_void) -> c_int,
    setctr: unsafe extern "C" fn(*const Ctr, *mut c_void, *const c_void) -> c_int,
    ctr: unsafe extern "C" fn(*mut c_void, usize, *const c_void, *mut c_void) -> c_int,
    custom: *const c_void,
}
#[repr(C)]
pub struct Xts {
    size: usize,
    tweak_size: usize,
    block_size: usize,
    init:
        unsafe extern "C" fn(*const Xts, *mut c_void, usize, *const c_void, *const c_void) -> c_int,
    key_sched: unsafe extern "C" fn(*const Xts, *mut c_void, usize, *const c_void, *const c_void),
    set_tweak: unsafe extern "C" fn(*const c_void, *mut c_void, *const c_void) -> c_int,
    xts: unsafe extern "C" fn(
        *const c_void,
        *mut c_void,
        usize,
        *const c_void,
        *mut c_void,
    ) -> *mut c_void,
    custom: *const c_void,
    custom1: *const c_void,
    implementation: u32,
}
// Descriptor metadata points only to immutable descriptors.
unsafe impl Sync for Cbc {}
unsafe impl Sync for Ctr {}
unsafe impl Sync for Xts {}

fn aligned<T>(p: *const c_void) -> bool {
    !p.is_null() && (p as usize) % align_of::<T>() == 0
}
fn buffer(p: *const c_void, n: usize) -> bool {
    n == 0 || (!p.is_null() && n <= isize::MAX as usize && (p as usize).checked_add(n).is_some())
}
fn buffers(input: *const c_void, output: *mut c_void, n: usize) -> bool {
    if !buffer(input, n) || !buffer(output, n) {
        return false;
    }
    n == 0
        || input == output.cast_const()
        || (input as usize + n <= output as usize)
        || (output as usize + n <= input as usize)
}
fn bytes(nblocks: usize, block_size: usize) -> Option<usize> {
    nblocks
        .checked_mul(block_size)
        .filter(|n| *n <= isize::MAX as usize)
}
fn key_valid(kind: u8, n: usize) -> bool {
    match kind {
        AES => matches!(n, 16 | 24 | 32),
        DES => n == 8,
        TDES => n == 24,
        _ => false,
    }
}
fn ctx_size(kind: u8) -> usize {
    match kind {
        AES => size_of::<KeyCtx>(),
        DES => size_of::<DesCtx>(),
        TDES => size_of::<TdesCtx>(),
        _ => 0,
    }
}
unsafe fn init_key(
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
    kind: u8,
    decrypt: bool,
) -> c_int {
    if !aligned::<KeyCtx>(ctx) {
        return INVALID;
    }
    let size = ctx_size(kind);
    if !key_valid(kind, n) || !buffer(key, n) {
        erase(ctx.cast(), size);
        return INVALID;
    }
    let header = Header {
        magic: MAGIC,
        kind,
        decrypt: decrypt as u8,
        key_len: n as u8,
        reserved: 0,
    };
    match kind {
        AES => {
            let mut raw = Secret([0u8; 32]);
            ptr::copy_nonoverlapping(key.cast(), raw.0.as_mut_ptr(), n);
            erase(ctx.cast(), size);
            ptr::write(ctx.cast::<KeyCtx>(), KeyCtx { header, key: raw.0 });
        }
        DES => {
            let cipher = match Des::new_from_slice(core::slice::from_raw_parts(key.cast(), n)) {
                Ok(c) => c,
                Err(_) => {
                    erase(ctx.cast(), size);
                    return INVALID;
                }
            };
            erase(ctx.cast(), size);
            ptr::write(ctx.cast::<DesCtx>(), DesCtx { header, cipher });
        }
        TDES => {
            let cipher = match TdesEde3::new_from_slice(core::slice::from_raw_parts(key.cast(), n))
            {
                Ok(c) => c,
                Err(_) => {
                    erase(ctx.cast(), size);
                    return INVALID;
                }
            };
            erase(ctx.cast(), size);
            ptr::write(ctx.cast::<TdesCtx>(), TdesCtx { header, cipher });
        }
        _ => return INVALID,
    }
    0
}

enum Cipher<'a> {
    A128(&'a Aes128),
    A192(&'a Aes192),
    A256(&'a Aes256),
    Des(&'a Des),
    Tdes(&'a TdesEde3),
}
impl Cipher<'_> {
    fn block_size(&self) -> usize {
        match self {
            Self::Des(_) | Self::Tdes(_) => 8,
            _ => 16,
        }
    }
    fn crypt(&self, b: &mut [u8; 16], decrypt: bool) {
        macro_rules! apply {
            ($c:expr, $t:ty, $n:expr) => {{
                let block = <&mut aes::cipher::Block<$t>>::try_from(&mut b[..$n])
                    .expect("cipher block size");
                if decrypt {
                    $c.decrypt_block(block)
                } else {
                    $c.encrypt_block(block)
                }
            }};
        }
        match self {
            Self::A128(c) => apply!(c, Aes128, 16),
            Self::A192(c) => apply!(c, Aes192, 16),
            Self::A256(c) => apply!(c, Aes256, 16),
            Self::Des(c) => apply!(c, Des, 8),
            Self::Tdes(c) => apply!(c, TdesEde3, 8),
        }
    }
}
unsafe fn with_cipher(ctx: *const c_void, f: impl FnOnce(Cipher<'_>, bool) -> c_int) -> c_int {
    if !aligned::<KeyCtx>(ctx) {
        return INVALID;
    }
    let h = &*ctx.cast::<Header>();
    if h.magic != MAGIC || h.decrypt > 1 || !key_valid(h.kind, h.key_len as usize) {
        return INVALID;
    }
    let dec = h.decrypt != 0;
    macro_rules! aes_cipher {
        ($t:ty, $v:ident) => {{
            let key = &(*ctx.cast::<KeyCtx>()).key;
            let raw = &key[..h.key_len as usize];
            match <$t>::new_from_slice(raw) {
                Ok(c) => f(Cipher::$v(&c), dec),
                Err(_) => INVALID,
            }
        }};
    }
    match h.kind {
        AES => match h.key_len {
            16 => aes_cipher!(Aes128, A128),
            24 => aes_cipher!(Aes192, A192),
            32 => aes_cipher!(Aes256, A256),
            _ => INVALID,
        },
        DES => f(Cipher::Des(&(*ctx.cast::<DesCtx>()).cipher), dec),
        TDES => f(Cipher::Tdes(&(*ctx.cast::<TdesCtx>()).cipher), dec),
        _ => INVALID,
    }
}
unsafe extern "C" fn ecb_crypt(
    ctx: *const c_void,
    nblocks: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    with_cipher(ctx, |cipher, dec| {
        let bs = cipher.block_size();
        let n = match bytes(nblocks, bs) {
            Some(n) => n,
            None => return INVALID,
        };
        if !buffers(input, output, n) {
            return INVALID;
        }
        let mut b = Secret([0u8; 16]);
        for i in 0..nblocks {
            ptr::copy_nonoverlapping(input.cast::<u8>().add(i * bs), b.0.as_mut_ptr(), bs);
            cipher.crypt(&mut b.0, dec);
            ptr::copy_nonoverlapping(b.0.as_ptr(), output.cast::<u8>().add(i * bs), bs);
        }
        0
    })
}
unsafe extern "C" fn cbc_crypt(
    ctx: *const c_void,
    iv: *mut c_void,
    nblocks: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    with_cipher(ctx, |cipher, dec| {
        let bs = cipher.block_size();
        let n = match bytes(nblocks, bs) {
            Some(n) => n,
            None => return INVALID,
        };
        if !buffer(iv, bs) || !buffers(input, output, n) {
            return INVALID;
        }
        let mut chain = Secret([0u8; 16]);
        let mut b = Secret([0u8; 16]);
        let mut saved = Secret([0u8; 16]);
        ptr::copy_nonoverlapping(iv.cast(), chain.0.as_mut_ptr(), bs);
        for i in 0..nblocks {
            ptr::copy_nonoverlapping(input.cast::<u8>().add(i * bs), b.0.as_mut_ptr(), bs);
            if dec {
                saved.0[..bs].copy_from_slice(&b.0[..bs]);
                cipher.crypt(&mut b.0, true);
                for j in 0..bs {
                    b.0[j] ^= chain.0[j];
                }
                chain.0[..bs].copy_from_slice(&saved.0[..bs]);
            } else {
                for j in 0..bs {
                    b.0[j] ^= chain.0[j];
                }
                cipher.crypt(&mut b.0, false);
                chain.0[..bs].copy_from_slice(&b.0[..bs]);
            }
            ptr::copy_nonoverlapping(b.0.as_ptr(), output.cast::<u8>().add(i * bs), bs);
        }
        ptr::copy_nonoverlapping(chain.0.as_ptr(), iv.cast(), bs);
        0
    })
}

macro_rules! modes {
    ($enc_init:ident, $dec_init:ident, $cbc_enc_init:ident, $cbc_dec_init:ident,
     $ee:ident, $ed:ident, $ce:ident, $cd:ident, $es:ident, $ds:ident, $ces:ident, $cds:ident,
     $kind:expr, $ctx:ty, $bs:expr, $sign:ident) => {
        unsafe extern "C" fn $enc_init(
            _: *const Ecb,
            ctx: *mut c_void,
            n: usize,
            key: *const c_void,
        ) -> c_int {
            init_key(ctx, n, key, $kind, false)
        }
        unsafe extern "C" fn $dec_init(
            _: *const Ecb,
            ctx: *mut c_void,
            n: usize,
            key: *const c_void,
        ) -> c_int {
            init_key(ctx, n, key, $kind, true)
        }
        unsafe extern "C" fn $cbc_enc_init(
            _: *const Cbc,
            ctx: *mut c_void,
            n: usize,
            key: *const c_void,
        ) -> c_int {
            init_key(ctx, n, key, $kind, false)
        }
        unsafe extern "C" fn $cbc_dec_init(
            _: *const Cbc,
            ctx: *mut c_void,
            n: usize,
            key: *const c_void,
        ) -> c_int {
            init_key(ctx, n, key, $kind, true)
        }
        static $ee: Mutable<Ecb> = Mutable::new(Ecb {
            size: size_of::<$ctx>(),
            block_size: $bs,
            init: $enc_init,
            ecb: ecb_crypt,
            reserved_roundkey: 0,
            implementation: 0,
        });
        static $ed: Mutable<Ecb> = Mutable::new(Ecb {
            size: size_of::<$ctx>(),
            block_size: $bs,
            init: $dec_init,
            ecb: ecb_crypt,
            reserved_roundkey: 0,
            implementation: 0,
        });
        static $ce: Mutable<Cbc> = Mutable::new(Cbc {
            size: size_of::<$ctx>(),
            block_size: $bs,
            init: $cbc_enc_init,
            cbc: cbc_crypt,
            custom: $ee.get() as *const Ecb as *const c_void,
        });
        static $cd: Mutable<Cbc> = Mutable::new(Cbc {
            size: size_of::<$ctx>(),
            block_size: $bs,
            init: $cbc_dec_init,
            cbc: cbc_crypt,
            custom: $ed.get() as *const Ecb as *const c_void,
        });
        /// Signs this cipher's tables for C (see `ptrauth`).
        unsafe fn $sign() {
            for ecb in [&mut *$ee.get(), &mut *$ed.get()] {
                ecb.init = ptrauth::sign(ecb.init);
                ecb.ecb = ptrauth::sign(ecb.ecb);
            }
            for cbc in [&mut *$ce.get(), &mut *$cd.get()] {
                cbc.init = ptrauth::sign(cbc.init);
                cbc.cbc = ptrauth::sign(cbc.cbc);
            }
        }
        #[no_mangle]
        pub extern "C" fn $es() -> *const Ecb {
            crate::ensure_tables_signed();
            $ee.get()
        }
        #[no_mangle]
        pub extern "C" fn $ds() -> *const Ecb {
            crate::ensure_tables_signed();
            $ed.get()
        }
        #[no_mangle]
        pub extern "C" fn $ces() -> *const Cbc {
            crate::ensure_tables_signed();
            $ce.get()
        }
        #[no_mangle]
        pub extern "C" fn $cds() -> *const Cbc {
            crate::ensure_tables_signed();
            $cd.get()
        }
    };
}
modes!(
    aes_enc_init,
    aes_dec_init,
    aes_cbc_enc_init,
    aes_cbc_dec_init,
    AES_EE,
    AES_ED,
    AES_CE,
    AES_CD,
    xnu_rc_aes_ecb_encrypt_mode,
    xnu_rc_aes_ecb_decrypt_mode,
    xnu_rc_aes_cbc_encrypt_mode,
    xnu_rc_aes_cbc_decrypt_mode,
    AES,
    KeyCtx,
    16,
    sign_aes
);
modes!(
    des_enc_init,
    des_dec_init,
    des_cbc_enc_init,
    des_cbc_dec_init,
    DES_EE,
    DES_ED,
    DES_CE,
    DES_CD,
    xnu_rc_des_ecb_encrypt_mode,
    xnu_rc_des_ecb_decrypt_mode,
    xnu_rc_des_cbc_encrypt_mode,
    xnu_rc_des_cbc_decrypt_mode,
    DES,
    DesCtx,
    8,
    sign_des
);
modes!(
    tdes_enc_init,
    tdes_dec_init,
    tdes_cbc_enc_init,
    tdes_cbc_dec_init,
    TDES_EE,
    TDES_ED,
    TDES_CE,
    TDES_CD,
    xnu_rc_tdes_ecb_encrypt_mode,
    xnu_rc_tdes_ecb_decrypt_mode,
    xnu_rc_tdes_cbc_encrypt_mode,
    xnu_rc_tdes_cbc_decrypt_mode,
    TDES,
    TdesCtx,
    8,
    sign_tdes
);

unsafe extern "C" fn ctr_init(
    _: *const Ctr,
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
    iv: *const c_void,
) -> c_int {
    if !aligned::<CtrCtx>(ctx) {
        return INVALID;
    }
    if !buffer(iv, 16) {
        erase(ctx.cast(), size_of::<CtrCtx>());
        return INVALID;
    }
    let mut ctr = Secret([0u8; 16]);
    ptr::copy_nonoverlapping(iv.cast(), ctr.0.as_mut_ptr(), 16);
    let rc = init_key(ctx, n, key, AES, false);
    if rc != 0 {
        erase(ctx.cast(), size_of::<CtrCtx>());
        return rc;
    }
    let c = &mut *ctx.cast::<CtrCtx>();
    c.counter = ctr.0;
    c.stream = [0; 16];
    c.used = 16;
    c.exhausted = 0;
    0
}
unsafe extern "C" fn ctr_set(_: *const Ctr, ctx: *mut c_void, iv: *const c_void) -> c_int {
    if !aligned::<CtrCtx>(ctx) || !buffer(iv, 16) {
        return INVALID;
    }
    let c = &mut *ctx.cast::<CtrCtx>();
    if c.key.header.magic != MAGIC || c.key.header.kind != AES {
        return INVALID;
    }
    ptr::copy(iv.cast(), c.counter.as_mut_ptr(), 16);
    erase(c.stream.as_mut_ptr(), 16);
    c.used = 16;
    c.exhausted = 0;
    0
}
unsafe extern "C" fn ctr_crypt(
    ctx: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if !aligned::<CtrCtx>(ctx) || !buffers(input, output, n) {
        return INVALID;
    }
    // The closure mutates only fields following KeyCtx; the shared key borrow
    // in with_cipher is disjoint from the counter and buffered keystream.
    let c = ctx.cast::<CtrCtx>();
    if (*c).used > 16 || (*c).exhausted > 1 {
        return INVALID;
    }
    let available = 16 - (*c).used as usize;
    let needed = n.saturating_sub(available).div_ceil(16);
    let counter = u128::from_be_bytes((*c).counter);
    if needed != 0 && ((*c).exhausted != 0 || (needed - 1) as u128 > u128::MAX - counter) {
        return INVALID;
    }
    with_cipher(ctx, |cipher, _| {
        if cipher.block_size() != 16 {
            return INVALID;
        }
        for i in 0..n {
            if (*c).used == 16 {
                (*c).stream = (*c).counter;
                cipher.crypt(&mut (*c).stream, false);
                let next = u128::from_be_bytes((*c).counter).overflowing_add(1);
                (*c).counter = next.0.to_be_bytes();
                (*c).exhausted = next.1 as u8;
                (*c).used = 0;
            }
            let byte = ptr::read(input.cast::<u8>().add(i));
            ptr::write(
                output.cast::<u8>().add(i),
                byte ^ (&(*c).stream)[(*c).used as usize],
            );
            (*c).used += 1;
        }
        0
    })
}
static AES_CTR: Mutable<Ctr> = Mutable::new(Ctr {
    size: size_of::<CtrCtx>(),
    block_size: 1,
    ecb_block_size: 16,
    init: ctr_init,
    setctr: ctr_set,
    ctr: ctr_crypt,
    custom: AES_EE.get() as *const Ecb as *const c_void,
});
#[no_mangle]
pub extern "C" fn xnu_rc_aes_ctr_crypt_mode() -> *const Ctr {
    crate::ensure_tables_signed();
    AES_CTR.get()
}

unsafe fn xts_key_init(
    ctx: *mut c_void,
    n: usize,
    data_key: *const c_void,
    tweak_key: *const c_void,
    dec: bool,
) -> c_int {
    if !aligned::<XtsCtx>(ctx) {
        return INVALID;
    }
    if !key_valid(AES, n) || !buffer(data_key, n) || !buffer(tweak_key, n) {
        erase(ctx.cast(), size_of::<XtsCtx>());
        return INVALID;
    }
    // IEEE 1619 requires independently chosen keys; reject identical halves.
    let mut different = 0u8;
    let mut tweak = Secret([0u8; 32]);
    for i in 0..n {
        tweak.0[i] = ptr::read(tweak_key.cast::<u8>().add(i));
        different |= tweak.0[i] ^ ptr::read(data_key.cast::<u8>().add(i));
    }
    if different == 0 {
        erase(ctx.cast(), size_of::<XtsCtx>());
        return INVALID;
    }
    let rc = init_key(ctx, n, data_key, AES, dec);
    if rc != 0 {
        erase(ctx.cast(), size_of::<XtsCtx>());
        return rc;
    }
    (*ctx.cast::<XtsCtx>()).tweak_key = tweak.0;
    0
}
unsafe extern "C" fn xts_enc_init(
    _: *const Xts,
    ctx: *mut c_void,
    n: usize,
    k: *const c_void,
    t: *const c_void,
) -> c_int {
    xts_key_init(ctx, n, k, t, false)
}
unsafe extern "C" fn xts_dec_init(
    _: *const Xts,
    ctx: *mut c_void,
    n: usize,
    k: *const c_void,
    t: *const c_void,
) -> c_int {
    xts_key_init(ctx, n, k, t, true)
}
unsafe extern "C" fn xts_enc_schedule(
    mode: *const Xts,
    ctx: *mut c_void,
    n: usize,
    k: *const c_void,
    t: *const c_void,
) {
    let _ = xts_enc_init(mode, ctx, n, k, t);
}
unsafe extern "C" fn xts_dec_schedule(
    mode: *const Xts,
    ctx: *mut c_void,
    n: usize,
    k: *const c_void,
    t: *const c_void,
) {
    let _ = xts_dec_init(mode, ctx, n, k, t);
}
unsafe extern "C" fn xts_set(ctx: *const c_void, tweak: *mut c_void, iv: *const c_void) -> c_int {
    if !aligned::<XtsCtx>(ctx) || !aligned::<XtsTweak>(tweak) || !buffer(iv, 16) {
        return INVALID;
    }
    let x = &*ctx.cast::<XtsCtx>();
    if x.data.header.magic != MAGIC
        || x.data.header.kind != AES
        || !key_valid(AES, x.data.header.key_len as usize)
    {
        return INVALID;
    }
    let mut key = KeyCtx {
        header: Header {
            magic: MAGIC,
            kind: AES,
            decrypt: 0,
            key_len: x.data.header.key_len,
            reserved: 0,
        },
        key: x.tweak_key,
    };
    let mut value = Secret([0u8; 16]);
    ptr::copy_nonoverlapping(iv.cast(), value.0.as_mut_ptr(), 16);
    let rc = with_cipher((&key as *const KeyCtx).cast(), |cipher, _| {
        cipher.crypt(&mut value.0, false);
        0
    });
    erase((&mut key as *mut KeyCtx).cast(), size_of::<KeyCtx>());
    if rc != 0 {
        return rc;
    }
    ptr::write(
        tweak.cast::<XtsTweak>(),
        XtsTweak {
            value: value.0,
            blocks: 0,
        },
    );
    0
}
fn multiply_alpha(value: &mut [u8; 16]) {
    let mut carry = 0;
    for byte in value.iter_mut() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    value[0] ^= 0x87 & 0u8.wrapping_sub(carry);
}
unsafe extern "C" fn xts_crypt(
    ctx: *const c_void,
    tweak: *mut c_void,
    nblocks: usize,
    input: *const c_void,
    output: *mut c_void,
) -> *mut c_void {
    if !aligned::<XtsTweak>(tweak) {
        return ptr::null_mut();
    }
    let t = &mut *tweak.cast::<XtsTweak>();
    let n = match bytes(nblocks, 16) {
        Some(n) => n,
        None => return ptr::null_mut(),
    };
    if !buffers(input, output, n) || t.blocks > XTS_LIMIT || nblocks > XTS_LIMIT - t.blocks {
        return ptr::null_mut();
    }
    let rc = with_cipher(ctx, |cipher, dec| {
        if cipher.block_size() != 16 {
            return INVALID;
        }
        let mut b = Secret([0u8; 16]);
        for i in 0..nblocks {
            ptr::copy_nonoverlapping(input.cast::<u8>().add(i * 16), b.0.as_mut_ptr(), 16);
            for j in 0..16 {
                b.0[j] ^= t.value[j];
            }
            cipher.crypt(&mut b.0, dec);
            for j in 0..16 {
                b.0[j] ^= t.value[j];
            }
            ptr::copy_nonoverlapping(b.0.as_ptr(), output.cast::<u8>().add(i * 16), 16);
            multiply_alpha(&mut t.value);
        }
        t.blocks += nblocks;
        0
    });
    if rc == 0 {
        tweak
    } else {
        ptr::null_mut()
    }
}
static AES_XE: Mutable<Xts> = Mutable::new(Xts {
    size: size_of::<XtsCtx>(),
    tweak_size: size_of::<XtsTweak>(),
    block_size: 16,
    init: xts_enc_init,
    key_sched: xts_enc_schedule,
    set_tweak: xts_set,
    xts: xts_crypt,
    custom: AES_EE.get() as *const Ecb as *const c_void,
    custom1: AES_EE.get() as *const Ecb as *const c_void,
    implementation: 0,
});
static AES_XD: Mutable<Xts> = Mutable::new(Xts {
    size: size_of::<XtsCtx>(),
    tweak_size: size_of::<XtsTweak>(),
    block_size: 16,
    init: xts_dec_init,
    key_sched: xts_dec_schedule,
    set_tweak: xts_set,
    xts: xts_crypt,
    custom: AES_ED.get() as *const Ecb as *const c_void,
    custom1: AES_EE.get() as *const Ecb as *const c_void,
    implementation: 0,
});
#[no_mangle]
pub extern "C" fn xnu_rc_aes_xts_encrypt_mode() -> *const Xts {
    crate::ensure_tables_signed();
    AES_XE.get()
}
#[no_mangle]
pub extern "C" fn xnu_rc_aes_xts_decrypt_mode() -> *const Xts {
    crate::ensure_tables_signed();
    AES_XD.get()
}

/// Signs this module's tables for C (see `ptrauth`).
pub(crate) fn sign_tables() {
    // SAFETY: called once from `ensure_tables_signed`, before C sees the tables.
    unsafe {
        sign_aes();
        sign_des();
        sign_tdes();
        let ctr = &mut *AES_CTR.get();
        ctr.init = ptrauth::sign(ctr.init);
        ctr.setctr = ptrauth::sign(ctr.setctr);
        ctr.ctr = ptrauth::sign(ctr.ctr);
        for xts in [&mut *AES_XE.get(), &mut *AES_XD.get()] {
            xts.init = ptrauth::sign(xts.init);
            xts.key_sched = ptrauth::sign(xts.key_sched);
            xts.set_tweak = ptrauth::sign(xts.set_tweak);
            xts.xts = ptrauth::sign(xts.xts);
        }
    }
}

// Bounded temporary storage accommodates all supported DES and AES contexts.
#[repr(C, align(16))]
struct Temporary<const N: usize>([u8; N]);
impl<const N: usize> Drop for Temporary<N> {
    fn drop(&mut self) {
        unsafe { erase(self.0.as_mut_ptr(), N) }
    }
}
macro_rules! sizes {
    ($context:ident, $block:ident, $mode:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn $context(mode: *const $mode) -> usize {
            if mode.is_null() {
                0
            } else {
                (*mode).size
            }
        }
        #[no_mangle]
        pub unsafe extern "C" fn $block(mode: *const $mode) -> usize {
            if mode.is_null() {
                0
            } else {
                (*mode).block_size
            }
        }
    };
}
sizes!(ccecb_context_size, ccecb_block_size, Ecb);
sizes!(cccbc_context_size, cccbc_block_size, Cbc);
sizes!(ccctr_context_size, ccctr_block_size, Ctr);
sizes!(ccxts_context_size, ccxts_block_size, Xts);
#[no_mangle]
pub unsafe extern "C" fn ccxts_tweak_size(mode: *const Xts) -> usize {
    if mode.is_null() {
        0
    } else {
        (*mode).tweak_size
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccecb_init(
    mode: *const Ecb,
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).init))(mode, ctx, n, key)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccecb_update(
    mode: *const Ecb,
    ctx: *const c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).ecb))(ctx, n, input, output)
    }
}
#[no_mangle]
pub unsafe extern "C" fn cccbc_init(
    mode: *const Cbc,
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).init))(mode, ctx, n, key)
    }
}
#[no_mangle]
pub unsafe extern "C" fn cccbc_copy_iv(iv: *mut c_void, input: *const c_void, n: usize) -> c_int {
    if !buffer(iv, n) || !buffer(input, n) {
        return INVALID;
    }
    if n != 0 {
        ptr::copy(input.cast::<u8>(), iv.cast::<u8>(), n);
    }
    0
}
#[no_mangle]
pub unsafe extern "C" fn cccbc_clear_iv(iv: *mut c_void, n: usize) -> c_int {
    if !buffer(iv, n) {
        return INVALID;
    }
    erase(iv.cast(), n);
    0
}
#[no_mangle]
pub unsafe extern "C" fn cccbc_set_iv(
    mode: *const Cbc,
    iv: *mut c_void,
    input: *const c_void,
) -> c_int {
    if mode.is_null() {
        return INVALID;
    }
    if input.is_null() {
        cccbc_clear_iv(iv, (*mode).block_size)
    } else {
        cccbc_copy_iv(iv, input, (*mode).block_size)
    }
}
#[no_mangle]
pub unsafe extern "C" fn cccbc_update(
    mode: *const Cbc,
    ctx: *const c_void,
    iv: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).cbc))(ctx, iv, n, input, output)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccctr_init(
    mode: *const Ctr,
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
    iv: *const c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).init))(mode, ctx, n, key, iv)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccctr_setctr(
    mode: *const Ctr,
    ctx: *mut c_void,
    iv: *const c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).setctr))(mode, ctx, iv)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccctr_update(
    mode: *const Ctr,
    ctx: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).ctr))(ctx, n, input, output)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccxts_init(
    mode: *const Xts,
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
    tweak: *const c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).init))(mode, ctx, n, key, tweak)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccxts_key_sched(
    mode: *const Xts,
    ctx: *mut c_void,
    n: usize,
    key: *const c_void,
    tweak: *const c_void,
) {
    if !mode.is_null() {
        (ptrauth::auth((*mode).key_sched))(mode, ctx, n, key, tweak);
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccxts_set_tweak(
    mode: *const Xts,
    ctx: *const c_void,
    tweak: *mut c_void,
    iv: *const c_void,
) -> c_int {
    if mode.is_null() {
        INVALID
    } else {
        (ptrauth::auth((*mode).set_tweak))(ctx, tweak, iv)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccxts_update(
    mode: *const Xts,
    ctx: *const c_void,
    tweak: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> *mut c_void {
    if mode.is_null() {
        ptr::null_mut()
    } else {
        (ptrauth::auth((*mode).xts))(ctx, tweak, n, input, output)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccecb_one_shot(
    mode: *const Ecb,
    n: usize,
    key: *const c_void,
    blocks: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() || (*mode).size > 400 {
        return INVALID;
    }
    let mut ctx = Temporary([0; 400]);
    let rc = ccecb_init(mode, ctx.0.as_mut_ptr().cast(), n, key);
    if rc != 0 {
        rc
    } else {
        ccecb_update(mode, ctx.0.as_ptr().cast(), blocks, input, output)
    }
}
#[no_mangle]
pub unsafe extern "C" fn cccbc_one_shot(
    mode: *const Cbc,
    n: usize,
    key: *const c_void,
    iv: *const c_void,
    blocks: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() || (*mode).size > 400 || (*mode).block_size > 16 {
        return INVALID;
    }
    let mut ctx = Temporary([0; 400]);
    let mut chain = Secret([0u8; 16]);
    let rc = cccbc_init(mode, ctx.0.as_mut_ptr().cast(), n, key);
    if rc != 0 {
        return rc;
    }
    let rc = cccbc_set_iv(mode, chain.0.as_mut_ptr().cast(), iv);
    if rc != 0 {
        return rc;
    }
    cccbc_update(
        mode,
        ctx.0.as_ptr().cast(),
        chain.0.as_mut_ptr().cast(),
        blocks,
        input,
        output,
    )
}
#[no_mangle]
pub unsafe extern "C" fn ccctr_one_shot(
    mode: *const Ctr,
    n: usize,
    key: *const c_void,
    iv: *const c_void,
    length: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() || (*mode).size > 96 {
        return INVALID;
    }
    let mut ctx = Temporary([0; 96]);
    let rc = ccctr_init(mode, ctx.0.as_mut_ptr().cast(), n, key, iv);
    if rc != 0 {
        rc
    } else {
        ccctr_update(mode, ctx.0.as_mut_ptr().cast(), length, input, output)
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccxts_one_shot(
    mode: *const Xts,
    n: usize,
    key: *const c_void,
    tweak_key: *const c_void,
    iv: *const c_void,
    blocks: usize,
    input: *const c_void,
    output: *mut c_void,
) -> c_int {
    if mode.is_null() || (*mode).size > 80 || (*mode).tweak_size > 32 {
        return INVALID;
    }
    let mut ctx = Temporary([0; 80]);
    let mut tweak = Temporary([0; 32]);
    let rc = ccxts_init(mode, ctx.0.as_mut_ptr().cast(), n, key, tweak_key);
    if rc != 0 {
        return rc;
    }
    let rc = ccxts_set_tweak(mode, ctx.0.as_ptr().cast(), tweak.0.as_mut_ptr().cast(), iv);
    if rc != 0 {
        return rc;
    }
    if ccxts_update(
        mode,
        ctx.0.as_ptr().cast(),
        tweak.0.as_mut_ptr().cast(),
        blocks,
        input,
        output,
    )
    .is_null()
    {
        INVALID
    } else {
        0
    }
}

// NIST SP 800-38A addendum, CBC-CS3: even an exact-length final pair
// is transposed. Preserve the original final two blocks for in-place calls.
unsafe fn cts3(
    mode: *const Cbc,
    ctx: *mut c_void,
    iv: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
    dec: bool,
) -> usize {
    if mode.is_null() {
        return 0;
    }
    let bs = (*mode).block_size;
    if !matches!(bs, 8 | 16) || n < bs || !buffers(input, output, n) || !buffer(iv, bs) {
        return 0;
    }
    if n == bs {
        return if cccbc_update(mode, ctx, iv, 1, input, output) == 0 {
            n
        } else {
            0
        };
    }
    let tail = (n - 1) % bs + 1;
    let prefix = n - bs - tail;
    let mut first = Secret([0u8; 16]);
    let mut last = Secret([0u8; 16]);
    let mut work = Secret([0u8; 16]);
    let mut saved_iv = Secret([0u8; 16]);
    ptr::copy_nonoverlapping(input.cast::<u8>().add(prefix), first.0.as_mut_ptr(), bs);
    ptr::copy_nonoverlapping(
        input.cast::<u8>().add(prefix + bs),
        last.0.as_mut_ptr(),
        tail,
    );
    if cccbc_update(mode, ctx, iv, prefix / bs, input, output) != 0 {
        return 0;
    }
    if !dec {
        if cccbc_update(
            mode,
            ctx,
            iv,
            1,
            first.0.as_ptr().cast(),
            work.0.as_mut_ptr().cast(),
        ) != 0
        {
            return 0;
        }
        first.0 = work.0;
        if cccbc_update(
            mode,
            ctx,
            iv,
            1,
            last.0.as_ptr().cast(),
            work.0.as_mut_ptr().cast(),
        ) != 0
        {
            return 0;
        }
        ptr::copy_nonoverlapping(work.0.as_ptr(), output.cast::<u8>().add(prefix), bs);
        ptr::copy_nonoverlapping(first.0.as_ptr(), output.cast::<u8>().add(prefix + bs), tail);
    } else {
        ptr::copy_nonoverlapping(iv.cast(), saved_iv.0.as_mut_ptr(), bs);
        // D(C_n) = padded P_n XOR C_(n-1). The stolen prefix and
        // the suffix of D(C_n) reconstruct the complete C_(n-1).
        let mut zero_iv = Secret([0u8; 16]);
        if cccbc_update(
            mode,
            ctx,
            zero_iv.0.as_mut_ptr().cast(),
            1,
            first.0.as_ptr().cast(),
            work.0.as_mut_ptr().cast(),
        ) != 0
        {
            return 0;
        }
        for i in 0..tail {
            let stolen = last.0[i];
            last.0[i] ^= work.0[i];
            work.0[i] = stolen;
        }
        if cccbc_update(
            mode,
            ctx,
            saved_iv.0.as_mut_ptr().cast(),
            1,
            work.0.as_ptr().cast(),
            work.0.as_mut_ptr().cast(),
        ) != 0
        {
            return 0;
        }
        ptr::copy_nonoverlapping(work.0.as_ptr(), output.cast::<u8>().add(prefix), bs);
        ptr::copy_nonoverlapping(last.0.as_ptr(), output.cast::<u8>().add(prefix + bs), tail);
        ptr::copy_nonoverlapping(first.0.as_ptr(), iv.cast(), bs);
    }
    n
}
#[no_mangle]
pub unsafe extern "C" fn ccpad_cts3_encrypt(
    mode: *const Cbc,
    ctx: *mut c_void,
    iv: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> usize {
    cts3(mode, ctx, iv, n, input, output, false)
}
#[no_mangle]
pub unsafe extern "C" fn ccpad_cts3_decrypt(
    mode: *const Cbc,
    ctx: *mut c_void,
    iv: *mut c_void,
    n: usize,
    input: *const c_void,
    output: *mut c_void,
) -> usize {
    cts3(mode, ctx, iv, n, input, output, true)
}

#[no_mangle]
pub unsafe extern "C" fn ccdes_key_set_odd_parity(key: *mut c_void, n: c_ulong) {
    let n = n as usize;
    if !buffer(key, n) {
        return;
    }
    for i in 0..n {
        let p = key.cast::<u8>().add(i);
        let byte = ptr::read(p) & 0xfe;
        ptr::write(p, byte | ((byte.count_ones() as u8 & 1) ^ 1));
    }
}
#[no_mangle]
pub unsafe extern "C" fn ccdes_key_is_weak(key: *mut c_void, n: c_ulong) -> c_int {
    if n != 8 || !buffer(key, 8) {
        return INVALID;
    }
    // The four weak and twelve semi-weak DES keys, ignoring parity bits.
    const WEAK: [u64; 16] = [
        0x0101010101010101,
        0xfefefefefefefefe,
        0xe0e0e0e0f1f1f1f1,
        0x1f1f1f1f0e0e0e0e,
        0x01fe01fe01fe01fe,
        0xfe01fe01fe01fe01,
        0x1fe01fe00ef10ef1,
        0xe01fe01ff10ef10e,
        0x01e001e001f101f1,
        0xe001e001f101f101,
        0x1ffe1ffe0efe0efe,
        0xfe1ffe1ffe0efe0e,
        0x011f011f010e010e,
        0x1f011f010e010e01,
        0xe0fee0fef1fef1fe,
        0xfee0fee0fef1fef1,
    ];
    let mut raw = Secret([0u8; 8]);
    ptr::copy_nonoverlapping(key.cast(), raw.0.as_mut_ptr(), 8);
    let value = u64::from_be_bytes(raw.0) & 0xfefefefefefefefe;
    let mut found = 0u64;
    for weak in WEAK {
        let difference = value ^ (weak & 0xfefefefefefefefe);
        found |= ((difference | difference.wrapping_neg()) >> 63) ^ 1;
    }
    found as c_int
}
