// SPDX-License-Identifier: MIT OR Apache-2.0
//! HMAC-SHA256 DRBGs for kernel runtime and caller-serialized kmem contexts.
//! The master is seeded from boot entropy; independent CPU streams absorb every
//! master reseed before their next request. SHA-256 uses RustCrypto's scalar
//! backend. No allocation, vector registers, or proprietary crypto dependency.

use crate::ptrauth::{self, Mutable};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sha2::{Digest, Sha256};

const MAX_GENERATORS: usize = 256;
const MAX_REQUEST: usize = 256;
const DRBG_MAX_REQUEST: usize = 65_536;
const RESEED_INTERVAL: u64 = 1 << 48;
const PARAMETER_ERROR: i32 = -7;

type GetEntropy = Option<unsafe extern "C" fn(*mut usize, *mut c_void, *mut c_void) -> i32>;

extern "C" {
    fn read_random(out: *mut c_void, nbytes: u32);
    fn ml_set_interrupts_enabled(enable: i32) -> i32;
    fn ml_get_interrupts_enabled() -> i32;
}

fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

struct Secret<const N: usize>([u8; N]);
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

// RFC 2104 with a fixed 256-bit key. Feed the seed components separately so
// instantiation/reseeding never allocates or concatenates secret input.
fn hmac_sha256(
    key: &[u8; 32],
    prefix: &[u8],
    separator: Option<u8>,
    parts: &[&[u8]],
    out: &mut [u8; 32],
) {
    let mut pad = Secret([0x36u8; 64]);
    for (dst, src) in pad.0.iter_mut().zip(key) {
        *dst ^= src;
    }
    let mut inner = Sha256::new();
    inner.update(&pad.0);
    inner.update(prefix);
    if let Some(separator) = separator {
        inner.update([separator]);
    }
    for part in parts {
        inner.update(part);
    }
    let mut digest = inner.finalize();
    for byte in &mut pad.0 {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(&pad.0);
    outer.update(&digest);
    let mut result = outer.finalize();
    out.copy_from_slice(&result);
    erase(&mut digest);
    erase(&mut result);
}

// Layout shared with osfmk/prng/hmac_drbg.h; counter zero means uninitialized.
#[repr(C)]
struct HmacDrbg {
    key: [u8; 32],
    v: [u8; 32],
    reseed_counter: u64,
}

impl HmacDrbg {
    const EMPTY: Self = Self {
        key: [0; 32],
        v: [1; 32],
        reseed_counter: 0,
    };

    fn update(&mut self, parts: &[&[u8]]) {
        let mut next = Secret([0u8; 32]);
        hmac_sha256(&self.key, &self.v, Some(0), parts, &mut next.0);
        self.key.copy_from_slice(&next.0);
        hmac_sha256(&self.key, &self.v, None, &[], &mut next.0);
        self.v.copy_from_slice(&next.0);
        if parts.iter().any(|part| !part.is_empty()) {
            hmac_sha256(&self.key, &self.v, Some(1), parts, &mut next.0);
            self.key.copy_from_slice(&next.0);
            hmac_sha256(&self.key, &self.v, None, &[], &mut next.0);
            self.v.copy_from_slice(&next.0);
        }
    }

    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) {
        assert!(
            entropy.len() >= 32,
            "RNG instantiation requires 256-bit seed material"
        );
        self.key.fill(0);
        self.v.fill(1);
        self.update(&[entropy, nonce, personalization]);
        self.reseed_counter = 1;
    }

    fn reseed(&mut self, parts: &[&[u8]]) {
        assert!(self.reseed_counter != 0, "RNG reseed before initialization");
        self.update(parts);
        self.reseed_counter = 1;
    }

    fn generate(&mut self, out: &mut [u8]) {
        assert!(
            out.len() <= DRBG_MAX_REQUEST,
            "RNG request exceeds SP 800-90A limit"
        );
        assert!(
            self.reseed_counter != 0 && self.reseed_counter <= RESEED_INTERVAL,
            "RNG requires reseeding"
        );
        let mut next = Secret([0u8; 32]);
        for chunk in out.chunks_mut(32) {
            hmac_sha256(&self.key, &self.v, None, &[], &mut next.0);
            self.v.copy_from_slice(&next.0);
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        self.update(&[]);
        self.reseed_counter += 1;
    }
}

unsafe fn input<'a>(data: *const c_void, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        assert!(
            !data.is_null() && len <= isize::MAX as usize,
            "Invalid RNG input buffer"
        );
        core::slice::from_raw_parts(data.cast(), len)
    }
}

unsafe fn output<'a>(data: *mut c_void, len: usize) -> &'a mut [u8] {
    if len == 0 {
        &mut []
    } else {
        assert!(
            !data.is_null() && len <= isize::MAX as usize,
            "Invalid RNG output buffer"
        );
        core::slice::from_raw_parts_mut(data.cast(), len)
    }
}

#[no_mangle]
pub unsafe extern "C" fn xnu_rc_hmac_drbg_instantiate(
    state: *mut c_void,
    entropy: *const c_void,
    entropy_len: usize,
    nonce: *const c_void,
    nonce_len: usize,
    personalization: *const c_void,
    personalization_len: usize,
) {
    assert!(!state.is_null());
    // The caller supplies uninitialized storage, so initialize before forming
    // a mutable reference to the state.
    let state = state.cast::<HmacDrbg>();
    ptr::write(state, HmacDrbg::EMPTY);
    (*state).instantiate(
        input(entropy, entropy_len),
        input(nonce, nonce_len),
        input(personalization, personalization_len),
    );
}

#[no_mangle]
pub unsafe extern "C" fn xnu_rc_hmac_drbg_generate(
    state: *mut c_void,
    out: *mut c_void,
    nbytes: usize,
) {
    assert!(!state.is_null());
    (*state.cast::<HmacDrbg>()).generate(output(out, nbytes));
}

#[no_mangle]
pub unsafe extern "C" fn xnu_rc_hmac_drbg_reseed(
    state: *mut c_void,
    seed: *const c_void,
    seed_len: usize,
) {
    assert!(
        !state.is_null() && seed_len >= 32,
        "Invalid early RNG reseed"
    );
    (*state.cast::<HmacDrbg>()).reseed(&[input(seed, seed_len)]);
}

// Raw IRQ masking protects only the early DRBG, before GSBASE/current_thread
// and scheduler services exist. Never enable an IRQ that was masked on entry.
// Runtime guards use the machine routines instead, preserving kernel AST and
// interrupt-disable debug bookkeeping once those services are initialized.
fn disable_irqs() -> usize {
    let state: usize;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("pushfq", "pop {state}", "cli", state = out(reg) state);
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("mrs {state}, daif", "msr daifset, #3", state = out(reg) state,
            options(nostack));
    }
    state
}

fn restore_irqs(state: usize) {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        if state & (1 << 9) != 0 {
            core::arch::asm!("sti", options(nostack));
        }
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("msr daif, {state}", state = in(reg) state, options(nostack));
    }
}

struct IrqSpin<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}
// All accesses to value, including the opaque callback argument, are under
// the IRQ-safe lock. No reference to value escapes a guard.
unsafe impl<T> Sync for IrqSpin<T> {}

impl<T> IrqSpin<T> {
    const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) -> Guard<'_, T> {
        let irq_state = unsafe { ml_set_interrupts_enabled(0) };
        acquire(&self.held);
        Guard {
            lock: self,
            irq_state,
        }
    }
}

fn acquire(lock: &AtomicBool) {
    while lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while lock.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    }
}

struct Guard<'a, T> {
    lock: &'a IrqSpin<T>,
    irq_state: i32,
}
impl<T> core::ops::Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.value.get() }
    }
}
impl<T> core::ops::DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.value.get() }
    }
}
impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
        unsafe { ml_set_interrupts_enabled(self.irq_state) };
    }
}

static EARLY_LOCK: AtomicBool = AtomicBool::new(false);
#[no_mangle]
pub extern "C" fn xnu_rc_rng_early_lock() -> usize {
    let irq_state = disable_irqs();
    acquire(&EARLY_LOCK);
    irq_state
}
#[no_mangle]
pub extern "C" fn xnu_rc_rng_early_unlock(irq_state: usize) {
    EARLY_LOCK.store(false, Ordering::Release);
    restore_irqs(irq_state);
}

struct Master {
    drbg: HmacDrbg,
    max_ngens: u32,
    getentropy: GetEntropy,
    getentropy_arg: *mut c_void,
}
struct Generator {
    drbg: HmacDrbg,
    epoch: u64,
}
struct KernelRng {
    master: IrqSpin<Master>,
    epoch: AtomicU64,
    refreshing: AtomicBool,
    generators: [IrqSpin<Generator>; MAX_GENERATORS],
}
static KERNEL_RNG: KernelRng = KernelRng {
    master: IrqSpin::new(Master {
        drbg: HmacDrbg::EMPTY,
        max_ngens: 0,
        getentropy: None,
        getentropy_arg: ptr::null_mut(),
    }),
    epoch: AtomicU64::new(0),
    refreshing: AtomicBool::new(false),
    generators: [const {
        IrqSpin::new(Generator {
            drbg: HmacDrbg::EMPTY,
            epoch: 0,
        })
    }; MAX_GENERATORS],
};

unsafe fn kernel_rng<'a>(ctx: *mut c_void) -> &'a KernelRng {
    assert!(!ctx.is_null(), "Missing runtime RNG context");
    &*ctx.cast::<KernelRng>()
}

#[no_mangle]
pub extern "C" fn xnu_rc_kprng_context() -> *mut c_void {
    (&KERNEL_RNG as *const KernelRng).cast_mut().cast()
}

#[no_mangle]
pub unsafe extern "C" fn cckprng_init(
    ctx: *mut c_void,
    seed_len: usize,
    seed: *const c_void,
    nonce_len: usize,
    nonce: *const c_void,
    getentropy: GetEntropy,
    getentropy_arg: *mut c_void,
) {
    cckprng_init_with_getentropy(
        ctx,
        MAX_GENERATORS as u32,
        seed_len,
        seed,
        nonce_len,
        nonce,
        getentropy,
        getentropy_arg,
    );
}

#[no_mangle]
pub unsafe extern "C" fn cckprng_init_with_getentropy(
    ctx: *mut c_void,
    max_ngens: u32,
    seed_len: usize,
    seed: *const c_void,
    nonce_len: usize,
    nonce: *const c_void,
    getentropy: GetEntropy,
    getentropy_arg: *mut c_void,
) {
    assert!(
        max_ngens != 0 && max_ngens as usize <= MAX_GENERATORS,
        "Unsupported runtime RNG CPU count"
    );
    let rng = kernel_rng(ctx);
    let mut master = rng.master.lock();
    assert!(
        master.drbg.reseed_counter == 0,
        "Runtime RNG initialized twice"
    );
    master.drbg.instantiate(
        input(seed, seed_len),
        input(nonce, nonce_len),
        b"xnu runtime master",
    );
    master.max_ngens = max_ngens;
    master.getentropy = getentropy;
    master.getentropy_arg = getentropy_arg;
    rng.epoch.store(1, Ordering::Release);
}

// Lock ordering is always generator -> master. A reseed holds only master;
// generation on already-current CPU streams does not touch the master lock.
fn seed_generator(rng: &KernelRng, generator: &mut Generator, index: u32, initialize: bool) {
    let mut master = rng.master.lock();
    assert!(
        index < master.max_ngens,
        "Runtime RNG CPU index out of range"
    );
    let mut seed = Secret([0u8; 32]);
    master.drbg.generate(&mut seed.0);
    let epoch = rng.epoch.load(Ordering::Relaxed);
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&index.to_le_bytes());
    nonce[4..].copy_from_slice(&epoch.to_le_bytes());
    if initialize {
        generator
            .drbg
            .instantiate(&seed.0, &nonce, b"xnu runtime cpu");
    } else {
        generator.drbg.reseed(&[&seed.0, &nonce]);
    }
    generator.epoch = epoch;
}

#[no_mangle]
pub unsafe extern "C" fn cckprng_initgen(ctx: *mut c_void, index: u32) {
    let rng = kernel_rng(ctx);
    assert!(
        (index as usize) < MAX_GENERATORS,
        "Runtime RNG CPU index out of range"
    );
    let mut generator = rng.generators[index as usize].lock();
    // CPU hotplug/resume may initialize the same CPU again. Give it a fresh
    // stream rather than reusing a previously exposed generator state.
    seed_generator(rng, &mut generator, index, true);
}

#[no_mangle]
pub unsafe extern "C" fn cckprng_reseed(ctx: *mut c_void, seed_len: usize, seed: *const c_void) {
    let rng = kernel_rng(ctx);
    assert!(seed_len >= 16, "Runtime RNG reseed input is too short");
    let seed = input(seed, seed_len);
    let mut master = rng.master.lock();
    let epoch = rng.epoch.load(Ordering::Relaxed);
    assert!(
        epoch != 0 && epoch != u64::MAX,
        "Runtime RNG reseed sequence exhausted"
    );
    master
        .drbg
        .reseed(&[seed, b"xnu runtime reseed", &epoch.to_le_bytes()]);
    rng.epoch.store(epoch + 1, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn cckprng_refresh(ctx: *mut c_void) {
    let rng = kernel_rng(ctx);
    // entropy_provide uses a kernel mutex and per-CPU storage. Never invoke
    // it under the IRQ-safe generator/master locks or from IRQ context.
    if ml_get_interrupts_enabled() == 0
        || rng
            .refreshing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let (callback, arg) = {
        let master = rng.master.lock();
        (master.getentropy, master.getentropy_arg)
    };
    if let Some(callback) = callback.map(ptrauth::auth) {
        let mut seed = Secret([0u8; 64]);
        let mut len = seed.0.len();
        let samples = callback(&mut len, seed.0.as_mut_ptr().cast(), arg);
        if samples < 0 {
            erase(&mut seed.0);
            panic!("Kernel entropy source failed its health tests");
        }
        assert!(
            len <= seed.0.len(),
            "Kernel entropy source exceeded buffer capacity"
        );
        if samples > 0 {
            assert!(
                len >= 32,
                "Kernel entropy source returned insufficient seed material"
            );
            cckprng_reseed(ctx, len, seed.0.as_ptr().cast());
        }
    }
    rng.refreshing.store(false, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn cckprng_generate(
    ctx: *mut c_void,
    index: u32,
    nbytes: usize,
    out: *mut c_void,
) {
    assert!(
        nbytes <= MAX_REQUEST,
        "Runtime RNG request exceeds callback limit"
    );
    let rng = kernel_rng(ctx);
    assert!(
        (index as usize) < MAX_GENERATORS,
        "Runtime RNG CPU index out of range"
    );
    let mut generator = rng.generators[index as usize].lock();
    assert!(
        generator.drbg.reseed_counter != 0,
        "Runtime RNG CPU stream is uninitialized"
    );
    if generator.epoch != rng.epoch.load(Ordering::Acquire) {
        seed_generator(rng, &mut generator, index, false);
    }
    generator.drbg.generate(output(out, nbytes));
}

#[repr(C)]
pub struct CcrngState {
    generate: unsafe extern "C" fn(*mut CcrngState, usize, *mut c_void) -> i32,
}
static DEFAULT_RNG: Mutable<CcrngState> = Mutable::new(CcrngState {
    generate: default_generate,
});

/// Signs this module's tables for C (see `ptrauth`).
pub(crate) fn sign_tables() {
    // SAFETY: called once from `ensure_tables_signed`, before C sees the table.
    unsafe {
        let rng = &mut *DEFAULT_RNG.get();
        rng.generate = ptrauth::sign(rng.generate);
    }
}

unsafe extern "C" fn default_generate(
    rng: *mut CcrngState,
    nbytes: usize,
    out: *mut c_void,
) -> i32 {
    if rng.is_null() || (nbytes != 0 && out.is_null()) || nbytes > isize::MAX as usize {
        return PARAMETER_ERROR;
    }
    xnu_rc_rng_generate(ptr::null_mut(), out, nbytes);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ccrng(error: *mut i32) -> *mut CcrngState {
    if !error.is_null() {
        ptr::write(error, 0);
    }
    crate::ensure_tables_signed();
    DEFAULT_RNG.get()
}

#[no_mangle]
pub unsafe extern "C" fn ccrng_uniform(rng: *mut CcrngState, bound: u64, out: *mut u64) -> i32 {
    if rng.is_null() || out.is_null() || bound == 0 {
        return PARAMETER_ERROR;
    }
    if bound == 1 {
        ptr::write(out, 0);
        return 0;
    }
    // Reject the short residue interval so reduction modulo bound is unbiased,
    // including when bound is near UINT64_MAX or a power of two.
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut bytes = [0u8; 8];
        let error = (ptrauth::auth((*rng).generate))(rng, bytes.len(), bytes.as_mut_ptr().cast());
        if error != 0 {
            return error;
        }
        let value = u64::from_ne_bytes(bytes);
        if value >= threshold {
            ptr::write(out, value % bound);
            return 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn xnu_rc_rng_generate(ctx: *mut c_void, out: *mut c_void, nbytes: usize) {
    let bytes = output(out, nbytes);
    if ctx.is_null() {
        // read_random performs refresh plus bounded per-CPU generation. It also
        // ensures the runtime is installed; this never uses the early DRBG as
        // a permanent runtime substitute.
        for chunk in bytes.chunks_mut(u32::MAX as usize) {
            read_random(chunk.as_mut_ptr().cast(), chunk.len() as u32);
        }
    } else {
        let state = &mut *ctx.cast::<HmacDrbg>();
        for chunk in bytes.chunks_mut(DRBG_MAX_REQUEST) {
            state.generate(chunk);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn xnu_rc_rng_uniform(ctx: *mut c_void, bound: u64, out: *mut u64) {
    assert!(
        bound != 0 && !out.is_null(),
        "Invalid uniform RNG bound/output"
    );
    if bound == 1 {
        ptr::write(out, 0);
        return;
    }
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut bytes = [0u8; 8];
        xnu_rc_rng_generate(ctx, bytes.as_mut_ptr().cast(), bytes.len());
        let value = u64::from_ne_bytes(bytes);
        if value >= threshold {
            ptr::write(out, value % bound);
            return;
        }
    }
}

#[no_mangle]
pub extern "C" fn xnu_rc_rng_ctx_size() -> usize {
    core::mem::size_of::<HmacDrbg>()
}

#[no_mangle]
pub unsafe extern "C" fn xnu_rc_rng_ctx_init(ctx: *mut c_void) {
    assert!(!ctx.is_null(), "Missing kmem RNG context");
    let mut seed = Secret([0u8; 32]);
    read_random(seed.0.as_mut_ptr().cast(), seed.0.len() as u32);
    let nonce = (ctx as usize as u64).to_le_bytes();
    let state = ctx.cast::<HmacDrbg>();
    ptr::write(state, HmacDrbg::EMPTY);
    (*state).instantiate(&seed.0, &nonce, b"xnu kmem random");
}
