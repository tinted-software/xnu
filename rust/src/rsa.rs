//! Caller-owned public RSA keys and strict RFC 8017 signature verification.
//!
//! The public wrapper admits 4096-bit keys; chunklist keys are 2048 bits.
//! All supported sizes use stack-allocated RustCrypto integers. Public-exponent
//! square-and-multiply avoids the 16-integer window table used by the crate's
//! general exponentiation API, keeping scratch storage bounded on kernel stacks.

use core::{mem, ptr, slice};
use crypto_bigint::{
    modular::{FixedMontyForm, FixedMontyParams},
    Limb, Odd, Uint, Word,
};

const MAX_BYTES: usize = 4096 / 8;
// Values of the shared clean cc_abi.h error interface.
const PARAMETER: i32 = -7;
const INVALID_INPUT: i32 = -23;

#[repr(C)]
pub struct PublicKey {
    n: usize,
    modulus_nbytes: usize,
    exponent_nbytes: usize,
}

// DER DigestInfo prefixes, including the AlgorithmIdentifier's NULL parameter
// and the OCTET STRING's digest length (RFC 8017, section 9.2).
const MD5: &[u8] = b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10";
const SHA1: &[u8] = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
const SHA224: &[u8] =
    b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c";
const SHA256: &[u8] =
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
const SHA384: &[u8] =
    b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30";
const SHA512: &[u8] =
    b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";
const SHA512_256: &[u8] =
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00\x04\x20";
const DIGEST_INFOS: &[(&[u8], usize)] = &[
    (MD5, 16),
    (SHA1, 20),
    (SHA224, 28),
    (SHA256, 32),
    (SHA384, 48),
    (SHA512, 64),
    (SHA512_256, 32),
];

fn unsigned_bytes(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

fn valid_public_values(modulus: &[u8], exponent: &[u8]) -> bool {
    if modulus.is_empty() || exponent.is_empty() || modulus[0] == 0 || exponent[0] == 0 {
        return false;
    }
    if modulus[modulus.len() - 1] & 1 == 0 || exponent[exponent.len() - 1] & 1 == 0 {
        return false;
    }
    if exponent.len() == 1 && exponent[0] < 3 {
        return false;
    }
    exponent.len() < modulus.len() || (exponent.len() == modulus.len() && exponent < modulus)
}

unsafe fn capacity(key: *const PublicKey) -> Option<usize> {
    let n = ptr::addr_of!((*key).n).read_unaligned();
    if n == 0 || n > MAX_BYTES / mem::size_of::<usize>() {
        None
    } else {
        Some(n * mem::size_of::<usize>())
    }
}

/// Import an unsigned big-endian public key into the caller's allocation.
///
/// # Safety
/// `key` points to a rsa_abi.h context with n already set and enough storage
/// for its n-word capacity. Nonempty inputs point to readable byte arrays;
/// input arrays must not overlap the context header or each other’s output
/// buffers. No pointers are retained after the import.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_ccrsa_make_pub(
    key: *mut PublicKey,
    exponent_nbytes: usize,
    exponent: *const u8,
    modulus_nbytes: usize,
    modulus: *const u8,
) -> i32 {
    if key.is_null() {
        return PARAMETER;
    }
    // A failed import must not leave an earlier key usable.
    ptr::addr_of_mut!((*key).modulus_nbytes).write_unaligned(0);
    ptr::addr_of_mut!((*key).exponent_nbytes).write_unaligned(0);
    let Some(capacity) = capacity(key) else {
        return PARAMETER;
    };
    if exponent.is_null()
        || modulus.is_null()
        || exponent_nbytes == 0
        || modulus_nbytes == 0
        || exponent_nbytes > capacity
        || modulus_nbytes > capacity
    {
        return PARAMETER;
    }
    let exponent = unsigned_bytes(slice::from_raw_parts(exponent, exponent_nbytes));
    let modulus = unsigned_bytes(slice::from_raw_parts(modulus, modulus_nbytes));
    if !valid_public_values(modulus, exponent) {
        return PARAMETER;
    }
    let storage = key.cast::<u8>().add(mem::size_of::<PublicKey>());
    ptr::copy(modulus.as_ptr(), storage, modulus.len());
    ptr::copy(exponent.as_ptr(), storage.add(capacity), exponent.len());
    ptr::addr_of_mut!((*key).modulus_nbytes).write_unaligned(modulus.len());
    ptr::addr_of_mut!((*key).exponent_nbytes).write_unaligned(exponent.len());
    0
}

// The ABI provides a DER OID without an independent length. Read only its
// two-byte short-form header before recognizing the supported bounded lengths.
unsafe fn digest_info(oid: *const u8) -> Option<(&'static [u8], usize)> {
    if oid.read() != 0x06 {
        return None;
    }
    let length = oid.add(1).read() as usize;
    if length != 5 && length != 8 && length != 9 {
        return None;
    }
    let oid = slice::from_raw_parts(oid, length + 2);
    for &(prefix, digest_len) in DIGEST_INFOS {
        let end = 6 + prefix[5] as usize;
        if oid == &prefix[4..end] {
            return Some((prefix, digest_len));
        }
    }
    None
}

// Inputs have already been bounded to the selected integer's capacity. Decode
// into its words directly, rather than padding/copying a second byte array.
fn integer<const LIMBS: usize>(bytes: &[u8]) -> Uint<LIMBS> {
    let mut value = Uint::<LIMBS>::ZERO;
    let words = value.as_mut_words();
    for (offset, &byte) in bytes.iter().rev().enumerate() {
        words[offset / Limb::BYTES] |= (byte as Word) << (8 * (offset % Limb::BYTES));
    }
    value
}

fn big_endian_byte<const LIMBS: usize>(value: &Uint<LIMBS>, length: usize, offset: usize) -> u8 {
    let offset = length - 1 - offset;
    (value.as_words()[offset / Limb::BYTES] >> (8 * (offset % Limb::BYTES))) as u8
}

// Exponent bits and branching are public. Avoiding a general-purpose secret
// exponent window table saves kernel stack space and unnecessary work for 65537.
fn public_power<const LIMBS: usize>(
    signature: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
    exponent: &[u8],
) -> Result<Uint<LIMBS>, i32> {
    // The modulus is public, so the variable-time constructor is fine. An
    // even modulus is refused rather than assumed away.
    let odd = Option::<Odd<Uint<LIMBS>>>::from(Odd::new(*modulus)).ok_or(PARAMETER)?;
    let params = FixedMontyParams::new_vartime(odd);
    let base = FixedMontyForm::new(signature, &params);
    let mut result = base;
    let mut bit = (exponent.len() - 1) * 8 + 8 - exponent[0].leading_zeros() as usize - 1;
    while bit > 0 {
        bit -= 1;
        result = result.square();
        if (exponent[exponent.len() - 1 - bit / 8] >> (bit % 8)) & 1 != 0 {
            result = result.mul(&base);
        }
    }
    Ok(result.retrieve())
}

#[inline(never)]
fn verify<const LIMBS: usize>(
    modulus: &[u8],
    exponent: &[u8],
    signature: &[u8],
    prefix: &[u8],
    digest: &[u8],
) -> Result<bool, i32> {
    let n = integer::<LIMBS>(modulus);
    let signature = integer::<LIMBS>(signature);
    if signature >= n {
        return Err(INVALID_INPUT);
    }
    let encoded = public_power(&signature, &n, exponent)?;
    let length = modulus.len();
    let delimiter = length - prefix.len() - digest.len() - 1;
    // Check every encoded byte against exactly 00 01 FF...FF 00 DigestInfo.
    // The caller checked that the FF padding has at least eight bytes.
    let mut different = 0u8;
    for offset in 0..length {
        let expected = if offset == 0 {
            0
        } else if offset == 1 {
            1
        } else if offset < delimiter {
            0xff
        } else if offset == delimiter {
            0
        } else if offset - delimiter - 1 < prefix.len() {
            prefix[offset - delimiter - 1]
        } else {
            digest[offset - delimiter - 1 - prefix.len()]
        };
        different |= big_endian_byte(&encoded, length, offset) ^ expected;
    }
    Ok(different == 0)
}

/// Verify one complete EMSA-PKCS1-v1_5 encoded signature.
///
/// # Safety
/// `key` is a caller-owned context with its declared storage readable; `oid`
/// points to a complete DER OBJECT IDENTIFIER. Digest/signature byte arrays
/// are readable for their given lengths, and `valid` is writable for one bool.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_ccrsa_verify_pkcs1v15(
    key: *mut PublicKey,
    oid: *const u8,
    digest_nbytes: usize,
    digest: *const u8,
    signature_nbytes: usize,
    signature: *const u8,
    valid: *mut bool,
) -> i32 {
    if valid.is_null() {
        return PARAMETER;
    }
    valid.write(false);
    if key.is_null() || oid.is_null() || digest.is_null() || signature.is_null() {
        return PARAMETER;
    }
    let Some(capacity) = capacity(key) else {
        return PARAMETER;
    };
    let modulus_nbytes = ptr::addr_of!((*key).modulus_nbytes).read_unaligned();
    let exponent_nbytes = ptr::addr_of!((*key).exponent_nbytes).read_unaligned();
    if modulus_nbytes == 0
        || modulus_nbytes > capacity
        || exponent_nbytes == 0
        || exponent_nbytes > capacity
        || signature_nbytes != modulus_nbytes
    {
        return PARAMETER;
    }
    let Some((prefix, expected_digest_nbytes)) = digest_info(oid) else {
        return PARAMETER;
    };
    if digest_nbytes != expected_digest_nbytes {
        return PARAMETER;
    }
    // 00 01, at least eight FF bytes, delimiter 00, then the DigestInfo.
    if modulus_nbytes < prefix.len() + digest_nbytes + 11 {
        return PARAMETER;
    }
    let storage = key.cast::<u8>().add(mem::size_of::<PublicKey>());
    let modulus = slice::from_raw_parts(storage, modulus_nbytes);
    let exponent = slice::from_raw_parts(storage.add(capacity), exponent_nbytes);
    if !valid_public_values(modulus, exponent) {
        return PARAMETER;
    }
    let signature = slice::from_raw_parts(signature, signature_nbytes);
    let digest = slice::from_raw_parts(digest, digest_nbytes);
    // Select the smallest tier fitting the modulus, including nonstandard
    // bit lengths. LIMBS tracks the target word width, not the host's width.
    let result = match modulus_nbytes {
        1..=64 => {
            verify::<{ 512 / (Limb::BITS as usize) }>(modulus, exponent, signature, prefix, digest)
        }
        65..=128 => {
            verify::<{ 1024 / (Limb::BITS as usize) }>(modulus, exponent, signature, prefix, digest)
        }
        129..=256 => {
            verify::<{ 2048 / (Limb::BITS as usize) }>(modulus, exponent, signature, prefix, digest)
        }
        257..=384 => {
            verify::<{ 3072 / (Limb::BITS as usize) }>(modulus, exponent, signature, prefix, digest)
        }
        385..=512 => {
            verify::<{ 4096 / (Limb::BITS as usize) }>(modulus, exponent, signature, prefix, digest)
        }
        _ => return PARAMETER,
    };
    match result {
        Ok(matched) => {
            valid.write(matched);
            0
        }
        Err(error) => error,
    }
}

/// # Safety
/// Same caller-owned context and input contract as xnu_rc_ccrsa_make_pub.
#[no_mangle]
pub unsafe extern "C" fn ccrsa_make_pub(
    key: *mut PublicKey,
    exponent_nbytes: usize,
    exponent: *const u8,
    modulus_nbytes: usize,
    modulus: *const u8,
) -> i32 {
    xnu_rc_ccrsa_make_pub(key, exponent_nbytes, exponent, modulus_nbytes, modulus)
}

/// # Safety
/// Same context and byte-array contract as xnu_rc_ccrsa_verify_pkcs1v15.
#[no_mangle]
pub unsafe extern "C" fn ccrsa_verify_pkcs1v15(
    key: *mut PublicKey,
    oid: *const u8,
    digest_nbytes: usize,
    digest: *const u8,
    signature_nbytes: usize,
    signature: *const u8,
    valid: *mut bool,
) -> i32 {
    xnu_rc_ccrsa_verify_pkcs1v15(
        key,
        oid,
        digest_nbytes,
        digest,
        signature_nbytes,
        signature,
        valid,
    )
}
