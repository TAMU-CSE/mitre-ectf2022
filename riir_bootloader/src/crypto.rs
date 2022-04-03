//! Contains various utilities for preserving confidentiality and integrity of bootloader data.

use crate::buffer::{CRYPTO_META_LEN, MAX_CIPHERTEXT_CHUNK_LEN};
use crate::error::{Error, Result};
use crate::peripherals::Flash;
use blake2::{
    digest::{consts::U32, generic_array::GenericArray},
    Blake2s256, Digest,
};
use chacha20poly1305::{
    aead::{AeadInPlace, NewAead},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
use rand_chacha::{rand_core::RngCore, ChaChaRng};

/// A [`Blake2s256`] digest.
pub type BlakeHash = GenericArray<u8, U32>;

/// Computes the [`Blake2s256`] hash of `data` and compares it against the provided hash. If there
/// is a mismatch, this will return [`Error::InvalidHash`].
#[link_section = ".data"]
pub fn verify_hash(data: &[u8], hash: &BlakeHash, r: &mut ChaChaRng) -> Result<()> {
    let rhs = oneshot_hash(data);
    jitter(r);
    if hash != &rhs {
        Err(Error::InvalidHash)
    } else {
        Ok(())
    }
}

/// Computes a [`Blake2s256`] digest.
#[link_section = ".data"]
pub fn oneshot_hash(data: &[u8]) -> BlakeHash {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Encrypts using [`XChaCha20Poly1305`].
///
/// # Implementation Note
/// This is _not_ in the data section because this is used to decrypt the second stage.
pub fn oneshot_decrypt(data: &mut [u8], key: &Key, tag: &Tag, nonce: &XNonce) -> Result<()> {
    XChaCha20Poly1305::new(key)
        .decrypt_in_place_detached(nonce, b"", data, tag)
        .map_err(|_| Error::DecryptionFailure)
}

/// Decrypts using [`XChaCha20Poly1305`].
#[link_section = ".data"]
pub fn oneshot_encrypt(data: &mut [u8], key: &Key, nonce: &XNonce) -> Result<Tag> {
    XChaCha20Poly1305::new(key)
        .encrypt_in_place_detached(nonce, b"", data)
        .map_err(|_| Error::EncryptionFailure)
}

/// Converts ciphertext length to plaintext length. This will return [`Error::InvalidLen`] if
/// the last chunk is too small.
#[link_section = ".data"]
pub fn ciphertext_to_plaintext_len(n: usize) -> Result<usize> {
    let q = n / MAX_CIPHERTEXT_CHUNK_LEN;
    let r = n % MAX_CIPHERTEXT_CHUNK_LEN;
    let full_pages = q * Flash::PAGE_SIZE;
    let last_page = if r != 0 {
        r.checked_sub(CRYPTO_META_LEN).ok_or(Error::InvalidLen)?
    } else {
        0
    };
    Ok(full_pages + last_page)
}

/// Delays for at least the provided number of cycles. 
///
/// # Implementation Note
/// This is lifted from [`cortex-m`]. This is a terrible hack to get around linking errors with
/// [`gen_eeprom`](../gen_eeprom/index.html) (`__delay` is an unresolved symbol).
#[inline]
#[link_section = ".data"]
#[allow(unused_variables)]
pub(crate) fn delay(cycles: u32) {
    // The loop will normally take 3 to 4 CPU cycles per iteration, but superscalar cores
    // (eg. Cortex-M7) can potentially do it in 2, so we use that as the lower bound, since delaying
    // for more cycles is okay.
    // Add 1 to prevent an integer underflow which would cause a long freeze
    // NOTE: We only build for the embedded target to avoid inline asm warnings.
    #[cfg(target_os = "unknown")]
    {
        let real_cycles = 1 + cycles / 2;
        unsafe {
            core::arch::asm!(
                // Use local labels to avoid R_ARM_THM_JUMP8 relocations which fail on thumbv6m.
                "1:",
                "subs {}, #1",
                "bne 1b",
                inout(reg) real_cycles => _,
                options(nomem, nostack),
            )
        };
    }
}

/// Delays for a random number of cycles.
#[link_section = ".data"]
pub fn jitter(rng: &mut ChaChaRng) {
    delay(rng.next_u32() & 0xFF);
}
