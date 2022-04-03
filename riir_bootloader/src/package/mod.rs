//! Utilities and types for securely receiving packages.

use crate::buffer::{Buffer, MAX_CIPHERTEXT_CHUNK_LEN};
use crate::crypto::{ciphertext_to_plaintext_len, verify_hash, BlakeHash};
use crate::error::Result;
use crate::peripherals::uart::FRAME_OK;
use crate::peripherals::{Flash, Peripherals};
use blake2::{Blake2s256, Digest};
use crypto_secretstream::PullStream;
use rand_chacha::ChaChaRng;
use static_assertions::{const_assert, const_assert_eq};

mod common;

pub use common::{Hashes, DynCompMeta, authenticate};
/// Maximum encrypted firmware image length.
pub const MAX_ENCRYPTED_FW_LEN: usize = MAX_CIPHERTEXT_CHUNK_LEN * 16;
/// Maximum encrypted config image length.
pub const MAX_ENCRYPTED_CFG_LEN: usize = MAX_CIPHERTEXT_CHUNK_LEN * 64;
/// Maximum encrypted release message length.
pub const MAX_ENCRYPTED_MSG_LEN: usize = MAX_CIPHERTEXT_CHUNK_LEN;
/// Maximum decrypted firmware image length.
pub const MAX_DECRYPTED_FW_LEN: usize = Flash::PAGE_SIZE * 16;

/// Rounds up to the nearest page.
const fn roundup_page(n: usize) -> usize {
    let r = n % Flash::PAGE_SIZE;
    if r == 0 {
        n
    } else {
        n + Flash::PAGE_SIZE - r
    }
}

/// Offset of encrypted firmware in flash.
pub const ENCRYPTED_FW: usize = 0x0001_9000;
/// Offset of encrypted release message in flash.
pub const ENCRYPTED_MSG: usize = roundup_page(ENCRYPTED_FW + MAX_ENCRYPTED_FW_LEN);
/// Offset of encrypted config in flash.
pub const ENCRYPTED_CFG: usize = roundup_page(ENCRYPTED_MSG + MAX_ENCRYPTED_MSG_LEN);

/// Offset of decrypted firmware in SRAM.
pub const FW_TARGET: usize = 0x2000_4000;
/// Offset of decrypted config in flash.
pub const CFG_TARGET: usize = 0x0003_0000;

const_assert_eq!(FW_TARGET, 0x2000_4000);
const_assert_eq!(CFG_TARGET, 0x0003_0000);

const_assert!(ENCRYPTED_FW + MAX_ENCRYPTED_FW_LEN <= ENCRYPTED_MSG);
const_assert!(ENCRYPTED_MSG + MAX_ENCRYPTED_MSG_LEN <= ENCRYPTED_CFG);
const_assert!(ENCRYPTED_CFG + MAX_ENCRYPTED_CFG_LEN <= CFG_TARGET);

const_assert_eq!(ENCRYPTED_FW % Flash::PAGE_SIZE, 0);
const_assert_eq!(ENCRYPTED_MSG % Flash::PAGE_SIZE, 0);
const_assert_eq!(ENCRYPTED_CFG % Flash::PAGE_SIZE, 0);
const_assert_eq!(CFG_TARGET % Flash::PAGE_SIZE, 0);

/// Decrypts the provided ciphertext, incrementally flashing it to the specified flash offset.
#[link_section = ".data"]
pub fn decrypt_to_flash<'a>(
    p: &mut Peripherals,
    data: &[u8],
    pull: &mut PullStream,
    out: usize,
) -> Result<&'a [u8]> {
    let mut buf = Buffer::new();
    let mut flash_offset = out;
    for chunk in data.chunks(MAX_CIPHERTEXT_CHUNK_LEN) {
        buf.clear();
        buf.extend_from_slice(chunk)?;
        pull.pull(&mut buf, b"")?;
        p.flash.erase_page(flash_offset)?;
        let words = buf.padded_flash_words()?;
        p.flash.write_words(words, flash_offset)?;
        flash_offset += Flash::PAGE_SIZE as usize;
    }
    let plaintext_len = ciphertext_to_plaintext_len(data.len())?;
    // SAFETY: We successfully wrote the plaintext to flash.
    Ok(unsafe { core::slice::from_raw_parts(out as *const u8, plaintext_len) })
}

/// Decrypts an encrypted image stored on flash and writes the plaintext to a specified region in SRAM.
#[link_section = ".data"]
pub fn decrypt_to_sram<'a>(
    data: &[u8],
    pull: &mut PullStream,
    out: usize,
) -> Result<&'a [u8]> {
    let mut buf = Buffer::new();
    let out = out as *mut u8;
    let mut sram_offset = out;
    for chunk in data.chunks(MAX_CIPHERTEXT_CHUNK_LEN) {
        buf.clear();
        buf.extend_from_slice(chunk)?;
        pull.pull(&mut buf, b"")?;
        // SAFETY: 
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), sram_offset, buf.len());
            sram_offset = sram_offset.add(Flash::PAGE_SIZE as usize);
        }
    }

    let plaintext_len = ciphertext_to_plaintext_len(data.len())?;
    // SAFETY: We successfully wrote the plaintext to SRAM.
    Ok(unsafe { core::slice::from_raw_parts(out, plaintext_len) })
}

/// Decrypts and hashes simultaneously.
#[link_section = ".data"]
pub fn decrypt_hash(data: &[u8], pull: &mut PullStream) -> Result<BlakeHash> {
    let mut buf = Buffer::new();
    let mut hasher = Blake2s256::new();
    for chunk in data.chunks(MAX_CIPHERTEXT_CHUNK_LEN) {
        buf.clear();
        buf.extend_from_slice(chunk)?;
        pull.pull(&mut buf, b"")?;
        hasher.update(&*buf);
    }
    Ok(hasher.finalize())
}

/// Simultaneously decrypts, hashes, and sends the release message back to host-tools.
#[link_section = ".data"]
pub fn decrypt_and_send_rel_msg(
    p: &mut Peripherals,
    r: &mut ChaChaRng,
    data: &[u8],
    pull: &mut PullStream,
    hash: &BlakeHash,
) -> Result<()> {
    let mut buf = Buffer::new();
    buf.clear();
    buf.extend_from_slice(data)?;
    pull.pull(&mut buf, b"")?;
    verify_hash(&*buf, hash, r)?;
    p.uart.write_u8(FRAME_OK);
    p.uart.write_all(&buf.len().to_be_bytes());
    p.uart.write_all(&*buf);
    Ok(())
}
