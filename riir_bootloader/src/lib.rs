//! # The SAFFRIIR System
//!
//! > _SAFFIRe but it's rewritten in Rust™_
//!
//! This is TAMU's submission for MITRE's 2022 Embedded System CTF (eCTF)!
//!
//! ## Building
//!
//! We **strongly** recommend you build with the provided [Docker image](../../dockerfiles/1_build_saffire.Dockerfile), following the [instructions](https://github.tamu.edu/mitre-ectf-2022/2022-ectf-insecure-example/blob/master/getting_started.md) provided by MITRE's [reference implementation](https://github.tamu.edu/mitre-ectf-2022/2022-ectf-insecure-example).
//!
//! ## Project Layout
//! The SAFFRIIR system is split into 3 main crates:
//! - [`riir_host_tools`]: Rust implementation of the host-tools.
//! - [`riir_bootloader`]: Rust implementation of the bootloader (you're already here).
//!   The entry point is in the [`bootloader`] crate.
//! - [`gen_eeprom`]: Rust tooling to generate an EEPROM image with pre-initialized secrets.
//!
//! ## Design
//! While the core functionality remains the same as the reference implementation, there are
//! two key differences:
//!
//! - It's written in Rust!
//! - It's (hopefully) secure!
//!
//! We chose to implement our design in Rust due to its core tenants of memory safety, performance,
//! and developer ergonomics. To remove dependencies on C code, we ported over the necessary
//! functionality from the provided TivaWare library, using the TM4C123GH6PM data sheet as a
//! reference.
//!
//! To harden the SAFFRIIR system's security, we implement the following tactics: 
//! ### Confidentiality
//! - Packages are transmitted and stored encrypted via [`crypto_secretstream`].
//! - Secrets in EEPROM are stored encrypted via [`chacha20poly1305`].
//! - We chose ChaCha20Poly1305 over other encryption schemes due to its built-in integrity
//!   checking via [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) and less prolific
//!   literature on power analysis attacks (compared to [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)).
//! ### Integrity
//! - To mitigate the flash trojan, the bootloader primarily runs in SRAM. A further discussion
//!   can be found in the documentation of the [`bootloader`] crate.
//! - Any flash writes are immediately followed by verification checks to ensure the `.text`
//!   section is not maliciously modified.
//! - Random jitter in execution delay is applied before critical checks to mitigate fault injection.
//! ### Authenticity
//! - Every host-tool that issues a bootloader command must authenticate itself before the
//!   bootloader proceeds with command execution. Signature production and verification is provided
//!   by the [`p256`] crate.
//! - All received packages contain signed hashes, which are verified against hardcoded public keys in
//!   EEPROM.
//! 
//! [`riir_host_tools`]: ../bootloader/index.html
//! [`gen_eeprom`]: ../gen_eeprom/index.html
//! [`riir_bootloader`]: ../riir_host_tools/index.html
//! [`bootloader`]: ../bootloader/index.html
#![no_std]

mod buffer;

pub mod crypto;
pub mod error;
pub mod handlers;
pub mod package;
pub mod peripherals;

use crate::error::Result;
use crate::peripherals::eeprom::{Primitive, Stage2Key, TextHash};
use crate::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

#[macro_export]
#[doc(hidden)]
macro_rules! size {
    ($($t:ty),*) => {
        $(core::mem::size_of::<$t>()+)* 0
    }
}

/// Computes the [`Blake2s256`] hash of the `.text` section, then compares it against the hash
/// stored in EEPROM. If the hashes mismatch, then the bootloader is deemed inoperable, so the second stage decryption key is zeroed to prevent further execution on subsequent power cycles.
///
/// [`Blake2s256`]: blake2::Blake2s256
#[link_section = ".data"]
pub fn verify_stage1(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    extern "C" {
        #[allow(improper_ctypes)]
        // This symbol is defined by the linker and denotes the start of the .text section.
        // The single underscore is intentional.
        static mut _stext: ();
        // This symbol is defined by the linker and denotes the end of the .text section.
        #[allow(improper_ctypes)]
        static mut __etext: ();
    }
    // SAFETY: The linker guarantees the presence and order of the above symbols.
    let text = unsafe {
        let start = core::ptr::addr_of!(_stext) as *const u8;
        let end = core::ptr::addr_of!(__etext) as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    };
    let s = p.eeprom.load_decrypted::<TextHash>()?;
    if crypto::verify_hash(text, &s.inner.hash, r).is_err() {
        let brick = Stage2Key::zeroed();
        brick.store(&p.eeprom)?;
        panic!("stage 1 was tampered with, so this is irrecoverable")
    } else {
        Ok(())
    }
}
