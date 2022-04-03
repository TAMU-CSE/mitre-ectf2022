use super::{Eeprom, Primitive};
use crate::crypto::{oneshot_decrypt, oneshot_encrypt};
use crate::error::Result;
use chacha20poly1305::{Key, Tag, XNonce};
use rand_chacha::{rand_core::RngCore, ChaChaRng};

#[repr(C, align(4))]
/// Wrapper to encrypt the inner type in EEPROM.
pub struct Encrypted<T: Primitive> {
    pub inner: T,
    pub tag: Tag,
    pub nonce: XNonce,
}

/// [`chacha20poly1305`] symmetric key to decrypt EEPROM sectors. This is stored encrypted (and
/// thus, unusable) until the first stage decrypts the `.data` section.
#[cfg(feature = "production")]
#[link_section = ".data"]
pub static EEPROM_KEY: [u8; 32] = *include_bytes!("/secrets/eeprom-symmetric.key");
#[cfg(not(feature = "production"))]
#[link_section = ".data"]
pub static EEPROM_KEY: [u8; 32] = *include_bytes!("../../../../secrets/eeprom-symmetric.key");

impl<T: Primitive> Encrypted<T> {
    /// Decrypts the inner type from EEPROM.
    pub fn load_decrypted(eeprom: &Eeprom) -> Result<Self> {
        let mut this = <Self as Primitive>::load(eeprom)?;
        let Self { inner, tag, nonce } = &mut this;
        let key = Key::from_slice(&EEPROM_KEY);

        oneshot_decrypt(inner.as_bytes_mut(), key, tag, nonce)?;
        Ok(this)
    }

    /// Encrypts the inner type, then stores it in EEPROM at the provided offset.
    #[link_section = ".data"]
    pub fn store_encrypted_raw(
        &mut self,
        eeprom: &Eeprom,
        rng: &mut ChaChaRng,
        offset: usize,
    ) -> Result<()> {
        let Self { inner, tag, nonce } = self;

        rng.fill_bytes(nonce);
        let key = Key::from_slice(&EEPROM_KEY);
        *tag = oneshot_encrypt(inner.as_bytes_mut(), key, nonce)?;

        <Self as Primitive>::store_raw(self, eeprom, offset)?;

        Ok(())
    }
    /// Encrypts the inner type, then stores it in EEPROM.
    #[link_section = ".data"]
    pub fn store_encrypted(&mut self, eeprom: &Eeprom, rng: &mut ChaChaRng) -> Result<()> {
        self.store_encrypted_raw(eeprom, rng, T::OFFSET)
    }
}

/// SAFETY: Invariants are upheld by implementors.
unsafe impl<T: Primitive> Primitive for Encrypted<T> {
    const OFFSET: usize = T::OFFSET;
}
