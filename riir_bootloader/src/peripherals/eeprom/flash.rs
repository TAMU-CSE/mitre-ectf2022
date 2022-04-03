use super::*;
use crypto_secretstream::Key;

#[repr(C, align(4))]
/// EEPROM sector containing data for decrypting firmware, configuration, and release message
/// packages, which are all encrypted with [`crypto_secretstream`]. This is stored _encrypted_.
pub struct FlashKey {
    pub key: Key,
}

impl_primitive!(FLASH_KEY_OFFSET, FlashKey, Key);

impl PartialEq for FlashKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_ref() == other.key.as_ref()
    }
}
