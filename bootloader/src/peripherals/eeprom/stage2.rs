use super::*;
use chacha20poly1305::{Key, Tag, XNonce};

/// EEPROM sector containing data for decrypting stage 2 of the bootloader. This is stored
/// _unencrypted_.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct Stage2Key {
    pub key: Key,
    pub nonce: XNonce,
    pub tag: Tag,
}

impl_primitive!(STAGE2_KEY_OFFSET, Stage2Key, Key, Tag, XNonce);
