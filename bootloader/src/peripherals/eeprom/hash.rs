use super::*;
use crate::crypto::BlakeHash;

/// EEPROM sector containing the hash of the `.text` section.
#[derive(PartialEq, Clone, Copy)]
#[repr(C, align(4))]
pub struct TextHash {
    pub hash: BlakeHash,
}

impl_primitive!(TEXT_HASH_OFFSET, TextHash, BlakeHash);
