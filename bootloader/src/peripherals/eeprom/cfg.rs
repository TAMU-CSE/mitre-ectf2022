use super::*;
use crate::crypto::BlakeHash;
use crate::package::ENCRYPTED_CFG;
use chacha20poly1305::{Tag, XNonce};
use crypto_secretstream::Header;
use static_assertions::const_assert_eq;

/// EEPROM sector containing data for verifying the integrity of updated configurations.
#[repr(C, align(4))]
#[derive(Clone, Copy, PartialEq)]
pub struct CfgMeta {
    pub hash: BlakeHash,
    pub header: Header,
    pub len: u32,
}

impl CfgMeta {
    pub(crate) fn encrypted_cfg<'a>(&self) -> &'a [u8] {
        // SAFETY: We perform verification checks to obtain an instance of `CfgMeta`, so
        // we trust the `len` field to be accurate. The lifetime is unbounded because the
        // backing slice resides in flash (we only need the length).
        unsafe { core::slice::from_raw_parts(ENCRYPTED_CFG as *const u8, self.len as usize) }
    }
}
impl_primitive!(CFG_META_OFFSET, CfgMeta, BlakeHash, Header, u32);
