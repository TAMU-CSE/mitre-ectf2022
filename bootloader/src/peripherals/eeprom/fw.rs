use super::*;
use crate::{
    crypto::BlakeHash,
    package::{ENCRYPTED_FW, ENCRYPTED_MSG},
};

#[repr(C, align(4))]
/// EEPROM sector containing data for verifying the integrity of updated firmware. This is stored
/// _encrypted_.
#[derive(Clone, Copy, PartialEq)]
pub struct FwMeta {
    pub latest_version: u32,
    pub msg_hash: BlakeHash,
    pub msg_header: Header,
    pub msg_len: u32,
    pub fw_hash: BlakeHash,
    pub fw_header: Header,
    pub fw_len: u32,
}

impl FwMeta {
    pub(crate) fn encrypted_fw<'a>(&self) -> &'a [u8] {
        // SAFETY: We perform verification checks to obtain an instance of `FwMeta`, so
        // we trust the `fw_len` field to be accurate. The lifetime is unbounded because the
        // backing slice resides in flash (we only need the length).
        unsafe { core::slice::from_raw_parts(ENCRYPTED_FW as *const u8, self.fw_len as usize) }
    }
    pub(crate) fn encrypted_msg<'a>(&self) -> &'a [u8] {
        // SAFETY: We perform verification checks to obtain an instance of `FwMeta`, so
        // we trust the `msg_len` field to be accurate. The lifetime is unbounded because the
        // backing slice resides in flash (we only need the length).
        unsafe { core::slice::from_raw_parts(ENCRYPTED_MSG as *const u8, self.msg_len as usize) }
    }
}

impl_primitive!(
    FW_META_OFFSET,
    FwMeta,
    BlakeHash,
    Header,
    u32,
    BlakeHash,
    Header,
    u32,
    u32
);
