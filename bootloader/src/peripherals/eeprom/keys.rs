use super::*;
use p256::ecdsa::VerifyingKey;

/// [`SEC1_PUBLIC_KEY_LEN`], but rounded up to the next multiple of 4 to ensure alignment in EEPROM
/// memory.
pub const PADDED_PUBLIC_KEY_LEN: usize = 68;
/// The actual length of an encoded [`VerifyingKey`].
pub const SEC1_PUBLIC_KEY_LEN: usize = 65;

/// Wrapper around privileged [`VerifyingKey`]. Used for package verification and readback.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct PrivilegedKey {
    pub raw_key: [u8; PADDED_PUBLIC_KEY_LEN],
}

/// Converts padded public key from EEPROM into a [`VerifyingKey`].
#[link_section = ".data"]
fn expand_key(bytes: &[u8; PADDED_PUBLIC_KEY_LEN]) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(&bytes[..SEC1_PUBLIC_KEY_LEN]).map_err(|e| e.into())
}

impl PrivilegedKey {
    #[link_section = ".data"]
    #[inline(always)]
    pub(crate) fn key(&self) -> Result<VerifyingKey> {
        expand_key(&self.raw_key)
    }
}

/// Wrapper around unprivileged [`VerifyingKey`]. Used for host-tools authentication and
/// unprivileged bootloader actions.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct UnprivilegedKey {
    pub raw_key: [u8; PADDED_PUBLIC_KEY_LEN],
}

impl UnprivilegedKey {
    #[link_section = ".data"]
    #[inline(always)]
    pub(crate) fn key(&self) -> Result<VerifyingKey> {
        expand_key(&self.raw_key)
    }
}

impl_primitive!(
    PRIVILEGED_KEY_OFFSET,
    PrivilegedKey,
    [u8; PADDED_PUBLIC_KEY_LEN]
);
impl_primitive!(
    UNPRIVILEGED_KEY_OFFSET,
    UnprivilegedKey,
    [u8; PADDED_PUBLIC_KEY_LEN]
);
