//! Provides utilities and wrapper types for working with EEPROM memory. Refer to [`EepromLayout`]
//! for an overview of how EEPROM memory is allocated.

use crate::crypto::delay;
use crate::error::{Error, Result};
use crate::size;
use chacha20poly1305::{Tag, XNonce};
use crypto_secretstream::Header;
use rand_chacha::ChaChaRng;
use static_assertions::{assert_eq_align, const_assert, const_assert_eq};
use tm4c123x_hal::{
    sysctl::{control_power, reset, Domain, PowerState, RunMode, Sysctl},
    tm4c123x::EEPROM,
};

mod cfg;
mod encrypted;
mod flag;
mod flash;
mod fw;
mod hash;
mod keys;
mod layout;
mod primitive;
mod seed;
mod stage2;

pub use cfg::CfgMeta;
pub use encrypted::Encrypted;
pub use flag::{CfgFlag, Flag, FwFlag};
pub use flash::FlashKey;
pub use fw::FwMeta;
pub use hash::TextHash;
pub use keys::{PrivilegedKey, UnprivilegedKey, PADDED_PUBLIC_KEY_LEN, SEC1_PUBLIC_KEY_LEN};
pub use layout::EepromLayout;
pub use primitive::Primitive;
pub use seed::{EmulatorSeed, PhysicalSeed};
pub use stage2::Stage2Key;

/// Offset of **unencrypted** stage 2 decryption key in EEPROM.
pub const STAGE2_KEY_OFFSET: usize = 0;
/// Offset of encrypted privileged public key in EEPROM.
pub const PRIVILEGED_KEY_OFFSET: usize = STAGE2_KEY_OFFSET + size!(Stage2Key);
/// Offset of encrypted unprivileged public key in EEPROM.
pub const UNPRIVILEGED_KEY_OFFSET: usize = PRIVILEGED_KEY_OFFSET + size!(Encrypted<PrivilegedKey>);
/// Offset of encrypted flash decryption key in EEPROM.
pub const FLASH_KEY_OFFSET: usize = UNPRIVILEGED_KEY_OFFSET + size!(Encrypted<UnprivilegedKey>);
/// Offset of encrypted hash of the .text section in EEPROM.
pub const TEXT_HASH_OFFSET: usize = FLASH_KEY_OFFSET + size!(Encrypted<FlashKey>);
/// Offset of encrypted CSPRNG seed for the emulator in EEPROM.
pub const EMULATOR_SEED_OFFSET: usize = TEXT_HASH_OFFSET + size!(Encrypted<TextHash>);
/// Offset of encrypted CSPRNG seed for the physical device in EEPROM.
pub const PHYSICAL_SEED_OFFSET: usize = EMULATOR_SEED_OFFSET + size!(Encrypted<EmulatorSeed>);
/// Offset of encrypted firmware metadata in EEPROM.
pub const FW_META_OFFSET: usize = PHYSICAL_SEED_OFFSET + size!(Encrypted<PhysicalSeed>);
/// Offset of encrypted configuration metadata in EEPROM.
pub const CFG_META_OFFSET: usize = FW_META_OFFSET + size!(Encrypted<FwMeta>);
/// Offset of encrypted firmware update flag in EEPROM.
pub const FW_FLAG_OFFSET: usize = CFG_META_OFFSET + size!(Encrypted<CfgMeta>);
/// Offset of encrypted configuration update flag in EEPROM.
pub const CFG_FLAG_OFFSET: usize = FW_FLAG_OFFSET + size!(Encrypted<FwFlag>);

const_assert!(CFG_FLAG_OFFSET + size!(Encrypted<CfgFlag>) < 1024);

#[macro_use]
mod macro_impl {
    macro_rules! impl_primitive {
        ($offset:expr, $t:ty, $($ts:ty),+) => {
            const_assert_eq!(size!($t), size!($($ts),+));
            assert_eq_align!($t, u32);
            const_assert_eq!(size!($t) % 4, 0);

            const_assert_eq!(size!(Encrypted<$t>), size!($t, XNonce, Tag));
            assert_eq_align!(Encrypted<$t>, u32);
            const_assert_eq!(size!(Encrypted<$t>) % 4, 0);

            const_assert_eq!($offset % 4, 0);
            // SAFETY: The static assertions above enforce Primitive's invariants.
            unsafe impl Primitive for $t {
                const OFFSET: usize = $offset;
            }
        }
    }

    pub(crate) use impl_primitive;
}
use macro_impl::impl_primitive;

/// High-level interface for reading and writing to EEPROM memory.
pub struct Eeprom(EEPROM);

impl Eeprom {
    #[inline(always)]
    fn wait(eeprom: &EEPROM) {
        while eeprom.eedone.read().working().bit_is_set() {}
    }
    #[inline(always)]
    fn check_errors(eeprom: &EEPROM) {
        let status = eeprom.eesupp.read();

        if status.pretry().bit_is_set() || status.eretry().bit_is_set() {
            panic!("initialization should never fail");
        }
    }
    /// Initializes EEPROM memory.
    ///
    /// Adapted from `EEPROMInit` of the TivaWare library.
    pub fn init(eeprom: EEPROM, sysctl: &mut Sysctl) -> Self {
        control_power(
            &sysctl.power_control,
            Domain::Eeprom,
            RunMode::Run,
            PowerState::On,
        );

        delay(6);

        Self::wait(&eeprom);
        Self::check_errors(&eeprom);

        reset(&sysctl.power_control, Domain::Eeprom);

        delay(2);

        Self::wait(&eeprom);
        Self::check_errors(&eeprom);

        Eeprom(eeprom)
    }
    /// Returns the word offset within the current block.
    ///
    /// Adapted from `OFFSET_FROM_ADDR` of the TivaWare library.
    const fn offset_from_addr(addr: usize) -> u32 {
        (addr as u32 >> 2) & 0b0000_1111
    }
    /// Returns the EEPROM block number containing a given offset address.
    ///
    /// Adapted from `EEPROMBlockFromAddr` of the TivaWare library.
    const fn block_from_addr(addr: usize) -> u32 {
        addr as u32 >> 6
    }
    /// Reads data from EEPROM.
    ///
    /// Adapted from `EEPROMRead` of the TivaWare library.
    pub fn read(&self, buf: &mut [u32], addr: usize) -> Result<()> {
        if buf.is_empty() {
            return Err(Error::EepromRead);
        }

        let last = buf.len() - 1;
        let block = Self::block_from_addr(addr);
        let offset = Self::offset_from_addr(addr);
        self.0.eeblock.write(|w| unsafe { w.bits(block) });
        self.0.eeoffset.write(|w| unsafe { w.bits(offset) });

        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = self.0.eerdwrinc.read().bits();

            // Only modify EEBLOCK if we're not on the last iteration.
            if i != last && self.0.eeoffset.read().bits() == 0 {
                self.0
                    .eeblock
                    .modify(|r, w| unsafe { w.bits(r.bits() + 1) });
            }
        }

        Ok(())
    }
    /// Writes data to EEPROM.
    ///
    /// Adapted from `EEPROMWrite` of the TivaWare library.
    pub fn write(&self, data: &[u32], addr: usize) -> Result<()> {
        if data.is_empty() {
            return Err(Error::EepromWrite);
        }

        // Make sure the EEPROM is idle before we start.
        Self::wait(&self.0);

        let last = data.len() - 1;
        let block = Self::block_from_addr(addr);
        let offset = Self::offset_from_addr(addr);
        self.0.eeblock.write(|w| unsafe { w.bits(block) });
        self.0.eeoffset.write(|w| unsafe { w.bits(offset) });

        for (i, &word) in data.iter().enumerate() {
            // Write the next word through the autoincrementing register.
            self.0.eerdwrinc.write(|w| unsafe { w.bits(word) });

            // Wait a few cycles.  In some cases, the WRBUSY bit is not set
            // immediately and this prevents us from dropping through the polling
            // loop before the bit is set.
            delay(10);

            Self::wait(&self.0);

            // Only modify EEBLOCK if we're not on the last iteration.
            if i != last && self.0.eeoffset.read().bits() == 0 {
                self.0
                    .eeblock
                    .modify(|r, w| unsafe { w.bits(r.bits() + 1) });
            }
        }

        Ok(())
    }
    /// Loads a decrypted `T` from EEPROM.
    #[inline(always)]
    pub fn load_decrypted<T: Primitive>(&self) -> Result<Encrypted<T>> {
        Encrypted::<T>::load_decrypted(self)
    }
    // This is manually outlined to save some space in the .data section.
    #[link_section = ".data"]
    pub(crate) fn set_flag(&self, r: &mut ChaChaRng, flag: Flag, offset: usize) -> Result<()> {
        let mut this = Encrypted::<FwFlag>::zeroed();
        this.inner.is_updated = flag;
        this.store_encrypted_raw(self, r, offset)?;
        Ok(())
    }
    /// Sets the firmware flag to [`Flag::TRUE`].
    #[link_section = ".data"]
    pub fn set_fw_flag(&self, r: &mut ChaChaRng, flag: Flag) -> Result<()> {
        self.set_flag(r, flag, FwFlag::OFFSET)
    }
    /// Sets the config flag to [`Flag::TRUE`].
    #[link_section = ".data"]
    pub fn set_cfg_flag(&self, r: &mut ChaChaRng, flag: Flag) -> Result<()> {
        self.set_flag(r, flag, CfgFlag::OFFSET)
    }
}
