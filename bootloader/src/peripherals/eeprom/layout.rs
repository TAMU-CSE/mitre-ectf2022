use super::*;

/// Layout of EEPROM memory.
#[repr(C, align(4))]
pub struct EepromLayout {
    pub stage2_key: Stage2Key,
    pub privileged_key: Encrypted<PrivilegedKey>,
    pub unprivileged_key: Encrypted<UnprivilegedKey>,
    pub flash_key: Encrypted<FlashKey>,
    pub text_hash: Encrypted<TextHash>,
    pub emulator_seed: Encrypted<EmulatorSeed>,
    pub physical_seed: Encrypted<PhysicalSeed>,
    pub fw_meta: Encrypted<FwMeta>,
    pub cfg_meta: Encrypted<CfgMeta>,
    pub fw_flag: Encrypted<FwFlag>,
    pub cfg_flag: Encrypted<CfgFlag>,
}

impl_primitive!(
    0,
    EepromLayout,
    Stage2Key,
    Encrypted<PrivilegedKey>,
    Encrypted<UnprivilegedKey>,
    Encrypted<FlashKey>,
    Encrypted<TextHash>,
    Encrypted<EmulatorSeed>,
    Encrypted<PhysicalSeed>,
    Encrypted<FwMeta>,
    Encrypted<CfgMeta>,
    Encrypted<FwFlag>,
    Encrypted<CfgFlag>
);
