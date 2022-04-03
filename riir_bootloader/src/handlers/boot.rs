use crate::crypto::{jitter, verify_hash};
use crate::package::{
    authenticate,
    decrypt_and_send_rel_msg, decrypt_to_flash, decrypt_to_sram, CFG_TARGET, FW_TARGET,
};
use crate::peripherals::eeprom::{Flag, FlashKey, FwMeta, UnprivilegedKey};
use crate::peripherals::Peripherals;
use crate::{
    error::{Error, Result},
    peripherals::eeprom::{CfgFlag, CfgMeta, FwFlag},
    verify_stage1,
};
use crypto_secretstream::PullStream;
use rand_chacha::ChaChaRng;

/// Loads configuration and boots firmware.
///
/// # Implementation Details
/// 1. Config and firmware boot flags are checked to ensure valid config and firmware images are
/// fully installed.
/// 2. An authentication step ensures the bootloader is communicating with a verified host-tool.
/// 3. Firmware is decrypted into SRAM and config is decrypted into flash.
/// 4. Each decryption step is immediately followed by hashing the decrypted image to ensure integrity
/// before boot.
/// 5. Flash writes are immediately followed by a hash of critical flash regions to ensure the bootloader
/// is not compromised.
/// 6. Once everything is successfully staged, the release message is sent to the host-tool and the
/// firmware is executed.
#[link_section = ".data"]
pub fn boot(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let auth_key = p.eeprom.load_decrypted::<UnprivilegedKey>()?.inner.key()?;
    let fw = p.eeprom.load_decrypted::<FwMeta>()?;
    let cfg = p.eeprom.load_decrypted::<CfgMeta>()?;
    let flash_key = p.eeprom.load_decrypted::<FlashKey>()?.inner.key;

    let fw_updated = p.eeprom.load_decrypted::<FwFlag>()?.inner.is_updated;
    let cfg_updated = p.eeprom.load_decrypted::<CfgFlag>()?.inner.is_updated;

    // Ensure both firmware and config are correctly updated.
    jitter(r);
    if fw_updated != Flag::TRUE {
        return Err(Error::FwNotUpdated);
    }
    jitter(r);
    if cfg_updated != Flag::TRUE {
        return Err(Error::CfgNotUpdated);
    }

    authenticate(p, &auth_key, r)?;

    // Write decrypted firmware to SRAM.
    let mut fw_pull = PullStream::init(fw.inner.fw_header, &flash_key);
    let encrypted_fw = fw.inner.encrypted_fw();
    let decrypted_fw = decrypt_to_sram(encrypted_fw, &mut fw_pull, FW_TARGET)?;

    // Verify hash of firmware plaintext.
    verify_hash(decrypted_fw, &fw.inner.fw_hash, r)?;

    // Write decrypted config to flash.
    let mut cfg_pull = PullStream::init(cfg.inner.header, &flash_key);
    let encrypted_cfg = cfg.inner.encrypted_cfg();
    let decrypted_cfg = decrypt_to_flash(p, encrypted_cfg, &mut cfg_pull, CFG_TARGET)?;
    verify_stage1(p, r)?;

    // Verify hash of config plaintext.
    verify_hash(decrypted_cfg, &cfg.inner.hash, r)?;

    // Decrypt, verify, and send the release message back to host-tools.
    let mut msg_pull = PullStream::init(fw.inner.msg_header, &flash_key);
    let encrypted_msg = fw.inner.encrypted_msg();
    decrypt_and_send_rel_msg(p, r, encrypted_msg, &mut msg_pull, &fw.inner.msg_hash)?;

    // Execute the firmware.
    // SAFETY: We've verified the integrity and origin of the firmware, and we trust that the privileged host tools sent us valid firmware. We set the first bit
    // of the target address to indicate that the firmware consists of thumb instructions.
    unsafe { core::mem::transmute::<_, fn() -> !>(FW_TARGET | 1)() }
}
