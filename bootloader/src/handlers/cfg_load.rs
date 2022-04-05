use crypto_secretstream::PullStream;
use rand_chacha::ChaChaRng;

use crate::crypto::jitter;
use crate::error::{Error, Result};
use crate::package::{authenticate, DynCompMeta, Hashes};
use crate::package::{decrypt_hash, ENCRYPTED_CFG, MAX_ENCRYPTED_CFG_LEN};
use crate::peripherals::eeprom::{
    CfgMeta, Encrypted, Flag, FlashKey, Primitive, PrivilegedKey, UnprivilegedKey,
};
use crate::peripherals::Peripherals;
use crate::verify_stage1;

/// Processes config updates provided by an authenticated host-tool.
/// This handler unpacks a protected config package and installs the config after a series of
/// verification checks.
///
/// # Implementation Details
/// 1. To ensure that a partially applied update cannot be booted, the config boot flag is unset.
/// 2. Component hashes are received and their signatures are verified, ensuring authenticity.
/// 3. The top-level hash is computed over the verified component hashes to ensure integrity of the
/// entire protected package.
/// 4. Each component is received and compared with its corresponding verified hash.
/// 5. Encrypted components with large sizes are written directly to flash to ensure confidentiality.
/// 6. Flash writes are immediately followed by a hash of critical flash regions to ensure the bootloader
/// is not compromised at-rest, as well as providing a cheap method for integrity checking via AEAD (tamper resistance).
/// 7. After encrypted components are written to flash they are immediately hashed with respect to their
/// corresponding verified hash.
/// 8. Critical component hashes are stored encrypted in EEPROM along with component metadata.
/// 9. Once the update is fully applied, the firmware boot flag is set.
#[link_section = ".data"]
pub fn configure(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    p.eeprom.set_cfg_flag(r, Flag::FALSE)?;

    let auth_key = p.eeprom.load_decrypted::<UnprivilegedKey>()?.inner.key()?;
    let verifier_key = p.eeprom.load_decrypted::<PrivilegedKey>()?.inner.key()?;
    let flash_key = p.eeprom.load_decrypted::<FlashKey>()?.inner.key;

    authenticate(p, &auth_key, r)?;

    let [header_hash, len_hash, cfg_hash] = Hashes::new(p, r, &verifier_key)?.components;

    let cfg_meta = DynCompMeta::new(p, r, &header_hash, &len_hash)?;

    jitter(r);
    if cfg_meta.len > MAX_ENCRYPTED_CFG_LEN as u32 || cfg_meta.len == 0 {
        return Err(Error::InvalidLen);
    }

    p.flash
        .load_data(&mut p.uart, ENCRYPTED_CFG, cfg_meta.len as usize)?;
    verify_stage1(p, r)?;

    // Verify plaintext.
    let mut pull = PullStream::init(cfg_meta.header, &flash_key);
    let data =
        unsafe { core::slice::from_raw_parts(ENCRYPTED_CFG as *const u8, cfg_meta.len as usize) };
    let computed_hash = decrypt_hash(data, &mut pull)?;
    jitter(r);
    if computed_hash != cfg_hash {
        return Err(Error::InvalidHash);
    }

    let mut cfg = Encrypted::<CfgMeta>::zeroed();
    cfg.inner.header = cfg_meta.header;
    cfg.inner.len = cfg_meta.len;
    cfg.inner.hash = cfg_hash;
    cfg.store_encrypted(&p.eeprom, r)?;
    p.eeprom.set_cfg_flag(r, Flag::TRUE)?;

    Ok(())
}
