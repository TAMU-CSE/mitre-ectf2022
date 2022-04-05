use crate::crypto::{jitter, verify_hash};
use crate::error::{Error, Result};
use crate::package::{authenticate, DynCompMeta, Hashes};
use crate::package::{
    decrypt_hash, ENCRYPTED_FW, ENCRYPTED_MSG, MAX_ENCRYPTED_FW_LEN, MAX_ENCRYPTED_MSG_LEN,
};
use crate::peripherals::eeprom::{Flag, FlashKey, UnprivilegedKey};
use crate::peripherals::eeprom::{FwMeta, PrivilegedKey};
use crate::peripherals::Peripherals;
use crate::verify_stage1;
use crypto_secretstream::PullStream;
use rand_chacha::ChaChaRng;

/// Processes firmware updates provided by an authenticated host-tool.
/// This handler unpacks a protected firmware package and installs the firmware after a series of verification checks.
///
/// # Implementation Details
/// 1. To ensure that a partially applied update cannot be booted, the firmware boot flag is unset.
/// 2. Component hashes are received and their signatures are verified, ensuring authenticity.
/// 3. The top-level hash is computed over the verified component hashes to ensure integrity of the
/// entire protected package.
/// 4. Each component is received and compared with its corresponding verified hash.
/// 5. Encrypted components with large sizes are written directly to flash to ensure confidentiality
/// 6. Flash writes are immediately followed by a hash of critical flash regions to ensure the bootloader
/// is not compromised at-rest, as well as providing a cheap method for integrity checking via AEAD (tamper resistance).
/// 7. After encrypted components are written to flash, they are immediately hashed with respect to their
/// corresponding verified hash.
/// 8. Critical component hashes are stored encrypted in EEPROM along with component metadata.
/// 9. Once the update is fully applied, the firmware boot flag is set.
#[link_section = ".data"]
pub fn update(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    p.eeprom.set_fw_flag(r, Flag::FALSE)?;

    let auth_key = p.eeprom.load_decrypted::<UnprivilegedKey>()?.inner.key()?;
    let verifier_key = p.eeprom.load_decrypted::<PrivilegedKey>()?.inner.key()?;
    let mut fw = p.eeprom.load_decrypted::<FwMeta>()?;
    let flash_key = p.eeprom.load_decrypted::<FlashKey>()?.inner.key;

    authenticate(p, &auth_key, r)?;

    let [version_hash, msg_header_hash, msg_len_hash, msg_hash, fw_header_hash, fw_len_hash, fw_hash] =
        Hashes::new(p, r, &verifier_key)?.components;

    let version = p.uart.ready_nonblocking_read_be_u32()?;
    verify_hash(&version.to_be_bytes(), &version_hash, r)?;

    jitter(r);
    if version != 0 && version < fw.inner.latest_version {
        return Err(Error::InvalidVersion);
    }

    // Receive release message.
    let msg_meta = DynCompMeta::new(p, r, &msg_header_hash, &msg_len_hash)?;

    jitter(r);
    if msg_meta.len > MAX_ENCRYPTED_MSG_LEN as u32 {
        return Err(Error::InvalidLen);
    }

    p.flash
        .load_data(&mut p.uart, ENCRYPTED_MSG, msg_meta.len as usize)?;
    verify_stage1(p, r)?;

    let mut pull = PullStream::init(msg_meta.header, &flash_key);
    let data =
        unsafe { core::slice::from_raw_parts(ENCRYPTED_MSG as *const u8, msg_meta.len as usize) };

    jitter(r);
    if decrypt_hash(data, &mut pull)? != msg_hash {
        return Err(Error::InvalidHash);
    }

    // Receive firmware.
    let fw_meta = DynCompMeta::new(p, r, &fw_header_hash, &fw_len_hash)?;

    jitter(r);
    if fw_meta.len > MAX_ENCRYPTED_FW_LEN as u32 || fw_meta.len == 0 {
        return Err(Error::InvalidLen);
    }

    p.flash
        .load_data(&mut p.uart, ENCRYPTED_FW, fw_meta.len as usize)?;
    verify_stage1(p, r)?;

    let mut pull = PullStream::init(fw_meta.header, &flash_key);
    let data =
        unsafe { core::slice::from_raw_parts(ENCRYPTED_FW as *const u8, fw_meta.len as usize) };
    let computed_hash = decrypt_hash(data, &mut pull)?;
    jitter(r);
    if computed_hash != fw_hash {
        return Err(Error::InvalidHash);
    }

    // Commit changes to EEPROM.
    fw.inner.msg_header = msg_meta.header;
    fw.inner.msg_len = msg_meta.len;
    fw.inner.msg_hash = msg_hash;

    fw.inner.fw_header = fw_meta.header;
    fw.inner.fw_len = fw_meta.len;
    fw.inner.fw_hash = fw_hash;

    jitter(r);
    if version != 0 {
        fw.inner.latest_version = version;
    }

    fw.store_encrypted(&p.eeprom, r)?;
    p.eeprom.set_fw_flag(r, Flag::TRUE)?;

    Ok(())
}
