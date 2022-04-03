use crate::crypto::jitter;
use crate::error::{Error, Result};
use crate::package::authenticate;
use crate::peripherals::eeprom::{CfgFlag, CfgMeta, Flag, FwFlag, FwMeta, PrivilegedKey};
use crate::peripherals::Peripherals;
use rand_chacha::ChaChaRng;

/// Sends package data back to host-tools.
///
/// **Readback is a privileged operation since it exfiltrates sensitive information.**
///
/// # Implementation Details
///
/// - An authentication step is used to verify that the host-tool is privileged and allowed to access
/// the sensitive information.
/// - The requested region is sent as ciphertext via [`crypto_secretstream`], ensuring exfiltrated data is confidential over the wire.
/// - By sending only ciphertext, the readback host-tool is required to decrypt with the image
///   flash key, providing a second factor of authentication.
#[link_section = ".data"]
pub fn readback(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    let verifier_key = p.eeprom.load_decrypted::<PrivilegedKey>()?.inner.key()?;

    authenticate(p, &verifier_key, r)?;

    let region = p.uart.ready_nonblocking_read_u8()?;

    let (header, data) = match region {
        b'F' => {
            let fw = p.eeprom.load_decrypted::<FwMeta>()?;
            let fw_updated = p.eeprom.load_decrypted::<FwFlag>()?.inner.is_updated;
            jitter(r);
            if fw_updated != Flag::TRUE {
                return Err(Error::FwNotUpdated);
            }
            (fw.inner.fw_header, fw.inner.encrypted_fw())
        }
        b'C' => {
            let cfg = p.eeprom.load_decrypted::<CfgMeta>()?;
            let cfg_updated = p.eeprom.load_decrypted::<CfgFlag>()?.inner.is_updated;
            jitter(r);
            if cfg_updated != Flag::TRUE {
                return Err(Error::CfgNotUpdated);
            }
            (cfg.inner.header, cfg.inner.encrypted_cfg())
        }
        _ => return Err(Error::InvalidRegion),
    };

    p.uart.write_all(header.as_ref());
    p.uart.write_all(&data.len().to_be_bytes());
    p.uart.write_all(data);

    Ok(())
}
