//! The firmware protect host-tool is a privileged operation and requires a valid secrets directory to
//! be present (only possible at the secure facility), ensuring malicious protected packages cannot be forged.
//!
//! # Implementation Details
//! 1. The unprotected firmware binary, version, and release message are loaded from the
//!    filesystem/command-line arguments, as well as secrets necessary for signing and 
//!    encrypting the protected package.
//! 2. The raw firmware and relevant secrets are passed to a new [`FirmwarePackage`] instance,
//!    which utilizes generic [`SignedHashes`] and [`DynComp`] to construct a protected package.
//! 3. The final protected package is serialized into a binary format and written it to disk, where it can
//!    later be read by the [`fw_update`] host-tool.
//!
//! [`DynComp`]: riir_host_tools::DynComp
//! [`SignedHashes`]: riir_host_tools::SignedHashes
//! [`fw_update`]: ../fw_update/index.html

use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use crypto_secretstream::Key;
use riir_host_tools::{firmware_path, print_banner, FirmwarePackage};
use std::path::PathBuf;
use p256::ecdsa::SigningKey;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    /// The name of the firmware image to protect.
    #[clap(long)]
    firmware: PathBuf,
    /// The version of this firmware.
    #[clap(long)]
    version: u32,
    /// The release message of this firmware.
    #[clap(long)]
    release_message: String,
    /// The name of the protected firmware image.
    #[clap(long)]
    output_file: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        firmware,
        version,
        release_message,
        output_file,
    } = Args::parse();
    print_banner("SAFFIRe Firmware Protect Tool");

    eprintln!("Reading the firmware...");
    let raw_firmware_path = firmware_path(firmware);
    let raw_firmware = std::fs::read(raw_firmware_path)?;

    // read keys from host-secrets
    let privileged_sig = SigningKey::from_bytes(include_bytes!(env!("PRIVILEGED_SIG")))
        .map_err(|_| eyre!("error deserializing privileged signing key"))?;

    let image_key = {
        let key = std::fs::read(env!("IMAGE_SYMMETRIC"))?;
        Key::try_from(key.as_slice()).map_err(|_| eyre!("invalid key length"))?
    };

    eprintln!("Packaging the firmware...");
    let protected_firmware = FirmwarePackage::new(
        version,
        release_message.as_str(),
        raw_firmware.as_slice(),
        &privileged_sig,
        &image_key,
    )?;

    let path = firmware_path(output_file);
    std::fs::write(path, bincode::serialize(&protected_firmware)?)?;

    eprintln!("Firmware protected\n");

    Ok(())
}
