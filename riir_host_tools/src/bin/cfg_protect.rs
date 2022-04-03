//! The config protect host-tool is a privileged operation and requires a valid secrets directory to
//! be present (only possible at the secure facility), ensuring malicious protected packages cannot be forged.
//!
//! # Implementation Details
//! 1. The unprotected config binary is read from the filesystem, as well as secrets necessary for signing and encrypting the protected package.
//! 2. The raw config and relevant secrets are passed to a new [`ConfigPackage`] instance,
//!    which utilizes generic [`SignedHashes`] and [`DynComp`] to construct a protected package.
//! 3. The final protected package is serialized into a binary format and written to disk, where it can
//!    later be read by the [`cfg_load`] host-tool.
//!
//! [`DynComp`]: riir_host_tools::DynComp
//! [`SignedHashes`]: riir_host_tools::SignedHashes
//! [`cfg_load`]: ../cfg_load/index.html

use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use crypto_secretstream::Key;
use p256::ecdsa::SigningKey;
use riir_host_tools::{config_path, print_banner, ConfigPackage};
use std::path::PathBuf;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    /// The name of the configuration to protect.
    #[clap(long)]
    input_file: PathBuf,
    /// The name of the protected configuration.
    #[clap(long)]
    output_file: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        input_file,
        output_file,
    } = Args::parse();
    print_banner("SAFFIRe Configuration Protect Tool");

    eprintln!("Reading the configuration...");
    let raw_config_path = config_path(input_file);
    let raw_config = std::fs::read(raw_config_path)?;

    // read keys from host-secrets
    let privileged_sig = {
        let bytes = std::fs::read(env!("PRIVILEGED_SIG"))?;
        SigningKey::from_bytes(&bytes)
            .map_err(|_| eyre!("error deserializing privileged signing key"))?
    };

    let image_key = {
        let key = std::fs::read(env!("IMAGE_SYMMETRIC"))?;
        Key::try_from(key.as_slice()).map_err(|_| eyre!("invalid key length"))?
    };

    eprintln!("Packaging the configuration...");
    let protected_config = ConfigPackage::new(raw_config.as_slice(), &privileged_sig, &image_key)?;

    let path = config_path(output_file);
    std::fs::write(path, bincode::serialize(&protected_config)?)?;

    eprintln!("Configuration protected\n");

    Ok(())
}
