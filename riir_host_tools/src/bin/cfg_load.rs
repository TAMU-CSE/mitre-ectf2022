//! The config load host-tool handles the update process for loading a protected config onto the device.
//!
//! # Implementation Details
//! 1. The protected config package is read from the filesystem.
//! 2. The protected package is validated.
//! 3. The config load command is sent to the bootloader.
//! 4. An authentication step is performed to prove that we are a valid host-tool.
//! 5. The verified protected package is sent to the bootloader
//! 6. The host-tool waits for a completion status from the bootloader.

use clap::Parser;
use color_eyre::eyre::eyre;
use color_eyre::eyre::Result;
use p256::ecdsa::{SigningKey, VerifyingKey};
use riir_host_tools::{config_path, print_banner, ConfigPackage, Socket};
use std::path::PathBuf;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    /// Port number of the socket to connect the host to the bootloader.
    #[clap(long)]
    socket: u16,
    /// Name of the protected configuration to load.
    #[clap(long)]
    config_file: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        socket,
        config_file,
    } = Args::parse();
    print_banner("SAFFIRe Configuration Tool");

    let sign_key = SigningKey::from_bytes(include_bytes!(env!("UNPRIVILEGED_SIG")))
        .map_err(|_| eyre!("error deserializing unprivileged signing key"))?;
    let verify_key = VerifyingKey::from_sec1_bytes(include_bytes!(env!("PRIVILEGED_PUB")))
        .map_err(|_| eyre!("error deserializing privileged verifying key"))?;

    eprintln!("Reading configuration file...");
    let config_package = {
        let path = config_path(config_file);
        let raw_package = std::fs::read(path)?;
        let config_package: ConfigPackage = bincode::deserialize(&raw_package)?;
        config_package.verify(&verify_key)?;
        config_package
    };

    eprintln!("Connecting socket...");
    let mut sock = Socket::connect(socket)?;

    eprintln!("Sending configure command...");
    sock.send(b"C")?;

    // authentication
    sock.authenticate(&sign_key)?;

    eprintln!("Sending configuration package...");
    config_package.send(&mut sock)?;
    sock.recv_ok()?;

    eprintln!("Configuration loaded.\n");

    Ok(())
}
