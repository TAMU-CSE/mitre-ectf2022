//! The firmware update host-tool handles the update process for updating the device with protected
//! firmware.
//!
//! # Implementation Details
//! 1. The protected firmware package is read from the filesystem.
//! 2. The protected package is validated.
//! 3. The firmware update command is sent to the bootloader.
//! 4. An authentication step is performed to prove that we are a valid host-tool.
//! 5. The verified protected package is sent to the bootloader
//! 6. The host-tool waits for a completion status from the bootloader.

use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use p256::ecdsa::{SigningKey, VerifyingKey};
use riir_host_tools::{firmware_path, print_banner, FirmwarePackage, Socket};
use std::path::PathBuf;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    /// Port number of the socket to connect the host to the bootloader.
    #[clap(long)]
    socket: u16,
    /// Name of the firmware image to load.
    #[clap(long)]
    firmware_file: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        socket,
        firmware_file,
    } = Args::parse();
    print_banner("SAFFIRe Firmware Update Tool");

    let sign_key = SigningKey::from_bytes(include_bytes!(env!("UNPRIVILEGED_SIG")))
        .map_err(|_| eyre!("error deserializing unprivileged signing key"))?;
    let verify_key = VerifyingKey::from_sec1_bytes(include_bytes!(env!("PRIVILEGED_PUB")))
        .map_err(|_| eyre!("error deserializing privileged verifying key"))?;

    eprintln!("Reading firmware package from file...");

    let firmware_package = {
        let path = firmware_path(firmware_file);
        let raw_package = std::fs::read(path)?;
        let firmware_package: FirmwarePackage = bincode::deserialize(&raw_package)?;
        firmware_package.verify(&verify_key)?;
        firmware_package
    };

    eprintln!("Connecting socket...");
    let mut sock = Socket::connect(socket)?;

    eprintln!("Sending update command...");
    sock.send(b"U")?;

    sock.authenticate(&sign_key)?;

    eprintln!("Sending firmware package...");
    firmware_package.send(&mut sock)?;
    sock.recv_ok()?;

    eprintln!("Firmware updated.\n");
    Ok(())
}
