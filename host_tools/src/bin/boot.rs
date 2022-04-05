//! The boot host-tool is used to instruct the bootloader to load an installed config and
//! boot the installed firmware.
//!
//! # Implementation Details
//! 1. The boot command is sent to the bootloader.
//! 2. An authentication step is performed to prove that we are a valid host-tool.
//! 3. The host-tool waits for a completion status from the bootloader for the boot process.
//! 4. Upon a successful boot, the release message is logged.

use clap::Parser;
use color_eyre::eyre::{ensure, eyre};
use color_eyre::Result;
use p256::ecdsa::SigningKey;
use riir_host_tools::{print_banner, release_msgs_path, Socket};
use std::path::PathBuf;

/// Command-line arguments.
#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
pub struct Args {
    /// Port number of the socket to connect the host to the bootloader.
    #[clap(long)]
    socket: u16,
    /// Name of a file to store the release message in.
    #[clap(long)]
    release_message_file: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        socket,
        release_message_file,
    } = Args::parse();
    print_banner("SAFFIRe Firmware Boot Tool");

    let sign_key = SigningKey::from_bytes(include_bytes!(env!("UNPRIVILEGED_SIG")))
        .map_err(|_| eyre!("error deserializing unprivileged signing key"))?;

    eprintln!("Connecting socket...");
    let mut sock = Socket::connect(socket)?;

    eprintln!("Sending boot command...");
    sock.send(b"B")?;

    // authentication
    sock.authenticate(&sign_key)?;

    eprintln!("Waiting for bootloader for copy firmware to RAM...");
    sock.recv_ok()?;

    eprintln!("Receiving release message...");
    let length = sock.recv_be_u32()?;
    ensure!(
        length <= 1024,
        "release message must fit in 1024 bytes, got {length}"
    );
    let msg = {
        let msg = sock.recv(length as usize)?;
        String::from_utf8(msg)?
    };

    eprintln!("Writing release message to output file...");
    let path = release_msgs_path(release_message_file);
    std::fs::write(path, msg)?;

    eprintln!("Firmware booted.\n");

    Ok(())
}
