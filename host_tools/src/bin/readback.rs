//! The readback protect host-tool is a privileged operation and requires a valid secrets directory to
//! be present (only possible at the secure facility).
//!
//! # Implementation Details
//! 1. The symmetric key for config/firmware decryption is read from the filesystem, as well as a privileged signing key to prove
//!    that the host-tool is authorized to perform the readback operation.
//! 2. The readback command is sent to the bootloader.
//! 3. An authentication step is performed to prove that we are a valid host-tool.
//! 4. A [`Region`] is sent that specifies which region to readback.
//! 5. The host-tool waits for the bootloader to send back a cryptographic header, length and complete ciphertext for the
//!    requested region.
//! 6. The ciphertext is decrypted with the provided information.
//! 7. The host-tool waits for a completion status from the bootloader. 
//!    On success, the specified number of bytes of plaintext is printed as a hex stream.

use clap::{ArgEnum, Parser};
use color_eyre::{eyre::eyre, Result};
use crypto_secretstream::{Header, Key, PullStream};
use p256::ecdsa::SigningKey;
use riir_host_tools::{print_banner, Socket};
use std::num::NonZeroU32;

#[derive(ArgEnum, Clone, Debug)]
#[clap(rename_all = "kebab")]
#[repr(u8)]
/// The region to read.
pub enum Region {
    Firmware = b'F',
    Configuration = b'C',
}

const MAX_CIPHERTEXT_CHUNK_LEN: usize = 1041;

/// Decrypts data received from readback.
pub fn decrypt_readback_data(ciphertext: &[u8], header: Header) -> Result<Vec<u8>> {
    let bytes = std::fs::read(env!("IMAGE_SYMMETRIC"))?;
    let key = Key::try_from(bytes.as_slice()).map_err(|_| eyre!("invalid key length"))?;
    let mut stream = PullStream::init(header, &key);
    let mut plaintext = Vec::new();
    let mut buf = Vec::with_capacity(MAX_CIPHERTEXT_CHUNK_LEN);

    for chunk in ciphertext.chunks(MAX_CIPHERTEXT_CHUNK_LEN) {
        buf.clear();
        buf.extend_from_slice(chunk);
        stream.pull(&mut buf, b"").unwrap();
        plaintext.extend_from_slice(&buf);
    }

    Ok(plaintext)
}

#[derive(Parser, Debug)]
#[clap(about, rename_all = "kebab")]
/// Command-line arguments.
pub struct Args {
    /// Port number of the socket to connect the host to the bootloader.
    #[clap(long)]
    socket: u16,
    /// The region to read.
    #[clap(long, arg_enum)]
    region: Region,
    /// The number of bytes to read from the region.
    #[clap(long)]
    num_bytes: NonZeroU32,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let Args {
        socket,
        region,
        num_bytes,
    } = Args::parse();
    print_banner("SAFFIRe Memory Readback Tool");

    let sign_key = {
        let bytes = std::fs::read(env!("PRIVILEGED_SIG"))?;
        SigningKey::from_bytes(bytes.as_slice())
            .map_err(|_| eyre!("error deserializing privileged signing key"))?
    };

    eprintln!("Connecting socket...");
    let mut sock = Socket::connect(socket)?;

    eprintln!("Sending readback command...");
    sock.send(b"R")?;

    // authentication
    sock.authenticate(&sign_key)?;

    eprintln!("Sending the region identifier to read back...");
    let byte = region as u8;
    sock.ready_send(std::array::from_ref(&byte))?;

    let header = Header::from(sock.recv_arr()?);
    let ciphertext_len = sock.recv_be_u32()? as usize;

    eprintln!("Receiving image...");
    let encrypted_firmware = sock.recv(ciphertext_len)?;
    let decrypted_firmware = decrypt_readback_data(&encrypted_firmware, header)?;
    let requested = decrypted_firmware
        .get(..num_bytes.get() as usize)
        .ok_or_else(|| eyre!("number of bytes requested is too large"))?;
    let firmware_hex = hex::encode(&requested);
    sock.recv_ok()?;

    eprint!("Memory Readback Data: ");
    // only write hex data to STDOUT
    print!("{firmware_hex}");
    eprintln!();

    Ok(())
}
