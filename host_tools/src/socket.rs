use chacha20poly1305::XNonce;
use color_eyre::{eyre::ensure, Result};
use p256::ecdsa::{signature::Signer, SigningKey};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;

/// Magic byte that indicates failure.
pub const FRAME_BAD: u8 = 0x2c;
/// Magic byte that indicates success.
pub const FRAME_OK: u8 = 0x69;

/// TCP connection to target device or emulator.
pub struct Socket {
    inner: BufReader<TcpStream>,
}

impl Socket {
    /// Opens a TCP connection on the specified port.
    pub fn connect(port: u16) -> Result<Self> {
        #[cfg(feature = "emulator")]
        let stream = TcpStream::connect(("saffire-net", port))?;
        #[cfg(not(feature = "emulator"))]
        let stream = TcpStream::connect(("localhost", port))?;
        Ok(Self {
            inner: BufReader::new(stream),
        })
    }
    /// Reads exactly `n` bytes; this will fail if there are fewer than `n` bytes.
    pub fn recv(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }
    /// Reads exactly `N` bytes into an array, where `N` is known at compile time.
    pub fn recv_arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut arr = [0u8; N];
        self.inner.read_exact(&mut arr)?;
        Ok(arr)
    }
    /// Reads a single byte.
    pub fn recv_byte(&mut self) -> Result<u8> {
        let mut byte = 0;
        self.inner.read_exact(std::array::from_mut(&mut byte))?;
        Ok(byte)
    }
    /// Reads a big-endian [`u32`].
    pub fn recv_be_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.recv_arr()?))
    }
    /// Waits for an acknowledge byte from the bootloader, then sends the provided message.
    pub fn ready_send(&mut self, msg: &[u8]) -> Result<()> {
        self.recv_ok()?;
        Ok(self.inner.get_mut().write_all(msg)?)
    }
    /// Sends a message to the bootloader.
    pub fn send(&mut self, msg: &[u8]) -> Result<()> {
        Ok(self.inner.get_mut().write_all(msg)?)
    }
    /// Reads a single byte, ensuring the bootloader responds with [`FRAME_OK`].
    pub fn recv_ok(&mut self) -> Result<()> {
        let response = self.recv_byte()?;
        ensure!(
            response == FRAME_OK,
            "ERROR: bootloader responded with {response}"
        );
        Ok(())
    }
    /// Reads a nonce, signs it with the provided [`SigningKey`], then sends the signature back to the
    /// bootloader for authentication.
    pub fn authenticate(&mut self, sign_key: &SigningKey) -> Result<()> {
        self.recv_ok()?;
        let nonce = XNonce::from(self.recv_arr()?);
        let signature = sign_key.sign(&nonce);
        self.ready_send(signature.as_ref())
    }
}
