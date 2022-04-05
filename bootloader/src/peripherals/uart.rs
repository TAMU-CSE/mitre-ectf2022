use crate::error::{Error, Result};
use nb::block;
use tm4c123x_hal::gpio::{
    gpioa::{PA0, PA1},
    AlternateFunction, PushPull, AF1,
};
use tm4c123x_hal::prelude::*;
use tm4c123x_hal::serial::{Serial, UART0};

/// Magic byte indicating failure.
pub const FRAME_BAD: u8 = 0x2c;
/// Magic byte indicating success.
pub const FRAME_OK: u8 = 0x69;

/// High-level interface for reading and writing to UART0.
pub struct Uart(
    pub  Serial<
        UART0,
        PA1<AlternateFunction<AF1, PushPull>>,
        PA0<AlternateFunction<AF1, PushPull>>,
        (),
        (),
    >,
);

impl Uart {
    /// Writes a single byte to UART.
    #[link_section = ".data"]
    pub fn write_u8(&mut self, b: u8) {
        // this will never fail, as the Err variant is parametrized by Void
        block!(self.0.write(b)).unwrap();
    }
    /// Writes the provided bytes to UART.
    #[link_section = ".data"]
    pub fn write_all(&mut self, bs: &[u8]) {
        self.0.write_all(bs);
    }
    /// Reads a single byte from UART, blocking until a byte is received.
    #[link_section = ".data"]
    pub fn blocking_read_u8(&mut self) -> u8 {
        // this will never fail, as the Err variant is parametrized by Void
        block!(self.0.read()).unwrap()
    }
    #[link_section = ".data"]
    /// Reads a single byte from UART, blocking until a fixed timeout expires.
    ///
    /// # Implementation Note
    /// The timeout is implemented by incrementing on every iteration with a read that would
    /// potentially block. If the count exceeds `2_000_000` (measured to be roughly 576 ms),
    /// this function returns [`Error::UartTimeout`].
    pub fn nonblocking_read_u8(&mut self) -> Result<u8> {
        const THRESHOLD: u32 = 2_000_000;
        let mut count = 0u32;
        loop {
            match self.0.read() {
                Ok(b) => return Ok(b),
                Err(nb::Error::WouldBlock) => {
                    count += 1;
                    if count > THRESHOLD {
                        return Err(Error::UartTimeout);
                    }
                }
                // this will never fail, as the Err variant is parametrized by Void
                Err(nb::Error::Other(_)) => {
                    unreachable!();
                }
            }
        }
    }
    /// Sends an acknowledgement byte, then performs a read for a single byte with a timeout.
    #[link_section = ".data"]
    pub fn ready_nonblocking_read_u8(&mut self) -> Result<u8> {
        self.write_u8(FRAME_OK);
        self.nonblocking_read_u8()
    }
    /// Sends an acknowledgement byte, then performs a read for a single byte, blocking until
    /// a byte is received.
    #[link_section = ".data"]
    pub fn ready_blocking_read_u8(&mut self) -> u8 {
        self.write_u8(FRAME_OK);
        self.blocking_read_u8()
    }
    /// Sends an acknowledgement byte, then performs a read for a [`u32`] with a timeout.
    #[link_section = ".data"]
    pub fn ready_nonblocking_read_be_u32(&mut self) -> Result<u32> {
        self.write_u8(FRAME_OK);
        Ok(u32::from_be_bytes([
            self.nonblocking_read_u8()?,
            self.nonblocking_read_u8()?,
            self.nonblocking_read_u8()?,
            self.nonblocking_read_u8()?,
        ]))
    }
    /// Sends an acknowledgement byte, then performs a read to fill the provided slice
    /// with a timeout.
    #[link_section = ".data"]
    pub fn ready_nonblocking_read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.write_u8(FRAME_OK);
        for b in buf.iter_mut() {
            *b = self.nonblocking_read_u8()?;
        }
        Ok(())
    }
    /// Sends an acknowledgement byte, then performs a read for a byte array of size `N` with a timeout.
    #[link_section = ".data"]
    pub fn ready_nonblocking_read_arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut arr = [0u8; N];
        self.ready_nonblocking_read_exact(&mut arr)?;
        Ok(arr)
    }
    /// Discards incoming bytes until the next read would be blocking.
    #[link_section = ".data"]
    pub fn flush(&mut self) {
        while self.0.read().is_ok() {}
    }
}
