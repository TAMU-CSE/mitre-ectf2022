//! This crate contains common functionality used across all host-tools. Each host-tool has its own
//! dedicated binary in `src/bin`.
//!
//! ## Security
//! The `secrets` directory is generated in a pre-build step via a build script (see `build.rs` for details) 
//! and contains cryptographic secrets for encryption and authentication.
//! Privileged tools require the presence of the `secrets` directory at runtime.
//!
//! ### Unprivileged Tools
//! - [`cfg_load`]: Sends a protected mission configuration image to the bootloader for installation.
//! - [`fw_update`]: Sends a protected firmware image to the bootloader for installation.
//! - [`boot`]: Requests the bootloader to boot the currently installed firmware and config.
//!
//! ### Privileged Tools
//! - [`cfg_protect`]: Protects a raw configuration image.
//! - [`fw_protect`]: Protects a raw firmware image.
//! - [`readback`]: Requests the bootloader to send back the currently installed firmware or
//! config.
//!
//! [`cfg_protect`]: ../cfg_protect/index.html
//! [`fw_protect`]: ../fw_protect/index.html
//! [`readback`]: ../readback/index.html
//! [`boot`]: ../boot/index.html
//! [`cfg_load`]: ../cfg_load/index.html
//! [`fw_update`]: ../fw_update/index.html
mod packaging;
mod paths;
mod socket;

pub use packaging::common::*;
pub use packaging::config::*;
pub use packaging::firmware::*;
pub use paths::*;
pub use socket::*;

/// The size of a single page of flash memory on the TM4C123G.
pub const FLASH_PAGE_SIZE: usize = 1024;
/// The size of the MAC used in [`crypto_secretstream`].
pub const MAC_SIZE: usize = 16;
/// The size of the message tag used in [`crypto_secretstream`].
pub const TAG_SIZE: usize = 1;

/// Prints a string, but with dashes above and below.
pub fn print_banner(s: &str) {
    let line = "-".repeat(s.len());
    eprintln!("\n{line}\n{s}\n{line}");
}

#[doc(hidden)]
#[macro_export]
macro_rules! format_bytes {
    ($($arg:expr),+) => {{
        let mut buf = Vec::<u8>::with_capacity(128);
        $(buf.extend_from_slice((&$arg).as_ref());)+
        buf
    }}
}
