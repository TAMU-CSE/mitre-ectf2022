//! Error handling.

use num_enum::{IntoPrimitive, TryFromPrimitive};

/// A catch-all error type for all error states in the bootloader.
#[derive(TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Error {
    /// Unaligned flash address.
    UnalignedFlash,
    /// Flash access violation.
    InvalidFlashAccess,
    /// Attempted to execute an invalid command.
    InvalidCmd,
    /// Attempted to readback an invalid region.
    InvalidRegion,
    /// Attempted firmware update with an invalid version.
    InvalidVersion,
    /// Invalid length.
    InvalidLen,
    /// Decryption failed.
    DecryptionFailure,
    /// Encryption failed.
    EncryptionFailure,
    /// Attempted to append to a full buffer.
    CapacityOverflow,
    /// Hash mismatch.
    InvalidHash,
    /// Signature verification failure.
    SignatureError,
    /// Attempted to access firmware when not ready.
    FwNotUpdated,
    /// Attempted to access config when not ready.
    CfgNotUpdated,
    /// Error while writing to EEPROM.
    EepromWrite,
    /// Error while reading from EEPROM.
    EepromRead,
    /// A UART read took too long.
    UartTimeout,
}

impl From<p256::ecdsa::Error> for Error {
    fn from(_: p256::ecdsa::Error) -> Self {
        Self::SignatureError
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Self::DecryptionFailure
    }
}

/// Convenient alias for a [`Result`] parametrized by [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
