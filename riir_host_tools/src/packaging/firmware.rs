use crate::{format_bytes, verify_hash, DynComp, SignedHashes, Socket};
use color_eyre::{eyre::ensure, Result};
use crypto_secretstream::Key;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A firmware update consists of a plaintext version, a release message, and a raw firmware binary.
///
/// Since the version is public knowledge and is statically sized, it is sent in plaintext with a
/// corresponding [`SignedHash`] to ensure authenticity and integrity.
/// The release message and raw firmware are both dynamically sized, so [`DynComp`] instances are
/// created for each.
/// Additionally, since the bootloader stores the release message and raw firmware encrypted at rest,
/// [`DynComp`] must be used for pre-encryption.
/// This is necessary in order to preserve confidentiality and provide a cheap way for on-device integrity
/// checks since modifications to ciphertext will fail due to AEAD.
/// [`SignedHashes`] are created for each component to ensure integrity and authenticity of the entire
/// protected package.
///
/// [`SignedHash`]: crate::SignedHash
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct FirmwarePackage {
    pub signed_hashes: SignedHashes<7>,
    pub version: u32,
    pub release_msg: DynComp,
    pub firmware: DynComp,
}

impl FirmwarePackage {
    /// Creates a protected firmware package.
    pub fn new(
        version: u32,
        release_msg: &str,
        firmware: &[u8],
        sign_key: &SigningKey,
        enc_key: &Key,
    ) -> Result<FirmwarePackage> {
        ensure!(
            release_msg.len() <= 1024,
            "release message must fit in 1 KB, got {}",
            release_msg.len(),
        );
        ensure!(
            !firmware.is_empty() && firmware.len() <= 1024 * 16,
            "firmware must be nonempty and fit in 16 KB, got {}",
            firmware.len(),
        );
        let (prot_release_msg, prot_firmware) = {
            (
                DynComp::new(release_msg.as_bytes(), enc_key),
                DynComp::new(firmware, enc_key),
            )
        };

        let prot_release_msg = prot_release_msg?;
        let prot_firmware = prot_firmware?;

        let signed_hashes = SignedHashes::new(
            sign_key,
            [
                &version.to_be_bytes(),
                prot_release_msg.header.as_ref(),
                &prot_release_msg.len.to_be_bytes(),
                release_msg.as_bytes(),
                prot_firmware.header.as_ref(),
                &prot_firmware.len.to_be_bytes(),
                firmware,
            ],
        );

        Ok(FirmwarePackage {
            signed_hashes,
            version,
            release_msg: prot_release_msg,
            firmware: prot_firmware,
        })
    }

    /// Verifies the authenticity of this firmware package with the provided [`VerifyingKey`].
    pub fn verify(&self, verifier_key: &VerifyingKey) -> Result<()> {
        ensure!(
            0 < self.firmware.len && self.firmware.len <= 1041 * 16,
            "encrypted firmware must be nonempty and fit in 16 encrypted chunks, got {}",
            self.firmware.len
        );
        ensure!(
            self.release_msg.len <= 1041,
            "encrypted release message must fit in 1 encrypted chunk, got {}",
            self.release_msg.len,
        );
        self.signed_hashes.verify(verifier_key)?;
        verify_hash(
            &self.version.to_be_bytes(),
            &self.signed_hashes.components[0].hash,
        )?;

        // ignore ciphertext for each since hashes are based on plaintext
        self.release_msg
            .verify_hashes(&self.signed_hashes.components[1..3])?;
        self.firmware
            .verify_hashes(&self.signed_hashes.components[4..6])?;
        Ok(())
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        format_bytes!(
            self.signed_hashes.to_bytes(),
            self.version.to_be_bytes(),
            self.release_msg.to_bytes(),
            self.firmware.to_bytes()
        )
    }

    /// Send raw bytes.
    pub fn send(&self, sock: &mut Socket) -> Result<()> {
        self.signed_hashes.send(sock)?;
        sock.ready_send(&self.version.to_be_bytes())?;
        self.release_msg.send(sock)?;
        self.firmware.send(sock)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::BlakeHash;
    use crate::FirmwarePackage;
    use crypto_secretstream::{Header, Key};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use std::io::Read;

    fn init() -> (FirmwarePackage, VerifyingKey) {
        let enc_key = Key::generate(&mut rand::thread_rng());
        let sign_key = SigningKey::random(&mut rand::thread_rng());
        let verifier_key = VerifyingKey::from(&sign_key);
        let raw_firmware = include_bytes!(env!("FIRMWARE_TEST"));
        (
            FirmwarePackage::new(
                0,
                "release message",
                raw_firmware.as_slice(),
                &sign_key,
                &enc_key,
            )
            .unwrap(),
            verifier_key,
        )
    }

    #[test]
    fn round_trip() {
        let (fw, verifying_key) = init();
        let bytes = bincode::serialize(&fw).unwrap();
        let new_fw: FirmwarePackage = bincode::deserialize(&bytes).unwrap();
        assert!(new_fw.verify(&verifying_key).is_ok());
        assert_eq!(fw, new_fw, "Testing Bytes Conversion using Valid Data:");
    }

    #[test]
    fn corrupt() {
        let (mut fw, verifying_key) = init();
        assert!(fw.verify(&verifying_key).is_ok());
        fw.signed_hashes.components[0].hash[0] =
            fw.signed_hashes.components[0].hash[0].wrapping_add(1);
        assert!(fw.verify(&verifying_key).is_err());
    }

    #[test]
    fn raw_bytes() {
        let (firmware, _) = init();
        let bytes = firmware.to_bytes();
        let mut bytes = bytes.as_slice();

        let mut hash = [0u8; 32];
        let mut signature = [0u8; std::mem::size_of::<Signature>()];

        bytes.read_exact(&mut signature).unwrap();
        bytes.read_exact(&mut hash).unwrap();

        // verify top-level
        assert_eq!(
            Signature::try_from(signature.as_slice()).unwrap(),
            firmware.signed_hashes.top_level.signature,
            "Top-level Signature"
        );
        assert_eq!(
            BlakeHash::from(hash),
            firmware.signed_hashes.top_level.hash,
            "Top-level Hash"
        );

        // verify component signatures / hashes
        for c in firmware.signed_hashes.components {
            bytes.read_exact(&mut signature).unwrap();
            bytes.read_exact(&mut hash).unwrap();
            assert_eq!(
                Signature::try_from(signature.as_slice()).unwrap(),
                c.signature,
                "Component Signature"
            );
            assert_eq!(BlakeHash::from(hash), c.hash, "Component Hash");
        }

        // version
        let mut version = [0u8; 4];
        bytes.read_exact(&mut version).unwrap();
        assert_eq!(u32::from_be_bytes(version), firmware.version);

        let mut header = [0u8; Header::BYTES];
        let mut len = [0u8; 4];

        // verify release message
        bytes.read_exact(&mut header).unwrap();
        bytes.read_exact(&mut len).unwrap();

        let mut ciphertext = vec![0u8; u32::from_be_bytes(len) as usize];
        bytes.read_exact(ciphertext.as_mut_slice()).unwrap();

        assert_eq!(Header::from(header), firmware.release_msg.header, "Header");
        assert_eq!(u32::from_be_bytes(len), firmware.release_msg.len, "Length");
        assert_eq!(ciphertext, firmware.release_msg.ciphertext, "Ciphertext");

        // verify firmware
        bytes.read_exact(&mut header).unwrap();
        bytes.read_exact(&mut len).unwrap();

        let mut ciphertext = vec![0u8; u32::from_be_bytes(len) as usize];
        bytes.read_exact(ciphertext.as_mut_slice()).unwrap();

        assert_eq!(Header::from(header), firmware.firmware.header, "Header");
        assert_eq!(u32::from_be_bytes(len), firmware.firmware.len, "Length");
        assert_eq!(ciphertext, firmware.firmware.ciphertext, "Ciphertext");
    }
}
