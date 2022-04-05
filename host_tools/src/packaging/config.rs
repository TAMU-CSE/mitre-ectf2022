use crate::{format_bytes, DynComp, SignedHashes, Socket};
use color_eyre::{eyre::ensure, Result};
use crypto_secretstream::Key;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A config update consists of a raw config binary that is dynamically sized and has a
/// confidentiality requirement.
/// This effectively wraps a single [`DynComp`] instance for the raw config and includes three
/// [`SignedHash`] instances for each component in [`DynComp`].
/// Since [`DynComp`] encrypts raw data, the confidentiality requirement for config is met,
/// and the [`SignedHashes`] ensures integrity and authenticity for the entire protected package.
///
/// [`SignedHash`]: crate::SignedHash
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ConfigPackage {
    pub signed_hashes: SignedHashes<3>,
    pub config: DynComp,
}

impl ConfigPackage {
    /// Creates a protected config package.
    pub fn new(config: &[u8], sign_key: &SigningKey, enc_key: &Key) -> Result<ConfigPackage> {
        ensure!(
            !config.is_empty() && config.len() <= 1024 * 64,
            "config must be nonempty and fit in 64 KB, got {}",
            config.len()
        );
        let prot_config = DynComp::new(config, enc_key)?;

        let signed_hashes = SignedHashes::new(
            sign_key,
            [
                prot_config.header.as_ref(),
                &prot_config.len.to_be_bytes(),
                config,
            ],
        );

        Ok(ConfigPackage {
            signed_hashes,
            config: prot_config,
        })
    }

    /// Verify signatures.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        ensure!(
            self.config.len <= 1041 * 64,
            "encrypted config must fit within 64 encrypted chunks, got {}",
            self.config.len
        );
        self.signed_hashes.verify(verifying_key)?;
        self.config.verify_hashes(&self.signed_hashes.components)?;
        Ok(())
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        format_bytes!(self.signed_hashes.to_bytes(), self.config.to_bytes())
    }

    /// Send raw bytes.
    pub fn send(&self, sock: &mut Socket) -> Result<()> {
        self.signed_hashes.send(sock)?;
        self.config.send(sock)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlakeHash;
    use crypto_secretstream::Header;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use std::io::Read;
    use std::mem::size_of;

    fn init() -> (ConfigPackage, VerifyingKey) {
        let enc_key = Key::generate(&mut rand::thread_rng());
        let sign_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&sign_key);

        let raw_config = include_bytes!(env!("CONFIG_TEST"));

        (
            ConfigPackage::new(raw_config.as_slice(), &sign_key, &enc_key).unwrap(),
            verifying_key,
        )
    }

    #[test]
    fn round_trip() {
        let (config, verifying_key) = init();
        let bytes = bincode::serialize(&config).unwrap();
        let new_config: ConfigPackage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(config, new_config);
        assert!(new_config.verify(&verifying_key).is_ok());
    }

    #[test]
    fn corrupt() {
        let (mut config, verifying_key) = init();
        assert!(config.verify(&verifying_key).is_ok());
        config.signed_hashes.components[0].hash[0] =
            config.signed_hashes.components[0].hash[0].wrapping_add(1);
        assert!(config.verify(&verifying_key).is_err());
    }

    #[test]
    fn raw_bytes() {
        let (config, _) = init();
        let bytes = config.to_bytes();
        let mut bytes = bytes.as_slice();

        let mut hash = [0u8; 32];
        let mut signature = [0u8; size_of::<Signature>()];

        // verify top-level
        bytes.read_exact(&mut signature).unwrap();
        bytes.read_exact(&mut hash).unwrap();
        assert_eq!(
            Signature::try_from(signature.as_slice()).unwrap(),
            config.signed_hashes.top_level.signature,
            "Top-level Signature"
        );
        assert_eq!(
            BlakeHash::from(hash),
            config.signed_hashes.top_level.hash,
            "Top-level Hash"
        );

        // verify component signatures / hashes
        for c in config.signed_hashes.components {
            bytes.read_exact(&mut signature).unwrap();
            bytes.read_exact(&mut hash).unwrap();
            assert_eq!(
                Signature::try_from(signature.as_slice()).unwrap(),
                c.signature,
                "Component Signature"
            );
            assert_eq!(BlakeHash::from(hash), c.hash, "Component Hash");
        }

        let mut header = [0u8; Header::BYTES];
        let mut length = [0u8; 4];

        // verify config
        bytes.read_exact(&mut header).unwrap();
        bytes.read_exact(&mut length).unwrap();

        let mut ciphertext = vec![0u8; u32::from_be_bytes(length) as usize];
        bytes.read_exact(ciphertext.as_mut_slice()).unwrap();

        assert_eq!(Header::from(header), config.config.header, "Header");
        assert_eq!(u32::from_be_bytes(length), config.config.len, "Length");
        assert_eq!(ciphertext, config.config.ciphertext, "Ciphertext");
    }
}
