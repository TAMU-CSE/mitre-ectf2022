//! Provides generalized interfaces for creating protected images.
//!
//! A protected image consists of signed hashes and components.
//! Components can either be metadata on raw data or raw data itself.
//! If a component is statically sized and can be transmitted in plaintext, it only needs a [`SignedHash`].
//! Otherwise, if the a component includes dynamically sized data or needs to be encrypted, [`DynComp`]
//! is used to package the dynamically sized data with necessary metadata for processing.
//! [`DynComp`] ensures confidentiality for sensitive data.
//!
//! Each component is associated with a [`SignedHash`] which ensures the integrity and authenticity of the component.
//! A complete package will likely have multiple components, dynamically sized components ([`DynComp`]),
//! and associated signed hashes.
//! Each [`SignedHash`] in a complete package is aggregated in [`SignedHashes`], where a top-level [`SignedHash`]
//! is computed.
//! This ensures the integrity and authenticity of the package as a single unit, thus completing the creation
//! of a protected package.

use crate::{format_bytes, Socket, FLASH_PAGE_SIZE, MAC_SIZE, TAG_SIZE};
use blake2::{digest::consts::U32, digest::generic_array::GenericArray, Blake2s256, Digest};
use color_eyre::{
    eyre::{ensure, eyre},
    Result,
};
use crypto_secretstream::{Header, Key, PushStream, Tag};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};

/// Utility function generating a [`Blake2s256`] hash.
pub fn oneshot_hash(data: &[u8]) -> BlakeHash {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize()
}

/// General utility function to verify data integrity using hashes.
pub fn verify_hash(data: &[u8], hash: &BlakeHash) -> Result<()> {
    ensure!(hash == &oneshot_hash(data), "hash mismatch");
    Ok(())
}

/// A [`Blake2s256`] digest.
pub type BlakeHash = GenericArray<u8, U32>;

/// Provides authenticity and integrity for a single component.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SignedHash {
    pub signature: Signature,
    pub hash: BlakeHash,
}

impl SignedHash {
    /// Create new signed hash instance given a blake hash and signing key.
    pub fn new(hash: BlakeHash, sign_key: &SigningKey) -> Self {
        Self {
            hash,
            signature: sign_key.sign(&hash),
        }
    }

    /// Verify signatures.
    pub fn verify(&self, verifier_key: &VerifyingKey) -> Result<()> {
        verifier_key
            .verify(&self.hash, &self.signature)
            .map_err(|_| eyre!("signature verification error"))
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // we want to verify signature first, then accept the hash
        format_bytes!(self.signature, self.hash)
    }

    /// Synced writes to bootloader sending signature and hash
    pub fn send(&self, s: &mut Socket) -> Result<()> {
        s.ready_send(self.signature.as_ref())?;
        s.ready_send(self.hash.as_slice())?;
        Ok(())
    }
}

/// Generic collection of [`SignedHash`] instances ensuring authenticity and integrity for each
/// protected component in a protected package.
/// A top-level [`SignedHash`] is automatically computed, ensuring authenticity and integrity for
/// all the component [`SignedHash`] instances.
/// The top-level [`SignedHash`] collects each [`SignedHash`] instance and defines this collection
/// as a single protected package that cannot be tampered with (mix-and-match).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SignedHashes<const N: usize> {
    pub top_level: SignedHash,
    #[serde(with = "serde_big_array::BigArray")]
    pub components: [SignedHash; N],
}

impl<const N: usize> SignedHashes<N> {
    /// Create a new instance of [`SignedHashes`] with `N` components and a top-level.
    pub fn new(sign_key: &SigningKey, data: [&[u8]; N]) -> SignedHashes<N> {
        let mut top_hasher = Blake2s256::new();
        let components = data.map(|c| {
            let hash = oneshot_hash(c);
            top_hasher.update(&hash);
            SignedHash::new(hash, sign_key)
        });
        Self {
            top_level: SignedHash::new(top_hasher.finalize(), sign_key),
            components,
        }
    }

    /// Verifies signatures for component hashes, then computes and verifies the top-level hash.
    pub fn verify(&self, verifier_key: &VerifyingKey) -> Result<()> {
        let mut hasher = Blake2s256::new();
        for c in &self.components {
            c.verify(verifier_key)?;
            hasher.update(&c.hash);
        }
        ensure!(
            hasher.finalize() == self.top_level.hash,
            "hashes must match"
        );
        Ok(())
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity((32 * (N + 1)) + (64 * (N + 1)));
        bytes.extend(self.top_level.to_bytes());
        self.components
            .iter()
            .for_each(|c| bytes.extend(c.to_bytes()));
        bytes
    }

    /// High-level interface abstracting synced writes with bootloader
    pub fn send(&self, s: &mut Socket) -> Result<()> {
        self.top_level.send(s)?;
        for c in &self.components {
            c.send(s)?;
        }
        Ok(())
    }
}

/// Dynamically sized components are described by this struct.
/// The data for this section is encrypted and thus requires a nonce.
/// Additionally, a length header is calculated to inform on the size.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct DynComp {
    pub header: Header,
    pub len: u32,
    pub ciphertext: Vec<u8>,
}

impl DynComp {
    /// Creates a new [`DynComp`].
    pub fn new(data: &[u8], key: &Key) -> Result<DynComp> {
        let (header, mut push_stream) = PushStream::init(&mut rand::thread_rng(), key);
        let mut ciphertext = Vec::<u8>::with_capacity(4096);
        let mut buf = Vec::<u8>::with_capacity(FLASH_PAGE_SIZE + MAC_SIZE + TAG_SIZE);
        for chunk in data.chunks(FLASH_PAGE_SIZE) {
            buf.clear();
            buf.extend_from_slice(chunk);
            push_stream
                .push(&mut buf, &[], Tag::Message)
                .map_err(|_| eyre!("stream encryption error"))?;
            ciphertext.extend_from_slice(&buf);
        }

        Ok(DynComp {
            header,
            len: ciphertext.len() as u32,
            ciphertext,
        })
    }

    /// Verify integrity of components using hashes
    pub fn verify_hashes(&self, hashes: &[SignedHash]) -> Result<()> {
        verify_hash(self.header.as_ref(), &hashes[0].hash)?;
        verify_hash(self.len.to_be_bytes().as_slice(), &hashes[1].hash)?;
        Ok(())
    }

    /// Convert to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        format_bytes!(self.header, self.len.to_be_bytes(), self.ciphertext)
    }

    /// High-level interface abstracting synced writes with bootloader
    pub fn send(&self, sock: &mut Socket) -> Result<()> {
        sock.ready_send(self.header.as_ref())?;
        sock.ready_send(&self.len.to_be_bytes())?;

        for c in self.ciphertext.chunks(FLASH_PAGE_SIZE) {
            sock.ready_send(c)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> (VerifyingKey, SignedHashes<3>, DynComp, &'static [u8]) {
        // initialize some data and generate secrets
        let data = b"some data";
        let enc_key = Key::generate(&mut rand::thread_rng());
        let sign_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&sign_key);

        // creating package
        let prot_image = DynComp::new(data, &enc_key).unwrap();

        let signed_hashes = SignedHashes::new(
            &sign_key,
            [
                prot_image.header.as_ref(),
                &prot_image.len.to_be_bytes(),
                data,
            ],
        );
        (verifying_key, signed_hashes, prot_image, data)
    }

    #[test]
    fn round_trip() {
        let (verifying_key, signed_hashes, img, data) = init();
        // verifying signatures
        signed_hashes.top_level.verify(&verifying_key).unwrap();
        signed_hashes
            .components
            .iter()
            .for_each(|c| c.verify(&verifying_key).unwrap());

        // verifying top-level hash
        let mut hasher = Blake2s256::new();
        signed_hashes
            .components
            .iter()
            .for_each(|c| hasher.update(&c.hash));
        assert_eq!(signed_hashes.top_level.hash, hasher.finalize(), "Top-Level");

        // verify component hashes
        assert_eq!(
            signed_hashes.components[0].hash,
            oneshot_hash(img.header.as_ref()),
            "Component 0: Header"
        );

        assert_eq!(
            signed_hashes.components[1].hash,
            oneshot_hash(&img.len.to_be_bytes()),
            "Component 2: Length Header"
        );

        assert_eq!(
            signed_hashes.components[2].hash,
            oneshot_hash(data),
            "Component 3: Plaintext Data"
        );

        // instantiate from bytes
        let bytes = bincode::serialize(&img).unwrap();
        let new_comp: DynComp = bincode::deserialize(&bytes).unwrap();
        assert!(new_comp.verify_hashes(&signed_hashes.components).is_ok());
        assert_eq!(img, new_comp, "Dynamic Components:");

        let bytes = bincode::serialize(&signed_hashes).unwrap();
        let new_hashes: SignedHashes<3> = bincode::deserialize(&bytes).unwrap();
        assert!(new_hashes.verify(&verifying_key).is_ok());
        assert_eq!(signed_hashes, new_hashes, "Signed Hashes:");
    }

    #[test]
    fn corrupt() {
        let mut header = Header(GenericArray::from([0u8; 24]));
        header.0[0] += 1;
        let (verifying_key, mut signed_hashes, mut img, _) = init();
        assert!(img.verify_hashes(&signed_hashes.components).is_ok());
        img.len = img.len.wrapping_add(1);
        assert!(img.verify_hashes(&signed_hashes.components).is_err());
        signed_hashes.components[0].hash[0] = signed_hashes.components[0].hash[0].wrapping_add(1);
        assert!(signed_hashes.verify(&verifying_key).is_err());
    }
}
