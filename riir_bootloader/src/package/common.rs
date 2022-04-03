use crate::crypto::BlakeHash;
use crate::crypto::{jitter, verify_hash};
use crate::error::{Error, Result};
use crate::peripherals::uart::FRAME_OK;
use crate::peripherals::Peripherals;
use crate::size;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::XNonce;
use crypto_secretstream::Header;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand_chacha::{rand_core::RngCore, ChaChaRng};

/// Verifies the authenticity of the host-tools currently communicating with the bootloader.
///
/// # Implementation Details
/// 1. An acknowledgement byte is sent back to the host-tools.
/// 2. A random challenge nonce is generated and sent to the host-tools.
/// 3. The response signature issued by host-tools is received.
/// 4. The signature is verified against the provided [`VerifyingKey`].
#[link_section = ".data"]
pub fn authenticate(
    p: &mut Peripherals,
    verifier_key: &VerifyingKey,
    r: &mut ChaChaRng,
) -> Result<()> {
    p.uart.write_u8(FRAME_OK);
    let mut nonce = [0u8; size!(XNonce)];
    r.fill_bytes(&mut nonce);
    p.uart.write_all(&nonce);
    let raw_signature = p
        .uart
        .ready_nonblocking_read_arr::<{ size!(Signature) }>()?;
    let signature = Signature::try_from(raw_signature.as_slice())?;
    jitter(r);
    verifier_key.verify(&nonce, &signature)?;
    Ok(())
}

/// Wrapper around component hashes of a package sent over UART.
pub struct Hashes<const N: usize> {
    pub components: [BlakeHash; N],
}

impl<const N: usize> Hashes<N> {
    /// Simultaneously reads and verifies component hashes from UART.
    #[link_section = ".data"]
    pub fn new(
        p: &mut Peripherals,
        r: &mut ChaChaRng,
        verifier_key: &VerifyingKey,
    ) -> Result<Hashes<N>> {
        // common buffers
        let mut top_level_hash = [0u8; 32];
        let mut signature_bytes = [0u8; size!(Signature)];
        let mut component_hashes = [BlakeHash::from([0u8; 32]); N];
        let mut hasher = Blake2s256::new();

        // top level hash
        p.uart.ready_nonblocking_read_exact(&mut signature_bytes)?;
        p.uart.ready_nonblocking_read_exact(&mut top_level_hash)?;
        let signature = Signature::try_from(signature_bytes.as_slice())?;
        jitter(r);
        verifier_key.verify(&top_level_hash, &signature)?;
        let top_level = BlakeHash::from(top_level_hash);

        for c in &mut component_hashes {
            p.uart.ready_nonblocking_read_exact(&mut signature_bytes)?;
            p.uart.ready_nonblocking_read_exact(c)?;
            let signature = Signature::try_from(signature_bytes.as_slice())?;
            jitter(r);
            verifier_key.verify(c, &signature)?;
        }

        for hash in &component_hashes {
            hasher.update(hash);
        }

        if hasher.finalize() != top_level {
            Err(Error::InvalidHash)
        } else {
            Ok(Hashes {
                components: component_hashes,
            })
        }
    }
}

/// Metadata for dynamically-sized components sent by host-tools.
pub struct DynCompMeta {
    /// Decryption header.
    pub header: Header,
    /// Length of _ciphertext_ (not plaintext!)
    pub len: u32,
}

impl DynCompMeta {
    /// Simultaneously reads and verifies dynamically-sized component metadata from UART.
    #[link_section = ".data"]
    pub fn new(
        p: &mut Peripherals,
        r: &mut ChaChaRng,
        header_hash: &BlakeHash,
        len_hash: &BlakeHash,
    ) -> Result<DynCompMeta> {
        let header: Header = p.uart.ready_nonblocking_read_arr()?.into();
        verify_hash(header.as_ref(), header_hash, r)?;

        let len = p.uart.ready_nonblocking_read_be_u32()?;
        verify_hash(&len.to_be_bytes(), len_hash, r)?;

        Ok(DynCompMeta { header, len })
    }
}
