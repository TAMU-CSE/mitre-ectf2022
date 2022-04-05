//! This crate provides functionality for post-processing of the generated ELF and raw bootloader binary.
//! This requires access to the `secrets` directory, so this will only work at the secure facility.
//!
//! This is intended to only work within Docker, so all filesystem paths are hardcoded.
//! 
//! It serves two chief purposes:
//! - Encryption of the `.data` section within the raw bootloader binary, which protects the second
//!   stage.
//! - Generation of the EEPROM image, pre-initialized with the necessary keys from `secrets`. Additionally, we
//!   leverage the host's plentiful entropy to generate CSPRNG seeds.

use chacha20poly1305::{Key, Tag, XNonce};
use color_eyre::{
    eyre::{ensure, eyre, Context},
    Result,
};
use crypto_secretstream::{Header, Key as StreamKey};
use goblin::elf::Elf;
use riir_bootloader::crypto::{oneshot_decrypt, oneshot_encrypt, oneshot_hash, BlakeHash};
use riir_bootloader::peripherals::eeprom::*;
use std::{mem::size_of, path::Path};

/// Offsets of symbols inside the provided ELF file.
#[derive(Debug)]
pub struct Offsets {
    sdata: usize,
    edata: usize,
    sidata: usize,
    stext: usize,
    etext: usize,
}

impl Offsets {
    /// Searches for section symbols in the provided ELF file, then returns their offsets.
    pub fn from_elf(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let elf = Elf::parse(&bytes)?;
        let mut sdata = None;
        let mut edata = None;
        let mut sidata = None;
        let mut stext = None;
        let mut etext = None;
        for s in elf.syms.iter() {
            let name = elf
                .strtab
                .get_at(s.st_name)
                .ok_or_else(|| eyre!("missing strtab entry"))?;
            match name {
                "__sdata" => sdata = Some(s),
                "__edata" => edata = Some(s),
                "__sidata" => sidata = Some(s),
                // this is a single underscore on purpose
                "_stext" => stext = Some(s),
                "__etext" => etext = Some(s),
                _ => {}
            }
        }
        let sdata = sdata.ok_or_else(|| eyre!("missing __sdata"))?;
        let edata = edata.ok_or_else(|| eyre!("missing __edata"))?;
        let sidata = sidata.ok_or_else(|| eyre!("missing __sidata"))?;
        let stext = stext.ok_or_else(|| eyre!("missing _stext"))?;
        let etext = etext.ok_or_else(|| eyre!("missing __etext"))?;
        Ok(Self {
            sdata: sdata.st_value as usize,
            edata: edata.st_value as usize,
            sidata: sidata.st_value as usize,
            stext: stext.st_value as usize,
            etext: etext.st_value as usize,
        })
    }
}

/// Creates a new encrypted sector.
fn new_encrypted<T: Primitive>(mut inner: T, key: &Key) -> Result<Encrypted<T>> {
    let nonce = XNonce::from(rand::random::<[u8; size_of::<XNonce>()]>());
    let tag = oneshot_encrypt(inner.as_bytes_mut(), key, &nonce)
        .map_err(|_| eyre!("encryption failure"))?;
    Ok(Encrypted { inner, nonce, tag })
}

/// Verifies the encrypted sector within the image is correct.
fn check_encrypted_sector<T: Primitive>(image: &[u8], original: &T, key: &Key) -> Result<()> {
    let mut decrypted = vec![0u8; size_of::<T>()];
    let source = &image[T::OFFSET..][..size_of::<T>()];
    decrypted.copy_from_slice(source);
    let tag = Tag::from_slice(&image[T::OFFSET + size_of::<T>()..][..size_of::<Tag>()]);
    let nonce = XNonce::from_slice(
        &image[T::OFFSET + size_of::<T>() + size_of::<Tag>()..][..size_of::<XNonce>()],
    );
    oneshot_decrypt(&mut decrypted, key, tag, nonce).map_err(|_| eyre!("decryption error"))?;
    ensure!(original.as_bytes() == decrypted, "bytes must match");
    Ok(())
}

/// Reads the provided file into a public key.
fn read_public_key(path: impl AsRef<Path>) -> Result<[u8; PADDED_PUBLIC_KEY_LEN]> {
    let mut bytes = std::fs::read(path)?;
    ensure!(bytes.len() == SEC1_PUBLIC_KEY_LEN, "sec1-encoded verifying key is 65 bytes");
    // pad with zeros for alignment
    bytes.resize(PADDED_PUBLIC_KEY_LEN, 0);
    bytes.try_into().map_err(|_| eyre!("invalid length"))
}

/// Reads the provided file into a fixed array of bytes.
fn read_to_arr<const N: usize, P>(path: P) -> Result<[u8; N]>
where
    P: AsRef<Path>,
{
    std::fs::read(path)?
        .try_into()
        .map_err(|_| eyre!("invalid length"))
}


fn main() -> Result<()> {
    color_eyre::install()?;
    let oldest_version = std::env::var("OLDEST_VERSION")?.parse::<u32>()?;
    let offsets = Offsets::from_elf("/bootloader/bootloader.elf")?;
    let mut bootloader = std::fs::read("/bootloader/unencrypted_bootloader.bin")?;
    let len = offsets.edata - offsets.sdata;
    let text = &bootloader[offsets.stext..offsets.etext];
    let text_hash = TextHash {
        hash: oneshot_hash(text),
    };
    let nonce = XNonce::from(rand::random::<[u8; size_of::<XNonce>()]>());
    let data = &mut bootloader[offsets.sidata..][..len];
    let eeprom_key = Key::from(read_to_arr("/secrets/eeprom-symmetric.key")?);
    let privileged_key = read_public_key("/secrets/privileged_sig.pub")?;
    let unprivileged_key = read_public_key("/secrets/unprivileged_sig.pub")?;
    let raw_flash_key = read_to_arr("/secrets/image-symmetric.key")?;
    let stage2_key = Key::from(read_to_arr("/secrets/multi-stage-symmetric.key")?);
    let tag =
        oneshot_encrypt(data, &stage2_key, &nonce).map_err(|_| eyre!("encryption failure"))?;
    let stage2_key = Stage2Key {
        key: stage2_key,
        nonce,
        tag,
    };
    let privileged_key = PrivilegedKey {
        raw_key: privileged_key,
    };
    let unprivileged_key = UnprivilegedKey {
        raw_key: unprivileged_key,
    };
    let flash_key = FlashKey {
        key: StreamKey::from(raw_flash_key),
    };
    let flash_key_copy = FlashKey {
        key: StreamKey::from(raw_flash_key),
    };
    let emulator_seed = EmulatorSeed {
        seed: rand::random(),
    };
    let physical_seed = PhysicalSeed {
        seed: rand::random(),
    };
    let fw_meta = FwMeta {
        latest_version: oldest_version,
        msg_len: 0,
        msg_hash: BlakeHash::default(),
        msg_header: Header(Default::default()),
        fw_len: 0,
        fw_hash: BlakeHash::default(),
        fw_header: Header(Default::default()),
    };
    let cfg_meta = CfgMeta {
        len: 0,
        hash: BlakeHash::default(),
        header: Header(Default::default()),
    };
    let fw_flag = FwFlag {
        is_updated: Flag::FALSE,
    };
    let cfg_flag = CfgFlag {
        is_updated: Flag::FALSE,
    };
    let image = EepromLayout {
        stage2_key,
        privileged_key: new_encrypted(privileged_key, &eeprom_key)?,
        unprivileged_key: new_encrypted(unprivileged_key, &eeprom_key)?,
        flash_key: new_encrypted(flash_key, &eeprom_key)?,
        text_hash: new_encrypted(text_hash, &eeprom_key)?,
        emulator_seed: new_encrypted(emulator_seed, &eeprom_key)?,
        physical_seed: new_encrypted(physical_seed, &eeprom_key)?,
        fw_meta: new_encrypted(fw_meta, &eeprom_key)?,
        cfg_meta: new_encrypted(cfg_meta, &eeprom_key)?,
        fw_flag: new_encrypted(fw_flag, &eeprom_key)?,
        cfg_flag: new_encrypted(cfg_flag, &eeprom_key)?,
    };

    let raw = image.as_bytes();
    ensure!(
        &raw[Stage2Key::OFFSET..][..size_of::<Stage2Key>()] == stage2_key.as_bytes(),
        "bytes must match"
    );
    check_encrypted_sector(raw, &privileged_key, &eeprom_key).context("privileged_key")?;
    check_encrypted_sector(raw, &unprivileged_key, &eeprom_key).context("unprivileged_key")?;
    check_encrypted_sector(raw, &flash_key_copy, &eeprom_key).context("flash_key")?;
    check_encrypted_sector(raw, &text_hash, &eeprom_key).context("text_hash")?;
    check_encrypted_sector(raw, &emulator_seed, &eeprom_key).context("emulator seed")?;
    check_encrypted_sector(raw, &physical_seed, &eeprom_key).context("physical seed")?;
    check_encrypted_sector(raw, &fw_meta, &eeprom_key).context("fw_meta")?;
    check_encrypted_sector(raw, &cfg_meta, &eeprom_key).context("cfg_meta")?;
    check_encrypted_sector(raw, &fw_flag, &eeprom_key).context("fw_flag")?;
    check_encrypted_sector(raw, &cfg_flag, &eeprom_key).context("cfg_flag")?;

    std::fs::write("/bootloader/encrypted_bootloader.bin", bootloader)?;
    std::fs::write("/bootloader/eeprom.bin", raw)?;
    println!("Successfully generated EEPROM image and encrypted bootloader with version {oldest_version}!");
    Ok(())
}
