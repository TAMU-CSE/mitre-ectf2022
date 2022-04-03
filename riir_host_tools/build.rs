use chacha20poly1305::Key;
use p256::ecdsa::{SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::mem::size_of;
use std::path::PathBuf;
use crypto_secretstream::Key as StreamKey;

fn gen_keypair() -> (SigningKey, VerifyingKey) {
    let private = SigningKey::random(&mut rand::thread_rng());
    let public = VerifyingKey::from(&private);
    (private, public)
}

fn main() {
    #[cfg(feature = "production")]
    let root = PathBuf::from("/");
    #[cfg(not(feature = "production"))]
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned();
    // register paths
    let paths = [
        // secrets
        ("PRIVILEGED_SIG", "secrets/privileged_sig"),
        ("PRIVILEGED_PUB", "secrets/privileged_sig.pub"),
        ("UNPRIVILEGED_SIG", "secrets/unprivileged_sig"),
        ("UNPRIVILEGED_PUB", "secrets/unprivileged_sig.pub"),
        ("IMAGE_SYMMETRIC", "secrets/image-symmetric.key"),
        ("MULTI_STAGE_SYMMETRIC", "secrets/multi-stage-symmetric.key"),
        ("EEPROM_SYMMETRIC", "secrets/eeprom-symmetric.key"),
        // paths
        ("CONFIG_PATH", "configuration"),
        ("FIRMWARE_PATH", "firmware"),
        ("MESSAGES_PATH", "messages"),
        // testing
        ("CONFIG_TEST", "configuration/example_cfg.bin"),
        ("FIRMWARE_TEST", "firmware/example_fw.bin"),
    ]
    .into_iter()
    .map(|(k, v)| (k, root.join(v)))
    .collect::<HashMap<_, _>>();

    // ignore errors if the directory already exists
    let _ = std::fs::create_dir(root.join("secrets"));
    let _ = std::fs::create_dir(&paths["MESSAGES_PATH"]);

    // create privileged signing keypair for use by privileged host-tool operations
    let (private, public) = gen_keypair();
    std::fs::write(&paths["PRIVILEGED_SIG"], private.to_bytes()).unwrap();
    std::fs::write(&paths["PRIVILEGED_PUB"], public.to_encoded_point(false)).unwrap();

    // create unprivileged signing keypair for use by unprivileged host-tool operations
    let (keypair, public) = gen_keypair();
    std::fs::write(&paths["UNPRIVILEGED_SIG"], keypair.to_bytes()).unwrap();
    std::fs::write(&paths["UNPRIVILEGED_PUB"], public.to_encoded_point(false)).unwrap();

    // create symmetric key for encrypting protected images
    let key = StreamKey::from(rand::random::<[u8; size_of::<StreamKey>()]>());
    std::fs::write(&paths["IMAGE_SYMMETRIC"], key.as_ref()).unwrap();

    // create symmetric key for encrypting 2nd-stage bootloader
    let key = Key::from(rand::random::<[u8; size_of::<Key>()]>());
    std::fs::write(&paths["MULTI_STAGE_SYMMETRIC"], key.as_slice()).unwrap();

    // create symmetric key for encrypting EEPROM
    let key = Key::from(rand::random::<[u8; size_of::<Key>()]>());
    std::fs::write(&paths["EEPROM_SYMMETRIC"], key.as_slice()).unwrap();

    // export paths to environment
    for (name, path) in paths {
        println!("cargo:rustc-env={name}={}", path.display());
    }
}
