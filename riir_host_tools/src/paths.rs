use std::path::{Path, PathBuf};

/// Prepends the config path.
pub fn config_path(path: impl AsRef<Path>) -> PathBuf {
    let mut ret = PathBuf::from(env!("CONFIG_PATH"));
    ret.push(path);
    ret
}

/// Prepends the firmware path.
pub fn firmware_path(path: impl AsRef<Path>) -> PathBuf {
    let mut ret = PathBuf::from(env!("FIRMWARE_PATH"));
    ret.push(path);
    ret
}

/// Prepends release message path.
pub fn release_msgs_path(path: impl AsRef<Path>) -> PathBuf {
    let mut ret = PathBuf::from(env!("MESSAGES_PATH"));
    ret.push(path);
    ret
}
