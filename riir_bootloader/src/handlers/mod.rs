//! Routines for handling commands sent from host-tools.

mod boot;
mod cfg_load;
mod fw_update;
mod readback;

pub use boot::boot;
pub use cfg_load::configure;
pub use fw_update::update;
pub use readback::readback;
