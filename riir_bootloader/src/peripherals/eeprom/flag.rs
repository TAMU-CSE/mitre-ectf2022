use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
/// Opaque wrapper for a boolean flag. Internally, the bit patterns for `true` and `false` have a maximally large
/// Hamming distance to make error detection easier.
pub struct Flag(u32);

impl Flag {
    /// True.
    pub const TRUE: Self = Self(0b0101_0101_0101_0101);
    /// False.
    pub const FALSE: Self = Self(0b1010_1010_1010_1010);
}

/// Firmware update flag.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct FwFlag {
    pub is_updated: Flag,
}

/// Config update flag.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct CfgFlag {
    pub is_updated: Flag,
}

impl_primitive!(FW_FLAG_OFFSET, FwFlag, Flag);
impl_primitive!(CFG_FLAG_OFFSET, CfgFlag, Flag);
