use super::Eeprom;
use crate::error::Result;
use crate::size;
/// Helper trait for making (de)serialization of types to/from EEPROM easier.
///
/// # Safety
/// Implementors of this trait must uphold the following invariants:
/// 1. `align_of<T>() == align_of::<u32>()`
/// 2. `size_of<T>() % 4 == 0`
/// 3. The all-zero byte pattern must be a valid instance of `T`.
/// 4. There are no padding bytes within or in between fields.
/// 5. Offsets of different implementors should not overlap.
pub unsafe trait Primitive: Sized {
    /// Offset of the type in EEPROM memory.
    const OFFSET: usize;
    /// Safe wrapper around [`core::mem::zeroed`].
    fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
    /// Safe mutable access to the type as a `&mut [u32]`.
    fn as_words_mut(&mut self) -> &mut [u32] {
        let ptr = self as *mut _ as *mut u32;
        let len = size!(Self) / size!(u32);
        // SAFETY: Implementors promise to uphold invariants #1, #2, and #4.
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
    /// Safe shared access to the type as a `&[u32]`.
    fn as_words(&self) -> &[u32] {
        let ptr = self as *const _ as *const u32;
        let len = size!(Self) / size!(u32);
        // SAFETY: Implementors promise to uphold invariants #1, #2, and #4.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
    /// Safe mutable access to the type as a `&mut [u8]`.
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let ptr = self as *mut _ as *mut u8;
        let len = size!(Self);
        // SAFETY: Implementors promise to uphold invariant #4.
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
    /// Safe shared access to the type as a `&[u8]`.
    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const _ as *const u8;
        let len = size!(Self);
        // SAFETY: Implementors promise to uphold invariant #4.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
    /// Load an instance of this type from EEPROM memory.
    fn load(eeprom: &Eeprom) -> Result<Self> {
        let mut this = Self::zeroed();
        let words = Self::as_words_mut(&mut this);
        eeprom.read(words, Self::OFFSET)?;
        Ok(this)
    }
    /// Store an instance of this type into EEPROM memory at the specified offset.
    fn store_raw(&self, eeprom: &Eeprom, offset: usize) -> Result<()> {
        eeprom.write(self.as_words(), offset)?;
        Ok(())
    }
    /// Store an instance of this type into EEPROM memory.
    fn store(&self, eeprom: &Eeprom) -> Result<()> {
        self.store_raw(eeprom, Self::OFFSET)
    }
}
