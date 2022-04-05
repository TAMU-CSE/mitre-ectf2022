use crate::buffer::Buffer;
use crate::error::{Error, Result};
use crate::package::CFG_TARGET;
use crate::peripherals::Uart;
use tm4c123x_hal::tm4c123x::FLASH_CTRL;

/// High-level interface for writing to flash memory.
pub struct Flash(pub FLASH_CTRL);

impl Flash {
    /// The size of a single page in flash memory, in bytes.
    pub const PAGE_SIZE: usize = 1024;
    // The TivaWare library uses `0xA442` for the flash write key, but `tm4c123x` performs bitwise operations that alter the `u16` we pass to FMC, so we have to adjust the key accordingly.
    const WRKEY: u16 = 0x5221;
    /// Writes a single word into flash memory at the specified address.
    ///
    /// Adapted from `flash.c` in the reference implementation.
    #[link_section = ".data"]
    pub fn write_word(&mut self, word: u32, addr: usize) -> Result<()> {
        // Verify address is 4-byte aligned.
        if addr & 0x3 != 0 {
            return Err(Error::UnalignedFlash);
        }

        // Clear flash access and error interrupts.
        self.0.fcmisc.write(|w| {
            w.amisc()
                .set_bit()
                .voltmisc()
                .set_bit()
                .invdmisc()
                .set_bit()
                .progmisc()
                .set_bit()
        });

        // Set address.
        self.0
            .fma
            .write(|w| unsafe { w.offset().bits(addr as u32) });

        // set data
        self.0.fmd.write(|w| unsafe { w.bits(word) });

        // Set memory write key and write bit.
        self.0
            .fmc
            .write(|w| unsafe { w.write().set_bit().wrkey().bits(Self::WRKEY) });

        // Wait for write bit to be cleared.
        while self.0.fmc.read().write().bit_is_set() {}

        let status = self.0.fcris.read();

        if status.aris().bit_is_set()
            || status.voltris().bit_is_set()
            || status.invdris().bit_is_set()
            || status.progris().bit_is_set()
        {
            Err(Error::InvalidFlashAccess)
        } else {
            Ok(())
        }
    }
    /// Writes the provided words to flash memory, starting from the provided address.
    #[link_section = ".data"]
    pub fn write_words(&mut self, words: &[u32], addr: usize) -> Result<()> {
        for (addr, word) in (addr..).step_by(4).zip(words.iter().copied()) {
            self.write_word(word, addr)?;
        }
        Ok(())
    }
    #[link_section = ".data"]
    /// Erases a page of flash memory. The provided address is rounded down to the nearest page.
    ///
    /// Adapted from `FlashErase` of the TivaWare library.
    pub fn erase_page(&mut self, addr: usize) -> Result<()> {
        // Align address.
        let addr = addr & !(Flash::PAGE_SIZE as usize - 1);

        // Clear flash access and error interrupts.
        self.0
            .fcmisc
            .write(|w| w.amisc().set_bit().voltmisc().set_bit().ermisc().set_bit());

        // Erase block.
        self.0.fma.write(|w| unsafe { w.bits(addr as u32) });
        self.0
            .fmc
            .write(|w| unsafe { w.wrkey().bits(Self::WRKEY).erase().set_bit() });

        // Wait until the block is erased.
        while self.0.fmc.read().erase().bit_is_set() {}

        let status = self.0.fcris.read();
        if status.aris().bit_is_set()
            || status.voltris().bit_is_set()
            || status.erris().bit_is_set()
        {
            Err(Error::InvalidFlashAccess)
        } else {
            Ok(())
        }
    }

    /// Reads data from UART and writes it directly to flash memory.
    #[link_section = ".data"]
    pub fn load_data(&mut self, uart: &mut Uart, mut dst: usize, mut len: usize) -> Result<()> {
        let mut page = Buffer::new();

        while len > 0 {
            // initialize page
            let chunk_len = len.min(Flash::PAGE_SIZE as usize);
            page.fill_from_uart(uart, chunk_len)?;
            let words = page.padded_flash_words()?;

            // write to flash
            self.erase_page(dst)?;
            self.write_words(words, dst)?;

            dst += Flash::PAGE_SIZE as usize;
            len -= chunk_len;
        }

        Ok(())
    }
    /// Disables flash modifications for all blocks up until the regions necessary for storing
    /// package data. This is called by the first stage, so this is _not_ in `.data`.
    pub fn disable_writes(&mut self) {
        // FMPPE0: 0 to 64 KB
        // FMPPE1: 65 to 128 KB
        // FMPPE2: 129 to 192 KB
        // FMPPE3: 193 to 256 KB
        // SAFETY: The writable regions in flash start at 0x0001_9000 and go to the end.
        // We want to forbid writes to all prior blocks, so 0x0001_9000 / 1024 = 100 KB.
        // A flash block is 2 KB, so 100 KB / 2KB = 50 blocks. Thus, we need to unset the
        // first 50 = 32 + 18 bits, so FMPPE0 needs to be zeroed, and FMPPE1 needs to have
        // its lower 18 bits zeroed.
        self.0.fmppe0.write(|w| unsafe { w.bits(0) });
        self.0
            .fmppe1
            .modify(|r, w| unsafe { w.bits(r.bits() & 0xFFFC0000) });
    }
    /// Erases all flash pages mapped to the decrypted configuration.
    #[link_section = ".data"]
    pub fn erase_decrypted_cfg(&mut self) -> Result<()> {
        for addr in (CFG_TARGET..).step_by(Self::PAGE_SIZE).take(64) {
            self.erase_page(addr)?;
        }
        Ok(())
    }
}
