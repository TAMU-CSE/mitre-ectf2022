//! The bootloader is comprised of two main stages, along with a short initialization stage within
//! the reset handler.
//!
//! ## Reset Handler
//!
//! The reset handler is provided by the [`cortex_m_rt`] crate and resides in flash at `0x5800`.
//! This is the very first thing that executes (barring MITRE bootstrapper code).
//!
//! ### Implementation Details
//!
//! 1. The stack pointer is reinitialized.
//! 2. The `.data` section is copied from flash to SRAM.
//! 3. The `.bss` section is zeroed in SRAM.
//! 4. [`stage1`] is executed.
//!
//! ## Stage 1
//! The first stage is the initial entry point to the bootloader and is responsible for setting up
//! the second stage. See [`stage1`] for more.
//!
//! ## Stage 2
//! The second stage contains the core logic for interacting with the host-tools. See [`stage2`]
//! for more.
#![no_std]
#![no_main]

use core::arch::asm;
use cortex_m::peripheral::DWT;
use cortex_m_rt::{entry, pre_init};
#[cfg(feature = "panic-halt")]
use panic_halt as _;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use riir_bootloader::error::{Error, Result};
use riir_bootloader::package::{FW_TARGET, MAX_DECRYPTED_FW_LEN};
use riir_bootloader::peripherals::eeprom::{EmulatorSeed, PhysicalSeed, Primitive, Stage2Key};
use riir_bootloader::peripherals::uart::{FRAME_BAD, FRAME_OK};
use riir_bootloader::peripherals::Peripherals;
use riir_bootloader::verify_stage1;
use riir_bootloader::{crypto, handlers};

/// Resets the stack pointer to the end of available SRAM.
///
/// # Safety
///
/// Setting the stack pointer ourselves is necessary because the MITRE bootstrapper code doesn't respect our provided offset.
/// We've manually verified that all functions up until `main` are executed via `bl`, so the return addresses are not corrupted -- they are safe inside the link register.
#[pre_init]
unsafe fn reset_sp() {
    let stack_top = 0x2000_4000_u32;
    asm!("msr MSP, {stack_top}", stack_top = in(reg) stack_top);
}

/// Initial entry point. This immediately delegates to [`stage1`].
#[entry]
fn main() -> ! {
    let _ = stage1();
    panic!("returning from stage 1 is an irrecoverable error");
}

/// Decrypts the second stage.
pub fn decrypt_stage2(p: &mut Peripherals) -> Result<()> {
    extern "C" {
        // This symbol is defined by the linker and denotes the start of the .data section.
        #[allow(improper_ctypes)]
        static mut __sdata: ();
        #[allow(improper_ctypes)]
        // This symbol is defined by the linker and denotes the end of the .data section.
        static mut __edata: ();
    }
    // SAFETY: The linker guarantees the presence and order of the above symbols.
    let data = unsafe {
        let start = core::ptr::addr_of_mut!(__sdata) as *mut u8;
        let end = core::ptr::addr_of_mut!(__edata) as *mut u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts_mut(start, len)
    };
    let s = Stage2Key::load(&p.eeprom)?;
    crypto::oneshot_decrypt(data, &s.key, &s.tag, &s.nonce)
}

/// The initial execution stage of the bootloader.
///
/// # Implementation Details
///
/// 1. Memory-mapped peripherals are initialized.
/// 2. Flash writes to the first stage are disabled.
/// 3. Second stage is decrypted (already present in SRAM, thanks to the reset handler).
/// 4. [`stage2`] is executed.
#[inline(always)]
pub fn stage1() -> Result<()> {
    let mut p = Peripherals::init();
    p.flash.disable_writes();
    decrypt_stage2(&mut p)?;
    stage2(p)?;
    Ok(())
}

/// The chief execution stage of the bootloader.
///
/// This runs in SRAM to prevent instruction patching at runtime.
///
/// # Implementation Details
///
/// 1. Firmware boot target in SRAM is zeroed out to prevent disclosure.
/// 2. CSPRNG seed is loaded from EEPROM based on emulator detection at runtime.
/// 3. Config boot target in flash is erased to prevent disclosure, followed by a verification
///    check of the first stage.
/// 4. The main loop is entered, and the bootloader awaits commands from authenticated host-tools.
#[link_section = ".data"]
#[inline(never)]
pub fn stage2(mut p: Peripherals) -> Result<()> {
    // Reset decrypted firmware if it exists.
    unsafe {
        core::ptr::write_bytes(FW_TARGET as *mut u8, 0, MAX_DECRYPTED_FW_LEN);
    }

    let mut rng = if DWT::cycle_count() == 0 {
        // QEMU doesn't implement instrumentation.
        let mut seed = p.eeprom.load_decrypted::<EmulatorSeed>()?;
        seed.inner.increment();
        let mut rng = ChaChaRng::from_seed(seed.inner.seed);
        seed.store_encrypted(&p.eeprom, &mut rng)?;
        rng
    } else {
        // The cycle count is almost certainly nonzero at this point of execution,
        // so this is for the physical device.
        let mut seed = p.eeprom.load_decrypted::<PhysicalSeed>()?;
        seed.inner.increment();
        let mut rng = ChaChaRng::from_seed(seed.inner.seed);
        seed.store_encrypted(&p.eeprom, &mut rng)?;
        rng
    };

    // Reset decrypted config if it exists.
    p.flash.erase_decrypted_cfg()?;
    verify_stage1(&mut p, &mut rng)?;

    loop {
        let status = if let Err(_e) = run_cmd(&mut p, &mut rng) {
            FRAME_BAD
        } else {
            FRAME_OK
        };
        p.uart.flush();
        p.uart.write_u8(status);
    }
}

/// Blocks until a command is received from host-tools, then executes the respective handler.
/// Invalid commands are rejected.
#[link_section = ".data"]
pub fn run_cmd(p: &mut Peripherals, r: &mut ChaChaRng) -> Result<()> {
    match p.uart.blocking_read_u8() {
        b'B' => handlers::boot(p, r),
        b'C' => handlers::configure(p, r),
        b'U' => handlers::update(p, r),
        b'R' => handlers::readback(p, r),
        _ => Err(Error::InvalidCmd),
    }
}
