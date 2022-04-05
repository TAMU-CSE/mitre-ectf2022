//! High-level abstractions over the TM4C123G's memory-mapped peripherals.

pub mod eeprom;
pub mod flash;
pub mod uart;

use cortex_m::peripheral::DWT;
use tm4c123x_hal::gpio;
use tm4c123x_hal::prelude::*;
use tm4c123x_hal::serial::{NewlineMode, Serial};
use tm4c123x_hal::sysctl::{CrystalFrequency, Oscillator, PllOutputFrequency, SystemClock};
use tm4c123x_hal::Peripherals as RawPeripherals;

pub use eeprom::Eeprom;
pub use flash::Flash;
pub use uart::Uart;

/// High-level interface to the device's peripherals used throughout the bootloader.
pub struct Peripherals {
    pub eeprom: Eeprom,
    pub flash: Flash,
    pub uart: Uart,
}

impl Peripherals {
    /// Initializes the device's peripherals. This should only be called once.
    pub fn init() -> Self {
        let p = RawPeripherals::take().unwrap();
        let mut sc = p.SYSCTL.constrain();
        // If we're on the physical device, we need to reconfigure the clock.
        if DWT::cycle_count() != 0 {
            sc.clock_setup.oscillator = Oscillator::Main(
                CrystalFrequency::_16mhz,
                SystemClock::UsePll(PllOutputFrequency::_80_00mhz),
            );
        }
        let eeprom = Eeprom::init(p.EEPROM, &mut sc);
        let clocks = sc.clock_setup.freeze();
        let mut porta = p.GPIO_PORTA.split(&sc.power_control);
        let tx = porta.pa1.into_af_push_pull::<gpio::AF1>(&mut porta.control);
        let rx = porta.pa0.into_af_push_pull::<gpio::AF1>(&mut porta.control);
        let uart = Uart(Serial::uart0(
            p.UART0,
            tx,
            rx,
            (),
            (),
            115_200.bps(),
            NewlineMode::Binary,
            &clocks,
            &sc.power_control,
        ));
        let flash = Flash(p.FLASH_CTRL);
        Self {
            eeprom,
            flash,
            uart,
        }
    }
}
