use super::*;

/// CSPRNG seed for the emulator.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct EmulatorSeed {
    pub seed: [u8; 32],
}

impl EmulatorSeed {
    /// Increments the seed.
    #[link_section = ".data"]
    pub fn increment(&mut self) {
        increment(&mut self.seed);
    }
}

/// CSPRNG seed for the physical device.
#[repr(C, align(4))]
#[derive(PartialEq, Clone, Copy)]
pub struct PhysicalSeed {
    pub seed: [u8; 32],
}

impl PhysicalSeed {
    #[link_section = ".data"]
    /// Increments the seed.
    pub fn increment(&mut self) {
        increment(&mut self.seed);
    }
}

/// Increments the seed. This ensures that each seed is different on every boot.
#[link_section = ".data"]
pub fn increment(bytes: &mut [u8; 32]) {
    for b in bytes.iter_mut() {
        let (res, carry) = b.overflowing_add(1);
        *b = res;
        if !carry {
            break;
        }
    }
}

impl_primitive!(EMULATOR_SEED_OFFSET, EmulatorSeed, [u8; 32]);
impl_primitive!(PHYSICAL_SEED_OFFSET, PhysicalSeed, [u8; 32]);
