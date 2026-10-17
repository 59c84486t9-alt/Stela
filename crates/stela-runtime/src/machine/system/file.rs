//! Storage for the profile's System registers: one 64-bit slot per register
//! instance, starting at the reset value. Writes keep the bits that are RES0
//! at 0 and RES1 at 1 in every layout the chip's profile allows
//! (`Register::res0`, `Register::res1`).
use super::{Chip, Register};
use alloc::{boxed::Box, vec};

#[derive(Debug, Clone)]
pub struct File {
    chip: Chip,
    values: Box<[u64]>,
}

impl Default for File {
    fn default() -> Self {
        Self::new(Chip::DEFAULT)
    }
}

impl File {
    /// Every register at its Cold reset value (`Register::reset`): the
    /// architectural field resets under `chip`'s profile, with RES1 bits set
    /// and UNKNOWN fields 0.
    pub fn new(chip: Chip) -> Self {
        let mut values = vec![0; Register::SLOTS].into_boxed_slice();
        for register in Register::ALL {
            for index in 0..register.instances() {
                values[register.offset() + index as usize] = register.reset(chip);
            }
        }
        Self { chip, values }
    }

    pub fn chip(&self) -> Chip {
        self.chip
    }

    /// The bits of `register` that are RES0 under the chip's profile.
    pub fn res0(&self, register: Register) -> u64 {
        register.res0(self.chip)
    }

    /// The bits of `register` that are RES1 under the chip's profile.
    pub fn res1(&self, register: Register) -> u64 {
        register.res1(self.chip)
    }

    fn slot(register: Register, index: u64) -> Option<usize> {
        (index < register.instances()).then(|| register.offset() + index as usize)
    }

    /// The stored value; an out-of-range array index reads 0.
    pub fn get(&self, register: Register, index: u64) -> u64 {
        Self::slot(register, index).map_or(0, |slot| self.values[slot])
    }

    /// Store with the reserved bits forced; an out-of-range index is ignored.
    pub fn set(&mut self, register: Register, index: u64, value: u64) {
        if let Some(slot) = Self::slot(register, index) {
            let (res0, res1) = (self.res0(register), self.res1(register));
            self.values[slot] = (value & !res0 & !res1) | res1;
        }
    }

    /// Store a register's value without reserved-bit masking, for state the
    /// engine itself produces (exception entry, reset values).
    pub fn set_raw(&mut self, register: Register, index: u64, value: u64) {
        if let Some(slot) = Self::slot(register, index) {
            self.values[slot] = value;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_bits_and_arrays() {
        let mut file = File::default();
        // HCR_EL2.E2H is RES1 without FEAT_E2H0.
        assert_eq!(file.get(Register::HCR_EL2, 0) >> 34 & 1, 1);
        file.set(Register::HCR_EL2, 0, 0);
        assert_eq!(file.get(Register::HCR_EL2, 0) >> 34 & 1, 1);
        file.set(Register::DBGBVR_EL1, 3, 0x1234);
        assert_eq!(file.get(Register::DBGBVR_EL1, 3), 0x1234);
        assert_eq!(file.get(Register::DBGBVR_EL1, 2), 0);
        assert_eq!(file.get(Register::DBGBVR_EL1, 99), 0);
    }

    #[test]
    fn registers_start_at_their_cold_reset_values() {
        let file = File::default();
        // Arm's System register XML, under the profile (highest EL EL2):
        // OSLSR_EL1.OSLK is set at Cold reset, MPAM2_EL2 traps EL1 and EL0
        // MPAM register accesses, RMR_EL2.AA64 resets to AArch64, and
        // SCTLR_EL2.M, C and I reset to 0.
        assert_eq!(file.get(Register::OSLSR_EL1, 0), 0b10);
        assert_eq!(file.get(Register::MPAM2_EL2, 0), 0b11 << 48);
        assert_eq!(file.get(Register::RMR_EL2, 0), 1);
        assert_eq!(file.get(Register::SCTLR_EL2, 0) & 0b1_0000_0000_0101, 0);
        assert_eq!(
            file.get(Register::SCTLR_EL2, 0),
            file.res1(Register::SCTLR_EL2)
        );
    }
}
