//! Storage for the profile's System registers: one 64-bit slot per register
//! instance. Writes keep the bits that are RES0 at 0 and RES1 at 1 in every
//! layout the profile allows (`Register::res0`, `Register::res1`).
use super::Register;
use alloc::{boxed::Box, vec};

#[derive(Debug, Clone)]
pub struct File {
    values: Box<[u64]>,
}

impl Default for File {
    fn default() -> Self {
        Self::new()
    }
}

impl File {
    /// Every register at its reset value: RES1 bits set, other bits 0.
    pub fn new() -> Self {
        let mut values = vec![0; Register::SLOTS].into_boxed_slice();
        for register in Register::ALL {
            for index in 0..register.instances() {
                values[register.offset() + index as usize] = register.res1();
            }
        }
        Self { values }
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
            self.values[slot] = (value & !register.res0() & !register.res1()) | register.res1();
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
        let mut file = File::new();
        // HCR_EL2.E2H is RES1 without FEAT_E2H0.
        assert_eq!(file.get(Register::HCR_EL2, 0) >> 34 & 1, 1);
        file.set(Register::HCR_EL2, 0, 0);
        assert_eq!(file.get(Register::HCR_EL2, 0) >> 34 & 1, 1);
        file.set(Register::DBGBVR_EL1, 3, 0x1234);
        assert_eq!(file.get(Register::DBGBVR_EL1, 3), 0x1234);
        assert_eq!(file.get(Register::DBGBVR_EL1, 2), 0);
        assert_eq!(file.get(Register::DBGBVR_EL1, 99), 0);
    }
}
