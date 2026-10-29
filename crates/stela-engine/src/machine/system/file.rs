//! Storage for the profile's System registers: one 64-bit slot per register
//! instance, starting at the reset value. Writes keep the bits that are RES0
//! at 0 and RES1 at 1 in every layout the PE's profile allows
//! (`Register::res0`, `Register::res1`, and `WITHHELD_LAYOUTS` for a PE that
//! withholds some of its chip's features).
use alloc::{boxed::Box, vec, vec::Vec};
use {
    super::Register, super::WithheldLayout, super::generated::WITHHELD_LAYOUTS,
    stela_contracts::Chip, stela_contracts::Feature,
};

#[derive(Debug, Clone)]
pub struct File {
    chip: Chip,
    /// The chip's features the PE's identification withholds
    /// (`identification::withheld`).
    withheld: u64,
    /// The layouts the withheld features change.
    layouts: Vec<&'static WithheldLayout>,
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
        Self {
            chip,
            withheld: 0,
            layouts: Vec::new(),
            values,
        }
    }

    pub fn chip(&self) -> Chip {
        self.chip
    }

    /// Treat the chip's features in `withheld` (one bit per [`Feature`],
    /// `identification::withheld`) as absent: the PE presents an
    /// identification without them, and its registers have the layouts of
    /// the chip's profile without them. A register still at the chip's
    /// Cold reset value takes the PE's; the others keep their values within
    /// the PE's reserved bits.
    pub fn withhold(&mut self, withheld: u64) {
        self.withheld = withheld;
        self.layouts = WITHHELD_LAYOUTS
            .iter()
            .filter(|layout| {
                layout.chip == self.chip && withheld & layout.relevant == layout.withheld
            })
            .collect();
        for layout in self.layouts.clone() {
            let register = layout.register;
            let chip_reset = register.reset(self.chip);
            for index in 0..register.instances() {
                let slot = register.offset() + index as usize;
                let value = self.values[slot];
                self.values[slot] = if value == chip_reset {
                    layout.reset
                } else {
                    value & !layout.res0 & !layout.res1 | layout.res1
                };
            }
        }
    }

    /// The PE's layout of `register`, where withheld features change it.
    fn layout(&self, register: Register) -> Option<&'static WithheldLayout> {
        self.layouts
            .iter()
            .find(|layout| layout.register == register)
            .copied()
    }

    /// Whether the PE has `feature`: the chip has it and the PE's
    /// identification presents it.
    pub fn has(&self, feature: Feature) -> bool {
        feature.on(self.chip) && self.withheld & 1 << feature as u64 == 0
    }

    /// Arm `IsFeatureImplemented` for the PE: [`Chip::implemented`] for a
    /// feature its identification presents, `Ok(false)` for one it
    /// withholds.
    pub fn implemented(&self, feature: Feature) -> Result<bool, &'static str> {
        if self.withheld & 1 << feature as u64 != 0 {
            Ok(false)
        } else {
            crate::machine::capabilities::implemented(self.chip, feature)
        }
    }

    /// The bits of `register` that are RES0 under the PE's profile.
    pub fn res0(&self, register: Register) -> u64 {
        self.layout(register)
            .map_or_else(|| register.res0(self.chip), |layout| layout.res0)
    }

    /// The bits of `register` that are RES1 under the PE's profile.
    pub fn res1(&self, register: Register) -> u64 {
        self.layout(register)
            .map_or_else(|| register.res1(self.chip), |layout| layout.res1)
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

    /// Complete a Warm reset of `old`, this file holding the reset values:
    /// the bits a Warm reset sets (`Register::warm`) keep this file's
    /// values, and the others, such as the debug and performance monitor
    /// state only a Cold reset sets, take `old`'s.
    pub fn keep_over_warm_reset(&mut self, old: &File) {
        for register in Register::ALL {
            let warm = self
                .layout(register)
                .map_or_else(|| register.warm(self.chip), |layout| layout.warm);
            for index in 0..register.instances() {
                let slot = register.offset() + index as usize;
                self.values[slot] = self.values[slot] & warm | old.values[slot] & !warm;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_bits_and_arrays() {
        let mut file = File::new(crate::machine::test_chip());
        // HCR_EL2.E2H is RES1 without FEAT_E2H0.
        assert_eq!(file.get(Register::HCR_EL2, 0) >> 34 & 1, 1);
        file.set(Register::HCR_EL2, 0, 0);
        assert_eq!(file.get(Register::HCR_EL2, 0) >> 34 & 1, 1);
        file.set(Register::DBGBVR_EL1, 3, 0x1234);
        assert_eq!(file.get(Register::DBGBVR_EL1, 3), 0x1234);
        assert_eq!(file.get(Register::DBGBVR_EL1, 2), 0);
        assert_eq!(file.get(Register::DBGBVR_EL1, 99), 0);
    }

    /// A PE that withholds features has its registers' layouts without
    /// them: an M5 that withholds memory tagging has no SCTLR_EL1.ATA or
    /// HCR_EL2.ATA, as a chip without FEAT_MTE2 has none.
    #[test]
    fn a_pe_withholding_features_has_the_layouts_without_them() {
        const SCTLR_ATA: u64 = 1 << 43;
        const HCR_ATA: u64 = 1 << 56;
        let tagging = Feature::ALL
            .into_iter()
            .filter(|feature| feature.on(Chip::AppleM5) && feature.name().starts_with("FEAT_MTE"))
            .fold(0, |bits, feature| bits | 1 << feature as u64);
        let mut file = File::new(Chip::AppleM5);
        assert_eq!(file.res0(Register::SCTLR_EL1) & SCTLR_ATA, 0);
        file.set(Register::SCTLR_EL1, 0, SCTLR_ATA);
        file.set(Register::HCR_EL2, 0, HCR_ATA);
        file.withhold(tagging);
        for (register, bit) in [
            (Register::SCTLR_EL1, SCTLR_ATA),
            (Register::HCR_EL2, HCR_ATA),
        ] {
            assert_eq!(file.res0(register) & bit, bit, "{register:?}");
            assert_eq!(register.res0(Chip::AppleM4) & bit, bit, "{register:?}");
            // The value already held loses the bit, and a write cannot set it.
            assert_eq!(file.get(register, 0) & bit, 0, "{register:?}");
            file.set(register, 0, bit);
            assert_eq!(file.get(register, 0) & bit, 0, "{register:?}");
        }
        // Presenting every feature again restores the chip's layouts.
        file.withhold(0);
        assert_eq!(
            file.res0(Register::SCTLR_EL1),
            Register::SCTLR_EL1.res0(Chip::AppleM5)
        );
        // A fresh PE starts at the PE's Cold reset values.
        let mut fresh = File::new(Chip::AppleM5);
        fresh.withhold(tagging);
        let layout = fresh.layout(Register::SCTLR_EL1).unwrap();
        assert_eq!(fresh.get(Register::SCTLR_EL1, 0), layout.reset);
    }

    #[test]
    fn registers_start_at_their_cold_reset_values() {
        let file = File::new(crate::machine::test_chip());
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

    #[test]
    fn a_warm_reset_keeps_what_only_a_cold_reset_sets() {
        let chip = crate::machine::test_chip();
        let mut old = File::new(chip);
        // The OS lock released, a breakpoint value, a return address and a
        // Warm reset request.
        old.set_raw(Register::OSLSR_EL1, 0, 0);
        old.set(Register::DBGBVR_EL1, 3, 0x1234);
        old.set(Register::ELR_EL2, 0, 0x8000);
        old.set(Register::VBAR_EL2, 0, 0x4_0000);
        old.set(Register::RMR_EL2, 0, 0b11);
        let mut file = File::new(chip);
        file.keep_over_warm_reset(&old);
        // Arm's System register XML: OSLSR_EL1.OSLK and the breakpoints
        // reset only on a Cold reset, RMR_EL2.RR on a Warm one while AA64
        // keeps its Cold reset value, and ELR_EL2 and VBAR_EL2 become
        // UNKNOWN (0 here).
        assert_eq!(file.get(Register::OSLSR_EL1, 0), 0);
        assert_eq!(file.get(Register::DBGBVR_EL1, 3), 0x1234);
        assert_eq!(file.get(Register::ELR_EL2, 0), 0);
        assert_eq!(file.get(Register::VBAR_EL2, 0), 0);
        assert_eq!(file.get(Register::RMR_EL2, 0), 1);
    }
}
