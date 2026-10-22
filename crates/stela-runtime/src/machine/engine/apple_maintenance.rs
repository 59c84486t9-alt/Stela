//! Apple maintenance word exits (`block::system::AppleMaintenance`): DC
//! INCPA4K and the three undocumented words beside it that the M4 and later
//! SPTMs execute. The contracts and their evidence are in
//! `docs/design/system.md` (GXF).
use super::{Devices, Host, Machine, RequirementKind, Step};
use crate::machine::{Chip, hacr, mmu::tlbi::Reach};
use stela_compiler::block::system::AppleMaintenance;

/// The first chip with DC INCPA4K, operation 25 and `0x00201401`: XNU gives
/// H16 and H17 `HAS_DC_INCPA`, the 26A434 SPTMs of the M4 to M6 (T8132,
/// T6041, T8140, T8142, T6050, T8152) execute all three, and none of the
/// seven M1 to M3 SPTMs holds one.
const FIRST_COPROCESSOR_FLUSH: Chip = Chip::AppleM4;
/// The first chip with operation 26: only the M5 and M6 SPTMs (T8142, T6050,
/// T8152) hold it, not the M4's or the A18 Pro's (T8140).
const FIRST_ADDRESS_SPACE: Chip = Chip::AppleM5;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Execute the Apple maintenance word `word` at the PC.
    pub(super) fn apple_maintenance(&mut self, word: u32, operation: AppleMaintenance) -> Step {
        let first = match operation {
            AppleMaintenance::AddressSpace { .. } => FIRST_ADDRESS_SPACE,
            _ => FIRST_COPROCESSOR_FLUSH,
        };
        if self.cpu.registers.chip() < first {
            // Before then the words keep their meaning: AMX operations 24 to
            // 26, and `0x00201401`, which "faults with unknown instruction"
            // (Asahi Linux, "Apple Proprietary Instructions").
            return match operation {
                AppleMaintenance::All => self.undefined(),
                _ => self.amx(word),
            };
        }
        if let Some(step) = self.hacr_guest(word, hacr::Operation::AppleMaintenance) {
            return step;
        }
        let unestablished = match operation {
            // A coprocessor cache flush by physical address. This machine's
            // memory is coherent and it models no coprocessor cache, so it
            // has nothing to write back or discard. XNU issues it from the
            // kernel and SPTM from GL2; at EL0 its permission is unknown.
            AppleMaintenance::CoprocessorCacheFlush { .. } if self.cpu.pstate.el != 0 => {
                return self.next();
            }
            AppleMaintenance::CoprocessorCacheFlush { .. } => {
                "DC INCPA4K at EL0 has no established permission; it completes without effect"
            }
            AppleMaintenance::PhysicalPage { .. } => {
                "Apple operation 25 (a physical page, after a SAPT entry change) has no \
                 established effect; every cached translation is dropped"
            }
            AppleMaintenance::AddressSpace { .. } => {
                "Apple operation 26 (a stale ASID generation) has no established effect; \
                 every cached translation is dropped"
            }
            AppleMaintenance::All => {
                "Apple 0x00201401 (operation 25 for every page) has no established effect; \
                 every cached translation is dropped"
            }
        };
        let requirement = self.requirement(RequirementKind::SystemInstruction {
            word,
            detail: unestablished,
        });
        self.degrade(requirement)?;
        // m1n1's SPTM emulator flushes the TLB for them; dropping every
        // translation this machine caches (the fetch translations of every PE
        // and the host's whole shadow) covers any translation scope.
        if !matches!(operation, AppleMaintenance::CoprocessorCacheFlush { .. }) {
            self.tlb_maintained(Reach::All);
        }
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::super::Stop;
    use super::super::guarded::tests::{UNDEFINED, VECTORS, gl1, gxf};
    use super::*;

    const DC_INCPA4K_X8: u32 = 0x0020_1308;
    const PHYSICAL_PAGE_X16: u32 = 0x0020_1330;
    const ADDRESS_SPACE_X13: u32 = 0x0020_134d;
    const ALL: u32 = 0x0020_1401;

    #[test]
    fn dc_incpa4k_completes_without_effect_from_the_m4() {
        for chip in [Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            for mut machine in [gl1(chip), gxf(chip)] {
                machine.set_strict(true);
                machine.cpu.state.x[8] = 0x8_1234_4000;
                let (pc, generation) = (machine.cpu.pc, machine.translation_generation);
                machine.system_instruction(DC_INCPA4K_X8).unwrap();
                assert_eq!(machine.cpu.pc, pc + 4, "{chip:?}");
                assert_eq!(machine.translation_generation, generation);
                assert!(machine.host.reaches.is_empty());
                assert!(machine.take_unmodeled().is_empty());
            }
        }
    }

    #[test]
    fn unestablished_words_stop_strictly_or_drop_every_translation_once_reported() {
        for (chip, words) in [
            (Chip::AppleM4, &[PHYSICAL_PAGE_X16, ALL][..]),
            (Chip::AppleM5, &[PHYSICAL_PAGE_X16, ADDRESS_SPACE_X13, ALL]),
            (Chip::AppleM6, &[PHYSICAL_PAGE_X16, ADDRESS_SPACE_X13, ALL]),
        ] {
            for &word in words {
                let mut machine = gl1(chip);
                machine.set_strict(true);
                let pc = machine.cpu.pc;
                assert!(
                    matches!(machine.system_instruction(word), Err(Stop::Unsupported(_))),
                    "{chip:?} {word:#x}"
                );
                assert_eq!(machine.cpu.pc, pc);
                machine.set_strict(false);
                for _ in 0..2 {
                    let generation = machine.translation_generation;
                    let reaches = machine.host.reaches.len();
                    machine.system_instruction(word).unwrap();
                    assert_eq!(machine.translation_generation, generation + 1);
                    assert_eq!(machine.host.reaches[reaches..], [Reach::All]);
                    assert!(machine.cpu.pstate.guarded);
                }
                assert_eq!(machine.cpu.pc, pc + 8);
                assert_eq!(machine.take_unmodeled().len(), 1, "{chip:?} {word:#x}");
            }
        }
    }

    #[test]
    fn before_their_chips_the_words_keep_their_amx_and_unallocated_meanings() {
        for chip in [Chip::AppleM1, Chip::AppleM2, Chip::AppleM3, Chip::AppleM4] {
            let mut machine = gl1(chip);
            let generation = machine.translation_generation;
            // AMX operation 26 with AMX disabled: the AMX path refuses it.
            assert!(machine.system_instruction(ADDRESS_SPACE_X13).is_err());
            if chip == Chip::AppleM4 {
                continue;
            }
            for word in [DC_INCPA4K_X8, PHYSICAL_PAGE_X16] {
                assert!(machine.system_instruction(word).is_err(), "{chip:?}");
            }
            // 0x00201401 is UNDEFINED, taken at the GL's vector.
            machine.system_instruction(ALL).unwrap();
            assert_eq!(machine.cpu.pc, VECTORS + 0x200, "{chip:?}");
            assert_eq!(machine.cpu.apple.guarded[0].esr, UNDEFINED);
            assert_eq!(machine.translation_generation, generation);
        }
    }
}
