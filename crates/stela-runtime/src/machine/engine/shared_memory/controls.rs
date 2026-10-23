//! Immutable effective controls copied only while Machine owns the actual Cpu.
use super::*;
use crate::{
    machine::{cpu::Cpu, system::Register as SystemRegister},
    system::{
        identification::Register, identification_snapshot::Snapshot,
        process_memory::ProcessMemoryFeatures,
    },
};
use stela_compiler::{block::CheckedMemoryProfile, context::memory::InstructionRequirements};

const SCTLR_M: u64 = 1;
const SCTLR_C: u64 = 1 << 2;
const SCTLR_SA: u64 = 1 << 3;
const SCTLR_SA0: u64 = 1 << 4;
const SCTLR_NAA: u64 = 1 << 6;
const SCTLR_E0E: u64 = 1 << 24;
const SCTLR_EE: u64 = 1 << 25;
const FEATURE_SHIFT: u32 = 20;
const FIELD_MASK: u64 = 15;

pub(super) struct Controls {
    pub(super) translation: mmu::Controls,
    pub(super) requester: mmu::Requester,
    pub(super) sp: CheckedMemoryProfile,
    /// Real source FP access permission and nonstreaming AdvSIMD mode.
    pub(super) asimd: bool,
    identification: Arc<Snapshot>,
}
impl Controls {
    pub(super) fn capture(
        cpu: &Cpu,
        name: &'static str,
        missing: &[SystemRegister],
    ) -> Result<Self, MemoryStatus> {
        // The checked lane does not claim debug stepping,
        // DIT recipes, CPA, MTE or scalable state through a copied control bit.
        if cpu.pstate.il
            || cpu.pstate.ss
            || cpu.pstate.dit
            || cpu.pstate.pacm
            || crate::machine::debug::watching(cpu)
            || crate::machine::debug::enabled(cpu)
                && cpu.field(SystemRegister::MDSCR_EL1, 0, 1) != 0
        {
            return Err(MemoryStatus::Unsupported);
        }
        let pairs = [
            (Register::IdAa64Dfr0El1, SystemRegister::ID_AA64DFR0_EL1),
            (Register::IdAa64Dfr1El1, SystemRegister::ID_AA64DFR1_EL1),
            (Register::IdAa64Dfr2El1, SystemRegister::ID_AA64DFR2_EL1),
            (Register::IdAa64Isar0El1, SystemRegister::ID_AA64ISAR0_EL1),
            (Register::IdAa64Isar1El1, SystemRegister::ID_AA64ISAR1_EL1),
            (Register::IdAa64Isar3El1, SystemRegister::ID_AA64ISAR3_EL1),
            (Register::IdAa64Mmfr0El1, SystemRegister::ID_AA64MMFR0_EL1),
            (Register::IdAa64Mmfr2El1, SystemRegister::ID_AA64MMFR2_EL1),
            (Register::IdAa64Pfr1El1, SystemRegister::ID_AA64PFR1_EL1),
        ];
        if pairs.iter().any(|(_, register)| missing.contains(register)) {
            return Err(MemoryStatus::Unsupported);
        }
        let values: Vec<_> = pairs
            .iter()
            .map(|&(id, register)| (id, cpu.read(register)))
            .collect();
        let identification =
            Arc::new(Snapshot::declared(name, &values).map_err(|_| MemoryStatus::Unsupported)?);
        ProcessMemoryFeatures::from_snapshot(&identification)
            .map_err(|_| MemoryStatus::Unsupported)?;
        let translation = cpu.controls(cpu.regime());
        let requester = cpu.requester();
        let cold_m0 = requester.el == 2
            && matches!(translation.regime, mmu::Regime::El2 | mmu::Regime::El20)
            && translation.sctlr & SCTLR_M == 0;
        if requester.el > 2
            || !cold_m0 && translation.sctlr & (SCTLR_M | SCTLR_C) != SCTLR_M | SCTLR_C
            || translation.sctlr & SCTLR_NAA != 0
            || translation.sctlr
                & if requester.el == 0 {
                    SCTLR_E0E
                } else {
                    SCTLR_EE
                }
                != 0
        {
            return Err(MemoryStatus::Unsupported);
        }
        let check_sp = translation.sctlr
            & if requester.el == 0 {
                SCTLR_SA0
            } else {
                SCTLR_SA
            }
            != 0;
        Ok(Self {
            asimd: cpu.floating_point_trap().is_none() && cpu.svcr() & 1 == 0,
            translation,
            requester,
            sp: if check_sp {
                CheckedMemoryProfile::SpAlignmentEnabled
            } else {
                CheckedMemoryProfile::SpAlignmentDisabled
            },
            identification,
        })
    }

    pub(super) fn cold_m0(&self) -> bool {
        self.requester.el == 2
            && matches!(
                self.translation.regime,
                mmu::Regime::El2 | mmu::Regime::El20
            )
            && self.translation.sctlr & SCTLR_M == 0
    }

    pub(super) fn identity(&self) -> alloc::string::String {
        crate::sha256(
            alloc::format!(
                "{:?} {:?} {:?} {} {}",
                self.translation,
                self.requester,
                self.sp,
                self.asimd,
                self.identification.provenance().input_sha256()
            )
            .as_bytes(),
        )
    }

    pub(super) fn instructions(
        &self,
        required: InstructionRequirements,
    ) -> Result<(), MemoryStatus> {
        if !required.valid() || required.contains(InstructionRequirements::LOR) {
            return Err(MemoryStatus::Unsupported);
        }
        let field = |register| {
            self.identification
                .read(register)
                .map(|raw| raw >> FEATURE_SHIFT & FIELD_MASK)
                .map_err(|_| MemoryStatus::Unsupported)
        };
        if required.contains(InstructionRequirements::LSE)
            && !matches!(field(Register::IdAa64Isar0El1)?, 2 | 3)
        {
            return Err(MemoryStatus::Unsupported);
        }
        if required.contains(InstructionRequirements::RCPC)
            || required.contains(InstructionRequirements::RCPC2)
        {
            let rcpc = field(Register::IdAa64Isar1El1)?;
            if !matches!(rcpc, 1..=3)
                || required.contains(InstructionRequirements::RCPC2) && rcpc < 2
            {
                return Err(MemoryStatus::Unsupported);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::machine::{Chip, CpuProfile, exception::Pstate, identification};
    pub(in crate::machine::engine::shared_memory) fn captured()
    -> (Cpu, CpuProfile, Vec<SystemRegister>) {
        let chip = Chip::AppleM1;
        let profile = CpuProfile {
            name: "source-bound-m1-shared-controls-fixture",
            chip,
            counter_frequency: 24_000_000,
            fixed: identification::derive(
                chip,
                stela_compiler::TargetCpu::Baseline,
                true,
                identification::Speculation::NONE,
            ),
            processors: Vec::new(),
        };
        let mut cpu = Cpu::of(chip, 0x1000, Pstate::reset(1));
        let mut missing = Vec::new();
        super::super::super::system::identify(&profile, 0, &mut cpu, &mut missing);
        cpu.registers
            .set_raw(SystemRegister::SCTLR_EL1, 0, SCTLR_M | SCTLR_C | (1 << 12));
        (cpu, profile, missing)
    }
    #[test]
    fn fp_memory_admission_tracks_actual_cpacr_and_cptr_permissions() {
        let (mut cpu, profile, missing) = captured();
        assert!(
            !Controls::capture(&cpu, profile.name, &missing)
                .unwrap()
                .asimd
        );
        cpu.registers.set_raw(SystemRegister::CPACR_EL1, 0, 3 << 20);
        cpu.registers.set_raw(SystemRegister::CPTR_EL2, 0, 3 << 20);
        let enabled = Controls::capture(&cpu, profile.name, &missing).unwrap();
        assert!(enabled.asimd);
        cpu.registers.set_raw(SystemRegister::CPTR_EL2, 0, 0);
        let disabled = Controls::capture(&cpu, profile.name, &missing).unwrap();
        assert!(!disabled.asimd);
        assert_ne!(enabled.identity(), disabled.identity());
        cpu.pstate.btype = 3;
        assert!(Controls::capture(&cpu, profile.name, &missing).is_ok());
        cpu.pstate.pacm = true;
        assert!(Controls::capture(&cpu, profile.name, &missing).is_err());
    }

    #[test]
    fn actual_cpu_ids_and_effective_controls_qualify_without_raw_authority() {
        let (mut cpu, profile, missing) = captured();
        let controls = Controls::capture(&cpu, profile.name, &missing).unwrap();
        assert_eq!(controls.sp, CheckedMemoryProfile::SpAlignmentDisabled);
        assert!(controls.instructions(InstructionRequirements::LSE).is_ok());
        assert!(controls.instructions(InstructionRequirements::RCPC).is_ok());
        assert!(controls.instructions(InstructionRequirements::LOR).is_err());
        assert!(
            Controls::capture(&cpu, profile.name, &[SystemRegister::ID_AA64ISAR0_EL1]).is_err()
        );
        let old = controls.identity();
        cpu.registers
            .set_raw(SystemRegister::TTBR0_EL1, 0, 0x1234_0000);
        assert_ne!(
            old,
            Controls::capture(&cpu, profile.name, &missing)
                .unwrap()
                .identity()
        );
        for value in [
            SCTLR_M,
            SCTLR_C,
            SCTLR_M | SCTLR_C | SCTLR_NAA,
            SCTLR_M | SCTLR_C | SCTLR_EE,
        ] {
            cpu.registers.set_raw(SystemRegister::SCTLR_EL1, 0, value);
            assert!(
                Controls::capture(&cpu, profile.name, &missing).is_err(),
                "SCTLR={value:x}"
            );
        }
    }
    #[test]
    fn source_feature_changes_and_current_el_sp_selection_are_not_assumed() {
        let (mut cpu, profile, missing) = captured();
        let isar0 = cpu.read(SystemRegister::ID_AA64ISAR0_EL1);
        cpu.registers.set_raw(
            SystemRegister::ID_AA64ISAR0_EL1,
            0,
            isar0 & !(FIELD_MASK << FEATURE_SHIFT),
        );
        let controls = Controls::capture(&cpu, profile.name, &missing).unwrap();
        assert!(controls.instructions(InstructionRequirements::LSE).is_err());
        cpu.registers
            .set_raw(SystemRegister::SCTLR_EL1, 0, SCTLR_M | SCTLR_C | SCTLR_SA);
        assert_eq!(
            Controls::capture(&cpu, profile.name, &missing).unwrap().sp,
            CheckedMemoryProfile::SpAlignmentEnabled
        );
        cpu.pstate.el = 0;
        assert_eq!(
            Controls::capture(&cpu, profile.name, &missing).unwrap().sp,
            CheckedMemoryProfile::SpAlignmentDisabled
        );
        cpu.pstate.ss = true;
        assert!(Controls::capture(&cpu, profile.name, &missing).is_err());
    }
}
