//! The fixed controls of a software EL1 machine. Control writes are not
//! supported.

use super::access::{ExceptionLevel, Profile, SecurityState};
use super::exception::{EntryControls, RequiredEffects, ServiceRequest};
use super::execution::EntrySnapshot;
use super::profile::{BaseSpeAbsence, EntryProfile, EntryProfileError};
use super::pstate::{DAIF_MASK, NZCV_MASK};
use super::state::{PSTATE_EL1H, PSTATE_EL1T, PSTATE_MODE_MASK, SystemState};
use stela_compiler::GuestState;

const SCTLR_MMU_ENABLE: u64 = 1;
const SOURCE_PSTATE_MASK: u64 = NZCV_MASK | DAIF_MASK | PSTATE_MODE_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedControlsError {
    MmuEnabled,
    EntryControls(EntryProfileError),
    DebugState,
    UnsupportedMode(u64),
    UnsupportedPstate(u64),
    MteState,
    ProfileMismatch,
    SourceLevelMismatch,
    ControlsMismatch,
    InterruptEntry,
    UnsupportedReturnMode(u64),
    UnsupportedDestination(ExceptionLevel),
}

/// Owner of the software machine's controls. Not Clone or Copy.
#[derive(Debug)]
pub struct FixedEl1Controls {
    features: EntryProfile,
    _base_spe: BaseSpeAbsence,
    sctlr_el1: u64,
    entry: EntryControls,
}

impl FixedEl1Controls {
    pub fn new(
        features: EntryProfile,
        base_spe: BaseSpeAbsence,
        sctlr_el1: u64,
        entry: EntryControls,
    ) -> Result<Self, FixedControlsError> {
        if sctlr_el1 & SCTLR_MMU_ENABLE != 0 {
            return Err(FixedControlsError::MmuEnabled);
        }
        features
            .check_controls(entry.tcr_el1, entry.mdscr_el1)
            .map_err(FixedControlsError::EntryControls)?;
        if entry.debug.halted || entry.debug.halting_allowed {
            return Err(FixedControlsError::DebugState);
        }
        Ok(Self {
            features,
            _base_spe: base_spe,
            sctlr_el1,
            entry,
        })
    }

    pub const fn entry_profile(&self) -> EntryProfile {
        self.features
    }

    pub const fn sctlr_el1(&self) -> u64 {
        self.sctlr_el1
    }

    pub const fn entry_controls(&self) -> EntryControls {
        self.entry
    }

    /// Values read from this owner and the current state.
    pub fn entry_snapshot(
        &self,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<EntrySnapshot, FixedControlsError> {
        check_source_pstate(system.pstate(registers))?;
        if system.mte().is_some() {
            return Err(FixedControlsError::MteState);
        }
        Ok(EntrySnapshot {
            profile: own_el1_profile(),
            features: self.features,
            controls: self.entry,
        })
    }

    /// CodePublicationScope checks the runtime, source site and operation; the
    /// exception plan checks the source state.
    pub fn check_exception_request(
        &self,
        request: &ServiceRequest,
    ) -> Result<(), FixedControlsError> {
        if request.profile != own_el1_profile() {
            return Err(FixedControlsError::ProfileMismatch);
        }
        if request.source_el != ExceptionLevel::El1 {
            return Err(FixedControlsError::SourceLevelMismatch);
        }
        if request.controls != self.entry {
            return Err(FixedControlsError::ControlsMismatch);
        }
        check_source_pstate(request.source_pstate)?;
        if matches!(request.effects, RequiredEffects::Entry { irq: true }) {
            return Err(FixedControlsError::InterruptEntry);
        }
        Ok(())
    }

    /// Restrict destination mode before return mutation. The exception owner
    /// retains saved-bit masking, debug-off SS handling and legal IL restoration;
    /// the next native entry independently rejects illegal execution state.
    pub fn validate_return(&self, system: &SystemState) -> Result<(), FixedControlsError> {
        if system.current_el() != ExceptionLevel::El1 {
            return Err(FixedControlsError::SourceLevelMismatch);
        }
        let mode = system.el1_registers().spsr() & PSTATE_MODE_MASK;
        match mode {
            PSTATE_EL1T | PSTATE_EL1H => Ok(()),
            mode => Err(FixedControlsError::UnsupportedReturnMode(mode)),
        }
    }

    /// TBI is off in this owner, so BranchAddr keeps every target bit.
    /// Alignment and fetch faults are checked later.
    pub fn branch_address(
        &self,
        target: u64,
        destination_el: ExceptionLevel,
    ) -> Result<u64, FixedControlsError> {
        if destination_el != ExceptionLevel::El1 {
            return Err(FixedControlsError::UnsupportedDestination(destination_el));
        }
        Ok(target)
    }
}

fn own_el1_profile() -> Profile {
    Profile {
        current_el: ExceptionLevel::El1,
        security: SecurityState::NonSecure,
        el2_enabled: false,
        el3_present: false,
    }
}

fn check_source_pstate(pstate: u64) -> Result<(), FixedControlsError> {
    match pstate & PSTATE_MODE_MASK {
        PSTATE_EL1T | PSTATE_EL1H => {}
        mode => return Err(FixedControlsError::UnsupportedMode(mode)),
    }
    let unsupported = pstate & !SOURCE_PSTATE_MASK;
    if unsupported != 0 {
        return Err(FixedControlsError::UnsupportedPstate(unsupported));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::tags::{AllocationTag, TagGenerationState, TagRandomization};
    use crate::system::debug::DebugControls;
    use crate::system::profile::{ScalableEntryAbsence, SystemEntryFeatures};
    use crate::system::pstate::MteFeature;
    use crate::system::state::{
        El1Registers, MteState, PSTATE_EL0T, PSTATE_IL_MASK, PSTATE_SS_MASK, StackBank,
    };

    const TCR_TBI0: u64 = 1 << 37;
    const TCR_TBI1: u64 = 1 << 38;
    const MDSCR_SOFTWARE_STEP: u64 = 1;
    const MDSCR_KERNEL_DEBUG_ENABLE: u64 = 1 << 13;
    const MDSCR_MONITOR_DEBUG_ENABLE: u64 = 1 << 15;
    const SP0: u64 = 0x1000;
    const SP1: u64 = 0x2000;
    const SOURCE_PC: u64 = 0x4000;
    const FLAGS: u32 = 0xa000_0000;

    fn features() -> EntryProfile {
        EntryProfile::base(
            SystemEntryFeatures::declared_absent(),
            ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
        )
        .unwrap()
    }

    fn entry() -> EntryControls {
        EntryControls {
            tcr_el1: 0,
            mdscr_el1: 0,
            debug: DebugControls {
                halted: false,
                ignore_traps_in_debug: false,
                halting_allowed: false,
                edscr_tda: false,
                os_locked: false,
                breakpoint_count: 0,
                watchpoint_count: 0,
                raw_bank: 0,
                effective_bank: 0,
            },
        }
    }

    fn controls() -> FixedEl1Controls {
        FixedEl1Controls::new(
            features(),
            crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
            0,
            entry(),
        )
        .unwrap()
    }

    fn state(mode: u64) -> (SystemState, GuestState) {
        let sp1_active = mode & PSTATE_MODE_MASK == PSTATE_EL1H;
        (
            SystemState::new(
                mode,
                if sp1_active { SP0 } else { SP1 },
                El1Registers::new(SOURCE_PC, PSTATE_EL1H, 0, 0, 0),
            )
            .unwrap(),
            GuestState {
                sp: if sp1_active { SP1 } else { SP0 },
                nzcv: FLAGS,
                ..GuestState::default()
            },
        )
    }

    fn request(effects: RequiredEffects) -> ServiceRequest {
        ServiceRequest {
            effects,
            profile: own_el1_profile(),
            source_el: ExceptionLevel::El1,
            source_pstate: PSTATE_EL1H | u64::from(FLAGS),
            source_pc: SOURCE_PC,
            controls: entry(),
        }
    }

    #[test]
    fn constructor_checks_actual_mmu_tbi_debug_controls() {
        assert_eq!(
            FixedEl1Controls::new(
                features(),
                crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                SCTLR_MMU_ENABLE,
                entry()
            )
            .unwrap_err(),
            FixedControlsError::MmuEnabled
        );
        for tbi in [TCR_TBI0, TCR_TBI1, TCR_TBI0 | TCR_TBI1] {
            let entry = EntryControls {
                tcr_el1: tbi,
                ..entry()
            };
            assert!(matches!(
                FixedEl1Controls::new(
                    features(),
                    crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                    0,
                    entry
                ),
                Err(FixedControlsError::EntryControls(_))
            ));
        }
        for debug in [
            MDSCR_SOFTWARE_STEP,
            MDSCR_KERNEL_DEBUG_ENABLE,
            MDSCR_MONITOR_DEBUG_ENABLE,
        ] {
            let entry = EntryControls {
                mdscr_el1: debug,
                ..entry()
            };
            assert!(matches!(
                FixedEl1Controls::new(
                    features(),
                    crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                    0,
                    entry
                ),
                Err(FixedControlsError::EntryControls(_))
            ));
        }
        for halted in [false, true] {
            for halting_allowed in [false, true] {
                let mut entry = entry();
                entry.debug.halted = halted;
                entry.debug.halting_allowed = halting_allowed;
                let result = FixedEl1Controls::new(
                    features(),
                    crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
                    0,
                    entry,
                );
                assert_eq!(result.is_ok(), !halted && !halting_allowed);
            }
        }
    }

    #[test]
    fn getters_preserve_declared_controls_without_mutable_access() {
        let sctlr = !SCTLR_MMU_ENABLE;
        let owner = FixedEl1Controls::new(
            features(),
            crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
            sctlr,
            entry(),
        )
        .unwrap();
        assert_eq!(owner.sctlr_el1(), sctlr);
        assert_eq!(owner.entry_controls(), entry());
        assert_eq!(owner.entry_profile(), features());
    }

    #[test]
    fn snapshots_read_actual_state_without_copying_its_authority() {
        let owner = controls();
        for mode in [PSTATE_EL1T, PSTATE_EL1H] {
            let (mut system, mut registers) = state(mode | DAIF_MASK);
            let before = (system.clone(), registers.clone());
            let snapshot = owner.entry_snapshot(&system, &registers).unwrap();
            assert_eq!(snapshot.profile, own_el1_profile());
            assert_eq!(snapshot.features, features());
            assert_eq!(snapshot.controls, entry());
            assert_eq!((system.clone(), registers.clone()), before);
            registers.nzcv = u32::MAX;
            system.set_spsel(&mut registers, StackBank::El0).unwrap();
            assert!(owner.entry_snapshot(&system, &registers).is_ok());
            assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
            assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
            assert_eq!(
                system.pstate(&registers),
                PSTATE_EL1T | DAIF_MASK | NZCV_MASK
            );
        }
    }

    #[test]
    fn snapshots_reject_el0_step_il_and_optional_state() {
        let owner = controls();
        for mode in [
            PSTATE_EL0T,
            PSTATE_EL1H | PSTATE_SS_MASK,
            PSTATE_EL1T | PSTATE_IL_MASK,
        ] {
            let (system, registers) = state(mode);
            assert!(owner.entry_snapshot(&system, &registers).is_err());
        }
        let system = SystemState::new_with_mte(
            PSTATE_EL1H,
            SP0,
            El1Registers::new(0, 0, 0, 0, 0),
            MteFeature::TwoOrLater,
            MteState::new(
                0,
                TagRandomization::ArchitecturalLfsr,
                TagGenerationState {
                    seed: 0,
                    tag: AllocationTag::new(0).unwrap(),
                },
            ),
        )
        .unwrap();
        assert!(matches!(
            owner.entry_snapshot(&system, &GuestState::default()),
            Err(FixedControlsError::MteState)
        ));
    }

    #[test]
    fn source_pstate_rejects_every_out_of_scope_bit_and_mode() {
        for mode in 0..=PSTATE_MODE_MASK {
            assert_eq!(
                check_source_pstate(mode).is_ok(),
                [PSTATE_EL1T, PSTATE_EL1H].contains(&mode)
            );
        }
        for bit in 0..u64::BITS {
            let value = 1u64 << bit;
            if value & SOURCE_PSTATE_MASK == 0 {
                assert_eq!(
                    check_source_pstate(PSTATE_EL1H | value),
                    Err(FixedControlsError::UnsupportedPstate(value))
                );
            }
        }
    }

    #[test]
    fn exception_requests_require_exact_profile_level_controls_and_non_irq_effects() {
        let owner = controls();
        for effect in [
            RequiredEffects::Entry { irq: false },
            RequiredEffects::Return,
        ] {
            assert_eq!(owner.check_exception_request(&request(effect)), Ok(()));
        }
        let base = request(RequiredEffects::Return);
        for profile in [
            Profile {
                current_el: ExceptionLevel::El0,
                ..base.profile
            },
            Profile {
                security: SecurityState::Secure,
                ..base.profile
            },
            Profile {
                el2_enabled: true,
                ..base.profile
            },
            Profile {
                el3_present: true,
                ..base.profile
            },
        ] {
            assert_eq!(
                owner.check_exception_request(&ServiceRequest { profile, ..base }),
                Err(FixedControlsError::ProfileMismatch)
            );
        }
        assert_eq!(
            owner.check_exception_request(&ServiceRequest {
                source_el: ExceptionLevel::El0,
                ..base
            }),
            Err(FixedControlsError::SourceLevelMismatch)
        );
        let different = EntryControls {
            tcr_el1: 1,
            ..entry()
        };
        assert_eq!(
            owner.check_exception_request(&ServiceRequest {
                controls: different,
                ..base
            }),
            Err(FixedControlsError::ControlsMismatch)
        );
        assert_eq!(
            owner.check_exception_request(&request(RequiredEffects::Entry { irq: true })),
            Err(FixedControlsError::InterruptEntry)
        );
        for source_pstate in [
            PSTATE_EL0T,
            PSTATE_EL1H | PSTATE_SS_MASK,
            PSTATE_EL1T | PSTATE_IL_MASK,
        ] {
            assert!(
                owner
                    .check_exception_request(&ServiceRequest {
                        source_pstate,
                        ..base
                    })
                    .is_err()
            );
        }
    }

    #[test]
    fn return_scope_checks_saved_mode_before_any_mutation() {
        let owner = controls();
        for current_mode in [PSTATE_EL1T, PSTATE_EL1H] {
            let (mut system, registers) = state(current_mode);
            for saved_mode in 0..=PSTATE_MODE_MASK {
                system
                    .el1_registers_mut()
                    .set_spsr(saved_mode | NZCV_MASK | DAIF_MASK | PSTATE_IL_MASK);
                let before = system.clone();
                assert_eq!(
                    owner.validate_return(&system).is_ok(),
                    [PSTATE_EL1T, PSTATE_EL1H].contains(&saved_mode)
                );
                assert_eq!(system, before);
                assert_eq!(registers.nzcv, FLAGS);
            }
        }
        let (system, _) = state(PSTATE_EL0T);
        assert_eq!(
            owner.validate_return(&system),
            Err(FixedControlsError::SourceLevelMismatch)
        );
    }

    #[test]
    fn tbi_off_branch_preserves_all_bits_and_rejects_other_levels() {
        let owner = controls();
        for target in [0, 1, SOURCE_PC, u64::MAX, 1 << 63] {
            assert_eq!(
                owner.branch_address(target, ExceptionLevel::El1),
                Ok(target)
            );
            for level in [
                ExceptionLevel::El0,
                ExceptionLevel::El2,
                ExceptionLevel::El3,
            ] {
                assert_eq!(
                    owner.branch_address(target, level),
                    Err(FixedControlsError::UnsupportedDestination(level))
                );
            }
        }
    }
}
