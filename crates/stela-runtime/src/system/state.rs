//! Owned A64 EL0/EL1 state, with flags and the active stack in `GuestState`.
//!
//! This owner validates storage transitions. Access traps, exception sequencing,
//! memory permissions and externally visible effects belong to their resolvers.

use super::access::ExceptionLevel;
use super::pstate::{DAIF_MASK, MteFeature, NZCV_MASK, SP_SELECT_MASK, TCO_MASK};
use crate::memory::tags::{TagGenerationControls, TagGenerationState, TagRandomization};
use stela_compiler::GuestState;

pub const PSTATE_MODE_MASK: u64 = 0x1f;
pub const PSTATE_EL_SHIFT: u32 = 2;
pub const PSTATE_EL0T: u64 = 0;
pub const PSTATE_EL1T: u64 = 1 << PSTATE_EL_SHIFT;
pub const PSTATE_EL1H: u64 = PSTATE_EL1T | SP_SELECT_MASK;
pub const PSTATE_SS_MASK: u64 = 1 << 21;
pub const PSTATE_IL_MASK: u64 = 1 << 20;
const BASE_MISC_MASK: u64 = PSTATE_MODE_MASK | DAIF_MASK | PSTATE_SS_MASK | PSTATE_IL_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackBank {
    El0,
    El1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    FlagsInMiscPstate,
    UnsupportedPstateBits(u64),
    UnsupportedMode(u64),
    El0StackSelection,
    ActiveSpEl0,
    UnsupportedMteProfile,
}

/// Architectural storage only. Register-specific write masks and use-time
/// validation belong to the access and exception resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct El1Registers {
    elr: u64,
    spsr: u64,
    esr: u64,
    far: u64,
    vbar: u64,
}

impl El1Registers {
    pub const fn new(elr: u64, spsr: u64, esr: u64, far: u64, vbar: u64) -> Self {
        Self {
            elr,
            spsr,
            esr,
            far,
            vbar,
        }
    }

    pub const fn elr(&self) -> u64 {
        self.elr
    }
    pub const fn spsr(&self) -> u64 {
        self.spsr
    }
    pub const fn esr(&self) -> u64 {
        self.esr
    }
    pub const fn far(&self) -> u64 {
        self.far
    }
    pub const fn vbar(&self) -> u64 {
        self.vbar
    }
    pub fn set_elr(&mut self, value: u64) {
        self.elr = value;
    }
    pub fn set_spsr(&mut self, value: u64) {
        self.spsr = value;
    }
    pub fn set_esr(&mut self, value: u64) {
        self.esr = value;
    }
    pub fn set_far(&mut self, value: u64) {
        self.far = value;
    }
    pub fn set_vbar(&mut self, value: u64) {
        self.vbar = value;
    }
}

/// Persistent GCR fields and RGSR state; effective allocation permission is
/// supplied by the CPU/control owner when constructing a dispatch snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MteState {
    excluded_tags: u16,
    randomization: TagRandomization,
    generation: TagGenerationState,
}

impl MteState {
    pub const fn new(
        excluded_tags: u16,
        randomization: TagRandomization,
        generation: TagGenerationState,
    ) -> Self {
        Self {
            excluded_tags,
            randomization,
            generation,
        }
    }

    pub const fn excluded_tags(&self) -> u16 {
        self.excluded_tags
    }
    pub fn set_excluded_tags(&mut self, value: u16) {
        self.excluded_tags = value;
    }
    pub const fn randomization(&self) -> TagRandomization {
        self.randomization
    }
    pub fn set_randomization(&mut self, value: TagRandomization) {
        self.randomization = value;
    }
    pub const fn generation(&self) -> &TagGenerationState {
        &self.generation
    }
    pub fn generation_mut(&mut self) -> &mut TagGenerationState {
        &mut self.generation
    }

    pub const fn generation_controls(
        &self,
        allocation_access_enabled: bool,
    ) -> TagGenerationControls {
        TagGenerationControls {
            allocation_access_enabled,
            excluded_tags: self.excluded_tags,
            randomization: self.randomization,
        }
    }
}

/// Exactly one inactive stack value. The selected bank and current EL derive
/// from checked PSTATE; flags and the active stack are never copied here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemState {
    pstate_misc: u64,
    inactive_sp: u64,
    el1_registers: El1Registers,
    mte: Option<MteState>,
}

impl SystemState {
    /// `inactive_sp` is the other bank relative to the supplied PSTATE mode.
    pub fn new(
        pstate_misc: u64,
        inactive_sp: u64,
        el1_registers: El1Registers,
    ) -> Result<Self, StateError> {
        Self::checked(pstate_misc, inactive_sp, el1_registers, None)
    }

    /// The authoritative CPU adapter supplies its existing MTE feature value.
    /// This narrow owner supports MTE2+ TCO storage, not MTE1's independent
    /// implementation-defined register/immediate choices.
    pub fn new_with_mte(
        pstate_misc: u64,
        inactive_sp: u64,
        el1_registers: El1Registers,
        feature: MteFeature,
        mte: MteState,
    ) -> Result<Self, StateError> {
        if feature != MteFeature::TwoOrLater {
            return Err(StateError::UnsupportedMteProfile);
        }
        Self::checked(pstate_misc, inactive_sp, el1_registers, Some(mte))
    }

    fn checked(
        pstate_misc: u64,
        inactive_sp: u64,
        el1_registers: El1Registers,
        mte: Option<MteState>,
    ) -> Result<Self, StateError> {
        validate_misc(pstate_misc, mte.is_some())?;
        Ok(Self {
            pstate_misc,
            inactive_sp,
            el1_registers,
            mte,
        })
    }

    /// PSTATE bits owned here; NZCV remains authoritative in GuestState.
    /// Use `pstate` when the complete composed value is required.
    pub const fn pstate_misc(&self) -> u64 {
        self.pstate_misc
    }

    pub fn pstate(&self, registers: &GuestState) -> u64 {
        self.pstate_misc | (u64::from(registers.nzcv) & NZCV_MASK)
    }

    pub fn current_el(&self) -> ExceptionLevel {
        match self.pstate_misc & PSTATE_MODE_MASK {
            PSTATE_EL0T => ExceptionLevel::El0,
            PSTATE_EL1T | PSTATE_EL1H => ExceptionLevel::El1,
            _ => unreachable!("PSTATE mode is checked before storage"),
        }
    }

    pub fn active_stack_bank(&self) -> StackBank {
        stack_bank(self.pstate_misc)
    }

    pub fn stack_pointer(&self, bank: StackBank, registers: &GuestState) -> u64 {
        if bank == self.active_stack_bank() {
            registers.sp
        } else {
            self.inactive_sp
        }
    }

    /// The resolver must perform privilege and trap checks before calling this.
    pub fn read_sp_el0(&self) -> Result<u64, StateError> {
        if self.active_stack_bank() == StackBank::El0 {
            return Err(StateError::ActiveSpEl0);
        }
        Ok(self.inactive_sp)
    }

    /// The resolver must perform privilege and trap checks before calling this.
    pub fn write_sp_el0(&mut self, value: u64) -> Result<(), StateError> {
        if self.active_stack_bank() == StackBank::El0 {
            return Err(StateError::ActiveSpEl0);
        }
        self.inactive_sp = value;
        Ok(())
    }

    pub fn set_spsel(
        &mut self,
        registers: &mut GuestState,
        bank: StackBank,
    ) -> Result<(), StateError> {
        if self.current_el() != ExceptionLevel::El1 {
            return Err(StateError::El0StackSelection);
        }
        let selected = match bank {
            StackBank::El0 => 0,
            StackBank::El1 => SP_SELECT_MASK,
        };
        self.replace_misc(registers, (self.pstate_misc & !SP_SELECT_MASK) | selected);
        Ok(())
    }

    /// Apply an already authorized state transition. No mutation occurs until
    /// all supported-bit and mode checks pass. Exception resolvers still own
    /// legal-return checks, synchronization, monitor/event effects and dispatch.
    pub fn transition_pstate(
        &mut self,
        registers: &mut GuestState,
        psr: u64,
    ) -> Result<(), StateError> {
        let misc = psr & !NZCV_MASK;
        validate_misc(misc, self.mte.is_some())?;
        self.replace_misc(registers, misc);
        registers.nzcv = (psr & NZCV_MASK) as u32;
        Ok(())
    }

    fn replace_misc(&mut self, registers: &mut GuestState, misc: u64) {
        if stack_bank(misc) != self.active_stack_bank() {
            std::mem::swap(&mut registers.sp, &mut self.inactive_sp);
        }
        self.pstate_misc = misc;
    }

    pub const fn el1_registers(&self) -> &El1Registers {
        &self.el1_registers
    }
    pub fn el1_registers_mut(&mut self) -> &mut El1Registers {
        &mut self.el1_registers
    }
    pub const fn mte(&self) -> Option<&MteState> {
        self.mte.as_ref()
    }
    pub fn mte_mut(&mut self) -> Option<&mut MteState> {
        self.mte.as_mut()
    }
    pub fn tag_check_override(&self) -> bool {
        self.pstate_misc & TCO_MASK != 0
    }
}

fn stack_bank(misc: u64) -> StackBank {
    if misc & SP_SELECT_MASK == 0 {
        StackBank::El0
    } else {
        StackBank::El1
    }
}

fn validate_misc(misc: u64, mte: bool) -> Result<(), StateError> {
    if misc & NZCV_MASK != 0 {
        return Err(StateError::FlagsInMiscPstate);
    }
    let allowed = BASE_MISC_MASK | if mte { TCO_MASK } else { 0 };
    let unsupported = misc & !allowed;
    if unsupported != 0 {
        return Err(StateError::UnsupportedPstateBits(unsupported));
    }
    match misc & PSTATE_MODE_MASK {
        PSTATE_EL0T | PSTATE_EL1T | PSTATE_EL1H => Ok(()),
        mode => Err(StateError::UnsupportedMode(mode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::tags::AllocationTag;

    const SP0: u64 = 0x1000;
    const SP1: u64 = 0x2000;
    const FLAGS: u32 = 0xa000_0000;

    fn el1() -> El1Registers {
        El1Registers::new(1, 2, 3, 4, 5)
    }
    fn state(mode: u64) -> (SystemState, GuestState) {
        let sp1_active = mode == PSTATE_EL1H;
        let registers = GuestState {
            sp: if sp1_active { SP1 } else { SP0 },
            nzcv: FLAGS,
            ..GuestState::default()
        };
        (
            SystemState::new(mode, if sp1_active { SP0 } else { SP1 }, el1()).unwrap(),
            registers,
        )
    }

    #[test]
    fn all_supported_modes_derive_el_and_stack() {
        for mode in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
            let (system, registers) = state(mode);
            assert_eq!(
                system.current_el(),
                if mode == PSTATE_EL0T {
                    ExceptionLevel::El0
                } else {
                    ExceptionLevel::El1
                }
            );
            assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
            assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
            assert_eq!(system.pstate(&registers), mode | u64::from(FLAGS));
        }
    }

    #[test]
    fn unsupported_bits_and_modes_are_rejected() {
        assert_eq!(
            SystemState::new(NZCV_MASK, 0, el1()),
            Err(StateError::FlagsInMiscPstate)
        );
        for mode in 0..=PSTATE_MODE_MASK {
            assert_eq!(
                SystemState::new(mode, 0, el1()).is_ok(),
                [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H].contains(&mode)
            );
        }
        for bit in 0..u64::BITS {
            let value = 1u64 << bit;
            if value & (BASE_MISC_MASK | NZCV_MASK) == 0 {
                assert_eq!(
                    SystemState::new(PSTATE_EL1H | value, 0, el1()),
                    Err(StateError::UnsupportedPstateBits(value))
                );
            }
        }
    }

    #[test]
    fn failed_transitions_preserve_complete_state() {
        for psr in [PSTATE_EL1H | TCO_MASK, PSTATE_MODE_MASK, 1 << 63] {
            let (mut system, mut registers) = state(PSTATE_EL0T);
            let before = (system.clone(), registers.clone());
            assert!(system.transition_pstate(&mut registers, psr).is_err());
            assert_eq!((system, registers), before);
        }
    }

    #[test]
    fn transitions_exchange_only_distinct_banks() {
        for from in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
            for to in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
                let (mut system, mut registers) = state(from);
                let original = registers.clone();
                system
                    .transition_pstate(&mut registers, to | u64::from(FLAGS))
                    .unwrap();
                assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
                assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
                let mut expected = original;
                expected.sp = if to == PSTATE_EL1H { SP1 } else { SP0 };
                assert_eq!(registers, expected);
            }
        }
    }

    #[test]
    fn flags_have_only_guest_state_authority() {
        let (mut system, mut registers) = state(PSTATE_EL1T);
        registers.nzcv = u32::MAX;
        assert_eq!(system.pstate(&registers), PSTATE_EL1T | NZCV_MASK);
        system.set_spsel(&mut registers, StackBank::El1).unwrap();
        assert_eq!(registers.nzcv, u32::MAX);
        system
            .transition_pstate(&mut registers, PSTATE_EL0T | u64::from(FLAGS))
            .unwrap();
        assert_eq!(registers.nzcv, FLAGS);
    }

    #[test]
    fn sp_el0_access_rejects_active_bank() {
        for mode in [PSTATE_EL0T, PSTATE_EL1T] {
            let (mut system, _) = state(mode);
            let before = system.clone();
            assert_eq!(system.read_sp_el0(), Err(StateError::ActiveSpEl0));
            assert_eq!(system.write_sp_el0(7), Err(StateError::ActiveSpEl0));
            assert_eq!(system, before);
        }
        let (mut system, registers) = state(PSTATE_EL1H);
        system.write_sp_el0(7).unwrap();
        assert_eq!(system.read_sp_el0(), Ok(7));
        assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
    }

    #[test]
    fn spsel_denies_el0_and_preserves_other_state() {
        for bank in [StackBank::El0, StackBank::El1] {
            let (mut system, mut registers) = state(PSTATE_EL0T);
            let before = (system.clone(), registers.clone());
            assert_eq!(
                system.set_spsel(&mut registers, bank),
                Err(StateError::El0StackSelection)
            );
            assert_eq!((system, registers), before);
        }
        let (mut system, mut registers) = state(PSTATE_EL1T);
        for bank in [StackBank::El1, StackBank::El0, StackBank::El0] {
            system.set_spsel(&mut registers, bank).unwrap();
            assert_eq!(system.active_stack_bank(), bank);
            assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
            assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
            assert_eq!(registers.nzcv, FLAGS);
        }
    }

    #[test]
    fn el1_registers_have_named_accessors() {
        let (mut system, _) = state(PSTATE_EL1H);
        let bank = system.el1_registers_mut();
        bank.set_elr(11);
        bank.set_spsr(12);
        bank.set_esr(13);
        bank.set_far(14);
        bank.set_vbar(15);
        let bank = system.el1_registers();
        assert_eq!(
            (bank.elr(), bank.spsr(), bank.esr(), bank.far(), bank.vbar()),
            (11, 12, 13, 14, 15)
        );
    }

    fn mte() -> MteState {
        MteState::new(
            0x1234,
            TagRandomization::ArchitecturalLfsr,
            TagGenerationState {
                seed: 0x5678,
                tag: AllocationTag::new(9).unwrap(),
            },
        )
    }

    #[test]
    fn mte_profile_is_explicit_and_tco_has_one_owner() {
        for feature in [
            MteFeature::Absent,
            MteFeature::One {
                register_raz_wi: false,
                immediate_ignored: false,
            },
        ] {
            assert_eq!(
                SystemState::new_with_mte(PSTATE_EL1H, SP0, el1(), feature, mte()),
                Err(StateError::UnsupportedMteProfile)
            );
        }
        let mut system = SystemState::new_with_mte(
            PSTATE_EL1H | TCO_MASK,
            SP0,
            el1(),
            MteFeature::TwoOrLater,
            mte(),
        )
        .unwrap();
        let mut registers = GuestState {
            sp: SP1,
            ..GuestState::default()
        };
        assert!(system.tag_check_override());
        system
            .transition_pstate(&mut registers, PSTATE_EL0T | u64::from(FLAGS))
            .unwrap();
        assert!(!system.tag_check_override());
        system
            .transition_pstate(&mut registers, PSTATE_EL1H | TCO_MASK)
            .unwrap();
        assert!(system.tag_check_override());
        assert_eq!(system.mte(), Some(&mte()));
    }

    #[test]
    fn allocation_permission_is_a_snapshot_not_persistent_gcr_state() {
        let mut state = mte();
        for enabled in [true, false, true] {
            let controls = state.generation_controls(enabled);
            assert_eq!(controls.allocation_access_enabled, enabled);
            assert_eq!(controls.excluded_tags, 0x1234);
            assert_eq!(controls.randomization, TagRandomization::ArchitecturalLfsr);
        }
        state.set_excluded_tags(7);
        state.set_randomization(TagRandomization::External);
        state.generation_mut().seed = 11;
        assert_eq!(state.excluded_tags(), 7);
        assert_eq!(state.randomization(), TagRandomization::External);
        assert_eq!(state.generation().seed, 11);
    }
}
