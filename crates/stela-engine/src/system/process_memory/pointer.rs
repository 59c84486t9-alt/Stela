//! FEAT_CPA2 controls for checked memory.

use super::FixedProcessMemoryControls;
#[cfg(feature = "std")]
use super::{ResolvedPointerChecks, SystemState};
#[cfg(feature = "std")]
use crate::system::debug::DebugControls;

// Explicit checked-memory validation for caller-owned raw execution.
#[cfg(feature = "std")]
use super::pointer_checks::{self};
#[cfg(feature = "std")]
use super::{
    MemoryControls, MemoryExecutionLoan, MemoryRequirements, MemoryThread, PointerChecksError,
    ProcessMemoryError,
};
#[cfg(feature = "std")]
use stela_compiler::{
    block::CheckedMemoryProfile,
    context::memory::{
        SpAlignmentRequirement,
        address::{AccessEl, IncrementChoice},
    },
};

#[cfg(feature = "std")]
pub(crate) struct PointerMemoryAuthorization<'run> {
    _controls: &'run FixedProcessMemoryControls,
    _system: &'run SystemState,
    _debug: &'run DebugControls,
    checks: ResolvedPointerChecks,
}
#[cfg(feature = "std")]
impl PointerMemoryAuthorization<'_> {
    pub(crate) const fn checks(&self) -> ResolvedPointerChecks {
        self.checks
    }
}

impl FixedProcessMemoryControls {
    #[cfg(feature = "std")]
    pub(super) fn qualify_pointer<'run>(
        &'run self,
        profile: CheckedMemoryProfile,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        debug: &'run DebugControls,
        thread: &MemoryThread<MemoryControls>,
        execution: &MemoryExecutionLoan,
    ) -> Result<PointerMemoryAuthorization<'run>, ProcessMemoryError> {
        let fail = || ProcessMemoryError::PointerChecks(PointerChecksError::UnsupportedProfile);
        let snapshot = self.identification_snapshot().ok_or_else(fail)?;
        if debug.halted {
            return Err(fail());
        }
        // A missing SCTLR2 is not zero; the lookup may be skipped only when the
        // feature facts make it inapplicable.
        let extended = if self.extended.is_some() {
            Some(
                self.extended_controls(snapshot, thread, execution)
                    .map_err(|_| {
                        ProcessMemoryError::PointerChecks(
                            PointerChecksError::ExtendedControlUnavailable,
                        )
                    })?,
            )
        } else {
            None
        };
        if extended
            .as_ref()
            .is_some_and(|loan| Some(loan.address_space()) != thread.address_space())
        {
            return Err(fail());
        }
        let checks = pointer_checks::resolve(snapshot, Some(debug), extended.as_ref())
            .map_err(ProcessMemoryError::PointerChecks)?;
        let base = if self.sctlr_el1 & super::SCTLR_SP_ALIGNMENT_EL0 != 0 {
            CheckedMemoryProfile::SpAlignmentEnabled
        } else {
            CheckedMemoryProfile::SpAlignmentDisabled
        };
        // `acquire_source_loan` proved EL0t, so both normal and unprivileged
        // accesses use EL0 here. Compare the whole profile, not the combined EL
        // requirements.
        let expected =
            base.with_address_checks(AccessEl::El0, AccessEl::El0, checks.address_checks());
        let arithmetic = if checks.feature().has_arithmetic() {
            expected.with_pointer_arithmetic(checks.arithmetic_at(AccessEl::El0))
        } else {
            None
        };
        if profile != expected && Some(profile) != arithmetic {
            return Err(fail());
        }
        if !requirements
            .required_address_checks
            .matches(checks.address_checks(), IncrementChoice::Unchecked)
        {
            return Err(fail());
        }
        if let Some(required) = requirements.required_pointer_arithmetic
            && (!checks.feature().has_arithmetic()
                || Some(profile) != arithmetic
                || required.access_el() != AccessEl::El0
                || required.checks() != checks.arithmetic_at(AccessEl::El0))
        {
            return Err(fail());
        }
        if requirements.required_sp_alignment != SpAlignmentRequirement::Any
            && requirements.required_sp_alignment != base.sp_requirement()
        {
            return Err(fail());
        }
        Ok(PointerMemoryAuthorization {
            _controls: self,
            _system: system,
            _debug: debug,
            checks,
        })
    }
}

#[cfg(test)]
mod tests {
    //! FEAT_CPA2 controls.
    use super::*;
    use crate::{
        memory::{
            domain::{DataPolicy, MemoryDomain, MemorySystem},
            policy::{LowerAddressProfile, TagCheckFaultMode},
        },
        system::{
            execution::EntryBoundary,
            identification::Register,
            identification_snapshot::Snapshot,
            state::{El1Registers, PSTATE_EL0T},
        },
    };
    use std::sync::Arc;
    use stela_compiler::{
        GuestAddress, GuestState, TargetCpu,
        context::{
            memory::{
                MemoryStatus,
                address::{AddressAddChecks, AddressCheckRequirements, EffectiveAddressChecks},
            },
            pointer::{EffectivePointerChecks, PointerArithmeticRequirement},
        },
    };
    const ADDRESS_SPACE: u64 = 7;
    const ERG_BYTES: u64 = 16;
    const MONITOR_STRIPES: usize = 4;
    const LOWER_BITS: u8 = 39;
    const LOWER_SIZE: u64 = u64::BITS as u64 - LOWER_BITS as u64;
    const EL10_A64: u64 = 0x11;
    const CPA2: u64 = 2;
    const AT_LSE2: u64 = 1 << 32;
    const SCTLRX_TCRX: u64 = 0x11;
    const SOURCE_PC: GuestAddress = GuestAddress(0x4000);
    const ADDPT_X0_X1_X2: u32 = 0x9a02_2020;
    const SCTLR_M_C: u64 = 5;

    fn ids() -> Arc<Snapshot> {
        Arc::new(
            Snapshot::declared(
                "same-owner-CPA2-component",
                &[
                    (Register::IdAa64Pfr0El1, EL10_A64),
                    (Register::IdAa64Mmfr0El1, 0),
                    (Register::IdAa64Mmfr2El1, AT_LSE2),
                    (Register::IdAa64Isar3El1, CPA2),
                    (Register::IdAa64Pfr1El1, 0),
                    (Register::IdAa64Dfr0El1, 0),
                    (Register::IdAa64Mmfr3El1, SCTLRX_TCRX),
                    (Register::IdAa64Mmfr4El1, 0),
                ],
            )
            .unwrap(),
        )
    }
    fn domain() -> Arc<MemoryDomain> {
        MemoryDomain::new_for_address_space(
            ADDRESS_SPACE,
            MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
            Vec::new(),
            TargetCpu::Baseline,
        )
        .unwrap()
    }
    fn source(domain: &Arc<MemoryDomain>) -> super::super::SourceNormalWbDomain {
        // SAFETY: a new empty declared domain, used only for construction.
        unsafe { super::super::SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }
            .unwrap()
    }
    fn memory(domain: &Arc<MemoryDomain>) -> MemoryThread<MemoryControls> {
        domain.thread(MemoryControls::new(
            LowerAddressProfile::new(LOWER_BITS, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ))
    }
    fn state() -> SystemState {
        SystemState::new(PSTATE_EL0T, 0x3000, El1Registers::new(0, 0, 0, 0, 0)).unwrap()
    }
    fn controls(
        ids: Arc<Snapshot>,
        domain: &Arc<MemoryDomain>,
        raw: u64,
    ) -> FixedProcessMemoryControls {
        FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
            ids,
            SCTLR_M_C,
            LOWER_SIZE,
            LOWER_BITS,
            source(domain),
            raw,
            0,
        )
        .unwrap()
    }
    fn profile(mode: EffectivePointerChecks) -> CheckedMemoryProfile {
        let add = if mode == EffectivePointerChecks::Unchecked {
            AddressAddChecks::Disabled
        } else {
            AddressAddChecks::Enabled
        };
        CheckedMemoryProfile::SpAlignmentDisabled
            .with_address_checks(
                AccessEl::El0,
                AccessEl::El0,
                EffectiveAddressChecks::new(add, AddressAddChecks::Disabled),
            )
            .with_pointer_arithmetic(mode)
            .unwrap()
    }
    fn requirements(mode: EffectivePointerChecks) -> MemoryRequirements {
        MemoryRequirements {
            required_pointer_arithmetic: Some(PointerArithmeticRequirement::new(
                AccessEl::El0,
                mode,
            )),
            ..Default::default()
        }
    }

    #[test]
    fn only_extended_factory_can_construct_cpa2_and_base_entry_declines_it() {
        let ids = ids();
        let domain = domain();
        assert!(super::super::ProcessMemoryFeatures::from_snapshot(&ids).is_err());
        assert!(
            FixedProcessMemoryControls::new_with_identification(
                Arc::clone(&ids),
                SCTLR_M_C,
                LOWER_SIZE,
                LOWER_BITS,
                source(&domain)
            )
            .is_err()
        );
        let controls = controls(ids, &domain, super::super::extended_controls::SCTLR2_CPTA0);
        let system = state();
        let registers = GuestState::default();
        let mut memory = memory(&domain);
        let boundary =
            EntryBoundary::new(ADDRESS_SPACE, 1, SOURCE_PC, SOURCE_PC, 4, ADDPT_X0_X1_X2);
        assert!(
            controls
                .prepare(
                    &boundary,
                    MemoryRequirements::default(),
                    &system,
                    &registers,
                    &mut memory,
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn same_bank_modes_bind_full_profile_and_private_policy() {
        for (raw, mode) in [
            (0, EffectivePointerChecks::Unchecked),
            (
                super::super::extended_controls::SCTLR2_CPTA0,
                EffectivePointerChecks::Addition,
            ),
            (
                super::super::extended_controls::SCTLR2_CPTA0
                    | super::super::extended_controls::SCTLR2_CPTM0,
                EffectivePointerChecks::AdditionAndMultiplication,
            ),
        ] {
            let domain = domain();
            let controls = controls(ids(), &domain, raw);
            let system = state();
            let debug = DebugControls::default();
            let memory = memory(&domain);
            let outer = memory.execution_loan().unwrap();
            let required = requirements(mode);
            let selected = profile(mode);
            let authorization = controls
                .qualify_pointer(selected, required, &system, &debug, &memory, &outer)
                .unwrap();
            let unbound = controls.memory_controls(&system);
            assert_eq!(
                unbound.validate_pointer_arithmetic(required.required_pointer_arithmetic),
                Err(MemoryStatus::Unsupported)
            );
            let bound = unbound.with_pointer_authority(&authorization);
            assert_eq!(
                bound.validate_pointer_arithmetic(required.required_pointer_arithmetic),
                Ok(())
            );
            let wrong = selected
                .with_address_checks(
                    AccessEl::El1,
                    AccessEl::El0,
                    authorization.checks().address_checks(),
                )
                .with_pointer_arithmetic(authorization.checks().arithmetic_at(AccessEl::El1))
                .unwrap();
            assert!(
                controls
                    .qualify_pointer(wrong, required, &system, &debug, &memory, &outer)
                    .is_err()
            );
            let opposite = if mode == EffectivePointerChecks::Unchecked {
                EffectivePointerChecks::Addition
            } else {
                EffectivePointerChecks::Unchecked
            };
            assert!(
                controls
                    .qualify_pointer(
                        selected,
                        requirements(opposite),
                        &system,
                        &debug,
                        &memory,
                        &outer
                    )
                    .is_err()
            );
            let address = AddressCheckRequirements::for_access(
                AccessEl::El0,
                if mode == EffectivePointerChecks::Unchecked {
                    AddressAddChecks::Disabled
                } else {
                    AddressAddChecks::Enabled
                },
            );
            assert_eq!(bound.validate_address_checks(address), Ok(()));
            assert_eq!(
                unbound.validate_address_checks(address),
                Err(MemoryStatus::Unsupported)
            );
        }
    }
}
