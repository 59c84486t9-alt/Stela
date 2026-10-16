//! PSTATE register and immediate writes. The caller sets PC afterwards, so a
//! later interrupt observes the completed instruction.

pub mod immediate;

use crate::system::{
    access::{Request, Resolution, StateWrite},
    pstate::{self, Context, DAIF_MASK, NZCV_MASK, PstateField, SP_SELECT_MASK, Snapshot},
    state::{PSTATE_IL_MASK, StackBank, StateError, SystemState},
};
use stela_compiler::GuestState;

const ZERO_REGISTER: u8 = 31;

/// An unapplied effect. Optional effects must reach their owner, never a plain
/// bit store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Nzcv { value: u32 },
    SpEl0 { value: u64 },
    SpSelect { bank: StackBank },
    Daif { mask: u64, value: u64 },
    Backend(pstate::BackendRequest),
    UnownedRead(Request),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    IllegalExecutionState,
    InvalidNzcv,
    InvalidDaifMask,
    InvalidDaifValue,
    State(StateError),
    BackendRequired,
}

/// Resolve against the flags, PSTATE and the inactive stack pointers. TLS reads
/// stay unsupported here and TLS writes stay StateWrite for the typed owner.
/// NotHandled is a family miss, not proof of UNDEFINED.
pub fn resolve(
    request: Request,
    context: &Context,
    system: &SystemState,
    registers: &GuestState,
) -> Resolution<Effect> {
    if context.profile.current_el != system.current_el() {
        return Resolution::Unsupported("PSTATE access context differs from current EL");
    }
    if system.pstate(registers) & PSTATE_IL_MASK != 0 {
        return Resolution::Unsupported("illegal execution state requires its exception owner");
    }
    if request.rt > ZERO_REGISTER {
        return Resolution::Unsupported("system register operand exceeds five bits");
    }
    let snapshot = Snapshot {
        pstate: Some(system.pstate(registers)),
        thread_id_el0: None,
        thread_id_read_only_el0: None,
        thread_id_el1: None,
        stack_pointer_el0: system.read_sp_el0().ok(),
    };
    match pstate::resolve(request, context, &snapshot) {
        Resolution::Read(_) if requires_read_owner(request, context, system) => {
            Resolution::BackendRequired(Effect::UnownedRead(request))
        }
        Resolution::Read(value) => Resolution::Read(value),
        Resolution::Write(StateWrite {
            encoding: pstate::NZCV,
            value,
        }) => Resolution::BackendRequired(Effect::Nzcv {
            value: value as u32,
        }),
        Resolution::Write(StateWrite {
            encoding: pstate::SP_EL0,
            value,
        }) => Resolution::BackendRequired(Effect::SpEl0 { value }),
        Resolution::Write(write) => Resolution::Write(write),
        Resolution::BackendRequired(pstate::BackendRequest::Pstate {
            field: PstateField::Daif,
            mask,
            value,
        }) => Resolution::BackendRequired(Effect::Daif { mask, value }),
        Resolution::BackendRequired(pstate::BackendRequest::Pstate {
            field: PstateField::SpSelect,
            mask: SP_SELECT_MASK,
            value,
        }) => Resolution::BackendRequired(Effect::SpSelect {
            bank: if value & SP_SELECT_MASK == 0 {
                StackBank::El0
            } else {
                StackBank::El1
            },
        }),
        Resolution::BackendRequired(operation) => {
            Resolution::BackendRequired(Effect::Backend(operation))
        }
        Resolution::NotHandled => Resolution::NotHandled,
        Resolution::Unallocated => Resolution::Unallocated,
        Resolution::Undefined => Resolution::Undefined,
        Resolution::Trap(trap) => Resolution::Trap(trap),
        Resolution::Unsupported(reason) => Resolution::Unsupported(reason),
    }
}

fn requires_read_owner(request: Request, context: &Context, system: &SystemState) -> bool {
    match request.encoding {
        pstate::PAN | pstate::UAO | pstate::DIT | pstate::SSBS => true,
        pstate::TCO => match context.features.mte {
            pstate::MteFeature::One {
                register_raz_wi: true,
                ..
            } => false,
            pstate::MteFeature::TwoOrLater => system.mte().is_none(),
            _ => true,
        },
        _ => false,
    }
}

/// Apply only an already authorized direct effect, with no external callbacks.
/// Every rejection occurs before mutation. DAIF updates never touch GuestState
/// flags, active SP, monitor/event state, or asynchronous interrupt delivery.
/// Success is instruction state completion; the runtime must commit nextPC
/// before a later boundary owner can arbitrate pending asynchronous exceptions.
pub fn commit(
    effect: Effect,
    system: &mut SystemState,
    registers: &mut GuestState,
) -> Result<(), CommitError> {
    if system.pstate(registers) & PSTATE_IL_MASK != 0 {
        return Err(CommitError::IllegalExecutionState);
    }
    match effect {
        Effect::Nzcv { value } => {
            if u64::from(value) & !NZCV_MASK != 0 {
                return Err(CommitError::InvalidNzcv);
            }
            registers.nzcv = value;
            Ok(())
        }
        Effect::SpEl0 { value } => system.write_sp_el0(value).map_err(CommitError::State),
        Effect::SpSelect { bank } => system
            .set_spsel(registers, bank)
            .map_err(CommitError::State),
        Effect::Daif { mask, value } => {
            if mask & !DAIF_MASK != 0 {
                return Err(CommitError::InvalidDaifMask);
            }
            if value & !mask != 0 {
                return Err(CommitError::InvalidDaifValue);
            }
            let updated = (system.pstate(registers) & !mask) | value;
            system.write_daif(updated);
            Ok(())
        }
        Effect::Backend(_) | Effect::UnownedRead(_) => Err(CommitError::BackendRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{
        access::{AccessKind, Encoding, ExceptionLevel, Profile, SecurityState, Trap},
        pstate::{Controls, Features, MteFeature, SsbsFeature, ThreadIdTrapBits},
        state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H, PSTATE_EL1T},
    };

    const SP0: u64 = 0x1234_5678_9abc_def1;
    const SP1: u64 = 0xfedc_ba98_7654_3213;
    const ORIGINAL_FLAGS: u32 = 0xa123_4567;
    const REPLACEMENT_FLAGS: u32 = 0x5000_0000;
    const FIELD_PATTERN: u64 = 5;
    const IMMEDIATE_CRN: u8 = 4;

    fn context(level: ExceptionLevel) -> Context {
        let no_traps = ThreadIdTrapBits {
            el0: false,
            read_only_el0: false,
            el1: false,
        };
        Context {
            profile: Profile {
                current_el: level,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            features: Features {
                aa64: true,
                pan: false,
                uao: false,
                dit: false,
                ssbs: SsbsFeature::Absent,
                mte: MteFeature::Absent,
                fine_grained_traps: false,
            },
            controls: Controls {
                el0_in_host: false,
                sctlr_el1_uma: true,
                hcr_el2_tge: false,
                effective_hcr_el2_nvx: 0,
                scr_el3_fgt_enable: false,
                thread_id_read_traps: no_traps,
                thread_id_write_traps: no_traps,
            },
        }
    }

    fn registers() -> GuestState {
        GuestState {
            x: std::array::from_fn(|index| (index as u64).wrapping_mul(0x0101_0101_0101_0101)),
            sp: SP1,
            nzcv: ORIGINAL_FLAGS,
            reserved: 0xdead_beef,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0x1234_5678,
            fpsr: 0x8765_4321,
        }
    }

    fn make_system(mode: u64, daif: u64) -> SystemState {
        SystemState::new(mode | daif, SP0, El1Registers::new(11, 22, 33, 44, 55)).unwrap()
    }

    fn immediate(op1: u8, op2: u8, operand: u8) -> Request {
        Request::write(
            Encoding::new(0, op1, IMMEDIATE_CRN, operand, op2),
            ZERO_REGISTER,
            0,
        )
    }

    fn effect(result: Resolution<Effect>) -> Effect {
        match result {
            Resolution::BackendRequired(effect) => effect,
            other => panic!("expected unapplied effect, got {other:?}"),
        }
    }

    #[test]
    fn actual_owner_reads_preserve_every_state_field_even_for_xzr() {
        let registers = registers();
        let system = make_system(PSTATE_EL1H, FIELD_PATTERN << pstate::DAIF_SHIFT);
        let before = (system.clone(), registers.clone());
        for rt in [0, ZERO_REGISTER] {
            for (encoding, expected) in [
                (pstate::NZCV, u64::from(ORIGINAL_FLAGS) & NZCV_MASK),
                (pstate::DAIF, FIELD_PATTERN << pstate::DAIF_SHIFT),
                (pstate::SPSEL, SP_SELECT_MASK),
                (pstate::SP_EL0, SP0),
                (pstate::CURRENT_EL, PSTATE_EL1T),
            ] {
                assert_eq!(
                    resolve(
                        Request::read(encoding, rt),
                        &context(ExceptionLevel::El1),
                        &system,
                        &registers
                    ),
                    Resolution::Read(expected)
                );
            }
        }
        assert_eq!((system, registers), before);
    }

    #[test]
    fn nzcv_write_and_xzr_source_change_only_the_flags_owner() {
        for (rt, expected_flags) in [(0, REPLACEMENT_FLAGS), (ZERO_REGISTER, 0)] {
            let mut registers = registers();
            let mut system = make_system(PSTATE_EL1H, DAIF_MASK);
            let original_system = system.clone();
            let mut expected_registers = registers.clone();
            expected_registers.nzcv = expected_flags;
            let plan = effect(resolve(
                Request::write(pstate::NZCV, rt, u64::from(REPLACEMENT_FLAGS) | !NZCV_MASK),
                &context(ExceptionLevel::El1),
                &system,
                &registers,
            ));
            commit(plan, &mut system, &mut registers).unwrap();
            assert_eq!(system, original_system);
            assert_eq!(registers, expected_registers);
        }
    }

    #[test]
    fn inactive_sp_write_preserves_active_sp_and_unrelated_owner_state() {
        let mut registers = registers();
        let mut system = make_system(PSTATE_EL1H, DAIF_MASK);
        let before_registers = registers.clone();
        let expected_system =
            SystemState::new(PSTATE_EL1H | DAIF_MASK, SP1, *system.el1_registers()).unwrap();
        let plan = effect(resolve(
            Request::write(pstate::SP_EL0, 0, SP1),
            &context(ExceptionLevel::El1),
            &system,
            &registers,
        ));
        commit(plan, &mut system, &mut registers).unwrap();
        assert_eq!(registers, before_registers);
        assert_eq!(system, expected_system);
        for request in [
            Request::read(pstate::SP_EL0, 0),
            Request::write(pstate::SP_EL0, 0, SP0),
        ] {
            let active_sp0 = make_system(PSTATE_EL1T, 0);
            assert_eq!(
                resolve(
                    request,
                    &context(ExceptionLevel::El1),
                    &active_sp0,
                    &registers
                ),
                Resolution::Undefined
            );
        }
    }

    #[test]
    fn register_and_immediate_spsel_share_bank_switching_and_same_value_behavior() {
        for original_mode in [PSTATE_EL1T, PSTATE_EL1H] {
            for operand in 0..=15 {
                for request in [
                    Request::write(pstate::SPSEL, 0, u64::from(operand)),
                    immediate(0, 5, operand),
                ] {
                    let mut registers = registers();
                    let mut system = make_system(original_mode, DAIF_MASK);
                    let mut expected_registers = registers.clone();
                    let selected = u64::from(operand) & SP_SELECT_MASK;
                    let changed = selected != original_mode & SP_SELECT_MASK;
                    let inactive = if changed {
                        expected_registers.sp = SP0;
                        SP1
                    } else {
                        SP0
                    };
                    let expected_system = SystemState::new(
                        PSTATE_EL1T | selected | DAIF_MASK,
                        inactive,
                        *system.el1_registers(),
                    )
                    .unwrap();
                    let plan = effect(resolve(
                        request,
                        &context(ExceptionLevel::El1),
                        &system,
                        &registers,
                    ));
                    commit(plan, &mut system, &mut registers).unwrap();
                    assert_eq!(registers, expected_registers);
                    assert_eq!(system, expected_system);
                    commit(plan, &mut system, &mut registers).unwrap();
                    assert_eq!(registers, expected_registers);
                    assert_eq!(system, expected_system);
                }
            }
        }
    }

    #[test]
    fn daif_register_and_immediate_effects_preserve_raw_flags_and_other_banks() {
        for original in [0, FIELD_PATTERN, 10, 15] {
            for operand in 0..=15 {
                for (request, expected) in [
                    (
                        Request::write(pstate::DAIF, 0, u64::from(operand) << pstate::DAIF_SHIFT),
                        u64::from(operand),
                    ),
                    (immediate(3, 6, operand), original | u64::from(operand)),
                    (immediate(3, 7, operand), original & !u64::from(operand)),
                ] {
                    let mut registers = registers();
                    let mut system = make_system(PSTATE_EL1H, original << pstate::DAIF_SHIFT);
                    let expected_registers = registers.clone();
                    let expected_system = SystemState::new(
                        PSTATE_EL1H | (expected << pstate::DAIF_SHIFT),
                        SP0,
                        *system.el1_registers(),
                    )
                    .unwrap();
                    let plan = effect(resolve(
                        request,
                        &context(ExceptionLevel::El1),
                        &system,
                        &registers,
                    ));
                    commit(plan, &mut system, &mut registers).unwrap();
                    assert_eq!(registers, expected_registers);
                    assert_eq!(system, expected_system);
                }
            }
        }
    }

    #[test]
    fn zero_immediate_and_xzr_reads_do_not_skip_access_traps() {
        let registers = registers();
        let system = make_system(PSTATE_EL0T, DAIF_MASK);
        let before = (system.clone(), registers.clone());
        let mut context = context(ExceptionLevel::El0);
        context.controls.sctlr_el1_uma = false;
        for target in [ExceptionLevel::El1, ExceptionLevel::El2] {
            context.profile.el2_enabled = target == ExceptionLevel::El2;
            context.controls.hcr_el2_tge = target == ExceptionLevel::El2;
            for request in [
                immediate(3, 6, 0),
                immediate(3, 7, 0),
                Request::read(pstate::DAIF, ZERO_REGISTER),
                Request::write(pstate::DAIF, ZERO_REGISTER, u64::MAX),
            ] {
                assert_eq!(
                    resolve(request, &context, &system, &registers),
                    Resolution::Trap(Trap::system_access(target))
                );
            }
        }
        assert_eq!(
            resolve(immediate(0, 5, 0), &context, &system, &registers),
            Resolution::Undefined
        );
        assert_eq!((system, registers), before);
    }

    #[test]
    fn permitted_el0_daif_and_nzcv_writes_preserve_unrelated_state() {
        let mut registers = registers();
        let mut system = make_system(PSTATE_EL0T, DAIF_MASK);
        let expected_registers = registers.clone();
        let context = context(ExceptionLevel::El0);
        let plan = effect(resolve(immediate(3, 7, 5), &context, &system, &registers));
        commit(plan, &mut system, &mut registers).unwrap();
        let expected_system = SystemState::new(
            PSTATE_EL0T | ((15 & !FIELD_PATTERN) << pstate::DAIF_SHIFT),
            SP0,
            *system.el1_registers(),
        )
        .unwrap();
        assert_eq!(system, expected_system);
        assert_eq!(registers, expected_registers);
        let plan = effect(resolve(
            Request::write(pstate::NZCV, 0, u64::from(REPLACEMENT_FLAGS)),
            &context,
            &system,
            &registers,
        ));
        commit(plan, &mut system, &mut registers).unwrap();
        let mut expected_registers = expected_registers;
        expected_registers.nzcv = REPLACEMENT_FLAGS;
        assert_eq!(system, expected_system);
        assert_eq!(registers, expected_registers);
    }

    #[test]
    fn xzr_writes_zero_to_the_selected_daif_and_inactive_stack_owners() {
        for (encoding, expected_daif, expected_inactive_sp) in
            [(pstate::DAIF, 0, SP0), (pstate::SP_EL0, DAIF_MASK, 0)]
        {
            let mut registers = registers();
            let mut system = make_system(PSTATE_EL1H, DAIF_MASK);
            let expected_registers = registers.clone();
            let expected_system = SystemState::new(
                PSTATE_EL1H | expected_daif,
                expected_inactive_sp,
                *system.el1_registers(),
            )
            .unwrap();
            let plan = effect(resolve(
                Request::write(encoding, ZERO_REGISTER, u64::MAX),
                &context(ExceptionLevel::El1),
                &system,
                &registers,
            ));
            commit(plan, &mut system, &mut registers).unwrap();
            assert_eq!(system, expected_system);
            assert_eq!(registers, expected_registers);
        }
    }

    #[test]
    fn optional_effects_never_commit_as_successful_stored_bits_or_zero_reads() {
        let mut registers = registers();
        let mut system = make_system(PSTATE_EL1H, 0);
        let before = (system.clone(), registers.clone());
        let mut context = context(ExceptionLevel::El1);
        context.features.pan = true;
        context.features.uao = true;
        context.features.dit = true;
        context.features.ssbs = SsbsFeature::ReadWrite;
        context.features.mte = MteFeature::TwoOrLater;
        for encoding in [
            pstate::PAN,
            pstate::UAO,
            pstate::DIT,
            pstate::SSBS,
            pstate::TCO,
        ] {
            let read = Request::read(encoding, 0);
            assert_eq!(
                resolve(read, &context, &system, &registers),
                Resolution::BackendRequired(Effect::UnownedRead(read))
            );
            let plan = effect(resolve(
                Request::write(encoding, 0, u64::MAX),
                &context,
                &system,
                &registers,
            ));
            assert!(matches!(plan, Effect::Backend(_)));
            assert_eq!(
                commit(plan, &mut system, &mut registers),
                Err(CommitError::BackendRequired)
            );
            assert_eq!(
                commit(Effect::UnownedRead(read), &mut system, &mut registers),
                Err(CommitError::BackendRequired)
            );
            assert_eq!((system.clone(), registers.clone()), before);
        }
    }

    #[test]
    fn declared_absence_and_mte1_choices_remain_distinct_from_missing_backend() {
        let mut registers = registers();
        let mut system = make_system(PSTATE_EL1H, 0);
        let mut context = context(ExceptionLevel::El1);
        assert_eq!(
            resolve(Request::read(pstate::DIT, 0), &context, &system, &registers),
            Resolution::Undefined
        );
        context.features.mte = MteFeature::One {
            register_raz_wi: true,
            immediate_ignored: true,
        };
        assert_eq!(
            resolve(Request::read(pstate::TCO, 0), &context, &system, &registers),
            Resolution::Read(0)
        );
        let plan = effect(resolve(immediate(3, 4, 1), &context, &system, &registers));
        assert_eq!(
            plan,
            Effect::Backend(pstate::BackendRequest::IgnoreTcoWrite)
        );
        assert_eq!(
            commit(plan, &mut system, &mut registers),
            Err(CommitError::BackendRequired)
        );
    }

    #[test]
    fn mismatched_or_illegal_source_state_and_forged_effects_fail_before_mutation() {
        let mut registers = registers();
        let mut system = make_system(PSTATE_EL1H, 0);
        let before = (system.clone(), registers.clone());
        assert!(matches!(
            resolve(
                Request::write(pstate::NZCV, 0, 0),
                &context(ExceptionLevel::El0),
                &system,
                &registers
            ),
            Resolution::Unsupported(_)
        ));
        for (plan, error) in [
            (Effect::Nzcv { value: 1 }, CommitError::InvalidNzcv),
            (
                Effect::Daif {
                    mask: SP_SELECT_MASK,
                    value: 0,
                },
                CommitError::InvalidDaifMask,
            ),
            (
                Effect::Daif {
                    mask: 0,
                    value: DAIF_MASK,
                },
                CommitError::InvalidDaifValue,
            ),
        ] {
            assert_eq!(commit(plan, &mut system, &mut registers), Err(error));
            assert_eq!((system.clone(), registers.clone()), before);
        }
        let mut illegal =
            SystemState::new(PSTATE_EL1H | PSTATE_IL_MASK, SP0, *system.el1_registers()).unwrap();
        let illegal_before = illegal.clone();
        assert!(matches!(
            resolve(
                immediate(3, 7, 15),
                &context(ExceptionLevel::El1),
                &illegal,
                &registers
            ),
            Resolution::Unsupported(_)
        ));
        assert_eq!(
            commit(
                Effect::Daif {
                    mask: DAIF_MASK,
                    value: 0
                },
                &mut illegal,
                &mut registers
            ),
            Err(CommitError::IllegalExecutionState)
        );
        assert_eq!(illegal, illegal_before);
        assert_eq!(registers, before.1);
    }

    #[test]
    fn tls_and_other_family_misses_are_not_fabricated_state_owners() {
        let registers = registers();
        let system = make_system(PSTATE_EL1H, 0);
        let context = context(ExceptionLevel::El1);
        assert!(matches!(
            resolve(
                Request::read(pstate::TPIDR_EL0, 0),
                &context,
                &system,
                &registers
            ),
            Resolution::Unsupported(_)
        ));
        assert_eq!(
            resolve(
                Request::write(pstate::TPIDR_EL0, 0, SP0),
                &context,
                &system,
                &registers
            ),
            Resolution::Write(StateWrite {
                encoding: pstate::TPIDR_EL0,
                value: SP0
            })
        );
        let wrong_direction = Request {
            encoding: pstate::CURRENT_EL,
            kind: AccessKind::Write { value: 0 },
            rt: 0,
        };
        assert_eq!(
            resolve(wrong_direction, &context, &system, &registers),
            Resolution::NotHandled
        );
        assert_eq!(
            resolve(immediate(1, 0, 0), &context, &system, &registers),
            Resolution::NotHandled
        );
    }
}
