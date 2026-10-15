use super::super::access::{AccessKind, Encoding};
use super::super::profile::{ScalableEntryAbsence, SystemEntryFeatures};
use super::*;

const SP0: u64 = 0x1230;
const SP1: u64 = 0x4560;
const FLAGS: u32 = 0xa000_0000;
const VECTOR_BASE: u64 = 0x8000;
const SOURCE_PC: u64 = 0x1000;
const RETURN_PC: u64 = 0x2001;
const OLD_ESR: u64 = 0x9876;
const OLD_FAR: u64 = 0x5432;

fn features() -> EntryProfile {
    EntryProfile::base(
        SystemEntryFeatures::declared_absent(),
        ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
    )
    .unwrap()
}

fn controls() -> EntryControls {
    EntryControls {
        tcr_el1: 0,
        mdscr_el1: 0,
        debug: DebugControls::default(),
    }
}

fn state(mode: u64) -> (Profile, SystemState, GuestState) {
    let registers = GuestState {
        sp: if mode == PSTATE_EL1H { SP1 } else { SP0 },
        nzcv: FLAGS,
        x: std::array::from_fn(|i| 0x1020_3040_5060_7080u64.wrapping_mul(i as u64 + 1)),
        v: std::array::from_fn(|i| [0x1122_3344_5566_7788u64 ^ i as u64, !i as u64]),
        reserved: 0xa5a5_5a5a,
        fpcr: 0x0240_0000,
        fpsr: 0x0800_009f,
    };
    let system = SystemState::new(
        mode,
        if mode == PSTATE_EL1H { SP0 } else { SP1 },
        El1Registers::new(
            RETURN_PC,
            PSTATE_EL0T,
            OLD_ESR,
            OLD_FAR,
            VECTOR_BASE | 0x123,
        ),
    )
    .unwrap();
    (
        Profile {
            current_el: system.current_el(),
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        system,
        registers,
    )
}

#[derive(Debug, Default)]
struct Services {
    requests: Vec<ServiceRequest>,
    calls: Vec<EffectStage>,
    fail_preflight: bool,
    fail: Option<EffectStage>,
    monitor_cleared: bool,
    event_set: bool,
}

impl Services {
    fn call(&mut self, stage: EffectStage) -> Result<(), EffectFailure<&'static str>> {
        self.calls.push(stage);
        if self.fail == Some(stage) {
            Err(EffectFailure {
                error: "injected",
                completion: Completion::Partial,
            })
        } else {
            Ok(())
        }
    }
}

impl ExceptionServices for Services {
    type Permit = ();
    type Error = &'static str;
    fn preflight(&mut self, request: ServiceRequest) -> Result<(), Self::Error> {
        self.requests.push(request);
        if self.fail_preflight {
            Err("unavailable")
        } else {
            Ok(())
        }
    }
    fn synchronize_context(
        &mut self,
        _: &mut (),
        _: ExceptionLevel,
    ) -> Result<(), EffectFailure<Self::Error>> {
        self.call(EffectStage::Synchronize)
    }
    fn clear_exclusive_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<Self::Error>> {
        self.call(EffectStage::ClearExclusive)?;
        self.monitor_cleared = true;
        Ok(())
    }
    fn send_event_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<Self::Error>> {
        self.call(EffectStage::SendEvent)?;
        self.event_set = true;
        Ok(())
    }
    fn branch_address(
        &mut self,
        _: &mut (),
        target: u64,
        _: ExceptionLevel,
    ) -> Result<u64, EffectFailure<Self::Error>> {
        self.call(EffectStage::BranchAddress)?;
        Ok(target)
    }
}

#[test]
fn every_source_mode_selects_old_stack_vector_and_preserves_other_state() {
    for (mode, offset) in [(PSTATE_EL0T, 0x400), (PSTATE_EL1T, 0), (PSTATE_EL1H, 0x200)] {
        for irq in [false, true] {
            let (profile, mut system, mut registers) = state(mode);
            let mut expected = registers.clone();
            expected.sp = SP1;
            let old_psr = system.pstate(&registers);
            let event = if irq {
                EntryEvent::Irq { next_pc: SOURCE_PC }
            } else {
                EntryEvent::Undefined {
                    instruction_pc: SOURCE_PC,
                }
            };
            let plan = prepare_entry(&features(), profile, controls(), &system, &registers, event)
                .unwrap();
            let mut services = Services::default();
            let pc = plan
                .execute(&mut system, &mut registers, &mut services)
                .unwrap();
            assert_eq!(pc, VECTOR_BASE + offset + if irq { VECTOR_IRQ } else { 0 });
            assert_eq!(registers, expected);
            assert_eq!(system.stack_pointer(StackBank::El0, &registers), SP0);
            assert_eq!(system.stack_pointer(StackBank::El1, &registers), SP1);
            assert_eq!(
                system.pstate(&registers),
                u64::from(FLAGS) | DAIF_MASK | PSTATE_EL1H
            );
            assert_eq!(system.el1_registers().spsr(), old_psr);
            assert_eq!(system.el1_registers().elr(), SOURCE_PC);
            assert_eq!(
                system.el1_registers().esr(),
                if irq { OLD_ESR } else { 0x0200_0000 }
            );
            assert_eq!(system.el1_registers().far(), OLD_FAR);
            assert_eq!(services.calls, [EffectStage::Synchronize]);
            assert_eq!(services.requests[0].effects, RequiredEffects::Entry { irq });
        }
    }
}

#[test]
fn svc_wraps_pc_and_system_trap_uses_original_selector() {
    let (profile, system, registers) = state(PSTATE_EL0T);
    let svc = prepare_entry(
        &features(),
        profile,
        controls(),
        &system,
        &registers,
        EntryEvent::SupervisorCall {
            instruction_pc: u64::MAX - 3,
            immediate: 0xbeef,
        },
    )
    .unwrap();
    assert_eq!(svc.preferred_pc, 0);
    assert_eq!(svc.esr, Some(0x5600_beef));
    let request = Request::write(Encoding::new(0, 3, 4, 0, 6), 31, 0);
    let trap = prepare_entry(
        &features(),
        profile,
        controls(),
        &system,
        &registers,
        EntryEvent::SystemAccess {
            instruction_pc: SOURCE_PC,
            request,
        },
    )
    .unwrap();
    assert_eq!(trap.preferred_pc, SOURCE_PC);
    assert_eq!(trap.esr, Some(0x620c_d3e0));
    let invalid = Request {
        rt: 32,
        kind: AccessKind::Read,
        ..request
    };
    assert_eq!(
        prepare_entry(
            &features(),
            profile,
            controls(),
            &system,
            &registers,
            EntryEvent::SystemAccess {
                instruction_pc: SOURCE_PC,
                request: invalid
            }
        ),
        Err(PrepareError::InvalidRegisterOperand)
    );
}

#[test]
fn unsupported_contexts_and_masked_irq_decline_without_effects() {
    let (profile, mut system, mut registers) = state(PSTATE_EL0T);
    system
        .transition_pstate(&mut registers, PSTATE_IRQ_MASK)
        .unwrap();
    assert_eq!(
        prepare_entry(
            &features(),
            profile,
            controls(),
            &system,
            &registers,
            EntryEvent::Irq { next_pc: SOURCE_PC }
        ),
        Err(PrepareError::MaskedIrq)
    );
    for security in [SecurityState::Secure, SecurityState::Realm] {
        assert_eq!(
            prepare_return(
                SOURCE_PC,
                &features(),
                Profile {
                    security,
                    ..profile
                },
                controls(),
                &system,
                &registers
            ),
            Err(PrepareError::UnsupportedScope)
        );
    }
    assert_eq!(
        prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers
        ),
        Err(PrepareError::ReturnAtEl0)
    );
}

#[test]
fn legal_return_restores_flags_banks_and_il_but_clears_saved_ss() {
    for mode in [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H] {
        let (profile, mut system, mut registers) = state(PSTATE_EL1H);
        let saved = mode | 0x5000_0000 | PSTATE_IL_MASK | PSTATE_SS_MASK | PSTATE_IRQ_MASK;
        system.el1_registers_mut().set_spsr(saved);
        let before = system.el1_registers().to_owned();
        let mut expected = registers.clone();
        expected.sp = if mode == PSTATE_EL1H { SP1 } else { SP0 };
        expected.nzcv = 0x5000_0000;
        let plan = prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers,
        )
        .unwrap();
        let mut services = Services::default();
        assert_eq!(
            plan.execute(&mut system, &mut registers, &mut services),
            Ok(RETURN_PC)
        );
        assert_eq!(system.pstate(&registers), saved & !PSTATE_SS_MASK);
        assert_eq!(registers, expected);
        assert_eq!(*system.el1_registers(), before);
        assert_eq!(
            services.calls,
            [
                EffectStage::Synchronize,
                EffectStage::ClearExclusive,
                EffectStage::SendEvent,
                EffectStage::BranchAddress
            ]
        );
        assert!(services.monitor_cleared && services.event_set);
    }
}

#[test]
fn illegal_saved_modes_are_explicitly_partial_before_mutation() {
    for mode in 0..=PSTATE_MODE_MASK {
        if [PSTATE_EL0T, PSTATE_EL1T, PSTATE_EL1H].contains(&mode) {
            continue;
        }
        let (profile, mut system, registers) = state(PSTATE_EL1H);
        system.el1_registers_mut().set_spsr(mode);
        assert_eq!(
            prepare_return(
                SOURCE_PC,
                &features(),
                profile,
                controls(),
                &system,
                &registers
            ),
            Err(PrepareError::UnsupportedSavedMode(mode))
        );
    }
}

#[test]
fn failed_return_exposes_exact_completed_prefix_without_rollback() {
    let stages = [
        (EffectStage::Synchronize, CommittedPrefix::None),
        (EffectStage::ClearExclusive, CommittedPrefix::RestoredPstate),
        (EffectStage::SendEvent, CommittedPrefix::ClearedExclusive),
        (EffectStage::BranchAddress, CommittedPrefix::SetLocalEvent),
    ];
    for (index, (stage, committed)) in stages.into_iter().enumerate() {
        let (profile, mut system, mut registers) = state(PSTATE_EL1H);
        system
            .el1_registers_mut()
            .set_spsr(PSTATE_EL0T | 0x5000_0000);
        let before = (system.clone(), registers.clone());
        let plan = prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers,
        )
        .unwrap();
        let mut services = Services {
            fail: Some(stage),
            ..Services::default()
        };
        assert_eq!(
            plan.execute(&mut system, &mut registers, &mut services),
            Err(ExecuteError::Effect {
                stage,
                committed,
                failure: EffectFailure {
                    error: "injected",
                    completion: Completion::Partial
                }
            })
        );
        assert_eq!(services.calls.len(), index + 1);
        if stage == EffectStage::Synchronize {
            assert_eq!((system, registers), before);
        } else {
            assert_eq!(system.pstate(&registers), 0x5000_0000);
            assert_eq!(registers.sp, SP0);
            assert_eq!(*system.el1_registers(), *before.0.el1_registers());
            let mut expected = before.1;
            expected.sp = SP0;
            expected.nzcv = 0x5000_0000;
            assert_eq!(registers, expected);
        }
        assert_eq!(services.monitor_cleared, index >= 2);
        assert_eq!(services.event_set, index >= 3);
    }
}

#[test]
fn preflight_failure_and_stale_plan_make_no_architectural_changes() {
    let (profile, mut system, mut registers) = state(PSTATE_EL1H);
    let plan = prepare_return(
        SOURCE_PC,
        &features(),
        profile,
        controls(),
        &system,
        &registers,
    )
    .unwrap();
    let before = (system.clone(), registers.clone());
    let mut services = Services {
        fail_preflight: true,
        ..Services::default()
    };
    assert_eq!(
        plan.execute(&mut system, &mut registers, &mut services),
        Err(ExecuteError::Preflight("unavailable"))
    );
    assert_eq!((system.clone(), registers.clone()), before);
    assert!(services.calls.is_empty());
    let plan = prepare_return(
        SOURCE_PC,
        &features(),
        profile,
        controls(),
        &system,
        &registers,
    )
    .unwrap();
    system.el1_registers_mut().set_elr(0x3000);
    let before = (system.clone(), registers.clone());
    let mut services = Services::default();
    assert_eq!(
        plan.execute(&mut system, &mut registers, &mut services),
        Err(ExecuteError::StalePlan)
    );
    assert_eq!((system, registers), before);
    assert!(services.requests.is_empty());
}

#[test]
fn entry_captures_old_il_daif_and_sync_failure_preserves_them() {
    for fail in [false, true] {
        let (profile, mut system, mut registers) = state(PSTATE_EL1T);
        let old_psr =
            PSTATE_EL1T | PSTATE_IL_MASK | (DAIF_MASK & !PSTATE_IRQ_MASK) | u64::from(FLAGS);
        system.transition_pstate(&mut registers, old_psr).unwrap();
        let before = (system.clone(), registers.clone());
        let plan = prepare_entry(
            &features(),
            profile,
            controls(),
            &system,
            &registers,
            EntryEvent::Irq { next_pc: SOURCE_PC },
        )
        .unwrap();
        let mut services = Services {
            fail: fail.then_some(EffectStage::Synchronize),
            ..Services::default()
        };
        let result = plan.execute(&mut system, &mut registers, &mut services);
        if fail {
            assert!(matches!(
                result,
                Err(ExecuteError::Effect {
                    committed: CommittedPrefix::None,
                    ..
                })
            ));
            assert_eq!((system, registers), before);
        } else {
            assert_eq!(result, Ok(VECTOR_BASE + VECTOR_IRQ));
            assert_eq!(system.el1_registers().spsr(), old_psr);
            assert_eq!(
                system.pstate(&registers),
                PSTATE_EL1H | DAIF_MASK | u64::from(FLAGS)
            );
        }
    }
}

#[test]
fn illegal_execution_state_precedes_instruction_generated_events_and_eret() {
    let (profile, mut system, mut registers) = state(PSTATE_EL1H);
    system
        .transition_pstate(&mut registers, PSTATE_EL1H | PSTATE_IL_MASK)
        .unwrap();
    for event in [
        EntryEvent::Undefined {
            instruction_pc: SOURCE_PC,
        },
        EntryEvent::SupervisorCall {
            instruction_pc: SOURCE_PC,
            immediate: 0,
        },
        EntryEvent::SystemAccess {
            instruction_pc: SOURCE_PC,
            request: Request::read(Encoding::new(3, 3, 4, 2, 0), 0),
        },
    ] {
        assert_eq!(
            prepare_entry(&features(), profile, controls(), &system, &registers, event),
            Err(PrepareError::UnsupportedIllegalExecutionState)
        );
    }
    assert_eq!(
        prepare_return(
            SOURCE_PC,
            &features(),
            profile,
            controls(),
            &system,
            &registers
        ),
        Err(PrepareError::UnsupportedIllegalExecutionState)
    );
}
