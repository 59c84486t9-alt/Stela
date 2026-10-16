use super::*;
use crate::system::state::{PSTATE_EL0T, PSTATE_EL1H};

mod ordering;
fn state(mode: u64) -> SystemState {
    SystemState::new(mode, 0x1000, El1Registers::new(1, 2, 3, 4, 0x8000)).unwrap()
}
fn context(el: ExceptionLevel) -> Context {
    let traps = FineGrainedTraps {
        esr: false,
        far: false,
        vbar: false,
    };
    Context {
        profile: Profile {
            current_el: el,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        aa64: true,
        gcs: false,
        fine_grained_traps: false,
        controls: Some(Controls {
            effective_nvx: 0,
            hcr_trvm: false,
            hcr_tvm: false,
            scr_fgt_enabled: false,
            read_traps: traps,
            write_traps: traps,
            current_exlock_enabled: false,
            halted: false,
            pstate_exlock: false,
        }),
    }
}
#[test]
fn source_el0_undefined_precedes_unavailable_controls_even_for_xzr() {
    let state = state(PSTATE_EL0T);
    let mut context = context(ExceptionLevel::El0);
    context.controls = None;
    for register in Register::ALL {
        for request in [
            Request::read(register.encoding(), ZERO_REGISTER),
            Request::write(register.encoding(), ZERO_REGISTER, u64::MAX),
        ] {
            assert_eq!(resolve(request, &context, &state), Resolution::Undefined);
        }
    }
}
#[test]
fn illegal_execution_state_precedes_access_and_blocks_every_direct_effect() {
    let mut state = state(PSTATE_EL1H | PSTATE_IL_MASK);
    let before = state.clone();
    let mut context = context(ExceptionLevel::El0);
    context.controls = None;
    for register in Register::ALL {
        for request in [
            Request::read(register.encoding(), ZERO_REGISTER),
            Request::write(register.encoding(), ZERO_REGISTER, u64::MAX),
        ] {
            assert_eq!(
                resolve(request, &context, &state),
                Resolution::Unsupported("illegal execution state requires its exception owner")
            );
            assert_eq!(state, before);
        }
    }
    for effect in [Effect::Elr(5), Effect::Far(6), Effect::Vbar(0x9000)] {
        assert_eq!(
            commit(effect, &mut state),
            Err(CommitError::IllegalExecutionState)
        );
        assert_eq!(state, before);
    }
}

#[test]
fn direct_effects_update_only_the_existing_named_register() {
    for (register, value) in [
        (Register::Elr, u64::MAX),
        (Register::Far, 0x5678),
        (Register::Vbar, 0x9000),
    ] {
        let mut state = state(PSTATE_EL1H);
        let before = state.clone();
        let request = Request::write(register.encoding(), 2, value);
        let Resolution::BackendRequired(BackendRequest::State(effect)) =
            resolve(request, &context(ExceptionLevel::El1), &state)
        else {
            panic!("direct effect");
        };
        commit(effect, &mut state).unwrap();
        assert_eq!(register.value(state.el1_registers()), value);
        for other in Register::ALL {
            if other != register {
                assert_eq!(
                    other.value(state.el1_registers()),
                    other.value(before.el1_registers())
                );
            }
        }
    }
}
#[test]
fn exlock_precedes_elr_nested_memory_and_traps_in_source_order() {
    let state = state(PSTATE_EL1H);
    let mut context = context(ExceptionLevel::El1);
    context.profile.el2_enabled = true;
    context.gcs = true;
    let controls = context.controls.as_mut().unwrap();
    controls.current_exlock_enabled = true;
    controls.pstate_exlock = true;
    let request = Request::write(Register::Elr.encoding(), 0, 1);
    assert_eq!(
        resolve(request, &context, &state),
        Resolution::BackendRequired(BackendRequest::ExlockException(request))
    );
    context.controls.as_mut().unwrap().effective_nvx = NV_TRAP;
    assert_eq!(
        resolve(request, &context, &state),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    context.controls.as_mut().unwrap().effective_nvx = NV_MEMORY;
    assert_eq!(
        resolve(request, &context, &state),
        Resolution::BackendRequired(BackendRequest::NestedMemory {
            offset: ELR_NVMEM,
            request
        })
    );
}
#[test]
fn field_and_forged_effect_requirements_never_silently_mask_writes() {
    let mut state = state(PSTATE_EL1H);
    let before = state.clone();
    for register in [Register::Spsr, Register::Esr] {
        let request = Request::write(register.encoding(), 0, u64::MAX);
        assert_eq!(
            resolve(request, &context(ExceptionLevel::El1), &state),
            Resolution::BackendRequired(BackendRequest::RegisterFields { register, request })
        );
    }
    assert_eq!(
        commit(Effect::Vbar(1), &mut state),
        Err(CommitError::UnalignedVectorBase)
    );
    assert_eq!(state, before);
}
