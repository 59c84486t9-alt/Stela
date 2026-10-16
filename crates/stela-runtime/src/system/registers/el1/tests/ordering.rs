use super::*;
use crate::system::state::PSTATE_EL1H;

fn inputs() -> (SystemState, Context) {
    let state = SystemState::new(PSTATE_EL1H, 0, El1Registers::new(1, 2, 3, 4, 0x8123)).unwrap();
    let no_traps = FineGrainedTraps {
        esr: false,
        far: false,
        vbar: false,
    };
    let context = Context {
        profile: Profile {
            current_el: ExceptionLevel::El1,
            security: SecurityState::NonSecure,
            el2_enabled: true,
            el3_present: true,
        },
        aa64: true,
        gcs: false,
        fine_grained_traps: true,
        controls: Some(Controls {
            effective_nvx: NV_MEMORY,
            hcr_trvm: false,
            hcr_tvm: false,
            scr_fgt_enabled: true,
            read_traps: no_traps,
            write_traps: no_traps,
            current_exlock_enabled: false,
            halted: false,
            pstate_exlock: false,
        }),
    };
    (state, context)
}

#[test]
fn vm_and_direction_specific_fgt_traps_precede_nested_redirection() {
    let (state, mut context) = inputs();
    let read = Request::read(Register::Esr.encoding(), ZERO_REGISTER);
    let write = Request::write(Register::Esr.encoding(), ZERO_REGISTER, u64::MAX);
    context.controls.as_mut().unwrap().hcr_trvm = true;
    assert_eq!(
        resolve(read, &context, &state),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    assert_eq!(
        resolve(write, &context, &state),
        Resolution::BackendRequired(BackendRequest::NestedMemory {
            offset: ESR_NVMEM,
            request: write
        })
    );
    context.controls.as_mut().unwrap().hcr_trvm = false;
    context.controls.as_mut().unwrap().read_traps.esr = true;
    assert_eq!(
        resolve(read, &context, &state),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    context.controls.as_mut().unwrap().scr_fgt_enabled = false;
    assert_eq!(
        resolve(read, &context, &state),
        Resolution::BackendRequired(BackendRequest::NestedMemory {
            offset: ESR_NVMEM,
            request: read
        })
    );
}

#[test]
fn vector_read_res0_does_not_authorize_masking_an_unknown_write_policy() {
    let (state, mut context) = inputs();
    context.controls.as_mut().unwrap().effective_nvx = 0;
    assert_eq!(
        resolve(
            Request::read(Register::Vbar.encoding(), 2),
            &context,
            &state
        ),
        Resolution::Read(0x8000)
    );
    let write = Request::write(Register::Vbar.encoding(), 2, 0x8123);
    assert_eq!(
        resolve(write, &context, &state),
        Resolution::BackendRequired(BackendRequest::RegisterFields {
            register: Register::Vbar,
            request: write
        })
    );
}

#[test]
fn missing_controls_and_profile_mismatch_cannot_return_bank_values() {
    let (state, mut context) = inputs();
    let request = Request::read(Register::Far.encoding(), 0);
    context.controls = None;
    assert_eq!(
        resolve(request, &context, &state),
        Resolution::BackendRequired(BackendRequest::ControlsRequired(request))
    );
    context.profile.current_el = ExceptionLevel::El0;
    assert!(matches!(
        resolve(request, &context, &state),
        Resolution::Unsupported(_)
    ));
}
