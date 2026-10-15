//! Component lifecycle tests; no original debug transport or ISA admission.
use super::*;
use crate::system::state::{El1Registers, PSTATE_EL1H};
fn ids() -> Arc<Snapshot> {
    Arc::new(
        Snapshot::declared(
            "debug-lifecycle-component-model",
            &[
                (Register::IdAa64Pfr0El1, 0x11),
                (Register::IdAa64Pfr1El1, 0),
                (Register::IdAa64Pfr2El1, 0),
                (Register::IdAa64Dfr0El1, 9),
                (Register::IdAa64Dfr1El1, 0),
                (Register::IdAa64Mmfr0El1, 0),
                (Register::IdAa64Mmfr1El1, 0),
                (Register::IdAa64Mmfr2El1, 0),
                (Register::IdAa64Isar1El1, 0),
                (Register::IdAa64Isar2El1, 0),
            ],
        )
        .unwrap(),
    )
}
fn initial(status: Status) -> Initialization {
    Initialization {
        edscr: status as u32 | EDSCR_ITE,
        edprsr: if status.halted() { EDPRSR_HALTED } else { 0 },
        dlr: 0x1000,
        dspsr: PSTATE_EL1H,
        edesr: 0,
        edecr: 0,
        mdscr_el1: 0,
        should_advance_ss: true,
        should_advance_hs: true,
        extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
        external: ExternalControls {
            powered: true,
            double_locked: false,
            software_locked: false,
            nonsecure_invasive: true,
            secure_invasive: false,
        },
    }
}
#[test]
fn actual_halted_resource_denies_normal_entry_and_serializes_itr() {
    let mut machine = DebugMachine::fresh_declared(ids(), initial(Status::ResetCatch)).unwrap();
    assert!(machine.qualify_normal_entry().is_err());
    machine.begin_itr().unwrap();
    assert_eq!(machine.edscr() & EDSCR_ITE, 0);
    assert_eq!(machine.begin_itr(), Err(LifecycleError::Busy));
    machine.complete_itr().unwrap();
    assert_eq!(machine.edscr() & EDSCR_ITE, EDSCR_ITE);
    assert_eq!(machine.status(), Status::ResetCatch);
    assert_eq!(machine.dlr(), 0x1000);
    assert_eq!(machine.dspsr(), PSTATE_EL1H);
}
#[test]
fn mismatched_initial_status_and_physical_restart_state_are_explicit() {
    let mut bad = initial(Status::ResetCatch);
    bad.edprsr = 0;
    assert!(matches!(
        DebugMachine::fresh_declared(ids(), bad),
        Err(LifecycleError::InitialStatus)
    ));
    assert!(matches!(
        DebugMachine::fresh_declared(ids(), initial(Status::Restarting)),
        Err(LifecycleError::InitialStatus)
    ));
}
#[test]
fn publication_requires_real_instruction_gate_transition() {
    let mut machine = DebugMachine::fresh_declared(ids(), initial(Status::NonDebug)).unwrap();
    machine.qualify_normal_entry().unwrap();
    assert_eq!(
        machine.publish_halt_instruction(),
        Err(LifecycleError::InitialGate)
    );
    machine.save_halt_state(0x4000, PSTATE_EL1H);
    machine.stop_prefetch_enable_itr();
    machine.publish_halt_instruction().unwrap();
    assert_eq!(machine.status(), Status::HaltInstruction);
    assert_ne!(machine.registers.edprsr & EDPRSR_HALTED, 0);
    assert!(machine.qualify_normal_entry().is_err());
}
#[test]
fn source_step_bookkeeping_changes_only_original_system_storage() {
    let mut machine = DebugMachine::fresh_declared(ids(), initial(Status::NonDebug)).unwrap();
    let mut system =
        SystemState::new(PSTATE_EL1H, 0x1000, El1Registers::new(1, 2, 3, 4, 5)).unwrap();
    let mut registers = GuestState {
        sp: 0x2000,
        nzcv: 0xa0000000,
        ..GuestState::default()
    };
    machine.qualify_initial(&system).unwrap();
    machine.ss_advance(&mut system, &mut registers).unwrap();
    machine.hs_advance(SecurityState::NonSecure);
    assert!(!machine.gate.should_advance_ss);
    assert!(!machine.gate.should_advance_hs);
    assert_eq!(system.pstate(&registers), PSTATE_EL1H | 0xa0000000);
    assert_eq!(registers.sp, 0x2000);
}
