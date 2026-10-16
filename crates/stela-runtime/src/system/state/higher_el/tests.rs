use super::*;
use crate::system::state::{PSTATE_EL1H, PSTATE_EL2H, PSTATE_EL3H, StackBank, SystemState};
use stela_compiler::GuestState;

fn snapshot(pfr0: u64) -> Arc<Snapshot> {
    Arc::new(
        Snapshot::declared(
            "privileged-state-component-model",
            &[
                (Register::IdAa64Pfr0El1, pfr0),
                (Register::IdAa64Pfr1El1, 0),
                (Register::IdAa64Pfr2El1, 0),
                (Register::IdAa64Dfr0El1, 0),
                (Register::IdAa64Dfr1El1, 0),
                (Register::IdAa64Mmfr0El1, 0),
                (Register::IdAa64Mmfr1El1, 0),
                (Register::IdAa64Mmfr2El1, 0),
                (Register::IdAa64Mmfr4El1, 0),
                (Register::IdAa64Isar1El1, 0),
                (Register::IdAa64Isar2El1, 0),
            ],
        )
        .unwrap(),
    )
}
fn initial() -> Initialization {
    Initialization {
        el2: Some(El2Initialization {
            exception: El1Registers::new(21, 22, 23, 24, 25),
            stack_pointer: 0x3000,
            hcr: 0,
            sctlr: 0,
            tcr: 0,
            hpfar: 26,
        }),
        el3: Some(El3Initialization {
            exception: El1Registers::new(31, 32, 33, 34, 35),
            stack_pointer: 0x4000,
            scr: SCR_NS,
            sctlr: 0,
            tcr: 0,
        }),
    }
}
#[test]
fn higher_banks_do_not_relax_base_regime_or_accept_missing_storage() {
    let ids = snapshot(0x1111);
    assert!(ids.check_el10_regime().is_err());
    assert!(ids.entry_profile().is_err());
    assert!(HigherElState::initialized(ids.clone(), initial()).is_ok());
    let mut missing = initial();
    missing.el2 = None;
    assert_eq!(
        HigherElState::initialized(ids, missing).unwrap_err(),
        InitializationError::BankPresence(ExceptionLevel::El2)
    );
    let absent = snapshot(0x11);
    assert_eq!(
        HigherElState::initialized(absent, initial()).unwrap_err(),
        InitializationError::BankPresence(ExceptionLevel::El2)
    );
}
#[test]
fn bank_transitions_preserve_actual_stack_values_and_flags() {
    let mut state = SystemState::new_with_higher_el(
        PSTATE_EL1H,
        0x1000,
        El1Registers::new(1, 2, 3, 4, 5),
        snapshot(0x1111),
        initial(),
    )
    .unwrap();
    let mut registers = GuestState {
        sp: 0x2000,
        nzcv: 0xa0000000,
        ..GuestState::default()
    };
    for mode in [
        PSTATE_EL2H,
        PSTATE_EL3H,
        PSTATE_EL1H,
        PSTATE_EL3H,
        PSTATE_EL2H,
        PSTATE_EL1H,
    ] {
        state
            .transition_pstate(&mut registers, mode | 0xa0000000)
            .unwrap();
        for (bank, value) in [
            (StackBank::El0, 0x1000),
            (StackBank::El1, 0x2000),
            (StackBank::El2, 0x3000),
            (StackBank::El3, 0x4000),
        ] {
            assert_eq!(state.read_stack_pointer(bank, &registers), Ok(value));
        }
        assert_eq!(registers.nzcv, 0xa0000000);
    }
    assert_eq!(
        state
            .exception_registers(ExceptionLevel::El1)
            .unwrap()
            .elr(),
        1
    );
    assert_eq!(
        state
            .exception_registers(ExceptionLevel::El2)
            .unwrap()
            .elr(),
        21
    );
    assert_eq!(
        state
            .exception_registers(ExceptionLevel::El3)
            .unwrap()
            .elr(),
        31
    );
}
#[test]
fn same_raw_declaration_is_not_same_snapshot() {
    let ids = snapshot(0x1111);
    let (banks, _, _) = HigherElState::initialized(ids.clone(), initial()).unwrap();
    assert!(banks.same_snapshot(&ids));
    assert!(!banks.same_snapshot(&snapshot(0x1111)));
    assert_eq!(
        banks.security(ExceptionLevel::El1),
        SecurityState::NonSecure
    );
    assert_eq!(banks.security(ExceptionLevel::El3), SecurityState::Secure);
}
#[test]
fn dual_state_controls_and_lower_security_must_be_explicit_a64() {
    let mut config = initial();
    let ids = snapshot(0x1222);
    assert!(matches!(
        HigherElState::initialized(ids.clone(), config),
        Err(InitializationError::ExecutionState {
            register: "SCR_EL3.RW",
            ..
        })
    ));
    config.el3.as_mut().unwrap().scr |= SCR_RW;
    assert!(matches!(
        HigherElState::initialized(ids.clone(), config),
        Err(InitializationError::ExecutionState {
            register: "HCR_EL2.RW",
            ..
        })
    ));
    config.el2.as_mut().unwrap().hcr |= HCR_RW;
    assert!(HigherElState::initialized(ids.clone(), config).is_ok());
    config.el3.as_mut().unwrap().scr &= !SCR_NS;
    assert_eq!(
        HigherElState::initialized(ids, config).unwrap_err(),
        InitializationError::LowerSecurity
    );
}

#[test]
fn lower_only_storage_guard_rejects_present_zero_higher_banks() {
    let lower = SystemState::new(PSTATE_EL1H, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
    assert_eq!(lower.check_lower_el_storage(), Ok(()));
    let mut banks = initial();
    let el2 = banks.el2.as_mut().unwrap();
    el2.exception = El1Registers::new(0, 0, 0, 0, 0);
    el2.stack_pointer = 0;
    el2.hpfar = 0;
    let el3 = banks.el3.as_mut().unwrap();
    el3.exception = El1Registers::new(0, 0, 0, 0, 0);
    el3.stack_pointer = 0;
    let higher = SystemState::new_with_higher_el(
        PSTATE_EL1H,
        0,
        El1Registers::new(0, 0, 0, 0, 0),
        snapshot(0x1111),
        banks,
    )
    .unwrap();
    assert_eq!(
        higher.check_lower_el_storage(),
        Err(StateError::UnexpectedHigherElStorage)
    );
}
