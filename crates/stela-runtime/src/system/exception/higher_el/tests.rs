use super::*;
use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H};

const INSTRUCTION_PC: u64 = u64::MAX - 1;
const IMMEDIATE: u16 = 0xa55a;
const SOURCE_SP: u64 = 0x1234;
const INACTIVE_SP: u64 = 0x5678;
const SOURCE_FLAGS: u32 = 0xa000_0000;

fn snapshot(el2: bool, el3: bool) -> Snapshot {
    let pfr0 = (A64_ONLY << PFR0_EL0_SHIFT)
        | (A64_ONLY << PFR0_EL1_SHIFT)
        | (u64::from(el2) << PFR0_EL2_SHIFT)
        | (u64::from(el3) << PFR0_EL3_SHIFT);
    Snapshot::declared(
        "higher-el-selector-fixture",
        &[
            (Register::IdAa64Pfr0El1, pfr0),
            (Register::IdAa64Mmfr2El1, FEATURE_ABSENT),
            (Register::IdAa64Mmfr4El1, FEATURE_ABSENT),
        ],
    )
    .unwrap()
}

fn source(mode: u64) -> (SystemState, GuestState) {
    let system =
        SystemState::new(mode, INACTIVE_SP, El1Registers::new(11, 12, 13, 14, 15)).unwrap();
    let registers = GuestState {
        sp: SOURCE_SP,
        nzcv: SOURCE_FLAGS,
        ..GuestState::default()
    };
    (system, registers)
}

fn implementation(policy: TrapSmcWithoutEl3) -> Implementation {
    Implementation {
        without_el3_security: WithoutEl3Security::NonSecureOnly,
        trap_smc_without_el3: policy,
    }
}

fn undefined(selection: Selection<'_>, expected: Undefined) {
    match selection {
        Selection::Undefined(actual) => assert_eq!(actual, expected),
        Selection::Entry(entry) => panic!("unexpected entry: {entry:?}"),
    }
}

#[test]
fn hypervisor_decode_absence_precedes_el0_and_controls() {
    let (system, registers) = source(PSTATE_EL0T);
    let absent = snapshot(false, false);
    undefined(
        select(
            &absent,
            ControlReadbacks {
                hcr_el2: None,
                scr_el3: None,
            },
            implementation(TrapSmcWithoutEl3::Disabled),
            &system,
            &registers,
            INSTRUCTION_PC,
            Call::Hypervisor {
                immediate: IMMEDIATE,
            },
        )
        .unwrap(),
        Undefined::HypervisorLevelAbsent,
    );
    let present = snapshot(true, true);
    undefined(
        select(
            &present,
            ControlReadbacks {
                hcr_el2: None,
                scr_el3: None,
            },
            implementation(TrapSmcWithoutEl3::Disabled),
            &system,
            &registers,
            INSTRUCTION_PC,
            Call::Hypervisor {
                immediate: IMMEDIATE,
            },
        )
        .unwrap(),
        Undefined::UnprivilegedCall,
    );
}

#[test]
fn hvc_hce_replaces_hcd_when_el3_present() {
    let ids = snapshot(true, true);
    let (system, registers) = source(PSTATE_EL1H);
    for hcd in [0, HCR_HCD] {
        for hce in [0, SCR_HCE] {
            let hcr = hcd;
            let scr = SCR_NS | hce;
            let result = select(
                &ids,
                ControlReadbacks {
                    hcr_el2: Some(&hcr),
                    scr_el3: Some(&scr),
                },
                implementation(TrapSmcWithoutEl3::Disabled),
                &system,
                &registers,
                INSTRUCTION_PC,
                Call::Hypervisor {
                    immediate: IMMEDIATE,
                },
            )
            .unwrap();
            if hce == 0 {
                undefined(result, Undefined::HypervisorCallDisabled);
            } else {
                let Selection::Entry(entry) = result else {
                    panic!("enabled HVC declined")
                };
                assert_eq!(entry.target_el, ExceptionLevel::El2);
                assert_eq!(entry.target_security, SecurityState::NonSecure);
                assert_eq!(
                    entry.preferred_pc,
                    INSTRUCTION_PC.wrapping_add(A64_INSTRUCTION_BYTES)
                );
                assert_eq!(
                    entry.esr,
                    (HVC_EXCEPTION_CLASS << ESR_EXCEPTION_CLASS_SHIFT)
                        | ESR_INSTRUCTION_LENGTH
                        | u64::from(IMMEDIATE)
                );
                assert_eq!(entry.call_prefix, CallPrefix::Hypervisor);
            }
        }
    }
}

#[test]
fn smc_tsc_precedes_smd_and_changes_return_address() {
    let ids = snapshot(true, true);
    let (system, registers) = source(PSTATE_EL1H);
    for tsc in [0, HCR_TSC] {
        for smd in [0, SCR_SMD] {
            let hcr = tsc;
            let scr = SCR_NS | smd;
            let result = select(
                &ids,
                ControlReadbacks {
                    hcr_el2: Some(&hcr),
                    scr_el3: Some(&scr),
                },
                implementation(TrapSmcWithoutEl3::Disabled),
                &system,
                &registers,
                INSTRUCTION_PC,
                Call::SecureMonitor {
                    immediate: IMMEDIATE,
                },
            )
            .unwrap();
            if tsc == 0 && smd != 0 {
                undefined(result, Undefined::SecureMonitorCallDisabled);
                continue;
            }
            let Selection::Entry(entry) = result else {
                panic!("enabled SMC declined")
            };
            let trapped = tsc != 0;
            assert_eq!(
                entry.target_el,
                if trapped {
                    ExceptionLevel::El2
                } else {
                    ExceptionLevel::El3
                }
            );
            assert_eq!(
                entry.target_security,
                if trapped {
                    SecurityState::NonSecure
                } else {
                    SecurityState::Secure
                }
            );
            assert_eq!(
                entry.preferred_pc,
                if trapped {
                    INSTRUCTION_PC
                } else {
                    INSTRUCTION_PC.wrapping_add(A64_INSTRUCTION_BYTES)
                }
            );
            assert_eq!(
                entry.esr,
                (SMC_EXCEPTION_CLASS << ESR_EXCEPTION_CLASS_SHIFT)
                    | ESR_INSTRUCTION_LENGTH
                    | u64::from(IMMEDIATE)
            );
            assert_eq!(
                entry.call_prefix,
                if trapped {
                    CallPrefix::TrappedSecureMonitor
                } else {
                    CallPrefix::SecureMonitor
                }
            );
            assert!(std::ptr::eq(entry.snapshot, &ids));
            assert!(std::ptr::eq(entry.source_system, &system));
            assert!(std::ptr::eq(entry.source_registers, &registers));
            assert_eq!(entry.source_pc, INSTRUCTION_PC);
            assert!(std::ptr::eq(entry.controls.scr_el3.unwrap(), &scr));
        }
    }
}

#[test]
fn no_el3_smc_requires_actual_trap_and_explicit_implementation_choice() {
    let ids = snapshot(true, false);
    let (system, registers) = source(PSTATE_EL1H);
    let before = (system.clone(), registers.clone());
    for tsc in [0, HCR_TSC] {
        for policy in [TrapSmcWithoutEl3::Disabled, TrapSmcWithoutEl3::Enabled] {
            let hcr = tsc;
            let result = select(
                &ids,
                ControlReadbacks {
                    hcr_el2: Some(&hcr),
                    scr_el3: None,
                },
                implementation(policy),
                &system,
                &registers,
                INSTRUCTION_PC,
                Call::SecureMonitor {
                    immediate: IMMEDIATE,
                },
            )
            .unwrap();
            if tsc == 0 || policy == TrapSmcWithoutEl3::Disabled {
                undefined(result, Undefined::SecureMonitorLevelAbsent);
            } else {
                let Selection::Entry(entry) = result else {
                    panic!("enabled trap declined")
                };
                assert_eq!(entry.target_el, ExceptionLevel::El2);
                assert_eq!(entry.preferred_pc, INSTRUCTION_PC);
            }
            assert_eq!((&system, &registers), (&before.0, &before.1));
        }
    }
}

#[test]
fn missing_present_controls_remain_unsupported() {
    let ids = snapshot(true, true);
    let (system, registers) = source(PSTATE_EL1H);
    let result = select(
        &ids,
        ControlReadbacks {
            hcr_el2: None,
            scr_el3: None,
        },
        implementation(TrapSmcWithoutEl3::Disabled),
        &system,
        &registers,
        INSTRUCTION_PC,
        Call::Hypervisor {
            immediate: IMMEDIATE,
        },
    );
    assert!(matches!(
        result,
        Err(Unsupported::MissingControl("SCR_EL3"))
    ));
    let scr = SCR_NS;
    let result = select(
        &ids,
        ControlReadbacks {
            hcr_el2: None,
            scr_el3: Some(&scr),
        },
        implementation(TrapSmcWithoutEl3::Disabled),
        &system,
        &registers,
        INSTRUCTION_PC,
        Call::SecureMonitor {
            immediate: IMMEDIATE,
        },
    );
    assert!(matches!(
        result,
        Err(Unsupported::MissingControl("HCR_EL2"))
    ));
}

#[test]
fn dual_state_capability_requires_actual_a64_execution_controls() {
    let pfr0 = (A64_AND_A32 << PFR0_EL0_SHIFT)
        | (A64_AND_A32 << PFR0_EL1_SHIFT)
        | (A64_AND_A32 << PFR0_EL2_SHIFT)
        | (A64_AND_A32 << PFR0_EL3_SHIFT);
    let ids = Snapshot::declared(
        "dual-capability-higher-el-fixture",
        &[
            (Register::IdAa64Pfr0El1, pfr0),
            (Register::IdAa64Mmfr2El1, FEATURE_ABSENT),
            (Register::IdAa64Mmfr4El1, FEATURE_ABSENT),
        ],
    )
    .unwrap();
    let (system, registers) = source(PSTATE_EL1H);
    let scr = SCR_NS | SCR_HCE | SCR_RW;
    let hcr = HCR_RW;
    for call in [
        Call::Hypervisor {
            immediate: IMMEDIATE,
        },
        Call::SecureMonitor {
            immediate: IMMEDIATE,
        },
    ] {
        let result = select(
            &ids,
            ControlReadbacks {
                hcr_el2: Some(&hcr),
                scr_el3: Some(&scr),
            },
            implementation(TrapSmcWithoutEl3::Disabled),
            &system,
            &registers,
            INSTRUCTION_PC,
            call,
        )
        .unwrap();
        assert!(matches!(result, Selection::Entry(_)));
    }
    for (hcr, scr, expected_register, expected_field) in [
        (HCR_RW, SCR_NS | SCR_HCE, "SCR_EL3", "RW"),
        (0, SCR_NS | SCR_HCE | SCR_RW, "HCR_EL2", "RW"),
        (
            HCR_RW | HCR_E2H,
            SCR_NS | SCR_HCE | SCR_RW,
            "HCR_EL2",
            "E2H/TGE",
        ),
        (
            HCR_RW | HCR_TGE,
            SCR_NS | SCR_HCE | SCR_RW,
            "HCR_EL2",
            "E2H/TGE",
        ),
    ] {
        let result = select(
            &ids,
            ControlReadbacks {
                hcr_el2: Some(&hcr),
                scr_el3: Some(&scr),
            },
            implementation(TrapSmcWithoutEl3::Disabled),
            &system,
            &registers,
            INSTRUCTION_PC,
            Call::Hypervisor {
                immediate: IMMEDIATE,
            },
        );
        assert!(
            matches!(result, Err(Unsupported::Control { register, field, .. }) if register == expected_register && field == expected_field)
        );
    }
}

#[test]
fn unreviewed_nested_virtualization_and_incoherent_security_decline() {
    let base =
        (A64_ONLY << PFR0_EL0_SHIFT) | (A64_ONLY << PFR0_EL1_SHIFT) | (A64_ONLY << PFR0_EL2_SHIFT);
    let (system, registers) = source(PSTATE_EL1H);
    let hcr = 0;
    for (nv, nv_frac, expected_field) in [
        (A64_ONLY << MMFR2_NV_SHIFT, 0, "NV"),
        (0, A64_ONLY << MMFR4_NV_FRAC_SHIFT, "NV_frac"),
    ] {
        let ids = Snapshot::declared(
            "unsupported-nv-fixture",
            &[
                (Register::IdAa64Pfr0El1, base),
                (Register::IdAa64Mmfr2El1, nv),
                (Register::IdAa64Mmfr4El1, nv_frac),
            ],
        )
        .unwrap();
        let result = select(
            &ids,
            ControlReadbacks {
                hcr_el2: Some(&hcr),
                scr_el3: None,
            },
            implementation(TrapSmcWithoutEl3::Disabled),
            &system,
            &registers,
            INSTRUCTION_PC,
            Call::Hypervisor {
                immediate: IMMEDIATE,
            },
        );
        assert!(matches!(result, Err(Unsupported::Field { field, .. }) if field == expected_field));
    }
    let ids = snapshot(true, false);
    for hcr in [HCR_E2H, HCR_TGE] {
        let result = select(
            &ids,
            ControlReadbacks {
                hcr_el2: Some(&hcr),
                scr_el3: None,
            },
            implementation(TrapSmcWithoutEl3::Disabled),
            &system,
            &registers,
            INSTRUCTION_PC,
            Call::Hypervisor {
                immediate: IMMEDIATE,
            },
        );
        assert!(matches!(
            result,
            Err(Unsupported::Control {
                register: "HCR_EL2",
                field: "E2H/TGE",
                ..
            })
        ));
    }
    let contradictory = Implementation {
        without_el3_security: WithoutEl3Security::SecureOnly,
        trap_smc_without_el3: TrapSmcWithoutEl3::Disabled,
    };
    let result = select(
        &ids,
        ControlReadbacks {
            hcr_el2: Some(&hcr),
            scr_el3: None,
        },
        contradictory,
        &system,
        &registers,
        INSTRUCTION_PC,
        Call::Hypervisor {
            immediate: IMMEDIATE,
        },
    );
    assert!(matches!(
        result,
        Err(Unsupported::ImplementationSecurityMismatch)
    ));
}
