//! HVC and SMC routing to a higher exception level.

use crate::system::access::{ExceptionLevel, SecurityState};
use crate::system::identification::Register;
use crate::system::identification_snapshot::{Snapshot, Unsupported as IdentificationUnsupported};
use crate::system::state::SystemState;
use stela_compiler::GuestState;

const ID_FIELD_MASK: u64 = 0xf;
const FEATURE_ABSENT: u64 = 0;
const A64_ONLY: u64 = 1;
const A64_AND_A32: u64 = 2;
const PFR0_EL0_SHIFT: u32 = 0;
const PFR0_EL1_SHIFT: u32 = 4;
const PFR0_EL2_SHIFT: u32 = 8;
const PFR0_EL3_SHIFT: u32 = 12;
const PFR0_SEL2_SHIFT: u32 = 36;
const PFR0_RME_SHIFT: u32 = 52;
const MMFR2_NV_SHIFT: u32 = 24;
const MMFR4_NV_FRAC_SHIFT: u32 = 20;
const HCR_HCD: u64 = 1 << 29;
const HCR_TSC: u64 = 1 << 19;
const HCR_RW: u64 = 1 << 31;
const HCR_E2H: u64 = 1 << 34;
const HCR_TGE: u64 = 1 << 27;
const SCR_NS: u64 = 1;
const SCR_SMD: u64 = 1 << 7;
const SCR_HCE: u64 = 1 << 8;
const SCR_RW: u64 = 1 << 10;
const A64_INSTRUCTION_BYTES: u64 = 4;
const ESR_INSTRUCTION_LENGTH: u64 = 1 << 25;
const ESR_EXCEPTION_CLASS_SHIFT: u32 = 26;
const HVC_EXCEPTION_CLASS: u64 = 0x16;
const SMC_EXCEPTION_CLASS: u64 = 0x17;

/// Readbacks under one control-owner borrow. A bank that is absent, or
/// implemented but unavailable, is None, never zero.
#[derive(Debug, Clone, Copy)]
pub struct ControlReadbacks<'a> {
    pub hcr_el2: Option<&'a u64>,
    pub scr_el3: Option<&'a u64>,
}

/// Declared implementation choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Implementation {
    pub without_el3_security: WithoutEl3Security,
    pub trap_smc_without_el3: TrapSmcWithoutEl3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithoutEl3Security {
    NonSecureOnly,
    SecureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapSmcWithoutEl3 {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    Hypervisor { immediate: u16 },
    SecureMonitor { immediate: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    Identification(IdentificationUnsupported),
    Field {
        register: Register,
        field: &'static str,
        value: u64,
    },
    MissingControl(&'static str),
    SourceExceptionLevel(ExceptionLevel),
    SecureSource,
    ImplementationSecurityMismatch,
    Control {
        register: &'static str,
        field: &'static str,
        value: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undefined {
    HypervisorLevelAbsent,
    UnprivilegedCall,
    HypervisorLevelDisabled,
    HypervisorCallDisabled,
    SecureMonitorCallDisabled,
    SecureMonitorLevelAbsent,
}

/// The architectural steps before the call, as one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPrefix {
    Hypervisor,
    SecureMonitor,
    TrappedSecureMonitor,
}

#[derive(Debug)]
pub enum Selection<'a> {
    Undefined(Undefined),
    Entry(EntryRequest<'a>),
}

/// Consumed by the shared entry preparer, which validates the debug, step, IL
/// and optional-state requirements and lends the destination bank.
#[derive(Debug)]
pub struct EntryRequest<'a> {
    pub(crate) snapshot: &'a Snapshot,
    pub(crate) controls: ControlReadbacks<'a>,
    pub(crate) source_system: &'a SystemState,
    pub(crate) source_registers: &'a GuestState,
    pub(crate) source_pc: u64,
    pub(crate) target_el: ExceptionLevel,
    pub(crate) target_security: SecurityState,
    pub(crate) preferred_pc: u64,
    pub(crate) esr: u64,
    // HVC: SSAdvance. SMC: HSAdvance, then SSAdvance. Trapped SMC: neither. Any
    // PACM clear follows these steps.
    pub(crate) call_prefix: CallPrefix,
}

fn field(
    register: Register,
    name: &'static str,
    shift: u32,
    value: u64,
    allowed: &[u64],
) -> Result<u64, Unsupported> {
    let value = (value >> shift) & ID_FIELD_MASK;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(Unsupported::Field {
            register,
            field: name,
            value,
        })
    }
}

fn read(snapshot: &Snapshot, register: Register) -> Result<u64, Unsupported> {
    snapshot.read(register).map_err(Unsupported::Identification)
}

/// Select the target for AArch64 EL0/EL1 sources. Secure EL2, Realm and nested
/// virtualization are unsupported. A64 capability is not the current state:
/// PSTATE and the HCR/SCR execution-state controls must establish AArch64
/// separately. Nothing is changed during selection.
pub fn select<'a>(
    snapshot: &'a Snapshot,
    controls: ControlReadbacks<'a>,
    implementation: Implementation,
    system: &'a SystemState,
    registers: &'a GuestState,
    instruction_pc: u64,
    call: Call,
) -> Result<Selection<'a>, Unsupported> {
    let pfr0_register = Register::IdAa64Pfr0El1;
    let pfr0 = read(snapshot, pfr0_register)?;
    for (name, shift) in [("EL0", PFR0_EL0_SHIFT), ("EL1", PFR0_EL1_SHIFT)] {
        field(pfr0_register, name, shift, pfr0, &[A64_ONLY, A64_AND_A32])?;
    }
    let el2 = field(
        pfr0_register,
        "EL2",
        PFR0_EL2_SHIFT,
        pfr0,
        &[FEATURE_ABSENT, A64_ONLY, A64_AND_A32],
    )? != FEATURE_ABSENT;
    let el3 = field(
        pfr0_register,
        "EL3",
        PFR0_EL3_SHIFT,
        pfr0,
        &[FEATURE_ABSENT, A64_ONLY, A64_AND_A32],
    )? != FEATURE_ABSENT;
    field(
        pfr0_register,
        "SEL2",
        PFR0_SEL2_SHIFT,
        pfr0,
        &[FEATURE_ABSENT],
    )?;
    field(
        pfr0_register,
        "RME",
        PFR0_RME_SHIFT,
        pfr0,
        &[FEATURE_ABSENT],
    )?;

    // HVC's absent-EL2 test is an architectural decode check, before EL0.
    if matches!(call, Call::Hypervisor { .. }) && !el2 {
        return Ok(Selection::Undefined(Undefined::HypervisorLevelAbsent));
    }
    match system.current_el() {
        ExceptionLevel::El0 => return Ok(Selection::Undefined(Undefined::UnprivilegedCall)),
        ExceptionLevel::El1 => {}
        level => return Err(Unsupported::SourceExceptionLevel(level)),
    }
    let scr = if el3 {
        Some(
            *controls
                .scr_el3
                .ok_or(Unsupported::MissingControl("SCR_EL3"))?,
        )
    } else {
        None
    };
    let source_security = match scr {
        Some(scr) if scr & SCR_NS != 0 => SecurityState::NonSecure,
        Some(_) => SecurityState::Secure,
        None if el2 => {
            // With no EL3, implemented EL2 and absent SEL2, the source helper
            // IsSecureBelowEL3 forces NS. A contradictory machine declaration
            // is unsupported, not permission to select a different security.
            if implementation.without_el3_security == WithoutEl3Security::SecureOnly {
                return Err(Unsupported::ImplementationSecurityMismatch);
            }
            SecurityState::NonSecure
        }
        None => match implementation.without_el3_security {
            WithoutEl3Security::NonSecureOnly => SecurityState::NonSecure,
            WithoutEl3Security::SecureOnly => SecurityState::Secure,
        },
    };
    for (register, name, shift) in [
        (Register::IdAa64Mmfr2El1, "NV", MMFR2_NV_SHIFT),
        (Register::IdAa64Mmfr4El1, "NV_frac", MMFR4_NV_FRAC_SHIFT),
    ] {
        field(
            register,
            name,
            shift,
            read(snapshot, register)?,
            &[FEATURE_ABSENT],
        )?;
    }
    // SEL2 is source-proven absent. With EL3, only NS enables EL2; without
    // EL3 the helper enables every implemented EL2 independently of security.
    let el2_enabled = el2 && (!el3 || source_security == SecurityState::NonSecure);
    let (target_el, immediate, trapped) = match call {
        Call::Hypervisor { immediate } => {
            if !el2_enabled {
                return Ok(Selection::Undefined(Undefined::HypervisorLevelDisabled));
            }
            let disabled = if let Some(scr) = scr {
                scr & SCR_HCE == 0
            } else {
                *controls
                    .hcr_el2
                    .ok_or(Unsupported::MissingControl("HCR_EL2"))?
                    & HCR_HCD
                    != 0
            };
            if disabled {
                return Ok(Selection::Undefined(Undefined::HypervisorCallDisabled));
            }
            (ExceptionLevel::El2, immediate, false)
        }
        Call::SecureMonitor { immediate } => {
            let trap = el2_enabled
                && *controls
                    .hcr_el2
                    .ok_or(Unsupported::MissingControl("HCR_EL2"))?
                    & HCR_TSC
                    != 0;
            // TSC has priority over SCR.SMD, including a subsequent no-EL3
            // implementation-policy refusal. HCR is not read if EL2 disabled.
            if !trap && scr.is_some_and(|scr| scr & SCR_SMD != 0) {
                return Ok(Selection::Undefined(Undefined::SecureMonitorCallDisabled));
            }
            if !el3 {
                if !trap {
                    return Ok(Selection::Undefined(Undefined::SecureMonitorLevelAbsent));
                }
                // EffectiveHCR_EL2_NVx() is exactly 000 in this subset.
                if implementation.trap_smc_without_el3 == TrapSmcWithoutEl3::Disabled {
                    return Ok(Selection::Undefined(Undefined::SecureMonitorLevelAbsent));
                }
            }
            (
                if trap {
                    ExceptionLevel::El2
                } else {
                    ExceptionLevel::El3
                },
                immediate,
                trap,
            )
        }
    };
    if source_security != SecurityState::NonSecure {
        return Err(Unsupported::SecureSource);
    }
    // EL3 is the highest AArch64-capable EL, so ELStateUsingAArch32K(EL3) is
    // FALSE even if A32 is also allowed. A dual-state EL2 below EL3 takes its
    // state from SCR.RW. EL1's PSTATE is A64, and its lower-EL execution
    // controls must agree.
    let el1_dual = (pfr0 >> PFR0_EL1_SHIFT) & ID_FIELD_MASK == A64_AND_A32;
    let el2_dual = (pfr0 >> PFR0_EL2_SHIFT) & ID_FIELD_MASK == A64_AND_A32;
    if let Some(scr) = scr
        && (el2 && el2_dual || !el2 && el1_dual)
        && scr & SCR_RW == 0
    {
        return Err(Unsupported::Control {
            register: "SCR_EL3",
            field: "RW",
            value: scr,
        });
    }
    if el2_enabled {
        let hcr = *controls
            .hcr_el2
            .ok_or(Unsupported::MissingControl("HCR_EL2"))?;
        if hcr & (HCR_E2H | HCR_TGE) != 0 {
            return Err(Unsupported::Control {
                register: "HCR_EL2",
                field: "E2H/TGE",
                value: hcr,
            });
        }
        if el1_dual && hcr & HCR_RW == 0 {
            return Err(Unsupported::Control {
                register: "HCR_EL2",
                field: "RW",
                value: hcr,
            });
        }
    }
    let exception_class = match call {
        Call::Hypervisor { .. } => HVC_EXCEPTION_CLASS,
        Call::SecureMonitor { .. } => SMC_EXCEPTION_CLASS,
    };
    Ok(Selection::Entry(EntryRequest {
        snapshot,
        controls,
        source_system: system,
        source_registers: registers,
        source_pc: instruction_pc,
        target_el,
        target_security: if target_el == ExceptionLevel::El3 {
            SecurityState::Secure
        } else {
            SecurityState::NonSecure
        },
        preferred_pc: if trapped {
            instruction_pc
        } else {
            instruction_pc.wrapping_add(A64_INSTRUCTION_BYTES)
        },
        esr: (exception_class << ESR_EXCEPTION_CLASS_SHIFT)
            | ESR_INSTRUCTION_LENGTH
            | u64::from(immediate),
        call_prefix: match call {
            Call::Hypervisor { .. } => CallPrefix::Hypervisor,
            Call::SecureMonitor { .. } if trapped => CallPrefix::TrappedSecureMonitor,
            Call::SecureMonitor { .. } => CallPrefix::SecureMonitor,
        },
    }))
}

#[cfg(test)]
mod tests {
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
        let base = (A64_ONLY << PFR0_EL0_SHIFT)
            | (A64_ONLY << PFR0_EL1_SHIFT)
            | (A64_ONLY << PFR0_EL2_SHIFT);
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
            assert!(
                matches!(result, Err(Unsupported::Field { field, .. }) if field == expected_field)
            );
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
}
