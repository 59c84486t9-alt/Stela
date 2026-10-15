//! Source-bound HVC/SMC selection for the base A64 higher-EL entry subset.
//!
//! This module selects an exception; the canonical exception entry owner alone
//! commits banks, PSTATE, security and runtime effects. Controls are borrowed
//! from their authoritative owner, never initialized here or inferred from the
//! host. Missing controls and unreviewed feature values explicitly decline.

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

/// Readbacks under one canonical control-owner loan. An absent bank is None;
/// an implemented but unavailable bank must also remain None, never zero.
#[derive(Debug, Clone, Copy)]
pub struct ControlReadbacks<'a> {
    pub hcr_el2: Option<&'a u64>,
    pub scr_el3: Option<&'a u64>,
}

/// Actual declared implementation choices, not defaults or enable controls.
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

/// Required architectural instruction prefix, selected as one indivisible kind.
/// The canonical exception owner consumes real source-bound phase authority;
/// this description cannot certify completion or authorize any runtime effect.
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

/// Non-Copy intent consumed by the generalized canonical entry preparer. It is
/// not a permit and cannot execute independently. The entry preparer validates
/// debug/step/IL/optional-state requirements and loans the destination bank.
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
    // HVC: SSAdvance; SMC: HSAdvance then SSAdvance; trapped SMC: neither.
    // Any applicable PACM clear follows these steps in the canonical owner.
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

/// Exact June selection for actual A64 EL0/EL1 sources. Secure EL2, Realm and
/// nested-virtualization execution are explicitly outside this first subset.
/// A64+A32 capability is distinct from actual state: canonical PSTATE and
/// reached HCR/SCR execution-state controls must establish A64 independently.
/// No source-state mutation or platform service occurs during selection.
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
    // EL3 is the highest A64-capable EL, so ELStateUsingAArch32K(EL3)
    // returns FALSE even when its capability also permits A32. For a dual-state
    // EL2 below EL3, actual SCR.RW selects its state. EL1's checked PSTATE is
    // A64; require its actual nonhost lower-EL execution controls to agree.
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
mod tests;
