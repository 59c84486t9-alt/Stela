//! Unapplied HLT/DCPS semantic intent. This module owns no architectural state.
//!
//! A plan is a recipe, never an execution permit or a successful instruction.
//! The canonical consumer must bind its exact word to the actual original-source
//! loan and consume its own one-use PE/phase authority. It alone applies the
//! ordered steps to the existing SystemState, DebugMachine and InstructionGate,
//! settles every terminal/prefix, and poisons indeterminate completion. There is
//! deliberately no generic Owner trait, executor, callback, or success fallback.

use super::halted::Status;
use crate::system::access::{ExceptionLevel, SecurityState};
use crate::system::pstate::{
    DAIF_MASK as PSTATE_DAIF, PAN_MASK as PSTATE_PAN, SP_SELECT_MASK as PSTATE_SPX,
    SSBS_MASK as PSTATE_SSBS, TCO_MASK as PSTATE_TCO, UAO_MASK as PSTATE_UAO,
};
use crate::system::state::{
    PSTATE_EL_SHIFT, PSTATE_IL_MASK as PSTATE_IL, PSTATE_MODE_MASK, PSTATE_SS_MASK as PSTATE_SS,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_compiler::aarch64::system::exception::{self, DebugTarget, Operation};

const PSTATE_BTYPE: u64 = 3 << 10;
const PSTATE_EXLOCK: u64 = 1 << 34;
const PSTATE_PACM: u64 = 1 << 35;
const PSTATE_UINJ: u64 = 1 << 36;
const SCTLR_SPAN: u64 = 1 << 23;
const EDSCR_EL_MASK: u32 = 3 << 8;
const EDSCR_EL_SHIFT: u32 = 8;
const EDSCR_RW_MASK: u32 = 0xf << 10;
const EDSCR_A64_RW: u32 = 0xf << 10;
const EDSCR_SERROR_PENDING: u32 = 1 << 7;
const EDSCR_SDD: u32 = 1 << 16;
const EDSCR_NS: u32 = 1 << 18;
const EDSCR_HDE: u32 = 1 << 14;
const EDSCR_MA: u32 = 1 << 20;
const EDSCR_ITE: u32 = 1 << 24;
const EDSCR_ITO: u32 = 1 << 28;
const HCR_AMO: u64 = 1 << 5;
const HCR_TGE: u64 = 1 << 27;

/// One documented, deterministic ARBITRARY selection, not an original oracle.
pub(crate) const ARBITRARY_REGISTER_ZERO: u64 = 0;
const ARBITRARY_HALT_PSTATE_ZERO: u64 = 0;

/// Filter the compiler-owned decoder without discarding its immediate/source
/// identity. There is no second runtime encoding table.
fn halting_operation(word: u32) -> Option<Operation> {
    match exception::decode(word)? {
        operation @ (Operation::Halt { .. } | Operation::DebugChange { .. }) => Some(operation),
        _ => None,
    }
}

/// Immutable instruction identity prepared by the existing System boundary.
/// Decoding is preparation work and is never repeated in the execution callback.
/// The containing canonical artifact retains input identity/build/source maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Instruction {
    word: u32,
    operation: Operation,
}
impl Instruction {
    pub(crate) fn prepare(word: u32) -> Option<Self> {
        Some(Self {
            word,
            operation: halting_operation(word)?,
        })
    }
}

/// Readbacks of the owner while its exclusive lease is held. The canonical
/// snapshot adapter derives feature presence; callers cannot manufacture a CPU
/// profile from compiler feature metadata. This value is never a mutable bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Features {
    pub pan: bool,
    pub uao: bool,
    pub mte: bool,
    pub bti: bool,
    pub pauth_lr: bool,
    pub gcs: bool,
    pub uinj: bool,
    pub brbe: bool,
    pub edhsr: bool,
    pub rme: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Context {
    pub features: Features,
    pub current_el: ExceptionLevel,
    pub security: SecurityState,
    pub aarch64_at_all_present_els: bool,
    pub el2_present: bool,
    pub el2_enabled: bool,
    pub el3_present: bool,
    pub secure_el2_enabled: bool,
    pub host_at_el0: bool,
    pub hcr_el2: Option<u64>,
    pub sctlr_el1: u64,
    pub sctlr_el2: Option<u64>,
    pub double_lock: bool,
    pub external_invasive_enabled: bool,
    pub external_secure_invasive_enabled: bool,
    pub delegated_serror_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unsupported {
    Aarch32State,
    RealmState,
    DecodeBtypeCompatibility,
    MissingControl(&'static str),
}

/// Symbolic operations. Runtime-dependent values are read at their source step,
/// after previous real effects, rather than cached in this preparation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    CrossHalt,
    SaveDlrAndDebugPsr,
    InitializeHaltEdscr,
    SetHaltPstate,
    BranchRecordDebugEntry,
    StopPrefetchEnableItr,
    PublishHaltInstruction,
    UpdateEdscrFields,
    UpdateExtendedHaltSyndrome,
    EndInstructionException,
    SynchronizeContext,
    UndefinedInDebugState,
    MaybeZeroSveUppers { requested: ExceptionLevel },
    SelectHandlerPstate { handler: ExceptionLevel },
    WriteHandlerArbitrary { handler: ExceptionLevel },
    WriteDlrDspsrArbitrary,
    SetDcpsOptionalPstate,
    CompleteHaltedInjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Halt,
    Dcps {
        requested: ExceptionLevel,
        handler: Option<ExceptionLevel>,
    },
}

/// Non-Clone, non-executable intent. Context/status/EDSCR are diagnostics, not
/// authority; the canonical consumer must requalify them under its actual loan.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    instruction: Instruction,
    context: Context,
    status: Status,
    edscr: u32,
    kind: Kind,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Preparation {
    DecodeUndefined,
    Plan(Plan),
}

pub(crate) fn prepare(
    instruction: Instruction,
    context: Context,
    status: Status,
    edscr: u32,
) -> Result<Preparation, Unsupported> {
    if context.el2_present && (context.hcr_el2.is_none() || context.sctlr_el2.is_none()) {
        return Err(Unsupported::MissingControl("EL2 controls"));
    }
    if !context.aarch64_at_all_present_els {
        return Err(Unsupported::Aarch32State);
    }
    if context.features.rme || context.security == SecurityState::Realm {
        return Err(Unsupported::RealmState);
    }
    let kind = match instruction.operation {
        Operation::Halt { .. } => {
            let invasive = match context.security {
                SecurityState::NonSecure => context.external_invasive_enabled,
                SecurityState::Secure => context.external_secure_invasive_enabled,
                SecurityState::Realm => unreachable!("RME refused above"),
            };
            if status.halted() || context.double_lock || !invasive || edscr & EDSCR_HDE == 0 {
                return Ok(Preparation::DecodeUndefined);
            }
            // HLT SetBTypeCompatible belongs to real decode/fetch priority.
            if context.features.bti {
                return Err(Unsupported::DecodeBtypeCompatibility);
            }
            Kind::Halt
        }
        Operation::DebugChange { target, .. } => {
            if !status.halted() {
                return Ok(Preparation::DecodeUndefined);
            }
            let requested = match target {
                DebugTarget::El1 => ExceptionLevel::El1,
                DebugTarget::El2 => ExceptionLevel::El2,
                DebugTarget::El3 => ExceptionLevel::El3,
            };
            Kind::Dcps {
                requested,
                handler: dcps_handle(requested, context, edscr),
            }
        }
        _ => unreachable!("Instruction is compiler-decoded HLT/DCPS only"),
    };
    Ok(Preparation::Plan(Plan {
        instruction,
        context,
        status,
        edscr,
        kind,
    }))
}

impl Plan {
    pub(crate) fn word(&self) -> u32 {
        self.instruction.word
    }

    /// Source-ordered intent only. In particular, a DCPS target Undefined is
    /// subsequent to actual SynchronizeContext, never a preparation success.
    pub(crate) fn steps(&self) -> Vec<Step> {
        match self.kind {
            Kind::Halt => {
                let mut steps = vec![
                    Step::CrossHalt,
                    Step::SaveDlrAndDebugPsr,
                    Step::InitializeHaltEdscr,
                    Step::SetHaltPstate,
                ];
                if self.context.features.brbe {
                    steps.push(Step::BranchRecordDebugEntry);
                }
                steps.extend([
                    Step::StopPrefetchEnableItr,
                    Step::PublishHaltInstruction,
                    Step::UpdateEdscrFields,
                ]);
                if self.context.features.edhsr {
                    steps.push(Step::UpdateExtendedHaltSyndrome);
                }
                steps.push(Step::EndInstructionException);
                steps
            }
            Kind::Dcps {
                requested,
                handler: None,
            } => {
                let _ = requested;
                vec![Step::SynchronizeContext, Step::UndefinedInDebugState]
            }
            Kind::Dcps {
                requested,
                handler: Some(handler),
            } => vec![
                Step::SynchronizeContext,
                Step::MaybeZeroSveUppers { requested },
                Step::SelectHandlerPstate { handler },
                Step::WriteHandlerArbitrary { handler },
                Step::WriteDlrDspsrArbitrary,
                Step::SetDcpsOptionalPstate,
                Step::UpdateEdscrFields,
                Step::CompleteHaltedInjection,
            ],
        }
    }
}

/// Apply only to the actual source PSTATE at SetHaltPstate. The deterministic
/// ARBITRARY zero policy is a software choice, not original-oracle equality.
pub(crate) fn halt_pstate(previous: u64, features: Features) -> u64 {
    let mut next = previous & !(PSTATE_SS | PSTATE_SSBS | PSTATE_DAIF | PSTATE_IL);
    next |= ARBITRARY_HALT_PSTATE_ZERO;
    if features.mte {
        next |= PSTATE_TCO;
    }
    if features.bti {
        next &= !PSTATE_BTYPE;
    }
    if features.pauth_lr {
        next &= !PSTATE_PACM;
    }
    if features.uinj {
        next &= !PSTATE_UINJ;
    }
    next
}

/// Apply after SaveDlrAndDebugPsr, preserving ERR and STATUS until publication.
pub(crate) fn halt_edscr(previous: u32, context: Context) -> u32 {
    let initialized = (previous | EDSCR_ITE) & !(EDSCR_ITO | EDSCR_MA);
    let disabled = match context.security {
        SecurityState::Secure => false,
        SecurityState::NonSecure => {
            !context.el3_present || !context.external_secure_invasive_enabled
        }
        SecurityState::Realm => unreachable!("RME refused before a plan exists"),
    };
    set_bit(initialized, EDSCR_SDD, disabled)
}

fn dcps_handle(target: ExceptionLevel, context: Context, edscr: u32) -> Option<ExceptionLevel> {
    use ExceptionLevel::{El0, El1, El2, El3};
    match target {
        El1 => match context.current_el {
            El2 | El3 => Some(context.current_el),
            El0 | El1
                if context.el2_enabled
                    && context.hcr_el2.is_some_and(|value| value & HCR_TGE != 0) =>
            {
                None
            }
            El0 | El1 => Some(El1),
        },
        El2 if !context.el2_present => None,
        El2 if context.current_el == El3 => Some(El3),
        El2 if !context.secure_el2_enabled && context.security == SecurityState::Secure => None,
        El2 => Some(El2),
        El3 if edscr & EDSCR_SDD != 0 || !context.el3_present => None,
        El3 => Some(El3),
        El0 => unreachable!("DCPS has no EL0 encoding"),
    }
}

pub(crate) fn dcps_pstate(previous: u64, handle: ExceptionLevel, context: Context) -> u64 {
    let mut next =
        (previous & !PSTATE_MODE_MASK) | (el_number(handle) << PSTATE_EL_SHIFT) | PSTATE_SPX;
    if context.features.pan
        && ((handle == ExceptionLevel::El1 && context.sctlr_el1 & SCTLR_SPAN == 0)
            || (handle == ExceptionLevel::El2
                && context.host_at_el0
                && context
                    .sctlr_el2
                    .is_some_and(|value| value & SCTLR_SPAN == 0)))
    {
        next |= PSTATE_PAN;
    }
    next
}

pub(crate) fn dcps_optional_pstate(previous: u64, features: Features) -> u64 {
    let mut next = previous;
    if features.uao {
        next &= !PSTATE_UAO;
    }
    if features.mte {
        next |= PSTATE_TCO;
    }
    if features.gcs {
        next &= !PSTATE_EXLOCK;
    }
    if features.uinj {
        next &= !PSTATE_UINJ;
    }
    next
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingSError {
    Physical,
    Virtual,
    Delegated,
}

/// Read the actual destination context after state/bank selection. Selecting a
/// pending source does not consume, acknowledge, or synthesize an interrupt.
pub(crate) fn pending_serror_source(context: Context) -> PendingSError {
    if context.el2_enabled
        && context
            .hcr_el2
            .is_some_and(|value| value & (HCR_AMO | HCR_TGE) == HCR_AMO)
        && matches!(
            context.current_el,
            ExceptionLevel::El0 | ExceptionLevel::El1
        )
    {
        PendingSError::Virtual
    } else if context.delegated_serror_enabled && context.current_el != ExceptionLevel::El3 {
        PendingSError::Delegated
    } else {
        PendingSError::Physical
    }
}

/// Pure EDSCR field calculation; `pending` is the real selected source readback,
/// not an assumed zero. Invoke only with actual destination EL/security state.
pub(crate) fn edscr_fields(previous: u32, destination: Context, pending: bool) -> u32 {
    let updated = (previous & !(EDSCR_EL_MASK | EDSCR_RW_MASK))
        | ((el_number(destination.current_el) as u32) << EDSCR_EL_SHIFT)
        | EDSCR_A64_RW;
    set_bit(
        set_bit(
            updated,
            EDSCR_NS,
            destination.security != SecurityState::Secure,
        ),
        EDSCR_SERROR_PENDING,
        pending,
    )
}

fn el_number(el: ExceptionLevel) -> u64 {
    match el {
        ExceptionLevel::El0 => 0,
        ExceptionLevel::El1 => 1,
        ExceptionLevel::El2 => 2,
        ExceptionLevel::El3 => 3,
    }
}
fn set_bit(value: u32, mask: u32, enabled: bool) -> u32 {
    if enabled { value | mask } else { value & !mask }
}

#[cfg(test)]
mod tests;
