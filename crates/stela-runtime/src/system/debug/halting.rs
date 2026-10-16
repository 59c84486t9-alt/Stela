//! HLT and DCPS: the ordered steps of entering debug state.

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

/// The value chosen for ARBITRARY registers.
pub(crate) const ARBITRARY_REGISTER_ZERO: u64 = 0;
const ARBITRARY_HALT_PSTATE_ZERO: u64 = 0;

/// Filter the compiler's decoder, keeping the immediate and source identity.
fn halting_operation(word: u32) -> Option<Operation> {
    match exception::decode(word)? {
        operation @ (Operation::Halt { .. } | Operation::DebugChange { .. }) => Some(operation),
        _ => None,
    }
}

/// Instruction identity prepared at the system boundary; decoding happens once,
/// during preparation.
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

/// Readbacks taken while the owner's exclusive borrow is held. Feature presence
/// comes from the identification snapshot, never from compiler feature
/// metadata.
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

/// A plan, not an execution. The context, status and EDSCR are diagnostics that
/// the consumer re-checks under its borrow.
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

    /// The steps in source order. A DCPS to an undefined target is detected
    /// after SynchronizeContext.
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

/// Apply to the source PSTATE at SetHaltPstate; ARBITRARY bits are chosen as
/// zero.
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

/// Read the destination context after the state and bank are selected.
/// Selecting a pending source does not consume, acknowledge or create an
/// interrupt.
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

/// Compute the EDSCR fields. `pending` is the selected source's readback; call
/// with the destination's EL and security state.
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
mod tests {
    use super::*;

    const HLT: u32 = 0xd440_0000;
    const DCPS1: u32 = 0xd4a0_0001;
    const DCPS2: u32 = 0xd4a0_0002;
    const DCPS3: u32 = 0xd4a0_0003;
    const EDSCR_ERR: u32 = 1 << 6;
    const FLAGS: u64 = 0xa000_0000;

    fn context() -> Context {
        Context {
            features: Features {
                pan: false,
                uao: false,
                mte: false,
                bti: false,
                pauth_lr: false,
                gcs: false,
                uinj: false,
                brbe: false,
                edhsr: false,
                rme: false,
            },
            current_el: ExceptionLevel::El1,
            security: SecurityState::NonSecure,
            aarch64_at_all_present_els: true,
            el2_present: true,
            el2_enabled: true,
            el3_present: true,
            secure_el2_enabled: false,
            host_at_el0: false,
            hcr_el2: Some(0),
            sctlr_el1: 0,
            sctlr_el2: Some(0),
            double_lock: false,
            external_invasive_enabled: true,
            external_secure_invasive_enabled: true,
            delegated_serror_enabled: false,
        }
    }
    fn plan(word: u32, context: Context, status: Status, edscr: u32) -> Plan {
        let Preparation::Plan(plan) =
            prepare(Instruction::prepare(word).unwrap(), context, status, edscr).unwrap()
        else {
            panic!("expected symbolic plan")
        };
        plan
    }

    #[test]
    fn exact_compiler_operation_and_immediate_remain_attached() {
        for immediate in [0, 1, 0x8000, u16::MAX] {
            let word = DCPS3 | (u32::from(immediate) << 5);
            let instruction = Instruction::prepare(word).unwrap();
            assert_eq!(instruction.word, word);
            assert_eq!(
                instruction.operation,
                Operation::DebugChange {
                    target: DebugTarget::El3,
                    immediate
                }
            );
            assert_eq!(plan(word, context(), Status::ResetCatch, 0).word(), word);
        }
    }

    #[test]
    fn halt_order_keeps_real_platform_and_terminal_requirements() {
        let mut ctx = context();
        ctx.features.brbe = true;
        ctx.features.edhsr = true;
        assert_eq!(
            plan(HLT, ctx, Status::NonDebug, EDSCR_HDE).steps(),
            vec![
                Step::CrossHalt,
                Step::SaveDlrAndDebugPsr,
                Step::InitializeHaltEdscr,
                Step::SetHaltPstate,
                Step::BranchRecordDebugEntry,
                Step::StopPrefetchEnableItr,
                Step::PublishHaltInstruction,
                Step::UpdateEdscrFields,
                Step::UpdateExtendedHaltSyndrome,
                Step::EndInstructionException,
            ]
        );
    }

    #[test]
    fn halted_hlt_and_running_dcps_are_decode_undefined() {
        assert_eq!(
            prepare(
                Instruction::prepare(HLT).unwrap(),
                context(),
                Status::ResetCatch,
                EDSCR_HDE
            ),
            Ok(Preparation::DecodeUndefined)
        );
        for word in [DCPS1, DCPS2, DCPS3] {
            assert_eq!(
                prepare(
                    Instruction::prepare(word).unwrap(),
                    context(),
                    Status::NonDebug,
                    0
                ),
                Ok(Preparation::DecodeUndefined)
            );
        }
    }

    #[test]
    fn halt_preserves_err_and_observable_state() {
        let mut ctx = context();
        ctx.features.pan = true;
        ctx.features.uao = true;
        ctx.features.mte = true;
        ctx.features.pauth_lr = true;
        ctx.features.uinj = true;
        let original = FLAGS
            | PSTATE_PAN
            | PSTATE_UAO
            | PSTATE_SS
            | PSTATE_IL
            | PSTATE_DAIF
            | PSTATE_SSBS
            | PSTATE_PACM
            | PSTATE_UINJ
            | 5;
        assert_eq!(
            halt_pstate(original, ctx.features),
            FLAGS | PSTATE_PAN | PSTATE_UAO | PSTATE_TCO | 5
        );
        let edscr = EDSCR_HDE | EDSCR_ERR | EDSCR_ITO | EDSCR_MA;
        assert_eq!(halt_edscr(edscr, ctx), EDSCR_HDE | EDSCR_ERR | EDSCR_ITE);
        ctx.el3_present = false;
        assert_eq!(halt_edscr(edscr, ctx) & EDSCR_SDD, EDSCR_SDD);
    }

    #[test]
    fn dcps_undefined_occurs_after_synchronization() {
        let mut ctx = context();
        ctx.el2_present = false;
        assert_eq!(
            plan(DCPS2, ctx, Status::ResetCatch, 0).steps(),
            vec![Step::SynchronizeContext, Step::UndefinedInDebugState]
        );
        ctx.el2_present = true;
        ctx.hcr_el2 = Some(HCR_TGE);
        assert_eq!(
            plan(DCPS1, ctx, Status::ResetCatch, 0).steps(),
            vec![Step::SynchronizeContext, Step::UndefinedInDebugState]
        );
        assert_eq!(
            plan(DCPS3, ctx, Status::ResetCatch, EDSCR_SDD).steps(),
            vec![Step::SynchronizeContext, Step::UndefinedInDebugState]
        );
    }

    #[test]
    fn dcps_current_higher_el_wins_before_tge_and_uses_requested_upper_target() {
        let mut ctx = context();
        ctx.current_el = ExceptionLevel::El3;
        ctx.hcr_el2 = Some(HCR_TGE);
        assert_eq!(
            plan(DCPS1, ctx, Status::ResetCatch, 0).steps(),
            vec![
                Step::SynchronizeContext,
                Step::MaybeZeroSveUppers {
                    requested: ExceptionLevel::El1
                },
                Step::SelectHandlerPstate {
                    handler: ExceptionLevel::El3
                },
                Step::WriteHandlerArbitrary {
                    handler: ExceptionLevel::El3
                },
                Step::WriteDlrDspsrArbitrary,
                Step::SetDcpsOptionalPstate,
                Step::UpdateEdscrFields,
                Step::CompleteHaltedInjection,
            ]
        );
        ctx.el2_present = false;
        assert_eq!(
            plan(DCPS2, ctx, Status::ResetCatch, 0).steps(),
            vec![Step::SynchronizeContext, Step::UndefinedInDebugState]
        );
    }

    #[test]
    fn dcps_preserves_flags_daif_and_applies_optional_fields_after_bank_selection() {
        let mut ctx = context();
        ctx.features.pan = true;
        ctx.features.uao = true;
        ctx.features.mte = true;
        ctx.features.gcs = true;
        ctx.features.uinj = true;
        let original = FLAGS | PSTATE_DAIF | PSTATE_UAO | PSTATE_EXLOCK | PSTATE_UINJ;
        let selected = dcps_pstate(original, ExceptionLevel::El1, ctx);
        assert_eq!(selected, original | PSTATE_PAN | 5);
        assert_eq!(
            dcps_optional_pstate(selected, ctx.features),
            FLAGS | PSTATE_DAIF | PSTATE_PAN | PSTATE_TCO | 5
        );
    }

    #[test]
    fn destination_serror_and_security_are_read_after_transition() {
        let mut ctx = context();
        ctx.hcr_el2 = Some(HCR_AMO);
        ctx.delegated_serror_enabled = true;
        assert_eq!(pending_serror_source(ctx), PendingSError::Virtual);
        ctx.hcr_el2 = Some(HCR_AMO | HCR_TGE);
        assert_eq!(pending_serror_source(ctx), PendingSError::Delegated);
        ctx.current_el = ExceptionLevel::El3;
        ctx.security = SecurityState::Secure;
        assert_eq!(pending_serror_source(ctx), PendingSError::Physical);
        let original = EDSCR_ERR | EDSCR_NS;
        let result = edscr_fields(original, ctx, true);
        assert_eq!(result & EDSCR_NS, 0);
        assert_eq!(result & EDSCR_SERROR_PENDING, EDSCR_SERROR_PENDING);
        assert_eq!(result & EDSCR_ERR, EDSCR_ERR);
        assert_eq!(result & EDSCR_EL_MASK, 3 << EDSCR_EL_SHIFT);
    }
}
