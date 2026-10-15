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
