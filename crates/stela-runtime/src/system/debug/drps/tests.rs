use super::*;
const DRPS: u32 = 0xd6bf_03e0;
#[test]
fn decode_undefined_precedes_saved_state_requirements() {
    assert_eq!(
        prepare(DRPS, Status::NonDebug, ExceptionLevel::El1, u64::MAX),
        Ok(Preparation::DecodeUndefined)
    );
    assert_eq!(
        prepare(DRPS, Status::ResetCatch, ExceptionLevel::El0, u64::MAX),
        Ok(Preparation::DecodeUndefined)
    );
    assert_eq!(
        prepare(DRPS, Status::ResetCatch, ExceptionLevel::El2, 0),
        Err(Unsupported::SourceLevel)
    );
}
#[test]
fn drps_has_no_branch_resume_event_or_exclusive_effect() {
    let Preparation::Plan(plan) =
        prepare(DRPS, Status::ResetCatch, ExceptionLevel::El1, PSTATE_EL1T).unwrap()
    else {
        panic!("plan")
    };
    assert_eq!(plan.word(), DRPS);
    assert_eq!(
        plan.steps(),
        [
            Step::SynchronizeContext,
            Step::RestoreActualSavedPstate,
            Step::ClearShouldAdvanceSs,
            Step::WriteArbitraryPstate,
            Step::WriteDlrDspsrArbitrary,
            Step::UpdateEdscrFields,
            Step::CompleteHaltedInjection
        ]
    );
    assert_eq!(
        arbitrary_pstate(NZCV_MASK | DAIF_MASK | PSTATE_SS_MASK | PSTATE_EL1T),
        PSTATE_EL1T
    );
}
#[test]
fn restricted_saved_state_declines_instead_of_masking() {
    for (saved, expected) in [
        (PSTATE_EL1H | (1 << 63), Unsupported::SavedBits),
        (PSTATE_EL1H | PSTATE_IL_MASK, Unsupported::SavedIllegalState),
        (0, Unsupported::SavedMode),
    ] {
        assert_eq!(
            prepare(DRPS, Status::ResetCatch, ExceptionLevel::El1, saved),
            Err(expected)
        );
    }
}
