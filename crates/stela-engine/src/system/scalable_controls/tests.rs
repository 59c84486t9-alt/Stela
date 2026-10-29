use super::*;
use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H};
use stela_compiler::{TargetCpu, aarch64::scalable::profile::ScalableControls};

const PC: GuestAddress = GuestAddress(0x1000);
const FP_ENABLED: u64 = 3 << FPEN_SHIFT;
const SME_ENABLED: u64 = 3 << SMEN_SHIFT;
const SVE_ENABLED: u64 = 3 << ZEN_SHIFT;
const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;

fn length(bytes: usize) -> VectorLength {
    VectorLength::from_bytes(bytes).unwrap()
}
fn ids(sve: bool) -> Snapshot {
    Snapshot::declared(
        "scalable-owner-pure-tests",
        &[
            (IdRegister::IdAa64Pfr0El1, 0x11 | (u64::from(sve) << 32)),
            (IdRegister::IdAa64Pfr1El1, 2 << 24),
            (IdRegister::IdAa64Smfr0El1, 1 << 56),
            (IdRegister::IdAa64Zfr0El1, 0),
            (IdRegister::IdAa64Isar1El1, 0),
            (IdRegister::IdAa64Isar3El1, 0),
            (IdRegister::IdAa64Dfr0El1, 0),
            (IdRegister::IdAa64Mmfr3El1, 0),
            (IdRegister::IdAa64Mmfr4El1, 0),
        ],
    )
    .unwrap()
}
fn state(el0: bool, extra: u64) -> SystemState {
    SystemState::new(
        if el0 { PSTATE_EL0T } else { PSTATE_EL1H } | extra,
        0,
        El1Registers::new(0, 0, 0, 0, 0),
    )
    .unwrap()
}
fn make_owner(ids: &Snapshot, cpacr: u64, smcr: u64) -> ScalableControlOwner<'_> {
    ScalableControlOwner::new_declared_el10(
        ids,
        Readbacks {
            cpacr_el1: cpacr,
            smcr_el1: smcr,
        },
        Implementation::declared(
            &[length(16), length(32), length(128)],
            MemoryImplementationProfile::ScalableTagChecks,
        )
        .unwrap(),
    )
    .unwrap()
}
/// The scalable execution requirements of the context leaf `source`.
fn execution_requirements(
    source: &[u8],
    profile: ScalableProfile,
) -> stela_compiler::aarch64::scalable::execution::ScalableExecutionRequirements {
    use stela_compiler::block::{BlockProfile, CompilationPlan, Features};
    let options = stela_compiler::Options::new(
        BlockProfile::new(Features::LEAF | Features::CONTEXT),
        TargetCpu::Baseline,
    )
    .with_scalable(profile);
    CompilationPlan::new(source, PC, &options)
        .unwrap()
        .execution_requirements()
        .unwrap()
}

fn profile(owner: &ScalableControlOwner<'_>, mode: ScalableMode) -> ScalableProfile {
    ScalableProfile::new_with_features(
        owner.current_svl(),
        mode,
        features::derive(owner.identification_snapshot()).unwrap(),
        ScalableControls::new(
            owner.implementation.maximum(),
            owner.readbacks().smcr_el1 & SMCR_EZT0_MASK != 0,
        ),
    )
    .unwrap()
}

#[test]
fn sparse_supported_lengths_select_down_then_up_without_rewriting_len() {
    let support = Implementation::declared(
        &[length(32), length(128)],
        MemoryImplementationProfile::ScalableTagChecks,
    )
    .unwrap();
    for (len, bytes) in [(0, 32), (1, 32), (2, 32), (6, 32), (7, 128), (15, 128)] {
        assert_eq!(support.select(len).bytes(), bytes);
    }
    assert!(matches!(
        Implementation::declared(
            &[length(32), length(16)],
            MemoryImplementationProfile::ScalableTagChecks
        ),
        Err(Error::InvalidSupportedLengths)
    ));
}

#[test]
fn cpacr_all_enable_values_have_source_el_dependent_behavior() {
    for field in 0_u64..4 {
        for el0 in [false, true] {
            let ids = ids(false);
            let owner = make_owner(&ids, (field << SMEN_SHIFT) | FP_ENABLED, 0);
            let result = owner.check_helper(
                Check::SmeEnabled,
                &state(el0, 0),
                ScalableMode::new(false, false),
                PC,
            );
            assert_eq!(result.is_ok(), field == 3 || (field == 1 && !el0));
        }
    }
}

#[test]
fn source_orders_smen_before_fp_and_zen_before_fp() {
    let ids = ids(true);
    let owner = make_owner(&ids, 0, 0);
    assert_eq!(
        owner.check_helper(
            Check::SmeEnabled,
            &state(false, 0),
            ScalableMode::new(false, false),
            PC
        ),
        Err(trap(PC, SME_EC, 0))
    );
    assert_eq!(
        owner.check_helper(
            Check::SveEnabled,
            &state(false, 0),
            ScalableMode::new(false, false),
            PC
        ),
        Err(trap(PC, SVE_EC, 0))
    );
    let owner = make_owner(&ids, SME_ENABLED | SVE_ENABLED, 0);
    assert_eq!(
        owner.check_helper(
            Check::SmeEnabled,
            &state(false, 0),
            ScalableMode::new(false, false),
            PC
        ),
        Err(trap(PC, FP_EC, A64_FP_ISS))
    );
}

#[test]
fn sme_only_sve_branch_uses_streaming_and_za_is_helper_specific() {
    let ids = ids(false);
    let owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
    let state = state(false, 0);
    assert_eq!(
        owner.check_helper(
            Check::SveEnabled,
            &state,
            ScalableMode::new(false, false),
            PC
        ),
        Err(trap(PC, SME_EC, 2))
    );
    assert!(
        owner
            .check_helper(
                Check::SveEnabled,
                &state,
                ScalableMode::new(true, false),
                PC
            )
            .is_ok()
    );
    assert!(
        owner
            .check_helper(
                Check::SmeAndZaEnabled,
                &state,
                ScalableMode::new(false, true),
                PC
            )
            .is_ok()
    );
    assert_eq!(
        owner.check_helper(
            Check::StreamingSveAndZaEnabled,
            &state,
            ScalableMode::new(false, true),
            PC
        ),
        Err(trap(PC, SME_EC, 2))
    );
    assert_eq!(
        owner.check_helper(
            Check::SmeZt0Enabled,
            &state,
            ScalableMode::new(false, false),
            PC
        ),
        Err(trap(PC, SME_EC, 3))
    );
    assert_eq!(
        owner.check_helper(
            Check::SmeZt0Enabled,
            &state,
            ScalableMode::new(false, true),
            PC
        ),
        Err(trap(PC, SME_EC, 4))
    );
}

#[test]
fn register_access_is_not_general_sme_instruction_access() {
    let ids = ids(false);
    let owner = make_owner(&ids, SME_ENABLED, 0);
    assert_eq!(owner.read(Register::SmcrEl1, &state(false, 0), PC), Ok(0));
    assert_eq!(
        owner.check_helper(
            Check::SmeEnabled,
            &state(false, 0),
            ScalableMode::new(false, false),
            PC
        ),
        Err(trap(PC, FP_EC, A64_FP_ISS))
    );
    assert_eq!(
        owner.read(Register::CpacrEl1, &state(true, 0), PC),
        Err(Error::Undefined)
    );
    let owner = make_owner(&ids, 0, 0);
    assert_eq!(owner.read(Register::CpacrEl1, &state(false, 0), PC), Ok(0));
    assert_eq!(
        owner.read(Register::SmcrEl1, &state(false, 0), PC),
        Err(trap(PC, SME_EC, 0))
    );
}

#[test]
fn smcr_writes_ignore_only_raz_fields_and_decline_length_changes() {
    let ids = ids(false);
    let mut owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
    let state = state(false, 0);
    let scalable = ScalableState::new(length(16), true);
    let value = (1u64 << 63) | SMCR_RAZ_WI_MASK | SMCR_EZT0_MASK;
    owner
        .prepare_write(Register::SmcrEl1, value, &state, &scalable, PC)
        .unwrap()
        .commit();
    assert_eq!(owner.readbacks().smcr_el1, value & !SMCR_RAZ_WI_MASK);
    let before = owner.readbacks();
    assert!(matches!(
        owner.prepare_write(Register::SmcrEl1, 1, &state, &scalable, PC),
        Err(Error::LengthChangeUnavailable)
    ));
    assert_eq!(owner.readbacks(), before);
    assert_eq!(owner.generation(), 1);
}

#[test]
fn sole_cpacr_bank_is_shared_with_fp_and_smcr_keeps_its_generation() {
    let ids = ids(false);
    let mut owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
    assert!(std::ptr::eq(
        owner.identification_snapshot(),
        owner.fp_controls().identification_snapshot()
    ));
    let el1 = state(false, 0);
    let el0 = state(true, 0);
    let scalable = ScalableState::new(length(16), true);
    assert_eq!(owner.fp_controls().check_fp_enabled(&el0, PC), Ok(()));
    let value = (1 << FPEN_SHIFT) | SME_ENABLED;
    owner
        .prepare_write(Register::CpacrEl1, value, &el1, &scalable, PC)
        .unwrap()
        .commit();
    assert_eq!(owner.readbacks().cpacr_el1, value);
    assert_eq!(owner.fp_controls().cpacr_el1(), value);
    assert_eq!(
        owner.fp_controls().check_fp_enabled(&el0, PC),
        Err(trap(PC, FP_EC, A64_FP_ISS))
    );
    assert_eq!(
        owner.check_fp(el0.current_el(), PC),
        Err(trap(PC, FP_EC, A64_FP_ISS))
    );
    assert_eq!(owner.generation(), 1);
    assert_eq!(owner.fp_controls().generation(), 1);
    owner
        .prepare_write(Register::SmcrEl1, 0, &el1, &scalable, PC)
        .unwrap()
        .commit();
    assert_eq!(owner.generation(), 2);
    assert_eq!(owner.fp_controls().generation(), 1);
    assert_eq!(owner.readbacks().cpacr_el1, value);
}

#[test]
fn il_declines_register_effects_and_checked_callback() {
    let ids = ids(false);
    let mut owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
    let state = state(false, PSTATE_IL_MASK);
    let mut scalable = ScalableState::new(length(16), true);
    let mut registers = GuestState::default();
    let profile = profile(&owner, scalable.mode());
    let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
    let requirements = execution_requirements(&source, profile);
    let mut called = false;
    let result = owner.with_checked_execution(
        &requirements,
        profile,
        &state,
        &mut registers,
        &mut scalable,
        |_, _, _| called = true,
    );
    assert_eq!(result, Err(Error::IllegalExecutionState));
    assert!(!called);
    assert_eq!(
        owner.read(Register::CpacrEl1, &state, PC),
        Err(Error::IllegalExecutionState)
    );
    assert!(matches!(
        owner.prepare_write(Register::CpacrEl1, 0, &state, &scalable, PC),
        Err(Error::IllegalExecutionState)
    ));
    assert_eq!(owner.generation(), 0);
}

#[test]
fn checked_callback_uses_same_state_and_named_implementation() {
    let ids = ids(false);
    let owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, 0);
    let state = state(false, 0);
    let mut scalable = ScalableState::new(length(16), true);
    let mut registers = GuestState::default();
    scalable
        .apply_mode(&mut registers, ScalableMode::new(true, false))
        .unwrap();
    let profile = profile(&owner, scalable.mode());
    let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
    let requirements = execution_requirements(&source, profile);
    owner
        .with_checked_execution(
            &requirements,
            profile,
            &state,
            &mut registers,
            &mut scalable,
            |effective, registers, scalable| {
                assert_eq!(
                    effective.implementation_profile(),
                    MemoryImplementationProfile::ScalableTagChecks
                );
                assert_eq!(effective.mode(), scalable.mode());
                assert_eq!(effective.vector_length(), scalable.vector_length());
                registers.x[3] = 0x1234;
            },
        )
        .unwrap();
    assert_eq!(registers.x[3], 0x1234);
}

#[test]
fn cpu_zt0_presence_does_not_prove_supplied_state_storage() {
    let ids = ids(false);
    let owner = make_owner(&ids, FP_ENABLED | SME_ENABLED, SMCR_EZT0_MASK);
    let state = state(false, 0);
    let mut scalable = ScalableState::new(length(16), false);
    let mut registers = GuestState::default();
    scalable
        .apply_mode(&mut registers, ScalableMode::new(true, true))
        .unwrap();
    let profile = profile(&owner, scalable.mode());
    let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
    let requirements = execution_requirements(&source, profile);
    let mut called = false;
    assert_eq!(
        owner.with_checked_execution(
            &requirements,
            profile,
            &state,
            &mut registers,
            &mut scalable,
            |_, _, _| called = true
        ),
        Err(Error::StateFeatureMismatch)
    );
    assert!(!called);
    let mut supported = ScalableState::new(length(16), true);
    supported
        .apply_mode(&mut registers, ScalableMode::new(true, true))
        .unwrap();
    owner
        .with_checked_execution(
            &requirements,
            profile,
            &state,
            &mut registers,
            &mut supported,
            |_, _, _| called = true,
        )
        .unwrap();
    assert!(called);
}

#[test]
fn source_atomicity_requires_its_explicit_cpu_declaration() {
    let unspecified = Implementation::declared(
        &[length(16)],
        MemoryImplementationProfile::ScalableTagChecks,
    )
    .unwrap();
    assert_eq!(unspecified.source_atomicity, SourceAtomicity::Unspecified);
    let explicit = Implementation::declared_sca16(
        &[length(16)],
        MemoryImplementationProfile::ScalableTagChecks,
    )
    .unwrap();
    assert_eq!(explicit.source_atomicity, SourceAtomicity::FixedSca16);
    let ids = ids(false);
    let owner = ScalableControlOwner::new_declared_el10(
        &ids,
        Readbacks {
            cpacr_el1: FP_ENABLED | SME_ENABLED,
            smcr_el1: 0,
        },
        explicit,
    )
    .unwrap();
    let state = state(false, 0);
    let mut registers = GuestState::default();
    let mut scalable = ScalableState::new(length(16), true);
    let profile = profile(&owner, scalable.mode());
    let source: Vec<u8> = [NOP, RET].into_iter().flat_map(u32::to_le_bytes).collect();
    let requirements = execution_requirements(&source, profile);
    assert_eq!(
        owner.with_checked_execution(
            &requirements,
            profile,
            &state,
            &mut registers,
            &mut scalable,
            |effective, _, _| effective.source_atomicity()
        ),
        Ok(SourceAtomicity::FixedSca16)
    );
}
