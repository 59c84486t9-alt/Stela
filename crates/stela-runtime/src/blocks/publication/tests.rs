use super::*;
use crate::system::{
    debug::DebugControls,
    exception::{EntryControls, RequiredEffects},
    execution::EntryBoundary,
    profile::{EntryProfile, ScalableEntryAbsence, SystemEntryFeatures},
    state::{El1Registers, PSTATE_EL1H, SystemState},
};
use stela_compiler::{
    GuestState,
    block::{BlockProfile, system::decode_system_instruction},
};

const ADDRESS_SPACE: u64 = 7;
const ENTRY: GuestAddress = GuestAddress(0x1000);
const SVC: u32 = 0xd400_0001;
const ERET: u32 = 0xd69f_03e0;
const INSTRUCTION_BYTES: usize = size_of::<u32>();

fn controls() -> FixedEl1Controls {
    FixedEl1Controls::new(
        EntryProfile::base(
            SystemEntryFeatures::declared_absent(),
            ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
        )
        .unwrap(),
        crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
        0,
        EntryControls {
            tcr_el1: 0,
            mdscr_el1: 0,
            debug: DebugControls::default(),
        },
    )
    .unwrap()
}

fn boundary(runtime: &BlockRuntime, word: u32) -> Boundary {
    let (base, region) = runtime.region(ENTRY).unwrap();
    Boundary::new(
        EntryBoundary::new(
            runtime.address_space(),
            region.generation,
            ENTRY,
            GuestAddress(base),
            region.source.len(),
            word,
        ),
        INSTRUCTION_BYTES,
        decode_system_instruction(ENTRY, word).unwrap().unwrap(),
    )
}

fn request(controls: &FixedEl1Controls, effects: RequiredEffects) -> ServiceRequest {
    let system = SystemState::new(PSTATE_EL1H, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
    let snapshot = controls
        .entry_snapshot(&system, &GuestState::default())
        .unwrap();
    ServiceRequest {
        effects,
        profile: snapshot.profile,
        source_el: snapshot.profile.current_el,
        source_pstate: PSTATE_EL1H,
        source_pc: ENTRY.0,
        controls: snapshot.controls,
    }
}

fn registered_runtime(word: u32) -> BlockRuntime {
    let mut runtime = BlockRuntime::new_with_profile(
        ADDRESS_SPACE,
        std::path::PathBuf::new(),
        BlockProfile::SystemV1,
    );
    runtime
        .register_code(ENTRY, word.to_le_bytes().to_vec())
        .unwrap();
    runtime
}

#[test]
fn publication_scope_checks_typed_boundary_and_request_before_serialization() {
    let runtime = registered_runtime(SVC);
    let boundary = boundary(&runtime, SVC);
    let mut scope = CodePublicationScope::new(&runtime, &boundary);
    let controls = controls();
    let request = request(&controls, RequiredEffects::Entry { irq: false });
    assert_eq!(scope.check_boundary(&boundary), Ok(()));
    assert_eq!(scope.check_exception_request(&controls, &request), Ok(()));
    #[cfg(target_arch = "x86_64")]
    assert_eq!(scope.synchronize_fixed_el1(&controls, &request), Ok(()));
    let mut wrong = request;
    wrong.source_pc += INSTRUCTION_BYTES as u64;
    assert_eq!(
        scope
            .synchronize_fixed_el1(&controls, &wrong)
            .unwrap_err()
            .completion,
        Completion::None
    );
    wrong = request;
    wrong.effects = RequiredEffects::Return;
    assert_eq!(
        scope
            .synchronize_fixed_el1(&controls, &wrong)
            .unwrap_err()
            .completion,
        Completion::None
    );
    wrong = request;
    wrong.controls.tcr_el1 = 1;
    assert_eq!(
        scope
            .synchronize_fixed_el1(&controls, &wrong)
            .unwrap_err()
            .completion,
        Completion::None
    );
}

#[test]
fn publication_scope_rejects_stale_generation_and_changed_original_word() {
    let mut runtime = registered_runtime(SVC);
    let stale = boundary(&runtime, SVC);
    runtime
        .register_code(ENTRY, SVC.to_le_bytes().to_vec())
        .unwrap();
    let scope = CodePublicationScope::new(&runtime, &stale);
    assert!(scope.check_boundary(&stale).is_err());
    let forged = boundary(&runtime, ERET);
    let scope = CodePublicationScope::new(&runtime, &forged);
    assert!(scope.check_boundary(&forged).is_err());
}

#[test]
fn publication_scope_rejects_other_source_identity_and_forged_typed_operands() {
    let runtime = registered_runtime(SVC);
    let current = boundary(&runtime, SVC);
    let scope = CodePublicationScope::new(&runtime, &current);
    let mut other = registered_runtime(SVC);
    other.address_space += 1;
    assert!(scope.check_boundary(&boundary(&other, SVC)).is_err());
    let mut instruction = current.instruction();
    instruction.next_pc = ENTRY;
    let source = current.source();
    let forged = Boundary::new(
        EntryBoundary::new(
            source.address_space(),
            source.generation(),
            source.entry(),
            source.region_base(),
            source.source_bytes(),
            source.word(),
        ),
        current.consumed_bytes(),
        instruction,
    );
    assert!(scope.check_boundary(&forged).is_err());
}

#[test]
fn publication_scope_additive_default_preserves_legacy_completion() {
    use crate::system::execution::{Dispatcher, Failure};
    struct Legacy(usize);
    impl Dispatcher for Legacy {
        fn address_space(&self) -> u64 {
            ADDRESS_SPACE
        }
        fn validate_entry(
            &mut self,
            _: &EntryBoundary,
            _: &[u8],
            _: &GuestState,
        ) -> Result<(), Failure> {
            Ok(())
        }
        fn complete(&mut self, _: Boundary, _: &mut GuestState) -> Result<GuestAddress, Failure> {
            self.0 += 1;
            Ok(ENTRY)
        }
    }
    let runtime = registered_runtime(SVC);
    let boundary = boundary(&runtime, SVC);
    let mut scope = CodePublicationScope::new(&runtime, &boundary);
    let mut legacy = Legacy(0);
    assert_eq!(
        legacy.complete_with_code_scope(boundary, &mut GuestState::default(), &mut scope),
        Ok(ENTRY)
    );
    assert_eq!(legacy.0, 1);
    // The default performs only the pre-existing provider's completion. It
    // receives no fixed-control/exception permit and certifies no new sync.
}
