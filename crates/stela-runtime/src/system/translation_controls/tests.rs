//! Owner-sequencing tests with a deliberately synthetic effects observer.
//! These do not prove real fetch, CSE, cacheability or publication. The concrete
//! same-MemorySystem/BlockRuntime adapter must supply its own execution evidence.
use super::*;
use crate::system::state::{El1Registers, PSTATE_EL1H};
use std::{cell::Cell, collections::BTreeMap};

const PC: u64 = 0x1000;
const ISB_SY: u32 = 0xd503_3fdf;
const MSR_SCTLR_X1: u32 = 0xd518_1001;
const MSR_TCR_X1: u32 = 0xd518_2041;
const MSR_TTBR1_XZR: u32 = 0xd518_203f;
const MRS_TTBR1_XZR: u32 = 0xd538_203f;
const DECLARED_TEST_PROVENANCE: EvidenceBinding = EvidenceBinding {
    id: "synthetic-owner-sequencing-test-not-hardware-evidence",
    sha256: [1; 32],
};

fn facts() -> BaseEl1FeatureFacts {
    BaseEl1FeatureFacts {
        pauth: Presence::Present,
        pan: PanFeatures::Pan3,
        ssbs: Presence::Absent,
        exs: Presence::Absent,
        asid_bits: AsidBits::Sixteen,
        endianness: Endianness::LittleOnly,
    }
}
fn cpu() -> stage1::CpuProfile {
    stage1::CpuProfile {
        pa_max: stage1::PaBits::Bits40,
        asid_bits: stage1::AsidBits::Bits16,
        granules: stage1::GranuleSupport {
            kib4: true,
            kib16: true,
            kib64: false,
            lower_fallback: stage1::Granule::KiB4,
            upper_fallback: stage1::Granule::KiB16,
        },
        pauth: true,
        pan: true,
        pan3: true,
    }
}
fn profile() -> ControlProfile {
    ControlProfile::base_el1(
        facts(),
        PolicyProvenance {
            cpu_features: DECLARED_TEST_PROVENANCE,
            implementation_choices: DECLARED_TEST_PROVENANCE,
        },
        cpu(),
    )
    .unwrap()
}
fn state() -> SystemState {
    SystemState::new(PSTATE_EL1H, 0x9876, El1Registers::new(1, 2, 3, 4, 5)).unwrap()
}
fn values() -> RegisterValues {
    RegisterValues {
        sctlr_el1: 0,
        tcr_el1: 0,
        ttbr0_el1: 0x2345,
        ttbr1_el1: 0x6789,
        mair_el1: 0xff,
    }
}

struct Observer {
    memory: Arc<MemorySystem>,
    installed: Option<ControlSnapshot>,
    words: BTreeMap<u64, u32>,
    source_generation: u64,
    unavailable: bool,
    failure: Option<PublicationFailure>,
    events: Vec<&'static str>,
    fetches: usize,
    poisoned: bool,
    memory_system_calls: Cell<usize>,
    prepare_calls: usize,
    source_validation_calls: usize,
}
impl Observer {
    fn new(memory: Arc<MemorySystem>, word: u32) -> Self {
        Self {
            memory,
            installed: None,
            words: BTreeMap::from([(PC, word), (PC + 4, ISB_SY)]),
            source_generation: 1,
            unavailable: false,
            failure: None,
            events: Vec::new(),
            fetches: 0,
            poisoned: false,
            memory_system_calls: Cell::new(0),
            prepare_calls: 0,
            source_validation_calls: 0,
        }
    }
    fn callback_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.memory_system_calls.get(),
            self.prepare_calls,
            self.source_validation_calls,
            self.fetches,
        )
    }
    fn current(&self, snapshot: &ControlSnapshot) -> Result<(), &'static str> {
        if self.poisoned {
            return Err("observer poisoned");
        }
        let installed = self.installed.as_ref().ok_or("no installed context")?;
        if !installed.same_pe(snapshot) || installed.generation() != snapshot.generation() {
            return Err("stale owner generation");
        }
        Ok(())
    }
}
struct PreparedObserver<'a> {
    observer: &'a mut Observer,
    after: Option<ControlSnapshot>,
    event: &'static str,
}
impl PreparedPublication for PreparedObserver<'_> {
    fn commit(self) -> Result<(), PublicationFailure> {
        if let Some(error) = self.observer.failure.take() {
            self.observer.poisoned = true;
            return Err(error);
        }
        if let Some(after) = self.after {
            self.observer.installed = Some(after);
        }
        self.observer.events.push(self.event);
        Ok(())
    }
}
impl TranslationServices for Observer {
    type Prepared<'a> = PreparedObserver<'a>;
    fn memory_system(&self) -> &Arc<MemorySystem> {
        self.memory_system_calls
            .set(self.memory_system_calls.get() + 1);
        &self.memory
    }
    fn prepare<'a>(
        &'a mut self,
        request: PublicationRequest<'a>,
    ) -> Result<Self::Prepared<'a>, &'static str> {
        self.prepare_calls += 1;
        if self.unavailable {
            return Err("actual effect unavailable");
        }
        let (after, event) = match request {
            PublicationRequest::Initial { snapshot, .. } => (Some(snapshot), "initial"),
            PublicationRequest::Read {
                snapshot,
                source,
                state,
                ..
            } => {
                self.validate_source(&snapshot, source, state)?;
                (None, "read")
            }
            PublicationRequest::Write { change, state, .. } => {
                self.validate_source(&change.before, change.source, state)?;
                assert!(change.before.same_pe(&change.after));
                assert_eq!(change.after.generation(), change.before.generation() + 1);
                (Some(change.after), "write")
            }
            PublicationRequest::Isb {
                before,
                after,
                source,
                state,
                operation,
                ..
            } => {
                self.validate_source(&before, source, state)?;
                assert!(matches!(operation, stela_compiler::aarch64::system::synchronization::Operation::InstructionSynchronization { .. }));
                assert!(before.same_pe(&after));
                assert_eq!(after.generation(), before.generation() + 1);
                assert_eq!(after.readbacks(), before.readbacks());
                (Some(after), "isb")
            }
        };
        Ok(PreparedObserver {
            observer: self,
            after,
            event,
        })
    }
    fn validate_source(
        &mut self,
        snapshot: &ControlSnapshot,
        source: PhysicalFetch,
        _: &SystemState,
    ) -> Result<(), &'static str> {
        self.source_validation_calls += 1;
        self.current(snapshot)?;
        if source.source_generation != self.source_generation
            || self.words.get(&source.pc) != Some(&source.word)
        {
            return Err("stale physical source");
        }
        Ok(())
    }
    fn fetch(
        &mut self,
        snapshot: &ControlSnapshot,
        _: &stage1::CpuProfile,
        _: &SystemState,
        pc: u64,
    ) -> Result<PhysicalFetch, FetchFailure> {
        self.current(snapshot).map_err(FetchFailure::Unavailable)?;
        self.fetches += 1;
        let word = *self
            .words
            .get(&pc)
            .ok_or(FetchFailure::Unavailable("synthetic unmapped fetch"))?;
        // An observer of current policy, not an MMU implementation or claim.
        let physical_address = if snapshot.consumer_inputs().sctlr_el1 & 1 != 0 {
            pc + 0x4000
        } else {
            pc
        };
        Ok(PhysicalFetch {
            pc,
            word,
            physical_address,
            source_generation: self.source_generation,
        })
    }
}
fn machine(word: u32) -> (TranslationControls, SystemState, Observer) {
    let memory = MemorySystem::new(16, 8).unwrap();
    let mut observer = Observer::new(Arc::clone(&memory), word);
    let state = state();
    let owner =
        TranslationControls::install(values(), profile(), memory, &state, &mut observer).unwrap();
    (owner, state, observer)
}

#[test]
fn exact_source_register_encodings_preserve_direction_and_rt() {
    let pairs = [
        (Register::SctlrEl1, 0xd518_1000, 0xd538_1000),
        (Register::TcrEl1, 0xd518_2040, 0xd538_2040),
        (Register::Ttbr0El1, 0xd518_2000, 0xd538_2000),
        (Register::Ttbr1El1, 0xd518_2020, 0xd538_2020),
        (Register::MairEl1, 0xd518_a200, 0xd538_a200),
    ];
    for (register, write, read) in pairs {
        for rt in 0..=31 {
            assert_eq!(decode_register(write | rt, false), Ok((register, rt as u8)));
            assert_eq!(decode_register(read | rt, true), Ok((register, rt as u8)));
            assert_eq!(
                decode_register(write | rt, true),
                Err(ControlError::NotOwned)
            );
        }
    }
}

#[test]
fn profile_rejects_incoherent_canonical_feature_witness() {
    let mut wrong = cpu();
    wrong.pauth = false;
    assert!(matches!(
        ControlProfile::base_el1(
            facts(),
            PolicyProvenance {
                cpu_features: DECLARED_TEST_PROVENANCE,
                implementation_choices: DECLARED_TEST_PROVENANCE,
            },
            wrong
        ),
        Err(FieldError::IncoherentCpuProfile(_))
    ));
}

#[test]
fn dormant_intermediate_write_commits_readback_and_invalidates_old_sites() {
    let (mut owner, state, mut observer) = machine(MSR_TCR_X1);
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    let mut registers = GuestState::default();
    registers.x[1] = u64::MAX;
    let result = owner
        .prepare_write(&fetched, &state, &registers, &mut observer)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(
        result,
        Completion::FetchRequired {
            pc: PC + 4,
            control_generation: 1
        }
    );
    assert_eq!(owner.snapshot().unwrap().readbacks().tcr_el1, u64::MAX);
    assert_eq!(owner.snapshot().unwrap().readbacks().sctlr_el1, 0);
    assert!(matches!(
        owner.prepare_write(&fetched, &state, &registers, &mut observer),
        Err(ControlError::StaleSource)
    ));
    assert_eq!(observer.events, vec!["initial", "write"]);
}

#[test]
fn unavailable_effect_leaves_the_real_bank_and_generation_unchanged() {
    let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    let before = owner.snapshot().unwrap().readbacks();
    let mut registers = GuestState::default();
    registers.x[1] = 1;
    observer.unavailable = true;
    assert!(matches!(
        owner.prepare_write(&fetched, &state, &registers, &mut observer),
        Err(ControlError::Unavailable(_))
    ));
    assert_eq!(owner.snapshot().unwrap().readbacks(), before);
    assert_eq!(owner.snapshot().unwrap().generation(), 0);
}

#[test]
fn commit_failure_preserves_register_prefix_and_poison_blocks_reentry() {
    let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    let mut registers = GuestState::default();
    registers.x[1] = 1;
    observer.failure = Some(PublicationFailure {
        progress: PublicationProgress::CodeDependenciesRetired,
        reason: "injected owner failure",
    });
    assert_eq!(
        owner
            .prepare_write(&fetched, &state, &registers, &mut observer)
            .unwrap()
            .commit(),
        Err(ControlError::Publication {
            register_committed: true,
            progress: PublicationProgress::CodeDependenciesRetired,
            reason: "injected owner failure"
        })
    );
    assert_eq!(owner.readbacks.sctlr_el1, 1);
    assert!(matches!(owner.snapshot(), Err(ControlError::Poisoned)));
    assert!(matches!(
        owner.fetch(PC + 4, &state, &mut observer),
        Err(ControlError::Poisoned)
    ));
}

#[test]
fn post_msr_isb_requires_a_fresh_current_policy_fetch_and_authoritative_after_generation() {
    let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
    let write = owner.fetch(PC, &state, &mut observer).unwrap();
    let mut registers = GuestState::default();
    registers.x[1] = 1;
    owner
        .prepare_write(&write, &state, &registers, &mut observer)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(observer.fetches, 1);
    let isb = owner.fetch(PC + 4, &state, &mut observer).unwrap();
    assert_eq!(isb.source.physical_address, PC + 4 + 0x4000);
    assert_eq!(
        owner
            .prepare_isb(&isb, &state, &registers, &mut observer)
            .unwrap()
            .commit()
            .unwrap(),
        Completion::FetchRequired {
            pc: PC + 8,
            control_generation: 2
        }
    );
    assert_eq!(observer.installed.as_ref().unwrap().generation(), 2);
    assert!(matches!(
        owner.prepare_isb(&isb, &state, &registers, &mut observer),
        Err(ControlError::StaleSource)
    ));
    assert_eq!(observer.events, vec!["initial", "write", "isb"]);
}

#[test]
fn stale_physical_source_is_checked_before_el0_undefined() {
    let (mut owner, _, mut observer) = machine(MRS_TTBR1_XZR);
    let el0 = SystemState::new(0, 0, El1Registers::new(1, 2, 3, 4, 5)).unwrap();
    let fetched = owner.fetch(PC, &el0, &mut observer).unwrap();
    observer.source_generation += 1;
    assert_eq!(
        owner.read(&fetched, &el0, &mut observer),
        Err(ControlError::Unavailable("stale physical source"))
    );
    let fetched = owner.fetch(PC, &el0, &mut observer).unwrap();
    assert_eq!(
        owner.read(&fetched, &el0, &mut observer),
        Err(ControlError::Undefined)
    );
}

#[test]
fn xzr_write_is_zero_and_xzr_read_still_checks_and_obtains_value() {
    let (mut owner, state, mut observer) = machine(MSR_TTBR1_XZR);
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    owner
        .prepare_write(&fetched, &state, &GuestState::default(), &mut observer)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(owner.snapshot().unwrap().readbacks().ttbr1_el1, 0);
    observer.words.insert(PC, MRS_TTBR1_XZR);
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    assert_eq!(
        owner.read(&fetched, &state, &mut observer),
        Ok(Completion::Read {
            rt: 31,
            value: 0,
            next_pc: PC + 4
        })
    );
    assert_eq!(observer.events.last(), Some(&"read"));
}

#[test]
fn foreign_machine_and_foreign_pe_sources_are_never_admitted() {
    let (owner, state, mut observer) = machine(MSR_TCR_X1);
    let mut foreign = Observer::new(MemorySystem::new(16, 8).unwrap(), MSR_TCR_X1);
    assert!(matches!(
        owner.fetch(PC, &state, &mut foreign),
        Err(ControlError::WrongMemorySystem)
    ));
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    let memory = Arc::clone(&observer.memory);
    let mut second_observer = Observer::new(Arc::clone(&memory), MSR_TCR_X1);
    let mut second =
        TranslationControls::install(values(), profile(), memory, &state, &mut second_observer)
            .unwrap();
    assert!(matches!(
        second.prepare_write(
            &fetched,
            &state,
            &GuestState::default(),
            &mut second_observer
        ),
        Err(ControlError::StaleSource)
    ));
}

#[test]
fn misaligned_fetch_reports_typed_pc_provenance_before_translation() {
    let (owner, state, mut observer) = machine(MSR_TCR_X1);
    assert!(
        matches!(owner.fetch(PC+1,&state,&mut observer),Err(ControlError::Fetch(FetchFailure::InstructionAlignment {raw_pc,exception_level:access::ExceptionLevel::El1})) if raw_pc==PC+1)
    );
    assert_eq!(observer.fetches, 0);
}

#[test]
fn subsequent_fetch_decline_preserves_the_completed_msr() {
    let (mut owner, state, mut observer) = machine(MSR_SCTLR_X1);
    let fetched = owner.fetch(PC, &state, &mut observer).unwrap();
    let mut registers = GuestState::default();
    registers.x[1] = 1;
    owner
        .prepare_write(&fetched, &state, &registers, &mut observer)
        .unwrap()
        .commit()
        .unwrap();
    observer.words.remove(&(PC + 4));
    assert!(matches!(
        owner.fetch(PC + 4, &state, &mut observer),
        Err(ControlError::Fetch(FetchFailure::Unavailable(_)))
    ));
    assert_eq!(owner.snapshot().unwrap().readbacks().sctlr_el1, 1);
    assert_eq!(owner.snapshot().unwrap().generation(), 1);
}

#[test]
fn actual_il_declines_all_control_operations_before_any_service_callback() {
    for word in [MRS_TTBR1_XZR, MSR_SCTLR_X1, ISB_SY] {
        let (mut owner, valid_state, mut observer) = machine(word);
        let fetched = owner.fetch(PC, &valid_state, &mut observer).unwrap();
        let illegal = SystemState::new(
            PSTATE_EL1H | PSTATE_IL_MASK,
            0x9876,
            El1Registers::new(1, 2, 3, 4, 5),
        )
        .unwrap();
        let before_state = illegal.clone();
        let before = owner.snapshot().unwrap();
        let mut registers = GuestState::default();
        registers.x.fill(0x9876_5432_10ab_cdef);
        registers.sp = 0x1234_5678;
        registers.nzcv = 0xa000_0000;
        registers.fpcr = 0x400_0000;
        registers.fpsr = 0x0800_0000;
        registers.v.fill([0xdead_beef, 0xbeef_dead]);
        let before_registers = registers.clone();
        // IL must decline even before source/backend failures can call a hook.
        observer.unavailable = true;
        observer.source_generation += 1;
        let callbacks = observer.callback_counts();
        let events = observer.events.clone();
        match word {
            MRS_TTBR1_XZR => assert_eq!(
                owner.read(&fetched, &illegal, &mut observer),
                Err(ControlError::IllegalExecutionState),
            ),
            MSR_SCTLR_X1 => assert!(matches!(
                owner.prepare_write(&fetched, &illegal, &registers, &mut observer),
                Err(ControlError::IllegalExecutionState),
            )),
            ISB_SY => assert!(matches!(
                owner.prepare_isb(&fetched, &illegal, &registers, &mut observer),
                Err(ControlError::IllegalExecutionState),
            )),
            _ => unreachable!("fixed three-operation test cohort"),
        }
        assert_eq!(observer.callback_counts(), callbacks);
        assert_eq!(observer.events, events);
        assert_eq!(illegal, before_state);
        assert_eq!(registers.x, before_registers.x);
        assert_eq!(registers.sp, before_registers.sp);
        assert_eq!(registers.nzcv, before_registers.nzcv);
        assert_eq!(registers.v, before_registers.v);
        assert_eq!(registers.fpcr, before_registers.fpcr);
        assert_eq!(registers.fpsr, before_registers.fpsr);
        let after = owner.snapshot().unwrap();
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.readbacks(), before.readbacks());
        assert_eq!(after.consumer_inputs(), before.consumer_inputs());
    }
}

#[test]
fn illegal_state_guard_uses_only_the_actual_owned_il_bit() {
    use crate::system::state::PSTATE_SS_MASK;
    let single_step = SystemState::new(
        PSTATE_EL1H | PSTATE_SS_MASK,
        0x9876,
        El1Registers::new(1, 2, 3, 4, 5),
    )
    .unwrap();
    assert_eq!(check_execution_state(&single_step), Ok(()));
    assert_eq!(check_execution_state(&state()), Ok(()));
    // The concrete service still owns stepping/debug eligibility. This helper
    // makes no claim that a single-step instruction may execute without it.
}

fn branch_machine(tcr_el1: u64, pauth: Presence) -> TranslationControls {
    let memory = MemorySystem::new(16, 8).unwrap();
    let mut observer = Observer::new(Arc::clone(&memory), ISB_SY);
    let mut actual_facts = facts();
    actual_facts.pauth = pauth;
    let mut actual_cpu = cpu();
    actual_cpu.pauth = pauth == Presence::Present;
    let profile = ControlProfile::base_el1(
        actual_facts,
        PolicyProvenance {
            cpu_features: DECLARED_TEST_PROVENANCE,
            implementation_choices: DECLARED_TEST_PROVENANCE,
        },
        actual_cpu,
    )
    .unwrap();
    let mut readbacks = values();
    readbacks.tcr_el1 = tcr_el1;
    TranslationControls::install(readbacks, profile, memory, &state(), &mut observer).unwrap()
}

#[test]
fn branch_address_uses_destination_region_and_instruction_tbid() {
    use super::fields::tcr;
    use crate::system::access::ExceptionLevel;
    const LOWER_TAGGED: u64 = 0xab12_3456_789a_bcde;
    const UPPER_TAGGED: u64 = 0xab92_3456_789a_bcde;
    const LOWER: u64 = 0x0012_3456_789a_bcde;
    const UPPER: u64 = 0xff92_3456_789a_bcde;
    for destination in [ExceptionLevel::El0, ExceptionLevel::El1] {
        for (bits, lower, upper) in [
            (0, LOWER_TAGGED, UPPER_TAGGED),
            (tcr::TBI0, LOWER, UPPER_TAGGED),
            (tcr::TBI1, LOWER_TAGGED, UPPER),
            (tcr::TBI0 | tcr::TBI1, LOWER, UPPER),
            (tcr::TBI0 | tcr::TBI1 | tcr::TBID0, LOWER_TAGGED, UPPER),
            (tcr::TBI0 | tcr::TBI1 | tcr::TBID1, LOWER, UPPER_TAGGED),
        ] {
            let owner = branch_machine(bits, Presence::Present);
            assert_eq!(owner.branch_address(LOWER_TAGGED, destination), Ok(lower));
            assert_eq!(owner.branch_address(UPPER_TAGGED, destination), Ok(upper));
        }
        let owner = branch_machine(
            tcr::TBI0 | tcr::TBI1 | tcr::TBID0 | tcr::TBID1,
            Presence::Absent,
        );
        assert_eq!(owner.branch_address(LOWER_TAGGED, destination), Ok(LOWER));
        assert_eq!(owner.branch_address(UPPER_TAGGED, destination), Ok(UPPER));
    }
}

#[test]
fn branch_address_refuses_unowned_regimes_and_poisoned_controls() {
    use crate::system::access::ExceptionLevel;
    let (mut owner, _, _) = machine(ISB_SY);
    for destination in [ExceptionLevel::El2, ExceptionLevel::El3] {
        assert!(matches!(
            owner.branch_address(PC, destination),
            Err(ControlError::Unavailable(_))
        ));
    }
    owner.poisoned = true;
    assert_eq!(
        owner.branch_address(PC, ExceptionLevel::El1),
        Err(ControlError::Poisoned)
    );
}
