use super::*;
use crate::memory::{
    domain::{AllocationTagPolicy, MemoryDomain, MemorySystem},
    tags::{AllocationTag, TagGenerationState, TagRandomization},
};
use crate::system::{
    access::SecurityState,
    debug::DebugControls,
    exception::{CommittedPrefix, Completion, EffectFailure, EffectStage, ServiceRequest},
    profile::{ScalableEntryAbsence, SystemEntryFeatures},
    pstate::{MteFeature, TCO_MASK},
    state::{El1Registers, MteState, PSTATE_EL1H},
};
use stela_compiler::{TargetCpu, block::system::decode_system_instruction, context::memory::flags};

const ADDRESS_SPACE: u64 = 7;
const SOURCE_PC: GuestAddress = GuestAddress(0x1000);
const DATA_ADDRESS: u64 = 0x4000;
const ADDRESS_BITS: u8 = 48;
const SVC: u32 = 0xd400_0001;
const IRG: u32 = 0x9ac0_1000;
const LDG: u32 = 0xd960_0000;
const VECTOR_BASE: u64 = 0x8000;
const ERG_BYTES: u64 = 16;
const STRIPES: usize = 4;
const GENERATION: u64 = 3;
const REGISTER_FLAGS: u32 = 0xa000_0000;

fn entry(word: u32) -> EntryBoundary {
    EntryBoundary::new(
        ADDRESS_SPACE,
        GENERATION,
        SOURCE_PC,
        SOURCE_PC,
        size_of::<u32>(),
        word,
    )
}

fn boundary(word: u32) -> Boundary {
    Boundary::new(
        entry(word),
        size_of::<u32>(),
        decode_system_instruction(SOURCE_PC, word).unwrap().unwrap(),
    )
}

fn state(mte: bool, tco: bool) -> SystemState {
    let registers = El1Registers::new(0, 0, 0, 0, VECTOR_BASE);
    if mte {
        SystemState::new_with_mte(
            PSTATE_EL1H | if tco { TCO_MASK } else { 0 },
            0x2000,
            registers,
            MteFeature::TwoOrLater,
            MteState::new(
                0,
                TagRandomization::ArchitecturalLfsr,
                TagGenerationState {
                    seed: 1,
                    tag: AllocationTag::new(0).unwrap(),
                },
            ),
        )
        .unwrap()
    } else {
        SystemState::new(PSTATE_EL1H, 0x2000, registers).unwrap()
    }
}

fn registers() -> GuestState {
    let mut registers = GuestState {
        sp: 0x3000,
        nzcv: REGISTER_FLAGS,
        ..GuestState::default()
    };
    registers.x[0] = DATA_ADDRESS;
    registers
}

struct BackendFixture {
    entry: Option<EntrySnapshot>,
    tags: Option<TagSnapshot>,
    memory: Option<MemoryThread<MemoryControls>>,
    fail_synchronize: bool,
    deny_cssc: bool,
    expected_source_pc: u64,
    calls: Vec<&'static str>,
}

impl BackendFixture {
    fn new() -> Self {
        Self {
            entry: Some(EntrySnapshot {
                profile: Profile {
                    current_el: ExceptionLevel::El1,
                    security: SecurityState::NonSecure,
                    el2_enabled: false,
                    el3_present: false,
                },
                features: EntryProfile::base(
                    SystemEntryFeatures::declared_absent(),
                    ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
                )
                .unwrap(),
                controls: EntryControls {
                    tcr_el1: 0,
                    mdscr_el1: 0,
                    debug: DebugControls::default(),
                },
            }),
            tags: None,
            memory: None,
            fail_synchronize: false,
            deny_cssc: false,
            expected_source_pc: SOURCE_PC.0,
            calls: Vec::new(),
        }
    }
}

// Test fixtures record ordering/failure only. They are not production backends
// and do not certify synchronization, monitor or event architectural effects.
impl ExceptionServices for BackendFixture {
    type Permit = ();
    type Error = String;

    fn preflight(&mut self, request: ServiceRequest) -> Result<(), String> {
        assert_eq!(request.source_pc, self.expected_source_pc);
        self.calls.push("preflight");
        Ok(())
    }
    fn synchronize_context(
        &mut self,
        _: &mut (),
        _: ExceptionLevel,
    ) -> Result<(), EffectFailure<String>> {
        self.calls.push("synchronize");
        if self.fail_synchronize {
            Err(EffectFailure {
                error: "unavailable synchronization".into(),
                completion: Completion::None,
            })
        } else {
            Ok(())
        }
    }
    fn clear_exclusive_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
        self.calls.push("clear_exclusive");
        Ok(())
    }
    fn send_event_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
        self.calls.push("send_event");
        Ok(())
    }
    fn branch_address(
        &mut self,
        _: &mut (),
        target: u64,
        _: ExceptionLevel,
    ) -> Result<u64, EffectFailure<String>> {
        self.calls.push("branch_address");
        Ok(target)
    }
}

impl Backend for BackendFixture {
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        _: &SystemState,
        _: &GuestState,
    ) -> Result<(), String> {
        self.calls.push("validate_entry");
        let analysis = stela_compiler::block::analyze_with_profile(
            source,
            boundary.entry(),
            stela_compiler::block::BlockProfile::SystemV1,
        )
        .map_err(|error| error.to_string())?;
        if self.deny_cssc
            && source[..analysis.source_bytes]
                .as_chunks::<4>()
                .0
                .iter()
                .any(|bytes| {
                    stela_compiler::aarch64::integer_unary::decode(u32::from_le_bytes(*bytes))
                        .is_some()
                })
        {
            return Err("FEAT_CSSC is absent in this source-authorized fixture profile".into());
        }
        Ok(())
    }
    fn entry_snapshot(
        &mut self,
        _: &Boundary,
        _: &SystemState,
        _: &GuestState,
    ) -> Result<EntrySnapshot, String> {
        self.calls.push("entry_snapshot");
        self.entry.ok_or_else(|| "entry backend unavailable".into())
    }
    fn tag_snapshot(
        &mut self,
        _: &Boundary,
        _: &SystemState,
        _: &GuestState,
    ) -> Result<TagSnapshot, String> {
        self.calls.push("tag_snapshot");
        self.tags.ok_or_else(|| "tag backend unavailable".into())
    }
    fn tag_memory(&mut self) -> Result<&mut MemoryThread<MemoryControls>, String> {
        self.calls.push("tag_memory");
        self.memory
            .as_mut()
            .ok_or_else(|| "memory backend unavailable".into())
    }
}

#[test]
fn wrong_space_and_il_decline_before_backend_or_register_effects() {
    let mut system = state(false, false);
    let mut registers = registers();
    let original = registers.clone();
    let mut backend = BackendFixture::new();
    let mut wrong = entry(SVC);
    wrong.address_space += 1;
    assert_eq!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend).validate_entry(
            &wrong,
            &SVC.to_le_bytes(),
            &registers
        ),
        Err(Failure::WrongAddressSpace)
    );
    system
        .transition_pstate(
            &mut registers,
            PSTATE_EL1H | PSTATE_IL_MASK | u64::from(REGISTER_FLAGS),
        )
        .unwrap();
    assert_eq!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend).validate_entry(
            &entry(SVC),
            &SVC.to_le_bytes(),
            &registers
        ),
        Err(Failure::IllegalExecutionState)
    );
    assert_eq!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
            .complete(boundary(IRG), &mut registers),
        Err(Failure::IllegalExecutionState)
    );
    assert_eq!(registers, original);
    assert!(backend.calls.is_empty());
}

#[test]
fn absent_or_failed_exception_backend_preserves_architectural_state() {
    let mut system = state(false, false);
    let mut registers = registers();
    let original_system = system.clone();
    let original_registers = registers.clone();
    let mut backend = BackendFixture::new();
    backend.entry = None;
    assert!(matches!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
            .complete(boundary(SVC), &mut registers),
        Err(Failure::Backend(_))
    ));
    backend = BackendFixture::new();
    backend.fail_synchronize = true;
    assert!(matches!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
            .complete(boundary(SVC), &mut registers),
        Err(Failure::ExceptionExecute(ExecuteError::Effect {
            stage: EffectStage::Synchronize,
            committed: CommittedPrefix::None,
            failure: EffectFailure {
                completion: Completion::None,
                ..
            },
        }))
    ));
    assert_eq!(system, original_system);
    assert_eq!(registers, original_registers);
    assert_eq!(
        backend.calls,
        ["entry_snapshot", "preflight", "synchronize"]
    );
}

#[test]
fn random_tag_completes_without_any_memory_backend() {
    let mut system = state(true, false);
    let mut registers = registers();
    let mut backend = BackendFixture::new();
    backend.tags = Some(TagSnapshot {
        allocation_access_enabled: true,
        memory: None,
    });
    assert_eq!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
            .complete(boundary(IRG), &mut registers),
        Ok(GuestAddress(SOURCE_PC.0 + size_of::<u32>() as u64))
    );
    assert_eq!(backend.calls, ["tag_snapshot"]);
    assert_eq!(registers.nzcv, REGISTER_FLAGS);
}

fn tag_snapshot(privileged: bool) -> TagSnapshot {
    TagSnapshot {
        allocation_access_enabled: true,
        memory: Some(TagMemorySnapshot {
            lower_address: LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
            fault_mode: TagCheckFaultMode::Asynchronous,
            tag_check_mask: false,
            transfer: tag_transfer::Profile::new(privileged, true, 16, 64).unwrap(),
        }),
    }
}

#[test]
fn tag_privilege_mismatch_is_rejected_before_memory_or_state_effects() {
    let mut system = state(true, false);
    let mut registers = registers();
    let original = registers.clone();
    let mut backend = BackendFixture::new();
    backend.tags = Some(tag_snapshot(false));
    assert!(matches!(
        Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
            .complete(boundary(LDG), &mut registers),
        Err(Failure::Unsupported(_))
    ));
    assert_eq!(backend.calls, ["tag_snapshot"]);
    assert_eq!(registers, original);
}

#[test]
fn tag_entry_refreshes_actual_policy_from_authoritative_el_and_tco() {
    for tco in [false, true] {
        let mut system = state(true, tco);
        let mut registers = registers();
        let mut backend = BackendFixture::new();
        backend.tags = Some(tag_snapshot(true));
        let stale = MemoryControls::new(
            LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
            false,
            true,
            !tco,
            TagCheckFaultMode::Asynchronous,
            false,
        );
        backend.memory = Some(
            MemoryDomain::new_for_address_space(
                ADDRESS_SPACE,
                MemorySystem::new(ERG_BYTES, STRIPES).unwrap(),
                Vec::new(),
                TargetCpu::detect(),
            )
            .unwrap()
            .thread(stale),
        );
        let result = Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
            .complete(boundary(LDG), &mut registers);
        assert!(matches!(
            result,
            Err(Failure::TagMemory {
                fault: tag_transfer::Fault {
                    cause: tag_transfer::Cause::Access {
                        error: MemoryStatus::Translation,
                        ..
                    },
                    ..
                },
                settlement_error: None,
            })
        ));
        let memory = backend.memory.as_mut().unwrap();
        assert_eq!(memory.policy_mut().validate_privilege(true), Ok(()));
        assert_eq!(
            memory.validate_execution(flags::TAG_CHECKED),
            if tco {
                Ok(())
            } else {
                Err(MemoryStatus::Unsupported)
            }
        );
    }
}

#[test]
fn tag_failure_report_retains_structured_access_prefix_and_settlement_error() {
    let failure = Failure::TagMemory {
        fault: tag_transfer::Fault {
            cause: tag_transfer::Cause::Access {
                access: tag_transfer::Access {
                    address: DATA_ADDRESS,
                    kind: tag_transfer::AccessKind::TagWrite,
                    privileged: true,
                    required_alignment: 16,
                    pair: true,
                    zero_bulk: false,
                    data_registers: [Some(0), None],
                    tag_checked: false,
                },
                error: MemoryStatus::Permission,
            },
            completed: tag_transfer::Progress {
                tag_reads: 0,
                tag_writes: 1,
                data_granules: 0,
            },
        },
        settlement_error: Some(MemoryStatus::Domain),
    };
    let report = serde_json::to_value(failure).unwrap();
    assert_eq!(report["cause"]["access"]["address"], DATA_ADDRESS);
    assert_eq!(report["cause"]["status"], MemoryStatus::Permission as u32);
    assert_eq!(report["completed"]["tag_writes"], 1);
    assert_eq!(report["settlement_error"], MemoryStatus::Domain as u32);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn actual_block_runtime_preserves_failed_exception_pc_and_completed_prefix() -> anyhow::Result<()> {
    use crate::blocks::{BlockRuntime, StopReason, ThreadState};
    use stela_compiler::block::BlockProfile;
    const ADD: u32 = 0x9100_0400;
    let cache = tempfile::tempdir()?;
    let mut runtime =
        BlockRuntime::new_with_profile(ADDRESS_SPACE, cache.path().into(), BlockProfile::SystemV1);
    runtime.register_code(
        SOURCE_PC,
        [ADD, SVC].into_iter().flat_map(u32::to_le_bytes).collect(),
    )?;
    let mut thread = ThreadState {
        registers: registers(),
        pc: SOURCE_PC,
    };
    let original_x0 = thread.registers.x[0];
    let mut system = state(false, false);
    let original_system = system.clone();
    let mut backend = BackendFixture::new();
    backend.fail_synchronize = true;
    backend.expected_source_pc = SOURCE_PC.0 + size_of::<u32>() as u64;
    let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
    // SAFETY: trusted pure ADD prefix and a checked System service boundary;
    // the fixture fails synchronization before any exception architectural effect.
    let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut execution)? };
    assert!(matches!(
        outcome.reason,
        StopReason::SystemFailure {
            failure: Failure::ExceptionExecute(ExecuteError::Effect {
                committed: CommittedPrefix::None,
                ..
            }),
            ..
        }
    ));
    assert_eq!(thread.pc, GuestAddress(backend.expected_source_pc));
    assert_eq!(thread.registers.x[0], original_x0 + 1);
    assert_eq!(system, original_system);
    Ok(())
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn illegal_state_stops_before_decode_and_any_native_prefix() -> anyhow::Result<()> {
    use crate::blocks::{BlockRuntime, StopReason, ThreadState};
    use stela_compiler::block::BlockProfile;
    const ADD: u32 = 0x9100_0400;
    const UNALLOCATED: u32 = u32::MAX;
    for words in [[ADD, SVC], [IRG, SVC], [UNALLOCATED, SVC]] {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
        );
        runtime.register_code(
            SOURCE_PC,
            words.into_iter().flat_map(u32::to_le_bytes).collect(),
        )?;
        let mut thread = ThreadState {
            registers: registers(),
            pc: SOURCE_PC,
        };
        let original = thread.registers.clone();
        let mut system = state(false, false);
        system
            .transition_pstate(
                &mut thread.registers,
                PSTATE_EL1H | PSTATE_IL_MASK | u64::from(REGISTER_FLAGS),
            )
            .unwrap();
        let mut backend = BackendFixture::new();
        let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
        // SAFETY: entry must reject IL before any decoding, mapping or invocation.
        let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut execution)? };
        assert!(matches!(
            outcome.reason,
            StopReason::SystemEntryFailure {
                instruction_pc: SOURCE_PC,
                failure: Failure::IllegalExecutionState,
                ..
            }
        ));
        assert_eq!(outcome.blocks_executed, 0);
        assert_eq!(outcome.compiled_blocks, 0);
        assert_eq!(thread.pc, SOURCE_PC);
        assert_eq!(thread.registers, original);
        assert!(backend.calls.is_empty());
    }
    Ok(())
}

#[test]
fn authorized_el0_bulk_is_undefined_without_memory_attachment_or_geometry() {
    use crate::system::state::PSTATE_EL0T;
    const LDGM: u32 = 0xd9e0_0000;
    const STGM: u32 = 0xd9a0_0000;
    const STZGM: u32 = 0xd920_0000;
    for word in [LDGM, STGM, STZGM] {
        let mut system = state(true, false);
        let mut registers = registers();
        system
            .transition_pstate(&mut registers, PSTATE_EL0T | u64::from(REGISTER_FLAGS))
            .unwrap();
        let original_registers = registers.clone();
        let original_system = system.clone();
        let mut backend = BackendFixture::new();
        backend.tags = Some(TagSnapshot {
            allocation_access_enabled: true,
            memory: None,
        });
        assert_eq!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(word), &mut registers),
            Err(Failure::TagMemory {
                fault: tag_transfer::Fault {
                    cause: tag_transfer::Cause::UndefinedPrivilege,
                    completed: tag_transfer::Progress::default()
                },
                settlement_error: None,
            })
        );
        assert_eq!(backend.calls, ["tag_snapshot"]);
        assert_eq!(registers, original_registers);
        assert_eq!(system, original_system);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn unavailable_optional_feature_beyond_first_word_prevents_all_prefix_effects() -> anyhow::Result<()>
{
    use crate::blocks::{BlockRuntime, StopReason, ThreadState};
    use stela_compiler::block::BlockProfile;
    const ADD: u32 = 0x9100_0400;
    const CSSC_ABS: u32 = 0xdac0_2000;
    let cache = tempfile::tempdir()?;
    let mut runtime =
        BlockRuntime::new_with_profile(ADDRESS_SPACE, cache.path().into(), BlockProfile::SystemV1);
    runtime.register_code(
        SOURCE_PC,
        [ADD, CSSC_ABS, SVC]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    )?;
    let mut thread = ThreadState {
        registers: registers(),
        pc: SOURCE_PC,
    };
    let original = thread.registers.clone();
    let mut system = state(false, false);
    let mut backend = BackendFixture::new();
    backend.deny_cssc = true;
    let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
    // SAFETY: authoritative feature rejection must happen before any native prefix.
    let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut execution)? };
    assert!(matches!(
        outcome.reason,
        StopReason::SystemEntryFailure {
            failure: Failure::Backend(_),
            ..
        }
    ));
    assert_eq!(thread.registers, original);
    assert_eq!(thread.pc, SOURCE_PC);
    assert_eq!(outcome.blocks_executed, 0);
    assert_eq!(outcome.compiled_blocks, 0);
    assert_eq!(backend.calls, ["validate_entry"]);
    // The shared parser bounds authorization at the first actual terminator.
    let source: Vec<_> = [SVC, CSSC_ABS]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(
        backend.validate_entry(&entry(SVC), &source, &system, &thread.registers),
        Ok(())
    );
    Ok(())
}
