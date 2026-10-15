//! Actual production block/runtime execution over validated original inputs.
//! This module does not import Expected; comparison data stays in the caller.
use super::provenance::{
    DENY_READ, DENY_WRITE, RAM_BYTES, TAGGED, ValidatedInput, hex, state_bytes,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::cell::UnsafeCell;
use std::ptr::NonNull;
use std::sync::Arc;
use stela_compiler::{GuestAddress, GuestState, TargetCpu, aarch64::tag_memory, block};
use stela_runtime::blocks::{BlockRuntime, StopReason, ThreadState};
use stela_runtime::memory::{
    backing::{AccessPermissions, MemoryBacking, MemoryView},
    domain::{MemoryDomain, MemorySystem, MemoryThread},
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    tag_transfer::{self, Cause, Progress},
    tags::{AllocationTag, TAG_GRANULE_BYTES, TagGenerationState, TagRandomization},
};
use stela_runtime::system::{
    access::ExceptionLevel,
    exception::{EffectFailure, ExceptionServices, ServiceRequest},
    execution::{
        Backend, Boundary, Dispatcher, EntryBoundary, EntrySnapshot, Execution, Failure,
        TagMemorySnapshot, TagSnapshot,
    },
    pstate::MteFeature,
    state::{El1Registers, MteState, SystemState},
};
const INSTRUCTION_BYTES: u64 = 4;
const RGSR_SEED_SHIFT: u32 = 8;
const ALLOCATION_TAG_MASK: u64 = 15;
const GCR_RRND: u64 = 1 << 16;
const UNUSED_GENERATION: (u64, u64) = (0, 0);
const ORIGINAL_MTE2_FEATURE: u64 = 2;
const ORIGINAL_MTE3_FEATURE: u64 = 3;
const OBSERVER_STRIPES: usize = 16;
const UNOBSERVED_INACTIVE_SP: u64 = 0;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
fn state_hex(state: &GuestState) -> String {
    hex(state_bytes(state))
}
#[repr(align(16))]
struct Storage(UnsafeCell<[u8; RAM_BYTES]>);
// SAFETY: storage is accessed only through raw pointers in this serialized
// observer; no byte references overlap service access and no threads are spawned.
unsafe impl Send for Storage {}
unsafe impl Sync for Storage {}

fn progress(value: Progress) -> Value {
    json!([value.tag_reads, value.tag_writes, value.data_granules])
}
fn fault(value: &tag_transfer::Fault<stela_compiler::context::memory::MemoryStatus>) -> Value {
    use stela_compiler::context::memory::MemoryStatus;
    let class = match &value.cause {
        Cause::UndefinedPrivilege => "undefined_privilege",
        Cause::StackAlignment { .. } => "stack_alignment",
        Cause::DataAlignment { .. } => "data_alignment",
        Cause::Access {
            error: MemoryStatus::Translation,
            ..
        } => "translation",
        Cause::Access {
            error: MemoryStatus::Permission,
            ..
        } => "permission",
        Cause::Access { .. } => "access_other",
        Cause::Platform(_) => "platform",
        Cause::InvalidOperands => "invalid_operands",
        Cause::NotMemoryInstruction => "not_memory_instruction",
    };
    let access = match &value.cause {
        Cause::Access { access, .. } => json!({
            "address": access.address, "kind": format!("{:?}", access.kind),
            "privileged": access.privileged, "required_alignment": access.required_alignment,
            "pair": access.pair, "zero_bulk": access.zero_bulk,
            "data_registers": access.data_registers, "tag_checked": access.tag_checked,
        }),
        _ => Value::Null,
    };
    let mut result =
        json!({"class": class, "cause_debug": format!("{:?}", value.cause), "access": access});
    match value.cause {
        Cause::StackAlignment { stack_pointer } => result["stack_pointer"] = json!(stack_pointer),
        Cause::DataAlignment { address } => result["address"] = json!(address),
        _ => {}
    }
    result
}
struct MemoryFixture {
    backing: Arc<MemoryBacking>,
    thread: MemoryThread<MemoryControls>,
    profile: tag_transfer::Profile,
    lower_address: LowerAddressProfile,
}
impl MemoryFixture {
    fn new(input: &ValidatedInput, system: &SystemState, address_space: u64) -> Result<Self> {
        let ram = input.ram.clone();
        let tags = input.tags.clone();
        ensure!(
            ram.len() == RAM_BYTES && tags.len() == RAM_BYTES / TAG_GRANULE_BYTES,
            "RAM/tag layout mismatch"
        );
        let storage = Arc::new(Storage(UnsafeCell::new(ram.try_into().unwrap())));
        let pointer = NonNull::new(storage.0.get().cast::<u8>()).unwrap();
        // SAFETY: aligned stable allocation retained by backing; only serialized raw
        // accesses occur while the service is live. Native rights remain RW.
        let backing =
            unsafe { MemoryBacking::new(pointer, RAM_BYTES, RIGHTS, Arc::clone(&storage)) }
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        for (index, tag) in tags.iter().enumerate() {
            backing
                .allocation_tags()
                .write(
                    index * TAG_GRANULE_BYTES,
                    AllocationTag::new(*tag).context("invalid input tag")?,
                )
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        }
        let flags = input.input.flags.context("missing validated flags")?;
        let address = input
            .input
            .ram_address
            .context("missing validated ram_address")?;
        let end = address + RAM_BYTES as u64;
        let denied_start = input
            .input
            .denied_start
            .context("missing validated denied_start")?;
        let denied_end = input
            .input
            .denied_end
            .context("missing validated denied_end")?;
        let mut boundaries = vec![address, end];
        boundaries.extend(
            [denied_start, denied_end]
                .into_iter()
                .filter(|value| *value > address && *value < end),
        );
        boundaries.sort_unstable();
        boundaries.dedup();
        let attributes = stela_runtime::memory::domain::MappingAttributes {
            tagged: flags & TAGGED != 0,
            shareable: true,
        };
        let mut views = Vec::new();
        for span in boundaries.windows(2) {
            let denied = span[0] >= denied_start && span[0] < denied_end;
            let rights = AccessPermissions {
                readable: !denied || flags & DENY_READ == 0,
                writable: !denied || flags & DENY_WRITE == 0,
                executable: false,
            };
            let view = MemoryView::new(
                Arc::clone(&backing),
                span[0],
                (span[0] - address) as usize,
                (span[1] - span[0]) as usize,
                rights,
            )
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            views.push((view, attributes));
        }
        let privileged = input.controls.privileged;
        let lower_address =
            LowerAddressProfile::new(input.controls.address_bits, input.controls.top_byte_ignore)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let controls = MemoryControls::new(
            lower_address,
            privileged,
            input.controls.allocation_enabled,
            system.tag_check_override(),
            TagCheckFaultMode::Ignore,
            false,
        );
        let coherence = MemorySystem::new(TAG_GRANULE_BYTES as u64, OBSERVER_STRIPES)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let domain =
            MemoryDomain::new_for_address_space(address_space, coherence, views, TargetCpu::Cx16)
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let thread = domain.thread(controls);
        let profile = tag_transfer::Profile::new(
            privileged,
            input.controls.check_sp,
            input.controls.gmid_bytes,
            input.controls.dczid_bytes,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok(Self {
            backing,
            thread,
            profile,
            lower_address,
        })
    }
    fn snapshot(&self) -> Result<(String, String)> {
        let pointer = self
            .backing
            .host_pointer(
                0,
                RAM_BYTES,
                stela_runtime::memory::backing::AccessKind::Read,
            )
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        // SAFETY: observer is serialized; this snapshot is taken only outside an
        // active service invocation. No references to these bytes survive it.
        let ram = unsafe { std::slice::from_raw_parts(pointer.as_ptr(), RAM_BYTES) };
        let tags = (0..RAM_BYTES / TAG_GRANULE_BYTES)
            .map(|index| {
                self.backing
                    .allocation_tags()
                    .read(index * TAG_GRANULE_BYTES)
                    .map(|tag| tag.value())
                    .map_err(|error| anyhow::anyhow!("{error:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((hex(ram), hex(&tags)))
    }
}

struct FixtureBackend {
    address_space: u64,
    expected_pc: GuestAddress,
    expected_word: u32,
    privileged: bool,
    allocation_enabled: bool,
    original_mte_feature_field: u64,
    memory: Option<MemoryFixture>,
    memory_calls: usize,
}
impl ExceptionServices for FixtureBackend {
    type Permit = std::convert::Infallible;
    type Error = String;
    fn preflight(&mut self, _: ServiceRequest) -> Result<Self::Permit, String> {
        Err("exception services are outside this MTE observer profile".into())
    }
    fn synchronize_context(
        &mut self,
        permit: &mut Self::Permit,
        _: ExceptionLevel,
    ) -> Result<(), EffectFailure<String>> {
        match *permit {}
    }
    fn clear_exclusive_local(
        &mut self,
        permit: &mut Self::Permit,
    ) -> Result<(), EffectFailure<String>> {
        match *permit {}
    }
    fn send_event_local(&mut self, permit: &mut Self::Permit) -> Result<(), EffectFailure<String>> {
        match *permit {}
    }
    fn branch_address(
        &mut self,
        permit: &mut Self::Permit,
        _: u64,
        _: ExceptionLevel,
    ) -> Result<u64, EffectFailure<String>> {
        match *permit {}
    }
}
impl Backend for FixtureBackend {
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        system: &SystemState,
        _: &GuestState,
    ) -> Result<(), String> {
        if boundary.address_space() != self.address_space
            || boundary.entry() != self.expected_pc
            || boundary.word() != self.expected_word
        {
            return Err("source-bound fixture controls do not match the production entry".into());
        }
        if (system.current_el() == ExceptionLevel::El1) != self.privileged {
            return Err("effective fixture privilege differs from authoritative PSTATE".into());
        }
        let analysis =
            block::analyze_with_profile(source, boundary.entry(), block::BlockProfile::SystemV1)
                .map_err(|error| error.to_string())?;
        if source.len() != INSTRUCTION_BYTES as usize
            || analysis.source_bytes != INSTRUCTION_BYTES as usize
        {
            return Err("fixture profile authorizes exactly one original System instruction, with no optional prefix".into());
        }
        let instruction = analysis
            .system_instruction
            .ok_or("fixture source has no System instruction")?;
        if !matches!(
            instruction.operation,
            block::system::SystemOperation::TagMemory(_)
        ) || !matches!(
            self.original_mte_feature_field,
            ORIGINAL_MTE2_FEATURE | ORIGINAL_MTE3_FEATURE
        ) {
            return Err(
                "fixture CPU profile does not authorize this reached MTE instruction".into(),
            );
        }
        Ok(())
    }
    fn entry_snapshot(
        &mut self,
        _: &Boundary,
        _: &SystemState,
        _: &GuestState,
    ) -> Result<EntrySnapshot, String> {
        Err("exception snapshots are outside this MTE observer profile".into())
    }
    fn tag_snapshot(
        &mut self,
        boundary: &Boundary,
        system: &SystemState,
        _: &GuestState,
    ) -> Result<TagSnapshot, String> {
        let instruction = boundary.instruction();
        if instruction.instruction_pc != self.expected_pc
            || instruction.word != self.expected_word
            || !instruction.matches_source(self.expected_pc, self.expected_word)
            || (system.current_el() == ExceptionLevel::El1) != self.privileged
            || !matches!(
                self.original_mte_feature_field,
                ORIGINAL_MTE2_FEATURE | ORIGINAL_MTE3_FEATURE
            )
        {
            return Err(
                "terminal MTE source/access controls differ from the authorized fixture".into(),
            );
        }
        let random = matches!(
            boundary.instruction().operation,
            block::system::SystemOperation::TagMemory(tag_memory::Operand::RandomTag { .. })
        );
        if random != self.memory.is_none() {
            return Err("actual source instruction and fixture memory requirements differ".into());
        }
        let memory = self.memory.as_ref().map(|memory| TagMemorySnapshot {
            lower_address: memory.lower_address,
            fault_mode: TagCheckFaultMode::Ignore,
            tag_check_mask: false,
            transfer: memory.profile,
        });
        Ok(TagSnapshot {
            allocation_access_enabled: self.allocation_enabled,
            memory,
        })
    }
    fn tag_memory(&mut self) -> Result<&mut MemoryThread<MemoryControls>, String> {
        self.memory_calls += 1;
        self.memory
            .as_mut()
            .map(|memory| &mut memory.thread)
            .ok_or_else(|| "memory-free instruction requested memory service".into())
    }
}

/// Record the real runtime-created boundary, then forward it unchanged to the
/// production dispatcher. Boundary constructors are crate-private; this wrapper
/// cannot substitute a public test-built descriptor for production recovery.
struct RecordingDispatcher<'a> {
    address_space: u64,
    system: &'a mut SystemState,
    backend: &'a mut FixtureBackend,
    initial: &'a GuestState,
    initial_system: &'a SystemState,
    recorded: Option<Value>,
}
impl Dispatcher for RecordingDispatcher<'_> {
    fn address_space(&self) -> u64 {
        self.address_space
    }
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        registers: &GuestState,
    ) -> Result<(), Failure> {
        Execution::new(self.address_space, self.system, self.backend)
            .validate_entry(boundary, source, registers)
    }
    fn complete(
        &mut self,
        boundary: Boundary,
        registers: &mut GuestState,
    ) -> Result<GuestAddress, Failure> {
        if self.recorded.is_some()
            || registers != self.initial
            || *self.system != *self.initial_system
        {
            return Err(Failure::Backend(
                "native System exit changed owned state or repeated dispatch".into(),
            ));
        }
        let mte = self
            .system
            .mte()
            .ok_or(Failure::Unsupported("missing authoritative MTE owner"))?;
        let generation = mte.generation();
        let mut record = json!({
            "state_at_exit_hex": state_hex(registers),
            "rgsr_at_exit": (u64::from(generation.seed) << RGSR_SEED_SHIFT) | u64::from(generation.tag.value()),
            "gcr_at_exit": u64::from(mte.excluded_tags()) | if mte.randomization() == TagRandomization::External { GCR_RRND } else { 0 },
            "exit_pc": boundary.instruction().instruction_pc.0,
            "recovered_word": boundary.instruction().word,
            "source_address_space": boundary.source().address_space(),
            "source_generation": boundary.source().generation(),
            "source_region_base": boundary.source().region_base().0,
            "source_region_bytes": boundary.source().source_bytes(),
            "consumed_bytes": boundary.consumed_bytes(),
        });
        if let Some(memory) = self.backend.memory.as_ref() {
            let (ram, tags) = memory
                .snapshot()
                .map_err(|error| Failure::Backend(error.to_string()))?;
            record["ram_at_exit_hex"] = json!(ram);
            record["tags_at_exit_hex"] = json!(tags);
        }
        self.recorded = Some(record);
        Execution::new(self.address_space, self.system, self.backend).complete(boundary, registers)
    }
}

pub(super) fn execute(runtime: &mut BlockRuntime, input: &ValidatedInput) -> Result<Value> {
    let pc = input.input.instruction_pc;
    let initial = input.registers.clone();
    let generation = input.controls.generation;
    // These registers are structurally unused by dedicated nonbulk operations.
    // Their fixture-selected zero storage is explicitly not an original readback.
    let (gcr, rgsr) = generation
        .map(|value| (value.gcr, value.rgsr))
        .unwrap_or(UNUSED_GENERATION);
    let generation_state = TagGenerationState {
        seed: (rgsr >> RGSR_SEED_SHIFT) as u16,
        tag: AllocationTag::new((rgsr & ALLOCATION_TAG_MASK) as u8).unwrap(),
    };
    let mte = MteState::new(
        gcr as u16,
        if gcr & GCR_RRND != 0 {
            TagRandomization::External
        } else {
            TagRandomization::ArchitecturalLfsr
        },
        generation_state,
    );
    // Exception registers/inactive stack are not observed or used by this MTE-only
    // profile. All exception callbacks decline; active State/PSTATE are original.
    let mut system = SystemState::new_with_mte(
        input.controls.pstate_misc,
        UNOBSERVED_INACTIVE_SP,
        El1Registers::new(0, 0, 0, 0, 0),
        MteFeature::TwoOrLater,
        mte,
    )
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let initial_system = system.clone();
    let memory = if input.input.kind == "IRG" {
        None
    } else {
        Some(MemoryFixture::new(input, &system, runtime.address_space())?)
    };
    let mut backend = FixtureBackend {
        address_space: runtime.address_space(),
        expected_pc: GuestAddress(pc),
        expected_word: input.input.word,
        privileged: input.controls.privileged,
        allocation_enabled: input.controls.allocation_enabled,
        original_mte_feature_field: input.controls.feature,
        memory,
        memory_calls: 0,
    };
    let mut state = ThreadState {
        registers: input.registers.clone(),
        pc: GuestAddress(pc),
    };
    let mut recorder = RecordingDispatcher {
        address_space: runtime.address_space(),
        system: &mut system,
        backend: &mut backend,
        initial: &initial,
        initial_system: &initial_system,
        recorded: None,
    };
    // SAFETY: original-authorized single MTE word, no native RAM prefix; the
    // production service owns the aligned physical backing and writer domain.
    let outcome = unsafe {
        runtime.run_with_system(
            &mut state,
            Some(GuestAddress(pc + INSTRUCTION_BYTES)),
            1,
            &mut recorder,
        )?
    };
    let mut observed = recorder
        .recorded
        .take()
        .context("runtime did not reach a validated MTE boundary")?;
    drop(recorder);
    match outcome.reason {
        StopReason::StopAddress => {
            observed["status"] = json!("success");
            observed["fault"] = Value::Null;
            observed["progress"] = Value::Null;
            observed["success_progress"] = Value::Null;
        }
        StopReason::SystemFailure {
            failure:
                Failure::TagMemory {
                    fault: failure,
                    settlement_error,
                },
            ..
        } => {
            ensure!(
                settlement_error.is_none(),
                "reservation settlement failed: {settlement_error:?}"
            );
            let report = fault(&failure);
            observed["status"] = report["class"].clone();
            observed["fault"] = report;
            observed["progress"] = progress(failure.completed);
        }
        other => bail!("unexpected production runtime stop: {other:?}"),
    }
    ensure!(
        outcome.blocks_executed == 1
            && outcome.last_exit == Some((pc, block::ExitKind::System as u64)),
        "wrong actual native System exit"
    );
    let mut preserved_system = system.clone();
    if input.input.kind == "IRG" {
        *preserved_system
            .mte_mut()
            .context("missing post-service MTE owner")?
            .generation_mut() = *initial_system
            .mte()
            .context("missing pre-service MTE owner")?
            .generation();
    }
    ensure!(
        preserved_system == initial_system,
        "service changed unrelated owned SystemState"
    );
    observed["unrelated_system_state_preserved"] = json!(true);
    let mte = system
        .mte()
        .context("missing authoritative MTE owner after dispatch")?;
    observed["rgsr"] = json!(
        (u64::from(mte.generation().seed) << RGSR_SEED_SHIFT)
            | u64::from(mte.generation().tag.value())
    );
    observed["gcr"] = json!(
        u64::from(mte.excluded_tags())
            | if mte.randomization() == TagRandomization::External {
                GCR_RRND
            } else {
                0
            }
    );
    observed["generation_authority"] = json!(if generation.is_some() {
        "captured_pre_readback"
    } else {
        "structurally_unused_fixture_storage"
    });
    observed["memory_service_calls"] = json!(backend.memory_calls);
    if let Some(memory) = &backend.memory {
        let (ram, tags) = memory.snapshot()?;
        observed["ram_hex"] = json!(ram);
        observed["tags_hex"] = json!(tags);
    }
    observed["case_id"] = json!(input.input.case_id);
    observed["exit_kind"] = json!("System");
    observed["source_recovery"] = json!("BlockRuntime_registered_region_shared_decoder");
    observed["state_hex"] = json!(state_hex(&state.registers));
    observed["next_pc"] = json!(state.pc.0);
    observed["native_blocks_executed"] = json!(outcome.blocks_executed);
    Ok(observed)
}
