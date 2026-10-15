//! Private bounded original replay through the real checked BlockRuntime entry.
//! No modeled callback, raw native entry or caller-authored body requirements.
use crate::{
    blocks::{BlockRuntime, ThreadState},
    memory::{
        MemoryRegionSpec, OwnedMemory, SharedMemoryConfig,
        domain::{MappingAttributes, MemorySystem, MemoryThread},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    },
    system::{
        access::ExceptionLevel,
        events::{EventDomain, EventEndpoint},
        exception::{Completion, EffectFailure, ExceptionServices, ServiceRequest},
        execution::{Backend, Boundary, EntryBoundary, EntrySnapshot, Execution, TagSnapshot},
        process_memory::{
            FixedProcessMemoryControls, PreparedProcessMemory, ProcessMemoryFeatures,
            SourceNormalWbDomain,
        },
        profile::BaseSpeAbsence,
        state::{El1Registers, PSTATE_EL0T, SystemState},
    },
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    mem::offset_of,
    path::{Path, PathBuf},
};
use stela_compiler::{
    GuestAddress, GuestState, SOURCE_FINGERPRINT_MATERIAL,
    block::{BlockProfile, CheckedMemoryProfile},
    context::{
        ExecutionContext,
        memory::{MemoryRequirements, flags},
    },
};
use stela_core::sha256;

const ADDRESS_SPACE: u64 = 71;
const ORIGINAL_CASES: usize = 32;
const STATE_BYTES: usize = 784;
const RAM_BYTES: usize = 8192;
const INSTRUCTION_BYTES: u64 = 4;
const RET_X30: u32 = 0xd65f_03c0;
const ERG_BYTES: u64 = 16;
const MONITOR_STRIPES: usize = 8;
const PSTATE_DAIF_MASKED: u64 = 0x3c0;
const TCR_T0SZ_MASK: u64 = 0x3f;
const CAPTURE_ID: &str = "8558460bc1c2434ad43e3a7b79c90df830ee73ff799f62b6485bb874bda2aab1";
const INITIAL_STATES_SHA256: &str =
    "8f59984e71b6e724536240933732e630d31bd2b4b2f88ee3ac128799bf50ec51";
const ORIGINAL_STATES_SHA256: &str =
    "fc3158e8d1d0b26d936bc10a744f28921a6f7db927d1fd16f70b3c2b1b09e0fa";
const ORIGINAL_RESULTS_SHA256: &str =
    "aa0d7fc6977cd4cfe1451febdb33dbe75eedb56ed956bcaac646890fdfd4575e";
const INITIAL_RAM_SHA256: &str = "85313ae132d8b99b9f9590315a07fa27dc86970eb56a5232bcf81fab2a1bf05b";
const PROJECTION_SHA256: &str = "06df72d57f9b8eb01320ba30c0c277222276dff13cb751021a8e932195035b5f";
const ORIGINAL_AUDIT_SHA256: &str =
    "b0a3573a191de2761d81a3a56c4319365bab4099640b87f5b99ffa8e72929305";
// This native proof constructs an explicit fresh bounded machine. These absence
// declarations are not inferred from the original QEMU max feature inventory.
const NATIVE_ID_AA64ISAR3_EL1: u64 = 0;
const NATIVE_ID_AA64PFR1_EL1: u64 = 0;
const NATIVE_ID_AA64DFR0_EL1: u64 = 0;
const MEMORY_PLAN_SHA256: &str = "6f33126dbad6143c54dc6a85d0785b23c089d7986ea6ba8e2f80b1f743953199";
const NZCV_MASK: u64 = 0xf000_0000;
const RESULTS_SCTLR_OFFSET: usize = 72;
const RESULTS_TCR_OFFSET: usize = 80;
const RESULTS_MMFR2_OFFSET: usize = 104;
// Exact retained C1 observer layout, independently reviewed in eb666efa.
const WB_HEADER_OFFSET: usize = 256;
const WB_CONTROL_COUNT: usize = 6;
const WB_PHASE_BYTES: usize = WB_CONTROL_COUNT * size_of::<u64>();
const WB_READY_OFFSET: usize = WB_HEADER_OFFSET + WB_PHASE_BYTES;
const WB_FINISHED_OFFSET: usize = WB_READY_OFFSET + WB_PHASE_BYTES;
const WB_DESCRIPTOR_OFFSET: usize = WB_FINISHED_OFFSET + WB_PHASE_BYTES;
const WB_MMFR0_OFFSET: usize = WB_DESCRIPTOR_OFFSET + size_of::<u64>();
const WB_SOURCE_ISAR3_OFFSET: usize = WB_MMFR0_OFFSET + size_of::<u64>();
const WB_SOURCE_DFR0_OFFSET: usize = WB_SOURCE_ISAR3_OFFSET + size_of::<u64>();
const SOURCE_EL1: u64 = 4;
const SOURCE_DATA_BLOCK_BYTES: u64 = 1 << 30;
const SOURCE_NORMAL_RW_ATTRIBUTES: u64 = (1 << 10) | (1 << 6) | (3 << 8) | 1;
const SOURCE_MAIR_NORMAL_WB: u64 = 0xff;
const SOURCE_TTBR0: u64 = 0x4001_0000;
const SCTLR_MMU_AND_DATA_CACHE: u64 = (1 << 0) | (1 << 2);
const CALLER_MXCSR_A: u32 = 0x3f95;
const CALLER_MXCSR_B: u32 = 0x5fa5;

#[derive(Deserialize)]
struct Projection {
    cases: usize,
    stride: usize,
    rows: Vec<OriginalRow>,
}
#[derive(Deserialize)]
struct OriginalRow {
    case: usize,
    words: Vec<u32>,
    source_pc: u64,
    initial_state_offset: usize,
    original_state_offset: usize,
    raw_ram_offset: usize,
    status: u32,
}
#[derive(Deserialize)]
struct MemoryPlan {
    ram_address: u64,
    ram_bytes: usize,
}

fn read_bound(
    path: &Path,
    expected: &str,
    bindings: &mut BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let hash = sha256(&bytes);
    ensure!(hash == expected, "fixture hash changed: {}", path.display());
    bindings.insert(path.display().to_string(), hash);
    Ok(bytes)
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + size_of::<u64>()].try_into().unwrap())
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + size_of::<u32>()].try_into().unwrap())
}
fn source_wb_facts(bytes: &[u8], plan: &MemoryPlan) -> Result<serde_json::Value> {
    let ready: [u64; WB_CONTROL_COUNT] =
        std::array::from_fn(|index| read_u64(bytes, WB_READY_OFFSET + index * size_of::<u64>()));
    let finished: [u64; WB_CONTROL_COUNT] =
        std::array::from_fn(|index| read_u64(bytes, WB_FINISHED_OFFSET + index * size_of::<u64>()));
    ensure!(
        ready == finished,
        "source controls changed during original capture"
    );
    ensure!(
        ready[0] == SOURCE_EL1,
        "observer EL differs from retained source contract"
    );
    ensure!(ready[1] == read_u64(bytes, RESULTS_SCTLR_OFFSET));
    ensure!(ready[1] & SCTLR_MMU_AND_DATA_CACHE == SCTLR_MMU_AND_DATA_CACHE);
    ensure!(ready[2] == read_u64(bytes, RESULTS_TCR_OFFSET));
    ensure!(ready[2] & TCR_T0SZ_MASK == 25);
    ensure!(ready[3] == SOURCE_MAIR_NORMAL_WB && ready[4] == SOURCE_TTBR0);
    ensure!((ready[5] >> 8) & 0xff == 0, "actual source has EL2 or EL3");
    let block_base = plan.ram_address & !(SOURCE_DATA_BLOCK_BYTES - 1);
    let ram_end = plan
        .ram_address
        .checked_add(plan.ram_bytes as u64)
        .context("RAM overflow")?;
    ensure!(ram_end <= block_base + SOURCE_DATA_BLOCK_BYTES);
    let descriptor = read_u64(bytes, WB_DESCRIPTOR_OFFSET);
    ensure!(
        descriptor == block_base | SOURCE_NORMAL_RW_ATTRIBUTES,
        "actual source block is not the reviewed identity NormalWB RW/shareable/AF mapping"
    );
    Ok(json!({"ready": ready, "finished": finished,
        "data_l1_descriptor": descriptor,
        "covered_ram_start": plan.ram_address, "covered_ram_end": ram_end,
        "ID_AA64MMFR0_EL1": read_u64(bytes, WB_MMFR0_OFFSET),
        "ID_AA64ISAR3_EL1": read_u64(bytes, WB_SOURCE_ISAR3_OFFSET),
        "ID_AA64DFR0_EL1": read_u64(bytes, WB_SOURCE_DFR0_OFFSET)}))
}
#[cfg(target_arch = "x86_64")]
fn caller_mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: valid writable scalar and MXCSR is available on every x86-64 host.
    unsafe {
        std::arch::asm!("stmxcsr [{address}]", address = in(reg) &mut value,
        options(nostack, preserves_flags));
    }
    value
}
#[cfg(target_arch = "x86_64")]
unsafe fn set_caller_mxcsr(value: u32) {
    // SAFETY: caller supplies the named legal masked x86-64 controls/sticky flags.
    unsafe {
        std::arch::asm!("ldmxcsr [{address}]", address = in(reg) &value,
        options(nostack, preserves_flags));
    }
}
fn state_from_bytes(bytes: &[u8]) -> Result<GuestState> {
    ensure!(bytes.len() == STATE_BYTES && size_of::<GuestState>() == STATE_BYTES);
    Ok(GuestState {
        x: std::array::from_fn(|index| read_u64(bytes, index * size_of::<u64>())),
        sp: read_u64(bytes, offset_of!(GuestState, sp)),
        nzcv: read_u32(bytes, offset_of!(GuestState, nzcv)),
        reserved: read_u32(bytes, offset_of!(GuestState, reserved)),
        v: std::array::from_fn(|register| {
            std::array::from_fn(|lane| {
                read_u64(
                    bytes,
                    offset_of!(GuestState, v) + (register * 2 + lane) * size_of::<u64>(),
                )
            })
        }),
        fpcr: read_u32(bytes, offset_of!(GuestState, fpcr)),
        fpsr: read_u32(bytes, offset_of!(GuestState, fpsr)),
    })
}
fn state_bytes(state: &GuestState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STATE_BYTES);
    for value in state.x {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(state.sp.to_le_bytes());
    bytes.extend(state.nzcv.to_le_bytes());
    bytes.extend(state.reserved.to_le_bytes());
    for vector in state.v {
        for value in vector {
            bytes.extend(value.to_le_bytes());
        }
    }
    bytes.extend(state.fpcr.to_le_bytes());
    bytes.extend(state.fpsr.to_le_bytes());
    assert_eq!(bytes.len(), STATE_BYTES);
    bytes
}

struct OriginalBackend {
    controls: FixedProcessMemoryControls,
    thread: MemoryThread<MemoryControls>,
    endpoint: EventEndpoint,
    source_pc: GuestAddress,
    generation: u64,
    source: Vec<u8>,
    validations: usize,
    memory_entries: usize,
    exception_attempts: usize,
}
impl Backend for OriginalBackend {
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        system: &SystemState,
        registers: &GuestState,
    ) -> std::result::Result<(), String> {
        self.validations += 1;
        if boundary.address_space() != ADDRESS_SPACE
            || boundary.generation() != self.generation
            || boundary.entry() != self.source_pc
            || boundary.region_base() != self.source_pc
            || boundary.source_bytes() != self.source.len()
            || source != self.source
            || boundary.word() != read_u32(&self.source, 0)
            || system.current_el() != ExceptionLevel::El0
            || system.pstate(registers) & !NZCV_MASK != PSTATE_EL0T | PSTATE_DAIF_MASKED
        {
            return Err("original replay immutable source or declared EL0 state differs".into());
        }
        Ok(())
    }
    fn prepare_process_memory<'run>(
        &'run mut self,
        boundary: &EntryBoundary,
        _source: &[u8],
        requirements: MemoryRequirements,
        system: &'run SystemState,
        registers: &GuestState,
    ) -> std::result::Result<PreparedProcessMemory<'run>, String> {
        self.memory_entries += 1;
        self.controls
            .prepare(
                boundary,
                requirements,
                system,
                registers,
                &mut self.thread,
                Some(&self.endpoint),
            )
            .map_err(|error| format!("actual process-memory authority declined: {error:?}"))
    }
    fn entry_snapshot(
        &mut self,
        _boundary: &Boundary,
        _system: &SystemState,
        _registers: &GuestState,
    ) -> std::result::Result<EntrySnapshot, String> {
        Err("exception backend unavailable in bounded original replay".into())
    }
    fn tag_snapshot(
        &mut self,
        _boundary: &Boundary,
        _system: &SystemState,
        _registers: &GuestState,
    ) -> std::result::Result<TagSnapshot, String> {
        Err("allocation-tag backend unavailable in bounded original replay".into())
    }
    fn tag_memory(&mut self) -> std::result::Result<&mut MemoryThread<MemoryControls>, String> {
        Err("dedicated tag-memory backend unavailable in bounded original replay".into())
    }
}
fn unavailable_effect() -> EffectFailure<String> {
    EffectFailure {
        error: "exception effect backend unavailable".into(),
        completion: Completion::None,
    }
}
impl ExceptionServices for OriginalBackend {
    type Permit = ();
    type Error = String;
    fn preflight(&mut self, _request: ServiceRequest) -> std::result::Result<(), String> {
        self.exception_attempts += 1;
        Err("exception backend unavailable in bounded original replay".into())
    }
    fn synchronize_context(
        &mut self,
        _permit: &mut (),
        _source_el: ExceptionLevel,
    ) -> std::result::Result<(), EffectFailure<String>> {
        Err(unavailable_effect())
    }
    fn clear_exclusive_local(
        &mut self,
        _permit: &mut (),
    ) -> std::result::Result<(), EffectFailure<String>> {
        Err(unavailable_effect())
    }
    fn send_event_local(
        &mut self,
        _permit: &mut (),
    ) -> std::result::Result<(), EffectFailure<String>> {
        Err(unavailable_effect())
    }
    fn branch_address(
        &mut self,
        _permit: &mut (),
        _target: u64,
        _destination_el: ExceptionLevel,
    ) -> std::result::Result<u64, EffectFailure<String>> {
        Err(unavailable_effect())
    }
}

/// # Safety
/// PRIVATE diagnostic observer only. All native and prepared authority scopes
/// have returned; this test is the sole storage owner/executor, without other
/// threads, writers, protection changes or retirement. OwnedMemory is retained
/// with its bound domain and pins exact-address anonymous storage and rights.
/// Copy only readable logical bytes into disjoint private Vec storage, exclude
/// allocation padding, and create no borrowed Rust reference to guest RAM.
unsafe fn observe_quiescent_ram(
    memory: &OwnedMemory,
    address: u64,
    bytes: usize,
) -> Result<Vec<u8>> {
    ensure!(memory.is_usable());
    let end = address
        .checked_add(bytes as u64)
        .context("snapshot extent overflow")?;
    ensure!(
        memory.regions().iter().any(|region| region.readable
            && region.guest_address <= address
            && end <= region.guest_address + region.virtual_bytes),
        "snapshot outside readable logical owner"
    );
    let mut result = vec![0_u8; bytes];
    unsafe {
        std::ptr::copy_nonoverlapping(address as usize as *const u8, result.as_mut_ptr(), bytes);
    }
    Ok(result)
}

#[test]
#[cfg(target_arch = "x86_64")]
#[ignore = "requires immutable original32 oracle artifacts and an explicitly selected fresh output directory"]
fn checked_owned_entry_matches_original_width4_states_and_ram() -> Result<()> {
    let fixture = PathBuf::from(
        std::env::var_os("STELA_EXCLUSIVE_ORIGINAL_DIRECTORY")
            .context("original fixture directory required")?,
    );
    let output = PathBuf::from(
        std::env::var_os("STELA_EXCLUSIVE_ENTRY_OUTPUT")
            .context("fresh output directory required")?,
    );
    ensure!(
        !output.exists(),
        "preserve existing original/native proof output"
    );
    std::fs::create_dir_all(&output)?;
    let mut bindings = BTreeMap::new();
    let projection_bytes = read_bound(
        &fixture.join("state-projection-1.json"),
        PROJECTION_SHA256,
        &mut bindings,
    )?;
    let projection: Projection = serde_json::from_slice(&projection_bytes)?;
    read_bound(
        &fixture.join("independent-saved-review-1.json"),
        ORIGINAL_AUDIT_SHA256,
        &mut bindings,
    )?;
    let initial_states = read_bound(
        &fixture.join("native-initial-states.bin"),
        INITIAL_STATES_SHA256,
        &mut bindings,
    )?;
    let original_states = read_bound(
        &fixture.join("original-post-states.bin"),
        ORIGINAL_STATES_SHA256,
        &mut bindings,
    )?;
    let capture = fixture.join(CAPTURE_ID);
    let original_results = read_bound(
        &capture.join("results.bin"),
        ORIGINAL_RESULTS_SHA256,
        &mut bindings,
    )?;
    let initial_ram = read_bound(
        &capture.join("memory.bin"),
        INITIAL_RAM_SHA256,
        &mut bindings,
    )?;
    let plan: MemoryPlan = serde_json::from_slice(&read_bound(
        &capture.join("memory-plan.json"),
        MEMORY_PLAN_SHA256,
        &mut bindings,
    )?)?;
    ensure!(
        projection.cases == ORIGINAL_CASES
            && projection.rows.len() == ORIGINAL_CASES
            && projection.stride == STATE_BYTES
    );
    ensure!(
        initial_states.len() == ORIGINAL_CASES * STATE_BYTES
            && original_states.len() == initial_states.len()
    );
    ensure!(plan.ram_bytes == RAM_BYTES && initial_ram.len() == RAM_BYTES);
    let source_normal_wb_facts = source_wb_facts(&original_results, &plan)?;
    let mmfr0 = read_u64(&original_results, WB_MMFR0_OFFSET);
    let sctlr = read_u64(&original_results, RESULTS_SCTLR_OFFSET);
    let tcr = read_u64(&original_results, RESULTS_TCR_OFFSET);
    let mmfr2 = read_u64(&original_results, RESULTS_MMFR2_OFFSET);
    let address_bits = u64::BITS - (tcr & TCR_T0SZ_MASK) as u32;
    let address_bits = u8::try_from(address_bits)?;
    let mut records = Vec::with_capacity(ORIGINAL_CASES);
    let mut native_states = Vec::with_capacity(ORIGINAL_CASES * STATE_BYTES);
    let mut native_ram = Vec::with_capacity(ORIGINAL_CASES * RAM_BYTES);
    for row in projection.rows {
        ensure!(row.case == records.len());
        let initial = state_from_bytes(
            &initial_states[row.initial_state_offset..row.initial_state_offset + STATE_BYTES],
        )?;
        let expected =
            &original_states[row.original_state_offset..row.original_state_offset + STATE_BYTES];
        let expected_ram = &original_results[row.raw_ram_offset..row.raw_ram_offset + RAM_BYTES];
        let source_pc = GuestAddress(row.source_pc);
        let mut source: Vec<u8> = row
            .words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        source.extend(RET_X30.to_le_bytes());
        ensure!(source.len() as u64 == INSTRUCTION_BYTES * (row.words.len() as u64 + 1));
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            output.join("cache"),
            BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentDisabled),
        );
        let generation = runtime.register_code(source_pc, source.clone())?;
        let prepared = runtime.prepare(source_pc)?;
        ensure!(
            prepared.analysis.source_bytes == source.len(),
            "not the complete original sequence plus RET"
        );
        let required = prepared
            .prepared
            .manifest
            .memory_requirements
            .context("canonical checked metadata absent")?;
        ensure!(required.required_flags & flags::EXCLUSIVE != 0);
        let native_bytes = std::fs::read(prepared.prepared.directory.join("native.bin"))?;
        for index in 0..=row.words.len() {
            let pc = GuestAddress(row.source_pc + index as u64 * INSTRUCTION_BYTES);
            ensure!(
                prepared
                    .prepared
                    .manifest
                    .source_map
                    .iter()
                    .any(|(address, offset)| *address == pc && *offset < native_bytes.len()),
                "selected body source map misses original word/RET"
            );
        }
        let mut owned = OwnedMemory::map(vec![MemoryRegionSpec {
            guest_address: plan.ram_address,
            virtual_bytes: RAM_BYTES as u64,
            initial_bytes: initial_ram.clone(),
            readable: true,
            writable: true,
            executable: false,
        }])?;
        let coherence = MemorySystem::new(ERG_BYTES, MONITOR_STRIPES)
            .map_err(|error| anyhow::anyhow!("memory system: {error:?}"))?;
        // SAFETY: one retained exact-address anonymous owner, no aliases/writers,
        // private input/output/source/State, fixed current Normal-WB host rights.
        let domain = unsafe {
            owned.bind_shared_memory(
                SharedMemoryConfig {
                    address_space: ADDRESS_SPACE,
                    system: coherence,
                    target: runtime.target_cpu(),
                    attributes: MappingAttributes {
                        tagged: false,
                        shareable: true,
                    },
                },
                &mut [],
            )
        }?;
        let mut thread = domain.thread(MemoryControls::new(
            LowerAddressProfile::new(address_bits, false)
                .map_err(|error| anyhow::anyhow!("lower address: {error:?}"))?,
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ));
        let events = EventDomain::new();
        let endpoint = events
            .register(false, None)
            .map_err(|error| anyhow::anyhow!("event endpoint: {error:?}"))?;
        thread
            .bind_events(&endpoint.producer())
            .map_err(|error| anyhow::anyhow!("event binding: {error:?}"))?;
        let spe = BaseSpeAbsence::from_id_aa64dfr0_el1(NATIVE_ID_AA64DFR0_EL1)
            .map_err(|error| anyhow::anyhow!("SPE fact: {error:?}"))?;
        let features = ProcessMemoryFeatures::from_id_registers(
            mmfr0,
            mmfr2,
            NATIVE_ID_AA64ISAR3_EL1,
            NATIVE_ID_AA64PFR1_EL1,
            spe,
        )
        .map_err(|error| anyhow::anyhow!("native features: {error:?}"))?;
        // SAFETY: the saved C1 facts above qualify the entire retained RAM range
        // as NormalWB, RW, untagged and shareable with matching identity offsets.
        // This fresh software component declares only this bounded RAM mapping;
        // it does not reproduce the oracle's complete address space. Its domain
        // and source-resolution contract remain immutable for the witness life.
        let source_domain =
            unsafe { SourceNormalWbDomain::from_source_resolved(std::sync::Arc::clone(&domain)) }
                .unwrap();
        let controls =
            FixedProcessMemoryControls::new(features, sctlr, tcr, address_bits, source_domain)
                .map_err(|error| anyhow::anyhow!("fixed controls: {error:?}"))?;
        let mut backend = OriginalBackend {
            controls,
            thread,
            endpoint,
            source_pc,
            generation,
            source: source.clone(),
            validations: 0,
            memory_entries: 0,
            exception_attempts: 0,
        };
        let mut system = SystemState::new(
            PSTATE_EL0T | PSTATE_DAIF_MASKED,
            0,
            El1Registers::new(0, 0, 0, 0, 0),
        )
        .map_err(|error| anyhow::anyhow!("SystemState: {error:?}"))?;
        let before_system = system.clone();
        let mut state = ThreadState {
            registers: initial,
            pc: source_pc,
        };
        let original_x30 = state.registers.x[30];
        let mut context = ExecutionContext::default();
        let _caller_restore =
            crate::execution::floating_environment::HostFloatingEnvironment::capture();
        let expected_caller_mxcsr = if row.case % 2 == 0 {
            CALLER_MXCSR_A
        } else {
            CALLER_MXCSR_B
        };
        // SAFETY: named values contain only legal rounding controls, masked
        // exceptions and sticky status bits, with no reserved bits or DAZ use.
        unsafe { set_caller_mxcsr(expected_caller_mxcsr) };
        let outcome_result = {
            let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
            // SAFETY: canonical checked source/metadata/profile/cache/ASID path,
            // actual fixed CPU authority, same real PE/thread/storage; no other
            // access, Rust RAM reference, protection change, unwind or open scope.
            unsafe {
                runtime.run_with_memory(
                    &mut state,
                    Some(GuestAddress(original_x30)),
                    1,
                    &mut execution,
                    &mut context,
                )
            }
        };
        let observed_state = state_bytes(&state.registers);
        let observed_caller_mxcsr = caller_mxcsr();
        ensure!(
            observed_caller_mxcsr == expected_caller_mxcsr,
            "full caller MXCSR changed across preparation/native/cleanup"
        );
        // SAFETY: native/token scopes returned even if the owned entry declined.
        let observed_ram = unsafe { observe_quiescent_ram(&owned, plan.ram_address, RAM_BYTES) }?;
        let outcome = match outcome_result {
            Ok(outcome) => outcome,
            Err(error) => {
                std::fs::write(
                    output.join(format!("failure-case{}-state.bin", row.case)),
                    &observed_state,
                )?;
                std::fs::write(
                    output.join(format!("failure-case{}-ram.bin", row.case)),
                    &observed_ram,
                )?;
                std::fs::write(
                    output.join(format!("failure-case{}.json", row.case)),
                    serde_json::to_vec_pretty(
                        &json!({"case": row.case, "error": format!("{error:#}"), "post_pc": state.pc.0, "prepared": prepared}),
                    )?,
                )?;
                return Err(error);
            }
        };
        let policy_restored = backend.thread.validate_execution(flags::EXCLUSIVE).is_err();
        let context_restored = context.has_supported_header()
            && context.memory.is_null()
            && context.scalable.is_null()
            && context.system.is_null();
        let matches = outcome.blocks_executed == 1
            && state.pc == GuestAddress(original_x30)
            && backend.memory_entries == 1
            && backend.validations >= 2
            && backend.exception_attempts == 0
            && system == before_system
            && observed_state == expected
            && observed_ram == expected_ram
            && policy_restored
            && context_restored;
        if !matches {
            std::fs::write(
                output.join(format!("failure-case{}-state.bin", row.case)),
                &observed_state,
            )?;
            std::fs::write(
                output.join(format!("failure-case{}-ram.bin", row.case)),
                &observed_ram,
            )?;
            std::fs::write(
                output.join(format!("failure-case{}.json", row.case)),
                serde_json::to_vec_pretty(
                    &json!({"case": row.case, "outcome": outcome, "post_pc": state.pc.0, "prepared": prepared, "policy_restored": policy_restored, "context_restored": context_restored, "selected_native_sha256": sha256(&native_bytes)}),
                )?,
            )?;
        }
        ensure!(
            outcome.blocks_executed == 1,
            "case{} did not execute exactly one owned block: {:?}",
            row.case,
            outcome
        );
        ensure!(
            state.pc == GuestAddress(original_x30),
            "case{} RET did not preserve original target",
            row.case
        );
        ensure!(
            backend.memory_entries == 1
                && backend.validations >= 2
                && backend.exception_attempts == 0
        );
        ensure!(
            system == before_system,
            "valid source changed architectural SystemState"
        );
        ensure!(
            observed_state == expected,
            "case{} full original State differs",
            row.case
        );
        ensure!(
            observed_ram == expected_ram,
            "case{} full original RAM differs",
            row.case
        );
        ensure!(
            policy_restored,
            "checked CPU category authorization escaped its entry loan"
        );
        ensure!(
            context_restored,
            "checked native view escaped its scoped context loan"
        );
        native_states.extend(&observed_state);
        native_ram.extend(&observed_ram);
        records.push(json!({"case": row.case, "words": row.words, "source_pc": source_pc.0, "source_sha256": sha256(&source), "generation": generation, "prepared": prepared, "regions": owned.regions(), "regions_sha256": sha256(&serde_json::to_vec(owned.regions())?), "native_state_sha256": sha256(&observed_state), "native_ram_sha256": sha256(&observed_ram), "original_status": row.status, "post_ret_pc": state.pc.0, "outcome": outcome, "validations": backend.validations, "actual_memory_entries": backend.memory_entries, "policy_restored": policy_restored, "context_restored": context_restored, "expected_caller_mxcsr": expected_caller_mxcsr, "observed_caller_mxcsr": observed_caller_mxcsr, "selected_native_sha256": sha256(&native_bytes)}));
    }
    std::fs::write(
        output.join("compiler-source-material.txt"),
        SOURCE_FINGERPRINT_MATERIAL,
    )?;
    std::fs::write(output.join("native-states.bin"), &native_states)?;
    std::fs::write(output.join("native-ram.bin"), &native_ram)?;
    let before_after: BTreeMap<_, _> = bindings
        .keys()
        .map(|path| Ok((path.clone(), sha256(&std::fs::read(path)?))))
        .collect::<Result<_>>()?;
    ensure!(
        bindings == before_after,
        "original fixture changed during replay"
    );
    let receipt = json!({"kind": "actual_owned_checked_entry_original_width4_replay", "passed": true, "cases": ORIGINAL_CASES, "state_bytes": STATE_BYTES, "ram_bytes": RAM_BYTES, "native_states_sha256": sha256(&native_states), "native_ram_sha256": sha256(&native_ram), "fixture_bindings": bindings, "source_normal_wb_facts": source_normal_wb_facts, "native_features": {"ID_AA64MMFR0_EL1": mmfr0, "ID_AA64MMFR2_EL1": mmfr2, "ID_AA64ISAR3_EL1": NATIVE_ID_AA64ISAR3_EL1, "ID_AA64PFR1_EL1": NATIVE_ID_AA64PFR1_EL1, "ID_AA64DFR0_EL1": NATIVE_ID_AA64DFR0_EL1}, "controls": {"sctlr": sctlr, "tcr": tcr}, "rows": records, "limits": ["Original observations stop at SVC before RET; native harness adds RET using unchanged original X30 and records the subsequent PC/stop independently", "Native bounded fresh machine explicitly declares MTE/CPA/SPE absent; this is not equality with every QEMU-max feature/System register", "Logical8192RAM snapshot is a private sole-owner quiescent diagnostic read after native/token return, not an architectural memory operation", "Natural scalar4/GPR9 sequences only; no SP/unaligned/fault/pair/contention/full25/admission or performance credit"]});
    std::fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("actual_owned_original_width4_cases={ORIGINAL_CASES}");
    Ok(())
}
