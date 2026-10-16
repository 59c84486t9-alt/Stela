//! Native block dispatch.
//!
//! Guest code is fetched from registered regions and translated a block at a
//! time; data accesses use direct RAM. Replacing code invalidates the dependent
//! native blocks before returning.
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};
pub(crate) mod retirement;
pub use retirement::checked::software_el1::{
    InitializedRamRegion, OwnedRamExtent, PhysicalRamRange, SoftwareEl1Config,
    SoftwareEl1InitialRam, SoftwareEl1Machine, SoftwareEl1Profile, SoftwareEl1Report,
    SoftwareEl1Request, SourceRamDeclaration, SourceRamPermissions, ZeroedRamExtent,
};

pub use retirement::checked::software_privileged::{
    DeclaredDebugExtendedHaltSyndrome, DeclaredDebugExternalControls, DeclaredDebugInitialization,
    DeclaredHigherElInitialization, DeclaredPrivilegedCode, DeclaredPrivilegedConfig,
    DeclaredPrivilegedReceipt, DeclaredPrivilegedReport, DeclaredPrivilegedRequest,
    DeclaredPrivilegedScalable, TrapSmcWithoutEl3, run_declared_privileged,
};

mod aot;
pub(crate) mod scalable;
use aot::ArtifactPreparation;

#[cfg(feature = "std")]
use crate::prepare_runtime_block_for_target;
use crate::{Prepared, clock, execution::platform, floating, memory, pauth, system, thread};
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use anyhow::{Context, Result, ensure};
use core::marker::PhantomData;
use serde::Serialize;
#[cfg(feature = "std")]
use std::io::Read;
#[cfg(feature = "std")]
use std::path::PathBuf;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{
        BlockAnalysis, BlockExit, BlockProfile, ClockInstruction, ClockOperation, DynamicEdge,
        ExitKind, MAX_BLOCK_INSTRUCTIONS, PointerAuthentication, PointerAuthenticationKey,
        PointerAuthenticationModifier, PointerAuthenticationOperation, SynchronousTrap,
        SystemInstruction, ThreadRegisterInstruction, analyze_with_profile,
        decode_clock_instruction, decode_pointer_authentication, decode_system_instruction,
        decode_thread_register_instruction, decode_trap,
    },
};
use stela_core::sha256;

mod checked_memory;
mod publication;
pub use publication::CodePublicationScope;

#[cfg(feature = "std")]
const MAX_NATIVE_BYTES: usize = 64 * 1024 * 1024;
const INSTRUCTION_BYTES: usize = 4;
const ZERO_REGISTER_INDEX: u8 = 31;
const REGISTER_COUNT: u8 = ZERO_REGISTER_INDEX + 1;

#[derive(Debug, Clone)]
pub struct ThreadState {
    pub registers: GuestState,
    pub pc: GuestAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
    Halted {
        instruction_pc: GuestAddress,
    },
    StopAddress,
    BudgetExhausted,
    UnmappedTarget,
    UnalignedTarget,
    TruncatedInstruction,
    NoncanonicalInstructionTarget {
        address: GuestAddress,
    },
    Unsupported {
        detail: String,
    },
    FloatingPointUnsupported {
        instruction_pc: GuestAddress,
        fpcr: u32,
        enabled_exceptions: u32,
    },
    SynchronousTrap {
        trap: SynchronousTrap,
    },
    PointerAuthenticationRequired {
        instruction: PointerAuthentication,
    },
    PointerAuthenticationUnsupported {
        instruction: PointerAuthentication,
        detail: String,
    },
    PointerAuthenticationKeyUnavailable {
        instruction: PointerAuthentication,
        key: PointerAuthenticationKey,
    },
    PointerAuthenticationGenericKeyUnavailable {
        instruction: PointerAuthentication,
    },
    /// FPAC/FPACCOMBINE raised an authentication failure before committing
    /// destinations or the link register. Exception delivery belongs to the CPU owner.
    PointerAuthenticationFailure {
        instruction: PointerAuthentication,
        code: u8,
    },
    PointerAuthenticationLoadUndefined {
        instruction: PointerAuthentication,
    },
    PointerAuthenticationStackAlignment {
        instruction: PointerAuthentication,
        stack_pointer: u64,
    },
    PointerAuthenticationMemoryRequired {
        instruction: PointerAuthentication,
    },
    PointerAuthenticationMemoryFault {
        instruction: PointerAuthentication,
        fault: memory::domain::MemoryFault,
    },
    /// A nonfaulting PAuth check produced an invalid return target. No target instruction executed;
    /// guest instruction-fetch exception delivery remains the caller's work.
    PointerAuthenticationPoisonedReturn {
        instruction: PointerAuthentication,
        poisoned_target: GuestAddress,
    },
    /// A nonfaulting PAuth check produced an invalid branch/call target before fetch.
    PointerAuthenticationPoisonedBranch {
        instruction: PointerAuthentication,
        poisoned_target: GuestAddress,
    },
    ThreadRegisterRequired {
        instruction: ThreadRegisterInstruction,
    },
    SystemContextRequired {
        instruction_pc: GuestAddress,
    },
    SystemEntryFailure {
        instruction_pc: GuestAddress,
        word: u32,
        failure: system::execution::Failure,
    },
    MemoryEntryDeclined {
        instruction_pc: GuestAddress,
        status: u32,
    },
    MemoryFault {
        instruction_pc: GuestAddress,
        address: GuestAddress,
        status: u32,
        completed_bytes: u64,
    },
    MemoryFinalizationFailed {
        instruction_pc: GuestAddress,
        status: u32,
        native_executed: bool,
        original_fault: Option<MemoryFaultObservation>,
        completed_bytes: u64,
        observed_exit: Option<(u64, u64)>,
        retry_safe: bool,
    },
    SystemFailure {
        instruction: SystemInstruction,
        failure: system::execution::Failure,
    },
    ClockRequired {
        instruction: ClockInstruction,
    },
    ClockUnavailable {
        instruction: ClockInstruction,
        detail: String,
    },
}

/// Copied host callback outcome; this does not invent an ARM syndrome or delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryFaultObservation {
    pub status: u32,
    pub address: GuestAddress,
    pub instruction_pc: GuestAddress,
    pub completed_bytes: u64,
}
impl From<checked_memory::MemoryFault> for MemoryFaultObservation {
    fn from(fault: checked_memory::MemoryFault) -> Self {
        Self {
            status: fault.status as u32,
            address: fault.address,
            instruction_pc: fault.pc,
            completed_bytes: fault.completed_bytes,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PointerAuthenticationEvent {
    pub instruction: PointerAuthentication,
    pub next_pc: GuestAddress,
    /// Signing has no authentication result; AUT/RET report the actual check.
    pub authenticated: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ClockEvent {
    pub instruction: ClockInstruction,
    pub next_pc: GuestAddress,
    /// ISB does not consume a clock sample. MRS XZR still reads/publishes one.
    pub counter: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ThreadRegisterEvent {
    pub instruction: ThreadRegisterInstruction,
    pub next_pc: GuestAddress,
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct RunOutcome {
    pub reason: StopReason,
    /// Completed original blocks, including resident internal edges.
    pub blocks_executed: usize,
    pub compiled_blocks: usize,
    pub disk_cache_hits: usize,
    pub memory_cache_hits: usize,
    pub last_exit: Option<(u64, u64)>,
    /// Successful numerical slowpath completions; no per-instruction event allocation.
    pub floating_point_helpers: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pointer_authentication_events: Vec<PointerAuthenticationEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clock_events: Vec<ClockEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub thread_register_events: Vec<ThreadRegisterEvent>,
}

mod translation;
pub(crate) use translation::{
    ControlCodeScope, InstalledEl1SourceScope, InstalledM0SourceScope, InstalledWalkedSource,
};
pub(in crate::blocks) use translation::{
    InstalledEl1Owner, InstalledEl1Sources, InstalledM0Owner, InstalledM0Sources,
};

#[derive(Debug)]
struct CodeRegion {
    source: Box<[u8]>,
    physical_binding: Option<translation::PhysicalCodeBinding>,
    end: u64,
    generation: u64,
}

#[derive(Debug)]
struct LoadedBlock {
    profile: BlockProfile,
    region_base: u64,
    generation: u64,
    source_bytes: usize,
    prepared: crate::artifact::LoadedArtifact,
    mapping: platform::Mapping,
    /// Checked-retirement plan facts, derived on first checked dispatch.
    checked: core::cell::OnceCell<retirement::checked::CheckedFacts>,
}

/// Services borrowed for one serialized run; absent owners remain explicit stops.
struct AuthenticatedMemory<'a> {
    reader: &'a mut dyn memory::domain::MemoryReader,
    controls: pauth::memory::Controls,
}

struct PauthExecution<'a> {
    context: &'a pauth::Context,
    memory: Option<AuthenticatedMemory<'a>>,
}

impl<'a> PauthExecution<'a> {
    fn keys_only(context: &'a pauth::Context) -> Self {
        Self {
            context,
            memory: None,
        }
    }
}

struct RuntimeServices<'a> {
    pointer_authentication: Option<PauthExecution<'a>>,
    clock: Option<&'a mut clock::Context>,
    thread: Option<&'a thread::Context>,
    system: Option<&'a mut dyn system::execution::Dispatcher>,
    memory_context: Option<&'a mut stela_compiler::context::ExecutionContext>,
}

impl<'a> RuntimeServices<'a> {
    fn legacy(
        pointer_authentication: Option<&'a pauth::Context>,
        clock: Option<&'a mut clock::Context>,
        thread: Option<&'a thread::Context>,
    ) -> Self {
        Self {
            pointer_authentication: pointer_authentication.map(PauthExecution::keys_only),
            clock,
            thread,
            system: None,
            memory_context: None,
        }
    }

    fn pauth_memory(
        context: &'a pauth::Context,
        reader: &'a mut dyn memory::domain::MemoryReader,
        controls: pauth::memory::Controls,
    ) -> Self {
        Self {
            pointer_authentication: Some(PauthExecution {
                context,
                memory: Some(AuthenticatedMemory { reader, controls }),
            }),
            clock: None,
            thread: None,
            system: None,
            memory_context: None,
        }
    }

    fn system(dispatcher: &'a mut dyn system::execution::Dispatcher) -> Self {
        Self {
            pointer_authentication: None,
            clock: None,
            thread: None,
            system: Some(dispatcher),
            memory_context: None,
        }
    }
    fn checked_memory(
        dispatcher: &'a mut dyn system::execution::Dispatcher,
        context: &'a mut stela_compiler::context::ExecutionContext,
    ) -> Self {
        Self {
            pointer_authentication: None,
            clock: None,
            thread: None,
            system: Some(dispatcher),
            memory_context: Some(context),
        }
    }
}

/// Source registration, resolution and execution are serialized through &mut.
/// No function pointer, mutable code slice or executable mapping escapes.
#[derive(Debug)]
pub struct BlockRuntime {
    /// Opaque membership in this original source/RX cache; no PE permission.
    identity: alloc::sync::Arc<()>,
    address_space: u64,
    profile: BlockProfile,
    target: stela_compiler::TargetCpu,
    preparation: ArtifactPreparation,
    next_generation: u64,
    regions: BTreeMap<u64, CodeRegion>,
    loaded: BTreeMap<u64, LoadedBlock>,
    _serialized: PhantomData<Rc<()>>,
}

/// Persistent preparation artifact shared by ahead-of-time discovery and JIT.
/// Preparing it performs no native mapping, invocation or guest memory access.
#[derive(Debug, Serialize)]
pub struct PreparedDiscoveryBlock {
    #[serde(skip)]
    artifact_profile: BlockProfile,
    #[cfg(not(feature = "std"))]
    #[serde(skip)]
    native: Vec<u8>,
    pub entry: GuestAddress,
    pub region_base: GuestAddress,
    pub generation: u64,
    pub analysis: BlockAnalysis,
    pub prepared: Prepared,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiscoveryProblem {
    UnmappedTarget,
    UnalignedTarget,
    TruncatedInstruction,
    Unsupported {
        failure_pc: GuestAddress,
        detail: String,
    },
}
#[derive(Debug, Serialize)]
pub struct DiscoveryIssue {
    pub entry: GuestAddress,
    pub problem: DiscoveryProblem,
}
#[derive(Debug, Serialize)]
pub struct DeferredDynamicEdge {
    pub entry: GuestAddress,
    pub instruction_pc: GuestAddress,
    pub edge: DynamicEdge,
}
#[derive(Debug, Serialize)]
pub struct DiscoveryReport {
    pub address_space: u64,
    pub roots: Vec<GuestAddress>,
    pub budget: usize,
    pub attempted_entries: usize,
    pub blocks: Vec<PreparedDiscoveryBlock>,
    pub issues: Vec<DiscoveryIssue>,
    pub deferred_dynamic_edges: Vec<DeferredDynamicEdge>,
    pub pending_entries: Vec<GuestAddress>,
    pub compiled_blocks: usize,
    pub disk_cache_hits: usize,
    pub static_worklist_exhausted: bool,
    pub dynamic_targets_unresolved: bool,
    pub native_pages_loaded: bool,
    pub native_executed: bool,
    pub complete_code_discovered: bool,
}

impl BlockRuntime {
    #[cfg(feature = "std")]
    pub fn new(address_space: u64, cache_root: PathBuf) -> Self {
        Self::new_with_profile(address_space, cache_root, BlockProfile::Ordinary)
    }

    /// Explicit helper profile is part of every persistent translation identity.
    /// Preparing AOT needs no keys; execution receives a separately bound context.
    #[cfg(feature = "std")]
    pub fn new_with_profile(
        address_space: u64,
        cache_root: PathBuf,
        profile: BlockProfile,
    ) -> Self {
        Self::new_for_target(
            address_space,
            cache_root,
            profile,
            stela_compiler::TargetCpu::detect(),
        )
    }
    #[cfg(feature = "std")]
    pub fn new_for_target(
        address_space: u64,
        cache_root: PathBuf,
        profile: BlockProfile,
        target: stela_compiler::TargetCpu,
    ) -> Self {
        Self::with_preparation(
            address_space,
            profile,
            target,
            ArtifactPreparation::HostedCache(cache_root),
        )
    }

    pub fn target_cpu(&self) -> stela_compiler::TargetCpu {
        self.target
    }

    pub fn address_space(&self) -> u64 {
        self.address_space
    }

    pub fn profile(&self) -> BlockProfile {
        self.profile
    }

    /// A permission service must not bypass immutable-source visibility or
    /// invalidation by presenting registered code as an ordinary data mapping.
    pub fn source_overlaps(&self, address: u64, bytes: u64) -> bool {
        let Some(end) = address.checked_add(bytes) else {
            return true;
        };
        bytes != 0
            && self
                .regions
                .range(..end)
                .next_back()
                .is_some_and(|(&base, r)| base < end && r.end > address)
    }

    /// Own an immutable file/code snapshot. Partial trailing bytes are retained
    /// but can never be padded into a fetchable instruction. Same-base replacement
    /// always advances generation, even when the source bytes are identical.
    pub fn register_code(&mut self, base: GuestAddress, source: Vec<u8>) -> Result<u64> {
        ensure!(
            base.0.is_multiple_of(4) && source.len() >= 4,
            "code region must have an aligned base and at least one instruction"
        );
        let end = base
            .0
            .checked_add(u64::try_from(source.len())?)
            .context("code region overflow")?;
        for (&start, region) in &self.regions {
            ensure!(
                start == base.0 || end <= start || base.0 >= region.end,
                "code registration overlaps an existing region"
            );
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .context("code generation exhausted")?;
        self.loaded.retain(|_, block| block.region_base != base.0);
        self.regions.insert(
            base.0,
            CodeRegion {
                source: source.into_boxed_slice(),
                physical_binding: None,
                end,
                generation,
            },
        );
        self.next_generation = generation;
        Ok(generation)
    }

    pub fn unregister_code(&mut self, base: GuestAddress) -> bool {
        let removed = self.regions.remove(&base.0).is_some();
        if removed {
            self.loaded.retain(|_, block| block.region_base != base.0);
        }
        removed
    }

    fn region(&self, pc: GuestAddress) -> Option<(u64, &CodeRegion)> {
        self.regions
            .range(..=pc.0)
            .next_back()
            .filter(|(_, region)| pc.0 < region.end)
            .map(|(&base, region)| (base, region))
    }

    /// Prepare one known entry into the persistent AOT/JIT cache, without RX
    /// loading or execution. Source bytes/edges share the compiler's parser.
    #[cfg(feature = "std")]
    pub fn prepare(&mut self, pc: GuestAddress) -> Result<PreparedDiscoveryBlock> {
        ensure!(pc.0.is_multiple_of(4), "unaligned preparation entry");
        let cache_root = self.preparation.cache_root(pc)?;
        let (base, region) = self.region(pc).context("unmapped preparation entry")?;
        ensure!(region.end - pc.0 >= 4, "truncated preparation instruction");
        let offset = usize::try_from(pc.0 - base)?;
        let available = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS) * 4;
        let generation = region.generation;
        let window = &region.source[offset..offset + available];
        let analysis = analyze_with_profile(window, pc, self.profile)?;
        let (prepared, artifact_profile) =
            prepare_runtime_block_for_target(window, pc, cache_root, self.profile, self.target)?;
        ensure!(
            prepared.source_bytes == analysis.source_bytes,
            "prepared block analysis extent mismatch"
        );
        let manifest = &prepared.prepared.manifest;
        ensure!(
            manifest.identity.guest_base == pc.0
                && manifest.identity.abi == artifact_profile.abi()
                && manifest.identity.target_cpu == self.target.id()
                && manifest.identity.schema_version == 1,
            "unsupported block translation identity"
        );
        ensure!(
            manifest.identity.compiler_source_sha256 == crate::compiler_source_sha256()
                && manifest.identity.source_sha256 == sha256(&window[..prepared.source_bytes]),
            "block compiler/source identity mismatch"
        );
        validate_source_map(&prepared.prepared.manifest, pc, prepared.source_bytes)?;
        ensure!(
            manifest.native_bytes > 0 && manifest.native_bytes <= MAX_NATIVE_BYTES,
            "invalid block native size"
        );
        Ok(PreparedDiscoveryBlock {
            artifact_profile,
            entry: pc,
            region_base: GuestAddress(base),
            generation,
            analysis,
            prepared: prepared.prepared,
        })
    }

    #[cfg(not(feature = "std"))]
    pub fn prepare(&mut self, pc: GuestAddress) -> Result<PreparedDiscoveryBlock> {
        ensure!(pc.0.is_multiple_of(4), "unaligned preparation entry");
        ensure!(
            matches!(self.preparation, ArtifactPreparation::InMemory),
            "AOT block unavailable at {:#x}; runtime compilation is unsupported",
            pc.0
        );
        let (base, region) = self.region(pc).context("unmapped preparation entry")?;
        ensure!(region.end - pc.0 >= 4, "truncated preparation instruction");
        let offset = usize::try_from(pc.0 - base)?;
        let available = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS) * 4;
        let generation = region.generation;
        let window = &region.source[offset..offset + available];
        let analysis = analyze_with_profile(window, pc, self.profile)?;
        let plan =
            stela_compiler::block::CompilationPlan::new(window, pc, self.profile, self.target)?
                .with_resident_loops();
        let artifact_profile = plan.profile();
        let source_bytes = plan.source_bytes();
        ensure!(
            source_bytes == analysis.source_bytes,
            "prepared block analysis extent mismatch"
        );
        let identity = crate::block_plan_identity(window, pc, self.target, &plan)?;
        let key = sha256(&serde_json::to_vec(&identity)?);
        let requirements = plan.memory_requirements();
        let (manifest, native) =
            crate::artifact::prepare::generate(identity, requirements, || {
                plan.compile().map(|block| block.native)
            })?;
        validate_source_map(&manifest, pc, source_bytes)?;
        Ok(PreparedDiscoveryBlock {
            artifact_profile,
            native,
            entry: pc,
            region_base: GuestAddress(base),
            generation,
            analysis,
            prepared: Prepared {
                key,
                cache_hit: false,
                manifest,
            },
        })
    }

    /// Follow known static successors only. A call continuation is a candidate,
    /// not proof of a return; BR/BLR/RET targets remain explicitly unresolved.
    /// Budget counts all attempted entries, including declines/missing regions.
    /// No native instructions or guest data accesses execute during discovery.
    pub fn discover(&mut self, roots: &[GuestAddress], budget: usize) -> Result<DiscoveryReport> {
        ensure!(
            !roots.is_empty() && roots.len() <= 1024,
            "discovery requires 1..1024 roots"
        );
        ensure!(
            budget <= 4096,
            "discovery budget exceeds 4096 attempted entries"
        );
        let mut unique = BTreeSet::new();
        for root in roots {
            ensure!(
                root.0.is_multiple_of(4) && unique.insert(root.0),
                "discovery roots must be aligned and distinct"
            );
        }
        let roots = unique.iter().copied().map(GuestAddress).collect::<Vec<_>>();
        let mut queue = unique.iter().copied().collect::<VecDeque<_>>();
        let mut blocks = Vec::new();
        let mut issues = Vec::new();
        let mut dynamic = Vec::new();
        let mut attempted = 0;
        let mut compiled = 0;
        let mut hits = 0;
        while attempted < budget {
            let Some(raw) = queue.pop_front() else {
                break;
            };
            attempted += 1;
            let pc = GuestAddress(raw);
            let problem = if !raw.is_multiple_of(4) {
                Some(DiscoveryProblem::UnalignedTarget)
            } else if let Some((base, region)) = self.region(pc) {
                if region.end - raw < 4 {
                    Some(DiscoveryProblem::TruncatedInstruction)
                } else {
                    let offset = usize::try_from(raw - base)?;
                    let available =
                        ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS) * 4;
                    match analyze_with_profile(
                        &region.source[offset..offset + available],
                        pc,
                        self.profile,
                    ) {
                        Ok(_) => None,
                        Err(error) => Some(DiscoveryProblem::Unsupported {
                            failure_pc: error.pc,
                            detail: error.detail,
                        }),
                    }
                }
            } else {
                Some(DiscoveryProblem::UnmappedTarget)
            };
            if let Some(problem) = problem {
                issues.push(DiscoveryIssue { entry: pc, problem });
                continue;
            }
            let block = self.prepare(pc)?;
            if block.prepared.cache_hit {
                hits += 1;
            } else {
                compiled += 1;
            }
            for successor in &block.analysis.static_successors {
                if unique.insert(successor.target.0) {
                    queue.push_back(successor.target.0);
                }
            }
            if let Some(edge) = &block.analysis.dynamic_edge {
                dynamic.push(DeferredDynamicEdge {
                    entry: pc,
                    instruction_pc: block
                        .analysis
                        .terminator_pc
                        .context("dynamic edge lacks terminator")?,
                    edge: edge.clone(),
                });
            }
            blocks.push(block);
        }
        let static_worklist_exhausted = queue.is_empty() && issues.is_empty();
        let dynamic_targets_unresolved = !dynamic.is_empty();
        Ok(DiscoveryReport {
            address_space: self.address_space,
            roots,
            budget,
            attempted_entries: attempted,
            blocks,
            issues,
            deferred_dynamic_edges: dynamic,
            pending_entries: queue.into_iter().map(GuestAddress).collect(),
            compiled_blocks: compiled,
            disk_cache_hits: hits,
            static_worklist_exhausted,
            dynamic_targets_unresolved,
            native_pages_loaded: false,
            native_executed: false,
            complete_code_discovered: false,
        })
    }

    fn load(&mut self, pc: GuestAddress, outcome: &mut RunOutcome) -> Result<()> {
        let (base, region) = self.region(pc).context("instruction mapping disappeared")?;
        if let Some(block) = self.loaded.get(&pc.0) {
            ensure!(
                block.region_base == base && block.generation == region.generation,
                "stale native block generation"
            );
            outcome.memory_cache_hits += 1;
            return Ok(());
        }
        #[cfg(not(feature = "std"))]
        {
            let discovery = self.prepare(pc)?;
            let profile = discovery.artifact_profile;
            let generation = discovery.generation;
            let source_bytes = discovery.analysis.source_bytes;
            let native = discovery.native;
            let prepared =
                crate::artifact::LoadedArtifact::bind(discovery.prepared.manifest, &native)
                    .context("block native snapshot checksum mismatch")?;
            let block = LoadedBlock::from_artifact(
                self.target,
                profile,
                base,
                generation,
                source_bytes,
                prepared,
                &native,
            )?;
            self.loaded.insert(pc.0, block);
            outcome.compiled_blocks += 1;
        }
        #[cfg(feature = "std")]
        {
            let prepared = self.prepare(pc)?;
            let profile = prepared.artifact_profile;
            let generation = prepared.generation;
            let source_bytes = prepared.analysis.source_bytes;
            let prepared = prepared.prepared;
            let mut native = Vec::new();
            std::fs::File::open(prepared.directory.join("native.bin"))?
                .take((MAX_NATIVE_BYTES + 1) as u64)
                .read_to_end(&mut native)?;
            let loaded_artifact = crate::artifact::LoadedArtifact::bind(prepared.manifest, &native)
                .context("block native snapshot checksum mismatch")?;
            let block = LoadedBlock::from_artifact(
                self.target,
                profile,
                base,
                generation,
                source_bytes,
                loaded_artifact,
                &native,
            )?;
            if prepared.cache_hit {
                outcome.disk_cache_hits += 1;
            } else {
                outcome.compiled_blocks += 1;
            }
            self.loaded.insert(pc.0, block);
        }

        Ok(())
    }

    /// Execute native blocks until a caller-owned stop address, a dispatch
    /// boundary that cannot be satisfied, a synchronous trap, or the finite
    /// block budget is reached. A trap leaves PC at its instruction and reports
    /// the preferred exception-return PC separately; only the caller may resume.
    /// No host syscall, guest exception entry or architectural EL change occurs.
    /// Unsupported compilation is returned as a stop, not a guest exception.
    /// A zero budget executes no blocks. PC denotes the next guest instruction.
    ///
    /// # Safety
    /// Registered instructions and their generated code must be trusted. Every
    /// guest data access must satisfy the compiler's direct private-RAM profile:
    /// live bounds, appropriate permissions/alignment, untagged/authenticated
    /// pointers, identical native virtual addresses, exclusive writes and no
    /// alias of Rust references, state, native code, runtime metadata or host
    /// stack. Source snapshots are instruction-fetch storage, not guest data
    /// mappings. The caller excludes concurrent mutation and assumes unguarded
    /// instruction pages with GCS disabled; PAC/BTI/GCS exception behavior is not
    /// modeled. Native faults can terminate the host process. This is neither a
    /// signal sandbox nor a complete Apple process/exception implementation.
    pub unsafe fn run(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
    ) -> Result<RunOutcome> {
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(None, None, None),
            )
        }
    }

    /// Execute the explicit software PAuth profile with a process-owned key domain.
    /// Keys are borrowed, never emitted into artifacts or copied into guest RAM.
    ///
    /// # Safety
    /// Same direct-RAM and trusted-code requirements as [`Self::run`]. The caller
    /// must retain a coherent process key lifecycle; this does not provide Apple
    /// hardware key identity, TLS, shared-cache signing or exception delivery.
    pub unsafe fn run_with_pauth(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        context: &pauth::Context,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_pointer_authentication(),
            "PAuth execution requires the explicit software PAuth block profile"
        );
        ensure!(
            context.address_space() == self.address_space,
            "PAuth context belongs to another guest address space"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(Some(context), None, None),
            )
        }
    }

    /// Execute PAC helpers with the address-space owner's checked data reader.
    /// Authenticated loads retain tags through the reader's translation policy;
    /// their base and destination commit only after the complete eight-byte read.
    ///
    /// # Safety
    /// Ordinary native prefixes retain the trusted-code/direct-RAM contract of
    /// [`Self::run`]. The reader is the actual owner of this guest address space,
    /// and its mappings, policy and backing remain valid throughout this call.
    /// `controls` is the effective SP-alignment policy from that same CPU owner;
    /// no SA0/SA/exception-level policy is inferred from RAM or process keys.
    pub unsafe fn run_with_pauth_memory(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        context: &pauth::Context,
        reader: &mut dyn memory::domain::MemoryReader,
        controls: pauth::memory::Controls,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_pointer_authentication(),
            "PAuth execution requires the explicit software PAuth block profile"
        );
        ensure!(
            context.address_space() == self.address_space,
            "PAuth context belongs to another guest address space"
        );
        ensure!(
            reader.address_space() == Some(self.address_space),
            "memory reader belongs to another guest address space"
        );
        reader
            .validate_privilege(controls.privileged)
            .map_err(|status| {
                anyhow::anyhow!("LDRA memory privilege profile unavailable: {status:?}")
            })?;
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::pauth_memory(context, reader, controls),
            )
        }
    }

    /// Execute explicit PAC/clock helpers using caller-owned address-space services.
    /// The clock owns its read-only commpage and publishes only at helper boundaries.
    ///
    /// # Safety
    /// Same trusted-code/direct-RAM requirements as [`Self::run`]. No concurrent
    /// translated execution may access the clock page during publication. The
    /// profile models ISB with host instruction serialization for immutable guest
    /// code, not arbitrary privilege/context/cache-maintenance changes.
    pub unsafe fn run_with_clock(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        pauth: &pauth::Context,
        clock: &mut clock::Context,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_clock(),
            "clock execution requires the explicit software clock block profile"
        );
        ensure!(
            pauth.address_space() == self.address_space,
            "PAuth context belongs to another guest address space"
        );
        ensure!(
            clock.address_space() == self.address_space,
            "clock context belongs to another guest address space"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(Some(pauth), Some(clock), None),
            )
        }
    }

    /// Execute explicit thread-register helpers from the same context used by
    /// Darwin thread services. Cached code never embeds the current TSD value.
    /// Optional PAC/clock services retain their own profile/ownership checks.
    ///
    /// # Safety
    /// Same trusted-code/direct-RAM requirements as [`Self::run`]. The context
    /// must remain on its owning host thread; this does not alter host TLS.
    pub unsafe fn run_with_thread(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        thread: &thread::Context,
        pauth: Option<&pauth::Context>,
        clock: Option<&mut clock::Context>,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_thread_registers(),
            "thread-register execution requires the explicit thread block profile"
        );
        ensure!(
            thread.address_space() == self.address_space,
            "thread context belongs to another guest address space"
        );
        if let Some(pauth) = pauth {
            ensure!(
                self.profile.supports_pointer_authentication(),
                "PAuth execution requires the explicit software PAuth block profile"
            );
            ensure!(
                pauth.address_space() == self.address_space,
                "PAuth context belongs to another guest address space"
            );
        }
        if let Some(clock) = clock.as_ref() {
            ensure!(
                self.profile.supports_clock() && pauth.is_some(),
                "clock execution requires the explicit software clock profile and PAC context"
            );
            ensure!(
                clock.address_space() == self.address_space,
                "clock context belongs to another guest address space"
            );
        }
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(pauth, clock, Some(thread)),
            )
        }
    }

    /// Execute the restricted System service profile. Registered prefixes have
    /// no ordinary RAM effects; dedicated memory services use their actual
    /// shared domain. System failures retain their exact original PC and prefix.
    ///
    /// # Safety
    /// Same trusted-code and invocation exclusions as [`Self::run`]. The service
    /// backend owns its architectural effects and memory synchronization domain.
    pub unsafe fn run_with_system(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        dispatcher: &mut dyn system::execution::Dispatcher,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_system(),
            "System execution requires the explicit System block profile"
        );
        ensure!(
            dispatcher.address_space() == self.address_space,
            "System dispatcher belongs to another guest address space"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::system(dispatcher),
            )
        }
    }

    /// Execute only the source-derived checked GPR memory profile against the
    /// existing System authority and its same MemoryThread/address space.
    ///
    /// # Safety
    /// Same trusted-code exclusions as run; backend owns pinned disjoint coherent
    /// memory. Context views cannot escape synchronous native invocation.
    pub unsafe fn run_with_memory(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        dispatcher: &mut dyn system::execution::Dispatcher,
        context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<RunOutcome> {
        let _floating_environment =
            crate::execution::floating_environment::HostFloatingEnvironment::capture();
        ensure!(
            self.profile.checked_memory().is_some(),
            "checked memory execution requires its distinct ABI/profile"
        );
        ensure!(
            dispatcher.address_space() == self.address_space,
            "checked dispatcher address space mismatch"
        );
        ensure!(
            context.has_supported_header(),
            "unsupported checked context header"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::checked_memory(dispatcher, context),
            )
        }
    }

    unsafe fn run_inner(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        services: RuntimeServices<'_>,
    ) -> Result<RunOutcome> {
        ensure!(
            !matches!(
                self.profile,
                BlockProfile::El1DirectBranchV1 | BlockProfile::El1M0IntegerV1
            ),
            "EL1 direct branch requires its original canonical retained owner"
        );
        let RuntimeServices {
            pointer_authentication: mut pauth_execution,
            clock: mut clock_context,
            thread: thread_context,
            system: mut system_dispatcher,
            mut memory_context,
        } = services;
        platform::ensure_supported()?;
        ensure!(
            self.profile.checked_memory().is_none() || memory_context.is_some(),
            "checked artifact cannot execute through direct entry"
        );
        let mut outcome = RunOutcome {
            reason: StopReason::BudgetExhausted,
            blocks_executed: 0,
            compiled_blocks: 0,
            disk_cache_hits: 0,
            memory_cache_hits: 0,
            last_exit: None,
            floating_point_helpers: 0,
            pointer_authentication_events: Vec::new(),
            clock_events: Vec::new(),
            thread_register_events: Vec::new(),
        };
        loop {
            let pc = state.pc;
            // A zero budget requests no instruction fetch or execution.
            if self.profile.supports_pointer_authentication() && block_budget == 0 {
                break;
            }
            // Instruction TBI is disabled in the fixed VA47 software profile.
            // This also prevents a resumed poisoned RETAB target from becoming
            // executable through a registered snapshot or matching stop sentinel.
            let extension = pc.0 >> 47;
            if self.profile.supports_pointer_authentication()
                && extension != 0
                && extension != u64::MAX >> 47
            {
                outcome.reason = StopReason::NoncanonicalInstructionTarget { address: pc };
                break;
            }
            if stop_pc == Some(pc) {
                outcome.reason = StopReason::StopAddress;
                break;
            }
            if outcome.blocks_executed == block_budget {
                break;
            }
            if !pc.0.is_multiple_of(4) {
                outcome.reason = StopReason::UnalignedTarget;
                break;
            }
            let Some((base, region)) = self.region(pc) else {
                outcome.reason = StopReason::UnmappedTarget;
                break;
            };
            if region.end - pc.0 < 4 {
                outcome.reason = StopReason::TruncatedInstruction;
                break;
            }
            // Current PSTATE and CPU controls take precedence over decoding an
            // available word. This guard performs no architectural effect.
            let system_entry = if self.profile.supports_system()
                || self.profile.checked_memory().is_some()
            {
                let Some(dispatcher) = system_dispatcher.as_deref_mut() else {
                    outcome.reason = StopReason::SystemContextRequired { instruction_pc: pc };
                    break;
                };
                let word = validate_terminal_word(pc, pc, INSTRUCTION_BYTES, base, &region.source)?;
                let boundary = system::execution::EntryBoundary::new(
                    self.address_space,
                    region.generation,
                    pc,
                    GuestAddress(base),
                    region.source.len(),
                    word,
                );
                let offset = usize::try_from(pc.0 - base)?;
                let available = ((region.source.len() - offset) / INSTRUCTION_BYTES)
                    .min(MAX_BLOCK_INSTRUCTIONS)
                    * INSTRUCTION_BYTES;
                let source = &region.source[offset..offset + available];
                if let Err(failure) = dispatcher.validate_entry(&boundary, source, &state.registers)
                {
                    outcome.reason = StopReason::SystemEntryFailure {
                        instruction_pc: pc,
                        word,
                        failure,
                    };
                    break;
                }
                Some(boundary)
            } else {
                None
            };
            // Decode ahead of loading so an unsupported instruction is a typed
            // dispatch stop. Disk corruption and allocation errors remain errors.
            if !self.loaded.contains_key(&pc.0) {
                let offset = usize::try_from(pc.0 - base)?;
                let words = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS);
                if let Err(error) = stela_compiler::block::source_bytes_with_profile(
                    &region.source[offset..offset + words * 4],
                    pc,
                    self.profile,
                ) {
                    outcome.reason = StopReason::Unsupported {
                        detail: error.to_string(),
                    };
                    break;
                }
            }
            self.load(pc, &mut outcome)?;
            let block = self.loaded.get(&pc.0).context("loaded block disappeared")?;
            let (_, current) = self.region(pc).context("loaded block unmapped")?;
            ensure!(
                block.generation == current.generation && block.source_bytes > 0,
                "refusing stale block execution"
            );
            let mut completed_blocks = 1;
            let native_exit = if self.profile.checked_memory().is_some() {
                let requirements = block
                    .prepared
                    .manifest
                    .memory_requirements
                    .context("checked block lacks source-derived memory requirements")?;
                let boundary = system_entry
                    .as_ref()
                    .context("checked source boundary missing")?;
                let dispatcher = system_dispatcher
                    .as_deref_mut()
                    .context("checked CPU owner missing")?;
                let context = memory_context
                    .as_deref_mut()
                    .context("checked context missing")?;
                let offset = usize::try_from(pc.0 - block.region_base)?;
                let source = &current.source[offset..offset + block.source_bytes];
                let result = unsafe {
                    checked_memory::call(
                        dispatcher,
                        boundary,
                        source,
                        &block.prepared.manifest.source_map,
                        stela_compiler::block::ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
                        requirements,
                        &block.mapping,
                        &mut state.registers,
                        context,
                    )?
                };
                match result {
                    checked_memory::CheckedReturn::Returned(exit) => exit,
                    checked_memory::CheckedReturn::CpuDeclined(failure) => {
                        outcome.reason = StopReason::SystemEntryFailure {
                            instruction_pc: pc,
                            word: boundary.word(),
                            failure,
                        };
                        break;
                    }
                    checked_memory::CheckedReturn::EntryDeclined(status) => {
                        outcome.reason = StopReason::MemoryEntryDeclined {
                            instruction_pc: pc,
                            status: status as u32,
                        };
                        break;
                    }
                    checked_memory::CheckedReturn::FinalizationFailed {
                        status,
                        native_executed,
                        original_fault,
                        completed_bytes,
                        observed_exit,
                        ..
                    } => {
                        let instruction_pc = original_fault.map_or(pc, |fault| fault.pc);
                        state.pc = instruction_pc;
                        outcome.blocks_executed += usize::from(native_executed);
                        outcome.reason = StopReason::MemoryFinalizationFailed {
                            instruction_pc,
                            status: status as u32,
                            native_executed,
                            original_fault: original_fault.map(Into::into),
                            completed_bytes,
                            observed_exit,
                            retry_safe: false,
                        };
                        break;
                    }
                    failed @ checked_memory::CheckedReturn::InvocationFailed { .. } => {
                        anyhow::bail!("checked native invocation unresolved: {failed:?}");
                    }
                    checked_memory::CheckedReturn::MemoryFault(fault) => {
                        state.pc = fault.pc;
                        outcome.blocks_executed += 1;
                        outcome.reason = StopReason::MemoryFault {
                            instruction_pc: fault.pc,
                            address: fault.address,
                            status: fault.status as u32,
                            completed_bytes: fault.completed_bytes,
                        };
                        break;
                    }
                }
            } else if block.profile.supports_resident_loops() {
                let available = block_budget - outcome.blocks_executed;
                let mut budget = stela_compiler::block::loop_budget::LoopBudget::new(available);
                // SAFETY: the distinct immutable profile/ABI binds this source
                // and mapping to the same bank and invocation-local counter.
                let returned = unsafe {
                    block
                        .mapping
                        .call_budgeted_block(&mut state.registers, &mut budget)?
                };
                completed_blocks = budget
                    .consumed(available)
                    .filter(|&consumed| consumed != 0)
                    .context("invalid resident-block budget accounting")?;
                returned
            } else {
                unsafe { block.mapping.call_block(&mut state.registers)? }
            };
            let BlockExit { next_pc, kind } = native_exit;
            let exit_kind = ExitKind::try_from(kind)
                .map_err(|_| anyhow::anyhow!("invalid native block exit kind"))?;
            ensure!(
                exit_kind != ExitKind::ScalableNumerical,
                "context-block numerical exit requires owned scalable entry"
            );
            let trap = if exit_kind == ExitKind::Trap {
                Some(validate_trap_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let pointer_authentication = if exit_kind == ExitKind::PointerAuthentication {
                ensure!(
                    self.profile.supports_pointer_authentication(),
                    "ordinary block produced an unrequested PAuth helper exit"
                );
                Some(validate_pauth_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let clock_instruction = if exit_kind == ExitKind::Clock {
                ensure!(
                    self.profile.supports_clock(),
                    "block produced an unrequested clock helper exit"
                );
                Some(validate_clock_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let thread_register_instruction = if exit_kind == ExitKind::ThreadRegister {
                ensure!(
                    self.profile.supports_thread_registers(),
                    "block produced an unrequested thread-register helper exit"
                );
                Some(validate_thread_register_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let system_boundary = if exit_kind == ExitKind::System {
                ensure!(
                    self.profile.supports_system(),
                    "block produced an unrequested System helper exit"
                );
                let instruction = validate_system_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?;
                Some(system::execution::Boundary::new(
                    system_entry.context("System exit lacks validated entry")?,
                    block.source_bytes,
                    instruction,
                ))
            } else {
                None
            };
            let numerical = if exit_kind == ExitKind::FloatingPoint {
                Some(validate_numerical_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            state.pc = GuestAddress(next_pc);
            outcome.last_exit = Some((next_pc, kind));
            outcome.blocks_executed += completed_blocks;
            if let Some(boundary) = system_boundary {
                let instruction = boundary.instruction();
                let dispatcher = system_dispatcher
                    .as_deref_mut()
                    .context("System exit lacks validated dispatcher")?;
                let mut code = CodePublicationScope::new(&*self, &boundary);
                match dispatcher.complete_with_code_scope(boundary, &mut state.registers, &mut code)
                {
                    Ok(next) => state.pc = next,
                    Err(failure) => {
                        outcome.reason = StopReason::SystemFailure {
                            instruction,
                            failure,
                        };
                        break;
                    }
                }
            }
            if let Some((operand, continuation)) = numerical {
                if let Err(error) = floating::complete(&mut state.registers, &operand) {
                    outcome.reason = StopReason::FloatingPointUnsupported {
                        instruction_pc: state.pc,
                        fpcr: state.registers.fpcr,
                        enabled_exceptions: error.enabled_exceptions,
                    };
                    break;
                }
                state.pc = continuation;
                outcome.floating_point_helpers += 1;
            }
            if let Some(instruction) = thread_register_instruction {
                let Some(thread) = thread_context else {
                    outcome.reason = StopReason::ThreadRegisterRequired { instruction };
                    break;
                };
                let value = thread.thread_specific_data();
                // The immutable decoder guarantees 0..=31. XZR discards only
                // after ownership and the required context have been validated.
                if instruction.destination != ZERO_REGISTER_INDEX {
                    state.registers.x[usize::from(instruction.destination)] = value;
                }
                state.pc = instruction.next_pc;
                outcome.thread_register_events.push(ThreadRegisterEvent {
                    instruction,
                    next_pc: instruction.next_pc,
                    value,
                });
            }
            if let Some(instruction) = clock_instruction {
                let Some(clock) = clock_context.as_deref_mut() else {
                    outcome.reason = StopReason::ClockRequired { instruction };
                    break;
                };
                let counter = match complete_clock(clock, &instruction, &mut state.registers) {
                    Ok(counter) => counter,
                    Err(error) => {
                        outcome.reason = StopReason::ClockUnavailable {
                            instruction,
                            detail: error.to_string(),
                        };
                        break;
                    }
                };
                state.pc = instruction.next_pc;
                outcome.clock_events.push(ClockEvent {
                    instruction,
                    next_pc: instruction.next_pc,
                    counter,
                });
            }
            if let Some(instruction) = pointer_authentication {
                // The implementation's permitted UNDEF constraint precedes key
                // availability checks and cannot invoke data translation.
                if let PointerAuthenticationOperation::Load(load) = instruction.operation
                    && load.undefined_overlap()
                {
                    outcome.reason = StopReason::PointerAuthenticationLoadUndefined { instruction };
                    break;
                }
                let Some(execution) = pauth_execution.as_mut() else {
                    outcome.reason = StopReason::PointerAuthenticationRequired { instruction };
                    break;
                };
                let context = execution.context;
                if let Some(key) = instruction.operation.required_key()
                    && !context.has_key(runtime_pauth_key(key))
                {
                    outcome.reason =
                        StopReason::PointerAuthenticationKeyUnavailable { instruction, key };
                    break;
                }
                if matches!(
                    instruction.operation,
                    PointerAuthenticationOperation::GenericCode(_)
                ) && !context.has_generic_key()
                {
                    outcome.reason =
                        StopReason::PointerAuthenticationGenericKeyUnavailable { instruction };
                    break;
                }
                let result = complete_pauth_with_memory(
                    context,
                    &instruction,
                    &mut state.registers,
                    execution.memory.as_mut(),
                );
                let (next, authenticated) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        outcome.reason = match error.downcast_ref::<pauth::AuthenticationError>() {
                            Some(pauth::AuthenticationError::Failure { code }) => {
                                StopReason::PointerAuthenticationFailure {
                                    instruction,
                                    code: *code,
                                }
                            }
                            _ => match error.downcast_ref::<AuthenticatedLoadError>() {
                                Some(AuthenticatedLoadError::UndefinedOverlap) => {
                                    StopReason::PointerAuthenticationLoadUndefined { instruction }
                                }
                                Some(AuthenticatedLoadError::StackAlignment { stack_pointer }) => {
                                    StopReason::PointerAuthenticationStackAlignment {
                                        instruction,
                                        stack_pointer: *stack_pointer,
                                    }
                                }
                                Some(AuthenticatedLoadError::MemoryRequired) => {
                                    StopReason::PointerAuthenticationMemoryRequired { instruction }
                                }
                                Some(AuthenticatedLoadError::Read(fault)) => {
                                    StopReason::PointerAuthenticationMemoryFault {
                                        instruction,
                                        fault: *fault,
                                    }
                                }
                                None => StopReason::PointerAuthenticationUnsupported {
                                    instruction,
                                    detail: error.to_string(),
                                },
                            },
                        };
                        break;
                    }
                };
                state.pc = next;
                let poisoned_transfer =
                    instruction.operation.is_transfer() && authenticated == Some(false);
                outcome
                    .pointer_authentication_events
                    .push(PointerAuthenticationEvent {
                        instruction,
                        next_pc: next,
                        authenticated,
                    });
                if poisoned_transfer {
                    outcome.reason = if instruction.operation.is_return() {
                        StopReason::PointerAuthenticationPoisonedReturn {
                            instruction,
                            poisoned_target: next,
                        }
                    } else {
                        StopReason::PointerAuthenticationPoisonedBranch {
                            instruction,
                            poisoned_target: next,
                        }
                    };
                    break;
                }
            }
            if let Some(trap) = trap {
                // The already executed instruction takes precedence over a
                // coincident stop address or exhausted block budget. Do not
                // advance to its return PC or execute another source block.
                outcome.reason = StopReason::SynchronousTrap { trap };
                break;
            }
        }
        Ok(outcome)
    }

    /// Inspect source/native identity and reverse maps without exposing RX pointers.
    pub fn loaded_manifest(&self, pc: GuestAddress) -> Option<&crate::Manifest> {
        self.loaded.get(&pc.0).map(|block| &block.prepared.manifest)
    }
}

fn complete_clock(
    context: &mut clock::Context,
    instruction: &ClockInstruction,
    registers: &mut GuestState,
) -> Result<Option<u64>> {
    match instruction.operation {
        ClockOperation::ReadVirtualCounter { destination } => {
            ensure!(
                destination < REGISTER_COUNT,
                "invalid clock destination register"
            );
            // Sampling and complete commpage publication must succeed before
            // committing the destination. X31 discards the result, not the read.
            let counter = context.read_counter()?;
            if destination != ZERO_REGISTER_INDEX {
                registers.x[usize::from(destination)] = counter;
            }
            Ok(Some(counter))
        }
        ClockOperation::InstructionSynchronization => {
            serialize_instruction_execution()?;
            Ok(None)
        }
    }
}

fn serialize_instruction_execution() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::{Ordering, compiler_fence};
        compiler_fence(Ordering::SeqCst);
        // CPUID is available on the x86-64 baseline. Leaf0 is a genuine
        // serializing instruction; the intrinsic owns its host scratch outputs.
        let _ = core::arch::x86_64::__cpuid(0);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    anyhow::bail!("instruction synchronization requires the x86-64 runtime")
}

fn validate_clock_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<ClockInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_clock_instruction(exit, word)?
        .context("clock exit does not identify a reviewed instruction")
}

fn runtime_pauth_key(key: PointerAuthenticationKey) -> pauth::Key {
    match key {
        PointerAuthenticationKey::Ia => pauth::Key::Ia,
        PointerAuthenticationKey::Ib => pauth::Key::Ib,
        PointerAuthenticationKey::Da => pauth::Key::Da,
        PointerAuthenticationKey::Db => pauth::Key::Db,
    }
}

fn pauth_modifier(registers: &GuestState, modifier: PointerAuthenticationModifier) -> Result<u64> {
    match modifier {
        PointerAuthenticationModifier::StackPointer => Ok(registers.sp),
        PointerAuthenticationModifier::Zero => Ok(0),
        PointerAuthenticationModifier::Register(index) => {
            ensure!(index < ZERO_REGISTER_INDEX, "invalid PAC modifier register");
            Ok(registers.x[usize::from(index)])
        }
    }
}

#[derive(Debug)]
enum AuthenticatedLoadError {
    UndefinedOverlap,
    StackAlignment { stack_pointer: u64 },
    MemoryRequired,
    Read(memory::domain::MemoryFault),
}

impl core::fmt::Display for AuthenticatedLoadError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "authenticated load failed: {self:?}")
    }
}

impl core::error::Error for AuthenticatedLoadError {}

#[cfg(test)]
fn complete_pauth(
    context: &pauth::Context,
    instruction: &PointerAuthentication,
    registers: &mut GuestState,
) -> Result<(GuestAddress, Option<bool>)> {
    complete_pauth_with_memory(context, instruction, registers, None)
}

fn complete_pauth_with_memory(
    context: &pauth::Context,
    instruction: &PointerAuthentication,
    registers: &mut GuestState,
    memory: Option<&mut AuthenticatedMemory<'_>>,
) -> Result<(GuestAddress, Option<bool>)> {
    use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
    const HINT_POINTER_REGISTER: usize = 17;
    const HINT_MODIFIER_REGISTER: usize = 16;
    match instruction.operation {
        PointerAuthenticationOperation::LinkRegister(_) => {
            anyhow::bail!("link-register authentication requires actual retained LR owners")
        }
        PointerAuthenticationOperation::Sign1716 { key } => {
            let value = context.sign(
                runtime_pauth_key(key),
                registers.x[HINT_POINTER_REGISTER],
                registers.x[HINT_MODIFIER_REGISTER],
            )?;
            registers.x[HINT_POINTER_REGISTER] = value;
            Ok((instruction.next_pc, None))
        }
        PointerAuthenticationOperation::Authenticate1716 { key } => {
            let result = context.authenticate_operation(
                runtime_pauth_key(key),
                registers.x[HINT_POINTER_REGISTER],
                registers.x[HINT_MODIFIER_REGISTER],
                false,
            )?;
            registers.x[HINT_POINTER_REGISTER] = result.pointer;
            Ok((instruction.next_pc, Some(result.authenticated)))
        }
        PointerAuthenticationOperation::SignIbSp => {
            let signed = context.sign_ib(registers.x[30], registers.sp)?;
            registers.x[30] = signed;
            Ok((instruction.next_pc, None))
        }
        PointerAuthenticationOperation::AuthenticateIbSp => {
            let result = context.authenticate_operation(
                pauth::Key::Ib,
                registers.x[30],
                registers.sp,
                false,
            )?;
            registers.x[30] = result.pointer;
            Ok((instruction.next_pc, Some(result.authenticated)))
        }
        PointerAuthenticationOperation::ReturnIbSp | PointerAuthenticationOperation::ReturnIaSp => {
            let key = if instruction.operation == PointerAuthenticationOperation::ReturnIbSp {
                pauth::Key::Ib
            } else {
                pauth::Key::Ia
            };
            let result =
                context.authenticate_operation(key, registers.x[30], registers.sp, true)?;
            // Authenticated RET uses a temporary target. The signed LR stays in X30.
            Ok((GuestAddress(result.pointer), Some(result.authenticated)))
        }
        PointerAuthenticationOperation::Branch {
            key,
            target,
            modifier,
            link,
        } => {
            ensure!(
                target < REGISTER_COUNT,
                "invalid authenticated branch target register"
            );
            let pointer = if target == ZERO_REGISTER_INDEX {
                0
            } else {
                registers.x[usize::from(target)]
            };
            // Both operands may alias X30. Authentication uses their old values.
            let modifier = pauth_modifier(registers, modifier)?;
            let result =
                context.authenticate_operation(runtime_pauth_key(key), pointer, modifier, true)?;
            if link {
                // Nonfaulting authentication still performs the architectural
                // link write before instruction fetch checks its resulting target.
                // FPACCOMBINE failure has already returned above.
                registers.x[30] = instruction.next_pc.0;
            }
            Ok((GuestAddress(result.pointer), Some(result.authenticated)))
        }
        Sign {
            key,
            destination,
            modifier,
        }
        | Authenticate {
            key,
            destination,
            modifier,
        } => {
            ensure!(
                destination < REGISTER_COUNT,
                "invalid PAC destination register"
            );
            let pointer = if destination == ZERO_REGISTER_INDEX {
                0
            } else {
                registers.x[usize::from(destination)]
            };
            // Snapshot all inputs before any destination write, including Rd==Rn.
            let modifier = pauth_modifier(registers, modifier)?;
            let (value, authenticated) = if matches!(instruction.operation, Sign { .. }) {
                (
                    context.sign(runtime_pauth_key(key), pointer, modifier)?,
                    None,
                )
            } else {
                let result = context.authenticate_operation(
                    runtime_pauth_key(key),
                    pointer,
                    modifier,
                    false,
                )?;
                (result.pointer, Some(result.authenticated))
            };
            // XZR is discarded only after the operation/service has succeeded.
            if destination != ZERO_REGISTER_INDEX {
                registers.x[usize::from(destination)] = value;
            }
            Ok((instruction.next_pc, authenticated))
        }
        PointerAuthenticationOperation::Load(load) => {
            let memory = memory.ok_or(AuthenticatedLoadError::MemoryRequired)?;
            let mut authenticated = false;
            let read_flags = if load.writeback || load.base != ZERO_REGISTER_INDEX {
                stela_compiler::context::memory::flags::TAG_CHECKED
            } else {
                0
            };
            pauth::memory::complete(
                load,
                memory.controls,
                registers,
                |key, pointer| -> core::result::Result<u64, pauth::AuthenticationError> {
                    let key = match key {
                        stela_compiler::block::pauth_memory::DataKey::A => pauth::Key::Da,
                        stela_compiler::block::pauth_memory::DataKey::B => pauth::Key::Db,
                    };
                    let result = context.authenticate_operation(key, pointer, 0, true)?;
                    authenticated = result.authenticated;
                    Ok(result.pointer)
                },
                |address| {
                    memory
                        .reader
                        .read_scalar(
                            address,
                            size_of::<u64>() as u8,
                            read_flags,
                            instruction.instruction_pc.0,
                        )
                        .map(|value| value as u64)
                        .map_err(AuthenticatedLoadError::Read)
                },
            )
            .map_err(|fault| match fault {
                pauth::memory::Fault::InvalidOperands => anyhow::anyhow!("invalid LDRA operands"),
                pauth::memory::Fault::UndefinedOverlap => {
                    AuthenticatedLoadError::UndefinedOverlap.into()
                }
                pauth::memory::Fault::Authentication(error) => anyhow::Error::new(error),
                pauth::memory::Fault::StackAlignment { stack_pointer } => {
                    AuthenticatedLoadError::StackAlignment { stack_pointer }.into()
                }
                pauth::memory::Fault::Read { error, .. } => error.into(),
            })?;
            Ok((instruction.next_pc, Some(authenticated)))
        }
        PointerAuthenticationOperation::GenericCode(code) => {
            pauth::generic::complete(code, registers, |data, modifier| {
                context.generic_code(data, modifier)
            })
            .map_err(|fault| match fault {
                pauth::generic::Fault::InvalidOperands => anyhow::anyhow!("invalid PACGA operands"),
                pauth::generic::Fault::Compute(error) => error,
            })?;
            Ok((instruction.next_pc, None))
        }
        Strip { data, destination } => {
            ensure!(
                destination < REGISTER_COUNT,
                "invalid XPAC destination register"
            );
            let pointer = if destination == ZERO_REGISTER_INDEX {
                0
            } else {
                registers.x[usize::from(destination)]
            };
            // XPAC chooses an address domain, not a cryptographic key. No key
            // needs to exist; the context owns the reviewed address/TBI profile.
            let value =
                context.strip(if data { pauth::Key::Da } else { pauth::Key::Ia }, pointer)?;
            if destination != ZERO_REGISTER_INDEX {
                registers.x[usize::from(destination)] = value;
            }
            Ok((instruction.next_pc, None))
        }
    }
}

fn validate_pauth_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<PointerAuthentication> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_pointer_authentication(exit, word)?
        .context("PAuth exit does not identify a reviewed instruction")
}

/// Every consumed aligned word is a source-map boundary, checked at preparation.
/// Numerical exits may identify an interior instruction; all operands are decoded
/// again from the registered immutable source, never from artifact descriptors.
fn validate_numerical_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<(
    stela_compiler::aarch64::FloatingPointOperation,
    GuestAddress,
)> {
    let word = validate_interior_word(entry, exit, source_bytes, region_base, source)?;
    let operand = stela_compiler::aarch64::FloatingPointOperation::decode(word)
        .context("numerical exit does not identify arithmetic")?
        .map_err(|()| anyhow::anyhow!("numerical exit identifies reserved arithmetic"))?;
    let next = GuestAddress(
        exit.0
            .checked_add(INSTRUCTION_BYTES as u64)
            .context("numerical continuation address overflow")?,
    );
    Ok((operand, next))
}

fn validate_interior_word(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<u32> {
    ensure!(
        entry.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            && exit.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            && source_bytes >= INSTRUCTION_BYTES
            && source_bytes.is_multiple_of(INSTRUCTION_BYTES),
        "invalid numerical helper block extent/alignment"
    );
    entry
        .0
        .checked_add(u64::try_from(source_bytes)?)
        .context("numerical consumed guest extent overflow")?;
    let prefix = usize::try_from(
        entry
            .0
            .checked_sub(region_base)
            .context("numerical block precedes immutable source")?,
    )?;
    let end = prefix
        .checked_add(source_bytes)
        .context("numerical block extent overflow")?;
    ensure!(
        end <= source.len(),
        "numerical block exceeds immutable source"
    );
    let relative = usize::try_from(
        exit.0
            .checked_sub(entry.0)
            .context("numerical exit precedes consumed block")?,
    )?;
    ensure!(
        relative < source_bytes,
        "numerical exit exceeds consumed block"
    );
    let offset = prefix
        .checked_add(relative)
        .context("numerical source offset overflow")?;
    Ok(u32::from_le_bytes(
        source[offset..offset + INSTRUCTION_BYTES].try_into()?,
    ))
}

/// Native exit metadata must identify the final immutable source instruction;
/// descriptors are decoded again instead of trusting artifact-supplied operands.
fn validate_terminal_word(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<u32> {
    ensure!(
        source_bytes >= INSTRUCTION_BYTES && source_bytes.is_multiple_of(INSTRUCTION_BYTES),
        "invalid native helper block extent"
    );
    let terminal = entry
        .0
        .checked_add(u64::try_from(source_bytes - INSTRUCTION_BYTES)?)
        .context("native helper terminal address overflow")?;
    ensure!(
        exit.0 == terminal,
        "native helper exit differs from consumed terminal instruction"
    );
    let offset = usize::try_from(
        terminal
            .checked_sub(region_base)
            .context("native helper precedes source region")?,
    )?;
    let end = offset
        .checked_add(INSTRUCTION_BYTES)
        .context("native helper source extent overflow")?;
    Ok(u32::from_le_bytes(
        source
            .get(offset..end)
            .context("native helper exceeds immutable source")?
            .try_into()?,
    ))
}

fn validate_system_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SystemInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_system_instruction(exit, word)?
        .context("native System exit is not an immutable System instruction")
}

fn validate_thread_register_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<ThreadRegisterInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_thread_register_instruction(exit, word)?
        .context("thread-register exit does not identify a reviewed instruction")
}

fn validate_trap_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SynchronousTrap> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_trap(exit, word)?.context("trap exit does not identify a reviewed instruction")
}

fn validate_source_map(
    manifest: &crate::Manifest,
    base: GuestAddress,
    source_bytes: usize,
) -> Result<()> {
    let first_native_offset = if manifest.memory_requirements.is_some()
        || manifest.identity.abi == stela_compiler::block::EL1_M0_INTEGER_BLOCK_ABI
    {
        stela_compiler::extended::CONTEXT_WRAPPER_BYTES
    } else {
        0
    };
    crate::artifact::validate_source_map(manifest, base, source_bytes, first_native_offset)?;
    Ok(())
}

#[cfg(test)]
mod tests;
