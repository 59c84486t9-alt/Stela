//! Serialized native block dispatch over immutable guest instruction snapshots.
//! Guest code bytes are fetched from owned regions; data addresses retain the
//! direct-RAM profile. Replacement invalidates dependent RX copies before return.
use crate::{Prepared, clock, execution::platform, pauth, prepare_block_with_profile};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_compiler::{
    GuestAddress, GuestState, SOURCE_FINGERPRINT_MATERIAL,
    block::{
        BlockAnalysis, BlockExit, BlockProfile, ClockInstruction, ClockOperation, DynamicEdge,
        ExitKind, MAX_BLOCK_INSTRUCTIONS, PointerAuthentication, PointerAuthenticationKey,
        PointerAuthenticationModifier, PointerAuthenticationOperation, SynchronousTrap,
        analyze_with_profile, decode_clock_instruction, decode_pointer_authentication, decode_trap,
    },
};
use stela_core::sha256;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Read,
    marker::PhantomData,
    path::PathBuf,
    rc::Rc,
};

const MAX_NATIVE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ThreadState {
    pub registers: GuestState,
    pub pc: GuestAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
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
    /// Classic PAuth poisoned a return target. No target instruction executed;
    /// guest instruction-fetch exception delivery remains the caller's work.
    PointerAuthenticationPoisonedReturn {
        instruction: PointerAuthentication,
        poisoned_target: GuestAddress,
    },
    ClockRequired {
        instruction: ClockInstruction,
    },
    ClockUnavailable {
        instruction: ClockInstruction,
        detail: String,
    },
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
pub struct RunOutcome {
    pub reason: StopReason,
    pub blocks_executed: usize,
    pub compiled_blocks: usize,
    pub disk_cache_hits: usize,
    pub memory_cache_hits: usize,
    pub last_exit: Option<(u64, u64)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pointer_authentication_events: Vec<PointerAuthenticationEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clock_events: Vec<ClockEvent>,
}

#[derive(Debug)]
struct CodeRegion {
    source: Box<[u8]>,
    end: u64,
    generation: u64,
}

#[derive(Debug)]
struct LoadedBlock {
    region_base: u64,
    generation: u64,
    source_bytes: usize,
    prepared: Prepared,
    mapping: platform::Mapping,
}

/// Source registration, resolution and execution are serialized through &mut.
/// No function pointer, mutable code slice or executable mapping escapes.
#[derive(Debug)]
pub struct BlockRuntime {
    address_space: u64,
    profile: BlockProfile,
    cache_root: PathBuf,
    next_generation: u64,
    regions: BTreeMap<u64, CodeRegion>,
    loaded: BTreeMap<u64, LoadedBlock>,
    _serialized: PhantomData<Rc<()>>,
}

/// Persistent preparation artifact shared by ahead-of-time discovery and JIT.
/// Preparing it performs no native mapping, invocation or guest memory access.
#[derive(Debug, Serialize)]
pub struct PreparedDiscoveryBlock {
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
    pub fn new(address_space: u64, cache_root: PathBuf) -> Self {
        Self::new_with_profile(address_space, cache_root, BlockProfile::Ordinary)
    }

    /// Explicit helper profile is part of every persistent translation identity.
    /// Preparing AOT needs no keys; execution receives a separately bound context.
    pub fn new_with_profile(
        address_space: u64,
        cache_root: PathBuf,
        profile: BlockProfile,
    ) -> Self {
        Self {
            address_space,
            profile,
            cache_root,
            next_generation: 0,
            regions: BTreeMap::new(),
            loaded: BTreeMap::new(),
            _serialized: PhantomData,
        }
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
    pub fn prepare(&mut self, pc: GuestAddress) -> Result<PreparedDiscoveryBlock> {
        ensure!(pc.0.is_multiple_of(4), "unaligned preparation entry");
        let (base, region) = self.region(pc).context("unmapped preparation entry")?;
        ensure!(region.end - pc.0 >= 4, "truncated preparation instruction");
        let offset = usize::try_from(pc.0 - base)?;
        let available = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS) * 4;
        let generation = region.generation;
        let window = &region.source[offset..offset + available];
        let analysis = analyze_with_profile(window, pc, self.profile)?;
        let prepared = prepare_block_with_profile(window, pc, &self.cache_root, self.profile)?;
        ensure!(
            prepared.source_bytes == analysis.source_bytes,
            "prepared block analysis extent mismatch"
        );
        let manifest = &prepared.prepared.manifest;
        ensure!(
            manifest.identity.guest_base == pc.0
                && manifest.identity.abi == self.profile.abi()
                && manifest.identity.target_cpu == "x86_64-baseline"
                && manifest.identity.schema_version == 1,
            "unsupported block translation identity"
        );
        ensure!(
            manifest.identity.compiler_source_sha256
                == sha256(SOURCE_FINGERPRINT_MATERIAL.as_bytes())
                && manifest.identity.source_sha256 == sha256(&window[..prepared.source_bytes]),
            "block compiler/source identity mismatch"
        );
        validate_source_map(&prepared.prepared, pc, prepared.source_bytes)?;
        ensure!(
            manifest.native_bytes > 0 && manifest.native_bytes <= MAX_NATIVE_BYTES,
            "invalid block native size"
        );
        Ok(PreparedDiscoveryBlock {
            entry: pc,
            region_base: GuestAddress(base),
            generation,
            analysis,
            prepared: prepared.prepared,
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
        let prepared = self.prepare(pc)?;
        let generation = prepared.generation;
        let source_bytes = prepared.analysis.source_bytes;
        let prepared = prepared.prepared;
        let manifest = &prepared.manifest;
        let mut native = Vec::new();
        std::fs::File::open(prepared.directory.join("native.bin"))?
            .take((MAX_NATIVE_BYTES + 1) as u64)
            .read_to_end(&mut native)?;
        ensure!(
            native.len() == manifest.native_bytes && sha256(&native) == manifest.native_sha256,
            "block native snapshot checksum mismatch"
        );
        let mapping = platform::Mapping::new(&native)?;
        if prepared.cache_hit {
            outcome.disk_cache_hits += 1;
        } else {
            outcome.compiled_blocks += 1;
        }
        self.loaded.insert(
            pc.0,
            LoadedBlock {
                region_base: base,
                generation,
                source_bytes,
                prepared,
                mapping,
            },
        );
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
        unsafe { self.run_inner(state, stop_pc, block_budget, None, None) }
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
        unsafe { self.run_inner(state, stop_pc, block_budget, Some(context), None) }
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
        unsafe { self.run_inner(state, stop_pc, block_budget, Some(pauth), Some(clock)) }
    }

    unsafe fn run_inner(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        context: Option<&pauth::Context>,
        mut clock_context: Option<&mut clock::Context>,
    ) -> Result<RunOutcome> {
        platform::ensure_supported()?;
        let mut outcome = RunOutcome {
            reason: StopReason::BudgetExhausted,
            blocks_executed: 0,
            compiled_blocks: 0,
            disk_cache_hits: 0,
            memory_cache_hits: 0,
            last_exit: None,
            pointer_authentication_events: Vec::new(),
            clock_events: Vec::new(),
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
            let BlockExit { next_pc, kind } =
                unsafe { block.mapping.call_block(&mut state.registers)? };
            let exit_kind = ExitKind::try_from(kind)
                .map_err(|_| anyhow::anyhow!("invalid native block exit kind"))?;
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
            state.pc = GuestAddress(next_pc);
            outcome.last_exit = Some((next_pc, kind));
            outcome.blocks_executed += 1;
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
                let Some(context) = context else {
                    outcome.reason = StopReason::PointerAuthenticationRequired { instruction };
                    break;
                };
                if let Some(key) = instruction.operation.required_key()
                    && !context.has_key(runtime_pauth_key(key))
                {
                    outcome.reason =
                        StopReason::PointerAuthenticationKeyUnavailable { instruction, key };
                    break;
                }
                let result = complete_pauth(context, &instruction, &mut state.registers);
                let (next, authenticated) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        outcome.reason = StopReason::PointerAuthenticationUnsupported {
                            instruction,
                            detail: error.to_string(),
                        };
                        break;
                    }
                };
                state.pc = next;
                let poisoned_return =
                    instruction.operation.is_return() && authenticated == Some(false);
                outcome
                    .pointer_authentication_events
                    .push(PointerAuthenticationEvent {
                        instruction,
                        next_pc: next,
                        authenticated,
                    });
                if poisoned_return {
                    outcome.reason = StopReason::PointerAuthenticationPoisonedReturn {
                        instruction,
                        poisoned_target: next,
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
            ensure!(destination < 32, "invalid clock destination register");
            // Sampling and complete commpage publication must succeed before
            // committing the destination. X31 discards the result, not the read.
            let counter = context.read_counter()?;
            if destination != 31 {
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
        use std::sync::atomic::{Ordering, compiler_fence};
        compiler_fence(Ordering::SeqCst);
        // CPUID is available on the x86-64 baseline. Leaf0 is a genuine
        // serializing instruction; the intrinsic owns its host scratch outputs.
        let _ = std::arch::x86_64::__cpuid(0);
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
    ensure!(
        source_bytes >= 4 && source_bytes.is_multiple_of(4),
        "invalid clock block extent"
    );
    let terminal = entry
        .0
        .checked_add(u64::try_from(source_bytes - 4)?)
        .context("clock terminal address overflow")?;
    ensure!(
        exit.0 == terminal,
        "clock exit differs from consumed terminal instruction"
    );
    let offset = usize::try_from(
        terminal
            .checked_sub(region_base)
            .context("clock precedes source region")?,
    )?;
    let end = offset
        .checked_add(4)
        .context("clock source extent overflow")?;
    let word = u32::from_le_bytes(
        source
            .get(offset..end)
            .context("clock exceeds immutable source")?
            .try_into()?,
    );
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
            ensure!(index < 31, "invalid PAC modifier register");
            Ok(registers.x[usize::from(index)])
        }
    }
}

fn complete_pauth(
    context: &pauth::Context,
    instruction: &PointerAuthentication,
    registers: &mut GuestState,
) -> Result<(GuestAddress, Option<bool>)> {
    use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
    match instruction.operation {
        PointerAuthenticationOperation::SignIbSp => {
            let signed = context.sign_ib(registers.x[30], registers.sp)?;
            registers.x[30] = signed;
            Ok((instruction.next_pc, None))
        }
        PointerAuthenticationOperation::AuthenticateIbSp => {
            let result = context.authenticate_ib(registers.x[30], registers.sp)?;
            registers.x[30] = result.pointer;
            Ok((instruction.next_pc, Some(result.authenticated)))
        }
        PointerAuthenticationOperation::ReturnIbSp | PointerAuthenticationOperation::ReturnIaSp => {
            let key = if instruction.operation == PointerAuthenticationOperation::ReturnIbSp {
                pauth::Key::Ib
            } else {
                pauth::Key::Ia
            };
            let result = context.authenticate(key, registers.x[30], registers.sp)?;
            // Authenticated RET uses a temporary target. The signed LR stays in X30.
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
            ensure!(destination < 32, "invalid PAC destination register");
            let pointer = if destination == 31 {
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
                let result = context.authenticate(runtime_pauth_key(key), pointer, modifier)?;
                (result.pointer, Some(result.authenticated))
            };
            // XZR is discarded only after the operation/service has succeeded.
            if destination != 31 {
                registers.x[usize::from(destination)] = value;
            }
            Ok((instruction.next_pc, authenticated))
        }
        Strip { data, destination } => {
            ensure!(destination < 32, "invalid XPAC destination register");
            let pointer = if destination == 31 {
                0
            } else {
                registers.x[usize::from(destination)]
            };
            // XPAC chooses an address domain, not a cryptographic key. No key
            // needs to exist; the context owns the reviewed address/TBI profile.
            let value =
                context.strip(if data { pauth::Key::Da } else { pauth::Key::Ia }, pointer)?;
            if destination != 31 {
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
    ensure!(
        source_bytes >= 4 && source_bytes.is_multiple_of(4),
        "invalid PAuth block extent"
    );
    let terminal = entry
        .0
        .checked_add(source_bytes as u64 - 4)
        .context("PAuth terminal address overflow")?;
    ensure!(
        exit.0 == terminal,
        "PAuth exit differs from consumed terminal instruction"
    );
    let offset = usize::try_from(
        terminal
            .checked_sub(region_base)
            .context("PAuth precedes source region")?,
    )?;
    let end = offset
        .checked_add(4)
        .context("PAuth source extent overflow")?;
    let word = u32::from_le_bytes(
        source
            .get(offset..end)
            .context("PAuth exceeds immutable source")?
            .try_into()?,
    );
    decode_pointer_authentication(exit, word)?
        .context("PAuth exit does not identify a reviewed instruction")
}

fn validate_trap_exit(
    entry: GuestAddress,
    returned: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SynchronousTrap> {
    ensure!(
        source_bytes >= 4 && source_bytes.is_multiple_of(4),
        "native trap has an invalid consumed source extent"
    );
    let expected = GuestAddress(
        entry
            .0
            .checked_add(u64::try_from(source_bytes - 4)?)
            .context("native trap instruction address overflow")?,
    );
    ensure!(
        returned == expected,
        "native trap PC does not identify the consumed terminator"
    );
    let offset = usize::try_from(
        expected
            .0
            .checked_sub(region_base)
            .context("native trap PC precedes its immutable source region")?,
    )?;
    let end = offset
        .checked_add(4)
        .context("native trap source extent overflow")?;
    let word = u32::from_le_bytes(
        source
            .get(offset..end)
            .context("native trap terminator exceeds immutable source region")?
            .try_into()?,
    );
    decode_trap(expected, word)?
        .context("native trap exit does not match an immutable trap instruction")
}

fn validate_source_map(prepared: &Prepared, base: GuestAddress, source_bytes: usize) -> Result<()> {
    let manifest = &prepared.manifest;
    ensure!(
        !manifest.verified && manifest.source_map.len() == source_bytes / 4,
        "invalid block source map length or verification claim"
    );
    let mut prior = None;
    for (index, &(guest, native)) in manifest.source_map.iter().enumerate() {
        ensure!(
            guest.0
                == base
                    .0
                    .checked_add(index as u64 * 4)
                    .context("source map address overflow")?,
            "block source map guest mismatch"
        );
        ensure!(
            native < manifest.native_bytes
                && prior.is_none_or(|old| native > old)
                && (index != 0 || native == 0),
            "invalid block native source map offset"
        );
        prior = Some(native);
    }
    Ok(())
}

#[cfg(test)]
mod trap_validation_tests {
    use super::*;

    #[test]
    fn clock_exit_requires_exact_consumed_source_descriptor() {
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(0x1004);
        for word in [0xd5033fdf_u32, 0xd53be049, 0xd53be05f] {
            let source: Vec<_> = [0x91000400u32, word]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            assert_eq!(
                validate_clock_exit(base, terminal, 8, base.0, &source).unwrap(),
                decode_clock_instruction(terminal, word).unwrap().unwrap()
            );
            for (returned, count, region) in [
                (base, 8, base.0),
                (terminal, 0, base.0),
                (terminal, 6, base.0),
                (GuestAddress(0x1008), 12, base.0),
                (terminal, 8, 0x2000),
            ] {
                assert!(validate_clock_exit(base, returned, count, region, &source).is_err());
            }
        }
        assert!(validate_clock_exit(base, base, 4, base.0, &0xd503237fu32.to_le_bytes()).is_err());
    }

    #[test]
    fn pauth_exit_requires_the_exact_consumed_immutable_helper_instruction() {
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(0x1004);
        let source: Vec<_> = [0x91000400u32, 0xd503237f]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(
            validate_pauth_exit(base, terminal, 8, base.0, &source).unwrap(),
            decode_pointer_authentication(terminal, 0xd503237f)
                .unwrap()
                .unwrap()
        );
        for (returned, bytes, region) in [
            (base, 8, base.0),
            (terminal, 0, base.0),
            (terminal, 6, base.0),
            (GuestAddress(0x1008), 12, base.0),
            (terminal, 8, 0x2000),
        ] {
            assert!(validate_pauth_exit(base, returned, bytes, region, &source).is_err());
        }
        assert!(validate_pauth_exit(base, base, 4, base.0, &source).is_err());
    }

    #[test]
    fn trap_exit_requires_the_exact_consumed_immutable_terminator() {
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(0x1004);
        let source: Vec<_> = [0x91000400u32, 0xd4001001]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(); // ADD; SVC #0x80
        assert_eq!(
            validate_trap_exit(base, terminal, 8, base.0, &source).unwrap(),
            decode_trap(terminal, 0xd4001001).unwrap().unwrap()
        );
        assert!(validate_trap_exit(base, base, 8, base.0, &source).is_err());
        assert!(validate_trap_exit(base, terminal, 0, base.0, &source).is_err());
        assert!(validate_trap_exit(base, terminal, 6, base.0, &source).is_err());
        assert!(validate_trap_exit(base, GuestAddress(0x1008), 12, base.0, &source).is_err());
        assert!(validate_trap_exit(base, terminal, 8, 0x2000, &source).is_err());
        let ordinary: Vec<_> = [0x91000400u32, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert!(validate_trap_exit(base, terminal, 8, base.0, &ordinary).is_err());
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod clock_dispatch_tests {
    use super::*;
    use crate::clock::{ReplaySource, Snapshot};

    const BASE: GuestAddress = GuestAddress(0x1000);
    const STOP: GuestAddress = GuestAddress(0x1400);
    const PROFILE: BlockProfile = BlockProfile::AppleArm64eSoftwarePauthClockV1;

    fn runtime(path: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
        let mut runtime = BlockRuntime::new_with_profile(1, path.to_path_buf(), PROFILE);
        runtime.register_code(
            BASE,
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        )?;
        Ok(runtime)
    }
    fn keys(address_space: u64) -> pauth::Context {
        pauth::Context::new(address_space, pauth::Keys::from_ib_words(1, 2))
    }
    fn initial_thread(flags: u32) -> ThreadState {
        let mut registers = GuestState {
            x: std::array::from_fn(|i| 0x0123456789abcdefu64.rotate_left(i as u32)),
            sp: 0x2000,
            nzcv: flags << 28,
            reserved: 0xa5c39e71,
            v: std::array::from_fn(|i| {
                [
                    0x123456789abcdef0u64.rotate_left(i as u32),
                    0xfedcba9876543210u64.rotate_right(i as u32),
                ]
            }),
            fpcr: 0x03c00000,
            fpsr: 0x0800001f,
        };
        registers.x[30] = STOP.0;
        ThreadState {
            registers,
            pc: BASE,
        }
    }

    #[test]
    fn all_counter_destinations_preserve_full_state_and_share_preparation_cache() -> Result<()> {
        let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
        let samples = (0..=512)
            .map(|i| Snapshot {
                counter: 1000 + i,
                sleep_ticks: 100,
            })
            .collect();
        let mut clock = clock::Context::new(1, Box::new(ReplaySource::new(samples)?))?;
        let keys = keys(1);
        let cache = tempfile::tempdir()?;
        for destination in 0..32 {
            let mut vm = runtime(cache.path(), &[0xd2800547, 0xd53be040 | destination])?;
            let prepared = vm.prepare(BASE)?;
            assert!(!prepared.prepared.cache_hit);
            for flags in 0..16 {
                let mut state = initial_thread(flags);
                let mut expected = state.registers.clone();
                expected.x[7] = 42;
                let counter = 1001 + u64::from(destination * 16 + flags);
                if destination != 31 {
                    expected.x[destination as usize] = counter;
                }
                // SAFETY: register prefix and checked service only, no guest RAM accesses.
                let result = unsafe {
                    vm.run_with_clock(
                        &mut state,
                        Some(GuestAddress(BASE.0 + 8)),
                        1,
                        &keys,
                        &mut clock,
                    )?
                };
                assert_eq!(state.registers, expected);
                assert_eq!(state.pc, GuestAddress(BASE.0 + 8));
                assert_eq!(result.reason, StopReason::StopAddress);
                assert_eq!(result.blocks_executed, 1);
                assert_eq!(result.compiled_blocks, 0);
                assert_eq!(result.disk_cache_hits, usize::from(flags == 0));
                assert_eq!(result.clock_events.len(), 1);
                assert_eq!(result.clock_events[0].counter, Some(counter));
                assert_eq!(
                    result.clock_events[0].instruction.operation,
                    ClockOperation::ReadVirtualCounter {
                        destination: destination as u8
                    }
                );
            }
        }
        assert_eq!(clock.events().len(), 513);
        Ok(())
    }

    #[test]
    fn isb_serializes_without_sampling_and_counter_xzr_discards_only_destination() -> Result<()> {
        let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
        let mut clock = clock::Context::new(
            1,
            Box::new(ReplaySource::new(vec![
                Snapshot {
                    counter: 100,
                    sleep_ticks: 10,
                },
                Snapshot {
                    counter: 150,
                    sleep_ticks: 20,
                },
            ])?),
        )?;
        let cache = tempfile::tempdir()?;
        let mut vm = runtime(cache.path(), &[0xd5033fdf, 0xd53be05f, 0xd65f03c0])?;
        let mut state = initial_thread(15);
        let before = state.registers.clone();
        let result = unsafe { vm.run_with_clock(&mut state, Some(STOP), 3, &keys(1), &mut clock)? };
        assert_eq!(result.reason, StopReason::StopAddress);
        assert_eq!(result.blocks_executed, 3);
        assert_eq!(state.registers, before);
        assert_eq!(result.clock_events.len(), 2);
        assert_eq!(result.clock_events[0].counter, None);
        assert_eq!(result.clock_events[1].counter, Some(150));
        assert_eq!(clock.events().len(), 2);
        Ok(())
    }

    #[test]
    fn unavailable_clock_preserves_destination_page_and_exact_resume_after_prefix() -> Result<()> {
        let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
        let mut clock = clock::Context::new(
            1,
            Box::new(ReplaySource::new(vec![Snapshot {
                counter: 100,
                sleep_ticks: 10,
            }])?),
        )?;
        let page = clock.snapshot_bytes(0, clock::GUEST_BYTES)?;
        let cache = tempfile::tempdir()?;
        let mut vm = runtime(cache.path(), &[0x91000400, 0xd53be048])?;
        let mut state = initial_thread(5);
        let mut expected = state.registers.clone();
        expected.x[0] = expected.x[0].wrapping_add(1);
        for _ in 0..2 {
            let result = unsafe {
                vm.run_with_clock(
                    &mut state,
                    Some(GuestAddress(BASE.0 + 8)),
                    1,
                    &keys(1),
                    &mut clock,
                )?
            };
            assert!(matches!(result.reason, StopReason::ClockUnavailable { .. }));
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, GuestAddress(BASE.0 + 4));
            assert_eq!(result.last_exit, Some((BASE.0 + 4, ExitKind::Clock as u64)));
            assert!(result.clock_events.is_empty());
            assert_eq!(clock.snapshot_bytes(0, clock::GUEST_BYTES)?, page);
            assert_eq!(clock.events().len(), 1);
        }
        Ok(())
    }

    #[test]
    fn missing_clock_and_foreign_services_decline_without_helper_effects() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut vm = runtime(cache.path(), &[0x91000400, 0xd5033fdf])?;
        let mut state = initial_thread(7);
        let mut expected = state.registers.clone();
        expected.x[0] = expected.x[0].wrapping_add(1);
        let result = unsafe { vm.run_with_pauth(&mut state, None, 1, &keys(1))? };
        assert!(matches!(result.reason, StopReason::ClockRequired { .. }));
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, GuestAddress(BASE.0 + 4));
        assert!(result.clock_events.is_empty());
        let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
        for address_space in [1, 2] {
            let mut clock = clock::Context::new(
                address_space,
                Box::new(ReplaySource::new(vec![Snapshot {
                    counter: 100,
                    sleep_ticks: 10,
                }])?),
            )?;
            let empty = tempfile::tempdir()?;
            let mut vm = runtime(empty.path(), &[0xd53be048])?;
            let mut state = initial_thread(0);
            let before = state.registers.clone();
            let pauth = keys(if address_space == 1 { 2 } else { 1 });
            assert!(unsafe { vm.run_with_clock(&mut state, None, 1, &pauth, &mut clock) }.is_err());
            assert_eq!(state.pc, BASE);
            assert_eq!(state.registers, before);
            assert_eq!(clock.events().len(), 1);
            assert_eq!(std::fs::read_dir(empty.path())?.count(), 0);
        }
        Ok(())
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod basic_pauth_tests {
    use super::*;

    const BASE: GuestAddress = GuestAddress(0x4000);
    const STOP: GuestAddress = GuestAddress(0x5000);

    fn full_context() -> pauth::Context {
        pauth::Context::new(9, pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]))
    }

    fn initial(flags: u32) -> ThreadState {
        ThreadState {
            pc: BASE,
            registers: GuestState {
                x: std::array::from_fn(|i| 0x123456789abcdef0u64.rotate_left(i as u32)),
                sp: 0x70000010000,
                nzcv: flags << 28,
                reserved: 0xc31a7e29,
                v: std::array::from_fn(|i| {
                    [
                        0x0123456789abcdefu64.rotate_left(i as u32),
                        0xfedcba9876543210u64.rotate_right(i as u32),
                    ]
                }),
                fpcr: 0x03c00000,
                fpsr: 0x0800001f,
            },
        }
    }

    fn runtime(cache: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
        let mut vm = BlockRuntime::new_with_profile(
            9,
            cache.into(),
            BlockProfile::AppleArm64eSoftwarePauthV1,
        );
        vm.register_code(
            BASE,
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        )?;
        Ok(vm)
    }

    #[test]
    fn all_basic_forms_preserve_full_state_across_native_helper_boundaries() -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        let fixed = [
            0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df, 0xd503231f, 0xd503233f, 0xd503235f,
            0xd503237f, 0xd503239f, 0xd50323bf, 0xd50323df, 0xd50323ff, 0xd50320ff, 0xd65f0bff,
            0xd65f0fff, 0xdac143f1, 0xdac147f1,
        ];
        let integer = (0..8).flat_map(|op| {
            [
                0xdac10000 | (op << 10) | (16 << 5) | 17,
                0xdac123e0 | (op << 10) | 17,
            ]
        });
        let words: Vec<_> = fixed.into_iter().chain(integer).collect();
        assert_eq!(words.len(), 33);
        for word in words {
            let mut vm = runtime(cache.path(), &[0xd2800547, word, 0])?; // MOV X7,#42; helper; bad code
            let instruction =
                decode_pointer_authentication(GuestAddress(BASE.0 + 4), word)?.unwrap();
            for flags in 0..16 {
                let mut state = initial(flags);
                if instruction.operation.is_return() {
                    let key = runtime_pauth_key(instruction.operation.required_key().unwrap());
                    state.registers.x[30] = context.sign(key, STOP.0, state.registers.sp)?;
                }
                let mut expected = state.registers.clone();
                expected.x[7] = 42;
                let (next_pc, authenticated) =
                    complete_pauth(&context, &instruction, &mut expected)?;
                // SAFETY: only register operations and a typed helper, no guest RAM accesses.
                let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &context)? };
                assert_eq!(state.registers, expected, "word {word:08x}, flags {flags}");
                assert_eq!(state.pc, next_pc);
                assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                assert_eq!(outcome.pointer_authentication_events.len(), 1);
                assert_eq!(
                    outcome.pointer_authentication_events[0].instruction,
                    instruction
                );
                assert_eq!(
                    outcome.pointer_authentication_events[0].authenticated,
                    authenticated
                );
            }
        }
        Ok(())
    }

    #[test]
    fn register_modifiers_aliases_sp_zero_and_xzr_have_precise_effects() -> Result<()> {
        let context = full_context();
        for key in [
            PointerAuthenticationKey::Ia,
            PointerAuthenticationKey::Ib,
            PointerAuthenticationKey::Da,
            PointerAuthenticationKey::Db,
        ] {
            for destination in 0..32u8 {
                for modifier in [
                    PointerAuthenticationModifier::Register(0),
                    PointerAuthenticationModifier::Register(destination.min(30)),
                    PointerAuthenticationModifier::StackPointer,
                    PointerAuthenticationModifier::Zero,
                ] {
                    let input = initial(15).registers;
                    let original = if destination == 31 {
                        0
                    } else {
                        input.x[usize::from(destination)]
                    };
                    let modifier_value = match modifier {
                        PointerAuthenticationModifier::Register(index) => {
                            input.x[usize::from(index)]
                        }
                        PointerAuthenticationModifier::StackPointer => input.sp,
                        PointerAuthenticationModifier::Zero => 0,
                    };
                    for authenticate in [false, true] {
                        let operation = if authenticate {
                            PointerAuthenticationOperation::Authenticate {
                                key,
                                destination,
                                modifier,
                            }
                        } else {
                            PointerAuthenticationOperation::Sign {
                                key,
                                destination,
                                modifier,
                            }
                        };
                        let instruction = PointerAuthentication {
                            operation,
                            instruction_pc: BASE,
                            next_pc: GuestAddress(BASE.0 + 4),
                        };
                        let mut actual = input.clone();
                        let mut expected = input.clone();
                        let value = if authenticate {
                            context
                                .authenticate(runtime_pauth_key(key), original, modifier_value)?
                                .pointer
                        } else {
                            context.sign(runtime_pauth_key(key), original, modifier_value)?
                        };
                        if destination != 31 {
                            expected.x[usize::from(destination)] = value;
                        }
                        let (pc, _) = complete_pauth(&context, &instruction, &mut actual)?;
                        assert_eq!(actual, expected);
                        assert_eq!(pc, instruction.next_pc);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_integer_pac_handles_alias_sp_and_zero_register_corners() -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        for opcode in 0..8u32 {
            for destination in [0, 16, 17, 30, 31] {
                for (rn, zero) in [(destination.min(30), false), (31, false), (31, true)] {
                    let word = 0xdac10000
                        | (opcode << 10)
                        | ((zero as u32) << 13)
                        | (rn << 5)
                        | destination;
                    let mut vm = runtime(cache.path(), &[word, 0])?;
                    let instruction = decode_pointer_authentication(BASE, word)?.unwrap();
                    let mut state = initial(15);
                    let mut expected = state.registers.clone();
                    let (next, authenticated) =
                        complete_pauth(&context, &instruction, &mut expected)?;
                    // SAFETY: exact register-only PAC/AUT helper, immutable code and no memory operand.
                    let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &context)? };
                    assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                    assert_eq!(state.registers, expected);
                    assert_eq!(state.pc, next);
                    assert_eq!(
                        outcome.pointer_authentication_events[0].authenticated,
                        authenticated
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn missing_key_stops_atomically_and_resumes_without_repeating_native_prefix() -> Result<()> {
        let ib_only = pauth::Context::new(9, pauth::Keys::from_ib_words(3, 4));
        let full = full_context();
        let cache = tempfile::tempdir()?;
        for (word, key) in [
            (0xdac10011, PointerAuthenticationKey::Ia),
            (0xdac10811, PointerAuthenticationKey::Da),
            (0xdac10c11, PointerAuthenticationKey::Db),
            (0xdac11011, PointerAuthenticationKey::Ia),
            (0xd65f0bff, PointerAuthenticationKey::Ia),
        ] {
            let mut vm = runtime(cache.path(), &[0x910004e7, word, 0])?; // ADD X7,X7,#1
            let mut state = initial(11);
            state.registers.x[30] = full.sign(pauth::Key::Ia, STOP.0, state.registers.sp)?;
            let mut expected = state.registers.clone();
            expected.x[7] = expected.x[7].wrapping_add(1);
            // SAFETY: register prefix/helper only; missing key cannot touch guest RAM.
            let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &ib_only)? };
            let instruction =
                decode_pointer_authentication(GuestAddress(BASE.0 + 4), word)?.unwrap();
            assert_eq!(
                outcome.reason,
                StopReason::PointerAuthenticationKeyUnavailable { instruction, key }
            );
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, instruction.instruction_pc);
            assert!(outcome.pointer_authentication_events.is_empty());
            let (next, _) = complete_pauth(&full, &instruction, &mut expected)?;
            // SAFETY: same immutable register-only helper with all requested keys.
            let resumed = unsafe { vm.run_with_pauth(&mut state, None, 1, &full)? };
            assert_eq!(resumed.reason, StopReason::BudgetExhausted);
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, next);
        }
        // XPAC needs no key, even for the IA/DA domain absent in an IB-only context.
        for word in [0xdac143f1, 0xdac147f1, 0xd50320ff, 0xdac143ff, 0xdac147ff] {
            let mut vm = runtime(cache.path(), &[word])?;
            let mut state = initial(7);
            let instruction = decode_pointer_authentication(BASE, word)?.unwrap();
            let mut expected = state.registers.clone();
            complete_pauth(&ib_only, &instruction, &mut expected)?;
            // SAFETY: keyless XPAC only, no guest memory accesses.
            let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &ib_only)? };
            assert_eq!(outcome.reason, StopReason::BudgetExhausted);
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, instruction.next_pc);
        }
        Ok(())
    }

    #[test]
    fn retaa_failure_keeps_signed_lr_and_stops_before_poisoned_fetch() -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        let mut vm = runtime(cache.path(), &[0xd65f0bff])?;
        let mut state = initial(8);
        let signed = context.sign(pauth::Key::Ia, STOP.0, state.registers.sp)?;
        state.registers.x[30] = signed ^ (1 << 47);
        let expected = state.registers.clone();
        let target =
            context.authenticate(pauth::Key::Ia, state.registers.x[30], state.registers.sp)?;
        assert!(!target.authenticated);
        // SAFETY: helper-only RETAA, no target is fetched by failed completion.
        let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &context)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, GuestAddress(target.pointer));
        assert!(
            matches!(outcome.reason, StopReason::PointerAuthenticationPoisonedReturn { poisoned_target, .. } if poisoned_target == state.pc)
        );
        Ok(())
    }
}
