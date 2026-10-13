//! Serialized native block dispatch over immutable guest instruction snapshots.
//! Guest code bytes are fetched from owned regions; data addresses retain the
//! direct-RAM profile. Replacement invalidates dependent RX copies before return.
use crate::{Prepared, execution::platform, prepare_block};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_compiler::{
    GuestAddress, GuestState, SOURCE_FINGERPRINT_MATERIAL,
    block::{
        BLOCK_ABI, BlockAnalysis, BlockExit, DynamicEdge, ExitKind, MAX_BLOCK_INSTRUCTIONS,
        SynchronousTrap, analyze, decode_trap,
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
    Unsupported { detail: String },
    SynchronousTrap { trap: SynchronousTrap },
}

#[derive(Debug, Serialize)]
pub struct RunOutcome {
    pub reason: StopReason,
    pub blocks_executed: usize,
    pub compiled_blocks: usize,
    pub disk_cache_hits: usize,
    pub memory_cache_hits: usize,
    pub last_exit: Option<(u64, u64)>,
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
        Self {
            address_space,
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
        let analysis = analyze(window, pc)?;
        let prepared = prepare_block(window, pc, &self.cache_root)?;
        ensure!(
            prepared.source_bytes == analysis.source_bytes,
            "prepared block analysis extent mismatch"
        );
        let manifest = &prepared.prepared.manifest;
        ensure!(
            manifest.identity.guest_base == pc.0
                && manifest.identity.abi == BLOCK_ABI
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
                    match analyze(&region.source[offset..offset + available], pc) {
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
        platform::ensure_supported()?;
        let mut outcome = RunOutcome {
            reason: StopReason::BudgetExhausted,
            blocks_executed: 0,
            compiled_blocks: 0,
            disk_cache_hits: 0,
            memory_cache_hits: 0,
            last_exit: None,
        };
        loop {
            let pc = state.pc;
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
                if let Err(error) = stela_compiler::block::source_bytes(
                    &region.source[offset..offset + words * 4],
                    pc,
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
            state.pc = GuestAddress(next_pc);
            outcome.last_exit = Some((next_pc, kind));
            outcome.blocks_executed += 1;
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
