//! Ahead-of-time preparation and static code discovery.
use super::BlockRuntime;
#[cfg(not(feature = "std"))]
use super::aot::ArtifactPreparation;
use super::validate::validate_source_map;
use crate::Prepared;
use crate::Result;
use alloc::collections::{BTreeSet, VecDeque};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use serde::Serialize;
use stela_compiler::{
    CompileErrorKind, GuestAddress,
    block::{
        BlockAnalysis, BlockProfile, CompilationPlan, DynamicEdge, Features,
        MAX_BLOCK_INSTRUCTIONS, analyze_and_plan, analyze_with_profile,
    },
};
use stela_contracts::{refuse, require};
#[cfg(not(feature = "std"))]
use stela_formats::sha256;

/// Persistent preparation artifact shared by ahead-of-time discovery and JIT.
/// Preparing it performs no native mapping, invocation or guest memory access.
#[derive(Debug, Serialize)]
pub struct PreparedDiscoveryBlock {
    #[serde(skip)]
    pub(super) artifact_profile: BlockProfile,
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
        encoding: Option<u32>,
        cause: CompileErrorKind,
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
    /// Prepare one known entry into the persistent AOT/JIT cache, without RX
    /// loading or execution. Source bytes/edges share the compiler's parser.
    pub fn prepare(&mut self, pc: GuestAddress) -> Result<PreparedDiscoveryBlock> {
        self.prepare_snapshot(pc).map(|(prepared, _)| prepared)
    }

    /// Keep the same native bytes whose checksum the preparation bound to the
    /// manifest, so dispatch can map them without reopening the cache file.
    pub(super) fn prepare_snapshot(
        &mut self,
        pc: GuestAddress,
    ) -> Result<(PreparedDiscoveryBlock, Vec<u8>)> {
        require!(pc.0.is_multiple_of(4), "unaligned preparation entry");
        #[cfg(feature = "std")]
        let cache_root = self.preparation.cache_root(pc)?;
        #[cfg(not(feature = "std"))]
        require!(
            matches!(self.preparation, ArtifactPreparation::InMemory),
            "AOT block unavailable; runtime compilation is unsupported",
            pc = pc.0
        );
        let (base, region) = self
            .region(pc)
            .ok_or_else(|| refuse!("unmapped preparation entry", pc = pc.0))?;
        require!(region.end - pc.0 >= 4, "truncated preparation instruction");
        let offset = (pc.0 - base) as usize;
        let available = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS) * 4;
        let generation = region.generation;
        let window = &region.source[offset..offset + available];
        let options = stela_compiler::Options::new(self.profile, self.target);
        // A leaf plan uses a different parser and consumes the entire window.
        let (analysis, plan) = if self.profile.has(Features::LEAF) {
            (
                analyze_with_profile(window, pc, self.profile)?,
                CompilationPlan::new(window, pc, &options),
            )
        } else {
            analyze_and_plan(window, pc, &options)?
        };
        let plan = plan?.with_resident_loops();
        let artifact_profile = plan.profile();
        let source_bytes = plan.source_bytes();
        require!(
            source_bytes == analysis.source_bytes,
            "prepared block analysis extent mismatch"
        );
        #[cfg(feature = "std")]
        let (prepared, native) =
            crate::prepare_block_plan(window, pc, cache_root, self.target, plan)?;
        #[cfg(not(feature = "std"))]
        let (prepared, native) = {
            let identity = crate::block_plan_identity(window, pc, self.target, &plan)?;
            let key = sha256(&serde_json::to_vec(&identity)?);
            let requirements = plan.memory_requirements();
            let (manifest, native) =
                crate::artifact::prepare::generate(identity, requirements, || {
                    plan.compile().map(|block| block.native)
                })?;
            (
                Prepared {
                    key,
                    cache_hit: false,
                    manifest,
                },
                native,
            )
        };
        validate_source_map(&prepared.manifest, pc, source_bytes)?;
        Ok((
            PreparedDiscoveryBlock {
                artifact_profile,
                entry: pc,
                region_base: GuestAddress(base),
                generation,
                analysis,
                prepared,
            },
            native,
        ))
    }

    /// Follow known static successors only. Call continuations are candidates,
    /// since the callee may not return; BR/BLR/RET targets stay unresolved. The
    /// budget counts every attempted entry, including refusals and missing
    /// regions. Nothing executes during discovery.
    pub fn discover(&mut self, roots: &[GuestAddress], budget: usize) -> Result<DiscoveryReport> {
        require!(
            !roots.is_empty() && roots.len() <= 1024,
            "discovery requires 1..1024 roots"
        );
        require!(
            budget <= 4096,
            "discovery budget exceeds 4096 attempted entries"
        );
        let mut unique = BTreeSet::new();
        for root in roots {
            require!(
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
                    let offset = (raw - base) as usize;
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
                            encoding: error.encoding,
                            cause: error.kind,
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
                        .ok_or(refuse!("dynamic edge lacks terminator"))?,
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
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn runtime_preparation_returns_the_validated_native_snapshot() -> anyhow::Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new(1, cache.path().to_owned());
        let entry = GuestAddress(0x1000);
        let source = [0x9100_0400u32, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        runtime.register_code(entry, source)?;
        let (fresh, original) = runtime.prepare_snapshot(entry)?;
        assert!(!fresh.prepared.cache_hit);
        let (hit, checked) = runtime.prepare_snapshot(entry)?;
        assert!(hit.prepared.cache_hit);
        assert_eq!(hit.prepared.key, fresh.prepared.key);
        assert_eq!(checked, original);
        assert_eq!(
            hit.prepared.manifest.native_sha256,
            stela_formats::sha256(&checked)
        );

        let mut corrupted = original;
        corrupted[0] ^= 1;
        std::fs::write(hit.prepared.directory.join("native.bin"), &corrupted)?;
        assert!(matches!(
            runtime.prepare_snapshot(entry),
            Err(crate::Error::InvalidCacheEntry { .. })
        ));
        assert_ne!(checked, corrupted);
        Ok(())
    }
}
