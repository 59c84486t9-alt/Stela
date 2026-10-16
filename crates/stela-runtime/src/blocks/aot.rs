//! Existing-format AOT intake into the original loaded-block/runtime path.
//! Bytes/manifest/plan are descriptive; original BoundSource/Active/source and
//! physical/control/retirement owners still qualify every actual native call.

use super::*;
use crate::artifact::{LoadedArtifact, prepare};
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};
use stela_compiler::block::CompilationPlan;

const MAX_MANIFEST_CHECKSUM_BYTES: usize = 1024;

#[derive(Debug)]
pub(super) enum ArtifactPreparation {
    #[cfg(feature = "std")]
    HostedCache(PathBuf),
    AheadOfTime,
}

impl ArtifactPreparation {
    #[cfg(feature = "std")]
    pub(super) fn cache_root(&self, pc: GuestAddress) -> Result<&Path> {
        match self {
            Self::HostedCache(root) => Ok(root),
            Self::AheadOfTime => anyhow::bail!(
                "AOT block unavailable at {:#x}; runtime compilation is unsupported",
                pc.0
            ),
        }
    }
}

impl LoadedBlock {
    // SAME original storage publication/check/insertion data for both intake
    // paths. Descriptive metadata cannot replace BoundSource or PE admission.
    pub(super) fn from_artifact(
        target: stela_compiler::TargetCpu,
        profile: BlockProfile,
        region_base: u64,
        generation: u64,
        source_bytes: usize,
        prepared: LoadedArtifact,
        native: &[u8],
    ) -> Result<Self> {
        ensure!(
            crate::platform::cpu::admitted(target),
            "host CPU lacks generated-code requirements {}",
            target.id()
        );
        let mapping = platform::Mapping::new(native)?;
        serialize_instruction_execution()?;
        Ok(Self {
            profile,
            region_base,
            generation,
            source_bytes,
            prepared,
            mapping,
        })
    }
}

impl BlockRuntime {
    pub(super) fn with_preparation(
        address_space: u64,
        profile: BlockProfile,
        target: stela_compiler::TargetCpu,
        preparation: ArtifactPreparation,
    ) -> Self {
        Self {
            identity: alloc::sync::Arc::new(()),
            address_space,
            profile,
            target,
            preparation,
            next_generation: 0,
            regions: BTreeMap::new(),
            loaded: BTreeMap::new(),
            _serialized: PhantomData,
        }
    }

    /// New original runtime using explicit AOT intake. A missing loaded body
    /// declines before disk-cache access or runtime emission. This changes only
    /// artifact availability; it grants no CPU, source, mapping or PE permission.
    /// Plain TargetCpu is requirements metadata, not hardware qualification.
    pub fn new_aot_for_target(
        address_space: u64,
        profile: BlockProfile,
        target: stela_compiler::TargetCpu,
    ) -> Self {
        Self::with_preparation(
            address_space,
            profile,
            target,
            ArtifactPreparation::AheadOfTime,
        )
    }

    /// Mount standard manifest.json / manifest.sha256.json / native.bin bytes.
    /// No alternate bundle codec or supplied source plan is accepted. Expected
    /// identity/profile/requirements come from the SAME compiler plan over this
    /// runtime's actual registered immutable source; source/PE ownership remains
    /// with the canonical parent. Original source maps and native checks precede
    /// RX storage publication. No native instructions or guest data are executed.
    pub fn preload_artifact(
        &mut self,
        pc: GuestAddress,
        manifest_bytes: &[u8],
        manifest_checksum_json: &[u8],
        native: &[u8],
    ) -> Result<()> {
        ensure!(pc.0.is_multiple_of(4), "unaligned preparation entry");
        ensure!(
            !self.loaded.contains_key(&pc.0),
            "native block already loaded"
        );
        let (base, region) = self.region(pc).context("unmapped preparation entry")?;
        ensure!(region.end - pc.0 >= 4, "truncated preparation instruction");
        let offset = usize::try_from(pc.0 - base)?;
        let available = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS) * 4;
        let generation = region.generation;
        let window = &region.source[offset..offset + available];
        let analysis = analyze_with_profile(window, pc, self.profile)?;
        let plan =
            CompilationPlan::new(window, pc, self.profile, self.target)?.with_resident_loops();
        let profile = plan.profile();
        let source_bytes = plan.source_bytes();
        ensure!(
            source_bytes == analysis.source_bytes,
            "prepared block analysis extent mismatch"
        );
        let expected_identity = crate::block_plan_identity(window, pc, self.target, &plan)?;

        // Preserve the hosted byte/provider rejection order, including checksum
        // codec before digest, then CPA specialization before fresh metadata.
        ensure!(
            manifest_bytes.len() <= prepare::MAX_CACHE_MANIFEST_BYTES,
            "cache file exceeds size limit"
        );
        ensure!(
            manifest_checksum_json.len() <= MAX_MANIFEST_CHECKSUM_BYTES,
            "cache file exceeds size limit"
        );
        let expected: String = serde_json::from_slice(manifest_checksum_json)?;
        prepare::validate_manifest_bytes(manifest_bytes, &expected)?;
        let manifest: crate::Manifest = serde_json::from_slice(manifest_bytes)?;
        ensure!(
            manifest.identity.memory_specialization_sha256
                == crate::memory_specialization_sha256(profile, manifest.memory_requirements)?,
            "cached memory specialization differs from complete requirements"
        );
        prepare::validate_preparation_metadata(
            &manifest,
            &expected_identity,
            plan.memory_requirements(),
        )?;
        prepare::validate_preparation_native(&manifest, native)
            .context("cached native code checksum mismatch")?;
        prepare::validate_preparation_claim(&manifest)?;
        validate_source_map(&manifest, pc, source_bytes)?;
        let prepared = LoadedArtifact::bind(manifest, native)
            .context("block native snapshot checksum mismatch")?;
        let block = LoadedBlock::from_artifact(
            self.target,
            profile,
            base,
            generation,
            source_bytes,
            prepared,
            native,
        )?;
        self.loaded.insert(pc.0, block);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
