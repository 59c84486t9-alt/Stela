//! Physical instruction identities on the actual serialized source/RX owner.
//!
//! Private source-binding seam only. The complete TranslationServices adapter
//! additionally needs reviewed current-control consumers, canonical fetch and
//! real post-return runtime entry hooks. No service succeeds from this leaf alone.

use super::{BlockRuntime, INSTRUCTION_BYTES};
use crate::{
    memory::domain::physical::BoundPhysicalInstruction,
    system::translation_controls::{ControlSnapshot, PhysicalFetch},
};
use anyhow::{Result, ensure};
use stela_compiler::GuestAddress;

/// Kept inside the existing CodeRegion, beside its one immutable source box.
/// The snapshot is a derived validity witness, not another mutable register bank.
pub(super) struct PhysicalCodeBinding {
    instruction: BoundPhysicalInstruction,
    snapshot: ControlSnapshot,
}

impl std::fmt::Debug for PhysicalCodeBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhysicalCodeBinding")
            .field("raw_pc", &self.instruction.raw_pc())
            .field("physical_address", &self.instruction.physical_address())
            .field("word", &self.instruction.word())
            .field("backing", &self.instruction.backing().id())
            .field("backing_offset", &self.instruction.backing_offset())
            .field("control_generation", &self.snapshot.generation())
            .finish_non_exhaustive()
    }
}

impl PhysicalCodeBinding {
    fn matches_binding(
        &self,
        instruction: &BoundPhysicalInstruction,
        snapshot: &ControlSnapshot,
    ) -> bool {
        self.snapshot.same_pe(snapshot)
            && self.snapshot.generation() == snapshot.generation()
            && self.instruction.is_current()
            && self.instruction.same_source(instruction)
    }

    fn matches_fetch(
        &self,
        snapshot: &ControlSnapshot,
        source: PhysicalFetch,
        generation: u64,
    ) -> bool {
        self.snapshot.same_pe(snapshot)
            && self.snapshot.generation() == snapshot.generation()
            && generation == source.source_generation
            && self.instruction.raw_pc() == source.pc
            && self.instruction.physical_address() == source.physical_address
            && self.instruction.word() == source.word
            && self.instruction.is_current()
    }
}

impl BlockRuntime {
    /// Add the actual reached word to the existing source/RX cache.
    ///
    /// This initial private control-transition cohort registers one instruction
    /// per source region. It is not a production block-size/performance choice.
    /// A different backing, offset, view generation or control generation retires
    /// the old RX through the existing register_code replacement path.
    pub(crate) fn bind_physical_instruction(
        &mut self,
        snapshot: &ControlSnapshot,
        instruction: BoundPhysicalInstruction,
    ) -> Result<PhysicalFetch> {
        ensure!(
            instruction.is_current(),
            "retired physical instruction source"
        );
        let pc = instruction.raw_pc();
        let physical_address = instruction.physical_address();
        let word = instruction.word();
        if let Some(region) = self.regions.get(&pc)
            && region.source.len() == INSTRUCTION_BYTES
            && region
                .physical_binding
                .as_ref()
                .is_some_and(|binding| binding.matches_binding(&instruction, snapshot))
        {
            return Ok(PhysicalFetch {
                pc,
                word,
                physical_address,
                source_generation: region.generation,
            });
        }
        // Source allocation occurs before replacement. register_code performs
        // checked range/generation/overlap validation before retiring old RX.
        let source = word.to_le_bytes().to_vec();
        let generation = self.register_code(GuestAddress(pc), source)?;
        let region = self
            .regions
            .get_mut(&pc)
            .expect("successful source registration owns its exact base");
        region.physical_binding = Some(PhysicalCodeBinding {
            instruction,
            snapshot: snapshot.clone(),
        });
        Ok(PhysicalFetch {
            pc,
            word,
            physical_address,
            source_generation: generation,
        })
    }

    /// Validate actual source/physical/control identities, without CSE or mutation.
    /// The reached instruction comes from a fresh canonical Fetch under current
    /// controls, including permissions. Compare its actual physical/view identity;
    /// equal copied metadata or an old cache entry never substitutes for that fetch.
    pub(crate) fn check_physical_source(
        &self,
        snapshot: &ControlSnapshot,
        source: PhysicalFetch,
        reached: &BoundPhysicalInstruction,
    ) -> Result<(), &'static str> {
        let region = self
            .regions
            .get(&source.pc)
            .ok_or("physical source registration is absent")?;
        let binding = region
            .physical_binding
            .as_ref()
            .ok_or("source registration has no physical owner")?;
        if region.source.len() != INSTRUCTION_BYTES
            || region.source.as_ref() != source.word.to_le_bytes()
            || !binding.matches_fetch(snapshot, source, region.generation)
            || !reached.is_current()
            || !binding.matches_binding(reached, snapshot)
        {
            return Err("physical source, control or mapping generation is stale");
        }
        Ok(())
    }

    /// Retire this PE's derived code dependencies before a changed current context.
    /// This conservative implementation-cache action is not architectural TLBI.
    /// No new allocation or failure occurs after the prepared control commit.
    pub(crate) fn retire_translation_sources(&mut self) {
        self.regions
            .retain(|_, region| region.physical_binding.is_none());
        self.loaded.retain(|_, block| {
            self.regions
                .get(&block.region_base)
                .is_some_and(|region| region.generation == block.generation)
        });
    }
}

#[path = "translation/owner.rs"]
mod owner;
#[path = "translation/profile.rs"]
mod profile;
#[path = "translation/scope.rs"]
mod scope;
#[path = "translation/source_lease.rs"]
mod source_lease;
pub(super) use owner::{
    InstalledEl1Owner, InstalledEl1Sources, InstalledM0Owner, InstalledM0Sources,
};
#[path = "translation/el1_source_lease.rs"]
mod el1_source_lease;
pub(crate) use el1_source_lease::InstalledEl1SourceScope;
pub(crate) use source_lease::InstalledM0SourceScope;

// Required by the original Initial publication/fetch service; grants no public owner entry.
pub(crate) use scope::ControlCodeScope;
