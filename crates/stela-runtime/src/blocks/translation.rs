//! Physical instruction fetch for translation.

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

impl core::fmt::Debug for PhysicalCodeBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            && self.instruction.bytes_are_current()
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
            && self.instruction.bytes_are_current()
    }
}

impl BlockRuntime {
    /// Add the fetched word to the source and native-code cache.
    ///
    /// Each source region holds one instruction. A different backing, offset,
    /// view generation or control generation retires the old native code
    /// through `register_code`.
    pub(crate) fn bind_physical_instruction(
        &mut self,
        snapshot: &ControlSnapshot,
        instruction: BoundPhysicalInstruction,
    ) -> Result<PhysicalFetch> {
        ensure!(
            instruction.is_current() && instruction.bytes_are_current(),
            "retired physical instruction source"
        );
        // Every source region here is one instruction, so an M0 write block
        // returns at that write and nothing stale can run before the next
        // fetch.
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

    /// Validate the source, physical and control identities without side
    /// effects. The instruction comes from a fresh fetch under the current
    /// controls, including permissions; matching metadata or an old cache entry
    /// never replaces that fetch.
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
            || !reached.bytes_are_current()
            || !binding.matches_binding(reached, snapshot)
        {
            return Err("physical source, control or mapping generation is stale");
        }
        Ok(())
    }

    /// Called after a mutable-source write completes and every native and
    /// source borrow has ended. Stale compiled snapshots stay pinned until
    /// their last user leaves, then the dependent native code is retired before
    /// dispatch.
    pub(crate) fn retire_mutated_translation_sources(&mut self) {
        self.regions.retain(|_, region| {
            region.physical_binding.as_ref().is_none_or(|binding| {
                binding.instruction.is_current() && binding.instruction.bytes_are_current()
            })
        });
        self.loaded.retain(|_, block| {
            self.regions
                .get(&block.region_base)
                .is_some_and(|region| region.generation == block.generation)
        });
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

mod owner;
mod profile;
mod scope;
mod source_lease;
mod stage1_cache;
pub(super) use owner::{
    InstalledEl1Owner, InstalledEl1Sources, InstalledM0Owner, InstalledM0Sources,
};
mod el1_source_lease;
pub(crate) use el1_source_lease::{InstalledEl1SourceScope, walked::InstalledWalkedSource};
pub(crate) use source_lease::InstalledM0SourceScope;

// Used by initial publication and fetch.
pub(crate) use scope::ControlCodeScope;
