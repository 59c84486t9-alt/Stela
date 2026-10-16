//! A view of a retired System instruction and its native source pin, owned by
//! Active. It allocates, fetches and caches nothing.
use crate::{
    blocks::retirement::ConsumerKey,
    memory::domain::physical::BoundPhysicalInstruction,
    system::{execution::EntryBoundary, translation_controls::PhysicalFetch},
};
use stela_compiler::block::SystemInstruction;

pub(crate) struct RetiredInstructionSource<'pin> {
    entry: &'pin EntryBoundary,
    instruction: SystemInstruction,
    physical: &'pin BoundPhysicalInstruction,
}
impl<'pin> RetiredInstructionSource<'pin> {
    pub(in crate::blocks::retirement::checked) fn borrow(
        _consumer: &ConsumerKey,
        entry: &'pin EntryBoundary,
        instruction: SystemInstruction,
        physical: &'pin BoundPhysicalInstruction,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            instruction.matches_source(entry.entry(), entry.word())
                && physical.raw_pc() == entry.entry().0
                && physical.word() == entry.word()
                && physical.is_current()
                && physical.bytes_are_current(),
            "retired boundary differs from native source pin"
        );
        Ok(Self {
            entry,
            instruction,
            physical,
        })
    }
    pub(crate) fn entry(&self) -> &EntryBoundary {
        self.entry
    }
    pub(crate) fn instruction(&self) -> SystemInstruction {
        self.instruction
    }
    pub(crate) fn source_pin(&self) -> &BoundPhysicalInstruction {
        self.physical
    }
    pub(crate) fn physical_fetch(&self) -> PhysicalFetch {
        PhysicalFetch {
            pc: self.physical.raw_pc(),
            word: self.physical.word(),
            physical_address: self.physical.physical_address(),
            source_generation: self.entry.generation(),
        }
    }
}
