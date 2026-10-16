//! Virtual instruction fetch with the MMU enabled.
use super::{BoundPhysicalInstruction, PhysicalAddressSpace};
use crate::{blocks::InstalledWalkedSource, system::translation_controls::FetchFailure};
impl PhysicalAddressSpace {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "enabled-source component remains unmounted")
    )]
    pub(crate) fn fetch_walked_instruction(
        &self,
        source: &InstalledWalkedSource<'_, '_>,
        raw_pc: u64,
    ) -> Result<BoundPhysicalInstruction, FetchFailure> {
        if !core::ptr::eq(self, source.physical_space()) {
            return Err(FetchFailure::Unavailable(
                "walked fetch uses different physical owner",
            ));
        }
        let translation = source.canonical_fetch(raw_pc)?;
        source.check_fetch_policy(&translation, raw_pc)?;
        let reached = self
            .read_instruction(
                source.execution(),
                &translation,
                raw_pc,
                source.immutable_sources(),
                source.source_cache_controls(),
            )
            .map_err(FetchFailure::Platform)?;
        source.check_source_word(raw_pc, reached.word())?;
        source.check_current()?;
        Ok(reached)
    }
}
