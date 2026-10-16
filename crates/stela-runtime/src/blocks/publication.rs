//! Borrowed source/RX publication authority for fixed EL1 exception execution.
//!
//! The actual runtime owns both source boxes and RX mappings. This borrow is
//! minted after native return and excludes replacement or reclamation until
//! completion returns; a generation number alone is not that exclusion.

use super::{BlockRuntime, serialize_instruction_execution, validate_terminal_word};
use crate::system::{
    exception::{Completion, EffectFailure, RequiredEffects, ServiceRequest},
    execution::Boundary,
    fixed_controls::FixedEl1Controls,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use stela_compiler::{
    GuestAddress,
    aarch64::system::exception::Operation,
    block::system::{SystemInstruction, SystemOperation},
};

struct SourceSite {
    address_space: u64,
    generation: u64,
    entry: GuestAddress,
    instruction: SystemInstruction,
    region_base: GuestAddress,
    registered_bytes: usize,
    consumed_bytes: usize,
}

/// A non-cloneable, post-return borrow of the actual registered code owner.
/// It exposes neither mutable source nor executable pointers. External memory
/// publication is not globally frozen; these private owners have no valid
/// writable MemoryBacking aliases in the supported fixed execution contract.
pub struct CodePublicationScope<'run> {
    runtime: &'run BlockRuntime,
    site: SourceSite,
}

impl<'run> CodePublicationScope<'run> {
    pub(crate) fn new(runtime: &'run BlockRuntime, boundary: &Boundary) -> Self {
        let source = boundary.source();
        Self {
            runtime,
            site: SourceSite {
                address_space: source.address_space(),
                generation: source.generation(),
                entry: source.entry(),
                instruction: boundary.instruction(),
                region_base: source.region_base(),
                registered_bytes: source.source_bytes(),
                consumed_bytes: boundary.consumed_bytes(),
            },
        }
    }

    /// Match the exact typed runtime boundary, rather than public PC/word
    /// metadata, and revalidate against the still-borrowed source owner.
    pub(crate) fn check_boundary(&self, boundary: &Boundary) -> Result<(), String> {
        let source = boundary.source();
        if source.address_space() != self.site.address_space
            || source.generation() != self.site.generation
            || source.entry() != self.site.entry
            || source.region_base() != self.site.region_base
            || source.source_bytes() != self.site.registered_bytes
            || boundary.consumed_bytes() != self.site.consumed_bytes
            || boundary.instruction() != self.site.instruction
        {
            return Err("code publication scope belongs to another boundary".into());
        }
        self.check_source()
    }

    pub(crate) fn check_exception_request(
        &self,
        controls: &FixedEl1Controls,
        request: &ServiceRequest,
    ) -> Result<(), String> {
        controls
            .check_exception_request(request)
            .map_err(|error| format!("fixed controls: {error:?}"))?;
        self.check_source()?;
        let matches_operation = matches!(
            (request.effects, self.site.instruction.operation),
            (
                RequiredEffects::Entry { irq: false },
                SystemOperation::Exception(
                    Operation::Undefined { .. } | Operation::SupervisorCall { .. }
                )
            ) | (
                RequiredEffects::Return,
                SystemOperation::Exception(Operation::ExceptionReturn { key: None })
            )
        );
        if request.source_pc != self.site.instruction.instruction_pc.0 || !matches_operation {
            return Err("fixed synchronization request differs from typed source".into());
        }
        Ok(())
    }

    /// Complete the actual host serializing component only after validating
    /// the immutable control owner and exact typed original source. No control,
    /// cache, TLBI, data, device or IRQ producer is admitted by this authority.
    pub(crate) fn synchronize_fixed_el1(
        &mut self,
        controls: &FixedEl1Controls,
        request: &ServiceRequest,
    ) -> Result<(), EffectFailure<String>> {
        self.check_exception_request(controls, request)
            .map_err(no_effect)?;
        // The supported helper has no fallible work after CPUID. An unsupported
        // host is declined before the host effect; no queued work is inferred.
        serialize_instruction_execution().map_err(|error| no_effect(error.to_string()))
    }

    fn check_source(&self) -> Result<(), String> {
        let (base, region) = self
            .runtime
            .region(self.site.entry)
            .ok_or("code publication source disappeared")?;
        if self.runtime.address_space() != self.site.address_space
            || base != self.site.region_base.0
            || region.generation != self.site.generation
            || region.source.len() != self.site.registered_bytes
        {
            return Err("code publication source identity changed".into());
        }
        let word = validate_terminal_word(
            self.site.entry,
            self.site.instruction.instruction_pc,
            self.site.consumed_bytes,
            base,
            &region.source,
        )
        .map_err(|error| error.to_string())?;
        if !self
            .site
            .instruction
            .matches_source(self.site.instruction.instruction_pc, word)
        {
            return Err("code publication original instruction changed".into());
        }
        Ok(())
    }
}

fn no_effect(error: String) -> EffectFailure<String> {
    EffectFailure {
        error,
        completion: Completion::None,
    }
}

#[cfg(test)]
mod tests;
