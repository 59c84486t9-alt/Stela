//! Refusals before lending a native frame. Diagnostics are allocated
//! only on failure; successful preparation carries no additional provenance.
use super::*;
use crate::machine::engine::{Requirement, RequirementKind, Stop};

#[derive(Debug)]
pub(in crate::machine::engine::shared_memory) struct PreparationFailure {
    pub(super) status: MemoryStatus,
    stage: &'static str,
    source: Option<(usize, u64, u8)>,
    first_word: Option<u32>,
    detail: Option<alloc::string::String>,
}

impl From<MemoryStatus> for PreparationFailure {
    fn from(status: MemoryStatus) -> Self {
        Self {
            status,
            stage: "cohort ownership",
            source: None,
            first_word: None,
            detail: None,
        }
    }
}

impl PreparationFailure {
    pub(super) fn at(
        stage: &'static str,
        status: MemoryStatus,
        source: (usize, u64, u8),
        first_word: Option<u32>,
    ) -> Self {
        Self {
            stage,
            status,
            source: Some(source),
            first_word,
            detail: None,
        }
    }

    pub(super) fn detail(mut self, detail: alloc::string::String) -> Self {
        self.detail = Some(detail);
        self
    }

    pub(in crate::machine::engine::shared_memory) fn into_stop(
        self,
        fallback_pc: u64,
        fallback_el: u8,
    ) -> Stop {
        use core::fmt::Write;
        let mut detail = alloc::format!(
            "{} refused before execution: status={:?}",
            self.stage,
            self.status
        );
        let (pc, el) = if let Some((pe, pc, el)) = self.source {
            write!(detail, " PE={pe} block_start={pc:#x}").unwrap();
            (pc, el)
        } else {
            (fallback_pc, fallback_el)
        };
        if let Some(word) = self.first_word {
            write!(detail, " first_word={word:#010x}").unwrap();
        }
        if let Some(reason) = self.detail {
            write!(detail, ": {reason}").unwrap();
        }
        Stop::Unsupported(Requirement {
            pc,
            el,
            link: 0,
            kind: RequirementKind::NativePreparation(detail),
            syndrome: None,
            address: None,
            written: None,
        })
    }
}
