//! Invocation-kept source/profile and installed native recovery owners.
use super::stored::Emission;
use super::{NativeCode, NativeFault, Preparation};
use crate::translations::StoredBlock;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use stela_compiler::NativeBlock;
use stela_compiler::block::{
    CompiledBlock, FaultRecovery, RecoveryQualificationError, RecoveryTemplate,
    UnqualifiedFaultRecovery,
};
use stela_compiler::x86_64::chain::DirectExit;

/// A block's native template, admitted input and recovery rows as
/// installation consumes them: for a block compiled in this process, the
/// emission the store and other PEs share.
pub(super) struct Template {
    emission: Arc<Emission>,
    /// A stored record's portable rows, which carry no minted permission.
    pending: Option<Box<[UnqualifiedFaultRecovery]>>,
}

/// An installed block's recovery owner: its code's length and the rows that
/// locate guest state at each faultable site of it.
pub(super) struct CodeRecovery {
    code_bytes: usize,
    rows: Rows,
    #[cfg(test)]
    qualification_attempts: usize,
}

enum Rows {
    Qualified(Box<[FaultRecovery]>),
    /// A stored record's template and portable rows, which its first fault
    /// emits again to qualify: replaced by the minted rows, never kept
    /// beside them.
    Pending {
        template: Arc<Emission>,
        rows: Box<[UnqualifiedFaultRecovery]>,
    },
}

/// A terminal native implementation failure. Captured data and code owners stay
/// on the stopped Machine; a caller cannot resume a partially committed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFailure {
    pub pc: u64,
    pub code: Option<NativeCode>,
    pub native_offset: usize,
    pub address: u64,
    pub origin: super::NativeFaultOrigin,
    pub trap: u16,
    pub error_code: u64,
    pub unsettled_chain: Option<UnsettledChain>,
    pub reason: NativeFailureReason,
}
/// Native control counters copied after return, without granting a resumable
/// architectural boundary or claiming that completed memory effects rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsettledChain {
    pub reported_retired: u64,
    pub last_block: u64,
    pub lookup_hits: u64,
    pub direct_links: u64,
}
pub(super) struct CapturedFailure {
    pub(super) summary: Arc<NativeFailure>,
    pub(super) capture: NativeFault,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFailureReason {
    CanonicalDomain { pe: usize, retired_before: u64 },
    UnknownCode,
    CodeExtent,
    InternalSite,
    TrapSiteMismatch,
    Position,
    Qualification(RecoveryQualificationError),
    Recovery(stela_compiler::block::FaultRecoveryError),
}

impl Template {
    /// The template of a block compiled in this process, here or by a PE
    /// that shared it through the store.
    pub(super) fn compiled(emission: Arc<Emission>) -> Self {
        Self {
            emission,
            pending: None,
        }
    }
    pub(super) fn stored(
        template: StoredBlock,
        input: Vec<u8>,
        preparation: Arc<Preparation>,
    ) -> Self {
        let block = CompiledBlock {
            native: template.native,
            source_bytes: template.source_bytes,
            direct_exits: template.direct_exits,
            fault_recovery: Vec::new(),
        };
        Self {
            emission: Arc::new(Emission::new(input, block, preparation)),
            pending: Some(template.fault_recovery.into_boxed_slice()),
        }
    }

    /// The native template.
    pub(super) fn native(&self) -> &NativeBlock {
        &self.emission.block.native
    }
    /// The guest bytes its native template consumed.
    pub(super) fn source_bytes(&self) -> usize {
        self.emission.block.source_bytes
    }
    /// The native template's direct exits to static successors.
    pub(super) fn direct_exits(&self) -> &[DirectExit] {
        &self.emission.block.direct_exits
    }
    /// A portable request may only reject this legacy implementation. Absence
    /// of tags never grants private/APX admission: that must be derived from an
    /// compiler/profile ABI permit before future eager invocation.
    pub(super) fn portable_requires_unavailable_capture(&self) -> bool {
        use stela_compiler::block::{
            RecoveryBinding, RecoverySource, RetirementPhase, RetirementPoint,
        };
        let requires = |retirement: RetirementPoint, bindings: &[RecoveryBinding]| {
            retirement.phase() != RetirementPhase::Before
                || bindings.iter().any(|binding| match binding.source {
                    RecoverySource::HostRegister(register) => register >= 16,
                    RecoverySource::NativeSpill(_) => true,
                })
        };
        match &self.pending {
            Some(rows) => rows
                .iter()
                .any(|row| requires(row.retirement, &row.bindings)),
            None => self
                .emission
                .block
                .fault_recovery
                .iter()
                .any(|row| requires(row.retirement, &row.bindings)),
        }
    }
    pub(super) fn matches_source(&self, source: &[u8]) -> bool {
        source.get(..self.emission.input.len()) == Some(self.emission.input.as_slice())
    }

    /// The owner of the installed template: its rows, moved when no one
    /// else shares the emission. Only a stored record keeps its template,
    /// until its first fault qualifies the rows.
    pub(super) fn installed(self) -> CodeRecovery {
        let code_bytes = self.emission.block.native.x86_64_code.len();
        let rows = match self.pending {
            Some(rows) => Rows::Pending {
                template: self.emission,
                rows,
            },
            None => Rows::Qualified(match Arc::try_unwrap(self.emission) {
                Ok(emission) => emission.block.fault_recovery.into_boxed_slice(),
                Err(shared) => shared.block.fault_recovery.as_slice().into(),
            }),
        };
        CodeRecovery {
            code_bytes,
            rows,
            #[cfg(test)]
            qualification_attempts: 0,
        }
    }
}

impl CodeRecovery {
    /// The installed code's length.
    pub(super) fn code_bytes(&self) -> usize {
        self.code_bytes
    }

    /// Make the owner a stored record's: `template`'s, whose rows are this
    /// owner's own, unqualified.
    #[cfg(test)]
    pub(super) fn test_make_pending(&mut self, template: Arc<Emission>) {
        let rows = self.test_portable_rows().into_boxed_slice();
        self.rows = Rows::Pending { template, rows };
    }
    #[cfg(test)]
    pub(super) fn test_rows_mut(&mut self) -> &mut [FaultRecovery] {
        match &mut self.rows {
            Rows::Qualified(rows) => rows,
            Rows::Pending { .. } => panic!("actual emitted plan"),
        }
    }
    #[cfg(test)]
    pub(super) fn test_portable_rows(&self) -> Vec<UnqualifiedFaultRecovery> {
        match &self.rows {
            Rows::Pending { rows, .. } => rows.to_vec(),
            Rows::Qualified(rows) => rows.iter().map(UnqualifiedFaultRecovery::from).collect(),
        }
    }
    #[cfg(test)]
    pub(super) fn test_pending_rows_mut(&mut self) -> &mut [UnqualifiedFaultRecovery] {
        match &mut self.rows {
            Rows::Pending { rows, .. } => rows,
            Rows::Qualified(_) => panic!("explicitly pending fixture"),
        }
    }
    #[cfg(test)]
    pub(super) fn test_push_pending(&mut self, row: UnqualifiedFaultRecovery) {
        let Rows::Pending { rows, .. } = &mut self.rows else {
            panic!("explicitly pending fixture");
        };
        let mut pushed = rows.to_vec();
        pushed.push(row);
        *rows = pushed.into_boxed_slice();
    }

    /// The rows, qualifying a stored record's on its first fault at `pc`, the
    /// block's entry: in the dispatcher, before any guest projection.
    pub(super) fn qualify(&mut self, pc: u64) -> Result<&[FaultRecovery], NativeFailureReason> {
        #[cfg(test)]
        if matches!(self.rows, Rows::Pending { .. }) {
            self.qualification_attempts += 1;
        }
        if let Rows::Pending { template, rows } = &self.rows {
            let block = template
                .preparation
                .qualify_recovery(
                    &template.input,
                    pc,
                    RecoveryTemplate {
                        code: &template.block.native.x86_64_code,
                        source_map: &template.block.native.source_map,
                        source_bytes: template.block.source_bytes,
                        direct_exits: &template.block.direct_exits,
                        recovery: rows,
                    },
                )
                .map_err(NativeFailureReason::Qualification)?;
            self.rows = Rows::Qualified(block.fault_recovery.into_boxed_slice());
        }
        let Rows::Qualified(rows) = &self.rows else {
            unreachable!("qualified above");
        };
        Ok(rows)
    }
}

#[cfg(test)]
mod tests;
