//! Invocation-kept source/profile and installed native recovery owners.
use super::stored::Emission;
use super::{NativeCode, NativeFault, Preparation, table::Table};
use crate::translations::{Digest, Record, StoredBlock};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use stela_compiler::NativeBlock;
use stela_compiler::block::{
    CompiledBlock, FaultRecovery, PackedRecovery, RecoveryQualificationError, RecoveryTemplate,
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
    /// Where those rows stay once installed, at this page offset.
    origin: Option<(Arc<StoredOrigin>, u16)>,
}

/// Where a stored block's record lies: everything but the page offset of its
/// entry, shared by the blocks of a page. The pack outlives every machine,
/// so a block keeps this and not a copy of its entry.
pub(super) struct StoredOrigin {
    pub(super) key: Digest,
    pub(super) context: Digest,
    pub(super) page: u64,
    pub(super) preparation: Arc<Preparation>,
}

/// An installed block's recovery owner: its code's length and the rows that
/// locate guest state at each faultable site of it.
pub(super) struct CodeRecovery {
    rows: Rows,
    #[cfg(test)]
    qualification_attempts: usize,
}

enum Rows {
    Qualified {
        code_bytes: u32,
        rows: PackedRecovery,
    },
    /// A stored record's entry, whose template and portable rows its first
    /// fault reads and emits again to qualify: replaced by the minted rows.
    Stored {
        origin: Arc<StoredOrigin>,
        code_bytes: u32,
        offset: u16,
    },
    /// A template and portable rows in hand, as a record's entry gives them.
    #[cfg(test)]
    Pending {
        template: Arc<Emission>,
        rows: Box<[UnqualifiedFaultRecovery]>,
        code_bytes: u32,
    },
}

// The code length shares the per-variant space of the row storage. Every
// installed block uses one slot, including those with no guest fault sites.
#[cfg(not(test))]
const _: () = assert!(core::mem::size_of::<Option<CodeRecovery>>() <= 24);

/// The installed blocks' recovery owners, by block slot.
pub(super) struct Owners {
    slots: Table<Option<CodeRecovery>>,
}

impl Owners {
    pub(super) const fn new() -> Self {
        Self {
            slots: Table::new(),
        }
    }

    pub(super) fn get(&self, slot: &usize) -> Option<&CodeRecovery> {
        (*slot < self.slots.len())
            .then(|| self.slots[*slot].as_ref())
            .flatten()
    }

    pub(super) fn get_mut(&mut self, slot: &usize) -> Option<&mut CodeRecovery> {
        (*slot < self.slots.len())
            .then(|| self.slots[*slot].as_mut())
            .flatten()
    }

    pub(super) fn insert(&mut self, slot: usize, owner: CodeRecovery) {
        while self.slots.len() <= slot {
            self.slots.push(None);
        }
        self.slots[slot] = Some(owner);
    }

    pub(super) fn remove(&mut self, slot: &usize) -> Option<CodeRecovery> {
        (*slot < self.slots.len())
            .then(|| self.slots[*slot].take())
            .flatten()
    }

    pub(super) fn clear(&mut self) {
        self.slots.clear();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }
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
    CanonicalDomain {
        pe: usize,
        retired_before: u64,
    },
    UnknownCode,
    CodeExtent,
    InternalSite,
    TrapSiteMismatch,
    Position,
    Qualification(RecoveryQualificationError),
    /// The pack no longer gives a stored block's entry.
    StoredRecord,
    Recovery(stela_compiler::block::FaultRecoveryError),
}

impl Template {
    /// The template of a block compiled in this process, here or by a PE
    /// that shared it through the store.
    pub(super) fn compiled(emission: Arc<Emission>) -> Self {
        Self {
            emission,
            pending: None,
            origin: None,
        }
    }
    pub(super) fn stored(
        template: StoredBlock,
        input: Vec<u8>,
        preparation: Arc<Preparation>,
        origin: Option<(Arc<StoredOrigin>, u16)>,
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
            origin,
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

    /// The owner of the installed template: its rows, packed, or for a stored
    /// record where they are, until its first fault qualifies them.
    pub(super) fn installed(self) -> CodeRecovery {
        let code_bytes = self.emission.block.native.x86_64_code.len() as u32;
        let rows = match (self.origin, self.pending) {
            (Some((origin, offset)), _) => Rows::Stored {
                origin,
                code_bytes,
                offset,
            },
            #[cfg(test)]
            (None, Some(rows)) => Rows::Pending {
                template: self.emission,
                rows,
                code_bytes,
            },
            _ => Rows::Qualified {
                code_bytes,
                rows: PackedRecovery::new(&self.emission.block.fault_recovery),
            },
        };
        CodeRecovery {
            rows,
            #[cfg(test)]
            qualification_attempts: 0,
        }
    }
}

impl CodeRecovery {
    /// The installed code's length.
    pub(super) fn code_bytes(&self) -> usize {
        self.rows.code_bytes() as usize
    }

    /// Make the owner a stored record's: `template`'s, whose rows are this
    /// owner's own, unqualified.
    #[cfg(test)]
    pub(super) fn test_make_pending(&mut self, template: Arc<Emission>) {
        let rows = self.test_portable_rows().into_boxed_slice();
        self.rows = Rows::Pending {
            template,
            rows,
            code_bytes: self.rows.code_bytes(),
        };
    }
    /// The rows of an actual emitted plan.
    #[cfg(test)]
    pub(super) fn test_rows(&self) -> Vec<FaultRecovery> {
        match &self.rows {
            Rows::Qualified { rows, .. } => rows.rows(),
            _ => panic!("actual emitted plan"),
        }
    }
    /// Change the rows of an actual emitted plan.
    #[cfg(test)]
    pub(super) fn test_edit_rows<T>(&mut self, edit: impl FnOnce(&mut [FaultRecovery]) -> T) -> T {
        let Rows::Qualified { rows: packed, .. } = &mut self.rows else {
            panic!("actual emitted plan");
        };
        let mut rows = packed.rows();
        let result = edit(&mut rows);
        *packed = PackedRecovery::new(&rows);
        result
    }
    #[cfg(test)]
    pub(super) fn test_packed_bytes(&self) -> usize {
        match &self.rows {
            Rows::Qualified { rows, .. } => rows.bytes(),
            _ => panic!("actual emitted plan"),
        }
    }
    #[cfg(test)]
    pub(super) fn test_portable_rows(&self) -> Vec<UnqualifiedFaultRecovery> {
        match &self.rows {
            Rows::Pending { rows, .. } => rows.to_vec(),
            Rows::Stored { .. } => panic!("explicitly pending fixture"),
            Rows::Qualified { rows, .. } => rows
                .rows()
                .iter()
                .map(UnqualifiedFaultRecovery::from)
                .collect(),
        }
    }
    #[cfg(test)]
    pub(super) fn test_pending_rows_mut(&mut self) -> &mut [UnqualifiedFaultRecovery] {
        match &mut self.rows {
            Rows::Pending { rows, .. } => rows,
            _ => panic!("explicitly pending fixture"),
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

    /// The key of the record whose entry this owner's rows still are.
    pub(super) fn stored_key(&self) -> Option<Digest> {
        match &self.rows {
            Rows::Stored { origin, .. } => Some(origin.key),
            _ => None,
        }
    }

    /// The rows, qualifying a stored record's on its first fault at `pc`, the
    /// block's entry: in the dispatcher, before any guest projection. `record`
    /// is the one [`Self::stored_key`] names.
    pub(super) fn qualify(
        &mut self,
        pc: u64,
        record: Option<&Record>,
    ) -> Result<Vec<FaultRecovery>, NativeFailureReason> {
        #[cfg(test)]
        if !matches!(self.rows, Rows::Qualified { .. }) {
            self.qualification_attempts += 1;
        }
        let block = match &self.rows {
            Rows::Qualified { rows, .. } => return Ok(rows.rows()),
            Rows::Stored { origin, offset, .. } => {
                let entry = record
                    .and_then(|record| record.find(*offset, &origin.context))
                    .ok_or(NativeFailureReason::StoredRecord)?;
                let stored = entry
                    .rebase(origin.page, &entry.input)
                    .ok_or(NativeFailureReason::StoredRecord)?;
                origin.preparation.qualify_recovery(
                    &entry.input,
                    pc,
                    RecoveryTemplate {
                        code: &stored.native.x86_64_code,
                        source_map: &stored.native.source_map,
                        source_bytes: stored.source_bytes,
                        direct_exits: &stored.direct_exits,
                        recovery: &stored.fault_recovery,
                    },
                )
            }
            #[cfg(test)]
            Rows::Pending { template, rows, .. } => template.preparation.qualify_recovery(
                &template.input,
                pc,
                RecoveryTemplate {
                    code: &template.block.native.x86_64_code,
                    source_map: &template.block.native.source_map,
                    source_bytes: template.block.source_bytes,
                    direct_exits: &template.block.direct_exits,
                    recovery: rows,
                },
            ),
        }
        .map_err(NativeFailureReason::Qualification)?;
        self.rows = Rows::Qualified {
            code_bytes: self.rows.code_bytes(),
            rows: PackedRecovery::new(&block.fault_recovery),
        };
        Ok(block.fault_recovery)
    }
}

impl Rows {
    fn code_bytes(&self) -> u32 {
        match *self {
            Self::Qualified { code_bytes, .. } | Self::Stored { code_bytes, .. } => code_bytes,
            #[cfg(test)]
            Self::Pending { code_bytes, .. } => code_bytes,
        }
    }
}

#[cfg(test)]
mod tests;
