//! Invocation-retained source/profile and immutable native recovery templates.
use super::{Host, NativeCode, NativeFault, Preparation};
use crate::translations::{Digest, StoredBlock};
use alloc::collections::BTreeMap;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use stela_compiler::block::{
    CompiledBlock, FaultRecovery, RecoveryQualificationError, RecoveryTemplate,
    UnqualifiedFaultRecovery,
};
use stela_compiler::{NativeBlock, x86_64::chain::DirectExit};

#[derive(Clone)]
pub(super) struct OwnedPatch {
    pub(super) bytes: Vec<u8>,
    pub(super) purpose: PatchPurpose,
}
#[derive(Debug, Clone, Copy)]
pub(super) enum PatchPurpose {
    Chain,
    NativeAdapter { pc: u64, kind: NativeAdapter },
}
#[derive(Debug, Clone, Copy)]
pub(super) enum NativeAdapter {
    PointerAuthentication,
    MirroredRead,
}

pub(super) struct CodeTemplate {
    pub(super) native: NativeBlock,
    pub(super) source_bytes: usize,
    pub(super) direct_exits: Vec<DirectExit>,
}

/// An installed owner retains one row bank. Portable records have no minted
/// authority; successful lazy qualification replaces that bank, never duplicates it.
enum RecoveryRows {
    Pending(Box<[UnqualifiedFaultRecovery]>),
    Qualified(Box<[FaultRecovery]>),
}

pub(super) struct CodeRecovery {
    pub(super) template: CodeTemplate,
    input: Vec<u8>,
    preparation: Arc<Preparation>,
    rows: RecoveryRows,
    source_record: Option<SourceRecord>,
    source_record_checked: bool,
    #[cfg(test)]
    qualification_attempts: usize,
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
    pub source_record: Option<SourceRecord>,
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
/// Original raw-page lookup and admitted preparation binding retained after
/// cache eviction. The key describes the fetched page, not current data RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRecord {
    pub page: u64,
    pub raw_page_sha256: Digest,
    pub preparation_context: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFailureReason {
    CanonicalDomain { pe: usize, retired_before: u64 },
    UnknownCode,
    CodeExtent,
    CodeReadback,
    LiveCodeMismatch,
    PatchPlan,
    InternalSite,
    TrapSiteMismatch,
    Position,
    SourceContext,
    Qualification(RecoveryQualificationError),
    Recovery(stela_compiler::block::FaultRecoveryError),
}
impl CodeRecovery {
    pub(super) fn source_record(&self) -> Option<SourceRecord> {
        self.source_record
    }
    pub(super) fn with_record(mut self, record: SourceRecord) -> Self {
        self.source_record = Some(record);
        self.source_record_checked = false;
        self
    }

    #[cfg(test)]
    pub(super) fn test_make_pending(&mut self) {
        self.rows = RecoveryRows::Pending(self.test_portable_rows().into_boxed_slice());
    }
    #[cfg(test)]
    pub(super) fn test_rows_mut(&mut self) -> &mut [FaultRecovery] {
        match &mut self.rows {
            RecoveryRows::Qualified(rows) => rows,
            RecoveryRows::Pending(_) => panic!("actual emitted plan"),
        }
    }
    #[cfg(test)]
    pub(super) fn test_portable_rows(&self) -> Vec<UnqualifiedFaultRecovery> {
        match &self.rows {
            RecoveryRows::Qualified(rows) => {
                rows.iter().map(UnqualifiedFaultRecovery::from).collect()
            }
            RecoveryRows::Pending(rows) => rows.to_vec(),
        }
    }
    #[cfg(test)]
    pub(super) fn test_pending_rows_mut(&mut self) -> &mut [UnqualifiedFaultRecovery] {
        match &mut self.rows {
            RecoveryRows::Pending(rows) => rows,
            RecoveryRows::Qualified(_) => panic!("explicitly pending fixture"),
        }
    }
    #[cfg(test)]
    pub(super) fn test_push_pending(&mut self, row: UnqualifiedFaultRecovery) {
        let mut rows = self.test_portable_rows();
        rows.push(row);
        self.rows = RecoveryRows::Pending(rows.into_boxed_slice());
    }
    /// A portable request may only reject this legacy implementation. Absence
    /// of tags never grants private/APX admission: that must be derived from an
    /// actual compiler/profile ABI permit before future eager invocation.
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
        match &self.rows {
            RecoveryRows::Pending(rows) => rows
                .iter()
                .any(|row| requires(row.retirement, &row.bindings)),
            RecoveryRows::Qualified(rows) => rows
                .iter()
                .any(|row| requires(row.retirement, &row.bindings)),
        }
    }
    pub(super) fn matches_source(&self, source: &[u8]) -> bool {
        source.get(..self.input.len()) == Some(self.input.as_slice())
    }
    pub(super) fn validate_live<H: Host>(
        &self,
        host: &mut H,
        code: NativeCode,
        patches: &BTreeMap<usize, OwnedPatch>,
    ) -> Result<(), NativeFailureReason> {
        use stela_compiler::x86_64::chain;
        let body = &self.template.native.x86_64_code;
        let end = code
            .0
            .checked_add(body.len())
            .ok_or(NativeFailureReason::CodeExtent)?;
        if let Some((&at, bytes)) = patches.range(..code.0).next_back()
            && at
                .checked_add(bytes.bytes.len())
                .is_none_or(|at| at > code.0)
        {
            return Err(NativeFailureReason::PatchPlan);
        }
        for (&at, patch) in patches.range(code.0..end) {
            let bytes = &patch.bytes;
            let offset = at - code.0;
            let finish = offset
                .checked_add(bytes.len())
                .ok_or(NativeFailureReason::PatchPlan)?;
            let direct = self.template.direct_exits.iter().any(|exit| {
                exit.offset == offset
                    && body.get(offset..offset + chain::DIRECT_EXIT_BYTES)
                        == Some(chain::direct_exit(exit.target, exit.kind).as_slice())
            });
            let dynamic = self.template.native.source_map.last().is_some_and(|_| {
                offset.checked_add(chain::DYNAMIC_EXIT_BYTES) == Some(body.len())
                    && [
                        stela_compiler::block::ExitKind::Return,
                        stela_compiler::block::ExitKind::Indirect,
                        stela_compiler::block::ExitKind::Call,
                    ]
                    .into_iter()
                    .any(|kind| body.get(offset..) == Some(chain::dynamic_exit(kind).as_slice()))
            });
            let admitted = match patch.purpose {
                PatchPurpose::Chain => direct || dynamic,
                PatchPurpose::NativeAdapter { pc, kind } => self.adapter_patch(offset, pc, kind),
            };
            if bytes.len() != chain::JUMP_BYTES || !admitted {
                return Err(NativeFailureReason::PatchPlan);
            }
            if finish > body.len() {
                return Err(NativeFailureReason::PatchPlan);
            }
        }
        // Bounded idle-owner reads avoid two code-sized allocations on every
        // device fault. Compiler re-emission remains lazy and runs only once.
        let mut actual = [0u8; 256];
        let mut expected = [0u8; 256];
        for (chunk, source) in body.chunks(actual.len()).enumerate() {
            let at = code
                .0
                .checked_add(chunk * actual.len())
                .ok_or(NativeFailureReason::CodeExtent)?;
            let chunk_end = at
                .checked_add(source.len())
                .ok_or(NativeFailureReason::CodeExtent)?;
            expected[..source.len()].copy_from_slice(source);
            let preceding = patches.range(..at).next_back().into_iter();
            for (&patch_at, patch) in preceding.chain(patches.range(at..chunk_end)) {
                let bytes = &patch.bytes;
                let patch_end = patch_at
                    .checked_add(bytes.len())
                    .ok_or(NativeFailureReason::PatchPlan)?;
                let first = at.max(patch_at);
                let last = chunk_end.min(patch_end);
                if first < last {
                    expected[first - at..last - at]
                        .copy_from_slice(&bytes[first - patch_at..last - patch_at]);
                }
            }
            if !host.read_native(NativeCode(at), &mut actual[..source.len()]) {
                return Err(NativeFailureReason::CodeReadback);
            }
            if actual[..source.len()] != expected[..source.len()] {
                return Err(NativeFailureReason::LiveCodeMismatch);
            }
        }
        Ok(())
    }

    fn adapter_patch(&self, offset: usize, pc: u64, kind: NativeAdapter) -> bool {
        use stela_compiler::{GuestAddress, block::ExitKind, x86_64::chain};
        let body = &self.template.native.x86_64_code;
        if offset.checked_add(chain::DIRECT_EXIT_BYTES) != Some(body.len())
            || self
                .template
                .native
                .source_map
                .last()
                .is_none_or(|(terminal, _)| terminal.0 != pc)
        {
            return false;
        }
        let Some((entry, _)) = self.template.native.source_map.first() else {
            return false;
        };
        let Some(at) = pc
            .checked_sub(entry.0)
            .and_then(|at| usize::try_from(at).ok())
        else {
            return false;
        };
        let Some(word) = at
            .checked_add(4)
            .and_then(|end| self.input.get(at..end))
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
        else {
            return false;
        };
        let (kind, source) = match kind {
            NativeAdapter::PointerAuthentication => (
                ExitKind::PointerAuthentication,
                stela_compiler::block::decode_pointer_authentication(GuestAddress(pc), word)
                    .ok()
                    .flatten()
                    .is_some(),
            ),
            NativeAdapter::MirroredRead => {
                (ExitKind::System, super::mirrored_read(pc, word).is_some())
            }
        };
        source && body.get(offset..) == Some(chain::direct_exit(GuestAddress(pc), kind).as_slice())
    }

    pub(super) fn compiled(
        block: CompiledBlock,
        input: Vec<u8>,
        preparation: Arc<Preparation>,
    ) -> Self {
        Self {
            template: CodeTemplate {
                native: block.native,
                source_bytes: block.source_bytes,
                direct_exits: block.direct_exits,
            },
            input,
            preparation,
            rows: RecoveryRows::Qualified(block.fault_recovery.into_boxed_slice()),
            source_record: None,
            source_record_checked: false,
            #[cfg(test)]
            qualification_attempts: 0,
        }
    }
    pub(super) fn stored(
        template: StoredBlock,
        input: Vec<u8>,
        preparation: Arc<Preparation>,
    ) -> Self {
        Self {
            template: CodeTemplate {
                native: template.native,
                source_bytes: template.source_bytes,
                direct_exits: template.direct_exits,
            },
            input,
            preparation,
            rows: RecoveryRows::Pending(template.fault_recovery.into_boxed_slice()),
            source_record: None,
            source_record_checked: false,
            #[cfg(test)]
            qualification_attempts: 0,
        }
    }
    /// Called only after actual installed-code/patch-owner validation, in the
    /// dispatcher. No portable tag authorizes a guest projection before this.
    pub(super) fn qualify(&mut self, pc: u64) -> Result<&[FaultRecovery], NativeFailureReason> {
        if !self.source_record_checked {
            if let Some(record) = self.source_record
                && (pc & !(crate::translations::PAGE_BYTES as u64 - 1) != record.page
                    || self.preparation.context(record.page) != record.preparation_context)
            {
                return Err(NativeFailureReason::SourceContext);
            }
            self.source_record_checked = true;
        }
        if let RecoveryRows::Pending(rows) = &self.rows {
            #[cfg(test)]
            {
                self.qualification_attempts += 1;
            }
            let block = self
                .preparation
                .qualify_recovery(
                    &self.input,
                    pc,
                    RecoveryTemplate {
                        code: &self.template.native.x86_64_code,
                        source_map: &self.template.native.source_map,
                        source_bytes: self.template.source_bytes,
                        direct_exits: &self.template.direct_exits,
                        recovery: rows,
                    },
                )
                .map_err(NativeFailureReason::Qualification)?;
            self.rows = RecoveryRows::Qualified(block.fault_recovery.into_boxed_slice());
        }
        match &self.rows {
            RecoveryRows::Qualified(rows) => Ok(rows),
            RecoveryRows::Pending(_) => unreachable!("qualified above"),
        }
    }
}

#[cfg(test)]
mod tests;
