//! Invocation-retained source/profile and immutable native recovery templates.
use super::{Host, NativeCode, NativeFault, Preparation};
use crate::translations::{Digest, StoredBlock};
use alloc::collections::BTreeMap;
use alloc::{sync::Arc, vec::Vec};
use stela_compiler::block::{
    CompiledBlock, FaultRecovery, RecoveryQualificationError, RecoveryTemplate,
    UnqualifiedFaultRecovery,
};

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

pub(super) struct CodeRecovery {
    pub(super) template: StoredBlock,
    input: Vec<u8>,
    preparation: Arc<Preparation>,
    qualified: Option<Vec<FaultRecovery>>,
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
        self.qualified = None;
    }
    #[cfg(test)]
    pub(super) fn test_rows_mut(&mut self) -> &mut Vec<FaultRecovery> {
        self.qualified.as_mut().expect("actual emitted plan")
    }
    /// A portable request may only reject this legacy implementation. Absence
    /// of tags never grants private/APX admission: that must be derived from an
    /// actual compiler/profile ABI permit before future eager invocation.
    pub(super) fn portable_requires_unavailable_capture(&self) -> bool {
        use stela_compiler::block::{RecoverySource, RetirementPhase};
        self.template.fault_recovery.iter().any(|row| {
            row.retirement.phase() != RetirementPhase::Before
                || row.bindings.iter().any(|binding| match binding.source {
                    RecoverySource::HostRegister(register) => register >= 16,
                    RecoverySource::NativeSpill(_) => true,
                })
        })
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
        let rows = block
            .fault_recovery
            .iter()
            .map(UnqualifiedFaultRecovery::from)
            .collect();
        Self {
            template: StoredBlock {
                native: block.native,
                source_bytes: block.source_bytes,
                direct_exits: block.direct_exits,
                fault_recovery: rows,
            },
            input,
            preparation,
            qualified: Some(block.fault_recovery),
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
            template,
            input,
            preparation,
            qualified: None,
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
        if self.qualified.is_none() {
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
                        recovery: &self.template.fault_recovery,
                    },
                )
                .map_err(NativeFailureReason::Qualification)?;
            self.qualified = Some(block.fault_recovery);
        }
        Ok(self.qualified.as_deref().expect("qualified above"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Fetched;
    use super::super::tests::{BASE, machine};

    #[test]
    fn legacy_first_fault_qualification_is_cached_and_reports_dispatcher_cost() {
        let mut machine = machine(&[0x91000400, 0xf9400043, 0xd4000001]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("actual emission");
        };
        let mut owner = machine.fault_recovery.remove(&index).unwrap();
        owner.test_make_pending();
        let started = std::time::Instant::now();
        let first = owner.qualify(BASE).unwrap().to_vec();
        let cold = started.elapsed();
        assert!(
            first
                .iter()
                .any(|row| row.site.kind() == stela_compiler::block::RecoverySiteKind::GuestAccess)
        );
        let started = std::time::Instant::now();
        for _ in 0..32 {
            assert_eq!(owner.qualify(BASE).unwrap(), first);
        }
        let cached = started.elapsed();
        assert_eq!(
            owner.qualification_attempts, 1,
            "only the first actual fault re-emits the plan"
        );
        eprintln!(
            "dispatcher recovery qualification: source={} native={} cold_ns={} cached_average_ns={} (current host; no native guest entered)",
            owner.input.len(),
            owner.template.native.x86_64_code.len(),
            cold.as_nanos(),
            cached.as_nanos() / 32
        );
    }
}
