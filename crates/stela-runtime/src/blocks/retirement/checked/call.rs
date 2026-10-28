//! Observations of one checked native call. Each is recorded as soon as it is
//! reached, so a later failed check or finalizer cannot erase it.

use super::{NativeObservation, OwnedMemoryFault};
#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
};
use anyhow::{Result, anyhow};
use core::fmt::Display;
use stela_compiler::{
    GuestAddress,
    block::BlockExit,
    context::memory::{MemoryContextView, MemoryStatus},
};

/// The memory view's fault fields as the native code left them, kept for
/// failure reports.
#[allow(dead_code, reason = "failure reports read the fields through Debug")]
#[derive(Debug, Clone, Copy)]
struct RawView {
    access_code: u32,
    status_code: u32,
    address: u64,
    pc: u64,
    completed_bytes: u64,
}

#[derive(Debug, Default)]
pub(crate) struct CallRecord {
    started: bool,
    executed: bool,
    returned: Option<(u64, u64)>,
    view: Option<RawView>,
    fault: Option<OwnedMemoryFault>,
    failure: Option<String>,
}

impl CallRecord {
    /// Whether the memory callback started; before that, no native effect happened.
    pub(crate) fn started(&self) -> bool {
        self.started
    }

    /// Run the memory callback's body, recording that it started and why it failed.
    pub(crate) fn run(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<NativeObservation>,
    ) -> Result<NativeObservation> {
        self.started = true;
        let result = body(self);
        if let Err(error) = &result {
            self.failure = Some(error.to_string());
        }
        result
    }

    /// Record a finished native call: its raw exit and memory view. The exit
    /// bits are unqualified; the view's fault state takes precedence.
    pub(crate) fn record(&mut self, returned: &Result<BlockExit>, view: &MemoryContextView) {
        self.executed = returned.is_ok();
        self.returned = returned.as_ref().ok().map(|exit| (exit.next_pc, exit.kind));
        self.view = Some(RawView {
            access_code: view.fault_access,
            status_code: view.fault_kind,
            address: view.fault_address,
            pc: view.fault_pc,
            completed_bytes: view.completed_bytes,
        });
    }

    /// Classify a returned call by its memory status. A fault is recorded,
    /// then checked by `validate`, before it is reported.
    pub(crate) fn classify(
        &mut self,
        exit: BlockExit,
        view: &MemoryContextView,
        validate: impl FnOnce(&OwnedMemoryFault) -> Result<()>,
    ) -> Result<NativeObservation> {
        let status = MemoryStatus::from_code(view.fault_kind)
            .ok_or_else(|| anyhow!("unknown checked memory status {}", view.fault_kind))?;
        let access = stela_compiler::context::memory::FaultAccess::from_code(view.fault_access)
            .ok_or_else(|| anyhow!("unknown checked memory fault access {}", view.fault_access))?;
        anyhow::ensure!(
            view.has_supported_header(),
            "invalid checked memory v2 header"
        );
        if status == MemoryStatus::Success {
            return Ok(NativeObservation::Returned {
                next_pc: exit.next_pc,
                kind: exit.kind,
            });
        }
        let fault = OwnedMemoryFault {
            access,
            status,
            address: GuestAddress(view.fault_address),
            pc: GuestAddress(view.fault_pc),
            completed_bytes: view.completed_bytes,
        };
        self.fault = Some(fault);
        validate(&fault)?;
        Ok(NativeObservation::Fault(fault))
    }

    /// The callback, or a check after the call, failed.
    pub(crate) fn invocation_failed(&self, error: impl Display) -> NativeObservation {
        NativeObservation::InvocationFailed(format!("{error}; {self:?}"))
    }

    /// The finalizer failed after the callback started.
    pub(crate) fn finalization_failed(&self, status: MemoryStatus) -> NativeObservation {
        NativeObservation::FinalizationFailed {
            status,
            fault: self.fault,
            detail: format!("{self:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::context::memory::{
        MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryRequest,
    };
    unsafe extern "sysv64" fn callback(_: *mut MemoryContextView, _: *const MemoryRequest) -> u32 {
        unreachable!()
    }
    #[test]
    fn unknown_access_and_status_codes_keep_raw_source_and_prefix_diagnostics() {
        for (status, access) in [
            (MemoryStatus::Permission as u32, 3),
            (u32::MAX, 0),
            (u32::MAX, u32::MAX),
            (0, 1),
        ] {
            let view = MemoryContextView {
                version: MEMORY_CONTEXT_VERSION,
                bytes: MEMORY_CONTEXT_BYTES,
                callback,
                opaque: core::ptr::null_mut(),
                fault_kind: status,
                fault_access: access,
                fault_address: 0x7777,
                fault_pc: 0x1234,
                completed_bytes: 7,
                reserved_tail: 0,
            };
            let exit = BlockExit {
                next_pc: 0x1234,
                kind: 0,
            };
            let mut call = CallRecord::default();
            call.record(&Ok(exit), &view);
            assert!(
                call.classify(exit, &view, |_| panic!("invalid ABI must not retire"))
                    .is_err()
            );
            let raw = call.view.unwrap();
            assert_eq!(
                (
                    raw.status_code,
                    raw.access_code,
                    raw.address,
                    raw.pc,
                    raw.completed_bytes
                ),
                (status, access, 0x7777, 0x1234, 7)
            );
        }
    }
}
