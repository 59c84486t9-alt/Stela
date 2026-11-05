//! Noncyclic source data leases and actual writer-stop receipts.
use super::*;

/// Source-owned writable fields backed by a genuine allocation/task reference
/// and independent code/root/data mappings. Never retain the same Queue,
/// Runtime, KernelOwner ExecutionPin or BindingArc in a Queue/Runtime sink.
///
/// # Safety
/// Prepare storage before native attach. Successful SwitchBinding::attach
/// initializes this exact lease in its nofallible tail, with real source task
/// reference and the matching native identity. publish performs ONLY bounded
/// aligned RAM stores through that qualified lease; no C, allocation, wait,
/// callback, Arc final release, native borrow or context switch is permitted.
/// Its mapping must be valid for the actual admitted process root. Default
/// destruction retains an unreleased source reference; only explicit source
/// process release AFTER StoppedPublication may invoke original put_task_struct.
pub unsafe trait ExecutionPublication: Send + Sync {
    /// # Safety
    /// Exact attached native identity, actual process/IF0 boundary and all
    /// data/code/mapping owners are kept; no Board borrow spans this call.
    unsafe fn publish(&self, sample: &ExecutionSample);
    /// Publish only when the actual entry independently qualifies data writes.
    /// Counter/Entry epoch retention and an RSP/range alone are insufficient.
    /// # Safety
    /// Scoped authentic entry, exact running identity, no Board borrow; any
    /// actual current-root/data-write qualification is the source lease's duty.
    /// No source field may be touched on refusal.
    unsafe fn publish_irq(
        &self,
        _entry: &dyn InterruptedExecution,
        _sample: &ExecutionSample,
    ) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }
}
/// Actual native publication stopped, physical frame returned and IRQ readers
/// joined for one exact attachment. This is NOT original task/RCU/DMA death.
#[must_use = "release original source data reference in process context, then finish"]
pub struct StoppedPublication {
    pub(super) cpu: Arc<dyn Cpu>,
    pub(super) target: ManuallyDrop<Arc<dyn ExecutionPublication>>,
    pub(super) identity: ExecutionIdentity,
}
impl core::fmt::Debug for StoppedPublication {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoppedPublication")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
impl StoppedPublication {
    pub fn identity(&self) -> ExecutionIdentity {
        self.identity
    }
    pub fn matches(&self, target: &Arc<dyn ExecutionPublication>) -> bool {
        Arc::ptr_eq(&self.target, target)
    }
    /// Finish only after the genuine source process released the original task
    /// data reference and joined the release function's actual callback tail.
    /// # Safety
    /// Caller consumed this exact stop proof for its same source lease; no old
    /// IRQ/row/source data reader or original reference-release frame remains.
    pub unsafe fn finish(self, entered: &dyn EnteredProcess) -> Result<(), (Self, WorkError)> {
        if let Err(error) = entered.check().and_then(|()| self.cpu.check_cpu()) {
            return Err((self, error));
        }
        if self.cpu.in_interrupt() {
            return Err((self, WorkError::InterruptContext));
        }
        let Self {
            cpu: _,
            target,
            identity: _,
        } = self;
        drop(ManuallyDrop::into_inner(target));
        Ok(())
    }
}
