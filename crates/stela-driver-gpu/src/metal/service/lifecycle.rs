//! Native-owner admission closure and GPU quiesce protocol.
use super::{
    Service,
    wire::{Fault, Operation, Status},
};
use crate::metal::{device::lifecycle::QuiesceStatus, shader::Compiler, vulkan::backend::Backend};

impl<B: Backend, C: Compiler> Service<B, C> {
    /// Closes connection, import and new-work admission. Existing event
    /// signals, releases and progress queries remain available to finish
    /// accepted work. The service cannot reopen under these identities.
    pub fn begin_quiesce(&mut self) {
        self.device.begin_quiesce();
    }

    /// Closes admission and advances accepted work once. `GpuIdle` proves
    /// only backend GPU idleness. Connection objects and imported memory
    /// stay owned: the gate must separately disconnect, consume retirement
    /// tokens and acknowledge DMA invalidation before reset or removal.
    /// `Unproven` requires the native roots to remain alive.
    pub fn quiesce_step(&mut self) -> QuiesceStatus {
        self.device.quiesce_step()
    }

    pub(super) fn admit_quiescing(&self, operation: Operation) -> Result<(), Fault> {
        if self.device.is_quiescing()
            && !matches!(
                operation,
                Operation::Release
                    | Operation::Poll
                    | Operation::AllocatedSize
                    | Operation::CommandBufferTimes
                    | Operation::EventSignaledValue
                    | Operation::SetEventSignaledValue
                    | Operation::WaitEvent
            )
        {
            Err(Fault::new(Status::Closed, "the device is quiescing"))
        } else {
            Ok(())
        }
    }
}
