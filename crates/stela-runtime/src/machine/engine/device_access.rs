//! One recovered cohort, one retained stop, and ordered consuming bus accesses.
use super::*;
use shared_memory::RecoveredDeviceAccess;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Diagnostic count only; each actual frame/generation remains private.
    pub fn pending_native_device_access_count(&self) -> usize {
        usize::from(self.pending_device_read.is_some() || self.pending_device_write.is_some())
            + self.pending_device_tail.len()
    }
    /// Diagnostic only; the actual frame/generation remains private.
    pub fn pending_native_device_access(&self) -> Option<Stop> {
        self.pending_device_read
            .as_ref()
            .map(device_read::Pending::stop)
            .or_else(|| {
                self.pending_device_write
                    .as_ref()
                    .map(device_write::Pending::stop)
            })
    }
}
impl<H: Host, T: NativeTransport, D: Devices> Machine<ServiceHost<H, T>, D> {
    pub(super) fn queue_device_accesses(
        &mut self,
        accesses: Vec<RecoveredDeviceAccess>,
        held: publication::StoppedWorkers,
    ) -> Stop {
        self.pending_device_tail = accesses.into();
        self.queue_next_device_access(held)
    }
    fn queue_next_device_access(&mut self, held: publication::StoppedWorkers) -> Stop {
        match self
            .pending_device_tail
            .pop_front()
            .expect("actual pending cohort")
        {
            RecoveredDeviceAccess::Read(read) => self.queue_device_read(read, held),
            RecoveredDeviceAccess::Write(write) => self.queue_device_write(write, held),
        }
    }
    pub(super) fn finish_device_access(&mut self, held: publication::StoppedWorkers) -> Step {
        if self.pending_device_tail.is_empty() {
            self.release_native_services(held);
            Ok(())
        } else {
            Err(self.queue_next_device_access(held))
        }
    }
    /// Consume only the actual current front; no caller-supplied request,
    /// recovered frame, data or worker generation is accepted.
    ///
    /// # Safety
    /// The complete closed synchronous native producer contract remains valid
    /// through every pending request. Each backend retains its prepared effect
    /// and ACK inside the same real worker generation.
    pub unsafe fn complete_native_device_access(&mut self) -> Step {
        if self.pending_device_read.is_some() {
            // SAFETY: same actual pending source and producer contract.
            unsafe { self.complete_device_read() }
        } else if self.pending_device_write.is_some() {
            // SAFETY: same actual pending source and producer contract.
            unsafe { self.complete_device_write() }
        } else {
            Err(self.unsupported(RequirementKind::Native(
                "no recovered device access is pending",
            )))
        }
    }
}
