//! A host RAM service that writes guest RAM and then raises the machine IRQ.
use super::super::{InstalledSource, SoftwareEl1Machine, SoftwareEl1Profile};
use super::HostedIrqProducer;
use crate::memory::source_ram::{SourceRamPublication, SourceRamPublisher};

/// Writes one RAM extent and owns the external IRQ line. It holds no
/// MemoryThread, guest registers or raw pointers, so it can run on a host
/// device thread.
pub struct HostedRamService {
    publisher: SourceRamPublisher,
    irq: HostedIrqProducer,
}

/// Result of one publication attempt.
pub enum HostedRamServiceAttempt {
    Published { irq_sequence: u64 },
    ExecutionBusy,
    ServiceBusy,
}

impl HostedRamService {
    /// Publish, release the service loan, then assert the IRQ. A failed
    /// publication reports its completed prefix and asserts nothing.
    pub fn publish_then_assert(&mut self, offset: usize, bytes: &[u8]) -> anyhow::Result<u64> {
        self.publisher.publish(offset, bytes)?;
        self.irq.assert()
    }

    /// Like `publish_then_assert` but without blocking. Only contention is
    /// retryable; every other failure is an error.
    pub fn try_publish_then_assert(
        &mut self,
        offset: usize,
        bytes: &[u8],
    ) -> anyhow::Result<HostedRamServiceAttempt> {
        match self.publisher.try_publish(offset, bytes)? {
            SourceRamPublication::Published => Ok(HostedRamServiceAttempt::Published {
                irq_sequence: self.irq.assert()?,
            }),
            SourceRamPublication::ExecutionBusy => Ok(HostedRamServiceAttempt::ExecutionBusy),
            SourceRamPublication::ServiceBusy => Ok(HostedRamServiceAttempt::ServiceBusy),
        }
    }
}

impl SoftwareEl1Machine {
    /// Take a RAM service for `bytes` at `source_pa` and the IRQ line, once,
    /// before the machine runs. The installed physical memory checks that the
    /// extent is writable RAM. Only the hosted-wait profile has this service.
    pub fn take_hosted_ram_service(
        &mut self,
        source_pa: u64,
        bytes: usize,
    ) -> anyhow::Result<HostedRamService> {
        anyhow::ensure!(
            self.profile == SoftwareEl1Profile::HostedWaitV1,
            "machine has no registered hosted service IRQ"
        );
        let InstalledSource::El1(installed) = &mut self.installed else {
            anyhow::bail!("hosted RAM service requires installed EL1 storage")
        };
        let publisher = installed.source_ram_publisher(source_pa, bytes)?;
        let irq = self.take_hosted_irq()?;
        Ok(HostedRamService { publisher, irq })
    }
}
