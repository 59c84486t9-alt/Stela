//! Hosted wait resources (IRQ line, counter and deadline) for a new software
//! EL1 machine.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
mod publication;
pub use publication::{HostedRamService, HostedRamServiceAttempt};

use super::super::provider::hosted_wait::HostedWaitResources;
#[cfg(feature = "std")]
use crate::blocks::retirement::software_async::WaitSourceKind;
use crate::{
    blocks::retirement::software_async::{
        AsyncError, LevelProducer, SoftwareAsyncDomain, WaitReceiver, WaitSourceKey,
    },
    system::events::{EventDomain, EventEndpoint, hosted::Counter},
};

enum LeaseState {
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    Available,
    Consumed,
}

/// The external end of the machine's IRQ line, which can be moved to a
/// device thread. It cannot reach PE state or memory. The source stays
/// registered after it is dropped.
pub(crate) struct HostedIrqProducer {
    producer: LevelProducer,
}
impl HostedIrqProducer {
    pub(crate) fn assert(&self) -> anyhow::Result<u64> {
        self.producer
            .publish(true)
            .map_err(|error| anyhow::anyhow!("IRQ assertion transport: {error:?}"))
    }
}

pub(super) enum AsyncInstallation {
    NoSources(SoftwareAsyncDomain),
    HostedWait {
        installation: HostedWaitInstallation,
        irq: Option<HostedIrqProducer>,
    },
}
impl AsyncInstallation {
    /// # Safety
    /// The caller is the constructor of a new software PE and owns every
    /// producer the PE can see for its whole lifetime.
    pub(super) unsafe fn no_sources() -> Self {
        Self::NoSources(unsafe { SoftwareAsyncDomain::fresh_software_pe() })
    }
    /// # Safety
    /// As for `HostedWaitInstallation::fresh`.
    pub(super) unsafe fn hosted_wait() -> anyhow::Result<Self> {
        let (installation, producer) = unsafe { HostedWaitInstallation::fresh() }
            .map_err(|error| anyhow::anyhow!("hosted wait installation: {error:?}"))?;
        Ok(Self::HostedWait {
            installation,
            irq: Some(HostedIrqProducer { producer }),
        })
    }
    pub(super) fn take_irq(&mut self) -> anyhow::Result<HostedIrqProducer> {
        match self {
            Self::HostedWait { irq, .. } => irq
                .take()
                .ok_or_else(|| anyhow::anyhow!("IRQ publisher already moved")),
            Self::NoSources(_) => anyhow::bail!("fixed no-source machine has no IRQ publisher"),
        }
    }
}

pub(in crate::blocks::retirement) struct HostedWaitInstallation {
    domain: SoftwareAsyncDomain,
    keys: Vec<WaitSourceKey>,
    counter: Counter,
    receiver: WaitReceiver,
    lease: LeaseState,
}

impl HostedWaitInstallation {
    /// # Safety
    /// Called once by the constructor of a new hosted software PE, before its
    /// SystemExecutionOwner exists. This declares every producer: one IRQ line
    /// and the local WFx deadline. No other registry, FIQ, SError or debug
    /// source, or external writer may exist.
    pub(in crate::blocks::retirement) unsafe fn fresh() -> Result<(Self, LevelProducer), AsyncError>
    {
        #[cfg(not(feature = "std"))]
        {
            Err(AsyncError::HostAdapterUnavailable)
        }
        #[cfg(feature = "std")]
        {
            // SAFETY: forwarded from this function's contract.
            let mut domain = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
            let keys = vec![
                domain.register_wait_source(WaitSourceKind::Irq)?,
                domain.register_wait_source(WaitSourceKind::LocalTimeout)?,
            ];
            let counter = Counter::new();
            let (receiver, mut producers) = domain.bind_wait_transport(&keys, &counter)?;
            let producer = producers.pop().ok_or(AsyncError::WrongProducer)?;
            if !producers.is_empty() {
                return Err(AsyncError::WrongProducer);
            }
            Ok((
                Self {
                    domain,
                    keys,
                    counter,
                    receiver,
                    lease: LeaseState::Available,
                },
                producer,
            ))
        }
    }

    /// Borrowed once by the factory for the backend's lifetime. The endpoint
    /// is the one already bound to the MemoryThread's monitor; the backend
    /// re-checks that binding.
    pub(in crate::blocks::retirement) fn resources<'pe>(
        &'pe mut self,
        events: &'pe EventDomain,
        endpoint: &'pe mut EventEndpoint,
    ) -> anyhow::Result<HostedWaitResources<'pe>> {
        anyhow::ensure!(
            matches!(self.lease, LeaseState::Available),
            "hosted installation already consumed"
        );
        self.lease = LeaseState::Consumed;
        let sources = self
            .domain
            .lease_wait_sources(&self.keys, &mut self.receiver, &mut self.counter)
            .map_err(|error| anyhow::anyhow!("wait source lease: {error:?}"))?;
        HostedWaitResources::new(sources, events, endpoint)
            .map_err(|error| anyhow::anyhow!("wait resources: {error}"))
    }
}

#[cfg(test)]
mod tests;
