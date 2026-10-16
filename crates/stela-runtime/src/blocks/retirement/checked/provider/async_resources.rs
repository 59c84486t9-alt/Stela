//! The asynchronous event resources of one backend. Each variant holds its
//! complete producer lease.
use super::hosted_wait::HostedWaitResources;
#[cfg(feature = "std")]
use super::hosted_wait::WaitReply;
use crate::{
    blocks::retirement::software_async::{HostedIrqResources, NoAsyncSources},
    system::{
        events::{EventEndpoint, Outcome},
        identification_snapshot::Snapshot,
    },
};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

pub(in crate::blocks::retirement::checked) enum AsyncResources<'pe> {
    NoSources {
        pending: NoAsyncSources<'pe>,
        endpoint: &'pe EventEndpoint,
    },
    HostedWait {
        wait: Box<HostedWaitResources<'pe>>,
        identification: &'pe Snapshot,
    },
}

impl<'pe> AsyncResources<'pe> {
    pub(in crate::blocks::retirement::checked) fn system_retirement(
        &self,
        system: &crate::system::state::SystemState,
    ) -> anyhow::Result<super::SystemRetirement> {
        self.check_resources()?;
        match self {
            Self::HostedWait { .. } if !crate::system::exception::irq_masked(system) => {
                Ok(super::SystemRetirement::ArbitrateHostedIrq)
            }
            _ => Ok(super::SystemRetirement::Complete),
        }
    }

    pub(in crate::blocks::retirement::checked) fn check_resources(&self) -> anyhow::Result<()> {
        match self {
            Self::NoSources { pending, .. } => pending
                .check_registry()
                .map_err(|error| anyhow::anyhow!("no-source registry: {error:?}")),
            Self::HostedWait { wait, .. } => wait
                .check_resources()
                .map_err(|error| anyhow::anyhow!("hosted registry: {error:?}")),
        }
    }
    pub(in crate::blocks::retirement::checked) fn check_native_boundary(
        &mut self,
        system: &crate::system::state::SystemState,
    ) -> anyhow::Result<()> {
        match self {
            Self::NoSources { pending, .. } => pending
                .check_registry()
                .map_err(|error| anyhow::anyhow!("no-source boundary: {error:?}")),
            Self::HostedWait { wait, .. } => wait
                .check_native_boundary(system)
                .map_err(|error| anyhow::anyhow!("hosted boundary: {error:?}")),
        }
    }
    pub(in crate::blocks::retirement::checked) fn endpoint(&self) -> &EventEndpoint {
        match self {
            Self::NoSources { endpoint, .. } => endpoint,
            Self::HostedWait { wait, .. } => wait.endpoint(),
        }
    }
    pub(in crate::blocks::retirement::checked) fn identification(&self) -> Option<&Snapshot> {
        match self {
            Self::NoSources { .. } => None,
            Self::HostedWait { identification, .. } => Some(identification),
        }
    }
    pub(in crate::blocks::retirement::checked) fn hosted(
        &mut self,
    ) -> anyhow::Result<(&mut HostedWaitResources<'pe>, &Snapshot)> {
        match self {
            Self::HostedWait {
                wait,
                identification,
            } => Ok((wait.as_mut(), identification)),
            Self::NoSources { .. } => {
                anyhow::bail!("fixed no-source cohort has no hosted wait owner")
            }
        }
    }
    pub(in crate::blocks::retirement::checked) fn irq_resources(
        &mut self,
    ) -> anyhow::Result<HostedIrqResources<'_>> {
        self.hosted()?
            .0
            .irq_resources()
            .map_err(|error| anyhow::anyhow!("IRQ resources: {error:?}"))
    }
    #[cfg(feature = "std")]
    pub(in crate::blocks::retirement::checked) fn check_wake_resources(
        &self,
    ) -> anyhow::Result<()> {
        match self {
            Self::HostedWait { wait, .. } => wait
                .check_wake_resources()
                .map_err(|error| anyhow::anyhow!("active wake resources: {error:?}")),
            Self::NoSources { .. } => anyhow::bail!("no-source owner cannot qualify a wake"),
        }
    }
    pub(in crate::blocks::retirement::checked) fn abandon_wait(&mut self) {
        if let Self::HostedWait { wait, .. } = self {
            wait.abandon();
        }
    }
    #[cfg(feature = "std")]
    pub(in crate::blocks::retirement::checked) fn poll_wait(
        &mut self,
    ) -> anyhow::Result<WaitReply> {
        self.hosted()?
            .0
            .poll()
            .map_err(|error| anyhow::anyhow!("retained wait poll: {error:?}"))
    }
    pub(in crate::blocks::retirement::checked) fn wait_outcome(&self) -> anyhow::Result<Outcome> {
        match self {
            Self::HostedWait { wait, .. } => wait
                .outcome()
                .map_err(|error| anyhow::anyhow!("retained wait outcome: {error:?}")),
            Self::NoSources { .. } => anyhow::bail!("fixed no-source cohort has no wait receipt"),
        }
    }
    pub(in crate::blocks::retirement::checked) fn settle_wait(&mut self) -> anyhow::Result<()> {
        self.hosted()?
            .0
            .settle()
            .map_err(|error| anyhow::anyhow!("retained wait settlement: {error:?}"))
    }
}
