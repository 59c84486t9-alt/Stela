//! The backend resources lent for IRQ entry after an instruction retires.
use super::*;
use crate::blocks::retirement::software_async::HostedIrqResources;

pub(crate) struct El1IrqResources<'call> {
    pub(in crate::blocks::retirement::checked) sources: &'call mut InstalledM0Sources,
    pub(in crate::blocks::retirement::checked) controls: &'call mut TranslationControls,
    pub(in crate::blocks::retirement::checked) platform:
        &'call super::super::super::el1_system::El1PlatformControls,
    pub(in crate::blocks::retirement::checked) memory: &'call mut MemoryThread<MemoryControls>,
    pub(in crate::blocks::retirement::checked) execution: &'call ProcessEntryControls,
    pub(in crate::blocks::retirement::checked) irq: HostedIrqResources<'call>,
    pub(in crate::blocks::retirement::checked) address_space: u64,
}

impl El1IrqResources<'_> {
    pub(in crate::blocks::retirement::checked) fn check(
        &self,
        outer: &MemoryExecutionLoan,
        system: &crate::system::state::SystemState,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space),
            "IRQ namespace differs"
        );
        self.execution.check()?;
        self.execution
            .check_snapshot(Some(self.platform.identification()), system)?;
        self.platform.check()?;
        self.memory
            .check_event_endpoint(self.irq.endpoint())
            .map_err(|error| anyhow::anyhow!("IRQ monitor/event endpoint: {error:?}"))?;
        outer
            .check_thread_domain(&*self.memory)
            .map_err(|error| anyhow::anyhow!("IRQ outer: {error:?}"))?;
        self.controls
            .validate_installed_el1_source(&self.sources.el1_scope().map_err(anyhow::Error::msg)?)
            .map_err(anyhow::Error::msg)?;
        if self.irq.receipt().is_some() {
            self.irq
                .validate_presented()
                .map_err(|error| anyhow::anyhow!("IRQ source receipt: {error:?}"))?;
        }
        Ok(())
    }
}
