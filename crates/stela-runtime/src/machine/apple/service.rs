//! Board-service inputs. Taking a model's queue transfers ownership;
//! a later refusal must neither drop its tail nor replay its committed prefix.
use super::*;
use crate::platform::apple::pmgr::DomainTransition;

/// A reached wire edge, with the context of its first service attempt.
/// Retrying delivery must not move an AIC timestamp to a later counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AicDelivery {
    pub input: AicInput,
    pub level: bool,
    pub cpu: CpuIndex,
    pub now: u64,
}

/// One reached input, ordered with every other queued board-service input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceInput {
    Aic(AicDelivery),
    CpuRelease {
        core: stela_soc_data::cpustart::Core,
        cpu: CpuIndex,
        now: u64,
    },
}

impl ServiceInput {
    fn context(self) -> (CpuIndex, u64) {
        match self {
            Self::Aic(input) => (input.cpu, input.now),
            Self::CpuRelease { cpu, now, .. } => (cpu, now),
        }
    }
}

/// An incomplete service batch belonging to this board's device owners.
/// Prefixes are already committed, not instructions to replay. Starts and the
/// first reset remain in the independent engine-output queues; lifecycle effects
/// remain on their clients. This receipt cannot roll back any of them.
#[derive(Debug, Default)]
pub struct ServiceBatch {
    inputs: Vec<ServiceInput>,
    committed: usize,
    pub(super) lifecycle: Vec<DomainTransition>,
    resets: Vec<Reset>,
    failure: Option<DeviceError>,
}

impl ServiceBatch {
    pub(super) fn retain_reset(&mut self, first: &mut Option<Reset>, reset: Option<Reset>) {
        if let Some(reset) = reset {
            if first.is_none() {
                *first = Some(reset.clone());
            }
            self.resets.push(reset);
        }
    }

    /// All captured inputs in service order, including the committed prefix.
    pub fn inputs(&self) -> &[ServiceInput] {
        &self.inputs
    }

    /// Inputs before this cursor have already taken effect on their owners.
    pub fn committed(&self) -> usize {
        self.committed
    }

    /// Lifecycle transitions already applied to every bound client, in order.
    pub fn lifecycle(&self) -> &[DomainTransition] {
        &self.lifecycle
    }

    /// Reached reset requests, including later requests behind the first reset.
    /// The engine still receives only the first queued reset under its existing
    /// first-request-wins contract.
    pub fn resets(&self) -> &[Reset] {
        &self.resets
    }

    pub fn failure(&self) -> Option<&DeviceError> {
        self.failure.as_ref()
    }
}

impl AppleDevices {
    /// Read-only receipt of an incomplete batch. Only successful service clears
    /// it; observing it never consumes an input or an engine output.
    pub fn pending_service(&self) -> Option<&ServiceBatch> {
        let batch = &self.service;
        (!batch.inputs.is_empty()
            || !batch.lifecycle.is_empty()
            || !batch.resets.is_empty()
            || batch.failure.is_some())
        .then_some(batch)
    }

    fn capture_inputs(&mut self, cpu: CpuIndex, now: u64) {
        self.service
            .inputs
            .extend(
                self.latch
                    .take_aic_inputs()
                    .into_iter()
                    .map(|(input, level)| {
                        ServiceInput::Aic(AicDelivery {
                            input,
                            level,
                            cpu,
                            now,
                        })
                    }),
            );
    }

    /// Forward queued wires and CPU releases, keeping exact progress on any
    /// refusal. AIC validation and CPU-release resolution refuse before effects;
    /// advancing the cursor follows the successful effect only.
    pub(super) fn settle(
        &mut self,
        cpu: CpuIndex,
        now: u64,
        reset: Option<Reset>,
    ) -> Result<(), DeviceError> {
        self.service.retain_reset(&mut self.reset, reset);
        self.settle_lifecycle(cpu, now);
        self.capture_reached(cpu, now, None);
        let result = self.apply_service();
        match &result {
            Ok(()) => self.service = ServiceBatch::default(),
            Err(error) => self.service.failure = Some(error.clone()),
        }
        result
    }

    /// Keep reached outputs even when the producing register operation
    /// subsequently refuses. Capturing never delivers an input or retries a
    /// peripheral effect, and keeps its original CPU/counter context.
    pub(super) fn capture_reached(&mut self, cpu: CpuIndex, now: u64, reset: Option<Reset>) {
        self.service.retain_reset(&mut self.reset, reset);
        // Capture both queues before either family can refuse. A release error
        // must not leave the reached wire batch unrepresented or discard it.
        if let Some(starter) = &self.cpu_start {
            self.service.inputs.extend(
                self.bus
                    .device_mut::<CpuStart>(starter.device)
                    .expect("the CPU start id names its model")
                    .take()
                    .into_iter()
                    .map(|core| ServiceInput::CpuRelease { core, cpu, now }),
            );
        }
        self.capture_inputs(cpu, now);
    }

    fn apply_service(&mut self) -> Result<(), DeviceError> {
        loop {
            while let Some(&input) = self.service.inputs.get(self.service.committed) {
                match input {
                    ServiceInput::CpuRelease { core, .. } => self.release_core(core)?,
                    ServiceInput::Aic(delivery) => self.deliver_input(delivery)?,
                }
                self.service.committed += 1;
            }
            // Preserve edges generated during forwarding, behind older inputs.
            let Some(last) = self.service.inputs.last().copied() else {
                return Ok(());
            };
            let (cpu, now) = last.context();
            self.capture_inputs(cpu, now);
            if self.service.inputs.len() == self.service.committed {
                return Ok(());
            }
        }
    }

    fn release_core(&mut self, core: stela_soc_data::cpustart::Core) -> Result<(), DeviceError> {
        let starter = self.cpu_start.as_ref().expect("captured CPU start owner");
        let affinity = u64::from(core.cluster) << 8 | u64::from(core.core);
        let cpu = starter
            .mpidrs
            .iter()
            .position(|&mpidr| mpidr & 0xffff == affinity)
            .ok_or_else(|| {
                DeviceError::Refused(format!(
                    "CPU start of cluster {} core {}, which the board does not have",
                    core.cluster, core.core
                ))
            })?;
        let address = self.locked_reset_vector(cpu).ok_or_else(|| {
            DeviceError::Refused(format!("CPU start of PE {cpu}, which has no RVBAR"))
        })?;
        self.starts.push(Start { cpu, address });
        Ok(())
    }

    fn deliver_input(&mut self, delivery: AicDelivery) -> Result<(), DeviceError> {
        let Some(aic) = self.aic else {
            return Err(DeviceError::Refused(format!(
                "AIC input {:?} changed but no AIC model is mapped",
                delivery.input
            )));
        };
        let mut access = Access::new(delivery.cpu, delivery.now, &mut self.latch);
        let result = match aic {
            Controller::V1(id) => self
                .bus
                .device_mut::<Aic1>(id)
                .expect("the AIC id names an Aic1")
                .set_input(delivery.input, delivery.level, &mut access)
                .map_err(|error| format!("{error:?}")),
            Controller::V2(id) => self
                .bus
                .device_mut::<Aic2>(id)
                .expect("the AIC id names an Aic2")
                .set_input(delivery.input, delivery.level, &mut access)
                .map_err(|error| format!("{error:?}")),
        };
        result.map_err(|error| DeviceError::Refused(format!("AIC input: {error}")))
    }
}

#[cfg(test)]
mod tests;
