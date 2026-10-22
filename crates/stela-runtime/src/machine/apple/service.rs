//! Retained board-service inputs. Taking a model's queue transfers ownership;
//! a later refusal must neither drop its tail nor replay its committed prefix.
use super::*;
use crate::platform::apple::pmgr::DomainTransition;

/// An actual reached wire edge, with the context of its first service attempt.
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
        core: cpustart::Core,
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

/// An incomplete service batch belonging to this board's actual device owners.
/// Prefixes are already committed, not instructions to replay. Starts and the
/// first reset remain in the independent engine-output queues; lifecycle effects
/// remain on their actual clients. This receipt cannot roll back any of them.
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

    /// Forward queued wires and CPU releases, retaining exact progress on any
    /// refusal. AIC validation and CPU-release resolution refuse before effects;
    /// advancing the cursor follows the actual successful effect only.
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

    /// Retain reached outputs even when the producing register operation
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

    fn release_core(&mut self, core: cpustart::Core) -> Result<(), DeviceError> {
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
mod tests {
    use super::*;
    use crate::platform::apple::{
        bus::MmioDevice,
        interrupt::{InterruptSink, Wire},
    };

    const AIC: u64 = 0x7000_0000;

    fn edge(board: &mut AppleDevices, irq: u16, level: bool) {
        board
            .latch
            .set_level(Wire::Aic(AicInput::new(0, irq)), level);
    }

    fn hardware(board: &mut AppleDevices) -> u64 {
        let mut access = Access::new(0, 100, &mut board.latch);
        match board.aic.unwrap() {
            Controller::V1(id) => board
                .bus
                .device_mut::<Aic1>(id)
                .unwrap()
                .read(0x4200, Width::Word, &mut access)
                .unwrap(),
            Controller::V2(id) => board
                .bus
                .device_mut::<Aic2>(id)
                .unwrap()
                .read(0x6800, Width::Word, &mut access)
                .unwrap(),
        }
    }

    #[test]
    fn aic_refusal_retains_committed_prefix_tail_and_later_edges() {
        for layout in [AicLayout::V1, AicLayout::aic2(0x8000, 0)] {
            let mut board = AppleDevices::new();
            board.add_aic(AIC, 32, layout).unwrap();
            edge(&mut board, 1, true);
            edge(&mut board, 32, true); // Unknown, after one successful input.
            edge(&mut board, 2, true);
            edge(&mut board, 1, false); // Must not be coalesced with the prefix.
            assert!(board.settle(0, 10, None).is_err());
            assert_eq!(hardware(&mut board), 1 << 1);
            let batch = board.pending_service().unwrap();
            assert_eq!(batch.committed(), 1);
            assert_eq!(batch.inputs().len(), 4);
            assert!(batch.failure().is_some());
            // Change the actual first input directly. A replay of the committed
            // prefix would wrongly set it again even though the cursor says 1.
            let mut access = Access::new(0, 20, &mut board.latch);
            match board.aic.unwrap() {
                Controller::V1(id) => board
                    .bus
                    .device_mut::<Aic1>(id)
                    .unwrap()
                    .set_input(AicInput::new(0, 1), false, &mut access)
                    .unwrap(),
                Controller::V2(id) => board
                    .bus
                    .device_mut::<Aic2>(id)
                    .unwrap()
                    .set_input(AicInput::new(0, 1), false, &mut access)
                    .unwrap(),
            }
            edge(&mut board, 3, true);
            assert!(board.settle(0, 99, None).is_err());
            assert_eq!(hardware(&mut board), 0);
            let batch = board.pending_service().unwrap();
            assert_eq!(batch.committed(), 1);
            assert_eq!(
                batch
                    .inputs()
                    .iter()
                    .map(|e| match e {
                        ServiceInput::Aic(e) => (e.input.irq, e.level, e.now),
                        _ => panic!("only AIC edges in this batch"),
                    })
                    .collect::<Vec<_>>(),
                [
                    (1, true, 10),
                    (32, true, 10),
                    (2, true, 10),
                    (1, false, 10),
                    (3, true, 99)
                ]
            );
            // An uncommitted tail cannot be silently retargeted to another AIC.
            assert!(board.add_aic(AIC + 0x10000, 64, layout).is_err());
        }
    }

    #[test]
    fn missing_aic_resumes_original_edges_and_timestamp_after_actual_binding() {
        let mut board = AppleDevices::new();
        edge(&mut board, 1, true);
        edge(&mut board, 1, false);
        edge(&mut board, 1, true);
        assert!(board.settle(0, 7, None).is_err());
        assert_eq!(board.pending_service().unwrap().committed(), 0);
        board.add_aic(AIC, 32, AicLayout::aic2(0x8000, 1)).unwrap();
        let Controller::V2(id) = board.aic.unwrap() else {
            unreachable!()
        };
        let mut access = Access::new(0, 80, &mut board.latch);
        board
            .bus
            .device_mut::<Aic2>(id)
            .unwrap()
            .write(0x1800, Width::Word, (1 << 31) | 1, &mut access)
            .unwrap();
        board.settle(0, 90, None).unwrap();
        assert!(board.pending_service().is_none());
        assert_eq!(hardware(&mut board), 1 << 1);
        let mut access = Access::new(0, 100, &mut board.latch);
        assert_eq!(
            board
                .bus
                .device_mut::<Aic2>(id)
                .unwrap()
                .read(0x1808, Width::Word, &mut access)
                .unwrap(),
            7
        );
    }

    fn rvbar(board: &mut AppleDevices, pe: usize) {
        board
            .add_lockdown(
                "cpu-impl-reg",
                0x5000,
                Range {
                    physical: 0x1000_0000 + pe as u64 * 0x10000,
                    bytes: 0x9010,
                },
                Some((pe, 0x8000_0000 + pe as u64 * 0x4000)),
            )
            .unwrap();
    }

    #[test]
    fn cpu_release_failure_keeps_starts_unapplied_tail_wires_and_reset() {
        let mut board = AppleDevices::new();
        rvbar(&mut board, 0);
        board.add_cpu_start(0x6000_0000, 1, &[0, 1, 2]).unwrap();
        edge(&mut board, 1, true);
        let first = Reset {
            transition: Transition::Restart,
            reason: "first reached reset".into(),
        };
        // Queue releases through the actual register, before service observes it.
        let starter = board.cpu_start.as_ref().unwrap().device;
        let mut access = Access::new(0, 10, &mut board.latch);
        board
            .bus
            .device_mut::<CpuStart>(starter)
            .unwrap()
            .write(8, Width::Word, 7, &mut access)
            .unwrap();
        assert!(board.settle(0, 10, Some(first.clone())).is_err());
        let batch = board.pending_service().unwrap();
        assert_eq!(batch.committed(), 1);
        assert_eq!(batch.inputs().len(), 4);
        assert_eq!(
            board.take_start(),
            Some(Start {
                cpu: 0,
                address: 0x8000_0000
            })
        );
        assert_eq!(board.take_start(), None);
        let later = Reset {
            transition: Transition::PowerOff,
            reason: "later reset".into(),
        };
        assert!(board.settle(0, 20, Some(later.clone())).is_err());
        assert_eq!(
            board.pending_service().unwrap().resets(),
            &[first.clone(), later]
        );
        assert_eq!(board.take_reset(), Some(first));
        assert_eq!(board.take_reset(), None);
        // Add missing actual RVBAR owners; service resumes at PE1, not PE0.
        rvbar(&mut board, 1);
        rvbar(&mut board, 2);
        assert!(board.settle(0, 30, None).is_err()); // Missing AIC, after starts.
        assert_eq!(board.pending_service().unwrap().committed(), 3);
        assert_eq!(
            board.take_start(),
            Some(Start {
                cpu: 1,
                address: 0x8000_4000
            })
        );
        assert_eq!(
            board.take_start(),
            Some(Start {
                cpu: 2,
                address: 0x8000_8000
            })
        );
        assert_eq!(board.take_start(), None);
        assert!(board.add_cpu_start(0x6001_0000, 1, &[0]).is_err());
        board.add_aic(AIC, 32, AicLayout::V1).unwrap();
        board.settle(0, 40, None).unwrap();
        assert!(board.pending_service().is_none());
        assert_eq!(board.take_start(), None);
        assert_eq!(board.take_reset(), None);
        assert_eq!(hardware(&mut board), 1 << 1);
    }

    /// A real lifecycle hook in a synthetic device: committing its supply edge
    /// emits both an interrupt and a reset, so forwarding can subsequently fail.
    #[derive(Default)]
    struct ResettingClient {
        states: Vec<LifecycleState>,
    }

    impl crate::platform::apple::bus::Lifecycle for ResettingClient {
        fn check_lifecycle(&self, _: LifecycleState) -> Result<(), &'static str> {
            Ok(())
        }

        fn set_lifecycle(&mut self, state: LifecycleState, access: &mut Access<'_>) {
            self.states.push(state);
            access.request_reset("service-test-client", "committed lifecycle edge");
            access
                .interrupts
                .set_level(Wire::Aic(AicInput::new(0, 1)), true);
        }
    }

    impl MmioDevice for ResettingClient {
        fn lifecycle(&mut self) -> Option<&mut dyn crate::platform::apple::bus::Lifecycle> {
            Some(self)
        }

        fn name(&self) -> &'static str {
            "service-test-client"
        }

        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            unreachable!("this fixture exercises the actual lifecycle hook only")
        }

        fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
            unreachable!("this fixture exercises the actual lifecycle hook only")
        }
    }

    #[test]
    fn lifecycle_callback_reset_and_actual_state_survive_failed_delivery_without_replay() {
        const SUPPLY: u64 = 0x5000_0000;
        let mut board = AppleDevices::new();
        board
            .add_power_states(
                &[Range {
                    physical: SUPPLY,
                    bytes: 4,
                }],
                &[SUPPLY],
            )
            .unwrap();
        let pmgr = board.pmgr.unwrap();
        let controller = board.bus.device_mut::<Pmgr>(pmgr).unwrap();
        controller.bind_lifecycle(SUPPLY).unwrap();
        let initial = controller.domain_state(SUPPLY).unwrap();
        let client = board.bus.add(Box::new(ResettingClient::default()));
        board.power_clients.push(PowerClient {
            resources: "test declared supply".into(),
            device: client,
            owner: PowerOwner::Mmio(0x4000_0000),
            domains: vec![(SUPPLY, initial)],
            retention: false,
        });
        // The actual PMGR accepts and retains this edge before board service.
        let mut access = Access::new(0, 12, &mut board.latch);
        board
            .bus
            .device_mut::<Pmgr>(pmgr)
            .unwrap()
            .write(SUPPLY, Width::Word, 0, &mut access)
            .unwrap();
        assert!(board.settle(0, 12, None).is_err());
        let batch = board.pending_service().unwrap();
        assert_eq!(batch.lifecycle().len(), 1);
        assert_eq!(batch.resets().len(), 1);
        assert_eq!(batch.resets()[0].transition, Transition::Restart);
        assert_eq!(
            batch.resets()[0].reason,
            "service-test-client: committed lifecycle edge at counter 12"
        );
        assert!(!board.bus.device::<ResettingClient>(client).unwrap().states[0].powered);
        assert!(board.settle(0, 24, None).is_err());
        assert_eq!(
            board
                .bus
                .device::<ResettingClient>(client)
                .unwrap()
                .states
                .len(),
            1
        );
        assert!(board.take_reset().is_some());
        board.add_aic(AIC, 32, AicLayout::V1).unwrap();
        board.settle(0, 36, None).unwrap();
        assert!(board.pending_service().is_none());
        assert_eq!(
            board
                .bus
                .device::<ResettingClient>(client)
                .unwrap()
                .states
                .len(),
            1
        );
        assert_eq!(board.take_reset(), None);
    }

    #[test]
    fn failed_aic_placement_cannot_bind_or_steal_pending_inputs() {
        let mut board = AppleDevices::new();
        rvbar(&mut board, 0);
        edge(&mut board, 1, true);
        assert!(board.settle(0, 1, None).is_err());
        // This conflicts with the actual RVBAR owner. No unmounted controller
        // may become the target of a subsequent pending-edge delivery.
        assert!(board.add_aic(0x1000_5000, 32, AicLayout::V1).is_err());
        assert!(board.aic.is_none());
        assert!(board.settle(0, 2, None).is_err());
        assert_eq!(board.pending_service().unwrap().committed(), 0);
        board.add_aic(AIC, 32, AicLayout::V1).unwrap();
        board.settle(0, 3, None).unwrap();
        assert_eq!(hardware(&mut board), 1 << 1);
    }

    #[test]
    fn later_cpu_release_cannot_overtake_an_older_refused_wire() {
        let mut board = AppleDevices::new();
        rvbar(&mut board, 0);
        board.add_cpu_start(0x6000_0000, 1, &[0]).unwrap();
        board.add_aic(AIC, 32, AicLayout::V1).unwrap();
        edge(&mut board, 32, true);
        assert!(board.settle(0, 10, None).is_err());
        let starter = board.cpu_start.as_ref().unwrap().device;
        let mut access = Access::new(0, 20, &mut board.latch);
        board
            .bus
            .device_mut::<CpuStart>(starter)
            .unwrap()
            .write(8, Width::Word, 1, &mut access)
            .unwrap();
        edge(&mut board, 1, true);
        assert!(board.settle(0, 20, None).is_err());
        assert_eq!(board.take_start(), None);
        assert_eq!(hardware(&mut board), 0);
        let batch = board.pending_service().unwrap();
        assert_eq!(batch.committed(), 0);
        assert_eq!(
            batch.inputs(),
            &[
                ServiceInput::Aic(AicDelivery {
                    input: AicInput::new(0, 32),
                    level: true,
                    cpu: 0,
                    now: 10
                }),
                ServiceInput::CpuRelease {
                    core: cpustart::Core {
                        cluster: 0,
                        core: 0
                    },
                    cpu: 0,
                    now: 20
                },
                ServiceInput::Aic(AicDelivery {
                    input: AicInput::new(0, 1),
                    level: true,
                    cpu: 0,
                    now: 20
                }),
            ]
        );
    }

    struct AdvancingClient {
        refuse: bool,
    }

    impl MmioDevice for AdvancingClient {
        fn name(&self) -> &'static str {
            "service-advance-test"
        }

        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            unreachable!("advance-only fixture")
        }

        fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
            unreachable!("advance-only fixture")
        }

        fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
            if self.refuse {
                return Err(crate::platform::apple::bus::refuse(
                    self.name(),
                    0,
                    Width::Word,
                    crate::platform::apple::bus::Direction::Read,
                    "advance refused",
                ));
            }
            access.request_reset(self.name(), "reached before later advance refusal");
            access
                .interrupts
                .set_level(Wire::Aic(AicInput::new(0, 1)), true);
            Ok(Some(access.now + 1))
        }
    }

    #[test]
    fn deadline_advance_keeps_reset_and_wires_before_later_service_failure() {
        let mut board = AppleDevices::new();
        board.bus.add(Box::new(AdvancingClient { refuse: false }));
        board.bus.add(Box::new(AdvancingClient { refuse: true }));
        assert_eq!(board.deadline(17), None);
        let batch = board.pending_service().unwrap();
        assert_eq!(batch.committed(), 0);
        assert_eq!(batch.inputs().len(), 1);
        assert_eq!(batch.resets().len(), 1);
        assert_eq!(
            board.take_reset(),
            Some(Reset {
                transition: Transition::Restart,
                reason: "service-advance-test: reached before later advance refusal at counter 17"
                    .into(),
            })
        );
    }

    #[test]
    fn lifecycle_and_rvbar_binding_failure_cannot_publish_partial_or_replacement_owners() {
        let mut board = AppleDevices::new();
        rvbar(&mut board, 0);
        let original = board.reset_vectors[0];
        // The new CONTROL bank fits; the later RVBAR bank conflicts with PE0.
        assert!(
            board
                .add_lockdown(
                    "cpu-impl-reg",
                    0x6000,
                    Range {
                        physical: 0x1000_0000,
                        bytes: 0x9010
                    },
                    Some((1, 0x9000_0000))
                )
                .is_err()
        );
        assert_eq!(board.reset_vectors[0], original);
        assert!(board.reset_vectors.get(1).copied().flatten().is_none());
        assert_eq!(board.read(0, 0x1000_6000, 8, 0), Err(DeviceError::NoDevice));
        // A distinct physical range cannot steal the same PE identity either.
        assert!(
            board
                .add_lockdown(
                    "cpu-impl-reg",
                    0x5000,
                    Range {
                        physical: 0x2000_0000,
                        bytes: 0x9010
                    },
                    Some((0, 0x9000_0000))
                )
                .is_err()
        );
        assert_eq!(board.reset_vector(0), Some(0x8000_0000));
        assert_eq!(board.read(0, 0x2000_5000, 8, 0), Err(DeviceError::NoDevice));
        const SUPPLY: u64 = 0x5000_0000;
        assert!(
            board
                .add_power_states(
                    &[
                        Range {
                            physical: SUPPLY,
                            bytes: 4
                        },
                        Range {
                            physical: 0x1000_0000,
                            bytes: 4
                        },
                    ],
                    &[SUPPLY]
                )
                .is_err()
        );
        assert!(board.pmgr.is_none());
        assert_eq!(board.read(0, SUPPLY, 4, 0), Err(DeviceError::NoDevice));
        board
            .add_power_states(
                &[Range {
                    physical: SUPPLY,
                    bytes: 4,
                }],
                &[SUPPLY],
            )
            .unwrap();
        let pmgr = board.pmgr;
        assert!(
            board
                .add_power_states(
                    &[Range {
                        physical: SUPPLY + 8,
                        bytes: 4
                    }],
                    &[SUPPLY + 8]
                )
                .is_err()
        );
        assert_eq!(board.pmgr, pmgr);
        assert_eq!(board.read(0, SUPPLY + 8, 4, 0), Err(DeviceError::NoDevice));
    }
}
