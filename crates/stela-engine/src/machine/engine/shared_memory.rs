//! Source-bound system accesses over the canonical physical RAM owner.
//! This is a checked execution service, not an additional VM or RAM image.
mod controls;
mod exclusive;
mod host;
mod lifecycle;
mod native_run;
mod policy;
mod scheduler;
#[cfg(feature = "native-profile")]
mod source_profile;
pub use host::{HeldRamService, NativeTransport, ServiceHost, ServiceTransport};
#[cfg(feature = "native-profile")]
pub use source_profile::Statistics as NativeSourceStatistics;

use super::{Devices, Host, Machine, mmu};
use crate::memory::{RegisteredSystemRam, domain::MemoryThread};
use alloc::{sync::Arc, vec::Vec};
use controls::Controls;
pub use native_run::{
    ArtifactCacheStats, Cohort as NativeCohort, Identity as NativeRunIdentity,
    MAX_NATIVE_EPOCH_BODIES, NativeEpochDeadline, NativeEpochEnd, NativeEpochStatistics, NativeRun,
    Observation as NativeRunObservation, ReturnedRun, dispatch as dispatch_native_run,
    recover as recover_native_run,
};
pub(in crate::machine::engine) use native_run::{
    RecoveredDeviceAccess, RecoveredRead, RecoveredWrite,
};
#[cfg(feature = "native-profile")]
pub use policy::DataTlbStatistics as NativeDataTlbStatistics;
use policy::Policy;
pub use policy::{Failure as SharedMemoryFailure, Refusal as SharedMemoryRefusal};
use stela_compiler::context::memory::MemoryStatus;

/// One PE's persistent global reservation and effective source-memory service.
/// Machine refreshes controls while it still owns that actual PE; no caller can
/// substitute raw registers, a physical-address identity map or a ready bit.
pub struct SharedMemory {
    memory: MemoryThread<Policy>,
    ram: Arc<RegisteredSystemRam>,
    pe: usize,
    machine: Arc<()>,
    event: crate::system::events::EventEndpoint,
    artifacts: native_run::ArtifactCache,
    #[cfg(feature = "native-profile")]
    epochs: NativeEpochStatistics,
    #[cfg(feature = "native-profile")]
    source: source_profile::Profile,
}
impl core::fmt::Debug for SharedMemory {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedMemory")
            .field("pe", &self.pe)
            .finish_non_exhaustive()
    }
}
impl SharedMemory {
    pub(crate) fn prepare_clear_reservation(
        &mut self,
    ) -> Result<crate::memory::domain::PreparedLocalClear<'_>, MemoryStatus> {
        self.memory.prepare_clear_reservation()
    }
    /// Tighten the per-PE retained compiler-artifact limit. This cannot raise
    /// the named default or a previously tightened bound; zero disables reuse.
    pub fn tighten_artifact_cache_budget(&mut self, bytes: usize) {
        self.artifacts.tighten(bytes);
    }
    pub fn native_artifact_stats(&self) -> ArtifactCacheStats {
        self.artifacts.stats()
    }
    pub fn processor(&self) -> usize {
        self.pe
    }
    pub(in crate::machine::engine) fn ram_owner(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    pub(super) fn prepare_reset_peer(
        &self,
        cpu: &crate::machine::Cpu,
        pe: usize,
        name: &'static str,
        missing: &[crate::machine::system::Register],
    ) -> Result<Self, MemoryStatus> {
        if cpu.canonical_memory.is_some() || cpu.monitor.is_some() {
            return Err(MemoryStatus::Unsupported);
        }
        let controls = Controls::capture(cpu, name, missing)?;
        let mut memory = self
            .ram
            .domain()
            .thread(Policy::new(controls, Arc::clone(&self.ram)));
        let event = self
            .event
            .domain()
            .register(cpu.event, None)
            .map_err(|_| MemoryStatus::Domain)?;
        memory.bind_events(&event.producer())?;
        Ok(Self {
            memory,
            ram: Arc::clone(&self.ram),
            pe,
            machine: Arc::clone(&self.machine),
            event,
            artifacts: self.artifacts.empty_like(),
            #[cfg(feature = "native-profile")]
            epochs: NativeEpochStatistics::default(),
            #[cfg(feature = "native-profile")]
            source: source_profile::Profile::default(),
        })
    }
    pub fn event_endpoint(&self) -> &crate::system::events::EventEndpoint {
        &self.event
    }
    pub(in crate::machine::engine) fn current_access_source<const WRITE: bool>(
        &self,
        cpu: &crate::machine::Cpu,
        profile: &crate::machine::CpuProfile,
        missing: &[crate::machine::system::Register],
        recovered: &native_run::RecoveredAccess<WRITE>,
        held: &crate::memory::CanonicalRamService<'_>,
    ) -> Result<(), MemoryStatus> {
        let (binding, _, pc, _) = recovered.source();
        let (word, _, _, _, _) = recovered.access().ok_or(MemoryStatus::Unsupported)?;
        let controls_hash = recovered.controls().ok_or(MemoryStatus::Unsupported)?;
        if binding.pe != self.pe
            || !recovered.machine_matches(&self.machine)
            || !held.belongs_to(&self.ram)
        {
            return Err(MemoryStatus::Domain);
        }
        held.validate_current()?;
        let controls = Controls::capture(cpu, profile.name, missing)?;
        if controls.identity() != controls_hash {
            return Err(MemoryStatus::Unsupported);
        }
        let mut actual = [0; 4];
        self.fetch(&controls, pc, &mut actual)?;
        if u32::from_le_bytes(actual) != word {
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }

    pub(in crate::machine::engine) fn current_device_access(
        &self,
        cpu: &crate::machine::Cpu,
        profile: &crate::machine::CpuProfile,
        missing: &[crate::machine::system::Register],
        request: crate::memory::domain::DataRequest,
        quantity_bytes: u8,
        physical: u64,
    ) -> Result<(), MemoryStatus> {
        use crate::memory::{
            backing::AccessKind,
            domain::{DataPart, DataPolicy},
        };
        let controls = Controls::capture(cpu, profile.name, missing)?;
        let mut policy = Policy::new(controls, Arc::clone(&self.ram));
        policy.validate_data_request(request)?;
        let width = usize::from(quantity_bytes);
        for offset in (0..request.bytes).step_by(width) {
            policy.failure = None;
            let address = request.address + offset as u64;
            let result = policy.translate_part(
                request,
                DataPart {
                    address,
                    bytes: width,
                    kind: if request.flags & stela_compiler::context::memory::flags::WRITE != 0 {
                        AccessKind::Write
                    } else {
                        AccessKind::Read
                    },
                },
            );
            let write = request.flags & stela_compiler::context::memory::flags::WRITE != 0;
            let reached = match policy.failure {
                Some(policy::Failure::DeviceRead {
                    physical, bytes, ..
                }) if !write => Some((physical, bytes)),
                Some(policy::Failure::DeviceWrite {
                    physical, bytes, ..
                }) if write => Some((physical, bytes)),
                _ => None,
            };
            if result != Err((MemoryStatus::Unsupported, address))
                || reached != Some((physical + offset as u64, width))
            {
                return Err(MemoryStatus::Unsupported);
            }
        }
        Ok(())
    }

    fn fetch(&self, controls: &Controls, pc: u64, output: &mut [u8]) -> Result<(), MemoryStatus> {
        let mut tables = policy::Tables::new(&self.ram);
        let result = self.fetch_with_tables(controls, pc, output, &mut tables);
        #[cfg(feature = "native-profile")]
        self.source.record(
            source_profile::Fetch::FullSource,
            1,
            tables.reads,
            output.len(),
            result.is_ok(),
        );
        result
    }

    fn fetch_with_tables(
        &self,
        controls: &Controls,
        pc: u64,
        output: &mut [u8],
        tables: &mut policy::Tables<'_>,
    ) -> Result<(), MemoryStatus> {
        let outcome = mmu::translate(
            &controls.translation,
            pc,
            mmu::Access::Execute,
            controls.requester,
            tables,
        );
        if let Some(status) = tables.failure {
            return Err(status);
        }
        let mmu::Outcome::Mapped(mapped) = outcome else {
            return Err(MemoryStatus::Unsupported);
        };
        if mapped.memory != mmu::MemoryType::Normal
            || mapped.attributes == mmu::attributes::TAGGED
            || output.len() as u64 > mapped.size - (mapped.physical & (mapped.size - 1))
        {
            return Err(MemoryStatus::Unsupported);
        }
        // SAFETY: private source staging, disjoint from actual RAM/frames. Code
        // publication is held stopped by the outer scheduler through preparation.
        unsafe { self.ram.read_physical(mapped.physical, output) }
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Execute-source observations for the current actual PE. This includes
    /// entry checks and artifact byte validation; data counters are separate.
    #[cfg(feature = "native-profile")]
    pub fn native_source_statistics(&self) -> Option<NativeSourceStatistics> {
        self.cpu
            .canonical_memory
            .as_ref()
            .map(|memory| memory.source.statistics())
    }

    /// Cumulative actual epoch entries for the current canonical PE.
    #[cfg(feature = "native-profile")]
    pub fn native_epoch_statistics(&self) -> Option<NativeEpochStatistics> {
        self.cpu
            .canonical_memory
            .as_ref()
            .map(|memory| memory.epochs)
    }

    /// Cumulative observations for this actual current PE, not the full cohort.
    #[cfg(feature = "native-profile")]
    pub fn native_data_tlb_statistics(&mut self) -> Option<NativeDataTlbStatistics> {
        Some(
            self.cpu
                .canonical_memory
                .as_mut()?
                .memory
                .policy_mut()
                .data_tlb_statistics(),
        )
    }

    /// Bound every currently instantiated canonical PE's compiler artifacts.
    /// Reset/start owners inherit the tightened bound from their real source.
    /// No executing code or architectural state is cached or invalidated here.
    pub fn tighten_native_artifact_cache_budget(
        &mut self,
        per_pe_bytes: usize,
    ) -> Result<(), MemoryStatus> {
        for (pe, peer) in self.peers.iter().enumerate() {
            let cpu = match peer {
                super::processors::Peer::Running if pe == self.current => &self.cpu,
                super::processors::Peer::Parked(parked) => parked.cpu(),
                super::processors::Peer::Off => continue,
                _ => return Err(MemoryStatus::Domain),
            };
            let memory = cpu
                .canonical_memory
                .as_ref()
                .ok_or(MemoryStatus::Unsupported)?;
            if memory.pe != pe || !Arc::ptr_eq(&memory.machine, &self.native_memory_identity) {
                return Err(MemoryStatus::Domain);
            }
        }
        for (pe, peer) in self.peers.iter_mut().enumerate() {
            let cpu = match peer {
                super::processors::Peer::Running if pe == self.current => &mut self.cpu,
                super::processors::Peer::Parked(parked) => parked.cpu_mut(),
                super::processors::Peer::Off => continue,
                _ => unreachable!("validated actual PE roster"),
            };
            cpu.canonical_memory
                .as_mut()
                .expect("validated canonical owner")
                .tighten_artifact_cache_budget(per_pe_bytes);
        }
        Ok(())
    }

    /// Move every active PE's monitor/event authority into its actual Cpu.
    /// Before worker binding, exclusive Machine ownership excludes native loans;
    /// afterwards the complete roster must be recovered/invalidated and held in
    /// one stop generation. No prior monitor is reconstructed from copied bytes.
    pub fn install_shared_memory_for_processors(
        &mut self,
        ram: Arc<RegisteredSystemRam>,
        events: &crate::system::events::EventDomain,
    ) -> Result<(), MemoryStatus> {
        self.install_shared_memory(ram, events, false)
    }

    /// Convert exactly the instantiated Running/Parked Cpu owners. Peer::Off
    /// has no Cpu/frame authority and remains unbound; starts/reset/rebind must
    /// refuse until a real canonical owner and physical worker can be joined.
    pub fn install_shared_memory_for_active_processors(
        &mut self,
        ram: Arc<RegisteredSystemRam>,
        events: &crate::system::events::EventDomain,
    ) -> Result<(), MemoryStatus> {
        self.install_shared_memory(ram, events, true)
    }

    fn install_shared_memory(
        &mut self,
        ram: Arc<RegisteredSystemRam>,
        events: &crate::system::events::EventDomain,
        active_only: bool,
    ) -> Result<(), MemoryStatus> {
        if !matches!(
            self.peers.get(self.current),
            Some(super::processors::Peer::Running)
        ) {
            return Err(MemoryStatus::Unsupported);
        }
        if ram.reservation_granule() != crate::machine::cpu::RESERVATION_GRANULE {
            return Err(MemoryStatus::Unsupported);
        }
        if let Some(publication) = &self.native_publication {
            let members: Vec<_> = self
                .peers
                .iter()
                .enumerate()
                .filter_map(|(pe, peer)| {
                    (!active_only || !matches!(peer, super::processors::Peer::Off)).then_some(pe)
                })
                .collect();
            if active_only {
                publication.require_held_members(&members)
            } else {
                publication.require_stopped(self.peers.len(), &members)
            }
            .map_err(|_| MemoryStatus::Unsupported)?;
        }
        let mut prepared = Vec::with_capacity(self.peers.len());
        for (pe, peer) in self.peers.iter().enumerate() {
            let cpu = match peer {
                super::processors::Peer::Running
                    if pe == self.current && self.waiting.is_none() =>
                {
                    &self.cpu
                }
                super::processors::Peer::Parked(parked) if parked.native_ready() => parked.cpu(),
                super::processors::Peer::Off if active_only => continue,
                _ => return Err(MemoryStatus::Unsupported),
            };
            if cpu.canonical_memory.is_some() || cpu.monitor.is_some() {
                return Err(MemoryStatus::Unsupported);
            }
            let controls = Controls::capture(cpu, self.profile.name, &self.profile_missing)?;
            let mut memory = ram.domain().thread(Policy::new(controls, Arc::clone(&ram)));
            let event = events
                .register(cpu.event, None)
                .map_err(|_| MemoryStatus::Domain)?;
            memory.bind_events(&event.producer())?;
            prepared.push((
                pe,
                SharedMemory {
                    memory,
                    ram: Arc::clone(&ram),
                    pe,
                    event,
                    machine: Arc::clone(&self.native_memory_identity),
                    artifacts: native_run::ArtifactCache::default(),
                    #[cfg(feature = "native-profile")]
                    epochs: NativeEpochStatistics::default(),
                    #[cfg(feature = "native-profile")]
                    source: source_profile::Profile::default(),
                },
            ));
        }
        // No fallible step after the first move. The old scalar event storage
        // ceases to be authoritative; all services use the moved endpoint.
        for (pe, memory) in prepared {
            let cpu = match &mut self.peers[pe] {
                super::processors::Peer::Running => &mut self.cpu,
                super::processors::Peer::Parked(parked) => parked.cpu_mut(),
                super::processors::Peer::Off | super::processors::Peer::Remote => {
                    unreachable!("preflight admitted active PE")
                }
            };
            cpu.event = false;
            cpu.canonical_memory = Some(memory);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{
        cpu::Reservation,
        engine::{
            NoDevices,
            tests::{FakeHost, board_on},
        },
        system::Register,
    };
    use crate::system::events::EventDomain;
    use stela_compiler::context::memory::{
        MemoryOrder, MemoryRequest, MemoryRequirements,
        exclusive::{ExclusiveData, ExclusiveOperation, ExclusiveShape},
        flags,
    };
    const VA: u64 = 0x4000;
    const PA: u64 = 0x14000;
    pub(super) fn machine() -> (
        Machine<FakeHost, NoDevices>,
        Arc<RegisteredSystemRam>,
        EventDomain,
    ) {
        let (cpu, profile, missing, ram) = policy::tests::fixture();
        let mut machine = board_on(stela_contracts::Chip::AppleM1, &[], NoDevices, Vec::new());
        machine.cpu = cpu;
        machine.profile = profile;
        machine.profile_missing = missing;
        (machine, ram, EventDomain::new())
    }
    /// Actual POSIX byte/native-scalar service fixture. Its prepared legacy
    /// entry is not a production CPL0 proof and cannot enter NativeRun.
    fn transfer(cpu: &mut crate::machine::Cpu, operation: ExclusiveOperation) -> ExclusiveData {
        let memory = cpu.canonical_memory.as_mut().unwrap();
        let mut payload = ExclusiveData {
            operation: operation as u32,
            order: MemoryOrder::Relaxed as u32,
            shape: ExclusiveShape::Scalar as u32,
            value: if operation == ExclusiveOperation::Store {
                [7, 0]
            } else {
                [0, 0]
            },
            ..ExclusiveData::default()
        };
        let request = MemoryRequest {
            address: VA,
            pc: cpu.pc,
            bytes: 8,
            flags: flags::EXCLUSIVE
                | if operation == ExclusiveOperation::Store {
                    flags::WRITE
                } else {
                    0
                },
            data: core::ptr::from_mut(&mut payload).cast(),
        };
        let entry = memory
            .memory
            .prepare(MemoryRequirements::default())
            .unwrap();
        // SAFETY: the actual admitted POSIX fixture owns initialized private
        // typed staging and retains its source policy/native byte owner.
        let result = unsafe { entry.with_checked_view(|view| (view.callback)(view, &request)) };
        assert_eq!(result, Ok(MemoryStatus::Success as u32));
        payload
    }
    #[test]
    fn linear_conversion_moves_the_event_register_and_refuses_live_legacy_reservations() {
        let (mut machine, ram, events) = machine();
        machine.cpu.event = true;
        machine.cpu.monitor = Some(Reservation {
            granule: PA,
            bytes: [0; 64],
        });
        assert_eq!(
            machine.install_shared_memory_for_processors(Arc::clone(&ram), &events),
            Err(MemoryStatus::Unsupported)
        );
        assert!(
            machine.cpu.event
                && machine.cpu.monitor.is_some()
                && !machine.cpu.has_canonical_memory()
        );
        machine.cpu.monitor = None;
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        assert!(!machine.cpu.event && machine.cpu.event_is_set());
        assert!(machine.cpu.consume_event());
        assert!(!machine.cpu.consume_event());
        let producer = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .event_endpoint()
            .producer();
        assert!(producer.signal_local());
        assert!(machine.cpu.event_is_set());
        assert!(machine.cpu.consume_event());
        assert!(!machine.cpu.event_is_set());
        machine.cpu.signal_event();
        machine.cpu.signal_event();
        assert!(machine.cpu.consume_event());
        assert!(!machine.cpu.consume_event());
        // A producer cannot keep the actual PE endpoint alive after its owner.
        drop(machine);
        assert!(!producer.signal_local());
    }
    #[test]
    fn clrex_clears_the_real_local_reservation_and_retains_its_global_event_mark() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(Arc::clone(&ram), &events)
            .unwrap();
        assert_eq!(
            transfer(&mut machine.cpu, ExclusiveOperation::Load).value,
            [0; 2]
        );
        machine.cpu.clear_exclusive().unwrap();
        assert!(!machine.cpu.event_is_set());
        // The independent global mark still opens and signals on canonical ABA.
        unsafe { ram.publish_physical(PA, &1u64.to_le_bytes()) }.unwrap();
        unsafe { ram.publish_physical(PA, &0u64.to_le_bytes()) }.unwrap();
        assert!(machine.cpu.consume_event());
        assert!(!machine.cpu.consume_event());
        assert_eq!(
            transfer(&mut machine.cpu, ExclusiveOperation::Store).status,
            1
        );
        let mut value = [0; 8];
        unsafe { ram.read_physical(PA, &mut value) }.unwrap();
        assert_eq!(value, [0; 8]);
    }
    #[test]
    fn eret_clears_the_same_reservation_and_publishes_the_same_event_endpoint() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(Arc::clone(&ram), &events)
            .unwrap();
        transfer(&mut machine.cpu, ExclusiveOperation::Load);
        machine.cpu.registers.set_raw(Register::SPSR_EL1, 0, 5);
        machine.cpu.exception_return(0x8000).unwrap();
        assert_eq!(machine.cpu.pc, 0x8000);
        assert!(machine.cpu.consume_event());
        assert!(!machine.cpu.event); // legacy scalar storage was never copied back
        assert_eq!(
            transfer(&mut machine.cpu, ExclusiveOperation::Store).status,
            1
        );
    }
    #[test]
    fn failed_memory_owner_refuses_eret_before_any_cpu_or_event_effect() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let memory = machine.cpu.canonical_memory.as_mut().unwrap();
        // Corrupt finalization is a terminal domain failure, not a source fault.
        let result = unsafe { memory.memory.with_checked_view(|view| view.version = 0) };
        assert_eq!(result, Err(MemoryStatus::Domain));
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.pstate,
            machine.cpu.retired,
        );
        assert_eq!(
            machine.cpu.exception_return(0x8000),
            Err(MemoryStatus::Domain)
        );
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.pstate,
                machine.cpu.retired
            ),
            before
        );
        assert!(!machine.cpu.event_is_set());
    }
    #[test]
    fn source_clrex_sevl_and_wfe_use_the_cpu_owned_endpoint_and_monitor() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        transfer(&mut machine.cpu, ExclusiveOperation::Load);
        const CLREX: u32 = 0xd503_305f;
        const SEVL: u32 = 0xd503_20bf;
        const WFE: u32 = 0xd503_205f;
        let pc = machine.cpu.pc;
        machine.system_instruction(CLREX).unwrap();
        assert_eq!(machine.cpu.pc, pc + 4);
        assert_eq!(
            transfer(&mut machine.cpu, ExclusiveOperation::Store).status,
            1
        );
        machine.system_instruction(SEVL).unwrap();
        assert!(machine.cpu.event_is_set() && !machine.cpu.event);
        machine.system_instruction(WFE).unwrap();
        assert!(!machine.cpu.event_is_set());
        assert_eq!(machine.cpu.pc, pc + 12);
    }
    #[test]
    fn dropped_monitor_preparation_does_not_clear_the_real_reservation() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        transfer(&mut machine.cpu, ExclusiveOperation::Load);
        drop(machine.cpu.prepare_clear_exclusive().unwrap());
        assert_eq!(
            transfer(&mut machine.cpu, ExclusiveOperation::Store).status,
            0
        );
    }
    fn clock_domain(
        machine: &mut Machine<FakeHost, NoDevices>,
    ) -> stela_contracts::bus::LifecycleState {
        use super::super::ProcessorBinding;
        use stela_contracts::processor::ProcessorTarget;
        let active = stela_contracts::bus::LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: false,
        };
        machine
            .bind_processor_power(&[ProcessorBinding {
                domain: 1,
                target: ProcessorTarget::Core { pe: 0 },
                initial: active,
            }])
            .unwrap();
        active
    }
    #[test]
    fn retained_pause_commits_the_same_monitor_before_controller_ack() {
        use super::super::ProcessorChange;
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let active = clock_domain(&mut machine);
        transfer(&mut machine.cpu, ExclusiveOperation::Load);
        let state = machine.cpu.state.clone();
        let request = [ProcessorChange {
            domain: 1,
            state: stela_contracts::bus::LifecycleState {
                clocked: false,
                ..active
            },
        }];
        let held = machine.processor_write().apply(&request).unwrap();
        assert_eq!(held.paused(0), Some(true));
        drop(held); // the controller ACK is inside the retained actual-owner lease
        assert_eq!(machine.cpu.state, state);
        let resumed = machine
            .processor_write()
            .apply(&[ProcessorChange {
                domain: 1,
                state: active,
            }])
            .unwrap();
        drop(resumed);
        assert_eq!(
            transfer(&mut machine.cpu, ExclusiveOperation::Store).status,
            1
        );
    }
    #[test]
    fn failed_pause_preparation_changes_no_cpu_or_controller_state() {
        use super::super::{ProcessorChange, ProcessorPowerError};
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let active = clock_domain(&mut machine);
        let memory = machine.cpu.canonical_memory.as_mut().unwrap();
        assert_eq!(
            unsafe { memory.memory.with_checked_view(|view| view.version = 0) },
            Err(MemoryStatus::Domain)
        );
        let state = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.pstate,
            machine.cpu.retired,
        );
        let request = [ProcessorChange {
            domain: 1,
            state: stela_contracts::bus::LifecycleState {
                clocked: false,
                ..active
            },
        }];
        let result = machine.processor_write().apply(&request);
        assert!(matches!(
            result,
            Err(ProcessorPowerError::CanonicalMemory {
                pe: 0,
                status: MemoryStatus::Domain
            })
        ));
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.pstate,
                machine.cpu.retired
            ),
            state
        );
        assert_eq!(machine.processors().paused(0), Some(false));
    }
    #[test]
    fn converted_cpu_cannot_reenter_the_serial_direct_ram_scheduler() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.pstate,
            machine.cpu.retired,
        );
        assert!(matches!(machine.run(1), super::super::Stop::Unsupported(_)));
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.pstate,
                machine.cpu.retired
            ),
            before
        );
    }
    #[test]
    fn unjoined_power_loss_and_reset_refuse_before_dropping_the_live_owner() {
        let (mut machine, ram, events) = machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        machine.cpu.apple.cyc_ovrd = 3 << 24;
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.pstate,
            machine.cpu.retired,
        );
        assert!(machine.system_instruction(0xd503_207f).is_err());
        assert!(machine.waiting.is_none());
        assert!(machine.warm_reset().is_err());
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.pstate,
                machine.cpu.retired
            ),
            before
        );
        assert!(machine.cpu.has_canonical_memory());
        let producer = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .event_endpoint()
            .producer();
        assert!(producer.signal_local());
        assert!(machine.cpu.consume_event());
    }
    #[test]
    fn unregistered_native_inventory_is_never_a_stopped_conversion_receipt() {
        let (mut machine, ram, events) = machine();
        machine
            .bind_native_workers(&[super::super::publication::WorkerBinding {
                pe: 0,
                worker: super::super::publication::WorkerId(0),
            }])
            .unwrap();
        assert_eq!(
            machine.install_shared_memory_for_processors(ram, &events),
            Err(MemoryStatus::Unsupported)
        );
        assert!(!machine.cpu.has_canonical_memory());
    }
}
