//! Source-bound system accesses over the canonical physical RAM owner.
//! This is a checked execution service, not an additional VM or RAM image.
mod controls;
mod native_run;
mod policy;

use super::{Devices, Host, Machine, mmu};
use crate::memory::{RegisteredSystemRam, domain::MemoryThread};
use alloc::{sync::Arc, vec::Vec};
use controls::Controls;
pub use native_run::{
    Cohort as NativeCohort, Identity as NativeRunIdentity, NativeRun,
    Observation as NativeRunObservation, ReturnedRun, dispatch as dispatch_native_run,
    recover as recover_native_run,
};
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
}
impl<H: Host, D: Devices> Machine<H, D> {
    /// Prepare the current PE's persistent checked-memory service. This neither
    /// dispatches native code nor enables parallel machine execution. The RAM
    /// registration's all-writer contract must remain valid through final return.
    pub fn shared_memory_for_current(
        &self,
        ram: Arc<RegisteredSystemRam>,
        events: &crate::system::events::EventDomain,
    ) -> Result<SharedMemory, MemoryStatus> {
        if ram.reservation_granule() != crate::machine::cpu::RESERVATION_GRANULE {
            return Err(MemoryStatus::Unsupported);
        }
        let controls = Controls::capture(&self.cpu, self.profile.name, &self.profile_missing)?;
        let mut memory = ram.domain().thread(Policy::new(controls, Arc::clone(&ram)));
        let event = events
            .register(self.cpu.event, None)
            .map_err(|_| MemoryStatus::Domain)?;
        memory.bind_events(&event.producer())?;
        Ok(SharedMemory {
            memory,
            ram,
            pe: self.current,
            event,
            machine: Arc::clone(&self.native_memory_identity),
        })
    }
}

impl SharedMemory {
    pub fn processor(&self) -> usize {
        self.pe
    }
    pub fn event_endpoint(&self) -> &crate::system::events::EventEndpoint {
        &self.event
    }
    fn fetch(&self, controls: &Controls, pc: u64, output: &mut [u8]) -> Result<(), MemoryStatus> {
        let mut tables = policy::Tables::new(&self.ram);
        let outcome = mmu::translate(
            &controls.translation,
            pc,
            mmu::Access::Execute,
            controls.requester,
            &mut tables,
        );
        if let Some(status) = tables.failure {
            return Err(status);
        }
        let mmu::Outcome::Mapped(mapped) = outcome else {
            return Err(MemoryStatus::Unsupported);
        };
        if mapped.memory != mmu::MemoryType::Normal
            || !mmu::attributes::write_back(mapped.attributes)
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
    /// Persistent services for the exact active PE inventory, in PE order.
    /// Held-reset/down/waiting PEs need their ordinary lifecycle before joining.
    pub fn shared_memory_for_processors(
        &self,
        ram: Arc<RegisteredSystemRam>,
        events: &crate::system::events::EventDomain,
    ) -> Result<Vec<SharedMemory>, MemoryStatus> {
        if ram.reservation_granule() != crate::machine::cpu::RESERVATION_GRANULE {
            return Err(MemoryStatus::Unsupported);
        }
        self.peers
            .iter()
            .enumerate()
            .map(|(pe, peer)| {
                let cpu = match peer {
                    super::processors::Peer::Running
                        if pe == self.current && self.waiting.is_none() =>
                    {
                        &self.cpu
                    }
                    super::processors::Peer::Parked(parked) if parked.native_ready() => {
                        parked.cpu()
                    }
                    _ => return Err(MemoryStatus::Unsupported),
                };
                let controls = Controls::capture(cpu, self.profile.name, &self.profile_missing)?;
                let mut memory = ram.domain().thread(Policy::new(controls, Arc::clone(&ram)));
                let event = events
                    .register(cpu.event, None)
                    .map_err(|_| MemoryStatus::Domain)?;
                memory.bind_events(&event.producer())?;
                Ok(SharedMemory {
                    memory,
                    ram: Arc::clone(&ram),
                    pe,
                    event,
                    machine: Arc::clone(&self.native_memory_identity),
                })
            })
            .collect()
    }
}
