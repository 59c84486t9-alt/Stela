//! Reset joins keep the canonical physical domain and real stopped workers.
//! Off PEs have assigned physical owners, never invented architectural frames.
use super::super::{processors::Peer, publication};
use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Bind the complete assigned physical roster. Unstarted PEs have no Cpu;
    /// their real Hosts must still publish initialization before any start.
    pub fn bind_assigned_native_workers(
        &mut self,
        bindings: &[publication::WorkerBinding],
    ) -> Result<Vec<publication::WorkerOwner>, publication::PublicationError> {
        for (pe, peer) in self.peers.iter().enumerate() {
            let cpu = match peer {
                Peer::Running if pe == self.current => &self.cpu,
                Peer::Parked(parked) => parked.cpu(),
                Peer::Off => continue,
                _ => return Err(publication::PublicationError::UnknownPe(pe)),
            };
            if !cpu.canonical_memory.as_ref().is_some_and(|memory| {
                memory.pe == pe && Arc::ptr_eq(&memory.machine, &self.native_memory_identity)
            }) {
                return Err(publication::PublicationError::UnknownPe(pe));
            }
        }
        self.bind_native_workers(bindings)
    }

    pub(in crate::machine::engine) fn require_native_lifecycle_hold(
        &self,
    ) -> Result<(), MemoryStatus> {
        let inventory = self
            .native_publication
            .as_ref()
            .ok_or(MemoryStatus::Unsupported)?;
        let members: Vec<_> = (0..self.peers.len()).collect();
        inventory
            .require_stopped(self.peers.len(), &members)
            .map_err(|_| MemoryStatus::Unsupported)
    }

    pub(in crate::machine::engine) fn prepare_native_reset(
        &self,
        pe: usize,
        cpu: &mut crate::machine::Cpu,
    ) -> Result<(), MemoryStatus> {
        self.require_native_lifecycle_hold()?;
        if pe >= self.peers.len() {
            return Err(MemoryStatus::Unsupported);
        }
        let source = self
            .cpu
            .canonical_memory
            .as_ref()
            .ok_or(MemoryStatus::Unsupported)?;
        if !Arc::ptr_eq(&source.machine, &self.native_memory_identity) {
            return Err(MemoryStatus::Domain);
        }
        for (index, peer) in self.peers.iter().enumerate() {
            let current = match peer {
                Peer::Running if index == self.current => &self.cpu,
                Peer::Parked(parked) => parked.cpu(),
                Peer::Off => continue,
                _ => return Err(MemoryStatus::Domain),
            };
            let memory = current
                .canonical_memory
                .as_ref()
                .ok_or(MemoryStatus::Unsupported)?;
            if memory.pe != index
                || !Arc::ptr_eq(&memory.ram, &source.ram)
                || !Arc::ptr_eq(&memory.machine, &source.machine)
                || !memory.event.same_domain(&source.event)
            {
                return Err(MemoryStatus::Domain);
            }
        }
        let memory =
            source.prepare_reset_peer(cpu, pe, self.profile.name, &self.profile_missing)?;
        cpu.event = false;
        cpu.canonical_memory = Some(memory);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
