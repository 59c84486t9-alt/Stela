//! Reset joins retain the canonical physical domain and real stopped workers.
//! Off PEs have assigned physical owners, never fabricated architectural frames.
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
mod tests {
    use super::*;
    use crate::machine::engine::Start;
    use crate::machine::exception::Pstate;
    use crate::machine::{Cpu, CpuProfile, InstallError, NativeCode, NativeExit, Regime};
    use publication::{StoppedWorkers, WorkerBinding, WorkerId, WorkerOwner};
    use stela_compiler::GuestState;

    struct Local(usize);
    impl Host for Local {
        fn native_worker(&self) -> Option<WorkerId> {
            Some(WorkerId(self.0))
        }
        fn read_ram(&mut self, _: u64, _: &mut [u8]) -> bool {
            panic!("raw RAM")
        }
        fn write_ram(&mut self, _: u64, _: &[u8]) -> bool {
            panic!("raw RAM")
        }
        fn install(&mut self, _: &[u8]) -> Result<NativeCode, InstallError> {
            unreachable!()
        }
        fn patch(&mut self, _: NativeCode, _: &[u8]) {
            unreachable!()
        }
        fn discard_code(&mut self) {}
        unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
            unreachable!()
        }
        fn set_regime(&mut self, _: &Regime) {}
        fn invalidate_translations(&mut self) {}
        fn counter(&mut self) -> u64 {
            1
        }
        fn arm_timer(&mut self, _: Option<u64>) {}
        fn wait_for_interrupt(&mut self) {
            unreachable!()
        }
    }
    struct Board {
        power: Vec<(usize, bool)>,
    }
    impl Devices for Board {
        fn read(
            &mut self,
            _: usize,
            _: u64,
            _: u8,
            _: u64,
        ) -> Result<u64, crate::machine::DeviceError> {
            Err(crate::machine::DeviceError::NoDevice)
        }
        fn write(
            &mut self,
            _: usize,
            _: u64,
            _: u8,
            _: u64,
            _: u64,
        ) -> Result<(), crate::machine::DeviceError> {
            Err(crate::machine::DeviceError::NoDevice)
        }
        fn lines(&mut self, _: usize, _: u64) -> crate::machine::engine::Lines {
            Default::default()
        }
        fn reset_vector(&self, _: usize) -> Option<u64> {
            Some(0x9000)
        }
        fn processor_power(&mut self, pe: usize, powered: bool) {
            self.power.push((pe, powered));
        }
    }
    fn fixture(count: usize) -> (Machine<Local, Board>, Vec<WorkerOwner>) {
        let (cpu, mut profile, missing, ram) = super::super::policy::tests::fixture();
        profile.processors = (0..count)
            .map(|pe| crate::machine::registers::Identity {
                midr: 0x611f0220,
                mpidr: 0x80000000 | pe as u64,
                clock: None,
                caches: None,
            })
            .collect();
        let mut machine = Machine::new(
            cpu,
            Local(0),
            Board { power: Vec::new() },
            profile,
            ram.target(),
        );
        machine.profile_missing = missing;
        machine
            .install_shared_memory_for_active_processors(
                ram,
                &crate::system::events::EventDomain::new(),
            )
            .unwrap();
        let bindings: Vec<_> = (0..count)
            .map(|pe| WorkerBinding {
                pe,
                worker: WorkerId(pe),
            })
            .collect();
        let mut owners = machine.bind_assigned_native_workers(&bindings).unwrap();
        let inventory = machine.native_publication.as_mut().unwrap();
        for owner in &mut owners {
            let initialized = owner
                .publish_initial(&mut Local(owner.binding().worker.0))
                .unwrap();
            inventory.accept_initial(initialized).unwrap();
        }
        (machine, owners)
    }
    // This is the real publication state machine with non-executing owner-local
    // test Hosts. It proves lifecycle authority, not physical/native execution.
    fn hold(machine: &mut Machine<Local, Board>, owners: &mut [WorkerOwner]) -> StoppedWorkers {
        let inventory = machine.native_publication.as_mut().unwrap();
        let members: Vec<_> = (0..owners.len()).collect();
        let request = inventory.request_stop(&members).unwrap();
        for command in inventory.native_stop_commands(&request).unwrap() {
            let pe = command.binding().pe;
            let receipt = owners[pe].invalidate(command, &mut Local(pe)).unwrap();
            inventory.accept_invalidation(receipt).unwrap();
        }
        inventory.hold_stop(request).unwrap()
    }
    fn fresh(profile: &CpuProfile, pe: usize) -> Cpu {
        let mut cpu = Cpu::of(profile.chip, 0x8000, Pstate::reset(2));
        crate::machine::engine::system::identify(profile, pe, &mut cpu, &mut Vec::new());
        cpu
    }
    #[test]
    fn assigned_off_pe_starts_only_with_actual_complete_held_roster() {
        let (mut machine, mut owners) = fixture(3);
        assert!(matches!(machine.peers[1], Peer::Off));
        let before = machine.cpu.state.clone();
        assert!(
            machine
                .start(Start {
                    cpu: 1,
                    address: 0x8000
                })
                .is_err()
        );
        assert!(matches!(machine.peers[1], Peer::Off));
        assert_eq!(machine.cpu.state, before);
        let held = hold(&mut machine, &mut owners);
        machine
            .start(Start {
                cpu: 1,
                address: 0x8000,
            })
            .unwrap();
        let Peer::Parked(parked) = &machine.peers[1] else {
            panic!("actual started Cpu")
        };
        assert_eq!(parked.cpu().pc, 0x8000);
        assert_eq!(parked.cpu().pstate, Pstate::reset(2));
        let source = machine.cpu.canonical_memory.as_ref().unwrap();
        let memory = parked.cpu().canonical_memory.as_ref().unwrap();
        assert_eq!(memory.pe, 1);
        assert!(Arc::ptr_eq(&source.ram, &memory.ram));
        assert!(source.event.same_domain(&memory.event));
        source.event.domain().signal_all().unwrap();
        assert!(machine.cpu.consume_event());
        let Peer::Parked(parked) = &mut machine.peers[1] else {
            unreachable!()
        };
        assert!(parked.cpu_mut().consume_event());
        assert!(matches!(machine.peers[2], Peer::Off));
        assert!(
            machine
                .start(Start {
                    cpu: 1,
                    address: 0x9000
                })
                .is_err()
        );
        machine
            .native_publication
            .as_ref()
            .unwrap()
            .require_all_held(&held)
            .unwrap();
    }
    #[test]
    fn reset_preparation_rejects_incomplete_or_released_generation_without_effects() {
        let (mut machine, mut owners) = fixture(2);
        let mut candidate = fresh(&machine.profile, 1);
        assert!(machine.prepare_native_reset(1, &mut candidate).is_err());
        assert!(!candidate.has_canonical_memory());
        let held = hold(&mut machine, &mut owners);
        let inventory = machine.native_publication.as_mut().unwrap();
        for command in inventory.release(held).unwrap() {
            let pe = command.binding().pe;
            inventory
                .accept_release(owners[pe].release(command).unwrap())
                .unwrap();
        }
        assert!(machine.prepare_native_reset(1, &mut candidate).is_err());
        assert!(!candidate.has_canonical_memory());
        assert!(matches!(machine.peers[1], Peer::Off));
    }
    #[test]
    fn warm_reset_retains_registered_ram_and_other_pe_event_identity() {
        let (mut machine, mut owners) = fixture(2);
        let held = hold(&mut machine, &mut owners);
        machine
            .start(Start {
                cpu: 1,
                address: 0x8000,
            })
            .unwrap();
        let Peer::Parked(parked) = &machine.peers[1] else {
            unreachable!()
        };
        let other = parked
            .cpu()
            .canonical_memory
            .as_ref()
            .unwrap()
            .event
            .producer();
        let ram = Arc::clone(&machine.cpu.canonical_memory.as_ref().unwrap().ram);
        machine.cpu.retired = 17;
        machine.cpu.state.x[0] = 0x12345678;
        machine.warm_reset().unwrap();
        assert_eq!(machine.cpu.pc, 0x9000);
        assert_eq!(machine.cpu.retired, 17);
        assert_eq!(machine.cpu.state.x[0], 0);
        assert_eq!(machine.cpu.pstate, Pstate::reset(2));
        let memory = machine.cpu.canonical_memory.as_ref().unwrap();
        assert!(Arc::ptr_eq(&memory.ram, &ram));
        assert!(other.signal_local());
        let Peer::Parked(parked) = &mut machine.peers[1] else {
            unreachable!()
        };
        assert!(parked.cpu_mut().consume_event());
        machine
            .native_publication
            .as_ref()
            .unwrap()
            .require_all_held(&held)
            .unwrap();
    }
}
