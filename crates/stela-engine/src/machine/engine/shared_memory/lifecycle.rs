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
            .map(|pe| stela_contracts::identity::Identity {
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
    // test Hosts. It proves lifecycle permission, not physical/native execution.
    fn hold(machine: &mut Machine<Local, Board>, owners: &mut [WorkerOwner]) -> StoppedWorkers {
        let members: Vec<_> = owners.iter().map(|owner| owner.binding().pe).collect();
        hold_members(
            machine.native_publication.as_mut().unwrap(),
            owners,
            &members,
        )
    }
    fn hold_members(
        inventory: &mut publication::WorkerPublications,
        owners: &mut [WorkerOwner],
        members: &[usize],
    ) -> StoppedWorkers {
        let request = inventory.request_stop(members).unwrap();
        for command in inventory.native_stop_commands(&request).unwrap() {
            let binding = command.binding();
            let owner = owners
                .iter_mut()
                .find(|owner| owner.binding() == binding)
                .unwrap();
            let receipt = owner
                .invalidate(command, &mut Local(binding.worker.0))
                .unwrap();
            inventory.accept_invalidation(receipt).unwrap();
        }
        inventory.hold_stop(request).unwrap()
    }
    fn release_members(
        inventory: &mut publication::WorkerPublications,
        owners: &mut [WorkerOwner],
        held: StoppedWorkers,
    ) {
        for command in inventory.release(held).unwrap() {
            let owner = owners
                .iter_mut()
                .find(|owner| owner.binding() == command.binding())
                .unwrap();
            inventory
                .accept_release(owner.release(command).unwrap())
                .unwrap();
        }
    }

    // These Hosts model fixed physical identities, not concurrent processors or
    // privileged native entry. Effects still require the real held owner token.
    struct OwnerServices(Vec<WorkerOwner>);
    impl ServiceTransport for OwnerServices {
        fn apply(
            &mut self,
            local: &mut dyn Host,
            command: publication::HostEffectCommand,
        ) -> Result<
            publication::HostEffectReceipt,
            publication::WithPayload<publication::HostEffectCommand>,
        > {
            let binding = command.binding();
            let owner = self
                .0
                .iter_mut()
                .find(|owner| owner.binding() == binding)
                .unwrap();
            if binding.worker == WorkerId(0) {
                owner.apply_host_effect(command, local)
            } else {
                owner.apply_host_effect(command, &mut Local(binding.worker.0))
            }
        }
        fn fail_stopped(&mut self, reason: &'static str) -> ! {
            panic!("{reason}");
        }
    }
    type FirstPMachine = Machine<ServiceHost<Local, OwnerServices>, Board>;
    const FIRST_P: usize = 2;
    const SOURCE: u64 = 0x14000;
    // Neither PE order nor worker order; PE2 is the host BSP.
    const PERMUTED: [WorkerBinding; 4] = [
        WorkerBinding {
            pe: 3,
            worker: WorkerId(2),
        },
        WorkerBinding {
            pe: 0,
            worker: WorkerId(3),
        },
        WorkerBinding {
            pe: 2,
            worker: WorkerId(0),
        },
        WorkerBinding {
            pe: 1,
            worker: WorkerId(1),
        },
    ];
    fn first_p_fixture() -> (FirstPMachine, Arc<RegisteredSystemRam>) {
        let (mut cpu, mut profile, missing, ram) = super::super::policy::tests::fixture();
        // Authored E,E,P,P roster; preserve the original indices and affinities.
        profile.processors = (0..4)
            .map(|pe| stela_contracts::identity::Identity {
                midr: if pe < FIRST_P { 0x611f0220 } else { 0x611f0230 },
                mpidr: 0x80000000
                    | if pe < FIRST_P {
                        pe as u64
                    } else {
                        0x10100 + (pe - FIRST_P) as u64
                    },
                clock: None,
                caches: None,
            })
            .collect();
        cpu.pstate = Pstate::reset(2);
        cpu.pc = SOURCE;
        cpu.registers
            .set_raw(crate::machine::system::Register::SCTLR_EL2, 0, 0);
        cpu.state.x[0] = 0xfeed1234;
        cpu.state.sp = 0x15800;
        // SAFETY: the fixture owns these registered bytes; no executor exists.
        unsafe { ram.publish_physical(SOURCE, &0x14000000u32.to_le_bytes()) }.unwrap();
        let mut machine = Machine::new_at(
            cpu,
            ServiceHost::new(Local(0), OwnerServices(Vec::new()), Arc::clone(&ram)),
            Board { power: Vec::new() },
            profile,
            ram.target(),
            FIRST_P,
        )
        .unwrap();
        machine.profile_missing = missing;
        machine
            .install_shared_memory_for_active_processors(
                Arc::clone(&ram),
                &crate::system::events::EventDomain::new(),
            )
            .unwrap();
        (machine, ram)
    }
    fn bind_first_p(machine: &mut FirstPMachine) {
        let mut owners = machine.bind_assigned_native_workers(&PERMUTED).unwrap();
        for owner in &mut owners {
            let initial = if owner.binding().worker == WorkerId(0) {
                owner.publish_initial(&mut machine.host)
            } else {
                owner.publish_initial(&mut Local(owner.binding().worker.0))
            }
            .unwrap();
            machine
                .native_publication
                .as_mut()
                .unwrap()
                .accept_initial(initial)
                .unwrap();
        }
        machine.host.transport.0 = owners;
    }
    fn hold_first_p(machine: &mut FirstPMachine, members: &[usize]) -> StoppedWorkers {
        hold_members(
            machine.native_publication.as_mut().unwrap(),
            &mut machine.host.transport.0,
            members,
        )
    }
    fn release_first_p(machine: &mut FirstPMachine, held: StoppedWorkers) {
        release_members(
            machine.native_publication.as_mut().unwrap(),
            &mut machine.host.transport.0,
            held,
        );
    }

    #[test]
    fn nonzero_first_p_binding_refuses_incomplete_or_nonbijective_rosters_before_publication() {
        use publication::PublicationError;
        let (mut machine, _) = first_p_fixture();
        let mut repeated_pe = PERMUTED;
        repeated_pe[3].pe = FIRST_P;
        let mut repeated_worker = PERMUTED;
        repeated_worker[3].worker = WorkerId(0);
        for (bindings, error) in [
            (
                &PERMUTED[..3],
                PublicationError::ProcessorCount {
                    expected: 4,
                    actual: 3,
                },
            ),
            (
                repeated_pe.as_slice(),
                PublicationError::ProcessorCount {
                    expected: 4,
                    actual: 4,
                },
            ),
            (
                repeated_worker.as_slice(),
                PublicationError::DuplicateWorker(WorkerId(0)),
            ),
        ] {
            assert_eq!(
                machine.bind_assigned_native_workers(bindings).unwrap_err(),
                error
            );
            assert!(machine.native_publication.is_none());
            assert_eq!(machine.current, FIRST_P);
            assert!(matches!(machine.peers[0], Peer::Off));
        }
        bind_first_p(&mut machine);
        assert_eq!(
            machine
                .native_publication
                .as_ref()
                .unwrap()
                .bindings()
                .collect::<Vec<_>>(),
            PERMUTED
        );
    }

    #[test]
    fn nonzero_first_p_bsp_recovers_actual_native_refusal_and_starts_unrenumbered_peers() {
        use publication::PublicationError;
        let (mut machine, ram) = first_p_fixture();
        let identities = machine.profile.processors.clone();
        let state = machine.cpu.state.clone();
        bind_first_p(&mut machine);
        assert_eq!(machine.cpu.canonical_memory.as_ref().unwrap().pe, FIRST_P);
        assert!(matches!(machine.peers[FIRST_P], Peer::Running));
        assert!(
            machine
                .start(Start {
                    cpu: 0,
                    address: SOURCE
                })
                .is_err()
        );
        assert!(matches!(machine.peers[0], Peer::Off));

        // Real source compilation, mutable architectural frame and publication
        // recovery; never replace the host privilege refusal with success.
        for start_others in [false, true] {
            if start_others {
                let held = hold_first_p(&mut machine, &[1, 3, 2, 0]);
                let inventory = machine.native_publication.as_mut().unwrap();
                let services = PERMUTED
                    .iter()
                    .map(|binding| inventory.open_services(&held, binding.pe).unwrap())
                    .collect();
                machine.host.begin_services(services).unwrap();
                for binding in PERMUTED {
                    assert!(machine.host.select_native_service(binding.worker));
                    machine.host.invalidate_translations();
                }
                for services in machine.host.end_services() {
                    inventory.close_services(services).unwrap();
                }
                for pe in [0, 1, 3] {
                    machine
                        .start(Start {
                            cpu: pe,
                            address: SOURCE,
                        })
                        .unwrap();
                }
                assert_eq!(machine.devices.power, [(0, true), (1, true), (3, true)]);
                release_first_p(&mut machine, held);
            }
            // SAFETY: canonical owners and exclusive borrowed frames;
            // no external writer or concurrent worker. Hosted entry must refuse.
            let cohort = unsafe { machine.shared_native_cohort(&PERMUTED) }.unwrap();
            assert_eq!(cohort.frames.len(), if start_others { 4 } else { 1 });
            for frame in cohort.frames {
                let pe = frame.identity().pe;
                let loan = super::super::dispatch_native_run(cohort.inventory, frame)
                    .unwrap_or_else(|_| panic!("actual frame dispatch"));
                let binding = loan.binding();
                assert_eq!(
                    binding,
                    *PERMUTED.iter().find(|binding| binding.pe == pe).unwrap()
                );
                let index = cohort
                    .host
                    .transport
                    .0
                    .iter()
                    .position(|owner| owner.binding() == binding)
                    .unwrap();
                let mut owner = cohort.host.transport.0.remove(index);
                let refused = match owner.execute(loan, &mut Local((binding.worker.0 + 1) % 4)) {
                    Err(refused) => refused,
                    Ok(_) => panic!("wrong Host must retain the unexecuted frame"),
                };
                assert_eq!(refused.error, PublicationError::WrongOwner);
                let returned = if binding.worker == WorkerId(0) {
                    owner.execute(refused.payload, cohort.host)
                } else {
                    owner.execute(refused.payload, &mut Local(binding.worker.0))
                }
                .unwrap_or_else(|_| panic!("actual owner return"));
                let generation = returned.generation();
                let observation = super::super::recover_native_run(cohort.inventory, returned)
                    .unwrap_or_else(|_| panic!("actual frame recovery"));
                assert_eq!(observation.identity.pe, pe);
                assert_eq!(observation.status, Err(MemoryStatus::Unsupported));
                assert_eq!(observation.native, None);
                assert_eq!(observation.physical_processor, None);
                assert_eq!((observation.settled_pc, observation.retired), (SOURCE, 0));
                cohort
                    .inventory
                    .require_recovered(binding, generation)
                    .unwrap();
                assert_eq!(
                    cohort.inventory.require_recovered(binding, generation - 1),
                    Err(PublicationError::StaleRun)
                );
                cohort.host.transport.0.insert(index, owner);
            }
        }
        assert_eq!(machine.profile.processors, identities);
        assert_eq!(machine.current, FIRST_P);
        assert_eq!(machine.cpu.state, state);
        assert_eq!((machine.cpu.pc, machine.cpu.retired), (SOURCE, 0));
        // The real domain loan pins every PE's same RAM owner. A numeric PE or
        // worker permutation cannot substitute for this all-writer exclusion.
        let execution = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .memory
            .execution_loan()
            .unwrap();
        for (pe, peer) in machine.peers.iter().enumerate() {
            let cpu = match peer {
                Peer::Running => &machine.cpu,
                Peer::Parked(parked) => parked.cpu(),
                Peer::Off | Peer::Remote => panic!("started PE"),
            };
            let memory = cpu.canonical_memory.as_ref().unwrap();
            assert_eq!(memory.pe, pe);
            execution.check_thread_domain(&memory.memory).unwrap();
            assert!(Arc::ptr_eq(&memory.ram, &ram));
            assert_eq!(
                cpu.read(crate::machine::system::Register::MPIDR_EL1),
                identities[pe].mpidr
            );
        }
        assert!(ram.try_service().unwrap().is_none());
        drop(execution);
        let service = ram.try_service().unwrap().unwrap();
        service.validate_current().unwrap();
        assert!(matches!(
            ram.domain().try_execution_loan().unwrap(),
            crate::memory::domain::ExecutionLoanAttempt::ServiceBusy
        ));
    }

    #[test]
    fn nonzero_first_p_lifecycle_refuses_mixed_and_released_stop_generations() {
        let (mut machine, _) = first_p_fixture();
        bind_first_p(&mut machine);
        let state = machine.cpu.state.clone();
        let first = hold_first_p(&mut machine, &[FIRST_P]);
        let second = hold_first_p(&mut machine, &[0, 1, 3]);
        let mut reset = fresh(&machine.profile, 0);
        assert_eq!(
            machine.prepare_native_reset(0, &mut reset),
            Err(MemoryStatus::Unsupported)
        );
        assert!(reset.canonical_memory.is_none());
        assert_eq!(machine.cpu.state, state);
        release_first_p(&mut machine, first);
        release_first_p(&mut machine, second);
        let held = hold_first_p(&mut machine, &[3, 1, 0, FIRST_P]);
        machine.prepare_native_reset(0, &mut reset).unwrap();
        assert_eq!(reset.canonical_memory.as_ref().unwrap().pe, 0);
        release_first_p(&mut machine, held);
        let mut next = fresh(&machine.profile, 1);
        assert_eq!(
            machine.prepare_native_reset(1, &mut next),
            Err(MemoryStatus::Unsupported)
        );
        assert!(next.canonical_memory.is_none());
        assert!(matches!(machine.peers[0], Peer::Off));
        assert!(machine.devices.power.is_empty());
    }
    #[test]
    fn actual_tlbi_and_both_preparations_refresh_every_retained_data_tlb() {
        use super::super::policy::tests::ordinary_transfer;
        use crate::machine::system::Register;
        const LEAF: u64 = 0x13020;
        const DATA: u64 = 0x14000;
        const OTHER: u64 = 0x15000;
        const VA: u64 = 0x4000;
        const TLBI_VAE1IS_X0: u32 = 0xd508_8320;
        let (mut machine, mut owners) = fixture(2);
        let held = hold(&mut machine, &mut owners);
        machine
            .start(Start {
                cpu: 1,
                address: VA,
            })
            .unwrap();
        machine.cpu.pc = VA;
        let ram = Arc::clone(&machine.cpu.canonical_memory.as_ref().unwrap().ram);
        let publish = |physical, bytes: &[u8]| {
            // SAFETY: fixture-owned canonical RAM; owners remain held.
            unsafe { ram.publish_physical(physical, bytes) }.unwrap();
        };
        for physical in [DATA, OTHER] {
            publish(physical, &0x1400_0000u32.to_le_bytes());
        }
        publish(DATA + 8, &7u64.to_le_bytes());
        publish(OTHER + 8, &9u64.to_le_bytes());
        let Peer::Parked(parked) = &mut machine.peers[1] else {
            panic!("started PE");
        };
        let cpu = parked.cpu_mut();
        cpu.pstate = Pstate::reset(1);
        cpu.registers
            .set_raw(Register::SCTLR_EL1, 0, 1 | (1 << 2) | (1 << 12));
        cpu.registers.set_raw(
            Register::TCR_EL1,
            0,
            16 | (16 << 16) | (1 << 23) | (5 << 32),
        );
        cpu.registers.set_raw(Register::TTBR0_EL1, 0, 0x10000);
        cpu.registers.set_raw(Register::MAIR_EL1, 0, 0xff);
        let bindings: Vec<_> = owners.iter().map(WorkerOwner::binding).collect();
        let read = |cpu: &mut Cpu| {
            let mut bytes = [0; 8];
            assert_eq!(
                ordinary_transfer(
                    &mut cpu.canonical_memory.as_mut().unwrap().memory,
                    VA + 8,
                    &mut bytes,
                    0
                )
                .0,
                MemoryStatus::Success
            );
            u64::from_le_bytes(bytes)
        };
        // Both preparation APIs receive the Machine epoch. No fixture
        // executes native code or invents a target/worker execution receipt.
        drop(machine.native_cohort(&bindings, true).unwrap());
        assert_eq!(read(&mut machine.cpu), 7);
        let Peer::Parked(parked) = &mut machine.peers[1] else {
            unreachable!()
        };
        assert_eq!(read(parked.cpu_mut()), 7);
        publish(LEAF, &(OTHER | 3 | (1 << 10) | (3 << 8)).to_le_bytes());
        // Routine worker invalidation leaves architectural TLB metadata intact.
        machine.host.invalidate_translations();
        drop(machine.native_cohort(&bindings, true).unwrap());
        assert_eq!(read(&mut machine.cpu), 7);
        let Peer::Parked(parked) = &mut machine.peers[1] else {
            unreachable!()
        };
        assert_eq!(read(parked.cpu_mut()), 7);
        machine.cpu.state.x[0] = VA >> 12;
        machine.system_instruction(TLBI_VAE1IS_X0).unwrap();
        // Refresh only the BSP first. The parked peer still has old metadata
        // until its next preparation consumes the newer global epoch.
        // SAFETY: all real fixture owners are held, and the unexecuted loan is
        // dropped before any Machine mutation. This grants no physical entry.
        drop(unsafe { machine.shared_native_run(bindings[0]) }.unwrap());
        assert_eq!(read(&mut machine.cpu), 9);
        drop(machine.native_cohort(&bindings, true).unwrap());
        let Peer::Parked(parked) = &mut machine.peers[1] else {
            unreachable!()
        };
        assert_eq!(read(parked.cpu_mut()), 9);
        release_members(
            machine.native_publication.as_mut().unwrap(),
            &mut owners,
            held,
        );
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
