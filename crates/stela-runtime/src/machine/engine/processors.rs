//! The board's PEs. One runs on [`Machine::cpu`]; each other one is off,
//! preempted at the end of its time slice, or waiting in WFI or WFE. The
//! scheduler gives each PE that can run a time slice in turn, of at most
//! [`QUANTUM`] blocks and [`QUANTUM_HZ`]⁻¹ seconds of the system counter, and
//! waits on the host when none can.
//!
//! The PEs share the system counter but not the host: a PE preempted while
//! it holds a spinlock keeps it until its next turn, while the others spin
//! against the kernel's timeout. XNU 26A434 panics once a ticket spinlock
//! stays held for 3,000,000 counts (125 ms at 24 MHz, `lock_ticket.c`), so
//! a slice bounded in counter time keeps the wait for a preempted holder,
//! at most one slice of every other PE, short of it on every board, and the
//! counter itself advances no faster than the PEs progress (`clock`).
//!
//! Native code writes guest RAM directly, so the engine cannot see the store
//! by one PE that clears another PE's global Exclusives monitor (Arm
//! `ClearExclusiveByAddress`) as it happens; `Machine::observe_writes`
//! finds it between runs, and a PE that resumes after another ran has lost
//! its reservation.
use super::{
    Devices, Host, Machine, RequirementKind, Start, Step, Stop, Wait, WaitKind, interrupt_pending,
    system, timer,
};
use crate::machine::{
    cpu::{Cpu, RESERVATION_GRANULE},
    exception::Pstate,
    registers::CpuProfile,
    registers::Lines,
};
use alloc::{boxed::Box, vec::Vec};

/// Blocks a PE runs before the next PE that can run gets its turn.
pub(super) const QUANTUM: u64 = 1 << 14;
/// The inverse of the longest time slice in seconds of the system counter:
/// 2 ms, so the seven other PEs of an eight-PE board hold a preempted
/// spinlock holder off for at most 14 ms.
pub(super) const QUANTUM_HZ: u64 = 500;

pub(super) enum Peer {
    /// The PE on [`Machine::cpu`].
    Running,
    /// Held in reset until a device starts it.
    Off,
    Parked(Box<Parked>),
}

pub(super) struct Parked {
    cpu: Cpu,
    event_sample: Option<u64>,
    waiting: Option<Wait>,
}

/// PE 0 runs; the others are off. A profile without processors has one PE.
pub(super) fn boot(profile: &CpuProfile) -> Vec<Peer> {
    let mut peers: Vec<Peer> = (0..profile.processors.len().max(1))
        .map(|_| Peer::Off)
        .collect();
    peers[0] = Peer::Running;
    peers
}

impl Parked {
    pub(super) fn cpu_mut(&mut self) -> &mut Cpu {
        &mut self.cpu
    }
}

/// A PE as a report shows it.
#[derive(Debug, Clone, Copy)]
pub enum PeerState<'a> {
    Running,
    Off,
    /// Out of reset but not running: its state, and whether it waits in
    /// WFI (`Some(true)`) or WFE (`Some(false)`).
    Parked {
        cpu: &'a Cpu,
        wfi: Option<bool>,
    },
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// The number of the running PE.
    pub fn processor(&self) -> usize {
        self.current
    }

    /// Every PE's state, in PE order.
    pub fn peer_states(&self) -> Vec<PeerState<'_>> {
        self.peers
            .iter()
            .map(|peer| match peer {
                Peer::Running => PeerState::Running,
                Peer::Off => PeerState::Off,
                Peer::Parked(parked) => PeerState::Parked {
                    cpu: &parked.cpu,
                    wfi: parked.waiting.map(|wait| wait.kind == WaitKind::Interrupt),
                },
            })
            .collect()
    }

    /// Release the PEs devices started, then keep the running PE until its
    /// time slice ends or it waits. Otherwise run the next PE that can, round
    /// robin from the running one, or wait on the host until one can; with
    /// nothing left to wake any PE the machine is idle.
    pub(super) fn schedule(&mut self) -> Step {
        while let Some(start) = self.devices.take_start() {
            self.start(start)?;
        }
        if self.waiting.is_none()
            && self.statistics.blocks < self.slice_end
            && (self.peers.len() < 2 || self.now() < self.slice_deadline)
        {
            return Ok(());
        }
        let host = self.host.counter();
        self.clock.end_slice(host, self.statistics.blocks);
        let mut waited = false;
        loop {
            self.observe_writes();
            let now = self.now();
            let (current, count) = (self.current, self.peers.len());
            if let Some(next) = (1..=count)
                .map(|offset| (current + offset) % count)
                .find(|&pe| self.ready(pe, now))
            {
                if waited {
                    self.host.arm_timer(None);
                }
                if next != self.current {
                    self.switch_to(next);
                }
                self.slice_end = self.statistics.blocks + QUANTUM;
                self.slice_deadline = now + self.profile.counter_frequency / QUANTUM_HZ;
                let host = self.host.counter();
                let share = self.runnable();
                self.clock.start_slice(host, self.statistics.blocks, share);
                return self.wake();
            }
            let Some(deadline) = self.next_deadline(now) else {
                return Err(Stop::Idle);
            };
            self.statistics.waits += 1;
            self.host
                .arm_timer(Some(self.clock.host_deadline(deadline)));
            self.host.wait_for_interrupt();
            waited = true;
        }
    }

    /// The PEs that share the round with the running one, itself included:
    /// those out of reset and not waiting for an interrupt. A PE in WFE
    /// spins, so it shares the round.
    fn runnable(&self) -> u64 {
        let parked = self.peers.iter().filter(|peer| {
            matches!(peer, Peer::Parked(parked)
                if parked.waiting.is_none_or(|wait| wait.kind != WaitKind::Interrupt))
        });
        1 + parked.count() as u64
    }

    /// Whether PE `pe` can run: it is running or preempted, or a WFI it waits
    /// in sees an interrupt pending (Arm `AArch64_InterruptPending`, masked or
    /// not), or a WFE sees that or its event register set, including by an
    /// event stream edge, or the local timeout of a WFIT or WFET expired.
    fn ready(&mut self, pe: usize, now: u64) -> bool {
        if pe == self.current {
            return match self.waiting {
                None => true,
                Some(Wait { kind, timeout }) => {
                    if kind == WaitKind::Event {
                        self.sample_events(now);
                    }
                    (kind == WaitKind::Event && self.cpu.event)
                        || timeout.is_some_and(|timeout| timeout.expired(now))
                        || self.interrupt_pending()
                }
            };
        }
        let Peer::Parked(parked) = &mut self.peers[pe] else {
            return false;
        };
        let Some(Wait { kind, timeout }) = parked.waiting else {
            return true;
        };
        if timeout.is_some_and(|timeout| timeout.expired(now)) {
            return true;
        }
        if kind == WaitKind::Event {
            if let Some(previous) = parked.event_sample
                && timer::event(&parked.cpu, previous, now)
            {
                parked.cpu.event = true;
            }
            parked.event_sample = Some(now);
            if parked.cpu.event {
                return true;
            }
        }
        let device = self.devices.lines(pe, now);
        let timer = timer::deadline(&parked.cpu).is_some_and(|deadline| now >= deadline)
            || super::monitor_asserted(&parked.cpu, now);
        let lines = parked.cpu.core_lines(Lines {
            irq: device.irq,
            fiq: device.fiq || timer,
        });
        interrupt_pending(&parked.cpu, lines)
    }

    /// Complete the wait the running PE woke from. A WFE or WFET that no
    /// interrupt woke consumes the event register (`Machine::wait`).
    fn wake(&mut self) -> Step {
        let Some(Wait { kind, .. }) = self.waiting.take() else {
            return Ok(());
        };
        self.sync_monitor();
        if kind == WaitKind::Event && !self.interrupt_pending() {
            self.cpu.event = false;
        }
        self.next()
    }

    /// The earliest counter value at which a waiting PE's timer fires, its
    /// event stream sets its event register, its local timeout expires, or a
    /// device changes state.
    fn next_deadline(&mut self, now: u64) -> Option<u64> {
        let streams = |cpu: &Cpu, waiting: Option<Wait>| {
            (waiting.map(|wait| wait.kind) == Some(WaitKind::Event))
                .then(|| timer::next_event(cpu, now))
                .flatten()
        };
        let timeout = |waiting: Option<Wait>| {
            waiting.and_then(|wait| wait.timeout).map(|timeout| {
                if timeout.expired(now) {
                    now
                } else {
                    timeout.deadline(now)
                }
            })
        };
        let mut deadlines = vec![
            self.timer_deadline(),
            self.cpu.pmu.as_ref().and_then(|monitor| monitor.deadline()),
            streams(&self.cpu, self.waiting),
            timeout(self.waiting),
        ];
        for peer in &self.peers {
            if let Peer::Parked(parked) = peer {
                deadlines.push(timer::deadline(&parked.cpu));
                deadlines.push(
                    parked
                        .cpu
                        .pmu
                        .as_ref()
                        .and_then(|monitor| monitor.deadline()),
                );
                deadlines.push(streams(&parked.cpu, parked.waiting));
                deadlines.push(timeout(parked.waiting));
            }
        }
        deadlines.push(self.devices.deadline(now));
        deadlines.into_iter().flatten().min()
    }

    /// Run PE `next` in place of the running one, which parks with its state.
    fn switch_to(&mut self, next: usize) {
        let Peer::Parked(incoming) = core::mem::replace(&mut self.peers[next], Peer::Running)
        else {
            unreachable!("only a parked PE is ready to run");
        };
        let incoming = *incoming;
        let outgoing = Parked {
            cpu: core::mem::replace(&mut self.cpu, incoming.cpu),
            event_sample: core::mem::replace(&mut self.event_sample, incoming.event_sample),
            waiting: core::mem::replace(&mut self.waiting, incoming.waiting),
        };
        self.peers[self.current] = Peer::Parked(Box::new(outgoing));
        self.current = next;
        self.statistics.switches += 1;
        // Another PE ran since the incoming one's exclusive load and may
        // have written its granule, even back to the same bytes: its
        // store-exclusive fails, as Arm permits of any (`observe_writes`).
        self.cpu.monitor = None;
        // The fetch and jump caches and the host's shadow tables follow the
        // incoming PE's translation regime.
        self.translations_changed();
    }

    /// Clear the Exclusives monitor of every PE whose reserved granule
    /// another observer has written since its exclusive load, which
    /// generates an event: the WFE wake-up event of a cleared global monitor
    /// (Arm `AArch64_ExclusiveMonitorsStatus`, `ClearExclusiveByAddress`).
    /// One PE runs at a time and only between runs can another PE's (or a
    /// device's) write reach a reservation, so it is observed then, as the
    /// granule's bytes changing. A write that leaves them as they were
    /// generates no event: a WFE that waits for the value to change sees
    /// none. It cannot let a store-exclusive pass, because a PE that
    /// resumes after another ran has lost its reservation (`switch_to`).
    fn observe_writes(&mut self) {
        let parked = self.peers.iter_mut().filter_map(|peer| match peer {
            Peer::Parked(parked) => Some(&mut parked.cpu),
            Peer::Running | Peer::Off => None,
        });
        for cpu in core::iter::once(&mut self.cpu).chain(parked) {
            let Some(reservation) = cpu.monitor else {
                continue;
            };
            let mut bytes = [0; RESERVATION_GRANULE as usize];
            if !self.host.read_ram(reservation.granule, &mut bytes) || bytes != reservation.bytes {
                cpu.monitor = None;
                cpu.event = true;
            }
        }
    }

    /// SEV signals an event to every PE and SEVL to this one (Arm
    /// `SendEvent`, `SendEventLocal`). A PE held in reset takes none.
    pub(super) fn send_event(&mut self, local: bool) {
        self.cpu.event = true;
        if local {
            return;
        }
        for peer in &mut self.peers {
            if let Peer::Parked(parked) = peer {
                parked.cpu.event = true;
            }
        }
    }

    /// Release PE `start.cpu` from reset at `start.address` in EL2h, the
    /// highest implemented EL, with the System registers' reset values and
    /// its own identification (Arm `TakeReset`).
    fn start(&mut self, start: Start) -> Step {
        match self.peers.get(start.cpu) {
            Some(Peer::Off) => {}
            Some(Peer::Running | Peer::Parked(_)) => {
                return Err(self.unsupported(RequirementKind::Native(
                    "a device started a PE that is not held in reset",
                )));
            }
            None => {
                return Err(self.unsupported(RequirementKind::Native(
                    "a device started a PE the CPU profile does not have",
                )));
            }
        }
        let mut cpu = Cpu::of(self.profile.chip, start.address, Pstate::reset(2));
        // Every PE has the registers of PE 0, the profile's missing ones
        // included.
        system::identify(&self.profile, start.cpu, &mut cpu, &mut Vec::new());
        // The PEs of a cluster (MPIDR_EL1 Aff2 and Aff1) share its CTRR
        // registers; the memory controller's lock binds every PE.
        let cluster = |pe: usize| {
            self.profile
                .processors
                .get(pe)
                .map(|identity| identity.mpidr & 0x00ff_ff00)
        };
        let shared = (0..self.peers.len())
            .filter(|&pe| cluster(pe) == cluster(start.cpu))
            .find_map(|pe| match &self.peers[pe] {
                Peer::Running => Some(self.cpu.ctrr.clone()),
                Peer::Parked(parked) => Some(parked.cpu.ctrr.clone()),
                Peer::Off => None,
            });
        if let Some(shared) = shared {
            cpu.ctrr = shared;
        }
        cpu.memory_lock = self.cpu.memory_lock;
        self.peers[start.cpu] = Peer::Parked(Box::new(Parked {
            cpu,
            event_sample: None,
            waiting: None,
        }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{BASE, FakeHost, board};
    use super::*;
    use crate::machine::{
        cpu::Reservation, engine::DeviceError, exception::DAIF_ALL, registers::Identity,
        system::Register,
    };

    const WFE: u32 = 0xd503_205f;
    const WFI: u32 = 0xd503_207f;
    const SEV: u32 = 0xd503_209f;
    const SEVL: u32 = 0xd503_20bf;
    const START: u64 = BASE + 0x800;

    /// Devices that start PEs on request and drive one IRQ line per PE.
    #[derive(Default)]
    struct Board {
        starts: Vec<Start>,
        irq: [bool; 2],
        lines_asked: Vec<usize>,
    }

    impl Devices for Board {
        fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            Err(DeviceError::NoDevice)
        }
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
            Err(DeviceError::NoDevice)
        }
        fn lines(&mut self, cpu: usize, _: u64) -> Lines {
            self.lines_asked.push(cpu);
            Lines {
                irq: self.irq[cpu],
                fiq: false,
            }
        }
        fn take_start(&mut self) -> Option<Start> {
            self.starts.pop()
        }
    }

    fn identity(cpu: u64) -> Identity {
        Identity {
            midr: 0x611f_0320 | cpu << 4,
            mpidr: 0x8000_0000 | cpu << 8,
            clock: None,
            caches: None,
        }
    }

    /// Two PEs, PE 1 started at START and both runnable, PE 0 running.
    fn pair() -> Machine<FakeHost, Board> {
        let devices = Board {
            starts: alloc::vec![Start {
                cpu: 1,
                address: START,
            }],
            ..Board::default()
        };
        let mut machine = board(&[], devices, alloc::vec![identity(0), identity(1)]);
        machine.schedule().unwrap();
        machine
    }

    fn end_slice(machine: &mut Machine<FakeHost, Board>) {
        machine.slice_end = machine.statistics.blocks;
    }

    fn parked(machine: &Machine<FakeHost, Board>, pe: usize) -> &Cpu {
        match &machine.peers[pe] {
            Peer::Parked(parked) => &parked.cpu,
            _ => panic!("PE {pe} is not parked"),
        }
    }

    #[test]
    fn a_started_pe_leaves_reset_at_its_address_in_el2_with_its_own_identity() {
        let mut machine = pair();
        // PE 0 keeps its time slice; PE 1 waits for its turn.
        assert_eq!(machine.processor(), 0);
        assert_eq!(machine.cpu.read(Register::MPIDR_EL1), 0x8000_0000);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert_eq!(machine.statistics.switches, 1);
        let cpu = &machine.cpu;
        assert_eq!((cpu.pc, cpu.pstate.el, cpu.pstate.sp), (START, 2, true));
        assert_eq!(cpu.pstate.daif, DAIF_ALL);
        assert_eq!(cpu.read(Register::MIDR_EL1), 0x611f_0330);
        assert_eq!(cpu.read(Register::MPIDR_EL1), 0x8000_0100);
        assert_eq!(cpu.read(Register::VMPIDR_EL2), 0x8000_0100);
        // FP/SIMD is not trapped out of reset.
        assert_eq!(cpu.read(Register::CPTR_EL2) >> 20 & 0b11, 0b11);
        assert_eq!(parked(&machine, 0).pc, BASE);
        // Round robin returns to PE 0.
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE));
        // A PE that is not held in reset, or that the profile does not have,
        // cannot be started.
        for cpu in [1, 2] {
            machine.devices.starts.push(Start {
                cpu,
                address: START,
            });
            assert!(matches!(machine.schedule(), Err(Stop::Unsupported(_))));
        }
    }

    #[test]
    fn a_slice_ends_after_its_blocks_or_its_counter_time() {
        let mut machine = pair();
        let quantum = machine.profile.counter_frequency / QUANTUM_HZ;
        // PE 0's blocks spent, PE 1 runs its slice.
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        // Within both bounds PE 1 keeps running.
        machine.host.now += quantum - 1;
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        // Its counter time spent, PE 0 runs, though blocks remain.
        machine.host.now += 1;
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
    }

    #[test]
    fn wfe_parks_until_an_event_and_writes_clear_other_pes_monitors() {
        let mut machine = pair();
        // PE 0 waits with no event: PE 1 runs.
        machine.system_instruction(WFE).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert!(!parked(&machine, 0).event);
        // SEVL is local: PE 0 stays parked when PE 1's slice ends.
        machine.system_instruction(SEVL).unwrap();
        assert!(machine.cpu.event && !parked(&machine, 0).event);
        machine.system_instruction(WFE).unwrap();
        assert!(!machine.cpu.event);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        // SEV reaches PE 0, whose WFE completes and consumes the event.
        machine.system_instruction(SEV).unwrap();
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 4, false));
        // A WFE that completes at once yields the rest of the slice to PE 1,
        // and PE 0 continues after it at PE 1's next WFE.
        machine.system_instruction(SEVL).unwrap();
        machine.system_instruction(WFE).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 12);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        machine.system_instruction(SEVL).unwrap();
        machine.system_instruction(WFE).unwrap();
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE + 12));
        // PE 0 waits in WFE behind a load exclusive. PE 1 running clears
        // nothing until it writes the granule; then PE 0's monitor clears,
        // which generates the event that wakes it.
        let data = 0x400;
        machine.cpu.monitor = Some(Reservation {
            granule: BASE + data as u64,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        machine.system_instruction(WFE).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert!(parked(&machine, 0).monitor.is_some() && !parked(&machine, 0).event);
        machine.host.ram[data + 8] = 1;
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        assert_eq!(machine.cpu.monitor, None);
        assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 16, false));
        // PE 1 may have written the granule and restored its bytes: PE 0,
        // preempted behind a load exclusive, resumes without its
        // reservation, and without an event since no change shows.
        let mut bytes = [0; RESERVATION_GRANULE as usize];
        bytes.copy_from_slice(&machine.host.ram[data..data + RESERVATION_GRANULE as usize]);
        machine.cpu.monitor = Some(Reservation {
            granule: BASE + data as u64,
            bytes,
        });
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        assert_eq!((machine.cpu.monitor, machine.cpu.event), (None, false));
    }

    #[test]
    fn wfi_parks_until_its_own_pes_lines_and_idles_when_nothing_can_wake() {
        let mut machine = pair();
        machine.system_instruction(WFI).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        // PE 1's IRQ does not wake PE 0.
        machine.devices.irq = [false, true];
        end_slice(&mut machine);
        machine.devices.lines_asked.clear();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert_eq!(machine.devices.lines_asked, [0]);
        // Its own line does, masked or not, and WFI completes.
        machine.devices.irq = [true, false];
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE + 4));
        assert_eq!(machine.cpu.pstate.daif, DAIF_ALL);
        // With both PEs in WFI and no timer, stream or device deadline, the
        // machine is idle.
        machine.devices.irq = [false, false];
        machine.system_instruction(WFI).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        machine.system_instruction(WFI).unwrap();
        assert_eq!(machine.schedule(), Err(Stop::Idle));
    }
}
