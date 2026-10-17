//! The board's PEs. One runs on [`Machine::cpu`]; each other one is off,
//! preempted at the end of its time slice, or waiting in WFI or WFE. The
//! scheduler gives each PE that can run [`QUANTUM`] blocks in turn and waits
//! on the host when none can.
//!
//! Native code writes guest RAM directly, so the engine cannot see the store
//! by one PE that clears another PE's global Exclusives monitor (Arm
//! `ClearExclusiveByAddress`). Every switch of the running PE therefore
//! clears every monitor, and a monitor that held a granule generates the
//! event Arm gives a cleared global monitor, which wakes a WFE. A store
//! exclusive may then fail spuriously, as the architecture permits, while a
//! load/store exclusive loop shorter than a time slice still completes.
use super::{
    Devices, Host, Machine, RequirementKind, Start, Step, Stop, Wait, WaitKind, interrupt_pending,
    system, timer,
};
use crate::machine::{cpu::Cpu, exception::Pstate, registers::CpuProfile, registers::Lines};
use alloc::{boxed::Box, vec::Vec};

/// Blocks a PE runs before the next PE that can run gets its turn.
pub(super) const QUANTUM: u64 = 1 << 14;

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

impl<H: Host, D: Devices> Machine<H, D> {
    /// The number of the running PE.
    pub fn processor(&self) -> usize {
        self.current
    }

    /// Release the PEs devices started, then keep the running PE until its
    /// time slice ends or it waits. Otherwise run the next PE that can, round
    /// robin from the running one, or wait on the host until one can; with
    /// nothing left to wake any PE the machine is idle.
    pub(super) fn schedule(&mut self) -> Step {
        while let Some(start) = self.devices.take_start() {
            self.start(start)?;
        }
        if self.waiting.is_none() && self.statistics.blocks < self.slice_end {
            return Ok(());
        }
        let mut waited = false;
        loop {
            let now = self.host.counter();
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
                return self.wake();
            }
            let Some(deadline) = self.next_deadline(now) else {
                return Err(Stop::Idle);
            };
            self.statistics.waits += 1;
            self.host.arm_timer(Some(deadline));
            self.host.wait_for_interrupt();
            waited = true;
        }
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
        interrupt_pending(
            &parked.cpu,
            Lines {
                irq: device.irq,
                fiq: device.fiq || timer,
            },
        )
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
        self.clear_monitors();
        // The fetch and jump caches and the host's shadow tables follow the
        // incoming PE's translation regime.
        self.translations_changed();
    }

    /// Clear every PE's Exclusives monitor. A monitor that held a granule
    /// generates an event, the WFE wake-up event of a cleared global monitor.
    fn clear_monitors(&mut self) {
        let parked = self.peers.iter_mut().filter_map(|peer| match peer {
            Peer::Parked(parked) => Some(&mut parked.cpu),
            Peer::Running | Peer::Off => None,
        });
        for cpu in core::iter::once(&mut self.cpu).chain(parked) {
            if cpu.monitor.take().is_some() {
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
        engine::DeviceError, exception::DAIF_ALL, registers::Identity, system::Register,
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
    fn wfe_parks_until_an_event_and_switches_clear_every_monitor() {
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
        // A switch clears every monitor, and one that held a granule
        // generates an event: PE 0, in WFE behind a load exclusive, wakes
        // once PE 1 has run and could have written the granule.
        machine.cpu.monitor = Some(BASE);
        machine.system_instruction(WFE).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert_eq!(parked(&machine, 0).monitor, None);
        assert!(parked(&machine, 0).event);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 8, false));
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
