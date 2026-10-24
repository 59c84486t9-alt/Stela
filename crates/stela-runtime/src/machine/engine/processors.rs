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
//!
//! A WFI in CYC_OVRD's power-down mode turns its core off: the core loses
//! its state and comes back only by leaving reset at its reset vector
//! (m1n1 `deep_wfi`, `src/utils_asm.S`, which saves its context first for
//! that reason). XNU 26A434 powers its cores down this way for system
//! sleep (`_ml_arm_sleep`, file 0x4d6f404) and to take a core offline
//! (file 0x4d6ea84), both through `arm64_prepare_for_sleep` (file
//! 0x4b99170). Its argument 0 first sets CYC_OVRD's IRQ and FIQ modes to
//! disable, and the core then leaves reset only when a device starts it
//! again; sleep passes 1, which keeps them. An interrupt line the core's
//! CYC_OVRD still enables wakes it: the board's device lines, since the
//! core's own timers, performance monitor and vGIC went down with it. Its
//! reset vector is the board's (`Devices::reset_vector`), and the board
//! learns of each power-down and power-up (`Devices::processor_power`).
pub mod publication;
mod retained;
mod transaction;
use super::{
    Devices, Host, Machine, RequirementKind, Start, Step, Stop, Wait, WaitKind, interrupt_pending,
    system, timer,
};
use crate::machine::{
    cpu::{Cpu, RESERVATION_GRANULE},
    ctrr,
    exception::Pstate,
    mmu,
    registers::CpuProfile,
    registers::Lines,
};
use alloc::{boxed::Box, vec::Vec};
pub use retained::{
    PreparedProcessorPower, ProcessorBinding, ProcessorChange, ProcessorPowerError,
    ProcessorTarget, Processors,
};
use transaction::NativeProcessorState;
pub use transaction::{ProcessorWrite, SettledProcessorWrite};

/// Blocks a PE runs before the next PE that can run gets its turn.
pub(super) const QUANTUM: u64 = 1 << 14;
/// The inverse of the longest time slice in seconds of the system counter:
/// 2 ms, so the seven other PEs of an eight-PE board hold a preempted
/// spinlock holder off for at most 14 ms.
pub(super) const QUANTUM_HZ: u64 = 500;
/// XNU xnu-12377.121.6 machine_routines.c:108,1251 groups the original
/// DeviceTree `reg` by Aff1 (proc_reg.h:1059-1061). Aff2 is a core type,
/// not part of the physical cluster, including the M6's mixed P/M cluster.
const PHYSICAL_CLUSTER_MASK: u64 = 0xff00;

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
    /// Its mirrored-read cells (`MIRRORED`) as it left them: their values
    /// follow from its own System registers and PSTATE, which no other PE
    /// changes, so it takes them back when it runs again.
    mirrors: super::Mirrors,
}

/// The selected existing PE runs; the others are off. A profile without
/// processors has one PE. The constructor validates the selected index.
pub(super) fn boot(profile: &CpuProfile, boot_processor: usize) -> Vec<Peer> {
    let mut peers: Vec<Peer> = (0..profile.processors.len().max(1))
        .map(|_| Peer::Off)
        .collect();
    peers[boot_processor] = Peer::Running;
    peers
}

impl Parked {
    pub(super) fn native_ready(&self) -> bool {
        self.waiting.is_none()
    }
    pub(super) fn cpu(&self) -> &Cpu {
        &self.cpu
    }
    /// Its state, to change: its mirrored-read cells close.
    pub(super) fn cpu_mut(&mut self) -> &mut Cpu {
        self.mirrors = super::Mirrors::default();
        &mut self.cpu
    }
}

/// Whether a PE waiting in `waiting` is powered down.
fn down(waiting: Option<Wait>) -> bool {
    waiting.is_some_and(|wait| wait.down)
}

/// A PE as a report shows it.
#[derive(Debug, Clone, Copy)]
pub enum PeerState<'a> {
    Running,
    Off,
    /// Powered down by a WFI in CYC_OVRD's power-down mode; its state is
    /// lost.
    Down,
    /// Out of reset but not running, including a retained clock/quiesce
    /// pause: its state, and whether it waits in WFI (`Some(true)`) or WFE
    /// (`Some(false)`).
    Parked {
        cpu: &'a Cpu,
        wfi: Option<bool>,
    },
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Qualified retained participants, separate from the live/parked Cpu
    /// ownership slots. An unbound inventory grants no PMGR support credit.
    pub fn processors(&self) -> &Processors {
        &self.processor_power
    }

    /// Bind positively identified owners with an explicit handoff state.
    /// Every binding is checked before any participant or CPU changes.
    pub fn bind_processor_power(
        &mut self,
        bindings: &[ProcessorBinding],
    ) -> Result<(), ProcessorPowerError> {
        check_owners(&self.processor_power, self.current, &self.peers)?;
        let plan = self.processor_power.prepare_bindings(bindings)?;
        self.settle_processor_power(plan)
    }

    pub fn prepare_processor_power(
        &self,
        changes: &[ProcessorChange],
    ) -> Result<PreparedProcessorPower, ProcessorPowerError> {
        check_owners(&self.processor_power, self.current, &self.peers)?;
        self.processor_power.prepare(changes)
    }

    /// Commit at one instruction boundary, before a controller acknowledges
    /// its request. Stale/replaced plans refuse before any CPU or clock effect.
    /// No production PMGR resolver/bridge is enabled by this independent API.
    pub fn settle_processor_power(
        &mut self,
        plan: PreparedProcessorPower,
    ) -> Result<(), ProcessorPowerError> {
        self.processor_write()
            .settle(plan)
            .map(|_settled: SettledProcessorWrite<'_>| ())
    }

    /// Borrow the actual scheduler and native-dispatch owners for one complete
    /// synchronous transaction. Its consuming apply cannot queue work for later.
    pub fn processor_write(&mut self) -> ProcessorWrite<'_> {
        self.processor_write_parts().1
    }

    /// Split the device receiver from the actual execution owners without a
    /// move, copied snapshot, unsafe alias or a borrow of the complete Machine.
    pub(super) fn processor_write_parts(&mut self) -> (&mut D, ProcessorWrite<'_>) {
        let processors = ProcessorWrite {
            processors: &mut self.processor_power,
            publication: &mut self.native_publication,
            current: self.current,
            cpu: &mut self.cpu,
            peers: &mut self.peers,
            waiting: self.waiting,
            clock: &mut self.clock,
            slice_end: &mut self.slice_end,
            native: NativeProcessorState {
                host: &mut self.host,
                statistics: &mut self.statistics,
                translation_generation: &mut self.translation_generation,
                timers: &mut self.timers,
                floating_point: &mut self.floating_point,
                memory_checks: &mut self.memory_checks,
                native_system: &mut self.native_system,
                debug: &mut self.debug,
                pointer: &mut self.pointer,
                mirrors: &mut self.mirrors,
                device_lines: &mut self.device_lines,
                watch: &mut self.watch,
                tag_checks: &mut self.tag_checks,
                prediction_context: &mut self.prediction_context,
            },
        };
        (&mut self.devices, processors)
    }

    pub(super) fn processor_paused(&self, pe: usize) -> bool {
        self.processor_power
            .paused(pe)
            .expect("one retained slot per PE")
    }

    /// The number of the running PE.
    pub fn processor(&self) -> usize {
        self.current
    }

    /// Completed guest instructions across retained PE incarnations, including
    /// stopped-service terminals and powered-down CPUs. No allocation or PE
    /// switching occurs. Each CPU's internal u64 retirement counter must not
    /// wrap within one incarnation; this is a performance counter, not PMU.
    pub fn retired_instructions(&self) -> u128 {
        self.peers
            .iter()
            .fold(self.statistics.replaced_retired, |total, peer| {
                let retired = match peer {
                    Peer::Running => self.cpu.retired,
                    Peer::Parked(parked) => parked.cpu.retired,
                    Peer::Off => 0,
                };
                total.saturating_add(u128::from(retired))
            })
    }

    /// Every PE's state, in PE order.
    pub fn peer_states(&self) -> Vec<PeerState<'_>> {
        self.peers
            .iter()
            .map(|peer| match peer {
                Peer::Running if down(self.waiting) => PeerState::Down,
                Peer::Running if self.processor_paused(self.current) => PeerState::Parked {
                    cpu: &self.cpu,
                    wfi: self.waiting.map(|wait| wait.kind == WaitKind::Interrupt),
                },
                Peer::Running => PeerState::Running,
                Peer::Off => PeerState::Off,
                Peer::Parked(parked) if down(parked.waiting) => PeerState::Down,
                Peer::Parked(parked) => PeerState::Parked {
                    cpu: &parked.cpu,
                    wfi: parked.waiting.map(|wait| wait.kind == WaitKind::Interrupt),
                },
            })
            .collect()
    }

    /// The execution PC a board debug sampler observes for a powered PE.
    pub(super) fn processor_pc(&self, cpu: usize) -> Option<u64> {
        match self.peers.get(cpu)? {
            Peer::Running if !down(self.waiting) => Some(self.cpu.pc),
            Peer::Parked(parked) if !down(parked.waiting) => Some(parked.cpu.pc),
            _ => None,
        }
    }

    /// Release the PEs devices started, then keep the running PE until its
    /// time slice ends or it waits. Otherwise run the next PE that can, round
    /// robin from the running one, or wait on the host until one can (or,
    /// with idle skip, leap the counter to the next deadline); with nothing
    /// left to wake any PE the machine is idle. A wait that reaches the wait
    /// limit, or that only the host's inputs can end, returns to the host.
    pub(super) fn schedule(&mut self) -> Step {
        self.take_starts()?;
        if !self.processor_paused(self.current)
            && self.waiting.is_none()
            && self.statistics.blocks < self.slice_end
            && (self.peers.len() < 2 || self.now() < self.slice_deadline)
        {
            return Ok(());
        }
        let host = self.host.counter();
        self.clock.end_slice(host, self.statistics.blocks);
        let mut waited = false;
        let mut wait_start = None;
        loop {
            self.observe_writes();
            let now = self.now();
            self.poll_devices(now)?;
            // A device can start a PE while every PE waits; the start reads
            // the count, so the rest of the pass reads it after.
            self.take_starts()?;
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
            let deadline = self.next_deadline(now);
            if deadline.is_none() && !self.devices.waits_on_host() {
                return Err(Stop::Idle);
            }
            if let (Some(deadline), true) = (deadline, self.idle_skip) {
                self.statistics.waits += 1;
                let host = self.host.counter();
                self.clock.skip_to(host, deadline);
                continue;
            }
            let limit = self
                .wait_limit
                .map(|limit| wait_start.get_or_insert(now).saturating_add(limit));
            let until = match (deadline, limit) {
                (_, Some(limit)) if now >= limit => None,
                (Some(deadline), Some(limit)) => Some(deadline.min(limit)),
                (deadline, limit) => deadline.or(limit),
            };
            let Some(until) = until else {
                if waited {
                    self.host.arm_timer(None);
                }
                return Err(Stop::Waiting);
            };
            self.statistics.waits += 1;
            self.host.arm_timer(Some(self.clock.host_deadline(until)));
            self.host.wait_for_interrupt();
            waited = true;
        }
    }

    pub(super) fn take_starts(&mut self) -> Step {
        while let Some(start) = self.devices.take_start() {
            self.start(start)?;
        }
        Ok(())
    }

    /// The PEs that share the round with the running one, itself included:
    /// those out of reset and not waiting for an interrupt. A PE in WFE
    /// spins, so it shares the round.
    fn runnable(&self) -> u64 {
        let parked = self.peers.iter().enumerate().filter(|(pe, peer)| {
            if self.processor_paused(*pe) {
                return false;
            }
            matches!(peer, Peer::Parked(parked)
                if parked.waiting.is_none_or(|wait| wait.kind != WaitKind::Interrupt))
        });
        u64::from(!self.processor_paused(self.current)) + parked.count() as u64
    }

    /// Parked PE `pe`.
    fn parked(&self, pe: usize) -> &Parked {
        let Peer::Parked(parked) = &self.peers[pe] else {
            unreachable!("PE {pe} is parked");
        };
        parked
    }

    /// Whether PE `pe` can run: it is running or preempted, or a WFI it waits
    /// in sees an interrupt pending (Arm `AArch64_InterruptPending`, masked or
    /// not), or a WFE sees that or its event register set, including by an
    /// event stream edge, or the local timeout of a WFIT or WFET expired. A
    /// powered-down PE wakes when a device line its CYC_OVRD enables
    /// asserts.
    pub(super) fn ready(&mut self, pe: usize, now: u64) -> bool {
        if self.processor_paused(pe) {
            return false;
        }
        if pe == self.current {
            return match self.waiting {
                None => true,
                Some(Wait { down: true, .. }) => {
                    let device = self.device_lines_of(pe, now);
                    self.cpu.wakes_for(device)
                }
                Some(Wait { kind, timeout, .. }) => {
                    if kind == WaitKind::Event {
                        self.sample_events(now);
                    }
                    (kind == WaitKind::Event && self.cpu.event_is_set())
                        || timeout.is_some_and(|timeout| timeout.expired(now))
                        || self.interrupt_pending_at(now)
                }
            };
        }
        let Peer::Parked(parked) = &mut self.peers[pe] else {
            return false;
        };
        let Some(Wait {
            kind,
            timeout,
            down,
        }) = parked.waiting
        else {
            return true;
        };
        if down {
            let device = self.device_lines_of(pe, now);
            return self.parked(pe).cpu.wakes_for(device);
        }
        if timeout.is_some_and(|timeout| timeout.expired(now)) {
            return true;
        }
        if kind == WaitKind::Event {
            if let Some(previous) = parked.event_sample
                && timer::event(&parked.cpu, previous, now)
            {
                parked.cpu.signal_event();
            }
            parked.event_sample = Some(now);
            if parked.cpu.event_is_set() {
                return true;
            }
        }
        let device = self.device_lines_of(pe, now);
        let parked = self.parked(pe);
        let timer = timer::deadline(&parked.cpu).is_some_and(|deadline| now >= deadline)
            || super::monitor_asserted(&parked.cpu, now);
        let lines = parked.cpu.core_lines(Lines {
            irq: device.irq,
            fiq: device.fiq || timer,
        });
        interrupt_pending(&parked.cpu, lines)
    }

    /// Complete the wait the running PE woke from. A WFE or WFET that no
    /// interrupt woke consumes the event register (`Machine::wait`). A PE
    /// that woke from power-down leaves reset instead.
    pub(super) fn wake(&mut self) -> Step {
        if self.waiting.is_some_and(|waiting| waiting.down) {
            let pe = self.current;
            let Some(address) = self.devices.reset_vector(pe) else {
                return Err(self.unsupported(RequirementKind::Native(
                    "a PE woke from CYC_OVRD's power-down mode, but the board holds no reset vector for it",
                )));
            };
            return self.restart(pe, address);
        }
        let Some(Wait { kind, .. }) = self.waiting.take() else {
            return Ok(());
        };
        self.sync_monitor();
        if kind == WaitKind::Event && !self.interrupt_pending() {
            self.cpu.consume_event();
        }
        self.next()
    }

    /// The earliest counter value at which a waiting PE's timer fires, its
    /// event stream sets its event register, its local timeout expires, or a
    /// device changes state. A powered-down PE has none of its own.
    pub(super) fn next_deadline(&mut self, now: u64) -> Option<u64> {
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
        let mut deadlines = Vec::new();
        if !self.processor_paused(self.current) && !down(self.waiting) {
            deadlines.extend([
                self.timer_deadline(),
                self.cpu.pmu.as_ref().and_then(|monitor| monitor.deadline()),
                streams(&self.cpu, self.waiting),
                timeout(self.waiting),
            ]);
        }
        for (pe, peer) in self.peers.iter().enumerate() {
            if let Peer::Parked(parked) = peer
                && !self.processor_paused(pe)
                && !down(parked.waiting)
            {
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
    pub(super) fn switch_to(&mut self, next: usize) {
        let Peer::Parked(incoming) = core::mem::replace(&mut self.peers[next], Peer::Running)
        else {
            unreachable!("only a parked PE is ready to run");
        };
        let incoming = *incoming;
        let inputs = [&incoming.cpu, &self.cpu].map(Cpu::translation_inputs);
        let upper = inputs.map(|(controls, hcr)| {
            let controls = controls.map(|controls| mmu::Controls {
                ttbr0: 0,
                ..controls
            });
            (controls, hcr)
        });
        let outgoing = Parked {
            cpu: core::mem::replace(&mut self.cpu, incoming.cpu),
            event_sample: core::mem::replace(&mut self.event_sample, incoming.event_sample),
            waiting: core::mem::replace(&mut self.waiting, incoming.waiting),
            mirrors: *self.mirrors,
        };
        self.peers[self.current] = Peer::Parked(Box::new(outgoing));
        self.current = next;
        self.statistics.switches += 1;
        // The switch changes no device: what derives from the PE goes, the
        // devices' lines and deadline stay, and the incoming PE's mirrored
        // reads reopen as it left them.
        let device_lines = self.device_lines;
        // Another PE ran since the incoming one's exclusive load and may
        // have written its granule, even back to the same bytes: its
        // store-exclusive fails, as Arm permits of any (`observe_writes`).
        self.cpu.monitor = None;
        // The fetch and jump caches and the host's shadow tables follow the
        // incoming PE's translation regime. One that translates alike keeps
        // them: the tables and TLBIs are shared, and what derives from its
        // other System registers is recomputed. One whose TTBR0s alone
        // differ changes the lower half's translations, as a TTBR0 write.
        if inputs[0] == inputs[1] {
            self.sync_regime();
        } else if upper[0] == upper[1] {
            self.table_base_changed();
        } else {
            self.controls_changed();
        }
        self.device_lines = device_lines;
        *self.mirrors = incoming.mirrors;
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
                cpu.signal_event();
            }
        }
    }

    /// SEV signals an event to every PE and SEVL to this one (Arm
    /// `SendEvent`, `SendEventLocal`). A PE held in reset or powered down
    /// takes none.
    pub(super) fn send_event(&mut self, local: bool) {
        self.cpu.signal_event();
        if local {
            return;
        }
        for peer in &mut self.peers {
            if let Peer::Parked(parked) = peer
                && !down(parked.waiting)
            {
                parked.cpu.signal_event();
            }
        }
    }

    /// The running PE's WFI in CYC_OVRD's power-down mode turned its core
    /// off: its reservation goes with its state, and the board learns of it.
    pub(super) fn power_down(&mut self) {
        self.cpu.monitor = None;
        self.device_lines = None;
        self.devices.processor_power(self.current, false);
    }

    /// Release PE `start.cpu` from reset at `start.address` in EL2h, the
    /// highest implemented EL, with the System registers' reset values and
    /// its own identification (Arm `TakeReset`). A powered-down PE can be
    /// started like one held in reset.
    pub(super) fn start(&mut self, start: Start) -> Step {
        let held = match self.peers.get(start.cpu) {
            Some(Peer::Off) => true,
            Some(Peer::Running) => down(self.waiting),
            Some(Peer::Parked(parked)) => down(parked.waiting),
            None => {
                return Err(self.unsupported(RequirementKind::Native(
                    "a device started a PE the CPU profile does not have",
                )));
            }
        };
        if !held {
            return Err(self.unsupported(RequirementKind::Native(
                "a device started a PE that is neither held in reset nor powered down",
            )));
        }
        self.restart(start.cpu, start.address)
    }

    /// The running PE's write of RMR_EL2.RR requested a Warm reset (Arm
    /// RMR_EL2), which it takes as the write completes: Arm leaves when to
    /// the reset logic, and software waits for it in WFI. The PE leaves reset
    /// at its reset vector (RVBAR_EL2) in EL2h, the highest implemented EL.
    /// The System register fields with a Warm reset take their reset
    /// values; the others keep theirs: the debug state, the OS lock, the
    /// breakpoints and watchpoints, the debug communications channel and
    /// claim tags, and RMR_EL2.AA64, which only a Cold reset sets. The
    /// activity monitors keep counting, as only their own reset resets them.
    /// The general-purpose and SIMD registers, UNKNOWN after the reset, read
    /// 0, the Exclusives monitor clears, and the PE's Apple
    /// IMPLEMENTATION DEFINED state (its registers, performance monitor and
    /// AMX unit) restarts as on its other resets (inference: no 26A434
    /// component requests a Warm reset). The cluster's shared registers stay.
    pub(super) fn warm_reset(&mut self) -> Step {
        let pe = self.current;
        let Some(address) = self.devices.reset_vector(pe) else {
            return Err(self.unsupported(RequirementKind::Native(
                "RMR_EL2.RR requested a Warm reset, but the board holds no reset vector for the PE",
            )));
        };
        let mut cpu = Cpu::of(self.profile.chip, address, Pstate::reset(2));
        system::identify(&self.profile, pe, &mut cpu, &mut Vec::new());
        if self.native_publication.is_some() || self.cpu.has_canonical_memory() {
            self.prepare_native_reset(pe, &mut cpu).map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "native warm reset requires the actual held physical roster and canonical RAM",
                ))
            })?;
            self.cpu.clear_exclusive().map_err(|_| {
                self.unsupported(RequirementKind::Native("native warm reset monitor refused"))
            })?;
        }
        let old = core::mem::replace(&mut self.cpu, cpu);
        let cpu = &mut self.cpu;
        cpu.registers.keep_over_warm_reset(&old.registers);
        cpu.dcc = old.dcc;
        cpu.claim = old.claim;
        cpu.amu = old.amu;
        cpu.retired = old.retired;
        cpu.ctrr = old.ctrr;
        cpu.ctrr_core = ctrr::Core::handed_off(&old.core_locks);
        cpu.core_locks = old.core_locks;
        cpu.apple.impdef.join(&old.apple.impdef);
        cpu.memory_lock = old.memory_lock;
        self.waiting = None;
        self.event_sample = None;
        self.device_lines = None;
        self.translations_changed();
        Ok(())
    }

    /// PE `pe` leaves reset at `address`.
    fn restart(&mut self, pe: usize, address: u64) -> Step {
        let mut cpu = Cpu::of(self.profile.chip, address, Pstate::reset(2));
        // Every PE has the registers of PE 0, the profile's missing ones
        // included.
        system::identify(&self.profile, pe, &mut cpu, &mut Vec::new());
        if self.native_publication.is_some() || self.cpu.has_canonical_memory() {
            self.prepare_native_reset(pe, &mut cpu).map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "native start/reset requires the actual held physical roster and canonical RAM",
                ))
            })?;
            let clear = match &mut self.peers[pe] {
                Peer::Running if pe == self.current => self.cpu.clear_exclusive(),
                Peer::Parked(parked) => parked.cpu.clear_exclusive(),
                Peer::Off => Ok(()),
                _ => unreachable!("reset preflight checked exact PE owners"),
            };
            clear.map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "native reset monitor retirement refused",
                ))
            })?;
        }
        // The PEs of a physical cluster (MPIDR_EL1 Aff1) share its CTRR
        // registers while one of them is powered; the memory controller's
        // lock binds every PE.
        let cluster = |other: usize| {
            self.profile
                .processors
                .get(other)
                .map(|identity| identity.mpidr & PHYSICAL_CLUSTER_MASK)
        };
        let shared = (0..self.peers.len())
            .filter(|&other| other != pe && cluster(other) == cluster(pe))
            .find_map(|other| match &self.peers[other] {
                Peer::Running if !down(self.waiting) => Some(&self.cpu),
                Peer::Parked(parked) if !down(parked.waiting) => Some(&parked.cpu),
                Peer::Running | Peer::Parked(_) | Peer::Off => None,
            });
        // Its cluster-scoped implementation-defined registers too
        // (`impdef::Scope::Cluster`). A new cluster's CTRR registers, and
        // every PE's own, start from what iBoot left (`ctrr::Handoff`).
        cpu.core_locks = self.cpu.core_locks.clone();
        cpu.ctrr_core = ctrr::Core::handed_off(&cpu.core_locks);
        if let Some(peer) = shared {
            cpu.ctrr = peer.ctrr.clone();
            cpu.apple.impdef.join(&peer.apple.impdef);
        } else {
            cpu.ctrr = alloc::rc::Rc::new(core::cell::RefCell::new(ctrr::Cluster::handed_off(
                &cpu.core_locks,
            )));
        }
        cpu.memory_lock = self.cpu.memory_lock;
        let now = self.now();
        pause_cpu(&mut cpu, None, now, self.processor_paused(pe));
        // Its SIQ_CFG_EL1 restarts at 0, which accepts IRQs.
        self.devices.irq_steering(pe, false, now);
        let replaced = match &self.peers[pe] {
            Peer::Running => self.cpu.retired,
            Peer::Parked(parked) => parked.cpu.retired,
            Peer::Off => 0,
        };
        self.statistics.replaced_retired = self
            .statistics
            .replaced_retired
            .saturating_add(u128::from(replaced));
        if pe == self.current {
            self.cpu = cpu;
            self.waiting = None;
            self.event_sample = None;
            self.device_lines = None;
            self.translations_changed();
        } else {
            self.peers[pe] = Peer::Parked(Box::new(Parked {
                cpu,
                event_sample: None,
                waiting: None,
                mirrors: super::Mirrors::default(),
            }));
        }
        self.devices.processor_power(pe, true);
        Ok(())
    }
}

/// Check the actual scheduler ownership before a checked participant plan can
/// mutate its inventory, the clock or any live/parked Cpu. An off PE has no
/// invented Cpu to settle; exactly one slot must refer to the live Cpu.
fn check_owners(
    processors: &Processors,
    current: usize,
    peers: &[Peer],
) -> Result<(), ProcessorPowerError> {
    if peers.len() != processors.count() {
        return Err(ProcessorPowerError::OwnerCount {
            expected: processors.count(),
            actual: peers.len(),
        });
    }
    if !matches!(peers.get(current), Some(Peer::Running)) {
        return Err(ProcessorPowerError::MissingLiveOwner(current));
    }
    if let Some(pe) = peers
        .iter()
        .enumerate()
        .find_map(|(pe, peer)| (pe != current && matches!(peer, Peer::Running)).then_some(pe))
    {
        return Err(ProcessorPowerError::UnexpectedLiveOwner(pe));
    }
    Ok(())
}

/// Preserve architectural state and pending status while stopping only the
/// declared core accounting. The system counter and timer comparators remain
/// global. Local reservations can be lost at any time (as at a PE switch).
fn pause_cpu(cpu: &mut Cpu, waiting: Option<Wait>, now: u64, paused: bool) {
    let waiting = paused || waiting.is_some();
    let context = cpu.pmu_context(waiting);
    if let Some(pmu) = cpu.pmu.as_mut() {
        pmu.sync(now, cpu.retired, context);
    }
    if let Some(amu) = cpu.amu.as_mut() {
        amu.sync(now, cpu.retired, waiting);
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
        dma: Option<u64>,
        /// Every PE's reset vector.
        reset: Option<u64>,
        /// The power-downs and power-ups the engine reported.
        power: Vec<(usize, bool)>,
        /// Something outside the board can still wake a PE.
        host_wake: bool,
        /// The counts its lines and deadlines were asked at, in order.
        counts: Vec<u64>,
        /// It answers `Devices::pins`, and the PEs that asked.
        pins: bool,
        pins_asked: Vec<usize>,
    }

    impl Board {
        /// Same synchronous call order required of the real PMGR adapter.
        fn retained_write(
            &mut self,
            processors: ProcessorWrite<'_>,
            changes: &[ProcessorChange],
            refuse_native: bool,
            events: &mut Vec<&'static str>,
        ) -> Result<(), DeviceError> {
            events.push("native preflight");
            if refuse_native {
                return Err(DeviceError::TransferRefused(
                    "native preflight refused".into(),
                ));
            }
            let settled = processors.apply(changes).map_err(|why| {
                DeviceError::TransferRefused(alloc::format!("processor transaction: {why:?}"))
            })?;
            // These are actual owners, still exclusively borrowed through ACK.
            assert_eq!(settled.paused(0), Some(true));
            assert_eq!(settled.paused(1), Some(true));
            assert!(settled.owners.cpu.monitor.is_none());
            let Peer::Parked(peer) = &settled.owners.peers[1] else {
                panic!("actual parked owner")
            };
            assert!(peer.cpu.monitor.is_none());
            assert!(settled.owners.native.timers.is_none());
            assert!(settled.owners.native.device_lines.is_none());
            assert_eq!(
                *settled.owners.native.mirrors,
                super::super::Mirrors::default()
            );
            assert!(settled.owners.native.prediction_context.is_some());
            events.push("CPU and native dispatch settled");
            events.push("native commit");
            events.push("controller ACK");
            Ok(())
        }
    }

    impl Devices for Board {
        fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            Err(DeviceError::NoDevice)
        }
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
            Err(DeviceError::NoDevice)
        }
        fn lines(&mut self, cpu: usize, now: u64) -> Lines {
            self.lines_asked.push(cpu);
            self.counts.push(now);
            Lines {
                irq: self.irq[cpu],
                fiq: false,
            }
        }
        fn pins(&mut self, cpu: usize) -> Option<Lines> {
            self.pins_asked.push(cpu);
            self.pins.then(|| Lines {
                irq: self.irq[cpu],
                fiq: false,
            })
        }
        fn dma_deadline(&self) -> Option<u64> {
            self.dma
        }
        fn deadline(&mut self, now: u64) -> Option<u64> {
            self.counts.push(now);
            self.dma
        }
        fn transfer(
            &mut self,
            _: usize,
            memory: &mut dyn crate::platform::dma::Memory,
            now: u64,
        ) -> Result<(), DeviceError> {
            if self.dma.is_some_and(|deadline| now >= deadline) {
                if !memory.write(BASE + 0x100, b"USB") {
                    return Err(DeviceError::Refused("test DMA RAM unavailable".into()));
                }
                self.dma = None;
                self.irq[0] = true;
            }
            Ok(())
        }
        fn take_start(&mut self) -> Option<Start> {
            self.starts.pop()
        }
        fn reset_vector(&self, _: usize) -> Option<u64> {
            self.reset
        }
        fn processor_power(&mut self, cpu: usize, on: bool) {
            self.power.push((cpu, on));
        }
        fn waits_on_host(&self) -> bool {
            self.host_wake
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

    #[test]
    fn a_nonzero_boot_processor_keeps_resource_indices_and_secondary_reset_state() {
        let mut prepared = board(&[], Board::default(), alloc::vec![identity(0), identity(1)]);
        prepared.cpu.state.x[0] = 0x1234_5678;
        prepared.cpu.state.sp = BASE + 0x400;
        let state = prepared.cpu.state.clone();
        let pc = prepared.cpu.pc;
        let mut machine = Machine::new_at(
            prepared.cpu,
            prepared.host,
            prepared.devices,
            prepared.profile,
            prepared.target,
            1,
        )
        .unwrap();
        assert_eq!(machine.processor(), 1);
        assert!(matches!(machine.peers[0], Peer::Off));
        assert!(matches!(machine.peers[1], Peer::Running));
        assert_eq!(machine.cpu.state, state);
        assert_eq!(machine.cpu.pc, pc);
        assert_eq!(machine.cpu.read(Register::MIDR_EL1), identity(1).midr);
        assert_eq!(machine.cpu.read(Register::MPIDR_EL1), identity(1).mpidr);
        assert_eq!(machine.profile.processors, [identity(0), identity(1)]);
        assert!(machine.devices.power.is_empty());
        machine.devices.starts.push(Start {
            cpu: 0,
            address: START,
        });
        machine.take_starts().unwrap();
        assert_eq!(parked(&machine, 0).pc, START);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        assert_eq!(machine.cpu.pc, START);
        assert_eq!(machine.cpu.read(Register::MPIDR_EL1), identity(0).mpidr);
        assert_eq!(parked(&machine, 1).state, state);
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert_eq!(machine.cpu.state, state);
        assert_eq!(machine.cpu.pc, pc);
    }

    #[test]
    fn a_boot_processor_outside_the_profile_is_refused() {
        for selected in [2, usize::MAX] {
            let prepared = board(&[], Board::default(), alloc::vec![identity(0), identity(1)]);
            assert!(
                Machine::new_at(
                    prepared.cpu,
                    prepared.host,
                    prepared.devices,
                    prepared.profile,
                    prepared.target,
                    selected,
                )
                .is_err()
            );
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

    #[test]
    fn retirement_totals_count_live_parked_and_replaced_cpus_once() {
        let mut machine = pair();
        let other = 1 - machine.current;
        machine.cpu.retired = 11;
        let Peer::Parked(parked) = &mut machine.peers[other] else {
            panic!("parked peer")
        };
        parked.cpu.retired = 7;
        parked.waiting = Some(Wait {
            kind: WaitKind::Interrupt,
            timeout: None,
            down: true,
        });
        assert_eq!(machine.retired_instructions(), 18);
        assert!(
            machine
                .start(Start {
                    cpu: machine.current,
                    address: START
                })
                .is_err()
        );
        assert_eq!(machine.retired_instructions(), 18);
        machine.restart(other, START).unwrap();
        assert_eq!(machine.retired_instructions(), 18);
        let Peer::Parked(parked) = &mut machine.peers[other] else {
            panic!("parked peer")
        };
        parked.cpu.retired = 5;
        assert_eq!(machine.retired_instructions(), 23);
        machine.switch_to(other);
        assert_eq!(machine.retired_instructions(), 23);
        machine.restart(other, START).unwrap();
        assert_eq!(machine.retired_instructions(), 23);
        machine.cpu.retired = 3;
        machine.devices.reset = Some(START);
        machine.warm_reset().unwrap();
        assert_eq!(machine.retired_instructions(), 26);
    }

    #[test]
    fn a_switch_keeps_cached_translations_only_between_pes_that_translate_alike() {
        let mut machine = pair();
        let (first, other) = (machine.current, 1 - machine.current);
        let generation = machine.translation_generation;
        machine.switch_to(other);
        assert_eq!(machine.translation_generation, generation);
        assert_eq!(machine.statistics.translation_changes, 0);
        let Peer::Parked(parked) = &mut machine.peers[first] else {
            panic!("parked peer")
        };
        parked.cpu.registers.set(Register::TTBR0_EL1, 0, 0x4000);
        machine.switch_to(first);
        assert!(machine.translation_generation > generation);
        assert_eq!(machine.statistics.table_base_changes, 1);
        assert_eq!(machine.statistics.translation_changes, 0);
        let Peer::Parked(parked) = &mut machine.peers[other] else {
            panic!("parked peer")
        };
        parked.cpu.registers.set(Register::TTBR1_EL1, 0, 0x8000);
        machine.switch_to(other);
        assert_eq!(machine.statistics.translation_changes, 1);
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

    const RETAINED_ACTIVE: crate::platform::apple::bus::LifecycleState =
        crate::platform::apple::bus::LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: false,
        };
    const RETAINED_GATED: crate::platform::apple::bus::LifecycleState =
        crate::platform::apple::bus::LifecycleState {
            clocked: false,
            ..RETAINED_ACTIVE
        };

    fn core_binding(domain: u64, pe: usize) -> ProcessorBinding {
        ProcessorBinding {
            domain,
            target: ProcessorTarget::Core { pe },
            initial: RETAINED_ACTIVE,
        }
    }

    fn power_change(
        machine: &mut Machine<FakeHost, Board>,
        domain: u64,
        state: crate::platform::apple::bus::LifecycleState,
    ) {
        let plan = machine
            .prepare_processor_power(&[ProcessorChange { domain, state }])
            .unwrap();
        machine.settle_processor_power(plan).unwrap();
    }

    #[test]
    fn retained_gates_pause_live_and_parked_owners_without_consuming_pending_state() {
        let mut machine = pair();
        machine
            .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
            .unwrap();
        machine.cpu.state.x[5] = 0x1234;
        machine.cpu.state.v[3] = [0x1234, 0x5678];
        machine.cpu.state.fpcr = 1 << 25;
        machine.cpu.state.fpsr = 1 << 27;
        let state = machine.cpu.state.clone();
        machine.cpu.amx.registers = Some(Box::new(stela_compiler::amx::AmxRegisters::zeroed()));
        machine.cpu.amx.registers.as_mut().unwrap().z[42] = [0xa5; 64];
        let amx = machine.cpu.amx.registers.clone();
        machine.cpu.event = true;
        machine.cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        let cluster = machine.cpu.ctrr.clone();
        let Peer::Parked(other) = &mut machine.peers[1] else {
            panic!("PE1 parked")
        };
        other.cpu.state.x[5] = 0x5678;
        other.cpu.state.v[7] = [0x9abc, 0xdef0];
        let other_state = other.cpu.state.clone();
        other.cpu.event = true;
        other.cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        let other_cluster = other.cpu.ctrr.clone();
        let plan = machine
            .prepare_processor_power(&[
                ProcessorChange {
                    domain: 1,
                    state: RETAINED_GATED,
                },
                ProcessorChange {
                    domain: 2,
                    state: crate::platform::apple::bus::LifecycleState {
                        quiesced: true,
                        ..RETAINED_ACTIVE
                    },
                },
            ])
            .unwrap();
        assert!(
            machine.cpu.monitor.is_some(),
            "preflight never clears reservations"
        );
        machine.settle_processor_power(plan).unwrap();
        machine.devices.irq = [true, true];
        assert_eq!(machine.runnable(), 0);
        assert!(!machine.ready(0, 100) && !machine.ready(1, 100));
        assert_eq!(machine.schedule(), Err(Stop::Idle));
        assert_eq!(machine.cpu.state.x[5], 0x1234);
        assert_eq!(machine.cpu.state, state);
        assert_eq!(parked(&machine, 1).state, other_state);
        assert!(machine.cpu.amx.registers == amx);
        assert!(machine.cpu.event && parked(&machine, 1).event);
        assert!(machine.cpu.monitor.is_none() && parked(&machine, 1).monitor.is_none());
        assert!(alloc::rc::Rc::ptr_eq(&cluster, &machine.cpu.ctrr));
        assert!(alloc::rc::Rc::ptr_eq(
            &other_cluster,
            &parked(&machine, 1).ctrr
        ));
        assert!(matches!(machine.peer_states()[0], PeerState::Parked { .. }));
        power_change(&mut machine, 2, RETAINED_ACTIVE);
        machine.schedule().unwrap();
        assert_eq!(
            (machine.processor(), machine.cpu.pc, machine.cpu.state.x[5]),
            (1, START, 0x5678)
        );
        assert!(machine.interrupt_pending());
        power_change(&mut machine, 1, RETAINED_ACTIVE);
        machine.schedule().unwrap();
        assert_eq!(
            (machine.processor(), machine.cpu.pc, machine.cpu.state.x[5]),
            (0, BASE, 0x1234)
        );
        assert_eq!(
            machine.devices.power,
            [(1, true)],
            "retained edges never request reset"
        );
    }

    #[test]
    fn a_stale_settlement_cannot_touch_cpu_reservations_or_clock_accounting() {
        let mut machine = pair();
        machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
        let stale = machine
            .prepare_processor_power(&[ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            }])
            .unwrap();
        power_change(&mut machine, 1, RETAINED_ACTIVE);
        machine.cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        machine.slice_end = 123;
        machine.host.now = 100;
        assert_eq!(
            machine.settle_processor_power(stale),
            Err(ProcessorPowerError::StalePlan)
        );
        assert!(machine.cpu.monitor.is_some());
        assert_eq!(machine.slice_end, 123);
        assert_eq!(machine.processors().paused(0), Some(false));
        assert_eq!(machine.statistics.switches, 0);
    }

    #[test]
    fn every_actual_owner_is_preflighted_before_any_retained_transaction_effect() {
        for broken in 0..3 {
            let mut machine = pair();
            machine
                .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
                .unwrap();
            let plan = machine
                .prepare_processor_power(&[ProcessorChange {
                    domain: 1,
                    state: RETAINED_GATED,
                }])
                .unwrap();
            machine.cpu.monitor = Some(Reservation {
                granule: BASE,
                bytes: [0; RESERVATION_GRANULE as usize],
            });
            machine.host.now = 100;
            machine.slice_end = 123;
            let expected = match broken {
                0 => {
                    machine.peers.pop();
                    ProcessorPowerError::OwnerCount {
                        expected: 2,
                        actual: 1,
                    }
                }
                1 => {
                    machine.peers[0] = Peer::Off;
                    ProcessorPowerError::MissingLiveOwner(0)
                }
                _ => {
                    machine.peers[1] = Peer::Running;
                    ProcessorPowerError::UnexpectedLiveOwner(1)
                }
            };
            assert_eq!(machine.settle_processor_power(plan), Err(expected.clone()));
            assert_eq!(
                machine
                    .prepare_processor_power(&[ProcessorChange {
                        domain: 1,
                        state: RETAINED_GATED,
                    }])
                    .unwrap_err(),
                expected
            );
            assert!(machine.cpu.monitor.is_some());
            assert_eq!(machine.processors().paused(0), Some(false));
            assert_eq!(machine.slice_end, 123);
            assert_eq!(machine.statistics.translation_changes, 0);
        }
    }

    #[test]
    fn synchronous_write_settles_actual_pe_and_native_owners_before_controller_ack() {
        let mut machine = pair();
        machine
            .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
            .unwrap();
        let mut originals = Vec::new();
        for pe in 0..2 {
            let cpu = if pe == 0 {
                &mut machine.cpu
            } else {
                let Peer::Parked(peer) = &mut machine.peers[pe] else {
                    panic!("parked PE")
                };
                &mut peer.cpu
            };
            cpu.state.x[3] = 0x1234 + pe as u64;
            cpu.monitor = Some(Reservation {
                granule: BASE,
                bytes: [0; RESERVATION_GRANULE as usize],
            });
            originals.push(cpu.state.clone());
        }
        machine.timers = Some(Some(100));
        machine.device_lines = Some((
            Lines {
                irq: true,
                fiq: false,
            },
            100,
            0,
        ));
        machine.mirrors[0] = stela_compiler::x86_64::register_read::Cell {
            readable: 1,
            value: 0x1234,
        };
        machine.prediction_context = None;
        let old_generation = machine.translation_generation;
        let old_regimes = machine.host.regimes.len();
        let mut events = Vec::new();
        let (devices, processors) = machine.processor_write_parts();
        devices
            .retained_write(
                processors,
                &[
                    ProcessorChange {
                        domain: 1,
                        state: RETAINED_GATED,
                    },
                    ProcessorChange {
                        domain: 2,
                        state: RETAINED_GATED,
                    },
                ],
                false,
                &mut events,
            )
            .unwrap();
        assert_eq!(
            events,
            [
                "native preflight",
                "CPU and native dispatch settled",
                "native commit",
                "controller ACK"
            ]
        );
        assert_eq!(machine.cpu.state, originals[0]);
        assert_eq!(parked(&machine, 1).state, originals[1]);
        assert_eq!(machine.translation_generation, old_generation + 1);
        assert_eq!(machine.host.regimes.len(), old_regimes + 1);
        assert_eq!(machine.runnable(), 0);
        assert!(
            machine.devices.power.len() == 1,
            "no new reset/power notification"
        );
    }

    #[test]
    fn refused_or_unused_synchronous_access_cannot_leave_a_partial_cpu_batch_or_ack() {
        for refusal in 0..3 {
            let mut machine = pair();
            machine
                .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
                .unwrap();
            machine.cpu.monitor = Some(Reservation {
                granule: BASE,
                bytes: [0; RESERVATION_GRANULE as usize],
            });
            machine.slice_end = 123;
            let old_generation = machine.translation_generation;
            let old_regimes = machine.host.regimes.len();
            let mut events = Vec::new();
            let mut changes = vec![
                ProcessorChange {
                    domain: 1,
                    state: RETAINED_GATED,
                },
                ProcessorChange {
                    domain: 2,
                    state: RETAINED_GATED,
                },
            ];
            if refusal == 1 {
                changes[1].domain = 999;
            }
            let (devices, processors) = machine.processor_write_parts();
            if refusal == 2 {
                let _unused = processors;
            } else {
                assert!(matches!(
                    devices.retained_write(processors, &changes, refusal == 0, &mut events),
                    Err(DeviceError::TransferRefused(_))
                ));
                assert_eq!(events, ["native preflight"]);
            }
            assert!(machine.cpu.monitor.is_some());
            assert_eq!(machine.processors().paused(0), Some(false));
            assert_eq!(machine.processors().paused(1), Some(false));
            assert_eq!(machine.slice_end, 123);
            assert_eq!(machine.translation_generation, old_generation);
            assert_eq!(machine.host.regimes.len(), old_regimes);
        }
    }

    #[test]
    fn native_dispatch_preflight_failure_precedes_participant_clock_and_cpu_changes() {
        for field in [
            "translation generation",
            "translation changes",
            "prediction isolations",
        ] {
            let mut machine = pair();
            machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
            machine.cpu.monitor = Some(Reservation {
                granule: BASE,
                bytes: [0; RESERVATION_GRANULE as usize],
            });
            machine.slice_end = 123;
            match field {
                "translation generation" => machine.translation_generation = u64::MAX,
                "translation changes" => machine.statistics.translation_changes = u64::MAX,
                _ => {
                    machine.prediction_context = None;
                    machine.statistics.prediction_isolations = u64::MAX;
                }
            }
            let before_generation = machine.translation_generation;
            let before_regimes = machine.host.regimes.len();
            let mut expected_clock = machine.clock;
            machine.host.now = 100;
            let result = machine.processor_write().apply(&[ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            }]);
            assert!(
                matches!(result, Err(ProcessorPowerError::NativeStateExhausted(actual)) if actual == field)
            );
            assert!(machine.cpu.monitor.is_some());
            assert_eq!(machine.processors().paused(0), Some(false));
            assert_eq!(machine.slice_end, 123);
            assert_eq!(machine.translation_generation, before_generation);
            assert_eq!(machine.host.regimes.len(), before_regimes);
            assert_eq!(machine.clock.read(100), expected_clock.read(100));
        }
    }

    #[test]
    fn borrowed_native_settlement_matches_full_canonical_regime_invalidation() {
        fn populated() -> Machine<FakeHost, Board> {
            let mut machine = pair();
            machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
            machine.timers = Some(Some(100));
            machine.floating_point = Some(Some(1));
            let _ = machine.memory_checks();
            let _ = machine.native_system();
            let _ = machine.debug_mode();
            machine.mirrors[0] = stela_compiler::x86_64::register_read::Cell {
                readable: 1,
                value: 7,
            };
            machine.device_lines = Some((
                Lines {
                    irq: true,
                    fiq: true,
                },
                100,
                0,
            ));
            machine.watch.ranges[0] = (0x1000, 0x1fff);
            machine.watch.pass = [Some(0x1000), None];
            machine.tag_checks = [true, true];
            machine.prediction_context = None;
            machine.pointer.open(super::super::pointer::PointerInputs {
                keys: [Some([1, 2]); 5],
                version: crate::pauth::Version::Classic,
                tcr: 17,
            });
            assert!(machine.pointer.is_open());
            machine
        }
        let mut expected = populated();
        let mut actual = populated();
        expected.translations_changed();
        let _settled = actual
            .processor_write()
            .apply(&[ProcessorChange {
                domain: 1,
                state: RETAINED_GATED,
            }])
            .unwrap();
        assert!(
            actual.timers == expected.timers && actual.floating_point == expected.floating_point
        );
        assert!(
            actual.memory_checks == expected.memory_checks
                && actual.native_system == expected.native_system
        );
        assert!(actual.debug.is_none() && expected.debug.is_none());
        assert!(!actual.pointer.is_open() && !expected.pointer.is_open());
        assert_eq!(*actual.mirrors, *expected.mirrors);
        assert_eq!(actual.device_lines, expected.device_lines);
        assert_eq!(actual.watch, expected.watch);
        assert_eq!(actual.tag_checks, expected.tag_checks);
        assert!(actual.prediction_context == expected.prediction_context);
        assert_eq!(
            actual.translation_generation,
            expected.translation_generation
        );
        assert_eq!(
            actual.statistics.translation_changes,
            expected.statistics.translation_changes
        );
        assert_eq!(
            actual.statistics.prediction_isolations,
            expected.statistics.prediction_isolations
        );
        assert_eq!(actual.host.regimes, expected.host.regimes);
        assert_eq!(actual.host.isolations, expected.host.isolations);
        assert_eq!(
            actual.host.code_invalidations,
            expected.host.code_invalidations
        );
    }

    #[test]
    fn paused_timer_events_and_timeouts_remain_pending_without_idle_skip_spinning() {
        let mut machine = pair();
        machine.clock.follow_host();
        machine
            .bind_processor_power(&[core_binding(1, 0), core_binding(2, 1)])
            .unwrap();
        machine.cpu.registers.set(Register::CNTHP_CTL_EL2, 0, 1);
        machine.cpu.registers.set(Register::CNTHP_CVAL_EL2, 0, 10);
        machine.cpu.registers.set(Register::CNTKCTL_EL1, 0, 1 << 2);
        machine.event_sample = Some(0);
        machine.waiting = Some(Wait {
            kind: WaitKind::Event,
            timeout: Some(super::super::Timeout {
                limit: 7,
                offset: 0,
            }),
            down: false,
        });
        let Peer::Parked(other) = &mut machine.peers[1] else {
            panic!("PE1 parked")
        };
        other.cpu.registers.set(Register::CNTHP_CTL_EL2, 0, 1);
        other.cpu.registers.set(Register::CNTHP_CVAL_EL2, 0, 15);
        other.waiting = Some(Wait {
            kind: WaitKind::Interrupt,
            timeout: None,
            down: false,
        });
        let plan = machine
            .prepare_processor_power(&[
                ProcessorChange {
                    domain: 1,
                    state: RETAINED_GATED,
                },
                ProcessorChange {
                    domain: 2,
                    state: RETAINED_GATED,
                },
            ])
            .unwrap();
        machine.settle_processor_power(plan).unwrap();
        machine.host.now = 20;
        machine.set_idle_skip(true);
        assert_eq!(machine.next_deadline(20), None);
        assert_eq!(machine.schedule(), Err(Stop::Idle));
        assert_eq!(
            machine.statistics.waits, 0,
            "expired paused deadlines are not wake sources"
        );
        assert_eq!(machine.cpu.read(Register::CNTHP_CVAL_EL2), 10);
        assert_eq!(machine.event_sample, Some(0), "event history is retained");
        power_change(&mut machine, 1, RETAINED_ACTIVE);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        assert_eq!(machine.cpu.pc, BASE + 4, "the original wait completes once");
        assert!(machine.waiting.is_none());
        assert!(machine.cpu.event && timer::asserted(&machine.cpu, 20));
    }

    #[test]
    fn retained_monitors_exclude_pause_time_and_preserve_fractional_cycles_and_pmi() {
        use crate::machine::{
            amu::Amu,
            pmu::{self, Context, Pmu},
        };
        let mut machine = board(&[], Board::default(), alloc::vec![identity(0)]);
        machine.clock.follow_host();
        machine.cpu.retired = 10;
        let context = Context {
            el: 1,
            filter: pmu::Filter::Guest,
            waiting: false,
        };
        let seed = (1 << 63) | 10;
        let mut monitor = Pmu::new(36_000_000, 24_000_000);
        monitor.write(pmu::PMCR1, 1 << 16, 0, 10, context).unwrap();
        monitor
            .write(pmu::PMCR1_EL12, 1 << 16, 0, 10, context)
            .unwrap();
        monitor.write(pmu::PMC[0], seed, 0, 10, context).unwrap();
        monitor
            .write(pmu::PMCR0, 1 | 4 << 8 | 1 << 12, 0, 10, context)
            .unwrap();
        machine.cpu.pmu = Some(monitor);
        let mut amu = Amu::new(36_000_000, 24_000_000);
        amu.set_enables(7, true, 0, 10);
        machine.cpu.amu = Some(amu);
        machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
        machine.host.now = 1;
        power_change(&mut machine, 1, RETAINED_GATED);
        machine.host.now = 1000;
        machine.sync_monitor();
        let monitor = machine.cpu.pmu.as_mut().unwrap();
        assert_eq!(
            monitor
                .read(
                    pmu::PMC[0],
                    1000,
                    10,
                    Context {
                        waiting: true,
                        ..context
                    }
                )
                .unwrap(),
            seed + 1
        );
        assert!(monitor.asserted(1000, 10), "pending PMI is retained");
        let amu = machine.cpu.amu.as_ref().unwrap();
        assert_eq!(
            (
                amu.count(0, 1000, 10),
                amu.count(1, 1000, 10),
                amu.count(2, 1000, 10)
            ),
            (1, 1, 0)
        );
        power_change(&mut machine, 1, RETAINED_ACTIVE);
        machine.host.now = 1001;
        let monitor = machine.cpu.pmu.as_mut().unwrap();
        assert_eq!(
            monitor.read(pmu::PMC[0], 1001, 10, context).unwrap(),
            seed + 3
        );
        let amu = machine.cpu.amu.as_ref().unwrap();
        assert_eq!(
            (
                amu.count(0, 1001, 10),
                amu.count(1, 1001, 10),
                amu.count(2, 1001, 10)
            ),
            (3, 2, 0)
        );
        assert_eq!(machine.cpu.retired, 10);
    }

    #[test]
    fn a_start_cannot_bypass_a_retained_clock_blocker() {
        let mut machine = board(&[], Board::default(), alloc::vec![identity(0), identity(1)]);
        let mut binding = core_binding(1, 1);
        binding.initial = RETAINED_GATED;
        machine.bind_processor_power(&[binding]).unwrap();
        machine
            .start(Start {
                cpu: 1,
                address: START,
            })
            .unwrap();
        assert!(!machine.ready(1, 0));
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 0);
        power_change(&mut machine, 1, RETAINED_ACTIVE);
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.pc), (1, START));
        assert_eq!(machine.devices.power, [(1, true)]);
    }

    /// Original J873GAP decoded ADT SHA-256
    /// 3252a3f13dc025ffa8551c7a5da6a71501f76ea6c5d38aa35390f9268a6dc378:
    /// CPU6/7 P and CPU8..11 M share physical cluster 1. Only these affinity
    /// coordinates are qualified: MIDR=0 is an explicit synthetic fixture,
    /// and using a modeled cluster register does not admit that register or
    /// any complete M6 hardware profile.
    #[test]
    fn original_m6_mixed_cluster_shares_live_or_parked_owners_in_either_start_order() {
        use super::super::tests::board_on;
        use crate::machine::{Chip, ctrr::Field, impdef};
        const MPIDRS: [u64; 12] = [
            0x8000_0000,
            0x8000_0001,
            0x8000_0002,
            0x8000_0003,
            0x8000_0004,
            0x8000_0005,
            0x8001_0100,
            0x8001_0101,
            0x8004_0102,
            0x8004_0103,
            0x8004_0104,
            0x8004_0105,
        ];
        let counter = impdef::lookup(impdef::CLUSTER_COUNTER_C0, Chip::AppleM2).unwrap();
        for order in [[6, 7, 8, 9, 10, 11], [8, 9, 10, 11, 6, 7]] {
            for live in [false, true] {
                let identities = MPIDRS
                    .into_iter()
                    .map(|mpidr| Identity {
                        midr: 0,
                        mpidr,
                        clock: None,
                        caches: None,
                    })
                    .collect();
                let mut machine = board_on(Chip::AppleM6, &[], super::super::NoDevices, identities);
                let first = order[0];
                machine
                    .start(Start {
                        cpu: first,
                        address: START,
                    })
                    .unwrap();
                let Peer::Parked(owner) = &mut machine.peers[first] else {
                    panic!("the first owner is parked")
                };
                owner
                    .cpu
                    .ctrr
                    .borrow_mut()
                    .write(0, Field::Lower, BASE)
                    .unwrap();
                owner
                    .cpu
                    .ctrr
                    .borrow_mut()
                    .write(0, Field::Lock, 1)
                    .unwrap();
                owner.cpu.apple.impdef.write(counter, 17).unwrap();
                let shared = owner.cpu.ctrr.clone();
                if live {
                    machine.switch_to(first);
                }
                for &pe in &order[1..] {
                    machine
                        .start(Start {
                            cpu: pe,
                            address: START + pe as u64 * 4,
                        })
                        .unwrap();
                    let Peer::Parked(target) = &mut machine.peers[pe] else {
                        panic!("a new PE is parked")
                    };
                    assert!(alloc::rc::Rc::ptr_eq(&shared, &target.cpu.ctrr));
                    assert_eq!(target.cpu.ctrr.borrow().read(0, Field::Lower), BASE);
                    assert!(
                        target
                            .cpu
                            .ctrr
                            .borrow_mut()
                            .write(0, Field::Lower, 0)
                            .is_err()
                    );
                    assert_eq!(target.cpu.apple.impdef.read(counter), Ok(17));
                    target.cpu.apple.impdef.write(counter, 19).unwrap();
                    if live {
                        assert_eq!(machine.cpu.apple.impdef.read(counter), Ok(19));
                        machine.cpu.apple.impdef.write(counter, 17).unwrap();
                    } else {
                        let Peer::Parked(owner) = &mut machine.peers[first] else {
                            panic!("the original owner is parked")
                        };
                        assert_eq!(owner.cpu.apple.impdef.read(counter), Ok(19));
                        owner.cpu.apple.impdef.write(counter, 17).unwrap();
                    }
                }
                // E cores are a different physical cluster even though all
                // P/M owners above now share one underlying register bank.
                machine
                    .start(Start {
                        cpu: 1,
                        address: START,
                    })
                    .unwrap();
                let Peer::Parked(other) = &mut machine.peers[1] else {
                    panic!("the E core is parked")
                };
                assert!(!alloc::rc::Rc::ptr_eq(&shared, &other.cpu.ctrr));
                assert_eq!(other.cpu.ctrr.borrow().read(0, Field::Lock), 0);
                assert_eq!(other.cpu.apple.impdef.read(counter), Ok(0));
            }
        }
    }

    #[test]
    fn every_pe_and_new_cluster_starts_from_the_core_lock_handoff() {
        use super::super::tests::board_on;
        use crate::machine::Chip;
        let identities = [0x8000_0000, 0x8001_0100]
            .into_iter()
            .map(|mpidr| Identity {
                midr: 0,
                mpidr,
                clock: None,
                caches: None,
            })
            .collect();
        let mut machine = board_on(Chip::AppleM5, &[], super::super::NoDevices, identities);
        let handoff = ctrr::Handoff {
            locked: alloc::vec![ctrr::Locked {
                region: ctrr::Region::CtxrA,
                first: 0x100_070a_4000,
                last: 0x100_0710_bfff,
            }],
            legacy_locked: true,
            tag_offset: 0,
        };
        machine.hand_off_core_locks(handoff.clone());
        assert_eq!(
            *machine.cpu.ctrr.borrow(),
            ctrr::Cluster::handed_off(&handoff)
        );
        machine.cpu.ctrr_core.el2.windows[0].lower = 0x1000;
        machine
            .start(Start {
                cpu: 1,
                address: START,
            })
            .unwrap();
        let Peer::Parked(other) = &mut machine.peers[1] else {
            panic!("the other cluster's PE is parked")
        };
        assert!(!alloc::rc::Rc::ptr_eq(&machine.cpu.ctrr, &other.cpu.ctrr));
        assert_eq!(
            *other.cpu.ctrr.borrow(),
            ctrr::Cluster::handed_off(&handoff)
        );
        assert_eq!(other.cpu.ctrr_core, ctrr::Core::handed_off(&handoff));
    }

    #[test]
    fn all_eight_pe_and_cluster_participants_preflight_and_settle_together() {
        use super::super::tests::board_on;
        let identities = (0..8)
            .map(|pe| Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000 | (pe / 4) << 16 | (pe / 4) << 8 | (pe % 4),
                clock: None,
                caches: None,
            })
            .collect();
        let mut machine = board_on(
            crate::machine::Chip::AppleM2,
            &[],
            super::super::NoDevices,
            identities,
        );
        for pe in 1..8 {
            machine
                .start(Start {
                    cpu: pe,
                    address: START + pe as u64 * 4,
                })
                .unwrap();
            let Peer::Parked(other) = &mut machine.peers[pe] else {
                panic!("started PE parked")
            };
            other.cpu.state.x[5] = pe as u64;
        }
        let mut bindings: Vec<_> = (0..8).map(|pe| core_binding(pe as u64 + 1, pe)).collect();
        for (domain, members) in [(9, alloc::vec![0, 1, 2, 3]), (10, alloc::vec![4, 5, 6, 7])] {
            bindings.push(ProcessorBinding {
                domain,
                target: ProcessorTarget::Cluster { members },
                initial: RETAINED_ACTIVE,
            });
        }
        machine.bind_processor_power(&bindings).unwrap();
        assert_eq!(machine.processors().domain_count(), 10);
        assert_eq!(machine.runnable(), 8);
        let good = ProcessorChange {
            domain: 9,
            state: RETAINED_GATED,
        };
        assert!(
            machine
                .prepare_processor_power(&[
                    good,
                    ProcessorChange {
                        domain: 7,
                        state: crate::platform::apple::bus::LifecycleState {
                            reset: true,
                            ..RETAINED_ACTIVE
                        }
                    }
                ])
                .is_err()
        );
        assert_eq!(machine.runnable(), 8);
        let plan = machine
            .prepare_processor_power(&[
                good,
                ProcessorChange {
                    domain: 10,
                    state: RETAINED_GATED,
                },
            ])
            .unwrap();
        machine.settle_processor_power(plan).unwrap();
        assert_eq!(machine.runnable(), 0);
        assert!((0..8).all(|pe| machine.processors().paused(pe) == Some(true)));
        assert_eq!(machine.schedule(), Err(Stop::Idle));
        let plan = machine
            .prepare_processor_power(&[ProcessorChange {
                domain: 9,
                state: RETAINED_ACTIVE,
            }])
            .unwrap();
        machine.settle_processor_power(plan).unwrap();
        assert_eq!(machine.runnable(), 4);
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.state.x[5]), (1, 1));
        let plan = machine
            .prepare_processor_power(&[
                ProcessorChange {
                    domain: 10,
                    state: RETAINED_ACTIVE,
                },
                ProcessorChange {
                    domain: 7,
                    state: RETAINED_GATED,
                },
            ])
            .unwrap();
        machine.settle_processor_power(plan).unwrap();
        assert_eq!(machine.runnable(), 7);
        assert_eq!(machine.processors().paused(6), Some(true));
    }

    #[test]
    fn debug_pc_sample_latches_the_requested_parked_pe() {
        use crate::machine::apple::AppleDevices;
        use crate::platform::apple::coresight::PC_SAMPLE;
        let base = 0x2_1004_0000;
        let mut devices = AppleDevices::new();
        devices.add_coresight_sampler(1, base).unwrap();
        let mut machine = board(&[], devices, alloc::vec![identity(0), identity(1)]);
        let pc = BASE + 0x400;
        machine.peers[1] = Peer::Parked(Box::new(Parked {
            cpu: Cpu::of(machine.profile.chip, pc, Pstate::reset(2)),
            event_sample: None,
            waiting: None,
            mirrors: super::super::Mirrors::default(),
        }));
        assert_eq!(machine.device_read(base + PC_SAMPLE, 8, 0), Ok(0));
        machine.device_read(base + PC_SAMPLE, 4, 0).unwrap();
        assert_eq!(machine.device_read(base + PC_SAMPLE, 8, 0), Ok(pc));
        if let Peer::Parked(parked) = &mut machine.peers[1] {
            parked.cpu.pc += 4;
        }
        assert_eq!(machine.device_read(base + PC_SAMPLE, 8, 0), Ok(pc));
        machine.device_read(base + PC_SAMPLE, 4, 0).unwrap();
        assert_eq!(machine.device_read(base + PC_SAMPLE, 8, 0), Ok(pc + 4));
        machine.peers[1] = Peer::Off;
        assert!(machine.device_read(base + PC_SAMPLE, 4, 0).is_err());
        assert_eq!(machine.device_read(base + PC_SAMPLE, 8, 0), Ok(pc + 4));
    }

    #[test]
    fn a_wait_only_the_host_can_end_or_that_reaches_the_limit_returns_to_the_host() {
        let mut machine = board(&[], Board::default(), alloc::vec![identity(0)]);
        machine.system_instruction(WFI).unwrap();
        // Nothing can wake the PE: idle.
        assert_eq!(machine.schedule(), Err(Stop::Idle));
        // Only the host's inputs can: without a limit, back to the host at
        // once, waiting on nothing.
        machine.devices.host_wake = true;
        assert_eq!(machine.schedule(), Err(Stop::Waiting));
        assert_eq!(machine.host.now, 0);
        // With a limit, after waiting that long (the fake host's waits last
        // 1000 ticks), and idle skip has no deadline to leap to.
        machine.set_wait_limit(Some(2500));
        machine.set_idle_skip(true);
        assert_eq!(machine.schedule(), Err(Stop::Waiting));
        assert_eq!(machine.host.now, 3000);
        // The limit bounds a wait for a deadline too; the deadline still
        // ends the wait it falls in.
        machine.set_idle_skip(false);
        machine.devices.host_wake = false;
        machine.devices.dma = Some(10_000);
        assert_eq!(machine.schedule(), Err(Stop::Waiting));
        assert_eq!(machine.host.now, 6000);
        machine.set_wait_limit(None);
        machine.schedule().unwrap();
        assert!(machine.host.now >= 10_000);
        assert_eq!(machine.processor(), 0);
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
    fn an_rmr_el2_reset_request_warm_resets_the_pe_at_its_reset_vector() {
        const MSR_RMR_EL2_X1: u32 = 0xd51c_c041;
        const MRS_X1_RMR_EL2: u32 = 0xd53c_c041;
        let devices = Board {
            reset: Some(START),
            ..Board::default()
        };
        let mut machine = board(&[], devices, alloc::vec![identity(0)]);
        let cpu = &mut machine.cpu;
        cpu.set_pstate(Pstate::reset(2));
        cpu.registers.set_raw(Register::OSLSR_EL1, 0, 0);
        cpu.registers.set(Register::DBGBVR_EL1, 1, 0x1000);
        cpu.registers.set(Register::ELR_EL2, 0, 0x8000);
        cpu.claim = 0b101;
        cpu.state.x[5] = 7;
        cpu.monitor = Some(Reservation {
            granule: BASE,
            bytes: [0; RESERVATION_GRANULE as usize],
        });
        // RR clear requests nothing.
        machine.cpu.state.x[1] = 0b01;
        machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        machine.cpu.state.x[1] = 0b10;
        machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
        let cpu = &machine.cpu;
        assert_eq!((cpu.pc, cpu.pstate.el, cpu.pstate.sp), (START, 2, true));
        assert_eq!(cpu.pstate.daif, DAIF_ALL);
        assert_eq!((cpu.state.x[5], cpu.monitor), (0, None));
        assert_eq!(cpu.read(Register::MPIDR_EL1), 0x8000_0000);
        // Only a Cold reset sets the OS lock, the breakpoints and the claim
        // tags; ELR_EL2 is UNKNOWN (0 here) and RR clears.
        assert_eq!(cpu.read(Register::OSLSR_EL1), 0);
        assert_eq!(cpu.registers.get(Register::DBGBVR_EL1, 1), 0x1000);
        assert_eq!(cpu.claim, 0b101);
        assert_eq!(cpu.read(Register::ELR_EL2), 0);
        machine.system_instruction(MRS_X1_RMR_EL2).unwrap();
        assert_eq!(machine.cpu.state.x[1], 1);
        // EL1 cannot reach RMR_EL2, and a board without a reset vector
        // cannot reset the PE.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.system_instruction(MSR_RMR_EL2_X1).unwrap();
        assert_eq!(machine.cpu.read(Register::ESR_EL1), 0x0200_0000);
        machine.devices.reset = None;
        machine.cpu.set_pstate(Pstate::reset(2));
        machine.cpu.state.x[1] = 0b10;
        assert!(matches!(
            machine.system_instruction(MSR_RMR_EL2_X1),
            Err(Stop::Unsupported(_))
        ));
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
        // PE 1's IRQ does not wake PE 0. The board's lines change as a
        // device access the engine is told of would change them.
        machine.devices.irq = [false, true];
        machine.device_lines = None;
        end_slice(&mut machine);
        machine.devices.lines_asked.clear();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert_eq!(machine.devices.lines_asked, [0]);
        // Its own line does, masked or not, and WFI completes.
        machine.devices.irq = [true, false];
        machine.device_lines = None;
        end_slice(&mut machine);
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.pc), (0, BASE + 4));
        assert_eq!(machine.cpu.pstate.daif, DAIF_ALL);
        // With both PEs in WFI and no timer, stream or device deadline, the
        // machine is idle.
        machine.devices.irq = [false, false];
        machine.device_lines = None;
        machine.system_instruction(WFI).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        machine.system_instruction(WFI).unwrap();
        assert_eq!(machine.schedule(), Err(Stop::Idle));
    }
    #[test]
    fn dma_dispatch_reads_one_clock_only_when_pending_and_publishes_when_due() {
        let mut machine = board(&[], Board::default(), Vec::new());
        let reads = machine.host.counter_reads;
        machine.poll_due_devices().unwrap();
        assert_eq!(machine.host.counter_reads, reads);
        machine.devices.dma = Some(100);
        machine.host.now = 99;
        machine.poll_due_devices().unwrap();
        assert_eq!(machine.host.counter_reads, reads + 1);
        assert_eq!(machine.devices.dma, Some(100));
        assert_eq!(&machine.host.ram[0x100..0x103], &[0; 3]);
        machine.host.now = 100;
        machine.poll_due_devices().unwrap();
        assert_eq!(machine.host.counter_reads, reads + 2);
        assert_eq!(machine.devices.dma, None);
        assert_eq!(&machine.host.ram[0x100..0x103], b"USB");
        assert!(machine.devices.irq[0]);
        assert!(machine.device_lines.is_none());
        machine.poll_due_devices().unwrap();
        assert_eq!(machine.host.counter_reads, reads + 2);
    }

    #[test]
    fn native_bus_peer_dma_runs_and_wakes_a_waiting_pe_without_mmio() {
        let devices = Board {
            dma: Some(1000),
            ..Board::default()
        };
        let mut machine = board(&[WFI], devices, Vec::new());
        machine.waiting = Some(Wait {
            kind: WaitKind::Interrupt,
            timeout: None,
            down: false,
        });
        machine.schedule().unwrap();
        assert!(machine.waiting.is_none());
        assert!(machine.host.now >= 1000);
        let mut bytes = [0; 3];
        assert!(machine.host.read_ram(BASE + 0x100, &mut bytes));
        assert_eq!(&bytes, b"USB");
        assert!(machine.devices.irq[0]);
        assert_eq!(machine.devices.dma_deadline(), None);
    }

    #[test]
    fn a_wait_pass_never_gives_the_devices_an_earlier_count() {
        let devices = Board {
            dma: Some(1000),
            ..Board::default()
        };
        let mut machine = board(&[WFI], devices, Vec::new());
        // The host counter moves on at every read, as a real one does.
        machine.host.counter_step = 7;
        machine.waiting = Some(Wait {
            kind: WaitKind::Interrupt,
            timeout: None,
            down: false,
        });
        machine.schedule().unwrap();
        assert!(machine.waiting.is_none());
        let counts = &machine.devices.counts;
        assert!(counts.len() > 2, "{counts:?}");
        assert!(counts.is_sorted(), "{counts:?}");
    }

    #[test]
    fn a_switch_keeps_the_device_lines_and_reads_the_incoming_pes_pins() {
        let mut machine = pair();
        machine.devices.pins = true;
        machine.devices.dma = Some(u64::MAX - 1);
        machine.devices.irq = [false, true];
        machine.device_lines = None;
        let current = machine.processor();
        let other = current ^ 1;
        assert_eq!(machine.lines().irq, machine.devices.irq[current]);
        let asked = machine.devices.lines_asked.len();
        machine.switch_to(other);
        // No device advances for the incoming PE: its latched pins answer.
        assert_eq!(machine.lines().irq, machine.devices.irq[other]);
        assert_eq!(machine.devices.lines_asked.len(), asked);
        assert_eq!(machine.devices.pins_asked, [other]);
        assert_eq!(machine.lines().irq, machine.devices.irq[other]);
        assert_eq!(machine.devices.pins_asked, [other]);
        // A board without latched pins is asked to advance again.
        machine.devices.pins = false;
        machine.switch_to(current);
        assert_eq!(machine.lines().irq, machine.devices.irq[current]);
        assert_eq!(machine.devices.lines_asked.len(), asked + 1);
    }

    #[test]
    fn a_pe_takes_its_open_mirrored_reads_back_when_it_runs_again() {
        const MRS_X8_TPIDR_EL1: u32 = 0xd538_d088;
        let mut machine = pair();
        let current = machine.processor();
        let other = current ^ 1;
        machine.cpu.registers.set(Register::TPIDR_EL1, 0, 0x7000);
        machine.system_instruction(MRS_X8_TPIDR_EL1).unwrap();
        let open = machine.mirrors[2];
        assert_eq!((open.readable, open.value), (1, 0x7000));
        // The other PE's cells are its own, closed until it reads.
        machine.switch_to(other);
        assert_eq!(machine.mirrors[2].readable, 0);
        machine.switch_to(current);
        assert_eq!(machine.mirrors[2], open);
        // A change to a parked PE closes the cells it left.
        machine.switch_to(other);
        if let Peer::Parked(parked) = &mut machine.peers[current] {
            parked
                .cpu_mut()
                .registers
                .set(Register::TPIDR_EL1, 0, 0x8000);
        }
        machine.switch_to(current);
        assert_eq!(machine.mirrors[2].readable, 0);
    }

    /// Switch to the next PE that can run, which must be `pe`.
    fn turn(machine: &mut Machine<FakeHost, Board>, pe: usize) {
        end_slice(machine);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), pe);
    }

    #[test]
    fn a_store_exclusive_fails_once_another_pe_wrote_the_granule_and_its_retry_counts_both() {
        const LDXR_X1_X2: u32 = 0xc85f_7c41;
        const STXR_W3_X4_X2: u32 = 0xc803_7c44;
        let data = 0x400;
        let mut machine = pair();
        let value = |machine: &Machine<FakeHost, Board>| {
            u64::from_le_bytes(machine.host.ram[data..data + 8].try_into().unwrap())
        };
        let load = |machine: &mut Machine<FakeHost, Board>| {
            machine.cpu.state.x[2] = BASE + data as u64;
            machine.system_instruction(LDXR_X1_X2).unwrap();
            machine.cpu.state.x[1]
        };
        let store = |machine: &mut Machine<FakeHost, Board>, value| {
            machine.cpu.state.x[4] = value;
            machine.system_instruction(STXR_W3_X4_X2).unwrap();
            machine.cpu.state.x[3]
        };
        // Two PEs increment one counter with LDXR/STXR loops. PE 0 loads 0
        // and is preempted before its store; PE 1's whole increment passes.
        assert_eq!(load(&mut machine), 0);
        turn(&mut machine, 1);
        let seen = load(&mut machine);
        assert_eq!((seen, store(&mut machine, seen + 1)), (0, 0));
        // PE 0's store fails without writing; its retry loads PE 1's value
        // and passes, so neither increment is lost.
        turn(&mut machine, 0);
        assert_eq!((store(&mut machine, 1), value(&machine)), (1, 1));
        let seen = load(&mut machine);
        assert_eq!((seen, store(&mut machine, seen + 1)), (1, 0));
        assert_eq!(value(&machine), 2);
        // An LSE atomic (LDADD) runs natively and writes RAM directly: PE 1's
        // clears PE 0's reservation too, and PE 0's store fails.
        assert_eq!(load(&mut machine), 2);
        turn(&mut machine, 1);
        machine.host.ram[data..data + 8].copy_from_slice(&3u64.to_le_bytes());
        turn(&mut machine, 0);
        assert_eq!(machine.cpu.monitor, None);
        assert_eq!((store(&mut machine, 3), value(&machine)), (1, 3));
    }

    const LEVEL1: usize = 0xf000;
    const LEVEL2: usize = 0xe000;
    const LEVEL3: usize = 0xd000;

    /// Write `value` to entry `index` of the translation table at `table`.
    fn descriptor(machine: &mut Machine<FakeHost, Board>, table: usize, index: usize, value: u64) {
        let at = table + index * 8;
        machine.host.ram[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// The level 3 page descriptor of the test RAM page at `output`.
    fn page(output: u64) -> u64 {
        const AF_INNER_SHAREABLE_PAGE: u64 = 1 << 10 | 3 << 8 | 0b11;
        output | AF_INNER_SHAREABLE_PAGE
    }

    /// Stage 1 of the running PE's EL1&0 regime with 4 KiB pages: VA = PA
    /// for the test RAM's 16 pages.
    fn map_pages(machine: &mut Machine<FakeHost, Board>) {
        const TABLE: u64 = 0b11;
        const TCR: u64 = 25 | 1 << 8 | 1 << 10 | 3 << 12 | 1 << 23 | 5 << 32;
        const SCTLR_M_C: u64 = 1 | 1 << 2;
        descriptor(
            machine,
            LEVEL1,
            (BASE >> 30) as usize,
            (BASE + LEVEL2 as u64) | TABLE,
        );
        descriptor(machine, LEVEL2, 0, (BASE + LEVEL3 as u64) | TABLE);
        for index in 0..16 {
            descriptor(machine, LEVEL3, index, page(BASE + index as u64 * 0x1000));
        }
        let registers = &mut machine.cpu.registers;
        registers.set(Register::TTBR0_EL1, 0, BASE + LEVEL1 as u64);
        registers.set(Register::TCR_EL1, 0, TCR);
        registers.set(Register::MAIR_EL1, 0, 0xff);
        let sctlr = registers.get(Register::SCTLR_EL1, 0) | SCTLR_M_C;
        registers.set(Register::SCTLR_EL1, 0, sctlr);
        machine.translations_changed();
    }

    #[test]
    fn a_tlbi_broadcast_by_one_pe_reaches_the_cached_fetch_translations_of_every_pe() {
        const TLBI_VAE1IS_X0: u32 = 0xd508_8320;
        let code = BASE + 0x1000;
        let mut machine = pair();
        let fetch = |machine: &mut Machine<FakeHost, Board>| machine.fetch_physical(code).ok();
        // Both PEs run EL1 code through the same tables.
        map_pages(&mut machine);
        assert_eq!(fetch(&mut machine), Some(code));
        turn(&mut machine, 1);
        machine.cpu.pstate = Pstate::reset(1);
        map_pages(&mut machine);
        assert_eq!(fetch(&mut machine), Some(code));
        // PE 1 remaps the page. Its cached translation stands until it
        // invalidates the VA, as a TLB entry may.
        descriptor(&mut machine, LEVEL3, 1, page(BASE + 0x2000));
        assert_eq!(fetch(&mut machine), Some(code));
        machine.cpu.state.x[0] = code >> 12;
        machine.system_instruction(TLBI_VAE1IS_X0).unwrap();
        assert_eq!(fetch(&mut machine), Some(BASE + 0x2000));
        // The Inner Shareable invalidation reached PE 0, whose earlier
        // translation of the page is gone too.
        turn(&mut machine, 0);
        assert_eq!(fetch(&mut machine), Some(BASE + 0x2000));
    }

    #[test]
    fn ic_ivau_by_one_pe_makes_every_pe_compile_the_new_code() {
        const RET: u32 = 0xd65f_03c0;
        const ADD_X0: u32 = 0x9100_0400;
        const IC_IVAU_X0: u32 = 0xd50b_7520;
        let code = 0x1000;
        for retained_pause in [false, true] {
            let mut machine = pair();
            machine.host.ram[code..code + 4].copy_from_slice(&RET.to_le_bytes());
            let compiled = |machine: &mut Machine<FakeHost, Board>| {
                let Ok(super::super::Fetched::Block(index)) =
                    machine.fetch_block(BASE + code as u64, false)
                else {
                    panic!("no block at the code");
                };
                (
                    machine.blocks[index].source_hash,
                    machine.statistics.compiled,
                )
            };
            let (old, count) = compiled(&mut machine);
            // PE 1, in the same regime, runs the shared compiled block.
            if retained_pause {
                machine.bind_processor_power(&[core_binding(1, 0)]).unwrap();
                power_change(&mut machine, 1, RETAINED_GATED);
                machine.schedule().unwrap();
                assert_eq!(machine.processor(), 1);
            } else {
                turn(&mut machine, 1);
            }
            machine.cpu.pstate = Pstate::reset(1);
            assert_eq!(compiled(&mut machine), (old, count));
            // It rewrites the code: until it invalidates the instruction cache
            // to the PoU the old block may still run, as stale instructions may.
            machine.host.ram[code..code + 8]
                .copy_from_slice(&[ADD_X0.to_le_bytes(), RET.to_le_bytes()].concat());
            assert_eq!(compiled(&mut machine), (old, count));
            machine.cpu.state.x[0] = BASE + code as u64;
            machine.system_instruction(IC_IVAU_X0).unwrap();
            // The host hears of it for PEs it runs in machines of their own.
            assert_eq!(machine.host.code_invalidations, [Some(BASE + code as u64)]);
            // The invalidation is broadcast: PE 0 compiles the new code.
            if retained_pause {
                power_change(&mut machine, 1, RETAINED_ACTIVE);
                machine.schedule().unwrap();
                assert_eq!(machine.processor(), 0);
            } else {
                turn(&mut machine, 0);
            }
            let (new, recompiled) = compiled(&mut machine);
            assert_ne!(new, old);
            assert_eq!(recompiled, count + 1);
        }
    }

    #[test]
    fn a_pes_interrupt_waits_for_its_turn_and_unmasking_and_preempts_where_it_stopped() {
        const MSR_DAIFCLR_I: u32 = 0xd503_42ff;
        const IRQ_CURRENT_SPX: u64 = 0x280;
        const HCR_TGE: u64 = 1 << 27;
        let mut machine = pair();
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        // PE 1's line does not interrupt PE 0, unmasked.
        machine.devices.irq = [false, true];
        machine.cpu.pstate.daif = 0;
        assert!(!machine.deliver_interrupts());
        // PE 1 runs in the host, at EL2 with every interrupt masked from
        // reset: its IRQ stays pending until it clears PSTATE.I.
        turn(&mut machine, 1);
        let hcr = machine.cpu.read(Register::HCR_EL2) | HCR_TGE;
        machine.cpu.registers.set(Register::HCR_EL2, 0, hcr);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        assert!(!machine.deliver_interrupts());
        machine.system_instruction(MSR_DAIFCLR_I).unwrap();
        assert!(machine.deliver_interrupts());
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pc),
            (2, 0x4_0000 + IRQ_CURRENT_SPX)
        );
        assert_eq!(machine.cpu.read(Register::ELR_EL2), START + 4);
        assert_eq!(machine.cpu.pstate.daif, DAIF_ALL);
        // PE 0's line rises while it is preempted; it takes the IRQ when it
        // runs again, returning to where its slice ended.
        machine.devices.irq = [true, false];
        turn(&mut machine, 0);
        assert!(machine.deliver_interrupts());
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pc),
            (1, 0x1_0000 + IRQ_CURRENT_SPX)
        );
        assert_eq!(machine.cpu.read(Register::ELR_EL1), BASE);
    }

    #[test]
    fn a_powered_down_pe_loses_its_state_and_leaves_reset_on_a_wake_line_or_a_start() {
        const MSR_CYC_OVRD_X0: u32 = 0xd51d_f500;
        const POWER_DOWN: u64 = 3 << 24;
        const LINES_DISABLED: u64 = 2 << 22 | 2 << 20;
        const RESET: u64 = BASE + 0xc00;
        let mut machine = pair();
        machine.devices.reset = Some(RESET);
        assert_eq!(machine.devices.power, [(1, true)]);
        // PE 0 powers down with its lines enabled; PE 1 runs, and its SEV
        // does not reach PE 0.
        machine.cpu.state.x[0] = POWER_DOWN;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        machine.cpu.state.x[5] = 0x1234;
        machine.system_instruction(WFI).unwrap();
        assert_eq!(machine.devices.power, [(1, true), (0, false)]);
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        assert!(matches!(machine.peer_states()[0], PeerState::Down));
        machine.system_instruction(SEV).unwrap();
        // Its device line wakes it at its reset vector, its state lost.
        machine.devices.irq = [true, false];
        turn(&mut machine, 0);
        let cpu = &machine.cpu;
        assert_eq!(
            (cpu.pc, cpu.pstate.el, cpu.state.x[5], cpu.event),
            (RESET, 2, 0, false)
        );
        assert_eq!(cpu.read(Register::MPIDR_EL1), 0x8000_0000);
        assert_eq!(machine.devices.power.last(), Some(&(0, true)));
        // With both its lines disabled the asserted line does not wake it,
        // and with PE 1 waiting too the machine is idle until a device
        // starts PE 0 again.
        machine.cpu.state.x[0] = POWER_DOWN | LINES_DISABLED;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        machine.system_instruction(WFI).unwrap();
        machine.schedule().unwrap();
        assert_eq!(machine.processor(), 1);
        machine.system_instruction(WFI).unwrap();
        assert_eq!(machine.schedule(), Err(Stop::Idle));
        machine.devices.starts.push(Start {
            cpu: 0,
            address: START,
        });
        machine.schedule().unwrap();
        assert_eq!((machine.processor(), machine.cpu.pc), (0, START));
        // A board that holds no reset vector cannot wake it.
        machine.devices.reset = None;
        machine.devices.irq = [false, false];
        machine.cpu.state.x[0] = POWER_DOWN;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        machine.system_instruction(WFI).unwrap();
        assert_eq!(machine.schedule(), Err(Stop::Idle));
        machine.devices.irq = [true, false];
        assert!(matches!(machine.schedule(), Err(Stop::Unsupported(_))));
    }
}
