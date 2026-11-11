//! Apple fast IPIs: implementation-defined system registers that raise a FIQ
//! on another CPU without the AIC (AICv2 has no IPI registers).
//!
//! Documented by Linux `drivers/irqchip/irq-apple-aic.c` and m1n1
//! `src/cpu_regs.h`:
//! - `IPI_RR_LOCAL_EL1` (S3_5_C15_C0_0) targets CPU [7:0] in the sender's
//!   cluster; `IPI_RR_GLOBAL_EL1` (S3_5_C15_C0_1) also takes CLUSTER [23:16].
//!   TYPE [29:28] is 0 immediate, 1 retract, 2 deferred, 3 no-wake.
//! - `IPI_SR_EL1` (S3_5_C15_C1_1) bit 0 is the pending FIQ, cleared by writing
//!   1 (`aic_handle_ipi`, `aic_init_cpu`).
//! - `IPI_CR_EL1` (S3_5_C15_C3_1) is the deferred-IPI countdown. XNU
//!   `osfmk/arm64/machine_routines.c` (`ml_cpu_signal_deferred_adjust_timer`)
//!   documents it as one global register of REFCLK ticks in a 16-bit field
//!   that a single write updates for every core.
//! - The cluster and CPU numbers are MPIDR Aff1 and Aff0 (`aic_ipi_send_fast`).
//!
//! Inferred, not documented: a retract cancels a deferred IPI that has not
//! fired yet, and an immediate IPI subsumes one. The IPI_CR reset value is not
//! known, so reading it or sending a deferred IPI before it is written is
//! refused. No-wake requests are refused because their effect on a waiting CPU
//! is not documented.
//!
//! These registers are EL1-accessible; the engine decides EL0 traps before
//! calling [`FastIpi::access`].
//!
//! Every FIQ handler reads IPI_SR, so a PE reads its own word outside the
//! devices' lock ([`FastIpi::status`]). The word is the FIQ wire itself: a
//! PE's FIQ line is its latched pins or a set IPI_SR ([`FastIpi::fiq`]), so
//! an immediate request to a CPU with no deferred IPI armed and an
//! acknowledgement complete on the atomics alone ([`Signals::send`],
//! [`Signals::acknowledge`]), with no lock; requests that arm, retract or
//! subsume a deferred IPI, and the countdown, stay under the devices' lock.
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{
    AtomicBool, AtomicU64,
    Ordering::{AcqRel, Acquire, Release, SeqCst},
};
use stela_engine::system::access::AccessKind;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_contracts::interrupt::CpuIndex;

use stela_engine::machine::fast_ipi::Register;

const RR_CPU: u64 = 0xff;
const RR_CLUSTER_SHIFT: u32 = 16;
const RR_CLUSTER: u64 = 0xff << RR_CLUSTER_SHIFT;
const RR_TYPE_SHIFT: u32 = 28;
const RR_TYPE: u64 = 0b11 << RR_TYPE_SHIFT;
const SR_PENDING: u64 = 1;
const CR_COUNTDOWN: u64 = 0xffff;

/// MPIDR affinity of one CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Affinity {
    pub cluster: u8,
    pub cpu: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiError {
    UnknownCpu(CpuIndex),
    Unsupported(Register, &'static str),
}

/// One CPU's IPI_SR and whether a deferred IPI is armed for it, on a cache
/// line of its own: senders write the word, and its CPU reads it at every
/// FIQ.
#[derive(Debug, Default)]
#[repr(align(64))]
struct Word {
    /// IPI_SR.
    pending: AtomicU64,
    /// [`FastIpi`] holds a deferred IPI for the CPU (written under the
    /// devices' lock).
    armed: AtomicBool,
}

/// What every CPU reaches of the fast IPIs without the devices' lock.
#[derive(Debug)]
pub struct Signals {
    cpus: Vec<Affinity>,
    words: Box<[Word]>,
}

impl Signals {
    /// The CPU an immediate request `value` written by `cpu` to `register`
    /// names, when it may complete without the lock: a well-formed
    /// immediate request (TYPE 0) to a CPU of the machine with no deferred
    /// IPI armed. A request that would clear an armed deferred IPI, or that
    /// is refused, takes [`FastIpi::access`].
    fn immediate_target(&self, cpu: CpuIndex, register: Register, value: u64) -> Option<CpuIndex> {
        let global = match register {
            Register::RequestLocal => false,
            Register::RequestGlobal => true,
            _ => return None,
        };
        let fields = RR_CPU | RR_TYPE | if global { RR_CLUSTER } else { 0 };
        if value & !fields != 0 || value & RR_TYPE != 0 {
            return None;
        }
        let sender = *self.cpus.get(cpu)?;
        let target = Affinity {
            cluster: if global {
                (value >> RR_CLUSTER_SHIFT) as u8
            } else {
                sender.cluster
            },
            cpu: (value & RR_CPU) as u8,
        };
        let target = self.cpus.iter().position(|&affinity| affinity == target)?;
        (!self.words[target].armed.load(Acquire)).then_some(target)
    }

    /// MSR `register` by `cpu` of `value` without the devices' lock, where
    /// it can complete so: `None` when it must take [`FastIpi::access`];
    /// `Some(Some(target))` when it raised `target`'s FIQ, whose PE must
    /// look at its lines again; `Some(None)` when it changed no line.
    ///
    /// An immediate request to a CPU with no deferred IPI armed only sets
    /// its IPI_SR: a deferred IPI armed after the check is ordered after
    /// the request, as if armed under the lock just after it, and keeps
    /// its countdown either way. An acknowledgement (IPI_SR write of
    /// PENDING) clears the CPU's own word.
    pub fn send(&self, cpu: CpuIndex, register: Register, value: u64) -> Option<Option<CpuIndex>> {
        match register {
            Register::Status if value == SR_PENDING => {
                self.acknowledge(cpu)?;
                Some(None)
            }
            Register::RequestLocal | Register::RequestGlobal => {
                let target = self.immediate_target(cpu, register, value)?;
                Some(self.raise(target).then_some(target))
            }
            _ => None,
        }
    }

    /// Clear `cpu`'s IPI_SR: its FIQ from the fast IPIs goes.
    ///
    /// A read-modify-write, not a store: a send whose `fetch_or` found the
    /// word still set (and so raised and woke nothing) is then ordered
    /// before the clear, which synchronizes with it, so the CPU's reads
    /// after the acknowledgement (its handler's mailbox) see what the
    /// sender wrote before the send. A plain store could sit in this host
    /// core's store buffer while those reads ran, and lose that IPI. The
    /// word holds PENDING alone, so the clear takes nothing else.
    pub fn acknowledge(&self, cpu: CpuIndex) -> Option<()> {
        self.words.get(cpu)?.pending.swap(0, SeqCst);
        Some(())
    }

    /// `cpu`'s IPI_SR.
    pub fn pending(&self, cpu: CpuIndex) -> u64 {
        self.words
            .get(cpu)
            .map_or(0, |word| word.pending.load(Acquire))
    }

    /// Where `cpu`'s IPI_SR lies, for the board's life.
    pub fn storage(&self, cpu: CpuIndex) -> Option<u64> {
        Some(self.words.get(cpu)?.pending.as_ptr() as u64)
    }

    /// Set `cpu`'s IPI_SR: whether that raised its FIQ.
    fn raise(&self, cpu: CpuIndex) -> bool {
        self.words[cpu].pending.fetch_or(SR_PENDING, AcqRel) == 0
    }
}

/// Fast-IPI state of every CPU. `cpus[i]` is the affinity of logical CPU `i`.
pub struct FastIpi {
    signals: Arc<Signals>,
    /// Counter value at which each CPU's deferred IPI fires.
    deferred: Vec<Option<u64>>,
    /// The global IPI_CR value.
    countdown: Option<u64>,
    /// CPUs whose FIQ a locked access or advance raised since
    /// [`Self::take_raised`] took theirs: bit `cpu % 64` of word `cpu / 64`,
    /// for every CPU of the machine.
    raised: Vec<u64>,
}
impl FastIpi {
    pub fn new(cpus: Vec<Affinity>) -> Self {
        let words = cpus.iter().map(|_| Word::default()).collect();
        let deferred = cpus.iter().map(|_| None).collect();
        let raised = vec![0; cpus.len().div_ceil(64)];
        Self {
            signals: Arc::new(Signals { cpus, words }),
            deferred,
            countdown: None,
            raised,
        }
    }
    /// What every CPU reaches without the lock.
    pub fn signals(&self) -> Arc<Signals> {
        Arc::clone(&self.signals)
    }
    /// `cpu`'s FIQ from the fast IPIs: its IPI_SR is set.
    pub fn fiq(&self, cpu: CpuIndex) -> bool {
        self.signals.pending(cpu) != 0
    }
    /// Whether a locked access or advance raised `cpu`'s FIQ since the
    /// last call for it.
    pub fn take_raised(&mut self, cpu: CpuIndex) -> bool {
        let bit = 1u64 << (cpu % 64);
        self.raised.get_mut(cpu / 64).is_some_and(|word| {
            let raised = *word & bit != 0;
            *word &= !bit;
            raised
        })
    }
    fn arm(&mut self, cpu: CpuIndex, deadline: Option<u64>) {
        self.deferred[cpu] = deadline;
        self.signals.words[cpu]
            .armed
            .store(deadline.is_some(), Release);
    }
    fn raise(&mut self, cpu: CpuIndex) {
        if self.signals.raise(cpu) {
            self.raised[cpu / 64] |= 1 << (cpu % 64);
        }
    }
    /// One MRS or MSR by `cpu` at counter value `now`. Returns the value read,
    /// or 0 for a write.
    pub fn access(
        &mut self,
        cpu: CpuIndex,
        register: Register,
        kind: AccessKind,
        now: u64,
    ) -> Result<u64, IpiError> {
        let sender = *self
            .signals
            .cpus
            .get(cpu)
            .ok_or(IpiError::UnknownCpu(cpu))?;
        let unsupported = |reason| Err(IpiError::Unsupported(register, reason));
        match (register, kind) {
            (Register::RequestLocal | Register::RequestGlobal, AccessKind::Read) => {
                unsupported("IPI request registers are write-only")
            }
            (Register::RequestLocal | Register::RequestGlobal, AccessKind::Write { value }) => {
                let global = register == Register::RequestGlobal;
                let fields = RR_CPU | RR_TYPE | if global { RR_CLUSTER } else { 0 };
                if value & !fields != 0 {
                    return unsupported("IPI request reserved field is not modeled");
                }
                let target = Affinity {
                    cluster: if global {
                        (value >> RR_CLUSTER_SHIFT) as u8
                    } else {
                        sender.cluster
                    },
                    cpu: (value & RR_CPU) as u8,
                };
                let Some(target) = self
                    .signals
                    .cpus
                    .iter()
                    .position(|&affinity| affinity == target)
                else {
                    return unsupported("IPI request names no CPU of this machine");
                };
                match value >> RR_TYPE_SHIFT & 0b11 {
                    0 => {
                        self.arm(target, None);
                        self.raise(target);
                    }
                    1 => self.arm(target, None),
                    2 => {
                        let Some(countdown) = self.countdown else {
                            return unsupported("deferred IPI sent before IPI_CR was written");
                        };
                        let deadline =
                            self.deferred[target].unwrap_or(now.saturating_add(countdown));
                        self.arm(target, Some(deadline));
                    }
                    _ => return unsupported("no-wake IPIs are not modeled"),
                }
                Ok(0)
            }
            (Register::Status, AccessKind::Read) => Ok(self.signals.pending(cpu)),
            (Register::Status, AccessKind::Write { value }) => {
                if value & !SR_PENDING != 0 {
                    return unsupported("IPI_SR fields other than PENDING are not modeled");
                }
                if value & SR_PENDING != 0 {
                    self.signals.acknowledge(cpu);
                }
                Ok(0)
            }
            (Register::Countdown, AccessKind::Read) => self.countdown.ok_or(IpiError::Unsupported(
                register,
                "IPI_CR read before it was written",
            )),
            (Register::Countdown, AccessKind::Write { value }) => {
                if value & !CR_COUNTDOWN != 0 {
                    return unsupported("IPI_CR has a 16-bit countdown field");
                }
                self.countdown = Some(value);
                Ok(0)
            }
        }
    }
    /// Fires deferred IPIs due at `now`; returns the next deferred deadline.
    pub fn advance(&mut self, now: u64) -> Option<u64> {
        let mut next: Option<u64> = None;
        for cpu in 0..self.deferred.len() {
            match self.deferred[cpu] {
                Some(deadline) if deadline <= now => {
                    self.arm(cpu, None);
                    self.raise(cpu);
                }
                Some(deadline) => next = Some(next.map_or(deadline, |next| next.min(deadline))),
                None => {}
            }
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::system::registers::Encoding;

    /// T8112: four E-cores in cluster 0, four P-cores in cluster 1.
    fn t8112() -> FastIpi {
        FastIpi::new(
            (0..8)
                .map(|index| Affinity {
                    cluster: index / 4,
                    cpu: index % 4,
                })
                .collect(),
        )
    }
    fn write(ipi: &mut FastIpi, cpu: CpuIndex, register: Register, value: u64, now: u64) {
        ipi.access(cpu, register, AccessKind::Write { value }, now)
            .unwrap();
    }

    /// Linux `aic_ipi_send_fast` (local and global) then `aic_handle_ipi`.
    #[test]
    fn linux_send_and_acknowledge() {
        let mut ipi = t8112();
        write(&mut ipi, 0, Register::RequestLocal, 2, 0);
        assert!(ipi.fiq(2));
        write(&mut ipi, 0, Register::RequestGlobal, 1 << 16 | 3, 0);
        assert!(ipi.fiq(7));
        assert_eq!(ipi.access(7, Register::Status, AccessKind::Read, 0), Ok(1));
        write(&mut ipi, 7, Register::Status, SR_PENDING, 0);
        assert!(!ipi.fiq(7));
        assert_eq!(ipi.access(7, Register::Status, AccessKind::Read, 0), Ok(0));
        // A P-core's local request stays in cluster 1.
        write(&mut ipi, 5, Register::RequestLocal, 0, 0);
        assert!(ipi.fiq(4) && !ipi.fiq(0));
    }

    #[test]
    fn deferred_ipis_fire_after_the_countdown_unless_retracted() {
        let mut ipi = t8112();
        write(&mut ipi, 0, Register::Countdown, 240, 0);
        write(&mut ipi, 0, Register::RequestLocal, 2 << 28 | 1, 100);
        assert!(!ipi.fiq(1));
        assert_eq!(ipi.advance(339), Some(340));
        assert_eq!(ipi.advance(340), None);
        assert!(ipi.fiq(1));
        write(&mut ipi, 1, Register::Status, SR_PENDING, 340);
        write(&mut ipi, 0, Register::RequestLocal, 2 << 28 | 1, 400);
        write(&mut ipi, 0, Register::RequestLocal, 1 << 28 | 1, 401);
        assert_eq!(ipi.advance(1000), None);
        assert!(!ipi.fiq(1));
    }

    /// Immediate requests and acknowledgements complete on the signals
    /// alone, with the same IPI_SR and FIQ as under the lock; a send to a
    /// CPU already pending raises nothing new.
    #[test]
    fn lock_free_sends_and_acknowledgements_match_the_locked_model() {
        let mut ipi = t8112();
        let signals = ipi.signals();
        assert_eq!(signals.send(0, Register::RequestLocal, 2), Some(Some(2)));
        assert!(ipi.fiq(2));
        assert_eq!(ipi.access(2, Register::Status, AccessKind::Read, 0), Ok(1));
        assert_eq!(signals.send(1, Register::RequestLocal, 2), Some(None));
        assert_eq!(
            signals.send(0, Register::RequestGlobal, 1 << 16 | 3),
            Some(Some(7))
        );
        assert_eq!(signals.send(2, Register::Status, SR_PENDING), Some(None));
        assert!(!ipi.fiq(2) && ipi.fiq(7));
        assert_eq!(ipi.access(2, Register::Status, AccessKind::Read, 0), Ok(0));
        // Nothing raised under the lock: the senders woke the targets.
        assert!((0..8).all(|cpu| !ipi.take_raised(cpu)));
        write(&mut ipi, 0, Register::RequestLocal, 1, 0);
        assert!(ipi.take_raised(1));
        assert!((0..8).all(|cpu| !ipi.take_raised(cpu)));
    }

    /// What the signals leave to the lock: refused requests, deferred,
    /// retracted and no-wake ones, other registers, IPI_SR values other than
    /// PENDING, and an immediate request to a CPU with a deferred IPI armed
    /// (which it clears).
    #[test]
    fn requests_that_touch_deferred_ipis_or_are_refused_take_the_lock() {
        let mut ipi = t8112();
        let signals = ipi.signals();
        for (register, value) in [
            (Register::RequestLocal, 1 << 16),
            (Register::RequestLocal, 1 << 8),
            (Register::RequestGlobal, 2 << 16),
            (Register::RequestLocal, 1 << 28 | 1),
            (Register::RequestLocal, 2 << 28 | 1),
            (Register::RequestLocal, 3 << 28 | 1),
            (Register::Status, 0),
            (Register::Status, 2),
            (Register::Countdown, 5),
        ] {
            assert_eq!(
                signals.send(0, register, value),
                None,
                "{register:?} {value:#x}"
            );
        }
        write(&mut ipi, 0, Register::Countdown, 240, 0);
        write(&mut ipi, 0, Register::RequestLocal, 2 << 28 | 1, 100);
        assert_eq!(signals.send(0, Register::RequestLocal, 1), None);
        // Under the lock the immediate request subsumes the deferred one,
        // which then never fires.
        write(&mut ipi, 0, Register::RequestLocal, 1, 101);
        assert!(ipi.fiq(1));
        write(&mut ipi, 1, Register::Status, SR_PENDING, 102);
        assert_eq!(ipi.advance(1000), None);
        assert!(!ipi.fiq(1));
        // Disarmed, the next immediate request goes without the lock.
        assert_eq!(signals.send(0, Register::RequestLocal, 1), Some(Some(1)));
        // A deferred IPI that fires sets IPI_SR and reports its CPU.
        signals.acknowledge(1);
        ipi.take_raised(1);
        write(&mut ipi, 0, Register::RequestLocal, 2 << 28 | 1, 2000);
        assert_eq!(ipi.advance(2240), None);
        assert!(ipi.fiq(1));
        assert!(ipi.take_raised(1));
    }

    /// Every CPU's raise is kept, however many the machine has: a deferred
    /// IPI that fires for CPU 64 or above wakes its PE as for any other.
    #[test]
    fn deferred_ipis_raise_every_cpu_of_a_large_machine() {
        let mut ipi = FastIpi::new(
            (0..130)
                .map(|index: u8| Affinity {
                    cluster: index / 16,
                    cpu: index % 16,
                })
                .collect(),
        );
        write(&mut ipi, 0, Register::Countdown, 10, 0);
        for cpu in [63, 64, 129] {
            let target = cpu as u64;
            write(
                &mut ipi,
                0,
                Register::RequestGlobal,
                (2 << 28) | ((target / 16) << 16) | (target % 16),
                0,
            );
        }
        assert_eq!(ipi.advance(10), None);
        for cpu in 0..130 {
            let fired = [63, 64, 129].contains(&cpu);
            assert_eq!(ipi.fiq(cpu), fired, "CPU {cpu}");
            assert_eq!(ipi.take_raised(cpu), fired, "CPU {cpu}");
            assert!(!ipi.take_raised(cpu), "taken once: CPU {cpu}");
        }
        assert!(!ipi.take_raised(130), "no such CPU");
    }

    #[test]
    fn decodes_encodings_and_refuses_unmodeled_requests() {
        assert_eq!(
            Register::decode(Encoding::new(3, 5, 15, 1, 1)),
            Some(Register::Status)
        );
        assert_eq!(Register::decode(Encoding::new(3, 5, 15, 1, 3)), None);
        let mut ipi = t8112();
        let mut write = |register, value| ipi.access(0, register, AccessKind::Write { value }, 0);
        assert!(write(Register::RequestLocal, 3 << 28).is_err(), "no-wake");
        assert!(
            write(Register::RequestLocal, 1 << 16).is_err(),
            "cluster in LOCAL"
        );
        assert!(
            write(Register::RequestGlobal, 2 << 16).is_err(),
            "no cluster 2"
        );
        assert!(write(Register::Status, 2).is_err());
        assert!(
            write(Register::RequestLocal, 2 << 28 | 1).is_err(),
            "IPI_CR unset"
        );
        assert!(write(Register::Countdown, 0x1_0000).is_err());
        assert!(
            ipi.access(0, Register::RequestLocal, AccessKind::Read, 0)
                .is_err()
        );
        assert_eq!(
            ipi.access(8, Register::Status, AccessKind::Read, 0),
            Err(IpiError::UnknownCpu(8))
        );
    }

    /// No lost IPI: an acknowledgement racing a send that finds IPI_SR still
    /// set (so raises and wakes nothing) leaves the receiver, which reads its
    /// mailbox after the acknowledgement, seeing the sender's mailbox write.
    /// The store-buffer litmus test with the sender's locked RMW on one side:
    /// a plain store on the other lets the receiver read the mailbox before
    /// its clear is visible. Rounds run for at most 1.5 s.
    #[test]
    fn an_acknowledgement_racing_a_send_never_loses_it() {
        use std::{
            thread,
            time::{Duration, Instant},
        };
        let ipi = t8112();
        let signals = ipi.signals();
        let mailbox = Arc::new(AtomicU64::new(0));
        let arrived = Arc::new(AtomicU64::new(0));
        let raised = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        // Both threads arrive at barrier `n` before either goes on.
        let meet = |arrived: &AtomicU64, n: u64| {
            arrived.fetch_add(1, SeqCst);
            while arrived.load(SeqCst) < 2 * n {
                core::hint::spin_loop();
            }
        };
        signals.words[1].pending.store(SR_PENDING, SeqCst);
        let sender = {
            let (signals, mailbox, arrived, raised, stop) = (
                Arc::clone(&signals),
                Arc::clone(&mailbox),
                Arc::clone(&arrived),
                Arc::clone(&raised),
                Arc::clone(&stop),
            );
            thread::spawn(move || {
                for round in 1u64.. {
                    meet(&arrived, 2 * round - 1);
                    if stop.load(SeqCst) {
                        return;
                    }
                    // What a lock-free send does once it has decoded its
                    // target ([`Signals::send`]).
                    mailbox.store(round, SeqCst);
                    raised.store(signals.raise(1), SeqCst);
                    meet(&arrived, 2 * round);
                }
            })
        };
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut lost = 0u64;
        let mut rounds = 0u64;
        for round in 1u64.. {
            let last = Instant::now() >= deadline || lost != 0;
            if last {
                stop.store(true, SeqCst);
            }
            meet(&arrived, 2 * round - 1);
            if last {
                break;
            }
            // A varying delay lines the acknowledgement up with the send
            // in some rounds whatever the two paths cost in this build.
            for _ in 0..round % 251 {
                core::hint::spin_loop();
            }
            signals.acknowledge(1);
            let seen = mailbox.load(SeqCst);
            meet(&arrived, 2 * round);
            // Neither the receiver saw the mail nor is its FIQ pending
            // again for it: the IPI is gone.
            if seen != round && !raised.load(SeqCst) && signals.words[1].pending.load(SeqCst) == 0 {
                lost += 1;
            }
            signals.words[1].pending.store(SR_PENDING, SeqCst);
            rounds = round;
        }
        sender.join().unwrap();
        assert_eq!(lost, 0, "IPIs lost in {rounds} rounds");
    }
}
