//! Apple fast-IPI register encodings, shared by architectural admission and
//! the board's interrupt model. Linux irq-apple-aic and m1n1 cpu_regs name
//! the four selectors; countdown and request effects belong to the model.
use stela_compiler::aarch64::system::registers::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    RequestLocal,
    RequestGlobal,
    Status,
    Countdown,
}
impl Register {
    pub const fn encoding(self) -> Encoding {
        match self {
            Self::RequestLocal => Encoding::new(3, 5, 15, 0, 0),
            Self::RequestGlobal => Encoding::new(3, 5, 15, 0, 1),
            Self::Status => Encoding::new(3, 5, 15, 1, 1),
            Self::Countdown => Encoding::new(3, 5, 15, 3, 1),
        }
    }
    pub const fn decode(encoding: Encoding) -> Option<Self> {
        match (
            encoding.op0(),
            encoding.op1(),
            encoding.crn(),
            encoding.crm(),
            encoding.op2(),
        ) {
            (3, 5, 15, 0, 0) => Some(Self::RequestLocal),
            (3, 5, 15, 0, 1) => Some(Self::RequestGlobal),
            (3, 5, 15, 1, 1) => Some(Self::Status),
            (3, 5, 15, 3, 1) => Some(Self::Countdown),
            _ => None,
        }
    }
}

/// One CPU's fast-IPI word as the board model holds it: its affinity
/// (MPIDR Aff1, Aff0) and, for the board's life, the address of its
/// IPI_SR (`u64`, bit 0 PENDING) and of its deferred-IPI flag (`u8`,
/// nonzero while a deferred IPI is armed for it). CPU `n` is PE `n`
/// ([`super::Devices::fast_ipi_words`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Word {
    pub cluster: u8,
    pub cpu: u8,
    pub status: u64,
    pub armed: u64,
}

/// What native code needs to complete an immediate request to one CPU
/// ([`Table`]): addresses fixed for the board's life, 0 throughout for a
/// CPU the board does not have or that no PE runs.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Target {
    /// The CPU's IPI_SR (`u64`; bit 0 PENDING).
    pub status: u64,
    /// Its deferred-IPI flag (`u8`; nonzero while armed).
    pub armed: u64,
    /// Its PE's line-change counter (`u64`), which the PE compares with
    /// the count it last saw before it halts and at every look.
    pub lines: u64,
    /// Its PE's native chaining interruption epoch (`u64`), which chained
    /// native code checks to leave its run.
    pub interrupt: u64,
    /// Its PE's halted flag (`u8`; nonzero while it sleeps in its host
    /// halt, set before its last look at `lines`).
    pub sleeping: u64,
    /// The PE number.
    pub pe: u64,
}

// Native code finds a target's words where the compiler's thunks read them.
const _: () = {
    use core::mem::{offset_of, size_of};
    use stela_compiler::x86_64::register_read as native;
    assert!(size_of::<Target>() == native::FAST_IPI_TARGET_BYTES);
    assert!(offset_of!(Target, status) == native::FAST_IPI_TARGET_STATUS);
    assert!(offset_of!(Target, armed) == native::FAST_IPI_TARGET_ARMED);
    assert!(offset_of!(Target, lines) == native::FAST_IPI_TARGET_LINES);
    assert!(offset_of!(Target, interrupt) == native::FAST_IPI_TARGET_INTERRUPT);
    assert!(offset_of!(Target, sleeping) == native::FAST_IPI_TARGET_SLEEPING);
    assert!(offset_of!(Target, pe) == native::FAST_IPI_TARGET_PE);
};

/// What an immediate request ([`Table::send`]) came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// Not completed, nothing changed: the engine runs the MSR
    /// ([`super::Devices::system_register`]).
    Exit,
    /// Completed.
    Done,
    /// Completed, and PE `pe` was found halted: the engine must wake it
    /// ([`super::Devices::wake_signalled`]) and must not run the MSR
    /// again, which would find the word set and wake nobody.
    Wake(usize),
}

/// A frozen per-board table from a fast IPI's target (cluster, CPU) to
/// what native code needs to complete an immediate request to it without
/// the devices' lock ([`super::Devices::fast_ipi_table`]). Entries are laid
/// out row-major from [`Self::base`]: the entry of `(cluster, cpu)` is at
/// `base + (cluster * cpus + cpu) * size_of::<Target>()` when
/// `cluster < clusters` and `cpu < cpus`; outside those bounds, or where
/// `status` is 0, the CPU is absent and the request exits.
///
/// [`Self::send`] is the reference a native thunk follows, step for step,
/// with the same orderings (on x86-64 each read-modify-write is a `lock`
/// instruction and each load a plain `mov`):
///
/// 1. Decode: exit unless every set bit of the value is in CPU [7:0],
///    TYPE [29:28] and, for IPI_RR_GLOBAL, CLUSTER [23:16], and TYPE is 0.
///    IPI_RR_LOCAL takes the sender's cluster ([`Self::cluster_of`]).
/// 2. Exit if the target is absent or is the sender (its own FIQ is taken
///    at the exit).
/// 3. Load `armed` (Acquire): exit if nonzero.
/// 4. Atomically OR 1 into `status` (SeqCst), keeping the old value: if it
///    was already set the request is done (that FIQ is pending already).
/// 5. Add 1 to `lines` (SeqCst).
/// 6. Add 1 to `interrupt` (Release) unless it is `u64::MAX`, which stays.
/// 7. Load `sleeping` (SeqCst): nonzero, the target must be woken
///    ([`Sent::Wake`]); else done.
///
/// Steps 5 and 7 pair with the halt (`Hub::sleep`), which stores its
/// `sleeping` and then loads `lines`: either the target sees the new count
/// and does not halt, or the sender sees it halted and has it woken.
/// Step 3 against an arm under the devices' lock orders the request
/// before the arm, as the model's own lock-free send does.
pub struct Table {
    targets: alloc::boxed::Box<[Target]>,
    clusters: u32,
    cpus: u32,
    /// Each PE's own cluster, for IPI_RR_LOCAL.
    clusters_of: alloc::boxed::Box<[u8]>,
}

const RR_CPU: u64 = 0xff;
const RR_CLUSTER_SHIFT: u32 = 16;
const RR_CLUSTER: u64 = 0xff << RR_CLUSTER_SHIFT;
const RR_TYPE: u64 = 0b11 << 28;

impl Table {
    /// The table for `words` (CPU `n` is PE `n`), of which PEs below `pes`
    /// run, each with its `(lines, interrupt, sleeping)` addresses from
    /// `pe`.
    pub fn new(words: &[Word], pes: usize, mut pe: impl FnMut(usize) -> (u64, u64, u64)) -> Self {
        let clusters = words
            .iter()
            .map(|w| u32::from(w.cluster) + 1)
            .max()
            .unwrap_or(0);
        let cpus = words
            .iter()
            .map(|w| u32::from(w.cpu) + 1)
            .max()
            .unwrap_or(0);
        let mut targets =
            alloc::vec![Target::default(); clusters as usize * cpus as usize].into_boxed_slice();
        for (index, word) in words.iter().enumerate().take(pes) {
            let (lines, interrupt, sleeping) = pe(index);
            targets[word.cluster as usize * cpus as usize + word.cpu as usize] = Target {
                status: word.status,
                armed: word.armed,
                lines,
                interrupt,
                sleeping,
                pe: index as u64,
            };
        }
        Self {
            targets,
            clusters,
            cpus,
            clusters_of: words.iter().take(pes).map(|w| w.cluster).collect(),
        }
    }

    /// The address of the first entry, for the board's life.
    pub fn base(&self) -> u64 {
        self.targets.as_ptr() as u64
    }
    /// The clusters the table covers (one past the highest).
    pub fn clusters(&self) -> u32 {
        self.clusters
    }
    /// The CPUs a cluster's row covers (one past the highest).
    pub fn cpus(&self) -> u32 {
        self.cpus
    }
    /// PE `pe`'s own cluster (MPIDR Aff1), which IPI_RR_LOCAL names.
    pub fn cluster_of(&self, pe: usize) -> Option<u8> {
        self.clusters_of.get(pe).copied()
    }
    /// The entry of `(cluster, cpu)`, `None` where absent.
    pub fn target(&self, cluster: u8, cpu: u8) -> Option<&Target> {
        let (cluster, cpu) = (u32::from(cluster), u32::from(cpu));
        if cluster >= self.clusters || cpu >= self.cpus {
            return None;
        }
        let target = &self.targets[(cluster * self.cpus + cpu) as usize];
        (target.status != 0).then_some(target)
    }

    /// An immediate request `value` to `register` by PE `sender`, completed
    /// by the contract above: the reference for native thunks.
    pub fn send(&self, sender: usize, register: Register, value: u64) -> Sent {
        use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
        let global = match register {
            Register::RequestLocal => false,
            Register::RequestGlobal => true,
            _ => return Sent::Exit,
        };
        let fields = RR_CPU | RR_TYPE | if global { RR_CLUSTER } else { 0 };
        if value & !fields != 0 || value & RR_TYPE != 0 {
            return Sent::Exit;
        }
        let cluster = if global {
            (value >> RR_CLUSTER_SHIFT) as u8
        } else {
            match self.cluster_of(sender) {
                Some(cluster) => cluster,
                None => return Sent::Exit,
            }
        };
        let Some(target) = self.target(cluster, (value & RR_CPU) as u8) else {
            return Sent::Exit;
        };
        if target.pe == sender as u64 {
            return Sent::Exit;
        }
        // SAFETY: a table's addresses are the board's atomics, for its life
        // (`Devices::fast_ipi_table`), each naturally aligned.
        let (status, armed, lines, interrupt, sleeping) = unsafe {
            (
                AtomicU64::from_ptr(target.status as *mut u64),
                AtomicU8::from_ptr(target.armed as *mut u8),
                AtomicU64::from_ptr(target.lines as *mut u64),
                AtomicU64::from_ptr(target.interrupt as *mut u64),
                AtomicU8::from_ptr(target.sleeping as *mut u8),
            )
        };
        if armed.load(Ordering::Acquire) != 0 {
            return Sent::Exit;
        }
        if status.fetch_or(1, Ordering::SeqCst) != 0 {
            return Sent::Done;
        }
        lines.fetch_add(1, Ordering::SeqCst);
        let _ = interrupt.try_update(Ordering::Release, Ordering::Relaxed, |epoch| {
            epoch.checked_add(1)
        });
        if sleeping.load(Ordering::SeqCst) != 0 {
            Sent::Wake(target.pe as usize)
        } else {
            Sent::Done
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_fast_ipi_selectors_round_trip_without_admitting_neighbors() {
        for register in [
            Register::RequestLocal,
            Register::RequestGlobal,
            Register::Status,
            Register::Countdown,
        ] {
            assert_eq!(Register::decode(register.encoding()), Some(register));
        }
        for encoding in [
            Encoding::new(2, 5, 15, 0, 0),
            Encoding::new(3, 4, 15, 0, 0),
            Encoding::new(3, 5, 14, 0, 0),
            Encoding::new(3, 5, 15, 2, 1),
            Encoding::new(3, 5, 15, 3, 0),
            Encoding::new(3, 5, 15, 3, 2),
        ] {
            assert_eq!(Register::decode(encoding), None);
        }
    }

    /// Every outcome of the reference send: done to a running target with
    /// its counters moved once, a pending word left alone, a halted target
    /// to wake, and exits that change nothing.
    #[test]
    fn the_reference_send_follows_its_contract() {
        use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        struct Cpu {
            status: AtomicU64,
            armed: AtomicBool,
            lines: AtomicU64,
            interrupt: AtomicU64,
            sleeping: AtomicBool,
        }
        let cpus: std::vec::Vec<Cpu> = (0..4)
            .map(|_| Cpu {
                status: AtomicU64::new(0),
                armed: AtomicBool::new(false),
                lines: AtomicU64::new(0),
                interrupt: AtomicU64::new(0),
                sleeping: AtomicBool::new(false),
            })
            .collect();
        // Two clusters of two; CPU 3 has no PE.
        let words: std::vec::Vec<Word> = (0..4)
            .map(|n| Word {
                cluster: (n / 2) as u8,
                cpu: (n % 2) as u8,
                status: cpus[n].status.as_ptr() as u64,
                armed: cpus[n].armed.as_ptr() as u64,
            })
            .collect();
        let table = Table::new(&words, 3, |pe| {
            (
                cpus[pe].lines.as_ptr() as u64,
                cpus[pe].interrupt.as_ptr() as u64,
                cpus[pe].sleeping.as_ptr() as u64,
            )
        });
        assert_eq!((table.clusters(), table.cpus()), (2, 2));
        assert!(table.target(1, 1).is_none() && table.target(2, 0).is_none());
        let counts = |n: usize| {
            (
                cpus[n].status.load(Ordering::SeqCst),
                cpus[n].lines.load(Ordering::SeqCst),
                cpus[n].interrupt.load(Ordering::SeqCst),
            )
        };
        // Running target in the sender's cluster.
        assert_eq!(table.send(0, Register::RequestLocal, 1), Sent::Done);
        assert_eq!(counts(1), (1, 1, 1));
        // Already pending: done, nothing moves.
        assert_eq!(table.send(0, Register::RequestLocal, 1), Sent::Done);
        assert_eq!(counts(1), (1, 1, 1));
        // A halted target in another cluster is to be woken.
        cpus[2].sleeping.store(true, Ordering::SeqCst);
        assert_eq!(
            table.send(0, Register::RequestGlobal, 1 << 16),
            Sent::Wake(2)
        );
        assert_eq!(counts(2), (1, 1, 1));
        // Exits that change nothing: self, armed, absent, other types,
        // stray bits, a cluster field in a local request, other registers.
        cpus[0].armed.store(true, Ordering::SeqCst);
        for (sender, register, value) in [
            (1, Register::RequestLocal, 1),
            (1, Register::RequestLocal, 0),
            (0, Register::RequestGlobal, 1 << 16 | 1),
            (0, Register::RequestGlobal, 3 << 16),
            (0, Register::RequestLocal, 2 << 28 | 1),
            (0, Register::RequestLocal, 1 << 8 | 1),
            (0, Register::RequestLocal, 1 << 16 | 1),
            (0, Register::Status, 1),
        ] {
            let before: std::vec::Vec<_> = (0..4).map(counts).collect();
            assert_eq!(
                table.send(sender, register, value),
                Sent::Exit,
                "{value:#x}"
            );
            assert_eq!((0..4).map(counts).collect::<std::vec::Vec<_>>(), before);
        }
        // A saturated interruption epoch stays.
        cpus[1].status.store(0, Ordering::SeqCst);
        cpus[1].interrupt.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(table.send(0, Register::RequestLocal, 1), Sent::Done);
        assert_eq!(counts(1), (1, 2, u64::MAX));
    }
}
