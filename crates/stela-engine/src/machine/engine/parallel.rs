//! Parallel execution: every PE runs its own [`Machine`] on its own host core.
//!
//! The machines share guest RAM, which native code reaches directly, the
//! board's devices through [`SharedDevices`], and a [`Hub`] that carries what
//! one PE does to the others: a start, an event (SEV), and TLB and
//! instruction-cache maintenance broadcast to the Inner Shareable domain. A
//! PE that broadcasts maintenance waits until every other running PE has
//! applied it, as the DSB after it would on hardware. As on hardware, it
//! neither wakes nor waits for a PE that sleeps, which applies it before it
//! runs again; and a running PE leaves native code at its next chained
//! transfer to apply it ([`Hub::interrupt`]).
//!
//! A machine holds its own PE as on a board of one: the others are
//! [`Peer::Remote`](super::processors::Peer::Remote). The PEs of one physical
//! cluster still share its CTRR and cluster-scoped implementation-defined
//! registers, which the hub keeps per cluster.
//!
//! A device access that needs canonical memory (CPU PMGR writes and the
//! memory controller's drains), which only the home machine holds, goes
//! there from another PE's machine ([`Machine::forward_read`]): the home
//! machine stops every other running PE, as that access requires, serves
//! it for the PE that made it, and sends the answer back.
//!
//! Exclusives pass by value: a store-exclusive succeeds when guest RAM still
//! holds what the exclusive load read, compared and stored in one host
//! compare-and-exchange ([`super::Host::compare_exchange_ram`]). A write of
//! the same value by another PE between them goes unseen, as with LSE CAS.
use super::chain_control;
use super::{
    CanonicalDeviceMemory, CanonicalDeviceWrite, ConsumedPair, ConsumedScalar, ConsumedWrite,
    DeviceError, DeviceReadShape, Devices, Host, Machine, RequirementKind, Reset, Start, Step,
    clock::Clock, processors::Peer,
};
use crate::machine::{
    ctrr,
    mmu::{self, tlbi},
    registers::Lines,
    shared::Shared,
    system::Broadcast,
};
use crate::platform::sync::Mutex;
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use stela_compiler::aarch64::system::registers::Encoding;

mod observation;
pub use observation::{MaterializedSource, SourceObservation, SourcePhase};
mod profile;
pub use profile::{BroadcastCounts, BroadcastKind, BroadcastProfile};

/// Brings the host core that runs a PE out of native code, or out of a wait,
/// to read its mail. Delivery is a host interrupt; a kick of a core already
/// in the engine costs it one return through its interrupt handler.
pub trait Kick: Send + Sync {
    fn kick(&self, pe: usize);
}

/// Maintenance one PE broadcasts to the others.
#[derive(Debug, Clone, Copy)]
pub(super) enum Maintenance {
    /// A TLBI's entries, which each PE reaches from its own context.
    Tlb(tlbi::Scope),
    /// IC IVAU of the page holding this physical address, or IC IALLUIS.
    Code(Option<u64>),
    /// A CPU power change, which pauses or resumes the PE it reaches and
    /// which every machine's record of the board's CPU power takes.
    Power(super::ProcessorChange),
}

/// What other PEs left for one PE.
#[derive(Debug, Default)]
pub(super) struct Mail {
    /// A device started the PE at this address.
    pub start: Option<u64>,
    /// SEV.
    pub event: bool,
    pub maintenance: Vec<Maintenance>,
    /// The serial of the last maintenance in `maintenance`.
    pub serial: u64,
}

struct Inbox {
    /// Mail is waiting.
    pending: AtomicBool,
    /// Its machine runs and reads its mail; a broadcast waits only for these.
    live: AtomicBool,
    /// Its host core halts until an interrupt: only then does mail kick it.
    /// A running core reads its mail at its next return to the engine,
    /// which [`Hub::interrupt`] brings forward to its next chained transfer.
    sleeping: AtomicBool,
    /// Stable native chaining allocation, kept even between PE owners.
    chain: Arc<chain_control::Storage>,
    /// Unique owner epoch; zero is free and u64::MAX is detaching.
    owner: AtomicU64,
    /// It runs no guest code until the world it was stopped for restarts,
    /// or while it waits in the engine for other PEs.
    parked: AtomicBool,
    /// The serial of the last maintenance posted and of the last applied.
    posted: AtomicU64,
    applied: AtomicU64,
    /// Device lines changed since the machine last read them.
    lines: AtomicU64,
    /// Its machine's counts, as it last published them ([`Hub::publish`]).
    counts: Mutex<Counts>,
    source: observation::Slot,
    broadcasts: profile::Slot,
    mail: Mutex<Mail>,
}

/// What one PE's machine has done, for reports on how the PEs run together:
/// work, compilation and the time spent idle or waiting on other PEs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub blocks: u64,
    pub retired: u64,
    /// Blocks it compiled, and blocks another PE compiled that it installed.
    pub compiled: u64,
    pub shared: u64,
    pub compile_ticks: u64,
    /// Counter ticks its host core halted or spun on a monitored granule
    /// ([`super::Statistics::sleep_ticks`], `spin_ticks`) and spent waiting
    /// on other PEs ([`super::Statistics::sync_ticks`]), and its waits.
    pub sleep_ticks: u64,
    pub spin_ticks: u64,
    pub sync_ticks: u64,
    pub waits: u64,
    pub broadcasts: u64,
    pub forwards: u64,
    pub exceptions: u64,
    pub device_accesses: u64,
}

/// The cluster state its powered PEs share.
#[derive(Clone)]
pub(super) struct Cluster {
    pub ctrr: Shared<ctrr::Cluster>,
    pub impdef: Shared<BTreeMap<u16, u64>>,
}

/// The mailboxes of every PE, by PE number.
pub struct Hub {
    inboxes: Box<[Inbox]>,
    kick: Box<dyn Kick>,
    /// Cluster state by physical cluster (MPIDR_EL1 Aff1).
    clusters: Mutex<BTreeMap<u64, Cluster>>,
    /// The home machine's counter as the board went parallel, which every
    /// other machine's starts from: each then follows the host's counter.
    clock: Mutex<Option<Clock>>,
    /// The home machine's PE.
    home: AtomicUsize,
    home_owner: AtomicU64,
    next_owner: AtomicU64,
    /// One PE's forwarded device access at a time, and that one.
    forwarding: AtomicBool,
    requested: AtomicBool,
    request: Mutex<Option<Request>>,
    /// Every running PE but the home one and the requester parks.
    stopped: AtomicBool,
    /// A device left bytes for the host to feed or drain
    /// ([`Hub::request_service`]).
    service: AtomicBool,
    source_observations: AtomicBool,
}

/// A device access that only the home machine's canonical memory serves.
#[derive(Debug, Clone, Copy)]
pub(super) enum Forwarded {
    Read {
        physical: u64,
        shape: DeviceReadShape,
    },
    Write {
        physical: u64,
        bytes: u8,
        value: u64,
    },
}

/// The home machine's answer to a [`Forwarded`] access.
#[derive(Debug, Clone)]
pub(super) enum Answer {
    Read(Result<ConsumedPair, DeviceError>),
    Write(Result<(), DeviceError>),
}

struct Request {
    pe: usize,
    access: Forwarded,
    answer: Option<Answer>,
}

impl Hub {
    pub fn new(pes: usize, kick: impl Kick + 'static) -> Arc<Self> {
        Arc::new(Self {
            inboxes: (0..pes)
                .map(|_| Inbox {
                    pending: AtomicBool::new(false),
                    live: AtomicBool::new(false),
                    sleeping: AtomicBool::new(false),
                    chain: chain_control::Storage::new(),
                    owner: AtomicU64::new(0),
                    parked: AtomicBool::new(false),
                    posted: AtomicU64::new(0),
                    applied: AtomicU64::new(0),
                    lines: AtomicU64::new(0),
                    counts: Mutex::new(Counts::default()),
                    source: observation::Slot::default(),
                    broadcasts: profile::Slot::default(),
                    mail: Mutex::new(Mail::default()),
                })
                .collect(),
            kick: Box::new(kick),
            clusters: Mutex::new(BTreeMap::new()),
            clock: Mutex::new(None),
            home: AtomicUsize::new(0),
            home_owner: AtomicU64::new(0),
            next_owner: AtomicU64::new(1),
            forwarding: AtomicBool::new(false),
            requested: AtomicBool::new(false),
            request: Mutex::new(None),
            stopped: AtomicBool::new(false),
            service: AtomicBool::new(false),
            source_observations: AtomicBool::new(false),
        })
    }

    pub fn pes(&self) -> usize {
        self.inboxes.len()
    }

    /// Enable optional owner observations. This changes no guest, mailbox,
    /// retirement or worker-admission state; ordinary boots leave it off.
    pub fn set_source_observations(&self, enabled: bool) {
        self.source_observations.store(enabled, Ordering::Release);
    }

    pub fn source_observations_enabled(&self) -> bool {
        self.source_observations.load(Ordering::Acquire)
    }

    /// Last materialized state copied by this PE's own Machine. None means
    /// disabled, unpublished, out of range, or no stable copy in three tries.
    /// A returned copy can already be stale and is no quiescence receipt.
    pub fn source_observation(&self, pe: usize) -> Option<SourceObservation> {
        if !self.source_observations_enabled() {
            return None;
        }
        self.inboxes.get(pe)?.source.read()
    }

    /// Bounded kept broadcast counters, enabled with owner observations.
    /// These may already be stale and never authorize native reclamation.
    pub fn broadcast_profile(&self, pe: usize) -> Option<BroadcastProfile> {
        if !self.source_observations_enabled() {
            return None;
        }
        self.inboxes.get(pe)?.broadcasts.read()
    }

    fn post(&self, pe: usize, write: impl FnOnce(&mut Mail)) {
        let inbox = &self.inboxes[pe];
        write(&mut inbox.mail.lock().unwrap_or_else(|e| e.into_inner()));
        inbox.pending.store(true, Ordering::SeqCst);
        self.interrupt(pe);
    }

    /// Publish interruption after its source; every next chain gate compares
    /// it with the owner's pre-drain snapshot, independently of budget resets.
    /// An already-passed gate can perform at most one further transfer.
    fn interrupt(&self, pe: usize) {
        self.inboxes[pe].chain.notify();
    }

    /// Kick PE `pe`'s core if it halts. Ordered after the store that tells
    /// it why, against its own store of `sleeping` before it looks
    /// ([`Self::sleep`]): one of them sees the other's.
    fn wake(&self, pe: usize) {
        if self.inboxes[pe].sleeping.load(Ordering::SeqCst) {
            self.kick.kick(pe);
        }
    }

    /// Halt PE `pe`'s core with `halt` unless mail or a line change it has
    /// not seen since `epoch` is already there.
    fn sleep(&self, pe: usize, epoch: u64, halt: impl FnOnce()) {
        let inbox = &self.inboxes[pe];
        inbox.sleeping.store(true, Ordering::SeqCst);
        if !inbox.pending.load(Ordering::SeqCst)
            && inbox.lines.load(Ordering::SeqCst) == epoch
            && !self.service.load(Ordering::SeqCst)
        {
            halt();
        }
        // Ordered before its look at its mail, against a broadcast's look
        // at `sleeping` ([`Self::applied`]).
        inbox.sleeping.store(false, Ordering::SeqCst);
    }

    /// A device left bytes for the host to feed or drain: the host's service
    /// is due. The first PE that sleeps wakes to serve it, which its idle
    /// core can without holding up any guest code; with none asleep, the
    /// next PE to wait takes it. Ordered against [`Self::sleep`]'s store of
    /// `sleeping` as [`Self::wake`] is.
    fn request_service(&self) {
        if self.service.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(pe) =
            (0..self.pes()).find(|&pe| self.inboxes[pe].sleeping.load(Ordering::SeqCst))
        {
            self.kick.kick(pe);
        }
    }

    /// Whether the host's service is due with no PE asleep to wake for it:
    /// every PE runs, and only one that waits would take it.
    pub fn service_unclaimed(&self) -> bool {
        self.service.load(Ordering::SeqCst)
            && !self
                .inboxes
                .iter()
                .any(|inbox| inbox.sleeping.load(Ordering::SeqCst))
    }

    /// Whether the host's service is due; once for each request.
    fn take_service(&self) -> bool {
        self.service.load(Ordering::Relaxed) && self.service.swap(false, Ordering::AcqRel)
    }

    /// Wait, halting with `halt`, until a device starts PE `pe`, which has
    /// no machine yet; the start's address.
    pub fn first_start(&self, pe: usize, mut halt: impl FnMut()) -> u64 {
        loop {
            if let Some(Mail {
                start: Some(address),
                ..
            }) = self.take(pe)
            {
                return address;
            }
            let epoch = self.lines_epoch(pe);
            self.sleep(pe, epoch, &mut halt);
        }
    }

    /// Mark PE `pe`'s machine as reading its mail, or no longer.
    pub fn set_live(&self, pe: usize, live: bool) {
        self.inboxes[pe].live.store(live, Ordering::Release);
    }

    /// A device started PE `pe` at `address`.
    pub(super) fn start(&self, pe: usize, address: u64) {
        self.post(pe, |mail| mail.start = Some(address));
        self.wake(pe);
    }

    /// SEV by PE `from`: every other running PE's event register.
    pub(super) fn event(&self, from: usize) {
        for pe in self.others(from) {
            self.post(pe, |mail| mail.event = true);
            self.wake(pe);
        }
    }

    /// Post `maintenance` to every other running PE, without waking those
    /// that sleep; the serials to wait for.
    pub(super) fn broadcast(&self, from: usize, maintenance: Maintenance) -> Vec<(usize, u64)> {
        let mut posted = Vec::new();
        for pe in self.others(from) {
            let inbox = &self.inboxes[pe];
            let mut serial = 0;
            self.post(pe, |mail| {
                mail.serial += 1;
                serial = mail.serial;
                mail.maintenance.push(maintenance);
            });
            inbox.posted.store(serial, Ordering::Release);
            posted.push((pe, serial));
        }
        posted
    }

    /// Whether every PE in `posted` applied its maintenance, stopped
    /// reading mail, or sleeps, which it reads before it runs again; the
    /// others stay in `posted`, interrupted.
    pub(super) fn applied(&self, posted: &mut Vec<(usize, u64)>) -> bool {
        posted.retain(|&(pe, serial)| {
            let inbox = &self.inboxes[pe];
            let done = inbox.applied.load(Ordering::Acquire) >= serial
                || !inbox.live.load(Ordering::Acquire)
                || inbox.sleeping.load(Ordering::SeqCst);
            if !done {
                self.interrupt(pe);
            }
            !done
        });
        posted.is_empty()
    }

    fn pending(&self, pe: usize) -> bool {
        self.inboxes[pe].pending.load(Ordering::SeqCst)
    }

    /// PE `pe`'s mail, if any, which its machine applies and then
    /// acknowledges with [`Self::acknowledge`].
    pub(super) fn take(&self, pe: usize) -> Option<Mail> {
        let inbox = &self.inboxes[pe];
        if !inbox.pending.swap(false, Ordering::AcqRel) {
            return None;
        }
        let mut mail = inbox.mail.lock().unwrap_or_else(|e| e.into_inner());
        let serial = mail.serial;
        let taken = core::mem::take(&mut *mail);
        mail.serial = serial;
        Some(taken)
    }

    pub(super) fn acknowledge(&self, pe: usize, serial: u64) {
        self.inboxes[pe].applied.fetch_max(serial, Ordering::AcqRel);
    }

    /// Publish PE `pe`'s machine's counts, for the home machine's reports.
    pub fn publish(&self, pe: usize, counts: Counts) {
        *self.inboxes[pe]
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = counts;
    }

    /// PE `pe`'s machine's last published counts.
    pub fn published(&self, pe: usize) -> Counts {
        *self.inboxes[pe]
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The count of device line changes PE `pe` has had.
    pub(super) fn lines_epoch(&self, pe: usize) -> u64 {
        self.inboxes[pe].lines.load(Ordering::Acquire)
    }

    fn lines_changed(&self, pe: usize) {
        self.inboxes[pe].lines.fetch_add(1, Ordering::SeqCst);
        self.interrupt(pe);
        self.wake(pe);
    }

    /// The state of the physical cluster `key`, made by `make` if no PE of
    /// it has run yet.
    pub(super) fn cluster(&self, key: u64, make: impl FnOnce() -> Cluster) -> Cluster {
        self.clusters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert_with(make)
            .clone()
    }

    /// Leave PE `pe`'s forwarded `access` for the home machine, and bring
    /// that machine to it.
    fn request(&self, pe: usize, access: Forwarded) {
        *self.request.lock().unwrap_or_else(|e| e.into_inner()) = Some(Request {
            pe,
            access,
            answer: None,
        });
        self.requested.store(true, Ordering::SeqCst);
        let home = self.home.load(Ordering::Relaxed);
        self.post(home, |_| {});
        self.wake(home);
    }

    /// The forwarded access waiting for the home machine, and its PE.
    fn take_request(&self) -> Option<(usize, Forwarded)> {
        if !self.requested.swap(false, Ordering::AcqRel) {
            return None;
        }
        let request = self.request.lock().unwrap_or_else(|e| e.into_inner());
        request.as_ref().map(|request| (request.pe, request.access))
    }

    fn answer(&self, answer: Answer) {
        if let Some(request) = self
            .request
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            request.answer = Some(answer);
        }
    }

    /// PE `pe`'s answer, once the home machine gave it.
    fn answered(&self, pe: usize) -> Option<Answer> {
        let mut request = self.request.lock().unwrap_or_else(|e| e.into_inner());
        if request
            .as_ref()
            .is_some_and(|request| request.pe == pe && request.answer.is_some())
        {
            return request.take()?.answer;
        }
        None
    }

    /// Stop every running PE but `home` and `requester`: each parks at its
    /// next return to the engine, or already waits there or sleeps, and
    /// reads its mail before it runs again.
    fn stop_others(&self, home: usize, requester: usize) {
        self.stopped.store(true, Ordering::SeqCst);
        for pe in self.others(home).filter(|&pe| pe != requester) {
            let inbox = &self.inboxes[pe];
            while !(inbox.parked.load(Ordering::SeqCst)
                || inbox.sleeping.load(Ordering::SeqCst)
                || !inbox.live.load(Ordering::Acquire))
            {
                self.interrupt(pe);
                core::hint::spin_loop();
            }
        }
    }

    fn restart_others(&self) {
        self.stopped.store(false, Ordering::Release);
    }

    fn set_parked(&self, pe: usize, parked: bool) {
        self.inboxes[pe].parked.store(parked, Ordering::SeqCst);
    }

    fn others(&self, from: usize) -> impl Iterator<Item = usize> + '_ {
        (0..self.inboxes.len())
            .filter(move |&pe| pe != from && self.inboxes[pe].live.load(Ordering::Acquire))
    }
}

/// Why a parallel PE cannot acquire its hub ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelAdmissionError {
    MachineAttached,
    PeOutOfBounds { pe: usize, pes: usize },
    PeOwned { pe: usize },
    HomeOwned,
    HomeUnavailable,
    OwnerEpochExhausted,
    PeersNotHeldInReset,
}
impl core::fmt::Display for ParallelAdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MachineAttached => f.write_str("machine already owns a parallel PE"),
            Self::PeOutOfBounds { pe, pes } => {
                write!(f, "parallel PE {pe} is outside the hub's {pes} slots")
            }
            Self::PeOwned { pe } => write!(f, "parallel PE {pe} already has a live owner"),
            Self::HomeOwned => f.write_str("parallel hub already has a home owner"),
            Self::HomeUnavailable => f.write_str("parallel hub has no admitted home owner"),
            Self::OwnerEpochExhausted => f.write_str("parallel ownership epochs exhausted"),
            Self::PeersNotHeldInReset => {
                f.write_str("only PEs held in reset can move to their own machines")
            }
        }
    }
}
impl core::error::Error for ParallelAdmissionError {}

/// One unique PE claim kept by its control owner through all native
/// invocations. The inbox independently keeps the budget allocation.
pub(super) struct Attached {
    hub: Arc<Hub>,
    pe: usize,
    epoch: u64,
    home: bool,
}
impl Attached {
    fn new(
        hub: &Arc<Hub>,
        pe: usize,
        home: bool,
    ) -> Result<(Arc<Self>, chain_control::Owner), ParallelAdmissionError> {
        let inbox = hub
            .inboxes
            .get(pe)
            .ok_or(ParallelAdmissionError::PeOutOfBounds { pe, pes: hub.pes() })?;
        let epoch = hub
            .next_owner
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1).filter(|value| *value < u64::MAX)
            })
            .map_err(|_| ParallelAdmissionError::OwnerEpochExhausted)?;
        inbox
            .owner
            .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ParallelAdmissionError::PeOwned { pe })?;
        let mut attached = Self {
            hub: Arc::clone(hub),
            pe,
            epoch,
            home: false,
        };
        if home {
            hub.home_owner
                .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ParallelAdmissionError::HomeOwned)?;
            attached.home = true;
        }
        let attached = Arc::new(attached);
        // SAFETY: this is the only writer minted for the newly acquired
        // epoch. The Owner keeps its claim independently of field drop order.
        let control = unsafe {
            chain_control::Owner::from_claimed(Arc::clone(&inbox.chain), Arc::clone(&attached))
        };
        Ok((attached, control))
    }
}
impl Drop for Attached {
    fn drop(&mut self) {
        let inbox = &self.hub.inboxes[self.pe];
        if inbox
            .owner
            .compare_exchange(self.epoch, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            inbox.live.store(false, Ordering::Release);
            if self.home {
                let _ = self.hub.home_owner.compare_exchange(
                    self.epoch,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            inbox.owner.store(0, Ordering::Release);
        }
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Copy this owner's last materialized Cpu image at an engine boundary.
    /// No executing native GuestState or another PE's frame is inspected.
    /// This is optional stale diagnostic data, never a retirement receipt.
    pub fn observe_parallel_source(&mut self, phase: SourcePhase) {
        // A failed native recipe can leave an unchecked partial frame. Keep
        // the preceding materialized sample stale instead of publishing it as
        // a new safe boundary.
        if self.native_failure.is_some() {
            return;
        }
        let Some(hub) = self.parallel.as_ref() else {
            return;
        };
        let Some(inbox) = self.observation_inbox(hub) else {
            return;
        };
        inbox.source.publish(MaterializedSource {
            host_counter: self.host.counter(),
            phase,
            pc: self.cpu.pc,
            sp: self.cpu.state.sp,
            lr: self.cpu.state.x[30],
            el: self.cpu.pstate.el,
            daif: self.cpu.pstate.daif,
        });
    }

    fn observation_inbox<'a>(&self, hub: &'a Arc<Hub>) -> Option<&'a Inbox> {
        if !hub.source_observations_enabled() {
            return None;
        }
        let owner = self.attached.as_ref()?;
        if owner.pe != self.current
            || !Arc::ptr_eq(&owner.hub, hub)
            || !matches!(self.peers.get(self.current), Some(Peer::Running))
        {
            return None;
        }
        hub.inboxes.get(owner.pe)
    }

    /// Become the home machine of a board whose PEs each run on their own
    /// host core: the running PE stays here, and every PE held in reset will
    /// start on its own machine ([`Self::start_parallel`]). The counter
    /// follows the host's from now on, as no machine can charge another's
    /// slices, and waits no longer leap it.
    pub fn enter_parallel(&mut self, hub: Arc<Hub>) -> Result<(), ParallelAdmissionError> {
        if self.attached.is_some() || self.parallel.is_some() {
            return Err(ParallelAdmissionError::MachineAttached);
        }
        if self
            .peers
            .iter()
            .any(|peer| !matches!(peer, Peer::Running | Peer::Off))
        {
            return Err(ParallelAdmissionError::PeersNotHeldInReset);
        }
        let (attached, control) = Attached::new(&hub, self.current, true)?;
        self.adopt_parallel_control(control);
        for peer in &mut self.peers {
            match peer {
                Peer::Running => {}
                Peer::Off => *peer = Peer::Remote,
                Peer::Parked(_) | Peer::Remote => {
                    unreachable!("peer states checked before claiming the hub");
                }
            }
        }
        // The running PE's cluster state is the one its other PEs join.
        let key = self
            .profile
            .processors
            .get(self.current)
            .map_or(0, |identity| {
                identity.mpidr & super::processors::PHYSICAL_CLUSTER_MASK
            });
        hub.cluster(key, || Cluster {
            ctrr: self.cpu.ctrr.clone(),
            impdef: self.cpu.apple.impdef.cluster_registers(),
        });
        self.clock.follow_host();
        *hub.clock.lock().unwrap_or_else(|e| e.into_inner()) = Some(*self.clock);
        hub.home.store(self.current, Ordering::Relaxed);
        self.share_kept_pages(hub.pes());
        self.idle_skip = false;
        hub.set_live(self.current, true);
        self.attached = Some(attached);
        self.parallel = Some(hub);
        Ok(())
    }

    fn adopt_parallel_control(&mut self, control: chain_control::Owner) {
        let contexts = self.chain.contexts();
        // Every installed thunk embeds the old control address. Retire the
        // whole local arena and lookup table before dropping that allocation.
        self.discard_code();
        self.targets
            .fill(stela_compiler::x86_64::chain::LookupEntry::default());
        self.chain = control;
        self.chain
            .initialize(self.targets.as_ptr() as u64, contexts);
    }

    /// Whether this machine runs one PE of a board whose PEs each run on
    /// their own host core.
    pub fn runs_parallel(&self) -> bool {
        self.parallel.is_some()
    }

    /// Start this machine's PE at `address`, as the device that started it
    /// asked through the hub; the home machine entered parallel first.
    pub fn start_parallel(
        &mut self,
        hub: Arc<Hub>,
        core_locks: Arc<ctrr::CoreLocks>,
        address: u64,
    ) -> Step {
        if self.attached.is_some() || self.parallel.is_some() {
            return Err(self.unsupported(RequirementKind::ParallelAdmission(
                ParallelAdmissionError::MachineAttached,
            )));
        }
        let clock = {
            let retained = hub.clock.lock().unwrap_or_else(|e| e.into_inner());
            let Some(clock) = retained
                .as_ref()
                .copied()
                .filter(|_| hub.home_owner.load(Ordering::Acquire) != 0)
            else {
                return Err(self.unsupported(RequirementKind::ParallelAdmission(
                    ParallelAdmissionError::HomeUnavailable,
                )));
            };
            clock
        };
        let (attached, control) = Attached::new(&hub, self.current, false)
            .map_err(|error| self.unsupported(RequirementKind::ParallelAdmission(error)))?;
        self.adopt_parallel_control(control);
        for (pe, peer) in self.peers.iter_mut().enumerate() {
            if pe != self.current {
                *peer = Peer::Remote;
            }
        }
        *self.clock = clock;
        self.idle_skip = false;
        self.cpu.core_locks = core_locks;
        self.cpu.memory_lock = self.devices.memory_lock();
        self.share_kept_pages(hub.pes());
        hub.set_live(self.current, true);
        self.attached = Some(attached);
        self.parallel = Some(hub);
        self.restart(self.current, address)
    }

    /// Apply what other PEs left for this one: changed device lines, an
    /// event, maintenance, and a start of a powered-down PE.
    pub(super) fn read_mail(&mut self) -> Step {
        let Some(hub) = &self.parallel else {
            return Ok(());
        };
        let hub = Arc::clone(hub);
        // Acquire BEFORE looking at any source. A later notification must
        // remain different even if this drain happens to consume its data.
        let observed = hub.inboxes[self.current]
            .chain
            .interrupt_epoch()
            .load(Ordering::Acquire);
        let result = (|| {
            if hub.home.load(Ordering::Relaxed) == self.current {
                self.serve_forwarded(&hub)?;
            } else if hub.stopped.load(Ordering::SeqCst) {
                self.park(&hub)?;
            }
            for page in core::mem::take(&mut self.deferred_code) {
                self.maintain(Maintenance::Code(page))?;
            }
            let epoch = hub.lines_epoch(self.current);
            if epoch != self.lines_epoch {
                self.lines_epoch = epoch;
                self.device_lines = None;
            }
            if !hub.pending(self.current) {
                return Ok(());
            }
            let Some(mail) = hub.take(self.current) else {
                return Ok(());
            };
            if mail.event && !self.waiting.is_some_and(|wait| wait.down) {
                self.cpu.signal_event();
            }
            for maintenance in &mail.maintenance {
                self.maintain(*maintenance)?;
            }
            hub.acknowledge(self.current, mail.serial);
            if let Some(address) = mail.start {
                self.start(Start {
                    cpu: self.current,
                    address,
                })?;
            }
            Ok(())
        })();
        if result.is_ok() {
            self.chain.acknowledge_interrupt(observed);
        }
        result
    }

    /// Whether the running PE waits in WFE on an armed monitor while other
    /// cores run: another core's store to its granule clears the monitor,
    /// which sends it the event, and no interrupt tells of that store, so
    /// the wait polls the granule (`observe_writes`) instead of halting.
    pub(super) fn polls_monitor(&self) -> bool {
        self.parallel.is_some()
            && self.cpu.monitor.is_some()
            && self
                .waiting
                .is_some_and(|wait| wait.kind == super::WaitKind::Event && !wait.down)
    }

    /// Halt the host core until an interrupt, or, in parallel, also until
    /// mail or a device line change reaches this PE.
    pub(super) fn sleep(&mut self) {
        match self.parallel.clone() {
            Some(hub) => hub.sleep(self.current, self.lines_epoch, || {
                self.host.wait_for_interrupt()
            }),
            None => self.host.wait_for_interrupt(),
        }
    }

    /// Maintenance another PE broadcast, reached from this PE's context.
    fn maintain(&mut self, maintenance: Maintenance) -> Step {
        match maintenance {
            Maintenance::Tlb(scope) => {
                let controls = self.cpu.controls(self.cpu.regime());
                let current = tlbi::Current {
                    regime: controls.regime,
                    asid: (controls.regime != mmu::Regime::El2)
                        .then(|| mmu::current_asid(&controls)),
                };
                self.tlb_maintained(scope.reach(&current), scope.everywhere());
            }
            Maintenance::Code(Some(physical)) => {
                self.invalidate_code_page(physical);
                self.host.code_invalidated(Some(physical));
            }
            Maintenance::Code(None) => {
                self.discard_code();
                self.host.code_invalidated(None);
            }
            Maintenance::Power(change) => {
                if self.processor_write().received().apply(&[change]).is_err() {
                    let requirement = self.requirement(RequirementKind::Native(
                        "another PE's CPU power change does not settle on this PE's machine",
                    ));
                    self.degrade(requirement);
                }
            }
        }
        Ok(())
    }

    /// Send the CPU power changes this PE made to every other PE's machine,
    /// and wait until each running one has applied them.
    pub(super) fn forward_power(&mut self) -> Step {
        for change in core::mem::take(&mut self.forwarded_power) {
            self.broadcast(Maintenance::Power(change))?;
        }
        Ok(())
    }

    /// Broadcast `maintenance` and wait until every other running PE has
    /// applied it, reading this PE's own mail meanwhile: two PEs may wait on
    /// each other. A start that arrives meanwhile is posted again.
    pub(super) fn broadcast(&mut self, maintenance: Maintenance) -> Step {
        let Some(hub) = self.parallel.clone() else {
            return Ok(());
        };
        let started = self.host.counter();
        self.observe_parallel_source(SourcePhase::BroadcastEnter);
        let mut posted = hub.broadcast(self.current, maintenance);
        let profile = self.observation_inbox(&hub).map(|inbox| &inbox.broadcasts);
        let kind = match maintenance {
            Maintenance::Tlb(_) => BroadcastKind::Tlb,
            Maintenance::Code(_) => BroadcastKind::Code,
            Maintenance::Power(_) => BroadcastKind::Power,
        };
        let active = profile.and_then(|slot| slot.begin(kind, started, posted.len()));
        let mut polls = 0u64;
        // A PE stopping the others need not wait for this one meanwhile.
        hub.set_parked(self.current, true);
        let mut applied = Ok(());
        while !hub.applied(&mut posted) {
            if profile.is_some() {
                polls = polls.saturating_add(1);
            }
            applied = applied.and(self.wait_for_others(&hub));
            core::hint::spin_loop();
        }
        hub.set_parked(self.current, false);
        self.statistics.broadcasts += 1;
        let elapsed = self.host.counter().wrapping_sub(started);
        self.statistics.sync_ticks += elapsed;
        // Publish only at boundaries, including a returned maintenance error.
        if let (Some(slot), Some(active)) = (profile, active) {
            slot.finish(active, elapsed, polls);
        }
        self.observe_parallel_source(SourcePhase::BroadcastExit);
        applied
    }

    /// This machine's counts, as [`Hub::publish`] takes them.
    pub fn counts(&self) -> Counts {
        let statistics = &self.statistics;
        Counts {
            blocks: statistics.blocks,
            retired: self.retired_instructions() as u64,
            compiled: statistics.compiled,
            shared: statistics.shared,
            compile_ticks: statistics.compile_ticks,
            sleep_ticks: statistics.sleep_ticks,
            spin_ticks: statistics.spin_ticks,
            sync_ticks: statistics.sync_ticks,
            waits: statistics.waits,
            broadcasts: statistics.broadcasts,
            forwards: statistics.forwards,
            exceptions: statistics.exceptions,
            device_accesses: statistics.device_accesses,
        }
    }

    /// Apply this PE's mail while it waits in the engine for other PEs,
    /// which may wait on it: an event, maintenance, and a start, which is
    /// posted again for the PE's next mail read.
    fn wait_for_others(&mut self, hub: &Arc<Hub>) -> Step {
        let Some(mail) = hub.take(self.current) else {
            return Ok(());
        };
        if mail.event {
            self.cpu.signal_event();
        }
        let mut applied = Ok(());
        for &maintenance in &mail.maintenance {
            match maintenance {
                // The instruction this PE waits in may still name its
                // block: its code goes at the next mail read, before the PE
                // fetches again.
                Maintenance::Code(page) => self.deferred_code.push(page),
                _ => applied = applied.and(self.maintain(maintenance)),
            }
        }
        hub.acknowledge(self.current, mail.serial);
        if let Some(address) = mail.start {
            hub.start(self.current, address);
        }
        applied
    }

    /// Run no guest code while the home machine has stopped the others.
    fn park(&mut self, hub: &Arc<Hub>) -> Step {
        let started = self.host.counter();
        self.observe_parallel_source(SourcePhase::ParkEnter);
        hub.set_parked(self.current, true);
        let mut applied = Ok(());
        while hub.stopped.load(Ordering::SeqCst) {
            applied = applied.and(self.wait_for_others(hub));
            core::hint::spin_loop();
        }
        hub.set_parked(self.current, false);
        self.statistics.sync_ticks += self.host.counter().wrapping_sub(started);
        self.observe_parallel_source(SourcePhase::ParkExit);
        applied
    }

    /// Serve the device access another PE forwarded, if any, with every
    /// other running PE stopped, and send that PE the CPU power changes it
    /// made before it runs again.
    fn serve_forwarded(&mut self, hub: &Arc<Hub>) -> Step {
        let Some((pe, access)) = hub.take_request() else {
            return Ok(());
        };
        let started = self.host.counter();
        hub.stop_others(self.current, pe);
        let now = self.now();
        let answer = match access {
            Forwarded::Read { physical, shape } => {
                Answer::Read(self.serial_read_canonical_as(pe, physical, shape, now))
            }
            Forwarded::Write {
                physical,
                bytes,
                value,
            } => Answer::Write(self.serial_write_canonical_as(pe, physical, bytes, value, now)),
        };
        let forwarded = self.forward_power();
        hub.restart_others();
        hub.answer(answer);
        self.statistics.sync_ticks += self.host.counter().wrapping_sub(started);
        forwarded
    }

    /// Forward a read only canonical memory serves to the home machine.
    pub(super) fn forward_read(
        &mut self,
        physical: u64,
        shape: DeviceReadShape,
    ) -> Result<ConsumedPair, DeviceError> {
        match self.forward(Forwarded::Read { physical, shape })? {
            Answer::Read(read) => read,
            Answer::Write(_) => unreachable!("a read's answer"),
        }
    }

    /// Forward a write only canonical memory serves to the home machine.
    pub(super) fn forward_write(
        &mut self,
        physical: u64,
        bytes: u8,
        value: u64,
    ) -> Result<(), DeviceError> {
        match self.forward(Forwarded::Write {
            physical,
            bytes,
            value,
        })? {
            Answer::Write(write) => write,
            Answer::Read(_) => unreachable!("a write's answer"),
        }
    }

    /// Wait, applying this PE's mail, until the home machine answered
    /// `access`; one PE's access at a time.
    fn forward(&mut self, access: Forwarded) -> Result<Answer, DeviceError> {
        let hub = Arc::clone(self.parallel.as_ref().expect("forwarded in parallel"));
        let started = self.host.counter();
        self.observe_parallel_source(SourcePhase::ForwardEnter);
        hub.set_parked(self.current, true);
        let mut applied = Ok(());
        while hub
            .forwarding
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            applied = applied.and(self.wait_for_others(&hub));
            core::hint::spin_loop();
        }
        hub.request(self.current, access);
        let answer = loop {
            if let Some(answer) = hub.answered(self.current) {
                break answer;
            }
            applied = applied.and(self.wait_for_others(&hub));
            core::hint::spin_loop();
        };
        hub.forwarding.store(false, Ordering::Release);
        hub.set_parked(self.current, false);
        self.statistics.forwards += 1;
        self.statistics.sync_ticks += self.host.counter().wrapping_sub(started);
        self.observe_parallel_source(SourcePhase::ForwardExit);
        // The mail applied meanwhile settles first: its refusal is this
        // access's.
        applied.map_err(|stop| {
            DeviceError::TransferRefused(alloc::format!("while forwarded: {stop:?}"))
        })?;
        Ok(answer)
    }
}

/// Whether a TLBI reaches other PEs.
pub(super) fn broadcasts(scope: &tlbi::Scope) -> bool {
    scope.broadcast != Broadcast::NSH
}

/// What a call to the board's devices is for, which [`SharedDevices::waits`]
/// counts the contended ones by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    /// A device register access or a DMA transfer.
    Access,
    /// The lines the devices drive into a PE.
    Lines,
    /// The devices' next deadline.
    Deadline,
    /// A System register the devices serve.
    Register,
    /// The home machine's questions: DMA due, a reset, the host's service.
    Home,
    Other,
}

impl Call {
    pub const ALL: [Self; 6] = [
        Self::Access,
        Self::Lines,
        Self::Deadline,
        Self::Register,
        Self::Home,
        Self::Other,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Lines => "lines",
            Self::Deadline => "deadline",
            Self::Register => "register",
            Self::Home => "home",
            Self::Other => "other",
        }
    }
}

struct Board<D> {
    devices: Mutex<D>,
    hub: Arc<Hub>,
    /// Calls that found the devices' lock held, by [`Call`].
    waits: [AtomicU64; Call::ALL.len()],
    /// The latest count any machine passed, which every later call sees at
    /// least: the PEs' counters agree only to within their reads.
    now: AtomicU64,
    /// Each PE's device lines as last seen.
    lines: Mutex<Vec<Lines>>,
    /// Each PE's latched pins as every call left them ([`pack`]), which
    /// another PE's machine reads without the lock: only the home machine
    /// advances the devices with time.
    pins: Box<[AtomicU8]>,
    /// The devices' DMA deadline (`u64::MAX`: none) and a reset they
    /// requested, as each call left them: the home machine asks at every
    /// step, without the lock.
    dma: AtomicU64,
    reset: Mutex<Option<Reset>>,
    resetting: AtomicBool,
    /// PE starts the devices made, which every machine asks for at every
    /// wait, without the lock; `starting` changes only under `starts`.
    starts: Mutex<VecDeque<Start>>,
    starting: AtomicBool,
    /// The SoC sleeps until the host's power button
    /// ([`Devices::waits_on_host`]).
    asleep: AtomicBool,
    /// The IMPLEMENTATION DEFINED registers (op0 3, CRn 15) the devices
    /// serve, by op1, CRm and op2 ([`register_bit`]): a PE's machine asks
    /// for every one it reaches, and the others take no lock.
    registers: [u64; 16],
}

/// Pins as [`Board::pins`] holds them: IRQ and FIQ, or [`UNLATCHED`] for
/// devices whose lines need an advance to read.
fn pack(pins: Option<Lines>) -> u8 {
    pins.map_or(UNLATCHED, |lines| {
        u8::from(lines.irq) | u8::from(lines.fiq) << 1
    })
}

const UNLATCHED: u8 = u8::MAX;

fn unpack(pins: u8) -> Option<Lines> {
    (pins != UNLATCHED).then_some(Lines {
        irq: pins & 1 != 0,
        fiq: pins & 2 != 0,
    })
}

/// The bit of `registers` for an IMPLEMENTATION DEFINED encoding.
fn register_bit(encoding: Encoding) -> Option<usize> {
    (encoding.op0() == 3 && encoding.crn() == 15).then(|| {
        usize::from(encoding.op1()) << 7
            | usize::from(encoding.crm()) << 3
            | usize::from(encoding.op2())
    })
}

impl<D: Devices> Board<D> {
    fn lock(&self, call: Call) -> Held<'_, D> {
        let devices = match self.devices.try_lock() {
            Ok(devices) => devices,
            Err(_) => {
                self.waits[call as usize].fetch_add(1, Ordering::Relaxed);
                self.devices.lock().unwrap_or_else(|e| e.into_inner())
            }
        };
        Held {
            board: self,
            devices,
        }
    }

    /// Record what the machines ask of `devices` at every step: the home
    /// machine its resets, DMA and host inputs, and any its starts and the
    /// host's service. Every call's release runs it, so it writes only what
    /// changed: the machines read these without the lock, and an unchanged
    /// store would still take each one's cache line from every reader.
    fn publish(&self, devices: &mut D) {
        if let Some(reset) = devices.take_reset() {
            self.reset
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert(reset);
            self.resetting.store(true, Ordering::Release);
        }
        if let Some(start) = devices.take_start() {
            let mut starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
            starts.push_back(start);
            starts.extend(core::iter::from_fn(|| devices.take_start()));
            self.starting.store(true, Ordering::Release);
        }
        // A deadline earlier than the last, such as a host transfer that
        // completed on another core, wakes the home machine if it sleeps.
        let dma = devices.dma_deadline().unwrap_or(u64::MAX);
        let published = self.dma.load(Ordering::Acquire);
        if published != dma {
            self.dma.store(dma, Ordering::Release);
            if published > dma {
                self.hub.wake(self.hub.home.load(Ordering::Acquire));
            }
        }
        for pe in 0..self.pins.len() {
            self.publish_pins(pe, devices.pins(pe));
        }
        let asleep = devices.waits_on_host();
        if self.asleep.load(Ordering::Relaxed) != asleep {
            self.asleep.store(asleep, Ordering::Release);
        }
        if devices.take_host_service() {
            self.hub.request_service();
        }
    }

    /// Publish the snapshot a remote PE reads without the devices' lock.
    fn publish_pins(&self, pe: usize, lines: Option<Lines>) {
        let pins = &self.pins[pe];
        let packed = pack(lines);
        if pins.load(Ordering::Relaxed) != packed {
            pins.store(packed, Ordering::Release);
        }
    }

    /// The oldest start [`Self::publish`] kept.
    fn take_start(&self) -> Option<Start> {
        if !self.starting.load(Ordering::Acquire) {
            return None;
        }
        let mut starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        let start = starts.pop_front();
        self.starting.store(!starts.is_empty(), Ordering::Release);
        start
    }
}

/// The devices while a call holds their lock; its release publishes what
/// the call left for the home machine ([`Board::publish`]).
struct Held<'a, D: Devices> {
    board: &'a Board<D>,
    devices: crate::platform::sync::MutexGuard<'a, D>,
}

impl<D: Devices> core::ops::Deref for Held<'_, D> {
    type Target = D;
    fn deref(&self) -> &D {
        &self.devices
    }
}

impl<D: Devices> core::ops::DerefMut for Held<'_, D> {
    fn deref_mut(&mut self) -> &mut D {
        &mut self.devices
    }
}

impl<D: Devices> Drop for Held<'_, D> {
    fn drop(&mut self) {
        self.board.publish(&mut self.devices);
    }
}

// SAFETY: the devices are reached only under `devices`' lock, so state they
// share through `Rc` or `RefCell` is never touched by two cores at once, and
// no reference into them outlives the guard.
unsafe impl<D> Send for Board<D> {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl<D> Sync for Board<D> {}

/// The board's devices, shared by every PE's machine.
pub struct SharedDevices<D> {
    board: Arc<Board<D>>,
    /// The machine that serves resets and DMA.
    home: bool,
}

impl<D: Devices> SharedDevices<D> {
    /// The home machine's handle.
    pub fn new(devices: D, hub: Arc<Hub>) -> Self {
        let pes = hub.pes();
        let mut registers = [0u64; 16];
        for bit in 0..1 << 10 {
            let (op1, crm, op2) = ((bit >> 7) as u8, (bit >> 3 & 15) as u8, (bit & 7) as u8);
            if devices.serves_register(Encoding::new(3, op1, 15, crm, op2)) {
                registers[bit / 64] |= 1 << (bit % 64);
            }
        }
        let board = Board {
            devices: Mutex::new(devices),
            hub,
            waits: Default::default(),
            now: AtomicU64::new(0),
            lines: Mutex::new(alloc::vec![Lines::default(); pes]),
            pins: (0..pes).map(|_| AtomicU8::new(UNLATCHED)).collect(),
            dma: AtomicU64::new(u64::MAX),
            reset: Mutex::new(None),
            resetting: AtomicBool::new(false),
            starts: Mutex::new(VecDeque::new()),
            starting: AtomicBool::new(false),
            asleep: AtomicBool::new(false),
            registers,
        };
        drop(board.lock(Call::Other));
        Self {
            board: Arc::new(board),
            home: true,
        }
    }

    /// A handle for another PE's machine.
    pub fn worker(&self) -> Self {
        Self {
            board: Arc::clone(&self.board),
            home: false,
        }
    }

    pub fn hub(&self) -> &Arc<Hub> {
        &self.board.hub
    }

    /// Run `f` on the devices while no PE reaches them.
    pub fn with<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        self.call(Call::Other, f)
    }

    fn call<R>(&self, call: Call, f: impl FnOnce(&mut D) -> R) -> R {
        f(&mut self.board.lock(call))
    }

    /// Calls that found the devices' lock held since the board was made, by
    /// [`Call`].
    pub fn waits(&self) -> [u64; Call::ALL.len()] {
        self.board
            .waits
            .each_ref()
            .map(|waits| waits.load(Ordering::Relaxed))
    }

    /// Serve the host's inputs with `f`, which can change any PE's lines.
    pub fn serve<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        let now = self.board.now.load(Ordering::Acquire);
        self.changing(Call::Home, usize::MAX, now, |devices, _| f(devices))
    }

    /// The count the devices see for a call at `now`, which no earlier
    /// call's passes. Taken under the devices' lock, so calls see counts in
    /// the order they reach the devices.
    fn now(&self, now: u64) -> u64 {
        self.board.now.fetch_max(now, Ordering::AcqRel).max(now)
    }

    /// Run `f` on the devices at `now`, as [`Self::now`] gives it.
    fn at<R>(&self, call: Call, now: u64, f: impl FnOnce(&mut D, u64) -> R) -> R {
        let mut devices = self.board.lock(call);
        let now = self.now(now);
        f(&mut devices, now)
    }

    /// A call that can change devices: run it, then tell every other PE
    /// whose lines it changed.
    fn changing<R>(&self, call: Call, cpu: usize, now: u64, f: impl FnOnce(&mut D, u64) -> R) -> R {
        let mut devices = self.board.lock(call);
        let now = self.now(now);
        let result = f(&mut devices, now);
        self.notify(&mut devices, cpu, now);
        result
    }

    /// Tell every PE but `cpu` whose lines changed since it last saw them.
    /// Every change reaches the devices under their lock, so a PE learns of
    /// each from the call that made it, and needs no device deadline of its
    /// own: only the home machine advances the devices with time.
    fn notify(&self, devices: &mut D, cpu: usize, now: u64) {
        let mut seen = self.board.lines.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(own) = seen.get_mut(cpu)
            && let Some(lines) = devices.pins(cpu)
        {
            // The caller reads its own lines after the call.
            *own = lines;
        }
        for pe in self.board.hub.others(cpu) {
            let pins = devices.pins(pe);
            let lines = match pins {
                Some(lines) => lines,
                None => devices.lines(pe, now),
            };
            // The receiver may read its pins as soon as the epoch changes,
            // before this call releases the devices' lock.
            self.board.publish_pins(pe, pins);
            if lines != seen[pe] {
                seen[pe] = lines;
                self.board.hub.lines_changed(pe);
            }
        }
    }
}

impl<D: Devices> Devices for SharedDevices<D> {
    fn pc_sample_target(&self, physical: u64, bytes: u8) -> Option<usize> {
        self.with(|devices| devices.pc_sample_target(physical, bytes))
    }
    fn observe_pc_sample(&mut self, physical: u64, pc: u64) {
        self.with(|devices| devices.observe_pc_sample(physical, pc));
    }
    fn read(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read(cpu, physical, bytes, now)
        })
    }
    fn requires_canonical_read(&self, cpu: usize, physical: u64, shape: DeviceReadShape) -> bool {
        self.with(|devices| devices.requires_canonical_read(cpu, physical, shape))
    }
    fn requires_canonical_write(&self, cpu: usize, physical: u64, bytes: u8) -> bool {
        self.with(|devices| devices.requires_canonical_write(cpu, physical, bytes))
    }
    fn read_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedScalar, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_canonical(cpu, physical, bytes, now, memory)
        })
    }
    fn read_pair_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedPair, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_pair_canonical(cpu, physical, bytes, now, memory)
        })
    }
    fn write_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<ConsumedWrite, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_canonical(cpu, physical, bytes, value, now, owners)
        })
    }
    fn write_pair_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        values: [u64; 2],
        now: u64,
        owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<ConsumedWrite, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_pair_canonical(cpu, physical, bytes, values, now, owners)
        })
    }
    fn read_pair(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
    ) -> Result<Option<ConsumedPair>, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_pair(cpu, physical, bytes, now)
        })
    }
    fn write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write(cpu, physical, bytes, value, now)
        })
    }
    fn write_with_processors(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        processors: super::ProcessorWrite<'_>,
    ) -> Result<(), DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_with_processors(cpu, physical, bytes, value, now, processors)
        })
    }
    /// The home machine's asking advances the devices to `now`, which can
    /// change any PE's lines; another PE's machine reads its latched pins.
    fn lines(&mut self, cpu: usize, now: u64) -> Lines {
        if !self.home
            && let Some(lines) = self.pins(cpu)
        {
            return lines;
        }
        let mut devices = self.board.lock(Call::Lines);
        let now = self.now(now);
        let lines = devices.lines(cpu, now);
        self.board.lines.lock().unwrap_or_else(|e| e.into_inner())[cpu] = lines;
        self.notify(&mut devices, cpu, now);
        lines
    }
    fn pins(&mut self, cpu: usize) -> Option<Lines> {
        unpack(self.board.pins.get(cpu)?.load(Ordering::Acquire))
    }
    /// The home machine advances the devices with time and tells the other
    /// PEs what that changes ([`Self::notify`]); their machines wait for
    /// those changes instead.
    fn deadline(&mut self, now: u64) -> Option<u64> {
        if !self.home {
            return None;
        }
        self.changing(Call::Deadline, usize::MAX, now, |devices, now| {
            devices.deadline(now)
        })
    }
    fn system_register(
        &mut self,
        cpu: usize,
        encoding: Encoding,
        write: Option<u64>,
        now: u64,
    ) -> Option<Result<u64, &'static str>> {
        if let Some(bit) = register_bit(encoding)
            && self.board.registers[bit / 64] & 1 << (bit % 64) == 0
        {
            return None;
        }
        if write.is_none() {
            return self.at(Call::Register, now, |devices, now| {
                devices.system_register(cpu, encoding, None, now)
            });
        }
        self.changing(Call::Register, cpu, now, |devices, now| {
            devices.system_register(cpu, encoding, write, now)
        })
    }
    /// Only the home machine takes a reset, which stops every PE.
    fn take_reset(&mut self) -> Option<Reset> {
        if !self.home || !self.board.resetting.swap(false, Ordering::Acquire) {
            return None;
        }
        self.board
            .reset
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
    fn take_start(&mut self) -> Option<Start> {
        self.board.take_start()
    }
    fn reset_vector(&self, cpu: usize) -> Option<u64> {
        self.with(|devices| devices.reset_vector(cpu))
    }
    fn processor_power(&mut self, cpu: usize, on: bool) {
        let now = self.board.now.load(Ordering::Acquire);
        self.changing(Call::Other, cpu, now, |devices, _| {
            devices.processor_power(cpu, on)
        });
    }
    fn irq_steering(&mut self, cpu: usize, refuses: bool, now: u64) {
        self.changing(Call::Other, cpu, now, |devices, now| {
            devices.irq_steering(cpu, refuses, now)
        });
    }
    /// Only the home machine takes the host's power button.
    fn waits_on_host(&self) -> bool {
        self.home && self.board.asleep.load(Ordering::Acquire)
    }
    /// Any PE that waits for an interrupt can serve the host.
    fn take_host_service(&mut self) -> bool {
        self.board.hub.take_service()
    }
    fn memory_lock(&self) -> mmu::MemoryLocks {
        self.with(|devices| devices.memory_lock())
    }
    fn serves_register(&self, encoding: Encoding) -> bool {
        register_bit(encoding)
            .is_none_or(|bit| self.board.registers[bit / 64] & 1 << (bit % 64) != 0)
    }
    /// Only the home machine moves devices' asynchronous DMA, through its
    /// host's canonical RAM owner.
    fn dma_deadline(&self) -> Option<u64> {
        if !self.home {
            return None;
        }
        let dma = self.board.dma.load(Ordering::Acquire);
        (dma != u64::MAX).then_some(dma)
    }
    fn transfer(
        &mut self,
        cpu: usize,
        memory: &mut dyn super::Memory,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.transfer(cpu, memory, now)
        })
    }
}

#[cfg(test)]
mod tests;
