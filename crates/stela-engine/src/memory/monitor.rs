//! Exclusive-monitor bookkeeping for a memory domain.
//!
//! Callers own the backing bytes, permission and translation checks, and mapping
//! pins. Each callback performs exactly one architectural access and must not
//! re-enter the domain. A Rust panic fails the whole domain.

use crate::platform::sync::{Mutex, MutexGuard};
use crate::system::events::{EventProducer, MonitorBinding};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

const MIN_ERG_BYTES: u64 = 16;
const MAX_ERG_BYTES: u64 = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Scalar,
    Pair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorError {
    InvalidErg,
    InvalidStripeCount,
    InvalidRange,
    InvalidShape,
    CrossesGranule,
    WrongDomain,
    DeadMapping,
    Poisoned,
    EventsUnbound,
    EventsAlreadyBound,
    ReservationActive,
    EventBindingUnavailable,
    WrongEventEndpoint,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessError<E> {
    Monitor(MonitorError),
    Memory(E),
}

impl<E> From<MonitorError> for AccessError<E> {
    fn from(error: MonitorError) -> Self {
        Self::Monitor(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConditionalWrite<T> {
    Failed,
    Stored(T),
}

/// Source-selected invalidation timing; this is distinct from committed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalidation {
    /// Ordinary reached fragment: a callback error means no bytes committed.
    OnCommit,
    /// A source-permitted clear-before-tag-check/attempt policy, including faults.
    BeforeAttempt,
}

/// Immutable view identity retains the real mapping payload for reservations.
/// Protection/backing/attribute changes revoke this identity and create another.
/// Root must also hold stable memory pins while invoking an access callback.
pub struct Mapping<M, A> {
    payload: Arc<M>,
    attributes: A,
    live: AtomicBool,
}

impl<M, A> Mapping<M, A> {
    pub fn new(payload: Arc<M>, attributes: A) -> Arc<Self> {
        Arc::new(Self {
            payload,
            attributes,
            live: AtomicBool::new(true),
        })
    }

    pub fn payload(&self) -> &Arc<M> {
        &self.payload
    }

    pub fn attributes(&self) -> &A {
        &self.attributes
    }

    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

/// Already resolved physical identity. It contains no guest/native RAM pointer.
pub struct Access<B, M, A> {
    backing: Arc<B>,
    mapping: Arc<Mapping<M, A>>,
    offset: u64,
    bytes: u8,
    shape: Shape,
}

impl<B, M, A> Access<B, M, A> {
    pub fn new(
        backing: Arc<B>,
        mapping: Arc<Mapping<M, A>>,
        offset: u64,
        bytes: u8,
        shape: Shape,
    ) -> Result<Self, MonitorError> {
        let valid_shape = match shape {
            Shape::Scalar => matches!(bytes, 1 | 2 | 4 | 8),
            Shape::Pair => matches!(bytes, 8 | 16),
        };
        if !valid_shape {
            return Err(MonitorError::InvalidShape);
        }
        offset
            .checked_add(u64::from(bytes))
            .ok_or(MonitorError::InvalidRange)?;
        Ok(Self {
            backing,
            mapping,
            offset,
            bytes,
            shape,
        })
    }
}

/// One actually reached writer event, not an entire speculative store footprint.
pub struct WriteRange<B> {
    backing: Arc<B>,
    offset: u64,
    bytes: u64,
}

impl<B> WriteRange<B> {
    pub fn new(backing: Arc<B>, offset: u64, bytes: u64) -> Result<Self, MonitorError> {
        if bytes == 0 || offset.checked_add(bytes).is_none() {
            return Err(MonitorError::InvalidRange);
        }
        Ok(Self {
            backing,
            offset,
            bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    backing: usize,
    granule: u64,
}

impl Key {
    fn new<B>(backing: &Arc<B>, granule: u64) -> Self {
        Self {
            backing: Arc::as_ptr(backing) as usize,
            granule,
        }
    }
}

/// No integer version or epoch counter exists. A live reservation retains this
/// allocation and its backing; allocator address reuse cannot revive that mark.
struct Epoch<B> {
    backing: Arc<B>,
    granule: u64,
    subscribers: Mutex<Vec<Weak<EventCell<B>>>>,
}

/// Event scope is chosen by the physical mapping owner, not an opcode name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationScope {
    Local,
    Global,
}

struct EventState<B> {
    epoch: Weak<Epoch<B>>,
    // Active GlobalMark retains this Mapping allocation; no address reuse.
    mapping: usize,
}

struct EventCell<B> {
    endpoint: MonitorBinding,
    current: Mutex<EventState<B>>,
}

/// Global lifetime is independent from local reservation validity.
struct GlobalMark<B, M, A> {
    epoch: Arc<Epoch<B>>,
    mapping: Arc<Mapping<M, A>>,
}

type Entries<B> = BTreeMap<Key, Weak<Epoch<B>>>;

struct Reservation<B, M, A> {
    epoch: Arc<Epoch<B>>,
    mapping: Arc<Mapping<M, A>>,
    offset: u64,
    bytes: u8,
    shape: Shape,
}

/// Rust unwinding is fatal for execution across every stripe, not just the
/// Mutex that happens to observe poisoning. This is not native fault recovery.
struct FailureBoundary<'a>(&'a AtomicBool);

impl Drop for FailureBoundary<'_> {
    fn drop(&mut self) {
        if crate::platform::unwind::panicking() {
            self.0.store(true, Ordering::Release);
        }
    }
}

/// Gates serialize bounded callbacks, never a whole
/// load-exclusive/store-exclusive sequence. Keys in one stripe share a gate but
/// never a reservation. Fairness is whatever std::Mutex provides.
pub struct MonitorDomain<B, M, A> {
    erg_bytes: u64,
    stripes: Vec<Mutex<Entries<B>>>,
    failed: AtomicBool,
    mapping: PhantomData<fn() -> (M, A)>,
}

pub struct ThreadMonitor<B, M, A> {
    domain: Arc<MonitorDomain<B, M, A>>,
    reservation: Option<Reservation<B, M, A>>,
    global: Option<GlobalMark<B, M, A>>,
    event: Option<Arc<EventCell<B>>>,
}

/// A retained exclusive borrow of the real local monitor. Dropping this
/// preparation changes nothing; commit cannot substitute another reservation.
pub(crate) struct PreparedClear<'a, B, M, A> {
    domain: &'a MonitorDomain<B, M, A>,
    thread: &'a mut ThreadMonitor<B, M, A>,
}
impl<B, M, A> PreparedClear<'_, B, M, A> {
    pub(crate) fn commit(self) {
        self.domain.retire(self.thread.reservation.take());
    }
}

/// Declare before stripe guards so error/unwind cleanup cannot self-deadlock.
struct LocalRetirement<'a, B, M, A> {
    domain: &'a MonitorDomain<B, M, A>,
    saved: Option<Reservation<B, M, A>>,
}
impl<B, M, A> Drop for LocalRetirement<'_, B, M, A> {
    fn drop(&mut self) {
        self.domain.retire(self.saved.take());
    }
}

struct GlobalRetirement<'a, B, M, A> {
    domain: &'a MonitorDomain<B, M, A>,
    saved: Option<GlobalMark<B, M, A>>,
    cell: Option<Arc<EventCell<B>>>,
    open: bool,
}
impl<B, M, A> Drop for GlobalRetirement<'_, B, M, A> {
    fn drop(&mut self) {
        self.domain
            .finish_global(self.saved.take(), self.cell.as_ref(), self.open);
    }
}

/// Retains every physical writer gate without changing bytes or reservations.
/// Only the canonical memory owner uses this while native frames are recovered.
/// No monitor operation may reenter while the guard is held.
pub(in crate::memory) struct FrozenWriters<'a, B, M, A> {
    domain: &'a MonitorDomain<B, M, A>,
    _gates: Vec<MutexGuard<'a, Entries<B>>>,
}

impl<B, M, A> FrozenWriters<'_, B, M, A> {
    /// Fail before releasing gates, including writers which already passed an
    /// outer memory-system check and are now waiting for their physical gate.
    pub(in crate::memory) fn fail(&self) {
        self.domain.failed.store(true, Ordering::Release);
    }
    pub(in crate::memory) fn validate_current(&self) -> Result<(), MonitorError> {
        self.domain.check_execution()
    }
}

impl<B, M, A> MonitorDomain<B, M, A> {
    pub fn new(erg_bytes: u64, stripe_count: usize) -> Result<Arc<Self>, MonitorError> {
        if !(MIN_ERG_BYTES..=MAX_ERG_BYTES).contains(&erg_bytes) || !erg_bytes.is_power_of_two() {
            return Err(MonitorError::InvalidErg);
        }
        if stripe_count == 0 {
            return Err(MonitorError::InvalidStripeCount);
        }
        Ok(Arc::new(Self {
            erg_bytes,
            stripes: (0..stripe_count)
                .map(|_| Mutex::new(BTreeMap::new()))
                .collect(),
            failed: AtomicBool::new(false),
            mapping: PhantomData,
        }))
    }

    pub fn thread(self: &Arc<Self>) -> ThreadMonitor<B, M, A> {
        ThreadMonitor {
            domain: Arc::clone(self),
            reservation: None,
            global: None,
            event: None,
        }
    }

    /// Bind one PE endpoint while the context has no reservation or binding.
    /// The endpoint can be bound to only one monitor domain.
    pub fn bind_events(
        &self,
        thread: &mut ThreadMonitor<B, M, A>,
        producer: &EventProducer,
    ) -> Result<(), MonitorError> {
        self.owner(thread)?;
        self.check_execution()?;
        if thread.event.is_some() {
            return Err(MonitorError::EventsAlreadyBound);
        }
        if thread.reservation.is_some() || thread.global.is_some() {
            return Err(MonitorError::ReservationActive);
        }
        let endpoint = producer
            .try_bind_monitor()
            .map_err(|_| MonitorError::EventBindingUnavailable)?;
        thread.event = Some(Arc::new(EventCell {
            endpoint,
            current: Mutex::new(EventState {
                epoch: Weak::new(),
                mapping: 0,
            }),
        }));
        Ok(())
    }

    /// Verify retained real endpoint identity; never rebind or mutate a mark.
    /// The higher owner borrows the live EventEndpoint for the complete entry.
    pub fn check_event_endpoint(
        &self,
        thread: &ThreadMonitor<B, M, A>,
        producer: &EventProducer,
    ) -> Result<(), MonitorError> {
        self.owner(thread)?;
        self.check_execution()?;
        let cell = thread.event.as_ref().ok_or(MonitorError::EventsUnbound)?;
        if cell.endpoint.same_endpoint(producer) {
            Ok(())
        } else {
            Err(MonitorError::WrongEventEndpoint)
        }
    }

    // Only monitor metadata mutexes; endpoint publication itself takes no lock.
    // Poison recovery is terminal teardown, never resumable guest execution.
    fn event_lock<'a, T>(&self, mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
        mutex.lock().unwrap_or_else(|error| {
            self.failed.store(true, Ordering::Release);
            error.into_inner()
        })
    }

    fn current_is(state: &EventState<B>, epoch: &Arc<Epoch<B>>) -> bool {
        core::ptr::eq(state.epoch.as_ptr(), Arc::as_ptr(epoch))
    }

    fn open_cell(
        &self,
        cell: &EventCell<B>,
        epoch: &Arc<Epoch<B>>,
        mapping: Option<usize>,
    ) -> bool {
        let mut current = self.event_lock(&cell.current);
        if Self::current_is(&current, epoch)
            && mapping.is_none_or(|mapping| current.mapping == mapping)
        {
            current.epoch = Weak::new();
            current.mapping = 0;
            // Concrete infallible atomic publication, no endpoint locks/callbacks.
            cell.endpoint.signal_local();
            true
        } else {
            false
        }
    }

    fn open_epoch(&self, epoch: &Arc<Epoch<B>>, mapping: Option<usize>) {
        let mut subscribers = self.event_lock(&epoch.subscribers);
        subscribers.retain(|subscriber| {
            let Some(cell) = subscriber.upgrade() else {
                return false;
            };
            if self.open_cell(&cell, epoch, mapping) {
                return false;
            }
            Self::current_is(&self.event_lock(&cell.current), epoch)
        });
    }

    fn subscribe(
        &self,
        epoch: &Arc<Epoch<B>>,
        cell: &Arc<EventCell<B>>,
        mapping: &Arc<Mapping<M, A>>,
    ) {
        let mut subscribers = self.event_lock(&epoch.subscribers);
        // Prune stale/dead entries; same reusable cell is never appended twice.
        subscribers.retain(|subscriber| {
            subscriber.upgrade().is_some_and(|other| {
                Arc::ptr_eq(&other, cell)
                    || Self::current_is(&self.event_lock(&other.current), epoch)
            })
        });
        {
            let mut current = self.event_lock(&cell.current);
            current.epoch = Arc::downgrade(epoch);
            current.mapping = Arc::as_ptr(mapping) as usize;
        }
        if !subscribers
            .iter()
            .any(|subscriber| Weak::ptr_eq(subscriber, &Arc::downgrade(cell)))
        {
            subscribers.push(Arc::downgrade(cell));
        }
    }

    fn finish_global(
        &self,
        mark: Option<GlobalMark<B, M, A>>,
        cell: Option<&Arc<EventCell<B>>>,
        open: bool,
    ) {
        let Some(mark) = mark else {
            return;
        };
        let key = Key::new(&mark.epoch.backing, mark.epoch.granule);
        let entries = self.stripes[self.stripe(key)]
            .lock()
            .unwrap_or_else(crate::platform::sync::PoisonError::into_inner);
        if let Some(cell) = cell {
            let mut subscribers = self.event_lock(&mark.epoch.subscribers);
            if open {
                self.open_cell(cell, &mark.epoch, Some(Arc::as_ptr(&mark.mapping) as usize));
            }
            // Same-Epoch retarget is still current: retain its reused subscriber.
            let still_current = Self::current_is(&self.event_lock(&cell.current), &mark.epoch);
            if !still_current {
                subscribers.retain(|subscriber| {
                    !Weak::ptr_eq(subscriber, &Arc::downgrade(cell))
                        && subscriber.strong_count() != 0
                });
            }
        }
        drop(entries);
        drop(mark);
        let mut entries = self.stripes[self.stripe(key)]
            .lock()
            .unwrap_or_else(crate::platform::sync::PoisonError::into_inner);
        if entries
            .get(&key)
            .is_some_and(|epoch| epoch.strong_count() == 0)
        {
            entries.remove(&key);
        }
    }

    fn stripe(&self, key: Key) -> usize {
        (key.backing.rotate_left(13) ^ key.granule as usize) % self.stripes.len()
    }

    /// Dispatch/helpers, including CLREX, must check execution viability. Clear
    /// and revocation remain available for teardown after a terminal failure.
    pub fn check_execution(&self) -> Result<(), MonitorError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(MonitorError::Poisoned);
        }
        Ok(())
    }

    fn lock(&self, stripe: usize) -> Result<MutexGuard<'_, Entries<B>>, MonitorError> {
        self.check_execution()?;
        let guard = self.stripes[stripe].lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            MonitorError::Poisoned
        })?;
        // A callback on another stripe may have unwound while this thread waited.
        self.check_execution()?;
        Ok(guard)
    }

    fn owner(&self, thread: &ThreadMonitor<B, M, A>) -> Result<(), MonitorError> {
        if !core::ptr::eq(self, Arc::as_ptr(&thread.domain)) {
            return Err(MonitorError::WrongDomain);
        }
        Ok(())
    }

    fn key(&self, access: &Access<B, M, A>) -> Result<Key, MonitorError> {
        if access.offset % self.erg_bytes + u64::from(access.bytes) > self.erg_bytes {
            return Err(MonitorError::CrossesGranule);
        }
        Ok(Key::new(&access.backing, access.offset / self.erg_bytes))
    }

    fn retire(&self, reservation: Option<Reservation<B, M, A>>) {
        let Some(reservation) = reservation else {
            return;
        };
        let key = Key::new(&reservation.epoch.backing, reservation.epoch.granule);
        // Drop before cleanup. Two simultaneous final clears must not both see
        // strong_count>1, leave the entry, then drop the last two references.
        drop(reservation);
        let mut entries = self.stripes[self.stripe(key)]
            .lock()
            .unwrap_or_else(crate::platform::sync::PoisonError::into_inner);
        if entries
            .get(&key)
            .is_some_and(|epoch| epoch.strong_count() == 0)
        {
            entries.remove(&key);
        }
    }

    pub(crate) fn prepare_clear<'a>(
        &'a self,
        thread: &'a mut ThreadMonitor<B, M, A>,
    ) -> Result<PreparedClear<'a, B, M, A>, MonitorError> {
        self.check_execution()?;
        self.owner(thread)?;
        Ok(PreparedClear {
            domain: self,
            thread,
        })
    }

    pub fn clear(&self, thread: &mut ThreadMonitor<B, M, A>) -> Result<(), MonitorError> {
        let _failure = FailureBoundary(&self.failed);
        self.owner(thread)?;
        self.retire(thread.reservation.take());
        Ok(())
    }

    pub fn load<T, E>(
        &self,
        thread: &mut ThreadMonitor<B, M, A>,
        access: &Access<B, M, A>,
        read: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, AccessError<E>> {
        self.load_with_scope(thread, access, ReservationScope::Local, read)
    }

    pub fn load_with_scope<T, E>(
        &self,
        thread: &mut ThreadMonitor<B, M, A>,
        access: &Access<B, M, A>,
        scope: ReservationScope,
        read: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, AccessError<E>> {
        let _failure = FailureBoundary(&self.failed);
        self.owner(thread)?;
        let key = self.key(access)?;
        if scope == ReservationScope::Global && thread.event.is_none() {
            return Err(MonitorError::EventsUnbound.into());
        }
        // Local replacement never itself opens the independent global mark.
        self.retire(thread.reservation.take());
        let mut old_global = GlobalRetirement {
            domain: self,
            saved: None,
            cell: thread.event.clone(),
            open: false,
        };
        let mut pending = LocalRetirement {
            domain: self,
            saved: None,
        };
        let value = {
            let mut entries = self.lock(self.stripe(key))?;
            let _gate_failure = FailureBoundary(&self.failed);
            if !access.mapping.is_live() {
                return Err(MonitorError::DeadMapping.into());
            }
            // Error/panic leaves the prior global hold and current cell intact.
            let value = read().map_err(AccessError::Memory)?;
            let epoch = entries
                .get(&key)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| {
                    let epoch = Arc::new(Epoch {
                        backing: Arc::clone(&access.backing),
                        granule: key.granule,
                        subscribers: Mutex::new(Vec::new()),
                    });
                    entries.insert(key, Arc::downgrade(&epoch));
                    epoch
                });
            pending.saved = Some(Reservation {
                epoch: Arc::clone(&epoch),
                mapping: Arc::clone(&access.mapping),
                offset: access.offset,
                bytes: access.bytes,
                shape: access.shape,
            });
            if scope == ReservationScope::Global {
                let cell = thread
                    .event
                    .as_ref()
                    .expect("global scope preflighted binding");
                self.subscribe(&epoch, cell, &access.mapping);
                old_global.saved = thread.global.replace(GlobalMark {
                    epoch,
                    mapping: Arc::clone(&access.mapping),
                });
            }
            self.check_execution()?;
            value
        };
        thread.reservation = pending.saved.take();
        drop(old_global); // Old stripe reacquisition occurs after new gate release.
        Ok(value)
    }

    pub fn store<T, E>(
        &self,
        thread: &mut ThreadMonitor<B, M, A>,
        access: &Access<B, M, A>,
        write: impl FnOnce() -> Result<T, E>,
    ) -> Result<ConditionalWrite<T>, AccessError<E>>
    where
        A: PartialEq,
    {
        let _failure = FailureBoundary(&self.failed);
        self.owner(thread)?;
        let key = self.key(access)?;
        let saved = LocalRetirement {
            domain: self,
            saved: thread.reservation.take(),
        };
        let result = {
            let mut entries = self.lock(self.stripe(key))?;
            let _gate_failure = FailureBoundary(&self.failed);
            if !access.mapping.is_live() {
                Err(MonitorError::DeadMapping.into())
            } else {
                let valid = saved.saved.as_ref().is_some_and(|saved| {
                    saved.mapping.is_live()
                        && saved.mapping.attributes == access.mapping.attributes
                        && saved.offset == access.offset
                        && saved.bytes == access.bytes
                        && saved.shape == access.shape
                        && entries
                            .get(&key)
                            .and_then(Weak::upgrade)
                            .is_some_and(|epoch| Arc::ptr_eq(&saved.epoch, &epoch))
                });
                if valid {
                    // Consume and invalidate before the attempted conditional
                    // write; a callback fault cannot leave a reusable mark.
                    entries.remove(&key);
                    self.open_epoch(
                        &saved.saved.as_ref().expect("valid saved reservation").epoch,
                        None,
                    );
                    self.check_execution()?;
                    write()
                        .map(ConditionalWrite::Stored)
                        .map_err(AccessError::Memory)
                } else {
                    Ok(ConditionalWrite::Failed)
                }
            }
        };
        drop(saved);
        // Stored and Failed are the only retired conditional outcomes. Errors
        // are not silently classified as retired StoreExcl or taken DataAbort.
        if result.is_ok() {
            self.finish_global(thread.global.take(), thread.event.as_ref(), true);
        }
        result
    }

    fn writer_stripes(&self, range: &WriteRange<B>) -> Vec<usize> {
        let first = range.offset / self.erg_bytes;
        let last = (range.offset + range.bytes - 1) / self.erg_bytes;
        if last - first >= self.stripes.len() as u64 - 1 {
            return (0..self.stripes.len()).collect();
        }
        let mut stripes: Vec<_> = (first..=last)
            .map(|granule| self.stripe(Key::new(&range.backing, granule)))
            .collect();
        stripes.sort_unstable();
        stripes.dedup();
        stripes
    }

    fn invalidate(&self, entries: &mut Entries<B>, range: &WriteRange<B>) {
        let backing = Arc::as_ptr(&range.backing) as usize;
        let first = range.offset / self.erg_bytes;
        let last = (range.offset + range.bytes - 1) / self.erg_bytes;
        // Bound work by live reservation metadata, not bytes/ERG in a large
        // copyout. Gate collisions never invalidate unrelated physical keys.
        entries.retain(|key, epoch| {
            if key.backing == backing && (first..=last).contains(&key.granule) {
                if let Some(epoch) = epoch.upgrade() {
                    self.open_epoch(&epoch, None);
                }
                false
            } else {
                epoch.strong_count() != 0
            }
        });
    }

    /// Hold every physical writer gate for an observer with no architectural
    /// store. A native atomic-read recipe may perform permitted unchanged-value
    /// host writeback, but must not mutate data or retire a source reservation.
    /// Source writes must continue to use `with_writer`/`store` instead.
    pub(in crate::memory) fn with_observer<T, E>(
        &self,
        range: &WriteRange<B>,
        read: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, AccessError<E>> {
        let _failure = FailureBoundary(&self.failed);
        let first = range.offset / self.erg_bytes;
        let last = (range.offset + range.bytes - 1) / self.erg_bytes;
        if first == last {
            let key = Key::new(&range.backing, first);
            let _gate = self.lock(self.stripe(key))?;
            let _gate_failure = FailureBoundary(&self.failed);
            let result = read().map_err(AccessError::Memory)?;
            self.check_execution()?;
            return Ok(result);
        }
        // Same stable order as writers, including aliases and shared ERGs.
        let _gates: Vec<_> = self
            .writer_stripes(range)
            .into_iter()
            .map(|stripe| self.lock(stripe))
            .collect::<Result<_, _>>()?;
        let _gate_failure = FailureBoundary(&self.failed);
        let result = read().map_err(AccessError::Memory)?;
        self.check_execution()?;
        Ok(result)
    }

    pub fn with_writer<T, E>(
        &self,
        range: &WriteRange<B>,
        policy: Invalidation,
        write: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, AccessError<E>> {
        let _failure = FailureBoundary(&self.failed);
        let first = range.offset / self.erg_bytes;
        let last = (range.offset + range.bytes - 1) / self.erg_bytes;
        if first == last {
            // The usual architectural part touches one reservation granule.
            // Keep its guard on the stack instead of allocating two vectors.
            let key = Key::new(&range.backing, first);
            let mut entries = self.lock(self.stripe(key))?;
            let _gate_failure = FailureBoundary(&self.failed);
            if policy == Invalidation::BeforeAttempt {
                self.invalidate(&mut entries, range);
                self.check_execution()?;
            }
            let result = write();
            if policy == Invalidation::OnCommit && result.is_ok() {
                self.invalidate(&mut entries, range);
                self.check_execution()?;
            }
            return result.map_err(AccessError::Memory);
        }
        let stripes = self.writer_stripes(range);
        // Stable acquisition order prevents cycles for cross-granule fragments.
        let mut guards: Vec<_> = stripes
            .into_iter()
            .map(|stripe| self.lock(stripe))
            .collect::<Result<_, _>>()?;
        let _gate_failure = FailureBoundary(&self.failed);
        if policy == Invalidation::BeforeAttempt {
            for entries in &mut guards {
                self.invalidate(entries, range);
            }
            self.check_execution()?;
        }
        let result = write();
        if policy == Invalidation::OnCommit && result.is_ok() {
            for entries in &mut guards {
                self.invalidate(entries, range);
            }
            self.check_execution()?;
        }
        result.map_err(AccessError::Memory)
    }

    /// Nonblocking acquisition in the same ascending order as cross-granule
    /// writers. Busy acquisition releases its prefix, performs no callback and
    /// does not invalidate a reservation. Poisoning remains terminal.
    pub(in crate::memory) fn try_freeze_writers(
        &self,
    ) -> Result<Option<FrozenWriters<'_, B, M, A>>, MonitorError> {
        self.check_execution()?;
        let mut gates = Vec::with_capacity(self.stripes.len());
        for stripe in &self.stripes {
            #[cfg(feature = "std")]
            let gate = match stripe.try_lock() {
                Ok(gate) => gate,
                Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    self.failed.store(true, Ordering::Release);
                    return Err(MonitorError::Poisoned);
                }
            };
            #[cfg(not(feature = "std"))]
            let gate = match stripe.try_lock() {
                Ok(gate) => gate,
                Err(_) => return Ok(None),
            };
            gates.push(gate);
        }
        self.check_execution()?;
        Ok(Some(FrozenWriters {
            domain: self,
            _gates: gates,
        }))
    }

    pub fn revoke_mapping(&self, mapping: &Mapping<M, A>) -> Result<(), MonitorError> {
        let _failure = FailureBoundary(&self.failed);
        // Declare before gates so generic backing payload destruction is outside all gates.
        let mut deferred_epochs = Vec::new();
        let _guards = self
            .stripes
            .iter()
            .map(|stripe| stripe.lock().map_err(|_| MonitorError::Poisoned))
            .collect::<Result<Vec<_>, _>>()?;
        mapping.live.store(false, Ordering::Release);
        // Finite mapping-lifetime spurious opening; not universal ISA semantics.
        for entries in &_guards {
            for weak in entries.values() {
                if let Some(epoch) = weak.upgrade() {
                    self.open_epoch(&epoch, Some(core::ptr::from_ref(mapping) as usize));
                    deferred_epochs.push(epoch);
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.stripes
            .iter()
            .map(|stripe| stripe.lock().unwrap().len())
            .sum()
    }
}

impl<B, M, A> Drop for ThreadMonitor<B, M, A> {
    fn drop(&mut self) {
        let _failure = FailureBoundary(&self.domain.failed);
        self.domain.retire(self.reservation.take());
        // Finite PE-owner teardown opening under B2.12.5, with mandatory event.
        self.domain
            .finish_global(self.global.take(), self.event.as_ref(), true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;

    const TEST_ERG_BYTES: u64 = 64;
    const TEST_STRIPES: usize = 8;
    type Domain = MonitorDomain<(), (), u8>;
    type TestAccess = Access<(), (), u8>;
    type TestThread = ThreadMonitor<(), (), u8>;

    fn fixture(erg: u64, stripes: usize) -> (Arc<Domain>, Arc<()>, Arc<Mapping<(), u8>>) {
        (
            Domain::new(erg, stripes).unwrap(),
            Arc::new(()),
            Mapping::new(Arc::new(()), 0),
        )
    }

    fn access(backing: &Arc<()>, mapping: &Arc<Mapping<(), u8>>, offset: u64) -> TestAccess {
        Access::new(
            Arc::clone(backing),
            Arc::clone(mapping),
            offset,
            8,
            Shape::Scalar,
        )
        .unwrap()
    }

    fn load(domain: &Domain, thread: &mut TestThread, access: &TestAccess) {
        domain.load(thread, access, || Ok::<_, ()>(())).unwrap();
    }

    fn store(domain: &Domain, thread: &mut TestThread, access: &TestAccess) -> bool {
        matches!(
            domain.store(thread, access, || Ok::<_, ()>(())).unwrap(),
            ConditionalWrite::Stored(())
        )
    }

    #[test]
    fn all_writer_hold_is_nonblocking_releases_busy_prefix_and_preserves_marks() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let original = access(&backing, &mapping, 0);
        let mut thread = domain.thread();
        load(&domain, &mut thread, &original);
        let last = domain.stripes.last().unwrap().lock().unwrap();
        assert!(domain.try_freeze_writers().unwrap().is_none());
        for stripe in &domain.stripes[..TEST_STRIPES - 1] {
            assert!(stripe.try_lock().is_ok());
        }
        drop(last);
        let hold = domain.try_freeze_writers().unwrap().unwrap();
        hold.validate_current().unwrap();
        assert!(
            domain
                .stripes
                .iter()
                .all(|stripe| stripe.try_lock().is_err())
        );
        assert!(domain.try_freeze_writers().unwrap().is_none());
        drop(hold);
        assert!(store(&domain, &mut thread, &original));
    }

    #[test]
    fn failed_all_writer_hold_denies_waiting_callback_before_any_byte_effect() {
        use std::{sync::mpsc, time::Duration};
        let (domain, backing, _) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let hold = domain.try_freeze_writers().unwrap().unwrap();
        let calls = AtomicUsize::new(0);
        let (started, ready) = mpsc::channel();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                let range = WriteRange::new(backing, 0, 8).unwrap();
                started.send(()).unwrap();
                domain.with_writer(&range, Invalidation::BeforeAttempt, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(())
                })
            });
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            hold.fail();
            drop(hold);
            assert_eq!(
                writer.join().unwrap(),
                Err(AccessError::Monitor(MonitorError::Poisoned))
            );
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn all_writer_hold_refuses_poison_without_a_completion() {
        let (domain, _, _) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let poisoned = Arc::clone(&domain);
        assert!(
            std::thread::spawn(move || {
                let _gate = poisoned.stripes[TEST_STRIPES - 1].lock().unwrap();
                panic!("deliberately poison the actual writer gate");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            domain.try_freeze_writers(),
            Err(MonitorError::Poisoned)
        ));
        assert_eq!(domain.check_execution(), Err(MonitorError::Poisoned));
        assert!(domain.stripes[0].try_lock().is_ok());
    }

    #[test]
    fn same_value_aba_and_replacement_invalidate_without_a_version_counter() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let first = access(&backing, &mapping, 0);
        let other = access(&backing, &mapping, TEST_ERG_BYTES);
        let range = WriteRange::new(Arc::clone(&backing), 0, 8).unwrap();
        let mut thread = domain.thread();
        for writes in [1, 2, 100] {
            load(&domain, &mut thread, &first);
            for _ in 0..writes {
                domain
                    .with_writer(&range, Invalidation::OnCommit, || Ok::<_, ()>(()))
                    .unwrap();
            }
            assert!(!store(&domain, &mut thread, &first));
        }
        load(&domain, &mut thread, &first);
        load(&domain, &mut thread, &other);
        assert!(!store(&domain, &mut thread, &first));
        load(&domain, &mut thread, &first);
        assert!(store(&domain, &mut thread, &first));
        assert!(!store(&domain, &mut thread, &first));
        assert_eq!(domain.entry_count(), 0);
    }

    #[test]
    fn aliases_lifetimes_attributes_and_shapes_are_independent() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let alias_mapping = Mapping::new(Arc::new(()), 0);
        let different_attributes = Mapping::new(Arc::new(()), 1);
        let original = access(&backing, &mapping, 0);
        let alias = access(&backing, &alias_mapping, 0);
        let mismatch = access(&backing, &different_attributes, 0);
        let cow = access(&Arc::new(()), &alias_mapping, 0);
        let pair = Access::new(
            Arc::clone(&backing),
            Arc::clone(&mapping),
            0,
            8,
            Shape::Pair,
        )
        .unwrap();
        let mut thread = domain.thread();
        load(&domain, &mut thread, &original);
        assert!(store(&domain, &mut thread, &alias));
        for target in [&mismatch, &cow, &pair] {
            load(&domain, &mut thread, &original);
            assert!(!store(&domain, &mut thread, target));
        }
        load(&domain, &mut thread, &original);
        domain.revoke_mapping(&mapping).unwrap();
        assert!(!store(&domain, &mut thread, &alias));
        assert_eq!(
            domain.load(&mut thread, &original, || Ok::<_, ()>(())),
            Err(AccessError::Monitor(MonitorError::DeadMapping))
        );
        load(&domain, &mut thread, &alias);
        assert!(store(&domain, &mut thread, &alias));
    }

    #[test]
    fn clear_and_drop_remove_dead_metadata_and_retain_real_lifetimes() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let weak_backing = Arc::downgrade(&backing);
        let weak_mapping_payload = Arc::downgrade(mapping.payload());
        let original = access(&backing, &mapping, 0);
        let mut thread = domain.thread();
        load(&domain, &mut thread, &original);
        drop(original);
        drop(backing);
        drop(mapping);
        assert!(weak_backing.upgrade().is_some());
        assert!(weak_mapping_payload.upgrade().is_some());
        domain.clear(&mut thread).unwrap();
        assert!(weak_backing.upgrade().is_none());
        assert!(weak_mapping_payload.upgrade().is_none());
        assert_eq!(domain.entry_count(), 0);
        let (other, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        for offset in 0..1000 {
            let mut thread = other.thread();
            load(
                &other,
                &mut thread,
                &access(&backing, &mapping, offset * TEST_ERG_BYTES),
            );
            assert_eq!(other.entry_count(), 1);
            drop(thread);
            assert_eq!(other.entry_count(), 0);
        }
    }

    #[test]
    fn callback_faults_have_explicit_invalidation_policy() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let original = access(&backing, &mapping, 0);
        let range = WriteRange::new(Arc::clone(&backing), 0, 8).unwrap();
        let mut thread = domain.thread();
        load(&domain, &mut thread, &original);
        assert_eq!(
            domain.with_writer(&range, Invalidation::OnCommit, || Err::<(), _>(7)),
            Err(AccessError::Memory(7))
        );
        assert!(store(&domain, &mut thread, &original));
        load(&domain, &mut thread, &original);
        assert_eq!(
            domain.with_writer(&range, Invalidation::BeforeAttempt, || Err::<(), _>(7)),
            Err(AccessError::Memory(7))
        );
        assert!(!store(&domain, &mut thread, &original));
        load(&domain, &mut thread, &original);
        assert_eq!(
            domain.load(&mut thread, &original, || Err::<(), _>(9)),
            Err(AccessError::Memory(9))
        );
        assert!(!store(&domain, &mut thread, &original));
        load(&domain, &mut thread, &original);
        assert_eq!(
            domain.store(&mut thread, &original, || Err::<(), _>(11)),
            Err(AccessError::Memory(11))
        );
        assert!(!store(&domain, &mut thread, &original));
        assert_eq!(domain.entry_count(), 0);
    }

    #[test]
    fn only_reached_prefix_and_physical_granules_are_invalidated() {
        let (domain, backing, mapping) = fixture(16, 1);
        let first = access(&backing, &mapping, 0);
        let second = access(&backing, &mapping, 16);
        let mut a = domain.thread();
        let mut b = domain.thread();
        load(&domain, &mut a, &first);
        load(&domain, &mut b, &second);
        domain
            .with_writer(
                &WriteRange::new(Arc::clone(&backing), 0, 8).unwrap(),
                Invalidation::OnCommit,
                || Ok::<_, ()>(()),
            )
            .unwrap();
        domain
            .with_writer(
                &WriteRange::new(Arc::clone(&backing), 16, 8).unwrap(),
                Invalidation::OnCommit,
                || Err::<(), _>(()),
            )
            .unwrap_err();
        assert!(!store(&domain, &mut a, &first));
        assert!(store(&domain, &mut b, &second));
    }

    #[test]
    fn concurrent_competing_stores_have_exactly_one_success() {
        const TRIALS: usize = 128;
        for _ in 0..TRIALS {
            let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
            let barrier = Arc::new(Barrier::new(2));
            let calls = Arc::new(AtomicUsize::new(0));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let domain = Arc::clone(&domain);
                    let backing = Arc::clone(&backing);
                    let mapping = Arc::clone(&mapping);
                    let barrier = Arc::clone(&barrier);
                    let calls = Arc::clone(&calls);
                    std::thread::spawn(move || {
                        let mut thread = domain.thread();
                        let access = access(&backing, &mapping, 0);
                        load(&domain, &mut thread, &access);
                        barrier.wait();
                        domain
                            .store(&mut thread, &access, || {
                                calls.fetch_add(1, Ordering::Relaxed);
                                Ok::<_, ()>(())
                            })
                            .unwrap()
                    })
                })
                .collect();
            let successes = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|result| matches!(result, ConditionalWrite::Stored(())))
                .count();
            assert_eq!(successes, 1);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            assert_eq!(domain.entry_count(), 0);
        }
    }

    #[test]
    fn concurrent_hash_collisions_never_share_invalidation() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, 1);
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let domain = Arc::clone(&domain);
                let backing = Arc::clone(&backing);
                let mapping = Arc::clone(&mapping);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut thread = domain.thread();
                    let access = access(&backing, &mapping, index * TEST_ERG_BYTES);
                    load(&domain, &mut thread, &access);
                    barrier.wait();
                    store(&domain, &mut thread, &access)
                })
            })
            .collect();
        for handle in handles {
            assert!(handle.join().unwrap());
        }
        assert_eq!(domain.entry_count(), 0);
    }

    #[test]
    fn concurrent_final_drops_leave_no_weak_metadata() {
        const THREADS: usize = 16;
        const ROUNDS: usize = 64;
        for _ in 0..ROUNDS {
            let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let domain = Arc::clone(&domain);
                    let backing = Arc::clone(&backing);
                    let mapping = Arc::clone(&mapping);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let mut thread = domain.thread();
                        load(&domain, &mut thread, &access(&backing, &mapping, 0));
                        barrier.wait();
                        drop(thread);
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
            assert_eq!(domain.entry_count(), 0);
        }
    }

    #[test]
    fn cross_granule_writer_orders_stripes_and_invalidates_both_edges() {
        let (domain, backing, mapping) = fixture(16, TEST_STRIPES);
        let first = access(&backing, &mapping, 0);
        let second = access(&backing, &mapping, 32);
        let unaffected = access(&backing, &mapping, 64);
        let mut a = domain.thread();
        let mut b = domain.thread();
        let mut c = domain.thread();
        load(&domain, &mut a, &first);
        load(&domain, &mut b, &second);
        load(&domain, &mut c, &unaffected);
        domain
            .with_writer(
                &WriteRange::new(Arc::clone(&backing), 15, 18).unwrap(),
                Invalidation::OnCommit,
                || Ok::<_, ()>(()),
            )
            .unwrap();
        assert!(!store(&domain, &mut a, &first));
        assert!(!store(&domain, &mut b, &second));
        assert!(store(&domain, &mut c, &unaffected));
    }

    #[test]
    fn malformed_bindings_and_wrong_domain_do_not_execute_callbacks() {
        for erg in [0, 8, 17, 4096] {
            assert!(matches!(Domain::new(erg, 1), Err(MonitorError::InvalidErg)));
        }
        assert!(matches!(
            Domain::new(16, 0),
            Err(MonitorError::InvalidStripeCount)
        ));
        let (domain, backing, mapping) = fixture(16, TEST_STRIPES);
        let (other, _, _) = fixture(16, TEST_STRIPES);
        let mut thread = domain.thread();
        let access = access(&backing, &mapping, 0);
        assert_eq!(
            other.load(&mut thread, &access, || panic!("wrong-domain callback")),
            Err::<(), _>(AccessError::<()>::Monitor(MonitorError::WrongDomain))
        );
        assert!(matches!(
            Access::new(
                Arc::clone(&backing),
                Arc::clone(&mapping),
                0,
                16,
                Shape::Scalar
            ),
            Err(MonitorError::InvalidShape)
        ));
        assert!(matches!(
            WriteRange::new(Arc::clone(&backing), u64::MAX, 1),
            Err(MonitorError::InvalidRange)
        ));
        let crossing = Access::new(backing, mapping, 15, 8, Shape::Scalar).unwrap();
        assert_eq!(
            domain.load(&mut thread, &crossing, || panic!("cross-granule callback")),
            Err::<(), _>(AccessError::<()>::Monitor(MonitorError::CrossesGranule))
        );
    }

    #[test]
    fn poisoned_callback_is_an_explicit_terminal_domain_error() {
        let (domain, backing, mapping) = fixture(TEST_ERG_BYTES, TEST_STRIPES);
        let range = WriteRange::new(Arc::clone(&backing), 0, 8).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ =
                domain.with_writer(&range, Invalidation::BeforeAttempt, || -> Result<(), ()> {
                    panic!("intentional callback panic")
                });
        }));
        assert!(caught.is_err());
        assert_eq!(domain.check_execution(), Err(MonitorError::Poisoned));
        let poisoned_stripe = domain.stripe(Key::new(&backing, 0));
        let another_granule = (1..100)
            .find(|granule| domain.stripe(Key::new(&backing, *granule)) != poisoned_stripe)
            .unwrap();
        let mut thread = domain.thread();
        assert_eq!(
            domain.load(
                &mut thread,
                &access(&backing, &mapping, another_granule * TEST_ERG_BYTES),
                || Ok::<_, ()>(())
            ),
            Err(AccessError::Monitor(MonitorError::Poisoned))
        );
        assert_eq!(
            domain.load(&mut thread, &access(&backing, &mapping, 0), || Ok::<_, ()>(
                ()
            )),
            Err(AccessError::Monitor(MonitorError::Poisoned))
        );
    }
}
