//! Physical exclusive-monitor bookkeeping for a participating memory domain.
//! This owner alone does not establish an executable exclusive-memory profile.
//!
//! The caller owns backing bytes, permission/translation preflight and stable
//! mapping pins. Callbacks perform exactly one architectural access/fragment
//! through an audited native memory boundary, never concurrent Rust `&mut` RAM.
//! No callback may reenter this domain or drop one of its thread contexts.
//! Native faults need root's actual resumable cleanup boundary; Rust unwinding
//! fails the whole execution domain and does not stand in for signal recovery.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

type Entries<B> = HashMap<Key, Weak<Epoch<B>>>;

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
        if std::thread::panicking() {
            self.0.store(true, Ordering::Release);
        }
    }
}

/// Gates serialize only bounded callbacks, never a load-exclusive/store-exclusive
/// sequence. Hash collisions share a gate, never reservation identity.
/// std::Mutex fairness is unspecified: progress admission remains unproven.
pub struct MonitorDomain<B, M, A> {
    erg_bytes: u64,
    stripes: Vec<Mutex<Entries<B>>>,
    failed: AtomicBool,
    mapping: PhantomData<fn() -> (M, A)>,
}

pub struct ThreadMonitor<B, M, A> {
    domain: Arc<MonitorDomain<B, M, A>>,
    reservation: Option<Reservation<B, M, A>>,
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
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            failed: AtomicBool::new(false),
            mapping: PhantomData,
        }))
    }

    pub fn thread(self: &Arc<Self>) -> ThreadMonitor<B, M, A> {
        ThreadMonitor {
            domain: Arc::clone(self),
            reservation: None,
        }
    }

    fn stripe(&self, key: Key) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.stripes.len()
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
        if !std::ptr::eq(self, Arc::as_ptr(&thread.domain)) {
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
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&key)
            .is_some_and(|epoch| epoch.upgrade().is_none())
        {
            entries.remove(&key);
        }
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
        let _failure = FailureBoundary(&self.failed);
        self.owner(thread)?;
        let key = self.key(access)?;
        self.retire(thread.reservation.take());
        let mut entries = self.lock(self.stripe(key))?;
        let _gate_failure = FailureBoundary(&self.failed);
        if !access.mapping.is_live() {
            return Err(MonitorError::DeadMapping.into());
        }
        let value = read().map_err(AccessError::Memory)?;
        let epoch = entries
            .get(&key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let epoch = Arc::new(Epoch {
                    backing: Arc::clone(&access.backing),
                    granule: key.granule,
                });
                entries.insert(key, Arc::downgrade(&epoch));
                epoch
            });
        thread.reservation = Some(Reservation {
            epoch,
            mapping: Arc::clone(&access.mapping),
            offset: access.offset,
            bytes: access.bytes,
            shape: access.shape,
        });
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
        let saved = thread.reservation.take();
        let result = {
            let mut entries = self.lock(self.stripe(key))?;
            let _gate_failure = FailureBoundary(&self.failed);
            if !access.mapping.is_live() {
                Err(MonitorError::DeadMapping.into())
            } else {
                let valid = saved.as_ref().is_some_and(|saved| {
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
                    write()
                        .map(ConditionalWrite::Stored)
                        .map_err(AccessError::Memory)
                } else {
                    Ok(ConditionalWrite::Failed)
                }
            }
        };
        self.retire(saved);
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
            !(key.backing == backing && (first..=last).contains(&key.granule))
                && epoch.strong_count() != 0
        });
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
            }
            let result = write();
            if policy == Invalidation::OnCommit && result.is_ok() {
                self.invalidate(&mut entries, range);
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
        }
        let result = write();
        if policy == Invalidation::OnCommit && result.is_ok() {
            for entries in &mut guards {
                self.invalidate(entries, range);
            }
        }
        result.map_err(AccessError::Memory)
    }

    pub fn revoke_mapping(&self, mapping: &Mapping<M, A>) -> Result<(), MonitorError> {
        let _failure = FailureBoundary(&self.failed);
        let _guards = self
            .stripes
            .iter()
            .map(|stripe| stripe.lock().map_err(|_| MonitorError::Poisoned))
            .collect::<Result<Vec<_>, _>>()?;
        mapping.live.store(false, Ordering::Release);
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
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let key = Key::new(&reservation.epoch.backing, reservation.epoch.granule);
        drop(reservation);
        // A poisoned domain remains poisoned and cannot execute again. Cleanup
        // may recover its bookkeeping guard solely to remove dead weak entries.
        let mut entries = self.domain.stripes[self.domain.stripe(key)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&key)
            .is_some_and(|epoch| epoch.upgrade().is_none())
        {
            entries.remove(&key);
        }
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
