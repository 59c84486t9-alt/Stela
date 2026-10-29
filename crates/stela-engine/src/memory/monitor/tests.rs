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
        let _ = domain.with_writer(&range, Invalidation::BeforeAttempt, || -> Result<(), ()> {
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
