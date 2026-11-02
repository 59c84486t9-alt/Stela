//! Real host-thread exclusion and kept graph lifetime around shared admission.
use super::*;
use core::sync::atomic::AtomicUsize;
extern crate std;

struct Owner {
    drops: Arc<AtomicUsize>,
    calls: AtomicUsize,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe extern "C" fn callback(context: *mut c_void) {
    // SAFETY: each admitted fixture retains this same Arc allocation in the
    // actual queue's owner. Admission itself must never invoke this function.
    let owner = unsafe { &*context.cast::<Owner>() };
    owner.calls.fetch_add(1, Ordering::Relaxed);
}
fn owner() -> (Arc<Owner>, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    (
        Arc::new(Owner {
            drops: drops.clone(),
            calls: AtomicUsize::new(0),
        }),
        drops,
    )
}

#[test]
fn bounded_admission_preserves_native_policy_without_delivering_callbacks() {
    let (owner, drops) = owner();
    let execution = HostedExecution::new();
    let queue = HostedQueue::<4>::new(execution, owner.clone()).unwrap();
    let context = Arc::as_ptr(&owner).cast_mut().cast();
    let mut tickets = alloc::vec::Vec::new();
    for _ in 0..3 {
        // SAFETY: actual queue and local Arc retain the callback's same owner.
        tickets.push(unsafe { queue.execute(Kind::General, callback, context) }.unwrap());
    }
    // Ordinary admission shares all four slots, exactly as the native ordinary
    // constructor does before an executor selects reserved-role geometry.
    // SAFETY: same exact owner retained through all queued callbacks.
    tickets.push(unsafe { queue.execute(Kind::Notify, callback, context) }.unwrap());
    assert_eq!(
        // SAFETY: same kept callback; all four admission slots are occupied.
        unsafe { queue.execute(Kind::General, callback, context) },
        Err(WorkError::Full)
    );
    assert_eq!(
        // SAFETY: same kept callback; rejection transfers no context owner.
        unsafe { queue.execute(Kind::Notify, callback, context) },
        Err(WorkError::Full)
    );
    assert!(
        tickets
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
    for ticket in tickets {
        assert_eq!(queue.completed(ticket), Ok(false));
    }
    queue.close().unwrap();
    // SAFETY: this sole producer is stopped. Pending work must refuse release;
    // there is no fabricated current/continuation or completion in this fixture.
    assert_eq!(unsafe { queue.retire() }, Err(WorkError::Busy));
    assert_eq!(owner.calls.load(Ordering::Relaxed), 0);
    drop(queue);
    drop(owner);
    assert_eq!(
        drops.load(Ordering::Relaxed),
        0,
        "pending original owner remains retained"
    );
}

#[test]
fn ticket_identity_and_close_do_not_create_completion_or_retirement() {
    let execution = HostedExecution::new();
    let (owner, drops) = owner();
    let queue = HostedQueue::<2>::new(execution.clone(), owner.clone()).unwrap();
    let other = HostedQueue::<2>::new(execution, owner.clone()).unwrap();
    // SAFETY: same original retained allocation and this sole producer.
    let ticket = unsafe {
        queue.execute(
            Kind::General,
            callback,
            Arc::as_ptr(&owner).cast_mut().cast(),
        )
    }
    .unwrap();
    assert_eq!(other.completed(ticket), Err(WorkError::InvalidTicket));
    assert_eq!(
        queue.completed(HostedTicket {
            queue: queue.id,
            sequence: 0
        }),
        Err(WorkError::InvalidTicket)
    );
    queue.close().unwrap();
    assert_eq!(
        // SAFETY: same kept callback/context; closed admission transfers nothing.
        unsafe {
            queue.execute(
                Kind::Notify,
                callback,
                Arc::as_ptr(&owner).cast_mut().cast(),
            )
        },
        Err(WorkError::Closed)
    );
    assert_eq!(queue.completed(ticket), Ok(false));
    other.close().unwrap();
    // SAFETY: other has never published a job or executor; no producer remains.
    unsafe { other.retire() }.unwrap();
    drop(other);
    drop(queue);
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn foreign_thread_refuses_before_queue_state_and_callbacks_then_original_thread_retires() {
    let execution = HostedExecution::new();
    let (owner, drops) = owner();
    let queue = HostedQueue::<4>::new(execution.clone(), owner.clone()).unwrap();
    let foreign = queue.clone();
    let kept = owner.clone();
    std::thread::spawn(move || {
        assert_eq!(
            // SAFETY: actual queue and Arc keep this same context. The foreign
            // thread must be refused before changing any shared policy state.
            unsafe {
                foreign.execute(
                    Kind::General,
                    callback,
                    Arc::as_ptr(&kept).cast_mut().cast(),
                )
            },
            Err(WorkError::WrongCpu)
        );
        assert_eq!(foreign.close(), Err(WorkError::WrongCpu));
        assert_eq!(
            foreign.completed(HostedTicket {
                queue: foreign.id,
                sequence: 1
            }),
            Err(WorkError::WrongCpu)
        );
        assert!(matches!(
            HostedQueue::<4>::new(execution, kept),
            Err(WorkError::WrongCpu)
        ));
    })
    .join()
    .unwrap();
    assert_eq!(owner.calls.load(Ordering::Relaxed), 0);
    queue.close().unwrap();
    // SAFETY: original checked thread, no publication or live producer.
    unsafe { queue.retire() }.unwrap();
    assert_eq!(queue.close(), Err(WorkError::Closed));
    drop(queue);
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn even_retired_foreign_thread_drop_keeps_thread_affine_original_roots() {
    let (owner, drops) = owner();
    let queue = HostedQueue::<4>::new(HostedExecution::new(), owner.clone()).unwrap();
    queue.close().unwrap();
    // SAFETY: original owner thread, no admitted callbacks or producers.
    unsafe { queue.retire() }.unwrap();
    std::thread::spawn(move || drop(queue)).join().unwrap();
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}
