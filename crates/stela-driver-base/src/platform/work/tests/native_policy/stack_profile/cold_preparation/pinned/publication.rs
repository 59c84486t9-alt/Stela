//! Pinned backing cannot release on creator or before actual child completion.
use super::*;
use crate::platform::work::PublishedGeneralStack;
use core::cell::UnsafeCell;
#[derive(Clone, Copy)]
enum Action {
    Release,
    Cancel,
    Drop,
    Forget,
    Overflow,
    Stale,
}
struct Publication {
    base: Arc<PinScene>,
    published: UnsafeCell<Option<PublishedGeneralStack<'static, 64>>>,
    child: AtomicUsize,
    probes: AtomicUsize,
    retained_context: AtomicU64,
    action: Action,
}
// SAFETY: test-only retention wrapper satisfies Queue's passive owner type.
// Its affine field is accessed solely by this fixture's checked callback CPU
// and successor dispatcher; no value/field is sent to another OS thread.
unsafe impl Send for Publication {}
// SAFETY: the same checked single-thread fixture serializes every UnsafeCell
// access; queue retention never reads or executes this affine field remotely.
unsafe impl Sync for Publication {}
unsafe extern "C" fn published_child(pointer: *mut c_void) {
    // SAFETY: the queue owns the same fixture before native publication.
    let f = unsafe { &*pointer.cast::<Publication>() };
    assert_eq!(f.base.pins_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(f.base.entered.load(Ordering::Acquire), 0);
    if matches!(f.action, Action::Release) {
        let binding = Arc::new(Binding {
            id: AtomicU64::new(0),
            blocked: AtomicBool::new(false),
        });
        let wake = f.base.runtime().bind_current(binding.clone()).unwrap();
        *f.base.binding.lock().unwrap() = Some((binding, wake));
    }
    f.child.fetch_add(1, Ordering::Release);
}
unsafe extern "C" fn unrelated(pointer: *mut c_void) {
    // SAFETY: the same queue-owned fixture survives every real probe callback.
    let f = unsafe { &*pointer.cast::<Publication>() };
    assert_ne!(
        f.base.runtime().current_context().unwrap().context_id,
        f.retained_context.load(Ordering::Acquire)
    );
    f.probes.fetch_add(1, Ordering::Release);
}
unsafe extern "C" fn publish_pinned(pointer: *mut c_void) {
    // SAFETY: the actual fixture and executor remain kept through both jobs.
    let f = unsafe { &*pointer.cast::<Publication>() };
    // SAFETY: this test stores the shared pin owner until the executor's exact
    // child join/release below. No raw view outlives that kept executor.
    let r: Pin<&'static Runtime<64>> = unsafe {
        Pin::new_unchecked(&*(f.base.runtime.load(Ordering::Acquire) as *const Runtime<64>))
    };
    let authority = f.base.authority();
    let owner = r
        .reserve_unstarted_general(&authority, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let cold = take_prepared(owner, &authority);
    let pinned = match cold.pin(&authority) {
        Ok(pin) => pin,
        Err(_) => panic!("valid pin refused"),
    };
    let ready = match pinned.reconstruct(&authority) {
        Ok(ready) => ready,
        Err(_) => panic!("valid frame refused"),
    };
    assert_eq!(f.base.pins_dropped.load(Ordering::Relaxed), 0);
    if matches!(f.action, Action::Cancel) {
        // SAFETY: no foreign descriptor/user or callback was ever published.
        unsafe { ready.cancel(&authority) }.unwrap();
        assert_eq!(f.base.pins_dropped.load(Ordering::Relaxed), 1);
        return;
    }
    if matches!(f.action, Action::Overflow | Action::Stale) {
        if matches!(f.action, Action::Overflow) {
            r.queue
                .published_stack_pins
                .store(usize::MAX, Ordering::Release);
        } else {
            f.base.active.store(false, Ordering::Release);
        }
        // SAFETY: scene/code are kept before attempted publication; injected
        // refusal must accept no callback and return the exact pin owner.
        let ready = match unsafe { ready.commit(&authority, published_child, pointer) } {
            Err((ready, error)) => {
                assert_eq!(
                    error,
                    if matches!(f.action, Action::Overflow) {
                        WorkError::Exhausted
                    } else {
                        WorkError::Unavailable
                    }
                );
                ready
            }
            _ => panic!("invalid pinned publication accepted"),
        };
        assert_eq!(f.child.load(Ordering::Acquire), 0);
        assert_eq!(f.base.pins_dropped.load(Ordering::Relaxed), 0);
        r.queue.published_stack_pins.store(0, Ordering::Release);
        f.base.active.store(true, Ordering::Release);
        // SAFETY: no descriptor or callback was accepted; fresh exact permission.
        unsafe { ready.cancel(&authority) }.unwrap();
        return;
    }
    // SAFETY: callback fits the qualified stack and queue owns context/code;
    // this fixture publishes no foreign descriptor or C task resources.
    let published = match unsafe { ready.commit(&authority, published_child, pointer) } {
        Ok(job) => job,
        Err(_) => panic!("valid child refused"),
    };
    assert_eq!(f.child.load(Ordering::Acquire), 0);
    f.retained_context
        .store(published.assigned().context_id().get(), Ordering::Release);
    // SAFETY: no foreign user exists, but checked actual current/native state
    // must still refuse release on this creator's executing stack.
    let published = match unsafe { published.release() } {
        Err((job, WorkError::Busy)) => job,
        _ => panic!("creator released child stack"),
    };
    assert_eq!(f.base.pins_dropped.load(Ordering::Relaxed), 0);
    // SAFETY: same CPU fixture; no callback can access this slot during mutation.
    unsafe { *f.published.get() = Some(published) };
}
fn check(action: Action) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode: Mode::Bytes,
        watch: AtomicU64::new(0),
        watch_state: AtomicU64::new(0),
        restored: AtomicBool::new(false),
    });
    let base = Arc::new(PinScene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        case: Case::Good,
        active: AtomicBool::new(true),
        entered: AtomicUsize::new(0),
        exports: AtomicUsize::new(0),
        pins_dropped: Arc::new(AtomicUsize::new(0)),
        marked: AtomicUsize::new(0),
        binding: Mutex::new(None),
        held_view: Mutex::new(None),
    });
    let f = Arc::new(Publication {
        base: base.clone(),
        published: UnsafeCell::new(None),
        child: AtomicUsize::new(0),
        probes: AtomicUsize::new(0),
        retained_context: AtomicU64::new(0),
        action,
    });
    // SAFETY: same-thread model, exact fixture/code and real mmap owners kept.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = Executor::new_hosted_profile_for_test(
        queue,
        mappings(&base, &dropped),
        policy(),
        profile(),
    )
    .unwrap();
    let r = executor.runtime();
    base.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    // SAFETY: exact fixture context stays kept through creator and child join.
    unsafe {
        r.call_foreground(
            publish_pinned,
            Arc::as_ptr(&f) as *mut c_void,
            cpu.ticks() + 1_000_000_000,
        )
    }
    .unwrap();
    if matches!(action, Action::Release | Action::Drop | Action::Forget) {
        // SAFETY: dispatcher, no live callback borrows this same CPU fixture.
        let published = unsafe { (*f.published.get()).take() }.unwrap();
        assert!(!r.queue.completed(published.assigned().ticket()).unwrap());
        // SAFETY: fixture has no foreign users, but the native child has not run.
        let published = match unsafe { published.release() } {
            Err((job, WorkError::Pending)) => job,
            _ => panic!("unrun child released"),
        };
        assert_eq!(base.pins_dropped.load(Ordering::Relaxed), 0);
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
        assert_eq!(f.child.load(Ordering::Acquire), 1);
        let published = if matches!(action, Action::Release) {
            // SAFETY: fixture has no foreign storage users, but the real native
            // SwitchBinding remains attached and must independently block reuse.
            let published = match unsafe { published.release() } {
                Err((job, WorkError::Busy)) => job,
                _ => panic!("attached binding released"),
            };
            let (binding, wake) = base.binding.lock().unwrap().take().unwrap();
            // SAFETY: exact callback completed and every fixture producer is
            // stopped; detach checks the real retained stack from its successor.
            drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
            drop(binding);
            drop(wake);
            published
        } else {
            published
        };
        for _ in 0..20 {
            // SAFETY: queue owns context/code and each unrelated body fits the
            // kernel stack geometry. The held worker must never be assigned.
            unsafe {
                r.queue.execute_general_with_requirement(
                    kernel(),
                    unrelated,
                    Arc::as_ptr(&f) as *mut c_void,
                )
            }
            .unwrap();
        }
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
        assert_eq!(f.probes.load(Ordering::Acquire), 20);
        assert_eq!(base.pins_dropped.load(Ordering::Relaxed), 0);
        r.queue.close().unwrap();
        // SAFETY: all external producers are stopped and native jobs joined;
        // the separately retained published pin must still refuse retirement.
        assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
        // SAFETY: same stopped/kept graph; independent queue retirement also
        // cannot release its real code/root owner while this pin is retained.
        assert_eq!(unsafe { r.queue.retire() }, Err(WorkError::Pending));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        if matches!(action, Action::Drop | Action::Forget) {
            if matches!(action, Action::Forget) {
                core::mem::forget(published);
            } else {
                drop(published);
            }
            assert_eq!(base.pins_dropped.load(Ordering::Relaxed), 0);
            // SAFETY: every native callback joined and external producer stopped.
            // Lost publication ownership must retain the full runtime graph.
            assert_eq!(unsafe { r.retire() }, Err(WorkError::Pending));
            drop(executor);
            assert_eq!(base.pins_dropped.load(Ordering::Relaxed), 0);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            return;
        }
        // SAFETY: exact child joined and no foreign task/descriptor was created;
        // its native stack is idle/unbound on the successor dispatcher.
        assert!(unsafe { published.release() }.is_ok());
    }
    assert_eq!(base.pins_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    r.queue.close().unwrap();
    // SAFETY: creator/child joined, no binding or external producer exists.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn actual_child_and_successor_fences_precede_pin_release() {
    check(Action::Release);
}
#[test]
fn unpublished_reconstructed_frame_can_cancel_without_child_execution() {
    check(Action::Cancel);
}

#[test]
fn refused_pinned_publication_returns_exact_owners_for_fresh_cancel() {
    check(Action::Overflow);
    check(Action::Stale);
}
#[test]
fn abandoned_completed_child_pin_keeps_runtime_code_and_all_stack_mappings() {
    check(Action::Drop);
    check(Action::Forget);
}

mod faults;

mod reuse;

mod child_phases;
