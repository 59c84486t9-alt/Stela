//! Real repeated reconstruction, final backing-view and stale-signal controls.
//! No C graph is substituted: these fixtures publish no original C task/page.
use super::*;
struct Reuse {
    base: Arc<PinScene>,
    published: UnsafeCell<Option<PublishedGeneralStack<'static, 64>>>,
    current: Mutex<Option<(Arc<Binding>, WakeHandle<64>)>>,
    stale: Mutex<Option<WakeHandle<64>>>,
    epoch: AtomicU64,
    context: AtomicU64,
    calls: AtomicUsize,
    check_return: bool,
}
// SAFETY: passive same-host-thread retention only; all affine cells are used
// solely by actual kept Runtime callbacks and its successor, no foreign thread.
unsafe impl Send for Reuse {}
// SAFETY: same single fixture CPU serializes every cell; no permission is made.
unsafe impl Sync for Reuse {}
unsafe extern "C" fn child(pointer: *mut c_void) {
    // SAFETY: actual queue owns this fixture/code until every join/release.
    let f = unsafe { &*pointer.cast::<Reuse>() };
    let r = f.base.runtime();
    let view = r.current_context().unwrap();
    assert_eq!(view.context_id, f.context.load(Ordering::Acquire));
    if let Some(stale) = f.stale.lock().unwrap().as_ref() {
        assert_eq!(stale.wake(), Err(WorkError::Closed));
    }
    let binding = Arc::new(Binding {
        id: AtomicU64::new(0),
        blocked: AtomicBool::new(false),
    });
    let wake = r.bind_current(binding.clone()).unwrap();
    *f.current.lock().unwrap() = Some((binding, wake));
    f.calls.fetch_add(1, Ordering::Release);
}
unsafe extern "C" fn create(pointer: *mut c_void) {
    // SAFETY: exact queue-kept fixture on its real creator continuation.
    let f = unsafe { &*pointer.cast::<Reuse>() };
    // SAFETY: actual pinned executor/fixture retained until all rounds join.
    let r: Pin<&'static Runtime<64>> = unsafe {
        Pin::new_unchecked(&*(f.base.runtime.load(Ordering::Acquire) as *const Runtime<64>))
    };
    let authority = f.base.authority();
    let owner = r
        .reserve_general(&authority, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    if f.check_return && f.calls.load(Ordering::Acquire) != 0 {
        let flags = f.base.cpu.save_disable().unwrap();
        // SAFETY: exact same fixture CPU holds IF0; the sole idle escrow is
        // reserved exclusively by this actual creator, with no live task borrow.
        let slot = unsafe {
            (&*r.tasks.get())
                .iter()
                .position(|t| t.state == TaskState::Escrow)
        }
        .unwrap();
        // SAFETY: restore the enclosing saved flags with no task borrow held.
        unsafe { f.base.cpu.restore(flags) };
        // SAFETY: private exact reserved idle worker, no mutable/foreign user.
        let real = unsafe { (*r.task(slot)).returned_sequence };
        // Independent fault control: completion alone must not authorize zero.
        // SAFETY: only this fixture CPU can use its privately reserved worker.
        unsafe { (*r.task(slot)).returned_sequence = 0 };
        // SAFETY: no C/alias users exist; expected refusal precedes all writes.
        let owner = match unsafe { owner.prepare_stack(&authority) } {
            Err((owner, WorkError::Pending)) => owner,
            _ => panic!("completion counter stood in for actual native return"),
        };
        assert!(owner.epoch().is_none());
        // SAFETY: restore the independently observed actual dispatcher receipt.
        unsafe { (*r.task(slot)).returned_sequence = real };
        // SAFETY: this failed Reserved-stage owner exported no user or pin.
        unsafe { owner.cancel(&authority) }.unwrap();
        return;
    }
    // SAFETY: prior epoch actually released from real off-stack successor;
    // fixture has no C/task/page/alias/RCU users or frames to manufacture.
    let prepared = match unsafe { owner.prepare_stack(&authority) } {
        Ok(owner) => owner,
        Err(_) => panic!("valid actual retired stack refused"),
    };
    let epoch = prepared.epoch().unwrap();
    assert_eq!(epoch, f.epoch.load(Ordering::Acquire) + 1);
    f.epoch.store(epoch, Ordering::Release);
    let pinned = prepared
        .pin(&authority)
        .unwrap_or_else(|_| panic!("actual fresh epoch pin refused"));
    let ready = pinned
        .reconstruct(&authority)
        .unwrap_or_else(|_| panic!("actual frame refused"));
    // SAFETY: queue owns context/code and each real kernel-shaped stack;
    // source/physical pin remains in the exact returned owner across completion.
    let published = unsafe { ready.commit(&authority, child, pointer) }
        .unwrap_or_else(|_| panic!("valid publication refused"));
    let id = published.assigned().context_id().get();
    let old = f.context.swap(id, Ordering::AcqRel);
    if old != 0 {
        assert_eq!(old, id, "control must really reuse the SAME native worker");
    }
    // SAFETY: same fixture CPU, no other callback reads this slot now.
    unsafe { *f.published.get() = Some(published) };
}
fn run(with_alias: bool, check_return: bool) {
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
        case: if with_alias {
            Case::HeldView
        } else {
            Case::Good
        },
        active: AtomicBool::new(true),
        entered: AtomicUsize::new(0),
        exports: AtomicUsize::new(0),
        pins_dropped: Arc::new(AtomicUsize::new(0)),
        marked: AtomicUsize::new(0),
        binding: Mutex::new(None),
        held_view: Mutex::new(None),
    });
    let f = Arc::new(Reuse {
        base: base.clone(),
        published: UnsafeCell::new(None),
        current: Mutex::new(None),
        stale: Mutex::new(None),
        epoch: AtomicU64::new(0),
        context: AtomicU64::new(0),
        calls: AtomicUsize::new(0),
        check_return,
    });
    // SAFETY: original real guarded owners and exact same-thread CPU/fixture.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor =
        Executor::new_hosted_profile_for_test(q, mappings(&base, &dropped), policy(), profile())
            .unwrap();
    let r = executor.runtime();
    base.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    let count = if check_return { 2 } else { 64 };
    let mut last_ticket = 0;
    for round in 0..count {
        // SAFETY: actual retained callback/context through exact creator join.
        unsafe {
            r.call_foreground(
                create,
                Arc::as_ptr(&f) as *mut c_void,
                cpu.ticks() + 1_000_000_000,
            )
        }
        .unwrap();
        if check_return && round != 0 {
            assert_eq!(f.calls.load(Ordering::Acquire), 1);
            assert_eq!(base.exports.load(Ordering::Acquire), 1);
            break;
        }
        // SAFETY: same CPU successor after actual creator return.
        let published = unsafe { (*f.published.get()).take() }.unwrap();
        assert!(published.assigned().ticket().sequence > last_ticket);
        last_ticket = published.assigned().ticket().sequence;
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
        assert_eq!(f.calls.load(Ordering::Acquire), round + 1);
        let (binding, wake) = f.current.lock().unwrap().take().unwrap();
        // SAFETY: no C/IRQ/foreign producer; this exact child returned physically.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        drop(binding);
        *f.stale.lock().unwrap() = Some(wake);
        let published = if with_alias {
            // SAFETY: no UNTRACKED C/raw user; counted backing view must refuse
            // before any data disposal/native release, as the API documents.
            let held = match unsafe { published.release() } {
                Err((held, WorkError::Pending)) => held,
                _ => panic!("live actual page-view alias permitted reuse"),
            };
            assert_eq!(base.pins_dropped.load(Ordering::Acquire), round);
            drop(base.held_view.lock().unwrap().take().unwrap());
            held
        } else {
            published
        };
        // SAFETY: every real physical view/user ended, actual off-stack native
        // successor and separate binding detach completed above; no C graph.
        unsafe { published.release() }.unwrap();
        assert_eq!(base.pins_dropped.load(Ordering::Acquire), round + 1);
        assert_eq!(base.exports.load(Ordering::Acquire), round + 1);
        assert_eq!(f.epoch.load(Ordering::Acquire), (round + 1) as u64);
    }
    drop(f.stale.lock().unwrap().take());
    r.queue.close().unwrap();
    // SAFETY: all real callbacks/users joined, admission closed and every
    // actual source view and binding retired. No code/storage user remains.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn repeated_same_worker_uses_fresh_actual_epoch_and_stale_wakes_stay_closed() {
    run(false, false);
}
#[test]
fn counted_actual_mapping_views_block_reuse_until_final_data_owner_drop() {
    run(true, false);
}
#[test]
fn completed_ticket_without_physical_native_return_cannot_zero_or_export() {
    run(false, true);
}
