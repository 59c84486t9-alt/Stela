//! Actual hosted guarded Runtime return-tail controls. CPU/IRQ remains modeled;
//! these tests grant no native CPL0/root, original C task or producer readiness.
use super::*;
use alloc::sync::Weak;
use core::sync::atomic::AtomicUsize;
struct Events {
    cpu: Arc<CpuModel>,
    queue: Weak<Queue<16>>,
    published: AtomicU64,
    consumed: AtomicU64,
    calls: AtomicU64,
    queue_events: AtomicU64,
    reusable: AtomicU64,
    cold: AtomicU64,
    reject: AtomicBool,
}
// SAFETY: bounded atomics-only fixture on the actual CpuModel thread. Weak is
// no owning backedge. The temporary view only reads current/lock metadata;
// no queue call, allocation, foreign code, switch or owner release occurs.
unsafe impl ResourceObserver for Events {
    fn released(&self, epoch: u64, actual: &GeneralRelease) -> Result<(), WorkError> {
        assert_eq!(self.cpu.flags.load(Ordering::Acquire), 0x202);
        let queue = self.queue.upgrade().unwrap();
        assert!(!queue.held.load(Ordering::Acquire));
        assert_eq!(queue.active.id.load(Ordering::Acquire), 0);
        assert!(queue.resource_busy.load(Ordering::Acquire));
        if actual.queue_credit() {
            self.queue_events.fetch_add(1, Ordering::Relaxed);
        }
        for shape in actual.stacks() {
            assert!(shape.supports(StackRequirement::exact(128 * 1024, 4096, 4096).unwrap()));
            self.reusable.fetch_add(1, Ordering::Relaxed);
            if shape.unstarted() {
                self.cold.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.published.store(epoch, Ordering::Release);
        if self.reject.load(Ordering::Acquire) {
            Err(WorkError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn drained(&self, epoch: u64) -> Result<bool, WorkError> {
        Ok(self.consumed.load(Ordering::Acquire) == epoch)
    }
}
fn setup(owner: RetainedOwner) -> (Executor<16>, Arc<Events>, Arc<AtomicUsize>) {
    let cpu = CpuModel::new();
    // SAFETY: retained exact hosted fixture/code; no hardware or native grant.
    let queue = unsafe { Queue::new(cpu.clone(), owner) }.unwrap();
    let events = Arc::new(Events {
        cpu,
        queue: Arc::downgrade(&queue),
        published: AtomicU64::new(0),
        consumed: AtomicU64::new(0),
        calls: AtomicU64::new(0),
        queue_events: AtomicU64::new(0),
        reusable: AtomicU64::new(0),
        cold: AtomicU64::new(0),
        reject: AtomicBool::new(false),
    });
    let dropped = Arc::new(AtomicUsize::new(0));
    let executor =
        Executor::new_hosted_for_test(queue, test_support::stacks_count(&dropped, 4)).unwrap();
    (executor, events, dropped)
}
fn consumed(events: &Events) {
    events
        .consumed
        .store(events.published.load(Ordering::Acquire), Ordering::Release);
}
#[test]
fn actual_runtime_release_notifies_after_physical_return_and_exact_consumption_joins() {
    let owner_drops = Arc::new(AtomicU64::new(0));
    let (executor, events, stacks) = setup(Arc::new(Owner(owner_drops.clone())));
    let runtime = executor.runtime();
    let queue = runtime.queue().clone();
    // SAFETY: exact real Runtime/source with fresh bounded nonowning sink.
    let mut registration = unsafe { runtime.observe_general_resources(events.clone()) }.unwrap();
    for _ in 0..8 {
        runtime.publish_general_resources().unwrap();
    }
    assert_eq!(events.calls.load(Ordering::Acquire), 0);
    // SAFETY: static no-op fits actual mapped stack; no context borrower.
    let ticket = unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap();
    assert_eq!(events.calls.load(Ordering::Acquire), 0);
    assert!(runtime.step().unwrap());
    assert!(queue.completed(ticket).unwrap());
    assert_eq!(events.calls.load(Ordering::Acquire), 1);
    assert_eq!(events.queue_events.load(Ordering::Acquire), 1);
    assert_eq!(events.reusable.load(Ordering::Acquire), 1);
    assert_eq!(events.cold.load(Ordering::Acquire), 0); // actual callback entered
    for _ in 0..8 {
        runtime.publish_general_resources().unwrap();
    }
    assert_eq!(events.calls.load(Ordering::Acquire), 1);
    registration.close(runtime).unwrap();
    assert_eq!(registration.retire(runtime), Err(WorkError::Pending));
    consumed(&events); // explicit hosted process-consumer model, no C grant
    registration.retire(runtime).unwrap();
    let weak = Arc::downgrade(&queue);
    // SAFETY: original fixture sole producer stopped, physical callback tail joined.
    unsafe { runtime.retire() }.unwrap();
    drop((registration, executor, queue));
    assert!(weak.upgrade().is_none());
    assert_eq!(owner_drops.load(Ordering::Acquire), 1);
    assert_eq!(stacks.load(Ordering::Acquire), 4);
}
#[test]
fn close_excludes_later_real_release_and_refused_sink_retains_actual_graph() {
    let (executor, events, _) = setup(Arc::new(()));
    let runtime = executor.runtime();
    // SAFETY: exact real Runtime/source with fresh bounded nonowning sink.
    let mut registration = unsafe { runtime.observe_general_resources(events.clone()) }.unwrap();
    // SAFETY: static no-op, actual backing retained through physical return.
    unsafe {
        runtime
            .queue()
            .execute(Kind::General, noop, core::ptr::null_mut())
    }
    .unwrap();
    assert!(runtime.step().unwrap());
    registration.close(runtime).unwrap();
    consumed(&events);
    registration.retire(runtime).unwrap();
    // SAFETY: static no-op with no context; actual queue remains open.
    unsafe {
        runtime
            .queue()
            .execute(Kind::General, noop, core::ptr::null_mut())
    }
    .unwrap();
    assert!(runtime.step().unwrap());
    assert_eq!(events.calls.load(Ordering::Acquire), 1);
    // SAFETY: all actual callback/stack return tails joined, sole producer stopped.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);

    let drops = Arc::new(AtomicU64::new(0));
    let (executor, events, stacks) = setup(Arc::new(Owner(drops.clone())));
    let runtime = executor.runtime();
    let queue = runtime.queue().clone();
    // SAFETY: exact source; explicit refusal tests default retaining lifecycle.
    let mut registration = unsafe { runtime.observe_general_resources(events.clone()) }.unwrap();
    events.reject.store(true, Ordering::Release);
    // SAFETY: static no-op, actual backing retained on refused notification.
    unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap();
    assert_eq!(runtime.step(), Err(WorkError::Unavailable));
    assert_eq!(registration.close(runtime), Err(WorkError::Pending));
    assert_eq!(registration.retire(runtime), Err(WorkError::Busy));
    // SAFETY: source attached/poisoned; retirement must refuse despite finished job.
    assert_eq!(unsafe { runtime.retire() }, Err(WorkError::Pending));
    let weak = Arc::downgrade(&queue);
    drop((registration, executor, queue));
    assert!(weak.upgrade().is_some());
    assert_eq!(drops.load(Ordering::Acquire), 0);
    assert_eq!(stacks.load(Ordering::Acquire), 0);
}
struct Fence {
    runtime: AtomicUsize,
    rejected: AtomicBool,
}
unsafe extern "C" fn still_on_worker(context: *mut c_void) {
    // SAFETY: original Queue keeps this exact fixture and pinned actual Runtime.
    let fence = unsafe { &*context.cast::<Fence>() };
    // SAFETY: original pinned Runtime published before accepting this callback.
    let runtime = unsafe {
        Pin::new_unchecked(&*(fence.runtime.load(Ordering::Acquire) as *const Runtime<16>))
    };
    let current = runtime.current.get();
    let context = runtime.current_context().unwrap();
    let flags = runtime.queue().cpu.save_disable().unwrap();
    // Deliberately model the completion tail's metadata-cleared window while
    // still physically on an ACTUAL constructor stack. No event is invented.
    runtime.current.set(NONE);
    runtime.queue().active.clear();
    let refused = runtime.publish_general_resources();
    runtime.current.set(current);
    runtime.queue().active.publish(
        ContextId(context.context_id),
        &(context.stack_start..context.stack_end),
    );
    // SAFETY: exact surrounding model IF save, all local metadata restored.
    unsafe { runtime.queue().cpu.restore(flags) };
    assert_eq!(refused, Err(WorkError::WouldDeadlock));
    fence.rejected.store(true, Ordering::Release);
}
#[test]
fn cleared_metadata_cannot_replace_the_actual_architectural_successor() {
    let fence = Arc::new(Fence {
        runtime: AtomicUsize::new(0),
        rejected: AtomicBool::new(false),
    });
    let (executor, events, _) = setup(fence.clone());
    let runtime = executor.runtime();
    fence.runtime.store(
        runtime.get_ref() as *const Runtime<16> as usize,
        Ordering::Release,
    );
    // SAFETY: exact source, fresh atomics-only sink; fixture owns no Runtime Arc.
    let mut registration = unsafe { runtime.observe_general_resources(events.clone()) }.unwrap();
    // SAFETY: fixture + actual Runtime/backing survive exact native callback join.
    unsafe {
        runtime.queue().execute(
            Kind::General,
            still_on_worker,
            Arc::as_ptr(&fence).cast_mut().cast(),
        )
    }
    .unwrap();
    assert!(runtime.step().unwrap());
    assert!(fence.rejected.load(Ordering::Acquire));
    assert_eq!(events.calls.load(Ordering::Acquire), 1); // true later dispatcher tail
    registration.close(runtime).unwrap();
    consumed(&events);
    registration.retire(runtime).unwrap();
    // SAFETY: exact callback and source/consumer event joins, no foreign bindings.
    unsafe { runtime.retire() }.unwrap();
    drop(executor);
}
