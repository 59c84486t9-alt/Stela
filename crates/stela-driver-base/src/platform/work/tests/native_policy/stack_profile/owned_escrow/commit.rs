//! Real owned-worker publication, refusal and exact child-ticket completion.
use super::*;
#[derive(Clone, Copy)]
enum Case {
    Publish,
    Stale,
    Closed,
    SequenceOverflow,
    WrongCreator,
}
struct CommitScene {
    runtime: AtomicU64,
    cpu: Arc<ModelCpu>,
    case: Case,
    children: AtomicUsize,
    child_ticket: Mutex<Option<Ticket>>,
    child_context: AtomicU64,
}
impl CommitScene {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: queue-owned scene and outer executor keep this exact Runtime.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
}
unsafe extern "C" fn child(pointer: *mut c_void) {
    // SAFETY: the Queue retains this scene before creator publication.
    let f = unsafe { &*pointer.cast::<CommitScene>() };
    let view = f.runtime().current_context().unwrap();
    assert_eq!(view.context_id, f.child_context.load(Ordering::Acquire));
    assert_eq!(view.stack_end - view.stack_start, 16 * 1024);
    assert_eq!(f.runtime().owned_escrows.get(), 0);
    f.children.fetch_add(1, Ordering::Release);
}
unsafe extern "C" fn publish(pointer: *mut c_void) {
    // SAFETY: this real foreground callback borrows the kept fixture.
    let f = unsafe { &*pointer.cast::<CommitScene>() };
    let r = f.runtime();
    let permission = Authority::new(&f.cpu);
    let owned = r
        .reserve_general(&permission, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let flags = f.cpu.save_disable().unwrap();
    let expected_context = {
        // SAFETY: this fixture's actual CPU has IRQs saved/disabled. The single
        // retained escrow excludes its stopped worker; no task borrow survives
        // this block or the matching restore. No production visibility changes.
        let tasks = unsafe { &*r.tasks.get() };
        let mut held = tasks.iter().filter(|task| task.state == TaskState::Escrow);
        let id = held.next().expect("actual escrow worker").id;
        assert!(held.next().is_none(), "fixture owns exactly one escrow");
        id
    };
    // SAFETY: exact saved flags above after every Task-table borrow has ended.
    unsafe { f.cpu.restore(flags) };
    f.child_context
        .store(expected_context.get(), Ordering::Release);
    let old_next = r.queue.lock().unwrap().state().next;
    let old_sequence = r.current_context().unwrap().sequence;
    match f.case {
        Case::Stale => permission.active.set(false),
        Case::Closed => r.queue.close().unwrap(),
        Case::SequenceOverflow => r.queue.lock().unwrap().state().next = u64::MAX,
        Case::WrongCreator => {
            let flags = f.cpu.save_disable().unwrap();
            // SAFETY: this isolated fixture alters only its current job's copied
            // identity; it restores it before using any subsequent authority.
            unsafe { (*r.task(r.current.get())).job.as_mut().unwrap().1.sequence += 1 };
            // SAFETY: exact save above, with no task borrow surviving.
            unsafe { f.cpu.restore(flags) };
        }
        Case::Publish => {}
    }
    // SAFETY: scene/code are Queue-owned before the publisher, including its
    // outer restore tail. A refused callback is not accepted or run.
    let result = unsafe { owned.commit(&permission, child, pointer) };
    assert_eq!(f.children.load(Ordering::Acquire), 0);
    match (f.case, result) {
        (Case::Publish, Ok(assigned)) => {
            assert_eq!(
                assigned.context_id().get(),
                f.child_context.load(Ordering::Acquire)
            );
            assert!(!r.queue.completed(assigned.ticket()).unwrap());
            *f.child_ticket.lock().unwrap() = Some(assigned.ticket());
            assert_eq!(r.owned_escrows.get(), 0);
            assert_eq!(r.queue.lock().unwrap().state().next, old_next + 1);
        }
        (case, Err((owned, error))) => {
            let expected = match case {
                Case::Stale => WorkError::Unavailable,
                Case::Closed => WorkError::Closed,
                Case::SequenceOverflow => WorkError::Exhausted,
                Case::WrongCreator => WorkError::CorruptContext,
                Case::Publish => panic!("valid owned child refused: {error:?}"),
            };
            assert_eq!(error, expected);
            assert_eq!(r.owned_escrows.get(), 1);
            assert_eq!(r.pending_reservations.get(), 0);
            if matches!(case, Case::SequenceOverflow) {
                r.queue.lock().unwrap().state().next = old_next;
            }
            if matches!(case, Case::WrongCreator) {
                let flags = f.cpu.save_disable().unwrap();
                // SAFETY: restore the same fixture-owned copied current identity.
                unsafe {
                    (*r.task(r.current.get())).job.as_mut().unwrap().1.sequence = old_sequence
                };
                // SAFETY: exact save above after the bounded mutation ends.
                unsafe { f.cpu.restore(flags) };
            }
            permission.active.set(true);
            owned.cancel(&permission).unwrap();
            assert_eq!(r.owned_escrows.get(), 0);
            assert_eq!(r.queue.lock().unwrap().state().next, old_next);
        }
        (_, Ok(_)) => panic!("invalid child publication accepted"),
    }
    assert_eq!(f.cpu.model.flags(), 0x202);
}
fn check(case: Case) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode: Mode::RoundTrip,
    });
    let f = Arc::new(CommitScene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        case,
        children: AtomicUsize::new(0),
        child_ticket: Mutex::new(None),
        child_context: AtomicU64::new(0),
    });
    // SAFETY: actual scene/code/backing owners precede every callback publication.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = Executor::new_hosted_profile_for_test(
        queue,
        support::stacks(&dropped, 20),
        policy(),
        profile(),
    )
    .unwrap();
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    // SAFETY: scene is retained through creator/child execution and exact join.
    unsafe {
        r.call_foreground(
            publish,
            Arc::as_ptr(&f) as *mut c_void,
            cpu.ticks() + 1_000_000_000,
        )
    }
    .unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    let expected = usize::from(matches!(case, Case::Publish));
    assert_eq!(f.children.load(Ordering::Acquire), expected);
    if let Some(ticket) = *f.child_ticket.lock().unwrap() {
        assert!(r.queue.completed(ticket).unwrap());
    }
    r.queue.close().unwrap();
    // SAFETY: every published native child/creator joined; no external producer.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn publication_assigns_the_reserved_stack_and_only_exact_completion_joins() {
    check(Case::Publish);
}
#[test]
fn refusal_returns_the_same_owned_escrow_for_fresh_explicit_cancel() {
    for case in [
        Case::Stale,
        Case::Closed,
        Case::SequenceOverflow,
        Case::WrongCreator,
    ] {
        check(case);
    }
}
