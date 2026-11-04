//! Original fork, publication, and reaping on the hosted execution owner.
use super::{initial::fatal, stack::ModelStackTicket, *};
use crate::{
    owner::RawOwner,
    task::{
        data::{
            CData, DataIdentity, DataView, stela_linux_task_data_prepare,
            stela_linux_task_data_release,
        },
        dispatch::{
            Dispatch, HostedHooks, SOURCE_FREED, SOURCE_TAIL, SourceEntry, TERMINAL_RETURNED,
        },
    },
};
use alloc::{boxed::Box, vec::Vec};
use core::ptr;
use stela_driver_base::platform::work::kernel_domain::{DomainRaised, HostedChild, HostedDomain};

unsafe extern "C" {
    fn stela_linux_task_child_identity(
        task: *mut CTask,
        owner: *const RawOwner,
        original: *mut *mut c_void,
        generation: *mut u64,
    ) -> i32;
    fn stela_linux_task_child_install_stack(
        task: *mut CTask,
        owner: *const RawOwner,
        base: *mut c_void,
        bytes: usize,
    );
    fn stela_linux_task_child_source_unwound(
        task: *mut CTask,
        owner: *const RawOwner,
        generation: u64,
    ) -> i32;
    fn stela_linux_task_child_tails_joined(
        task: *mut CTask,
        owner: *const RawOwner,
        generation: u64,
    ) -> i32;
    fn stela_linux_task_source_broker_wake(owner: *const RawOwner) -> i32;
    fn stela_linux_task_run_original(context: *mut c_void);
    fn stela_linux_page_stack_lend(
        ticket: *const ModelStackTicket,
        original: *const c_void,
        base: *mut *mut c_void,
    ) -> i32;
    fn stela_linux_page_stack_prepare_publish(
        ticket: *const ModelStackTicket,
        original: *const c_void,
    ) -> i32;
    fn stela_linux_page_stack_publish(ticket: *const ModelStackTicket, original: *const c_void);
    fn stela_linux_page_stack_retire(
        ticket: *const ModelStackTicket,
        original: *const c_void,
    ) -> i32;
}

const DISPATCH_JOINED: u8 = 32;

pub(super) struct Broker<const N: usize> {
    runtime: NonNull<HostedRuntime<N>>,
    owner: *const RawOwner,
    initial: Option<NonNull<CTask>>,
    raised: DomainRaised<HostedDomain>,
    slots: Box<[Slot<N>]>,
}

struct Slot<const N: usize> {
    child: RefCell<Option<Child<N>>>,
    events: Cell<u8>,
    source_tail: Cell<bool>,
}

struct Child<const N: usize> {
    binding: Rc<HostedTaskBinding<N>>,
    original: NonNull<c_void>,
    generation: u64,
    data: NonNull<CData>,
    stage: Stage<N>,
}

enum Stage<const N: usize> {
    Reserved(HostedStackReservation<'static, N>, bool),
    Dormant(Published<N>),
    Running(Published<N>),
    Joining(Published<N>),
    Detach(HostedChild<'static, N>),
    Final,
    Transition,
}

struct Published<const N: usize> {
    worker: HostedChild<'static, N>,
    descriptors: ModelStackTicket,
}

impl<const N: usize> Broker<N> {
    pub(super) fn new(
        runtime: Pin<&HostedRuntime<N>>,
        owner: *const RawOwner,
        capacity: usize,
    ) -> Result<Self, WorkError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| WorkError::Full)?;
        for _ in 0..capacity {
            slots.push(Slot {
                child: RefCell::new(None),
                events: Cell::new(0),
                source_tail: Cell::new(false),
            });
        }
        Ok(Self {
            runtime: NonNull::from(runtime.get_ref()),
            owner,
            initial: None,
            raised: runtime.service_raised_work()?,
            slots: slots.into_boxed_slice(),
        })
    }

    pub(super) unsafe fn install(mut self, initial: NonNull<CTask>) -> Result<(), WorkError> {
        self.initial = Some(initial);
        let broker = Box::leak(Box::new(self));
        let dispatch = Dispatch {
            hosted: Some(HostedHooks {
                runtime: broker.runtime.as_ptr().cast(),
                start: start::<N>,
                service: service::<N>,
                dispatcher: dispatcher::<N>,
            }),
            owner: broker.owner,
            context: ptr::from_ref(broker).cast(),
            allocate: allocate::<N>,
            thread: thread::<N>,
            reserve_rank: reserve_rank::<N>,
            publish: publish::<N>,
            activate: activate::<N>,
            event: event::<N>,
            abort: abort::<N>,
            pending: pending::<N>,
            process: process::<N>,
        };
        // SAFETY: mounted source, broker and original host runtime stay kept.
        unsafe { dispatch.install() }.map_err(|()| WorkError::Busy)
    }

    fn runtime(&'static self) -> Pin<&'static HostedRuntime<N>> {
        // SAFETY: installation keeps the exact original pinned host runtime.
        unsafe { Pin::new_unchecked(self.runtime.as_ref()) }
    }

    fn slot(
        &self,
        record: *mut CTask,
        owner: *const RawOwner,
        generation: Option<u64>,
    ) -> &Slot<N> {
        if owner != self.owner {
            fatal();
        }
        self.slots
            .iter()
            .find(|slot| {
                slot.child.borrow().as_ref().is_some_and(|child| {
                    child.binding.task.as_ptr() == record
                        && generation.is_none_or(|v| child.generation == v)
                })
            })
            .unwrap_or_else(|| fatal())
    }

    fn raise(&self) {
        self.raised.raise().unwrap_or_else(|_| fatal());
    }

    fn pending(&self) -> bool {
        self.slots.iter().any(|slot| slot.events.get() != 0)
    }
}

unsafe fn broker<const N: usize>(context: *const c_void) -> &'static Broker<N> {
    // SAFETY: the installed table supplies the exact permanently kept broker.
    unsafe { &*context.cast() }
}

fn result(status: i32) -> Result<(), ResourceBootstrapError> {
    if status == 0 {
        Ok(())
    } else {
        Err(ResourceBootstrapError::Native(status))
    }
}

pub(super) unsafe fn start_threads<const N: usize>(
    owner: *const RawOwner,
    runtime: Pin<&HostedRuntime<N>>,
) -> Result<(), ResourceBootstrapError> {
    use ResourceBootstrapError::Work;
    DomainRef::borrow_hosted(runtime)
        .and_then(|domain| domain.current_context())
        .map_err(Work)?;
    let (table, hooks) = Dispatch::hosted(ptr::from_ref(runtime.get_ref()).cast())
        .filter(|(table, _)| table.owner == owner)
        .ok_or(Work(WorkError::InvalidTicket))?;
    // SAFETY: caller owns the source scope. C checks the exact Initial record.
    result(unsafe { (hooks.start)(table.context) })
}

pub(crate) unsafe fn service_progress<const N: usize>(
    owner: &RawOwner,
    runtime: Pin<&HostedRuntime<N>>,
) -> Result<(), ResourceBootstrapError> {
    use ResourceBootstrapError::Work;
    let (table, hooks) = Dispatch::hosted(ptr::from_ref(runtime.get_ref()).cast())
        .filter(|(table, _)| ptr::eq(table.owner, owner))
        .ok_or(Work(WorkError::InvalidTicket))?;
    // SAFETY: the owned timer batch's exact Initial is current and entered.
    result(unsafe { (hooks.service)(table.context) })
}

/// Drive the mounted hosted Linux runtime and consume any completed source
/// child releases on the actual taskless dispatcher.
pub fn step_hosted<const N: usize>(
    runtime: Pin<&HostedRuntime<N>>,
    idle: bool,
) -> Result<bool, ResourceBootstrapError> {
    use ResourceBootstrapError::Work;
    DomainRef::borrow_hosted(runtime)
        .and_then(|domain| domain.dispatcher_successor())
        .map_err(Work)?;
    let (table, hooks) = Dispatch::hosted(ptr::from_ref(runtime.get_ref()).cast())
        .ok_or(Work(WorkError::InvalidTicket))?;
    // SAFETY: actual taskless dispatcher and the installed exact runtime.
    result(unsafe { (hooks.dispatcher)(table.context) })?;
    if idle {
        runtime.step_or_idle()
    } else {
        runtime.step()
    }
    .map_err(Work)
}

unsafe fn start<const N: usize>(context: *const c_void) -> i32 {
    // SAFETY: the installed context and exact Initial remain kept.
    let this = unsafe { broker::<N>(context) };
    let initial = this.initial.unwrap_or_else(|| fatal());
    // SAFETY: C authenticates the genuine current and entered source owner.
    unsafe { stela_linux_task_start_threads(initial.as_ptr(), this.owner) }
}

unsafe fn service<const N: usize>(context: *const c_void) -> i32 {
    // SAFETY: exact installed hosted Initial service context.
    let this = unsafe { broker::<N>(context) };
    if !this.pending() {
        return 0;
    }
    // SAFETY: only the genuine current Initial delivers the recorded reason.
    unsafe { stela_linux_task_source_broker_wake(this.owner) }
}

unsafe fn allocate<const N: usize>(
    context: *const c_void,
    birth: *mut OriginalBirth,
    node: i32,
    unexposed: *mut bool,
) -> i32 {
    // SAFETY: original dup_task_struct lends its birth and writable result.
    let this = unsafe { broker::<N>(context) };
    let Some(slot) = this.slots.iter().find(|slot| slot.child.borrow().is_none()) else {
        // SAFETY: no birth or stack was accepted.
        unsafe { *unexposed = true };
        return -12;
    };
    if !matches!(node, -1 | 0) {
        // SAFETY: no birth or stack was accepted.
        unsafe { *unexposed = true };
        return -95;
    }
    // SAFETY: exact mounted creator, before consuming the original birth.
    let stack = match unsafe { reserve_hosted_child_stack(this.runtime(), this.owner) } {
        Ok(stack) => stack,
        Err(ResourceBootstrapError::Work(WorkError::Full)) => {
            // SAFETY: worker exhaustion accepted neither stack nor birth.
            unsafe { *unexposed = true };
            return -12;
        }
        Err(_) => fatal(),
    };
    let mut record = ptr::null_mut();
    // SAFETY: the original allocator lends this one-shot birth to the same creator.
    let error = unsafe { stela_linux_task_child_allocate(this.owner, birth, &mut record) };
    if error != 0 {
        // SAFETY: C refused before consuming birth. No source borrowed the stack.
        unsafe { stack.cancel() }.unwrap_or_else(|_| fatal());
        // SAFETY: actual rollback joined both reservations.
        unsafe { *unexposed = true };
        return error;
    }
    let task = NonNull::new(record).unwrap_or_else(|| fatal());
    let mut original = ptr::null_mut();
    let mut generation = 0;
    let mut data = DataView {
        lease: ptr::null_mut(),
        total: ptr::null_mut(),
        system: ptr::null_mut(),
    };
    // SAFETY: the sole actual creator owns this new source-born record.
    if unsafe { stela_linux_task_child_identity(record, this.owner, &mut original, &mut generation) } != 0
        || generation == 0
        // SAFETY: these projections are prepared before either attachment or publication.
        || unsafe { stela_linux_task_data_prepare(record, this.owner, &mut data) } != 0
    {
        fatal();
    }
    let original = NonNull::new(original).unwrap_or_else(|| fatal());
    let data = NonNull::new(data.lease).unwrap_or_else(|| fatal());
    let binding = HostedTaskBinding::new_record(task, this.runtime(), Kind::Child);
    let mapping = stack.stack();
    let expected = mapping
        .cpu_address(0, mapping.bytes())
        .unwrap_or_else(|_| fatal());
    let ticket = stack.descriptors.as_ref().unwrap_or_else(|| fatal());
    let mut base = ptr::null_mut();
    // SAFETY: actual original birth and its exact reserved page descriptors.
    if unsafe { stela_linux_page_stack_lend(ticket, original.as_ptr(), &mut base) } != 0
        || base != expected.as_ptr().cast()
    {
        fatal();
    }
    *slot.child.borrow_mut() = Some(Child {
        binding,
        original,
        generation,
        data,
        stage: Stage::Reserved(stack, false),
    });
    // SAFETY: the registry keeps the precise stopped worker before exposure.
    unsafe { stela_linux_task_child_install_stack(record, this.owner, base, mapping.bytes()) };
    0
}

unsafe fn thread<const N: usize>(
    context: *const c_void,
    record: *mut CTask,
    owner: *const RawOwner,
    entry: Option<SourceEntry>,
    _: *mut c_void,
) -> i32 {
    // SAFETY: C authenticates this prepared record and retains the function and argument.
    let slot = unsafe { broker::<N>(context) }.slot(record, owner, None);
    let mut child = slot.child.borrow_mut();
    let Stage::Reserved(_, prepared) = &mut child.as_mut().unwrap_or_else(|| fatal()).stage else {
        fatal();
    };
    if *prepared || entry.is_none() {
        return -22;
    }
    *prepared = true;
    0
}

unsafe fn reserve_rank<const N: usize>(
    context: *const c_void,
    record: *mut CTask,
    owner: *const RawOwner,
    rank: *const Rank,
) -> i32 {
    // SAFETY: C lends the exact source rank in original sched_fork.
    let slot = unsafe { broker::<N>(context) }.slot(record, owner, None);
    // SAFETY: the bounded original fork hook lends the initialized rank.
    let Some(rank) = (unsafe { rank.as_ref() }) else {
        return -22;
    };
    let Ok(rank) = rank.snapshot() else {
        return -95;
    };
    let mut child = slot.child.borrow_mut();
    let Stage::Reserved(stack, _) = &mut child.as_mut().unwrap_or_else(|| fatal()).stage else {
        fatal();
    };
    match stack.worker.reserve_rank(rank) {
        Ok(()) => 0,
        Err(WorkError::Full) => -12,
        Err(WorkError::Unavailable) => -95,
        Err(_) => -5,
    }
}

unsafe fn publish<const N: usize>(
    context: *const c_void,
    record: *mut CTask,
    owner: *const RawOwner,
    rank: *const Rank,
) {
    // SAFETY: original C validates the accepted fork rank and permanent source graph.
    if unsafe { reserve_rank::<N>(context, record, owner, rank) } != 0 {
        fatal();
    }
    // SAFETY: installed context retains the slot through source and dispatcher joins.
    let slot = unsafe { broker::<N>(context) }.slot(record, owner, None);
    let mut kept = slot.child.borrow_mut();
    let child = kept.as_mut().unwrap_or_else(|| fatal());
    let Stage::Reserved(mut stack, true) = core::mem::replace(&mut child.stage, Stage::Transition)
    else {
        fatal();
    };
    let descriptors = stack.descriptors.take().unwrap_or_else(|| fatal());
    // SAFETY: exact lent descriptor graph, still before Dormant publication.
    if unsafe { stela_linux_page_stack_prepare_publish(&descriptors, child.original.as_ptr()) } != 0
    {
        fatal();
    }
    // SAFETY: immutable slot and original C callback are kept through every join.
    let worker = unsafe {
        stack
            .worker
            .publish(run::<N>, ptr::from_ref(slot).cast_mut().cast())
    }
    .unwrap_or_else(|_| fatal());
    // SAFETY: same accepted Dormant worker and validated exact original child.
    unsafe { stela_linux_page_stack_publish(&descriptors, child.original.as_ptr()) };
    child.stage = Stage::Dormant(Published {
        worker,
        descriptors,
    });
}

unsafe fn activate<const N: usize>(
    context: *const c_void,
    record: *mut CTask,
    owner: *const RawOwner,
) {
    // SAFETY: C has published this exact child and reached wake_up_new_task.
    let slot = unsafe { broker::<N>(context) }.slot(record, owner, None);
    let mut kept = slot.child.borrow_mut();
    let child = kept.as_mut().unwrap_or_else(|| fatal());
    let Stage::Dormant(mut published) = core::mem::replace(&mut child.stage, Stage::Transition)
    else {
        fatal();
    };
    // SAFETY: exact source publication plus the first original runnable wake.
    unsafe { published.worker.activate() }.unwrap_or_else(|_| fatal());
    child.stage = Stage::Running(published);
}

unsafe extern "C" fn run<const N: usize>(context: *mut c_void) {
    // SAFETY: this slot is retained through terminal, source and dispatcher joins.
    let slot = unsafe { &*context.cast::<Slot<N>>() };
    let binding = {
        let kept = slot.child.borrow();
        let binding = &kept.as_ref().unwrap_or_else(|| fatal()).binding;
        binding.bind_current().unwrap_or_else(|_| fatal());
        ptr::from_ref(binding.as_ref())
    };
    // SAFETY: the permanent slot independently retains the binding. No owning
    // Rust value or borrow guard is abandoned by the original do_exit path.
    let binding = unsafe { &*binding };
    // SAFETY: actual active child on the exact source stack and original callback.
    let _ =
        unsafe { binding.run_scoped(stela_linux_task_run_original, binding.task.as_ptr().cast()) };
    fatal();
}

unsafe fn event<const N: usize>(
    context: *const c_void,
    record: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
    event: u8,
) {
    // SAFETY: original callback tail lends the exact kept record and generation.
    let this = unsafe { broker::<N>(context) };
    let slot = this.slot(record, owner, Some(generation));
    if event == SOURCE_TAIL {
        slot.source_tail.set(true);
    }
    slot.events.set(slot.events.get() | event);
    this.raise();
}

unsafe fn abort<const N: usize>(
    context: *const c_void,
    record: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
) {
    // SAFETY: original unwind supplies the exact kept unpublished record.
    let this = unsafe { broker::<N>(context) };
    let slot = this.slot(record, owner, Some(generation));
    let mut kept = slot.child.borrow_mut();
    let child = kept.as_mut().unwrap_or_else(|| fatal());
    let Stage::Reserved(stack, _) = core::mem::replace(&mut child.stage, Stage::Transition) else {
        fatal();
    };
    // SAFETY: C authenticates its actual reverse unwind and original object free.
    if unsafe { stela_linux_task_child_source_unwound(record, owner, generation) } != 0 {
        fatal();
    }
    // SAFETY: same creator and joined unpublished source stack references.
    unsafe { stack.cancel() }.unwrap_or_else(|_| fatal());
    // SAFETY: the source data reference was never claimed and unwind has joined.
    if unsafe { stela_linux_task_data_release(child.data.as_ptr(), owner, ptr::null()) } != 0 {
        fatal();
    }
    child.stage = Stage::Final;
}

unsafe fn pending<const N: usize>(context: *const c_void) -> bool {
    // SAFETY: the genuine C supervisor calls its exact mounted broker.
    unsafe { broker::<N>(context) }.pending()
}

unsafe fn process<const N: usize>(context: *const c_void) -> i32 {
    // SAFETY: the genuine original supervisor supplies its installed context.
    let this = unsafe { broker::<N>(context) };
    let Some(slot) = this.slots.iter().find(|slot| slot.events.get() != 0) else {
        return 0;
    };
    let events = slot.events.replace(0);
    let (record, generation, data, identity, reap, join, finalize) = {
        let mut kept = slot.child.borrow_mut();
        let child = kept.as_mut().unwrap_or_else(|| fatal());
        let mut reap = false;
        if events & TERMINAL_RETURNED != 0 {
            let Stage::Running(published) = core::mem::replace(&mut child.stage, Stage::Transition)
            else {
                fatal();
            };
            if published.worker.returned_to_peer() != Ok(true) {
                fatal();
            }
            child.stage = Stage::Joining(published);
            reap = true;
        }
        (
            child.binding.task.as_ptr(),
            child.generation,
            child.data,
            child.binding.identity.get(),
            reap,
            matches!(child.stage, Stage::Joining(_)) && (reap || events & SOURCE_FREED != 0),
            matches!(child.stage, Stage::Final) && slot.source_tail.get(),
        )
    };
    if reap {
        // SAFETY: the same held stack physically returned before this process ran.
        // No slot borrow crosses original reaping or any source callback.
        if unsafe { stela_linux_task_reap_source(record, this.owner, generation) } != 0 {
            fatal();
        }
        let view = identity.unwrap_or_else(|| fatal());
        let identity = DataIdentity {
            queue_id: view.queue_id,
            context_id: view.context_id,
            sequence: view.sequence,
        };
        // SAFETY: the hosted CPU stopped the sole writer and joined the scheduler refs.
        if unsafe { stela_linux_task_data_release(data.as_ptr(), this.owner, &identity) } != 0 {
            fatal();
        }
    }
    if join {
        // SAFETY: the genuine supervisor owns source reap and data release.
        // The original RCU barrier may park, so hold no slot/runtime borrow.
        match unsafe { stela_linux_task_join_source(record, this.owner, generation) } {
            0 => {}
            -11 => return 1, // kernel_wait4 and later actual source-free delivery
            _ => fatal(),
        }
        let mut kept = slot.child.borrow_mut();
        let child = kept.as_mut().unwrap_or_else(|| fatal());
        let Stage::Joining(published) = core::mem::replace(&mut child.stage, Stage::Transition)
        else {
            fatal();
        };
        // SAFETY: exact actual source and physical return joined. The
        // descriptor owner independently checks page references are zero.
        if unsafe { stela_linux_page_stack_retire(&published.descriptors, child.original.as_ptr()) }
            != 0
        {
            fatal();
        }
        child.stage = Stage::Detach(published.worker);
    }
    if finalize {
        // SAFETY: exact source callback tails and the runtime detach have joined.
        if unsafe { stela_linux_task_child_tails_joined(record, this.owner, generation) } != 0 {
            fatal();
        }
        // SAFETY: all actual source and hosted owners returned; this is final source release.
        if unsafe { stela_linux_task_release_original(record, this.owner, generation) } != 0 {
            fatal();
        }
        let mut child = slot.child.borrow_mut().take().unwrap_or_else(|| fatal());
        slot.source_tail.set(false);
        Rc::get_mut(&mut child.binding)
            .unwrap_or_else(|| fatal())
            .released = true;
    }
    1
}

unsafe fn dispatcher<const N: usize>(context: *const c_void) -> i32 {
    // SAFETY: exact taskless hosted dispatcher, checked by step_hosted.
    let this = unsafe { broker::<N>(context) };
    for slot in &this.slots {
        let mut kept = slot.child.borrow_mut();
        let Some(child) = kept.as_mut() else { continue };
        if !matches!(child.stage, Stage::Detach(_)) {
            continue;
        }
        let Stage::Detach(worker) = core::mem::replace(&mut child.stage, Stage::Transition) else {
            fatal();
        };
        let wake = child.binding.wake.borrow();
        let wake = wake.as_ref().unwrap_or_else(|| fatal());
        // SAFETY: source C tails, page references and exact physical return joined.
        let binding = unsafe { this.runtime().detach_binding(wake) }.unwrap_or_else(|_| fatal());
        drop(binding);
        // SAFETY: exact source joins and runtime binding detach completed.
        unsafe { worker.release() }.unwrap_or_else(|_| fatal());
        child.stage = Stage::Final;
        slot.events.set(slot.events.get() | DISPATCH_JOINED);
        this.raise();
    }
    0
}
