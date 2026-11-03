use super::*;
pub(super) struct Dispatch {
    pending: unsafe fn(*const c_void) -> bool,
    process: unsafe fn(*const c_void) -> i32,
    context: *const c_void,
    owner: *const RawOwner,
    allocate: unsafe fn(*const c_void, *mut OriginalBirth, i32, *mut bool) -> i32,
    thread: unsafe fn(
        *const c_void,
        *mut CTask,
        *const RawOwner,
        Option<NativeEntry>,
        *mut c_void,
    ) -> i32,
    publish: unsafe fn(*const c_void, *mut CTask, *const RawOwner, *const Rank),
    activate: unsafe fn(*const c_void, *mut CTask, *const RawOwner),
    event: unsafe fn(*const c_void, *mut CTask, *const RawOwner, u64, u8),
    abort: unsafe fn(*const c_void, *mut CTask, *const RawOwner, u64),
}
pub(super) static DISPATCH: AtomicPtr<Dispatch> = AtomicPtr::new(ptr::null_mut());
pub(super) unsafe fn publish<
    K: KernelThreadPlatform + 'static,
    P: Provider + 'static,
    const N: usize,
>(
    broker: &'static Broker<K, P, N>,
) -> Result<(), Error> {
    let pointer = Box::into_raw(Box::new(Dispatch {
        pending: pending::<K, P, N>,
        process: process::<K, P, N>,
        context: broker as *const _ as *const c_void,
        owner: broker.kernel.raw(),
        allocate: allocate::<K, P, N>,
        thread: thread::<K, P, N>,
        publish: publish_child::<K, P, N>,
        activate: activate::<K, P, N>,
        event: event::<K, P, N>,
        abort: abort::<K, P, N>,
    }));
    if DISPATCH
        .compare_exchange(
            ptr::null_mut(),
            pointer,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // SAFETY: publication failed, so only this caller owns the raw box.
        drop(unsafe { Box::from_raw(pointer) });
        return Err(Error::Busy);
    }
    Ok(())
}
fn dispatch() -> &'static Dispatch {
    let pointer = DISPATCH.load(Ordering::Acquire);
    if pointer.is_null() {
        fatal();
    }
    // SAFETY: permanent unique actual owner graph kept before release-store.
    unsafe { &*pointer }
}
unsafe fn broker<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
) -> &'static Broker<K, P, N> {
    // SAFETY: only permanent installed typed Dispatch creates this pointer.
    unsafe { &*context.cast() }
}
unsafe fn allocate<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
    birth: *mut OriginalBirth,
    node: i32,
    out: *mut bool,
) -> i32 {
    // SAFETY: The dispatch supplies the typed broker, and C lends the birth and output.
    unsafe { broker::<K, P, N>(context).allocate(birth, node, out) }
}
unsafe fn thread<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
    task: *mut CTask,
    owner: *const RawOwner,
    entry: Option<NativeEntry>,
    argument: *mut c_void,
) -> i32 {
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, None);
    // SAFETY: The read guard pins the request, and C retains the entry and argument.
    unsafe { (&*read.pointer).prepare_thread(entry, argument) }
}
unsafe fn publish_child<
    K: KernelThreadPlatform + 'static,
    P: Provider + 'static,
    const N: usize,
>(
    context: *const c_void,
    task: *mut CTask,
    owner: *const RawOwner,
    rank: *const Rank,
) {
    if rank.is_null() {
        fatal();
    }
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, None);
    // SAFETY: The guard pins the matched request and C lends the initialized rank.
    unsafe { (&*read.pointer).publish(&*rank) };
}
unsafe fn activate<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
    task: *mut CTask,
    owner: *const RawOwner,
) {
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, None);
    // SAFETY: The read guard pins the exact published request C is activating.
    unsafe { (&*read.pointer).activate() };
}
unsafe fn event<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
    task: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
    event: u8,
) {
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, Some(generation));
    // Record + same real IRQ-safe work reason ONLY. No C/current, allocation,
    // child-state borrow, task/stack drop or original reaper wait occurs here.
    // SAFETY: The generation-checked guard pins the request for IRQ-safe notification.
    unsafe { (&*read.pointer).notify(event) };
}
unsafe fn abort<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
    task: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
) {
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, Some(generation));
    // SAFETY: The generation-checked read guard pins this request.
    let request = unsafe { &*read.pointer };
    // SAFETY: C retains the source borrow while cancelling this unpublished request.
    if unsafe { request.cancel() }.is_err() {
        fatal();
    }
    // Stable NoPub is retained while original C's source_borrow is STILL live;
    // no source metadata finalization/release happens on this callback tail.
    request.notify(ABORT_RECORDED);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_stack_allocate(
    birth: *mut OriginalBirth,
    node: i32,
    out: *mut bool,
) -> i32 {
    if out.is_null() {
        fatal();
    }
    // SAFETY: C lends writable storage for the duration of this call.
    unsafe { *out = false };
    let d = dispatch();
    // SAFETY: The dispatch retains its context and C lends the birth and writable output.
    unsafe { (d.allocate)(d.context, birth, node, out) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_thread_prepare(
    task: *mut CTask,
    owner: *const RawOwner,
    entry: Option<NativeEntry>,
    argument: *mut c_void,
) -> i32 {
    let d = dispatch();
    if d.owner != owner {
        fatal();
    }
    // SAFETY: The owner matches and C lends the task and retained entry argument.
    unsafe { (d.thread)(d.context, task, owner, entry, argument) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_publish(
    task: *mut CTask,
    owner: *const RawOwner,
    rank: *const Rank,
) {
    let d = dispatch();
    if d.owner != owner {
        fatal();
    }
    // SAFETY: The owner matches and C lends the task and initialized rank.
    unsafe { (d.publish)(d.context, task, owner, rank) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_activate(task: *mut CTask, owner: *const RawOwner) {
    let d = dispatch();
    if d.owner != owner {
        fatal();
    }
    // SAFETY: The owner matches and C is activating the published source task.
    unsafe { (d.activate)(d.context, task, owner) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_source_freed(
    task: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
) {
    let d = dispatch();
    // SAFETY: The callback validates source identity and generation before pinning the request.
    unsafe { (d.event)(d.context, task, owner, generation, SOURCE_FREED) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_terminal_returned(
    task: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
) {
    let d = dispatch();
    // SAFETY: The callback validates source identity and generation before pinning the request.
    unsafe { (d.event)(d.context, task, owner, generation, TERMINAL_RETURNED) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_abort(
    task: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
) {
    let d = dispatch();
    // SAFETY: C retains the unpublished source task through cancellation.
    unsafe { (d.abort)(d.context, task, owner, generation) }
}

unsafe fn pending<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
) -> bool {
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    unsafe { broker::<K, P, N>(context) }.pending()
}
unsafe fn process<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
) -> i32 {
    // SAFETY: the dispatch supplies the typed broker on its supervisor CPU.
    unsafe { broker::<K, P, N>(context).process_one() }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_source_tail(
    task: *mut CTask,
    owner: *const RawOwner,
    generation: u64,
) {
    let d = dispatch();
    // SAFETY: The callback validates source identity and generation before pinning the request.
    unsafe { (d.event)(d.context, task, owner, generation, SOURCE_TAIL) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_pending(owner: *const RawOwner) -> bool {
    let d = dispatch();
    if d.owner != owner {
        fatal();
    }
    // SAFETY: The owner matches the calling supervisor and the dispatch retains its context.
    unsafe { (d.pending)(d.context) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_linux_task_native_process_one(owner: *const RawOwner) -> i32 {
    let d = dispatch();
    if d.owner != owner {
        fatal();
    }
    // SAFETY: The owner matches the calling supervisor and the dispatch retains its context.
    unsafe { (d.process)(d.context) }
}
