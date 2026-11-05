use super::*;
use crate::task::dispatch::Dispatch;

pub(super) unsafe fn publish<
    K: KernelThreadPlatform + 'static,
    P: Provider + 'static,
    const N: usize,
>(
    broker: &'static Broker<K, P, N>,
) -> Result<(), Error> {
    let dispatch = Dispatch {
        #[cfg(all(
            feature = "hosted-runtime",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        hosted: None,
        pending: pending::<K, P, N>,
        process: process::<K, P, N>,
        context: broker as *const _ as *const c_void,
        owner: broker.kernel.raw(),
        allocate: allocate::<K, P, N>,
        thread: thread::<K, P, N>,
        reserve_rank: reserve_rank::<K, P, N>,
        publish: publish_child::<K, P, N>,
        activate: activate::<K, P, N>,
        event: event::<K, P, N>,
        abort: abort::<K, P, N>,
    };
    // SAFETY: the exact typed broker remains permanently retained by its installer.
    unsafe { dispatch.install() }.map_err(|()| Error::Busy)
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
    entry: Option<SourceEntry>,
    argument: *mut c_void,
) -> i32 {
    // SAFETY: The dispatch pairs this trampoline with its typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, None);
    // SAFETY: The read guard pins the request, and C retains the entry and argument.
    unsafe { (&*read.pointer).prepare_thread(entry, argument) }
}
unsafe fn reserve_rank<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>(
    context: *const c_void,
    task: *mut CTask,
    owner: *const RawOwner,
    rank: *const Rank,
) -> i32 {
    if rank.is_null() {
        fatal();
    }
    // SAFETY: dispatch retains the typed broker.
    let b = unsafe { broker::<K, P, N>(context) };
    let read = b.lookup(task, owner, None);
    // SAFETY: the request stays pinned and C lends the initialized rank.
    unsafe { (&*read.pointer).reserve_rank(&*rank) }
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
