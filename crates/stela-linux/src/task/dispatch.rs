//! Single installed execution owner for the original Linux child callbacks.
use super::{CTask, OriginalBirth, Rank};
use crate::owner::RawOwner;
use alloc::boxed::Box;
use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

pub(super) type SourceEntry = unsafe extern "C" fn(*mut c_void) -> i32;
pub(super) const SOURCE_FREED: u8 = 2;
pub(super) const TERMINAL_RETURNED: u8 = 4;
pub(super) const SOURCE_TAIL: u8 = 16;

#[cfg(all(
    feature = "hosted-runtime",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(super) struct HostedHooks {
    pub(super) runtime: *const c_void,
    pub(super) start: unsafe fn(*const c_void) -> i32,
    pub(super) service: unsafe fn(*const c_void) -> i32,
    pub(super) dispatcher: unsafe fn(*const c_void) -> i32,
}

pub(super) struct Dispatch {
    #[cfg(all(
        feature = "hosted-runtime",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) hosted: Option<HostedHooks>,
    pub(super) pending: unsafe fn(*const c_void) -> bool,
    pub(super) process: unsafe fn(*const c_void) -> i32,
    pub(super) context: *const c_void,
    pub(super) owner: *const RawOwner,
    pub(super) allocate: unsafe fn(*const c_void, *mut OriginalBirth, i32, *mut bool) -> i32,
    pub(super) thread: unsafe fn(
        *const c_void,
        *mut CTask,
        *const RawOwner,
        Option<SourceEntry>,
        *mut c_void,
    ) -> i32,
    pub(super) reserve_rank:
        unsafe fn(*const c_void, *mut CTask, *const RawOwner, *const Rank) -> i32,
    pub(super) publish: unsafe fn(*const c_void, *mut CTask, *const RawOwner, *const Rank),
    pub(super) activate: unsafe fn(*const c_void, *mut CTask, *const RawOwner),
    pub(super) event: unsafe fn(*const c_void, *mut CTask, *const RawOwner, u64, u8),
    pub(super) abort: unsafe fn(*const c_void, *mut CTask, *const RawOwner, u64),
}
static DISPATCH: AtomicPtr<Dispatch> = AtomicPtr::new(ptr::null_mut());

impl Dispatch {
    pub(super) fn installed() -> bool {
        !DISPATCH.load(Ordering::Acquire).is_null()
    }

    #[cfg(all(
        feature = "hosted-runtime",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(super) fn hosted(runtime: *const c_void) -> Option<(&'static Self, &'static HostedHooks)> {
        let pointer = DISPATCH.load(Ordering::Acquire);
        // SAFETY: successful publication keeps this immutable table permanently.
        let table = unsafe { pointer.as_ref() }?;
        let hooks = table.hosted.as_ref()?;
        (hooks.runtime == runtime).then_some((table, hooks))
    }

    /// Publish the sole source callback owner.
    ///
    /// # Safety
    /// Every callback must interpret this exact retained context and owner.
    /// They remain valid for the life of this archive. The installer must
    /// establish the actual execution domain before any source callback.
    pub(super) unsafe fn install(self) -> Result<(), ()> {
        let pointer = Box::into_raw(Box::new(self));
        if DISPATCH
            .compare_exchange(
                ptr::null_mut(),
                pointer,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // SAFETY: no callback can observe this unpublished allocation.
            drop(unsafe { Box::from_raw(pointer) });
            return Err(());
        }
        Ok(())
    }
}

#[inline(never)]
fn fatal() -> ! {
    // SAFETY: source publication cannot proceed without its exact kept owner.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn dispatch() -> &'static Dispatch {
    let pointer = DISPATCH.load(Ordering::Acquire);
    if pointer.is_null() {
        fatal();
    }
    // SAFETY: permanent unique actual owner graph kept before release-store.
    unsafe { &*pointer }
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
    entry: Option<SourceEntry>,
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
unsafe extern "C" fn stela_linux_task_native_reserve_rank(
    task: *mut CTask,
    owner: *const RawOwner,
    rank: *const Rank,
) -> i32 {
    let d = dispatch();
    if d.owner != owner {
        fatal();
    }
    // SAFETY: the owner matches and C lends the task and initialized rank.
    unsafe { (d.reserve_rank)(d.context, task, owner, rank) }
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
