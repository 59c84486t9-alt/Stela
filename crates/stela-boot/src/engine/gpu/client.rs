//! NVK's process services (`compat/libc/stela/host.h`), from whichever PE runs
//! it.
//!
//! Linux's files belong to the environment on the boot CPU, so a PE posts its
//! call, ends the boot PE's slice and spins: an ioctl costs the caller a
//! round trip, not a core. Each call runs as a Linux task, since an ioctl may
//! sleep on the GPU. On the boot CPU itself there is no one to wait for, so the
//! caller runs the environment until its call is done.
//!
//! A thread Mesa starts is a Linux task too, as Linux's own kthreads are, so it
//! makes its calls in place and sleeps in Linux. It runs Mesa on a stack of its
//! own and goes back to the task's, which is what Linux knows, for those. Everything
//! that waits in the C library comes through `stela_libc_wait`: a PE services
//! shootdowns and spins, the boot CPU also runs the environment, and a task
//! thread sleeps.
use super::{
    BOOT_CPU, Installed, PAGE, installed,
    stack::{self, Stack},
};
use crate::{engine::host, output};
use alloc::{
    alloc::{Layout, alloc, dealloc},
    boxed::Box,
    rc::Rc,
    vec::Vec,
};
use core::{
    cell::Cell,
    ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void},
    hint,
    pin::Pin,
    ptr::{self, NonNull},
    slice, str,
    sync::atomic::{AtomicI64, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence},
};
use stela_boot_core::page_window::Cache;
use stela_drivers::platform::work::{WorkError, service::Idle};
use stela_linux::{
    client,
    task::runtime::{ManagedJob, Outcome, Pending, SubmitError},
};

fn nanoseconds(ticks: u64, tsc_hz: u64) -> u64 {
    (u128::from(ticks) * 1_000_000_000 / u128::from(tsc_hz)) as u64
}

const ENODEV: i64 = -19;
const EFAULT: i64 = -14;
const ENOMEM: i64 = -12;
const EAGAIN: i64 = -11;

/// `struct stela_libc_drm_device`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct DrmDevice {
    pub segment: u16,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub revision: u8,
}

/// `struct drm_nouveau_getparam`.
#[repr(C)]
struct GetParam {
    parameter: u64,
    value: u64,
}

/// `DRM_IOCTL_NOUVEAU_GETPARAM`.
const GET_PARAM: u32 = 0xc010_6440;
const CHIPSET_ID: u64 = 11;
/// The first render node's minor.
const RENDER_MINOR: u32 = 128;

#[derive(Clone, Copy)]
enum Operation {
    Open(u32),
    Close(c_int),
    Duplicate(c_int),
    Device(c_int),
    Control {
        fd: c_int,
        request: u32,
        argument: *mut c_void,
    },
    Map {
        fd: c_int,
        offset: u64,
        size: usize,
    },
    Unmap(u64),
    Fault {
        address: u64,
        write: bool,
    },
    Thread(*mut Thread),
    Wake,
    Export(*const client::Run, usize),
    /// Stop the GPUs as a power-off does.
    Shutdown,
}

/// What Mesa's threads run on: their calls go to Linux, off this stack. Linux's
/// default.
const THREAD_STACK_BYTES: usize = 8 << 20;
/// What stays free of a task's stack below `run_thread`'s frame, which a
/// thread's Linux calls start past.
const TASK_STACK_MARGIN: u64 = 256;

/// A thread for its task to run.
struct Thread {
    body: unsafe extern "C" fn(*mut c_void),
    argument: *mut c_void,
    core: c_uint,
}

/// A running thread of Mesa's.
#[derive(Clone, Copy)]
pub(super) struct Running {
    top: u64,
    core: c_uint,
    /// Where its Linux calls run on its task's stack.
    task: u64,
}

/// `STELA_LIBC_PROCESSORS` and `STELA_LIBC_THREADS`: a thread's core is past
/// the processors'.
const PROCESSORS: usize = 256;
const THREADS: usize = 16;
/// The word each thread is asleep on in `stela_libc_wait`. Every unlock wakes
/// its word, so one nobody sleeps on must cost no call into Linux.
static SLEEPING: [AtomicPtr<c_uint>; THREADS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; THREADS];

fn run_thread(gpu: &Installed, thread: &Thread, stack: &Stack) {
    let running = Running {
        top: stack.top(),
        core: thread.core,
        task: (stack::pointer() - TASK_STACK_MARGIN) & !15,
    };
    gpu.mesa_threads
        .borrow_mut()
        .insert(stack.bottom(), running);
    // SAFETY: the thread's own stack, and the C library's thread.
    unsafe { stack::on_stack(running.top, &mut || (thread.body)(thread.argument)) };
    gpu.mesa_threads.borrow_mut().remove(&stack.bottom());
}

/// The Mesa thread running here, by its stack.
fn current_thread(gpu: &Installed) -> Option<Running> {
    if host::processor() != BOOT_CPU.load(Ordering::Relaxed) {
        return None;
    }
    let pointer = stack::pointer();
    let threads = gpu.mesa_threads.borrow();
    let (_, thread) = threads.range(..=pointer).next_back()?;
    (pointer < thread.top).then_some(*thread)
}

/// A posted call, which its caller keeps until `done`.
struct Request {
    operation: Operation,
    next: Cell<*const Request>,
    result: AtomicI64,
    done: AtomicU32,
    wake_task: bool,
}

impl Request {
    fn new(operation: Operation) -> Self {
        Self {
            operation,
            next: Cell::new(ptr::null()),
            result: AtomicI64::new(0),
            done: AtomicU32::new(0),
            wake_task: false,
        }
    }

    fn complete(&self, result: i64) -> bool {
        let wake_task = self.wake_task;
        self.result.store(result, Ordering::Relaxed);
        self.done.store(1, Ordering::Release);
        wake_task
    }

    fn refuse(&self, result: i64) -> bool {
        if let Operation::Thread(thread) = self.operation {
            // SAFETY: no original child executed the request or took its box.
            drop(unsafe { Box::from_raw(thread) });
        }
        self.complete(result)
    }
}

/// The posted calls, newest first.
static REQUESTS: AtomicPtr<Request> = AtomicPtr::new(ptr::null_mut());
/// The mappings clients hold. A fault with none is no client's, so it reports
/// on the spot instead of waiting for the boot PE, which may be waiting for it.
static MAPPINGS: AtomicUsize = AtomicUsize::new(0);

fn post(request: &Request) {
    let this = ptr::from_ref(request).cast_mut();
    let mut head = REQUESTS.load(Ordering::Relaxed);
    loop {
        request.next.set(head);
        match REQUESTS.compare_exchange_weak(head, this, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return,
            Err(current) => head = current,
        }
    }
}

/// Stops the GPUs' drivers within `seconds`, as a reset is safest for a card
/// whose GSP has unloaded, and says whether they did. A GSP that does not answer
/// its unload stays running: Linux then waits on it for minutes, with the guest
/// already stopped.
pub(super) fn shutdown(seconds: u64) -> bool {
    // A wait that gives up leaves this with the Linux task.
    unload(
        Box::leak(Box::new(Request::new(Operation::Shutdown))),
        seconds,
    )
}

/// [`shutdown`] for a fatal stop, which allocates nothing: the stop never
/// returns, so its stack keeps the request for a wait that gives up.
pub(super) fn shutdown_for_fatal(seconds: u64) -> bool {
    unload(&Request::new(Operation::Shutdown), seconds)
}

fn unload(request: &Request, seconds: u64) -> bool {
    let Some(gpu) = installed() else {
        return true;
    };
    let deadline = host::rdtsc().saturating_add(seconds.saturating_mul(gpu.tsc_hz));
    wait(gpu, request, deadline);
    request.done.load(Ordering::Acquire) != 0
}

/// A dma-buf of `runs` and the host's mapping of them, for the GPU's service.
pub(super) fn export(runs: &[client::Run]) -> Option<(c_int, NonNull<u8>)> {
    let address = map_runs(runs)?;
    let fd = submit(Operation::Export(runs.as_ptr(), runs.len()));
    let Ok(fd) = c_int::try_from(fd).and_then(|fd| u32::try_from(fd).map(|_| fd)) else {
        crate::output::arguments(format_args!("GPU export of {} runs: {fd}\n", runs.len()));
        let bytes = runs.iter().map(|run| run.bytes).sum();
        unmap_export(address.as_ptr() as u64, bytes);
        return None;
    };
    Some((fd, address))
}

/// The host's mapping of `runs`, in one piece.
fn map_runs(runs: &[client::Run]) -> Option<NonNull<u8>> {
    let gpu = installed()?;
    let pages: u64 = runs.iter().map(|run| run.bytes / PAGE).sum();
    let address = gpu.window.reserve(pages as usize)?;
    let mut next = address;
    for run in runs {
        for page in 0..run.bytes / PAGE {
            if !gpu
                .window
                .install(next, run.physical + page * PAGE, Cache::WriteBack)
            {
                unmap_export(address, pages * PAGE);
                return None;
            }
            next += PAGE;
        }
    }
    NonNull::new(address as *mut u8)
}

/// Ends the host's mapping of an export.
pub(super) fn unmap_export(address: u64, bytes: u64) {
    let (Some(gpu), pages) = (installed(), (bytes / PAGE) as usize) else {
        return;
    };
    // A processor that kept the translation keeps the addresses too.
    if gpu.window.remove(address, pages) {
        gpu.window.release(address, pages);
    }
}

/// Closes a descriptor Linux gave out.
pub(super) fn close_descriptor(fd: c_int) {
    let result = submit(Operation::Close(fd));
    if result < 0 {
        // This void exporter/display cleanup contract cannot return the error
        // or prove that its caller will keep the original physical owner.
        // Stop before releasing that owner's stack, export mapping or memory.
        output::fatal(format_args!(
            "GPU descriptor {fd} cleanup refused ({result}); retaining its owners"
        ));
    }
}

/// Run `operation` on a Linux task.
///
/// # Safety
/// Entered in the owner, on a task; `operation`'s pointers are its caller's.
unsafe fn perform(gpu: &Installed, operation: Operation) -> i64 {
    // SAFETY: the function's own contract for every arm.
    unsafe {
        match operation {
            Operation::Open(minor) => stela_drivers::gpu::drm::open(minor).into(),
            Operation::Close(fd) => client::close(fd).into(),
            Operation::Duplicate(fd) => client::duplicate(fd).into(),
            Operation::Device(fd) => client::device(fd),
            Operation::Control {
                fd,
                request,
                argument,
            } => client::control(fd, request, argument),
            Operation::Map { fd, offset, size } => {
                let pages = size / PAGE as usize;
                let Some(address) = gpu.window.reserve(pages) else {
                    return ENOMEM;
                };
                match client::map(fd, address, size, offset) {
                    Ok(mapping) => {
                        gpu.mappings.borrow_mut().insert(address, (mapping, pages));
                        MAPPINGS.fetch_add(1, Ordering::Relaxed);
                        address as i64
                    }
                    Err(error) => {
                        gpu.window.release(address, pages);
                        error.into()
                    }
                }
            }
            Operation::Unmap(address) => {
                let Some((mapping, pages)) = gpu.mappings.borrow_mut().remove(&address) else {
                    return EFAULT;
                };
                client::unmap(mapping);
                MAPPINGS.fetch_sub(1, Ordering::Relaxed);
                // A processor that kept the translation keeps the addresses too.
                if gpu.window.remove(address, pages) {
                    gpu.window.release(address, pages);
                }
                0
            }
            Operation::Fault { address, write } => {
                let mappings = gpu.mappings.borrow();
                let found = mappings.range(..=address).next_back();
                let Some((&start, &(mapping, pages))) = found else {
                    return EFAULT;
                };
                if address >= start + pages as u64 * PAGE || !client::fault(mapping, address, write)
                {
                    return EFAULT;
                }
                0
            }
            Operation::Thread(_) => unreachable!("a thread runs in its original managed child"),
            Operation::Export(runs, count) => {
                client::export(slice::from_raw_parts(runs, count)).into()
            }
            Operation::Wake => {
                client::wake();
                0
            }
            Operation::Shutdown => {
                let gpu = installed().expect("requests are posted to a running environment");
                gpu.start
                    ._attached
                    .iter()
                    .for_each(|attached| attached.shutdown());
                0
            }
        }
    }
}

struct RequestJob {
    request: NonNull<Request>,
    completed: Rc<Cell<bool>>,
    thread: Option<(Box<Thread>, Stack)>,
}

// SAFETY: the caller retains the posted record through completion. After
// completion neither the job nor its join dereferences the request again.
// Thread storage remains owned by the job through native and source join.
unsafe impl ManagedJob for RequestJob {
    fn run(mut self: Pin<&mut Self>) {
        let gpu = installed().expect("managed requests have a running environment");
        // SAFETY: the request stays live through its release acknowledgement.
        let request = unsafe { self.request.as_ref() };
        let code = request_code(&request.operation);
        let started = host::rdtsc();
        let result = if let Operation::Thread(thread) = request.operation {
            // SAFETY: this original child is the sole consumer of the box.
            let thread = unsafe { Box::from_raw(thread) };
            if let Some(stack) = Stack::map(gpu.window, THREAD_STACK_BYTES) {
                self.thread = Some((thread, stack));
                0
            } else {
                EAGAIN
            }
        } else {
            // SAFETY: the broker entered the canonical Linux owner on this
            // original task. The requester retains the operation's inputs.
            unsafe { perform(gpu, request.operation) }
        };
        count(&SERVED, code, host::rdtsc().wrapping_sub(started));
        self.completed.set(true);
        if request.complete(result) {
            // SAFETY: the same source task owns the Linux wait queue.
            unsafe { client::wake() };
        }
        if let Some((thread, stack)) = &self.thread {
            run_thread(gpu, thread, stack);
        }
    }
}

pub(super) struct PendingRequest {
    job: Pending,
    request: NonNull<Request>,
    completed: Rc<Cell<bool>>,
}

fn join_requests(gpu: &Installed) {
    let mut requests = gpu.requests.take();
    let mut index = 0;
    while index < requests.len() {
        if !requests[index].job.status().joined {
            index += 1;
            continue;
        }
        let PendingRequest {
            job,
            request,
            completed,
        } = requests.swap_remove(index);
        // SAFETY: same taskless dispatcher, after all active C/native frames
        // have returned, with no source or metadata loan.
        match unsafe { job.try_join() } {
            Ok(joined) => {
                if !completed.get() {
                    if !matches!(
                        joined.outcome(),
                        Outcome::CreationFailed(_) | Outcome::Skipped(_)
                    ) {
                        output::fatal(format_args!(
                            "Linux request ended before completion: {:?}",
                            joined.outcome()
                        ));
                    }
                    // SAFETY: the poster still waits and no callback took the box.
                    let wake = unsafe { request.as_ref() }.refuse(ENOMEM);
                    gpu.wake_task.set(gpu.wake_task.get() || wake);
                }
            }
            Err(job) => {
                requests.push(PendingRequest {
                    job,
                    request,
                    completed,
                });
                break;
            }
        }
    }
    gpu.requests.replace(requests);
}

unsafe extern "C" fn wake_waiters(_: *mut c_void) {
    // SAFETY: a reserved service leaf is already entered in the exact owner.
    unsafe { client::wake() };
}

/// An ioctl by its request code; every other request as zero.
fn request_code(operation: &Operation) -> u32 {
    match *operation {
        Operation::Control { request, .. } => request,
        _ => 0,
    }
}

/// Request counts and ticks by request code plus one, in slots that fill in
/// order and stay claimed, as the gate's call counts do.
type Counts = [(AtomicU32, AtomicU64, AtomicU64); 64];

fn count(counts: &Counts, code: u32, ticks: u64) {
    let key = code.wrapping_add(1);
    if let Some(slot) = counts.iter().find(|slot| {
        match slot
            .0
            .compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => true,
            Err(claimed) => claimed == key,
        }
    }) {
        slot.1.fetch_add(1, Ordering::Relaxed);
        slot.2.fetch_add(ticks, Ordering::Relaxed);
    }
}

/// Each code's count and ticks since the last call, most ticks first.
fn take(counts: &Counts) -> Vec<(u32, u64, u64)> {
    let mut taken: Vec<_> = counts
        .iter()
        .filter_map(|slot| {
            let count = slot.1.swap(0, Ordering::Relaxed);
            (count != 0).then(|| {
                (
                    slot.0.load(Ordering::Relaxed).wrapping_sub(1),
                    count,
                    slot.2.swap(0, Ordering::Relaxed),
                )
            })
        })
        .collect();
    taken.sort_unstable_by_key(|&(_, _, ticks)| core::cmp::Reverse(ticks));
    taken
}

/// A wake leaf uses the service task's existing owner/process scope. Its
/// requester keeps the stack record live until the release acknowledgement.
unsafe extern "C" fn serve_wake(context: *mut c_void) {
    // SAFETY: start deferred this Wake request and its poster waits for done.
    let request = unsafe { &*context.cast::<Request>() };
    // SAFETY: the service owns a real entered process continuation; waking
    // waiters is bounded and cannot sleep or enter another owner.
    unsafe { client::wake() };
    request.complete(0);
}

/// Admit posted operations in the dispatcher. General capacity refusal is an
/// immediate resource failure; queued operations must not depend on a later
/// unaccepted ioctl or thread startup. Wake leaves use the reserved service.
pub(super) fn start(gpu: &Installed) -> Result<(), WorkError> {
    join_requests(gpu);
    let mut request = REQUESTS
        .swap(ptr::null_mut(), Ordering::Acquire)
        .cast_const();
    let mut deferred = false;
    // Capacity refusal must not hide a Wake behind occupied original children.
    // SAFETY: captured requests stay live until their completion is published.
    while let Some(current) = unsafe { request.as_ref() } {
        let next = current.next.get();
        if matches!(current.operation, Operation::Wake) {
            // SAFETY: the poster holds the record until this reserved leaf runs.
            match unsafe {
                gpu.owner
                    .environment()
                    .defer_service(serve_wake, request.cast_mut().cast())
            } {
                Ok(()) => {}
                Err(WorkError::Full) => {
                    post(current);
                    deferred = true;
                }
                Err(error) => return Err(error),
            }
        } else {
            let completed = Rc::new(Cell::new(false));
            let request = NonNull::from(current);
            let job = Box::pin(RequestJob {
                request,
                completed: completed.clone(),
                thread: None,
            });
            // SAFETY: the exact dispatcher and installed owner retain the
            // original child and the caller retains the record through completion.
            match unsafe { gpu.threads.submit(job) } {
                Ok(job) => gpu.requests.borrow_mut().push(PendingRequest {
                    job,
                    request,
                    completed,
                }),
                Err(refusal) => match refusal.error {
                    SubmitError::Capacity => {
                        let wake = current.refuse(ENOMEM);
                        gpu.wake_task.set(gpu.wake_task.get() || wake);
                    }
                    SubmitError::Context(error) => return Err(error),
                },
            }
        }
        request = next;
    }
    if gpu.wake_task.get() {
        // SAFETY: this wake needs no caller storage and cannot sleep.
        match unsafe {
            gpu.owner
                .environment()
                .defer_service(wake_waiters, ptr::null_mut())
        } {
            Ok(()) => gpu.wake_task.set(false),
            Err(WorkError::Full) => deferred = true,
            Err(error) => return Err(error),
        }
    }
    if deferred {
        gpu.events.notify()?;
    }
    Ok(())
}

fn submit(operation: Operation) -> i64 {
    let Some(gpu) = installed() else {
        return {
            if let Operation::Thread(thread) = operation {
                // SAFETY: the thread was never accepted.
                drop(unsafe { Box::from_raw(thread) });
            }
            ENODEV
        };
    };
    if let Some(thread) = current_thread(gpu) {
        let mut result = 0;
        let mut call = || {
            if matches!(operation, Operation::Thread(_)) {
                let mut request = Request::new(operation);
                request.wake_task = true;
                post(&request);
                if let Err(error) = gpu.events.notify() {
                    output::fatal(format_args!(
                        "the host's Linux environment failed: {error:?}"
                    ));
                }
                // SAFETY: Mesa is back on its original source task stack.
                // The completion word stays live through the Linux wait.
                unsafe { client::wait(request.done.as_ptr(), 0, u64::MAX) };
                result = request.result.load(Ordering::Acquire);
            } else {
                // SAFETY: back on the original source task's Linux stack.
                result = unsafe { perform(gpu, operation) };
            }
        };
        // SAFETY: the task runs nothing else below its thread's frame.
        unsafe { stack::on_stack(thread.task, &mut call) };
        return result;
    }
    let code = request_code(&operation);
    let request = Request::new(operation);
    let posted = host::rdtsc();
    wait(gpu, &request, u64::MAX);
    let waited = host::rdtsc().wrapping_sub(posted);
    if let Some(mine) = MINE.get(host::processor() as usize) {
        mine.0.fetch_add(1, Ordering::Relaxed);
        mine.1.fetch_add(waited, Ordering::Relaxed);
    }
    count(&POSTED, code, waited);
    request.result.load(Ordering::Acquire)
}

/// Requests posted to the service task since [`take_posted`] by request
/// code: how many, and the TSC ticks their posters waited for them.
static POSTED: Counts = [const { (AtomicU32::new(0), AtomicU64::new(0), AtomicU64::new(0)) }; 64];

/// Posted requests the service task performed since [`take_served`] by
/// request code: how many, and the TSC ticks performing them took, which the
/// boot CPU spends unless the request sleeps.
static SERVED: Counts = [const { (AtomicU32::new(0), AtomicU64::new(0), AtomicU64::new(0)) }; 64];

/// Requests each processor posted since it last called [`take_mine`]: how
/// many, and the TSC ticks it waited for them.
static MINE: [(AtomicU64, AtomicU64); PROCESSORS] =
    [const { (AtomicU64::new(0), AtomicU64::new(0)) }; PROCESSORS];

/// How many requests this processor posted since it last asked, and the
/// ticks it waited for them: a gate call's share of the boot CPU's work.
pub(super) fn take_mine() -> (u64, u64) {
    MINE.get(host::processor() as usize).map_or((0, 0), |mine| {
        (
            mine.0.swap(0, Ordering::Relaxed),
            mine.1.swap(0, Ordering::Relaxed),
        )
    })
}

/// The requests posted since the last call: each request code with its
/// count and the ticks they waited, most waited first.
pub(super) fn take_posted() -> Vec<(u32, u64, u64)> {
    take(&POSTED)
}

/// The requests the service task performed since the last call: each
/// request code with its count and the ticks performing them took.
pub(super) fn take_served() -> Vec<(u32, u64, u64)> {
    take(&SERVED)
}

/// Posts `request` to the service and waits for it, until the host counter
/// reaches `deadline`.
fn wait(gpu: &Installed, request: &Request, deadline: u64) {
    let waiting = || request.done.load(Ordering::Acquire) == 0 && host::rdtsc() < deadline;
    post(request);
    if let Err(error) = gpu.events.notify() {
        output::fatal(format_args!(
            "the host's Linux environment failed: {error:?}"
        ));
    }
    if host::processor() != BOOT_CPU.load(Ordering::Relaxed) {
        while waiting() {
            // The boot CPU's work may be retiring a mapping, which waits for this.
            crate::native_mmio::shootdown::service();
            hint::spin_loop();
        }
    } else {
        let ran = gpu.work.dispatch_linux(|runtime| {
            while waiting() {
                gpu.advance_children();
                start(gpu)?;
                if waiting() {
                    runtime.step_or_idle()?;
                }
            }
            Ok(())
        });
        if let Err(error) = ran {
            output::fatal(format_args!("the host's Linux environment failed: {error}"));
        }
    }
}

/// A file of the DRM node at `minor`.
pub(super) fn open_node(minor: u32) -> Option<c_int> {
    let fd = submit(Operation::Open(minor)) as c_int;
    (fd >= 0).then_some(fd)
}

/// The ioctl `request` on `fd`: zero or a negative errno.
pub(super) fn control(fd: c_int, request: u32, argument: *mut c_void) -> i64 {
    submit(Operation::Control {
        fd,
        request,
        argument,
    })
}

/// Maps `size` bytes of `fd` at `offset`.
pub(super) fn map(fd: c_int, offset: u64, size: usize) -> Option<NonNull<u8>> {
    let address = submit(Operation::Map { fd, offset, size });
    NonNull::new(u64::try_from(address).ok()? as *mut u8)
}

/// `NOUVEAU_GETPARAM_CHIPSET_ID` of the bound GPU at `index`.
pub(super) fn chipset(index: u32) -> Option<u16> {
    let fd = submit(Operation::Open(RENDER_MINOR + index)) as c_int;
    if fd < 0 {
        return None;
    }
    let mut parameter = GetParam {
        parameter: CHIPSET_ID,
        value: 0,
    };
    let result = submit(Operation::Control {
        fd,
        request: GET_PARAM,
        argument: (&raw mut parameter).cast(),
    });
    close_descriptor(fd);
    (result == 0).then_some(parameter.value as u16)
}

/// Serve a fault on a mapping that moved, as Linux unmaps a buffer it evicts.
/// False when `address` is not one a client mapped.
pub(in crate::engine) fn serve_fault(address: u64, write: bool) -> bool {
    installed().is_some_and(|gpu| {
        gpu.window.contains(address)
            && MAPPINGS.load(Ordering::Relaxed) != 0
            && submit(Operation::Fault { address, write }) == 0
    })
}

fn text(pointer: *const c_char) -> &'static str {
    // SAFETY: the C library's message, a literal.
    unsafe { CStr::from_ptr(pointer) }.to_str().unwrap_or("?")
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_allocate(size: usize, alignment: usize) -> *mut u8 {
    match Layout::from_size_align(size, alignment) {
        // SAFETY: the C library never asks for zero bytes: a block has a header.
        Ok(layout) => unsafe { alloc(layout) },
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_release(pointer: *mut u8, size: usize, alignment: usize) {
    // SAFETY: the C library gives back what it got with this size and alignment.
    unsafe { dealloc(pointer, Layout::from_size_align_unchecked(size, alignment)) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_log(pointer: *const u8, size: usize) {
    // SAFETY: the C library's live text.
    let bytes = unsafe { slice::from_raw_parts(pointer, size) };
    if let Ok(line) = str::from_utf8(bytes) {
        output::arguments(format_args!("{line}"));
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_fatal(message: *const c_char) -> ! {
    output::fatal(text(message))
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_memory_bytes() -> u64 {
    installed().map_or(0, |gpu| gpu.heap_bytes)
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_now_ns() -> u64 {
    installed().map_or(0, |gpu| nanoseconds(host::rdtsc(), gpu.tsc_hz))
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_core() -> c_uint {
    installed()
        .and_then(current_thread)
        .map_or_else(host::processor, |thread| thread.core)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_thread_start(
    body: unsafe extern "C" fn(*mut c_void),
    argument: *mut c_void,
    core: c_uint,
) -> c_int {
    let thread = Box::into_raw(Box::new(Thread {
        body,
        argument,
        core,
    }));
    submit(Operation::Thread(thread)) as c_int
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_wait(word: *const c_uint, value: c_uint, deadline: u64) {
    let Some(gpu) = installed() else {
        return hint::spin_loop();
    };
    let Some(thread) = current_thread(gpu) else {
        return super::gate::relax();
    };
    let sleeping = &SLEEPING[thread.core as usize - PROCESSORS];
    sleeping.store(word.cast_mut(), Ordering::SeqCst);
    let left = match deadline {
        u64::MAX => u64::MAX,
        _ => deadline.saturating_sub(nanoseconds(host::rdtsc(), gpu.tsc_hz)),
    };
    let mut sleep = || {
        // SAFETY: entered, on a task, and the C library's word outlives its wait.
        unsafe { client::wait(word, value, left) };
    };
    // SAFETY: the task runs nothing else below its thread's frame.
    unsafe { stack::on_stack(thread.task, &mut sleep) };
    sleeping.store(ptr::null_mut(), Ordering::SeqCst);
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_wake(word: *const c_uint) {
    // Against a sleeper's mark before it reads the word.
    fence(Ordering::SeqCst);
    let asleep = |slot: &AtomicPtr<c_uint>| slot.load(Ordering::SeqCst).cast_const() == word;
    if SLEEPING.iter().any(asleep) {
        submit(Operation::Wake);
    }
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_open(minor: c_uint) -> c_int {
    submit(Operation::Open(minor)) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_close(fd: c_int) -> c_int {
    submit(Operation::Close(fd)) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_dup(fd: c_int) -> c_int {
    submit(Operation::Duplicate(fd)) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_rdev(fd: c_int) -> c_long {
    submit(Operation::Device(fd)) as c_long
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_ioctl(fd: c_int, request: c_ulong, argument: *mut c_void) -> c_int {
    submit(Operation::Control {
        fd,
        request: request as u32,
        argument,
    }) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_mmap(fd: c_int, offset: u64, size: usize) -> *mut c_void {
    submit(Operation::Map { fd, offset, size }) as *mut c_void
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_munmap(address: *mut c_void, _size: usize) -> c_int {
    let mapped = installed().is_some_and(|gpu| gpu.window.contains(address as u64));
    if !mapped {
        return 0;
    }
    let result = submit(Operation::Unmap(address as u64));
    if result < 0 { result as c_int } else { 1 }
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_devices() -> c_uint {
    installed().map_or(0, |gpu| gpu.start.bound.len() as c_uint)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_drm_device(index: c_uint, device: *mut DrmDevice) {
    if let Some(found) = installed().and_then(|gpu| gpu.start.bound.get(index as usize)) {
        // SAFETY: the C library's record.
        unsafe { device.write(found.drm) };
    }
}
