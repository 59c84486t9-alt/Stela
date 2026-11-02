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
//! that waits in the C library comes through `stela_libc_wait`: a PE spins; the
//! boot CPU runs the environment, as what it waits for may need it; a thread
//! sleeps.
use super::{
    BOOT_CPU, Installed, PAGE, environment_error, installed, nanoseconds,
    stack::{self, Stack},
};
use crate::{engine::host, output};
use alloc::{
    alloc::{Layout, alloc, dealloc},
    boxed::Box,
};
use core::{
    cell::Cell,
    ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void},
    hint,
    ptr::{self, NonNull},
    slice, str,
    sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicUsize, Ordering, fence},
};
use stela_boot_core::page_window::Cache;
use stela_drivers::platform::work::{WorkError, service::Idle};
use stela_linux::{client, owner::Entered};

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
}

/// What Mesa's threads run on: their calls go to Linux, off this stack. Linux's
/// default, as llvmpipe's compiled shaders probe nothing and one frame can pass 1 MiB.
const THREAD_STACK_BYTES: usize = 8 << 20;
/// What stays free of a task's stack below `run_thread`'s frame, which a
/// thread's Linux calls start past.
const TASK_STACK_MARGIN: u64 = 256;

/// A thread for its task to run.
struct Thread {
    body: unsafe extern "C" fn(*mut c_void),
    argument: *mut c_void,
    core: c_uint,
    stack: Option<Stack>,
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

unsafe extern "C" fn run_thread(context: *mut c_void) {
    // SAFETY: `perform` gave this task the box.
    let thread = unsafe { Box::from_raw(context.cast::<Thread>()) };
    let gpu = installed().expect("threads start in a running environment");
    let stack = thread.stack.as_ref().expect("`perform` gave it one");
    let running = Running {
        top: stack.top(),
        core: thread.core,
        task: (stack::pointer() - TASK_STACK_MARGIN) & !15,
    };
    gpu.threads.borrow_mut().insert(stack.bottom(), running);
    // SAFETY: the thread's own stack, and the C library's thread.
    unsafe { stack::on_stack(running.top, &mut || (thread.body)(thread.argument)) };
    gpu.threads.borrow_mut().remove(&stack.bottom());
}

/// The Mesa thread running here, by its stack.
fn current_thread(gpu: &Installed) -> Option<Running> {
    if host::processor() != BOOT_CPU.load(Ordering::Relaxed) {
        return None;
    }
    let pointer = stack::pointer();
    let threads = gpu.threads.borrow();
    let (_, thread) = threads.range(..=pointer).next_back()?;
    (pointer < thread.top).then_some(*thread)
}

/// A posted call, on its caller's stack until `done`.
struct Request {
    operation: Operation,
    next: Cell<*const Request>,
    result: AtomicI64,
    done: AtomicBool,
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

/// A dma-buf of `runs` and the host's mapping of them, for the GPU's service.
pub(super) fn export(runs: &[client::Run]) -> Option<(c_int, NonNull<u8>)> {
    let address = map_runs(runs, 0, 0)?;
    let fd = submit(Operation::Export(runs.as_ptr(), runs.len()));
    let Ok(fd) = c_int::try_from(fd).and_then(|fd| u32::try_from(fd).map(|_| fd)) else {
        let bytes = runs.iter().map(|run| run.bytes).sum();
        unmap_export(address.as_ptr() as u64, bytes);
        return None;
    };
    Some((fd, address))
}

/// The host's mapping of `runs`, in one piece, then `tail` pages of `scratch`.
pub(super) fn map_runs(runs: &[client::Run], tail: u64, scratch: u64) -> Option<NonNull<u8>> {
    let gpu = installed()?;
    let pages: u64 = runs.iter().map(|run| run.bytes / PAGE).sum::<u64>() + tail;
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
    for page in 0..tail {
        if !gpu
            .window
            .install(next + page * PAGE, scratch, Cache::WriteBack)
        {
            unmap_export(address, pages * PAGE);
            return None;
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
            Operation::Thread(thread) => {
                (*thread).stack = Stack::map(gpu.window, THREAD_STACK_BYTES);
                let spawned = match (*thread).stack {
                    Some(_) => gpu.environment.as_ref().spawn(run_thread, thread.cast()),
                    None => Err(WorkError::Full),
                };
                match spawned {
                    Ok(_) => 0,
                    Err(_) => {
                        drop(Box::from_raw(thread));
                        EAGAIN
                    }
                }
            }
            Operation::Export(runs, count) => {
                client::export(slice::from_raw_parts(runs, count)).into()
            }
            Operation::Wake => {
                client::wake();
                0
            }
        }
    }
}

unsafe extern "C" fn serve(context: *mut c_void) {
    // SAFETY: the poster waits for `done`, so the request is live.
    let request = unsafe { &*context.cast::<Request>() };
    let gpu = installed().expect("requests are posted to a running environment");
    // SAFETY: a task of the environment, whose owner lasts for the boot.
    let _entered = unsafe { Entered::new(gpu.owner.raw()) };
    // SAFETY: entered, on a task, and the poster keeps what the call names.
    let result = unsafe { perform(gpu, request.operation) };
    request.result.store(result, Ordering::Relaxed);
    request.done.store(true, Ordering::Release);
}

/// A wake leaf uses the service task's existing owner/process scope. Its
/// requester keeps the stack record live until the release acknowledgement.
unsafe extern "C" fn serve_wake(context: *mut c_void) {
    // SAFETY: start deferred this Wake request and its poster waits for done.
    let request = unsafe { &*context.cast::<Request>() };
    // SAFETY: the service owns a real entered process continuation; waking
    // waiters is bounded and cannot sleep or enter another owner.
    unsafe { client::wake() };
    request.result.store(0, Ordering::Relaxed);
    request.done.store(true, Ordering::Release);
}

/// Admit posted operations in the dispatcher. General capacity refusal is an
/// immediate resource failure; queued operations must not depend on a later
/// unaccepted ioctl or thread startup. Wake leaves use the reserved service.
pub(super) fn start(gpu: &Installed) -> Result<(), WorkError> {
    let mut request = REQUESTS
        .swap(ptr::null_mut(), Ordering::Acquire)
        .cast_const();
    let mut deferred = false;
    // Inspect every captured request: Owner pressure must not hide a Wake
    // farther down this list, because that wake can release the occupied tasks.
    // SAFETY: captured posted requests stay live until the done acknowledgement.
    while let Some(current) = unsafe { request.as_ref() } {
        let next = current.next.get();
        // SAFETY: posted storage lives until done. Wake leaves run on the
        // existing service task; all other requests retain ordinary task rules.
        let accepted = unsafe {
            match current.operation {
                Operation::Wake => gpu
                    .environment
                    .as_ref()
                    .defer_service(serve_wake, request.cast_mut().cast()),
                _ => gpu
                    .environment
                    .as_ref()
                    .spawn(serve, request.cast_mut().cast())
                    .map(drop),
            }
        };
        match accepted {
            Ok(()) => {}
            Err(WorkError::Full) if matches!(current.operation, Operation::Wake) => {
                // Every occupied leaf slot has a raised SERVICE reason and a
                // bounded nonblocking callback. Retry after that independent
                // service drains; this never waits for a General/pool credit.
                post(current);
                deferred = true;
            }
            Err(WorkError::Full) => {
                if let Operation::Thread(thread) = current.operation {
                    // SAFETY: no serve task accepted this request, so its
                    // transferred thread box has never run or been consumed.
                    drop(unsafe { Box::from_raw(thread) });
                }
                current.result.store(ENOMEM, Ordering::Relaxed);
                current.done.store(true, Ordering::Release);
            }
            Err(error) => return Err(error),
        }
        request = next;
    }
    if deferred {
        gpu.events.notify()?;
    }
    Ok(())
}

fn submit(operation: Operation) -> i64 {
    let Some(gpu) = installed() else {
        return ENODEV;
    };
    if let Some(thread) = current_thread(gpu) {
        let mut result = 0;
        let mut call = || {
            // SAFETY: a task of the environment, as in `serve`.
            let _entered = unsafe { Entered::new(gpu.owner.raw()) };
            // SAFETY: entered, on a task, and the caller keeps what the call
            // names.
            result = unsafe { perform(gpu, operation) };
        };
        // SAFETY: the task runs nothing else below its thread's frame.
        unsafe { stack::on_stack(thread.task, &mut call) };
        return result;
    }
    let request = Request {
        operation,
        next: Cell::new(ptr::null()),
        result: AtomicI64::new(0),
        done: AtomicBool::new(false),
    };
    post(&request);
    if let Err(error) = gpu.events.notify() {
        output::fatal(format_args!(
            "the host's Linux environment failed: {error:?}"
        ));
    }
    if host::processor() != BOOT_CPU.load(Ordering::Relaxed) {
        while !request.done.load(Ordering::Acquire) {
            // The boot CPU's work may be retiring a mapping, which waits for this.
            crate::native_mmio::shootdown::service();
            hint::spin_loop();
        }
    } else {
        let ran = gpu.work.dispatch(|runtime| {
            while !request.done.load(Ordering::Acquire) {
                start(gpu)?;
                runtime.step_or_idle()?;
            }
            Ok::<_, WorkError>(())
        });
        if let Err(error) = ran.and_then(|ran| ran.map_err(environment_error)) {
            output::fatal(format_args!("the host's Linux environment failed: {error}"));
        }
    }
    request.result.load(Ordering::Acquire)
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
        stack: None,
    }));
    submit(Operation::Thread(thread)) as c_int
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_wait(word: *const c_uint, value: c_uint, deadline: u64) {
    let Some(gpu) = installed() else {
        return hint::spin_loop();
    };
    let Some(thread) = current_thread(gpu) else {
        if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
            super::pump();
        }
        return hint::spin_loop();
    };
    let sleeping = &SLEEPING[thread.core as usize - PROCESSORS];
    sleeping.store(word.cast_mut(), Ordering::SeqCst);
    let left = match deadline {
        u64::MAX => u64::MAX,
        _ => deadline.saturating_sub(nanoseconds(host::rdtsc(), gpu.tsc_hz)),
    };
    let mut sleep = || {
        // SAFETY: a task of the environment, as in `serve`.
        let _entered = unsafe { Entered::new(gpu.owner.raw()) };
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
