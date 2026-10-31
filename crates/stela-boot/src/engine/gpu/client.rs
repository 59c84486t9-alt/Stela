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
//! makes its calls in place and sleeps in Linux. Everything that waits in the C
//! library comes through `stela_libc_wait`: a PE spins; the boot CPU runs the
//! environment, as what it waits for may need it; a thread sleeps.
use super::{BOOT_CPU, Installed, PAGE, environment_error, installed, nanoseconds};
use crate::{engine::host, output};
use alloc::{
    alloc::{Layout, alloc, dealloc},
    boxed::Box,
};
use core::{
    cell::Cell,
    ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void},
    hint, ptr, slice, str,
    sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicUsize, Ordering, fence},
};
use stela_drivers::{
    gpu::linux::{client, owner::Entered},
    platform::work::{WorkError, service::Idle},
};

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
}

/// A thread for its task to run.
struct Thread {
    body: unsafe extern "C" fn(*mut c_void),
    argument: *mut c_void,
    core: c_uint,
}

/// Threads asleep in `stela_libc_wait`.
static SLEEPING: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn run_thread(context: *mut c_void) {
    // SAFETY: `perform` gave this task the box.
    let thread = unsafe { Box::from_raw(context.cast::<Thread>()) };
    let gpu = installed().expect("threads start in a running environment");
    let id = match gpu.work.current_id() {
        Ok(id) => id,
        Err(error) => output::fatal(format_args!("a Mesa thread has no task: {error}")),
    };
    gpu.threads.borrow_mut().insert(id, thread.core);
    // SAFETY: the C library's thread, on a task of its own.
    unsafe { (thread.body)(thread.argument) };
    gpu.threads.borrow_mut().remove(&id);
}

/// The Mesa thread running here, by its `stela_libc_core`.
fn current_thread(gpu: &Installed) -> Option<c_uint> {
    if host::processor() != BOOT_CPU.load(Ordering::Relaxed) {
        return None;
    }
    let threads = gpu.threads.borrow();
    if threads.is_empty() {
        return None;
    }
    threads.get(&gpu.work.current_id().ok()?).copied()
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

/// Run `operation` on a Linux task.
///
/// # Safety
/// Entered in the owner, on a task; `operation`'s pointers are its caller's.
unsafe fn perform(gpu: &Installed, operation: Operation) -> i64 {
    // SAFETY: the function's own contract for every arm.
    unsafe {
        match operation {
            Operation::Open(minor) => client::open(minor).into(),
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
                match gpu.environment.as_ref().spawn(run_thread, thread.cast()) {
                    Ok(_) => 0,
                    Err(_) => {
                        drop(Box::from_raw(thread));
                        EAGAIN
                    }
                }
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

/// Start a task for each posted call. In the dispatcher. Calls past what the
/// queue holds go back, to wait for a task to finish.
pub(super) fn start(gpu: &Installed) -> Result<(), WorkError> {
    let mut request = REQUESTS
        .swap(ptr::null_mut(), Ordering::Acquire)
        .cast_const();
    // SAFETY: a posted request stays live until it is done, and only this
    // function reads `next` once it has been taken.
    while let Some(current) = unsafe { request.as_ref() } {
        let next = current.next.get();
        // SAFETY: as above: `serve` ends before its poster stops waiting.
        let spawned = unsafe {
            gpu.environment
                .as_ref()
                .spawn(serve, request.cast_mut().cast())
        };
        match spawned {
            Ok(_) => request = next,
            Err(WorkError::Full) => {
                // SAFETY: as above, for this and what follows it.
                while let Some(left) = unsafe { request.as_ref() } {
                    request = left.next.get();
                    post(left);
                }
                return gpu.events.notify();
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn submit(operation: Operation) -> i64 {
    let Some(gpu) = installed() else {
        return ENODEV;
    };
    if current_thread(gpu).is_some() {
        // SAFETY: a task of the environment, as in `serve`.
        let _entered = unsafe { Entered::new(gpu.owner.raw()) };
        // SAFETY: entered, on a task, and the caller keeps what the call names.
        return unsafe { perform(gpu, operation) };
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

/// Serve a fault on a mapping that moved, as Linux unmaps a buffer it evicts.
/// False when `address` is not one a client mapped.
pub(in crate::engine) fn serve_fault(address: u64, write: bool) -> bool {
    installed().is_some_and(|gpu| {
        gpu.window.contains(address) && submit(Operation::Fault { address, write }) == 0
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
extern "C" fn stela_libc_now_ns() -> u64 {
    installed().map_or(0, |gpu| nanoseconds(host::rdtsc(), gpu.tsc_hz))
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_core() -> c_uint {
    installed()
        .and_then(current_thread)
        .unwrap_or_else(host::processor)
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
    if current_thread(gpu).is_none() {
        if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
            super::pump();
        }
        return hint::spin_loop();
    }
    SLEEPING.fetch_add(1, Ordering::SeqCst);
    let left = match deadline {
        u64::MAX => u64::MAX,
        _ => deadline.saturating_sub(nanoseconds(host::rdtsc(), gpu.tsc_hz)),
    };
    // SAFETY: a task of the environment, as in `serve`.
    let _entered = unsafe { Entered::new(gpu.owner.raw()) };
    // SAFETY: entered, on a task, and the C library's word outlives its wait.
    unsafe { client::wait(word, value, left) };
    SLEEPING.fetch_sub(1, Ordering::SeqCst);
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_wake(_word: *const c_uint) {
    // Against a sleeper's count before it reads the word.
    fence(Ordering::SeqCst);
    if SLEEPING.load(Ordering::SeqCst) != 0 {
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
    if mapped {
        submit(Operation::Unmap(address as u64));
    }
    mapped.into()
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_drm_devices() -> c_uint {
    installed().map_or(0, |gpu| gpu.start.bound.len() as c_uint)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_libc_drm_device(index: c_uint, device: *mut DrmDevice) {
    if let Some(found) = installed().and_then(|gpu| gpu.start.bound.get(index as usize)) {
        // SAFETY: the C library's record.
        unsafe { device.write(*found) };
    }
}
