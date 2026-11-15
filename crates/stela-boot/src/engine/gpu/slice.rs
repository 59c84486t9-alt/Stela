//! Deferred GPU jobs in bounded host steps.
//!
//! A shader compilation can run for seconds, and a processor kept from its
//! guest for about half a second makes XNU panic. So each job runs as a
//! fiber on its service's compile stack (`stela_boot_core::fiber`), and a
//! slice of it gives its processor back at the first of these past
//! [`SLICE_MICROS`]: an allocation, which NIR, NAK and LLVM make all the
//! time ([`allocation_point`]); a C-library wait; a host call that is not
//! done. Any processor resumes it later from its run loop, as it took the
//! job; one that waits for the compile lock or a lock the job holds
//! resumes it too ([`help`]). The job computes the same, only split in
//! time, and holds the compile lock from its first slice to its end.
//!
//! A slice gives its processor back only where it may: in the job's own
//! code with interrupts on (never in an interrupt handler), on the compile
//! stack, and holding no spin lock: neither inside the host callbacks that
//! take a lock of their own ([`without_yields`]) nor inside a driver's
//! (`deferred::hold_lock`, [`enter_lock`]). Elsewhere it runs on to the
//! next such point. The lock holds are the fiber's own: a job resumed on a
//! processor starts with none of the processor's, and a processor that
//! holds one resumes no job ([`help`]), which might wait for it.
//!
//! While a slice runs, the C library sees the job as a core of its own
//! ([`job_core`]), so its thread-local values and lock owners stay the
//! job's on whichever processor resumes it.
use super::{BOOT_CPU, gate, installed};
use crate::engine::host;
use alloc::boxed::Box;
use core::{
    ffi::c_uint,
    sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
};
use stela_boot_core::fiber::{Fiber, Handle, Step};
use stela_drivers::gpu::metal::deferred::Sliced;

/// How long a slice runs before it gives its processor back at its next
/// point: a guest interrupt on that processor waits about this long.
pub(super) const SLICE_MICROS: u64 = 2000;

/// `STELA_LIBC_PROCESSORS`: the C library's cores for host processors.
pub(super) const LIBC_PROCESSORS: usize = 256;

/// What a processor runs of a job now.
struct Slot {
    /// The running fiber's [`Handle`] address, zero while it runs none.
    fiber: AtomicUsize,
    /// When its slice ends, in TSC ticks.
    deadline: AtomicU64,
    /// The compile stack's top.
    top: AtomicU64,
    /// The C library's core for it, `u32::MAX` for the processor's own.
    core: AtomicU32,
    /// Spin locks and host callbacks held that a slice may not end in: the
    /// running fiber's while it runs one, else the processor's.
    held: AtomicU32,
}

static SLOTS: [Slot; LIBC_PROCESSORS] = [const {
    Slot {
        fiber: AtomicUsize::new(0),
        deadline: AtomicU64::new(0),
        top: AtomicU64::new(0),
        core: AtomicU32::new(u32::MAX),
        held: AtomicU32::new(0),
    }
}; LIBC_PROCESSORS];

/// Processors running a slice now, so that an allocation elsewhere pays
/// one load.
static SLICING: AtomicU32 = AtomicU32::new(0);
/// Jobs that ran a slice and wait to be resumed.
static BETWEEN: AtomicU32 = AtomicU32::new(0);

/// A job on a compile stack, run in slices.
struct Job {
    fiber: Fiber,
    top: u64,
    /// The C library's core for it.
    core: c_uint,
    /// It ran a slice and waits.
    between: bool,
}

/// The platform's [`stela_drivers::gpu::metal::deferred::Slicer`]: `body`
/// as a job on the compile stack below `top`, whose first slice begins it.
pub(super) fn start(top: u64, body: Box<dyn FnOnce() + Send>) -> Box<dyn Sliced> {
    // SAFETY: a service's compile stack, which only its jobs use, one at a
    // time under the compile lock this job holds until it ends.
    let fiber = unsafe { Fiber::new(top, body) };
    Box::new(Job {
        fiber,
        top,
        core: gate::job_core(top),
        between: false,
    })
}

impl Sliced for Job {
    fn resume(&mut self) -> bool {
        if core::mem::take(&mut self.between) {
            BETWEEN.fetch_sub(1, Ordering::AcqRel);
        }
        let slot = SLOTS.get(host::processor() as usize);
        if let Some(slot) = slot {
            let tsc_hz = installed().map_or(0, |gpu| gpu.tsc_hz);
            slot.deadline.store(
                host::rdtsc().saturating_add(tsc_hz / 1_000_000 * SLICE_MICROS),
                Ordering::Relaxed,
            );
            slot.top.store(self.top, Ordering::Relaxed);
            // A core past every processor's, which no processor answers as.
            let own = self.core >= host::processors();
            slot.core
                .store(if own { self.core } else { u32::MAX }, Ordering::Relaxed);
            slot.fiber
                .store(self.fiber.handle().address(), Ordering::Relaxed);
            SLICING.fetch_add(1, Ordering::AcqRel);
        }
        // The fiber counts its own locks, from none: it suspended or began
        // holding none, and the processor's are not its own.
        let outside = slot.map_or(0, |slot| slot.held.swap(0, Ordering::Relaxed));
        // SAFETY: a job runs where long host work is allowed, from a run
        // loop or a wait that holds nothing the doorbell's or the
        // shootdown's handler takes; it leaves IF and CR8 as they were.
        let step = unsafe { crate::native_mmio::shootdown::job(|| self.fiber.resume()) };
        if let Some(slot) = slot {
            let inside = slot.held.swap(outside, Ordering::Relaxed);
            debug_assert_eq!(inside, 0, "a job's slice ended holding a spin lock");
            slot.fiber.store(0, Ordering::Relaxed);
            SLICING.fetch_sub(1, Ordering::AcqRel);
        }
        match step {
            Step::Finished => true,
            Step::Suspended => {
                self.between = true;
                BETWEEN.fetch_add(1, Ordering::AcqRel);
                false
            }
        }
    }
}

/// The slot of the slice this processor runs, when its job may give the
/// processor back here, with the job's handle.
fn may_end() -> Option<(&'static Slot, Handle)> {
    if SLICING.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let slot = SLOTS.get(host::processor() as usize)?;
    let fiber = slot.fiber.load(Ordering::Relaxed);
    if fiber == 0 || slot.held.load(Ordering::Relaxed) != 0 || !interrupts_on() {
        return None;
    }
    let top = slot.top.load(Ordering::Relaxed);
    let pointer = super::stack::pointer();
    if pointer >= top || top - pointer >= gate::STACK_BYTES as u64 {
        return None;
    }
    // SAFETY: set from the running fiber's handle, which lives while it runs.
    Some((slot, unsafe { Handle::from_address(fiber) }))
}

fn interrupts_on() -> bool {
    let flags: u64;
    // SAFETY: reads RFLAGS through the stack, which the push and pop balance.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
    flags & (1 << 9) != 0
}

/// The heap's allocation hook: a slice past its time gives its processor
/// back here, before the heap takes anything.
pub(super) fn allocation_point() {
    let Some((slot, handle)) = may_end() else {
        return;
    };
    if host::rdtsc() >= slot.deadline.load(Ordering::Relaxed) {
        // SAFETY: the running job's own frame, on its stack, interrupts on.
        unsafe { suspend(slot, handle) };
    }
}

/// End the running slice: the job holds no spin lock ([`may_end`]).
///
/// # Safety
/// As [`Handle::suspend`]: the running job's own frame, on its stack.
unsafe fn suspend(slot: &Slot, handle: Handle) {
    debug_assert_eq!(
        slot.held.load(Ordering::Relaxed),
        0,
        "a job's slice would end holding a spin lock"
    );
    // SAFETY: the caller's contract.
    unsafe { handle.suspend() };
}

/// A moment of a wait in a job's slice: past the slice's time, or on the
/// boot processor, whose run loop serves the Linux work the job may wait
/// for, it gives the processor back. Whether this processor runs a slice.
pub(super) fn wait_point() -> bool {
    let Some((slot, handle)) = may_end() else {
        return in_job();
    };
    if host::processor() == BOOT_CPU.load(Ordering::Relaxed)
        || host::rdtsc() >= slot.deadline.load(Ordering::Relaxed)
    {
        // SAFETY: as in `allocation_point`.
        unsafe { suspend(slot, handle) };
    }
    true
}

/// Whether a slice that waits here can give its processor back.
pub(super) fn can_end() -> bool {
    may_end().is_some()
}

/// Whether this processor runs a job's slice.
pub(super) fn in_job() -> bool {
    SLICING.load(Ordering::Relaxed) != 0
        && SLOTS
            .get(host::processor() as usize)
            .is_some_and(|slot| slot.fiber.load(Ordering::Relaxed) != 0)
}

/// The C library's core for the job this processor runs a slice of.
pub(super) fn job_core() -> Option<c_uint> {
    if SLICING.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let slot = SLOTS.get(host::processor() as usize)?;
    if slot.fiber.load(Ordering::Relaxed) == 0 {
        return None;
    }
    match slot.core.load(Ordering::Relaxed) {
        u32::MAX => None,
        core => Some(core),
    }
}

/// Runs `body`, a host callback that takes a lock of its own, with no slice
/// ending inside it.
pub(super) fn without_yields<R>(body: impl FnOnce() -> R) -> R {
    enter_lock();
    let result = body();
    // No slice ended in it, so it ends on the processor it began on.
    leave_lock();
    result
}

/// A spin lock or a callback that takes one is entered here
/// (`deferred::set_lock_hooks`): no slice ends until [`leave_lock`], so the
/// fiber that holds it stays on this processor.
pub(super) fn enter_lock() {
    if let Some(slot) = SLOTS.get(host::processor() as usize) {
        slot.held.fetch_add(1, Ordering::Relaxed);
    }
}

/// The lock [`enter_lock`] counted is let go.
pub(super) fn leave_lock() {
    if let Some(slot) = SLOTS.get(host::processor() as usize) {
        let held = slot.held.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(held != 0, "a spin lock let go that was never counted");
    }
}

/// Whether this processor, outside a job, holds a counted lock.
fn holds_lock() -> bool {
    SLOTS
        .get(host::processor() as usize)
        .is_some_and(|slot| slot.held.load(Ordering::Relaxed) != 0)
}

/// A moment of a wait outside a job: resumes a job that waits between
/// slices, as the wait may be for the compile lock or a lock the job
/// holds. Never from a job's own slice, only where the slice would run
/// with interrupts on and can end, and never while this processor holds a
/// counted lock, which the job might spin on below this wait's frame.
pub(super) fn help() {
    if BETWEEN.load(Ordering::Relaxed) == 0
        || in_job()
        || !crate::native_mmio::shootdown::job_opens()
        || holds_lock()
    {
        return;
    }
    gate::resume_job();
}
