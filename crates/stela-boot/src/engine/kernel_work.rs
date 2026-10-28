//! Actual BSP work continuations over the loader's separately reserved stacks.
//! Admission here creates no Linux service, ACPI capability, or cross-CPU
//! execution grant. Those producers must join this affine owner explicitly.
use super::{
    host::{HostOwner, local::context::RootIdentity},
    storage::RestoreRoot,
};
use crate::{
    handoff::{Handoff, Region},
    layout, native_mmio, native_smp,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    arch::asm,
    cell::{Cell, UnsafeCell},
    ffi::c_void,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_boot_core::guarded_stacks::mappings;
use stela_drivers::{
    Clock,
    bus::dma::memory::MemoryError,
    platform::work::{self, Cpu, Executor, Queue, Stack, StackBacking, WorkError},
};
const SLOTS: usize = 64;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
static CLAIMED: AtomicBool = AtomicBool::new(false);
#[derive(Debug)]
pub(super) enum Error {
    Inventory,
    WrongCpu,
    Clock,
    Geometry,
    Allocation,
    AlreadyOwned,
    Mapping(mappings::Error),
    Cache(MemoryError),
    Work(WorkError),
    Qualification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inventory => f.write_str("sealed loader stack inventory unavailable"),
            Self::WrongCpu => f.write_str("kernel work requires the actual BSP"),
            Self::Clock => f.write_str("kernel work counter calibration unavailable"),
            Self::Geometry => f.write_str("kernel stack geometry is invalid"),
            Self::Allocation => f.write_str("kernel work metadata allocation failed"),
            Self::AlreadyOwned => f.write_str("kernel stack pool is already owned"),
            Self::Mapping(error) => write!(f, "kernel stack page-table qualification: {error:?}"),
            Self::Cache(error) => {
                write!(f, "kernel stack effective cache qualification: {error:?}")
            }
            Self::Work(error) => write!(f, "native continuation admission: {error:?}"),
            Self::Qualification => f.write_str("native continuation identity or stack differs"),
        }
    }
}
struct Reservation {
    identity: Arc<RootIdentity>,
    _wire: &'static native_mmio::Wire,
    _handoff: &'static Handoff,
    _physical: Region,
}
struct Backing {
    _reservation: Arc<Reservation>,
    bounds: Range<usize>,
    guard: Range<usize>,
}
// SAFETY: prepare consumes one actual loader allocation exactly once, verifies
// every root's exact RW/NX/supervisor/WB backing and absent guards, and verifies
// effective MTRRs on the original BSP. Slots are disjoint and excluded from
// guest/DMA allocations. The physical reservation and shared window are never
// reclaimed during this boot; each backing additionally pins the actual CPU/
// descriptor/root owner. Runtime retains paused/quarantined frames and backing.
unsafe impl StackBacking for Backing {
    fn bounds(&self) -> Range<usize> {
        self.bounds.clone()
    }
    fn guard(&self) -> Range<usize> {
        self.guard.clone()
    }
}
struct NativeCpu {
    reservation: Arc<Reservation>,
    clock: Clock,
}
// SAFETY: immutable actual RootIdentity checks CPU/GS/descriptors and the real
// retained root catalog before local-state access. IRQ enqueue/wake may observe
// another owned guest root, but execution switches happen only via the affine
// owner under RestoreRoot; Runtime additionally checks captured CR3/controls.
// Ticks use the executing BSP's real calibrated progressing TSC; no task migrates
// or reconfigures controls. This constructor grants no fixed-rate Linux clock or
// idle/deadline service, which needs separate clock/IRQ qualification. Descriptor/local storage is permanently retained even on quarantine.
unsafe impl Cpu for NativeCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        self.reservation.identity.check_irq_cpu()
    }
    fn in_interrupt(&self) -> bool {
        self.reservation.identity.in_interrupt()
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        let saved;
        // SAFETY: actual owning CPL0 CPU; exact save brackets metadata changes.
        unsafe {
            asm!("pushfq","pop {}","cli",out(reg)saved);
        }
        Ok(saved)
    }
    unsafe fn restore(&self, flags: u64) {
        if let Err(error) = self.check_cpu() {
            self.fatal(error);
        }
        // SAFETY: caller supplies this CPU's exact enclosing save after restoring
        // task metadata/context; no queue lock spans this restoration.
        unsafe {
            asm!("push {}","popfq",in(reg)flags);
        }
    }
    fn ticks(&self) -> u64 {
        if let Err(error) = self.check_cpu() {
            self.fatal(error);
        }
        self.clock.now_us()
    }
    fn fatal(&self, error: WorkError) -> ! {
        self.reservation.identity.fatal(error)
    }
}
/// !Send/!Sync executor: producers may eventually receive owned mailbox views,
/// never an Arc wrapping this Runtime or a foreign-CPU task-switch permission.
pub(super) struct KernelWork {
    executor: Executor<SLOTS>,
    _cpu: Arc<NativeCpu>,
    foreground: Range<usize>,
    root: u64,
    busy: Cell<bool>,
}
/// Owned closure/result storage. It is never made Send/Sync or exposed to an
/// AP; the real queue checks its BSP before the callback can touch these cells.
struct OwnedCall<F, T> {
    input: UnsafeCell<Option<F>>,
    output: UnsafeCell<Option<T>>,
    complete: AtomicBool,
}
unsafe extern "C" fn owned_call<F: FnOnce() -> T, T>(context: *mut c_void) {
    // SAFETY: call_owned admitted this exact owned box once on the real affine
    // runtime. It remains retained through completion or permanent quarantine.
    let call = unsafe { &*context.cast::<OwnedCall<F, T>>() };
    // SAFETY: only this one callback takes the closure; the dispatcher waits
    // for its actual ticket completion before reading or freeing output.
    let Some(function) = (unsafe { &mut *call.input.get() }).take() else {
        return;
    };
    let output = function();
    // SAFETY: the same unique callback initializes output before publication.
    unsafe { *call.output.get() = Some(output) };
    call.complete.store(true, Ordering::Release);
}

impl KernelWork {
    /// # Safety
    /// Actual post-EBS BSP owns this immutable validated handoff and all loader
    /// allocations, before APs/producers run. Reserved stack bytes have never
    /// carried another frame or been lent to a device; source tables and all
    /// aliases remain retained WB. No external root/cache writer overlaps.
    pub(super) unsafe fn prepare(
        handoff: &'static Handoff,
        owner: &mut HostOwner,
    ) -> Result<Self, Error> {
        // SAFETY: inherited genuine handoff/physmap lifetime and sealed capture.
        let wire = unsafe { native_mmio::captured(handoff) }.map_err(|_| Error::Inventory)?;
        let identity = owner.root_identity().map_err(Error::Work)?;
        let snapshot = identity.memory_snapshot().map_err(Error::Work)?;
        // SAFETY: same immutable genuine processor capture as native admission.
        let capture = unsafe { native_smp::firmware::captured(handoff.native_processors) }
            .map_err(|_| Error::Inventory)?;
        let bsp = capture.processors[capture.selected[0] as usize];
        if snapshot.apic_id().map(u64::from) != Some(bsp.apic_id) {
            return Err(Error::WrongCpu);
        }
        if handoff.tsc_hz < 1_000_000 {
            return Err(Error::Clock);
        }
        let geometry = native_smp::resources::task_stacks();
        let region = handoff.native_resources.tasks;
        if region.bytes != geometry.physical_bytes()
            || !wire.loader_ram(region.physical, region.bytes)
        {
            return Err(Error::Inventory);
        }
        // SAFETY: genuine retained loader root, excluding task/native entry.
        let _root = unsafe { RestoreRoot::enter(handoff.root) };
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(geometry.count())
            .map_err(|_| Error::Allocation)?;
        for index in 0..geometry.count() {
            let slot = geometry
                .slot(layout::task_stacks(), index)
                .map_err(|_| Error::Geometry)?;
            let physical = region.physical
                + geometry
                    .physical_offset(index)
                    .map_err(|_| Error::Geometry)?;
            mappings::qualify(
                &slot,
                physical,
                identity.root_pages(),
                wire.levels(),
                snapshot.pat,
                |table, index| {
                    if !wire.table_owned(table) {
                        return None;
                    }
                    // SAFETY: actual sealed LOADER_DATA table page, retained through
                    // the physmap; walker bounds index to0..512. No table writer runs.
                    Some(unsafe {
                        (layout::physical(table) as *const u64)
                            .add(index)
                            .read_volatile()
                    })
                },
            )
            .map_err(Error::Mapping)?;
            // Qualify every physical slot, not merely the first MTRR interval.
            crate::native_memory::cache::verify_writeback(
                slot.usable.start,
                physical,
                native_smp::resources::TASK_STACK_BYTES as usize,
                layout::physical(0),
            )
            .map_err(Error::Cache)?;
            spans.push((
                usize::try_from(slot.usable.start).map_err(|_| Error::Geometry)?
                    ..usize::try_from(slot.usable.end).map_err(|_| Error::Geometry)?,
                usize::try_from(slot.lower_guard.start).map_err(|_| Error::Geometry)?
                    ..usize::try_from(slot.lower_guard.end).map_err(|_| Error::Geometry)?,
            ));
        }
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyOwned)?;
        // A failed/uncertain admission intentionally never reuses this pool.
        let reservation = Arc::new(Reservation {
            identity,
            _wire: wire,
            _handoff: handoff,
            _physical: region,
        });
        let clock = Clock {
            ticks_per_microsecond: handoff.tsc_hz / 1_000_000,
        };
        let cpu = Arc::new(NativeCpu {
            reservation: reservation.clone(),
            clock,
        });
        let foreground = spans[0].0.clone();
        let mut stacks = Vec::new();
        stacks
            .try_reserve_exact(spans.len())
            .map_err(|_| Error::Allocation)?;
        for (bounds, guard) in spans {
            stacks.push(
                Stack::new(Box::new(Backing {
                    _reservation: reservation.clone(),
                    bounds,
                    guard,
                }))
                .map_err(Error::Work)?,
            );
        }
        // SAFETY: real retained source/root/code ownership; callbacks cannot
        // outlive this boot, and no producer is published by construction.
        let queue =
            unsafe { Queue::<SLOTS>::new(cpu.clone(), reservation) }.map_err(Error::Work)?;
        let executor = Executor::new_with_services(queue, stacks).map_err(Error::Work)?;
        let result = Self {
            executor,
            _cpu: cpu,
            foreground,
            root: handoff.root,
            busy: Cell::new(false),
        };
        result.qualify_foreground()?;
        Ok(result)
    }
    /// Execute owned boot preparation in a real foreground continuation.
    /// Neither closure nor result may borrow the caller's stack. This is not
    /// asynchronous producer admission or a fixed-rate deadline-clock grant.
    /// An uncertain call retains its whole job/runtime and closes this sync
    /// entry, so repeated callers cannot leak another job on every poll.
    pub(super) fn call_owned<F: FnOnce() -> T + 'static, T: 'static>(
        &self,
        timeout_us: u64,
        function: F,
    ) -> Result<T, Error> {
        self._cpu
            .reservation
            .identity
            .check_dispatch()
            .map_err(Error::Work)?;
        // SAFETY: genuine retained loader root on this physical BSP, no native
        // or IRQ frame; every continuation was qualified in this same domain.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        let runtime = self.executor.runtime();
        match runtime.current_id() {
            Ok(_) => return Err(Error::Work(WorkError::WouldDeadlock)),
            Err(WorkError::Unavailable) => {}
            Err(error) => return Err(Error::Work(error)),
        }
        let deadline = self
            ._cpu
            .ticks()
            .checked_add(timeout_us)
            .ok_or(Error::Clock)?;
        if self.busy.replace(true) {
            return Err(Error::Work(WorkError::Busy));
        }
        let call = Box::into_raw(Box::new(OwnedCall {
            input: UnsafeCell::new(Some(function)),
            output: UnsafeCell::new(None),
            complete: AtomicBool::new(false),
        }));
        // SAFETY: owned 'static closure/result, genuine pinned runtime and
        // static monomorphized callback code. On error the owned box stays
        // retained; Executor also quarantines uncertain continuation frames.
        unsafe { runtime.call_foreground(owned_call::<F, T>, call.cast(), deadline) }
            .map_err(Error::Work)?;
        // SAFETY: allocation remains owned; the actual callback ticket completed.
        if !unsafe { &*call }.complete.load(Ordering::Acquire) {
            return Err(Error::Qualification);
        }
        // SAFETY: actual completed ticket excludes every callback borrower; this
        // function is the only owner allowed to reclaim this exact Rust box.
        let call = unsafe { Box::from_raw(call) };
        // SAFETY: completed callback published output and cannot run again.
        let result = unsafe { &mut *call.output.get() }
            .take()
            .ok_or(Error::Qualification)?;
        drop(call);
        self.busy.set(false);
        Ok(result)
    }
    fn qualify_foreground(&self) -> Result<(), Error> {
        let pointer = self.executor.runtime().get_ref() as *const _ as usize;
        let bounds = self.foreground.clone();
        let expected_root = self.root;
        let valid = self.call_owned(1_000_000, move || {
            let (rsp, root): (usize, u64);
            // SAFETY: pure observations from this genuine foreground callback.
            unsafe {
                asm!("mov {}, rsp",out(reg)rsp,options(nomem,nostack,preserves_flags));
                asm!("mov {}, cr3",out(reg)root,options(nomem,nostack,preserves_flags));
            }
            // SAFETY: pointer is this actual pinned Runtime. An uncertain call
            // retains its owned closure and complete runtime through quarantine.
            let runtime = unsafe { &*(pointer as *const work::Runtime<SLOTS>) };
            runtime.current_id().is_ok_and(|id| id.get() != 0)
                && bounds.contains(&rsp)
                && root & ADDRESS == expected_root
        })?;
        if !valid {
            return Err(Error::Qualification);
        }
        Ok(())
    }
}
