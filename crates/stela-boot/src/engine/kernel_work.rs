//! BSP work continuations over the loader's separately reserved stacks.
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
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use stela_boot_core::guarded_stacks::mappings;
use stela_drivers::{
    Clock,
    bus::dma::memory::MemoryError,
    platform::work::{self, Cpu, Executor, Queue, Stack, StackBacking, WorkError},
};
pub(super) const SLOTS: usize = 64;
mod firmware;
#[cfg(feature = "diagnostics")]
mod pages;
mod pin;
mod plan;
pub(crate) use firmware::FirmwareContext;
use plan::Plan;
#[cfg(feature = "diagnostics")]
mod mixed;
#[cfg(feature = "diagnostics")]
pub(super) use mixed::check as check_mixed;
#[derive(Debug)]
pub(crate) enum Error {
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
    #[cfg(feature = "diagnostics")]
    NoKernelStacks,
    #[cfg(feature = "diagnostics")]
    Pages(stela_drivers::gpu::linux::pages::Error),
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
            #[cfg(feature = "diagnostics")]
            Self::NoKernelStacks => {
                f.write_str("actual work pool has no Linux-compatible stack slots")
            }
            #[cfg(feature = "diagnostics")]
            Self::Pages(error) => write!(f, "Linux page catalog: {error:?}"),
        }
    }
}
struct Reservation {
    identity: Arc<RootIdentity>,
    _wire: &'static native_mmio::Wire,
    _handoff: &'static Handoff,
    allocation: native_smp::resources::AllocationClaim,
    released_stack_views: AtomicUsize,
}
struct Backing {
    _reservation: Arc<Reservation>,
    bounds: Range<usize>,
    guard: Range<usize>,
    physical: u64,
}
// SAFETY: prepare consumes one loader allocation exactly once, verifies
// every root's exact RW/NX/supervisor/WB backing and absent guards, and verifies
// effective MTRRs on the original BSP. Slots are disjoint and excluded from
// guest/DMA allocations. The physical reservation and shared window are never
// reclaimed during this boot; each backing additionally pins the CPU/
// descriptor/root owner. Runtime keeps paused/quarantined frames and backing.
unsafe impl StackBacking for Backing {
    fn bounds(&self) -> Range<usize> {
        self.bounds.clone()
    }
    fn guard(&self) -> Range<usize> {
        self.guard.clone()
    }
    unsafe fn pin_cold_pages(
        &self,
    ) -> Result<stela_drivers::bus::dma::memory::PinnedPages, MemoryError> {
        // SAFETY: the work owner holds this never-entered slot in Preparing
        // and has zeroed only its usable range. The allocation and checked
        // mappings remain held by this backing throughout export.
        unsafe { pin::export(self) }
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        // This retires one view only. Its raw loader allocation/root mapping
        // remains owned for the whole boot; no physical reclaim is inferred.
        self._reservation
            .released_stack_views
            .fetch_add(1, Ordering::Relaxed);
    }
}
struct NativeCpu {
    reservation: Arc<Reservation>,
    clock: Clock,
}
// SAFETY: immutable RootIdentity checks CPU/GS/descriptors and the real
// root catalog before local-state access. IRQ enqueue/wake may observe
// another owned guest root, but execution switches happen only via the affine
// owner under RestoreRoot; Runtime additionally checks captured CR3/controls.
// Ticks use the executing BSP's real calibrated progressing TSC; no task migrates
// or reconfigures controls. This constructor grants no fixed-rate Linux clock or
// idle/deadline service, which needs separate clock/IRQ validation. Descriptor/local storage is permanently kept even on quarantine.
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
        // SAFETY: owning CPL0 CPU; exact save brackets metadata changes.
        unsafe {
            asm!("pushfq","pop {}","cli",out(reg)saved);
        }
        Ok(saved)
    }
    unsafe fn restore(&self, flags: u64) {
        if let Err(error) = self.check_cpu() {
            self.fatal(error);
        }
        // SAFETY: caller supplies this CPU's enclosing save after restoring
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
    /// The queue's own view of `_cpu`, which a service domain must share.
    cpu: Arc<dyn Cpu>,
    foreground: Arc<firmware::Foreground>,
    root: u64,
    busy: Cell<bool>,
    #[cfg(feature = "diagnostics")]
    stack_pages: pages::TaskPageInventory,
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
    // runtime. It remains held through completion or permanent quarantine.
    let call = unsafe { &*context.cast::<OwnedCall<F, T>>() };
    // SAFETY: only this one callback takes the closure; the dispatcher waits
    // for its ticket completion before reading or freeing output.
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
    /// Post-EBS BSP owns this immutable validated handoff and all loader
    /// allocations, before APs/producers run. Reserved stack bytes have never
    /// carried another frame or been lent to a device; source tables and all
    /// aliases remain held WB. No external root/cache writer overlaps.
    pub(super) unsafe fn prepare(
        handoff: &'static Handoff,
        owner: &mut HostOwner,
    ) -> Result<Self, Error> {
        // SAFETY: original caller's handoff/owner/stack lifetime contract.
        unsafe { Self::prepare_plan(handoff, owner, Plan::new(handoff)?) }
    }
    /// # Safety
    /// Same original handoff/owner contract as prepare. A Plan describes
    /// only layout; it cannot supply allocation, root or execution permission.
    unsafe fn prepare_plan(
        handoff: &'static Handoff,
        owner: &mut HostOwner,
        plan: Plan,
    ) -> Result<Self, Error> {
        plan.validate(handoff)?;
        // SAFETY: inherited handoff/physmap lifetime and sealed capture.
        let wire = unsafe { native_mmio::captured(handoff) }.map_err(|_| Error::Inventory)?;
        let identity = owner.root_identity().map_err(Error::Work)?;
        let snapshot = identity.memory_snapshot().map_err(Error::Work)?;
        // SAFETY: same immutable processor capture as native admission.
        let capture = unsafe { native_smp::firmware::captured(handoff.native_processors) }
            .map_err(|_| Error::Inventory)?;
        let bsp = capture.processors[capture.selected[0] as usize];
        if snapshot.apic_id().map(u64::from) != Some(bsp.apic_id) {
            return Err(Error::WrongCpu);
        }
        if handoff.tsc_hz < 1_000_000 {
            return Err(Error::Clock);
        }
        let region = plan.region();
        if region.physical == 0
            || region.bytes != plan.raw_bytes()
            || !wire.loader_ram(region.physical, region.bytes)
        {
            return Err(Error::Inventory);
        }
        // SAFETY: loader root, excluding task/native entry.
        let _root = unsafe { RestoreRoot::enter(handoff.root) };
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(plan.count())
            .map_err(|_| Error::Allocation)?;
        let mut previous = plan.virtual_range().start;
        let mut read = |table, index| {
            if !wire.table_owned(table) {
                return None;
            }
            // SAFETY: sealed kept LoaderData table; walker bounds
            // index to0..512 and this root exclusion admits no table writer.
            Some(unsafe {
                (layout::physical(table) as *const u64)
                    .add(index)
                    .read_volatile()
            })
        };
        for index in 0..plan.count() {
            let (slot, physical) = plan.slot(index)?;
            mappings::absent(
                previous..slot.usable.start,
                identity.root_pages(),
                wire.levels(),
                &mut read,
            )
            .map_err(Error::Mapping)?;
            previous = slot.usable.end;
            mappings::qualify(
                &slot,
                physical,
                identity.root_pages(),
                wire.levels(),
                snapshot.pat,
                &mut read,
            )
            .map_err(Error::Mapping)?;
            // Check every physical slot, not the first MTRR interval.
            crate::native_memory::cache::verify_writeback(
                slot.usable.start,
                physical,
                (slot.usable.end - slot.usable.start) as usize,
                layout::physical(0),
            )
            .map_err(Error::Cache)?;
            spans.push((
                usize::try_from(slot.usable.start).map_err(|_| Error::Geometry)?
                    ..usize::try_from(slot.usable.end).map_err(|_| Error::Geometry)?,
                usize::try_from(slot.lower_guard.start).map_err(|_| Error::Geometry)?
                    ..usize::try_from(slot.lower_guard.end).map_err(|_| Error::Geometry)?,
                physical,
            ));
        }
        mappings::absent(
            previous..plan.virtual_range().end,
            identity.root_pages(),
            wire.levels(),
            &mut read,
        )
        .map_err(Error::Mapping)?;
        crate::native_memory::cache::verify_writeback(
            layout::physical(region.physical),
            region.physical,
            region.bytes as usize,
            layout::physical(0),
        )
        .map_err(Error::Cache)?;
        let allocation =
            handoff
                .native_task_allocations
                .claim(region)
                .map_err(|error| match error {
                    native_smp::resources::ClaimError::AlreadyOwned => Error::AlreadyOwned,
                    native_smp::resources::ClaimError::DescriptorMismatch => Error::Inventory,
                })?;
        // A failed/uncertain admission never reuses this pool.
        let reservation = Arc::new(Reservation {
            identity,
            _wire: wire,
            _handoff: handoff,
            allocation,
            released_stack_views: AtomicUsize::new(0),
        });
        let clock = Clock {
            ticks_per_microsecond: handoff.tsc_hz / 1_000_000,
        };
        let cpu = Arc::new(NativeCpu {
            reservation: reservation.clone(),
            clock,
        });
        #[cfg(feature = "diagnostics")]
        let stack_pages = pages::TaskPageInventory::from_spans(reservation.clone(), &spans)?;
        let (foreground_slot, foreground_physical) = plan.slot(0)?;
        let foreground = Arc::new(firmware::Foreground {
            reservation: reservation.clone(),
            bounds: spans[0].0.clone(),
            lower: foreground_slot.lower_guard.start as usize
                ..foreground_slot.lower_guard.end as usize,
            upper: foreground_slot.upper_guard.start as usize
                ..foreground_slot.upper_guard.end as usize,
            physical: foreground_physical,
        });
        let mut stacks = Vec::new();
        stacks
            .try_reserve_exact(spans.len())
            .map_err(|_| Error::Allocation)?;
        for (bounds, guard, physical) in spans {
            stacks.push(
                Stack::new(Box::new(Backing {
                    _reservation: reservation.clone(),
                    bounds,
                    guard,
                    physical,
                }))
                .map_err(Error::Work)?,
            );
        }
        let shared: Arc<dyn Cpu> = cpu.clone();
        // SAFETY: real kept source/root/code ownership; callbacks cannot
        // outlive this boot, and no producer is published by construction.
        let queue =
            unsafe { Queue::<SLOTS>::new(shared.clone(), reservation) }.map_err(Error::Work)?;
        let executor = Executor::new_with_profile(
            queue,
            stacks,
            work::ReservationPolicy::NativeFirmware32Protected {
                gpe: work::GpeQueueBudget::QUALIFICATION,
            },
            plan::profile()?,
        )
        .map_err(Error::Work)?;
        let result = Self {
            executor,
            _cpu: cpu,
            cpu: shared,
            foreground,
            root: handoff.root,
            busy: Cell::new(false),
            #[cfg(feature = "diagnostics")]
            stack_pages,
        };
        // Validation enters the owned-call boundary, which acquires the
        // global driver/root guard itself. No mapping walk or table borrower
        // survives here; release this non-reentrant construction guard first.
        drop(_root);
        result.qualify_foreground()?;
        Ok(result)
    }
    /// Execute owned boot preparation in a real foreground continuation.
    /// Neither closure nor result may borrow the caller's stack. This is not
    /// asynchronous producer admission or a fixed-rate deadline-clock grant.
    /// An uncertain call keeps its whole job/runtime and closes this sync
    /// entry, so repeated callers cannot leak another job on every poll.
    pub(super) fn call_owned<F: FnOnce() -> T + 'static, T: 'static>(
        &self,
        timeout_us: u64,
        function: F,
    ) -> Result<T, Error> {
        self._cpu
            .reservation
            .identity
            .check_clock_root()
            .map_err(Error::Work)?;
        self._cpu
            .reservation
            .identity
            .check_dispatch()
            .map_err(Error::Work)?;
        let runtime = self.executor.runtime();
        match runtime.current_id() {
            Ok(_) => return Err(Error::Work(WorkError::WouldDeadlock)),
            Err(WorkError::Unavailable) => {}
            Err(error) => return Err(Error::Work(error)),
        }
        // SAFETY: loader root on this physical BSP, no native
        // or IRQ frame; every continuation was checked in this same domain.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        // This checks the original allocation/entered root link only;
        // it supplies no rate, timer, firmware-service or task admission grant.
        self._cpu
            .reservation
            .identity
            .check_clock_root()
            .map_err(Error::Work)?;
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
        // SAFETY: owned 'static closure/result, pinned runtime and
        // static monomorphized callback code. On error the owned box stays
        // kept; Executor also quarantines uncertain continuation frames.
        unsafe { runtime.call_foreground(owned_call::<F, T>, call.cast(), deadline) }
            .map_err(Error::Work)?;
        // SAFETY: allocation remains owned; the callback ticket completed.
        if !unsafe { &*call }.complete.load(Ordering::Acquire) {
            return Err(Error::Qualification);
        }
        // SAFETY: completed ticket excludes every callback borrower; this
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
    /// The CPU the runtime runs on.
    pub(super) fn cpu(&self) -> Arc<dyn Cpu> {
        self.cpu.clone()
    }

    /// Run `body` in the dispatcher, on the loader's root under the host
    /// drivers' lock, from anywhere the boot PE's run loop is: unlike
    /// [`Self::call_owned`], this also serves the run, whose tagged guest
    /// roots only the entered root's checks accept.
    pub(super) fn dispatch<T>(
        &self,
        body: impl FnOnce(Pin<&work::Runtime<SLOTS>>) -> T,
    ) -> Result<T, Error> {
        // SAFETY: the loader root on this physical BSP, with no native or IRQ
        // frame, which the checks below refuse.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        let identity = &self._cpu.reservation.identity;
        identity.check_clock_root().map_err(Error::Work)?;
        identity.check_dispatch().map_err(Error::Work)?;
        Ok(body(self.executor.runtime()))
    }

    /// Continuation identity; dispatcher/IRQ/foreign-root callers refuse.
    pub(super) fn current_id(&self) -> Result<u64, Error> {
        self.executor
            .runtime()
            .current_id()
            .map(|id| id.get())
            .map_err(Error::Work)
    }
    /// Check the continuation and both OSL flush roles immediately before
    /// C removal. This neither captures queue boundaries nor synchronizes SCI.
    pub(super) fn check_firmware_wait(&self) -> Result<(), Error> {
        let runtime = self.executor.runtime();
        runtime.current_id().map_err(Error::Work)?;
        runtime
            .check_firmware_join(work::FirmwareQueue::Gpe)
            .map_err(Error::Work)?;
        runtime
            .check_firmware_join(work::FirmwareQueue::Notify)
            .map_err(Error::Work)
    }
    /// Run only on the real owned foreground stack, under the dispatcher's
    /// existing serialized original-root guard. No borrowed caller stack or
    /// process permission is captured or kept in a queued job.
    pub(super) fn call_firmware_owned<F, T>(&self, timeout_us: u64, function: F) -> Result<T, Error>
    where
        F: FnOnce(&super::FirmwareContext<'_>) -> T + 'static,
        T: 'static,
    {
        let stack = self.foreground.clone();
        let queue = self.executor.runtime().queue().clone();
        self.call_owned(timeout_us, move || {
            let context = FirmwareContext::enter(&stack, &queue)?;
            let output = function(&context);
            context.check()?;
            Ok(output)
        })?
    }
    fn qualify_foreground(&self) -> Result<(), Error> {
        let valid = self.call_firmware_owned(1_000_000, |context| context.id() != 0)?;
        if !valid {
            return Err(Error::Qualification);
        }
        Ok(())
    }
}
