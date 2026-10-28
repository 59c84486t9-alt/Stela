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
    ffi::c_void,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
}
struct Probe {
    runtime: usize,
    bounds: Range<usize>,
    root: u64,
    observed: AtomicUsize,
    task: AtomicU64,
    valid: AtomicBool,
}
unsafe extern "C" fn probe(context: *mut c_void) {
    // SAFETY: prepare retains this boxed owned probe through completion; on any
    // uncertain completion it remains leaked with the quarantined real Runtime.
    let probe = unsafe { &*context.cast::<Probe>() };
    let (rsp, root): (usize, u64);
    // SAFETY: pure observations on this actual runtime continuation.
    unsafe {
        asm!("mov {}, rsp",out(reg)rsp,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr3",out(reg)root,options(nomem,nostack,preserves_flags));
    }
    // SAFETY: pointer came from this actual pinned Runtime; its executor remains
    // alive through completion/quarantine and cannot migrate.
    let runtime = unsafe { &*(probe.runtime as *const work::Runtime<SLOTS>) };
    if let Ok(id) = runtime.current_id() {
        probe.task.store(id.get(), Ordering::Relaxed);
        probe.valid.store(
            probe.bounds.contains(&rsp) && root & ADDRESS == probe.root,
            Ordering::Release,
        );
    }
    probe.observed.store(rsp, Ordering::Release);
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
        };
        result.qualify_foreground(clock)?;
        Ok(result)
    }
    fn qualify_foreground(&self, clock: Clock) -> Result<(), Error> {
        let runtime = self.executor.runtime();
        let state = Box::leak(Box::new(Probe {
            runtime: runtime.get_ref() as *const _ as usize,
            bounds: self.foreground.clone(),
            root: self.root,
            observed: AtomicUsize::new(0),
            task: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }));
        let deadline = clock.now_us().checked_add(1_000_000).ok_or(Error::Clock)?;
        // SAFETY: owned leaked probe, actual pinned runtime, genuine static
        // callback code; uncertain completion retains both through quarantine.
        unsafe { runtime.call_foreground(probe, (state as *mut Probe).cast(), deadline) }
            .map_err(Error::Work)?;
        if state.observed.load(Ordering::Acquire) == 0
            || state.task.load(Ordering::Acquire) == 0
            || !state.valid.load(Ordering::Acquire)
        {
            return Err(Error::Qualification);
        }
        Ok(())
    }
}
