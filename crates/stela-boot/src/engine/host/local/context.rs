//! Time-free native root admission. Intended child of engine::host::local.
//! No timer, work::Cpu implementation, interrupt delivery or device access.
use super::{MmioRoots, Owner, current, irq_active, native_frames_idle, state};
use crate::{
    engine::interrupts,
    native_smp::{firmware, topology::Snapshot},
};
use alloc::sync::Arc;
use core::{
    arch::asm,
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_drivers::{bus::mmio::owned::PhysicalSpan, platform::work::WorkError};

const IF: u64 = 1 << 9;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

fn gs_base() -> u64 {
    // SAFETY: CPL0 architectural observation at this native entry.
    unsafe { crate::cpu::msr::GS_BASE.read() }
}
fn root() -> u64 {
    let value;
    // SAFETY: read-only CPL0 architectural observation.
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
fn processor_id() -> u32 {
    let maximum = core::arch::x86_64::__cpuid(0).eax;
    for leaf in [0x1f, 0xb] {
        if maximum >= leaf {
            let value = core::arch::x86_64::__cpuid_count(leaf, 0);
            if value.ebx & 0xffff != 0 && value.ecx >> 8 & 0xff != 0 {
                return value.edx;
            }
        }
    }
    core::arch::x86_64::__cpuid(1).ebx >> 24
}
fn disable() -> u64 {
    let saved;
    // SAFETY: actual native CPL0 dispatcher. Memory clobber encloses the save.
    unsafe {
        asm!("pushfq", "pop {}", "cli", out(reg) saved);
    }
    saved
}
unsafe fn restore(saved: u64) {
    // SAFETY: caller retains the same actual CPU and exact enclosing IRQ save.
    unsafe {
        asm!("push {}", "popfq", in(reg) saved);
    }
}
fn unavailable<T>(_: T) -> WorkError {
    WorkError::Unavailable
}

/// Canonical immutable witness from the actual private Owner/State allocation.
/// The permanent MMIO Authority can retain this root for the kernel image's
/// lifetime. Finite Clock/mapping closure does not release that registration.
pub(crate) struct RootContext {
    roots: Arc<MmioRoots>,
    snapshot: Snapshot,
    id: u32,
    gs: u64,
    gdt: u64,
    idt: u64,
    task: u16,
    executing: AtomicBool,
}
impl RootContext {
    fn affinity(&self) -> Result<(), WorkError> {
        // BEFORE any GS-local dereference: colliding legacy CPUID IDs on a
        // different CPU cannot borrow this processor's removable scope.
        if gs_base() != self.gs
            || processor_id() != self.id
            || crate::apic::base_msr() != self.snapshot.apic_base
        {
            return Err(WorkError::WrongCpu);
        }
        // SAFETY: immutable architectural observation; original owner retained.
        let observed = unsafe { interrupts::observe() };
        if observed.gs != self.gs
            || observed.gdt != self.gdt
            || observed.idt != self.idt
            || observed.task != self.task
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    pub(crate) fn check_current(&self) -> Result<(), WorkError> {
        self.affinity()?;
        if root() != self.snapshot.cr3 {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    pub(crate) fn check_irq_cpu(&self) -> Result<(), WorkError> {
        self.affinity()?;
        let current = root();
        if current & !ADDRESS != 0 || !self.roots.roots().contains(&current) {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
    pub(crate) fn in_interrupt(&self) -> bool {
        self.affinity().is_err() || irq_active()
    }
    pub(crate) fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_current()?;
        Ok(disable())
    }
    /// # Safety
    /// Exact enclosing save from this same context; no switch or migration.
    pub(crate) unsafe fn restore(&self, saved: u64) {
        if self.check_current().is_err() {
            self.fatal(WorkError::WrongCpu);
        }
        // SAFETY: caller supplies this actual CPU's exact enclosing save.
        unsafe {
            restore(saved);
        }
    }
    pub(crate) fn fatal(&self, error: WorkError) -> ! {
        crate::output::arguments(format_args!("NATIVE ROOT FATAL {error:?}\n"));
        crate::output::fatal("native root contract failed")
    }
    pub(crate) fn roots(&self) -> &Arc<MmioRoots> {
        &self.roots
    }
    pub(crate) fn memory_snapshot(&self) -> Result<Snapshot, WorkError> {
        self.check_current()?;
        Ok(self.snapshot)
    }
}

struct Epoch {
    context: Arc<RootContext>,
    active: AtomicBool,
}
/// Immutable exact execution epoch. It never reopens after closure.
pub(crate) struct RootProcessScope {
    epoch: Arc<Epoch>,
}
impl RootProcessScope {
    pub(crate) fn context(&self) -> &Arc<RootContext> {
        &self.epoch.context
    }
    pub(crate) fn check(&self) -> Result<(), WorkError> {
        if !self.epoch.active.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        self.context().check_current()?;
        if self.context().in_interrupt() {
            return Err(WorkError::InterruptContext);
        }
        Ok(())
    }
    pub(crate) fn check_irq_cpu(&self) -> Result<(), WorkError> {
        if !self.epoch.active.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        self.context().check_irq_cpu()
    }
}
/// CPU-affine process epoch. This owner never moves to another processor.
/// Bootstrap begins with IF0 and grants no interrupt enable or runtime entry.
pub(crate) struct RootExecution {
    epoch: Arc<Epoch>,
    saved: u64,
    _local: PhantomData<*mut ()>,
}
impl RootExecution {
    pub(crate) fn check(&self) -> Result<(), WorkError> {
        if !self.epoch.active.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        self.context().check_current()?;
        if self.context().in_interrupt() {
            return Err(WorkError::InterruptContext);
        }
        Ok(())
    }
    pub(crate) fn context(&self) -> &Arc<RootContext> {
        &self.epoch.context
    }
    pub(crate) fn process_scope(&self) -> Result<Arc<RootProcessScope>, WorkError> {
        self.check()?;
        Ok(Arc::new(RootProcessScope {
            epoch: self.epoch.clone(),
        }))
    }
}
impl Drop for RootExecution {
    fn drop(&mut self) {
        if let Err(error) = self.check() {
            self.context().fatal(error);
        }
        let context = self.context();
        let _saved = disable();
        // Fail BEFORE invalidating scope or restoring flags. An outstanding
        // mapping/IRQ source must retain its exact epoch, including quarantine.
        if Arc::strong_count(&self.epoch) != 1 {
            context.fatal(WorkError::Busy);
        }
        self.epoch.active.store(false, Ordering::Release);
        context.executing.store(false, Ordering::Release);
        // SAFETY: actual same-CPU entry, no remaining epoch views or callbacks.
        unsafe {
            restore(self.saved);
        }
    }
}

impl Owner {
    /// Admit this exact original Owner/context pair before Clock effects.
    /// The numbers inside an unrelated snapshot cannot satisfy this check.
    pub(crate) fn check_root(&self, execution: &RootExecution) -> Result<(), WorkError> {
        if gs_base() != self.local.as_ptr() as u64 {
            return Err(WorkError::WrongCpu);
        }
        execution.check()?;
        let context = self.root_context.upgrade().ok_or(WorkError::Closed)?;
        if !Arc::ptr_eq(&context, execution.context()) {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }

    /// Called only by the actual post-EBS native dispatcher on its owner CPU.
    /// The initial supported profile enters with IF0; timed Clock installation
    /// later supplies its own independently qualified interrupt-delivery scope.
    pub(crate) fn enter_root(&mut self) -> Result<RootExecution, WorkError> {
        // Architectural preguard BEFORE current()/state()/local slot access.
        if gs_base() != self.local.as_ptr() as u64 {
            return Err(WorkError::WrongCpu);
        }
        let saved = disable();
        let result = (|| {
            if saved & IF != 0 {
                return Err(WorkError::InterruptContext);
            }
            if current() != self.local.as_ptr() || irq_active() || !native_frames_idle() {
                return Err(WorkError::Busy);
            }
            let context = if let Some(context) = self.root_context.upgrade() {
                context.check_current()?;
                context
            } else {
                let lease = self.retain_clock_root()?;
                // SAFETY: original physical Owner, IF0, no native frame or ISR.
                let snapshot = unsafe { firmware::observe() }.map_err(unavailable)?;
                let id = snapshot.apic_id().ok_or(WorkError::Unavailable)?;
                // SAFETY: retained actual processor's installed descriptor set.
                let observed = unsafe { interrupts::observe() };
                if observed.gs != self.local.as_ptr() as u64 || snapshot.cr3 & !ADDRESS != 0 {
                    return Err(WorkError::CorruptContext);
                }
                let state = state();
                if state.native || snapshot.cr3 != state.host_root {
                    return Err(WorkError::Busy);
                }
                let mut roots = alloc::vec::Vec::new();
                roots
                    .try_reserve_exact(2 + super::super::ROOTS * (1 + super::super::BANKS))
                    .map_err(unavailable)?;
                roots.push(state.window_root);
                roots.push(state.host_root);
                roots.extend(state.all_roots());
                roots.sort_unstable();
                roots.dedup();
                if roots.iter().any(|r| *r == 0 || r & !ADDRESS != 0) {
                    return Err(WorkError::CorruptContext);
                }
                let mut ram = alloc::vec::Vec::new();
                ram.try_reserve_exact(state.ram.len())
                    .map_err(unavailable)?;
                for range in &state.ram {
                    ram.push(PhysicalSpan::new(range.host, range.bytes).map_err(unavailable)?);
                }
                let context = Arc::new(RootContext {
                    roots: Arc::new(MmioRoots {
                        roots,
                        ram,
                        _lease: lease,
                    }),
                    snapshot,
                    id,
                    gs: observed.gs,
                    gdt: observed.gdt,
                    idt: observed.idt,
                    task: observed.task,
                    executing: AtomicBool::new(false),
                });
                context.check_current()?;
                self.root_context = Arc::downgrade(&context);
                context
            };
            context
                .executing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| WorkError::Busy)?;
            Ok(RootExecution {
                epoch: Arc::new(Epoch {
                    context,
                    active: AtomicBool::new(true),
                }),
                saved,
                _local: PhantomData,
            })
        })();
        if result.is_err() {
            // SAFETY: exact same-CPU save above, no scope was published.
            unsafe {
                restore(saved);
            }
        }
        result
    }
}
