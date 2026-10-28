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
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
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

/// Actual immutable CPU/descriptor/fixed-root identity, pinned by HostOwner.
/// This survives only checked RAM ownership joins. It grants no RAM-absence,
/// mutable mapping-publication, task switching, or cross-CPU execution authority.
/// Descriptor/local storage is static or permanently pinned through terminal IRQs.
pub(crate) struct RootIdentity {
    roots: Arc<MmioRoots>,
    snapshot: Snapshot,
    id: u32,
    gs: u64,
    gdt: u64,
    idt: u64,
    task: u16,
    ram_generation: AtomicU64,
}
impl RootIdentity {
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
    /// Immutable-root identity admission for process work, without a RAM grant.
    /// A native/helper frame cannot suspend its independent guest-state/code
    /// loan by starting a separate work executor underneath it.
    pub(crate) fn check_dispatch(&self) -> Result<(), WorkError> {
        self.check_irq_cpu()?;
        if irq_active() || !native_frames_idle() {
            return Err(WorkError::Busy);
        }
        Ok(())
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
    pub(crate) fn root_pages(&self) -> &[u64] {
        self.roots.roots()
    }
    pub(crate) fn memory_snapshot(&self) -> Result<Snapshot, WorkError> {
        self.check_current()?;
        Ok(self.snapshot)
    }
}

/// One generation's RAM-absence/publication view. Retaining this still prevents
/// RAM adoption; keeping only immutable RootIdentity does not retain this grant.
pub(crate) struct RootContext {
    identity: Arc<RootIdentity>,
    ram_generation: u64,
    executing: AtomicBool,
}
impl RootContext {
    fn generation(&self) -> Result<(), WorkError> {
        if self.ram_generation != self.identity.ram_generation.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    pub(crate) fn check_current(&self) -> Result<(), WorkError> {
        self.generation()?;
        self.identity.check_current()
    }
    pub(crate) fn check_irq_cpu(&self) -> Result<(), WorkError> {
        self.generation()?;
        self.identity.check_irq_cpu()
    }
    pub(crate) fn in_interrupt(&self) -> bool {
        self.generation().is_err() || self.identity.in_interrupt()
    }
    pub(crate) fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_current()?;
        self.identity.save_disable()
    }
    /// # Safety
    /// Exact enclosing same-CPU save; no switch/migration or active task-frame change.
    pub(crate) unsafe fn restore(&self, saved: u64) {
        if self.check_current().is_err() {
            self.fatal(WorkError::Closed);
        }
        // SAFETY: same retained identity and caller's exact enclosing save.
        unsafe { self.identity.restore(saved) };
    }
    pub(crate) fn fatal(&self, error: WorkError) -> ! {
        self.identity.fatal(error)
    }
    pub(crate) fn roots(&self) -> &Arc<MmioRoots> {
        &self.identity.roots
    }
    pub(crate) fn memory_snapshot(&self) -> Result<Snapshot, WorkError> {
        self.check_current()?;
        self.identity.memory_snapshot()
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
    /// Retain actual CPU/root identity without extending a RAM-absence epoch.
    /// Only pristine same-CPU process dispatch, IF0, may create/borrow it.
    pub(crate) fn root_identity(&mut self) -> Result<Arc<RootIdentity>, WorkError> {
        if gs_base() != self.local.as_ptr() as u64 {
            return Err(WorkError::WrongCpu);
        }
        let flags: u64;
        // SAFETY: CPL0 observation before any local-state borrow.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if flags & IF != 0 || irq_active() || !native_frames_idle() {
            return Err(WorkError::Busy);
        }
        if let Some(identity) = &self.root_identity {
            identity.check_current()?;
            return Ok(identity.clone());
        }
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
        let identity = Arc::new(RootIdentity {
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
            ram_generation: AtomicU64::new(0),
        });
        identity.check_current()?;
        self.root_identity = Some(identity.clone());
        Ok(identity)
    }

    /// Join the new canonical RAM owner without granting it additional host bytes.
    /// Old publication/absence views must already be closed; no ISR/native/helper
    /// frame can overlap. CPU/root identity survives, but its old generation ends.
    pub(super) fn join_ram_identity(
        &mut self,
        incoming: &[super::super::RamRange],
    ) -> Result<(), &'static str> {
        if self.root_context.strong_count() != 0 {
            return Err("RAM absence/publication views are still retained");
        }
        let Some(identity) = &self.root_identity else {
            return Ok(());
        };
        identity
            .check_current()
            .map_err(|_| "retained CPU/root identity changed before RAM adoption")?;
        if irq_active() || !native_frames_idle() {
            return Err("active native/IRQ frame prevents RAM adoption");
        }
        let flags: u64;
        // SAFETY: current physical Owner, read-only IRQ observation.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if flags & IF != 0 {
            return Err("RAM adoption requires excluded local interrupts");
        }
        let state = state();
        let mut roots = alloc::vec::Vec::new();
        roots
            .try_reserve_exact(2 + super::super::ROOTS * (1 + super::super::BANKS))
            .map_err(|_| "RAM transition root catalog allocation failed")?;
        roots.extend([state.window_root, state.host_root]);
        roots.extend(state.all_roots());
        roots.sort_unstable();
        roots.dedup();
        if roots != identity.root_pages() {
            return Err("retained native root catalog changed before RAM adoption");
        }
        let backing = identity.roots.ram().iter().map(|r| (r.start(), r.bytes()));
        let existing = state.ram.iter().map(|r| (r.host, r.bytes));
        let incoming = incoming.iter().map(|r| (r.host, r.bytes));
        let existing_matches =
            stela_boot_core::root_transition::same_backing_iter(backing.clone(), existing)
                .map_err(|_| "malformed old physical backing before RAM adoption")?;
        let incoming_matches =
            stela_boot_core::root_transition::same_backing_iter(backing, incoming)
                .map_err(|_| "malformed canonical physical backing before RAM adoption")?;
        if !existing_matches || !incoming_matches {
            return Err("canonical RAM adoption changes retained physical placements");
        }
        let next = identity
            .ram_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or("native RAM ownership generation exhausted")?;
        // Every old absence view is gone, proven above. There is no callback,
        // root mutation or IRQ between this invalidation and the caller's join.
        identity.ram_generation.store(next, Ordering::Release);
        self.root_context = alloc::sync::Weak::new();
        Ok(())
    }

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
            let identity = self.root_identity()?;
            let context = if let Some(context) = self.root_context.upgrade() {
                context.check_current()?;
                if !Arc::ptr_eq(&context.identity, &identity) {
                    return Err(WorkError::CorruptContext);
                }
                context
            } else {
                let context = Arc::new(RootContext {
                    ram_generation: identity.ram_generation.load(Ordering::Acquire),
                    identity,
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
