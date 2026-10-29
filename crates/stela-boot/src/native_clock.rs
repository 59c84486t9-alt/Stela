//! One physical root's fixed-clock producer, multiplexed through the engine's
//! existing local APIC timer/vector. No Linux callback enters from this ISR.
//!
//! General wall time is an exclusively owned actual HPET64 source, read with
//! coherent32 sampling. The old bounded PM path exists only for its explicit
//! short fixture. No source grants NTP, suspend or cross-CPU synchronization.
use crate::{
    apic::{self, Apic},
    engine::{host, interrupts},
};
use alloc::sync::Arc;
use core::{
    arch::asm,
    cell::UnsafeCell,
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering},
};
use stela_drivers::platform::work::{
    Cpu, RetainedOwner, WorkError,
    service::{Clock, Idle, RaisedWork},
};
mod counter;
#[cfg(feature = "diagnostics")]
pub(crate) mod diagnostic;
pub(crate) mod hpet;
mod pm;
mod source;
pub(crate) mod tsc;
pub(crate) use counter::Counter as HpetCounter;
pub(crate) use source::Prepared;
const IF: u64 = 1 << 9;
const TICK_NS: u64 = 1_000_000;
const NONE: u64 = u64::MAX;

// Exactly one registered timer consumer. Publication and removal occur on its
// owning processor with IF off; the hardware ISR never takes an Arc reference.
static ACTIVE: AtomicPtr<State> = AtomicPtr::new(ptr::null_mut());
// Other native host processors use the same engine handler. They must reject
// BEFORE loading/dereferencing the owning CPU's registration pointer: checking
// State.cpu afterward would race real BSP removal and permit a use-after-free.
static ACTIVE_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
// A legacy CPUID APIC ID can be narrower than the actual x2APIC ID namespace.
// The original HostOwner also owns a distinct permanently pinned GS record on
// every physical CPU. Validate that live architectural identity BEFORE ACTIVE,
// so a remote CPU with a colliding legacy ID cannot borrow a removable pointer.
static ACTIVE_GS: AtomicU64 = AtomicU64::new(0);

fn processor_id() -> u32 {
    let highest = core::arch::x86_64::__cpuid(0).eax;
    for leaf in [0x1f, 0xb] {
        if highest >= leaf {
            let topology = core::arch::x86_64::__cpuid_count(leaf, 0);
            if topology.ebx != 0 {
                return topology.edx;
            }
        }
    }
    core::arch::x86_64::__cpuid(1).ebx >> 24
}

fn gs_base() -> u64 {
    // SAFETY: read-only architectural CPL0 GS context, not device MMIO.
    unsafe { crate::cpu::msr::GS_BASE.read() }
}

fn registration_cpu() -> bool {
    if processor_id() != ACTIVE_CPU.load(Ordering::Acquire) {
        return false;
    }
    let expected_gs = ACTIVE_GS.load(Ordering::Acquire);
    expected_gs != 0 && gs_base() == expected_gs
}

fn flags_disable() -> u64 {
    let flags;
    // SAFETY: boot-owned CPL0 entry; memory clobber encloses the critical scope.
    unsafe {
        asm!("pushfq", "pop {}", "cli", out(reg) flags);
    }
    flags
}
unsafe fn restore(flags: u64) {
    // SAFETY: enclosing IRQ-save on this same physical processor.
    unsafe {
        asm!("push {}", "popfq", in(reg) flags);
    }
}
fn root() -> u64 {
    let root;
    // SAFETY: read-only privileged root observation.
    unsafe {
        asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags));
    }
    root
}

/// Immutable CPU view. The actual !Send HostOwner remains on its processor;
/// its root lease refuses owner destruction while any view still exists.
pub(crate) struct RootCpu {
    identity: Arc<host::RootIdentity>,
    base: u64,
    registers: u64,
    id: u32,
    root: u64,
    gs: u64,
    idt: u64,
    task: u16,
    max_cpuid: u32,
    thermal_eax: u32,
    deadline_control: tsc::DeadlineControl,
    source: Prepared,
    previous: AtomicU64,
    elapsed: AtomicU64,
    closed: AtomicBool,
    health: source::Health,
}
impl RootCpu {
    fn controller(&self) -> Apic {
        Apic::new(self.base, self.registers)
    }
    fn affinity(&self) -> Result<(), WorkError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(WorkError::Closed);
        }
        // The retained immutable Owner identity checks the actual CPU/GS/
        // descriptors and original root catalog before device access.
        self.identity.check_irq_cpu()
    }
    /// Caller holds actual local IRQ exclusion. A source fault does not
    /// revoke the time-free CPU identity needed to drain/release resources.
    fn sample_ticks(&self) -> Result<u64, WorkError> {
        self.health.check()?;
        let result = (|| {
            self.deadline_control.check()?;
            // SAFETY: original owner and CPU remain retained. Source checks
            // real control/power eligibility around the coherent read.
            let mut raw = unsafe { self.source.read()? };
            let previous = self.previous.load(Ordering::Relaxed);
            if raw == previous {
                raw = self.source.progress_after(previous)?;
            }
            let elapsed = self
                .elapsed
                .load(Ordering::Relaxed)
                .checked_add(self.source.delta(previous, raw)?)
                .ok_or(WorkError::Exhausted)?;
            self.previous.store(raw, Ordering::Relaxed);
            self.elapsed.store(elapsed, Ordering::Release);
            Ok(elapsed)
        })();
        result.map_err(|error| self.health.fail(error))
    }
    fn sample(&self) -> Result<u64, WorkError> {
        self.source
            .ns(self.sample_ticks()?)
            .map_err(|error| self.health.fail(error))
    }
    fn now(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        let flags = flags_disable();
        let result = self.sample();
        // SAFETY: exact enclosing save, no switch/callback or migration.
        unsafe {
            restore(flags);
        }
        result
    }
}
// SAFETY: immutable root/CPU witnesses are checked before entry; all mutable
// clock publication is atomic and serialized by actual same-CPU IRQ exclusion.
// The lease prevents HostOwner destruction, and foreign CPU entry is refused.
unsafe impl Cpu for RootCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        self.affinity()?;
        self.identity.check_clock_root()
    }
    fn in_interrupt(&self) -> bool {
        self.affinity().is_err() || host::root_irq_active()
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        Ok(flags_disable())
    }
    unsafe fn restore(&self, flags: u64) {
        if self.check_cpu().is_err() {
            self.fatal(WorkError::WrongCpu);
        }
        // SAFETY: the Cpu contract requires this same CPU's enclosing save.
        unsafe {
            restore(flags);
        }
    }
    fn ticks(&self) -> u64 {
        self.now().unwrap_or_else(|error| self.fatal(error))
    }
    fn fatal(&self, error: WorkError) -> ! {
        crate::output::arguments(format_args!("NATIVE CLOCK FATAL {error:?}\n"));
        crate::output::fatal("native clock/root contract failed")
    }
}

/// Continuous-source identity retained with the original physical CPU owner.
/// Cloning retains ownership; it neither migrates sampling nor rebases time.
#[derive(Clone)]
pub(crate) struct CounterEpoch {
    cpu: Arc<RootCpu>,
}
#[derive(Clone)]
pub(crate) struct CounterSample {
    epoch: CounterEpoch,
    ticks: u64,
}
/// A sealed pairing of the existing installed CPU, clock and idle producer.
/// Its private fields cannot pair an unrelated Cpu/Idle with a counter epoch.
pub(crate) struct ClockServices {
    state: Arc<State>,
    clock: Arc<dyn Clock>,
    idle: Arc<dyn Idle>,
}
impl ClockServices {
    pub(crate) fn check_identity(
        &self,
        identity: &Arc<host::RootIdentity>,
    ) -> Result<(), WorkError> {
        self.state.process()?;
        if !Arc::ptr_eq(identity, &self.state.cpu.identity) {
            return Err(WorkError::WrongCpu);
        }
        self.state.cpu.health.check()?;
        self.state
            .cpu
            .source
            .continuous_period()
            .map_err(|error| self.state.cpu.health.fail(error))?;
        Ok(())
    }
    pub(crate) fn cpu(&self) -> Arc<dyn Cpu> {
        self.state.cpu_view.clone()
    }
    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }
    pub(crate) fn idle(&self) -> Arc<dyn Idle> {
        self.idle.clone()
    }
    pub(crate) fn epoch(&self) -> Result<CounterEpoch, WorkError> {
        self.check_identity(&self.state.cpu.identity)?;
        Ok(CounterEpoch {
            cpu: self.state.cpu.clone(),
        })
    }
}
pub(crate) use source::ElapsedBounds;
impl CounterEpoch {
    /// Nominal monotonic nanoseconds for transport deadlines. UTC callers use
    /// sample/elapsed_bounds, which retain the source's outward uncertainty.
    pub(crate) fn now_ns(&self) -> Result<u64, WorkError> {
        let sample = self.sample()?;
        self.cpu
            .source
            .ns(sample.ticks)
            .map_err(|error| self.cpu.health.fail(error))
    }
    pub(crate) fn sample(&self) -> Result<CounterSample, WorkError> {
        self.cpu.health.check()?;
        self.cpu.check_cpu()?;
        self.cpu
            .source
            .continuous_period()
            .map_err(|error| self.cpu.health.fail(error))?;
        let flags = flags_disable();
        let result = self.cpu.sample_ticks();
        // Restore depends only on the real time-free CPU identity. A failed
        // source must not prevent resources from being drained on that CPU.
        // SAFETY: exact same CPU's enclosing IRQ save; no switch/callback.
        unsafe {
            self.cpu.restore(flags);
        }
        let ticks = result?;
        self.cpu.check_cpu()?;
        self.cpu.health.check()?;
        Ok(CounterSample {
            epoch: self.clone(),
            ticks,
        })
    }

    pub(crate) fn elapsed_bounds(
        &self,
        start: &CounterSample,
        end: &CounterSample,
    ) -> Result<ElapsedBounds, WorkError> {
        if !Arc::ptr_eq(&self.cpu, &start.epoch.cpu) || !Arc::ptr_eq(&self.cpu, &end.epoch.cpu) {
            return Err(WorkError::InvalidTicket);
        }
        // A retained old reading never supplies readiness after detach,
        // control/root loss or a source transition.
        self.sample()?;
        let ticks = end
            .ticks
            .checked_sub(start.ticks)
            .ok_or(WorkError::CorruptContext)?;
        self.cpu
            .source
            .elapsed_bounds(ticks)
            .map_err(|error| self.cpu.health.fail(error))
    }
}

struct Counter {
    word: NonNull<AtomicU64>,
    generation: NonNull<AtomicU64>,
    expected: u64,
    initial: u64,
    origin_ns: u64,
    _owner: RetainedOwner,
}
impl Counter {
    fn publish(&self, now: u64) -> Result<(), WorkError> {
        // SAFETY: source-bound immutable counter registration retains both
        // aligned atomic words until actual same-CPU detach with IF off.
        let (word, generation) = unsafe { (self.word.as_ref(), self.generation.as_ref()) };
        if generation.load(Ordering::Acquire) != self.expected {
            return Err(WorkError::Closed);
        }
        let elapsed = now
            .checked_sub(self.origin_ns)
            .ok_or(WorkError::CorruptContext)?
            / TICK_NS;
        let old = word.load(Ordering::Acquire);
        if old.wrapping_sub(self.initial) < elapsed {
            // The original poll writer is on THIS CPU and cannot run during
            // this IF-off publication. Strong CAS avoids an unbounded weak-CAS
            // retry in the ISR; a competing writer violates root admission.
            word.compare_exchange(
                old,
                self.initial.wrapping_add(elapsed),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| WorkError::CorruptContext)?;
        }
        Ok(())
    }
}

struct State {
    cpu: Arc<RootCpu>,
    apic_hz: u64,
    cpu_view: Arc<dyn Cpu>,
    pending: AtomicBool,
    executing: AtomicBool,
    execution_generation: AtomicU64,
    guest: AtomicU64,
    idle: AtomicU64,
    heartbeat: AtomicU64,
    raised: UnsafeCell<Option<RaisedWork>>,
    counter: UnsafeCell<Option<Counter>>,
}
// SAFETY: pointer fields never leave the actual owning CPU, every effect checks
// affinity first, and process mutation excludes the same real ISR with CLI.
unsafe impl Send for State {}
// SAFETY: same CPU and actual IRQ exclusion; no callback accesses mutable State.
unsafe impl Sync for State {}
impl State {
    fn process(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()?;
        if self.cpu.in_interrupt() {
            return Err(WorkError::InterruptContext);
        }
        if !ptr::eq(ACTIVE.load(Ordering::Acquire), self) {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    fn rearm(&self, now: u64) -> Result<(), WorkError> {
        self.cpu.health.check()?;
        self.cpu
            .deadline_control
            .check()
            .map_err(|error| self.cpu.health.fail(error))?;
        let next = self
            .heartbeat
            .load(Ordering::Relaxed)
            .min(self.guest.load(Ordering::Relaxed))
            .min(self.idle.load(Ordering::Relaxed));
        let delta = next.saturating_sub(now).max(1);
        let ticks = (u128::from(delta) * u128::from(self.apic_hz))
            .div_ceil(u128::from(pm::NS))
            .clamp(1, u128::from(u32::MAX)) as u32;
        let apic = self.cpu.controller();
        if apic.read(apic::DIVIDE) & 0b1011 != 0b1011 {
            return Err(self.cpu.health.fail(WorkError::CorruptContext));
        }
        apic.write(apic::LVT_TIMER, u32::from(interrupts::TIMER_VECTOR));
        apic.write(apic::INITIAL, ticks);
        Ok(())
    }
}
struct NativeClock(Arc<State>);
// SAFETY: time comes from the actual retained hardware counter. Its coherent
// reads and elapsed accumulator are serialized by this physical CPU's IRQ save.
unsafe impl Clock for NativeClock {
    fn cpu(&self) -> &Arc<dyn Cpu> {
        &self.0.cpu_view
    }
    fn now_ns(&self) -> Result<u64, WorkError> {
        self.0.cpu.now()
    }
}
struct NativeIdle {
    state: Arc<State>,
    clock: Arc<dyn Clock>,
}
// SAFETY: all notifications are same physical CPU and retained GS/IDT roots;
// pending is published before sleeping's CLI/check/STI;HLT sequence. An incoming
// IF=0 refuses waiting, so the provider never creates permission for progress.
unsafe impl Idle for NativeIdle {
    fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }
    fn notify(&self) -> Result<(), WorkError> {
        self.state.cpu.affinity()?;
        self.state.pending.store(true, Ordering::Release);
        Ok(())
    }
    fn wait_until_ns(&self, deadline: Option<u64>) -> Result<(), WorkError> {
        self.state.process()?;
        let flags = flags_disable();
        let result = (|| {
            if flags & IF == 0 {
                return Err(WorkError::WouldDeadlock);
            }
            let now = self.state.cpu.sample()?;
            if self.state.pending.swap(false, Ordering::AcqRel)
                || deadline.is_some_and(|d| d <= now)
            {
                return Ok(());
            }
            self.state
                .idle
                .store(deadline.unwrap_or(NONE), Ordering::Relaxed);
            self.state.rearm(now)?;
            // SAFETY: incoming IF was set, root owns actual IDT/LAPIC. STI's
            // shadow spans HLT; same-CPU interrupt publication cannot be lost.
            unsafe {
                asm!("sti", "hlt", "cli", options(nostack));
            }
            self.state.idle.store(NONE, Ordering::Relaxed);
            self.state.pending.swap(false, Ordering::AcqRel);
            self.state.rearm(self.state.cpu.sample()?)
        })();
        // SAFETY: exact flags from the same physical dispatcher entry.
        unsafe {
            restore(flags);
        }
        result
    }
}

/// Own the native registration until the actual service has stopped and joined.
/// Forgetting this guard pins the real root rather than freeing live ISR state.
pub(crate) struct Installed {
    state: ManuallyDrop<Arc<State>>,
    pub(crate) clock: ManuallyDrop<Arc<dyn Clock>>,
    pub(crate) idle: ManuallyDrop<Arc<dyn Idle>>,
    _local: PhantomData<*mut ()>,
}

pub(crate) struct Observation {
    pub(crate) source: source::Observation,
    pub(crate) apic_hz: u64,
    pub(crate) cpu: u32,
    pub(crate) root: u64,
    pub(crate) idt: u64,
    pub(crate) gs: u64,
    pub(crate) max_cpuid: u32,
    pub(crate) thermal_eax: u32,
}
impl core::fmt::Debug for Observation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut record = f.debug_struct("Observation");
        self.source.debug_fields(&mut record);
        record
            .field("apic_hz", &self.apic_hz)
            .field("cpu", &self.cpu)
            .field("root", &self.root)
            .field("idt", &self.idt)
            .field("gs", &self.gs)
            .field("max_cpuid", &self.max_cpuid)
            .field("thermal_eax", &self.thermal_eax)
            .finish()
    }
}

/// Explicit main-owned permission for physical IRQ delivery during driver
/// execution. Generic Cpu, Runtime and Idle code cannot create this grant.
pub(crate) struct DriverExecution<'a> {
    installed: &'a Installed,
    flags: u64,
    generation: u64,
    scope_leases: Arc<()>,
    _local: PhantomData<*mut ()>,
}
/// Immutable process authority for exported native mapping views. A live scope
/// view prevents the actual !Send execution grant from ending; numerical root
/// equality alone does not supply this authority or reopen an older scope.
pub(crate) struct ProcessScope {
    state: Arc<State>,
    generation: u64,
    _lease: Arc<()>,
}
impl ProcessScope {
    pub(crate) fn check(&self) -> Result<(), WorkError> {
        self.state.process()?;
        if !self.state.executing.load(Ordering::Acquire)
            || self.state.execution_generation.load(Ordering::Acquire) != self.generation
        {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    pub(crate) fn cpu(&self) -> Result<Arc<dyn Cpu>, WorkError> {
        self.check()?;
        Ok(self.state.cpu_view.clone())
    }
}
/// Existing APIC/IDT admission metadata from the actual live root grant. This
/// retains only the immutable CPU view; it neither moves HostOwner nor reserves
/// another vector or hardware timer.
pub(crate) struct IrqAdapter {
    root_cpu: Arc<RootCpu>,
    pub(crate) cpu: Arc<dyn Cpu>,
    pub(crate) base: u64,
    pub(crate) registers: u64,
}
impl IrqAdapter {
    /// Validate this actual retained physical CPU and existing IDT/GS across
    /// every engine root. This supplies no Linux owner or process-entry proof.
    pub(crate) fn check_irq_cpu(&self) -> Result<(), WorkError> {
        self.root_cpu.affinity()
    }
}
impl DriverExecution<'_> {
    pub(crate) fn check(&self) -> Result<(), WorkError> {
        self.installed.state.process()?;
        if !self.installed.state.executing.load(Ordering::Acquire)
            || self
                .installed
                .state
                .execution_generation
                .load(Ordering::Acquire)
                != self.generation
        {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    pub(crate) fn cpu(&self) -> Result<Arc<dyn Cpu>, WorkError> {
        self.check()?;
        Ok(self.installed.state.cpu_view.clone())
    }
    pub(crate) fn process_scope(&self) -> Result<Arc<ProcessScope>, WorkError> {
        self.check()?;
        Ok(Arc::new(ProcessScope {
            state: Arc::clone(&self.installed.state),
            generation: self.generation,
            _lease: self.scope_leases.clone(),
        }))
    }
    pub(crate) fn irq_adapter(&self) -> Result<IrqAdapter, WorkError> {
        self.check()?;
        let cpu = &self.installed.state.cpu;
        Ok(IrqAdapter {
            root_cpu: cpu.clone(),
            cpu: self.installed.state.cpu_view.clone(),
            base: cpu.base,
            registers: cpu.registers,
        })
    }
}
impl Drop for DriverExecution<'_> {
    fn drop(&mut self) {
        if self.check().is_err() {
            self.installed.state.cpu.fatal(WorkError::CorruptContext);
        }
        if Arc::strong_count(&self.scope_leases) != 1 {
            self.installed.state.cpu.fatal(WorkError::Busy);
        }
        flags_disable();
        self.installed
            .state
            .executing
            .store(false, Ordering::Release);
        // SAFETY: actual same-CPU owner scope; no C frame/IRQ remains active.
        unsafe {
            restore(self.flags);
        }
    }
}
impl Installed {
    /// # Safety
    /// Post-EBS actual owning CPU and canonical time-free RootExecution.
    /// HPET source owns its UC mapping/controller and the same immutable identity.
    /// No stop/reset/counter-write/rate/decode/suspend discontinuity is allowed.
    /// PM is admitted only under its separate explicit complete sample-gap bound.
    /// No suspend/reset/migration/root replacement occurs before final release.
    /// Existing all-root IDT/GS/xstate/clock code mappings remain retained. The
    /// hardware timer is quiescent and its sole owner hands it to this mux.
    /// The ARAT-qualified LAPIC timer's measured rate remains stable and running
    /// through every actual HLT, including platform/VMM power transitions. No
    /// reconfiguration invalidates that retained rate/idle contract. A platform
    /// without ARAT requires a separate real broadcast/deadline producer.
    pub(crate) unsafe fn attach(
        owner: &mut host::HostOwner,
        root_execution: &host::RootExecution,
        source: Prepared,
    ) -> Result<Self, WorkError> {
        owner.check_root(root_execution)?;
        let identity = root_execution.context().identity().clone();
        // SAFETY: actual owner/root execution and complete controller/deadline
        // handoff are supplied by this constructor's existing contract.
        unsafe { Self::attach_identity(identity, source) }
    }
    /// # Safety
    /// Same actual timer/IDT/controller/rate/ARAT handoff as attach, using the
    /// production resource owner and immutable HostOwner identity. Every old
    /// absence/publication capability must independently close before RAM
    /// adoption; this clock never retains or recreates one of those grants.
    pub(crate) unsafe fn attach_native(
        identity: Arc<host::RootIdentity>,
        source: Prepared,
    ) -> Result<Self, WorkError> {
        identity.check_dispatch()?;
        source.admit(&identity)?;
        source.continuous_period()?;
        // SAFETY: caller retains the genuine physical controller/root/deadline
        // owner; source admission below checks the exact same identity.
        unsafe { Self::attach_identity(identity, source) }
    }
    /// Actual source and local timer handoff required by the two constructors.
    unsafe fn attach_identity(
        identity: Arc<host::RootIdentity>,
        source: Prepared,
    ) -> Result<Self, WorkError> {
        identity.check_dispatch()?;
        source.admit(&identity)?;
        let deadline_control = tsc::DeadlineControl::capture()?;
        let max_cpuid = deadline_control.max_cpuid();
        let thermal_eax = deadline_control.thermal_eax();
        // ARAT is the actual local timer's invariant-rate/idle prerequisite;
        // the existing guest timer or successful periodic delivery supplies no
        // such proof. Refuse before CLI, calibration, ownership or publication.
        // Keep a source owner outside the IRQ-off closure so failed admission
        // cannot perform its final Mapping/root owner release before restore.
        let deferred_source = source.clone();
        let flags = flags_disable();
        let result = (|| {
            if !ACTIVE.load(Ordering::Acquire).is_null() {
                return Err(WorkError::Busy);
            }
            identity.check_dispatch()?;
            let base = apic::base_msr();
            let registers = crate::layout::physical(base & apic::BASE_ADDRESS);
            let apic = Apic::new(base, registers);
            if apic.id() == u32::MAX || processor_id() != apic.id() {
                return Err(WorkError::WrongCpu);
            }
            let timer_bit = 1u32 << (interrupts::TIMER_VECTOR % 32);
            let timer_group = u32::from(interrupts::TIMER_VECTOR / 32) * 16;
            if apic.read(apic::INITIAL) != 0
                || apic.read(apic::CURRENT) != 0
                || apic.read(0x200 + timer_group) & timer_bit != 0
                || apic.read(0x100 + timer_group) & timer_bit != 0
                || apic.read(apic::LVT_TIMER) & 255 != u32::from(interrupts::TIMER_VECTOR)
            {
                return Err(WorkError::Busy);
            }
            // SAFETY: genuine retained descriptor/root ownership from owner.
            let observed = unsafe { interrupts::observe() };
            if host::root_irq_active() {
                return Err(WorkError::InterruptContext);
            }
            // SAFETY: exact canonical actual source/root ownership retained;
            // HPET validates the original CPU/root before coherent MMIO reads.
            let previous = unsafe { source.read()? };
            let cpu = Arc::new(RootCpu {
                identity,
                base,
                registers,
                id: apic.id(),
                root: root(),
                gs: observed.gs,
                idt: observed.idt,
                task: observed.task,
                max_cpuid,
                thermal_eax,
                deadline_control,
                source,
                previous: AtomicU64::new(previous),
                elapsed: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                health: source::Health::new(),
            });
            let apic_hz = calibrate(&cpu)?;
            let now = cpu.sample()?;
            let state = Arc::new(State {
                cpu_view: cpu.clone(),
                cpu,
                apic_hz,
                pending: AtomicBool::new(false),
                executing: AtomicBool::new(false),
                execution_generation: AtomicU64::new(0),
                guest: AtomicU64::new(NONE),
                idle: AtomicU64::new(NONE),
                heartbeat: AtomicU64::new(now.checked_add(TICK_NS).ok_or(WorkError::Exhausted)?),
                raised: UnsafeCell::new(None),
                counter: UnsafeCell::new(None),
            });
            // Complete fallible hardware validation before publishing an IRQ
            // registration. A changed controller must leave no orphaned Arc.
            state.rearm(now)?;
            // The explicit raw strong reference is registration ownership;
            // removal is same-CPU IRQ-excluded and precedes from_raw release.
            ACTIVE_GS.store(state.cpu.gs, Ordering::Release);
            ACTIVE_CPU.store(state.cpu.id, Ordering::Release);
            ACTIVE.store(Arc::into_raw(state.clone()).cast_mut(), Ordering::Release);
            let clock: Arc<dyn Clock> = Arc::new(NativeClock(state.clone()));
            let idle: Arc<dyn Idle> = Arc::new(NativeIdle {
                state: state.clone(),
                clock: clock.clone(),
            });
            Ok(Self {
                state: ManuallyDrop::new(state),
                clock: ManuallyDrop::new(clock),
                idle: ManuallyDrop::new(idle),
                _local: PhantomData,
            })
        })();
        // SAFETY: exact enclosing owner-local save, no switch occurred.
        unsafe {
            restore(flags);
        }
        drop(deferred_source);
        result
    }
    /// Only the real installed native source can mint a continuous epoch.
    /// A scoped fixture or bounded PM counter cannot satisfy this constructor.
    pub(crate) fn epoch(&self) -> Result<CounterEpoch, WorkError> {
        self.state.process()?;
        self.state.cpu.health.check()?;
        self.state
            .cpu
            .source
            .continuous_period()
            .map_err(|error| self.state.cpu.health.fail(error))?;
        self.state.cpu.now()?;
        Ok(CounterEpoch {
            cpu: self.state.cpu.clone(),
        })
    }

    pub(crate) fn services(&self) -> Result<ClockServices, WorkError> {
        self.epoch()?;
        Ok(ClockServices {
            state: Arc::clone(&self.state),
            clock: Arc::clone(&self.clock),
            idle: Arc::clone(&self.idle),
        })
    }
    pub(crate) fn cpu(&self) -> Arc<dyn Cpu> {
        self.state.cpu_view.clone()
    }
    pub(crate) fn observation(&self) -> Result<Observation, WorkError> {
        self.state.process()?;
        let cpu = &self.state.cpu;
        Ok(Observation {
            source: cpu.source.observation(),
            apic_hz: self.state.apic_hz,
            cpu: cpu.id,
            root: cpu.root,
            idt: cpu.idt,
            gs: cpu.gs,
            max_cpuid: cpu.max_cpuid,
            thermal_eax: cpu.thermal_eax,
        })
    }
    /// # Safety
    /// Called only by the actual main/root dispatcher, which grants interrupt
    /// delivery through the retained existing IDT/IST/xstate/LAPIC ownership.
    /// All ISR-reachable publications/code/storage are installed and retained;
    /// no mutable Host State borrow or native/foreign critical scope survives
    /// this entry. All driver continuations and foreign frames return/join
    /// before dropping the grant. Preserve the source's qualified sample bound.
    pub(crate) unsafe fn enter_driver_execution(&self) -> Result<DriverExecution<'_>, WorkError> {
        self.state.process()?;
        let scope_leases = Arc::new(());
        let flags = flags_disable();
        if self.state.executing.load(Ordering::Acquire) {
            unsafe {
                restore(flags);
            }
            return Err(WorkError::Busy);
        }
        let generation = match self
            .state
            .execution_generation
            .load(Ordering::Relaxed)
            .checked_add(1)
        {
            Some(generation) => generation,
            None => {
                unsafe {
                    restore(flags);
                }
                return Err(WorkError::Exhausted);
            }
        };
        self.state
            .execution_generation
            .store(generation, Ordering::Release);
        self.state.executing.store(true, Ordering::Release);
        // SAFETY: this is the explicit main-owned execution permission, never
        // an implicit attempt by Idle/Runtime to manufacture interrupt progress.
        unsafe {
            asm!("sti", options(nostack));
        }
        Ok(DriverExecution {
            installed: self,
            flags,
            generation,
            scope_leases,
            _local: PhantomData,
        })
    }
    pub(crate) fn bind_raised(&self, raised: RaisedWork) -> Result<(), WorkError> {
        self.state.process()?;
        let flags = flags_disable();
        // SAFETY: same owning process, actual local ISR excluded.
        let result = unsafe {
            let slot = &mut *self.state.raised.get();
            if slot.is_some() {
                Err(WorkError::Busy)
            } else {
                *slot = Some(raised);
                Ok(())
            }
        };
        // SAFETY: balanced flags, no switch.
        unsafe {
            restore(flags);
        }
        result
    }
    /// # Safety
    /// Exact original wheel_counter_acquire snapshot, with both aligned u64
    /// words and original image/storage retained in owner. Its producer uses the
    /// same clock Arc/origin and HZ=1000. Wheel polling shares this CAS-max ABI.
    /// Counter release/unregister may occur only AFTER detach_publications.
    pub(crate) unsafe fn bind_counter(
        &self,
        word: NonNull<AtomicU64>,
        generation: NonNull<AtomicU64>,
        expected: u64,
        initial: u64,
        origin_ns: u64,
        owner: RetainedOwner,
    ) -> Result<(), WorkError> {
        self.state.process()?;
        if expected == 0 || origin_ns > self.state.cpu.now()? {
            return Err(WorkError::InvalidTicket);
        }
        // Keep rejected ownership outside the artificial IRQ-masked scope.
        // Validation/sample/Busy failures must restore flags before releasing
        // an arbitrary retained original-code/storage/provider owner.
        let mut candidate = Some(Counter {
            word,
            generation,
            expected,
            initial,
            origin_ns,
            _owner: owner,
        });
        let flags = flags_disable();
        let result = (|| {
            // SAFETY: actual IRQ exclusion and retained immutable snapshot.
            let slot = unsafe { &mut *self.state.counter.get() };
            if slot.is_some() {
                return Err(WorkError::Busy);
            }
            candidate
                .as_ref()
                .ok_or(WorkError::CorruptContext)?
                .publish(self.state.cpu.sample()?)?;
            *slot = candidate.take();
            Ok(())
        })();
        // SAFETY: exact same CPU's save.
        unsafe {
            restore(flags);
        }
        drop(candidate);
        result
    }
    /// Stop ISR reason/counter publication before original producers are
    /// released. The hardware clock remains alive for service drain and join.
    pub(crate) fn detach_publications(&self) -> Result<(), WorkError> {
        self.state.process()?;
        let flags = flags_disable();
        // SAFETY: no same-CPU IRQ can still borrow either immutable view.
        let (counter, raised) = unsafe {
            (
                (&mut *self.state.counter.get()).take(),
                (&mut *self.state.raised.get()).take(),
            )
        };
        // SAFETY: restore before actual process-context final owner releases.
        unsafe {
            restore(flags);
        }
        drop(counter);
        drop(raised);
        Ok(())
    }
    /// # Safety
    /// All original producers are stopped, publications detached, actual Timer
    /// task and every driver continuation joined, and no idle call is active.
    /// Every Runtime, Domain, service receiver, Queue, WakeHandle and executor
    /// whose final release validates Cpu::check_cpu is FINALLY RELEASED before
    /// this call, while its CPU remains live. Merely retiring/joining such an
    /// object and dropping it later is insufficient: this call closes the CPU
    /// view, so that later qualified release would instead quarantine it.
    /// Only direct CPU/Clock/Idle Arc clones whose destructors do not validate
    /// that closed view may remain for later release. Drop those final clones
    /// before closing RootExecution or dropping the real !Send HostOwner.
    /// The physical root epoch remains active through any later direct clone
    /// release. For HPET, a real caller-retained HpetCounter must survive this
    /// retirement, then stop/drain and retire its actual mapping before that
    /// epoch ends. No automatic Drop is permission to unmap a live source.
    /// Permanent adopted IRQ/kernel-image roots have no finite epoch closure.
    /// Main's actual NativeDomain
    /// teardown must enforce this ordering; this method does not perform it.
    /// A full original kernel image retains kthreadd/global workers for its
    /// lifetime, so Installed, DriverExecution and HostOwner remain rooted for
    /// that same lifetime. Such an image has no finite retirement permission;
    /// this entry is for actually quiescent bounded/failure retirements only.
    pub(crate) unsafe fn retire(mut self) -> Result<(), WorkError> {
        self.state.process()?;
        let flags = flags_disable();
        if self.state.executing.load(Ordering::Acquire) {
            unsafe {
                restore(flags);
            }
            return Err(WorkError::Busy);
        }
        // SAFETY: genuine IRQ exclusion; publications must already be drained.
        if unsafe {
            (&*self.state.counter.get()).is_some() || (&*self.state.raised.get()).is_some()
        } {
            unsafe {
                restore(flags);
            }
            return Err(WorkError::Busy);
        }
        // A source fault must not block time-free cleanup when no guest
        // deadline needs conversion. If one exists, validate its handback
        // before removing the registration; failed time cannot cancel it.
        let guest = self.state.guest.load(Ordering::Relaxed);
        let now = if guest == NONE {
            0
        } else {
            match self.state.cpu.sample() {
                Ok(now) => now,
                Err(error) => {
                    // SAFETY: same physical CPU's enclosing save. The live
                    // registration stays pinned with its original deadline.
                    unsafe { restore(flags) };
                    return Err(error);
                }
            }
        };
        let pointer = ACTIVE.swap(ptr::null_mut(), Ordering::AcqRel);
        ACTIVE_CPU.store(u32::MAX, Ordering::Release);
        ACTIVE_GS.store(0, Ordering::Release);
        let apic = self.state.cpu.controller();
        // Hand the original guest deadline back to its existing host owner.
        // Closing a driver clock cannot silently cancel that separate timer.
        if guest == NONE {
            apic.write(apic::INITIAL, 0);
            apic.write(
                apic::LVT_TIMER,
                apic::LVT_MASKED | u32::from(interrupts::TIMER_VECTOR),
            );
        } else {
            let ticks = (u128::from(guest.saturating_sub(now).max(1))
                * u128::from(self.state.apic_hz))
            .div_ceil(u128::from(pm::NS))
            .clamp(1, u128::from(u32::MAX)) as u32;
            apic.write(apic::LVT_TIMER, u32::from(interrupts::TIMER_VECTOR));
            apic.write(apic::INITIAL, ticks);
        }
        self.state.cpu.closed.store(true, Ordering::Release);
        // SAFETY: the ISR is excluded; the raw Arc belongs to this registration.
        let registration = unsafe { Arc::from_raw(pointer) };
        // SAFETY: exact enclosing save; a stale vector now takes the host path.
        unsafe {
            restore(flags);
        }
        drop(registration);
        // SAFETY: real process retirement, all callback/storage leases detached.
        unsafe {
            ManuallyDrop::drop(&mut self.idle);
            ManuallyDrop::drop(&mut self.clock);
            ManuallyDrop::drop(&mut self.state);
        }
        Ok(())
    }
}

fn calibrate(cpu: &RootCpu) -> Result<u64, WorkError> {
    let apic = cpu.controller();
    let saved_lvt = apic.read(apic::LVT_TIMER);
    let saved_divide = apic.read(apic::DIVIDE);
    apic.write(
        apic::LVT_TIMER,
        apic::LVT_MASKED | u32::from(interrupts::TIMER_VECTOR),
    );
    apic.write(apic::DIVIDE, 0b1011); // Existing engine divider: one.
    apic.write(apic::INITIAL, u32::MAX);
    let result = (|| {
        let begin_ns = cpu.sample()?;
        let begin_apic = apic.read(apic::CURRENT);
        for _ in 0..10_000_000 {
            let now = cpu.sample()?;
            if now - begin_ns >= 10_000_000 {
                let end_apic = apic.read(apic::CURRENT);
                if end_apic == 0 || end_apic >= begin_apic {
                    return Err(WorkError::Unavailable);
                }
                let hz = u128::from(begin_apic - end_apic) * u128::from(pm::NS)
                    / u128::from(now - begin_ns);
                return u64::try_from(hz)
                    .ok()
                    .filter(|hz| *hz != 0)
                    .ok_or(WorkError::Unavailable);
            }
            core::hint::spin_loop();
        }
        Err(WorkError::TimedOut)
    })();
    apic.write(apic::INITIAL, 0);
    apic.write(apic::LVT_TIMER, saved_lvt);
    if result.is_err() {
        apic.write(apic::DIVIDE, saved_divide);
    }
    result
}

/// Existing host owner routes its guest timer count here when registered.
/// Saves/restores local IRQ state itself, including callers already at IF=0.
/// No independent vector namespace is allocated.
pub(crate) fn arm_guest(ticks: Option<u32>) -> bool {
    let flags = flags_disable();
    let result = arm_guest_disabled(ticks);
    // SAFETY: exact same-CPU save; no callback or switch occurred in the mux.
    unsafe {
        restore(flags);
    }
    result
}
fn arm_guest_disabled(ticks: Option<u32>) -> bool {
    if !registration_cpu() {
        return false;
    }
    let pointer = ACTIVE.load(Ordering::Acquire);
    if pointer.is_null() {
        return false;
    }
    // SAFETY: IRQ-excluded pointer owned by the real same-CPU registration.
    let state = unsafe { &*pointer };
    if state.cpu.affinity().is_err() {
        return false;
    }
    let result = (|| {
        let now = state.cpu.sample()?;
        let deadline = match ticks {
            Some(ticks) => now
                .checked_add(
                    u64::try_from(
                        (u128::from(ticks) * u128::from(pm::NS))
                            .div_ceil(u128::from(state.apic_hz)),
                    )
                    .map_err(|_| WorkError::Exhausted)?,
                )
                .ok_or(WorkError::Exhausted)?,
            None => NONE,
        };
        state.guest.store(deadline, Ordering::Relaxed);
        state.rearm(now)
    })();
    if let Err(error) = result {
        state.cpu.fatal(error);
    }
    true
}

/// Fast path called by the genuine existing timer-vector entry BEFORE its EOI.
/// It samples actual elapsed time, atomically publishes counters/reasons, and
/// rearms the shared minimum. It enters no Linux owner or original callback.
pub(crate) fn interrupt() {
    if !registration_cpu() {
        return;
    }
    let pointer = ACTIVE.load(Ordering::Acquire);
    if pointer.is_null() {
        return;
    }
    // SAFETY: same-CPU IRQ entry/removal exclusion retains registration's Arc.
    let state = unsafe { &*pointer };
    if state.cpu.affinity().is_err() {
        return;
    } // Other physical CPUs own their timers.
    let result = (|| {
        let now = state.cpu.sample()?;
        let heartbeat = state.heartbeat.load(Ordering::Relaxed);
        if now >= heartbeat {
            let phases = (now - heartbeat) / TICK_NS + 1;
            state.heartbeat.store(
                heartbeat
                    .checked_add(phases.checked_mul(TICK_NS).ok_or(WorkError::Exhausted)?)
                    .ok_or(WorkError::Exhausted)?,
                Ordering::Relaxed,
            );
            // SAFETY: same-CPU actual entry, no process mutation while IF=0.
            if let Some(counter) = unsafe { &*state.counter.get() } {
                counter.publish(now)?;
            }
            if let Some(raised) = unsafe { &*state.raised.get() } {
                raised.raise()?;
            }
        }
        if state.guest.load(Ordering::Relaxed) <= now {
            state.guest.store(NONE, Ordering::Relaxed);
        }
        if state.idle.load(Ordering::Relaxed) <= now {
            state.idle.store(NONE, Ordering::Relaxed);
            state.pending.store(true, Ordering::Release);
        }
        state.rearm(now)
    })();
    if let Err(error) = result {
        state.cpu.fatal(error);
    }
}
