//! The boot processor's device interrupts: physical MSI and owned I/O APIC
//! line routes through the engine's IDT vectors 0x50..=0x5f and its local
//! APIC. [`start`] attaches the registry once the host is installed; the
//! host drivers request routes through [`service`], and the engine takes
//! their interrupts in its wait windows. Interrupt remapping is off.
use crate::apic::{self, Apic};
use alloc::{boxed::Box, sync::Arc};
use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering},
};
use stela_drivers::bus::irq::{IrqController, IrqError, Platform, Registry, Target};
use stela_drivers::platform::work::Cpu;

mod context;
#[allow(dead_code)]
mod crs;
#[cfg(feature = "diagnostics")]
pub(crate) mod diagnostic;
#[allow(dead_code)]
pub mod ioapic;
#[cfg(feature = "diagnostics")]
pub(crate) mod level_diagnostic;
#[allow(dead_code)]
pub mod madt;
#[allow(dead_code)]
pub(crate) mod root;
#[cfg(feature = "diagnostics")]
pub(crate) mod work_diagnostic;

static CONTEXT: context::Context = context::Context::new();
static READY: AtomicBool = AtomicBool::new(false);
static BASE: AtomicU64 = AtomicU64::new(0);
static REGISTERS: AtomicU64 = AtomicU64::new(0);
static BSP: AtomicU32 = AtomicU32::new(0);
static TIMEOUT: AtomicU64 = AtomicU64::new(0);
// Main's original immutable CPU/root view, permanently retained with this
// static registry and its possible quarantines. Never moves HostOwner itself.
static ROOT_ADAPTER: AtomicPtr<crate::native_clock::IrqAdapter> =
    AtomicPtr::new(core::ptr::null_mut());

fn root_adapter() -> Option<&'static crate::native_clock::IrqAdapter> {
    let adapter = ROOT_ADAPTER.load(Ordering::Acquire);
    // SAFETY: publication leaks this exact Box for the permanent registry
    // lifetime. No path removes it, including failed source retirement.
    unsafe { adapter.as_ref() }
}
fn root_cpu() -> Option<&'static Arc<dyn Cpu>> {
    root_adapter().map(|adapter| &adapter.cpu)
}

/// Join main's existing physical CPU/IDT/APIC owner for external device IRQs.
/// No local timer register or engine vector is changed.
///
/// # Safety
/// Actual post-EBS main owns the installed 0x50..0x5f IDT stubs and exclusively
/// hands those routes to this registry. Physical delivery/remapping policy is
/// qualified; no firmware/SMM/other CPU owns these routes. The actual root and
/// descriptor allocations remain retained through this permanent registration.
/// Active external routes must be stopped before leaving their qualified root
/// execution scope; the CPU view refuses unsupported root/context changes.
pub(crate) unsafe fn adopt(
    execution: &crate::native_clock::DriverExecution<'_>,
) -> Result<(), IrqError> {
    let adapter = execution.irq_adapter().map_err(|_| IrqError::Unavailable)?;
    if READY.load(Ordering::Acquire) {
        return match root_cpu() {
            Some(cpu)
                if Arc::ptr_eq(cpu, &adapter.cpu)
                    && BASE.load(Ordering::Relaxed) == adapter.base
                    && REGISTERS.load(Ordering::Relaxed) == adapter.registers =>
            {
                NativePlatform(()).check_cpu()
            }
            _ => Err(IrqError::Unavailable),
        };
    }
    let adapter = Box::new(adapter);
    let saved = adapter.cpu.save_disable().map_err(|_| IrqError::WrongCpu)?;
    // SAFETY: typed actual main-owned APIC mapping, installed IDT/CPU grant
    // and explicit external-route handoff required above. Deadline units for
    // this adopted path are actual fixed PM-clock monotonic nanoseconds.
    let result = unsafe { initialize(adapter.base, adapter.registers, 2_000_000_000) };
    if result.is_ok() {
        ROOT_ADAPTER.store(Box::into_raw(adapter), Ordering::Release);
        // SAFETY: the original same-CPU view is now permanently retained.
        unsafe { root_cpu().unwrap().restore(saved) };
    } else {
        // SAFETY: exact enclosing CPU save, no switch or publication occurred.
        unsafe { adapter.cpu.restore(saved) };
    }
    result
}

pub struct NativePlatform(());
pub static CONTROLLER: Registry<NativePlatform> = Registry::new(NativePlatform(()));

pub fn service() -> Result<&'static dyn IrqController, IrqError> {
    NativePlatform(()).check_cpu()?;
    Ok(&CONTROLLER)
}

/// Attach the registry to the installed boot processor's local APIC, which
/// `registers` maps in every root, with a two-second drain bound.
///
/// # Safety
/// The boot processor after `host::install`, with interrupts off; its IDT
/// routes 0x50..=0x5f to [`dispatch`] and nothing else owns those vectors.
pub(crate) unsafe fn start(registers: u64, tsc_hz: u64) -> Result<(), IrqError> {
    let timeout = tsc_hz.checked_mul(2).ok_or(IrqError::Unsupported)?;
    // SAFETY: forwarded from the caller; `registers` maps the APIC base MSR's
    // page in every root.
    unsafe { initialize(apic::base_msr(), registers, timeout) }
}

/// Whether this processor is running a device interrupt's handler.
pub(crate) fn in_device_dispatch() -> bool {
    matches!(current_context(), Ok(Some(_)))
}

fn controller() -> Apic {
    Apic::new(
        BASE.load(Ordering::Relaxed),
        REGISTERS.load(Ordering::Relaxed),
    )
}
fn id(apic: &Apic) -> Result<u32, IrqError> {
    let raw = apic.read(0x20);
    if raw == u32::MAX {
        return Err(IrqError::FailedRead);
    }
    Ok(if apic.is_x2apic() { raw } else { raw >> 24 })
}

/// Attach the existing, already enabled APIC and installed device-vector IDT.
///
/// # Safety
/// One BSP only, with interrupts disabled, no migration/SMM/other owner of the
/// reserved vectors or APIC, and the existing IDT's 0x50..0x5f stubs installed.
/// The actual xAPIC UC mapping is root-stable for the permanent registry lifetime
/// (including quarantine); x2APIC mode uses the existing APIC MSR adapter.
/// Interrupt remapping is off and physical MSI is qualified by the platform.
pub unsafe fn initialize(base: u64, registers: u64, timeout_ticks: u64) -> Result<(), IrqError> {
    if READY.load(Ordering::Acquire) {
        return Err(IrqError::Unavailable);
    }
    if base & (1 << 11) == 0
        || base != apic::base_msr()
        || timeout_ticks == 0
        || timeout_ticks > u64::MAX / 2
    {
        return Err(IrqError::Unsupported);
    }
    let apic = Apic::new(base, registers);
    let bsp = id(&apic)?;
    let priority = apic.read(0x80);
    if priority == u32::MAX {
        return Err(IrqError::FailedRead);
    }
    if priority & 255 != 0 {
        return Err(IrqError::Unsupported);
    }
    // 0xff is the legacy physical broadcast destination, not a unicast CPU.
    if bsp >= 255 {
        return Err(IrqError::Unsupported);
    }
    BASE.store(base, Ordering::Relaxed);
    REGISTERS.store(registers, Ordering::Relaxed);
    BSP.store(bsp, Ordering::Relaxed);
    TIMEOUT.store(timeout_ticks, Ordering::Relaxed);
    READY.store(true, Ordering::Release);
    Ok(())
}

pub fn dispatch(vector: u8) -> bool {
    // Existing CPU entry calls this with local IRQs off. It does not supply
    // an interrupted-SP witness, so no such frame proof may be claimed.
    unsafe { dispatch_entry(vector, None) }
}

/// Actual device-vector dispatch with the unchanged IDT's hardware frame.
/// # Safety
/// Called only by the genuine existing CPU interrupt handler with IRQs off;
/// `interrupted_rsp` is Frame.rsp from that entry, not the ISR's current RSP.
#[cfg(feature = "diagnostics")]
pub(crate) unsafe fn dispatch_frame(vector: u8, interrupted_rsp: usize) -> bool {
    unsafe { dispatch_entry(vector, Some(interrupted_rsp)) }
}
unsafe fn dispatch_entry(vector: u8, interrupted_rsp: Option<usize>) -> bool {
    use stela_drivers::bus::irq::{FIRST_VECTOR, VECTOR_COUNT};
    if !READY.load(Ordering::Acquire)
        || vector < FIRST_VECTOR
        || usize::from(vector - FIRST_VECTOR) >= VECTOR_COUNT
    {
        return false;
    }
    let cpu = NativePlatform(()).check_cpu();
    if cpu.is_err() {
        return false;
    }
    // SAFETY: the actual existing ISR entry and owning BSP were checked above;
    // IRQs stay disabled through this balanced callback/EOI scope.
    let _context = unsafe { CONTEXT.enter(cpu, interrupted_rsp) }
        .unwrap_or_else(|_| crate::output::fatal("native IRQ context depth exhausted"));
    CONTROLLER.dispatch(vector)
}
pub(crate) fn current_context() -> Result<Option<context::Snapshot>, IrqError> {
    CONTEXT.current(NativePlatform(()).check_cpu())
}

// SAFETY: initialization qualifies the actual existing APIC/IDT on one BSP,
// preserves its mapping forever, refuses migration and uses real IRQ-save,
// APIC pending/EOI and physical MSI operations. No CPU/IDT is allocated here.
unsafe impl Platform for NativePlatform {
    fn check_cpu(&self) -> Result<(), IrqError> {
        if !READY.load(Ordering::Acquire) {
            return Err(IrqError::Unavailable);
        }
        if let Some(adapter) = root_adapter() {
            adapter.check_irq_cpu().map_err(|_| IrqError::WrongCpu)?;
        }
        if id(&controller())? != BSP.load(Ordering::Relaxed) {
            return Err(IrqError::WrongCpu);
        }
        Ok(())
    }
    fn save_and_disable(&self) -> u64 {
        let saved;
        // SAFETY: native privileged CPU; memory clobber orders the critical
        // region, and exact IF state is restored on this same BSP.
        unsafe {
            asm!("pushfq", "pop {}", "cli", out(reg) saved);
        }
        saved
    }
    unsafe fn restore(&self, saved: u64) {
        if saved & (1 << 9) != 0 {
            // SAFETY: immediately enclosing saved state from the same BSP.
            unsafe {
                asm!("sti", options(nostack));
            }
        }
    }
    fn target(&self, vector: u8) -> Result<Target, IrqError> {
        self.check_cpu()?;
        // Physical destination, fixed delivery, edge trigger, one vector.
        Ok(Target {
            destination: BSP.load(Ordering::Relaxed) as u8,
            vector,
        })
    }
    fn pending(&self, vector: u8) -> Result<bool, IrqError> {
        self.check_cpu()?;
        let apic = controller();
        let offset = u32::from(vector / 32) * 16;
        let irr = apic.read(0x200 + offset);
        let isr = apic.read(0x100 + offset);
        if irr == u32::MAX || isr == u32::MAX {
            return Err(IrqError::FailedRead);
        }
        Ok((irr | isr) & (1u32 << (vector % 32)) != 0)
    }
    fn eoi(&self) {
        controller().eoi();
    }
    fn ticks(&self) -> u64 {
        root_cpu().map_or_else(apic::rdtsc, |cpu| cpu.ticks())
    }
    fn timeout_ticks(&self) -> u64 {
        TIMEOUT.load(Ordering::Relaxed)
    }
    unsafe fn interrupt_window(&self) {
        // SAFETY: caller holds no resource/registry lock. The NOP consumes
        // STI's interrupt shadow; pending IRQs run before the following CLI.
        unsafe {
            asm!("sti", "nop", "cli", options(nostack));
        }
    }
}
