//! BSP physical MSI routes through the existing native IDT and local APIC.
//! This supplies no IOAPIC/INTx/MSI-X or interrupt-remapping implementation.
use crate::apic::{self, Apic};
use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use stela_drivers::bus::irq::{IrqController, IrqError, MsiMessage, Platform, Registry};

pub(crate) mod diagnostic;

static READY: AtomicBool = AtomicBool::new(false);
static BASE: AtomicU64 = AtomicU64::new(0);
static REGISTERS: AtomicU64 = AtomicU64::new(0);
static BSP: AtomicU32 = AtomicU32::new(0);
static TIMEOUT: AtomicU64 = AtomicU64::new(0);

pub struct NativePlatform(());
pub static CONTROLLER: Registry<NativePlatform> = Registry::new(NativePlatform(()));

pub fn service() -> Result<&'static dyn IrqController, IrqError> {
    NativePlatform(()).check_cpu()?;
    Ok(&CONTROLLER)
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
    if !READY.load(Ordering::Acquire) {
        return false;
    }
    CONTROLLER.dispatch(vector)
}

// SAFETY: initialization qualifies the actual existing APIC/IDT on one BSP,
// preserves its mapping forever, refuses migration and uses real IRQ-save,
// APIC pending/EOI and physical MSI operations. No CPU/IDT is allocated here.
unsafe impl Platform for NativePlatform {
    fn check_cpu(&self) -> Result<(), IrqError> {
        if !READY.load(Ordering::Acquire) {
            return Err(IrqError::Unavailable);
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
    fn message(&self, vector: u8) -> Result<MsiMessage, IrqError> {
        self.check_cpu()?;
        // Physical destination, fixed delivery, edge trigger, one vector.
        Ok(MsiMessage {
            address: 0xfee00000 | u64::from(BSP.load(Ordering::Relaxed)) << 12,
            data: u32::from(vector),
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
        apic::rdtsc()
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
