//! Actual EDU MSI lifecycle under the source-bound QEMU TCG fixture grant.
use alloc::{format, string::String, sync::Arc};
use core::{
    arch::asm,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use stela_drivers::{
    Clock,
    bus::{
        irq::{Disposition, Handler, IrqError, Route, RouteRequest, Source},
        pci::{ConfigSpace, Function, Msi},
    },
};

pub(super) struct Edu {
    base: usize,
    received: AtomicU64,
    observed: AtomicU32,
    bad_ack: AtomicU32,
}
impl Edu {
    pub(super) fn read(&self, offset: usize) -> u32 {
        // SAFETY: actual retained root-stable UC EDU BAR, checked by the
        // enclosing exclusive QEMU-only fixture before ownership transfer.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }
    pub(super) fn write(&self, offset: usize, value: u32) {
        // SAFETY: as for read; exact 32-bit EDU register below 0x80.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) };
    }
    pub(super) fn interrupt_trigger(&self) -> *mut u32 {
        (self.base + 0x60) as *mut u32
    }
    pub(super) fn received(&self) -> u64 {
        self.received.load(Ordering::Acquire)
    }
    pub(super) fn observed(&self) -> u32 {
        self.observed.load(Ordering::Relaxed)
    }
    pub(super) fn bad_ack(&self) -> u32 {
        self.bad_ack.load(Ordering::Relaxed)
    }
    fn dma_idle(&self) -> bool {
        // SAFETY: actual owned EDU DMA_COMMAND supports a 64-bit read.
        unsafe { ((self.base + 0x98) as *const u64).read_volatile() & 1 == 0 }
    }
}
impl Handler for Edu {
    fn handle(&self) -> Disposition {
        let cause = self.read(0x24);
        self.observed.fetch_or(cause, Ordering::Relaxed);
        self.write(0x64, cause);
        if self.read(0x24) != 0 {
            self.bad_ack.fetch_add(1, Ordering::Relaxed);
        }
        // Release publishes actual cause/ACK observation to the waiting owner.
        self.received.fetch_add(1, Ordering::Release);
        if cause == 0 {
            Disposition::NotMine
        } else {
            Disposition::Handled
        }
    }
}

pub(super) struct EduSource {
    function: Function,
    msi: Msi,
    edu: Arc<Edu>,
}
impl EduSource {
    fn control(&mut self) -> u16 {
        self.function
            .config()
            .read16(u16::from(self.msi.offset) + 2)
    }
}
// SAFETY: only the exact QEMU EDU fixture creates this source, after DMA has
// completed, BusMaster is off and VT-d shutdown acknowledged. It has no queued
// worker/timer; RUN-clear/idle, cause ACK and synchronous TCG device callbacks
// qualify stopped DMA/posted interrupts. This is not physical PCI quiescence.
unsafe impl Source for EduSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        let offset = u16::from(self.msi.offset);
        let control = self.control();
        if control == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        self.function.config().write16(offset + 2, control & !1);
        let command = self.function.config().read16(4);
        if command == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        self.function.config().write16(4, command | 1 << 10);
        let actual_command = self.function.config().read16(4);
        let control = self.control();
        if control == u16::MAX || actual_command == u16::MAX {
            Err(IrqError::FailedRead)
        } else if control & 1 != 0 || actual_command & (1 << 10) == 0 {
            Err(IrqError::Mask)
        } else {
            Ok(())
        }
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        if !self.edu.dma_idle() || self.edu.read(0x20) & 1 != 0 {
            return Err(IrqError::Quiesce);
        }
        let command = self.function.config().read16(4);
        if command == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        self.function.config().write16(4, command & !4);
        let actual = self.function.config().read16(4);
        if actual == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if actual & 4 != 0 {
            return Err(IrqError::Quiesce);
        }
        self.edu.write(0x20, 0);
        self.edu.write(0x64, u32::MAX);
        if self.edu.read(0x24) != 0 {
            return Err(IrqError::Quiesce);
        }
        Ok(())
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        self.quiesce()
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        let Route::Msi(message) = route else {
            return Err(IrqError::Route);
        };
        if self.control() & 1 != 0
            || message.address > u64::from(u32::MAX)
            || message.data > u32::from(u16::MAX)
        {
            return Err(IrqError::Route);
        }
        let offset = u16::from(self.msi.offset);
        let control = self.control() & !(7 << 4);
        let config = self.function.config();
        config.write16(offset + 2, control);
        config.write32(offset + 4, message.address as u32);
        let data_offset = if self.msi.wide {
            config.write32(offset + 8, 0);
            offset + 12
        } else {
            offset + 8
        };
        config.write16(data_offset, message.data as u16);
        if config.read32(offset + 4) != message.address as u32
            || config.read16(data_offset) != message.data as u16
            || (self.msi.wide && config.read32(offset + 8) != 0)
        {
            return Err(IrqError::Route);
        }
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        let control = self.control();
        if control == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        self.function
            .config()
            .write16(u16::from(self.msi.offset) + 2, control | 1);
        let actual = self.control();
        if actual == u16::MAX {
            Err(IrqError::FailedRead)
        } else if actual & 1 == 0 {
            Err(IrqError::Mask)
        } else {
            // An MSI is itself a bus-master memory write. The exact stopped
            // EDU fixture has no queued DMA/factorial work and issues no new
            // DMA command; enable only after the route/handler is published.
            let command = self.function.config().read16(4);
            if command == u16::MAX {
                return Err(IrqError::FailedRead);
            }
            self.function.config().write16(4, command | 4);
            let command = self.function.config().read16(4);
            if command == u16::MAX {
                return Err(IrqError::FailedRead);
            }
            if command & 4 == 0 {
                return Err(IrqError::Route);
            }
            Ok(())
        }
    }
}

/// Only called after the exact controlled fixture's VT-d teardown succeeded.
/// Its existing IDT/APIC page is installed/mapped; interrupts are off.
pub(super) struct Parts {
    pub source: EduSource,
    pub edu: Arc<Edu>,
}
pub(super) fn prepare_source(function: Function, base: u64, clock: Clock) -> Result<Parts, String> {
    let interrupts = function.interrupts();
    if interrupts.msix.is_some() {
        return Err(String::from("EDU fixture has unexpected MSI-X"));
    }
    let msi = interrupts
        .msi
        .ok_or_else(|| String::from("EDU has no actual MSI capability"))?;
    if !(0x40..=0xec).contains(&msi.offset) || !msi.offset.is_multiple_of(4) || msi.vectors != 1 {
        return Err(String::from("unsupported EDU MSI layout"));
    }
    let timeout = clock
        .ticks_per_microsecond
        .checked_mul(2_000_000)
        .ok_or_else(|| String::from("IRQ timeout overflow"))?;
    let apic_base = crate::apic::base_msr();
    let apic_registers = apic_base & crate::apic::BASE_ADDRESS;
    let apic = crate::apic::Apic::new(apic_base, apic_registers);
    apic.start(
        crate::engine::interrupts::SPURIOUS_VECTOR,
        crate::engine::interrupts::TIMER_VECTOR,
        clock.ticks_per_microsecond * 1_000_000,
    );
    // SAFETY: same strict TCG/SMM-off single-BSP fixture, actual installed
    // reserved-vector IDT and permanently retained identity UC APIC mapping.
    unsafe { super::initialize(apic_base, apic_registers, timeout) }
        .map_err(|error| format!("native IRQ attach: {error:?}"))?;
    let edu = Arc::new(Edu {
        base: base as usize,
        received: AtomicU64::new(0),
        observed: AtomicU32::new(0),
        bad_ack: AtomicU32::new(0),
    });
    let source = EduSource {
        function,
        msi,
        edu: edu.clone(),
    };
    Ok(Parts { source, edu })
}

pub(crate) fn run(
    function: Function,
    base: u64,
    clock: Clock,
) -> Result<(String, Function), String> {
    let Parts { source, edu } = prepare_source(function, base, clock)?;
    let mut registration = super::CONTROLLER
        .request_owned(source, edu.clone())
        .map_err(|error| format!("EDU MSI request: {error:?}"))?;
    let vector = registration.vector();
    // No heap/resource lock is held. The real IDT handler acknowledges the
    // EDU cause and the registry EOIs before its inflight reference ends.
    unsafe {
        asm!("sti", options(nostack));
    }
    edu.write(0x60, 1);
    let completed = clock.wait(2_000_000, || edu.received.load(Ordering::Acquire) != 0);
    unsafe {
        asm!("cli", options(nostack));
    }
    if !completed
        || edu.received.load(Ordering::Acquire) != 1
        || edu.observed.load(Ordering::Relaxed) != 1
        || edu.bad_ack.load(Ordering::Relaxed) != 0
        || registration.handled() != Ok(1)
    {
        return Err(format!(
            "actual EDU MSI failed completed={completed} count={} cause={:#x} bad_ack={}",
            edu.received.load(Ordering::Acquire),
            edu.observed.load(Ordering::Relaxed),
            edu.bad_ack.load(Ordering::Relaxed)
        ));
    }
    let retired = registration
        .retire()
        .map_err(|error| format!("EDU MSI retire: {error:?}"))?;
    if retired.route().vector() != vector {
        return Err(String::from("EDU MSI retired a different route"));
    }
    // Recover exactly the original uniquely owned Function after actual
    // source/IRR/ISR/callback/work drain. No second ECAM enumeration or cloned
    // configuration/root owner is introduced by the following INTx phase.
    // SAFETY: concrete source owns the stopped EDU/Function. Keep its original
    // callback owner until the source is consumed immediately below.
    let (source, handler, _route) = unsafe { retired.into_parts() };
    let EduSource {
        function,
        msi: _,
        edu: source_edu,
    } = *source;
    drop(source_edu);
    drop(handler);
    if Arc::strong_count(&edu) != 1 {
        return Err(String::from(
            "retired IRQ retained handler/source unexpectedly",
        ));
    }
    // Trigger a new device cause after acknowledged MSI disable/detach. The
    // retained observer must see no callback before the cause is cleared.
    edu.write(0x60, 2);
    unsafe {
        asm!("sti", options(nostack));
    }
    let late = clock.wait(1_000, || edu.received.load(Ordering::Acquire) != 1);
    unsafe {
        asm!("cli", options(nostack));
    }
    edu.write(0x64, u32::MAX);
    if late || edu.read(0x24) != 0 {
        return Err(String::from("EDU MSI callback survived retire"));
    }
    Ok((
        format!(
            "EDU vector={vector:#x} actual_cause=0x1 device_ACK+EOI=verified mask+quiesce+IRR/ISR+inflight=drained handler_refs=released late_delivery=absent owner_return=original_function"
        ),
        function,
    ))
}
