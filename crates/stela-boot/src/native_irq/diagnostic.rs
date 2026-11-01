//! EDU MSI lifecycle under the source-bound QEMU TCG fixture grant.
use crate::Result;
use alloc::{boxed::Box, format, string::String, sync::Arc};
use core::{
    arch::asm,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use stela_contracts::refuse;
use stela_drivers::{
    Clock,
    bus::{
        irq::{
            CpuTarget, Disposition, Handler, IrqError, MsiMessage, Platform, Request, Route,
            RouteRequest, Source,
            posted_msi::{self, AllocationError, EndpointRetirement, MsiRoute, RouteOwner},
        },
        pci::{ConfigSpace, Function as PciFunction, Msi, owned::OwnedConfig},
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
        // SAFETY: root-stable UC EDU BAR, checked by the
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
        // SAFETY: owned EDU DMA_COMMAND supports a 64-bit read.
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
        // Release publishes cause/ACK observation to the waiting owner.
        self.received.fetch_add(1, Ordering::Release);
        if cause == 0 {
            Disposition::NotMine
        } else {
            Disposition::Handled
        }
    }
}

/// Only this existing boot-diagnostics module can issue the bounded TCG
/// contract. It has no RequesterId, config pin, or native detach/reset proof.
struct TcgDomain {
    edu: Arc<Edu>,
}
// SAFETY: issued only inside the existing exact single-BSP synchronous TCG
// fixture. Actual CPU and original retained EDU identity are checked on IRQ.
unsafe impl posted_msi::NotificationDomain for TcgDomain {
    fn check(&self) -> core::result::Result<(), posted_msi::Error> {
        super::NativePlatform(())
            .check_cpu()
            .map_err(|_| posted_msi::Error::Context)?;
        if self.edu.read(0) != 0x0100_00ed {
            return Err(posted_msi::Error::RootFailed);
        }
        Ok(())
    }
}
struct TcgDelivery {
    edu: Arc<Edu>,
    message: Option<MsiMessage>,
}
impl TcgDelivery {
    fn check(&self) -> core::result::Result<(), posted_msi::Error> {
        super::NativePlatform(())
            .check_process()
            .map_err(|_| posted_msi::Error::Context)?;
        // Read actual exact retained EDU registers, never infer delivery from
        // an unrelated source's idle or a generic all-success provider.
        if self.edu.read(0) != 0x0100_00ed {
            return Err(posted_msi::Error::RootFailed);
        }
        Ok(())
    }
}
// SAFETY: private diagnostics issuer is reached only after the original exact
// single-BSP synchronous TCG EDU fixture contract and VT-d shutdown. The owned
// EDU peer checks its actual stopped state; this is model evidence only.
unsafe impl RouteOwner for TcgDelivery {
    fn allocate(
        &mut self,
        target: &CpuTarget<'_>,
    ) -> core::result::Result<MsiMessage, AllocationError> {
        self.check().map_err(AllocationError::Unexposed)?;
        if !target.belongs_to(super::CONTROLLER.identity()) {
            return Err(AllocationError::Unexposed(posted_msi::Error::Context));
        }
        target
            .check_current()
            .map_err(|_| AllocationError::Unexposed(posted_msi::Error::Context))?;
        let data = target.descriptor();
        let message = MsiMessage {
            address: 0xfee0_0000 | u64::from(data.destination) << 12,
            data: u32::from(data.vector),
        };
        if self.message.is_some() {
            return Err(AllocationError::Unexposed(posted_msi::Error::AlreadyBound));
        }
        self.message = Some(message);
        Ok(message)
    }
    fn validate(&self) -> core::result::Result<(), posted_msi::Error> {
        self.check()
    }
    fn notification_domain(
        &self,
    ) -> core::result::Result<Arc<dyn posted_msi::NotificationDomain>, posted_msi::Error> {
        self.check()?;
        Ok(Arc::new(TcgDomain {
            edu: self.edu.clone(),
        }))
    }
    unsafe fn strong_fence(&mut self) -> core::result::Result<(), posted_msi::Error> {
        self.check()?;
        if self.message.is_none()
            || !self.edu.dma_idle()
            || self.edu.read(0x20) & 1 != 0
            || self.edu.read(0x24) != 0
        {
            return Err(posted_msi::Error::RootFailed);
        }
        // Under this exact synchronous TCG device contract, stopped RUN/DMA
        // and acknowledged causes exclude another queued EDU callback.
        Ok(())
    }
    unsafe fn release_endpoint(
        &mut self,
        proof: &EndpointRetirement<'_>,
    ) -> core::result::Result<(), posted_msi::Error> {
        self.check()?;
        if proof.requester().is_some() {
            return Err(posted_msi::Error::NotRetired);
        }
        Ok(())
    }
}
pub(super) fn tcg_route(edu: Arc<Edu>) -> RouteRequest {
    // SAFETY: module-private issuer of this exact diagnostics contract, never
    // an attachment grant or a native platform service.
    RouteRequest::Msi(unsafe {
        MsiRoute::bounded_fixture(Box::new(TcgDelivery { edu, message: None }))
    })
}

pub(super) struct EduSource {
    pub(super) function: Function,
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
// check stopped DMA/posted interrupts. This is not physical PCI quiescence.
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
    fn route_kind(&self) -> stela_drivers::bus::irq::RouteKind {
        stela_drivers::bus::irq::RouteKind::Msi
    }
    fn requester(&self) -> Option<&stela_drivers::bus::pci::requester::RequesterId> {
        None
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        self.quiesce()
    }
    unsafe fn program(
        &mut self,
        route: &stela_drivers::bus::irq::AllocatedRoute<'_>,
    ) -> Result<(), IrqError> {
        let Route::Msi(message) = route.programming() else {
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
pub(super) fn prepare_source(function: Function, base: u64, clock: Clock) -> Result<Parts> {
    let interrupts = function.interrupts();
    if interrupts.msix.is_some() {
        return Err(refuse!("EDU fixture has unexpected MSI-X"));
    }
    let msi = interrupts
        .msi
        .ok_or_else(|| refuse!("EDU has no actual MSI capability"))?;
    if !(0x40..=0xec).contains(&msi.offset) || !msi.offset.is_multiple_of(4) || msi.vectors != 1 {
        return Err(refuse!("unsupported EDU MSI layout"));
    }
    let timeout = clock
        .ticks_per_microsecond
        .checked_mul(2_000_000)
        .ok_or_else(|| refuse!("IRQ timeout overflow"))?;
    let apic_base = crate::apic::base_msr();
    let apic_registers = apic_base & crate::apic::BASE_ADDRESS;
    let apic = crate::apic::Apic::new(apic_base, apic_registers);
    apic.start(
        crate::engine::interrupts::SPURIOUS_VECTOR,
        crate::engine::interrupts::TIMER_VECTOR,
        clock.ticks_per_microsecond * 1_000_000,
    );
    // SAFETY: same strict TCG/SMM-off single-BSP fixture, installed
    // reserved-vector IDT and permanently kept identity UC APIC mapping.
    unsafe { super::initialize(apic_base, apic_registers, timeout) }
        .map_err(|error| refuse!("native IRQ attach: {error}", ?error))?;
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

pub(crate) fn run(function: Function, base: u64, clock: Clock) -> Result<(String, Function)> {
    let Parts { source, edu } = prepare_source(function, base, clock)?;
    let mut registration = super::CONTROLLER
        .request_owned(Request {
            source,
            handler: edu.clone(),
            routing: tcg_route(edu.clone()),
        })
        .map_err(|error| refuse!("EDU MSI request: {error}", ?error))?;
    let vector = registration.vector();
    // No heap/resource lock is held. The real IDT handler acknowledges the
    // EDU cause and the registry EOIs before its inflight reference ends.
    // SAFETY: no heap or resource lock is held, the IDT handler is installed and interrupts are
    // masked again right after the wait.
    unsafe {
        asm!("sti", options(nostack));
    }
    edu.write(0x60, 1);
    let completed = clock.wait(2_000_000, || edu.received.load(Ordering::Acquire) != 0);
    // SAFETY: masks interrupts on this CPU.
    unsafe {
        asm!("cli", options(nostack));
    }
    if !completed
        || edu.received.load(Ordering::Acquire) != 1
        || edu.observed.load(Ordering::Relaxed) != 1
        || edu.bad_ack.load(Ordering::Relaxed) != 0
        || registration.handled() != Ok(1)
    {
        return Err(refuse!(
            "actual EDU MSI failed completed={completed} count={count} cause={cause:#x} bad_ack={bad_ack}",
            completed,
            count = edu.received.load(Ordering::Acquire),
            cause = edu.observed.load(Ordering::Relaxed),
            bad_ack = edu.bad_ack.load(Ordering::Relaxed)
        ));
    }
    let retired = registration
        .retire()
        .map_err(|error| refuse!("EDU MSI retire: {error}", ?error))?;
    if retired.route().vector() != vector {
        return Err(refuse!("EDU MSI retired a different route"));
    }
    // Recover exactly the original uniquely owned Function after
    // source/IRR/ISR/callback/work drain. No second ECAM enumeration or cloned
    // configuration/root owner is introduced by the following INTx phase.
    // SAFETY: concrete source owns the stopped EDU/Function. Keep its original
    // callback owner until the source is consumed immediately below.
    let (source, handler, mut route) = unsafe { retired.into_parts() }.map_err(|failure| {
        let error = failure.error;
        refuse!("EDU retirement context changed: {error}", ?error)
    })?;
    route
        .release_unattached_fixture()
        .map_err(|e| refuse!("EDU bounded route release: {e}", ?e))?;
    drop(route);
    let EduSource {
        function,
        msi: _,
        edu: source_edu,
    } = *source;
    drop(source_edu);
    drop(handler);
    if Arc::strong_count(&edu) != 1 {
        return Err(refuse!("retired IRQ retained handler/source unexpectedly"));
    }
    // Trigger a new device cause after acknowledged MSI disable/detach. The
    // observer must see no callback before the cause is cleared.
    edu.write(0x60, 2);
    // SAFETY: no heap or resource lock is held, the IDT handler is installed and interrupts are
    // masked again right after the wait.
    unsafe {
        asm!("sti", options(nostack));
    }
    let late = clock.wait(1_000, || edu.received.load(Ordering::Acquire) != 1);
    // SAFETY: masks interrupts on this CPU.
    unsafe {
        asm!("cli", options(nostack));
    }
    edu.write(0x64, u32::MAX);
    if late || edu.read(0x24) != 0 {
        return Err(refuse!("EDU MSI callback survived retire"));
    }
    Ok((
        format!(
            "EDU vector={vector:#x} actual_cause=0x1 device_ACK+EOI=verified mask+quiesce+IRR/ISR+inflight=drained handler_refs=released late_delivery=absent owner_return=original_function"
        ),
        function,
    ))
}

// Native configuration owner, never a CPU-bound raw transport.
type Function = PciFunction<OwnedConfig>;
