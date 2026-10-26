// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! Native PCI/UC-MMIO/MSI-X/IRQ attachment for the Intel Bluetooth transport.
//! The real source stops before IRQ retirement. A hard-IRQ callback only masks
//! this source and requests serialized service; it never fabricates completion.
use super::{Identity, Platform, Result as DriverResult, registers::*};
use crate::{
    Clock,
    bus::{
        irq::{
            self, Disposition, Handler, IrqController, IrqRegistration, Route, RouteRequest, Source,
        },
        mmio::owned::{self, CacheAttribute, Mapping, PhysicalSpan, Protection},
        pci::{
            Function,
            msi::{MsiConfigSpace, RetainedOwner},
            msix::{self, BarAccess, MsixConfig},
        },
    },
};
use alloc::{boxed::Box, rc::Rc, sync::Arc};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

const REGISTER_BYTES: usize = IVAR + 0x26;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Requirement(&'static str),
    Mapping(owned::Error),
    Msix(msix::Error),
    Irq(irq::IrqError),
    Readback { offset: usize, observed: u32 },
    Handler { offset: usize },
}
impl From<Error> for super::Error {
    fn from(error: Error) -> Self {
        Self::Native(error)
    }
}

/// Actual exclusive BAR0 registers, or an explicit independent device model.
/// # Safety
/// The full span names this same Function/reset epoch's actual reserved BAR0.
/// All accesses are bounded native UC byte/DWORD effects, hard-IRQ-safe with no
/// allocation, blocking, final-owner release or wider W1C read/modify/write.
/// The retained owner keeps its mapping and resource valid through callback
/// drain. Dropping uncertain storage must quarantine it, never unmap/reuse it.
pub unsafe trait Registers: Send + Sync + 'static {
    fn full_bar(&self) -> PhysicalSpan;
    fn read32(&self, offset: usize) -> core::result::Result<u32, Error>;
    fn write32(&self, offset: usize, value: u32) -> core::result::Result<(), Error>;
    fn write8(&self, offset: usize, value: u8) -> core::result::Result<(), Error>;
}
pub struct MappedRegisters {
    full_bar: PhysicalSpan,
    mapping: Mapping,
}
impl MappedRegisters {
    /// # Safety
    /// The full BAR reservation and mapping belong to the same actual Function
    /// and authorized shared-reset epoch. No competing firmware/driver remains.
    /// Mapping Drop preserves the boot-lifetime reservation; no unmap is implied.
    pub unsafe fn new(
        full_bar: PhysicalSpan,
        mapping: Mapping,
    ) -> core::result::Result<Self, (Error, Mapping)> {
        let valid = (|| {
            let span = mapping.physical_span().map_err(Error::Mapping)?;
            if mapping.attribute().map_err(Error::Mapping)? != CacheAttribute::Uncached
                || mapping.protection().map_err(Error::Mapping)? != Protection::ReadWrite
                || span.start() != full_bar.start()
                || span.end() > full_bar.end()
                || span.bytes() < REGISTER_BYTES as u64
            {
                return Err(Error::Requirement(
                    "actual UC read/write BAR0 register window",
                ));
            }
            Ok(())
        })();
        match valid {
            Ok(()) => Ok(Self { full_bar, mapping }),
            Err(error) => Err((error, mapping)),
        }
    }
}
// SAFETY: unsafe construction binds the actual exclusive UC mapping. Every
// address is checked against that retained live mapping; stores use exact widths.
unsafe impl Registers for MappedRegisters {
    fn full_bar(&self) -> PhysicalSpan {
        self.full_bar
    }
    fn read32(&self, offset: usize) -> core::result::Result<u32, Error> {
        let p = self.mapping.address(offset, 4).map_err(Error::Mapping)?;
        if !(p.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::Requirement("aligned native register DWORD"));
        }
        // SAFETY: checked live retained aligned UC register address.
        Ok(unsafe { p.as_ptr().cast::<u32>().read_volatile() })
    }
    fn write32(&self, offset: usize, value: u32) -> core::result::Result<(), Error> {
        let p = self.mapping.address(offset, 4).map_err(Error::Mapping)?;
        if !(p.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::Requirement("aligned native register DWORD"));
        }
        // SAFETY: same checked UC owner; exact native DWORD effect, no RMW.
        unsafe { p.as_ptr().cast::<u32>().write_volatile(value) };
        Ok(())
    }
    fn write8(&self, offset: usize, value: u8) -> core::result::Result<(), Error> {
        let p = self.mapping.address(offset, 1).map_err(Error::Mapping)?;
        // SAFETY: checked live UC byte, required for each source IVAR entry.
        unsafe { p.as_ptr().write_volatile(value) };
        Ok(())
    }
}

pub struct Inputs<C: MsiConfigSpace, B: BarAccess, R: Registers> {
    pub function: Function<C>,
    pub retained: RetainedOwner,
    pub bars: [Option<B>; 6],
    pub registers: R,
    pub clock: Clock,
    pub interrupts: &'static dyn IrqController,
}
struct Signals<R: Registers> {
    registers: R,
    pending: AtomicBool,
    handler_fault: AtomicBool,
    fault_offset: AtomicUsize,
    fh_mask: AtomicU32,
    hw_mask: AtomicU32,
    disconnect_ack: AtomicBool,
    reset_issued: AtomicBool,
}
impl<R: Registers> Signals<R> {
    fn stopped(&self) -> core::result::Result<(), Error> {
        let function = self.registers.read32(FUNC)?;
        if function == u32::MAX
            || !self.disconnect_ack.load(Ordering::Acquire)
            || !self.reset_issued.load(Ordering::Acquire)
            || function & (ENABLE | MAC_INIT | FUNC_INIT) != 0
            || self.registers.read32(BOOT)? != 0
        {
            return Err(Error::Requirement(
                "actual DMA disconnect and reset BOOT0 before IRQ retirement",
            ));
        }
        for offset in [FH_CAUSE, HW_CAUSE] {
            if self.registers.read32(offset)? != 0 {
                return Err(Error::Requirement("reset interrupt causes drained"));
            }
        }
        Ok(())
    }
    fn check_handler(&self) -> core::result::Result<(), Error> {
        if self.handler_fault.load(Ordering::Acquire) {
            return Err(Error::Handler {
                offset: self.fault_offset.load(Ordering::Relaxed),
            });
        }
        Ok(())
    }
    fn mask(&self) -> core::result::Result<(), (usize, Error)> {
        for offset in [FH_MASK, HW_MASK] {
            self.registers
                .write32(offset, u32::MAX)
                .map_err(|error| (offset, error))?;
            let observed = self
                .registers
                .read32(offset)
                .map_err(|error| (offset, error))?;
            if observed != u32::MAX {
                return Err((offset, Error::Readback { offset, observed }));
            }
        }
        Ok(())
    }
}
struct Callback<R: Registers>(Arc<Signals<R>>);
impl<R: Registers> Handler for Callback<R> {
    fn handle(&self) -> Disposition {
        // No allocation, waits, W1C or DMA completion handling in hard IRQ.
        // Actual mask/readback contains the source until serialized service.
        if let Err((offset, _)) = self.0.mask()
            && !self.0.handler_fault.load(Ordering::Acquire)
        {
            self.0.fault_offset.store(offset, Ordering::Relaxed);
            self.0.handler_fault.store(true, Ordering::Release);
        }
        self.0.pending.store(true, Ordering::Release);
        Disposition::Handled
    }
}
struct Configuration<C: MsiConfigSpace, B: BarAccess> {
    msix: MsixConfig<C, B>,
    fault: Option<Error>,
    released: Option<msix::Owners<C, B>>,
}
struct NativeSource<C: MsiConfigSpace, B: BarAccess, R: Registers> {
    configuration: Rc<RefCell<Configuration<C, B>>>,
    signals: Arc<Signals<R>>,
}
impl<C: MsiConfigSpace, B: BarAccess, R: Registers> NativeSource<C, B, R> {
    fn checked(
        &mut self,
        result: core::result::Result<(), Error>,
        kind: irq::IrqError,
    ) -> core::result::Result<(), irq::IrqError> {
        if let Err(error) = result {
            self.configuration.borrow_mut().fault.get_or_insert(error);
            return Err(kind);
        }
        Ok(())
    }
}
// SAFETY: the consumed native grant binds actual PCI/reset/UC/DMA ownership.
// Source quiescence independently observes stop/reset/cause acknowledgments;
// registry retirement drains actual CPU/callbacks before pending work is canceled.
unsafe impl<C: MsiConfigSpace, B: BarAccess, R: Registers> Source for NativeSource<C, B, R> {
    fn mask(&mut self) -> core::result::Result<(), irq::IrqError> {
        let result = self
            .configuration
            .borrow_mut()
            .msix
            .mask()
            .map_err(Error::Msix);
        self.checked(result, irq::IrqError::Mask)
    }
    fn quiesce(&mut self) -> core::result::Result<(), irq::IrqError> {
        self.checked(self.signals.stopped(), irq::IrqError::Quiesce)
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> core::result::Result<(), irq::IrqError> {
        let Route::Msi(message) = route else {
            return Err(irq::IrqError::Route);
        };
        // SAFETY: the actual registry retains its qualified route and callback;
        // mask and independently observed source stop precede programming.
        let result =
            unsafe { self.configuration.borrow_mut().msix.program(message) }.map_err(Error::Msix);
        self.checked(result, irq::IrqError::Route)
    }
    unsafe fn unmask(&mut self) -> core::result::Result<(), irq::IrqError> {
        // SAFETY: registry has published this source's LIVE retained callback.
        let result = unsafe { self.configuration.borrow_mut().msix.unmask() }.map_err(Error::Msix);
        self.checked(result, irq::IrqError::Mask)
    }
    unsafe fn synchronize(&mut self) -> core::result::Result<(), irq::IrqError> {
        self.checked(self.signals.stopped(), irq::IrqError::Drain)?;
        // There is exactly one deferred work item: this retained flag. The
        // exclusive process owner cannot run service during its own retirement.
        self.signals.pending.store(false, Ordering::Release);
        Ok(())
    }
}

pub struct NativePlatform<C: MsiConfigSpace, B: BarAccess, R: Registers> {
    identity: Identity,
    configuration: Option<Rc<RefCell<Configuration<C, B>>>>,
    signals: Option<Arc<Signals<R>>>,
    interrupts: &'static dyn IrqController,
    clock: Clock,
    clock_origin: u64,
    registration: Option<Box<dyn IrqRegistration>>,
    attempted: bool,
    retired: bool,
}
impl<C: MsiConfigSpace + 'static, B: BarAccess + 'static, R: Registers> NativePlatform<C, B, R> {
    /// # Safety
    /// Inputs own the actual unique Function/root, BIR-indexed complete BAR
    /// resources, BAR0 UC mapping and reset epoch; PCI D0, memory decoding and
    /// bus mastering are already acknowledged. All former firmware/driver/CPU
    /// interrupt and DMA owners are drained. Shared combo reset is authorized by
    /// its actual coordinator. Supplied DMA is coherent, identity-addressed and
    /// boot-lifetime reserved for this requester. IRQ routing is real/qualified.
    /// Only one serialized process/deferred owner may service this transport;
    /// the callback's retained pending flag is its entire work queue. No source,
    /// mapping, DMA or reset owner may be revoked while retained. Native mappings
    /// stay reserved for the boot even after successful controller close.
    /// Constructor errors perform no writes and return every exact input owner.
    pub unsafe fn new(
        mut inputs: Inputs<C, B, R>,
    ) -> core::result::Result<Self, (Error, Inputs<C, B, R>)> {
        let valid = (|| {
            inputs
                .clock
                .check_duration(120_000_000)
                .map_err(|_| Error::Requirement("qualified representable native TSC timing"))?;
            let clock_origin = inputs
                .clock
                .try_start()
                .map_err(|_| Error::Requirement("qualified native TSC origin"))?;
            let f = &mut inputs.function;
            if f.vendor != 0x8086
                || !super::DEVICE_IDS.contains(&f.device)
                || f.config().read32(0) != u32::from(f.vendor) | (u32::from(f.device) << 16)
            {
                return Err(Error::Requirement(
                    "actual source Intel PCIe Function identity",
                ));
            }
            if inputs.clock.ticks_per_microsecond == 0 || f.config().read16(4) & 6 != 6 {
                return Err(Error::Requirement(
                    "qualified clock and acknowledged PCI memory/bus mastering",
                ));
            }
            if inputs.bars[0]
                .as_ref()
                .is_none_or(|bar| bar.physical_span() != inputs.registers.full_bar())
            {
                return Err(Error::Requirement(
                    "same actual BAR0 register/MSI-X resource owner",
                ));
            }
            Ok((
                Identity {
                    address: f.address,
                    vendor: f.vendor,
                    device: f.device,
                    subsystem_vendor: f.config().read16(0x2c),
                    subsystem_device: f.config().read16(0x2e),
                },
                clock_origin,
            ))
        })();
        let (identity, clock_origin) = match valid {
            Ok(identity) => identity,
            Err(error) => return Err((error, inputs)),
        };
        let Inputs {
            function,
            retained,
            bars,
            registers,
            clock,
            interrupts,
        } = inputs;
        // SAFETY: same consumed actual Function/reset/resources grant. Old real
        // routes/CPU callbacks are independently drained; no numeric substitute.
        let msix = match unsafe { MsixConfig::new(function, retained, bars) } {
            Ok(msix) => msix,
            Err((error, (function, retained, bars))) => {
                return Err((
                    Error::Msix(error),
                    Inputs {
                        function,
                        retained,
                        bars,
                        registers,
                        clock,
                        interrupts,
                    },
                ));
            }
        };
        Ok(Self {
            identity,
            configuration: Some(Rc::new(RefCell::new(Configuration {
                msix,
                fault: None,
                released: None,
            }))),
            signals: Some(Arc::new(Signals {
                registers,
                pending: AtomicBool::new(false),
                handler_fault: AtomicBool::new(false),
                fault_offset: AtomicUsize::new(0),
                fh_mask: AtomicU32::new(u32::MAX),
                hw_mask: AtomicU32::new(u32::MAX),
                disconnect_ack: AtomicBool::new(false),
                reset_issued: AtomicBool::new(false),
            })),
            interrupts,
            clock,
            clock_origin,
            registration: None,
            attempted: false,
            retired: false,
        })
    }
    pub fn service_pending(&self) -> bool {
        self.signals
            .as_ref()
            .is_some_and(|s| s.pending.load(Ordering::Acquire))
    }
    fn signals(&self) -> &Signals<R> {
        self.signals.as_ref().unwrap()
    }
    fn irq_error(&self, error: irq::IrqError) -> super::Error {
        self.configuration
            .as_ref()
            .unwrap()
            .borrow()
            .fault
            .clone()
            .unwrap_or(Error::Irq(error))
            .into()
    }
}
// SAFETY: native constructor's consumed actual grants and concrete owned PCI,
// MSI-X, UC mappings and IRQ registry implement the full Platform contract.
unsafe impl<C: MsiConfigSpace + 'static, B: BarAccess + 'static, R: Registers> Platform
    for NativePlatform<C, B, R>
{
    fn identity(&self) -> Identity {
        self.identity
    }
    fn read32(&mut self, offset: usize) -> DriverResult<u32> {
        let value = self.signals().registers.read32(offset)?;
        if offset == FUNC
            && value != u32::MAX
            && value & (MASTER_DISCONNECT | MASTER_STOPPED) == MASTER_DISCONNECT | MASTER_STOPPED
            && value & (ENABLE | MAC_INIT | FUNC_INIT) == 0
        {
            // Actual pre-reset bus-master-stop acknowledgment. SW_RESET need
            // not preserve this read-only status bit in the post-reset CSR.
            self.signals().disconnect_ack.store(true, Ordering::Release);
        }
        Ok(value)
    }
    fn write32(&mut self, offset: usize, value: u32) -> DriverResult<()> {
        if offset == FUNC {
            self.signals().reset_issued.store(false, Ordering::Release);
            if value & (ENABLE | MAC_INIT | FUNC_INIT) != 0 {
                self.signals()
                    .disconnect_ack
                    .store(false, Ordering::Release);
            }
        }
        self.signals().registers.write32(offset, value)?;
        if offset == FUNC
            && value & RESET != 0
            && self.signals().disconnect_ack.load(Ordering::Acquire)
        {
            self.signals().reset_issued.store(true, Ordering::Release);
        }
        if offset == FH_MASK {
            self.signals().fh_mask.store(value, Ordering::Release);
        }
        if offset == HW_MASK {
            self.signals().hw_mask.store(value, Ordering::Release);
        }
        Ok(())
    }
    fn write8(&mut self, offset: usize, value: u8) -> DriverResult<()> {
        self.signals()
            .registers
            .write8(offset, value)
            .map_err(Into::into)
    }
    fn now_us(&self) -> u64 {
        self.clock
            .try_elapsed_us(self.clock_origin)
            .expect("admitted Intel PCIe native clock")
    }
    fn arm_vector_zero(&mut self) -> DriverResult<()> {
        if self.attempted {
            return Err(Error::Requirement("one actual native IRQ registration attempt").into());
        }
        self.attempted = true;
        let source = NativeSource {
            configuration: self.configuration.as_ref().unwrap().clone(),
            signals: self.signals.as_ref().unwrap().clone(),
        };
        let handler = Callback(self.signals.as_ref().unwrap().clone());
        match self.interrupts.request(Box::new(source), Arc::new(handler)) {
            Ok(registration) => {
                self.registration = Some(registration);
                Ok(())
            }
            Err(error) => Err(self.irq_error(error)),
        }
    }
    fn service_complete(&mut self) -> DriverResult<()> {
        let signals = self.signals();
        signals.check_handler()?;
        if signals.pending.load(Ordering::Acquire) {
            // A callback has already contained newer work. Keep that source
            // masked until its next serialized cause/completion pass.
            signals.check_handler()?;
            signals.mask().map_err(|(_, error)| error)?;
            signals.check_handler()?;
            return Ok(());
        }
        for (offset, value) in [
            (FH_MASK, signals.fh_mask.load(Ordering::Acquire)),
            (HW_MASK, signals.hw_mask.load(Ordering::Acquire)),
        ] {
            signals.registers.write32(offset, value)?;
            let observed = signals.registers.read32(offset)?;
            // Restoring a source can deliver a pending real message before
            // this process continues. Preserve a callback's mask fault here,
            // rather than publishing a successful service result.
            let pending = signals.pending.load(Ordering::Acquire);
            signals.check_handler()?;
            if observed != value && !(pending && observed == u32::MAX) {
                return Err(Error::Readback { offset, observed }.into());
            }
            if pending {
                // A callback can run between the prior pending check and this
                // restore store. Explicitly contain BOTH sources: this store
                // may otherwise supersede one of the callback's earlier masks.
                signals.mask().map_err(|(_, error)| error)?;
                signals.check_handler()?;
                return Ok(());
            }
        }
        Ok(())
    }
    fn service_begin(&mut self) -> DriverResult<()> {
        self.signals().check_handler()?;
        self.signals().pending.swap(false, Ordering::AcqRel);
        Ok(())
    }
    fn retire_vector_zero(&mut self) -> DriverResult<()> {
        if self.retired {
            return Ok(());
        }
        if self.attempted && self.registration.is_none() {
            return Err(Error::Requirement("uncertain native IRQ admission retained").into());
        }
        if let Some(registration) = self.registration.as_mut()
            && let Err(error) = registration.retire()
        {
            return Err(self.irq_error(error));
        }
        // The actual registry masks MSI-X before its source quiescence checks.
        // A failed DMA stop still gets that real mask/quarantine attempt.
        self.signals().stopped()?;
        self.registration = None;
        let mut configuration = self.configuration.as_ref().unwrap().borrow_mut();
        // SAFETY: actual bus-master stop/reset/cause acknowledgments and real
        // registry CPU/callback/work drain all completed. DMA pages remain pinned.
        let owners = unsafe { configuration.msix.release() }.map_err(Error::Msix)?;
        configuration.released = Some(owners);
        self.retired = true;
        Ok(())
    }
}
impl<C: MsiConfigSpace, B: BarAccess, R: Registers> Drop for NativePlatform<C, B, R> {
    fn drop(&mut self) {
        if !self.retired {
            // No destructor retries or frees an uncertain physical owner.
            if let Some(registration) = self.registration.take() {
                core::mem::forget(registration);
            }
            if let Some(configuration) = self.configuration.take() {
                core::mem::forget(configuration);
            }
            if let Some(signals) = self.signals.take() {
                core::mem::forget(signals);
            }
        }
        // Successful physical retirement permits owner Drop. Owned mappings
        // deliberately retain/quarantine their boot-lifetime native reservations.
    }
}
impl<C: MsiConfigSpace + 'static, B: BarAccess + 'static, R: Registers>
    super::Transport<NativePlatform<C, B, R>>
{
    /// A real callback requested another serialized process/deferred pass.
    /// This flag never represents an HCI packet, transfer or firmware result.
    pub fn service_pending(&self) -> bool {
        self.platform.service_pending()
    }
}
