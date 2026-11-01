// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! Native PCI/UC-MMIO/MSI-X/IRQ attachment for the Intel Bluetooth transport.
//! The real source stops before IRQ retirement. A hard-IRQ callback only masks
//! this source and requests serialized service; it never invents completion.
use super::{Identity, Platform, Result as DriverResult, registers::*};
use crate::bus::pci::regs;
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
const MEMORY_AND_MASTER: u16 = regs::COMMAND_MEMORY | regs::COMMAND_MASTER;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Requirement(&'static str),
    Mapping(owned::Error),
    Msix(msix::Error),
    Irq(irq::IrqError),
    Delivery(irq::posted_msi::Error),
    Readback {
        offset: usize,
        observed: u32,
    },
    Handler {
        offset: usize,
    },
    Claim(crate::bus::pci::requester::ClaimError),
    Power(crate::block::BlockError),
    Dma {
        operation: lifetime::DmaOperation,
        source: crate::bus::dma::mapping::DmaError,
    },
}
impl From<Error> for super::Error {
    fn from(error: Error) -> Self {
        Self::Native(error)
    }
}

/// Exclusive BAR0 registers, or an explicit independent device model.
/// # Safety
/// The full span names this same Function/reset epoch's reserved BAR0.
/// All accesses are bounded native UC byte/DWORD effects, hard-IRQ-safe with no
/// allocation, blocking, final-owner release or wider W1C read/modify/write.
/// The kept owner keeps its mapping and resource valid through callback
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
    /// The full BAR reservation and mapping belong to the same Function
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
// SAFETY: unsafe construction binds the exclusive UC mapping. Every
// address is checked against that live mapping; stores use exact widths.
unsafe impl Registers for MappedRegisters {
    fn full_bar(&self) -> PhysicalSpan {
        self.full_bar
    }
    fn read32(&self, offset: usize) -> core::result::Result<u32, Error> {
        let p = self.mapping.address(offset, 4).map_err(Error::Mapping)?;
        if !(p.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::Requirement("aligned native register DWORD"));
        }
        // SAFETY: checked live aligned UC register address.
        Ok(unsafe { p.as_ptr().cast::<u32>().read_volatile() })
    }
    fn write32(&self, offset: usize, value: u32) -> core::result::Result<(), Error> {
        let p = self.mapping.address(offset, 4).map_err(Error::Mapping)?;
        if !(p.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::Requirement("aligned native register DWORD"));
        }
        // SAFETY: same checked UC owner; native DWORD effect, no RMW.
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
    pub domain: Arc<dyn crate::bus::dma::mapping::DmaDomain>,
    pub msi_completion: irq::posted_msi::MsiCompletion,
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
        // Mask/readback contains the source until serialized service.
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
    retiring_configuration: Option<Mapping>,
}
struct NativeSource<C: MsiConfigSpace, B: BarAccess, R: Registers> {
    configuration: Rc<RefCell<Configuration<C, B>>>,
    signals: Arc<Signals<R>>,
    domain: Arc<dyn crate::bus::dma::mapping::DmaDomain>,
    delivery: Rc<RefCell<irq::posted_msi::MsiCompletion>>,
    programmed: bool,
    drained: bool,
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
// SAFETY: the consumed native grant binds PCI/reset/UC/DMA ownership.
// Source quiescence observes stop/reset/cause acknowledgments, completes the
// paired payload path and independently drains bound posted MSI-X delivery.
// Registry then drains CPU/callbacks before pending work is canceled.
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
        let result = (|| {
            self.signals.stopped()?;
            if self.programmed && !self.drained {
                // SAFETY: this original function acknowledged disconnect/reset,
                // all MSI-X entries are masked, and the serialized core cannot
                // resume. Its buffers/configuration and root remain held.
                unsafe { self.domain.drain_posted_writes() }.map_err(|source| Error::Dma {
                    operation: lifetime::DmaOperation::Drain,
                    source,
                })?;
                // SAFETY: same source/payload completion, masked original route
                // and kept owners. This is independent of payload/CPU drain.
                unsafe { self.delivery.borrow().drain() }.map_err(Error::Delivery)?;
                self.drained = true;
            }
            Ok(())
        })();
        self.checked(result, irq::IrqError::Quiesce)
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> core::result::Result<(), irq::IrqError> {
        let Route::Msi(message) = route else {
            return Err(irq::IrqError::Route);
        };
        self.programmed = true;
        let result = (|| {
            // SAFETY: Source::program holds this registry's original exclusive
            // route for the paired requester/root owner.
            unsafe { self.delivery.borrow_mut().bind_route(message) }.map_err(Error::Delivery)?;
            // SAFETY: registry keeps the checked route/callback while masked.
            unsafe { self.configuration.borrow_mut().msix.program(message) }.map_err(Error::Msix)
        })();
        self.checked(result, irq::IrqError::Route)
    }
    unsafe fn unmask(&mut self) -> core::result::Result<(), irq::IrqError> {
        // SAFETY: registry has published this source's LIVE callback.
        let result = unsafe { self.configuration.borrow_mut().msix.unmask() }.map_err(Error::Msix);
        self.checked(result, irq::IrqError::Mask)
    }
    unsafe fn synchronize(&mut self) -> core::result::Result<(), irq::IrqError> {
        self.checked(self.signals.stopped(), irq::IrqError::Drain)?;
        // There is exactly one deferred work item: this flag. The
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
    domain: Option<Arc<dyn crate::bus::dma::mapping::DmaDomain>>,
    delivery: Option<Rc<RefCell<irq::posted_msi::MsiCompletion>>>,
    clock: Clock,
    clock_origin: u64,
    registration: Option<Box<dyn IrqRegistration>>,
    attempted: bool,
    retired: bool,
}
impl<C: MsiConfigSpace + 'static, B: BarAccess + 'static, R: Registers> NativePlatform<C, B, R> {
    /// # Safety
    /// Inputs own the unique Function/root, BIR-indexed complete BAR
    /// resources, BAR0 UC mapping and reset epoch; PCI D0, memory decoding and
    /// bus mastering are already acknowledged. All former firmware/driver/CPU
    /// interrupt and DMA owners are drained. Shared combo reset is authorized by
    /// its coordinator. Supplied DMA retains coherent mappings and page pins
    /// for this requester; bus addresses need not equal physical/CPU addresses.
    /// IRQ routing is real/checked. `domain` is the paired coherent payload
    /// root; `msi_completion` owns its independent posted-interrupt path.
    /// Unavailable completion permits I/O but refuses armed route retirement.
    /// Only one serialized process/deferred owner may service this transport;
    /// the callback's pending flag is its entire work queue. No source,
    /// mapping, DMA or reset owner may be revoked while kept. Native mappings
    /// remain kept until explicit device/DMA/IRQ and mapping retirement.
    /// Constructor errors perform no writes and return every exact input owner.
    #[expect(
        clippy::result_large_err,
        reason = "read-only refusal returns the original function, BAR, root and delivery owners without allocating"
    )]
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
                || f.config().read32(regs::VENDOR_ID)
                    != u32::from(f.vendor) | (u32::from(f.device) << 16)
            {
                return Err(Error::Requirement(
                    "actual source Intel PCIe Function identity",
                ));
            }
            if inputs.clock.ticks_per_microsecond == 0
                || f.config().read16(regs::COMMAND) & MEMORY_AND_MASTER != MEMORY_AND_MASTER
            {
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
            domain,
            msi_completion,
        } = inputs;
        // SAFETY: same consumed Function/reset/resources grant. Old real
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
                        domain,
                        msi_completion,
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
                retiring_configuration: None,
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
            domain: Some(domain),
            delivery: Some(Rc::new(RefCell::new(msi_completion))),
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
// SAFETY: native constructor's consumed grants and concrete owned PCI,
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
            // Pre-reset bus-master-stop acknowledgment. SW_RESET need
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
            domain: self.domain.as_ref().unwrap().clone(),
            delivery: self.delivery.as_ref().unwrap().clone(),
            programmed: false,
            drained: false,
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
        // The registry masks MSI-X before its source quiescence checks.
        // A failed DMA stop still gets that real mask/quarantine attempt.
        self.signals().stopped()?;
        self.registration = None;
        let mut configuration = self.configuration.as_ref().unwrap().borrow_mut();
        // SAFETY: bus-master stop/reset/cause acknowledgments and real
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
            core::mem::forget(self.domain.take());
            core::mem::forget(self.delivery.take());
        }
        // Successful physical retirement permits owner Drop. Owned mappings
        // keep/quarantine their boot-lifetime native reservations.
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

pub mod cold;

pub mod lifetime;

/// Register owner whose mapping can be retired after all device/CPU users stop.
/// # Safety
/// `retire_mapping` retires this same original mapping, with its real context
/// checks and acknowledged unmap. Error and Drop retain uncertain backing.
pub unsafe trait RetirableRegisters: Registers {
    /// # Safety
    /// This original device cannot restart; payload/IRQ/work/CPU users are
    /// drained, requester translations detached, and every table/PBA view is
    /// dropped. No retained callback or accessor can reach these registers.
    unsafe fn retire_mapping(&mut self) -> core::result::Result<(), Error>;
}
// SAFETY: Mapping performs the original context/lease checks and acknowledged
// unmap. Its failed retirement/Drop preserves the original resources.
unsafe impl RetirableRegisters for MappedRegisters {
    unsafe fn retire_mapping(&mut self) -> core::result::Result<(), Error> {
        // SAFETY: the caller supplies full device/translation/CPU retirement.
        unsafe { self.mapping.retire() }.map_err(Error::Mapping)
    }
}

impl<B: BarAccess + 'static, R: Registers>
    NativePlatform<crate::bus::pci::owned::OwnedConfig, B, R>
{
    fn stop_requester(
        &mut self,
        seal: &crate::bus::pci::owned::ConfigRetention,
    ) -> DriverResult<()> {
        use crate::bus::pci::{ConfigSpace, requester::validate_stopped};
        if !self.retired || self.registration.is_some() {
            return Err(
                Error::Requirement("actual BT IRQ retirement before requester stop").into(),
            );
        }
        let mut configuration = self.configuration.as_ref().unwrap().borrow_mut();
        let (function, _, _) = configuration.released.as_mut().ok_or(Error::Requirement(
            "same original BT configuration after IRQ retirement",
        ))?;
        if !function
            .config()
            .matches_retention(seal)
            .map_err(Error::Mapping)?
        {
            return Err(Error::Requirement("current original BT configuration epoch").into());
        }
        let command = function.config().read16(regs::COMMAND);
        if command == u16::MAX {
            return Err(Error::Readback {
                offset: regs::COMMAND.into(),
                observed: u32::MAX,
            }
            .into());
        }
        function.config().write16(
            regs::COMMAND,
            command & !regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE,
        );
        validate_stopped(function).map_err(Error::Claim)?;
        Ok(())
    }
}
impl<B: BarAccess + 'static, R: RetirableRegisters>
    NativePlatform<crate::bus::pci::owned::OwnedConfig, B, R>
{
    /// # Safety
    /// This original transport's engines/BME and IRQ/work/CPU users are
    /// retired; all DMA buffers are unmapped and its unique attachment detached.
    /// The configuration seal was checked before that retirement and is now
    /// released. No reset, resource reassignment or new accessor can intervene.
    unsafe fn retire_resources(&mut self) -> DriverResult<()> {
        if !self.retired || self.registration.is_some() {
            return Err(Error::Requirement("current BT IRQ/resource retirement").into());
        }
        let signals = Arc::get_mut(self.signals.as_mut().unwrap()).ok_or(Error::Requirement(
            "all original BT callback register owners released",
        ))?;
        let configuration = self.configuration.as_ref().unwrap();
        if Rc::strong_count(configuration) != 1 {
            return Err(
                Error::Requirement("all original BT IRQ configuration owners released").into(),
            );
        }
        let mut configuration = configuration.borrow_mut();
        if configuration.retiring_configuration.is_none() {
            let (function, retained, bars) = configuration.released.take().ok_or(
                Error::Requirement("original BT configuration retirement owner"),
            )?;
            // Drop every MSI-X mapping view before retiring the register mapping.
            drop(bars);
            drop(retained);
            configuration.retiring_configuration = Some(function.into_config().into_mapping());
        }
        // SAFETY: full caller proof, unique signals and all table/PBA views gone.
        unsafe { signals.registers.retire_mapping() }?;
        // SAFETY: the unique requester attachment already released its binding,
        // no live config writer/view remains and IRQ/work/CPU users are retired.
        unsafe {
            configuration
                .retiring_configuration
                .as_mut()
                .unwrap()
                .retire()
        }
        .map_err(Error::Mapping)?;
        Ok(())
    }
}
