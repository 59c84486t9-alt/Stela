// SPDX-License-Identifier: MIT AND GPL-2.0-only
// Copyright (C) The Asahi Linux Contributors
// Copyright (c) 2026 Stela contributors
//! Explicit native Broadcom PCIe attachment. No discovery or guest service is
//! implied. Actual original configuration, UC BARs, coherent domain and root
//! epoch survive terminal source stop, posted-write completion and IRQ drain.
mod config;
pub(crate) mod delivery;
pub use delivery::MsiCompletion;
mod registers;
use super::{Board, Chip, PciIdentity, Platform, Result as DriverResult, Space, Transport, memory};
use crate::{
    Clock,
    bus::{
        dma::{
            mapping::{DmaDomain, DmaError},
            memory::{CacheAttribute, PageSource},
        },
        irq::{
            self, Disposition, Handler, IrqController, IrqRegistration, Route, RouteRequest, Source,
        },
        mmio::owned::{self, Mapping},
        pci::{
            Address, Function,
            msi::{self, DisabledMsiConfig, MsiConfig, MsiConfigSpace, RetainedOwner},
            native_aspm,
            owned::OwnedConfig,
        },
    },
};
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};
pub use registers::{MappedRegisters, Registers};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Requirement(&'static str),
    ConfigRead { offset: u16, width: u8 },
    ConfigReadback { offset: u16, observed: u32 },
    Mapping(owned::Error),
    Msi(msi::MsiError),
    Aspm(native_aspm::Error),
    Dma(DmaError),
    Irq(irq::IrqError),
    Timeout(&'static str),
}
impl From<Error> for super::Error {
    fn from(error: Error) -> Self {
        Self::Native(error)
    }
}

/// Original native configuration mapping owner, or an explicit device model.
/// # Safety
/// Accesses are actual serialized native config effects under the unique owner;
/// owned_address is its immutable real BDF, not copied Function metadata. The
/// returned Mapping is that same original mapping and resource epoch, without
/// escaped aliases/accessors. No reset/removal/config writer can revoke it.
pub unsafe trait Configuration: MsiConfigSpace + 'static {
    fn owned_address(&self) -> Address;
    fn into_mapping(self) -> Mapping;
}
// SAFETY: OwnedConfig retains the original exclusive native mapping and BDF;
// its concrete accesses are exact-width volatile loads/stores.
unsafe impl Configuration for OwnedConfig {
    fn owned_address(&self) -> Address {
        self.address()
    }
    fn into_mapping(self) -> Mapping {
        self.into_mapping()
    }
}
/// Actual monotonic microsecond clock, or an explicit advancing device model.
/// # Safety
/// This clock advances during bounded waits, does not regress, and includes
/// time spent in actual config/MMIO/domain calls. Final operations are process
/// context. A stalled clock or artificial tick count is not native qualification.
pub unsafe trait Time: 'static {
    fn now_us(&self) -> u64;
}
pub struct NativeClock(Clock);
impl NativeClock {
    /// # Safety
    /// This is the platform's actually calibrated invariant TSC; it advances
    /// monotonically on every execution context admitted by this attachment.
    pub unsafe fn new(clock: Clock) -> Result<Self, Error> {
        if clock.ticks_per_microsecond == 0 {
            return Err(Error::Requirement("qualified nonzero native TSC rate"));
        }
        Ok(Self(clock))
    }
}
// SAFETY: native attachment additionally requires calibrated invariant TSC and
// an execution context with monotonic, advancing same-platform observations.
unsafe impl Time for NativeClock {
    fn now_us(&self) -> u64 {
        self.0.now_us()
    }
}

pub struct Inputs<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    pub function: Function<C>,
    /// Actual coordinated root/resource/reset/firmware-node lifetime owner.
    pub retained: RetainedOwner,
    pub topology: native_aspm::Topology<C>,
    pub registers: R,
    pub domain: Arc<dyn DmaDomain>,
    pub pages: Box<dyn PageSource>,
    pub board: Board,
    /// Original values read from this same retained requester's firmware node.
    pub properties: Vec<(&'static str, Vec<u8>)>,
    pub clock: T,
    pub interrupts: &'static dyn IrqController,
    pub msi_completion: MsiCompletion,
}
struct Allocator {
    domain: Arc<dyn DmaDomain>,
    pages: Box<dyn PageSource>,
}
// SAFETY: the native constructor's actual coherent same-requester grant binds
// this exact domain and PageSource. Each result independently retains real pins.
unsafe impl memory::CoherentAllocator for Allocator {
    fn allocate(&mut self, bytes: usize) -> DriverResult<memory::CoherentBuffer> {
        let pages = self
            .pages
            .allocate(bytes, 4096, CacheAttribute::WriteBack)
            .map_err(super::Error::Memory)?;
        if pages.logical_bytes() < bytes {
            return Err(Error::Requirement("complete actual native coherent allocation").into());
        }
        // SAFETY: exact same retained qualified requester/domain as the platform.
        unsafe { memory::CoherentBuffer::map(pages, self.domain.clone()) }
    }
}
struct Signals {
    pending: AtomicBool,
    stopped: AtomicBool,
}
struct Callback(Arc<Signals>);
impl Handler for Callback {
    fn handle(&self) -> Disposition {
        // Donor MSI auto-acknowledges. Unknown mask/cause registers are never
        // invented. No MMIO/config/DMA access, allocation or final release here.
        self.0.pending.store(true, Ordering::Release);
        Disposition::Handled
    }
}
struct ConfigurationState<C: Configuration> {
    msi: MsiConfig<C>,
    disabled: Option<DisabledMsiConfig<C>>,
    fault: Option<Error>,
}
struct NativeSource<C: Configuration> {
    config: Rc<RefCell<ConfigurationState<C>>>,
    signals: Arc<Signals>,
    delivery: Rc<RefCell<MsiCompletion>>,
}
impl<C: Configuration> NativeSource<C> {
    fn checked(&self, result: Result<(), Error>, kind: irq::IrqError) -> Result<(), irq::IrqError> {
        if let Err(error) = result {
            self.config.borrow_mut().fault.get_or_insert(error);
            return Err(kind);
        }
        Ok(())
    }
}
// SAFETY: admission is a fresh independently drained unpublished reset epoch;
// retirement's stopped latch requires actual FLR, domain payload completion
// AND the independent root/route posted-MSI completion. Registry then drains
// actual CPU pending vectors/callbacks separately.
unsafe impl<C: Configuration> Source for NativeSource<C> {
    fn mask(&mut self) -> Result<(), irq::IrqError> {
        let result = {
            let mut state = self.config.borrow_mut();
            if state.disabled.is_some() {
                Ok(())
            } else {
                state.msi.mask().map_err(Error::Msi)
            }
        };
        self.checked(result, irq::IrqError::Mask)
    }
    fn quiesce(&mut self) -> Result<(), irq::IrqError> {
        if self.signals.stopped.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(irq::IrqError::Quiesce)
        }
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), irq::IrqError> {
        let Route::Msi(message) = route else {
            return Err(irq::IrqError::Route);
        };
        let result = (|| {
            self.delivery.borrow_mut().bind_route(message)?;
            // SAFETY: registry retains the actual route and original owners.
            unsafe { self.config.borrow_mut().msi.program(message) }.map_err(Error::Msi)
        })();
        self.checked(result, irq::IrqError::Route)
    }
    unsafe fn unmask(&mut self) -> Result<(), irq::IrqError> {
        // SAFETY: actual registry published the live retained callback.
        let result = unsafe { self.config.borrow_mut().msi.unmask() }.map_err(Error::Msi);
        self.checked(result, irq::IrqError::Mask)
    }
    unsafe fn synchronize(&mut self) -> Result<(), irq::IrqError> {
        self.quiesce()?;
        // Only after actual CPU pending-vector/callback drain may this sole
        // work item be canceled. Process service is exclusively serialized.
        self.signals.pending.store(false, Ordering::Release);
        Ok(())
    }
}

pub struct NativePlatform<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    identity: PciIdentity,
    board: Board,
    properties: Vec<(&'static str, Vec<u8>)>,
    function: Option<Function<C>>,
    retained: Option<RetainedOwner>,
    topology: Option<native_aspm::Topology<C>>,
    registers: Option<R>,
    domain: Option<Arc<dyn DmaDomain>>,
    allocator: Option<Allocator>,
    clock: T,
    interrupts: &'static dyn IrqController,
    layout: config::Layout,
    configuration: Option<Rc<RefCell<ConfigurationState<C>>>>,
    registration: Option<Box<dyn IrqRegistration>>,
    signals: Arc<Signals>,
    mappings: Vec<Mapping>,
    delivery: Option<Rc<RefCell<MsiCompletion>>>,
    prepared: bool,
    admission_attempted: bool,
    retirement_attempted: bool,
    retirement_error: Option<super::Error>,
    retired: bool,
}
impl<C: Configuration, R: Registers, T: Time> NativePlatform<C, R, T> {
    /// # Safety
    /// Inputs are this actual exclusive native endpoint's original config,
    /// reserved UC BAR0/2 mappings, complete retained bridge/root topology and
    /// acknowledged stopped requester epoch. Former device/firmware/CPU/DMA/IRQ
    /// owners, aliases, timers and work are independently stopped/drained. The
    /// same actual domain is attached to this requester and retains its root /
    /// remapper epoch, with native coherent WB payload/ring-index accesses and
    /// low IOVA capability; the allocator returns real exclusive zeroed pages.
    /// Board/properties are immutable actual observations from its bound node.
    /// Shared combo/reset and ASPM policy ownership are actually coordinated;
    /// no firmware/AML, raw config/mapping alias, reset or removal can race.
    /// NativeClock's TSC is calibrated/invariant/monotonic in this context, and
    /// IRQ registry routing is actually qualified. One process/deferred owner
    /// serializes all service/retirement. No device effect is inferred from
    /// numerical matching. Constructor errors return every original input owner
    /// without native writes; later failures quarantine uncertain ownership.
    pub unsafe fn new(mut inputs: Inputs<C, R, T>) -> Result<Self, (Error, Inputs<C, R, T>)> {
        let checked = (|| {
            let f = &mut inputs.function;
            let vendor = f.vendor;
            let device = f.device;
            let address = f.address;
            let c = f.config();
            let class = c.read32(8);
            let subsystem = c.read32(0x2c);
            if class == u32::MAX || subsystem == u32::MAX {
                return Err(Error::Requirement(
                    "actual readable native class/subsystem identity",
                ));
            }
            let id = PciIdentity {
                address,
                vendor,
                device,
                subsystem_vendor: subsystem as u16,
                subsystem_device: (subsystem >> 16) as u16,
                revision: class as u8,
                class: class >> 8,
            };
            let chip = Chip::select(id)
                .map_err(|_| Error::Requirement("actual supported Broadcom PCIe identity"))?;
            let layout = config::Layout::discover(f)?;
            inputs.topology.validate(f).map_err(Error::Aspm)?;
            // Validate required ASPM controls without changing either link side.
            if chip == Chip::Bcm4377 {
                inputs.topology.validate_link(f).map_err(Error::Aspm)?;
            }
            let spans = inputs.registers.spans();
            for (slot, span, bytes) in [
                (0, spans[0], chip.otp_offset() as u64 + 0xe0),
                (2, spans[1], u64::from(chip.bar2(0x20049c)) + 4),
            ] {
                let (base, _) = layout.bar(slot)?;
                if span.start() != base || span.bytes() < bytes {
                    return Err(Error::Requirement(
                        "same actual complete owned BAR0/2 register windows",
                    ));
                }
            }
            if spans[0].start() < spans[1].end() && spans[1].start() < spans[0].end() {
                return Err(Error::Requirement("nonoverlapping native BAR resources"));
            }
            if inputs
                .properties
                .iter()
                .enumerate()
                .any(|(i, (name, _))| inputs.properties[..i].iter().any(|(old, _)| old == name))
            {
                return Err(Error::Requirement(
                    "unambiguous original firmware-node properties",
                ));
            }
            Ok((id, layout))
        })();
        let (identity, layout) = match checked {
            Ok(checked) => checked,
            Err(error) => return Err((error, inputs)),
        };
        let Inputs {
            function,
            retained,
            topology,
            registers,
            domain,
            pages,
            board,
            properties,
            clock,
            interrupts,
            msi_completion,
        } = inputs;
        Ok(Self {
            identity,
            board,
            properties,
            function: Some(function),
            retained: Some(retained),
            topology: Some(topology),
            registers: Some(registers),
            allocator: Some(Allocator {
                domain: domain.clone(),
                pages,
            }),
            domain: Some(domain),
            clock,
            interrupts,
            layout,
            configuration: None,
            registration: None,
            signals: Arc::new(Signals {
                pending: AtomicBool::new(false),
                stopped: AtomicBool::new(true),
            }),
            mappings: Vec::new(),
            delivery: Some(Rc::new(RefCell::new(msi_completion))),
            prepared: false,
            admission_attempted: false,
            retirement_attempted: false,
            retirement_error: None,
            retired: false,
        })
    }
    /// Allocate through the same actual domain bound by construction; this
    /// entry cannot accidentally pair the platform with another requester's DMA.
    pub fn into_transport(mut self) -> DriverResult<Transport<Self>> {
        let mut allocator = self.allocator.take().expect("unused native allocator");
        Transport::new(self, &mut allocator)
    }
    pub fn service_pending(&self) -> bool {
        !self.retirement_attempted && self.signals.pending.load(Ordering::Acquire)
    }
    fn irq_error(&self, fallback: irq::IrqError) -> super::Error {
        self.configuration
            .as_ref()
            .and_then(|state| state.borrow().fault.clone())
            .unwrap_or(Error::Irq(fallback))
            .into()
    }
    fn live(&self) -> Result<(), Error> {
        if self.retirement_attempted {
            Err(Error::Requirement("terminal native Broadcom epoch"))
        } else {
            Ok(())
        }
    }
    fn retire_inner(&mut self) -> DriverResult<()> {
        if self.configuration.is_some() && self.registration.is_none() {
            return Err(Error::Requirement("uncertain native MSI admission retained").into());
        }
        if let Some(configuration) = &self.configuration {
            let mut state = configuration.borrow_mut();
            state.disabled = Some(state.msi.begin_device_retirement().map_err(Error::Msi)?);
            // SAFETY: one serialized terminal stop on the exact original config;
            // pins/root/route remain owned; no BAR access after this reset.
            unsafe {
                state
                    .disabled
                    .as_mut()
                    .unwrap()
                    .with_device_stop(|c| self.layout.stop(c, &self.clock))
            }
            .map_err(Error::Msi)??;
        } else if let Some(function) = self.function.as_mut() {
            self.layout.stop(function.config(), &self.clock)?;
        }
        // SAFETY: actual supported FLR and current BM-off exclude new requests;
        // submissions are terminal, every actual page/domain/root stays retained.
        // BM/TRPND/reset alone never authorize this operation's success.
        unsafe { self.domain.as_ref().unwrap().drain_posted_writes() }.map_err(Error::Dma)?;
        if self.registration.is_some() {
            // SAFETY: actual source/reset and payload completion above; this
            // independently retained root/route owner completes MSI delivery.
            unsafe { self.delivery.as_ref().unwrap().borrow().drain() }?;
        }
        self.signals.stopped.store(true, Ordering::Release);
        if let Some(registration) = self.registration.as_mut() {
            if let Err(error) = registration.retire() {
                return Err(self.irq_error(error));
            }
        }
        self.registration = None;
        self.signals.pending.store(false, Ordering::Release);
        if let Some(configuration) = self.configuration.take() {
            // The registry has released its source/callback on acknowledged
            // retirement. No second native owner or config access path exists.
            let mut state = configuration.borrow_mut();
            // SAFETY: actual device/domain completion preceded real registry
            // CPU/callback/work drain. This release performs no config access.
            let (function, retained) =
                unsafe { state.disabled.as_mut().unwrap().release_after_drain() }
                    .map_err(Error::Msi)?;
            self.retained = Some(retained);
            self.function = Some(function);
        }
        if let Some(function) = self.function.take() {
            self.mappings.push(function.into_config().into_mapping());
        }
        if let Some(topology) = self.topology.take() {
            self.mappings.extend(
                topology
                    .into_functions()
                    .into_iter()
                    .map(|f| f.into_config().into_mapping()),
            );
        }
        // SAFETY: all CPU/config/BAR/device/posted/IRQ/deferred users are stopped
        // and drained. Every mapping remains retained on failed native unmap.
        unsafe { self.registers.as_mut().unwrap().retire() }?;
        for mapping in &mut self.mappings {
            // SAFETY: exact original owned mappings after the same actual drain.
            unsafe { mapping.retire() }.map_err(Error::Mapping)?;
        }
        self.retired = true;
        Ok(())
    }
}
// SAFETY: constructor consumes real owners; every operation uses those exact
// native resources. Terminal retirement is one-shot and completion is ordered
// device stop → domain payload drain → independent root/route MSI completion
// → real registry CPU/work drain → unmap.
unsafe impl<C: Configuration, R: Registers, T: Time> Platform for NativePlatform<C, R, T> {
    fn identity(&self) -> PciIdentity {
        self.identity
    }
    fn board(&self) -> Board {
        self.board.clone()
    }
    fn property(&self, name: &'static str) -> DriverResult<Option<Vec<u8>>> {
        Ok(self
            .properties
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone()))
    }
    fn prepare(&mut self, chip: Chip) -> DriverResult<()> {
        self.live()?;
        if self.prepared || Chip::select(self.identity)? != chip {
            return Err(Error::Requirement("one same-chip native preparation").into());
        }
        // Latch before any possible effect; no safe retry after partial reset.
        self.prepared = true;
        let result: DriverResult<()> = (|| {
            let function = self.function.as_mut().unwrap();
            if chip == Chip::Bcm4377 {
                self.topology
                    .as_mut()
                    .unwrap()
                    .disable(function)
                    .map_err(Error::Aspm)?;
            }
            self.layout.prepare(function.config(), &self.clock)?;
            if chip == Chip::Bcm4377 {
                self.topology
                    .as_mut()
                    .unwrap()
                    .disable(function)
                    .map_err(Error::Aspm)?;
            }
            // SAFETY: actual reset completed with no published DMA address;
            // all original root/domain/backing resources remain retained.
            unsafe { self.domain.as_ref().unwrap().drain_posted_writes() }.map_err(Error::Dma)?;
            self.layout.enable(function.config())?;
            Ok(())
        })();
        if let Err(error) = &result {
            self.retirement_attempted = true;
            self.retirement_error = Some(error.clone());
        }
        result
    }

    fn read32(&mut self, space: Space, offset: u32) -> DriverResult<u32> {
        self.live()?;
        if space == Space::Configuration {
            if offset > 4092 || !offset.is_multiple_of(4) {
                return Err(
                    Error::Requirement("bounded aligned native configuration DWORD").into(),
                );
            }
            let value = self
                .function
                .as_mut()
                .ok_or(Error::Requirement(
                    "configuration transferred to real MSI owner",
                ))?
                .config()
                .read32(offset as u16);
            return Ok(value);
        }
        if !self.prepared {
            return Err(
                Error::Requirement("native FLR/D0/MEM preparation before BAR access").into(),
            );
        }
        self.registers
            .as_ref()
            .unwrap()
            .read32(space, offset)
            .map_err(Into::into)
    }
    fn write32(&mut self, space: Space, offset: u32, value: u32) -> DriverResult<()> {
        self.live()?;
        if !self.prepared {
            return Err(
                Error::Requirement("native preparation before configuration/BAR writes").into(),
            );
        }
        if space == Space::Configuration {
            // Only source vendor window controls are DWORD writes. Command,
            // PMCSR and MSI use their independently checked native word paths.
            if !matches!(offset, 0x70 | 0x74 | 0x78 | 0x80 | 0x84 | 0x88) {
                return Err(
                    Error::Requirement("source Broadcom vendor DWORD configuration").into(),
                );
            }
            self.function
                .as_mut()
                .ok_or(Error::Requirement(
                    "configuration transferred to real MSI owner",
                ))?
                .config()
                .write32(offset as u16, value);
            return Ok(());
        }
        self.registers
            .as_ref()
            .unwrap()
            .write32(space, offset, value)
            .map_err(Into::into)
    }
    fn read8(&mut self, space: Space, offset: u32) -> DriverResult<u8> {
        self.live()?;
        if !self.prepared || space != Space::Bar0 {
            return Err(Error::Requirement("native prepared BAR0 OTP byte read").into());
        }
        self.registers
            .as_ref()
            .unwrap()
            .read8(space, offset)
            .map_err(Into::into)
    }
    fn now_us(&self) -> u64 {
        self.clock.now_us()
    }
    fn service_begin(&mut self) -> DriverResult<()> {
        self.live()?;
        self.signals.pending.swap(false, Ordering::AcqRel);
        Ok(())
    }
    fn retire_unpublished(&self) -> bool {
        true
    }
    fn arm_msi(&mut self) -> DriverResult<()> {
        self.live()?;
        if !self.prepared || self.admission_attempted {
            return Err(Error::Requirement("one prepared native single-MSI admission").into());
        }
        self.admission_attempted = true;
        let chip = Chip::select(self.identity)?;
        for offset in [super::BOOT_STAGE, super::RTI_STATUS] {
            if self
                .registers
                .as_ref()
                .unwrap()
                .read32(Space::Bar2, chip.bar2(offset))?
                != 0
            {
                return Err(Error::Requirement(
                    "fresh unpublished BOOT0/RTI0 at actual MSI admission",
                )
                .into());
            }
        }
        let function = self.function.take().unwrap();
        let retained = self.retained.take().unwrap();
        // SAFETY: real current reset epoch, former owners drained; actual
        // registry retains callback, route, root and original config resources.
        let msi = match unsafe { MsiConfig::new(function, retained) } {
            Ok(msi) => msi,
            Err((error, (function, retained))) => {
                self.function = Some(function);
                self.retained = Some(retained);
                return Err(Error::Msi(error).into());
            }
        };
        let configuration = Rc::new(RefCell::new(ConfigurationState {
            msi,
            disabled: None,
            fault: None,
        }));
        self.configuration = Some(configuration.clone());
        let source = NativeSource {
            config: configuration,
            signals: self.signals.clone(),
            delivery: self.delivery.as_ref().unwrap().clone(),
        };
        match self
            .interrupts
            .request(Box::new(source), Arc::new(Callback(self.signals.clone())))
        {
            Ok(registration) => {
                self.registration = Some(registration);
                self.signals.stopped.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => Err(self.irq_error(error)),
        }
    }
    fn retire(&mut self) -> DriverResult<()> {
        if self.retirement_attempted {
            return self.retirement_error.clone().map_or(Ok(()), Err);
        }
        self.retirement_attempted = true;
        let result = self.retire_inner();
        if let Err(error) = &result {
            self.retirement_error = Some(error.clone());
        }
        result
    }
}
impl<C: Configuration, R: Registers, T: Time> Drop for NativePlatform<C, R, T> {
    fn drop(&mut self) {
        if !self.retired {
            // No hidden reset/drain retries or final releases on uncertainty.
            // Includes constructor success never converted into a transport.
            if let Some(value) = self.function.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.retained.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.topology.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.registers.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.domain.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.allocator.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.configuration.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.registration.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.delivery.take() {
                core::mem::forget(value);
            }
            for mapping in self.mappings.drain(..) {
                core::mem::forget(mapping);
            }
        }
    }
}
impl<C: Configuration, R: Registers, T: Time> Transport<NativePlatform<C, R, T>> {
    /// An actual callback requested process service; packet/HCI completion
    /// still comes exclusively from the coherent DMA completion rings.
    pub fn service_pending(&self) -> bool {
        self.platform
            .as_ref()
            .is_some_and(NativePlatform::service_pending)
    }
}
