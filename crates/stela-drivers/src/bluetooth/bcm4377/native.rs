// SPDX-License-Identifier: MIT AND GPL-2.0-only
// Copyright (C) The Asahi Linux Contributors
// Copyright (c) 2026 Stela contributors
//! Explicit native Broadcom PCIe attachment. No discovery or guest service is
//! implied. Original configuration, UC BARs, coherent domain and root
//! epoch survive terminal source stop, posted-write completion and IRQ drain.
pub(crate) mod cold;
mod config;
use crate::bus::irq::posted_msi::MsiRoute;
mod registers;
use super::{Board, Chip, PciIdentity, Platform, Result as DriverResult, Space, Transport, memory};
use crate::bus::pci::regs;
use crate::{
    Clock,
    bus::{
        dma::{
            mapping::{DmaDomain, DmaError},
            memory::{CacheAttribute, PageSource},
        },
        irq::{self, Disposition, Handler, IrqController, IrqRegistration, Route, Source},
        mmio::owned,
        pci::{
            Address, Function,
            msi::{self, DisabledMsiConfig, MsiConfig, MsiConfigSpace, RetainedOwner},
            native_aspm,
            owned::{ConfigRetention, OwnedConfig},
            requester::preparation::{self, Attachment},
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
    Minimum(crate::bus::pci::power::Error),
    Config(crate::bus::pci::ConfigError),
    Capability(crate::bus::pci::CapabilityError),
    Requirement(&'static str),
    Preparation(preparation::Error),
    Power(crate::block::BlockError),
    ConfigRead { offset: u16, width: u8 },
    ConfigReadback { offset: u16, observed: u32 },
    Mapping(owned::Error),
    Msi(msi::MsiError),
    Aspm(native_aspm::Error),
    Dma(DmaError),
    Irq(irq::IrqError),
    Delivery(irq::posted_msi::Error),
    Timeout(&'static str),
}
impl From<Error> for super::Error {
    fn from(error: Error) -> Self {
        Self::Native(error)
    }
}

/// Original native configuration mapping owner, or an explicit device model.
/// # Safety
/// Accesses are serialized native config effects under the unique owner;
/// owned_address is its immutable real BDF, not copied Function metadata. The
/// configuration keeps its same actual grant/mapping and resource epoch,
/// without escaped aliases/accessors. `retain_epoch` pins that exact mapping and
/// `matches_retention` compares its original permission identity, rather than
/// BDF or physical labels. No reset/removal/config writer can revoke it.
pub unsafe trait Configuration: MsiConfigSpace + 'static {
    fn owned_address(&self) -> Address;
    fn retain_epoch(&self) -> Result<ConfigRetention, owned::Error>;
    fn matches_retention(&self, seal: &ConfigRetention) -> Result<bool, owned::Error>;
    /// # Safety
    /// All original device, DMA, IRQ, CPU/config and deferred users have ended;
    /// attachment pins are released in the same actual retirement context.
    /// Failure/unwind keeps this exact configuration, grant and mapping. A
    /// mapping retirement grants no reset/reassignment/root release permission.
    unsafe fn retire(&mut self) -> Result<(), owned::Error>;
}
// SAFETY: OwnedConfig keeps the original exclusive native mapping and BDF;
// its concrete accesses are exact-width volatile loads/stores.
unsafe impl Configuration for OwnedConfig {
    fn owned_address(&self) -> Address {
        self.address()
    }
    fn retain_epoch(&self) -> Result<ConfigRetention, owned::Error> {
        self.retain_epoch()
    }
    fn matches_retention(&self, seal: &ConfigRetention) -> Result<bool, owned::Error> {
        self.matches_retention(seal)
    }
    unsafe fn retire(&mut self) -> Result<(), owned::Error> {
        // SAFETY: original native caller forwards the complete same-owner
        // retirement boundary; OwnedConfig independently checks actual custody.
        unsafe { OwnedConfig::retire(self) }
    }
}
/// Monotonic microsecond clock, or an explicit advancing device model.
/// # Safety
/// This clock advances during bounded waits, does not regress, and includes
/// time spent in config/MMIO/domain calls. Final operations are process
/// context. A stalled clock or artificial tick count is not native validation.
pub unsafe trait Time: 'static {
    fn now_us(&self) -> u64;
}
pub struct NativeClock(Clock, u64);
impl NativeClock {
    /// # Safety
    /// This is the platform's calibrated invariant TSC; it advances
    /// monotonically on every execution context admitted by this attachment.
    pub unsafe fn new(clock: Clock) -> Result<Self, Error> {
        clock
            .check_duration(120_000_000)
            .map_err(|_| Error::Requirement("qualified representable native TSC timing"))?;
        let origin = clock
            .try_start()
            .map_err(|_| Error::Requirement("qualified native TSC origin"))?;
        Ok(Self(clock, origin))
    }
}
// SAFETY: native attachment additionally requires calibrated invariant TSC and
// an execution context with monotonic, advancing same-platform observations.
unsafe impl Time for NativeClock {
    fn now_us(&self) -> u64 {
        self.0
            .try_elapsed_us(self.1)
            .expect("admitted BCM4377 native clock")
    }
}

pub struct Inputs<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    pub function: Function<C>,
    /// Coordinated root/resource/reset/firmware-node lifetime owner.
    pub retained: RetainedOwner,
    pub topology: native_aspm::Topology<C>,
    pub registers: R,
    pub attachment: Attachment,
    pub pages: Box<dyn PageSource>,
    pub board: Board,
    /// Original values read from this same requester's firmware node.
    pub properties: Vec<(&'static str, Vec<u8>)>,
    pub clock: T,
    pub minimum: alloc::rc::Rc<dyn crate::bus::pci::power::Timer>,
    pub interrupts: &'static dyn IrqController,
}
struct Allocator {
    domain: Arc<dyn DmaDomain>,
    pages: Box<dyn PageSource>,
}
// SAFETY: the native constructor's coherent same-requester grant binds
// this exact domain and PageSource. Each result independently keeps real pins.
unsafe impl memory::CoherentAllocator for Allocator {
    fn allocate(&mut self, bytes: usize) -> DriverResult<memory::CoherentBuffer> {
        let pages = self
            .pages
            .allocate(bytes, 4096, CacheAttribute::WriteBack)
            .map_err(super::Error::Memory)?;
        if pages.logical_bytes() < bytes {
            return Err(Error::Requirement("complete actual native coherent allocation").into());
        }
        // SAFETY: same checked requester/domain as the platform.
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
    requester: crate::bus::pci::requester::RequesterId,
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
// retirement's stopped latch requires this owner's authorized containment FLR
// and domain payload completion. It does not advance the ownership generation.
// Registry separately fences the original root route, then CPU/callback/work;
// foreign reset/reassignment invalidates the grant instead of renewing it.
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
    fn route_kind(&self) -> crate::bus::irq::RouteKind {
        crate::bus::irq::RouteKind::Msi
    }
    fn requester(&self) -> Option<&crate::bus::pci::requester::RequesterId> {
        Some(&self.requester)
    }
    unsafe fn program(
        &mut self,
        route: &crate::bus::irq::AllocatedRoute<'_>,
    ) -> Result<(), irq::IrqError> {
        let Route::Msi(message) = route.programming() else {
            return Err(irq::IrqError::Route);
        };
        if !route.matches_requester(&self.requester) {
            return Err(irq::IrqError::Route);
        }
        let result = {
            // SAFETY: registry keeps the route and original owners.
            unsafe { self.config.borrow_mut().msi.program(message) }.map_err(Error::Msi)
        };
        self.checked(result, irq::IrqError::Route)
    }
    unsafe fn unmask(&mut self) -> Result<(), irq::IrqError> {
        // SAFETY: registry published the live callback.
        let result = unsafe { self.config.borrow_mut().msi.unmask() }.map_err(Error::Msi);
        self.checked(result, irq::IrqError::Mask)
    }
    unsafe fn synchronize(&mut self) -> Result<(), irq::IrqError> {
        self.quiesce()?;
        // Only after CPU pending-vector/callback drain may this sole
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
    attachment: Option<Attachment>,
    retention: Option<ConfigRetention>,
    quiesced: bool,
    resources_attempted: bool,
    clock: T,
    minimum: Option<alloc::rc::Rc<dyn crate::bus::pci::power::Timer>>,
    interrupts: &'static dyn IrqController,
    layout: config::Layout,
    configuration: Option<Rc<RefCell<ConfigurationState<C>>>>,
    registration: Option<Box<dyn IrqRegistration>>,
    signals: Arc<Signals>,
    retiring_configurations: Vec<C>,
    msi_route: Option<MsiRoute>,
    requester: crate::bus::pci::requester::RequesterId,
    irq_retirement: Option<irq::RetiredRoute>,
    prepared: bool,
    admission_attempted: bool,
    retirement_attempted: bool,
    retirement_error: Option<super::Error>,
    retired: bool,
}
impl<C: Configuration, R: Registers, T: Time> NativePlatform<C, R, T> {
    /// # Safety
    /// Inputs are this exclusive native endpoint's original config,
    /// reserved UC BAR0/2 mappings, complete kept bridge/root topology and
    /// acknowledged cold FLR/D0/BAR-restored requester epoch. The consumed
    /// driver receipt drained the original root before the unique private
    /// attachment was created; no allocation or IRQ predates that binding.
    /// Former device/firmware/CPU/DMA/IRQ
    /// owners, aliases, timers and work are independently stopped/drained. The
    /// attachment's domain is bound to this requester and keeps its root /
    /// remapper epoch, with native coherent WB payload/ring-index accesses and
    /// low IOVA capability; the allocator returns real exclusive zeroed pages.
    /// Board/properties are immutable observations from its bound node.
    /// Shared combo/reset and ASPM policy ownership are coordinated;
    /// no firmware/AML, raw config/mapping alias, reset or removal can race.
    /// NativeClock's TSC is calibrated/invariant/monotonic in this context, and
    /// IRQ registry routing is checked. One process/deferred owner
    /// serializes all service/retirement. No device effect is inferred from
    /// numerical matching. Constructor errors return every original input owner
    /// without native writes; later failures quarantine uncertain ownership.
    // Return the exact potentially unchecked owners without allocating or
    // dropping any native resource on rejection.
    #[allow(
        clippy::result_large_err,
        reason = "Failed BCM4377 claim returns the exact original PCI, MMIO, timer and DMA inputs needed for safe native retirement"
    )]
    pub unsafe fn new(mut inputs: Inputs<C, R, T>) -> Result<Self, (Error, Inputs<C, R, T>)> {
        let checked = (|| {
            inputs.minimum.check().map_err(Error::Minimum)?;
            let f = &mut inputs.function;
            let vendor = f.vendor;
            let device = f.device;
            let address = f.address;
            let c = f.config();
            let class = c.read32(regs::CLASS_REVISION).map_err(Error::Config)?;
            let subsystem = c.read32(regs::SUBSYSTEM_VENDOR_ID).map_err(Error::Config)?;
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
        let retention = match inputs.function.config().retain_epoch() {
            Ok(retention) => retention,
            Err(error) => return Err((Error::Mapping(error), inputs)),
        };
        // Compare the actual original allocation before any route/entry or
        // device write; equal BDF/vendor/BAR numbers are not source authority.
        match inputs.attachment.matches_retention(&retention) {
            Ok(true) => {}
            Ok(false) => {
                return Err((
                    Error::Requirement("same actual source/attachment config allocation"),
                    inputs,
                ));
            }
            Err(error) => return Err((Error::Dma(error), inputs)),
        }
        let requester = inputs.attachment.requester().clone();
        let msi_route = match inputs.attachment.irq_route() {
            Ok(route) => route,
            Err(error) => return Err((Error::Dma(error), inputs)),
        };
        let Inputs {
            function,
            retained,
            topology,
            registers,
            attachment,
            pages,
            board,
            properties,
            clock,
            minimum,
            interrupts,
        } = inputs;
        let domain = attachment.domain();
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
            attachment: Some(attachment),
            retention: Some(retention),
            quiesced: false,
            resources_attempted: false,
            clock,
            minimum: Some(minimum),
            interrupts,
            layout,
            configuration: None,
            registration: None,
            signals: Arc::new(Signals {
                pending: AtomicBool::new(false),
                stopped: AtomicBool::new(true),
            }),
            retiring_configurations: Vec::new(),
            msi_route: Some(msi_route),
            requester,
            irq_retirement: None,
            prepared: false,
            admission_attempted: false,
            retirement_attempted: false,
            retirement_error: None,
            retired: false,
        })
    }
    /// Allocate through the same domain bound by construction; this
    /// entry cannot accidentally pair the platform with another requester's DMA.
    pub fn into_transport(mut self) -> DriverResult<Transport<Self>> {
        // The page source belongs to this entire native graph, including
        // partially allocated/error and unwind paths.
        let mut allocator =
            core::mem::ManuallyDrop::new(self.allocator.take().expect("unused native allocator"));
        let mut transport = Transport::new(self, &mut *allocator)?;
        transport.platform.as_mut().unwrap().allocator =
            Some(core::mem::ManuallyDrop::into_inner(allocator));
        Ok(transport)
    }
    pub fn service_pending(&self) -> bool {
        !self.retirement_attempted
            && !self.resources_attempted
            && self.retirement_error.is_none()
            && self.signals.pending.load(Ordering::Acquire)
    }
    fn irq_error(&self, fallback: irq::IrqError) -> super::Error {
        self.configuration
            .as_ref()
            .and_then(|state| state.borrow().fault.clone())
            .unwrap_or(Error::Irq(fallback))
            .into()
    }
    fn live(&self) -> DriverResult<()> {
        if let Some(error) = &self.retirement_error {
            return Err(error.clone());
        }
        if self.retirement_attempted || self.resources_attempted {
            Err(self
                .retirement_error
                .clone()
                .unwrap_or_else(|| Error::Requirement("terminal native Broadcom epoch").into()))
        } else {
            Ok(())
        }
    }
    fn retire_inner(&mut self) -> DriverResult<()> {
        self.retention
            .as_ref()
            .unwrap()
            .check_live()
            .map_err(Error::Mapping)?;
        if self.configuration.is_some() && self.registration.is_none() {
            return Err(Error::Requirement("uncertain native MSI admission retained").into());
        }
        if let Some(configuration) = &self.configuration {
            let mut state = configuration.borrow_mut();
            state.disabled = Some(state.msi.begin_device_retirement().map_err(Error::Msi)?);
            // SAFETY: one serialized terminal stop on the original config;
            // pins/root/route remain owned; no BAR access after this reset.
            unsafe {
                state.disabled.as_mut().unwrap().with_device_stop(|c| {
                    if !c
                        .matches_retention(self.retention.as_ref().unwrap())
                        .map_err(Error::Mapping)?
                    {
                        return Err(Error::Requirement("same original Broadcom config epoch"));
                    }
                    self.layout
                        .stop(c, &self.clock, self.minimum.as_ref().unwrap().as_ref())
                })
            }
            .map_err(Error::Msi)??;
        } else if let Some(function) = self.function.as_mut() {
            if !function
                .config()
                .matches_retention(self.retention.as_ref().unwrap())
                .map_err(Error::Mapping)?
            {
                return Err(Error::Requirement("same original Broadcom config epoch").into());
            }
            self.layout.stop(
                function.config(),
                &self.clock,
                self.minimum.as_ref().unwrap().as_ref(),
            )?;
        }
        // SAFETY: supported FLR and current BM-off exclude new requests;
        // submissions are terminal, every page/domain/root stays held.
        // BM/TRPND/reset alone never authorize this operation's success.
        unsafe { self.domain.as_ref().unwrap().drain_posted_writes() }.map_err(Error::Dma)?;
        self.signals.stopped.store(true, Ordering::Release);
        if let Some(registration) = self.registration.as_mut() {
            let retired = registration
                .retire()
                .map_err(|error| self.irq_error(error))?;
            // SAFETY: exact checked original action/CPU/work retirement. Keep
            // callback until source destruction and route through native close.
            let (source, handler, route) =
                unsafe { retired.into_parts() }.map_err(|failure| self.irq_error(failure.error))?;
            drop(source);
            drop(handler);
            self.irq_retirement = Some(route);
        }
        self.registration = None;
        self.signals.pending.store(false, Ordering::Release);
        if let Some(configuration) = self.configuration.take() {
            // The registry has released its source/callback on acknowledged
            // retirement. No second native owner or config access path exists.
            let mut state = configuration.borrow_mut();
            // SAFETY: device/domain completion preceded real registry
            // CPU/callback/work drain. This release performs no config access.
            let (function, retained) =
                unsafe { state.disabled.as_mut().unwrap().release_after_drain() }
                    .map_err(Error::Msi)?;
            self.retained = Some(retained);
            self.function = Some(function);
        }
        self.quiesced = true;
        Ok(())
    }
    fn retire_resources_inner(&mut self) -> DriverResult<()> {
        if !self.quiesced {
            return Err(
                Error::Requirement("native Broadcom quiescence before resource release").into(),
            );
        }
        // SAFETY: full engine/payload/action/CPU/work drain excludes every live
        // consumer and original PCI owners remain. Normal transport close
        // already removed coherent leases. A direct safe platform call before
        // lease removal independently refuses inside Attachment::detach;
        // no BAR/config retirement can occur before its acknowledgement.
        if let Some(grant) = self.msi_route.take() {
            self.attachment
                .as_mut()
                .unwrap()
                .cancel_unpublished_irq(grant)
                .map_err(|failure| Error::Dma(failure.error))?;
        }
        if let Some(route) = self.irq_retirement.take() {
            self.attachment
                .as_mut()
                .unwrap()
                .retain_irq_action(route)
                .map_err(|failure| Error::Irq(failure.error))?;
        }
        // SAFETY: separate terminal engine/payload and DMA-unmap proof above;
        // every issued action is canceled or retained with its real join.
        let detached = unsafe { self.attachment.as_mut().unwrap().detach() }.map_err(Error::Dma)?;
        self.attachment
            .as_mut()
            .unwrap()
            .release_irq_pins(detached)
            .map_err(|failure| Error::Irq(failure.error))?;
        self.retention.take();
        if let Some(function) = self.function.take() {
            self.retiring_configurations.push(function.into_config());
        }
        if let Some(topology) = self.topology.take() {
            self.retiring_configurations.extend(
                topology
                    .into_functions()
                    .into_iter()
                    .map(Function::into_config),
            );
        }
        // SAFETY: all CPU/config/BAR/device/posted/IRQ/deferred users are stopped
        // and drained. Every mapping remains held on failed native unmap.
        unsafe { self.registers.as_mut().unwrap().retire() }?;
        for configuration in &mut self.retiring_configurations {
            // SAFETY: same actual configuration owner after the independent
            // hardware/root/IRQ/users boundary, never a mapping-only substitute.
            unsafe { configuration.retire() }.map_err(Error::Mapping)?;
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
            let error: super::Error = Error::Requirement("one same-chip native preparation").into();
            self.retirement_attempted = true;
            self.retirement_error = Some(error.clone());
            return Err(error);
        }
        // Latch before BME admission; unwind cannot permit access or retry.
        self.prepared = true;
        self.retirement_error =
            Some(Error::Requirement("interrupted native Broadcom preparation").into());
        let result: DriverResult<()> = (|| {
            let function = self.function.as_mut().unwrap();
            if !function
                .config()
                .matches_retention(self.retention.as_ref().unwrap())
                .map_err(Error::Mapping)?
            {
                return Err(Error::Requirement("same cold Broadcom config epoch").into());
            }
            self.layout.enable(function.config())?;
            Ok(())
        })();
        if let Err(error) = &result {
            self.retirement_attempted = true;
            self.retirement_error = Some(error.clone());
        } else {
            self.retirement_error = None;
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
                .read32(offset as u16)
                .map_err(Error::Config)?;
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
            // PMCSR and MSI use their checked native word paths.
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
                .write32(offset as u16, value)
                .map_err(Error::Config)?;
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
        // registry keeps callback, route, root and original config resources.
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
            requester: self.requester.clone(),
        };
        match self.interrupts.request(irq::Request {
            source: Box::new(source),
            handler: Arc::new(Callback(self.signals.clone())),
            routing: irq::RouteRequest::Msi(
                self.msi_route
                    .take()
                    .ok_or(Error::Requirement("original unused IRQ grant"))?,
            ),
        }) {
            Ok(registration) => {
                self.registration = Some(registration);
                self.signals.stopped.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => Err(self.irq_error(error.error)),
        }
    }
    fn retire_resources(&mut self) -> DriverResult<()> {
        if let Some(error) = &self.retirement_error {
            return Err(error.clone());
        }
        if self.resources_attempted {
            if let Some(route) = &self.irq_retirement {
                route.validate().map_err(|error| self.irq_error(error))?;
            }
            if let Some(attachment) = &self.attachment {
                attachment.validate_irq_actions().map_err(Error::Irq)?;
            }
            return Ok(());
        }
        self.resources_attempted = true;
        self.retirement_error =
            Some(Error::Requirement("interrupted native Broadcom resource retirement").into());
        let result = self.retire_resources_inner();
        self.retirement_error = result.as_ref().err().cloned();
        result
    }
    fn retire(&mut self) -> DriverResult<()> {
        if let Some(error) = &self.retirement_error {
            return Err(error.clone());
        }
        if self.retirement_attempted || self.resources_attempted {
            if let Some(route) = &self.irq_retirement {
                route.validate().map_err(|error| self.irq_error(error))?;
            }
            if let Some(attachment) = &self.attachment {
                attachment.validate_irq_actions().map_err(Error::Irq)?;
            }
            return Ok(());
        }
        self.retirement_attempted = true;
        self.retirement_error =
            Some(Error::Requirement("interrupted native Broadcom quiescence").into());
        let result = self.retire_inner();
        self.retirement_error = result.as_ref().err().cloned();
        result
    }
}
impl<C: Configuration, R: Registers, T: Time> Drop for NativePlatform<C, R, T> {
    fn drop(&mut self) {
        if !self.retired {
            core::mem::forget(self.minimum.take());
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
            if let Some(value) = self.attachment.take() {
                core::mem::forget(value);
            }
            if let Some(value) = self.retention.take() {
                core::mem::forget(value);
            }
            core::mem::forget(self.irq_retirement.take());
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
            if let Some(value) = self.msi_route.take() {
                core::mem::forget(value);
            }
            for configuration in self.retiring_configurations.drain(..) {
                core::mem::forget(configuration);
            }
        }
    }
}
impl<C: Configuration, R: Registers, T: Time> Transport<NativePlatform<C, R, T>> {
    /// A callback requested process service; packet/HCI completion
    /// still comes exclusively from the coherent DMA completion rings.
    pub fn service_pending(&self) -> bool {
        self.platform
            .as_ref()
            .is_some_and(NativePlatform::service_pending)
    }
}
