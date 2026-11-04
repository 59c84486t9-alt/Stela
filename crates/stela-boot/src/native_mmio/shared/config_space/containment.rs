//! Retain the original PCI fabric after disabling each captured function.
use super::*;
use alloc::rc::Rc;
use core::{any::Any, cell::RefCell, cmp::Reverse, fmt};
use stela_boot_core::ecam::topology;
use stela_drivers::{
    bus::pci::{
        ConfigEffect, ConfigError, ConfigFailure,
        owned::{
            PreparedConfig, UnpublishedConfig,
            grant::{
                CompletionCheck, ConfigCustody, ConfigEpoch, ConfigOperation, Operation,
                PrepublicationCustody, PrepublicationGrant,
            },
        },
        requester::{ClaimError, containment::Plan, wait_for_pending_transactions},
    },
    sync::{FaultState, FirstFault},
};

/// The captured native fabric with PCI command, interrupt and requester
/// controls contained and its original writable maps retired.
pub(crate) struct ContainedPci<'a> {
    source: &'a Source,
    functions: usize,
}

impl<'a> ContainedPci<'a> {
    pub(crate) fn source(&self) -> &'a Source {
        self.source
    }

    pub(crate) fn functions(&self) -> usize {
        self.functions
    }

    /// Compare firmware's framebuffer association with the same parked
    /// function and its current BAR. This grants no reset or scanout access.
    ///
    /// # Safety
    /// The caller keeps the original configuration writers excluded.
    pub(crate) unsafe fn check_framebuffer(
        &self,
        source: crate::pci_io::FramebufferSource,
    ) -> Result<(), Error> {
        // SAFETY: the original source and its configuration exclusion are kept.
        unsafe {
            self.source.with_config_inventory(|_, reader| {
                for (offset, expected) in source.bar.words() {
                    let observed = reader.read32(source.address, offset)?;
                    if offset < 0x10 {
                        self.check_observation(source.address, offset, observed)?;
                    }
                    if expected != observed {
                        return Err(Error::InvalidPlatformReply);
                    }
                }
                Ok(())
            })
        }?;
        self.source
            .verified_framebuffer
            .set(source)
            .map_err(|_| Error::Busy)
    }

    pub(crate) fn check_observation(
        &self,
        address: Address,
        offset: u16,
        value: u32,
    ) -> Result<(), Error> {
        let cohort = self.source.pci_slots.0.borrow();
        let Cohort::Parked(fabric) = &*cohort else {
            return Err(Error::Unavailable);
        };
        let index = fabric
            .slots
            .binary_search_by_key(&address, |slot| slot.address)
            .map_err(|_| Error::OutsideResource)?;
        if fabric.slots[index].header.word(offset) != Some(value) {
            return Err(Error::InvalidPlatformReply);
        }
        Ok(())
    }

    /// Observe every parked function through the same read-only census.
    pub(crate) fn check_stopped(
        &self,
        reader: &mut ConfigInventory<'_>,
    ) -> Result<(), ContainmentError> {
        if !core::ptr::eq(self.source, reader.source) {
            return Err(Error::InvalidPlatformReply.into());
        }
        let cohort = self.source.pci_slots.0.borrow();
        let Cohort::Parked(fabric) = &*cohort else {
            return Err(Error::Unavailable.into());
        };
        for slot in &fabric.slots {
            slot.header
                .verify(|offset| reader.read32(slot.address, offset).map_err(mapping_error))
                .and_then(|()| {
                    slot.plan.check_disabled(|offset| {
                        reader
                            .read(slot.address, offset, 2)
                            .map(|value| value as u16)
                            .map_err(mapping_error)
                    })
                })
                .and_then(|()| {
                    if slot.header.bridge.is_some() {
                        let prepared = slot
                            .configuration
                            .as_ref()
                            .ok_or_else(|| mapping_error(Error::Unavailable))?;
                        prepared.check_bridge_routing(|offset, width| {
                            reader
                                .read(slot.address, offset, width)
                                .map_err(mapping_error)
                        })?;
                    }
                    Ok(())
                })
                .map_err(|error| ContainmentError::from(error).at(slot.address))?;
        }
        Ok(())
    }

    /// Reopen a read-only view after the remapping units have drained.
    ///
    /// # Safety
    /// The original source still excludes every configuration and topology writer.
    pub(crate) unsafe fn recheck_stopped(&self) -> Result<(), ContainmentError> {
        // SAFETY: the caller retains the original exclusive census ownership.
        unsafe {
            self.source
                .with_config_inventory(|_, reader| self.check_stopped(reader))
        }
    }
}

#[derive(Debug)]
pub(crate) struct ContainmentError {
    address: Option<Address>,
    cause: Cause,
    effect: ConfigEffect,
}

#[derive(Debug)]
enum Cause {
    Claim(ClaimError),
    Topology(topology::Error),
}

impl fmt::Display for ContainmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(address) = self.address {
            write!(f, "{address} ")?;
        }
        match self.cause {
            Cause::Claim(cause) => write!(f, "{cause:?} ({:?})", self.effect),
            Cause::Topology(cause) => write!(f, "PCI topology {cause:?}"),
        }
    }
}

impl From<ClaimError> for ContainmentError {
    fn from(cause: ClaimError) -> Self {
        let effect = match cause {
            ClaimError::Config(error) => error.effect,
            _ => ConfigEffect::None,
        };
        Self {
            address: None,
            cause: Cause::Claim(cause),
            effect,
        }
    }
}

impl From<topology::Error> for ContainmentError {
    fn from(cause: topology::Error) -> Self {
        Self {
            address: None,
            cause: Cause::Topology(cause),
            effect: ConfigEffect::None,
        }
    }
}

impl From<Error> for ContainmentError {
    fn from(error: Error) -> Self {
        ClaimError::Mapping(error).into()
    }
}

impl From<ConfigError> for ContainmentError {
    fn from(error: ConfigError) -> Self {
        ClaimError::Config(error).into()
    }
}

impl ContainmentError {
    fn at(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }
}

struct Slot {
    address: Address,
    configuration: Option<PreparedConfig<PrepublicationGrant>>,
    header: Header,
    plan: Rc<Plan>,
    ancestor: Parent,
}

#[derive(Default)]
struct Fabric {
    roots: Vec<Option<Assignment<RootBus>>>,
    slots: Vec<Slot>,
}

enum Cohort {
    Unclaimed,
    Incomplete(Fabric),
    Parked(Fabric),
}

struct RootBus {
    _descriptor: &'static RootWindow,
    platform: Arc<Platform>,
    aperture: Parent,
}

// SAFETY: the descriptor comes from the retained capture. Each unique root
// bus assignment is a child of that capture's aperture owner.
unsafe impl PhysicalAssignment for RootBus {
    fn parent(&self) -> Option<&Parent> {
        Some(&self.aperture)
    }

    fn check_control(&self) -> Result<(), assignment::Error> {
        self.platform
            .check_mapping_control()
            .map_err(|_| assignment::Error::Context)
    }
}

pub(in crate::native_mmio::shared) struct PciSlots(RefCell<Cohort>);

impl PciSlots {
    pub(in crate::native_mmio::shared) const fn new() -> Self {
        Self(RefCell::new(Cohort::Unclaimed))
    }
}

#[derive(Clone, Copy)]
struct Header {
    identity: u32,
    class_revision: u32,
    layout: u32,
    bridge: Option<u32>,
}

impl Header {
    fn word(self, offset: u16) -> Option<u32> {
        match offset {
            0 => Some(self.identity),
            8 => Some(self.class_revision),
            0x0c => Some(self.layout),
            0x18 => self.bridge,
            _ => None,
        }
    }

    fn verify(
        self,
        mut read: impl FnMut(u16) -> Result<u32, ConfigError>,
    ) -> Result<(), ConfigError> {
        for offset in [0, 8, 0x0c, 0x18] {
            let Some(expected) = self.word(offset) else {
                continue;
            };
            let observed = read(offset)?;
            if observed != expected {
                return Err(ConfigError::before_effect(ConfigFailure::Readback {
                    offset,
                    width: 4,
                    expected,
                    observed,
                }));
            }
        }
        Ok(())
    }
}

struct Input {
    address: Address,
    window: EcamWindow,
    span: PhysicalSpan,
    header: Header,
    plan: Rc<Plan>,
}

impl Input {
    fn observe(
        reader: &mut ConfigInventory<'_>,
        address: Address,
    ) -> Result<Option<Self>, ContainmentError> {
        let identity = reader.read32(address, 0)?;
        match identity as u16 {
            u16::MAX => return Ok(None),
            0 | 1 => return Err(Error::InvalidPlatformReply.into()),
            _ => {}
        }
        let class_revision = reader.read32(address, 8)?;
        if class_revision == u32::MAX {
            return Err(Error::InvalidPlatformReply.into());
        }
        let layout = reader.read32(address, 0x0c)?;
        let bridge = if reader.header_type(layout)? == 1 {
            if class_revision >> 16 != 0x0604 {
                return Err(Error::InvalidPlatformReply.into());
            }
            let buses = reader.read32(address, 0x18)?;
            reader.check_bridge(address, buses)?;
            Some(buses)
        } else {
            None
        };
        let plan = Plan::read(|offset, width| {
            reader
                .read(address, offset, width)
                .map_err(ClaimError::Mapping)
        })?;
        let (window, span) = reader
            .geometry
            .function(address, reader.source.platform.wire().roots())?;
        Ok(Some(Self {
            address,
            window,
            span,
            header: Header {
                identity,
                class_revision,
                layout,
                bridge,
            },
            plan: Rc::new(plan),
        }))
    }
}

fn census(
    windows: &[EcamWindow],
    reader: &mut ConfigInventory<'_>,
) -> Result<Vec<Input>, ContainmentError> {
    let mut inputs = Vec::new();
    for window in windows {
        for bus in window.start_bus..=window.end_bus {
            for device in 0..32 {
                for function in 0..8 {
                    let address = Address {
                        segment: window.segment,
                        bus,
                        device,
                        function,
                    };
                    if let Some(input) =
                        Input::observe(reader, address).map_err(|error| error.at(address))?
                    {
                        inputs.try_reserve(1).map_err(|_| Error::Exhausted)?;
                        inputs.push(input);
                    }
                }
            }
        }
    }
    Ok(inputs)
}

#[derive(Clone)]
struct Epoch {
    platform: Arc<Platform>,
    original: Retention<Reservation>,
}

impl Epoch {
    fn context(&self) -> Result<(), Error> {
        self.platform.check_mapping_control()
    }
}

// SAFETY: this projection only keeps the original aperture and slot count.
// It creates no mapping or configuration access.
unsafe impl ConfigEpoch for Epoch {
    fn check(&self) -> Result<(), Error> {
        self.context()?;
        self.original.check_admission().map_err(Error::Assignment)
    }

    fn retain(&self) -> Result<Box<dyn ConfigEpoch>, Error> {
        self.check()?;
        Ok(Box::new(self.clone()))
    }

    fn same_epoch(&self, other: &dyn ConfigEpoch) -> Result<bool, Error> {
        self.check()?;
        other.check()?;
        Ok(other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.original.same_assignment(&other.original)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Completion {
    epoch: Epoch,
    fault: FirstFault<ConfigError>,
}

fn mapping_error(error: Error) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

// SAFETY: the preowned validator checks the original aperture in the
// accepting context and latches its first failure without reentry.
unsafe impl CompletionCheck for Completion {
    fn postvalidate(&self) -> Result<(), ConfigError> {
        let result = self.epoch.context().map_err(mapping_error);
        if let Err(error) = result {
            self.fault.latch(error);
        }
        result
    }

    fn failure(&self) -> FaultState<ConfigError> {
        self.fault.observe()
    }
}

struct SlotCustody {
    _original: Assignment<Reservation>,
    resource: Resource,
    completion: Arc<Completion>,
    address: Address,
    window: EcamWindow,
    plan: Rc<Plan>,
}

// SAFETY: the census issues one exact slot from the original aperture
// reservation, shared by its resource backing and configuration counts.
unsafe impl ConfigCustody for SlotCustody {
    fn address(&self) -> Address {
        self.address
    }

    fn window(&self) -> EcamWindow {
        self.window
    }

    fn resource(&self) -> &Resource {
        &self.resource
    }

    fn begin(&self, operation: Operation) -> Result<ConfigOperation, ConfigError> {
        self.completion.epoch.context().map_err(mapping_error)?;
        if let Operation::Write {
            offset,
            width,
            value,
        } = operation
            && !self.plan.permits(offset, width, value)
        {
            return Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ));
        }
        match self.completion.failure() {
            FaultState::Ready(error) => return Err(error),
            FaultState::Publishing => {
                return Err(ConfigError::before_effect(ConfigFailure::FaultPublishing));
            }
            FaultState::Empty => {}
        }
        let count = self
            .completion
            .epoch
            .original
            .begin_use(UseKind::Configuration)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Ownership(error)))?;
        // SAFETY: the accepted operation retains the exact slot and validator.
        Ok(unsafe { ConfigOperation::new(count.erase(), self.completion.clone()) })
    }

    fn retirement_context(&self) -> Result<(), Error> {
        self.completion.epoch.context()
    }

    fn retain_epoch(&self) -> Result<Box<dyn ConfigEpoch>, Error> {
        self.completion.epoch.retain()
    }
}

// SAFETY: the original exclusive source issues the slot once. Its only
// writes are the exact disabling values planned from the complete census.
unsafe impl PrepublicationCustody for SlotCustody {}

impl Source {
    /// Contain the captured fabric once and park each original configuration.
    /// The return value qualifies PCI-level controls for remapper takeover.
    ///
    /// # Safety
    /// Firmware and APs are stopped. The caller keeps all captured buses and
    /// their topology exclusive, including reset and hotplug.
    pub(crate) unsafe fn contain_pci(
        &self,
        tsc_hz: u64,
    ) -> Result<ContainedPci<'_>, ContainmentError> {
        {
            let mut cohort = self.pci_slots.0.borrow_mut();
            if !matches!(*cohort, Cohort::Unclaimed) {
                return Err(Error::Busy.into());
            }
            *cohort = Cohort::Incomplete(Fabric::default());
        }
        // SAFETY: the caller keeps the complete captured topology exclusive.
        // with_config_inventory retires the last read-only map before return.
        let inputs = unsafe { self.with_config_inventory(census) }?;
        let fabric = self.prepare_fabric(inputs)?;
        let count = fabric.slots.len();
        let mut order = Vec::new();
        order
            .try_reserve_exact(count)
            .map_err(|_| Error::Exhausted)?;
        order.extend(0..count);
        // Stop endpoints while their bridges still forward. Stop downstream
        // bridges before their upstream parents.
        order.sort_unstable_by_key(|&index| {
            let slot = &fabric.slots[index];
            (slot.header.bridge.is_some(), Reverse(slot.address.bus))
        });
        *self.pci_slots.0.borrow_mut() = Cohort::Incomplete(fabric);

        for index in order {
            let (address, prepared, header, plan) = {
                let mut cohort = self.pci_slots.0.borrow_mut();
                let Cohort::Incomplete(fabric) = &mut *cohort else {
                    unreachable!("exclusive containment owns the incomplete fabric");
                };
                let slot = &mut fabric.slots[index];
                (
                    slot.address,
                    slot.configuration
                        .take()
                        .expect("one prepared configuration"),
                    slot.header,
                    slot.plan.clone(),
                )
            };
            let parked = self
                .contain_slot(prepared, header, &plan, tsc_hz)
                .map_err(|error| error.at(address))?;
            let mut cohort = self.pci_slots.0.borrow_mut();
            let Cohort::Incomplete(fabric) = &mut *cohort else {
                unreachable!("exclusive containment owns the incomplete fabric");
            };
            fabric.slots[index].configuration = Some(parked);
        }
        let mut cohort = self.pci_slots.0.borrow_mut();
        let Cohort::Incomplete(fabric) = &mut *cohort else {
            unreachable!("exclusive containment owns the incomplete fabric");
        };
        *cohort = Cohort::Parked(core::mem::take(fabric));
        Ok(ContainedPci {
            source: self,
            functions: count,
        })
    }

    fn prepare_fabric(&self, mut inputs: Vec<Input>) -> Result<Fabric, ContainmentError> {
        let roots = self.platform.wire().roots();
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(inputs.len())
            .map_err(|_| Error::Exhausted)?;
        observed.extend(inputs.iter().map(|input| topology::Function {
            address: input.address,
            bridge_buses: input.header.bridge,
        }));
        let parents = topology::resolve(roots, &observed)?;
        inputs.sort_unstable_by_key(|input| input.address);

        let mut fabric = Fabric::default();
        fabric
            .roots
            .try_reserve_exact(roots.len())
            .map_err(|_| Error::Exhausted)?;
        fabric
            .slots
            .try_reserve_exact(inputs.len())
            .map_err(|_| Error::Exhausted)?;
        for descriptor in roots {
            let assignment = (descriptor.space == 2).then(|| {
                Assignment::from_owned(RootBus {
                    _descriptor: descriptor,
                    platform: self.platform.clone(),
                    aperture: self.aperture.parent(),
                })
            });
            fabric.roots.push(assignment);
        }
        // Secondary bus numbers exceed their upstream bus. BDF order keeps
        // each real bridge assignment before any of its children.
        for ((address, parent), input) in parents.into_iter().zip(inputs) {
            debug_assert_eq!(address, input.address);
            let parent = match parent {
                topology::Parent::Root(index) => fabric.roots[index]
                    .as_ref()
                    .expect("resolved root grant")
                    .parent(),
                topology::Parent::Bridge(bridge) => {
                    let at = fabric
                        .slots
                        .binary_search_by_key(&bridge, |slot| slot.address)
                        .expect("upstream slot is ordered before its children");
                    fabric.slots[at].ancestor.clone()
                }
            };
            let slot = self
                .prepare_slot(input, parent)
                .map_err(|error| error.at(address))?;
            fabric.slots.push(slot);
        }
        Ok(fabric)
    }

    fn prepare_slot(&self, input: Input, parent: Parent) -> Result<Slot, ContainmentError> {
        let (resource, original) =
            self.reservation_under(input.span, ResourceKind::Configuration, parent)?;
        let ancestor = original.parent();
        let close = original.admission_close();
        let owner = Box::new(SlotCustody {
            completion: Arc::new(Completion {
                epoch: Epoch {
                    platform: self.platform.clone(),
                    original: original.retain(),
                },
                fault: FirstFault::new(),
            }),
            _original: original,
            resource,
            address: input.address,
            window: input.window,
            plan: input.plan.clone(),
        });
        // SAFETY: the same affine slot backs the bounded operation and map.
        let grant = unsafe { PrepublicationGrant::from_boxed(owner, close) };
        Ok(Slot {
            address: input.address,
            configuration: Some(UnpublishedConfig::prepare(grant)),
            header: input.header,
            plan: input.plan,
            ancestor,
        })
    }

    fn contain_slot(
        &self,
        prepared: PreparedConfig<PrepublicationGrant>,
        header: Header,
        plan: &Plan,
        tsc_hz: u64,
    ) -> Result<PreparedConfig<PrepublicationGrant>, ContainmentError> {
        let mapping = self.authority.map(
            prepared.configuration_resource().clone(),
            0,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )?;
        let mut config = prepared
            .attach(mapping)
            .map_err(|(error, _original)| error)?;
        header.verify(|offset| config.try_read32(offset))?;
        let effect = plan.apply(&mut config)?;
        let acknowledge = (|| -> Result<(), ClaimError> {
            let started = crate::apic::rdtsc();
            let limit = (tsc_hz / 1_000 * 64).max(1);
            wait_for_pending_transactions(&config, || {
                crate::apic::rdtsc().wrapping_sub(started) >= limit
            })?;
            plan.check_disabled(|offset| config.try_read16(offset))?;
            config.seal_bus_master()?;
            if header.bridge.is_some() {
                config.seal_bus_routing()?;
            }
            header.verify(|offset| config.try_read32(offset))?;
            Ok(())
        })();
        acknowledge.map_err(|cause| ContainmentError {
            address: None,
            cause: Cause::Claim(cause),
            effect,
        })?;
        // SAFETY: the only accesses were synchronous and bounded, with no
        // escaped aliases. Source keeps this original decode and assignment.
        unsafe { config.park() }.map_err(|(error, _original)| ContainmentError {
            address: None,
            cause: Cause::Claim(ClaimError::Mapping(error)),
            effect,
        })
    }
}
