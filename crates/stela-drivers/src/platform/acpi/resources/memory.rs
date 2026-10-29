// SPDX-License-Identifier: MIT
//! Memory resources from device `_CRS` templates and their reservations.
use super::*;
use crate::bus::mmio::owned::{
    PhysicalSpan, Resource as MmioResource, ResourceBacking, ResourceKind,
};
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::cell::RefCell;

/// Correlates one namespace inspection with its reservations. This is
/// identity only: native resource ownership still comes from MemoryBroker.
#[derive(Clone)]
pub(crate) struct DeviceIdentity(Arc<()>);
impl DeviceIdentity {
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// CPU-affine snapshot from the namespace. Inspection also checks `_STA`;
/// missing `_STA` means the specification default, rather than an invented grant.
pub struct DeviceResources<'a> {
    identity: DeviceIdentity,
    handle: Handle<'a>,
    path: String,
    descriptors: Vec<Descriptor>,
    dependencies: Vec<Handle<'a>>,
}
impl<'a> DeviceResources<'a> {
    pub fn inspect(handle: Handle<'a>) -> Result<Self, Error> {
        match handle.evaluate(Some("_STA"), &[]) {
            Err(super::super::Error(5)) => {}
            Ok(Some(Value::Integer(status))) if status & 0x0b == 0x0b => {}
            Ok(Some(Value::Integer(status))) => return Err(Error::Unavailable(status)),
            Ok(_) => return Err(Error::InvalidObject("_STA")),
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            identity: DeviceIdentity(Arc::new(())),
            handle,
            path: handle.path()?,
            descriptors: evaluate(handle, "_CRS")?,
            dependencies: super::dependencies(handle)?,
        })
    }
    pub fn handle(&self) -> Handle<'a> {
        self.handle
    }
    #[cfg(test)]
    pub(crate) fn identity(&self) -> DeviceIdentity {
        self.identity.clone()
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn descriptors(&self) -> &[Descriptor] {
        &self.descriptors
    }
    pub fn dependencies(&self) -> &[Handle<'a>] {
        &self.dependencies
    }
    /// Use ACPICA's real `_HID`/`_CID`/`_STA` matching and exact handle.
    pub fn matches_hid(&self, hid: &str) -> Result<bool, Error> {
        Ok(self.handle.session.devices(hid)?.contains(&self.handle))
    }
    /// Resource mutation or namespace replacement must not silently rebind a live
    /// mapping. Owners keep the old resource and report the changed namespace.
    pub fn revalidate(&self) -> Result<(), Error> {
        let current = Self::inspect(self.handle)?;
        if current.path != self.path
            || current.descriptors != self.descriptors
            || current.dependencies != self.dependencies
        {
            return Err(Error::ResourceChanged);
        }
        Ok(())
    }
}

struct Pin {
    identity: DeviceIdentity,
    parent: MmioResource,
    logical: PhysicalSpan,
    physical: PhysicalSpan,
    device: String,
    ordinal: usize,
}
struct Backing(Arc<Pin>);
/// Inspect the native parent when a mapping adapter validates
/// resource provenance. An unrecognized backing is never treated as a grant.
pub fn reservation_parent(resource: &MmioResource) -> Option<&MmioResource> {
    resource
        .backing()
        .downcast_ref::<Backing>()
        .map(|backing| &backing.0.parent)
}
// SAFETY: the original Resource keeps the exclusive native allocation
// and epoch. The broker admits only nonoverlapping subranges. This pin keeps its
// parent and reservation live through the final clone/mapping's drop.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.0.physical
    }
    fn kind(&self) -> ResourceKind {
        self.0.parent.kind()
    }
}

/// Firmware provenance joined to a native reservation, never an address
/// tuple or a caller-set admission flag. Clones pin the same reservation.
#[derive(Clone)]
pub struct MemoryReservation {
    pin: Arc<Pin>,
    resource: MmioResource,
}
impl MemoryReservation {
    /// The reservation `resource` was cut from, when a [`MemoryBroker`]
    /// reserved it: what a mount's `NativeServices::acpi_memory` hands back.
    pub fn of(resource: &MmioResource) -> Option<Self> {
        let backing = resource.backing().downcast_ref::<Backing>()?;
        Some(Self {
            pin: backing.0.clone(),
            resource: resource.clone(),
        })
    }
    pub fn resource(&self) -> &MmioResource {
        &self.resource
    }
    pub fn physical_span(&self) -> PhysicalSpan {
        self.pin.logical
    }
    pub fn device_path(&self) -> &str {
        &self.pin.device
    }
    pub fn ordinal(&self) -> usize {
        self.pin.ordinal
    }
    /// Match the exact immutable reservation snapshot to a still-live namespace.
    pub fn matches(&self, device: &DeviceResources<'_>) -> Result<(), Error> {
        if !self.pin.identity.same(&device.identity) {
            return Err(Error::ResourceChanged);
        }
        device.revalidate()?;
        let span = memory_span(device, self.pin.ordinal)?;
        if device.path != self.pin.device || span != self.pin.logical {
            return Err(Error::ResourceChanged);
        }
        Ok(())
    }
}

/// Suballocator of exclusive native MMIO root reservations. It is
/// CPU-affine, as native discovery and ACPICA handles are.
pub struct MemoryBroker {
    roots: Vec<MmioResource>,
    pins: RefCell<Vec<Weak<Pin>>>,
}
impl MemoryBroker {
    /// Import the real platform's already reserved device windows after firmware
    /// handoff. The original owners, their assignment epochs and exclusions stay
    /// kept. AML alone can never construct these root resources.
    ///
    /// # Safety
    /// This is the sole suballocator/admitter for every supplied root; no other
    /// holder of a root alias may map or operate subranges independently. The
    /// platform must have completed ExitBootServices and excluded RAM, firmware
    /// allocations, other drivers and unowned parent assignments, as required by
    /// ResourceBacking. It must keep firmware/OS lifecycle ownership for the
    /// epoch. No `_OSC` call, `_DEP` result or GPIO firmware-mutex rule is inferred.
    pub unsafe fn new(roots: Vec<MmioResource>) -> Result<Self, Error> {
        for (at, root) in roots.iter().enumerate() {
            if root.kind() != ResourceKind::Registers
                || roots[..at]
                    .iter()
                    .any(|other| overlaps(root.physical_span(), other.physical_span()))
            {
                return Err(Error::Conflict);
            }
        }
        Ok(Self {
            roots,
            pins: RefCell::new(Vec::new()),
        })
    }
    pub fn reserve(
        &self,
        device: &DeviceResources<'_>,
        ordinal: usize,
    ) -> Result<MemoryReservation, Error> {
        device.revalidate()?;
        let logical = memory_span(device, ordinal)?;
        let start = logical.start() & !4095;
        let end = logical
            .end()
            .checked_add(4095)
            .ok_or(Error::OutsideReservation)?
            & !4095;
        let physical =
            PhysicalSpan::new(start, end - start).map_err(|_| Error::OutsideReservation)?;
        let parent = self
            .roots
            .iter()
            .find(|root| contains(root.physical_span(), physical))
            .ok_or(Error::OutsideReservation)?;
        let mut pins = self.pins.try_borrow_mut().map_err(|_| Error::Conflict)?;
        pins.retain(|pin| pin.strong_count() != 0);
        if pins
            .iter()
            .filter_map(Weak::upgrade)
            .any(|pin| overlaps(pin.physical, physical))
        {
            return Err(Error::Conflict);
        }
        let pin = Arc::new(Pin {
            identity: device.identity.clone(),
            parent: parent.clone(),
            logical,
            physical,
            device: device.path.clone(),
            ordinal,
        });
        let resource = MmioResource::new(Box::new(Backing(pin.clone())));
        pins.push(Arc::downgrade(&pin));
        Ok(MemoryReservation { pin, resource })
    }
}
fn contains(outer: PhysicalSpan, inner: PhysicalSpan) -> bool {
    outer.start() <= inner.start() && inner.end() <= outer.end()
}
fn overlaps(a: PhysicalSpan, b: PhysicalSpan) -> bool {
    a.start() < b.end() && b.start() < a.end()
}
fn memory_span(device: &DeviceResources<'_>, ordinal: usize) -> Result<PhysicalSpan, Error> {
    let Some(Descriptor {
        resource: Resource::Address(address),
        ..
    }) = device.descriptors.get(ordinal)
    else {
        return Err(Error::Unassigned);
    };
    if address.space != Space::Memory
        || !address.consumer
        || address.subtractive
        || !address.minimum_fixed
        || !address.maximum_fixed
        || address.translation != 0
        || address.source.is_some()
    {
        return Err(Error::Unassigned);
    }
    let physical =
        PhysicalSpan::new(address.minimum, address.length).map_err(|_| Error::Unassigned)?;
    if physical.end().checked_sub(1) != Some(address.maximum) {
        return Err(Error::Unassigned);
    }
    Ok(physical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::acpi::{
        Mode, Session,
        tests::{TEST_SERIAL, reduced_hardware_fixture},
    };
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    struct Root {
        physical: PhysicalSpan,
        drops: Arc<AtomicUsize>,
    }
    // SAFETY: the authored native resource model reserves this disjoint interval
    // exclusively; each test owns the sole modeled platform and reservation.
    unsafe impl ResourceBacking for Root {
        fn physical_span(&self) -> PhysicalSpan {
            self.physical
        }
        fn kind(&self) -> ResourceKind {
            ResourceKind::Registers
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }
    fn root(bytes: u64, drops: Arc<AtomicUsize>) -> MmioResource {
        MmioResource::new(Box::new(Root {
            physical: PhysicalSpan::new(0x9000, bytes).unwrap(),
            drops,
        }))
    }
    #[test]
    fn actual_crs_subpage_reservation_pins_whole_owned_pages_through_last_mapping_resource() {
        let _serial = TEST_SERIAL.lock().unwrap();
        // SAFETY: OSL provider and singleton remain test-serialized.
        let session =
            unsafe { Session::start(reduced_hardware_fixture(&[]), Mode::InterpreterOnly) }
                .unwrap();
        let device = DeviceResources::inspect(session.handle("\\_SB.UCSI").unwrap()).unwrap();
        assert_eq!(device.dependencies.len(), 1);
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: this model root has one exclusive broker and no other mapper.
        let broker = unsafe { MemoryBroker::new(vec![root(4096, drops.clone())]) }.unwrap();
        let reservation = broker.reserve(&device, 0).unwrap();
        assert_eq!(
            reservation.physical_span(),
            PhysicalSpan::new(0x9000, 0x210).unwrap()
        );
        assert_eq!(
            reservation.resource().physical_span(),
            PhysicalSpan::new(0x9000, 4096).unwrap()
        );
        assert!(reservation_parent(reservation.resource()).is_some());
        reservation.matches(&device).unwrap();
        assert!(matches!(broker.reserve(&device, 0), Err(Error::Conflict)));
        let mapping_resource = reservation.resource().clone();
        drop(reservation);
        assert!(matches!(broker.reserve(&device, 0), Err(Error::Conflict)));
        drop(mapping_resource);
        let reservation = broker.reserve(&device, 0).unwrap();
        drop(broker);
        assert_eq!(drops.load(Ordering::Acquire), 0);
        drop(reservation);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        session.shutdown().unwrap();
    }
    #[test]
    fn crs_never_grants_unreserved_neighbor_pages_and_unknown_ordinals_refuse() {
        let _serial = TEST_SERIAL.lock().unwrap();
        // SAFETY: provider and singleton remain serialized by TEST_SERIAL.
        let session =
            unsafe { Session::start(reduced_hardware_fixture(&[]), Mode::InterpreterOnly) }
                .unwrap();
        let device = DeviceResources::inspect(session.handle("\\_SB.UCSI").unwrap()).unwrap();
        // SAFETY: exclusive authored root owns only its stated bytes; importing
        // it does not authorize this broker to expand its physical coverage.
        let broker =
            unsafe { MemoryBroker::new(vec![root(0x210, Arc::new(AtomicUsize::new(0)))]) }.unwrap();
        assert!(matches!(
            broker.reserve(&device, 0),
            Err(Error::OutsideReservation)
        ));
        assert!(matches!(broker.reserve(&device, 1), Err(Error::Unassigned)));
        drop(broker);
        session.shutdown().unwrap();
    }
}
