//! Guest-physical MMIO routing for the Apple device models.
//!
//! The system engine decodes a guest load or store that hits device memory,
//! then calls [`Bus::read`] or [`Bus::write`] with the guest PA, the access
//! width and an [`Access`] carrying the accessing CPU, the system counter value
//! and an interrupt sink. Any refusal is returned unchanged; the engine must
//! stop or fault rather than invent a value.
use super::interrupt::{CpuIndex, InterruptSink};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
use core::any::Any;

mod container;
pub(crate) use container::SharedView;

/// Access width in bytes. Apple MMIO is little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Byte = 1,
    Half = 2,
    Word = 4,
    Double = 8,
}
impl Width {
    pub const fn bytes(self) -> u64 {
        self as u64
    }
    pub const fn from_bytes(bytes: u64) -> Option<Self> {
        match bytes {
            1 => Some(Self::Byte),
            2 => Some(Self::Half),
            4 => Some(Self::Word),
            8 => Some(Self::Double),
            _ => None,
        }
    }
    /// All-ones value of this width.
    pub const fn mask(self) -> u64 {
        match self {
            Self::Double => u64::MAX,
            width => (1 << (width.bytes() * 8)) - 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
}

/// A refused device access. Earlier device, wire or transition effects may
/// already be retained by their owners; this error alone proves no byte prefix
/// and grants no replay or source-retirement authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    /// No device is mapped at this guest PA.
    Unmapped { address: u64, width: Width },
    /// The access is not naturally aligned.
    Misaligned { address: u64, width: Width },
    /// A device refused the access. `offset` is device-relative.
    Unsupported {
        device: &'static str,
        offset: u64,
        width: Width,
        direction: Direction,
        reason: &'static str,
    },
}

/// What a guest request does to the whole machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The machine resets and boots again (a watchdog bite, the SMC's
    /// restart command).
    Restart,
    /// The machine powers off (the SMC's standby command).
    PowerOff,
    /// The machine cannot continue (a model reached a state it cannot run
    /// in); neither a reset nor a power-off was asked for.
    Halt,
}

/// A guest request to reset or stop the machine, surfaced instead of acting
/// on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetRequest {
    pub device: &'static str,
    pub transition: Transition,
    pub reason: &'static str,
    /// System counter value at which the request took effect.
    pub at: u64,
}

/// Inputs and outputs of one device access or time advance.
pub struct Access<'a> {
    /// The CPU performing the access; selects per-CPU register views.
    pub cpu: CpuIndex,
    /// Current system counter value in 24 MHz ticks (`counter::SystemCounter`).
    pub now: u64,
    pub interrupts: &'a mut dyn InterruptSink,
    reset: Option<ResetRequest>,
}
impl<'a> Access<'a> {
    pub fn new(cpu: CpuIndex, now: u64, interrupts: &'a mut dyn InterruptSink) -> Self {
        Self {
            cpu,
            now,
            interrupts,
            reset: None,
        }
    }
    /// The guest asked for a machine reset.
    pub fn request_reset(&mut self, device: &'static str, reason: &'static str) {
        self.request_transition(device, Transition::Restart, reason);
    }
    /// The guest's request takes the whole machine through `transition`;
    /// the first request of an access wins.
    pub fn request_transition(
        &mut self,
        device: &'static str,
        transition: Transition,
        reason: &'static str,
    ) {
        self.reset.get_or_insert(ResetRequest {
            device,
            transition,
            reason,
            at: self.now,
        });
    }
    /// The first reset requested during this access, if any. The engine must
    /// stop the guest and report it; the models never touch host reset paths.
    pub fn reset_request(&self) -> Option<ResetRequest> {
        self.reset
    }
}

/// Effective supply, clock, DMA-quiesce and reset inputs of one actual native
/// device. Retention describes that device's declared ordinary-state contract,
/// not a request to reconstruct software configuration after a destructive edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleState {
    pub powered: bool,
    pub clocked: bool,
    pub quiesced: bool,
    pub reset: bool,
    pub retention: bool,
}

/// An actual native device's complete lifecycle boundary. Capability does not
/// imply every proposed state is qualified. The machine checks every affected
/// device without side effects before acknowledging the controller request,
/// then commits the checked state before any subsequent client activity.
/// A commit must not fail or generate synthetic completion of canceled work.
pub trait Lifecycle {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str>;
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>);
}

/// A memory-mapped device model. Offsets are relative to the start of the
/// device's address space as placed by [`Bus::map`]. Values occupy the low
/// `width` bytes; implementations refuse widths their registers do not have.
pub trait MmioDevice: Any {
    /// Type-erased capability: e.g. a UART keeps a generic console sink, so
    /// lifecycle dispatch must not require downcasting to its concrete type.
    /// Returning None keeps missing lifecycle support explicit.
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        None
    }
    fn name(&self) -> &'static str;
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError>;
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError>;
    /// Re-evaluates time-driven state at `access.now` and returns the next
    /// counter value at which this device must be advanced again, if any.
    fn advance(&mut self, _access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        Ok(None)
    }
}

/// Builds the refusal for one device register.
pub(crate) fn refuse(
    device: &'static str,
    offset: u64,
    width: Width,
    direction: Direction,
    reason: &'static str,
) -> MmioError {
    MmioError::Unsupported {
        device,
        offset,
        width,
        direction,
        reason,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceId(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    Empty,
    Overflow,
    Overlap {
        existing: DeviceId,
    },
    UnknownDevice,
    Allocation,
    ProposedOverlap,
    /// An explicit shared view lacks complete, matching existing ownership.
    InvalidSharedView,
}

#[derive(Debug, Clone, Copy)]
struct Region {
    start: u64,
    /// Exclusive.
    end: u64,
    device: DeviceId,
    device_offset: u64,
}

/// Routes guest PA ranges to devices. One device may own several ranges, for
/// example the AIC2 core and event blocks, which are separate DeviceTree `reg`
/// entries.
#[derive(Default)]
pub struct Bus {
    devices: Vec<Box<dyn MmioDevice>>,
    /// Sorted by `start`, nonoverlapping.
    regions: Vec<Region>,
}
impl Bus {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, device: Box<dyn MmioDevice>) -> DeviceId {
        self.devices.push(device);
        DeviceId(self.devices.len() - 1)
    }
    /// Install one actual device and all its ranges atomically. Validate both
    /// existing and proposed ownership before publishing any route or device.
    /// Each binding is (guest PA, length, device offset).
    pub fn install(
        &mut self,
        device: Box<dyn MmioDevice>,
        bindings: &[(u64, u64, u64)],
    ) -> Result<DeviceId, MapError> {
        if bindings.is_empty() {
            return Err(MapError::Empty);
        }
        let id = DeviceId(self.devices.len());
        let mut proposed = Vec::new();
        proposed
            .try_reserve_exact(bindings.len())
            .map_err(|_| MapError::Allocation)?;
        for &(start, len, device_offset) in bindings {
            if len == 0 {
                return Err(MapError::Empty);
            }
            let end = start.checked_add(len).ok_or(MapError::Overflow)?;
            device_offset.checked_add(len).ok_or(MapError::Overflow)?;
            let overlaps = |region: &Region| region.start < end && start < region.end;
            if let Some(region) = self.regions.iter().find(|region| overlaps(region)) {
                return Err(MapError::Overlap {
                    existing: region.device,
                });
            }
            if proposed.iter().any(overlaps) {
                return Err(MapError::ProposedOverlap);
            }
            proposed.push(Region {
                start,
                end,
                device: id,
                device_offset,
            });
        }
        // Both allocations precede publication. Capacity changes on failure do
        // not add observable routes or a device with partially mapped state.
        self.devices
            .try_reserve(1)
            .map_err(|_| MapError::Allocation)?;
        self.regions
            .try_reserve(proposed.len())
            .map_err(|_| MapError::Allocation)?;
        self.devices.push(device);
        self.regions.extend(proposed);
        self.regions.sort_unstable_by_key(|region| region.start);
        Ok(id)
    }
    /// Maps guest PAs `[start, start + len)` to device offsets
    /// `[device_offset, device_offset + len)`.
    pub fn map(
        &mut self,
        device: DeviceId,
        start: u64,
        len: u64,
        device_offset: u64,
    ) -> Result<(), MapError> {
        if device.0 >= self.devices.len() {
            return Err(MapError::UnknownDevice);
        }
        if len == 0 {
            return Err(MapError::Empty);
        }
        let end = start.checked_add(len).ok_or(MapError::Overflow)?;
        device_offset.checked_add(len).ok_or(MapError::Overflow)?;
        let index = self.free_index(start, end)?;
        self.regions.insert(
            index,
            Region {
                start,
                end,
                device,
                device_offset,
            },
        );
        Ok(())
    }
    /// Pure whole-range preflight for a new explicitly owned resource. It
    /// reserves nothing and publishes no model or aperture. Callers retain
    /// exclusive Bus access through their complete batch publication.
    pub fn check_free(&self, start: u64, len: u64) -> Result<(), MapError> {
        if len == 0 {
            return Err(MapError::Empty);
        }
        let end = start.checked_add(len).ok_or(MapError::Overflow)?;
        self.free_index(start, end).map(|_| ())
    }
    fn free_index(&self, start: u64, end: u64) -> Result<usize, MapError> {
        let index = self.regions.partition_point(|region| region.start < start);
        let overlaps = |region: &Region| region.start < end && start < region.end;
        for neighbor in [index.checked_sub(1), Some(index)].into_iter().flatten() {
            if let Some(region) = self.regions.get(neighbor).filter(|region| overlaps(region)) {
                return Err(MapError::Overlap {
                    existing: region.device,
                });
            }
        }
        Ok(index)
    }

    /// Maps the parts of guest PAs `[start, start + len)` that no device
    /// owns yet, each at its own offset from `device_offset`: a window whose
    /// span the DeviceTree shares with smaller register banks (the `sgx`
    /// window around `gfx-asc` and a fabric bridge) owns only what they leave.
    /// A window with no free byte refuses.
    pub fn map_gaps(
        &mut self,
        device: DeviceId,
        start: u64,
        len: u64,
        device_offset: u64,
    ) -> Result<(), MapError> {
        if len == 0 {
            return Err(MapError::Empty);
        }
        let end = start.checked_add(len).ok_or(MapError::Overflow)?;
        device_offset.checked_add(len).ok_or(MapError::Overflow)?;
        let owned: Vec<(u64, u64, DeviceId)> = self
            .regions
            .iter()
            .filter(|region| region.start < end && start < region.end)
            .map(|region| (region.start.max(start), region.end.min(end), region.device))
            .collect();
        let mut cursor = start;
        let mut gaps = Vec::new();
        for &(first, last, _) in &owned {
            if first > cursor {
                gaps.push((cursor, first));
            }
            cursor = cursor.max(last);
        }
        if cursor < end {
            gaps.push((cursor, end));
        }
        if gaps.is_empty() {
            return Err(MapError::Overlap {
                existing: owned[0].2,
            });
        }
        for (first, last) in gaps {
            self.map(device, first, last - first, device_offset + (first - start))?;
        }
        Ok(())
    }
    /// The device and device offset for a complete guest PA access. Mounts
    /// may inspect ownership without reading or changing a register.
    pub(crate) fn route(&self, address: u64, width: Width) -> Result<(DeviceId, u64), MmioError> {
        if !address.is_multiple_of(width.bytes()) {
            return Err(MmioError::Misaligned { address, width });
        }
        let index = self
            .regions
            .partition_point(|region| region.start <= address);
        let region = index
            .checked_sub(1)
            .map(|index| self.regions[index])
            .filter(|region| {
                address
                    .checked_add(width.bytes())
                    .is_some_and(|end| end <= region.end)
            })
            .ok_or(MmioError::Unmapped { address, width })?;
        Ok((
            region.device,
            region.device_offset + (address - region.start),
        ))
    }
    pub fn read(
        &mut self,
        address: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let (device, offset) = self.route(address, width)?;
        let value = self.devices[device.0].read(offset, width, access)?;
        debug_assert_eq!(value & !width.mask(), 0, "device read wider than access");
        Ok(value & width.mask())
    }
    pub fn write(
        &mut self,
        address: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let (device, offset) = self.route(address, width)?;
        self.devices[device.0].write(offset, width, value & width.mask(), access)
    }
    /// Advances every device and returns the earliest next deadline.
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        let mut next: Option<u64> = None;
        for device in &mut self.devices {
            if let Some(deadline) = device.advance(access)? {
                next = Some(next.map_or(deadline, |next| next.min(deadline)));
            }
        }
        Ok(next)
    }
    /// A model's state, for engine wiring such as the AMCC's write lock.
    pub fn lifecycle(&mut self, device: DeviceId) -> Option<&mut dyn Lifecycle> {
        self.devices.get_mut(device.0)?.lifecycle()
    }

    pub fn device<T: MmioDevice>(&self, device: DeviceId) -> Option<&T> {
        let device: &dyn Any = self.devices.get(device.0)?.as_ref();
        device.downcast_ref::<T>()
    }
    /// Typed access to two different models at once, for wiring between
    /// them such as a DMA master and its IOMMU.
    pub fn pair_mut<A: MmioDevice, B: MmioDevice>(
        &mut self,
        a: DeviceId,
        b: DeviceId,
    ) -> Option<(&mut A, &mut B)> {
        let [a, b] = self.devices.get_disjoint_mut([a.0, b.0]).ok()?;
        let a: &mut dyn Any = a.as_mut();
        let b: &mut dyn Any = b.as_mut();
        Some((a.downcast_mut::<A>()?, b.downcast_mut::<B>()?))
    }
    /// Typed access to a model, for engine wiring such as AIC inputs, UART
    /// receive data or fast-IPI system registers.
    pub fn device_mut<T: MmioDevice>(&mut self, device: DeviceId) -> Option<&mut T> {
        let device: &mut dyn Any = self.devices.get_mut(device.0)?.as_mut();
        device.downcast_mut::<T>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    /// A 16-byte scratch register file, for routing tests only.
    struct Scratch([u8; 16]);
    impl MmioDevice for Scratch {
        fn name(&self) -> &'static str {
            "scratch"
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            _: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            let mut bytes = [0; 8];
            let range = offset as usize..(offset + width.bytes()) as usize;
            bytes[..range.len()].copy_from_slice(&self.0[range]);
            Ok(u64::from_le_bytes(bytes))
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            value: u64,
            _: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            let range = offset as usize..(offset + width.bytes()) as usize;
            let len = range.len();
            self.0[range].copy_from_slice(&value.to_le_bytes()[..len]);
            Ok(())
        }
    }

    #[test]
    fn routing_requires_a_nonwrapping_complete_access_without_register_effects() {
        let mut bus = Bus::new();
        let bank = bus.add(Box::new(Scratch([0; 16])));
        bus.map(bank, 0x1000, 16, 0).unwrap();
        assert_eq!(bus.route(0x1008, Width::Double), Ok((bank, 8)));
        for address in [0x1010, u64::MAX - 7] {
            assert_eq!(
                bus.route(address, Width::Double),
                Err(MmioError::Unmapped {
                    address,
                    width: Width::Double,
                })
            );
        }
    }

    #[test]
    fn install_validates_all_ranges_before_publishing_any_owner() {
        let mut bus = Bus::new();
        let original = bus
            .install(Box::new(Scratch([0; 16])), &[(0x2000, 16, 0)])
            .unwrap();
        for bindings in [
            vec![(0x1000, 16, 0), (0x2008, 16, 16)],
            vec![(0x1000, 16, 0), (0x1008, 16, 16)],
            vec![(0x1000, 16, 0), (u64::MAX - 7, 16, 0)],
            vec![(0x1000, 16, 0), (0x3000, 16, u64::MAX - 7)],
            vec![(0x1000, 16, 0), (0x3000, 0, 0)],
            vec![],
        ] {
            assert!(bus.install(Box::new(Scratch([0; 16])), &bindings).is_err());
            assert_eq!(bus.devices.len(), 1);
            assert_eq!(bus.regions.len(), 1);
            assert!(bus.route(0x1000, Width::Word).is_err());
            assert_eq!(bus.route(0x2000, Width::Word), Ok((original, 0)));
        }
        assert_eq!(
            bus.install(
                Box::new(Scratch([0; 16])),
                &[(0x1000, 16, 0), (0x1008, 16, 16)]
            ),
            Err(MapError::ProposedOverlap)
        );
        let added = bus
            .install(
                Box::new(Scratch([0; 16])),
                &[(0x3000, 8, 8), (0x1000, 8, 0)],
            )
            .unwrap();
        assert_eq!(bus.route(0x3004, Width::Word), Ok((added, 12)));
        assert_eq!(bus.route(0x1000, Width::Word), Ok((added, 0)));
    }

    #[test]
    fn a_window_maps_only_the_bytes_smaller_banks_leave() {
        let mut bus = Bus::new();
        let small = bus.add(Box::new(Scratch([0; 16])));
        let window = bus.add(Box::new(Scratch([0; 16])));
        bus.map(small, 0x1400, 0x100, 0).unwrap();
        bus.map(small, 0x1000, 0x10, 0x100).unwrap();
        bus.map_gaps(window, 0x1000, 0x1000, 0).unwrap();
        let route = |bus: &Bus, address| bus.route(address, Width::Word).unwrap();
        assert_eq!(route(&bus, 0x1000), (small, 0x100));
        assert_eq!(route(&bus, 0x1010), (window, 0x10));
        assert_eq!(route(&bus, 0x1404), (small, 0x4));
        assert_eq!(route(&bus, 0x1500), (window, 0x500));
        assert_eq!(route(&bus, 0x1ffc), (window, 0xffc));
        assert!(bus.route(0x2000, Width::Word).is_err());
        // A window that is already wholly owned refuses.
        let other = bus.add(Box::new(Scratch([0; 16])));
        assert!(matches!(
            bus.map_gaps(other, 0x1400, 0x100, 0),
            Err(MapError::Overlap { .. })
        ));
    }

    #[test]
    fn whole_range_preflight_sees_interior_owners_and_publishes_nothing() {
        let mut bus = Bus::new();
        let bank = bus.add(Box::new(Scratch([7; 16])));
        bus.map(bank, 0x1800, 16, 0).unwrap();
        assert_eq!(
            bus.check_free(0x1000, 0x1000),
            Err(MapError::Overlap { existing: bank })
        );
        assert_eq!(
            bus.check_free(0x1801, 1),
            Err(MapError::Overlap { existing: bank })
        );
        assert_eq!(bus.check_free(0x17f0, 16), Ok(()));
        assert_eq!(bus.check_free(0x1810, 16), Ok(()));
        assert_eq!(bus.check_free(0, 0), Err(MapError::Empty));
        assert_eq!(bus.check_free(u64::MAX, 2), Err(MapError::Overflow));
        assert_eq!(bus.regions.len(), 1);
        assert_eq!(bus.devices.len(), 1);
        assert_eq!(bus.device::<Scratch>(bank).unwrap().0, [7; 16]);
        // A successful preflight is not a reservation; actual map follows
        // the same checked overlap path under exclusive mutable Bus access.
        bus.map(bank, 0x1810, 16, 0).unwrap();
        assert_eq!(
            bus.check_free(0x1810, 16),
            Err(MapError::Overlap { existing: bank })
        );
    }

    #[test]
    fn routes_ranges_with_device_offsets_and_refuses_gaps() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut bus = Bus::new();
        let scratch = bus.add(Box::new(Scratch([0; 16])));
        bus.map(scratch, 0x2_3b0c_0000, 8, 0).unwrap();
        bus.map(scratch, 0x2_3b0c_8000, 8, 8).unwrap();
        bus.write(0x2_3b0c_8000, Width::Word, 0xdead_beef, &mut access)
            .unwrap();
        assert_eq!(
            bus.read(0x2_3b0c_8000, Width::Half, &mut access),
            Ok(0xbeef)
        );
        bus.write(0x2_3b0c_0004, Width::Word, 0x1234_5678, &mut access)
            .unwrap();
        assert_eq!(
            bus.read(0x2_3b0c_0000, Width::Double, &mut access),
            Ok(0x1234_5678_0000_0000)
        );
        assert_eq!(
            bus.read(0x2_3b0c_0008, Width::Word, &mut access),
            Err(MmioError::Unmapped {
                address: 0x2_3b0c_0008,
                width: Width::Word
            })
        );
        assert_eq!(
            bus.read(0x2_3b0c_0002, Width::Word, &mut access),
            Err(MmioError::Misaligned {
                address: 0x2_3b0c_0002,
                width: Width::Word
            })
        );
        assert_eq!(
            bus.map(scratch, 0x2_3b0c_0004, 8, 0),
            Err(MapError::Overlap { existing: scratch })
        );
        assert!(bus.device_mut::<Scratch>(scratch).is_some());
    }
}
