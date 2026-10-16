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

/// Why a device access was not performed. No register effect happened.
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

/// A guest request to reset or stop the machine, surfaced instead of acting
/// on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetRequest {
    pub device: &'static str,
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
    pub fn request_reset(&mut self, device: &'static str, reason: &'static str) {
        self.reset.get_or_insert(ResetRequest {
            device,
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

/// A memory-mapped device model. Offsets are relative to the start of the
/// device's address space as placed by [`Bus::map`]. Values occupy the low
/// `width` bytes; implementations refuse widths their registers do not have.
pub trait MmioDevice: Any {
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
    Overlap { existing: DeviceId },
    UnknownDevice,
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
        let index = self.regions.partition_point(|region| region.start < start);
        let overlaps = |region: &Region| region.start < end && start < region.end;
        for neighbor in [index.checked_sub(1), Some(index)].into_iter().flatten() {
            if let Some(region) = self.regions.get(neighbor).filter(|region| overlaps(region)) {
                return Err(MapError::Overlap {
                    existing: region.device,
                });
            }
        }
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
    /// The device and device offset for a guest PA access.
    fn route(&self, address: u64, width: Width) -> Result<(DeviceId, u64), MmioError> {
        if !address.is_multiple_of(width.bytes()) {
            return Err(MmioError::Misaligned { address, width });
        }
        let index = self
            .regions
            .partition_point(|region| region.start <= address);
        let region = index
            .checked_sub(1)
            .map(|index| self.regions[index])
            .filter(|region| address + width.bytes() <= region.end)
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
