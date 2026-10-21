//! The modern (virtio 1.x) PCI transport the virtio drivers share: the
//! register regions, reset, feature negotiation and split virtqueue setup.
use super::{
    dma::DmaBuffer,
    mmio::Mmio,
    pci::{self, CAPABILITY_VENDOR, ConfigSpace, Function},
};
use crate::{Handoff, block::BlockError, registers};

pub const VENDOR: u16 = 0x1af4;

const COMMON: u8 = 1;
const NOTIFY: u8 = 2;
const DEVICE: u8 = 4;

// Common configuration registers.
const DEVICE_FEATURE_SELECT: usize = 0x00;
const DEVICE_FEATURE: usize = 0x04;
const DRIVER_FEATURE_SELECT: usize = 0x08;
const DRIVER_FEATURE: usize = 0x0c;
const CONFIG_VECTOR: usize = 0x10;
const DEVICE_STATUS: usize = 0x14;
const QUEUE_SELECT: usize = 0x16;
const QUEUE_SIZE: usize = 0x18;
const QUEUE_VECTOR: usize = 0x1a;
const QUEUE_ENABLE: usize = 0x1c;
const QUEUE_NOTIFY_OFF: usize = 0x1e;
const QUEUE_DESCRIPTORS: usize = 0x20;
const QUEUE_DRIVER: usize = 0x28;
const QUEUE_DEVICE: usize = 0x30;
const NO_VECTOR: u16 = 0xffff;

const ACKNOWLEDGE: u8 = 1;
const DRIVER: u8 = 2;
const DRIVER_OK: u8 = 4;
const FEATURES_OK: u8 = 8;
const FAILED: u8 = 0x80;

const FEATURE_VERSION_1: u64 = 1 << 32;

pub(crate) const DESCRIPTOR_NEXT: u16 = 1;
pub(crate) const DESCRIPTOR_WRITE: u16 = 2;

pub(crate) const AVAIL: usize = 0x100;
pub(crate) const USED: usize = 0x200;
/// How long a device may take to reset or to complete a request.
pub(crate) const TIMEOUT_US: u64 = 10_000_000;

/// A modern virtio PCI function's register regions, reset and acknowledged
/// (virtio 1.2 section 4.1.4 and 3.1.1).
pub(crate) struct Modern {
    common: Mmio,
    pub(crate) device: Mmio,
    notify: (Option<pci::Bar>, u64, u64, u32),
}

impl Modern {
    pub(crate) fn new(function: &mut Function, handoff: &Handoff) -> Result<Self, BlockError> {
        let bars = function.bars();
        let mut common = None;
        let mut device = None;
        let mut notify = None;
        for (offset, id) in function.capabilities() {
            if id != CAPABILITY_VENDOR {
                continue;
            }
            let config = function.config();
            let base = u16::from(offset);
            let kind = config.read8(base + 3);
            let bar = bars
                .get(usize::from(config.read8(base + 4)))
                .copied()
                .flatten();
            let start = u64::from(config.read32(base + 8));
            let length = u64::from(config.read32(base + 12));
            let region = || registers(handoff, bar, start, length);
            match kind {
                COMMON if common.is_none() => common = Some(region()?),
                DEVICE if device.is_none() => device = Some(region()?),
                NOTIFY if notify.is_none() => {
                    notify = Some((bar, start, length, config.read32(base + 16)))
                }
                _ => {}
            }
        }
        let (Some(common), Some(device), Some(notify)) = (common, device, notify) else {
            return Err(BlockError::Unsupported(
                "virtio device without modern registers",
            ));
        };
        function.enable_polled();
        common.write8(DEVICE_STATUS, 0);
        if !handoff
            .clock
            .wait(TIMEOUT_US, || common.read8(DEVICE_STATUS) == 0)
        {
            return Err(BlockError::Timeout);
        }
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER);
        Ok(Self {
            common,
            device,
            notify,
        })
    }

    /// Accepts the offered features among `wanted`; VERSION_1 is required.
    pub(crate) fn negotiate(&self, wanted: u64) -> Result<u64, BlockError> {
        let common = &self.common;
        let features = |select: u32| {
            common.write32(DEVICE_FEATURE_SELECT, select);
            u64::from(common.read32(DEVICE_FEATURE)) << (32 * select)
        };
        let offered = features(0) | features(1);
        if offered & FEATURE_VERSION_1 == 0 {
            common.write8(DEVICE_STATUS, FAILED);
            return Err(BlockError::Unsupported("virtio device without VERSION_1"));
        }
        let accepted = offered & (FEATURE_VERSION_1 | wanted);
        for select in 0..2u32 {
            common.write32(DRIVER_FEATURE_SELECT, select);
            common.write32(DRIVER_FEATURE, (accepted >> (32 * select)) as u32);
        }
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
        if common.read8(DEVICE_STATUS) & FEATURES_OK == 0 {
            common.write8(DEVICE_STATUS, FAILED);
            return Err(BlockError::Unsupported(
                "virtio device refused its features",
            ));
        }
        common.write16(CONFIG_VECTOR, NO_VECTOR);
        Ok(accepted)
    }

    /// Enables queue `index` of at most `entries` entries in `memory`
    /// (descriptors at 0, the driver ring at [`AVAIL`], the device ring
    /// at [`USED`]), returning its size and notify register.
    pub(crate) fn queue(
        &self,
        handoff: &Handoff,
        index: u16,
        entries: u16,
        memory: &DmaBuffer,
    ) -> Result<(u16, Mmio), BlockError> {
        let common = &self.common;
        common.write16(QUEUE_SELECT, index);
        let maximum = common.read16(QUEUE_SIZE);
        if maximum == 0 {
            return Err(BlockError::Unsupported("virtio queue is absent"));
        }
        let entries = entries.min(1 << (15 - maximum.leading_zeros()));
        common.write16(QUEUE_SIZE, entries);
        common.write16(QUEUE_VECTOR, NO_VECTOR);
        common.write64(QUEUE_DESCRIPTORS, memory.physical());
        common.write64(QUEUE_DRIVER, memory.physical() + AVAIL as u64);
        common.write64(QUEUE_DEVICE, memory.physical() + USED as u64);
        let (bar, start, length, multiplier) = self.notify;
        let offset = u64::from(common.read16(QUEUE_NOTIFY_OFF)) * u64::from(multiplier);
        if offset + 2 > length {
            return Err(BlockError::Unsupported(
                "virtio notify register outside its region",
            ));
        }
        let notify = registers(handoff, bar, start + offset, 2)?;
        common.write16(QUEUE_ENABLE, 1);
        Ok((entries, notify))
    }

    pub(crate) fn ready(&self) {
        self.common.write8(
            DEVICE_STATUS,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        );
    }
}
