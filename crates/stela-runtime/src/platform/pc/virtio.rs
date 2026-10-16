//! Modern (virtio 1.x) PCI block devices with one polled split virtqueue,
//! as QEMU's `virtio-blk-pci` presents them.
use super::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity, Transport, ascii},
    dma::{DmaAllocator, DmaBuffer},
    mmio::Mmio,
    pci::{CAPABILITY_VENDOR, ConfigSpace, Function},
    registers,
};
use alloc::format;
use core::sync::atomic::{Ordering, fence};

pub const VENDOR: u16 = 0x1af4;
const MODERN_BLOCK: u16 = 0x1042;
const TRANSITIONAL_BLOCK: u16 = 0x1001;

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

const FEATURE_READ_ONLY: u64 = 1 << 5;
const FEATURE_BLOCK_SIZE: u64 = 1 << 6;
const FEATURE_FLUSH: u64 = 1 << 9;
const FEATURE_VERSION_1: u64 = 1 << 32;

const REQUEST_IN: u32 = 0;
const REQUEST_OUT: u32 = 1;
const REQUEST_FLUSH: u32 = 4;
const REQUEST_GET_ID: u32 = 8;

const DESCRIPTOR_NEXT: u16 = 1;
const DESCRIPTOR_WRITE: u16 = 2;

const QUEUE_ENTRIES: u16 = 8;
const AVAIL: usize = 0x100;
const USED: usize = 0x200;
const BOUNCE_BYTES: usize = 64 * 1024;
const SECTOR: u64 = 512;
const TIMEOUT_US: u64 = 10_000_000;

pub fn matches(function: &Function) -> bool {
    function.vendor == VENDOR
        && (function.device == MODERN_BLOCK || function.device == TRANSITIONAL_BLOCK)
}

pub struct VirtioBlk {
    device: Mmio,
    notify: Mmio,
    queue: DmaBuffer,
    request: DmaBuffer,
    bounce: DmaBuffer,
    entries: u16,
    next: u16,
    flush: bool,
    sectors_per_block: u64,
    identity: Identity,
    clock: Clock,
}

impl VirtioBlk {
    pub fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
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
        let (
            Some(common),
            Some(device),
            Some((notify_bar, notify_start, notify_length, multiplier)),
        ) = (common, device, notify)
        else {
            return Err(BlockError::Unsupported(
                "virtio device without modern registers",
            ));
        };
        function.enable();

        common.write8(DEVICE_STATUS, 0);
        if !handoff
            .clock
            .wait(TIMEOUT_US, || common.read8(DEVICE_STATUS) == 0)
        {
            return Err(BlockError::Timeout);
        }
        common.write8(DEVICE_STATUS, ACKNOWLEDGE | DRIVER);
        let features = |select: u32| {
            common.write32(DEVICE_FEATURE_SELECT, select);
            u64::from(common.read32(DEVICE_FEATURE)) << (32 * select)
        };
        let offered = features(0) | features(1);
        if offered & FEATURE_VERSION_1 == 0 {
            common.write8(DEVICE_STATUS, FAILED);
            return Err(BlockError::Unsupported("virtio device without VERSION_1"));
        }
        let accepted =
            offered & (FEATURE_VERSION_1 | FEATURE_READ_ONLY | FEATURE_BLOCK_SIZE | FEATURE_FLUSH);
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

        common.write16(QUEUE_SELECT, 0);
        let maximum = common.read16(QUEUE_SIZE);
        if maximum == 0 {
            return Err(BlockError::Unsupported("virtio block device has no queue"));
        }
        let entries = QUEUE_ENTRIES.min(1 << (15 - maximum.leading_zeros()));
        let queue = dma.allocate(4096, 4096)?;
        common.write16(QUEUE_SIZE, entries);
        common.write16(QUEUE_VECTOR, NO_VECTOR);
        common.write64(QUEUE_DESCRIPTORS, queue.physical());
        common.write64(QUEUE_DRIVER, queue.physical() + AVAIL as u64);
        common.write64(QUEUE_DEVICE, queue.physical() + USED as u64);
        let notify_offset = u64::from(common.read16(QUEUE_NOTIFY_OFF)) * u64::from(multiplier);
        if notify_offset + 2 > notify_length {
            return Err(BlockError::Unsupported(
                "virtio notify register outside its region",
            ));
        }
        let notify = registers(handoff, notify_bar, notify_start + notify_offset, 2)?;
        common.write16(QUEUE_ENABLE, 1);
        common.write8(
            DEVICE_STATUS,
            ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
        );

        let block_size = match accepted & FEATURE_BLOCK_SIZE {
            0 => SECTOR as u32,
            _ => device.read32(0x14),
        };
        if block_size < SECTOR as u32
            || !block_size.is_power_of_two()
            || block_size as usize > BOUNCE_BYTES
        {
            return Err(BlockError::Unsupported("virtio block size"));
        }
        let sectors_per_block = u64::from(block_size) / SECTOR;
        let mut driver = Self {
            device,
            notify,
            queue,
            request: dma.allocate(4096, 4096)?,
            bounce: dma.allocate(BOUNCE_BYTES, 4096)?,
            entries,
            next: 0,
            flush: accepted & FEATURE_FLUSH != 0,
            sectors_per_block,
            identity: Identity {
                transport: Transport::VirtioBlk,
                location: format!("{}", function.address),
                model: format!("virtio-blk {:04x}:{:04x}", function.vendor, function.device),
                serial: alloc::string::String::new(),
                blocks: 0,
                block_size,
                read_only: accepted & FEATURE_READ_ONLY != 0,
            },
            clock: handoff.clock,
        };
        driver.identity.blocks = driver.device.read64(0) / sectors_per_block;
        driver.identity.serial = match driver.submit(REQUEST_GET_ID, 0, 20, true) {
            Ok(()) => ascii(&driver.bounce.bytes()[..20]),
            Err(BlockError::Device { .. }) => alloc::string::String::new(),
            Err(error) => return Err(error),
        };
        Ok(driver)
    }

    /// Run one request of `bytes` data bytes through the bounce buffer and
    /// wait for the device to return it.
    fn submit(
        &mut self,
        kind: u32,
        sector: u64,
        bytes: usize,
        device_writes: bool,
    ) -> Result<(), BlockError> {
        let request = self.request.physical();
        self.request.write(0, kind);
        self.request.write(4, 0u32);
        self.request.write(8, sector);
        self.request.write(16, 0xffu8);
        let mut chain = [(request, 16u32, 0u16); 3];
        let mut length = 1;
        if bytes > 0 {
            let flags = if device_writes { DESCRIPTOR_WRITE } else { 0 };
            chain[1] = (self.bounce.physical(), bytes as u32, flags);
            length = 2;
        }
        chain[length] = (request + 16, 1, DESCRIPTOR_WRITE);
        for (index, (address, len, flags)) in chain[..=length].iter().enumerate() {
            let next = if index < length { DESCRIPTOR_NEXT } else { 0 };
            let base = 16 * index;
            self.queue.write(base, *address);
            self.queue.write(base + 8, *len);
            self.queue.write(base + 12, flags | next);
            self.queue.write(base + 14, index as u16 + 1);
        }
        let slot = AVAIL + 4 + 2 * usize::from(self.next % self.entries);
        self.queue.write(slot, 0u16);
        fence(Ordering::SeqCst);
        self.next = self.next.wrapping_add(1);
        self.queue.write(AVAIL + 2, self.next);
        fence(Ordering::SeqCst);
        self.notify.write16(0, 0);
        let expected = self.next;
        let queue = &self.queue;
        if !self
            .clock
            .wait(TIMEOUT_US, || queue.read::<u16>(USED + 2) == expected)
        {
            return Err(BlockError::Timeout);
        }
        fence(Ordering::SeqCst);
        match self.request.read::<u8>(16) {
            0 => Ok(()),
            status => Err(BlockError::Device {
                status: u32::from(status),
            }),
        }
    }

    fn chunk_blocks(&self) -> u64 {
        (BOUNCE_BYTES / self.identity.block_size as usize) as u64
    }
}

impl BlockDevice for VirtioBlk {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_blocks() as usize * block;
        for (index, part) in buffer.chunks_mut(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            self.submit(REQUEST_IN, first * self.sectors_per_block, part.len(), true)?;
            part.copy_from_slice(&self.bounce.bytes()[..part.len()]);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_blocks() as usize * block;
        for (index, part) in data.chunks(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            self.bounce.bytes_mut()[..part.len()].copy_from_slice(part);
            self.submit(
                REQUEST_OUT,
                first * self.sectors_per_block,
                part.len(),
                false,
            )?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        // Without FLUSH the device has no volatile write cache to empty.
        match self.flush {
            true => self.submit(REQUEST_FLUSH, 0, 0, false),
            false => Ok(()),
        }
    }
}
