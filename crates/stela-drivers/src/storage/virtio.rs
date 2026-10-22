//! virtio-blk block devices with one polled split virtqueue, as QEMU's
//! `virtio-blk-pci` presents them.
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity, Transport, ascii},
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::Function,
        virtio::{AVAIL, DESCRIPTOR_NEXT, DESCRIPTOR_WRITE, Modern, TIMEOUT_US, USED, VENDOR},
    },
};
use alloc::format;
use core::sync::atomic::{Ordering, fence};

const MODERN_BLOCK: u16 = 0x1042;
const TRANSITIONAL_BLOCK: u16 = 0x1001;

const FEATURE_READ_ONLY: u64 = 1 << 5;
const FEATURE_BLOCK_SIZE: u64 = 1 << 6;
const FEATURE_FLUSH: u64 = 1 << 9;

/// Configuration space: capacity in sectors, and the logical block size.
const CONFIG_CAPACITY: usize = 0x00;
const CONFIG_BLOCK_SIZE: usize = 0x14;

/// `virtio_blk_req`: type, reserved, sector, then the device's status byte
/// after the data (virtio 1.2 §5.2.6).
const REQUEST_HEADER: u32 = 16;
const REQUEST_TYPE: usize = 0;
const REQUEST_RESERVED: usize = 4;
const REQUEST_SECTOR: usize = 8;
const REQUEST_STATUS: usize = 16;
/// A status byte the device has not written yet.
const STATUS_PENDING: u8 = 0xff;
/// Linux `VIRTIO_BLK_ID_BYTES`.
const ID_BYTES: usize = 20;

const REQUEST_IN: u32 = 0;
const REQUEST_OUT: u32 = 1;
const REQUEST_FLUSH: u32 = 4;
const REQUEST_GET_ID: u32 = 8;

const QUEUE_ENTRIES: u16 = 8;
const BOUNCE_BYTES: usize = 64 * 1024;
const SECTOR: u64 = 512;

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
    /// A request timed out and the device may still own its buffers; none
    /// is reused until a reset this driver does not perform.
    fault: Option<BlockError>,
}

impl VirtioBlk {
    pub fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let transport = Modern::new(function, handoff)?;
        let accepted =
            transport.negotiate(FEATURE_READ_ONLY | FEATURE_BLOCK_SIZE | FEATURE_FLUSH)?;
        let queue = dma.allocate(4096, 4096)?;
        let (entries, notify) = transport.queue(handoff, 0, QUEUE_ENTRIES, &queue)?;
        transport.ready();
        let device = transport.device;

        let block_size = match accepted & FEATURE_BLOCK_SIZE {
            0 => SECTOR as u32,
            _ => device.read32(CONFIG_BLOCK_SIZE),
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
            fault: None,
        };
        driver.identity.blocks = driver.device.read64(CONFIG_CAPACITY) / sectors_per_block;
        driver.identity.serial = match driver.submit(REQUEST_GET_ID, 0, ID_BYTES, true) {
            Ok(()) => ascii(&driver.bounce.bytes()[..ID_BYTES]),
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
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        let request = self.request.physical();
        self.request.write(REQUEST_TYPE, kind);
        self.request.write(REQUEST_RESERVED, 0u32);
        self.request.write(REQUEST_SECTOR, sector);
        self.request.write(REQUEST_STATUS, STATUS_PENDING);
        let mut chain = [(request, REQUEST_HEADER, 0u16); 3];
        let mut length = 1;
        if bytes > 0 {
            let flags = if device_writes { DESCRIPTOR_WRITE } else { 0 };
            chain[1] = (self.bounce.physical(), bytes as u32, flags);
            length = 2;
        }
        chain[length] = (request + u64::from(REQUEST_HEADER), 1, DESCRIPTOR_WRITE);
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
            self.fault = Some(BlockError::Timeout);
            return Err(BlockError::Timeout);
        }
        fence(Ordering::SeqCst);
        // The chain always starts at descriptor 0; any other head was never
        // offered (Linux `virtqueue_get_buf` marks the queue broken).
        let used = USED + 4 + 8 * usize::from(expected.wrapping_sub(1) % self.entries);
        if self.queue.read::<u32>(used) != 0 {
            let error = BlockError::Device { status: u32::MAX };
            self.fault = Some(error.clone());
            return Err(error);
        }
        match self.request.read::<u8>(REQUEST_STATUS) {
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
