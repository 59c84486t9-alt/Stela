//! virtio-net PCI devices (virtio 1.2 section 5.1), as QEMU's
//! `virtio-net-pci` presents them, as a polled raw Ethernet [`Link`].
//!
//! The driver negotiates only VERSION_1, MAC and STATUS: no checksum or
//! segmentation offload, no mergeable receive buffers and no control
//! queue, so every frame is one buffer behind the 12-byte
//! `virtio_net_hdr` (section 5.1.6, `num_buffers` included under
//! VERSION_1) with all-zero offload fields. A device without a MAC
//! address refuses: the stack needs a stable station address.
use super::{Link, LinkError, MAX_FRAME, Mac};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::Function,
        virtio::{AVAIL, DESCRIPTOR_WRITE, Modern, USED, VENDOR},
    },
};
use alloc::{format, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const MODERN_NET: u16 = 0x1041;
const TRANSITIONAL_NET: u16 = 0x1000;
const FEATURE_MAC: u64 = 1 << 5;
const FEATURE_STATUS: u64 = 1 << 16;
const CONFIG_MAC: usize = 0;
const CONFIG_STATUS: usize = 6;
const LINK_UP: u16 = 1;
const RECEIVE: u16 = 0;
const TRANSMIT: u16 = 1;
/// The queue layout `Modern::queue` uses fits 16 descriptors.
const QUEUE_ENTRIES: u16 = 16;
const HEADER: usize = 12;
const BUFFER: usize = 2048;
const TRANSMIT_WAIT_US: u64 = 100_000;

pub fn matches(function: &Function) -> bool {
    function.vendor == VENDOR
        && (function.device == MODERN_NET || function.device == TRANSITIONAL_NET)
}

/// One split virtqueue and its buffers, one per descriptor.
struct Queue {
    ring: DmaBuffer,
    buffers: DmaBuffer,
    notify: Mmio,
    entries: u16,
    /// The used index consumed so far, and the driver ring's index.
    used: u16,
    available: u16,
}

impl Queue {
    fn new(
        transport: &Modern,
        handoff: &Handoff,
        index: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let ring = dma.allocate(4096, 4096)?;
        let (entries, notify) = transport.queue(handoff, index, QUEUE_ENTRIES, &ring)?;
        let buffers = dma.allocate(usize::from(entries) * BUFFER, 4096)?;
        Ok(Self {
            ring,
            buffers,
            notify,
            entries,
            used: 0,
            available: 0,
        })
    }

    fn describe(&mut self, id: u16, length: usize, flags: u16) {
        let base = 16 * usize::from(id);
        let address = self.buffers.physical() + (usize::from(id) * BUFFER) as u64;
        self.ring.write(base, address);
        self.ring.write(base + 8, length as u32);
        self.ring.write(base + 12, flags);
        self.ring.write(base + 14, 0u16);
    }

    fn offer(&mut self, id: u16) {
        let slot = AVAIL + 4 + 2 * usize::from(self.available % self.entries);
        self.ring.write(slot, id);
        self.available = self.available.wrapping_add(1);
        fence(Ordering::SeqCst);
        self.ring.write(AVAIL + 2, self.available);
        fence(Ordering::SeqCst);
        self.notify.write16(0, 0);
    }

    /// The next buffer the device returned: its descriptor and length.
    fn take(&mut self) -> Option<(u16, usize)> {
        fence(Ordering::SeqCst);
        let produced: u16 = self.ring.read(USED + 2);
        if self.used == produced {
            return None;
        }
        let slot = USED + 4 + 8 * usize::from(self.used % self.entries);
        let id = self.ring.read::<u32>(slot) as u16 % self.entries;
        let length = self.ring.read::<u32>(slot + 4) as usize;
        self.used = self.used.wrapping_add(1);
        Some((id, length.min(BUFFER)))
    }

    fn buffer(&mut self, id: u16) -> &mut [u8] {
        let start = usize::from(id) * BUFFER;
        &mut self.buffers.bytes_mut()[start..start + BUFFER]
    }
}

pub struct VirtioNet {
    device: Mmio,
    receive: Queue,
    transmit: Queue,
    /// Transmit descriptors the device has handed back.
    free: Vec<u16>,
    mac: Mac,
    status: bool,
    clock: Clock,
    pub location: alloc::string::String,
}

impl VirtioNet {
    pub fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let transport = Modern::new(function, handoff)?;
        let accepted = transport.negotiate(FEATURE_MAC | FEATURE_STATUS)?;
        if accepted & FEATURE_MAC == 0 {
            return Err(BlockError::Unsupported(
                "virtio-net device without a MAC address",
            ));
        }
        let receive = Queue::new(&transport, handoff, RECEIVE, dma)?;
        let transmit = Queue::new(&transport, handoff, TRANSMIT, dma)?;
        let device = transport.device;
        let mac = Mac(core::array::from_fn(|n| device.read8(CONFIG_MAC + n)));
        let mut net = Self {
            device,
            free: (0..transmit.entries).collect(),
            receive,
            transmit,
            mac,
            status: accepted & FEATURE_STATUS != 0,
            clock: handoff.clock,
            location: format!("{}", function.address),
        };
        transport.ready();
        for id in 0..net.receive.entries {
            net.receive.describe(id, BUFFER, DESCRIPTOR_WRITE);
            net.receive.offer(id);
        }
        Ok(net)
    }

    fn reclaim(&mut self) {
        while let Some((id, _)) = self.transmit.take() {
            self.free.push(id);
        }
    }
}

impl Link for VirtioNet {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn carrier(&mut self) -> bool {
        !self.status || self.device.read16(CONFIG_STATUS) & LINK_UP != 0
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if frame.len() > MAX_FRAME {
            return Err(LinkError::Invalid("frame exceeds the Ethernet maximum"));
        }
        self.reclaim();
        if self.free.is_empty() {
            let transmit = &mut self.transmit;
            let free = &mut self.free;
            self.clock.wait(TRANSMIT_WAIT_US, || {
                if let Some((id, _)) = transmit.take() {
                    free.push(id);
                }
                !free.is_empty()
            });
        }
        let id = self.free.pop().ok_or_else(|| {
            LinkError::Adapter(format!(
                "virtio-net {} transmit queue stalled",
                self.location
            ))
        })?;
        let buffer = self.transmit.buffer(id);
        buffer[..HEADER].fill(0);
        buffer[HEADER..HEADER + frame.len()].copy_from_slice(frame);
        self.transmit.describe(id, HEADER + frame.len(), 0);
        self.transmit.offer(id);
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        let Some((id, length)) = self.receive.take() else {
            return Ok(None);
        };
        let frame = (length > HEADER).then(|| self.receive.buffer(id)[HEADER..length].to_vec());
        self.receive.describe(id, BUFFER, DESCRIPTOR_WRITE);
        self.receive.offer(id);
        Ok(frame)
    }
}
