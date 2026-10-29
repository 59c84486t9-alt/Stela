//! virtio-net PCI devices (virtio 1.2 section 5.1), as QEMU's
//! `virtio-net-pci` presents them, as a raw Ethernet [`Link`] that sends
//! the handoff's completion signal for received frames and link changes
//! when the function has MSI-X.
//!
//! The driver negotiates only VERSION_1, MAC and STATUS: no checksum or
//! segmentation offload, no mergeable receive buffers and no control
//! queue, so every frame is one buffer behind the 12-byte
//! `virtio_net_hdr` (section 5.1.6, `num_buffers` included under
//! VERSION_1) with all-zero offload fields. A device without a MAC
//! address refuses: the stack needs a stable station address.
use super::{HEADER as ETHERNET_HEADER, Link, LinkError, MAX_FRAME, Mac, check_frame};
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
/// `virtio_net_hdr` under VERSION_1.
const HEADER: usize = 12;
const BUFFER: usize = 2048;
/// The shortest and longest receive lengths that carry one whole frame
/// (Linux `receive_small` drops others as length errors).
const SHORTEST_RECEIVE: usize = HEADER + ETHERNET_HEADER;
const LONGEST_RECEIVE: usize = HEADER + MAX_FRAME;
const TRANSMIT_WAIT_US: u64 = 100_000;

pub fn matches(function: &Function) -> bool {
    matches_identity(&function.identity())
}

/// Candidate selection from copied identity DATA; owned attachment still
/// revalidates configuration and platform requirements.
pub fn matches_identity(function: &crate::bus::pci::Identity) -> bool {
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
        let address = self.buffers.bus_address() + (usize::from(id) * BUFFER) as u64;
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

    /// The next buffer the device returned: its descriptor and length. A
    /// descriptor the driver never offered, or a length past its buffer,
    /// breaks the queue, as Linux `virtqueue_get_buf` does.
    fn take(&mut self) -> Result<Option<(u16, usize)>, Broken> {
        fence(Ordering::SeqCst);
        let produced: u16 = self.ring.read(USED + 2);
        if self.used == produced {
            return Ok(None);
        }
        let slot = USED + 4 + 8 * usize::from(self.used % self.entries);
        let id = self.ring.read::<u32>(slot);
        let length = self.ring.read::<u32>(slot + 4) as usize;
        self.used = self.used.wrapping_add(1);
        match u16::try_from(id) {
            Ok(id) if id < self.entries && length <= BUFFER => Ok(Some((id, length))),
            _ => Err(Broken),
        }
    }

    fn buffer(&mut self, id: u16) -> &mut [u8] {
        let start = usize::from(id) * BUFFER;
        &mut self.buffers.bytes_mut()[start..start + BUFFER]
    }
}

/// The device returned a descriptor or length it was never given.
struct Broken;

pub struct VirtioNet {
    device: Mmio,
    receive: Queue,
    transmit: Queue,
    /// Transmit descriptors the device has handed back.
    free: Vec<u16>,
    /// The device broke a queue; it carries no more frames.
    broken: bool,
    mac: Mac,
    status: bool,
    clock: Clock,
    pub location: alloc::string::String,
    /// Whether the device sends the handoff's completion signal.
    signalled: bool,
}

impl VirtioNet {
    pub fn new(
        function: &mut Function,
        handoff: &Handoff,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let mut transport = Modern::new(function, handoff)?;
        if let Some(message) = handoff.completion {
            transport.signal(function, handoff, message, &[RECEIVE])?;
        }
        let accepted = transport.negotiate(FEATURE_MAC | FEATURE_STATUS)?;
        if accepted & FEATURE_MAC == 0 {
            return Err(BlockError::Unsupported(
                "virtio-net device without a MAC address",
            ));
        }
        let receive = Queue::new(&transport, handoff, RECEIVE, dma)?;
        let transmit = Queue::new(&transport, handoff, TRANSMIT, dma)?;
        let signalled = transport.signals();
        let device = transport.device;
        let mac = Mac(core::array::from_fn(|n| device.read8(CONFIG_MAC + n)));
        let mut net = Self {
            device,
            free: (0..transmit.entries).collect(),
            broken: false,
            receive,
            transmit,
            mac,
            status: accepted & FEATURE_STATUS != 0,
            clock: handoff.clock,
            location: format!("{}", function.address),
            signalled,
        };
        transport.ready();
        for id in 0..net.receive.entries {
            net.receive.describe(id, BUFFER, DESCRIPTOR_WRITE);
            net.receive.offer(id);
        }
        Ok(net)
    }

    /// Take back every transmit descriptor the device returned; one it
    /// returns twice breaks the queue.
    fn reclaim(&mut self) -> Result<(), Broken> {
        while let Some((id, _)) = self.transmit.take()? {
            if self.free.contains(&id) {
                return Err(Broken);
            }
            self.free.push(id);
        }
        Ok(())
    }

    fn usable(&self) -> Result<(), LinkError> {
        match self.broken {
            true => Err(LinkError::Adapter(format!(
                "virtio-net {} returned a buffer it was never given",
                self.location
            ))),
            false => Ok(()),
        }
    }

    fn break_on<T>(&mut self, result: Result<T, Broken>) -> Result<T, LinkError> {
        result.map_err(|Broken| {
            self.broken = true;
            self.usable().unwrap_err()
        })
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
        check_frame(frame)?;
        self.usable()?;
        let reclaimed = self.reclaim();
        self.break_on(reclaimed)?;
        if self.free.is_empty() {
            let deadline = self.clock.deadline(TRANSMIT_WAIT_US);
            while self.free.is_empty() && !deadline.passed() {
                let reclaimed = self.reclaim();
                self.break_on(reclaimed)?;
                crate::waiting();
            }
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

    fn signals(&self) -> bool {
        self.signalled
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.usable()?;
        loop {
            let taken = self.receive.take();
            let Some((id, length)) = self.break_on(taken)? else {
                return Ok(None);
            };
            let frame = (SHORTEST_RECEIVE..=LONGEST_RECEIVE)
                .contains(&length)
                .then(|| self.receive.buffer(id)[HEADER..length].to_vec());
            self.receive.describe(id, BUFFER, DESCRIPTOR_WRITE);
            self.receive.offer(id);
            // A runt or oversized buffer is dropped and the next one read.
            if frame.is_some() {
                return Ok(frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::boxed::Box;

    const ENTRIES: u16 = 4;

    struct Fixture {
        net: VirtioNet,
        _registers: Box<[u64]>,
        _memory: Vec<u64>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut registers = vec![0u64; 64].into_boxed_slice();
            let mut memory = vec![0u64; 8192];
            let start = memory.as_mut_ptr() as u64;
            // SAFETY: the fixture owns both stable allocations for every
            // access the driver makes; no device is involved.
            let (mmio, mut dma) = unsafe {
                (
                    Mmio::new(registers.as_mut_ptr() as u64),
                    RegionAllocator::new(start..start + (memory.len() * 8) as u64),
                )
            };
            let mut queue = || Queue {
                ring: dma.allocate(4096, 4096).unwrap(),
                buffers: dma.allocate(usize::from(ENTRIES) * BUFFER, 4096).unwrap(),
                notify: mmio,
                entries: ENTRIES,
                used: 0,
                available: 0,
            };
            let (receive, transmit) = (queue(), queue());
            Self {
                net: VirtioNet {
                    device: mmio,
                    receive,
                    transmit,
                    free: (0..ENTRIES).collect(),
                    broken: false,
                    mac: Mac([2, 0, 0, 0, 0, 1]),
                    status: false,
                    clock: Clock {
                        ticks_per_microsecond: 0,
                    },
                    location: "fixture".into(),
                    signalled: false,
                },
                _registers: registers,
                _memory: memory,
            }
        }
    }

    /// The device hands back descriptor `id` holding `length` bytes.
    fn give_back(queue: &mut Queue, produced: &mut u16, id: u32, length: u32) {
        let slot = USED + 4 + 8 * usize::from(*produced % queue.entries);
        queue.ring.write(slot, id);
        queue.ring.write(slot + 4, length);
        *produced = produced.wrapping_add(1);
        queue.ring.write(USED + 2, *produced);
    }

    #[test]
    fn bad_length_frames_are_dropped() {
        let mut fixture = Fixture::new();
        let net = &mut fixture.net;
        let mut produced = 0;
        give_back(&mut net.receive, &mut produced, 0, (HEADER + 13) as u32);
        give_back(
            &mut net.receive,
            &mut produced,
            1,
            (HEADER + MAX_FRAME + 1) as u32,
        );
        net.receive.buffer(2)[HEADER..HEADER + 60].fill(0x5a);
        give_back(&mut net.receive, &mut produced, 2, (HEADER + 60) as u32);
        assert_eq!(net.receive(), Ok(Some(vec![0x5a; 60])));
        assert_eq!(net.receive(), Ok(None));
        // Every buffer, dropped or delivered, went back to the device.
        assert_eq!(net.receive.available, 3);
    }

    #[test]
    fn a_descriptor_never_offered_breaks_the_device() {
        let mut fixture = Fixture::new();
        let net = &mut fixture.net;
        let mut produced = 0;
        give_back(&mut net.receive, &mut produced, u32::from(ENTRIES), 64);
        assert!(net.receive().is_err());
        assert!(net.broken);
        assert!(net.transmit(&[0; 60]).is_err());
        assert!(net.receive().is_err());
    }

    #[test]
    fn a_transmit_descriptor_returned_twice_breaks_the_device() {
        let mut fixture = Fixture::new();
        let net = &mut fixture.net;
        net.transmit(&[1; 60]).unwrap();
        let sent = 3; // `free` hands out its last descriptor first
        let mut produced = 0;
        give_back(&mut net.transmit, &mut produced, sent, 0);
        give_back(&mut net.transmit, &mut produced, sent, 0);
        assert!(net.transmit(&[1; 60]).is_err());
        assert!(net.broken);
    }

    #[test]
    fn frames_without_an_ethernet_header_are_refused() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.net.transmit(&[0; 13]),
            Err(LinkError::Invalid("frame shorter than its header"))
        );
        assert_eq!(fixture.net.transmit(&[0; 14]), Ok(()));
    }
}
