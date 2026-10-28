//! The polled descriptor rings the PCI Ethernet drivers share: sixteen-byte
//! descriptors, 32 unless a driver asks for more, with one 2 KiB DMA buffer
//! each, the next descriptor the driver fills and, for transmit, the oldest
//! one the controller still owns.
use crate::{
    Clock,
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
};
use core::sync::atomic::{Ordering, fence};

pub(crate) const DESCRIPTORS: usize = 32;
pub(crate) const DESCRIPTOR: usize = 16;
pub(crate) const BUFFER: usize = 2048;
const PAGE: usize = 4096;
/// How long a transmit waits for the controller to hand a descriptor back.
const TRANSMIT_WAIT_US: u64 = 100_000;

pub(crate) struct Ring {
    pub(crate) descriptors: DmaBuffer,
    buffers: DmaBuffer,
    /// Descriptors in the ring.
    pub(crate) count: usize,
    /// The next descriptor the driver fills or reads.
    pub(crate) next: usize,
    /// The oldest transmit descriptor the controller has not written back.
    pub(crate) clean: usize,
}

impl Ring {
    pub(crate) fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Self::with(dma, DESCRIPTORS)
    }

    /// A ring of `count` descriptors, a multiple of eight so its length
    /// stays a multiple of 128 bytes.
    pub(crate) fn with(dma: &mut dyn DmaAllocator, count: usize) -> Result<Self, BlockError> {
        if count == 0 || !count.is_multiple_of(8) {
            return Err(BlockError::Unsupported("Ethernet ring length"));
        }
        let descriptors = dma.allocate(count * DESCRIPTOR, PAGE)?;
        let buffers = dma.allocate(count * BUFFER, PAGE)?;
        let fits = |buffer: &DmaBuffer, bytes: usize| {
            buffer.len() == bytes
                && buffer.physical().is_multiple_of(PAGE as u64)
                && buffer.physical().checked_add(bytes as u64).is_some()
        };
        if !fits(&descriptors, count * DESCRIPTOR) || !fits(&buffers, count * BUFFER) {
            return Err(BlockError::Unsupported(
                "Ethernet ring outside its DMA allocation",
            ));
        }
        Ok(Self {
            descriptors,
            buffers,
            count,
            next: 0,
            clean: 0,
        })
    }

    /// The descriptors' bus address and length in bytes, for the
    /// controller's base and length registers.
    pub(crate) fn base(&self) -> u64 {
        self.descriptors.physical()
    }

    pub(crate) fn bytes(&self) -> u32 {
        (self.count * DESCRIPTOR) as u32
    }

    /// Point a controller's base and length registers at the descriptors.
    pub(crate) fn program(
        &self,
        write: impl Fn(usize, u32),
        low: usize,
        high: usize,
        length: usize,
    ) {
        write(length, self.bytes());
        write(high, (self.base() >> 32) as u32);
        write(low, self.base() as u32);
    }

    pub(crate) fn address(&self, index: usize) -> u64 {
        self.buffers.physical() + (index * BUFFER) as u64
    }

    pub(crate) fn buffer(&mut self, index: usize) -> &mut [u8] {
        &mut self.buffers.bytes_mut()[index * BUFFER..(index + 1) * BUFFER]
    }

    /// Step to the next descriptor, returning the current one.
    pub(crate) fn advance(&mut self) -> usize {
        let index = self.next;
        self.next = (index + 1) % self.count;
        index
    }

    /// Whether transmit descriptors are still with the controller.
    pub(crate) fn pending(&self) -> bool {
        self.clean != self.next
    }

    /// Retire the transmit descriptors `done` reports written back, and say
    /// whether one is free. Head equal to tail means empty, so one
    /// descriptor always stays unused.
    pub(crate) fn reclaim(&mut self, done: impl Fn(&DmaBuffer, usize) -> bool) -> bool {
        while self.pending() && done(&self.descriptors, self.clean * DESCRIPTOR) {
            fence(Ordering::Acquire);
            self.clean = (self.clean + 1) % self.count;
        }
        (self.next + 1) % self.count != self.clean
    }

    /// Wait up to the transmit bound for a free descriptor.
    pub(crate) fn free(&mut self, clock: Clock, done: impl Fn(&DmaBuffer, usize) -> bool) -> bool {
        self.reclaim(&done) || clock.wait(TRANSMIT_WAIT_US, || self.reclaim(&done))
    }

    /// Forget every descriptor, once the controller's queue is stopped and
    /// its head and tail are back at zero.
    pub(crate) fn reset(&mut self) {
        self.descriptors.bytes_mut().fill(0);
        self.next = 0;
        self.clean = 0;
    }
}
