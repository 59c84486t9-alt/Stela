//! Producer rings of one segment closed by a toggling Link TRB (xHCI 4.9,
//! 6.4, 6.5) and the event TRBs the controller writes back.
use super::*;

/// An event TRB the controller wrote to the event ring.
#[derive(Clone, Copy, Debug)]
pub(super) struct Event {
    pub(super) parameter: u64,
    pub(super) status: u32,
    pub(super) control: u32,
}

impl Event {
    pub(super) fn kind(&self) -> u32 {
        self.control >> 10 & 0x3f
    }
    pub(super) fn code(&self) -> u32 {
        self.status >> 24
    }
    pub(super) fn slot(&self) -> u8 {
        (self.control >> 24) as u8
    }
    pub(super) fn endpoint(&self) -> u8 {
        (self.control >> 16 & 0x1f) as u8
    }
    pub(super) fn residual(&self) -> usize {
        (self.status & 0xff_ffff) as usize
    }
}

/// A producer ring of one segment closed by a toggling Link TRB.
pub(super) struct Ring {
    pub(super) buffer: memory::Buffer,
    pub(super) index: usize,
    pub(super) cycle: bool,
    pub(super) normal: transfer::Queue,
}

impl Ring {
    #[cfg(test)]
    pub(super) fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Self::with_profile(dma, dma::Profile::SPEC)
    }

    #[cfg(test)]
    pub(super) fn with_profile(
        dma: &mut dyn DmaAllocator,
        profile: dma::Profile,
    ) -> Result<Self, BlockError> {
        Self::with_memory(dma, profile, None)
    }

    pub(super) fn with_memory(
        dma: &mut dyn DmaAllocator,
        profile: dma::Profile,
        memory: Option<&Rc<memory::Native>>,
    ) -> Result<Self, BlockError> {
        // A segment cannot cross a 64 KiB boundary (xHCI 1.2 4.9.2).
        // Its whole allocation (including a quirk's dummy second page) is
        // aligned to its size, keeping both within one 64 KiB boundary.
        let bytes = profile.segment_bytes();
        let mut buffer = profile.allocate_memory(dma, bytes, bytes, memory)?;
        let physical = buffer.device_address();
        buffer.write((RING_TRBS - 1) * TRB, physical);
        Ok(Self {
            buffer,
            index: 0,
            cycle: true,
            normal: transfer::Queue::default(),
        })
    }

    /// Only called for storage returned by the complete Disable Slot boundary.
    pub(super) fn reinitialize(&mut self) {
        self.buffer.bytes_mut().fill(0);
        self.buffer
            .write((RING_TRBS - 1) * TRB, self.buffer.device_address());
        self.index = 0;
        self.cycle = true;
        self.normal = transfer::Queue::default();
    }

    pub(super) fn address(&self) -> u64 {
        self.buffer.device_address() + (self.index * TRB) as u64
    }

    /// The enqueue pointer with its cycle state, for CRCR or Set TR Dequeue.
    pub(super) fn dequeue_pointer(&self) -> u64 {
        self.address() | u64::from(self.cycle)
    }

    /// Linux trb_to_noop: a command the controller never fetched becomes a
    /// No Op Command with its cycle bit kept.
    pub(super) fn no_op(&mut self, address: u64) -> Result<(), BlockError> {
        let at = (address - self.buffer.device_address()) as usize;
        let cycle = self.buffer.read::<u32>(at + 12) & CYCLE;
        self.buffer.write(at, 0u64);
        self.buffer.write(at + 8, 0u32);
        fence(Ordering::Release);
        self.buffer.write(at + 12, NO_OP_COMMAND << 10 | cycle);
        self.buffer.sync_device(at..at + TRB)
    }

    /// Writes one TD, its first TRB owned last, and returns each TRB's
    /// address.
    pub(super) fn push(&mut self, trbs: &[(u64, u32, u32)]) -> Result<Vec<u64>, BlockError> {
        let mut addresses = Vec::with_capacity(trbs.len());
        let mut first = None;
        for (n, &(parameter, status, control)) in trbs.iter().enumerate() {
            let at = self.index * TRB;
            addresses.push(self.address());
            self.buffer.write(at, parameter);
            self.buffer.write(at + 8, status);
            let cycle = u32::from(self.cycle);
            if n == 0 {
                first = Some((at, control, cycle));
                self.buffer.write(at + 12, control | (cycle ^ 1));
            } else {
                fence(Ordering::Release);
                self.buffer.write(at + 12, control | cycle);
            }
            self.index += 1;
            if self.index == RING_TRBS - 1 {
                // A Link TRB inside a TD chains it on.
                let chain = control & CHAIN;
                fence(Ordering::Release);
                self.buffer.write(
                    (RING_TRBS - 1) * TRB + 12,
                    LINK << 10 | TOGGLE | chain | u32::from(self.cycle),
                );
                self.index = 0;
                self.cycle = !self.cycle;
            }
        }
        // Make the complete TD and Link visible while its first Cycle still
        // belongs to software. Only then publish that actual ownership word.
        self.buffer.sync_dirty()?;
        if let Some((at, control, cycle)) = first {
            fence(Ordering::Release);
            self.buffer.write(at + 12, control | cycle);
            self.buffer.sync_device(at + 12..at + 16)?;
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;

    #[test]
    fn ring_segments_never_cross_a_64k_boundary_and_refuse_bad_allocations() {
        let mut backing = vec![0u64; 32 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let boundary = (base + 65536).next_multiple_of(65536);
        for offset in (64..4096u64).step_by(64) {
            // SAFETY: each allocator is used sequentially, within this live
            // backing; no segment is published to hardware or retained.
            let mut dma = unsafe { RegionAllocator::new(boundary - offset..boundary + 8192) };
            let ring = Ring::new(&mut dma).unwrap();
            assert_eq!(ring.buffer.physical(), boundary);
            assert_eq!(
                ring.buffer.physical() / 65536,
                (ring.buffer.physical() + (RING_TRBS * TRB - 1) as u64) / 65536,
            );
        }
        struct WrongAlignment(RegionAllocator);
        impl DmaAllocator for WrongAlignment {
            fn allocate(&mut self, bytes: usize, _: usize) -> Result<DmaBuffer, BlockError> {
                self.0.allocate(bytes, 64)
            }
        }
        // SAFETY: within the same backing, sequentially after all rings above.
        let mut dma =
            WrongAlignment(unsafe { RegionAllocator::new(boundary - 64..boundary + 8192) });
        assert!(matches!(
            Ring::new(&mut dma),
            Err(BlockError::Unsupported(_))
        ));
        // Alignment padding is part of the allocation budget, not permission
        // to return a truncated or boundary-crossing ring.
        let mut short = unsafe { RegionAllocator::new(boundary - 64..boundary + 2048) };
        assert!(matches!(
            Ring::new(&mut short),
            Err(BlockError::NoDmaMemory)
        ));
    }

    #[test]
    fn a_ring_wraps_through_its_link_trb_with_the_cycle_toggled() {
        let mut backing: Vec<u64> = vec![0; 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the vector outlives the allocator.
        let mut dma = unsafe { RegionAllocator::new(start..start + 8192) };
        let mut ring = Ring::new(&mut dma).unwrap();
        for _ in 0..RING_TRBS - 2 {
            ring.push(&[(0, 0, NORMAL << 10)]).unwrap();
        }
        assert!(ring.cycle);
        let addresses = ring
            .push(&[(1, 0, NORMAL << 10), (2, 0, NORMAL << 10)])
            .unwrap();
        assert_eq!(addresses[1], ring.buffer.physical());
        assert!(!ring.cycle);
        let link: u32 = ring.buffer.read((RING_TRBS - 1) * TRB + 12);
        assert_eq!(link, LINK << 10 | TOGGLE | CYCLE);
        let first: u32 = ring.buffer.read((RING_TRBS - 2) * TRB + 12);
        assert_eq!(first & CYCLE, CYCLE);
        let wrapped: u32 = ring.buffer.read(12);
        assert_eq!(wrapped & CYCLE, 0);
    }
}
