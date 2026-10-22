// SPDX-License-Identifier: GPL-2.0-or-later
//! Native xHCI adapter. Each direction reserves a monotonic private ring arena.
//! Controller retains and reactivates the same owned rings only after acknowledged
//! stop/dequeue/drop and event retirement. The class never resets its allocator.
use super::{AudioDevice, Binding, Completion, Control, PacketStatus, Transport};
use crate::{
    audio::Direction,
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer, RegionAllocator},
    usb::xhci::{Device, Endpoint, IsoStatus, IsoTransfer, Shared},
};
use alloc::vec::Vec;

struct Arena {
    _memory: DmaBuffer,
    allocator: RegionAllocator,
    endpoints: Vec<Endpoint>,
}
impl Arena {
    fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        let memory = dma.allocate(65536, 65536)?;
        // SAFETY: reserved exclusively for this adapter, retained for the boot.
        let allocator = unsafe {
            RegionAllocator::new(memory.physical()..memory.physical() + memory.len() as u64)
        };
        Ok(Self {
            _memory: memory,
            allocator,
            endpoints: Vec::new(),
        })
    }
    fn released(&mut self) {
        self.endpoints.clear();
        // The controller retains old ring addresses for the boot. Keep this
        // allocator monotonic even after Drop Context ACK; only PCM can recycle.
    }
}
/// Owns a retained native controller reference and the audio endpoint arenas.
pub struct Native {
    shared: Shared,
    slot: u8,
    playback: Arena,
    capture: Arena,
}
impl Native {
    fn arena(&mut self, owner: Direction) -> &mut Arena {
        match owner {
            Direction::Playback => &mut self.playback,
            Direction::Capture => &mut self.capture,
        }
    }
}
impl Control for Native {
    fn control(&mut self, request: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        self.shared.borrow_mut().control(self.slot, request, out)
    }
    fn now_us(&self) -> u64 {
        self.shared.borrow().clock.now_us()
    }
    fn relax(&mut self) {
        crate::waiting();
        core::hint::spin_loop();
    }
}
impl Transport for Native {
    type Ticket = IsoTransfer;
    fn preflight(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        self.shared
            .borrow_mut()
            .preflight_endpoints(self.slot, endpoints)
    }
    fn configure(&mut self, owner: Direction, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        let shared = self.shared.clone();
        let slot = self.slot;
        let arena = self.arena(owner);
        if !arena.endpoints.is_empty() {
            return Err(BlockError::Unsupported(
                "USB audio endpoint owner already configured",
            ));
        }
        // Keep one exclusive controller borrow from the authoritative recheck
        // through publication. A refusal cannot stage a foreign cleanup owner.
        let mut controller = shared.borrow_mut();
        controller.preflight_endpoints(slot, endpoints)?;
        arena.endpoints.extend_from_slice(endpoints);
        controller.configure(slot, endpoints, None, &mut arena.allocator)
    }
    fn deconfigure(&mut self, owner: Direction, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        let shared = self.shared.clone();
        let slot = self.slot;
        let arena = self.arena(owner);
        if arena.endpoints.is_empty() {
            return Ok(());
        }
        if arena.endpoints != endpoints {
            return Err(BlockError::Unsupported(
                "USB audio endpoint teardown owner mismatch",
            ));
        }
        shared.borrow_mut().deconfigure(slot, endpoints)?;
        arena.released();
        Ok(())
    }
    fn submit(
        &mut self,
        endpoint: &Endpoint,
        physical: u64,
        bytes: usize,
    ) -> Result<Self::Ticket, BlockError> {
        self.shared
            .borrow_mut()
            .submit_iso(self.slot, endpoint.dci(), physical, bytes)
    }
    fn completed(&mut self, ticket: &Self::Ticket) -> Option<Result<Completion, BlockError>> {
        self.shared.borrow_mut().completed_iso(ticket).map(|r| {
            r.map(|c| Completion {
                bytes: c.bytes,
                status: match c.status {
                    IsoStatus::Success => PacketStatus::Success,
                    IsoStatus::Short => PacketStatus::Short,
                    IsoStatus::MissedService => PacketStatus::MissedService,
                    IsoStatus::Transaction => PacketStatus::Transaction,
                    IsoStatus::Babble => PacketStatus::Babble,
                    IsoStatus::Bandwidth => PacketStatus::Bandwidth,
                    IsoStatus::BufferOverrun => PacketStatus::BufferOverrun,
                },
            })
        })
    }
}
/// Native playback/capture owner published by xHCI and retained in probe::Disks.
pub type UsbAudio = AudioDevice<Native>;
impl UsbAudio {
    pub(crate) fn attach(
        shared: Shared,
        device: &Device,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        if !super::supported_identity(&device.descriptor, device.speed) {
            return Err(BlockError::Unsupported(
                "unsupported native USB audio identity",
            ));
        }
        let native = Native {
            shared,
            slot: device.slot,
            playback: Arena::new(dma)?,
            capture: Arena::new(dma)?,
        };
        Self::new(native, binding, dma).map_err(|error| match error {
            super::Error::Transport(e) => e,
            _ => BlockError::Unsupported("USB audio allocation failed"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::xhci;
    #[test]
    fn native_recheck_never_records_or_retires_foreign_pending_dma() {
        for halted in [false, true] {
            let mut memory = alloc::vec![0u64;256*1024];
            let base = memory.as_mut_ptr() as u64;
            // SAFETY: backing RAM is exclusive and outlives every model/owner.
            let mut dma = unsafe { RegionAllocator::new(base..base + memory.len() as u64 * 8) };
            let foreign = dma.allocate(512, 512).unwrap();
            let shared = xhci::tests::controller_with_unresolved_td(
                &mut dma,
                foreign.physical(),
                512,
                5,
                halted,
            );
            let mut native = Native {
                shared: shared.clone(),
                slot: 1,
                playback: Arena::new(&mut dma).unwrap(),
                capture: Arena::new(&mut dma).unwrap(),
            };
            let ep = Endpoint {
                address: 0x82,
                attributes: 1,
                max_packet: 192,
                interval: 4,
                companion: None,
            };
            let refused = BlockError::Unsupported("xHCI endpoint cancellation failed");
            assert_eq!(
                shared.borrow_mut().preflight_endpoints(1, &[ep]),
                Err(refused.clone())
            );
            let before = memory.clone();
            assert!(native.configure(Direction::Playback, &[ep]).is_err());
            assert!(native.playback.endpoints.is_empty());
            // Cleanup of an unstaged candidate is inert; the pre-existing TD
            // cannot be cancelled, poisoned or dropped by the audio owner.
            native.deconfigure(Direction::Playback, &[ep]).unwrap();
            assert_eq!(
                shared.borrow_mut().preflight_endpoints(1, &[ep]),
                Err(refused)
            );
            assert_eq!(memory, before);
        }
    }
}
