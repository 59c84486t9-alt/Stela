// SPDX-License-Identifier: GPL-2.0-only
//! Per-hardware-slot EP0 storage for unpublished enumeration retries.
//!
//! Only retirement's noncopyable proof can return storage. Neither a slot ID,
//! physical-port status nor the current ledger can manufacture that proof.
//! Published class/data owners are deliberately outside this cache.
use super::*;

pub(super) struct Resources {
    pub(super) output: DmaBuffer,
    pub(super) input: DmaBuffer,
    pub(super) control: DmaBuffer,
    pub(super) ring: Ring,
}

pub(super) struct Cache {
    // Keep the entire original owner until a new enabled grant and current
    // reservation exist. The old generation is never returned as authority.
    slots: Vec<Option<Slot>>,
}

impl Cache {
    pub(super) fn new(slots: usize) -> Self {
        Self {
            slots: core::iter::repeat_with(|| None).take(slots).collect(),
        }
    }

    pub(super) fn retain(&mut self, retired: retirement::Unpublished) {
        let (slot, state) = retired.into_slot();
        let retained = &mut self.slots[usize::from(slot)];
        assert!(retained.is_none(), "duplicate xHCI retry resource owner");
        *retained = Some(state);
    }

    fn take(&mut self, slot: u8) -> Option<Resources> {
        let state = self.slots[usize::from(slot)].take()?;
        let Slot {
            mut input,
            _output: mut output,
            mut control,
            mut endpoints,
            ..
        } = state;
        let mut ring = endpoints[1].take().unwrap().ring;
        // Disable Slot and its complete ordered event/health fence have already
        // retired every fetch of these addresses. Erase all context bytes and
        // the full segment allocation, including any overfetch padding.
        output.bytes_mut().fill(0);
        input.bytes_mut().fill(0);
        control.bytes_mut().fill(0);
        ring.buffer.bytes_mut().fill(0);
        ring.buffer
            .write((RING_TRBS - 1) * TRB, ring.buffer.physical());
        ring.index = 0;
        ring.cycle = true;
        ring.normal = transfer::Queue::default();
        Some(Resources {
            output,
            input,
            control,
            ring,
        })
    }
}

impl Controller {
    pub(super) fn address_resources(
        &mut self,
        slot: u8,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Resources, BlockError> {
        let index = usize::from(slot);
        // The fresh Enable Slot grant and successful current reservation are
        // established by address before entering here. A cache is storage, never
        // a substitute for either grant or the physical reset between retries.
        if slot == 0
            || self.slot_ownership.get(index) != Some(&reset::Ownership::Enabled)
            || self.slots.get(index).is_none_or(Option::is_some)
            || self.dcbaa.read::<u64>(index * 8) != 0
        {
            return Err(BlockError::Unsupported("invalid xHCI retry resource owner"));
        }
        if let Some(resources) = self.retry_resources.take(slot) {
            return Ok(resources);
        }
        let context = self.context();
        Ok(Resources {
            output: self.dma_profile.allocate(dma, 32 * context, 64)?,
            input: self.dma_profile.allocate(dma, 33 * context, 64)?,
            control: self
                .dma_profile
                .allocate(dma, CONTROL_BYTES, CONTROL_BYTES)?,
            ring: Ring::with_profile(dma, self.dma_profile)?,
        })
    }
}
