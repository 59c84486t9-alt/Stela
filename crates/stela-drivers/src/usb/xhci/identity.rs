// SPDX-License-Identifier: GPL-2.0-only
//! Exact software ownership of an acknowledged Address Device generation.
//!
//! Linux usb_disconnect detaches class consumers before xhci_free_dev disables
//! the hardware slot. A slot number alone cannot express that lifetime: the
//! next Enable Slot may return the same number. This boundary preserves old
//! consumers' permanent refusal across that hardware reuse.
use super::*;
use core::sync::atomic::AtomicU64;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Consumer {
    Unclaimed,
    Native,
    Forwarded,
}

pub(super) fn next_generation() -> Result<u64, BlockError> {
    NEXT_GENERATION
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| BlockError::Unsupported("xHCI device generation space exhausted"))
}

/// Unforgeable identity of one addressed device. Cloning descriptors preserves
/// the same identity; a physical reset or re-enumeration creates a fresh one.
/// Identities are unique across controllers, not just across slots in one host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotId {
    slot: u8,
    generation: u64,
}

impl SlotId {
    /// The hardware slot number is diagnostic data, not an access credential.
    pub fn hardware_slot(self) -> u8 {
        self.slot
    }

    #[cfg(test)]
    pub(crate) fn fixture(slot: u8) -> Self {
        Self {
            slot,
            generation: 0,
        }
    }
}

impl Controller {
    #[cfg(test)]
    pub(crate) fn test_device_id(&self, slot: u8) -> Result<SlotId, BlockError> {
        self.device_id(slot)
    }

    pub(super) fn device_id(&self, slot: u8) -> Result<SlotId, BlockError> {
        self.live_slot(slot)?;
        let state = self.slots[usize::from(slot)].as_ref().unwrap();
        Ok(SlotId {
            slot,
            generation: state.generation,
        })
    }

    pub(super) fn validate_id(&self, id: SlotId) -> Result<u8, BlockError> {
        self.live_slot(id.slot)?;
        if self.slots[usize::from(id.slot)]
            .as_ref()
            .is_none_or(|state| state.generation != id.generation)
        {
            return Err(BlockError::Unsupported(
                "xHCI device generation is permanently retired",
            ));
        }
        if self.slots[usize::from(id.slot)].as_ref().unwrap().suspended {
            return Err(BlockError::Unsupported(
                "USB consumer is fenced for device lifecycle",
            ));
        }
        Ok(id.slot)
    }

    pub(super) fn known_id(&self, id: SlotId) -> bool {
        self.slots
            .get(usize::from(id.slot))
            .and_then(Option::as_ref)
            .is_some_and(|state| state.generation == id.generation)
    }

    /// The private hub recovery capability deliberately retains a quarantined
    /// generation. It never grants ordinary class access or matches a reuse.
    pub(super) fn validate_recovery_id(&self, id: SlotId) -> Result<(), BlockError> {
        if self.slot_ownership.get(usize::from(id.slot)) != Some(&reset::Ownership::Enabled)
            || self
                .slots
                .get(usize::from(id.slot))
                .and_then(Option::as_ref)
                .is_none_or(|state| state.generation != id.generation || !state.retiring)
        {
            return Err(BlockError::Unsupported(
                "USB recovery generation is permanently retired",
            ));
        }
        Ok(())
    }

    /// Borrow operations for this exact device. Validation is pure and occurs
    /// before any MMIO, DMA, completion drain or endpoint mutation. The mutable
    /// controller borrow prevents topology mutation while this access is live.
    pub fn device(&mut self, id: SlotId) -> Result<DeviceAccess<'_>, BlockError> {
        self.validate_id(id)?;
        Ok(DeviceAccess {
            controller: self,
            id,
        })
    }

    /// Bind dispatch takes the whole composite device before the first class
    /// SET_CONFIGURATION or vendor initialization. A failed bind keeps its claim.
    pub(super) fn claim_native(&mut self, id: SlotId) -> Result<(), BlockError> {
        let slot = self.validate_id(id)?;
        let state = self.slot(slot)?;
        if state.consumer != Consumer::Unclaimed {
            return Err(BlockError::Unsupported("USB device already has a consumer"));
        }
        state.consumer = Consumer::Native;
        Ok(())
    }

    pub(super) fn claim_forwarding(&mut self, id: SlotId) -> Result<(), BlockError> {
        let slot = self.validate_id(id)?;
        let state = self.slot(slot)?;
        if state.consumer != Consumer::Unclaimed
            || state.current_configuration != Some(0)
            || state.endpoints.iter().skip(2).any(Option::is_some)
        {
            return Err(BlockError::Unsupported(
                "USB forwarding requires an unclaimed Address-state device",
            ));
        }
        state.consumer = Consumer::Forwarded;
        Ok(())
    }
}

/// Device operations whose slot authority comes from physical enumeration.
/// There is deliberately no Deref to the raw controller or slot setter.
pub struct DeviceAccess<'a> {
    controller: &'a mut Controller,
    id: SlotId,
}

impl DeviceAccess<'_> {
    fn slot(&self) -> Result<u8, BlockError> {
        self.controller.validate_id(self.id)
    }

    pub fn control(&mut self, request: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        let slot = self.slot()?;
        self.controller.control(slot, request, out)
    }

    pub fn connected(&mut self) -> Result<bool, BlockError> {
        let slot = self.slot()?;
        self.controller.connected(slot)
    }

    pub fn endpoint_ready(&mut self, dci: u8) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.endpoint_ready(slot, dci)
    }

    pub fn current_configuration(&mut self) -> Result<Option<u8>, BlockError> {
        let slot = self.slot()?;
        self.controller.current_configuration(slot)
    }

    pub fn set_configuration(&mut self, value: u8) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.set_configuration(slot, value)
    }

    pub fn configure(
        &mut self,
        endpoints: &[Endpoint],
        hub: Option<(u8, u8, bool)>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.configure(slot, endpoints, hub, dma)
    }

    pub fn preflight_endpoints(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.preflight_endpoints(slot, endpoints)
    }

    pub fn deconfigure(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.deconfigure(slot, endpoints)
    }

    pub fn configure_streams(
        &mut self,
        endpoints: &[Endpoint],
        stream_endpoints: &[u8],
        requested: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u16, BlockError> {
        let slot = self.slot()?;
        self.controller
            .configure_streams(slot, endpoints, stream_endpoints, requested, dma)
    }

    pub(crate) fn stream_capacity(
        &self,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<u16, BlockError> {
        let slot = self.slot()?;
        self.controller
            .stream_capacity(slot, endpoints, selected, requested)
    }

    pub fn submit(&mut self, dci: u8, buffer: u64, length: usize) -> Result<u64, BlockError> {
        let slot = self.slot()?;
        self.controller.submit(slot, dci, buffer, length)
    }

    pub fn submit_ticket(
        &mut self,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<TransferTicket, BlockError> {
        let slot = self.slot()?;
        self.controller.submit_ticket(slot, dci, buffer, length)
    }

    pub fn completed_ticket(
        &mut self,
        ticket: &TransferTicket,
    ) -> Option<Result<usize, BlockError>> {
        if let Err(error) = self.slot() {
            return Some(Err(error));
        }
        if ticket.device_id() != self.id {
            return Some(Err(BlockError::Unsupported("foreign USB transfer ticket")));
        }
        self.controller.completed_ticket(ticket)
    }

    pub fn cancel_ticket(
        &mut self,
        ticket: &TransferTicket,
    ) -> Result<TransferCancellation, BlockError> {
        self.slot()?;
        if ticket.device_id() != self.id {
            return Err(BlockError::Unsupported(
                "foreign USB transfer cancellation ticket",
            ));
        }
        self.controller.cancel_ticket(ticket)
    }

    pub fn completed(
        &mut self,
        dci: u8,
        trb: u64,
        length: usize,
    ) -> Option<Result<usize, BlockError>> {
        let slot = match self.slot() {
            Ok(slot) => slot,
            Err(error) => return Some(Err(error)),
        };
        self.controller.completed(slot, dci, trb, length)
    }

    pub fn transfer(
        &mut self,
        dci: u8,
        buffer: u64,
        length: usize,
        microseconds: u64,
    ) -> Result<usize, BlockError> {
        let slot = self.slot()?;
        self.controller
            .transfer(slot, dci, buffer, length, microseconds)
    }

    pub fn submit_stream(
        &mut self,
        dci: u8,
        stream: u16,
        buffer: u64,
        length: usize,
    ) -> Result<StreamTransfer, BlockError> {
        let slot = self.slot()?;
        self.controller
            .submit_stream(slot, dci, stream, buffer, length)
    }

    pub fn completed_stream(
        &mut self,
        ticket: &StreamTransfer,
    ) -> Option<Result<usize, BlockError>> {
        if let Err(error) = self.slot() {
            return Some(Err(error));
        }
        if ticket.device_id() != self.id {
            return Some(Err(BlockError::Unsupported("foreign USB stream ticket")));
        }
        self.controller.completed_stream(ticket)
    }

    pub fn submit_iso(
        &mut self,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<IsoTransfer, BlockError> {
        let slot = self.slot()?;
        self.controller.submit_iso(slot, dci, buffer, length)
    }

    /// Preflight scheduling requests for this exact addressed generation.
    /// Returned values reserve nothing and every submission revalidates native
    /// identity, endpoint state, controller time and scheduling constraints.
    pub fn iso_schedule_list(
        &mut self,
        dci: u8,
        schedule: IsoSchedule,
        packet_count: usize,
    ) -> Result<Vec<IsoSchedule>, BlockError> {
        let slot = self.slot()?;
        self.controller
            .iso_schedule_list(slot, dci, schedule, packet_count)
    }

    /// Submit a scheduling request for this exact addressed generation. The
    /// request carries no hardware authority; controller admission follows
    /// identity validation and precedes DMA publication.
    pub fn submit_iso_scheduled(
        &mut self,
        dci: u8,
        buffer: u64,
        length: usize,
        schedule: IsoSchedule,
    ) -> Result<IsoTransfer, BlockError> {
        let slot = self.slot()?;
        self.controller
            .submit_iso_scheduled(slot, dci, buffer, length, schedule)
    }

    pub fn completed_iso(
        &mut self,
        ticket: &IsoTransfer,
    ) -> Option<Result<IsoCompletion, BlockError>> {
        if let Err(error) = self.slot() {
            return Some(Err(error));
        }
        if ticket.device_id() != self.id {
            return Some(Err(BlockError::Unsupported(
                "foreign USB isochronous ticket",
            )));
        }
        self.controller.completed_iso(ticket)
    }

    pub fn cancel(&mut self, dci: u8) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.cancel(slot, dci)
    }

    pub fn reset_endpoint(&mut self, endpoint: &Endpoint) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.reset_endpoint(slot, endpoint)
    }

    pub fn clear(&mut self, endpoint: &Endpoint) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.clear(slot, endpoint)
    }

    /// Quarantine this generation without asserting that DMA has stopped.
    pub(crate) fn quarantine(&mut self) {
        if let Ok(slot) = self.slot() {
            self.controller.quarantine_slot(slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_identity_is_controller_specific_and_refused_before_mmio() {
        let mut first_memory = vec![0u64; 512 * 1024];
        let mut second_memory = vec![0u64; 512 * 1024];
        let (first, first_device, first_hardware, _first_dma) =
            reset::tests::fixture(&mut first_memory, HIGH_SPEED, 32, 3);
        let (second, second_device, second_hardware, _second_dma) =
            reset::tests::fixture(&mut second_memory, HIGH_SPEED, 32, 3);
        assert_eq!(first_device.slot, second_device.slot);
        assert_ne!(first_device.id, second_device.id);
        let first_accesses = first_hardware.borrow().accesses;
        let second_accesses = second_hardware.borrow().accesses;
        assert!(first.borrow_mut().device(second_device.id).is_err());
        assert!(second.borrow_mut().device(first_device.id).is_err());
        assert_eq!(first_hardware.borrow().accesses, first_accesses);
        assert_eq!(second_hardware.borrow().accesses, second_accesses);
    }

    #[test]
    fn quarantined_identity_cannot_read_cached_configuration_or_take_another_claim() {
        let mut memory = vec![0u64; 512 * 1024];
        let (controller, device, hardware, _dma) =
            reset::tests::fixture(&mut memory, HIGH_SPEED, 64, 3);
        controller.borrow_mut().claim_native(device.id).unwrap();
        assert!(controller.borrow_mut().claim_native(device.id).is_err());
        assert!(controller.borrow_mut().claim_forwarding(device.id).is_err());
        controller.borrow_mut().quarantine_slot(device.slot);
        let accesses = hardware.borrow().accesses;
        assert!(controller.borrow_mut().device(device.id).is_err());
        assert_eq!(hardware.borrow().accesses, accesses);
    }
}
