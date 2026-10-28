// SPDX-License-Identifier: GPL-2.0-only
//! Exact software ownership of an acknowledged Address Device generation.
//!
//! Linux usb_disconnect detaches class consumers before xhci_free_dev disables
//! the hardware slot. A slot number alone cannot express that lifetime: the
//! next Enable Slot may return the same number. This boundary preserves old
//! consumers' permanent refusal across that hardware reuse. Linux's pinned
//! xhci_check_args also compares virt_dev->udev with the actual usb_device;
//! a bare numerical slot is deliberately insufficient here after retirement.
//!
//! Public raw operations check one monotonic retirement fence. Exact access
//! validates its genuine SlotId before entering private implementations; no
//! public bypass flag or raw-to-current identity conversion is exposed.
//! This identity boundary alone does not authorize recycling published slots.
//! Exclusive root-leaf reset also requires retirement's actual physical-reset
//! witness; a new generation never clears the permanent raw-slot fence.
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

    pub(super) fn generation(self) -> u64 {
        self.generation
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
    /// Pure permanent legacy boundary. In particular, no readiness read, event
    /// drain, descriptor access, endpoint index or DMA mutation precedes it.
    pub(super) fn legacy_slot(&self, slot: u8) -> Result<(), BlockError> {
        if self.legacy_slot_fenced.get(usize::from(slot)) != Some(&false) {
            return Err(BlockError::Unsupported(
                "raw xHCI slot authority is permanently retired",
            ));
        }
        self.live_slot(slot)
    }

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
        // Reject the consumer's own retired identity before walking the current
        // replacement's topology. This pure, permanent refusal must also win
        // over a suspended replacement and any absent or foreign parent grant.
        if !self.known_id(id) {
            return Err(BlockError::Unsupported(
                "xHCI device generation is permanently retired",
            ));
        }
        self.validate_ancestry(id)?;
        self.live_slot(id.slot)?;
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

    /// Validate the identities stored at actual enumeration, including the
    /// original parent objects. This pure check also works for a disabled child
    /// whose physical current grant must outlive Disable Slot. Suspension is
    /// allowed for private topology sequencing, never for class access.
    pub(super) fn validate_ancestry(&self, id: SlotId) -> Result<(), BlockError> {
        let mut current = id;
        for depth in 0..=MAX_TIERS {
            if !self.known_id(current) {
                return Err(BlockError::Unsupported(
                    "USB original topology generation retired",
                ));
            }
            let state = self.slots[usize::from(current.slot)].as_ref().unwrap();
            self.power
                .validate_generation(current, state.parent_id, state.attachment)?;
            match (state.attachment.parent, state.parent_id) {
                (None, None) if state.attachment.tier == 0 && state.attachment.route == 0 => {
                    return Ok(());
                }
                (Some((slot, port)), Some(parent))
                    if slot == parent.slot && port != 0 && depth < MAX_TIERS =>
                {
                    if !self.known_id(parent)
                        || self.slot_ownership.get(usize::from(slot))
                            != Some(&reset::Ownership::Enabled)
                    {
                        return Err(BlockError::Unsupported(
                            "USB original parent generation retired",
                        ));
                    }
                    let ancestor = self.slots[usize::from(slot)].as_ref().unwrap();
                    let translator = match (state.attachment.speed, ancestor.attachment.speed) {
                        (LOW_SPEED | FULL_SPEED, HIGH_SPEED) => Some((slot, port)),
                        _ => ancestor.attachment.translator,
                    };
                    if ancestor.retiring
                        || state.attachment.translator != translator
                        || ancestor.attachment.root_port != state.attachment.root_port
                        || ancestor.attachment.tier.checked_add(1) != Some(state.attachment.tier)
                        || enumerate::child_route(
                            ancestor.attachment.route,
                            ancestor.attachment.tier,
                            port,
                        ) != state.attachment.route
                    {
                        return Err(BlockError::Unsupported(
                            "USB original parent attachment changed",
                        ));
                    }
                    current = parent;
                }
                _ => {
                    return Err(BlockError::Unsupported(
                        "USB original parent identity absent",
                    ));
                }
            }
        }
        Err(BlockError::Unsupported(
            "USB original topology exceeds depth",
        ))
    }

    /// Private owned command paths may act before descriptor inventory exists,
    /// e.g. failed EP0 enumeration retirement. Check their stored graph without
    /// issuing a new credential to any retained raw-slot caller.
    pub(super) fn validate_owned_slot_ancestry(&self, slot: u8) -> Result<(), BlockError> {
        let state = self
            .slots
            .get(usize::from(slot))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported("USB owned topology slot absent"))?;
        self.validate_ancestry(SlotId {
            slot,
            generation: state.generation,
        })
    }

    pub(super) fn validate_topology_id(&self, id: SlotId) -> Result<u8, BlockError> {
        self.validate_ancestry(id)?;
        self.live_slot(id.slot)?;
        Ok(id.slot)
    }

    pub(super) fn original_parent(&self, id: SlotId) -> Result<Option<SlotId>, BlockError> {
        self.validate_ancestry(id)?;
        Ok(self.slots[usize::from(id.slot)].as_ref().unwrap().parent_id)
    }

    pub(super) fn validate_attachment_parent(
        &self,
        attachment: Attachment,
        parent: Option<SlotId>,
    ) -> Result<(), BlockError> {
        match (attachment.parent, parent) {
            (None, None)
                if attachment.tier == 0
                    && attachment.route == 0
                    && attachment.translator.is_none() =>
            {
                Ok(())
            }
            (Some((slot, port)), Some(id)) if slot == id.slot && port != 0 => {
                self.validate_topology_id(id)?;
                let ancestor = self.slots[usize::from(slot)].as_ref().unwrap();
                let translator = match (attachment.speed, ancestor.attachment.speed) {
                    (LOW_SPEED | FULL_SPEED, HIGH_SPEED) => Some((slot, port)),
                    _ => ancestor.attachment.translator,
                };
                if attachment.translator != translator
                    || ancestor.attachment.root_port != attachment.root_port
                    || ancestor.attachment.tier.checked_add(1) != Some(attachment.tier)
                    || enumerate::child_route(
                        ancestor.attachment.route,
                        ancestor.attachment.tier,
                        port,
                    ) != attachment.route
                    || self.power.hub_ports(slot).is_none_or(|ports| port > ports)
                {
                    return Err(BlockError::Unsupported(
                        "USB new attachment has a foreign original parent",
                    ));
                }
                Ok(())
            }
            _ => Err(BlockError::Unsupported(
                "USB enumeration requires its original typed parent",
            )),
        }
    }

    /// The private hub recovery capability deliberately retains a quarantined
    /// generation. It never grants ordinary class access or matches a reuse.
    pub(super) fn validate_recovery_id(&self, id: SlotId) -> Result<(), BlockError> {
        self.validate_ancestry(id)?;
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

    /// Pure admission for a retained native consumer, including its original
    /// ancestor generations. No register, completion or DMA access occurs.
    pub(crate) fn validate_device_id(&self, id: SlotId) -> Result<(), BlockError> {
        self.validate_id(id).map(|_| ())
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
        self.controller.control_owned(slot, request, out)
    }

    /// Read a standard string descriptor for this exact addressed generation.
    pub(crate) fn string(&mut self, language: u16, index: u8) -> Option<String> {
        let slot = self.slot().ok()?;
        self.controller.string_owned(slot, language, index)
    }

    pub fn connected(&mut self) -> Result<bool, BlockError> {
        let slot = self.slot()?;
        self.controller.connected_owned(slot)
    }

    pub fn endpoint_ready(&mut self, dci: u8) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.endpoint_ready_owned(slot, dci)
    }

    pub fn current_configuration(&mut self) -> Result<Option<u8>, BlockError> {
        let slot = self.slot()?;
        self.controller.current_configuration_owned(slot)
    }

    pub fn set_configuration(&mut self, value: u8) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.set_configuration_owned(slot, value)
    }

    pub fn configure(
        &mut self,
        endpoints: &[Endpoint],
        hub: Option<(u8, u8, bool)>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.configure_owned(slot, endpoints, hub, dma)
    }

    pub fn preflight_endpoints(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.preflight_endpoints_owned(slot, endpoints)
    }

    pub fn deconfigure(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.deconfigure_owned(slot, endpoints)
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
            .configure_streams_owned(slot, endpoints, stream_endpoints, requested, dma)
    }

    pub(crate) fn stream_capacity(
        &self,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<u16, BlockError> {
        self.controller
            .stream_capacity_for_device(self.id, endpoints, selected, requested)
    }

    pub fn submit(&mut self, dci: u8, buffer: u64, length: usize) -> Result<u64, BlockError> {
        let slot = self.slot()?;
        self.controller.submit_owned(slot, dci, buffer, length)
    }

    pub fn submit_ticket(
        &mut self,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<TransferTicket, BlockError> {
        let slot = self.slot()?;
        self.controller
            .submit_ticket_owned(slot, dci, buffer, length)
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
        self.controller.completed_owned(slot, dci, trb, length)
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
            .transfer_owned(slot, dci, buffer, length, microseconds)
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
            .submit_stream_owned(slot, dci, stream, buffer, length)
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
        self.controller.submit_iso_owned(slot, dci, buffer, length)
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
            .iso_schedule_list_owned(slot, dci, schedule, packet_count)
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
            .submit_iso_scheduled_owned(slot, dci, buffer, length, schedule)
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
        self.controller.cancel_owned(slot, dci)
    }

    pub fn reset_endpoint(&mut self, endpoint: &Endpoint) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.reset_endpoint_owned(slot, endpoint)
    }

    pub fn clear(&mut self, endpoint: &Endpoint) -> Result<(), BlockError> {
        let slot = self.slot()?;
        self.controller.clear_owned(slot, endpoint)
    }

    /// Quarantine this generation without asserting that DMA has stopped.
    pub(crate) fn quarantine(&mut self) {
        if let Ok(slot) = self.slot() {
            self.controller.quarantine_slot_owned(slot);
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

    fn trapped(controller: &Shared, operation: impl FnOnce()) {
        struct NoAccess;
        impl Registers for NoAccess {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("retired USB Ethernet consumer reached MMIO read")
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("retired USB Ethernet consumer reached MMIO write")
            }
        }
        let pending = |c: &Controller| {
            c.pending
                .iter()
                .map(|e| (e.parameter, e.status, e.control))
                .collect::<Vec<_>>()
        };
        let queues = |c: &Controller| {
            c.slots
                .iter()
                .flat_map(|slot| slot.iter())
                .flat_map(|slot| {
                    slot.endpoints
                        .iter()
                        .flatten()
                        .map(|ep| (ep.ring.index, ep.ring.cycle, ep.in_flight))
                })
                .collect::<Vec<_>>()
        };
        let mut c = controller.borrow_mut();
        let before_pending = pending(&c);
        let before_cursor = (c.event_index, c.event_cycle);
        let before_queues = queues(&c);
        let registers = core::mem::replace(&mut c.registers, Box::new(NoAccess));
        drop(c);
        operation();
        let mut c = controller.borrow_mut();
        assert_eq!(pending(&c), before_pending);
        assert_eq!((c.event_index, c.event_cycle), before_cursor);
        assert_eq!(queues(&c), before_queues);
        c.registers = registers;
    }

    fn network_generation_peer(vendor: bool) {
        use crate::bus::dma::RegionAllocator;
        use crate::usb::{
            cdc::generation_tests as cdc_peer, ethernet::generation_tests as vendor_peer,
        };
        for already_pending in [false, true] {
            let mut backing = vec![0u64; 512 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: every modeled DMA buffer remains inside this live allocation.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let configuration = if vendor { 7 } else { 42 };
            let (previous, old_hardware) =
                model::unconfigured_cancellation_controller_with_configurations(
                    &mut dma,
                    &[vec![9, 2, 9, 0, 0, configuration, 0, 0x80, 50]],
                );
            let (current, new_hardware) = model::cancellation_controller(&mut dma);
            let previous = Rc::new(RefCell::new(previous));
            let current = Rc::new(RefCell::new(current));
            let old_id = previous.borrow().device_id(1).unwrap();
            let fresh_id = current.borrow().device_id(1).unwrap();
            assert_eq!(old_id.hardware_slot(), fresh_id.hardware_slot());
            assert_ne!(old_id, fresh_id);
            let mut mac = vec![26, STRING_DESCRIPTOR];
            for unit in "025354000001".encode_utf16() {
                mac.extend_from_slice(&unit.to_le_bytes());
            }
            old_hardware.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, mac)];
            old_hardware.borrow_mut().ethernet =
                vendor.then(|| ethernet::rtl815x::tests::Model::new(0x4c00));
            let mut cdc = (!vendor).then(|| cdc_peer::peer(previous.clone(), &mut dma));
            let mut ethernet = vendor.then(|| vendor_peer::peer(previous.clone(), &mut dma));
            if let Some(peer) = &mut cdc {
                old_hardware.borrow_mut().push_event(vec![
                    DEVICE_TO_HOST | TYPE_CLASS | RECIPIENT_INTERFACE,
                    0,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
                cdc_peer::queue(peer);
            }
            if let Some(peer) = &mut ethernet {
                vendor_peer::queue(peer);
            }
            assert!(old_hardware.borrow().active[3].is_some());
            if !vendor {
                assert!(old_hardware.borrow().active[5].is_some());
            }
            // Execute actual Stop/Set Dequeue and matching Disable Slot completion;
            // no fabricated software retirement or new-generation ID is installed.
            previous
                .borrow_mut()
                .disable_slot(1, reset::Ownership::Retired)
                .unwrap();
            assert!(old_hardware.borrow().active.iter().all(Option::is_none));
            assert_eq!(
                old_hardware.borrow().seen.last(),
                Some(&reset::DISABLE_SLOT)
            );
            assert_eq!(
                previous.borrow().slot_ownership[1],
                reset::Ownership::Retired
            );
            assert_eq!(previous.borrow().dcbaa.read::<u64>(8), 0);
            for dci in [1, 3, 4] {
                assert!(old_hardware.borrow().seen.contains(&STOP_ENDPOINT));
                assert_eq!(old_hardware.borrow().state(dci), ENDPOINT_STOPPED);
            }
            if !vendor {
                assert_eq!(old_hardware.borrow().state(5), ENDPOINT_STOPPED);
            }
            let before = backing.clone();
            trapped(&previous, || {
                if let Some(peer) = &mut cdc {
                    cdc_peer::refuse(peer, &previous);
                }
                if let Some(peer) = &mut ethernet {
                    vendor_peer::refuse(peer, &previous);
                }
                let mut host = previous.borrow_mut();
                let mut access = DeviceAccess {
                    controller: &mut host,
                    id: old_id,
                };
                assert_eq!(access.string(LANGUAGE_EN_US, 1), None);
            });
            assert!(backing == before);

            let mut data = dma.allocate(128, 64).unwrap();
            data.bytes_mut().fill(0xa5);
            let fresh = current
                .borrow_mut()
                .device(fresh_id)
                .unwrap()
                .submit_ticket(5, data.physical(), 64)
                .unwrap();
            new_hardware.borrow_mut().push_acl(vec![0x6a; 64]);
            new_hardware.borrow_mut().receive(5);
            if already_pending {
                current.borrow_mut().drain();
            }
            assert_eq!(current.borrow().pending.len(), usize::from(already_pending));
            let before = backing.clone();
            trapped(&current, || {
                if let Some(peer) = &mut cdc {
                    cdc_peer::refuse(peer, &current);
                }
                if let Some(peer) = &mut ethernet {
                    vendor_peer::refuse(peer, &current);
                }
                let mut host = current.borrow_mut();
                assert!(host.device(old_id).is_err());
                let mut access = DeviceAccess {
                    controller: &mut host,
                    id: old_id,
                };
                assert_eq!(access.string(LANGUAGE_EN_US, 1), None);
            });
            assert!(backing == before);
            assert_eq!(
                current
                    .borrow_mut()
                    .device(fresh_id)
                    .unwrap()
                    .completed_ticket(&fresh),
                Some(Ok(64))
            );
            assert_eq!(&data.bytes()[..64], &[0x6a; 64]);
            assert_eq!(&data.bytes()[64..], &[0xa5; 64]);
            // This exercises retained consumer admission across real retirement
            // and distinct controller generations. Hardware-slot reuse stays
            // disabled and is deliberately not established by this fixture.
        }
    }

    #[test]
    fn retained_cdc_generation_refuses_before_mmio_and_preserves_current_completion() {
        network_generation_peer(false);
    }

    #[test]
    fn retained_vendor_ethernet_generation_refuses_before_mmio_and_preserves_current_completion() {
        network_generation_peer(true);
    }

    fn media_generation_peer(kind: u8) {
        use crate::bus::dma::RegionAllocator;
        use crate::usb::{
            audio::generation_tests as audio_peer,
            bluetooth::{
                ath3k::generation_tests as ath3k_peer, generation_tests as bluetooth_peer,
            },
        };
        for already_pending in [false, true] {
            let mut backing = vec![0u64; 512 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: all native owners/DMAs remain inside this live allocation.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let configuration = match kind {
                0 => audio_peer::configuration(),
                1 | 3 | 4 => bluetooth_peer::configuration(),
                _ => ath3k_peer::configuration(),
            };
            let (previous, hardware) = model::high_speed_media_controller(&mut dma, &configuration);
            let previous = Rc::new(RefCell::new(previous));
            let old_id = previous.borrow().device_id(1).unwrap();
            let mut audio = (kind == 0).then(|| audio_peer::peer(previous.clone(), &mut dma));
            let mut bluetooth =
                (kind == 1).then(|| bluetooth_peer::peer(previous.clone(), &mut dma));
            let mut ath3k = (kind == 2).then(|| ath3k_peer::peer(previous.clone(), &mut dma));
            let mut session =
                (kind == 3).then(|| bluetooth_peer::session_peer(previous.clone(), &mut dma));
            let mut cached_hci =
                (kind == 4).then(|| bluetooth_peer::cached_peer(previous.clone(), &mut dma));
            if kind != 2 {
                assert!(hardware.borrow().active.iter().any(Option::is_some));
            }
            previous
                .borrow_mut()
                .disable_slot(1, reset::Ownership::Retired)
                .unwrap();
            assert!(hardware.borrow().active.iter().all(Option::is_none));
            assert_eq!(hardware.borrow().seen.last(), Some(&reset::DISABLE_SLOT));
            assert_eq!(
                previous.borrow().slot_ownership[1],
                reset::Ownership::Retired
            );
            assert_eq!(previous.borrow().dcbaa.read::<u64>(8), 0);
            let before = backing.clone();
            let before_remaining = dma.remaining();
            trapped(&previous, || {
                if let Some(peer) = &mut audio {
                    audio_peer::refuse(peer, &previous);
                }
                if let Some(peer) = &mut bluetooth {
                    bluetooth_peer::refuse(peer, &previous);
                }
                if let Some(peer) = &mut ath3k {
                    ath3k_peer::refuse(peer, &previous);
                }
                if let Some(peer) = &mut session {
                    bluetooth_peer::session_refuse(peer, &previous);
                }
                if let Some(peer) = &mut cached_hci {
                    bluetooth_peer::cached_refuse(peer, &previous);
                }
            });
            assert_eq!(dma.remaining(), before_remaining);
            assert_eq!(backing, before);

            // A second actual addressed controller independently mints the same
            // hardware slot number; no old identity or publication fence is reset.
            let (current, current_hardware) = model::cancellation_controller(&mut dma);
            let current = Rc::new(RefCell::new(current));
            let current_id = current.borrow().device_id(1).unwrap();
            assert_eq!(current_id.hardware_slot(), old_id.hardware_slot());
            assert_ne!(current_id, old_id);
            let mut data = dma.allocate(128, 64).unwrap();
            data.bytes_mut().fill(0xa5);
            let ticket = current
                .borrow_mut()
                .device(current_id)
                .unwrap()
                .submit_ticket(5, data.physical(), 64)
                .unwrap();
            current_hardware.borrow_mut().push_acl(vec![0x6a; 64]);
            current_hardware.borrow_mut().receive(5);
            if already_pending {
                current.borrow_mut().drain();
            }
            assert_eq!(current.borrow().pending.len(), usize::from(already_pending));
            let before = backing.clone();
            let before_remaining = dma.remaining();
            trapped(&current, || {
                if let Some(peer) = &mut audio {
                    audio_peer::refuse(peer, &current);
                }
                if let Some(peer) = &mut bluetooth {
                    bluetooth_peer::refuse(peer, &current);
                }
                if let Some(peer) = &mut ath3k {
                    ath3k_peer::refuse(peer, &current);
                }
                if let Some(peer) = &mut session {
                    bluetooth_peer::session_refuse(peer, &current);
                }
                if let Some(peer) = &mut cached_hci {
                    bluetooth_peer::cached_refuse(peer, &current);
                }
            });
            assert_eq!(dma.remaining(), before_remaining);
            assert_eq!(backing, before);
            assert_eq!(
                current
                    .borrow_mut()
                    .device(current_id)
                    .unwrap()
                    .completed_ticket(&ticket),
                Some(Ok(64))
            );
            assert_eq!(&data.bytes()[..64], &[0x6a; 64]);
            assert_eq!(&data.bytes()[64..], &[0xa5; 64]);
            // This verifies native admission across retirement and distinct
            // addressed generations. Published hardware-slot reuse stays closed.
        }
    }

    #[test]
    fn retained_uac2_generation_refuses_before_mmio_and_preserves_current_completion() {
        media_generation_peer(0);
    }

    #[test]
    fn retained_mt7925_media_generation_refuses_before_mmio_and_preserves_current_completion() {
        media_generation_peer(1);
    }
    #[test]
    fn retained_hci_generation_refuses_cached_partial_timeout_and_close_before_mmio_and_preserves_current_completion()
     {
        media_generation_peer(4);
    }

    #[test]
    fn retained_mt7925_session_generation_refuses_cached_state_before_mmio_and_preserves_current_completion()
     {
        media_generation_peer(3);
    }

    #[test]
    fn retained_ath3k_initializer_generation_refuses_before_mmio_and_preserves_current_completion()
    {
        media_generation_peer(2);
    }
}

#[cfg(test)]
#[path = "identity/raw_tests.rs"]
pub(super) mod raw_tests;
