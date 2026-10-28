//! Control, bulk and interrupt transfers on retained rings, and the
//! cancellation that must be acknowledged before a buffer is reused.
use super::*;
mod operation;
mod ordinary;
mod queue;
pub use operation::Operation;
pub(super) use operation::{Cancel, Control, Kind};
pub use ordinary::{TransferCancellation, TransferTicket};
const BABBLE_DETECTED: u32 = 3;
pub(super) const USB_TRANSACTION_ERROR: u32 = 4;
/// Reset Endpoint's Transfer State Preserve flag.
pub(super) const TSP: u32 = 1 << 9;
/// Slot context tt_info's TT Hub Slot ID.
const TT_SLOT: u32 = 0xff;
/// Linux MAX_SOFT_RETRY.
pub(super) const MAX_SOFT_RETRY: u32 = 3;
const SPLIT_TRANSACTION_ERROR: u32 = 36;
const STOPPED_TRANSFER: u32 = 26;
const STOPPED_SHORT_PACKET: u32 = 28;
const INCOMPATIBLE_DEVICE: u32 = 22;
const EVENT_DATA: u32 = 1 << 2;
pub(super) use queue::Queue;

/// Linux process_bulk_intr_td's test for a transaction error: never retried
/// with XHCI_NO_SOFT_RETRY (err_count untouched); otherwise counted, and
/// retried in place while within MAX_SOFT_RETRY on a slot not behind a TT.
pub(super) fn retry_in_place(errors: &mut u32, no_soft_retry: bool, tt_info: u32) -> bool {
    if no_soft_retry {
        return false;
    }
    let previous = *errors;
    *errors = previous.saturating_add(1);
    previous <= MAX_SOFT_RETRY && tt_info & TT_SLOT == 0
}

impl Controller {
    /// Linux xhci_handle_halted_endpoint(EP_SOFT_RESET): Reset Endpoint with
    /// TSP keeps the halted TD in place, and its completion rings every
    /// pending ring again (ring_doorbell_for_active_rings). Like
    /// xhci_handle_cmd_reset_ep, the completion code is ignored; only a
    /// command the controller never completed is an error.
    pub(super) fn soft_reset(
        &mut self,
        slot: u8,
        dci: u8,
        doorbells: &[u32],
    ) -> Result<(), BlockError> {
        self.reset_halted(slot, dci, TSP)?;
        fence(Ordering::SeqCst);
        for value in doorbells {
            self.registers
                .write32(self.doorbells + 4 * usize::from(slot), *value);
        }
        Ok(())
    }

    /// Linux xhci_reset_halted_ep: Reset Endpoint, with TSP for a soft reset.
    pub(super) fn reset_halted(&mut self, slot: u8, dci: u8, flags: u32) -> Result<(), BlockError> {
        let target = u32::from(slot) << 24 | u32::from(dci) << 16;
        match self.command(0, 0, RESET_ENDPOINT << 10 | flags | target) {
            Ok(_) => Ok(()),
            Err(BlockError::Device { .. }) if !self.command_poisoned => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Recovers a halted endpoint: Reset Endpoint, then its dequeue pointer
    /// moved past the failed TD (4.6.8, 4.6.10).
    pub(super) fn recover(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.cancel_owned(slot, dci)
    }

    /// Check controller/endpoint poison before modifying a buffer used by a
    /// previous failed transfer. This does not claim completion of a currently
    /// outstanding TD; its normal completion/cancellation must still be awaited.
    pub fn endpoint_ready(&mut self, id: impl DeviceRef, dci: u8) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        self.endpoint_ready_owned(slot, dci)
    }

    pub(super) fn endpoint_ready_owned(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.completion_ready(slot, dci)?;
        // Incompatible Device may be transferless; its pointer need not name
        // any ticket. It requires slot retirement before new DMA publication.
        let incompatible = self.pending.iter().any(|event| {
            event.kind() == TRANSFER_EVENT
                && event.slot() == slot
                && event.endpoint() == dci
                && event.code() == INCOMPATIBLE_DEVICE
        });
        let endpoint = self.slot(slot)?.endpoints[usize::from(dci)]
            .as_mut()
            .unwrap();
        if incompatible {
            endpoint.poisoned = true;
            return Err(BlockError::Device {
                status: INCOMPATIBLE_DEVICE,
            });
        }
        endpoint.ring.normal.readiness()?;
        if endpoint
            .streams
            .as_ref()
            .is_some_and(streams::Streams::requires_cancellation)
        {
            return Err(BlockError::Unsupported(
                "stream endpoint requires cancellation",
            ));
        }
        if endpoint
            .iso
            .as_ref()
            .is_some_and(iso::Queue::requires_cancellation)
        {
            return Err(BlockError::Unsupported(
                "isochronous endpoint requires cancellation",
            ));
        }
        Ok(())
    }

    /// Completion polling may inspect an errored TD while its buffer remains
    /// fenced against resubmission. Cancellation deliberately bypasses this
    /// submission fence and establishes retirement through actual commands.
    pub(super) fn completion_ready(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.live_slot(slot)?;
        self.endpoint_ready_inner(slot, dci)
    }

    fn endpoint_ready_inner(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.ready()?;
        let state = self.slot(slot)?;
        if dci != 1 && !state.current_configuration.is_some_and(|value| value != 0) {
            return Err(BlockError::Unsupported(
                "USB device configuration is not acknowledged",
            ));
        }
        let endpoint = state
            .endpoints
            .get(usize::from(dci))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported("xHCI endpoint not configured"))?;
        if endpoint.poisoned {
            return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
        }
        if !endpoint.enabled {
            return Err(BlockError::Unsupported(
                "xHCI endpoint configuration is not acknowledged",
            ));
        }
        Ok(())
    }

    /// One control transfer on EP0; IN data is returned, OUT data sent.
    pub fn control(
        &mut self,
        id: impl DeviceRef,
        request: [u8; 8],
        out: &[u8],
    ) -> Result<Vec<u8>, BlockError> {
        let slot = id.current_slot(self)?;
        self.control_owned(slot, request, out)
    }

    pub(super) fn control_owned(
        &mut self,
        slot: u8,
        request: [u8; 8],
        out: &[u8],
    ) -> Result<Vec<u8>, BlockError> {
        let control = self.start_control_owned(slot, request, out)?;
        self.run_control(control)
    }

    pub(super) fn start_control_owned(
        &mut self,
        slot: u8,
        request: [u8; 8],
        out: &[u8],
    ) -> Result<Control, BlockError> {
        self.live_slot(slot)?;
        // Any raw class requester must acquire the same physical-port current
        // reservation as enumeration before publishing a PORT_POWER request.
        if request[0] == 0x23 && request[2..4] == PORT_POWER.to_le_bytes() {
            if request[1] == CLEAR_FEATURE {
                return Err(BlockError::Unsupported(
                    "USB hub port power removal requires subtree retirement",
                ));
            }
            if request[1] == SET_FEATURE {
                if request[5..] != [0; 3] || !out.is_empty() {
                    return Err(BlockError::Unsupported(
                        "invalid USB hub PORT_POWER request",
                    ));
                }
                self.prepare_port_current(slot, request[4])?;
            }
        }
        let configuration = request[0] == 0 && request[1] == SET_CONFIGURATION;
        if configuration {
            if request[3..] != [0; 5] || !out.is_empty() {
                return Err(BlockError::Unsupported("invalid SET_CONFIGURATION request"));
            }
            if self.slot(slot)?.endpoints[2..].iter().any(Option::is_some) {
                return Err(BlockError::Unsupported(
                    "USB configuration change requires endpoint teardown",
                ));
            }
        }
        // A timeout may occur after the device accepted the request; do not
        // preserve the old value or infer success from cancellation of EP0.
        self.endpoint_ready_owned(slot, 1)?;
        let configuration = if configuration {
            let demand = self.prepare_current_configuration(slot, request[2])?;
            self.slot(slot)?.current_configuration = None;
            Some((request[2], demand))
        } else {
            None
        };
        self.start_control(slot, request, out, configuration)
    }

    /// Only the topology owner can mint this capability, after every old alias
    /// is fenced and every descendant/status TD is actually retired. No public
    /// slot API can obtain access merely by naming this still-enabled EP0.
    pub(super) fn recovery_control(
        &mut self,
        owner: &lifecycle::Recovery,
        request: [u8; 8],
    ) -> Result<Vec<u8>, BlockError> {
        self.validate_recovery_id(owner.id())?;
        let slot = owner.slot();
        let status = request == setup(0x80, GET_STATUS, 0, 0, 2)
            || request == setup(0xa0, GET_STATUS, 0, 0, 4);
        let hub_ack = request == setup(0x20, CLEAR_FEATURE, 0, 0, 0)
            || request == setup(0x20, CLEAR_FEATURE, 1, 0, 0);
        let port = request[4];
        let port_request = port != 0
            && self
                .power
                .hub_ports(slot)
                .is_some_and(|ports| port <= ports)
            && (request == setup(0xa3, GET_STATUS, 0, u16::from(port), 4)
                || request == setup(0x23, CLEAR_FEATURE, 19, u16::from(port), 0)
                || request == setup(0x23, SET_FEATURE, PORT_POWER, u16::from(port), 0));
        if !(status || hub_ack || port_request)
            || self.slot_ownership.get(usize::from(slot)) != Some(&reset::Ownership::Enabled)
            || !self.slot(slot)?.retiring
            || (1..self.slots.len()).any(|id| {
                id != usize::from(slot)
                    && self.power.belongs_to(id as u8, slot)
                    && self.slot_ownership[id] == reset::Ownership::Enabled
            })
        {
            return Err(BlockError::Unsupported(
                "invalid quiesced USB hub control authority",
            ));
        }
        if request == setup(0x23, SET_FEATURE, PORT_POWER, u16::from(port), 0) {
            // Preserve all old downstream grants. Only an already reserved
            // physical port may be repowered before the upstream reset ACK.
            self.power.recovery_power(slot, port)?;
        }
        let control = self.start_control(slot, request, &[], None)?;
        self.run_control(control)
    }

    pub(super) fn descriptor(
        &mut self,
        slot: u8,
        kind: u8,
        index: u8,
        length: u16,
    ) -> Result<Vec<u8>, BlockError> {
        let value = u16::from(kind) << 8 | u16::from(index);
        self.control_owned(
            slot,
            setup(DEVICE_TO_HOST, GET_DESCRIPTOR, value, 0, length),
            &[],
        )
    }

    /// Linux `usb_get_langid`: the first language string descriptor 0 lists,
    /// English when it lists none, and no strings when it cannot be read.
    pub(super) fn language(&mut self, slot: u8) -> Option<u16> {
        let bytes = self.descriptor(slot, STRING_DESCRIPTOR, 0, 255).ok()?;
        if bytes.get(1).is_some_and(|kind| *kind != STRING_DESCRIPTOR) {
            return Some(LANGUAGE_EN_US);
        }
        match usize::from(*bytes.first()?).min(bytes.len()) & !1 {
            0 => None,
            2 => Some(LANGUAGE_EN_US),
            _ => Some(u16::from_le_bytes([bytes[2], bytes[3]])),
        }
    }

    #[cfg(test)]
    pub(crate) fn string(
        &mut self,
        id: impl DeviceRef,
        language: u16,
        index: u8,
    ) -> Option<String> {
        let slot = id.current_slot(self).ok()?;
        self.string_owned(slot, language, index)
    }

    pub(super) fn string_owned(&mut self, slot: u8, language: u16, index: u8) -> Option<String> {
        if index == 0 {
            return None;
        }
        let value = u16::from(STRING_DESCRIPTOR) << 8 | u16::from(index);
        let request = setup(DEVICE_TO_HOST, GET_DESCRIPTOR, value, language, 255);
        let bytes = self.control_owned(slot, request, &[]).ok()?;
        if bytes.len() < 2 || bytes[1] != STRING_DESCRIPTOR {
            return None;
        }
        let units: Vec<u16> = bytes[2..usize::from(bytes[0]).min(bytes.len())]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text: String = char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
        Some(String::from(text.trim()))
    }

    /// Current connection of the slot's root port. Downstream hub-port loss
    /// is reported by transfer errors; hotplug enumeration is not performed.
    pub fn connected(&mut self, id: impl DeviceRef) -> Result<bool, BlockError> {
        let slot = id.current_slot(self)?;
        self.connected_owned(slot)
    }

    pub(super) fn connected_owned(&mut self, slot: u8) -> Result<bool, BlockError> {
        self.live_slot(slot)?;
        self.ready()?;
        let port = (self.slot(slot)?.context[1] >> 16 & 0xff) as u8;
        if port == 0 || port > self.max_ports {
            return Err(BlockError::Unsupported("xHCI invalid slot root port"));
        }
        let at = self.port_offset(port);
        Ok(self.registers.read32(at) & CCS != 0)
    }

    /// Abandons every outstanding TD on one exclusively owned
    /// endpoint. Running endpoints are stopped, halted endpoints reset, then
    /// Set TR Dequeue moves past the abandoned TDs (xHCI 1.2 4.6.9/4.6.10).
    /// Success acknowledges that their buffers are no longer hardware-owned.
    /// Failure permanently poisons submission to this endpoint: callers must
    /// retain the buffers and must not read, rewrite or recycle them. Device
    /// disconnect alone is not proof that controller DMA has stopped.
    pub fn cancel(&mut self, id: impl DeviceRef, dci: u8) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        self.cancel_owned(slot, dci)
    }

    pub(super) fn cancel_owned(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.live_slot(slot)?;
        self.cancel_inner(slot, dci)
    }

    pub(super) fn cancel_inner(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.cancel_observed(slot, dci).map(|_| ())
    }

    fn cancel_observed(&mut self, slot: u8, dci: u8) -> Result<Vec<Event>, BlockError> {
        let cancel = self.start_cancel(slot, dci)?;
        self.run_cancel(cancel)
    }

    /// Resets the host side of an endpoint a transaction error halted; the
    /// device's endpoint is not halted, so no CLEAR_FEATURE follows.
    pub fn reset_endpoint(
        &mut self,
        id: impl DeviceRef,
        endpoint: &Endpoint,
    ) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        self.reset_endpoint_owned(slot, endpoint)
    }

    pub(super) fn reset_endpoint_owned(
        &mut self,
        slot: u8,
        endpoint: &Endpoint,
    ) -> Result<(), BlockError> {
        self.recover(slot, endpoint.dci())
    }

    /// Clears a halted bulk or interrupt endpoint on both sides.
    pub fn clear(&mut self, id: impl DeviceRef, endpoint: &Endpoint) -> Result<(), BlockError> {
        let slot = id.current_slot(self)?;
        self.clear_owned(slot, endpoint)
    }

    pub(super) fn clear_owned(&mut self, slot: u8, endpoint: &Endpoint) -> Result<(), BlockError> {
        let (cancel, request) = self.start_clear_owned(slot, endpoint)?;
        self.run_cancel(cancel)?;
        self.control_owned(slot, request, &[])?;
        Ok(())
    }

    /// The host side's cancellation, begun, and the CLEAR_FEATURE that
    /// follows it.
    pub(super) fn start_clear_owned(
        &mut self,
        slot: u8,
        endpoint: &Endpoint,
    ) -> Result<(Cancel, [u8; 8]), BlockError> {
        if endpoint.kind() == 1 {
            return Err(BlockError::Unsupported(
                "isochronous endpoints have no USB halt feature",
            ));
        }
        self.live_slot(slot)?;
        let cancel = self.start_cancel(slot, endpoint.dci())?;
        let request = setup(
            RECIPIENT_ENDPOINT,
            CLEAR_FEATURE,
            0,
            u16::from(endpoint.address),
            0,
        );
        Ok((cancel, request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use crate::usb::xhci::model::*;

    #[test]
    fn strings_use_the_first_listed_language_and_default_to_english() {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all modeled controller DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        for (descriptor, language) in [
            (vec![6, STRING_DESCRIPTOR, 0x07, 0x04, 0x09, 0x04], 0x0407),
            (vec![2, STRING_DESCRIPTOR], LANGUAGE_EN_US),
            (vec![4, DEVICE_DESCRIPTOR, 0x07, 0x04], LANGUAGE_EN_US),
        ] {
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 0, descriptor)];
            assert_eq!(controller.language(1), Some(language));
        }
        // A descriptor too short to hold a language means no strings at all.
        model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 0, vec![1])];
        assert_eq!(controller.language(1), None);
    }

    #[test]
    fn cancellation_stops_running_resets_halted_and_clears_late_events() {
        for initial in [1, 2, 3] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing is exclusive live DMA throughout this test.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(512, 512).unwrap();
            let trb = controller.submit(1, 3, buffer.physical(), 512).unwrap();
            model.borrow_mut().set_state(3, initial);
            model.borrow_mut().stale = Some(trb);
            let pointer = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .ring
                .dequeue_pointer();
            controller.cancel(1, 3).unwrap();
            let expected = match initial {
                1 => vec![STOP_ENDPOINT, SET_DEQUEUE],
                2 => vec![RESET_ENDPOINT, SET_DEQUEUE],
                _ => vec![SET_DEQUEUE],
            };
            assert_eq!(model.borrow().seen, expected);
            assert_eq!(model.borrow().dequeues, vec![pointer]);
            assert_eq!(controller.completed(1, 3, trb, 512), None);
            assert!(controller.submit(1, 3, buffer.physical(), 512).is_ok());
        }
    }

    #[test]
    fn a_full_transfer_ring_refuses_submission_until_cancelled() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing is exclusive live DMA throughout this test.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(512, 512).unwrap();
        for _ in 0..RING_TRBS - 2 {
            controller.submit(1, 3, buffer.physical(), 512).unwrap();
        }
        assert_eq!(
            controller.submit(1, 3, buffer.physical(), 512),
            Err(BlockError::Unsupported("xHCI transfer ring full"))
        );
        model.borrow_mut().set_state(3, 1);
        controller.cancel(1, 3).unwrap();
        assert!(controller.submit(1, 3, buffer.physical(), 512).is_ok());
    }

    #[test]
    fn cancellation_failure_keeps_dma_recorded_and_blocks_reuse() {
        for failure in [
            Some((STOP_ENDPOINT, 11)),
            Some((STOP_ENDPOINT, 19)),
            Some((SET_DEQUEUE, 17)),
            None,
        ] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives controller/model/DMA access.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(512, 512).unwrap();
            controller.submit(1, 3, buffer.physical(), 512).unwrap();
            model.borrow_mut().fail = failure;
            if failure.is_none() {
                model.borrow_mut().silence = Some(STOP_ENDPOINT);
            }
            assert!(controller.cancel(1, 3).is_err());
            assert!(
                controller.slots[1].as_ref().unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .poisoned
            );
            let commands = model.borrow().seen.len();
            assert!(controller.submit(1, 3, buffer.physical(), 512).is_err());
            assert!(controller.cancel(1, 3).is_err());
            let endpoint = Endpoint {
                address: 0x81,
                attributes: 3,
                max_packet: 16,
                interval: 1,
                companion: None,
            };
            assert!(controller.clear(1, &endpoint).is_err());
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            assert_eq!(model.borrow().seen.len(), commands);
            if failure != Some((SET_DEQUEUE, 17)) {
                assert!(model.borrow().active[3].is_some());
                assert_eq!(model.borrow().state(3), 1);
            }
        }
    }

    #[test]
    fn cancellation_handles_completion_and_halt_races_without_resetting_running() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains exclusive and live through controller/model use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(512, 512).unwrap();
        let trb = controller.submit(1, 3, buffer.physical(), 512).unwrap();
        model.borrow_mut().event(trb, SUCCESS, TRANSFER_EVENT, 3, 0);
        assert_eq!(controller.completed(1, 3, trb, 512), Some(Ok(512)));
        controller.cancel(1, 3).unwrap(); // Empty ring still Running.
        model.borrow_mut().seen.clear();
        controller.submit(1, 3, buffer.physical(), 512).unwrap();
        model.borrow_mut().race_halt = true;
        controller.cancel(1, 3).unwrap();
        assert_eq!(
            model.borrow().seen,
            vec![STOP_ENDPOINT, RESET_ENDPOINT, SET_DEQUEUE]
        );
    }

    #[test]
    fn short_control_out_after_status_ack_fails_without_poisoning_completed_endpoint() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all model DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        model.borrow_mut().short_control_out = true;
        let request = setup(0x40, 5, 0xe810, 0x0188, 4);
        assert_eq!(
            controller.control(1, request, &[0; 4]),
            Err(BlockError::Unsupported("short USB control OUT transfer"))
        );
        assert!(controller.endpoint_ready(1, 1).is_ok());
        assert_eq!(model.borrow().indices[1], 3);
        assert!(model.borrow().seen.is_empty());
        model.borrow_mut().short_control_out = false;
        assert!(controller.control(1, request, &[0; 4]).is_ok());
        assert_eq!(model.borrow().indices[1], 6);
        assert!(model.borrow().active[1].is_none());
    }

    #[test]
    fn control_timeout_stops_running_ep0_and_retains_poison_if_stop_fails() {
        for fail_stop in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive test backing outlives all DMA/controller use.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            model.borrow_mut().silence_transfer = Some(1);
            if fail_stop {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
            }
            let result = controller.control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0]);
            if fail_stop {
                assert!(matches!(
                    result,
                    Err(BlockError::Unsupported("xHCI endpoint did not stop"))
                ));
                assert!(
                    controller.slots[1].as_ref().unwrap().endpoints[1]
                        .as_ref()
                        .unwrap()
                        .poisoned
                );
                assert!(model.borrow().active[1].is_some());
                let old = controller.slots[1]
                    .as_ref()
                    .unwrap()
                    .control
                    .bytes()
                    .to_vec();
                let count = model.borrow().setup.len();
                assert!(
                    controller
                        .control(1, setup(0x20, 0, 0, 0, 3), &[9, 8, 7])
                        .is_err()
                );
                assert_eq!(controller.slots[1].as_ref().unwrap().control.bytes(), old);
                assert_eq!(model.borrow().setup.len(), count);
            } else {
                assert_eq!(result, Err(BlockError::Timeout));
                assert_eq!(model.borrow().seen, vec![STOP_ENDPOINT, SET_DEQUEUE]);
                assert!(model.borrow().active[1].is_none());
                model.borrow_mut().silence_transfer = None;
                assert!(
                    controller
                        .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
                        .is_ok()
                );
            }
            assert!(!model.borrow().seen.contains(&RESET_ENDPOINT));
        }
    }

    #[test]
    fn bulk_timeout_stops_running_td_and_cannot_reuse_it_after_failed_cancel() {
        for fail_stop in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive test backing outlives all DMA/controller use.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(512, 512).unwrap();
            if fail_stop {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
            }
            // Keep a valid publication window in this shortened Clock1 model;
            // the actual held TD then consumes the budget and must stop.
            let result = controller.transfer(1, 5, buffer.physical(), 512, 3_000_000);
            if fail_stop {
                assert!(matches!(
                    result,
                    Err(BlockError::Unsupported("xHCI endpoint did not stop"))
                ));
                assert!(model.borrow().active[5].is_some());
                let old = controller.slots[1].as_ref().unwrap().endpoints[5]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes()
                    .to_vec();
                assert!(controller.endpoint_ready(1, 5).is_err());
                assert!(
                    controller
                        .transfer(1, 5, buffer.physical(), 512, 1)
                        .is_err()
                );
                assert_eq!(
                    controller.slots[1].as_ref().unwrap().endpoints[5]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .bytes(),
                    old
                );
            } else {
                assert_eq!(result, Err(BlockError::Timeout));
                assert_eq!(model.borrow().seen, vec![STOP_ENDPOINT, SET_DEQUEUE]);
                assert!(model.borrow().active[5].is_none());
                model.borrow_mut().push_acl(vec![1, 2, 3]);
                assert_eq!(
                    controller.transfer(1, 5, buffer.physical(), 512, 50_000_000),
                    Ok(3)
                );
                assert_eq!(&buffer.bytes()[..3], &[1, 2, 3]);
            }
            assert!(!model.borrow().seen.contains(&RESET_ENDPOINT));
        }
    }

    #[test]
    fn halted_reset_with_failed_dequeue_refuses_endpoint_and_dma_reuse() {
        for dci in [1, 3, 4, 5] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives controller/model and every DMA buffer.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let buffer = dma.allocate(512, 512).unwrap();
            let (mut controller, model) =
                failed_stall_recovery(&mut dma, buffer.physical(), buffer.len(), dci);
            let slot = controller.slots[1].as_ref().unwrap();
            let control = slot.control.bytes().to_vec();
            let input = slot.input.bytes().to_vec();
            let transfer = slot.endpoints[usize::from(dci)].as_ref().unwrap();
            assert!(transfer.poisoned);
            let ring = transfer.ring.buffer.bytes().to_vec();
            let commands = controller.commands.buffer.bytes().to_vec();
            let seen = model.borrow().seen.len();
            let setup_count = model.borrow().setup.len();
            let old_index = model.borrow().indices[usize::from(dci)];
            assert!(controller.endpoint_ready(1, dci).is_err());
            assert!(controller.submit(1, dci, buffer.physical(), 512).is_err());
            assert!(
                controller
                    .completed(1, dci, buffer.physical(), 512)
                    .unwrap()
                    .is_err()
            );
            assert!(controller.cancel(1, dci).is_err());
            if dci == 1 {
                assert!(
                    controller
                        .control(1, setup(0x20, 0, 0, 0, 3), &[0; 3])
                        .is_err()
                );
                assert!(controller.recover(1, dci).is_err());
            } else {
                let endpoint = fixture_endpoint(dci);
                assert!(controller.clear(1, &endpoint).is_err());
                assert!(
                    controller
                        .configure(1, &[endpoint], None, &mut dma)
                        .is_err()
                );
            }
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(slot.control.bytes(), control);
            assert_eq!(slot.input.bytes(), input);
            assert_eq!(
                slot.endpoints[usize::from(dci)]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes(),
                ring
            );
            assert_eq!(controller.commands.buffer.bytes(), commands);
            assert_eq!(model.borrow().seen.len(), seen);
            assert_eq!(model.borrow().setup.len(), setup_count);
            assert_eq!(model.borrow().indices[usize::from(dci)], old_index);
            // An acknowledged Set Dequeue error poisons only its endpoint.
            let healthy = if dci == 5 { 3 } else { 5 };
            assert!(controller.endpoint_ready(1, healthy).is_ok());
            model.borrow_mut().fail = None;
            assert!(controller.command(0, 0, ENABLE_SLOT << 10).is_ok());
            assert!(!controller.command_poisoned);
        }
    }
}
