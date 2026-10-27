// SPDX-License-Identifier: GPL-2.0-only
//! Ordinary bulk/interrupt TD submission, exact completion identity and DMA
//! retirement. Linux xhci-ring.c (Copyright (C) 2008 Intel Corp., Sarah Sharp)
//! supplies the completion-accounting reference; this is native Rust state.
use super::*;

/// Generation-bound identity of one ordinary bulk/interrupt TD. A dropped
/// ticket leaves DMA owned until completion or acknowledged cancellation.
#[derive(Debug)]
pub struct TransferTicket {
    id: u64,
    device: SlotId,
    dci: u8,
    trb: u64,
}

/// An observed receive boundary after acknowledged endpoint cancellation.
/// Every variant means the endpoint's TDs retired; Unknown supplies no byte
/// count and must not be treated as zero bytes or a complete protocol packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferCancellation {
    Completed(usize),
    Stopped(usize),
    Unknown,
}

impl TransferCancellation {
    fn observed(
        length: usize,
        cached: Option<Result<usize, BlockError>>,
        trb: u64,
        events: &[Event],
    ) -> Self {
        let mut matching = events.iter().filter(|event| event.parameter == trb);
        let event = matching.next();
        if matching.next().is_some() {
            return Self::Unknown;
        }
        if let Some(done) = cached {
            return match (done, event) {
                (Ok(bytes), None) => Self::Completed(bytes),
                _ => Self::Unknown,
            };
        }
        let Some(event) = event else {
            return Self::Unknown;
        };
        if event.control & EVENT_DATA != 0 || event.residual() > length {
            return Self::Unknown;
        }
        match event.code() {
            SUCCESS | SHORT_PACKET => Self::Completed(length - event.residual()),
            // Linux process_bulk_intr_td: Stopped uses bytes remaining,
            // whereas Stopped Short Packet's field already holds actual bytes.
            STOPPED_TRANSFER => Self::Stopped(length - event.residual()),
            STOPPED_SHORT_PACKET => Self::Stopped(event.residual()),
            _ => Self::Unknown,
        }
    }
}

impl TransferTicket {
    pub(in crate::usb::xhci) fn hardware_slot(&self) -> u8 {
        self.device.hardware_slot()
    }

    pub(in crate::usb::xhci) fn device_id(&self) -> SlotId {
        self.device
    }
}

impl Controller {
    /// Queues an ordinary TD and returns its ring address. This legacy API
    /// requires the caller to forget the address after completion/cancellation;
    /// it cannot distinguish that address from a later TD after ring wrap.
    /// New asynchronous consumers should use [`Self::submit_ticket`].
    pub fn submit(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<u64, BlockError> {
        self.legacy_slot(slot)?;
        self.submit_owned(slot, dci, buffer, length)
    }

    pub(in crate::usb::xhci) fn submit_owned(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<u64, BlockError> {
        self.submit_ticket_owned(slot, dci, buffer, length)
            .map(|ticket| ticket.trb)
    }

    /// Publishes a bulk/interrupt TD with an exact, nonwrapping identity.
    /// Each TD fits a single TRB and a single 64 KiB DMA boundary.
    pub fn submit_ticket(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<TransferTicket, BlockError> {
        self.legacy_slot(slot)?;
        self.submit_ticket_owned(slot, dci, buffer, length)
    }

    pub(in crate::usb::xhci) fn submit_ticket_owned(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<TransferTicket, BlockError> {
        self.device_id(slot)?;
        if self.native_memory.is_some() {
            return Err(BlockError::Unsupported(
                "native xHCI requires a retained typed payload",
            ));
        }
        self.submit_ticket_buffer(slot, dci, buffer, length)
    }

    pub(in crate::usb::xhci) fn submit_ticket_buffer(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<TransferTicket, BlockError> {
        let device = self.device_id(slot)?;
        self.validate_id(device)?;
        self.endpoint_ready_owned(slot, dci)?;
        if dci == 1 {
            return Err(BlockError::Unsupported(
                "control endpoint requires control transfer",
            ));
        }
        if length > MAX_TD || (buffer % MAX_TD as u64) as usize + length > MAX_TD {
            return Err(BlockError::Unsupported("TD crosses a 64 KiB boundary"));
        }
        self.dma_profile.check(buffer, length)?;
        let transfer = self.slot(slot)?.endpoints[usize::from(dci)]
            .as_mut()
            .unwrap();
        if transfer.iso.is_some() {
            return Err(BlockError::Unsupported(
                "isochronous endpoint requires submit_iso",
            ));
        }
        if transfer.streams.is_some() {
            return Err(BlockError::Unsupported(
                "stream ID required for this endpoint",
            ));
        }
        let trb = transfer.ring.address();
        let id = transfer.ring.normal.reserve(trb, length)?;
        let direction = if transfer.is_in { ISP } else { 0 };
        transfer
            .ring
            .push(&[(buffer, length as u32, NORMAL << 10 | IOC | direction)])?;
        transfer.in_flight += 1;
        self.doorbell(slot, dci);
        Ok(TransferTicket {
            id,
            device,
            dci,
            trb,
        })
    }

    /// Polls a legacy ring address, checking the original submitted length.
    /// The caller must discard this address after completion or cancellation.
    pub fn completed(
        &mut self,
        slot: u8,
        dci: u8,
        trb: u64,
        length: usize,
    ) -> Option<Result<usize, BlockError>> {
        if let Err(error) = self.legacy_slot(slot) {
            return Some(Err(error));
        }
        self.completed_owned(slot, dci, trb, length)
    }

    pub(in crate::usb::xhci) fn completed_owned(
        &mut self,
        slot: u8,
        dci: u8,
        trb: u64,
        length: usize,
    ) -> Option<Result<usize, BlockError>> {
        if let Err(error) = self.completion_ready(slot, dci) {
            return Some(Err(error));
        }
        let endpoint = self.slot(slot).unwrap().endpoints[usize::from(dci)]
            .as_ref()
            .unwrap();
        if endpoint.iso.is_some() || endpoint.streams.is_some() || dci == 1 {
            return Some(Err(BlockError::Unsupported(
                "endpoint requires its typed completion API",
            )));
        }
        let queue = &self.slot(slot).unwrap().endpoints[usize::from(dci)]
            .as_ref()
            .unwrap()
            .ring
            .normal;
        let id = match queue.identity(trb, length) {
            Ok(Some(id)) => id,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        };
        // A raw address carries only its documented current-generation lifetime.
        let device = match self.device_id(slot) {
            Ok(device) => device,
            Err(error) => return Some(Err(error)),
        };
        self.completed_ticket(&TransferTicket {
            id,
            device,
            dci,
            trb,
        })
    }

    /// Polls an exact submitted TD. Only a valid terminal success/short event
    /// releases that buffer. Errors retain records until acknowledged cancel.
    /// Stale/foreign tickets cannot consume a later generation's completion.
    pub fn completed_ticket(
        &mut self,
        ticket: &TransferTicket,
    ) -> Option<Result<usize, BlockError>> {
        // Reject a retired device before readiness can drain a replacement's events.
        if let Err(error) = self.validate_id(ticket.device_id()) {
            return Some(Err(error));
        }
        let slot = ticket.hardware_slot();
        if let Err(error) = self.completion_ready(slot, ticket.dci) {
            return Some(Err(error));
        }
        let transfer = self.slot(slot).unwrap().endpoints[usize::from(ticket.dci)]
            .as_ref()
            .unwrap();
        if !transfer.ring.normal.contains(ticket.id, ticket.trb) {
            return Some(Err(BlockError::Unsupported(
                "stale or foreign xHCI transfer ticket",
            )));
        }
        let no_soft_retry = self.quirks.no_soft_retry;
        while let Some(event) = self
            .take(|e| e.kind() == TRANSFER_EVENT && e.slot() == slot && e.endpoint() == ticket.dci)
        {
            let state = self.slot(slot).unwrap();
            let translated = state.context[2] & TT_SLOT != 0;
            let endpoint = state.endpoints[usize::from(ticket.dci)].as_mut().unwrap();
            if endpoint
                .ring
                .normal
                .soft_retry(&event, no_soft_retry, translated)
            {
                match self.soft_reset(slot, ticket.dci) {
                    Ok(()) => continue,
                    Err(error) => {
                        // The TD stays halted on the ring; fence it as failed.
                        let _ = self.slot(slot).unwrap().endpoints[usize::from(ticket.dci)]
                            .as_mut()
                            .unwrap()
                            .ring
                            .normal
                            .event(event);
                        return Some(Err(error));
                    }
                }
            }
            if event.code() == INCOMPATIBLE_DEVICE {
                // Incompatible Device requires slot retirement, not merely an
                // endpoint dequeue. Do not allow endpoint cancellation to revive it.
                endpoint.poisoned = true;
                return Some(Err(BlockError::Device {
                    status: event.code(),
                }));
            }
            if let Err(error) = endpoint.ring.normal.event(event) {
                return Some(Err(error));
            }
        }
        let endpoint = self.slot(slot).unwrap().endpoints[usize::from(ticket.dci)]
            .as_mut()
            .unwrap();
        let done = endpoint.ring.normal.completed(ticket.id);
        if done.as_ref().is_some_and(Result::is_ok) {
            endpoint.in_flight -= 1;
        }
        done
    }

    /// Linux xhci_handle_halted_endpoint(EP_SOFT_RESET): Reset Endpoint with
    /// TSP keeps the halted TD in place, and its completion rings the
    /// endpoint again. Like xhci_handle_cmd_reset_ep, the completion code is
    /// ignored; only a command the controller never completed is an error.
    fn soft_reset(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        let target = u32::from(slot) << 24 | u32::from(dci) << 16;
        match self.command(0, 0, RESET_ENDPOINT << 10 | TSP | target) {
            Ok(_) => {}
            Err(BlockError::Device { .. }) if !self.command_poisoned => {}
            Err(error) => return Err(error),
        }
        self.doorbell(slot, dci);
        Ok(())
    }

    /// Cancels this endpoint's complete queue and preserves the requested
    /// ordinary TD's observed receive boundary, including completions racing
    /// Stop Endpoint. Other endpoint tickets become stale. Only exact retained
    /// generation identity authorizes the operation; no raw address assertion
    /// can recover a forgotten ticket. Err retains cancellation uncertainty.
    pub fn cancel_ticket(
        &mut self,
        ticket: &TransferTicket,
    ) -> Result<TransferCancellation, BlockError> {
        let slot = self.validate_id(ticket.device_id())?;
        let queue = &self
            .slot(slot)?
            .endpoints
            .get(usize::from(ticket.dci))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported("xHCI endpoint not configured"))?
            .ring
            .normal;
        let (length, cached) =
            queue
                .cancellation_snapshot(ticket.id, ticket.trb)
                .ok_or(BlockError::Unsupported(
                    "stale or foreign xHCI transfer ticket",
                ))?;
        let observed = self.cancel_observed(slot, ticket.dci)?;
        Ok(TransferCancellation::observed(
            length, cached, ticket.trb, &observed,
        ))
    }

    /// One TD with a budget covering publication and observed completion.
    /// An already expired budget publishes no TD. Actual DMA retirement after
    /// expiry may outlast the budget; failed retirement retains endpoint poison.
    pub fn transfer(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
        microseconds: u64,
    ) -> Result<usize, BlockError> {
        self.legacy_slot(slot)?;
        self.transfer_owned(slot, dci, buffer, length, microseconds)
    }

    pub(in crate::usb::xhci) fn transfer_owned(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
        microseconds: u64,
    ) -> Result<usize, BlockError> {
        // Admit the complete caller budget before publishing any actual TD.
        // The budget includes submission; invalid timing cannot leave a new
        // DMA owner behind an infallible legacy Clock panic.
        let deadline = self.clock.try_deadline(microseconds).map_err(|_| {
            BlockError::Unsupported(
                "xHCI transfer timeout clock unavailable or duration out of range",
            )
        })?;
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        let ticket = self.submit_ticket_owned(slot, dci, buffer, length)?;
        loop {
            if deadline.passed() {
                self.cancel_owned(slot, dci)?;
                return Err(BlockError::Timeout);
            }
            let observed = self.completed_ticket(&ticket);
            // Polling can itself consume the rest of the caller's budget.
            // A late actual completion is not success within this deadline;
            // stop/dequeue still must acknowledge before the buffer returns.
            if deadline.passed() {
                self.cancel_owned(slot, dci)?;
                return Err(BlockError::Timeout);
            }
            if let Some(result) = observed {
                return match result {
                    Ok(bytes) => Ok(bytes),
                    Err(error) => {
                        // Class transports may check readiness and rewrite
                        // their retained buffer after a synchronous error.
                        // Establish actual DMA retirement before returning it.
                        if !matches!(
                            error,
                            BlockError::Device {
                                status: INCOMPATIBLE_DEVICE
                            }
                        ) {
                            self.cancel_owned(slot, dci)?;
                        }
                        Err(error)
                    }
                };
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use crate::usb::xhci::model::*;
    #[test]
    fn transaction_errors_soft_retry_in_place_like_linux() {
        let mut memory = vec![0u64; 64 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: actual fixture RAM remains retained through every owner.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut c, peer) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(64, 64).unwrap().physical();
        let run = |c: &mut Controller, errors: usize| {
            {
                let mut peer = peer.borrow_mut();
                peer.transaction_errors[4] = errors;
                peer.soft_resets.clear();
                peer.seen.clear();
            }
            let ticket = c.submit_ticket(1, 4, buffer, 64).unwrap();
            // Each soft reset leaves the TD in flight for a later poll.
            let result = (0..8).find_map(|_| c.completed_ticket(&ticket));
            (result, peer.borrow().soft_resets.len())
        };
        // Four retries with Transfer State Preserve, the TD kept in place.
        assert_eq!(run(&mut c, 4), (Some(Ok(64)), 4));
        assert_eq!(peer.borrow().seen, vec![RESET_ENDPOINT; 4]);
        assert_eq!(peer.borrow().outgoing.len(), 1);
        assert!(peer.borrow().dequeues.is_empty());
        // The success cleared err_count; the fifth error then fails the TD,
        // which is retired by a hard reset.
        assert_eq!(
            run(&mut c, 5),
            (
                Some(Err(BlockError::Device {
                    status: USB_TRANSACTION_ERROR
                })),
                4
            )
        );
        c.cancel(1, 4).unwrap();
        assert_eq!(peer.borrow().soft_resets.len(), 4);
        assert_eq!(peer.borrow().seen[4..], [RESET_ENDPOINT, SET_DEQUEUE]);
        // err_count stays above the limit until a success.
        let failed = Some(Err(BlockError::Device {
            status: USB_TRANSACTION_ERROR,
        }));
        assert_eq!(run(&mut c, 1), (failed.clone(), 0));
        c.cancel(1, 4).unwrap();
        assert_eq!(run(&mut c, 0), (Some(Ok(64)), 0));
        assert_eq!(run(&mut c, 1), (Some(Ok(64)), 1));
        // XHCI_NO_SOFT_RETRY and a slot behind a TT fail at once.
        c.quirks.no_soft_retry = true;
        assert_eq!(run(&mut c, 1), (failed.clone(), 0));
        c.cancel(1, 4).unwrap();
        c.quirks.no_soft_retry = false;
        c.slots[1].as_mut().unwrap().context[2] = 2;
        assert_eq!(run(&mut c, 1), (failed, 0));
    }

    #[test]
    fn invalid_synchronous_budget_refuses_before_mmio_and_preserves_current_actual_dma_receipt() {
        struct NoAccess;
        impl Registers for NoAccess {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("invalid budget read controller")
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("invalid budget wrote controller")
            }
        }
        let mut memory = vec![0u64; 64 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: actual fixture RAM remains retained through every owner.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut c, peer) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(128, 64).unwrap();
        let old = c.submit_ticket(1, 3, buffer.physical(), 64).unwrap();
        peer.borrow_mut()
            .event(old.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
        let before = memory.clone();
        let cursor = (c.event_index, c.event_cycle);
        let registers = core::mem::replace(&mut c.registers, Box::new(NoAccess));
        for (rate, duration, error) in [
            (
                0,
                1,
                BlockError::Unsupported(
                    "xHCI transfer timeout clock unavailable or duration out of range",
                ),
            ),
            (
                3,
                u64::MAX,
                BlockError::Unsupported(
                    "xHCI transfer timeout clock unavailable or duration out of range",
                ),
            ),
            (
                1,
                u64::MAX / 2 + 1,
                BlockError::Unsupported(
                    "xHCI transfer timeout clock unavailable or duration out of range",
                ),
            ),
            (1, 0, BlockError::Timeout),
        ] {
            c.clock.ticks_per_microsecond = rate;
            assert_eq!(
                c.transfer(1, 3, buffer.physical() + 64, 64, duration),
                Err(error)
            );
            assert_eq!(memory, before);
            assert_eq!((c.event_index, c.event_cycle), cursor);
            let ep = c.slots[1].as_ref().unwrap().endpoints[3].as_ref().unwrap();
            assert_eq!(ep.in_flight, 1);
            assert!(ep.ring.normal.contains(old.id, old.trb));
            assert!(peer.borrow().active[3].is_some());
            assert!(!c.command_poisoned);
        }
        c.registers = registers;
        c.clock.ticks_per_microsecond = 1;
        assert_eq!(c.completed_ticket(&old), Some(Ok(64)));
    }

    #[test]
    fn expired_valid_budget_retires_actual_late_td_and_never_credits_late_completion() {
        struct Empty;
        impl Registers for Empty {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("temporary owner read")
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("temporary owner wrote")
            }
        }
        struct Delayed {
            inner: Box<dyn Registers>,
            after_submit: bool,
            armed: bool,
        }
        impl Delayed {
            fn expire(&mut self) {
                self.armed = false;
                // Explicit test TSC scale: consume four times the complete
                // caller budget after an actual TD was published (and, when
                // polling, after its actual device-side completion).
                let start = Clock::ticks();
                while Clock::ticks().wrapping_sub(start) < 12_000_000 {
                    core::hint::spin_loop();
                }
            }
        }
        impl Registers for Delayed {
            fn read32(&mut self, at: usize) -> u32 {
                let value = self.inner.read32(at);
                if self.armed && !self.after_submit && at == 0x40 + USBSTS {
                    self.expire();
                }
                value
            }
            fn write32(&mut self, at: usize, value: u32) {
                self.inner.write32(at, value);
                if at == 0x1004 {
                    self.armed = true;
                    if self.after_submit {
                        self.expire();
                    }
                }
            }
        }
        for after_submit in [false, true] {
            for failing in [None, Some(STOP_ENDPOINT), Some(SET_DEQUEUE)] {
                let mut memory = vec![0u64; 64 * 1024];
                let start = memory.as_mut_ptr() as u64;
                // SAFETY: actual native-layout fixture RAM outlives every owner.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
                let (mut c, peer) = cancellation_controller(&mut dma);
                let mut buffer = dma.allocate(64, 64).unwrap();
                buffer.bytes_mut().fill(0xa5);
                peer.borrow_mut().incoming_events.push_back(vec![0x79; 64]);
                peer.borrow_mut().fail = failing.map(|kind| (kind, 17));
                let inner = core::mem::replace(&mut c.registers, Box::new(Empty));
                c.registers = Box::new(Delayed {
                    inner,
                    after_submit,
                    armed: false,
                });
                let result = c.transfer(1, 3, buffer.physical(), 64, 3_000_000);
                assert_eq!(buffer.bytes(), &[0x79; 64]); // Real device-side DMA completed.
                let endpoint = c.slots[1].as_ref().unwrap().endpoints[3].as_ref().unwrap();
                assert!(peer.borrow().seen.contains(&STOP_ENDPOINT));
                if failing.is_none() {
                    assert_eq!(result, Err(BlockError::Timeout));
                    assert!(peer.borrow().seen.contains(&SET_DEQUEUE));
                    assert!(!endpoint.poisoned);
                    assert_eq!(endpoint.in_flight, 0);
                    assert!(peer.borrow().active[3].is_none());
                    c.endpoint_ready(1, 3).unwrap();
                } else {
                    assert_eq!(result, Err(BlockError::Device { status: 17 }));
                    assert!(endpoint.poisoned);
                    // Even when polling observed the real terminal event,
                    // failed Stop/dequeue keeps endpoint/context ownership.
                    assert!(c.endpoint_ready(1, 3).is_err());
                    assert_eq!(buffer.bytes(), &[0x79; 64]);
                }
            }
        }
    }
    #[test]
    fn retired_device_ticket_is_pure_before_readiness_and_preserves_current_dma() {
        struct NoAccess;
        impl Registers for NoAccess {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("retired transfer ticket reached MMIO read")
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("retired transfer ticket reached MMIO write")
            }
        }
        for already_pending in [false, true] {
            let mut backing = vec![0u64; 256 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: all modeled DMA remains in this live, disjoint allocation.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut previous, _) = cancellation_controller(&mut dma);
            let (mut current, model) = cancellation_controller(&mut dma);
            let data = dma.allocate(128, 64).unwrap();
            let mut old = previous.submit_ticket(1, 3, data.physical(), 64).unwrap();
            let fresh = current
                .submit_ticket(1, 3, data.physical() + 64, 64)
                .unwrap();
            let current_id = current.device_id(1).unwrap();
            // Distinct modeled generations share hardware slot 1. This tests
            // ticket admission, not the separate architectural slot-reuse proof.
            assert_eq!(old.hardware_slot(), fresh.hardware_slot());
            assert_ne!(old.device_id(), current_id);
            assert_eq!(fresh.device_id(), current_id);
            model
                .borrow_mut()
                .event(fresh.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
            if already_pending {
                current.drain();
            }
            let pending = |c: &Controller| {
                c.pending
                    .iter()
                    .map(|event| (event.parameter, event.status, event.control))
                    .collect::<Vec<_>>()
            };
            let pending_before = pending(&current);
            assert_eq!(pending_before.len(), usize::from(already_pending));
            let memory_before = backing.clone();
            let cursor_before = (current.event_index, current.event_cycle);
            let transfer = current.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            let queue_before = transfer
                .ring
                .normal
                .cancellation_snapshot(fresh.id, fresh.trb);
            let ring_before = (transfer.ring.index, transfer.ring.cycle, transfer.in_flight);
            let registers = core::mem::replace(&mut current.registers, Box::new(NoAccess));
            for (dci, unhealthy) in [(3, false), (u8::MAX, false), (3, true), (u8::MAX, true)] {
                old.dci = dci;
                current.error = unhealthy.then_some(HSE);
                current.command_poisoned = unhealthy;
                let retired =
                    BlockError::Unsupported("xHCI device generation is permanently retired");
                assert_eq!(current.completed_ticket(&old), Some(Err(retired.clone())));
                assert_eq!(current.cancel_ticket(&old), Err(retired));
                assert_eq!(
                    current.device(current_id).unwrap().completed_ticket(&old),
                    Some(Err(BlockError::Unsupported("foreign USB transfer ticket")))
                );
                assert_eq!(
                    current.device(current_id).unwrap().cancel_ticket(&old),
                    Err(BlockError::Unsupported(
                        "foreign USB transfer cancellation ticket"
                    ))
                );
                assert_eq!(current.error, unhealthy.then_some(HSE));
                assert_eq!(current.command_poisoned, unhealthy);
            }
            // Even a malformed current ticket must reject before endpoint indexing.
            let malformed = TransferTicket {
                dci: u8::MAX,
                ..fresh
            };
            assert_eq!(
                current.cancel_ticket(&malformed),
                Err(BlockError::Unsupported("xHCI endpoint not configured"))
            );
            current.slots[1].as_mut().unwrap().suspended = true;
            let retired = BlockError::Unsupported("xHCI device generation is permanently retired");
            assert_eq!(current.completed_ticket(&old), Some(Err(retired.clone())));
            assert_eq!(current.cancel_ticket(&old), Err(retired));
            assert!(matches!(
                current.submit_ticket(1, 3, data.physical(), 64),
                Err(BlockError::Unsupported(
                    "USB consumer is fenced for device lifecycle"
                ))
            ));
            current.slots[1].as_mut().unwrap().suspended = false;
            assert_eq!(pending(&current), pending_before);
            assert_eq!((current.event_index, current.event_cycle), cursor_before);
            assert!(backing == memory_before);
            let transfer = current.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert_eq!(
                transfer
                    .ring
                    .normal
                    .cancellation_snapshot(fresh.id, fresh.trb),
                queue_before
            );
            assert_eq!(
                (transfer.ring.index, transfer.ring.cycle, transfer.in_flight),
                ring_before
            );
            current.registers = registers;
            current.error = None;
            current.command_poisoned = false;
            assert_eq!(current.completed_ticket(&fresh), Some(Ok(64)));
        }
    }

    #[test]
    fn exact_ticket_rejects_foreign_retired_and_reused_addresses() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: one allocator supplies disjoint retained controller/data DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut first, one) = cancellation_controller(&mut dma);
        let (mut second, two) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(64, 64).unwrap();
        let old = first.submit_ticket(1, 3, buffer.physical(), 64).unwrap();
        let foreign = second.submit_ticket(1, 3, buffer.physical(), 64).unwrap();
        two.borrow_mut()
            .event(foreign.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
        assert!(matches!(second.completed_ticket(&old), Some(Err(_))));
        assert_eq!(second.completed_ticket(&foreign), Some(Ok(64)));
        one.borrow_mut()
            .event(old.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
        assert_eq!(first.completed_ticket(&old), Some(Ok(64)));
        // Real producer wrap, not a fabricated new pointer/generation.
        for _ in 1..RING_TRBS - 1 {
            let ticket = first.submit_ticket(1, 3, buffer.physical(), 64).unwrap();
            one.borrow_mut()
                .event(ticket.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
            assert_eq!(first.completed_ticket(&ticket), Some(Ok(64)));
        }
        let fresh = first.submit_ticket(1, 3, buffer.physical(), 64).unwrap();
        assert_eq!(old.trb, fresh.trb);
        one.borrow_mut()
            .event(fresh.trb, SHORT_PACKET, TRANSFER_EVENT, 3, 17);
        assert!(matches!(first.completed_ticket(&old), Some(Err(_))));
        assert_eq!(first.completed_ticket(&fresh), Some(Ok(47)));
    }

    #[test]
    fn out_of_order_polling_cannot_overwrite_an_unconsumed_ring_entry() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all actual descriptor/context accesses.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(64, 64).unwrap();
        let held = controller
            .submit_ticket(1, 3, buffer.physical(), 64)
            .unwrap();
        model
            .borrow_mut()
            .event(held.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
        for _ in 1..RING_TRBS - 1 {
            let ticket = controller
                .submit_ticket(1, 3, buffer.physical(), 64)
                .unwrap();
            model
                .borrow_mut()
                .event(ticket.trb, SUCCESS, TRANSFER_EVENT, 3, 0);
            assert_eq!(controller.completed_ticket(&ticket), Some(Ok(64)));
        }
        let before = controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .bytes()
            .to_vec();
        assert_eq!(
            controller
                .submit_ticket(1, 3, buffer.physical(), 64)
                .unwrap_err(),
            BlockError::Unsupported("xHCI transfer ring full")
        );
        assert_eq!(
            controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .bytes(),
            before
        );
        assert_eq!(controller.completed_ticket(&held), Some(Ok(64)));
        assert!(
            controller
                .submit_ticket(1, 3, buffer.physical(), 64)
                .is_ok()
        );
    }

    #[test]
    fn caller_length_cannot_consume_or_change_the_submitted_completion() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: test allocations remain live until all completion checks finish.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(64, 64).unwrap();
        let trb = controller.submit(1, 3, buffer.physical(), 64).unwrap();
        model
            .borrow_mut()
            .event(trb, SHORT_PACKET, TRANSFER_EVENT, 3, 12);
        assert!(matches!(controller.completed(1, 3, trb, 128), Some(Err(_))));
        assert_eq!(controller.completed(1, 3, trb, 64), Some(Ok(52)));
        assert_eq!(controller.completed(1, 3, trb, 64), None);
    }

    #[test]
    fn malformed_and_error_events_retain_records_until_real_cancel_ack() {
        for (code, residual, parameter_offset, event_data) in [
            (SUCCESS, 65, 0, false),
            (SUCCESS, 0, 8, false),
            (SUCCESS, 0, 0, true),
            (26, 0, 0, false),
            (27, 0, 0, false),
            (28, 0, 0, false),
            (STALL, 0, 0, false),
        ] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: retained backing includes model event ring and data.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(64, 64).unwrap();
            let ticket = controller
                .submit_ticket(1, 3, buffer.physical(), 64)
                .unwrap();
            {
                let mut hardware = model.borrow_mut();
                let at = hardware.events + ((hardware.event_index % RING_TRBS) * TRB) as u64;
                hardware.event(
                    ticket.trb + parameter_offset,
                    code,
                    TRANSFER_EVENT,
                    3,
                    residual,
                );
                if event_data {
                    // SAFETY: fault injection changes only the emitted event's ED flag.
                    unsafe {
                        let p = (at + 12) as *mut u32;
                        p.write_volatile(p.read_volatile() | EVENT_DATA);
                    }
                }
            }
            assert!(matches!(controller.completed_ticket(&ticket), Some(Err(_))));
            assert!(matches!(controller.completed_ticket(&ticket), Some(Err(_))));
            let endpoint = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert_eq!(endpoint.in_flight, 1);
            assert!(endpoint.ring.normal.contains(ticket.id, ticket.trb));
            assert!(
                controller
                    .submit_ticket(1, 3, buffer.physical(), 64)
                    .is_err()
            );
            controller.cancel(1, 3).unwrap();
            assert!(model.borrow().active[3].is_none());
            assert!(matches!(controller.completed_ticket(&ticket), Some(Err(_))));
            assert!(
                controller
                    .submit_ticket(1, 3, buffer.physical(), 64)
                    .is_ok()
            );
        }
    }

    #[test]
    fn actual_dma_payload_and_success_residual_complete_once() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: one retained range contains every actual DMA allocation.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let mut buffer = dma.allocate(64, 64).unwrap();
        buffer.bytes_mut().fill(0xa5);
        model.borrow_mut().incoming_events.push_back(vec![9, 8, 7]);
        let ticket = controller
            .submit_ticket(1, 3, buffer.physical(), 64)
            .unwrap();
        assert_eq!(controller.completed_ticket(&ticket), Some(Ok(3)));
        assert_eq!(&buffer.bytes()[..4], &[9, 8, 7, 0xa5]);
        assert!(matches!(controller.completed_ticket(&ticket), Some(Err(_))));
        let ticket = controller
            .submit_ticket(1, 3, buffer.physical(), 64)
            .unwrap();
        model
            .borrow_mut()
            .event(ticket.trb, SUCCESS, TRANSFER_EVENT, 3, 7);
        assert_eq!(controller.completed_ticket(&ticket), Some(Ok(57)));
    }

    #[test]
    fn ordinary_submit_cannot_publish_normal_trbs_on_ep0() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing retained throughout the refused submission.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(64, 64).unwrap();
        let before = controller.slots[1].as_ref().unwrap().endpoints[1]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .bytes()
            .to_vec();
        let setup = model.borrow().setup.len();
        assert!(
            controller
                .submit_ticket(1, 1, buffer.physical(), 64)
                .is_err()
        );
        assert_eq!(model.borrow().setup.len(), setup);
        assert_eq!(
            controller.slots[1].as_ref().unwrap().endpoints[1]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .bytes(),
            before
        );
    }
    #[test]
    #[ignore = "requires STELA_XHCI_COMPLETION_ORACLE pinned unchanged Linux trace"]
    fn unchanged_linux_one_trb_completion_accounting() {
        extern crate std;
        let path = std::env::var("STELA_XHCI_COMPLETION_ORACLE").unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let mut count = 0;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 5);
            if fields[0] != "B" {
                continue;
            }
            let code: u32 = fields[1].parse().unwrap();
            let length: usize = fields[2].parse().unwrap();
            let residual: usize = fields[3].parse().unwrap();
            let actual: usize = fields[4].parse().unwrap();
            let mut queue = Queue::default();
            let id = queue.reserve(0x1000, length).unwrap();
            queue
                .event(Event {
                    parameter: 0x1000,
                    status: code << 24 | residual as u32,
                    control: TRANSFER_EVENT << 10,
                })
                .unwrap();
            assert_eq!(queue.completed(id), Some(Ok(actual)));
            count += 1;
        }
        assert_eq!(count, 140464);
    }
    #[test]
    fn malformed_control_status_never_acknowledges_or_reuses_dma_without_cancel() {
        struct Empty;
        impl Registers for Empty {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("temporary register owner used");
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("temporary register owner used");
            }
        }
        struct Corrupt {
            inner: Box<dyn Registers>,
            model: Rc<RefCell<CancelModel>>,
            fault: u8,
        }
        impl Registers for Corrupt {
            fn read32(&mut self, at: usize) -> u32 {
                self.inner.read32(at)
            }
            fn write32(&mut self, at: usize, value: u32) {
                self.inner.write32(at, value);
                if at == 0x1004 && value == 1 {
                    let model = self.model.borrow();
                    let event = model.events + (((model.event_index - 1) % RING_TRBS) * TRB) as u64;
                    // SAFETY: corrupt only the real Status event just written
                    // to this test's live event DMA by the underlying model.
                    unsafe {
                        match self.fault {
                            0 => {
                                let p = (event + 12) as *mut u32;
                                p.write_volatile(p.read_volatile() | EVENT_DATA);
                            }
                            1 => ((event + 8) as *mut u32).write_volatile(SUCCESS << 24 | 1),
                            2 => {
                                let p = event as *mut u64;
                                p.write_volatile(p.read_volatile() + 8);
                            }
                            _ => ((event + 8) as *mut u32).write_volatile(SHORT_PACKET << 24),
                        }
                    }
                }
            }
        }
        for fault in 0..4 {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: retained exclusive DMA for underlying and fault model.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let inner = core::mem::replace(&mut controller.registers, Box::new(Empty));
            controller.registers = Box::new(Corrupt {
                inner,
                model: model.clone(),
                fault,
            });
            assert_eq!(
                controller.control(1, setup(0x80, GET_STATUS, 0, 0, 2), &[]),
                Err(BlockError::Unsupported(
                    "invalid xHCI control transfer event"
                ))
            );
            assert_eq!(model.borrow().seen, vec![STOP_ENDPOINT, SET_DEQUEUE]);
            assert!(model.borrow().active[1].is_none());
            assert!(controller.endpoint_ready(1, 1).is_ok());
        }
    }

    #[test]
    fn incompatible_device_event_requires_slot_retirement() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: no allocation is released after uncertain slot ownership.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(64, 64).unwrap();
        let ticket = controller
            .submit_ticket(1, 3, buffer.physical(), 64)
            .unwrap();
        model
            .borrow_mut()
            .event(ticket.trb, INCOMPATIBLE_DEVICE, TRANSFER_EVENT, 3, 0);
        assert_eq!(
            controller.completed_ticket(&ticket),
            Some(Err(BlockError::Device {
                status: INCOMPATIBLE_DEVICE
            }))
        );
        assert!(controller.cancel(1, 3).is_err());
        assert!(
            controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .ring
                .normal
                .contains(ticket.id, ticket.trb)
        );
        assert!(
            controller
                .submit_ticket(1, 3, buffer.physical(), 64)
                .is_err()
        );
        assert!(model.borrow().seen.is_empty());
    }
    #[test]
    fn readiness_fences_async_error_dma_until_acknowledged_retirement() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: actual model DMA is retained through the failed readiness path.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let mut buffer = dma.allocate(64, 64).unwrap();
        buffer.bytes_mut().fill(0xa5);
        let ticket = controller
            .submit_ticket(1, 5, buffer.physical(), 64)
            .unwrap();
        model
            .borrow_mut()
            .event(ticket.trb, SUCCESS, TRANSFER_EVENT, 5, 65);
        assert!(matches!(controller.completed_ticket(&ticket), Some(Err(_))));
        // This is the class transport's readiness-before-buffer-write order.
        // A refused readiness check must stop that write before submit rejects.
        if controller.endpoint_ready(1, 5).is_ok() {
            buffer.bytes_mut().fill(0x37);
        }
        assert_eq!(buffer.bytes(), &[0xa5; 64]);
        assert!(model.borrow().active[5].is_some());
        controller.cancel(1, 5).unwrap();
        assert!(model.borrow().active[5].is_none());
        controller.endpoint_ready(1, 5).unwrap();
        buffer.bytes_mut().fill(0x37);
        assert_eq!(buffer.bytes(), &[0x37; 64]);
    }

    #[test]
    fn synchronous_error_retires_real_dma_before_class_recovery_readiness() {
        for fail_dequeue in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing stays allocated even when cancellation is uncertain.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let mut buffer = dma.allocate(64, 64).unwrap();
            buffer.bytes_mut().fill(0xa5);
            model.borrow_mut().halt_transfer = Some(5);
            if fail_dequeue {
                model.borrow_mut().fail = Some((SET_DEQUEUE, 17));
            }
            // Clock1 is a shortened test TSC scale; this case exercises STALL
            // retirement, not a sub-microsecond whole-operation deadline.
            let result = controller.transfer(1, 5, buffer.physical(), 64, 50_000_000);
            assert!(result.is_err());
            assert_eq!(model.borrow().seen, vec![RESET_ENDPOINT, SET_DEQUEUE]);
            assert_eq!(controller.endpoint_ready(1, 5).is_err(), fail_dequeue);
            assert_eq!(buffer.bytes(), &[0xa5; 64]);
            let endpoint = controller.slots[1].as_ref().unwrap().endpoints[5]
                .as_ref()
                .unwrap();
            if fail_dequeue {
                assert!(endpoint.poisoned);
                assert!(
                    endpoint
                        .ring
                        .normal
                        .identity(endpoint.ring.buffer.physical(), 64)
                        .unwrap()
                        .is_some()
                );
            } else {
                assert_eq!(result, Err(BlockError::Device { status: STALL }));
                assert_eq!(endpoint.in_flight, 0);
            }
        }
    }
    #[test]
    fn cancellation_observes_actual_dma_completion_racing_stop_ack() {
        struct Empty;
        impl Registers for Empty {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("temporary register owner used")
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("temporary register owner used")
            }
        }
        struct Race {
            inner: Box<dyn Registers>,
            model: Rc<RefCell<CancelModel>>,
            code: u32,
        }
        impl Registers for Race {
            fn read32(&mut self, at: usize) -> u32 {
                self.inner.read32(at)
            }
            fn write32(&mut self, at: usize, value: u32) {
                if at == 0x1000 {
                    let mut hardware = self.model.borrow_mut();
                    let command = hardware.commands + (hardware.command_index * TRB) as u64;
                    // SAFETY: actual published command TRB in retained model DMA.
                    let kind =
                        unsafe { ((command + 12) as *const u32).read_volatile() >> 10 & 0x3f };
                    if kind == STOP_ENDPOINT && self.code != 0 {
                        let (trb, buffer, length) = hardware.active[5].unwrap();
                        let bytes = if self.code == 27 { 0 } else { 7 };
                        // SAFETY: the model still owns this submitted receive
                        // DMA. Payload becomes visible before its event/Stop ACK.
                        unsafe {
                            core::slice::from_raw_parts_mut(buffer as *mut u8, bytes).fill(0x37);
                        }
                        let residual = if self.code == 28 {
                            bytes
                        } else {
                            length - bytes
                        };
                        hardware.event(trb, self.code, TRANSFER_EVENT, 5, residual);
                    }
                }
                self.inner.write32(at, value);
            }
        }
        for code in [0, SUCCESS, SHORT_PACKET, 26, 27, 28] {
            for stop_failure in [false, true] {
                let mut backing = vec![0u64; 64 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: controller, observed events and receive bytes retain DMA.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = cancellation_controller(&mut dma);
                let mut buffer = dma.allocate(64, 64).unwrap();
                buffer.bytes_mut().fill(0xa5);
                let ticket = controller
                    .submit_ticket(1, 5, buffer.physical(), 64)
                    .unwrap();
                let inner = core::mem::replace(&mut controller.registers, Box::new(Empty));
                controller.registers = Box::new(Race {
                    inner,
                    model: model.clone(),
                    code,
                });
                if stop_failure {
                    model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
                }
                let result = controller.cancel_ticket(&ticket);
                if stop_failure {
                    assert!(result.is_err());
                    assert!(controller.endpoint_ready(1, 5).is_err());
                    assert!(model.borrow().active[5].is_some());
                    continue;
                }
                let expected = match code {
                    SUCCESS | SHORT_PACKET => TransferCancellation::Completed(7),
                    26 | 28 => TransferCancellation::Stopped(7),
                    _ => TransferCancellation::Unknown,
                };
                assert_eq!(result, Ok(expected));
                if !matches!(expected, TransferCancellation::Unknown) {
                    assert_eq!(
                        &buffer.bytes()[..8],
                        &[0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0xa5]
                    );
                }
                assert!(model.borrow().active[5].is_none());
                controller.endpoint_ready(1, 5).unwrap();
                let commands = model.borrow().seen.clone();
                assert!(controller.cancel_ticket(&ticket).is_err());
                assert_eq!(model.borrow().seen, commands);
            }
        }
    }

    #[test]
    fn cancellation_preserves_an_unpolled_cached_completion_and_retires_siblings() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all allocations remain retained through endpoint-wide cancel.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(128, 64).unwrap();
        model.borrow_mut().incoming_events.push_back(vec![1, 2, 3]);
        let first = controller
            .submit_ticket(1, 3, buffer.physical(), 64)
            .unwrap();
        let second = controller
            .submit_ticket(1, 3, buffer.physical() + 64, 64)
            .unwrap();
        assert_eq!(controller.completed_ticket(&second), None);
        assert_eq!(
            controller.cancel_ticket(&first),
            Ok(TransferCancellation::Completed(3))
        );
        assert_eq!(&buffer.bytes()[..3], &[1, 2, 3]);
        assert!(matches!(controller.completed_ticket(&second), Some(Err(_))));
        assert!(model.borrow().active[3].is_none());
    }

    #[test]
    #[ignore = "requires STELA_XHCI_COMPLETION_ORACLE pinned unchanged Linux trace"]
    fn unchanged_linux_stopped_td_byte_accounting() {
        extern crate std;
        let path = std::env::var("STELA_XHCI_COMPLETION_ORACLE").unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let mut count = 0;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 5);
            if fields[0] != "C" {
                continue;
            }
            let code: u32 = fields[1].parse().unwrap();
            let length: usize = fields[2].parse().unwrap();
            let residual: usize = fields[3].parse().unwrap();
            let actual: usize = fields[4].parse().unwrap();
            let event = Event {
                parameter: 0x1000,
                status: code << 24 | residual as u32,
                control: TRANSFER_EVENT << 10,
            };
            assert_eq!(
                TransferCancellation::observed(length, None, 0x1000, &[event]),
                TransferCancellation::Stopped(actual)
            );
            count += 1;
        }
        assert_eq!(count, 140464);
    }
}
