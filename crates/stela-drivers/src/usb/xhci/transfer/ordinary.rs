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
            // whereas Stopped Short Packet's field already holds bytes.
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
        id: impl DeviceRef,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<u64, BlockError> {
        let slot = id.current_slot(self)?;
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
        id: impl DeviceRef,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<TransferTicket, BlockError> {
        let slot = id.current_slot(self)?;
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
        id: impl DeviceRef,
        dci: u8,
        trb: u64,
        length: usize,
    ) -> Option<Result<usize, BlockError>> {
        let slot = match id.current_slot(self) {
            Ok(slot) => slot,
            Err(error) => {
                return Some(Err(error));
            }
        };
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
    /// releases that buffer. Errors keep records until acknowledged cancel.
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
            let tt_info = state.context[2];
            let endpoint = state.endpoints[usize::from(ticket.dci)].as_mut().unwrap();
            if endpoint
                .ring
                .normal
                .soft_retry(&event, no_soft_retry, tt_info)
            {
                match self.soft_reset(slot, ticket.dci, &[u32::from(ticket.dci)]) {
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
                // Incompatible Device requires slot retirement, not an
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

    /// Cancels this endpoint's complete queue and preserves the requested
    /// ordinary TD's observed receive boundary, including completions racing
    /// Stop Endpoint. Other endpoint tickets become stale. Only kept
    /// generation identity authorizes the operation; no raw address assertion
    /// can recover a forgotten ticket. Err keeps cancellation uncertainty.
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
    /// An already expired budget publishes no TD. DMA retirement after
    /// expiry may outlast the budget; failed retirement keeps endpoint poison.
    pub fn transfer(
        &mut self,
        id: impl DeviceRef,
        dci: u8,
        buffer: u64,
        length: usize,
        microseconds: u64,
    ) -> Result<usize, BlockError> {
        let slot = id.current_slot(self)?;
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
        // Admit the complete caller budget before publishing any TD.
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
            // A late completion is not success within this deadline;
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
                        // their buffer after a synchronous error.
                        // Establish DMA retirement before returning it.
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
mod tests;
