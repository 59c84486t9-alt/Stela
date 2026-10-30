// SPDX-License-Identifier: GPL-2.0-only
//! Requests own bounce buffers, never unchecked guest DMA addresses. Identity,
//! data extent and stream/type checks precede native ring publication.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering, fence};
pub(super) const MAX_RETAINED_COMPLETIONS: usize = 256;
pub(super) static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

impl Device {
    /// Queue one control-independent transfer. `out` must be exactly
    /// `length` for OUT and empty for IN. ISO is one native ASAP service interval;
    /// use submit_isochronous for a queued packet list. Native admission checks
    /// speed, route and service payload before publication.
    /// Stream zero selects an ordinary ring; nonzero selects allocated streams.
    pub fn submit(
        &mut self,
        address: u8,
        stream: u16,
        length: usize,
        out: &[u8],
    ) -> Result<Request, BlockError> {
        self.ready()?;
        if self.completed.len()
            + self.iso_requests.len()
            + self
                .pipes
                .values()
                .filter(|pipe| pipe.pending.is_some())
                .count()
            >= MAX_RETAINED_COMPLETIONS
        {
            return Err(BlockError::Unsupported(
                "forwarded USB completion queue full",
            ));
        }
        if self
            .iso_requests
            .values()
            .any(|request| request.address == address)
        {
            return Err(BlockError::Unsupported(
                "forwarded ISO endpoint has queued requests",
            ));
        }
        let pipe = self
            .pipes
            .get_mut(&address)
            .ok_or(BlockError::Unsupported("inactive forwarded USB endpoint"))?;
        if pipe.pending.is_some() {
            return Err(BlockError::Unsupported(
                "forwarded USB endpoint already has a request",
            ));
        }
        if length > pipe.buffer.len()
            || if pipe.endpoint.is_in() {
                !out.is_empty()
            } else {
                out.len() != length
            }
        {
            return Err(BlockError::Unsupported("invalid forwarded USB data extent"));
        }
        if (pipe.streams == 0 && stream != 0)
            || (pipe.streams != 0 && (stream == 0 || stream > pipe.streams))
        {
            return Err(BlockError::Unsupported(
                "invalid forwarded USB stream identity",
            ));
        }
        // Controller poison must be checked before touching a previously used
        // DMA buffer. A prior successful poll/cancel already ended its TD.
        self.controller
            .borrow_mut()
            .device(self.physical.id)?
            .endpoint_ready(pipe.endpoint.dci())?;
        let id = NEXT_REQUEST
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BlockError::Unsupported("USB request identities exhausted"))?;
        if !pipe.endpoint.is_in() {
            pipe.buffer.bytes_mut()[..length].copy_from_slice(out);
        }
        fence(Ordering::SeqCst);
        let mut native = self.controller.borrow_mut();
        let mut controller = native.device(self.physical.id)?;
        let ticket = if stream != 0 {
            Ticket::Stream(controller.submit_stream(
                pipe.endpoint.dci(),
                stream,
                pipe.buffer.physical(),
                length,
            )?)
        } else if pipe.endpoint.kind() == 1 {
            Ticket::Iso(controller.submit_iso(
                pipe.endpoint.dci(),
                pipe.buffer.physical(),
                length,
            )?)
        } else {
            Ticket::Normal(controller.submit_ticket(
                pipe.endpoint.dci(),
                pipe.buffer.physical(),
                length,
            )?)
        };
        let request = Request(id);
        pipe.pending = Some(Pending {
            request,
            ticket,
            length,
        });
        Ok(request)
    }

    /// None means still DMA-owned. A transport failure is terminal only after
    /// acknowledged cancellation; failed cancellation fences the whole owner,
    /// keeps the pending identity and never reads its buffer.
    pub fn poll(&mut self, request: Request) -> Result<Option<Completion>, BlockError> {
        // A current owner may consume acknowledged shutdown receipts even when
        // fenced. Identity admission must still precede cache lookup/removal.
        self.validate_identity()?;
        if let Some(index) = self.completed.iter().position(|c| c.request == request) {
            return Ok(Some(self.completed.remove(index)));
        }
        let address = self.pipes.iter().find_map(|(&address, pipe)| {
            pipe.pending
                .as_ref()
                .is_some_and(|pending| pending.request == request)
                .then_some(address)
        });
        let is_isochronous = self.iso_requests.contains_key(&request);
        if address.is_none() && !is_isochronous {
            return Err(BlockError::Unsupported(
                "stale or foreign forwarded USB request",
            ));
        }
        // Request admission must precede readiness: readiness can drain current
        // events and touch MMIO even when the caller supplied a retired ticket.
        self.ready()?;
        if is_isochronous {
            return self.poll_isochronous(request);
        }
        let address = address.unwrap();
        let pipe = self.pipes.get_mut(&address).unwrap();
        let pending = pipe.pending.as_ref().unwrap();
        let mut native = self.controller.borrow_mut();
        let mut controller = native.device(self.physical.id)?;
        let result = match &pending.ticket {
            Ticket::Normal(ticket) => controller
                .completed_ticket(ticket)
                .map(|r| r.map(|bytes| (bytes, Status::Complete))),
            Ticket::Stream(ticket) => controller
                .completed_stream(ticket)
                .map(|r| r.map(|bytes| (bytes, Status::Complete))),
            Ticket::Iso(ticket) => controller
                .completed_iso(ticket)
                .map(|r| r.map(|done| (done.bytes, Status::Isochronous(done.status)))),
        };
        let Some(result) = result else {
            return Ok(None);
        };
        let (actual, status, data) = match result {
            Ok((bytes, status)) if bytes <= pending.length => {
                fence(Ordering::SeqCst);
                let data = if pipe.endpoint.is_in() {
                    pipe.buffer.bytes()[..bytes].to_vec()
                } else {
                    Vec::new()
                };
                (Some(bytes), status, data)
            }
            failed => {
                if let Err(error) = controller.cancel(pipe.endpoint.dci()) {
                    self.fenced = true;
                    return Err(error);
                }
                let error = match failed {
                    Err(error) => error,
                    Ok(_) => BlockError::Protocol("USB completion exceeds submitted DMA extent"),
                };
                (None, Status::Failed(error), Vec::new())
            }
        };
        pipe.pending = None;
        Ok(Some(Completion {
            request,
            endpoint: address,
            status,
            actual,
            data,
            packets: Vec::new(),
        }))
    }

    /// Cancellation is endpoint-wide in xHCI. All requests and packet buffers
    /// remain owned until Stop/Set Dequeue acknowledges that complete endpoint.
    /// Observed terminal results survive cancellation. Ordinary stopped receive
    /// prefixes carry Cancelled with a count; unknown extents carry None.
    /// Failed acknowledgement keeps the pending request and exposes no data.
    pub fn cancel(&mut self, address: u8) -> Result<(), BlockError> {
        self.validate_identity()?;
        if let Err(error) = self.ready() {
            self.fenced = true;
            return Err(error);
        }
        let pipe = self.pipes.get(&address).ok_or(BlockError::Unsupported(
            "inactive USB cancellation endpoint",
        ))?;
        let count = self
            .iso_requests
            .values()
            .filter(|r| r.address == address)
            .count();
        if pipe.pending.is_none() && count == 0 {
            return Ok(());
        }
        self.completed
            .try_reserve(count + usize::from(pipe.pending.is_some()))
            .map_err(|_| BlockError::NoDmaMemory)?;
        let dci = pipe.endpoint.dci();
        let requests: Vec<_> = self
            .iso_requests
            .iter()
            .filter_map(|(id, r)| (r.address == address).then_some(*id))
            .collect();
        // Preserve terminal events already available at cancellation, including
        // their individual residuals. A transport error cannot release a
        // buffer; native cancellation below still has to acknowledge retirement.
        let requests: Vec<_> = requests
            .into_iter()
            .map(|request| (request, self.collect_isochronous(request).err()))
            .collect();
        // Observe terminal events before Stop, but keep every buffer and
        // pending identity until the whole endpoint acknowledges retirement.
        // The exact ordinary ticket also preserves a completion/receive prefix
        // racing Stop; a ring address alone cannot carry that permission.
        let outcome = {
            let mut native = self.controller.borrow_mut();
            let mut controller = native.device(self.physical.id)?;
            let pending = self.pipes[&address].pending.as_ref();
            let result = pending.and_then(|pending| match &pending.ticket {
                Ticket::Normal(ticket) => controller
                    .completed_ticket(ticket)
                    .map(|done| done.map(|bytes| (bytes, Status::Complete))),
                Ticket::Stream(ticket) => controller
                    .completed_stream(ticket)
                    .map(|done| done.map(|bytes| (bytes, Status::Complete))),
                Ticket::Iso(ticket) => controller
                    .completed_iso(ticket)
                    .map(|done| done.map(|done| (done.bytes, Status::Isochronous(done.status)))),
            });
            let retired = match (pending, result) {
                (
                    Some(Pending {
                        ticket: Ticket::Normal(ticket),
                        ..
                    }),
                    None,
                ) => controller
                    .cancel_ticket(ticket)
                    .map(|observed| match observed {
                        xhci::TransferCancellation::Completed(bytes) => {
                            (Some(bytes), Status::Complete)
                        }
                        xhci::TransferCancellation::Stopped(bytes) => {
                            (Some(bytes), Status::Cancelled)
                        }
                        xhci::TransferCancellation::Unknown => (None, Status::Cancelled),
                    }),
                (_, result) => controller.cancel(dci).map(|()| match result {
                    Some(Ok((bytes, status))) => (Some(bytes), status),
                    Some(Err(error)) => (None, Status::Failed(error)),
                    None => (None, Status::Cancelled),
                }),
            };
            match retired {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.fenced = true;
                    return Err(error);
                }
            }
        };
        if let Some(pending) = self.pipes.get_mut(&address).unwrap().pending.take() {
            let (mut actual, mut status) = outcome;
            if actual.is_some_and(|bytes| bytes > pending.length) {
                actual = None;
                status = Status::Failed(BlockError::Protocol(
                    "USB cancellation exceeds submitted DMA extent",
                ));
            }
            fence(Ordering::SeqCst);
            let pipe = &self.pipes[&address];
            let data = if pipe.endpoint.is_in() {
                actual.map_or_else(Vec::new, |bytes| pipe.buffer.bytes()[..bytes].to_vec())
            } else {
                Vec::new()
            };
            self.completed.push(Completion {
                request: pending.request,
                endpoint: address,
                status,
                actual,
                data,
                packets: Vec::new(),
            });
        }
        for (request, error) in requests {
            self.finish_isochronous(request, error.map_or(Status::Cancelled, Status::Failed));
        }
        Ok(())
    }

    /// Drain acknowledged cancellation completions, including those generated
    /// by configuration, alternate-setting or shutdown operations. A stale
    /// physical generation returns an error and keeps every receipt. A still
    /// current shutdown-fenced owner may drain its acknowledged receipts.
    pub fn take_completions(&mut self) -> Result<Vec<Completion>, BlockError> {
        self.validate_identity()?;
        Ok(core::mem::take(&mut self.completed))
    }
}
