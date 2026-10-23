// SPDX-License-Identifier: GPL-2.0-only
//! Requests own bounce buffers, never unchecked guest DMA addresses. Identity,
//! data extent and stream/type checks precede native ring publication.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering, fence};
pub(super) const MAX_RETAINED_COMPLETIONS: usize = 256;
pub(super) static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

impl Device {
    /// Queue one actual control-independent transfer. `out` must be exactly
    /// `length` for OUT and empty for IN. ISO is one native ASAP service interval;
    /// use submit_isochronous for a queued packet list. Native admission checks
    /// actual speed, route and service payload before publication.
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
            Ticket::Normal {
                trb: controller.submit(pipe.endpoint.dci(), pipe.buffer.physical(), length)?,
                length,
            }
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
    /// retains the pending identity and never reads its buffer.
    pub fn poll(&mut self, request: Request) -> Result<Option<Completion>, BlockError> {
        if let Some(index) = self.completed.iter().position(|c| c.request == request) {
            return Ok(Some(self.completed.remove(index)));
        }
        self.ready()?;
        if self.iso_requests.contains_key(&request) {
            return self.poll_isochronous(request);
        }
        let (&address, pipe) = self
            .pipes
            .iter_mut()
            .find(|(_, p)| p.pending.as_ref().is_some_and(|p| p.request == request))
            .ok_or(BlockError::Unsupported(
                "stale or foreign forwarded USB request",
            ))?;
        let pending = pipe.pending.as_ref().unwrap();
        let mut native = self.controller.borrow_mut();
        let mut controller = native.device(self.physical.id)?;
        let result = match &pending.ticket {
            Ticket::Normal { trb, length } => controller
                .completed(pipe.endpoint.dci(), *trb, *length)
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
    /// Packet results already collected remain visible in the final completion.
    pub fn cancel(&mut self, address: u8) -> Result<(), BlockError> {
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
        for request in &requests {
            let _ = self.collect_isochronous(*request);
        }
        if let Err(error) = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .cancel(dci)
        {
            self.fenced = true;
            return Err(error);
        }
        if let Some(pending) = self.pipes.get_mut(&address).unwrap().pending.take() {
            self.completed.push(Completion {
                request: pending.request,
                endpoint: address,
                status: Status::Cancelled,
                actual: None,
                data: Vec::new(),
                packets: Vec::new(),
            });
        }
        for request in requests {
            self.finish_isochronous(request, Status::Cancelled);
        }
        Ok(())
    }

    /// Drain acknowledged cancellation completions, including those generated
    /// by configuration, alternate-setting or shutdown operations.
    pub fn take_completions(&mut self) -> Vec<Completion> {
        core::mem::take(&mut self.completed)
    }
}
