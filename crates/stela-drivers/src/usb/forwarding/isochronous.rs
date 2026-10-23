// SPDX-License-Identifier: GPL-2.0-only
//! Packet-list ownership above the actual xHCI service-interval queue.
//! The native controller validates schedules from its own MFINDEX and retained
//! endpoint queue. This adapter never invents a guest frame calendar.
use super::*;
use core::sync::atomic::{Ordering, fence};

const MAX_REQUESTS: usize = 8;
const MAX_PACKETS: usize = 32;
const MAX_ENDPOINT_PACKETS: usize = 128;

struct Packet {
    offset: usize,
    length: usize,
    ticket: Option<xhci::IsoTransfer>,
    done: Option<IsoPacketCompletion>,
}
pub(super) struct IsoRequest {
    pub(super) address: u8,
    pub(super) buffer: DmaBuffer,
    packets: Vec<Packet>,
}

impl Device {
    /// Queue a bounded list of consecutive ASAP service intervals. Each entry
    /// is one native TD, including a zero-length entry. Packet lengths partition
    /// `out` for OUT endpoints; IN requires an empty `out`. Up to eight retained
    /// requests and 128 uncollected packets per endpoint are permitted, with at
    /// most 32 packets and 64 KiB of bounce storage in one request.
    ///
    /// Repeated calls append to the real endpoint schedule while earlier TDs
    /// remain active. Late service is reported per packet by the controller.
    /// Use `submit_isochronous_scheduled` to request an explicit native frame.
    pub fn submit_isochronous(
        &mut self,
        address: u8,
        lengths: &[usize],
        out: &[u8],
        dma: &mut dyn DmaAllocator,
    ) -> Result<Request, BlockError> {
        self.submit_isochronous_scheduled(address, lengths, out, xhci::IsoSchedule::Asap, dma)
    }

    /// Queue consecutive service intervals starting at a caller-selected native
    /// microframe, or preserve the native ASAP policy. The actual addressed
    /// endpoint supplies the interval and queued continuation. The controller
    /// preflights every requested slot before payload allocation or publication,
    /// then validates each TD again as it is submitted. Clock movement or a
    /// controller failure during publication cancels the entire endpoint through
    /// its real acknowledgement path; failed retirement retains all buffers.
    ///
    /// Explicit requests require an encodable first phase, the controller's
    /// scheduling window, and Contiguous Frame ID capability for continuation.
    /// They never fall back to ASAP. Microframe values select the next bounded
    /// occurrence of the native 14-bit clock, not a host-wall-clock epoch.
    pub fn submit_isochronous_scheduled(
        &mut self,
        address: u8,
        lengths: &[usize],
        out: &[u8],
        schedule: xhci::IsoSchedule,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Request, BlockError> {
        self.ready()?;
        let pipe = self
            .pipes
            .get(&address)
            .ok_or(BlockError::Unsupported("inactive forwarded ISO endpoint"))?;
        if pipe.endpoint.kind() != 1 || pipe.streams != 0 || pipe.pending.is_some() {
            return Err(BlockError::Unsupported(
                "forwarded endpoint is not idle packet-list ISO",
            ));
        }
        let endpoint = pipe.endpoint;
        let retained = self.completed.len()
            + self.iso_requests.len()
            + self.pipes.values().filter(|p| p.pending.is_some()).count();
        let queued: usize = self
            .iso_requests
            .values()
            .filter(|r| r.address == address)
            .map(|r| r.packets.len())
            .sum();
        if lengths.is_empty()
            || lengths.len() > MAX_PACKETS
            || queued + lengths.len() > MAX_ENDPOINT_PACKETS
            || self.iso_requests.len() >= MAX_REQUESTS
            || retained >= transfer::MAX_RETAINED_COMPLETIONS
        {
            return Err(BlockError::Unsupported("forwarded ISO request queue limit"));
        }
        // This is only an extent preflight against the retained original
        // descriptor. Native submit_iso independently validates its actual
        // configured recipe, route, controller capability and ring ownership.
        let payload = if let Some(companion) = endpoint.companion {
            usize::from(companion.bytes_per_interval)
        } else {
            usize::from(endpoint.max_packet & 0x7ff)
                * (usize::from(endpoint.max_packet >> 11 & 3) + 1)
        };
        let total = lengths
            .iter()
            .try_fold(0usize, |total, &length| {
                if length > payload {
                    None
                } else {
                    total.checked_add(length)
                }
            })
            .ok_or(BlockError::Unsupported(
                "invalid forwarded ISO packet extent",
            ))?;
        if total > xhci::MAX_TD
            || if endpoint.is_in() {
                !out.is_empty()
            } else {
                out.len() != total
            }
        {
            return Err(BlockError::Unsupported(
                "invalid forwarded ISO request extent",
            ));
        }
        let schedules = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .iso_schedule_list(endpoint.dci(), schedule, lengths.len())?;
        if schedules.len() != lengths.len() {
            return Err(BlockError::Protocol(
                "native ISO schedule list extent mismatch",
            ));
        }
        let mut packets = Vec::new();
        packets
            .try_reserve_exact(lengths.len())
            .map_err(|_| BlockError::NoDmaMemory)?;
        let mut offset = 0;
        for &length in lengths {
            packets.push(Packet {
                offset,
                length,
                ticket: None,
                done: None,
            });
            offset += length;
        }
        // Reserve pool capacity before publication, including return of this
        // request on completion. Buffers are recycled, not reallocated on each
        // packet or successful request.
        self.iso_spare
            .try_reserve(MAX_REQUESTS)
            .map_err(|_| BlockError::NoDmaMemory)?;
        let mut buffer = match self.iso_spare.pop() {
            Some(buffer) => buffer,
            None => dma.allocate(xhci::MAX_TD, xhci::MAX_TD)?,
        };
        let id =
            match transfer::NEXT_REQUEST
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            {
                Ok(id) => id,
                Err(_) => {
                    self.iso_spare.push(buffer);
                    return Err(BlockError::Unsupported("USB request identities exhausted"));
                }
            };
        if !endpoint.is_in() {
            buffer.bytes_mut()[..total].copy_from_slice(out);
        }
        fence(Ordering::SeqCst);
        let request = Request(id);
        // Install ownership BEFORE publishing the first TD. Any partial failure
        // can then cancel every request on the endpoint, or quarantine all of
        // their original buffers if cancellation cannot be acknowledged.
        self.iso_requests.insert(
            request,
            IsoRequest {
                address,
                buffer,
                packets,
            },
        );
        let failure = {
            let mut native = self.controller.borrow_mut();
            let mut controller = native.device(self.physical.id)?;
            let pending = self.iso_requests.get_mut(&request).unwrap();
            let mut failure = None;
            for (packet, schedule) in pending.packets.iter_mut().zip(schedules) {
                match controller.submit_iso_scheduled(
                    endpoint.dci(),
                    pending.buffer.physical() + packet.offset as u64,
                    packet.length,
                    schedule,
                ) {
                    Ok(ticket) => packet.ticket = Some(ticket),
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            failure
        };
        if let Some(error) = failure {
            self.cancel(address)?;
            // No successful submission returned this identity. Earlier requests
            // retain their cancellation completions; this failed call returns
            // its error directly instead of exposing a phantom completion.
            self.completed.retain(|done| done.request != request);
            return Err(error);
        }
        Ok(request)
    }

    /// Observe only actual terminal packet events. This does not release the
    /// request buffer or turn a transport failure into DMA retirement.
    pub(super) fn collect_isochronous(&mut self, request: Request) -> Result<(), BlockError> {
        let pending = self.iso_requests.get_mut(&request).unwrap();
        let endpoint = self.pipes[&pending.address].endpoint;
        {
            let mut native = self.controller.borrow_mut();
            let mut controller = native.device(self.physical.id)?;
            for packet in &mut pending.packets {
                if packet.done.is_some() {
                    continue;
                }
                let Some(ticket) = packet.ticket.as_ref() else {
                    return Err(BlockError::Protocol(
                        "forwarded ISO packet was not submitted",
                    ));
                };
                match controller.completed_iso(ticket) {
                    None => {}
                    Some(Ok(done)) if done.bytes <= packet.length => {
                        fence(Ordering::SeqCst);
                        packet.done = Some(IsoPacketCompletion {
                            offset: packet.offset,
                            requested: packet.length,
                            actual: Some(done.bytes),
                            status: Status::Isochronous(done.status),
                            data: if endpoint.is_in() {
                                pending.buffer.bytes()[packet.offset..packet.offset + done.bytes]
                                    .to_vec()
                            } else {
                                Vec::new()
                            },
                        });
                        packet.ticket = None;
                    }
                    Some(result) => {
                        return Err(match result {
                            Err(error) => error,
                            Ok(_) => BlockError::Protocol(
                                "ISO completion exceeds submitted packet extent",
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn poll_isochronous(
        &mut self,
        request: Request,
    ) -> Result<Option<Completion>, BlockError> {
        if let Err(error) = self.collect_isochronous(request) {
            let address = self.iso_requests[&request].address;
            // No unknown packet bytes are read, even if Stop/Set Dequeue fails.
            self.cancel(address)?;
            let done = self
                .completed
                .iter_mut()
                .find(|done| done.request == request)
                .unwrap();
            done.status = Status::Failed(error.clone());
            for packet in &mut done.packets {
                if packet.status == Status::Cancelled {
                    packet.status = Status::Failed(error.clone());
                }
            }
        } else if self.iso_requests[&request]
            .packets
            .iter()
            .all(|packet| packet.done.is_some())
        {
            self.finish_isochronous(request, Status::Complete);
        } else {
            return Ok(None);
        }
        let index = self
            .completed
            .iter()
            .position(|done| done.request == request)
            .unwrap();
        Ok(Some(self.completed.remove(index)))
    }

    /// Called only after every packet completed, or after native endpoint-wide
    /// cancellation has acknowledged all remaining DMA. Already collected
    /// packet statuses and payloads survive cancellation unchanged.
    pub(super) fn finish_isochronous(&mut self, request: Request, status: Status) {
        let pending = self.iso_requests.remove(&request).unwrap();
        let packets: Vec<_> = pending
            .packets
            .into_iter()
            .map(|packet| {
                packet.done.unwrap_or(IsoPacketCompletion {
                    offset: packet.offset,
                    requested: packet.length,
                    actual: None,
                    status: status.clone(),
                    data: Vec::new(),
                })
            })
            .collect();
        let actual = packets.iter().try_fold(0usize, |total, packet| {
            packet.actual.map(|actual| total + actual)
        });
        self.completed.push(Completion {
            request,
            endpoint: pending.address,
            status,
            actual,
            data: Vec::new(),
            packets,
        });
        self.iso_spare.push(pending.buffer);
    }
}
