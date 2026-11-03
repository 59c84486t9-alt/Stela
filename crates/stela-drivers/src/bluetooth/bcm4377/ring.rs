// SPDX-License-Identifier: MIT
// Copyright (C) The Asahi Linux Contributors
//! Fixed converged-IPC ring messages and ownership from hci_bcm4377.c.
use super::*;
use core::sync::atomic::{Ordering, fence};

const ENTRIES: usize = 128;
const CR_HEAD: usize = STATE_OFFSET;
const CR_TAIL: usize = STATE_OFFSET + 12;
const TR_HEAD: usize = STATE_OFFSET + 24;
const TR_TAIL: usize = STATE_OFFSET + 42;
const FOOTER: u8 = 2;
const MAPPED: u8 = 1;
const CONTROL_BYTES: usize = 52;

pub(super) struct Transfer {
    buffer: Option<CoherentBuffer>,
    payloads: Option<CoherentBuffer>,
    footer: usize,
    mapped: usize,
    completion: u16,
    doorbell: u16,
    virtual_ring: bool,
    sync: bool,
    enabled: bool,
    generation: u8,
    inflight: [bool; ENTRIES],
}
impl Transfer {
    pub fn allocate_all(dma: &mut dyn CoherentAllocator) -> Result<[Self; 7]> {
        let configs = [
            (52, 0, 0, 0, false, false),
            (264, 0, 1, 1, false, false),
            (0, 0, 2, 2, true, false),
            (260, 0, 3, 6, false, true),
            (0, 0, 4, 6, true, true),
            (0, 1032, 1, 3, false, false),
            (0, 1032, 2, 4, false, false),
        ];
        let mut rings = Vec::new();
        for (id, (footer, mapped, completion, doorbell, virtual_ring, sync)) in
            configs.into_iter().enumerate()
        {
            let bytes = ENTRIES * (16 + footer);
            let buffer = if virtual_ring {
                None
            } else {
                Some(dma.allocate(bytes)?)
            };
            let payloads = if mapped == 0 {
                None
            } else {
                Some(dma.allocate(ENTRIES * mapped)?)
            };
            if buffer.as_ref().is_some_and(|b| b.len() < bytes)
                || payloads
                    .as_ref()
                    .is_some_and(|b| b.len() < ENTRIES * mapped)
            {
                return Err(Error::Unsupported("complete owned Broadcom transfer ring"));
            }
            rings.push(Self {
                buffer,
                payloads,
                footer,
                mapped,
                completion,
                doorbell,
                virtual_ring,
                sync,
                enabled: false,
                generation: u8::from(id != 0),
                inflight: [false; ENTRIES],
            });
        }
        rings
            .try_into()
            .map_err(|_| Error::Unsupported("seven source Broadcom transfer rings"))
    }
    fn address(&self) -> u64 {
        self.buffer.as_ref().map_or(0, CoherentBuffer::address)
    }
    pub fn retain(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            core::mem::forget(buffer);
        }
        if let Some(payloads) = self.payloads.take() {
            core::mem::forget(payloads);
        }
    }
    pub unsafe fn release(&mut self) -> Result<()> {
        if let Some(buffer) = self.buffer.as_mut() {
            // SAFETY: caller independently retired all DMA/posted/IRQ/work.
            unsafe { buffer.release()? };
        }
        if let Some(payloads) = self.payloads.as_mut() {
            // SAFETY: same whole-requester retirement.
            unsafe { payloads.release()? };
        }
        Ok(())
    }
}
pub(super) struct Completion {
    buffer: Option<CoherentBuffer>,
    entries: usize,
    footer: usize,
    transfers: u16,
    delay: u16,
    enabled: bool,
}
impl Completion {
    pub fn allocate_all(dma: &mut dyn CoherentAllocator) -> Result<[Self; 5]> {
        let configs = [
            (32, 0, 1, 0),
            (256, 0, 0x22, 1000),
            (256, 264, 0x44, 1000),
            (128, 0, 8, 0),
            (128, 260, 16, 0),
        ];
        let mut rings = Vec::new();
        for (entries, footer, transfers, delay) in configs {
            let bytes = entries * (16 + footer);
            let buffer = dma.allocate(bytes)?;
            if buffer.len() < bytes {
                return Err(Error::Unsupported(
                    "complete owned Broadcom completion ring",
                ));
            }
            rings.push(Self {
                buffer: Some(buffer),
                entries,
                footer,
                transfers,
                delay,
                enabled: false,
            });
        }
        rings
            .try_into()
            .map_err(|_| Error::Unsupported("five source Broadcom completion rings"))
    }
    fn address(&self) -> u64 {
        self.buffer.as_ref().unwrap().address()
    }
    pub fn retain(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            core::mem::forget(buffer);
        }
    }
    pub unsafe fn release(&mut self) -> Result<()> {
        // SAFETY: caller independently retired all DMA/posted/IRQ/work.
        unsafe { self.buffer.as_mut().unwrap().release() }
    }
}
fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

impl<P: Platform> Transport<P> {
    pub(super) fn initialize_context(&mut self) {
        let base = self.core().address();
        let mut context = [0; 104];
        // Donor prose says 2, but its initializer writes version 1.
        put16(&mut context, 0, 1);
        put16(&mut context, 2, 104);
        put32(&mut context, 4, 2);
        for (offset, address) in [
            (8, base + PERIPHERAL_OFFSET as u64),
            (16, base + CR_HEAD as u64),
            (24, base + TR_TAIL as u64),
            (32, base + CR_TAIL as u64),
            (40, base + TR_HEAD as u64),
            (52, self.completions[0].address()),
            (60, self.transfers[0].address()),
        ] {
            put64(&mut context, offset, address);
        }
        put16(&mut context, 48, 6);
        put16(&mut context, 50, 9);
        put16(&mut context, 68, 128);
        put16(&mut context, 70, 32);
        put16(&mut context, 74, 0xffff);
        context[81] = 13;
        self.core_mut().write(0, &context);
    }
    fn ring_index(&self, array: usize, ring: usize, entries: usize) -> Result<u16> {
        let index = self.core().read16(array + ring * 2);
        if usize::from(index) >= entries {
            return Err(Error::Protocol {
                requirement: "bounded actual Broadcom ring index",
                observed: u64::from(index),
            });
        }
        Ok(index)
    }
    fn doorbell(&mut self, ring: usize, head: u16) -> Result<()> {
        let value = u32::from(head) << 16 | u32::from(self.transfers[ring].doorbell) << 8 | 0x20;
        self.write(Space::Bar0, DOORBELL, value)
    }
    pub(super) fn enqueue_ring(&mut self, id: usize, bytes: &[u8]) -> Result<Submission> {
        self.check_budget()?;
        let ring = &self.transfers[id];
        if !ring.enabled || ring.virtual_ring || bytes.len() > ring.footer.max(ring.mapped) {
            return Err(Error::Unsupported(
                "enabled bounded Broadcom host transfer ring",
            ));
        }
        let head = self.ring_index(TR_HEAD, id, ENTRIES)?;
        let tail = self.ring_index(TR_TAIL, id, ENTRIES)?;
        let next = (head + 1) % ENTRIES as u16;
        if next == tail {
            return Err(Error::QueueFull(id as u16));
        }
        let message = ring
            .inflight
            .iter()
            .position(|used| !used)
            .ok_or(Error::QueueFull(id as u16))?;
        let raw = u16::from(ring.generation) << 8 | message as u16;
        let ring = &mut self.transfers[id];
        ring.inflight[message] = true;
        let mut entry = [0; 16];
        entry[0] = if bytes.len() <= ring.footer {
            FOOTER
        } else {
            MAPPED
        };
        put16(&mut entry, 1, bytes.len() as u16);
        put16(&mut entry, 12, raw);
        if entry[0] == FOOTER {
            let offset = usize::from(head) * (16 + ring.footer);
            ring.buffer.as_mut().unwrap().write(offset + 16, bytes);
        } else {
            let payloads = ring.payloads.as_mut().unwrap();
            put64(
                &mut entry,
                4,
                payloads.address() + (message * ring.mapped) as u64,
            );
            payloads.write(message * ring.mapped, bytes);
        }
        let offset = usize::from(head) * (16 + ring.footer);
        ring.buffer.as_mut().unwrap().write(offset, &entry);
        let sync = ring.sync;
        if entry[0] == MAPPED {
            self.publish(self.transfers[id].payloads.as_ref().unwrap())?;
        }
        self.publish(self.transfers[id].buffer.as_ref().unwrap())?;
        self.write(Space::Bar0, SLEEP, 2)?;
        self.check_budget()?;
        self.core_mut().write16(TR_HEAD + id * 2, next);
        self.publish(self.core())?;
        if !sync {
            self.doorbell(id, next)?;
        }
        Ok(Submission {
            ring: id as u16,
            message: raw,
        })
    }
    fn control(&mut self, bytes: &[u8; CONTROL_BYTES]) -> Result<()> {
        let deadline = self.platform().now_us().saturating_add(1_000_000);
        self.request_deadline = Some(RequestDeadline::Control(deadline));
        let result = self.control_inner(bytes, deadline);
        self.request_deadline = None;
        result
    }
    fn control_inner(&mut self, bytes: &[u8; CONTROL_BYTES], deadline: u64) -> Result<()> {
        let submitted = self.enqueue_ring(0, bytes)?;
        loop {
            if self.platform().now_us() >= deadline {
                return Err(Error::Timeout(
                    "actual Broadcom control-ring acknowledgment",
                ));
            }
            self.service()?;
            if self.platform().now_us() >= deadline {
                return Err(Error::Timeout(
                    "actual Broadcom control-ring acknowledgment",
                ));
            }
            if !self.transfers[0].inflight[usize::from(submitted.message & 0xff)] {
                return Ok(());
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    pub(super) fn open_rings(&mut self) -> Result<()> {
        self.transfers[0].enabled = true;
        self.completions[0].enabled = true;
        for id in 1..5 {
            let ring = &self.completions[id];
            let mut message = [0; CONTROL_BYTES];
            message[0] = 2;
            message[2] = (ring.footer / 4) as u8;
            put16(&mut message, 4, id as u16);
            put16(&mut message, 6, id as u16);
            put64(&mut message, 8, ring.address());
            put16(&mut message, 16, ring.entries as u16);
            put32(&mut message, 18, u32::MAX);
            put16(&mut message, 30, ring.delay);
            put32(&mut message, 32, u32::MAX);
            self.control(&message)?;
            self.completions[id].enabled = true;
        }
        for id in 1..7 {
            let ring = &self.transfers[id];
            let mut message = [0; CONTROL_BYTES];
            message[0] = 1;
            message[2] = (ring.footer / 4) as u8;
            put16(&mut message, 4, id as u16);
            put16(&mut message, 6, id as u16);
            put64(&mut message, 8, ring.address());
            put16(&mut message, 24, ENTRIES as u16);
            put16(&mut message, 26, ring.completion);
            put16(&mut message, 28, ring.doorbell);
            put16(
                &mut message,
                30,
                (u16::from(ring.virtual_ring) * 0x80) | (u16::from(ring.sync) * 0x100),
            );
            self.control(&message)?;
            self.transfers[id].enabled = true;
            if id == 6 {
                self.check_budget()?;
                let ring = &mut self.transfers[id];
                for index in 0..ENTRIES {
                    let mut entry = [0; 16];
                    entry[0] = MAPPED;
                    put16(&mut entry, 1, ring.mapped as u16);
                    put64(
                        &mut entry,
                        4,
                        ring.payloads.as_ref().unwrap().address() + (index * ring.mapped) as u64,
                    );
                    put16(
                        &mut entry,
                        12,
                        u16::from(ring.generation) << 8 | index as u16,
                    );
                    ring.buffer.as_mut().unwrap().write(index * 16, &entry);
                }
                self.publish(self.transfers[id].buffer.as_ref().unwrap())?;
            }
            if matches!(id, 2 | 4 | 6) {
                self.check_budget()?;
                self.core_mut().write16(TR_HEAD + id * 2, 15);
                self.publish(self.core())?;
                self.doorbell(id, 15)?;
            }
        }
        Ok(())
    }
    /// Publish a source descriptor, not an invented DMA/HCI completion.
    pub fn send(&mut self, kind: Kind, bytes: &[u8]) -> Result<Submission> {
        if self.state != State::Active {
            return Err(Error::State(self.state));
        }
        packet_length(kind, bytes)?;
        let id = match kind {
            Kind::Command => 1,
            Kind::Acl => 5,
            Kind::Sco => 3,
            Kind::Event => return Err(Error::Unsupported("outbound Broadcom event")),
        };
        if bytes.len() > self.transfers[id].footer.max(self.transfers[id].mapped) {
            return Err(Error::Packet {
                kind,
                bytes: bytes.into(),
            });
        }
        let result = self.service().and_then(|()| self.enqueue_ring(id, bytes));
        match result {
            Ok(submission) => Ok(submission),
            Err(error @ Error::QueueFull(_)) => Err(error),
            Err(error) => Err(self.fail(error)),
        }
    }
    pub fn poll(&mut self) -> Result<Observations> {
        if self.state != State::Active {
            return Err(Error::State(self.state));
        }
        if let Err(error) = self.service() {
            return Err(self.fail(error));
        }
        Ok(self.take_observations())
    }
    fn record_bytes(&mut self, bytes: usize) -> Result<()> {
        self.observation_bytes = self
            .observation_bytes
            .checked_add(bytes)
            .ok_or(Error::ObservationLimit)?;
        if self.observation_bytes > OBSERVATION_BYTES {
            return Err(Error::ObservationLimit);
        }
        Ok(())
    }
    pub(super) fn service(&mut self) -> Result<()> {
        self.platform().service_begin()?;
        self.refresh_snapshot()?;
        if self.snapshot.boot_stage != 2 || self.snapshot.rti_status != 2 {
            return Err(Error::Protocol {
                requirement: "live Broadcom firmware and RTI state2",
                observed: u64::from(self.snapshot.boot_stage) << 32
                    | u64::from(self.snapshot.rti_status),
            });
        }
        for ring_id in [0, 2, 1, 3, 4] {
            if !self.completions[ring_id].enabled {
                continue;
            }
            let count = self.completions[ring_id].entries;
            let mut tail = self.ring_index(CR_TAIL, ring_id, count)?;
            for _ in 0..count {
                if tail == self.ring_index(CR_HEAD, ring_id, count)? {
                    break;
                }
                // Native coherent producer-index publication precedes payload.
                fence(Ordering::Acquire);
                let ring = &self.completions[ring_id];
                let offset = usize::from(tail) * (16 + ring.footer);
                let entry: [u8; 16] = ring
                    .buffer
                    .as_ref()
                    .unwrap()
                    .read(offset, 16)
                    .try_into()
                    .unwrap();
                self.snapshot.completion = Some(entry);
                self.snapshot.completion_footer =
                    ring.buffer.as_ref().unwrap().read(offset + 16, ring.footer);
                let transfer = usize::from(u16::from_le_bytes([entry[2], entry[3]]));
                if transfer >= 7
                    || ring.transfers & (1 << transfer) == 0
                    || !self.transfers[transfer].enabled
                {
                    return Err(Error::Protocol {
                        requirement: "actual enabled Broadcom completion-to-transfer mapping",
                        observed: transfer as u64,
                    });
                }
                let raw = u16::from_le_bytes([entry[4], entry[5]]);
                if matches!(transfer, 0 | 1 | 3 | 5) {
                    let id = self.message_id(transfer, raw)?;
                    if !self.transfers[transfer].inflight[id] {
                        return Err(Error::Protocol {
                            requirement: "owned actual Broadcom ACK message",
                            observed: u64::from(raw),
                        });
                    }
                    self.observations.completions.push(Receipt {
                        submission: Submission {
                            ring: transfer as u16,
                            message: raw,
                        },
                        completion: entry,
                    });
                    self.record_bytes(16)?;
                    self.transfers[transfer].inflight[id] = false;
                } else {
                    self.receive(ring_id, offset, transfer, raw, entry)?;
                }
                tail = (tail + 1) % count as u16;
                self.check_budget()?;
                self.core_mut().write16(CR_TAIL + ring_id * 2, tail);
                self.publish(self.core())?;
            }
        }
        Ok(())
    }
    fn message_id(&self, ring: usize, raw: u16) -> Result<usize> {
        let id = usize::from(raw & 0xff);
        if raw >> 8 != u16::from(self.transfers[ring].generation) || id >= ENTRIES {
            return Err(Error::Protocol {
                requirement: "source Broadcom generation and bounded message id",
                observed: u64::from(raw),
            });
        }
        Ok(id)
    }
    fn receive(
        &mut self,
        completion: usize,
        offset: usize,
        transfer: usize,
        raw: u16,
        entry: [u8; 16],
    ) -> Result<()> {
        let ring = &self.completions[completion];
        let len = u32::from_le_bytes(entry[6..10].try_into().unwrap()) as usize;
        let footer = ring.buffer.as_ref().unwrap().read(offset + 16, ring.footer);
        self.snapshot.completion_footer = footer.clone();
        let bytes = if transfer == 6 && entry[0] & MAPPED != 0 {
            let id = self.message_id(transfer, raw)?;
            let ring = &self.transfers[transfer];
            if len > ring.mapped {
                return Err(Error::Protocol {
                    requirement: "bounded Broadcom mapped RX length",
                    observed: len as u64,
                });
            }
            ring.payloads.as_ref().unwrap().read(id * ring.mapped, len)
        } else {
            if len > ring.footer {
                return Err(Error::Protocol {
                    requirement: "bounded Broadcom completion footer length",
                    observed: len as u64,
                });
            }
            footer[..len].to_vec()
        };
        let kind = match transfer {
            2 => Kind::Event,
            4 => Kind::Sco,
            6 => Kind::Acl,
            _ => unreachable!(),
        };
        packet_length(kind, &bytes)?;
        let observed_bytes = 16 + bytes.len() + footer.len();
        self.observations.packets.push(Packet {
            kind,
            bytes,
            completion: entry,
            footer,
        });
        self.record_bytes(observed_bytes)?;
        let head = self.ring_index(TR_HEAD, transfer, ENTRIES)?;
        let next = (head + 1) % ENTRIES as u16;
        self.check_budget()?;
        self.core_mut().write16(TR_HEAD + transfer * 2, next);
        self.publish(self.core())?;
        self.doorbell(transfer, next)
    }
    pub fn close(&mut self) -> Result<()> {
        if self.state == State::Closed {
            return Ok(());
        }
        if self.state == State::Failed {
            return Err(self.fault.as_ref().unwrap().clone());
        }
        if self.state == State::Closing {
            let error = Error::Unsupported("interrupted Broadcom transport close");
            self.state = State::Failed;
            self.fault = Some(error.clone());
            return Err(error);
        }
        let previous = self.state;
        // Seal external admission before protocol callbacks or DMA effects.
        // Internal control service may finish the close, but an unwind leaves
        // Closing observable and no public operation can resume this epoch.
        self.state = State::Closing;
        let result = self.close_inner(previous);
        match result {
            Ok(()) => {
                self.state = State::Closed;
                Ok(())
            }
            Err(error) => Err(self.fail(error)),
        }
    }
    fn close_inner(&mut self, previous: State) -> Result<()> {
        if matches!(previous, State::Rti | State::Active) {
            for id in (1..7).rev() {
                if !self.transfers[id].enabled {
                    continue;
                }
                let mut message = [0; CONTROL_BYTES];
                message[0] = 3;
                put16(&mut message, 2, id as u16);
                self.control(&message)?;
                self.transfers[id].enabled = false;
            }
            for id in (1..5).rev() {
                if !self.completions[id].enabled {
                    continue;
                }
                let mut message = [0; CONTROL_BYTES];
                message[0] = 4;
                put16(&mut message, 2, id as u16);
                self.control(&message)?;
                self.completions[id].enabled = false;
            }
        }
        // Source ring destroys do not stop its firmware/control DMA. The real
        // root/platform must separately acknowledge whole retirement.
        if previous != State::Allocated {
            self.refresh_snapshot()?;
        }
        if previous != State::Allocated || self.platform().retire_unpublished() {
            self.retire_platform()?;
        }
        for (id, ring) in self.transfers.iter_mut().enumerate() {
            for (message, used) in ring.inflight.iter_mut().enumerate() {
                if *used {
                    self.observations.retired_without_ack.push(Submission {
                        ring: id as u16,
                        message: u16::from(ring.generation) << 8 | message as u16,
                    });
                    *used = false;
                }
            }
        }
        self.record_bytes(self.observations.retired_without_ack.len() * 4)?;
        // SAFETY: platform DMA/posted/CPU/IRQ/callback/work retirement.
        // Allocated state has never published any device address or MMIO write.
        unsafe {
            self.core.as_mut().unwrap().release()?;
            self.firmware.as_mut().unwrap().release()?;
            for ring in &mut self.transfers {
                ring.release()?;
            }
            for ring in &mut self.completions {
                ring.release()?;
            }
        }
        Ok(())
    }
}
fn packet_length(kind: Kind, bytes: &[u8]) -> Result<()> {
    let length = match kind {
        Kind::Command if bytes.len() >= 3 => Some(3 + usize::from(bytes[2])),
        Kind::Event if bytes.len() >= 2 => Some(2 + usize::from(bytes[1])),
        Kind::Acl if bytes.len() >= 4 => {
            Some(4 + usize::from(u16::from_le_bytes([bytes[2], bytes[3]])))
        }
        Kind::Sco if bytes.len() >= 3 => Some(3 + usize::from(bytes[2])),
        _ => None,
    };
    if length != Some(bytes.len()) {
        return Err(Error::Packet {
            kind,
            bytes: bytes.into(),
        });
    }
    Ok(())
}
