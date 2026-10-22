// SPDX-License-Identifier: GPL-2.0-only
// Isochronous scheduling/completion follows pinned Linux xhci-ring.c and xhci-mem.c.
// Copyright (C) 2008 Intel Corp. Author: Sarah Sharp.
//! Queued root-direct USB2 service intervals on retained native transfer rings.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

const ISOCH: u32 = 5;
const BABBLE: u32 = 3;
const TRANSACTION_ERROR: u32 = 4;
const BANDWIDTH_OVERRUN: u32 = 18;
const INCOMPATIBLE_DEVICE: u32 = 22;
const MISSED_SERVICE: u32 = 23;
const ISO_BUFFER_OVERRUN: u32 = 31;
const EVENT_DATA: u32 = 1 << 2;
const SIA: u32 = 1 << 31;
const FRAMES: u32 = 2048;
const MICROFRAMES: u32 = FRAMES * 8;
const CFC_DELAY: u32 = 10;
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

/// A terminal packet status. Every variant is a completed service interval;
/// transport errors are returned separately and do not release DMA ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsoStatus {
    Success,
    Short,
    MissedService,
    Transaction,
    Babble,
    Bandwidth,
    BufferOverrun,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsoCompletion {
    pub bytes: usize,
    pub status: IsoStatus,
}
/// An exact controller/endpoint service interval. Dropping this ticket does not
/// cancel DMA; the endpoint retains it until completion or acknowledged cancel.
#[derive(Debug)]
pub struct IsoTransfer {
    id: u64,
    slot: u8,
    dci: u8,
    trb: u64,
}

/// Exact source-audited PCI profiles for this bounded PC cut. No older AMD
/// quirk predicate is selected from a CPU/chipset family name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Policy {
    Unknown,
    Amd(u16),
    Qemu,
}
impl Policy {
    pub fn pci(vendor: u16, device: u16) -> Self {
        match (vendor, device) {
            (0x1022, 0x15b6 | 0x15b7 | 0x15b8 | 0x43fc) => Self::Amd(device),
            (0x1b36, 0x000d) => Self::Qemu,
            _ => Self::Unknown,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Capabilities {
    version: u16,
    policy: Policy,
    ist: u32,
    cfc: bool,
}
impl Capabilities {
    pub fn new(version: u16, hcs2: u32, hcc1: u32) -> Self {
        Self {
            version,
            policy: Policy::Unknown,
            ist: (hcs2 & 7) * if hcs2 & 8 != 0 { 8 } else { 1 },
            cfc: hcc1 & (1 << 11) != 0,
        }
    }
    pub fn qualify(&mut self, policy: Policy) {
        self.policy = policy;
    }
    pub fn admit(self) -> Result<(), BlockError> {
        if self.policy == Policy::Unknown {
            return Err(BlockError::Unsupported(
                "isochronous transport requires an audited actual PCI controller profile",
            ));
        }
        // Legacy 0.96 AMD/NEC isoch Link-TRB quirks are outside these actual
        // PC profiles. Do not silently apply 1.0 TLBPC/FrameID semantics there.
        if self.version < 0x100 {
            return Err(BlockError::Unsupported(
                "isochronous transport requires xHCI 1.0 or newer",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct Recipe {
    packet: u32,
    burst: u32,
    exponent: u32,
    payload: u32,
    is_in: bool,
}
impl Recipe {
    pub fn new(ep: &Endpoint, speed: u8) -> Result<Self, BlockError> {
        let invalid = || BlockError::Unsupported("invalid root-direct USB2 isochronous endpoint");
        let packet = u32::from(ep.max_packet & 0x7ff);
        let transactions = u32::from(ep.max_packet >> 11 & 3);
        if ep.kind() != 1
            || ep.address & 0x70 != 0
            || ep.dci() < 2
            || ep.attributes & 0xc0 != 0
            || ep.attributes >> 4 & 3 == 3
            || ep.max_packet & 0xe000 != 0
            || packet == 0
            || !(1..=16).contains(&ep.interval)
            || ep.companion.is_some()
        {
            return Err(invalid());
        }
        let (burst, exponent) = match speed {
            FULL_SPEED if packet <= 1023 && transactions == 0 => (0, u32::from(ep.interval) + 2),
            HIGH_SPEED if packet <= 1024 && transactions <= 2 => {
                (transactions, u32::from(ep.interval) - 1)
            }
            _ => return Err(invalid()),
        };
        // A single submission must fit xHCI's bounded scheduling window. The
        // USB descriptor can express longer intervals; they are not discarded.
        if exponent > 12 {
            return Err(BlockError::Unsupported(
                "isochronous interval exceeds scheduling window",
            ));
        }
        Ok(Self {
            packet,
            burst,
            exponent,
            payload: packet * (burst + 1),
            is_in: ep.is_in(),
        })
    }
    pub fn context(self) -> endpoint::Context {
        endpoint::Context {
            info: self.exponent << 16,
            info2: (if self.is_in { 5 } else { 1 }) << 3 | self.burst << 8 | self.packet << 16,
            tx_info: self.payload | self.payload << 16,
        }
    }
}
struct Active {
    id: u64,
    trb: u64,
    bytes: usize,
}
pub(super) struct Queue {
    recipe: Recipe,
    active: Vec<Active>,
    next: Option<u32>,
    recovery: bool,
}
impl Queue {
    pub fn new(recipe: Recipe) -> Self {
        Self {
            recipe,
            active: Vec::new(),
            next: None,
            recovery: false,
        }
    }
    pub fn cancelled(&mut self) {
        self.active.clear();
        self.next = None;
        self.recovery = false;
    }
}

fn in_window(frame: u32, start: u32, end: u32) -> bool {
    if start > end {
        frame >= start || frame <= end
    } else {
        frame >= start && frame <= end
    }
}
fn schedule(
    mfindex: u32,
    caps: Capabilities,
    interval: u32,
    next: Option<u32>,
) -> Result<(u32, u32), BlockError> {
    let mfindex = mfindex & (MICROFRAMES - 1);
    let first = next.is_none();
    let start = next.unwrap_or_else(|| {
        (mfindex + caps.ist + CFC_DELAY)
            .next_multiple_of(8)
            .next_multiple_of(interval)
            % MICROFRAMES
    });
    let current = mfindex / 8;
    let low = (current + caps.ist.div_ceil(8) + 1) % FRAMES;
    let high = (current + 895) % FRAMES;
    if !in_window(start / 8, low, high) {
        return Err(BlockError::Unsupported(
            "isochronous service interval missed scheduling window",
        ));
    }
    let field = if caps.cfc || first {
        (start / 8) << 20
    } else {
        SIA
    };
    Ok((start, field))
}
fn completion(code: u32, bytes: usize, residual: usize) -> Result<IsoCompletion, BlockError> {
    if residual > bytes {
        return Err(BlockError::Unsupported(
            "invalid isochronous completion residual",
        ));
    }
    let status = match code {
        SUCCESS => IsoStatus::Success,
        SHORT_PACKET => IsoStatus::Short,
        MISSED_SERVICE => IsoStatus::MissedService,
        TRANSACTION_ERROR => IsoStatus::Transaction,
        BABBLE => IsoStatus::Babble,
        BANDWIDTH_OVERRUN => IsoStatus::Bandwidth,
        ISO_BUFFER_OVERRUN => IsoStatus::BufferOverrun,
        status => return Err(BlockError::Device { status }),
    };
    Ok(IsoCompletion {
        bytes: match status {
            IsoStatus::Bandwidth | IsoStatus::BufferOverrun => bytes,
            _ => bytes - residual,
        },
        status,
    })
}

fn trb_control(recipe: Recipe, length: usize, frame: u32) -> u32 {
    let packets = (length as u32).div_ceil(recipe.packet).max(1);
    ISOCH << 10 | IOC | frame | (packets - 1) << 16 | if recipe.is_in { ISP } else { 0 }
}

impl Controller {
    /// Test fixtures supply an explicit observed profile without claiming native
    /// PCI qualification. This grant is absent from production/raw starts.
    #[cfg(test)]
    pub(crate) fn qualify_iso_test_model(&mut self, vendor: u16, device: u16) {
        self.iso_caps.qualify(Policy::pci(vendor, device));
    }
    /// Queue one USB2 isochronous service interval. The entire DMA extent must
    /// stay live and unmodified until terminal completion or successful endpoint
    /// cancellation. Buffers must not cross 64 KiB; maximum payload is the actual
    /// endpoint's packet size times its advertised HS transactions (<=3072).
    /// A full queue or late schedule is refused before any ring publication.
    pub fn submit_iso(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<IsoTransfer, BlockError> {
        self.endpoint_ready(slot, dci)?;
        self.iso_caps.admit()?;
        self.dma_profile.check(buffer, length)?;
        if length > MAX_TD || buffer % MAX_TD as u64 + length as u64 > MAX_TD as u64 {
            return Err(BlockError::Unsupported(
                "isochronous TD crosses a 64 KiB boundary",
            ));
        }
        let mfindex = self.registers.read32(self.runtime);
        let caps = self.iso_caps;
        let state = self.slot(slot)?;
        let transfer = state.endpoints[usize::from(dci)].as_mut().unwrap();
        let queue = transfer
            .iso
            .as_mut()
            .ok_or(BlockError::Unsupported("endpoint is not isochronous"))?;
        if queue.recovery {
            return Err(BlockError::Unsupported(
                "isochronous endpoint requires cancellation",
            ));
        }
        if length > queue.recipe.payload as usize {
            return Err(BlockError::Unsupported(
                "isochronous service payload exceeds descriptor",
            ));
        }
        let trb = transfer.ring.address();
        if queue.active.len() >= RING_TRBS - 2
            || queue.active.iter().any(|active| active.trb == trb)
        {
            return Err(BlockError::Unsupported("isochronous ring is full"));
        }
        let interval = 1 << queue.recipe.exponent;
        let (start, frame) = schedule(mfindex, caps, interval, queue.next)?;
        let id = NEXT_TICKET
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(1)
            })
            .map_err(|_| BlockError::Unsupported("isochronous ticket identities exhausted"))?;
        queue
            .active
            .try_reserve(1)
            .map_err(|_| BlockError::NoDmaMemory)?;
        let control = trb_control(queue.recipe, length, frame);
        // Reserve identity before DMA publication. One TRB is a complete TD;
        // no intermediate-error event can release a later contributor.
        queue.active.push(Active {
            id,
            trb,
            bytes: length,
        });
        transfer.ring.push(&[(buffer, length as u32, control)]);
        queue.next = Some((start + interval) % MICROFRAMES);
        self.doorbell(slot, dci);
        Ok(IsoTransfer { id, slot, dci, trb })
    }

    /// Poll an exact service interval. Ok (including packet-error statuses) is
    /// terminal and releases that TD's buffer. Err is a transport/identity error;
    /// retain all outstanding DMA until successful endpoint-wide cancel. None
    /// means no terminal event. Dropped/retired tickets never name a new TD.
    pub fn completed_iso(
        &mut self,
        ticket: &IsoTransfer,
    ) -> Option<Result<IsoCompletion, BlockError>> {
        if let Err(error) = self.endpoint_ready(ticket.slot, ticket.dci) {
            return Some(Err(error));
        }
        let valid = self
            .slot(ticket.slot)
            .ok()
            .and_then(|slot| slot.endpoints[usize::from(ticket.dci)].as_ref())
            .and_then(|transfer| transfer.iso.as_ref())
            .is_some_and(|queue| {
                !queue.recovery
                    && queue
                        .active
                        .iter()
                        .any(|active| active.id == ticket.id && active.trb == ticket.trb)
            });
        if !valid {
            return Some(Err(BlockError::Unsupported(
                "stale or foreign isochronous ticket",
            )));
        }
        // Missed-service and ring-xrun events may legally have no valid TRB
        // pointer. They cannot complete an arbitrary ticket. Force a bounded
        // endpoint-wide cancellation, retaining every contributor.
        let index = self.pending.iter().position(|event| {
            event.kind() == TRANSFER_EVENT
                && event.slot() == ticket.slot
                && event.endpoint() == ticket.dci
                && (event.parameter == ticket.trb
                    || !matches!(event.code(), SUCCESS | SHORT_PACKET))
        })?;
        let event = self.pending.remove(index);
        if event.code() == INCOMPATIBLE_DEVICE {
            // Incompatible Device requires Disable Slot (Linux handle_tx_event),
            // not merely Stop/Reset/Set Dequeue. Keep permanent poison until a
            // separate exclusive slot-retirement service establishes ownership.
            let endpoint = self.slot(ticket.slot).unwrap().endpoints[usize::from(ticket.dci)]
                .as_mut()
                .unwrap();
            endpoint.poisoned = true;
            return Some(Err(BlockError::Device {
                status: INCOMPATIBLE_DEVICE,
            }));
        }
        let queue = self.slot(ticket.slot).unwrap().endpoints[usize::from(ticket.dci)]
            .as_mut()
            .unwrap()
            .iso
            .as_mut()
            .unwrap();
        let index = queue
            .active
            .iter()
            .position(|active| active.id == ticket.id)
            .unwrap();
        let result = if event.parameter != ticket.trb || event.control & EVENT_DATA != 0 {
            Err(BlockError::Device {
                status: event.code(),
            })
        } else {
            completion(event.code(), queue.active[index].bytes, event.residual())
        };
        if result.is_ok() {
            queue.active.remove(index);
            // A valid pointer identifies this TD, but other earlier service
            // intervals may also have been missed without their own events.
            queue.recovery = event.code() == MISSED_SERVICE;
        } else {
            queue.recovery = true;
        }
        Some(result)
    }
}

#[cfg(test)]
pub(super) mod tests;
