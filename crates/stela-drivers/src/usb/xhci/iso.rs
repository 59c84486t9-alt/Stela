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
const RING_UNDERRUN: u32 = 14;
const RING_OVERRUN: u32 = 15;
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

#[derive(Clone, Copy)]
pub(super) struct Capabilities {
    version: u16,
    ist: u32,
    cfc: bool,
}
impl Capabilities {
    pub fn new(version: u16, hcs2: u32, hcc1: u32) -> Self {
        Self {
            version,
            ist: (hcs2 & 7) * if hcs2 & 8 != 0 { 8 } else { 1 },
            cfc: hcc1 & (1 << 11) != 0,
        }
    }
    pub fn admit(self) -> Result<(), BlockError> {
        // Pre-1.0 hosts need Linux's 0.96 Link-TRB and TLBPC quirks, which
        // are not implemented; 1.0 FrameID semantics are never applied there.
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
    /// The terminal status, held until the ticket's owner collects it.
    done: Option<IsoCompletion>,
}
pub(super) struct Queue {
    recipe: Recipe,
    active: Vec<Active>,
    next: Option<u32>,
    /// Linux `ep->skip`: a missed service interval left earlier TDs without
    /// their own events.
    skip: bool,
    recovery: bool,
}
impl Queue {
    pub fn new(recipe: Recipe) -> Self {
        Self {
            recipe,
            active: Vec::new(),
            next: None,
            skip: false,
            recovery: false,
        }
    }
    pub fn cancelled(&mut self) {
        self.active.clear();
        self.next = None;
        self.skip = false;
        self.recovery = false;
    }
    fn outstanding(&mut self) -> Option<&mut Active> {
        self.active.iter_mut().find(|active| active.done.is_none())
    }
    /// Apply one transfer event the way Linux `handle_tx_event` does for an
    /// isochronous ring of single-TRB TDs.
    fn event(
        &mut self,
        code: u32,
        trb: u64,
        control: u32,
        residual: usize,
    ) -> Result<(), BlockError> {
        let xrun = matches!(code, RING_UNDERRUN | RING_OVERRUN);
        if code == MISSED_SERVICE {
            self.skip = true;
            // Without a TD pointer the number of missed TDs is unknown; the
            // next event settles it.
            if !self
                .active
                .iter()
                .any(|active| active.done.is_none() && active.trb == trb)
            {
                return Ok(());
            }
        }
        loop {
            let skip = self.skip;
            let Some(td) = self.outstanding() else {
                self.skip = false;
                return if xrun {
                    Ok(())
                } else {
                    Err(BlockError::Protocol(
                        "isochronous event without a queued TD",
                    ))
                };
            };
            if td.trb == trb {
                break;
            }
            if !skip {
                // A TD queued after an underrun or overrun has not run yet,
                // and, as in Linux, a success naming no queued TD is stale.
                return if xrun || matches!(code, SUCCESS | SHORT_PACKET) {
                    Ok(())
                } else {
                    Err(BlockError::Protocol(
                        "isochronous event outside the current TD",
                    ))
                };
            }
            td.done = Some(IsoCompletion {
                bytes: 0,
                status: IsoStatus::MissedService,
            });
            if self.outstanding().is_none() {
                self.skip = false;
                return Ok(());
            }
            if xrun {
                // Where an xrun happened is unknown: skip one TD only.
                return Ok(());
            }
        }
        self.skip = false;
        if xrun {
            return Ok(());
        }
        if control & EVENT_DATA != 0 {
            return Err(BlockError::Device { status: code });
        }
        let td = self.outstanding().unwrap();
        td.done = Some(completion(code, td.bytes, residual)?);
        Ok(())
    }
}

/// Linux `xhci_get_isoc_start_frame` and `xhci_isoc_td_uses_frame_id`: a
/// new stream starts at the next aligned interval past the scheduling
/// threshold, and a mid-stream TD keeps its slot even when late; the
/// controller then reports a missed service interval. The returned field is
/// the TRB's Frame ID, or SIA where Linux schedules as soon as possible.
fn schedule(mfindex: u32, caps: Capabilities, interval: u32, next: Option<u32>) -> (u32, u32) {
    let mfindex = mfindex & (MICROFRAMES - 1);
    let start = next.unwrap_or_else(|| {
        (mfindex + caps.ist + CFC_DELAY)
            .next_multiple_of(8)
            .next_multiple_of(interval)
            % MICROFRAMES
    });
    let field = if caps.cfc || next.is_none() {
        (start / 8) << 20
    } else {
        SIA
    };
    (start, field)
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
        // Like Linux, a stream whose earlier TDs have all completed restarts
        // at a fresh start frame instead of continuing a stale schedule.
        if queue.outstanding().is_none() {
            queue.next = None;
        }
        let interval = 1 << queue.recipe.exponent;
        let (start, frame) = schedule(mfindex, caps, interval, queue.next);
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
            done: None,
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
        // Apply this endpoint's events in ring order; any of them may finish
        // this ticket or earlier ones.
        while let Some(index) = self.pending.iter().position(|event| {
            event.kind() == TRANSFER_EVENT
                && event.slot() == ticket.slot
                && event.endpoint() == ticket.dci
        }) {
            let event = self.pending.remove(index);
            let endpoint = self.slot(ticket.slot).unwrap().endpoints[usize::from(ticket.dci)]
                .as_mut()
                .unwrap();
            if event.code() == INCOMPATIBLE_DEVICE {
                // Incompatible Device requires Disable Slot (Linux handle_tx_event),
                // not merely Stop/Reset/Set Dequeue. Keep permanent poison until a
                // separate exclusive slot-retirement service establishes ownership.
                endpoint.poisoned = true;
                return Some(Err(BlockError::Device {
                    status: INCOMPATIBLE_DEVICE,
                }));
            }
            let queue = endpoint.iso.as_mut().unwrap();
            if let Err(error) = queue.event(
                event.code(),
                event.parameter,
                event.control,
                event.residual(),
            ) {
                queue.recovery = true;
                return Some(Err(error));
            }
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
        let done = queue.active[index].done?;
        queue.active.remove(index);
        Some(Ok(done))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::collections::BTreeMap;
    extern crate std;

    struct Td {
        trb: u64,
        buffer: u64,
        bytes: usize,
        control: u32,
    }
    struct Hardware {
        commands: u64,
        command_index: usize,
        events: u64,
        event_index: usize,
        output: u64,
        context_bytes: usize,
        cursors: BTreeMap<u8, (u64, usize, u32)>,
        active: Vec<(u8, Td)>,
        seen: Vec<(u32, u8)>,
        mfindex: u32,
        fail: Option<u32>,
        silent: Option<u32>,
        fatal: bool,
        output_bytes: Vec<u8>,
    }
    impl Hardware {
        fn word(address: u64) -> u32 {
            assert!(address > 65536 && address.is_multiple_of(4));
            unsafe { (address as *const u32).read_volatile() }
        }
        fn long(address: u64) -> u64 {
            assert!(address > 65536 && address.is_multiple_of(8));
            unsafe { (address as *const u64).read_volatile() }
        }
        fn state(&mut self, dci: u8, state: u32) {
            let at = self.output + u64::from(dci) * self.context_bytes as u64;
            unsafe {
                (at as *mut u32).write_volatile(Self::word(at) & !7 | state);
            }
        }
        fn event(&mut self, parameter: u64, code: u32, dci: u8, residual: usize, kind: u32) {
            let at = self.events + (self.event_index % RING_TRBS * TRB) as u64;
            unsafe {
                (at as *mut u64).write_volatile(parameter);
                ((at + 8) as *mut u32).write_volatile(code << 24 | residual as u32);
                ((at + 12) as *mut u32).write_volatile(
                    1 << 24
                        | u32::from(dci) << 16
                        | kind << 10
                        | u32::from((self.event_index / RING_TRBS).is_multiple_of(2)),
                );
            }
            self.event_index += 1;
        }
        fn command(&mut self) {
            let at = self.commands + (self.command_index % (RING_TRBS - 1) * TRB) as u64;
            let parameter = Self::long(at);
            let control = Self::word(at + 12);
            assert_eq!(
                control & CYCLE,
                u32::from((self.command_index / (RING_TRBS - 1)).is_multiple_of(2))
            );
            let kind = control >> 10 & 63;
            let dci = (control >> 16 & 31) as u8;
            self.command_index += 1;
            self.seen.push((kind, dci));
            if self.silent == Some(kind) {
                return;
            }
            let code = if self.fail == Some(kind) { 17 } else { SUCCESS };
            if code == SUCCESS {
                match kind {
                    CONFIGURE_ENDPOINT => {
                        let add = Self::word(parameter + 4);
                        let drop = Self::word(parameter);
                        for ep in 2..32u8 {
                            if drop & (1 << ep) != 0 {
                                self.state(ep, 0);
                                self.cursors.remove(&ep);
                            }
                            if add & (1 << ep) == 0 {
                                continue;
                            }
                            let from = parameter + (u64::from(ep) + 1) * self.context_bytes as u64;
                            let to = self.output + u64::from(ep) * self.context_bytes as u64;
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    from as *const u8,
                                    to as *mut u8,
                                    self.context_bytes,
                                );
                            }
                            let info2 = Self::word(to + 4);
                            assert!(matches!(info2 >> 3 & 7, 1 | 5));
                            assert_eq!(info2 & 6, 0);
                            assert_eq!(Self::word(to + 16) & 0xffff, Self::word(to + 16) >> 16);
                            self.state(ep, ENDPOINT_RUNNING);
                        }
                    }
                    STOP_ENDPOINT => self.state(dci, ENDPOINT_STOPPED),
                    RESET_ENDPOINT => self.state(dci, ENDPOINT_STOPPED),
                    SET_DEQUEUE => {
                        let endpoint = self.output + u64::from(dci) * self.context_bytes as u64;
                        assert_eq!(Self::word(endpoint) & 7, ENDPOINT_STOPPED);
                        let base = Self::long(endpoint + 8) & !((RING_TRBS * TRB) as u64 - 1);
                        self.cursors.insert(
                            dci,
                            (
                                base,
                                ((parameter & !15) - base) as usize / TRB,
                                parameter as u32 & 1,
                            ),
                        );
                        let old = core::mem::take(&mut self.active);
                        for (ep, td) in old {
                            if ep == dci {
                                self.event(td.trb, 26, dci, td.bytes, TRANSFER_EVENT);
                            } else {
                                self.active.push((ep, td));
                            }
                        }
                    }
                    _ => panic!("unexpected command {kind}"),
                }
            }
            self.event(at, code, 0, 0, COMMAND_COMPLETION);
        }
        fn transfer(&mut self, dci: u8) {
            let ep = self.output + u64::from(dci) * self.context_bytes as u64;
            let initial = Self::long(ep + 8);
            let base = initial & !((RING_TRBS * TRB) as u64 - 1);
            let cursor = self.cursors.entry(dci).or_insert((
                base,
                ((initial & !15) - base) as usize / TRB,
                initial as u32 & 1,
            ));
            let trb = cursor.0 + (cursor.1 * TRB) as u64;
            let control = Self::word(trb + 12);
            let bytes = (Self::word(trb + 8) & 0x1ffff) as usize;
            assert_eq!(control & CYCLE, cursor.2);
            assert_eq!(control >> 10 & 63, ISOCH);
            assert_ne!(control & IOC, 0);
            let packet = Self::word(ep + 4) >> 16;
            assert_eq!(
                control >> 16 & 15,
                (bytes as u32).div_ceil(packet).max(1) - 1
            );
            let buffer = Self::long(trb);
            assert!(buffer % 65536 + bytes as u64 <= 65536);
            assert!(
                !self
                    .active
                    .iter()
                    .any(|(ep, td)| *ep == dci && td.trb == trb)
            );
            self.active.push((
                dci,
                Td {
                    trb,
                    buffer,
                    bytes,
                    control,
                },
            ));
            cursor.1 += 1;
            if cursor.1 == RING_TRBS - 1 {
                let link = cursor.0 + ((RING_TRBS - 1) * TRB) as u64;
                assert_eq!(Self::long(link), cursor.0);
                assert_eq!(Self::word(link + 12) & 1, cursor.2);
                assert_eq!(Self::word(link + 12) >> 10 & 63, LINK);
                assert_ne!(Self::word(link + 12) & TOGGLE, 0);
                cursor.1 = 0;
                cursor.2 ^= 1;
            }
            self.state(dci, ENDPOINT_RUNNING);
        }
        fn complete(&mut self, dci: u8, index: usize, code: u32, residual: usize) {
            let at = self
                .active
                .iter()
                .enumerate()
                .filter(|(_, (ep, _))| *ep == dci)
                .nth(index)
                .unwrap()
                .0;
            let (_, td) = self.active.remove(at);
            if code == 6 {
                self.state(dci, ENDPOINT_HALTED);
            }
            if matches!(code, SUCCESS | SHORT_PACKET) && residual <= td.bytes {
                let n = td.bytes - residual;
                if dci & 1 != 0 {
                    unsafe {
                        core::ptr::write_bytes(td.buffer as *mut u8, 0x5a, n);
                    }
                } else {
                    self.output_bytes.extend_from_slice(unsafe {
                        core::slice::from_raw_parts(td.buffer as *const u8, n)
                    });
                }
            }
            self.event(td.trb, code, dci, residual, TRANSFER_EVENT);
        }
    }
    struct Model(Rc<RefCell<Hardware>>);
    impl Registers for Model {
        fn read32(&mut self, offset: usize) -> u32 {
            let model = self.0.borrow();
            if offset == 0x800 {
                model.mfindex
            } else if offset == 0x40 + USBSTS && model.fatal {
                HSE
            } else {
                0
            }
        }
        fn write32(&mut self, offset: usize, value: u32) {
            match offset {
                0x1000 => self.0.borrow_mut().command(),
                0x1004 => self.0.borrow_mut().transfer(value as u8),
                _ => {}
            }
        }
    }
    fn endpoint(address: u8, speed: u8) -> Endpoint {
        Endpoint {
            address,
            attributes: 1,
            max_packet: if speed == FULL_SPEED {
                192
            } else {
                1024 | 2 << 11
            },
            interval: 1,
            companion: None,
        }
    }
    fn controller(
        dma: &mut dyn DmaAllocator,
        speed: u8,
        context_bytes: usize,
        cfc: bool,
    ) -> (Controller, Rc<RefCell<Hardware>>) {
        let commands = Ring::new(dma).unwrap();
        let events = dma.allocate(RING_TRBS * TRB, RING_TRBS * TRB).unwrap();
        let output = dma.allocate(32 * context_bytes, 64).unwrap();
        let model = Rc::new(RefCell::new(Hardware {
            commands: commands.buffer.physical(),
            command_index: 0,
            events: events.physical(),
            event_index: 0,
            output: output.physical(),
            context_bytes,
            cursors: BTreeMap::new(),
            active: Vec::new(),
            seen: Vec::new(),
            mfindex: 0x3ff0,
            fail: None,
            silent: None,
            fatal: false,
            output_bytes: Vec::new(),
        }));
        let mut slots = vec![None];
        slots.push(Some(Slot {
            attachment: Attachment {
                root_port: 1,
                route: 0,
                tier: 0,
                speed,
                translator: None,
            },
            retiring: false,
            input: dma.allocate(33 * context_bytes, 64).unwrap(),
            _output: output,
            context: [u32::from(speed) << 20 | 1 << 27, 1 << 16, 0, 0],
            endpoints: Default::default(),
            retired_rings: Default::default(),
            control: dma.allocate(CONTROL_BYTES, CONTROL_BYTES).unwrap(),
            speed,
            current_configuration: Some(1),
        }));
        (
            Controller {
                registers: Box::new(Model(model.clone())),
                clock: Clock {
                    ticks_per_microsecond: 1,
                },
                operational: 0x40,
                runtime: 0x800,
                doorbells: 0x1000,
                context_bytes,
                dma_profile: dma::Profile::SPEC,
                max_primary_streams: 4,
                stream_policy: streams::Policy::Unknown,
                iso_caps: Capabilities::new(0x110, 0xb, if cfc { 1 << 11 } else { 0 }),
                max_slots: 1,
                max_ports: 1,
                port_major: vec![2],
                dcbaa: dma.allocate(16, 64).unwrap(),
                _scratchpads: Vec::new(),
                commands,
                events,
                _event_table: dma.allocate(16, 64).unwrap(),
                event_index: 0,
                event_cycle: true,
                slots,
                slot_ownership: vec![reset::Ownership::Vacant, reset::Ownership::Enabled],
                pending: Vec::new(),
                error: None,
                command_poisoned: false,
                location: String::from("native iso model"),
            },
            model,
        )
    }

    #[test]
    fn queued_native_iso_contexts_and_scheduling_complete_actual_dma_for_both_directions() {
        for speed in [FULL_SPEED, HIGH_SPEED] {
            for context_bytes in [32, 64] {
                for cfc in [false, true] {
                    let mut backing = vec![0u64; 128 * 1024];
                    let start = backing.as_mut_ptr() as u64;
                    let mut dma =
                        unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                    let (mut controller, model) = controller(&mut dma, speed, context_bytes, cfc);
                    let endpoints = [endpoint(1, speed), endpoint(0x82, speed)];
                    controller.configure(1, &endpoints, None, &mut dma).unwrap();
                    let out = dma.allocate(4096, 4096).unwrap();
                    let input = dma.allocate(4096, 4096).unwrap();
                    unsafe {
                        core::ptr::write_bytes(out.as_ptr(), 0xa5, out.len());
                    }
                    let mut tickets = Vec::new();
                    for n in 0..32 {
                        for endpoint in &endpoints {
                            tickets.push(
                                controller
                                    .submit_iso(
                                        1,
                                        endpoint.dci(),
                                        if endpoint.is_in() {
                                            input.physical()
                                        } else {
                                            out.physical()
                                        } + n * 32,
                                        32,
                                    )
                                    .unwrap(),
                            );
                        }
                    }
                    assert_eq!(model.borrow().active.len(), 64);
                    for dci in [2, 5] {
                        let fields: Vec<u32> = model
                            .borrow()
                            .active
                            .iter()
                            .filter(|(ep, _)| *ep == dci)
                            .map(|(_, td)| td.control)
                            .collect();
                        assert_eq!(fields[0] & SIA, 0);
                        assert_eq!(fields[1] & SIA, if cfc { 0 } else { SIA });
                        for n in 0..32 {
                            model.borrow_mut().complete(
                                dci,
                                0,
                                if n % 2 == 0 { SUCCESS } else { SHORT_PACKET },
                                if n % 2 == 0 { 0 } else { 4 },
                            );
                        }
                    }
                    for (n, ticket) in tickets.iter().enumerate() {
                        let completion = controller.completed_iso(ticket).unwrap().unwrap();
                        assert_eq!(completion.bytes, if n / 2 % 2 == 0 { 32 } else { 28 });
                        assert!(controller.completed_iso(ticket).unwrap().is_err());
                    }
                    assert_eq!(model.borrow().output_bytes.len(), 16 * 32 + 16 * 28);
                    assert_eq!(&input.bytes()[..32], &[0x5a; 32]);
                }
            }
        }
    }

    #[test]
    fn packet_failures_are_terminal_but_invalid_residual_and_transport_faults_retain_dma() {
        for (code, status) in [
            (23, IsoStatus::MissedService),
            (4, IsoStatus::Transaction),
            (3, IsoStatus::Babble),
            (18, IsoStatus::Bandwidth),
            (31, IsoStatus::BufferOverrun),
        ] {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
            controller
                .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
                .unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            let ticket = controller.submit_iso(1, 3, buffer.physical(), 128).unwrap();
            model.borrow_mut().complete(3, 0, code, 32);
            assert_eq!(
                controller.completed_iso(&ticket).unwrap().unwrap().status,
                status
            );
            let ticket = controller.submit_iso(1, 3, buffer.physical(), 128).unwrap();
            model.borrow_mut().complete(3, 0, SUCCESS, 129);
            assert!(controller.completed_iso(&ticket).unwrap().is_err());
            assert!(controller.submit_iso(1, 3, buffer.physical(), 128).is_err());
            controller.cancel(1, 3).unwrap();
            assert!(controller.completed_iso(&ticket).unwrap().is_err());
        }
    }

    #[test]
    fn cancellation_acknowledges_all_intervals_and_stale_events_before_reuse() {
        for failure in [None, Some(STOP_ENDPOINT), Some(SET_DEQUEUE)] {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
            controller
                .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
                .unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            let tickets: Vec<_> = (0..32)
                .map(|n| {
                    controller
                        .submit_iso(1, 3, buffer.physical() + n * 32, 32)
                        .unwrap()
                })
                .collect();
            model.borrow_mut().fail = failure;
            let result = controller.cancel(1, 3);
            if failure.is_some() {
                assert!(result.is_err());
                assert!(controller.submit_iso(1, 3, buffer.physical(), 32).is_err());
                assert_eq!(
                    controller.slot(1).unwrap().endpoints[3]
                        .as_ref()
                        .unwrap()
                        .iso
                        .as_ref()
                        .unwrap()
                        .active
                        .len(),
                    32
                );
                assert_eq!(model.borrow().active.len(), 32);
            } else {
                result.unwrap();
                assert!(controller.pending.is_empty());
                assert!(model.borrow().active.is_empty());
                for ticket in tickets {
                    assert!(controller.completed_iso(&ticket).unwrap().is_err());
                }
                controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
            }
        }
    }

    #[test]
    fn occupancy_wrap_schedule_and_descriptor_failures_do_not_overwrite_owned_trbs() {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let tickets: Vec<_> = (0..RING_TRBS - 2)
            .map(|_| controller.submit_iso(1, 3, buffer.physical(), 16).unwrap())
            .collect();
        let before = controller.slot(1).unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .ring
            .address();
        assert!(controller.submit_iso(1, 3, buffer.physical(), 16).is_err());
        assert_eq!(
            controller.slot(1).unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .ring
                .address(),
            before
        );
        for ticket in tickets {
            model.borrow_mut().complete(3, 0, SUCCESS, 0);
            assert_eq!(
                controller.completed_iso(&ticket).unwrap().unwrap().bytes,
                16
            );
        }
        for _ in 0..300 {
            let ticket = controller.submit_iso(1, 3, buffer.physical(), 16).unwrap();
            model.borrow_mut().complete(3, 0, SUCCESS, 0);
            controller.completed_iso(&ticket).unwrap().unwrap();
        }
        // A late TD is still queued; the controller reports the missed interval.
        model.borrow_mut().mfindex = 1024;
        controller.submit_iso(1, 3, buffer.physical(), 16).unwrap();
        assert!(controller.submit(1, 3, buffer.physical(), 16).is_err());
        for speed in [LOW_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS] {
            assert!(Recipe::new(&endpoint(0x81, HIGH_SPEED), speed).is_err());
        }
        let mut endpoint = endpoint(0x81, HIGH_SPEED);
        endpoint.max_packet |= 3 << 11;
        assert!(Recipe::new(&endpoint, HIGH_SPEED).is_err());
        endpoint.max_packet = 1024;
        endpoint.attributes = 0x31;
        assert!(Recipe::new(&endpoint, HIGH_SPEED).is_err());
    }

    #[test]
    fn acknowledged_endpoint_drop_retains_rings_and_failure_quarantines_every_selected_owner() {
        for failure in [
            None,
            Some(CONFIGURE_ENDPOINT),
            Some(STOP_ENDPOINT),
            Some(SET_DEQUEUE),
        ] {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
            let endpoints = [
                endpoint(1, HIGH_SPEED),
                endpoint(0x82, HIGH_SPEED),
                endpoint(0x83, HIGH_SPEED),
            ];
            controller.configure(1, &endpoints, None, &mut dma).unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            let a = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
            let b = controller
                .submit_iso(1, 5, buffer.physical() + 32, 32)
                .unwrap();
            let keep = controller
                .submit_iso(1, 7, buffer.physical() + 64, 32)
                .unwrap();
            let old_ring = controller.slot(1).unwrap().endpoints[2]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .physical();
            model.borrow_mut().fail = failure;
            let result = controller.deconfigure(1, &endpoints[..2]);
            if failure.is_some() {
                assert!(result.is_err());
                let slot = controller.slot(1).unwrap();
                assert!(slot.endpoints[2].as_ref().unwrap().poisoned);
                assert!(slot.endpoints[5].as_ref().unwrap().poisoned);
                assert!(slot.retired_rings[2].is_none());
                assert!(slot.retired_rings[5].is_none());
                assert!(!slot.endpoints[7].as_ref().unwrap().poisoned);
                assert!(controller.submit_iso(1, 2, buffer.physical(), 32).is_err());
                assert!(
                    controller
                        .configure(1, &endpoints[..2], None, &mut dma)
                        .is_err()
                );
            } else {
                result.unwrap();
                assert!(controller.slot(1).unwrap().endpoints[2].is_none());
                assert!(controller.slot(1).unwrap().endpoints[5].is_none());
                assert!(controller.slot(1).unwrap().endpoints[7].is_some());
                controller
                    .configure(1, &endpoints[..2], None, &mut dma)
                    .unwrap();
                assert_eq!(
                    old_ring,
                    controller.slot(1).unwrap().endpoints[2]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .physical()
                );
                assert!(controller.completed_iso(&a).unwrap().is_err());
                assert!(controller.completed_iso(&b).unwrap().is_err());
                model.borrow_mut().complete(7, 0, SUCCESS, 0);
                controller.completed_iso(&keep).unwrap().unwrap();
                let fresh = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
                model
                    .borrow_mut()
                    .event(a.trb, SUCCESS, 2, 0, TRANSFER_EVENT);
                assert!(controller.completed_iso(&fresh).is_none());
                model.borrow_mut().complete(2, 0, SUCCESS, 0);
                controller.completed_iso(&fresh).unwrap().unwrap();
            }
        }
    }

    mod reuse {
        use super::*;

        struct Exhausted;
        impl DmaAllocator for Exhausted {
            fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
                Err(BlockError::NoDmaMemory)
            }
        }

        #[test]
        fn repeated_drop_and_configure_preserves_ring_cursor_without_more_dma_allocations() {
            for context_bytes in [32, 64] {
                let mut backing = vec![0u64; 32 * 1024];
                let start = backing.as_mut_ptr() as u64;
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = controller(&mut dma, HIGH_SPEED, context_bytes, true);
                let endpoints = [endpoint(1, HIGH_SPEED), endpoint(0x82, HIGH_SPEED)];
                controller.configure(1, &endpoints, None, &mut dma).unwrap();
                let buffer = dma.allocate(4096, 4096).unwrap();
                let original = endpoints.map(|endpoint| {
                    controller.slot(1).unwrap().endpoints[usize::from(endpoint.dci())]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .physical()
                });
                let mut old = Vec::new();
                // More than two producer-cycle wraps and many times the native audio
                // reservation's old 8/16-start limit. No allocator reset is permitted.
                for generation in 0..600 {
                    let tickets = endpoints.map(|endpoint| {
                        controller
                            .submit_iso(1, endpoint.dci(), buffer.physical(), 32)
                            .unwrap()
                    });
                    // Before this generation's hardware event, an old event must not
                    // retire its buffer, including when physical TRB positions recur.
                    for ticket in &tickets {
                        assert!(controller.completed_iso(ticket).is_none());
                    }
                    for endpoint in endpoints {
                        model.borrow_mut().complete(endpoint.dci(), 0, SUCCESS, 0);
                    }
                    // Leave successful old events pending while cancellation/drop runs.
                    // The acknowledged retirement boundary must drain those events.
                    let pointers = endpoints.map(|endpoint| {
                        controller.slot(1).unwrap().endpoints[usize::from(endpoint.dci())]
                            .as_ref()
                            .unwrap()
                            .ring
                            .dequeue_pointer()
                    });
                    controller.deconfigure(1, &endpoints).unwrap();
                    for (n, endpoint) in endpoints.iter().enumerate() {
                        let cached = controller.slot(1).unwrap().retired_rings
                            [usize::from(endpoint.dci())]
                        .as_ref()
                        .unwrap();
                        assert_eq!(cached.buffer.physical(), original[n]);
                        assert_eq!(cached.dequeue_pointer(), pointers[n]);
                    }
                    controller
                        .configure(1, &endpoints, None, &mut Exhausted)
                        .unwrap();
                    for (n, endpoint) in endpoints.iter().enumerate() {
                        let ring = &controller.slot(1).unwrap().endpoints
                            [usize::from(endpoint.dci())]
                        .as_ref()
                        .unwrap()
                        .ring;
                        assert_eq!(ring.buffer.physical(), original[n]);
                        assert_eq!(ring.dequeue_pointer(), pointers[n]);
                    }
                    old.extend(tickets);
                    // Old software tickets remain stale even after physical addresses
                    // and cycle bits recur. They cannot consume a new owner's event.
                    assert!(controller.completed_iso(&old[0]).unwrap().is_err());
                    model.borrow_mut().mfindex = (0x3ff0 + generation * 8) % MICROFRAMES;
                }
                let fresh = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
                model.borrow_mut().complete(2, 0, SUCCESS, 0);
                for ticket in &old {
                    assert!(controller.completed_iso(ticket).unwrap().is_err());
                }
                assert_eq!(controller.completed_iso(&fresh).unwrap().unwrap().bytes, 32);
            }
        }

        #[test]
        fn failed_prepublication_allocation_retains_reclaimed_rings_for_retry() {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
            let first = endpoint(1, HIGH_SPEED);
            controller.configure(1, &[first], None, &mut dma).unwrap();
            controller.deconfigure(1, &[first]).unwrap();
            let address = controller.slot(1).unwrap().retired_rings[2]
                .as_ref()
                .unwrap()
                .buffer
                .physical();
            let before = model.borrow().seen.len();
            assert_eq!(
                controller.configure(
                    1,
                    &[first, endpoint(0x82, HIGH_SPEED)],
                    None,
                    &mut Exhausted
                ),
                Err(BlockError::NoDmaMemory)
            );
            assert_eq!(model.borrow().seen.len(), before);
            assert!(controller.slot(1).unwrap().endpoints[2].is_none());
            assert_eq!(
                controller.slot(1).unwrap().retired_rings[2]
                    .as_ref()
                    .unwrap()
                    .buffer
                    .physical(),
                address
            );
            controller
                .configure(1, &[first], None, &mut Exhausted)
                .unwrap();
        }

        #[test]
        fn rejected_or_unacknowledged_replacement_never_returns_its_ring_to_the_cache() {
            for silent in [false, true] {
                let mut backing = vec![0u64; 32 * 1024];
                let start = backing.as_mut_ptr() as u64;
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
                let endpoint = endpoint(1, HIGH_SPEED);
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .unwrap();
                controller.deconfigure(1, &[endpoint]).unwrap();
                let address = controller.slot(1).unwrap().retired_rings[2]
                    .as_ref()
                    .unwrap()
                    .buffer
                    .physical();
                if silent {
                    model.borrow_mut().silent = Some(CONFIGURE_ENDPOINT);
                } else {
                    model.borrow_mut().fail = Some(CONFIGURE_ENDPOINT);
                }
                assert!(
                    controller
                        .configure(1, &[endpoint], None, &mut Exhausted)
                        .is_err()
                );
                let state = controller.slot(1).unwrap();
                assert!(state.retired_rings[2].is_none());
                let retained = state.endpoints[2].as_ref().unwrap();
                assert_eq!(retained.ring.buffer.physical(), address);
                assert!(retained.poisoned);
                let bytes = retained.ring.buffer.bytes().to_vec();
                let commands = model.borrow().seen.len();
                model.borrow_mut().silent = None;
                model.borrow_mut().fail = None;
                assert!(
                    controller
                        .configure(1, &[endpoint], None, &mut dma)
                        .is_err()
                );
                assert!(controller.deconfigure(1, &[endpoint]).is_err());
                assert_eq!(model.borrow().seen.len(), commands);
                assert_eq!(
                    controller.slot(1).unwrap().endpoints[2]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .bytes(),
                    bytes
                );
            }
        }

        #[test]
        fn endpoint_preflight_refuses_foreign_owners_without_commands_or_ring_mutation() {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
            let foreign = endpoint(0x82, HIGH_SPEED);
            let available = endpoint(1, HIGH_SPEED);
            controller.configure(1, &[foreign], None, &mut dma).unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            let active = controller.submit_iso(1, 5, buffer.physical(), 32).unwrap();
            let commands = model.borrow().seen.len();
            let bytes = controller.slot(1).unwrap().endpoints[5]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .bytes()
                .to_vec();
            assert!(
                controller
                    .preflight_endpoints(1, &[available, foreign])
                    .is_err()
            );
            assert!(
                controller
                    .preflight_endpoints(1, &[available, available])
                    .is_err()
            );
            assert_eq!(model.borrow().seen.len(), commands);
            assert_eq!(
                controller.slot(1).unwrap().endpoints[5]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes(),
                bytes
            );
            assert!(
                !controller.slot(1).unwrap().endpoints[5]
                    .as_ref()
                    .unwrap()
                    .poisoned
            );
            model.borrow_mut().complete(5, 0, SUCCESS, 0);
            assert_eq!(
                controller.completed_iso(&active).unwrap().unwrap().bytes,
                32
            );
            controller.preflight_endpoints(1, &[available]).unwrap();
            // Preflight is not a reservation. If another serialized owner claims that
            // DCI before publication, configure must refuse without tearing it down.
            controller
                .configure(1, &[available], None, &mut dma)
                .unwrap();
            let commands = model.borrow().seen.len();
            assert!(
                controller
                    .configure(1, &[available], None, &mut dma)
                    .is_err()
            );
            assert_eq!(model.borrow().seen.len(), commands);
        }
    }

    #[test]
    fn invalid_descriptor_route_teardown_and_submission_have_no_dma_publication() {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        let endpoint = endpoint(0x81, HIGH_SPEED);
        controller.slot(1).unwrap().attachment.tier = 1;
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut dma)
                .is_err()
        );
        assert!(model.borrow().seen.is_empty());
        controller.slot(1).unwrap().attachment.tier = 0;
        controller
            .configure(1, &[endpoint], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let commands = model.borrow().seen.len();
        let remaining = dma.remaining();
        assert!(controller.deconfigure(1, &[endpoint, endpoint]).is_err());
        assert_eq!(model.borrow().seen.len(), commands);
        assert!(
            controller
                .submit_iso(1, 3, buffer.physical(), 3073)
                .is_err()
        );
        assert!(
            controller
                .submit_iso(1, 3, buffer.physical().next_multiple_of(65536) - 1, 32)
                .is_err()
        );
        assert_eq!(dma.remaining(), remaining);
        assert!(model.borrow().active.is_empty());
        assert!(controller.clear(1, &endpoint).is_err());
        assert_eq!(model.borrow().seen.len(), commands);
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 0).unwrap();
        assert_eq!(model.borrow().active[0].1.control >> 16 & 15, 0);
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        assert_eq!(controller.completed_iso(&ticket).unwrap().unwrap().bytes, 0);
    }

    #[test]
    fn silent_cancellation_and_fatal_controller_status_never_release_queued_buffers() {
        for silent in [STOP_ENDPOINT, SET_DEQUEUE] {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
            controller
                .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
                .unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
            model.borrow_mut().silent = Some(silent);
            assert!(controller.cancel(1, 3).is_err());
            assert!(controller.command_poisoned);
            assert_eq!(
                controller.slot(1).unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .iso
                    .as_ref()
                    .unwrap()
                    .active
                    .len(),
                1
            );
            assert!(controller.completed_iso(&ticket).unwrap().is_err());
        }
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        model.borrow_mut().fatal = true;
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
        assert!(controller.cancel(1, 3).is_err());
        assert_eq!(
            controller.slot(1).unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .iso
                .as_ref()
                .unwrap()
                .active
                .len(),
            1
        );
    }

    #[test]
    fn any_xhci_1_0_controller_admits_isochronous_transport() {
        assert!(Capabilities::new(0x96, 0, 0).admit().is_err());
        for version in [0x100, 0x110, 0x120] {
            Capabilities::new(version, 0, 0).admit().unwrap();
        }
    }

    #[test]
    #[ignore = "requires immutable pinned Linux isochronous helper trace"]
    fn unchanged_linux_iso_context_scheduling_burst_and_terminal_completion() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read_to_string(
            std::env::var("STELA_XHCI_ISO_ORACLE").expect("path to fresh source oracle trace"),
        )
        .unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "8dff7cfded211423e137dde9864585635f4ac2467fe7c93057081a0c925927e6"
        );
        let mut count = 0;
        for line in trace.lines() {
            let mut fields = line.split_whitespace();
            let kind = fields.next().unwrap();
            let values: Vec<i64> = fields.map(|v| v.parse().unwrap()).collect();
            match kind {
                "E" => {
                    assert_eq!(values.len(), 8);
                    let speed = if values[0] == 2 {
                        FULL_SPEED
                    } else {
                        HIGH_SPEED
                    };
                    let ep = Endpoint {
                        address: if values[3] != 0 { 0x81 } else { 1 },
                        attributes: 1,
                        max_packet: values[4] as u16 | (values[2] as u16) << 11,
                        interval: values[1] as u8,
                        companion: None,
                    };
                    match Recipe::new(&ep, speed) {
                        Ok(recipe) => {
                            let context = recipe.context();
                            assert_eq!(
                                [context.info, context.info2, context.tx_info],
                                [values[5] as u32, values[6] as u32, values[7] as u32]
                            );
                        }
                        Err(_) => assert!(values[5] >> 16 > 12),
                    }
                }
                "S" => {
                    assert_eq!(values.len(), 8);
                    let caps = Capabilities::new(
                        0x110,
                        values[1] as u32,
                        if values[2] != 0 { 1 << 11 } else { 0 },
                    );
                    let next = if values[4] < 0 {
                        None
                    } else {
                        Some(values[4] as u32)
                    };
                    // Linux only logs a start outside the window (values[7]).
                    let (start, field) = schedule(values[0] as u32, caps, values[3] as u32, next);
                    assert_eq!(start, values[5] as u32);
                    assert_eq!(
                        field,
                        if values[6] != 0 {
                            (start / 8) << 20
                        } else {
                            SIA
                        }
                    );
                }
                "C" => {
                    assert_eq!(values.len(), 6);
                    assert_eq!(values[4], 1); // process_isoc_td reached finish callback.
                    if matches!(values[0], 6 | 22) {
                        // The original finish path still requires halt/slot recovery:
                        // its packet-status assignment is not a DMA-release ACK.
                        assert!(completion(values[0] as u32, 128, values[1] as usize).is_err());
                        assert_eq!(values[3], -71);
                        assert_eq!(values[5], i64::from(values[0] == 6));
                    } else {
                        assert_eq!(values[5], 0);
                        let packet = completion(values[0] as u32, 128, values[1] as usize).unwrap();
                        assert_eq!(packet.bytes, values[2] as usize);
                        assert_eq!(
                            match packet.status {
                                IsoStatus::Success | IsoStatus::Short => 0,
                                IsoStatus::MissedService => -18,
                                IsoStatus::Transaction => -71,
                                IsoStatus::Babble | IsoStatus::BufferOverrun => -75,
                                IsoStatus::Bandwidth => -70,
                            },
                            values[3]
                        );
                    }
                }
                "B" => {
                    assert_eq!(values.len(), 3);
                    let recipe = Recipe::new(&endpoint(0x81, HIGH_SPEED), HIGH_SPEED).unwrap();
                    let field = trb_control(recipe, values[0] as usize * 1024, 0);
                    assert_eq!(field >> 7 & 3, values[1] as u32);
                    assert_eq!(field >> 16 & 15, values[2] as u32);
                }
                _ => panic!("unknown source trace row"),
            }
            count += 1;
        }
        assert_eq!(count, 4656);
    }

    #[test]
    fn ring_xruns_are_ignored_and_missed_service_skips_earlier_tds() {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let tickets: Vec<_> = (0..3)
            .map(|n| {
                controller
                    .submit_iso(1, 3, buffer.physical() + n * 32, 32)
                    .unwrap()
            })
            .collect();
        for code in [RING_UNDERRUN, RING_OVERRUN] {
            model.borrow_mut().event(0, code, 3, 0, TRANSFER_EVENT);
            assert!(controller.completed_iso(&tickets[0]).is_none());
        }
        // Without a TD pointer the next event decides how many TDs were missed.
        model
            .borrow_mut()
            .event(0, MISSED_SERVICE, 3, 0, TRANSFER_EVENT);
        assert!(controller.completed_iso(&tickets[0]).is_none());
        model.borrow_mut().complete(3, 1, SUCCESS, 0);
        let missed = IsoCompletion {
            bytes: 0,
            status: IsoStatus::MissedService,
        };
        assert_eq!(controller.completed_iso(&tickets[0]).unwrap(), Ok(missed));
        assert_eq!(
            controller
                .completed_iso(&tickets[1])
                .unwrap()
                .unwrap()
                .bytes,
            32
        );
        assert!(controller.completed_iso(&tickets[2]).is_none());
        // An xrun while TDs are being skipped skips exactly one.
        model
            .borrow_mut()
            .event(0, MISSED_SERVICE, 3, 0, TRANSFER_EVENT);
        model
            .borrow_mut()
            .event(0, RING_OVERRUN, 3, 0, TRANSFER_EVENT);
        assert_eq!(controller.completed_iso(&tickets[2]).unwrap(), Ok(missed));
        controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
    }

    #[test]
    fn transferless_errors_stalls_and_incompatible_slots_never_release_an_arbitrary_ticket() {
        for code in [6, 22, 36, 99] {
            let mut backing = vec![0u64; 32 * 1024];
            let start = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
            controller
                .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
                .unwrap();
            let buffer = dma.allocate(4096, 4096).unwrap();
            let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
            let other = controller
                .submit_iso(1, 3, buffer.physical() + 32, 32)
                .unwrap();
            if code == 6 || code == 22 {
                model.borrow_mut().complete(3, 0, code, 0);
            } else {
                model.borrow_mut().event(0, code, 3, 0, TRANSFER_EVENT);
            }
            assert!(controller.completed_iso(&ticket).unwrap().is_err());
            assert_eq!(
                controller.slot(1).unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .iso
                    .as_ref()
                    .unwrap()
                    .active
                    .len(),
                2
            );
            assert!(controller.completed_iso(&other).unwrap().is_err());
            assert!(
                controller
                    .submit_iso(1, 3, buffer.physical() + 64, 32)
                    .is_err()
            );
            if code == 22 {
                let n = model.borrow().seen.len();
                assert!(controller.cancel(1, 3).is_err());
                assert_eq!(model.borrow().seen.len(), n);
            } else {
                controller.cancel(1, 3).unwrap();
                assert!(model.borrow().active.is_empty());
                assert!(controller.completed_iso(&ticket).unwrap().is_err());
                controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
                if code == 6 {
                    assert!(
                        model
                            .borrow()
                            .seen
                            .iter()
                            .any(|(kind, _)| *kind == RESET_ENDPOINT)
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "requires immutable pinned Linux AMD PCI quirk and PLL trace"]
    fn unchanged_linux_actual_amd_pci_profiles_and_saved_smbus_do_not_inherit_legacy_quirks() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read_to_string(
            std::env::var("STELA_XHCI_AMD_PCI_ORACLE").expect("path to fresh source oracle trace"),
        )
        .unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "f15c7bae3478f2cbf04438ef5fa64d24799ee708dc73d32fec4d1f687c4e57b9"
        );
        let mut count = 0;
        let mut legacy_positive = false;
        let mut actual_negative = 0;
        for line in trace.lines() {
            let mut fields = line.split_whitespace();
            let kind = fields.next().unwrap();
            let values: Vec<u64> = fields.map(|v| v.parse().unwrap()).collect();
            assert_eq!(values.len(), 5);
            match kind {
                "P" => {
                    assert!(matches!(values[0], 0x15b6 | 0x15b7 | 0x15b8 | 0x43fc));
                    Capabilities::new(values[2] as u16, 0, 0).admit().unwrap();
                    // xHCI>=1.2 permits runtime PM generically; this cold polled
                    // backend does not claim a suspend/runtime-power service.
                    assert_eq!(values[3], if values[2] >= 0x120 { 1 << 33 } else { 0 });
                    assert_eq!(values[4], 0);
                }
                "L" => {
                    if values[0] == 0x1022 && values[1] == 0x790b {
                        assert_eq!(values[3], 0);
                        actual_negative += 1;
                    }
                    legacy_positive |= values[3] != 0;
                }
                _ => panic!("unknown PCI source trace"),
            }
            count += 1;
        }
        assert_eq!(count, 4096);
        assert_eq!(actual_negative, 256);
        assert!(legacy_positive);
    }

    /// Opaque reuse of the real-ring ISO model by class lifecycle regressions. This
    /// is not USB enumeration, normal control/HCI I/O or a hardware qualification.
    pub(crate) struct ClassIsoFixture {
        controller: Shared,
        hardware: Rc<RefCell<Hardware>>,
    }
    pub(crate) fn class_fixture(dma: &mut dyn DmaAllocator, speed: u8) -> ClassIsoFixture {
        let (controller, hardware) = controller(dma, speed, 32, true);
        ClassIsoFixture {
            controller: Rc::new(RefCell::new(controller)),
            hardware,
        }
    }
    impl ClassIsoFixture {
        pub(crate) fn controller(&self) -> Shared {
            self.controller.clone()
        }
        pub(crate) fn set_mfindex(&self, value: u32) {
            self.hardware.borrow_mut().mfindex = value;
        }
        /// Complete the oldest actual queued service on this endpoint.
        pub(crate) fn complete(&self, dci: u8, code: u32, residual: usize) {
            self.hardware.borrow_mut().complete(dci, 0, code, residual);
        }
        pub(crate) fn commands(&self) -> Vec<(u32, u8)> {
            self.hardware.borrow().seen.clone()
        }
    }
}
