// SPDX-License-Identifier: GPL-2.0-only
// Primary stream setup follows pinned Linux xhci.c/xhci-mem.c/xhci-ring.c.
// Copyright (C) 2008 Intel Corp. Author: Sarah Sharp.
//! Owned primary stream arrays. Stream zero and unused entries stay zero;
//! each usable stream owns a separate producer ring and at most one TD.
use super::*;
use crate::bus::pci::ConfigSpace;
use core::sync::atomic::{AtomicU64, Ordering};

const PRIMARY_TRANSFER_RING: u64 = 1 << 1;
const LINEAR_STREAM_ARRAY: u32 = 1 << 15;
const STREAM_CONTEXT_BYTES: usize = 16;
const EVENT_DATA: u32 = 1 << 2;
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

/// Immutable qualification for this controller's current reset/ownership
/// epoch. Public raw-register starts have no actual PCI observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Policy {
    Unknown,
    Standard,
    Broken,
    Cadence,
}
impl Policy {
    fn pci(vendor: u16, device: u16) -> Self {
        match (vendor, device) {
            (0x1b73, 0x1000 | 0x1009)
            | (0x1b6f, 0x7023 | 0x7052)
            | (0x1106, 0x3432)
            | (0x1b21, 0x1042) => Self::Broken,
            (0x17cd, 0x0200) => Self::Cadence,
            _ => Self::Standard,
        }
    }
    pub(super) fn admit(self) -> Result<(), BlockError> {
        match self {
            Self::Unknown => Err(BlockError::Unsupported(
                "xHCI streams require actual controller quirk qualification",
            )),
            Self::Broken => Err(BlockError::Unsupported(
                "PCI xHCI controller has broken streams",
            )),
            Self::Standard | Self::Cadence => Ok(()),
        }
    }
}

pub(super) fn pci_policy<C: ConfigSpace>(function: &mut Function<C>) -> Result<Policy, BlockError> {
    let id = function.config().read32(0);
    let class = function.config().read32(8);
    let observed = [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8];
    if id == u32::MAX
        || id as u16 == 0
        || id as u16 != function.vendor
        || (id >> 16) as u16 != function.device
        || observed != CLASS
        || function.class != CLASS
    {
        return Err(BlockError::Unsupported(
            "xHCI PCI identity/class changed before attachment",
        ));
    }
    Ok(Policy::pci(id as u16, (id >> 16) as u16))
}

pub(super) fn doorbell_value(dci: u8, stream: u16) -> u32 {
    u32::from(dci) | u32::from(stream) << 16
}
pub(super) fn dequeue_status(stream: u16) -> u32 {
    u32::from(stream) << 16
}

/// An exact submitted TD, including its controller-independent, nonwrapping
/// identity. Dropping a ticket does not cancel hardware: the endpoint retains
/// its active record and blocks reuse until acknowledged endpoint cancellation.
#[derive(Debug)]
pub struct StreamTransfer {
    id: u64,
    slot: u8,
    dci: u8,
    stream: u16,
    trb: u64,
    length: usize,
}

#[derive(Clone, Copy)]
pub(super) struct Layout {
    pub usable: u16,
    contexts: u32,
}

impl Layout {
    pub fn new(
        maximum: u32,
        speed: u8,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<Self, BlockError> {
        // Linux explicitly treats HCC MaxPSASize=0 (two entries) as no streams.
        if !(4..=65536).contains(&maximum) || !maximum.is_power_of_two() {
            return Err(BlockError::Unsupported(
                "xHCI controller has no primary streams",
            ));
        }
        if !matches!(speed, SUPER_SPEED | SUPER_SPEED_PLUS) || selected.is_empty() || requested == 0
        {
            return Err(BlockError::Unsupported("invalid USB bulk stream selection"));
        }
        let mut usable = u32::from(requested);
        let mut seen = 0u32;
        for address in selected {
            let endpoint = endpoints
                .iter()
                .find(|endpoint| endpoint.address == *address)
                .ok_or(BlockError::Unsupported("stream endpoint is not configured"))?;
            let flag = 1u32 << endpoint.dci();
            if endpoint.address & 0x70 != 0
                || endpoint.dci() < 2
                || seen & flag != 0
                || endpoint.kind() != 2
            {
                return Err(BlockError::Unsupported(
                    "duplicate or non-bulk stream endpoint",
                ));
            }
            seen |= flag;
            endpoint::Context::new(endpoint, speed)?;
            let exponent = endpoint.companion.unwrap().attributes;
            if !(1..=16).contains(&exponent) {
                return Err(BlockError::Unsupported(
                    "USB endpoint does not advertise streams",
                ));
            }
            usable = usable.min(1u32 << exponent);
        }
        // Include the reserved stream-zero context before rounding/clamping.
        let contexts = (usable + 1).next_power_of_two().min(maximum);
        usable = usable.min(contexts - 1);
        Ok(Self {
            usable: usable as u16,
            contexts,
        })
    }

    fn info(self) -> u32 {
        (self.contexts.trailing_zeros() - 1) << 10 | LINEAR_STREAM_ARRAY
    }
}

struct Active {
    id: u64,
    trb: u64,
    length: usize,
    error: Option<BlockError>,
}
struct Stream {
    ring: Ring,
    active: Option<Active>,
}

pub(super) struct Streams {
    array: DmaBuffer,
    layout: Layout,
    rings: Vec<Stream>,
    recovery: bool,
    cadence: bool,
}

impl Streams {
    pub fn new(
        dma: &mut dyn DmaAllocator,
        layout: Layout,
        profile: dma::Profile,
        cadence: bool,
    ) -> Result<Self, BlockError> {
        let bytes = layout.contexts as usize * STREAM_CONTEXT_BYTES;
        let mut array = profile.allocate(dma, bytes, 64)?;
        let mut rings = Vec::new();
        rings
            .try_reserve_exact(usize::from(layout.usable))
            .map_err(|_| BlockError::NoDmaMemory)?;
        for stream in 1..=layout.usable {
            let ring = Ring::with_profile(dma, profile)?;
            array.write(
                usize::from(stream) * STREAM_CONTEXT_BYTES,
                ring.dequeue_pointer() | PRIMARY_TRANSFER_RING,
            );
            rings.push(Stream { ring, active: None });
        }
        Ok(Self {
            array,
            layout,
            rings,
            recovery: false,
            cadence,
        })
    }

    pub fn context(&self) -> (u32, u64) {
        (self.layout.info(), self.array.physical())
    }

    fn stream(&mut self, id: u16) -> Result<&mut Stream, BlockError> {
        let index = id
            .checked_sub(1)
            .ok_or(BlockError::Unsupported("stream zero is reserved"))?;
        self.rings
            .get_mut(usize::from(index))
            .ok_or(BlockError::Unsupported("invalid xHCI stream ID"))
    }

    pub fn dequeue_pointers(&self) -> Vec<(u16, u64)> {
        self.rings
            .iter()
            .enumerate()
            .map(|(index, stream)| {
                (
                    (index + 1) as u16,
                    stream.ring.dequeue_pointer() | PRIMARY_TRANSFER_RING,
                )
            })
            .collect()
    }

    pub fn dequeue_acknowledged(&mut self, id: u16) {
        if self.cadence {
            // Linux xhci_handle_cmd_set_deq: Cadence retains hidden state in
            // these reserved words after Set TR Dequeue. Clear only after its
            // actual success, while the entire endpoint is still stopped.
            let at = usize::from(id) * STREAM_CONTEXT_BYTES;
            self.array.write(at + 8, 0u32);
            self.array.write(at + 12, 0u32);
            fence(Ordering::Release);
        }
    }

    pub fn cancelled(&mut self) {
        for stream in &mut self.rings {
            stream.active = None;
        }
        self.recovery = false;
    }
}

impl Controller {
    /// Pure planning query for an addressed slot in this controller epoch.
    /// The result is a negotiable limit, not an allocation/configuration ACK.
    /// It intentionally works before SET_CONFIGURATION so a selector can fall
    /// back to BOT without first changing the device's alternate setting.
    pub(crate) fn stream_capacity(
        &self,
        slot: u8,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<u16, BlockError> {
        self.live_slot(slot)?;
        self.stream_policy.admit()?;
        if self.command_poisoned || self.error.is_some() {
            return Err(BlockError::Unsupported(
                "xHCI controller is not available for stream planning",
            ));
        }
        let state = self
            .slots
            .get(usize::from(slot))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported("xHCI slot not enabled"))?;
        Layout::new(
            self.max_primary_streams,
            state.speed,
            endpoints,
            selected,
            requested,
        )
        .map(|layout| layout.usable)
    }

    /// Configures new endpoints, with primary streams on exactly the selected
    /// endpoint addresses. All rings/arrays are allocated before publication;
    /// any uncertain Configure Endpoint keeps all of them inaccessible/retained.
    /// Returns the actual usable nonzero IDs shared by every selected endpoint.
    pub fn configure_streams(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        stream_endpoints: &[u8],
        requested: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u16, BlockError> {
        self.stream_capacity(slot, endpoints, stream_endpoints, requested)?;
        self.configure_inner(slot, endpoints, None, stream_endpoints, requested, dma)
    }

    /// Publishes one TD on a nonzero stream. Each stream accepts only one
    /// outstanding ticket; different streams/endpoints may complete in any
    /// order. The caller retains the actual DMA buffer unchanged until success
    /// or acknowledged endpoint-wide cancellation. An error alone never grants
    /// permission to reuse any possibly outstanding contributor's buffer.
    pub fn submit_stream(
        &mut self,
        slot: u8,
        dci: u8,
        stream_id: u16,
        buffer: u64,
        length: usize,
    ) -> Result<StreamTransfer, BlockError> {
        self.endpoint_ready(slot, dci)?;
        if length > MAX_TD
            || (buffer % MAX_TD as u64) as usize + length > MAX_TD
            || buffer.checked_add(length as u64).is_none()
        {
            return Err(BlockError::Unsupported("stream TD outside DMA boundary"));
        }
        self.dma_profile.check(buffer, length)?;
        let endpoint = self.slot(slot)?.endpoints[usize::from(dci)]
            .as_mut()
            .unwrap();
        let streams = endpoint
            .streams
            .as_mut()
            .ok_or(BlockError::Unsupported("endpoint has no streams"))?;
        if streams.recovery {
            return Err(BlockError::Unsupported(
                "stream endpoint requires cancellation",
            ));
        }
        let stream = streams.stream(stream_id)?;
        if stream.active.is_some() {
            return Err(BlockError::Unsupported(
                "xHCI stream already has an active TD",
            ));
        }
        let id = NEXT_TICKET
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BlockError::Unsupported("xHCI stream ticket space exhausted"))?;
        let direction = if endpoint.is_in { ISP } else { 0 };
        let trb = stream
            .ring
            .push(&[(buffer, length as u32, NORMAL << 10 | IOC | direction)])[0];
        stream.active = Some(Active {
            id,
            trb,
            length,
            error: None,
        });
        fence(Ordering::SeqCst);
        self.registers.write32(
            self.doorbells + 4 * usize::from(slot),
            doorbell_value(dci, stream_id),
        );
        Ok(StreamTransfer {
            id,
            slot,
            dci,
            stream: stream_id,
            trb,
            length,
        })
    }

    /// Polls the exact active ticket. Successful completion returns the actual
    /// transferred length; a terminal error remains recorded until cancellation.
    /// Stale, cancelled and foreign tickets cannot consume a current TD's event.
    pub fn completed_stream(
        &mut self,
        ticket: &StreamTransfer,
    ) -> Option<Result<usize, BlockError>> {
        if let Err(error) = self.endpoint_ready(ticket.slot, ticket.dci) {
            return Some(Err(error));
        }
        let checked = (|| {
            let endpoint = self.slot(ticket.slot)?.endpoints[usize::from(ticket.dci)]
                .as_mut()
                .unwrap();
            let streams = endpoint
                .streams
                .as_mut()
                .ok_or(BlockError::Unsupported("endpoint has no streams"))?;
            let active = streams
                .stream(ticket.stream)?
                .active
                .as_ref()
                .ok_or(BlockError::Unsupported("stream ticket is no longer active"))?;
            if (active.id, active.trb, active.length) != (ticket.id, ticket.trb, ticket.length) {
                return Err(BlockError::Unsupported("stale or foreign stream ticket"));
            }
            Ok(active.error.clone())
        })();
        match checked {
            Err(error) | Ok(Some(error)) => return Some(Err(error)),
            Ok(None) => {}
        }
        let event = self.take(|e| {
            e.kind() == TRANSFER_EVENT
                && e.slot() == ticket.slot
                && e.endpoint() == ticket.dci
                && e.parameter == ticket.trb
        })?;
        let endpoint = self.slot(ticket.slot).unwrap().endpoints[usize::from(ticket.dci)]
            .as_mut()
            .unwrap();
        let streams = endpoint.streams.as_mut().unwrap();
        if event.control & EVENT_DATA != 0 || event.residual() > ticket.length {
            endpoint.poisoned = true;
            return Some(Err(BlockError::Unsupported(
                "invalid xHCI stream transfer event",
            )));
        }
        if matches!(event.code(), SUCCESS | SHORT_PACKET) {
            streams.stream(ticket.stream).unwrap().active = None;
            Some(Ok(ticket.length - event.residual()))
        } else {
            let error = BlockError::Device {
                status: event.code(),
            };
            streams.recovery = true;
            streams
                .stream(ticket.stream)
                .unwrap()
                .active
                .as_mut()
                .unwrap()
                .error = Some(error.clone());
            Some(Err(error))
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::collections::BTreeMap;

    struct Cursor {
        base: u64,
        index: usize,
        cycle: u32,
    }
    struct DeviceTd {
        trb: u64,
        buffer: u64,
        bytes: usize,
    }
    struct Hardware {
        command_base: u64,
        command_index: usize,
        event_base: u64,
        event_index: usize,
        output: u64,
        context_bytes: usize,
        cursors: BTreeMap<(u8, u16), Cursor>,
        active: BTreeMap<(u8, u16), DeviceTd>,
        doorbells: Vec<(u8, u16)>,
        commands: Vec<(u32, u16, u64)>,
        fail_command: Option<(u32, u16)>,
        silent_command: Option<u32>,
        fatal: bool,
        cadence: bool,
    }
    impl Hardware {
        fn word(address: u64) -> u32 {
            // SAFETY: the model only accesses retained, aligned allocator
            // ranges published in the real controller's contexts/TRBs.
            unsafe { (address as *const u32).read_volatile() }
        }
        fn long(address: u64) -> u64 {
            // SAFETY: same published live test allocation as word().
            unsafe { (address as *const u64).read_volatile() }
        }
        fn state(&self, dci: u8) -> u32 {
            Self::word(self.output + u64::from(dci) * self.context_bytes as u64) & 7
        }
        fn set_state(&mut self, dci: u8, state: u32) {
            let address = self.output + u64::from(dci) * self.context_bytes as u64;
            // SAFETY: the complete output context is live through this test.
            unsafe { (address as *mut u32).write_volatile(Self::word(address) & !7 | state) };
        }
        fn event(&mut self, trb: u64, code: u32, kind: u32, dci: u8, residual: usize) {
            let address = self.event_base + ((self.event_index % RING_TRBS) * TRB) as u64;
            let cycle = u32::from((self.event_index / RING_TRBS).is_multiple_of(2));
            // SAFETY: the test event ring remains allocated; ownership is
            // published in control last, exactly as a real controller does.
            unsafe {
                (address as *mut u64).write_volatile(trb);
                ((address + 8) as *mut u32).write_volatile(code << 24 | residual as u32);
                ((address + 12) as *mut u32)
                    .write_volatile(1 << 24 | u32::from(dci) << 16 | kind << 10 | cycle);
            }
            self.event_index += 1;
        }
        fn command(&mut self) {
            let address = self.command_base + (self.command_index * TRB) as u64;
            let parameter = Self::long(address);
            let status = Self::word(address + 8);
            let control = Self::word(address + 12);
            let kind = control >> 10 & 0x3f;
            let dci = (control >> 16 & 0x1f) as u8;
            let stream = (status >> 16) as u16;
            self.commands.push((kind, stream, parameter));
            self.command_index = (self.command_index + 1) % (RING_TRBS - 1);
            if self.silent_command == Some(kind) {
                return;
            }
            let mut code = if self.fail_command == Some((kind, stream)) {
                17
            } else {
                SUCCESS
            };
            if code == SUCCESS {
                match kind {
                    CONFIGURE_ENDPOINT => {
                        let added = Self::word(parameter + 4);
                        for ep in 2..32u8 {
                            if added & (1 << ep) == 0 {
                                continue;
                            }
                            let from = parameter + (u64::from(ep) + 1) * self.context_bytes as u64;
                            let to = self.output + u64::from(ep) * self.context_bytes as u64;
                            // SAFETY: separate retained input/output contexts,
                            // validated by the real Configure Endpoint path.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    from as *const u8,
                                    to as *mut u8,
                                    self.context_bytes,
                                );
                            }
                            self.set_state(ep, ENDPOINT_RUNNING);
                        }
                    }
                    STOP_ENDPOINT => {
                        if self.state(dci) != ENDPOINT_RUNNING {
                            code = CONTEXT_STATE_ERROR;
                        } else {
                            self.set_state(dci, ENDPOINT_STOPPED);
                        }
                    }
                    RESET_ENDPOINT => {
                        if self.state(dci) != ENDPOINT_HALTED {
                            code = CONTEXT_STATE_ERROR;
                        } else {
                            self.set_state(dci, ENDPOINT_STOPPED);
                        }
                    }
                    SET_DEQUEUE => {
                        if self.state(dci) != ENDPOINT_STOPPED {
                            code = CONTEXT_STATE_ERROR;
                        } else {
                            assert_ne!(stream, 0);
                            assert_eq!(parameter & 0xe, PRIMARY_TRANSFER_RING);
                            let cursor = self.cursors.get_mut(&(dci, stream));
                            if let Some(cursor) = cursor {
                                cursor.index = ((parameter & !0xf) - cursor.base) as usize / TRB;
                                cursor.cycle = parameter as u32 & 1;
                            } else {
                                let at = self.output + u64::from(dci) * self.context_bytes as u64;
                                let array = Self::long(at + 8);
                                let base = Self::long(array + u64::from(stream) * 16) & !0xf;
                                self.cursors.insert(
                                    (dci, stream),
                                    Cursor {
                                        base,
                                        index: ((parameter & !0xf) - base) as usize / TRB,
                                        cycle: parameter as u32 & 1,
                                    },
                                );
                            }
                            if self.cadence {
                                let at = self.output + u64::from(dci) * self.context_bytes as u64;
                                let array = Self::long(at + 8);
                                // SAFETY: retained stream array in the actual
                                // output endpoint context; emulate its quirk.
                                unsafe {
                                    ((array + u64::from(stream) * 16 + 8) as *mut u32)
                                        .write_volatile(0xcafef00d);
                                    ((array + u64::from(stream) * 16 + 12) as *mut u32)
                                        .write_volatile(0xdeadbeef);
                                }
                            }
                            // A stopped-TD event precedes the final command ACK;
                            // the real cancellation must drain it before reuse.
                            if let Some(td) = self.active.remove(&(dci, stream)) {
                                self.event(td.trb, 26, TRANSFER_EVENT, dci, td.bytes);
                            }
                        }
                    }
                    _ => panic!("unexpected command {kind}"),
                }
            }
            self.event(address, code, COMMAND_COMPLETION, 0, 0);
        }
        fn transfer(&mut self, dci: u8, stream: u16) {
            let context = self.output + u64::from(dci) * self.context_bytes as u64;
            let info = Self::word(context);
            let initial = if info & LINEAR_STREAM_ARRAY != 0 {
                let contexts = 1u32 << ((info >> 10 & 0x1f) + 1);
                assert!(stream != 0 && u32::from(stream) < contexts);
                let array = Self::long(context + 8);
                assert!(array.is_multiple_of(16));
                assert_eq!(Self::long(array), 0);
                let initial = Self::long(array + u64::from(stream) * 16);
                assert_eq!(initial & 0xe, PRIMARY_TRANSFER_RING);
                if self.cadence {
                    assert_eq!(
                        Self::long(array + u64::from(stream) * 16 + 8),
                        0,
                        "Cadence state was not cleared after acknowledged dequeue"
                    );
                }
                initial
            } else {
                assert_eq!(stream, 0);
                Self::long(context + 8)
            };
            let cursor = self.cursors.entry((dci, stream)).or_insert(Cursor {
                base: initial & !0xf,
                index: 0,
                cycle: initial as u32 & 1,
            });
            let trb = cursor.base + (cursor.index * TRB) as u64;
            let control = Self::word(trb + 12);
            assert_eq!(control & CYCLE, cursor.cycle, "unpublished/stale TD");
            assert_eq!(control >> 10 & 0x3f, NORMAL);
            assert_ne!(control & IOC, 0);
            let buffer = Self::long(trb);
            let bytes = (Self::word(trb + 8) & 0x1ffff) as usize;
            assert!(bytes <= MAX_TD && buffer % MAX_TD as u64 + bytes as u64 <= MAX_TD as u64);
            assert!(
                self.active
                    .insert((dci, stream), DeviceTd { trb, buffer, bytes })
                    .is_none()
            );
            cursor.index += 1;
            if cursor.index == RING_TRBS - 1 {
                let link = cursor.base + ((RING_TRBS - 1) * TRB) as u64;
                let control = Self::word(link + 12);
                assert_eq!(Self::long(link), cursor.base);
                assert_eq!(control >> 10 & 0x3f, LINK);
                assert_eq!(control & CYCLE, cursor.cycle);
                assert_ne!(control & TOGGLE, 0);
                cursor.index = 0;
                cursor.cycle ^= 1;
            }
            self.set_state(dci, ENDPOINT_RUNNING);
            self.doorbells.push((dci, stream));
        }
        fn complete(&mut self, dci: u8, stream: u16, code: u32, residual: usize) {
            let td = self.active.remove(&(dci, stream)).unwrap();
            if matches!(code, SUCCESS | SHORT_PACKET) && residual <= td.bytes {
                let n = td.bytes - residual;
                // SAFETY: the exact real submitted DMA range is retained;
                // only device model accesses it before the event below.
                if dci & 1 != 0 {
                    unsafe { core::ptr::write_bytes(td.buffer as *mut u8, stream as u8, n) };
                }
            }
            if code == STALL {
                self.set_state(dci, ENDPOINT_HALTED);
            }
            self.event(td.trb, code, TRANSFER_EVENT, dci, residual);
        }
    }
    struct Model(Rc<RefCell<Hardware>>);
    impl Registers for Model {
        fn read32(&mut self, offset: usize) -> u32 {
            if offset == 0x40 + USBSTS && self.0.borrow().fatal {
                HSE
            } else {
                0
            }
        }
        fn write32(&mut self, offset: usize, value: u32) {
            match offset {
                0x1000 => self.0.borrow_mut().command(),
                0x1004 => self
                    .0
                    .borrow_mut()
                    .transfer(value as u8, (value >> 16) as u16),
                _ => {}
            }
        }
    }
    fn endpoint(address: u8, exponent: u8) -> Endpoint {
        Endpoint {
            address,
            attributes: 2,
            max_packet: 1024,
            interval: 0,
            companion: Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: exponent,
                bytes_per_interval: 0,
            }),
        }
    }
    fn controller(
        dma: &mut dyn DmaAllocator,
        context_bytes: usize,
    ) -> (Controller, Rc<RefCell<Hardware>>) {
        let commands = Ring::new(dma).unwrap();
        let events = dma.allocate(RING_TRBS * TRB, RING_TRBS * TRB).unwrap();
        let output = dma.allocate(32 * context_bytes, 64).unwrap();
        let model = Rc::new(RefCell::new(Hardware {
            command_base: commands.buffer.physical(),
            command_index: 0,
            event_base: events.physical(),
            event_index: 0,
            output: output.physical(),
            context_bytes,
            cursors: BTreeMap::new(),
            active: BTreeMap::new(),
            doorbells: Vec::new(),
            commands: Vec::new(),
            fail_command: None,
            silent_command: None,
            fatal: false,
            cadence: false,
        }));
        let mut slots = vec![None];
        slots.push(Some(Slot {
            attachment: Attachment {
                root_port: 1,
                route: 0,
                tier: 0,
                speed: SUPER_SPEED,
                translator: None,
            },
            retiring: false,
            input: dma.allocate(33 * context_bytes, 64).unwrap(),
            _output: output,
            context: [u32::from(SUPER_SPEED) << 20 | 1 << 27, 1 << 16, 0, 0],
            endpoints: Default::default(),
            control: dma.allocate(CONTROL_BYTES, CONTROL_BYTES).unwrap(),
            speed: SUPER_SPEED,
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
                max_primary_streams: 16,
                stream_policy: Policy::Standard,
                iso_caps: iso::Capabilities::new(0x100, 0, 0),
                max_slots: 1,
                max_ports: 1,
                port_major: vec![3],
                dcbaa: dma.allocate(16, 64).unwrap(),
                _scratchpads: Vec::new(),
                commands,
                events,
                _event_table: dma.allocate(16, 64).unwrap(),
                event_index: 0,
                event_cycle: true,
                slot_ownership: vec![reset::Ownership::Vacant, reset::Ownership::Enabled],
                slots,
                pending: Vec::new(),
                error: None,
                command_poisoned: false,
                location: String::from("stream model"),
            },
            model,
        )
    }

    #[test]
    fn primary_arrays_match_actual_limits_and_keep_zero_unused_contexts() {
        let endpoints = [endpoint(0x81, 4), endpoint(2, 3), endpoint(0x83, 0)];
        for maximum in [4, 8, 16, 65536] {
            for requested in [1, 2, 3, 4, 7, 8, 9, 65535] {
                let layout =
                    Layout::new(maximum, SUPER_SPEED, &endpoints, &[0x81, 2], requested).unwrap();
                assert_eq!(
                    u32::from(layout.usable),
                    u32::from(requested).min(8).min(maximum - 1)
                );
                assert_eq!(1 << ((layout.info() >> 10 & 0x1f) + 1), layout.contexts);
                let mut backing = vec![0u64; 64 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: this whole backing is exclusive/live for the model.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let streams = Streams::new(&mut dma, layout, dma::Profile::SPEC, false).unwrap();
                for index in 0..layout.contexts as usize {
                    let value = streams.array.read::<u64>(index * 16);
                    if index == 0 || index > usize::from(layout.usable) {
                        assert_eq!(value, 0);
                    } else {
                        assert_eq!(
                            value,
                            streams.rings[index - 1].ring.dequeue_pointer() | PRIMARY_TRANSFER_RING
                        );
                        assert_eq!(streams.array.read::<u64>(index * 16 + 8), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn real_contexts_independent_dma_completions_and_stream_rings_wrap() {
        for (context_bytes, overfetch) in [(32, false), (64, false), (32, true), (64, true)] {
            let mut backing = vec![0u64; 256 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing remains exclusive and outlives every DMA access.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, context_bytes);
            if overfetch {
                controller.dma_profile = dma::Profile::pci(0x1d17, 0x9202);
            }
            let endpoints = [endpoint(0x81, 4), endpoint(2, 4)];
            assert_eq!(
                controller.configure_streams(1, &endpoints, &[0x81, 2], 2, &mut dma),
                Ok(2)
            );
            for endpoint in controller.slots[1]
                .as_ref()
                .unwrap()
                .endpoints
                .iter()
                .flatten()
            {
                assert_eq!(
                    endpoint.ring.buffer.len(),
                    controller.dma_profile.segment_bytes()
                );
                for stream in &endpoint.streams.as_ref().unwrap().rings {
                    assert_eq!(
                        stream.ring.buffer.len(),
                        controller.dma_profile.segment_bytes()
                    );
                    assert!(stream.ring.buffer.bytes()[4096..].iter().all(|b| *b == 0));
                }
            }
            let a = dma.allocate(64, 64).unwrap();
            let b = dma.allocate(64, 64).unwrap();
            assert!(controller.submit(1, 3, a.physical(), 64).is_err());
            assert!(controller.submit_stream(1, 3, 0, a.physical(), 64).is_err());
            assert!(controller.submit_stream(1, 3, 3, a.physical(), 64).is_err());
            let mut old = None;
            for index in 0..600 {
                let first = controller.submit_stream(1, 3, 1, a.physical(), 64).unwrap();
                let second = controller.submit_stream(1, 3, 2, b.physical(), 64).unwrap();
                assert!(controller.submit_stream(1, 3, 1, a.physical(), 64).is_err());
                assert_eq!(controller.completed_stream(&first), None);
                if let Some(ticket) = &old {
                    assert!(matches!(controller.completed_stream(ticket), Some(Err(_))));
                }
                model.borrow_mut().complete(3, 2, SHORT_PACKET, 7);
                assert_eq!(controller.completed_stream(&first), None);
                assert_eq!(controller.completed_stream(&second), Some(Ok(57)));
                assert_eq!(&b.bytes()[..57], &[2; 57]);
                model.borrow_mut().complete(3, 1, SUCCESS, 0);
                if let Some(ticket) = &old {
                    assert!(matches!(controller.completed_stream(ticket), Some(Err(_))));
                }
                assert_eq!(controller.completed_stream(&first), Some(Ok(64)));
                assert_eq!(a.bytes(), &[1; 64]);
                if index == 0 {
                    old = Some(first);
                }
            }
            assert!(
                model
                    .borrow()
                    .doorbells
                    .iter()
                    .all(|&(dci, stream)| dci == 3 && (1..=2).contains(&stream))
            );
            let out = controller.submit_stream(1, 4, 2, a.physical(), 64).unwrap();
            model.borrow_mut().complete(4, 2, SUCCESS, 0);
            assert_eq!(controller.completed_stream(&out), Some(Ok(64)));
        }
    }

    #[test]
    fn actual_ordinary_and_stream_submissions_reject_high_payloads_before_ring_mutation() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the model retains exclusive live backing for all DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32);
        controller
            .configure_streams(
                1,
                &[endpoint(0x81, 4), endpoint(2, 0)],
                &[0x81],
                2,
                &mut dma,
            )
            .unwrap();
        // These test epochs model invalid caller payloads; production profiles
        // are immutable and applied during controller construction.
        for (profile, address) in [
            (dma::Profile::pci(0x1b21, 0x3242), 1u64 << 32),
            (dma::Profile::pci(0x1106, 0x3483), 1u64 << 36),
        ] {
            controller.dma_profile = profile;
            let stream = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .streams
                .as_ref()
                .unwrap()
                .rings[0]
                .ring
                .buffer
                .bytes()
                .to_vec();
            let ordinary = controller.slots[1].as_ref().unwrap().endpoints[4]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .bytes()
                .to_vec();
            let doorbells = model.borrow().doorbells.len();
            assert!(controller.submit_stream(1, 3, 1, address, 64).is_err());
            assert!(controller.submit(1, 4, address, 64).is_err());
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(
                slot.endpoints[3]
                    .as_ref()
                    .unwrap()
                    .streams
                    .as_ref()
                    .unwrap()
                    .rings[0]
                    .ring
                    .buffer
                    .bytes(),
                stream
            );
            assert_eq!(
                slot.endpoints[4].as_ref().unwrap().ring.buffer.bytes(),
                ordinary
            );
            assert_eq!(model.borrow().doorbells.len(), doorbells);
        }
    }

    #[test]
    fn cancel_retires_every_stream_then_rejects_stale_tickets_and_events() {
        for halted in [false, true] {
            let mut backing = vec![0u64; 256 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: all actual context/ring/data addresses remain live.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, 32);
            controller
                .configure_streams(1, &[endpoint(0x81, 4)], &[0x81], 3, &mut dma)
                .unwrap();
            let data = dma.allocate(256, 64).unwrap();
            let mut tickets = Vec::new();
            for id in 1..=3 {
                tickets.push(
                    controller
                        .submit_stream(1, 3, id, data.physical() + u64::from(id - 1) * 64, 64)
                        .unwrap(),
                );
            }
            if halted {
                model.borrow_mut().complete(3, 2, STALL, 64);
                assert_eq!(
                    controller.completed_stream(&tickets[1]),
                    Some(Err(BlockError::Device { status: STALL }))
                );
                assert!(
                    controller
                        .submit_stream(1, 3, 2, data.physical(), 64)
                        .is_err()
                );
            }
            controller.cancel(1, 3).unwrap();
            assert!(model.borrow().active.is_empty());
            assert!(controller.pending.iter().all(|event| event.endpoint() != 3));
            let commands = model.borrow().commands.clone();
            let set: Vec<_> = commands
                .iter()
                .filter(|c| c.0 == SET_DEQUEUE)
                .map(|c| c.1)
                .collect();
            assert_eq!(set, vec![1, 2, 3]);
            assert_eq!(
                commands
                    .iter()
                    .filter(|c| c.0
                        == if halted {
                            RESET_ENDPOINT
                        } else {
                            STOP_ENDPOINT
                        })
                    .count(),
                1
            );
            for ticket in &tickets {
                assert!(matches!(controller.completed_stream(ticket), Some(Err(_))));
            }
            let fresh = controller
                .submit_stream(1, 3, 1, data.physical(), 64)
                .unwrap();
            assert_eq!(controller.completed_stream(&fresh), None);
            model.borrow_mut().complete(3, 1, SUCCESS, 0);
            assert_eq!(controller.completed_stream(&fresh), Some(Ok(64)));
        }
    }

    #[test]
    fn partial_dequeue_failure_retains_every_stream_and_blocks_all_mutation() {
        for fail_stream in 1..=3 {
            let mut backing = vec![0u64; 256 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: this test retains every allocation after uncertain stop.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, 32);
            controller
                .configure_streams(1, &[endpoint(0x81, 4)], &[0x81], 3, &mut dma)
                .unwrap();
            let data = dma.allocate(256, 64).unwrap();
            let mut tickets = Vec::new();
            for id in 1..=3 {
                tickets.push(
                    controller
                        .submit_stream(1, 3, id, data.physical() + u64::from(id - 1) * 64, 64)
                        .unwrap(),
                );
            }
            // An idle stream must also remain closed after another stream's
            // uncertain cancellation; active-record busy checks are insufficient.
            model.borrow_mut().complete(3, 3, SUCCESS, 0);
            assert_eq!(controller.completed_stream(&tickets[2]), Some(Ok(64)));
            model.borrow_mut().fail_command = Some((SET_DEQUEUE, fail_stream));
            assert!(controller.cancel(1, 3).is_err());
            let endpoint = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert!(endpoint.poisoned);
            let streams = endpoint.streams.as_ref().unwrap();
            assert!(streams.rings[..2].iter().all(|s| s.active.is_some()));
            assert!(streams.rings[2].active.is_none());
            let bytes: Vec<_> = streams
                .rings
                .iter()
                .map(|s| s.ring.buffer.bytes().to_vec())
                .collect();
            let doorbells = model.borrow().doorbells.len();
            for id in 1..=3 {
                assert!(
                    controller
                        .submit_stream(1, 3, id, data.physical(), 64)
                        .is_err()
                );
            }
            assert!(controller.cancel(1, 3).is_err());
            assert_eq!(model.borrow().doorbells.len(), doorbells);
            let endpoint = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            for (stream, before) in endpoint.streams.as_ref().unwrap().rings.iter().zip(bytes) {
                assert_eq!(stream.ring.buffer.bytes(), before);
            }
        }
    }

    #[test]
    fn invalid_limits_and_advertisements_refuse_before_context_publication() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all DMA remains live/exclusive and no failed plan is published.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32);
        for (maximum, speed, exponent, selected, requested) in [
            (2, SUPER_SPEED, 4, vec![0x81], 2),
            (3, SUPER_SPEED, 4, vec![0x81], 2),
            (16, HIGH_SPEED, 4, vec![0x81], 2),
            (16, SUPER_SPEED, 0, vec![0x81], 2),
            (16, SUPER_SPEED, 17, vec![0x81], 2),
            (16, SUPER_SPEED, 4, vec![0x81, 0x81], 2),
            (16, SUPER_SPEED, 4, vec![0x82], 2),
            (16, SUPER_SPEED, 4, vec![0x81], 0),
        ] {
            controller.max_primary_streams = maximum;
            controller.slots[1].as_mut().unwrap().speed = speed;
            assert!(
                controller
                    .configure_streams(
                        1,
                        &[endpoint(0x81, exponent)],
                        &selected,
                        requested,
                        &mut dma
                    )
                    .is_err()
            );
            assert!(model.borrow().commands.is_empty());
            assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
        }
    }

    #[test]
    fn uncertain_configuration_and_invalid_residual_never_release_streams() {
        for configure_error in [false, true] {
            let mut backing = vec![0u64; 256 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: all allocations retained through completion/poison checks.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, 32);
            if configure_error {
                model.borrow_mut().fail_command = Some((CONFIGURE_ENDPOINT, 0));
            }
            let result =
                controller.configure_streams(1, &[endpoint(0x81, 4)], &[0x81], 2, &mut dma);
            let data = dma.allocate(64, 64).unwrap();
            if configure_error {
                assert!(result.is_err());
                assert!(
                    controller
                        .submit_stream(1, 3, 1, data.physical(), 64)
                        .is_err()
                );
                let endpoint = controller.slots[1].as_ref().unwrap().endpoints[3]
                    .as_ref()
                    .unwrap();
                assert!(!endpoint.enabled && endpoint.poisoned && endpoint.streams.is_some());
            } else {
                result.unwrap();
                let ticket = controller
                    .submit_stream(1, 3, 1, data.physical(), 64)
                    .unwrap();
                model.borrow_mut().complete(3, 1, SUCCESS, 65);
                assert!(matches!(
                    controller.completed_stream(&ticket),
                    Some(Err(BlockError::Unsupported(_)))
                ));
                assert!(
                    controller.slots[1].as_ref().unwrap().endpoints[3]
                        .as_ref()
                        .unwrap()
                        .poisoned
                );
                assert!(
                    controller
                        .submit_stream(1, 3, 2, data.physical(), 64)
                        .is_err()
                );
            }
        }
    }

    #[test]
    #[ignore = "requires pinned unchanged Linux stream helper trace"]
    fn unchanged_linux_primary_size_context_and_wire_encodings() {
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_XHCI_STREAMS_ORACLE")
            .expect("path to immutable source-helper trace");
        let trace = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "204f854062e00199edf3c744ccc6f282876c8051f87282372710d6af1289f36f"
        );
        let mut count = 0;
        for line in trace.lines() {
            let mut parts = line.split_whitespace();
            let kind = parts.next().unwrap();
            let n: Vec<u64> = parts.map(|s| s.parse().unwrap()).collect();
            match kind {
                "S" => {
                    assert_eq!(n.len(), 8);
                    let endpoints = [
                        endpoint(0x81, n[1] as u8),
                        endpoint(2, (n[1] + 4).min(16) as u8),
                    ];
                    let layout = Layout::new(
                        1 << (n[0] + 1),
                        SUPER_SPEED,
                        &endpoints,
                        &[0x81, 2],
                        n[2] as u16,
                    )
                    .unwrap();
                    assert_eq!(u64::from(layout.usable), n[3], "{line}");
                    assert_eq!(u64::from(layout.contexts), n[4], "{line}");
                    assert_eq!(u64::from(0x12800000 | layout.info()), n[5], "{line}");
                    assert_eq!(n[6], 0x123456780);
                    assert_eq!(n[7], 1 << endpoints[0].dci() | 1 << endpoints[1].dci());
                }
                "E" => {
                    assert_eq!(n.len(), 5);
                    assert_eq!(u64::from(doorbell_value(n[0] as u8, n[1] as u16)), n[2]);
                    assert_eq!(u64::from(dequeue_status(n[1] as u16)), n[3]);
                    assert_eq!(PRIMARY_TRANSFER_RING, n[4]);
                }
                _ => panic!("unknown oracle record"),
            }
            count += 1;
        }
        assert_eq!(count, 4560);
    }

    #[test]
    fn status_and_data_streams_are_posted_before_ordinary_uas_command() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusively retained RAM for all device/context/ring accesses.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 64);
        let endpoints = [
            endpoint(0x81, 4),
            endpoint(0x82, 4),
            endpoint(3, 4),
            endpoint(4, 0),
        ];
        controller
            .configure_streams(1, &endpoints, &[0x81, 0x82, 3], 2, &mut dma)
            .unwrap();
        let data = dma.allocate(256, 64).unwrap();
        let status = controller
            .submit_stream(1, 3, 1, data.physical(), 16)
            .unwrap();
        let receive = controller
            .submit_stream(1, 5, 1, data.physical() + 64, 64)
            .unwrap();
        let send = controller
            .submit_stream(1, 6, 1, data.physical() + 128, 64)
            .unwrap();
        let command = controller.submit(1, 8, data.physical() + 192, 32).unwrap();
        assert_eq!(
            model.borrow().doorbells,
            vec![(3, 1), (5, 1), (6, 1), (8, 0)]
        );
        // Completion order is independent of command/doorbell order.
        model.borrow_mut().complete(3, 1, SHORT_PACKET, 0);
        assert_eq!(controller.completed_stream(&status), Some(Ok(16)));
        assert_eq!(controller.completed_stream(&receive), None);
        model.borrow_mut().complete(8, 0, SUCCESS, 0);
        assert_eq!(controller.completed(1, 8, command, 32), Some(Ok(32)));
        model.borrow_mut().complete(6, 1, SUCCESS, 0);
        assert_eq!(controller.completed_stream(&send), Some(Ok(64)));
        model.borrow_mut().complete(5, 1, SHORT_PACKET, 5);
        assert_eq!(controller.completed_stream(&receive), Some(Ok(59)));
    }

    #[test]
    fn foreign_ticket_cannot_consume_another_controllers_pending_completion() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: a single allocator gives distinct retained ranges to both controllers.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut first, one) = controller(&mut dma, 32);
        let (mut second, two) = controller(&mut dma, 32);
        for controller in [&mut first, &mut second] {
            controller
                .configure_streams(1, &[endpoint(0x81, 4)], &[0x81], 2, &mut dma)
                .unwrap();
        }
        let data = dma.allocate(128, 64).unwrap();
        let a = first.submit_stream(1, 3, 1, data.physical(), 64).unwrap();
        let b = second
            .submit_stream(1, 3, 1, data.physical() + 64, 64)
            .unwrap();
        two.borrow_mut().complete(3, 1, SUCCESS, 0);
        assert!(matches!(second.completed_stream(&a), Some(Err(_))));
        assert_eq!(second.completed_stream(&b), Some(Ok(64)));
        one.borrow_mut().complete(3, 1, SUCCESS, 0);
        assert_eq!(first.completed_stream(&a), Some(Ok(64)));
    }

    #[test]
    fn each_stream_allocation_failure_precedes_every_hardware_context_change() {
        struct Fail<'a> {
            inner: &'a mut dyn DmaAllocator,
            at: usize,
            count: usize,
        }
        impl DmaAllocator for Fail<'_> {
            fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
                let at = self.count;
                self.count += 1;
                if at == self.at {
                    Err(BlockError::NoDmaMemory)
                } else {
                    self.inner.allocate(bytes, align)
                }
            }
        }
        for fail_at in 0..13 {
            let mut backing = vec![0u64; 256 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusively retained backing for all actual test DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = controller(&mut dma, 32);
            let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
            let endpoints = [
                endpoint(0x81, 4),
                endpoint(0x82, 4),
                endpoint(3, 4),
                endpoint(4, 0),
            ];
            let mut fail = Fail {
                inner: &mut dma,
                at: fail_at,
                count: 0,
            };
            assert!(matches!(
                controller.configure_streams(1, &endpoints, &[0x81, 0x82, 3], 2, &mut fail),
                Err(BlockError::NoDmaMemory)
            ));
            assert_eq!(fail.count, fail_at + 1);
            assert!(model.borrow().commands.is_empty());
            let slot = controller.slots[1].as_ref().unwrap();
            assert!(slot.endpoints.iter().all(Option::is_none));
            assert_eq!(slot.input.bytes(), input);
        }
    }

    #[test]
    fn command_timeout_and_32bit_dma_refusal_keep_unacknowledged_streams_inaccessible() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all allocations retained even after uncertain command completion.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32);
        model.borrow_mut().silent_command = Some(CONFIGURE_ENDPOINT);
        assert_eq!(
            controller.configure_streams(1, &[endpoint(0x81, 4)], &[0x81], 2, &mut dma),
            Err(BlockError::Timeout)
        );
        let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap();
        assert!(!transfer.enabled && transfer.poisoned && transfer.streams.is_some());
        assert!(controller.command_poisoned);
        let data = dma.allocate(64, 64).unwrap();
        assert!(
            controller
                .submit_stream(1, 3, 1, data.physical(), 64)
                .is_err()
        );
        // The hosted allocation's actual pointer is above the narrow hardware
        // aperture; it must never be truncated into an apparently valid address.
        if start > u64::from(u32::MAX) {
            let layout = Layout::new(16, SUPER_SPEED, &[endpoint(0x81, 4)], &[0x81], 2).unwrap();
            assert!(
                Streams::new(
                    &mut dma,
                    layout,
                    dma::Profile::SPEC.capabilities(false),
                    false
                )
                .is_err()
            );
        }
    }

    #[test]
    fn actual_pci_identity_binds_exact_stream_quirks_without_writes() {
        use crate::bus::pci::Address;
        struct Config {
            id: u32,
            class: u32,
        }
        impl ConfigSpace for Config {
            fn read32(&self, at: u16) -> u32 {
                match at {
                    0 => self.id,
                    8 => self.class,
                    _ => 0,
                }
            }
            fn write32(&mut self, _: u16, _: u32) {
                panic!("preflight must never mutate PCI");
            }
        }
        for (vendor, device, expected) in [
            (0x8086u16, 0x1e31u16, Some(Policy::Standard)),
            (0x1b36, 0x000d, Some(Policy::Standard)),
            (0x1b73, 0x1000, Some(Policy::Broken)),
            (0x1b73, 0x1009, Some(Policy::Broken)),
            (0x1b6f, 0x7023, Some(Policy::Broken)),
            (0x1b6f, 0x7052, Some(Policy::Broken)),
            (0x1106, 0x3432, Some(Policy::Broken)),
            (0x1b21, 0x1042, Some(Policy::Broken)),
            (0x17cd, 0x0200, Some(Policy::Cadence)),
            (0x1b21, 0x1142, Some(Policy::Standard)),
            (0x1b21, 0x1242, Some(Policy::Standard)),
            (0x1b21, 0x2142, Some(Policy::Standard)),
            (0x1b21, 0x3242, Some(Policy::Standard)),
            (0x1106, 0x3483, Some(Policy::Standard)),
            (0x1d17, 0x9202, Some(Policy::Standard)),
            (0x1d17, 0x9203, Some(Policy::Standard)),
        ] {
            let address = Address {
                segment: 0,
                bus: 0,
                device: 1,
                function: 0,
            };
            let id = u32::from(vendor) | u32::from(device) << 16;
            let mut function = Function::new(
                address,
                Config {
                    id,
                    class: 0x0c033001,
                },
            )
            .unwrap();
            let result = pci_policy(&mut function);
            match expected {
                Some(policy) => assert_eq!(result, Ok(policy)),
                None => assert!(result.is_err()),
            }
            function.config().id ^= 1 << 16;
            assert!(pci_policy(&mut function).is_err());
            function.config().id = id;
            function.config().class ^= 1 << 8;
            assert!(pci_policy(&mut function).is_err());
            function.config().class = 0x0c033001;
            function.vendor ^= 1;
            assert!(pci_policy(&mut function).is_err());
        }
    }

    #[test]
    fn pure_capacity_query_never_publishes_and_unknown_or_broken_identity_refuses() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: single retained exclusive model allocation range.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32);
        controller.slots[1].as_mut().unwrap().current_configuration = Some(0);
        let endpoints = [endpoint(0x81, 4), endpoint(2, 3)];
        assert_eq!(
            controller.stream_capacity(1, &endpoints, &[0x81, 2], 32),
            Ok(8)
        );
        assert!(
            controller.slots[1]
                .as_ref()
                .unwrap()
                .endpoints
                .iter()
                .all(Option::is_none)
        );
        assert!(model.borrow().commands.is_empty() && model.borrow().doorbells.is_empty());
        for policy in [Policy::Unknown, Policy::Broken] {
            controller.stream_policy = policy;
            assert!(
                controller
                    .stream_capacity(1, &endpoints, &[0x81, 2], 32)
                    .is_err()
            );
            assert!(
                controller
                    .configure_streams(1, &endpoints, &[0x81, 2], 32, &mut dma)
                    .is_err()
            );
        }
        assert!(model.borrow().commands.is_empty());
    }

    #[test]
    fn cadence_reserved_state_is_cleared_after_each_acknowledged_stream_dequeue() {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all model contexts, arrays, rings and data remain allocated.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32);
        controller.stream_policy = Policy::pci(0x17cd, 0x0200);
        model.borrow_mut().cadence = true;
        controller
            .configure_streams(1, &[endpoint(0x81, 4)], &[0x81], 2, &mut dma)
            .unwrap();
        let data = dma.allocate(128, 64).unwrap();
        for id in 1..=2 {
            controller
                .submit_stream(1, 3, id, data.physical() + u64::from(id - 1) * 64, 64)
                .unwrap();
        }
        controller.cancel(1, 3).unwrap();
        let streams = controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .streams
            .as_ref()
            .unwrap();
        for id in 1..=2 {
            assert_eq!(streams.array.read::<u64>(id * 16 + 8), 0);
        }
        let ticket = controller
            .submit_stream(1, 3, 1, data.physical(), 64)
            .unwrap();
        model.borrow_mut().complete(3, 1, SUCCESS, 0);
        assert_eq!(controller.completed_stream(&ticket), Some(Ok(64)));
    }
}
