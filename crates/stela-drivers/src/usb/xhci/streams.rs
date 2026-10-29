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
const INCOMPATIBLE_DEVICE: u32 = 22;
const INVALID_STREAM_TYPE: u32 = 10;
const RING_UNDERRUN: u32 = 14;
const RING_OVERRUN: u32 = 15;
const STOPPED_LENGTH_INVALID: u32 = 27;
const INVALID_STREAM_ID: u32 = 34;
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

/// Immutable validation for this controller's current reset/ownership
/// epoch. Public raw-register starts have no PCI observation.
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

/// An exact submitted TD, including its addressed-device generation and
/// controller-independent, nonwrapping TD identity. Dropping a ticket does not
/// cancel hardware: the endpoint keeps its active record and blocks reuse
/// until acknowledged endpoint cancellation.
#[derive(Debug)]
pub struct StreamTransfer {
    id: u64,
    device: SlotId,
    dci: u8,
    stream: u16,
    trb: u64,
    length: usize,
}

impl StreamTransfer {
    #[cfg(test)]
    pub(super) fn submitted_pointer(&self) -> u64 {
        self.trb
    }

    pub(super) fn hardware_slot(&self) -> u8 {
        self.device.hardware_slot()
    }

    pub(in crate::usb::xhci) fn device_id(&self) -> SlotId {
        self.device
    }
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
    array: memory::Buffer,
    layout: Layout,
    rings: Vec<Stream>,
    recovery: bool,
    cadence: bool,
    /// Linux `xhci_virt_ep.err_count` for this endpoint's stream TDs.
    errors: u32,
}

impl Streams {
    #[cfg(test)]
    pub fn new(
        dma: &mut dyn DmaAllocator,
        layout: Layout,
        profile: dma::Profile,
        cadence: bool,
    ) -> Result<Self, BlockError> {
        Self::with_memory(dma, layout, profile, cadence, None)
    }

    pub(super) fn with_memory(
        dma: &mut dyn DmaAllocator,
        layout: Layout,
        profile: dma::Profile,
        cadence: bool,
        memory: Option<&Rc<memory::Native>>,
    ) -> Result<Self, BlockError> {
        let bytes = layout.contexts as usize * STREAM_CONTEXT_BYTES;
        let mut array = profile.allocate_memory(dma, bytes, 64, memory)?;
        let mut rings = Vec::new();
        rings
            .try_reserve_exact(usize::from(layout.usable))
            .map_err(|_| BlockError::NoDmaMemory)?;
        for stream in 1..=layout.usable {
            let ring = Ring::with_memory(dma, profile, memory)?;
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
            errors: 0,
        })
    }

    pub(super) fn sync_device(&self) -> Result<(), BlockError> {
        self.array.sync_dirty()?;
        for stream in &self.rings {
            stream.ring.buffer.sync_dirty()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn allocation_geometry(&self) -> Vec<(u64, usize)> {
        core::iter::once((self.array.device_address(), self.array.len()))
            .chain(
                self.rings
                    .iter()
                    .map(|s| (s.ring.buffer.device_address(), s.ring.buffer.len())),
            )
            .collect()
    }

    pub(super) fn matches(&self, layout: Layout, cadence: bool) -> bool {
        self.layout.usable == layout.usable
            && self.layout.contexts == layout.contexts
            && self.cadence == cadence
    }

    /// All stream fetches and events were retired before Disable Slot.
    pub(super) fn reinitialize(&mut self) {
        self.array.bytes_mut().fill(0);
        for (index, stream) in self.rings.iter_mut().enumerate() {
            stream.ring.reinitialize();
            stream.active = None;
            self.array.write(
                (index + 1) * STREAM_CONTEXT_BYTES,
                stream.ring.dequeue_pointer() | PRIMARY_TRANSFER_RING,
            );
        }
        self.recovery = false;
    }

    pub fn context(&self) -> (u32, u64) {
        (self.layout.info(), self.array.device_address())
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
            // Linux xhci_handle_cmd_set_deq: Cadence keeps hidden state in
            // these reserved words after Set TR Dequeue. Clear only after its
            // success, while the entire endpoint is still stopped.
            let at = usize::from(id) * STREAM_CONTEXT_BYTES;
            self.array.write(at + 8, 0u32);
            self.array.write(at + 12, 0u32);
            fence(Ordering::Release);
        }
    }

    pub(super) fn requires_cancellation(&self) -> bool {
        self.recovery
    }

    pub fn cancelled(&mut self) {
        for stream in &mut self.rings {
            stream.active = None;
        }
        self.recovery = false;
    }
}

impl Controller {
    pub(super) fn cancel_native_stream(
        &mut self,
        ticket: &StreamTransfer,
    ) -> Result<(), BlockError> {
        let slot = self.validate_id(ticket.device_id())?;
        let valid = self.slots[usize::from(slot)]
            .as_ref()
            .and_then(|state| state.endpoints[usize::from(ticket.dci)].as_ref())
            .and_then(|endpoint| endpoint.streams.as_ref())
            .and_then(|streams| streams.rings.get(usize::from(ticket.stream) - 1))
            .and_then(|stream| stream.active.as_ref())
            .is_some_and(|active| {
                (active.id, active.trb, active.length) == (ticket.id, ticket.trb, ticket.length)
            });
        if !valid {
            return Err(BlockError::Unsupported(
                "stale or foreign native stream cancellation",
            ));
        }
        self.cancel_owned(slot, ticket.dci)
    }

    /// Pure planning query for an addressed slot in this controller epoch.
    /// The result is a negotiable limit, not an allocation/configuration ACK.
    /// It works before SET_CONFIGURATION so a selector can fall
    /// back to BOT without first changing the device's alternate setting.
    #[cfg(test)]
    pub(crate) fn stream_capacity(
        &self,
        id: impl DeviceRef,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<u16, BlockError> {
        let slot = id.current_slot(self)?;
        self.stream_capacity_owned(slot, endpoints, selected, requested)
    }

    /// Plan streams for one addressed generation without MMIO or DMA
    /// publication. A recycled hardware slot keeps its permanent raw fence;
    /// only its current identity may reach the private capacity calculation.
    pub(crate) fn stream_capacity_for_device(
        &self,
        id: SlotId,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<u16, BlockError> {
        let slot = self.validate_id(id)?;
        self.stream_capacity_owned(slot, endpoints, selected, requested)
    }

    pub(super) fn stream_capacity_owned(
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
    /// any uncertain Configure Endpoint keeps all of them inaccessible/kept.
    /// Returns the usable nonzero IDs shared by every selected endpoint.
    pub fn configure_streams(
        &mut self,
        id: impl DeviceRef,
        endpoints: &[Endpoint],
        stream_endpoints: &[u8],
        requested: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u16, BlockError> {
        let slot = id.current_slot(self)?;
        self.configure_streams_owned(slot, endpoints, stream_endpoints, requested, dma)
    }

    pub(super) fn configure_streams_owned(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        stream_endpoints: &[u8],
        requested: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u16, BlockError> {
        self.stream_capacity_owned(slot, endpoints, stream_endpoints, requested)?;
        self.configure_inner(slot, endpoints, None, stream_endpoints, requested, dma)
    }

    /// Publishes one TD on a nonzero stream. Each stream accepts only one
    /// outstanding ticket; different streams/endpoints may complete in any
    /// order. The caller keeps the DMA buffer unchanged until success
    /// or acknowledged endpoint-wide cancellation. An error alone never grants
    /// permission to reuse any possibly outstanding contributor's buffer.
    pub fn submit_stream(
        &mut self,
        id: impl DeviceRef,
        dci: u8,
        stream_id: u16,
        buffer: u64,
        length: usize,
    ) -> Result<StreamTransfer, BlockError> {
        let slot = id.current_slot(self)?;
        self.submit_stream_owned(slot, dci, stream_id, buffer, length)
    }

    pub(super) fn submit_stream_owned(
        &mut self,
        slot: u8,
        dci: u8,
        stream_id: u16,
        buffer: u64,
        length: usize,
    ) -> Result<StreamTransfer, BlockError> {
        self.device_id(slot)?;
        if self.native_memory.is_some() {
            return Err(BlockError::Unsupported(
                "native xHCI requires a retained typed payload",
            ));
        }
        self.submit_stream_buffer(slot, dci, stream_id, buffer, length)
    }

    pub(in crate::usb::xhci) fn submit_stream_buffer(
        &mut self,
        slot: u8,
        dci: u8,
        stream_id: u16,
        buffer: u64,
        length: usize,
    ) -> Result<StreamTransfer, BlockError> {
        let device = self.device_id(slot)?;
        self.validate_id(device)?;
        self.endpoint_ready_owned(slot, dci)?;
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
            .push(&[(buffer, length as u32, NORMAL << 10 | IOC | direction)])?[0];
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
            device,
            dci,
            stream: stream_id,
            trb,
            length,
        })
    }

    /// Linux handle_transferless_tx_event: events whose TRB pointer lies in
    /// none of the endpoint's stream rings reset the endpoint, softly while
    /// within MAX_SOFT_RETRY. Other such events are dropped.
    fn transferless(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        let streams = self.slot(slot)?.endpoints[usize::from(dci)]
            .as_ref()
            .and_then(|endpoint| endpoint.streams.as_ref())
            .ok_or(BlockError::Unsupported("endpoint has no streams"))?;
        let rings: Vec<_> = streams
            .rings
            .iter()
            .map(|stream| {
                let base = stream.ring.buffer.device_address();
                base..base + (RING_TRBS * TRB) as u64
            })
            .collect();
        while let Some(event) = self.take(|e| {
            e.kind() == TRANSFER_EVENT
                && e.slot() == slot
                && e.endpoint() == dci
                && e.code() != INCOMPATIBLE_DEVICE
                && !rings.iter().any(|ring| ring.contains(&e.parameter))
        }) {
            match event.code() {
                STALL
                | transfer::USB_TRANSACTION_ERROR
                | INVALID_STREAM_TYPE
                | INVALID_STREAM_ID => {
                    let streams = self.slot(slot)?.endpoints[usize::from(dci)]
                        .as_mut()
                        .unwrap()
                        .streams
                        .as_mut()
                        .unwrap();
                    let previous = streams.errors;
                    streams.errors = previous.saturating_add(1);
                    if previous > transfer::MAX_SOFT_RETRY {
                        // EP_HARD_RESET with no TD: the endpoint stays
                        // stopped until it is rung again.
                        self.reset_halted(slot, dci, 0)?;
                    } else {
                        let doorbells: Vec<u32> = (1..=streams.rings.len() as u16)
                            .filter(|id| streams.rings[usize::from(*id) - 1].active.is_some())
                            .map(|id| doorbell_value(dci, id))
                            .collect();
                        self.soft_reset(slot, dci, &doorbells)?;
                    }
                }
                RING_UNDERRUN | RING_OVERRUN | STOPPED_LENGTH_INVALID => {}
                _ => {}
            }
        }
        Ok(())
    }

    /// Polls the exact active ticket. Successful completion returns the
    /// transferred length; a terminal error remains recorded until cancellation.
    /// Stale, cancelled and foreign tickets cannot consume a current TD's event.
    pub fn completed_stream(
        &mut self,
        ticket: &StreamTransfer,
    ) -> Option<Result<usize, BlockError>> {
        // Generation validation precedes every readiness read and completion drain.
        if let Err(error) = self.validate_id(ticket.device_id()) {
            return Some(Err(error));
        }
        let slot = ticket.hardware_slot();
        if let Err(error) = self.completion_ready(slot, ticket.dci) {
            return Some(Err(error));
        }
        let checked = (|| {
            let endpoint = self.slot(slot)?.endpoints[usize::from(ticket.dci)]
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
        if let Err(error) = self.transferless(slot, ticket.dci) {
            return Some(Err(error));
        }
        let event = self.take(|e| {
            e.kind() == TRANSFER_EVENT
                && e.slot() == slot
                && e.endpoint() == ticket.dci
                && (e.parameter == ticket.trb || e.code() == INCOMPATIBLE_DEVICE)
        })?;
        let no_soft_retry = self.quirks.no_soft_retry;
        let state = self.slot(slot).unwrap();
        let tt_info = state.context[2];
        let endpoint = state.endpoints[usize::from(ticket.dci)].as_mut().unwrap();
        let streams = endpoint.streams.as_mut().unwrap();
        if event.code() == INCOMPATIBLE_DEVICE {
            endpoint.poisoned = true;
            return Some(Err(BlockError::Device {
                status: event.code(),
            }));
        }
        if event.control & EVENT_DATA != 0 || event.residual() > ticket.length {
            endpoint.poisoned = true;
            return Some(Err(BlockError::Unsupported(
                "invalid xHCI stream transfer event",
            )));
        }
        if matches!(event.code(), SUCCESS | SHORT_PACKET) {
            streams.errors = 0;
            streams.stream(ticket.stream).unwrap().active = None;
            Some(Ok(ticket.length - event.residual()))
        } else {
            // Linux process_bulk_intr_td handles stream TDs the same way.
            if event.code() == transfer::USB_TRANSACTION_ERROR
                && !streams.recovery
                && transfer::retry_in_place(&mut streams.errors, no_soft_retry, tt_info)
            {
                let doorbells: Vec<u32> = (1..=streams.rings.len() as u16)
                    .filter(|id| streams.rings[usize::from(*id) - 1].active.is_some())
                    .map(|id| doorbell_value(ticket.dci, id))
                    .collect();
                match self.soft_reset(slot, ticket.dci, &doorbells) {
                    Ok(()) => return None,
                    Err(error) => {
                        let streams = self.slot(slot).unwrap().endpoints[usize::from(ticket.dci)]
                            .as_mut()
                            .unwrap()
                            .streams
                            .as_mut()
                            .unwrap();
                        streams.recovery = true;
                        streams
                            .stream(ticket.stream)
                            .unwrap()
                            .active
                            .as_mut()
                            .unwrap()
                            .error = Some(error.clone());
                        return Some(Err(error));
                    }
                }
            }
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
mod tests;
