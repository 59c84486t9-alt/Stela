//! Device slots: their contexts, the commands that manage them, and the
//! transfer rings that move data to and from the device on a root port.
//!
//! Evidence: xHCI 1.2 sections 4.5 (device slots), 4.6.3-4.6.11 (slot and
//! endpoint commands), 4.8 (endpoint states), 4.9 (TRB rings), 4.10-4.11
//! (transfer execution, TRB types, short packets, Event Data) and 6.2
//! (context layouts). Contexts are 32 bytes (HCCPARAMS1.CSZ clear). The
//! output Device Context is the one DCBAA names when Address Device runs;
//! the controller writes its slot and endpoint states, the USB address and
//! each stopped or halted endpoint's TR Dequeue Pointer back to it, as the
//! specification requires before the command's completion.
//!
//! A TD is the TRBs from one with CH clear to the next, Link TRBs aside.
//! A TD runs once its first TRB is owned (software writes that cycle bit
//! last). Packets are max-packet sized and may span TRBs; an IN packet
//! shorter than max packet ends the TD with a Short Packet event on the
//! TRB it ended in (when ISP or IOC is set) and a Short Packet completion
//! on the TD's later Event Data TRBs. A device sending more than the TD
//! holds babbles. STALL halts the endpoint with a Stall Error; a missing
//! device or a port that is not Enabled halts it with a USB Transaction
//! Error, as after the retries CErr counts. A NAK leaves the TD in place:
//! a periodic endpoint is polled again at its next service interval once
//! its function has something to say, an asynchronous one at the next
//! microframe.
//!
//! A slot's Route String (4.5.2, 8.9) selects its device below the root
//! port: each nibble is a hub's downstream port, so a hub function that
//! enables the port (`usb::Function::downstream`) reaches the device;
//! otherwise it is missing, as a disconnected device is. Configure
//! Endpoint records a hub's Hub, MTT, Number of Ports and TT Think Time;
//! split transactions are the hub function's concern, not the
//! controller's. The controller assigns USB address `slot ID`. Refused
//! rather than modeled: streams (MaxPSASize 0), isochronous TRBs (no
//! function has an isochronous endpoint), Link TRBs with IOC on transfer
//! rings, and TDs of more than `MAX_TD_TRBS` TRBs.
use super::{
    CONTEXT_STATE_ERROR, CYCLE, Event, LINK, MAX_SLOTS, MICROFRAME, PARAMETER_ERROR,
    SLOT_NOT_ENABLED, SUCCESS, TOGGLE, TRANSACTION_ERROR, TRB_BYTES, TRB_ERROR, Xhci,
};
use crate::Result;
use alloc::{boxed::Box, format, vec::Vec};
use stela_contracts::refuse;
use {
    crate::platform::usb, crate::platform::usb::Function, crate::platform::usb::Reply,
    crate::platform::usb::Token, stela_contracts::dma::Port,
};

pub(super) const ENDPOINTS: usize = 31;
const CONTEXT: u64 = 32;
const MAX_TD_TRBS: usize = 64;
/// Packets one service may move before yielding to the engine.
const PACKETS_PER_SERVICE: usize = 512;
/// Tries at a NAKed SET_ADDRESS status stage before Address Device fails.
const CONTROL_RETRIES: usize = 8;

const NORMAL: u32 = 1;
const SETUP: u32 = 2;
const DATA: u32 = 3;
const STATUS: u32 = 4;
const ISOCH: u32 = 5;
const EVENT_DATA: u32 = 7;
const NO_OP: u32 = 8;
const TRANSFER: u32 = 32;

const ISP: u32 = 1 << 2;
const CH: u32 = 1 << 4;
const IOC: u32 = 1 << 5;
const IDT: u32 = 1 << 6;
const BEI: u32 = 1 << 9;
const DIR_IN: u32 = 1 << 16;

const BABBLE: u32 = 3;
const STALL_ERROR: u32 = 6;
const ENDPOINT_NOT_ENABLED: u32 = 12;
const SHORT_PACKET: u32 = 13;
const STOPPED: u32 = 26;

const CONTROL: u32 = 4;
const ISOCH_OUT: u32 = 1;
const ISOCH_IN: u32 = 5;
const INTERRUPT_OUT: u32 = 3;
const INTERRUPT_IN: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SlotState {
    Enabled = 0,
    Default = 1,
    Addressed = 2,
    Configured = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpState {
    Disabled = 0,
    Running = 1,
    Halted = 2,
    Stopped = 3,
}

#[derive(Clone, Copy, Default)]
struct Ring {
    dequeue: u64,
    cycle: bool,
}

#[derive(Clone, Copy)]
struct Trb {
    address: u64,
    /// The consumer cycle state at this TRB, for a dequeue pointer here.
    cycle: bool,
    parameter: u64,
    status: u32,
    control: u32,
}

impl Trb {
    fn kind(&self) -> u32 {
        self.control >> 10 & 0x3f
    }
    fn length(&self) -> u32 {
        match self.kind() {
            NORMAL | DATA => self.status & 0x1_ffff,
            _ => 0,
        }
    }
    fn interrupter(&self) -> usize {
        (self.status >> 22) as usize
    }
}

/// The TD at an endpoint's dequeue pointer and how far it has run.
#[derive(Clone)]
struct Td {
    trbs: Vec<Trb>,
    after: Ring,
    index: usize,
    offset: u32,
    in_direction: bool,
    /// Bytes moved since the TD began or its last Event Data TRB (EDTLA).
    accumulated: u32,
    short: bool,
    started: bool,
}

impl Td {
    /// Data bytes the TD still takes, from the cursor.
    fn remaining(&self) -> u64 {
        self.trbs[self.index..]
            .iter()
            .map(|t| u64::from(t.length()))
            .sum::<u64>()
            - u64::from(self.offset)
    }
}

#[derive(Clone)]
struct Endpoint {
    state: EpState,
    /// Software's endpoint context; state and dequeue fields are written
    /// from `state` and `ring`.
    context: [u32; 8],
    ring: Ring,
    td: Option<Td>,
    /// A doorbell names this endpoint and it has not yet run dry.
    rung: bool,
    /// The function NAKed: poll again from `next`.
    waiting: bool,
    next: u64,
}

impl Endpoint {
    const fn disabled() -> Self {
        Self {
            state: EpState::Disabled,
            context: [0; 8],
            ring: Ring {
                dequeue: 0,
                cycle: false,
            },
            td: None,
            rung: false,
            waiting: false,
            next: 0,
        }
    }

    fn kind(&self) -> u32 {
        self.context[1] >> 3 & 7
    }

    fn max_packet(&self) -> usize {
        (self.context[1] >> 16) as usize
    }

    fn periodic(&self) -> bool {
        matches!(
            self.kind(),
            ISOCH_OUT | INTERRUPT_OUT | ISOCH_IN | INTERRUPT_IN
        )
    }

    /// System counts between service opportunities: 2^Interval
    /// microframes for a periodic endpoint.
    fn period(&self) -> u64 {
        if self.periodic() {
            MICROFRAME << (self.context[0] >> 16 & 0xf)
        } else {
            MICROFRAME
        }
    }

    fn output(&self) -> [u32; 8] {
        let mut context = self.context;
        context[0] = context[0] & !7 | self.state as u32;
        context[2] = self.ring.dequeue as u32 & !0xf | u32::from(self.ring.cycle);
        context[3] = (self.ring.dequeue >> 32) as u32;
        context
    }
}

#[derive(Clone)]
pub(super) struct Slot {
    pub(super) state: SlotState,
    /// The output Device Context, once Address Device has read DCBAA.
    output: u64,
    context: [u32; 8],
    endpoints: [Endpoint; ENDPOINTS],
}

impl Slot {
    pub(super) fn new() -> Box<Self> {
        Box::new(Self {
            state: SlotState::Enabled,
            output: 0,
            context: [0; 8],
            endpoints: [const { Endpoint::disabled() }; ENDPOINTS],
        })
    }

    fn port(&self) -> usize {
        (self.context[1] >> 16 & 0xff) as usize
    }

    /// The route string from the root port through hubs (6.2.2).
    fn route(&self) -> u32 {
        self.context[0] & 0xf_ffff
    }

    fn output_context(&self) -> [u32; 8] {
        let mut context = self.context;
        context[3] = context[3] & 0xff | (self.state as u32) << 27;
        context
    }
}

/// The USB endpoint address of Device Context Index `dci`.
fn address(dci: usize) -> u8 {
    if dci == 1 {
        0
    } else {
        (dci / 2) as u8 | if dci % 2 == 1 { 0x80 } else { 0 }
    }
}

fn words(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|n| u32::from_le_bytes(bytes[n * 4..n * 4 + 4].try_into().unwrap()))
}

fn transfer_event(
    trb: u64,
    residual: u32,
    code: u32,
    ed: bool,
    slot: usize,
    dci: usize,
) -> [u32; 4] {
    [
        trb as u32,
        (trb >> 32) as u32,
        residual & 0xff_ffff | code << 24,
        u32::from(ed) << 2 | TRANSFER << 10 | (dci as u32) << 16 | (slot as u32) << 24,
    ]
}

/// The outcome of running an endpoint's TD.
enum Step {
    Done,
    Nak,
    Halt,
    /// The service's packet budget ran out; the endpoint stays rung.
    Yield,
}

impl Xhci {
    fn read_context(port: &mut Port<'_, '_>, at: u64) -> Result<[u32; 8]> {
        let mut bytes = [0u8; 32];
        port.read(at, &mut bytes)
            .map_err(|_| refuse!("xHCI context DMA fault"))?;
        Ok(words(&bytes))
    }

    fn write_context(port: &mut Port<'_, '_>, at: u64, context: [u32; 8]) -> Result<()> {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(context) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        port.write(at, &bytes)
            .map_err(|_| refuse!("xHCI output context DMA fault"))
    }

    fn write_slot_context(port: &mut Port<'_, '_>, slot: &Slot) -> Result<()> {
        Self::write_context(port, slot.output, slot.output_context())
    }

    fn write_endpoint_context(port: &mut Port<'_, '_>, slot: &Slot, dci: usize) -> Result<()> {
        let at = slot.output + CONTEXT * dci as u64;
        Self::write_context(port, at, slot.endpoints[dci - 1].output())
    }

    /// Slot ID `id`'s slot, if enabled.
    fn slot_mut(&mut self, id: usize) -> Option<&mut Slot> {
        (1..=MAX_SLOTS)
            .contains(&id)
            .then(|| self.slots[id - 1].as_deref_mut())
            .flatten()
    }

    /// Whether the root port numbered `number` has an enabled device.
    fn port_ready(&self, number: usize) -> bool {
        (1..=self.ports.len()).contains(&number) && self.ports[number - 1].enabled()
    }

    /// Address Device (4.6.5).
    pub(super) fn address_device(
        &mut self,
        port: &mut Port<'_, '_>,
        function: Option<&mut (dyn Function + '_)>,
        id: usize,
        input: u64,
        bsr: bool,
    ) -> Result<u32> {
        let Some(slot) = self.slot_mut(id) else {
            return Ok(SLOT_NOT_ENABLED);
        };
        match slot.state {
            SlotState::Enabled => {}
            SlotState::Default if !bsr => {}
            _ => return Ok(CONTEXT_STATE_ERROR),
        }
        let control = Self::read_context(port, input)?;
        if control[1] & 3 != 3 {
            return Ok(PARAMETER_ERROR);
        }
        let context = Self::read_context(port, input + CONTEXT)?;
        let ep0 = Self::read_context(port, input + 2 * CONTEXT)?;
        if ep0[1] >> 3 & 7 != CONTROL || ep0[1] >> 16 == 0 {
            return Ok(PARAMETER_ERROR);
        }
        let root = (context[1] >> 16 & 0xff) as usize;
        if !self.port_ready(root) {
            return Ok(TRANSACTION_ERROR);
        }
        // A route through a hub port that is not enabled reaches nothing.
        let device = function.and_then(|f| usb::route(f, context[0]));
        let mut entry = [0u8; 8];
        port.read(self.dcbaap + 8 * id as u64, &mut entry)
            .map_err(|_| refuse!("xHCI DCBAA DMA fault"))?;
        let output = u64::from_le_bytes(entry);
        if output == 0 || output & 0x3f != 0 {
            return Err(refuse!(
                "xHCI Address Device: DCBAA names no aligned output Device Context"
            ));
        }
        if !bsr && !Self::set_address(device, id as u8)? {
            return Ok(TRANSACTION_ERROR);
        }
        let slot = self.slot_mut(id).unwrap();
        slot.state = if bsr {
            SlotState::Default
        } else {
            SlotState::Addressed
        };
        slot.output = output;
        slot.context = context;
        slot.context[3] = if bsr { 0 } else { id as u32 };
        let endpoint = &mut slot.endpoints[0];
        *endpoint = Endpoint::disabled();
        endpoint.context = ep0;
        endpoint.state = EpState::Running;
        endpoint.ring = Ring {
            dequeue: u64::from(ep0[2] & !0xf) | u64::from(ep0[3]) << 32,
            cycle: ep0[2] & 1 != 0,
        };
        Self::write_slot_context(port, slot)?;
        Self::write_endpoint_context(port, slot, 1)?;
        Ok(SUCCESS)
    }

    /// SET_ADDRESS to the device on its port's default address: a
    /// no-data control transfer.
    fn set_address(function: Option<&mut (dyn Function + '_)>, address: u8) -> Result<bool> {
        let Some(function) = function else {
            return Ok(false);
        };
        let mut setup = [0, 5, address, 0, 0, 0, 0, 0];
        if function.packet(0, Token::Setup, &mut setup)? != Reply::Ack(8) {
            return Ok(false);
        }
        for _ in 0..CONTROL_RETRIES {
            match function.packet(0, Token::In, &mut [])? {
                Reply::Ack(0) => return Ok(true),
                Reply::Nak => continue,
                _ => return Ok(false),
            }
        }
        Ok(false)
    }

    /// Configure Endpoint (4.6.6).
    pub(super) fn configure_endpoint(
        &mut self,
        port: &mut Port<'_, '_>,
        id: usize,
        input: u64,
        deconfigure: bool,
    ) -> Result<u32> {
        let Some(slot) = self.slot_mut(id) else {
            return Ok(SLOT_NOT_ENABLED);
        };
        if !matches!(slot.state, SlotState::Addressed | SlotState::Configured) {
            return Ok(CONTEXT_STATE_ERROR);
        }
        if deconfigure {
            for dci in 2..=ENDPOINTS {
                slot.endpoints[dci - 1] = Endpoint::disabled();
                Self::write_endpoint_context(port, slot, dci)?;
            }
            slot.state = SlotState::Addressed;
            slot.context[0] = slot.context[0] & !(0x1f << 27) | 1 << 27;
            Self::write_slot_context(port, slot)?;
            return Ok(SUCCESS);
        }
        let control = Self::read_context(port, input)?;
        let (drop, add) = (control[0], control[1]);
        if drop & 3 != 0 || add & 2 != 0 {
            return Ok(PARAMETER_ERROR);
        }
        // Validate every added context before changing any.
        let mut added = Vec::new();
        for dci in 2..=ENDPOINTS {
            if add & 1 << dci != 0 {
                let context = Self::read_context(port, input + CONTEXT * (dci as u64 + 1))?;
                let kind = context[1] >> 3 & 7;
                let streams = context[0] >> 10 & 0x1f;
                // Types 0 (not valid) and Control are not addable here;
                // an endpoint's direction must match its index.
                let in_type = kind >= 5;
                let valid = kind != 0
                    && kind != CONTROL
                    && in_type == (dci % 2 == 1)
                    && context[1] >> 16 != 0
                    && streams == 0;
                if !valid {
                    return Ok(PARAMETER_ERROR);
                }
                added.push((dci, context));
            }
        }
        let slot_context = if add & 1 != 0 {
            Some(Self::read_context(port, input + CONTEXT)?)
        } else {
            None
        };
        let slot = self.slot_mut(id).unwrap();
        for dci in 2..=ENDPOINTS {
            if drop & 1 << dci != 0 {
                slot.endpoints[dci - 1] = Endpoint::disabled();
                Self::write_endpoint_context(port, slot, dci)?;
            }
        }
        for (dci, context) in added {
            let endpoint = &mut slot.endpoints[dci - 1];
            *endpoint = Endpoint::disabled();
            endpoint.context = context;
            endpoint.state = EpState::Running;
            endpoint.ring = Ring {
                dequeue: u64::from(context[2] & !0xf) | u64::from(context[3]) << 32,
                cycle: context[2] & 1 != 0,
            };
            Self::write_endpoint_context(port, slot, dci)?;
        }
        if let Some(context) = slot_context {
            // Context Entries, and a hub's Hub, MTT, Number of Ports and TT
            // Think Time (6.2.2.3).
            const ENTRIES_HUB_MTT: u32 = 0x1f << 27 | 1 << 26 | 1 << 25;
            slot.context[0] = slot.context[0] & !ENTRIES_HUB_MTT | context[0] & ENTRIES_HUB_MTT;
            slot.context[1] = slot.context[1] & 0x00ff_ffff | context[1] & 0xff00_0000;
            slot.context[2] = slot.context[2] & !(3 << 16) | context[2] & 3 << 16;
        }
        let configured = slot.endpoints[1..]
            .iter()
            .any(|e| e.state != EpState::Disabled);
        slot.state = if configured {
            SlotState::Configured
        } else {
            SlotState::Addressed
        };
        Self::write_slot_context(port, slot)?;
        Ok(SUCCESS)
    }

    /// Evaluate Context (4.6.7): the slot's Max Exit Latency and
    /// Interrupter Target, and EP0's Max Packet Size.
    pub(super) fn evaluate_context(
        &mut self,
        port: &mut Port<'_, '_>,
        id: usize,
        input: u64,
    ) -> Result<u32> {
        let Some(slot) = self.slot_mut(id) else {
            return Ok(SLOT_NOT_ENABLED);
        };
        if slot.state == SlotState::Enabled {
            return Ok(CONTEXT_STATE_ERROR);
        }
        let control = Self::read_context(port, input)?;
        if control[1] & 1 != 0 {
            let context = Self::read_context(port, input + CONTEXT)?;
            slot.context[1] = slot.context[1] & !0xffff | context[1] & 0xffff;
            slot.context[2] = slot.context[2] & 0x3f_ffff | context[2] & !0x3f_ffff;
            Self::write_slot_context(port, slot)?;
        }
        if control[1] & 2 != 0 {
            let ep0 = Self::read_context(port, input + 2 * CONTEXT)?;
            if ep0[1] >> 16 == 0 {
                return Ok(PARAMETER_ERROR);
            }
            let endpoint = &mut slot.endpoints[0];
            endpoint.context[1] = endpoint.context[1] & 0xffff | ep0[1] & 0xffff_0000;
            Self::write_endpoint_context(port, slot, 1)?;
        }
        Ok(SUCCESS)
    }

    /// Reset Endpoint (4.6.8): a Halted endpoint becomes Stopped, its
    /// dequeue pointer at the TRB that halted.
    pub(super) fn reset_endpoint(
        &mut self,
        port: &mut Port<'_, '_>,
        id: usize,
        dci: usize,
    ) -> Result<u32> {
        self.endpoint_command(port, id, dci, |endpoint| {
            if endpoint.state != EpState::Halted {
                return CONTEXT_STATE_ERROR;
            }
            endpoint.state = EpState::Stopped;
            SUCCESS
        })
    }

    /// Stop Endpoint (4.6.9). A TD the endpoint had begun reports Stopped
    /// on its current TRB, ahead of the command's completion.
    pub(super) fn stop_endpoint(
        &mut self,
        port: &mut Port<'_, '_>,
        id: usize,
        dci: usize,
    ) -> Result<u32> {
        let mut stopped = None;
        let code = self.endpoint_command(port, id, dci, |endpoint| {
            if endpoint.state != EpState::Running {
                return CONTEXT_STATE_ERROR;
            }
            if let Some(td) = endpoint.td.take() {
                let trb = td.trbs[td.index.min(td.trbs.len() - 1)];
                if td.started {
                    stopped = Some((trb, trb.length().saturating_sub(td.offset)));
                }
                endpoint.ring = Ring {
                    dequeue: trb.address,
                    cycle: trb.cycle,
                };
            }
            endpoint.state = EpState::Stopped;
            endpoint.rung = false;
            endpoint.waiting = false;
            SUCCESS
        })?;
        if let Some((trb, residual)) = stopped {
            let event = transfer_event(trb.address, residual, STOPPED, false, id, dci);
            self.post_to(trb.interrupter(), event, true)?;
        }
        Ok(code)
    }

    /// Set TR Dequeue Pointer (4.6.10) of a Stopped endpoint.
    pub(super) fn set_dequeue(
        &mut self,
        port: &mut Port<'_, '_>,
        id: usize,
        dci: usize,
        pointer: u64,
        stream: u32,
    ) -> Result<u32> {
        if stream != 0 {
            return Ok(TRB_ERROR);
        }
        self.endpoint_command(port, id, dci, |endpoint| {
            if endpoint.state != EpState::Stopped {
                return CONTEXT_STATE_ERROR;
            }
            endpoint.ring = Ring {
                dequeue: pointer & !0xf,
                cycle: pointer & 1 != 0,
            };
            endpoint.td = None;
            SUCCESS
        })
    }

    /// An endpoint command's common checks and output write.
    fn endpoint_command(
        &mut self,
        port: &mut Port<'_, '_>,
        id: usize,
        dci: usize,
        command: impl FnOnce(&mut Endpoint) -> u32,
    ) -> Result<u32> {
        let Some(slot) = self.slot_mut(id) else {
            return Ok(SLOT_NOT_ENABLED);
        };
        if !(1..=ENDPOINTS).contains(&dci) || slot.endpoints[dci - 1].state == EpState::Disabled {
            return Ok(ENDPOINT_NOT_ENABLED);
        }
        let code = command(&mut slot.endpoints[dci - 1]);
        if code == SUCCESS {
            Self::write_endpoint_context(port, slot, dci)?;
        }
        Ok(code)
    }

    /// Reset Device (4.6.11): back to Default, address 0, EP0 only.
    pub(super) fn reset_device(&mut self, port: &mut Port<'_, '_>, id: usize) -> Result<u32> {
        let Some(slot) = self.slot_mut(id) else {
            return Ok(SLOT_NOT_ENABLED);
        };
        if slot.state == SlotState::Enabled {
            return Ok(CONTEXT_STATE_ERROR);
        }
        for dci in 2..=ENDPOINTS {
            slot.endpoints[dci - 1] = Endpoint::disabled();
            Self::write_endpoint_context(port, slot, dci)?;
        }
        slot.endpoints[0].td = None;
        slot.state = SlotState::Default;
        slot.context[0] = slot.context[0] & !(0x1f << 27) | 1 << 27;
        slot.context[3] &= !0xff;
        Self::write_slot_context(port, slot)?;
        Ok(SUCCESS)
    }

    /// A device slot doorbell: `target` is the endpoint's DCI. A Stopped
    /// endpoint restarts; doorbells of Halted or Disabled endpoints, and of
    /// slots below Default, do nothing (4.7).
    pub(super) fn ring(&mut self, id: usize, value: u32) -> Result<()> {
        let dci = (value & 0xff) as usize;
        if !(1..=ENDPOINTS).contains(&dci) {
            return Err(refuse!("xHCI doorbell target is not an endpoint"));
        }
        if value >> 16 != 0 {
            return Err(refuse!(
                "xHCI doorbell names a stream; streams are not supported"
            ));
        }
        let Some(slot) = self.slot_mut(id) else {
            self.note(format!("doorbell {id} dci {dci} ignored: slot not enabled"));
            return Ok(());
        };
        if slot.state == SlotState::Enabled {
            self.note(format!(
                "doorbell {id} dci {dci} ignored: slot not addressed"
            ));
            return Ok(());
        }
        let endpoint = &mut slot.endpoints[dci - 1];
        if endpoint.state == EpState::Stopped {
            endpoint.state = EpState::Running;
        }
        if endpoint.state == EpState::Running {
            endpoint.rung = true;
            endpoint.waiting = false;
        } else {
            let state = endpoint.state;
            self.note(format!(
                "doorbell {id} dci {dci} ignored: endpoint {state:?}"
            ));
        }
        Ok(())
    }

    /// Endpoints with work to try now.
    pub(super) fn transfers_pending(&self) -> bool {
        self.slots.iter().flatten().any(|slot| {
            slot.endpoints
                .iter()
                .any(|e| e.state == EpState::Running && e.rung && !e.waiting)
        })
    }

    /// The earliest system count at which an endpoint that NAKed is due
    /// for another try.
    pub(super) fn transfer_deadline(&self, function: Option<&(dyn Function + '_)>) -> Option<u64> {
        let mut deadline: Option<u64> = None;
        for slot in self.slots.iter().flatten() {
            let device = function.and_then(|f| usb::route_ref(f, slot.route()));
            for (n, endpoint) in slot.endpoints.iter().enumerate() {
                if endpoint.state != EpState::Running || !endpoint.waiting {
                    continue;
                }
                let dci = n + 1;
                let ready = if dci % 2 == 1 && dci > 1 {
                    device.and_then(|f| f.ready_at(address(dci)))
                } else {
                    Some(0)
                };
                if let Some(ready) = ready {
                    let due = ready.max(endpoint.next);
                    deadline = Some(deadline.map_or(due, |d| d.min(due)));
                }
            }
        }
        deadline
    }

    /// Runs every endpoint with work to try at `now`.
    pub(super) fn run_transfers(
        &mut self,
        port: &mut Port<'_, '_>,
        mut function: Option<&mut (dyn Function + '_)>,
    ) -> Result<()> {
        let now = port.access.now;
        if let Some(f) = function.as_deref_mut() {
            f.set_time(now);
        }
        let mut budget = PACKETS_PER_SERVICE;
        for id in 1..=MAX_SLOTS {
            for dci in 1..=ENDPOINTS {
                let Some(slot) = self.slot_mut(id) else {
                    break;
                };
                let (root, route) = (slot.port(), slot.route());
                // A suspended link schedules nothing.
                if self.port_ready(root) && !self.ports[root - 1].active() {
                    break;
                }
                let endpoint = &mut self.slot_mut(id).unwrap().endpoints[dci - 1];
                if endpoint.state != EpState::Running {
                    continue;
                }
                if endpoint.waiting {
                    let ready = if dci % 2 == 1 && dci > 1 {
                        function
                            .as_deref()
                            .and_then(|f| usb::route_ref(f, route))
                            .and_then(|f| f.ready_at(address(dci)))
                    } else {
                        Some(0)
                    };
                    if !ready.is_some_and(|ready| now >= ready.max(endpoint.next)) {
                        continue;
                    }
                    endpoint.waiting = false;
                } else if !endpoint.rung {
                    continue;
                }
                self.run_endpoint(port, function.as_deref_mut(), id, dci, &mut budget)?;
                if budget == 0 {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn run_endpoint(
        &mut self,
        port: &mut Port<'_, '_>,
        mut function: Option<&mut (dyn Function + '_)>,
        id: usize,
        dci: usize,
        budget: &mut usize,
    ) -> Result<()> {
        let now = port.access.now;
        let slot = self.slot_mut(id).unwrap();
        let (root, route) = (slot.port(), slot.route());
        let present = self.port_ready(root);
        while *budget > 0 {
            let endpoint = &mut self.slot_mut(id).unwrap().endpoints[dci - 1];
            if endpoint.td.is_none() {
                match Self::gather(port, endpoint.ring, dci)? {
                    Some(td) => endpoint.td = Some(td),
                    None => {
                        endpoint.rung = false;
                        return Ok(());
                    }
                }
            }
            let device = function
                .as_deref_mut()
                .filter(|_| present)
                .and_then(|f| usb::route(f, route));
            match self.run_td(port, device, id, dci, budget)? {
                Step::Done => {
                    let endpoint = &mut self.slot_mut(id).unwrap().endpoints[dci - 1];
                    let td = endpoint.td.take().unwrap();
                    endpoint.ring = td.after;
                }
                Step::Nak => {
                    let endpoint = &mut self.slot_mut(id).unwrap().endpoints[dci - 1];
                    endpoint.waiting = true;
                    endpoint.next = now.saturating_add(endpoint.period());
                    return Ok(());
                }
                Step::Halt | Step::Yield => return Ok(()),
            }
        }
        Ok(())
    }

    /// The TD at `ring`, if software has handed over its first TRB.
    fn gather(port: &mut Port<'_, '_>, ring: Ring, dci: usize) -> Result<Option<Td>> {
        let mut at = ring;
        let mut trbs = Vec::new();
        loop {
            let mut bytes = [0u8; 16];
            port.read(at.dequeue, &mut bytes)
                .map_err(|_| refuse!("xHCI transfer ring DMA fault"))?;
            let word = |n: usize| u32::from_le_bytes(bytes[n * 4..n * 4 + 4].try_into().unwrap());
            let control = word(3);
            if (control & CYCLE != 0) != at.cycle {
                // A TD whose later TRBs are not yet owned waits for them.
                return Ok(None);
            }
            let parameter = u64::from(word(0)) | u64::from(word(1)) << 32;
            if control >> 10 & 0x3f == LINK {
                if control & IOC != 0 {
                    return Err(refuse!(
                        "xHCI Link TRB with IOC on a transfer ring is not modeled"
                    ));
                }
                at = Ring {
                    dequeue: parameter & !0xf,
                    cycle: at.cycle ^ (control & TOGGLE != 0),
                };
                continue;
            }
            if trbs.len() == MAX_TD_TRBS {
                return Err(refuse!("xHCI TD exceeds the modeled TRB count"));
            }
            trbs.push(Trb {
                address: at.dequeue,
                cycle: at.cycle,
                parameter,
                status: word(2),
                control,
            });
            at.dequeue += TRB_BYTES;
            // Setup Stage TRBs have no chain bit: each is a TD.
            if control & CH == 0 || control >> 10 & 0x3f == SETUP {
                break;
            }
        }
        let first = trbs[0];
        let in_direction = match first.kind() {
            DATA | STATUS => first.control & DIR_IN != 0,
            _ => dci % 2 == 1,
        };
        Ok(Some(Td {
            trbs,
            after: at,
            index: 0,
            offset: 0,
            in_direction,
            accumulated: 0,
            short: false,
            started: false,
        }))
    }

    fn post_to(&mut self, interrupter: usize, trb: [u32; 4], interrupt: bool) -> Result<()> {
        if interrupter >= self.interrupters.len() {
            return Err(refuse!(
                "xHCI TRB names an interrupter the controller does not have"
            ));
        }
        self.queue(Event {
            interrupter,
            trb,
            interrupt,
        });
        Ok(())
    }

    /// Posts `trb`'s completion when its flags ask for one; errors always.
    fn complete(
        &mut self,
        trb: &Trb,
        residual: u32,
        code: u32,
        id: usize,
        dci: usize,
    ) -> Result<()> {
        let asked = trb.control & IOC != 0 || (code == SHORT_PACKET && trb.control & ISP != 0);
        let failed = !matches!(code, SUCCESS | SHORT_PACKET);
        if dci == 1 || failed {
            self.note(format!(
                "slot {id} dci {dci} TRB {:#x}: completion {code}, residual {residual}{}",
                trb.address,
                if asked || failed { "" } else { ", no event" }
            ));
        }
        if asked || failed {
            let event = transfer_event(trb.address, residual, code, false, id, dci);
            self.post_to(trb.interrupter(), event, trb.control & BEI == 0)?;
        }
        Ok(())
    }

    /// Halts the endpoint at the current TRB with `code`.
    fn halt(&mut self, port: &mut Port<'_, '_>, id: usize, dci: usize, code: u32) -> Result<Step> {
        let slot = self.slot_mut(id).unwrap();
        let endpoint = &mut slot.endpoints[dci - 1];
        let td = endpoint.td.take().unwrap();
        let trb = td.trbs[td.index.min(td.trbs.len() - 1)];
        endpoint.state = EpState::Halted;
        endpoint.rung = false;
        endpoint.waiting = false;
        endpoint.ring = Ring {
            dequeue: trb.address,
            cycle: trb.cycle,
        };
        Self::write_endpoint_context(port, slot, dci)?;
        let residual = trb.length().saturating_sub(td.offset);
        self.complete(&trb, residual, code, id, dci)?;
        Ok(Step::Halt)
    }

    fn td(&mut self, id: usize, dci: usize) -> &mut Td {
        self.slot_mut(id).unwrap().endpoints[dci - 1]
            .td
            .as_mut()
            .unwrap()
    }

    /// Runs the endpoint's TD from its cursor until it completes, NAKs or
    /// halts.
    fn run_td(
        &mut self,
        port: &mut Port<'_, '_>,
        mut device: Option<&mut (dyn Function + '_)>,
        id: usize,
        dci: usize,
        budget: &mut usize,
    ) -> Result<Step> {
        let max_packet = self.slot_mut(id).unwrap().endpoints[dci - 1].max_packet();
        let endpoint_address = address(dci);
        loop {
            let td = self.td(id, dci);
            let Some(&trb) = td.trbs.get(td.index) else {
                return Ok(Step::Done);
            };
            match trb.kind() {
                EVENT_DATA => {
                    let (code, length) = (
                        if td.short { SHORT_PACKET } else { SUCCESS },
                        td.accumulated,
                    );
                    td.accumulated = 0;
                    td.index += 1;
                    if trb.control & IOC != 0 {
                        let event = transfer_event(trb.parameter, length, code, true, id, dci);
                        self.post_to(trb.interrupter(), event, trb.control & BEI == 0)?;
                    }
                    continue;
                }
                NO_OP => {
                    td.index += 1;
                    self.complete(&trb, 0, SUCCESS, id, dci)?;
                    continue;
                }
                ISOCH => return Err(refuse!("xHCI isochronous transfers are not modeled")),
                SETUP | STATUS | NORMAL | DATA => {}
                _ => {
                    td.index += 1;
                    self.complete(&trb, 0, TRB_ERROR, id, dci)?;
                    continue;
                }
            }
            if *budget == 0 {
                return Ok(Step::Yield);
            }
            let Some(function) = device.as_deref_mut() else {
                return self.halt(port, id, dci, TRANSACTION_ERROR);
            };
            *budget -= 1;
            td.started = true;
            let in_direction = td.in_direction;
            match trb.kind() {
                SETUP => {
                    if trb.control & IDT == 0 || trb.status & 0x1_ffff != 8 || dci != 1 {
                        td.index += 1;
                        self.complete(&trb, 8, TRB_ERROR, id, dci)?;
                        continue;
                    }
                    let mut setup = trb.parameter.to_le_bytes();
                    let route = self.slot_mut(id).unwrap().route();
                    self.note(format!("slot {id} route {route:#x} SETUP {setup:02x?}"));
                    match function.packet(endpoint_address, Token::Setup, &mut setup)? {
                        Reply::Ack(8) => {
                            self.td(id, dci).index += 1;
                            self.complete(&trb, 0, SUCCESS, id, dci)?;
                        }
                        // A device ACKs every SETUP; anything else is a
                        // failed transaction.
                        _ => return self.halt(port, id, dci, TRANSACTION_ERROR),
                    }
                }
                STATUS => {
                    let token = if in_direction { Token::In } else { Token::Out };
                    match function.packet(endpoint_address, token, &mut [])? {
                        Reply::Ack(0) => {
                            self.td(id, dci).index += 1;
                            self.complete(&trb, 0, SUCCESS, id, dci)?;
                        }
                        Reply::Ack(_) => return self.halt(port, id, dci, BABBLE),
                        Reply::Nak => return Ok(Step::Nak),
                        Reply::Stall => return self.halt(port, id, dci, STALL_ERROR),
                    }
                }
                _ if in_direction => match self.packet_in(port, function, id, dci, max_packet)? {
                    Some(step) => return Ok(step),
                    None => continue,
                },
                _ => match self.packet_out(port, function, id, dci, max_packet)? {
                    Some(step) => return Ok(step),
                    None => continue,
                },
            }
        }
    }

    /// One IN data packet, scattered over the TD's TRBs from the cursor.
    /// `None` continues the TD.
    fn packet_in(
        &mut self,
        port: &mut Port<'_, '_>,
        function: &mut dyn Function,
        id: usize,
        dci: usize,
        max_packet: usize,
    ) -> Result<Option<Step>> {
        let mut buffer = [0u8; 1024];
        let packet = &mut buffer[..max_packet.min(1024)];
        let n = match function.packet(address(dci), Token::In, packet)? {
            Reply::Ack(n) => n,
            Reply::Nak => return Ok(Some(Step::Nak)),
            Reply::Stall => return self.halt(port, id, dci, STALL_ERROR).map(Some),
        };
        let remaining = self.td(id, dci).remaining();
        if n as u64 > remaining {
            return self.halt(port, id, dci, BABBLE).map(Some);
        }
        let mut data = &packet[..n];
        loop {
            let td = self.td(id, dci);
            let Some(&trb) = td.trbs.get(td.index) else {
                break;
            };
            if !matches!(trb.kind(), NORMAL | DATA) {
                // An Event Data TRB between data TRBs runs on its own.
                if data.is_empty() {
                    break;
                }
                return Err(refuse!("xHCI packet spans a non-data TRB"));
            }
            if trb.control & IDT != 0 {
                td.index += 1;
                self.complete(&trb, trb.length(), TRB_ERROR, id, dci)?;
                continue;
            }
            let room = (trb.length() - td.offset) as usize;
            let take = room.min(data.len());
            if take > 0 {
                port.write(trb.parameter + u64::from(td.offset), &data[..take])
                    .map_err(|_| refuse!("xHCI transfer buffer DMA fault"))?;
            }
            let td = self.td(id, dci);
            td.offset += take as u32;
            td.accumulated += take as u32;
            data = &data[take..];
            if td.offset == trb.length() {
                td.index += 1;
                td.offset = 0;
                self.complete(&trb, 0, SUCCESS, id, dci)?;
                if data.is_empty() {
                    break;
                }
            } else {
                break;
            }
        }
        let td = self.td(id, dci);
        if n < max_packet && td.remaining() > 0 {
            // Short packet: the TRB it ended in reports it; the TD's later
            // Event Data TRBs run, the rest of its data TRBs do not.
            td.short = true;
            let trb = td.trbs[td.index];
            let residual = trb.length() - td.offset;
            td.index += 1;
            td.offset = 0;
            self.complete(&trb, residual, SHORT_PACKET, id, dci)?;
            let td = self.td(id, dci);
            let events: Vec<Trb> = td
                .trbs
                .drain(td.index..)
                .filter(|t| t.kind() == EVENT_DATA)
                .collect();
            td.trbs.extend(events);
        }
        Ok(None)
    }

    /// One OUT data packet gathered from the TD's TRBs from the cursor (or
    /// a zero-length packet for a TD with no data). `None` continues.
    fn packet_out(
        &mut self,
        port: &mut Port<'_, '_>,
        function: &mut dyn Function,
        id: usize,
        dci: usize,
        max_packet: usize,
    ) -> Result<Option<Step>> {
        let mut buffer = [0u8; 1024];
        let want = (self.td(id, dci).remaining() as usize).min(max_packet.min(1024));
        // Gather without moving the cursor: a NAK resends the same bytes.
        let (mut index, mut offset, mut filled) = {
            let td = self.td(id, dci);
            (td.index, td.offset, 0)
        };
        while filled < want {
            let trb = self.td(id, dci).trbs[index];
            if !matches!(trb.kind(), NORMAL | DATA) {
                return Err(refuse!("xHCI packet spans a non-data TRB"));
            }
            let take = ((trb.length() - offset) as usize).min(want - filled);
            if trb.control & IDT != 0 {
                let immediate = trb.parameter.to_le_bytes();
                let start = offset as usize;
                buffer[filled..filled + take].copy_from_slice(&immediate[start..start + take]);
            } else {
                port.read(
                    trb.parameter + u64::from(offset),
                    &mut buffer[filled..filled + take],
                )
                .map_err(|_| refuse!("xHCI transfer buffer DMA fault"))?;
            }
            filled += take;
            offset += take as u32;
            if offset == trb.length() {
                index += 1;
                offset = 0;
            }
        }
        match function.packet(address(dci), Token::Out, &mut buffer[..want])? {
            Reply::Ack(n) if n == want => {}
            Reply::Ack(_) => return Err(refuse!("function acknowledged part of an OUT packet")),
            Reply::Nak => return Ok(Some(Step::Nak)),
            Reply::Stall => return self.halt(port, id, dci, STALL_ERROR).map(Some),
        }
        // Advance over the bytes sent, completing whole TRBs.
        let mut left = want;
        loop {
            let td = self.td(id, dci);
            let Some(&trb) = td.trbs.get(td.index) else {
                break;
            };
            if !matches!(trb.kind(), NORMAL | DATA) {
                break;
            }
            let take = ((trb.length() - td.offset) as usize).min(left);
            td.offset += take as u32;
            td.accumulated += take as u32;
            left -= take;
            if td.offset == trb.length() {
                td.index += 1;
                td.offset = 0;
                self.complete(&trb, 0, SUCCESS, id, dci)?;
                // A zero-length TD sends one packet for its first TRB.
                if left == 0 && (want != 0 || trb.length() == 0) {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_addresses_follow_device_context_indices() {
        assert_eq!(address(1), 0);
        assert_eq!(address(2), 0x01);
        assert_eq!(address(3), 0x81);
        assert_eq!(address(5), 0x82);
        assert_eq!(address(31), 0x8f);
    }

    #[test]
    fn periodic_intervals_are_powers_of_two_microframes() {
        let mut e = Endpoint::disabled();
        e.context[1] = INTERRUPT_IN << 3 | 8 << 16;
        e.context[0] = 3 << 16;
        assert_eq!(e.period(), 8 * MICROFRAME);
        assert_eq!(e.max_packet(), 8);
        e.context[1] = 6 << 3;
        assert_eq!(e.period(), MICROFRAME);
        e.state = EpState::Halted;
        e.ring = Ring {
            dequeue: 0x1234_5670,
            cycle: true,
        };
        assert_eq!(e.output()[0] & 7, 2);
        assert_eq!(e.output()[2], 0x1234_5671);
    }
}
