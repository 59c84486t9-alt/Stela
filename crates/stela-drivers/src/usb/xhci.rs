//! xHCI host controllers (PCI class 0C0330) that the mount drives itself
//! after ExitBootServices, polled, for the host's USB keyboards, pointers,
//! disks and Ethernet adapters.
//!
//! Evidence: eXtensible Host Controller Interface 1.2: initialization
//! (4.2), the USB Legacy Support capability and BIOS handoff (7.1), the
//! Supported Protocol capability (7.2), scratchpad buffers (4.20), device
//! slots and contexts (4.5, 6.2), the command, transfer and event rings
//! (4.9, 6.4, 6.5), root hub port reset (4.19), and USB 2.0 chapters 9 and
//! 11 for standard requests and hubs.
//!
//! One controller runs one command ring, one event ring on interrupter 0
//! (polled; its interrupt stays disabled) and one transfer ring per enabled
//! endpoint, each a single 256-TRB segment closed by a Link TRB. A TD is
//! one TRB of at most 64 KiB that never crosses a 64 KiB boundary (the
//! buffers come from aligned DMA pages). Contexts are 32 or 64 bytes as
//! HCCPARAMS1.CSZ says; scratchpad pages are given when the controller
//! asks. Devices are enumerated once, at attach: every powered root port
//! with a connection is reset (USB 2 ports) or trained (USB 3 ports), and
//! every USB 2.0 hub's ports are powered, reset and enumerated in turn,
//! with each slot's route string and, for low- and full-speed devices
//! behind a high-speed hub, its transaction translator. A STALL on a
//! control pipe resets the endpoint and fails the request; on a bulk or
//! interrupt pipe it also clears the device's halt (USB 2.0 9.4.5). Missing
//! transfer completions require acknowledged Stop Endpoint and Set TR Dequeue;
//! failed cancellation poisons the endpoint. An unresolved command completion or
//! fatal controller status prevents all later DMA/ring mutation until an
//! independently proven controller reset (not implemented as recovery here).
//!
//! Refused rather than handled: SuperSpeed hubs (they need Set Hub Depth
//! and SuperSpeed port control, and no class driver here needs one),
//! isochronous endpoints, streams, hubs more than five tiers deep, and
//! controllers without 4 KiB pages. Hot plug after attach is not seen.
use super::{bluetooth, cdc, hid, storage};
use crate::{
    Clock, Handoff,
    block::BlockError,
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::Function,
    },
    registers,
};
use alloc::{boxed::Box, format, rc::Rc, string::String, vec, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{Ordering, fence},
};

pub const CLASS: [u8; 3] = [0x0c, 0x03, 0x30];

// Capability registers.
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;
// Operational registers.
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const PAGESIZE: usize = 0x08;
const CRCR: usize = 0x18;
const DCBAAP: usize = 0x30;
const CONFIG: usize = 0x38;
const PORTSC: usize = 0x400;
// Interrupter 0.
const IMAN: usize = 0x20;
const ERSTSZ: usize = 0x28;
const ERSTBA: usize = 0x30;
const ERDP: usize = 0x38;

const RUN: u32 = 1;
const HCRST: u32 = 1 << 1;
const HCH: u32 = 1;
const HSE: u32 = 1 << 2;
const CNR: u32 = 1 << 11;
const HCE: u32 = 1 << 12;
const EHB: u64 = 1 << 3;

const CCS: u32 = 1;
const PED: u32 = 1 << 1;
const PR: u32 = 1 << 4;
const PP: u32 = 1 << 9;
const PORT_CHANGES: u32 = 0x7f << 17;
const PRC: u32 = 1 << 21;
/// PORTSC bits a write keeps: power and the wake enables.
const PORT_KEEP: u32 = PP | 0x7 << 25;

const LEGACY_SUPPORT: u32 = 1;
const SUPPORTED_PROTOCOL: u32 = 2;
const BIOS_OWNED: u32 = 1 << 16;
const OS_OWNED: u32 = 1 << 24;
/// USBLEGCTLSTS: the SMI enables, and the RW1C SMI status bits.
const LEGACY_SMI_ENABLES: u32 = 1 | 1 << 4 | 0x7 << 13;
const LEGACY_SMI_STATUS: u32 = 0x7 << 29;

const RING_TRBS: usize = 256;
const TRB: usize = 16;
const CYCLE: u32 = 1;
const TOGGLE: u32 = 1 << 1;
const ISP: u32 = 1 << 2;
const CHAIN: u32 = 1 << 4;
const IOC: u32 = 1 << 5;
const IDT: u32 = 1 << 6;
const DIRECTION_IN: u32 = 1 << 16;

const NORMAL: u32 = 1;
const SETUP: u32 = 2;
const DATA: u32 = 3;
const STATUS: u32 = 4;
const LINK: u32 = 6;
const ENABLE_SLOT: u32 = 9;
const ADDRESS_DEVICE: u32 = 11;
const CONFIGURE_ENDPOINT: u32 = 12;
const EVALUATE_CONTEXT: u32 = 13;
const RESET_ENDPOINT: u32 = 14;
const STOP_ENDPOINT: u32 = 15;
const SET_DEQUEUE: u32 = 16;
const TRANSFER_EVENT: u32 = 32;
const COMMAND_COMPLETION: u32 = 33;

pub const SUCCESS: u32 = 1;
pub const STALL: u32 = 6;
pub const SHORT_PACKET: u32 = 13;
const CONTEXT_STATE_ERROR: u32 = 19;
const ENDPOINT_RUNNING: u32 = 1;
const ENDPOINT_HALTED: u32 = 2;
const ENDPOINT_STOPPED: u32 = 3;

/// `error` in words: a transfer's or command's completion code by its name
/// (xHCI 1.2 table 6-90), which [`BlockError::Device`] carries as a number.
pub fn explain(error: &BlockError) -> String {
    let BlockError::Device { status } = error else {
        return format!("{error}");
    };
    let name = match status {
        2 => "data buffer error",
        3 => "babble detected",
        4 => "USB transaction error",
        5 => "TRB error",
        6 => "stall",
        7 => "resource error",
        8 => "bandwidth error",
        9 => "no slots available",
        11 => "slot not enabled",
        12 => "endpoint not enabled",
        17 => "parameter error",
        19 => "context state error",
        20 => "no ping response",
        22 => "incompatible device",
        26 => "stopped",
        36 => "split transaction error",
        _ => "error",
    };
    format!("{name} (xHCI completion code {status})")
}

/// Port speed IDs (the default Protocol Speed IDs, xHCI 7.2.2.1.1).
pub const FULL_SPEED: u8 = 1;
pub const LOW_SPEED: u8 = 2;
pub const HIGH_SPEED: u8 = 3;
pub const SUPER_SPEED: u8 = 4;

const CONTROL_TYPE: u32 = 4;
const MAX_SLOTS: usize = 32;
const MAX_TIERS: u8 = 5;
/// The most one TD moves, and the boundary it must not cross.
pub const MAX_TD: usize = 64 * 1024;
const CONTROL_BYTES: usize = 4096;

const RESET_US: u64 = 1_000_000;
const HALT_US: u64 = 20_000;
const COMMAND_US: u64 = 5_000_000;
const CONTROL_US: u64 = 5_000_000;
const PORT_RESET_US: u64 = 500_000;
const RESET_RECOVERY_US: u64 = 10_000;
const ADDRESS_RECOVERY_US: u64 = 2_000;
const BIOS_HANDOFF_US: u64 = 1_000_000;

// Standard requests and descriptors (USB 2.0 9.4, 9.6).
pub const GET_STATUS: u8 = 0;
pub const CLEAR_FEATURE: u8 = 1;
pub const SET_FEATURE: u8 = 3;
pub const GET_DESCRIPTOR: u8 = 6;
pub const SET_CONFIGURATION: u8 = 9;
pub const SET_INTERFACE: u8 = 11;
pub const DEVICE_DESCRIPTOR: u8 = 1;
pub const CONFIGURATION_DESCRIPTOR: u8 = 2;
pub const STRING_DESCRIPTOR: u8 = 3;
pub const INTERFACE_DESCRIPTOR: u8 = 4;
pub const ENDPOINT_DESCRIPTOR: u8 = 5;
const HUB_DESCRIPTOR: u8 = 0x29;
const HUB_CLASS: u8 = 9;
/// bInterfaceClass 0xff: a vendor-specific interface.
const VENDOR_CLASS: u8 = 0xff;
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;
const C_PORT_CONNECTION: u16 = 16;
const C_PORT_RESET: u16 = 20;
const LANGUAGE_EN_US: u16 = 0x0409;

/// Register access, so the controller logic runs against a model in tests.
pub trait Registers {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    /// A 64-bit register, as two 32-bit writes, low half first (5.1).
    fn write64(&mut self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}

impl Registers for Mmio {
    fn read32(&mut self, offset: usize) -> u32 {
        Mmio::read32(self, offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        Mmio::write32(self, offset, value);
    }
}

/// An eight-byte SETUP packet.
pub fn setup(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
    let [v0, v1] = value.to_le_bytes();
    let [i0, i1] = index.to_le_bytes();
    let [l0, l1] = length.to_le_bytes();
    [request_type, request, v0, v1, i0, i1, l0, l1]
}

/// Enumeration reports retain the original error alongside the operation
/// that failed. In particular, Address Device and an EP0 transfer can both
/// report USB Transaction Error, with different recovery requirements.
fn during<T>(
    operation: impl Into<String>,
    result: Result<T, BlockError>,
) -> Result<T, (String, BlockError)> {
    result.map_err(|error| (operation.into(), error))
}

#[derive(Clone, Copy, Debug)]
struct Event {
    parameter: u64,
    status: u32,
    control: u32,
}

impl Event {
    fn kind(&self) -> u32 {
        self.control >> 10 & 0x3f
    }
    fn code(&self) -> u32 {
        self.status >> 24
    }
    fn slot(&self) -> u8 {
        (self.control >> 24) as u8
    }
    fn endpoint(&self) -> u8 {
        (self.control >> 16 & 0x1f) as u8
    }
    fn residual(&self) -> usize {
        (self.status & 0xff_ffff) as usize
    }
}

/// A producer ring of one segment closed by a toggling Link TRB.
struct Ring {
    buffer: DmaBuffer,
    index: usize,
    cycle: bool,
}

impl Ring {
    fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        let mut buffer = dma.allocate(RING_TRBS * TRB, 64)?;
        let physical = buffer.physical();
        buffer.write((RING_TRBS - 1) * TRB, physical);
        Ok(Self {
            buffer,
            index: 0,
            cycle: true,
        })
    }

    fn address(&self) -> u64 {
        self.buffer.physical() + (self.index * TRB) as u64
    }

    /// The enqueue pointer with its cycle state, for CRCR or Set TR Dequeue.
    fn dequeue_pointer(&self) -> u64 {
        self.address() | u64::from(self.cycle)
    }

    /// Writes one TD, its first TRB owned last, and returns each TRB's
    /// address.
    fn push(&mut self, trbs: &[(u64, u32, u32)]) -> Vec<u64> {
        let mut addresses = Vec::with_capacity(trbs.len());
        let mut first = None;
        for (n, &(parameter, status, control)) in trbs.iter().enumerate() {
            let at = self.index * TRB;
            addresses.push(self.address());
            self.buffer.write(at, parameter);
            self.buffer.write(at + 8, status);
            let cycle = u32::from(self.cycle);
            if n == 0 {
                first = Some((at, control, cycle));
                self.buffer.write(at + 12, control | (cycle ^ 1));
            } else {
                fence(Ordering::Release);
                self.buffer.write(at + 12, control | cycle);
            }
            self.index += 1;
            if self.index == RING_TRBS - 1 {
                // A Link TRB inside a TD chains it on.
                let chain = control & CHAIN;
                fence(Ordering::Release);
                self.buffer.write(
                    (RING_TRBS - 1) * TRB + 12,
                    LINK << 10 | TOGGLE | chain | u32::from(self.cycle),
                );
                self.index = 0;
                self.cycle = !self.cycle;
            }
        }
        if let Some((at, control, cycle)) = first {
            fence(Ordering::Release);
            self.buffer.write(at + 12, control | cycle);
        }
        addresses
    }
}

/// An endpoint as its descriptor describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: u8,
    pub attributes: u8,
    pub max_packet: u16,
    pub interval: u8,
}

impl Endpoint {
    /// The endpoint's Device Context Index.
    pub fn dci(&self) -> u8 {
        let number = self.address & 0xf;
        2 * number + u8::from(self.address & 0x80 != 0)
    }
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }
    pub fn kind(&self) -> u8 {
        self.attributes & 3
    }
}

/// One interface setting from a configuration descriptor, with the class
/// descriptors that follow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub number: u8,
    pub alternate: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<Endpoint>,
    /// Descriptors between this interface's and the next one's, endpoints
    /// excluded, whole (length and type first).
    pub extra: Vec<Vec<u8>>,
}

/// Whether a configuration's first interface has a standard class.
fn standard_class(configuration: &[u8]) -> bool {
    interfaces(configuration)
        .first()
        .is_some_and(|interface| interface.class != VENDOR_CLASS)
}

/// The interfaces of a configuration descriptor, in order.
pub fn interfaces(configuration: &[u8]) -> Vec<Interface> {
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut at = 0;
    while at + 2 <= configuration.len() {
        let length = usize::from(configuration[at]);
        if length < 2 || at + length > configuration.len() {
            break;
        }
        let d = &configuration[at..at + length];
        match d[1] {
            INTERFACE_DESCRIPTOR if length >= 9 => interfaces.push(Interface {
                number: d[2],
                alternate: d[3],
                class: d[5],
                subclass: d[6],
                protocol: d[7],
                endpoints: Vec::new(),
                extra: Vec::new(),
            }),
            ENDPOINT_DESCRIPTOR if length >= 7 => {
                if let Some(interface) = interfaces.last_mut() {
                    interface.endpoints.push(Endpoint {
                        address: d[2],
                        attributes: d[3],
                        max_packet: u16::from_le_bytes([d[4], d[5]]),
                        interval: d[6],
                    });
                }
            }
            _ => {
                if let Some(interface) = interfaces.last_mut() {
                    interface.extra.push(d.to_vec());
                }
            }
        }
        at += length;
    }
    interfaces
}

/// A device the controller addressed, with what it said about itself.
#[derive(Clone, Debug)]
pub struct Device {
    pub slot: u8,
    pub speed: u8,
    /// Where it is: the controller's PCI function, root port and hub ports.
    pub location: String,
    pub descriptor: [u8; 18],
    pub configuration: Vec<u8>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

impl Device {
    pub fn configuration_value(&self) -> u8 {
        self.configuration.get(5).copied().unwrap_or(1)
    }
    /// A name for logs: the product string, or the IDs.
    pub fn name(&self) -> String {
        match &self.product {
            Some(product) => product.clone(),
            None => format!(
                "{:04x}:{:04x}",
                u16::from_le_bytes([self.descriptor[8], self.descriptor[9]]),
                u16::from_le_bytes([self.descriptor[10], self.descriptor[11]])
            ),
        }
    }
}

struct Transfer {
    ring: Ring,
    is_in: bool,
    /// A failed cancellation leaves hardware ownership unresolved.
    poisoned: bool,
}

struct Slot {
    input: DmaBuffer,
    _output: DmaBuffer,
    /// The slot context as software last set it.
    context: [u32; 4],
    endpoints: [Option<Transfer>; 32],
    control: DmaBuffer,
    speed: u8,
}

/// Where a device hangs off the controller.
#[derive(Clone, Copy, Debug)]
struct Attachment {
    root_port: u8,
    route: u32,
    tier: u8,
    speed: u8,
    /// The high-speed hub slot and port a low- or full-speed device's
    /// transactions go through.
    translator: Option<(u8, u8)>,
}

pub struct Controller {
    registers: Box<dyn Registers>,
    pub(crate) clock: Clock,
    operational: usize,
    runtime: usize,
    doorbells: usize,
    context_bytes: usize,
    wide: bool,
    max_slots: usize,
    max_ports: u8,
    /// Each root port's USB major revision from the Supported Protocol
    /// capabilities.
    port_major: Vec<u8>,
    dcbaa: DmaBuffer,
    _scratchpads: Vec<DmaBuffer>,
    commands: Ring,
    events: DmaBuffer,
    _event_table: DmaBuffer,
    event_index: usize,
    event_cycle: bool,
    slots: Vec<Option<Slot>>,
    /// Transfer events that arrived while waiting for something else.
    pending: Vec<Event>,
    /// USBSTS once the controller reported a fatal error.
    error: Option<u32>,
    /// An unacknowledged command still owns its ring entry. Never wrap/reuse
    /// that entry or mutate command-dependent DMA without a controller reset.
    command_poisoned: bool,
    pub location: String,
}

/// A controller shared by the class drivers of its devices.
pub type Shared = Rc<RefCell<Controller>>;

impl Controller {
    /// Takes the controller from firmware, resets it and starts it.
    pub(crate) fn new(
        mut registers: Box<dyn Registers>,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
        location: String,
    ) -> Result<Self, BlockError> {
        let capability = registers.read32(0);
        let operational = (capability & 0xff) as usize;
        let parameters1 = registers.read32(HCSPARAMS1);
        let parameters2 = registers.read32(HCSPARAMS2);
        let capabilities1 = registers.read32(HCCPARAMS1);
        let doorbells = (registers.read32(DBOFF) & !3) as usize;
        let runtime = (registers.read32(RTSOFF) & !0x1f) as usize;
        let wide = capabilities1 & 1 != 0;
        let context_bytes = if capabilities1 & 1 << 2 != 0 { 64 } else { 32 };
        let extended = ((capabilities1 >> 16) as usize) * 4;
        let max_ports = (parameters1 >> 24) as u8;
        let max_slots = ((parameters1 & 0xff) as usize).min(MAX_SLOTS);
        if max_slots == 0 || max_ports == 0 {
            return Err(BlockError::Unsupported(
                "xHCI controller without slots or ports",
            ));
        }
        let mut port_major = vec![0u8; usize::from(max_ports)];
        if extended != 0 {
            let mut at = extended;
            loop {
                let header = registers.read32(at);
                match header & 0xff {
                    LEGACY_SUPPORT => take_from_firmware(&mut *registers, at, clock),
                    SUPPORTED_PROTOCOL => {
                        let ports = registers.read32(at + 8);
                        let (first, count) =
                            ((ports & 0xff) as usize, (ports >> 8 & 0xff) as usize);
                        for port in first.max(1)..(first + count).min(port_major.len() + 1) {
                            port_major[port - 1] = (header >> 24) as u8;
                        }
                    }
                    _ => {}
                }
                let next = (header >> 8 & 0xff) as usize;
                if next == 0 {
                    break;
                }
                at += next * 4;
            }
        }
        // Halt, then reset (4.2).
        if registers.read32(operational + USBSTS) & HCH == 0 {
            let command = registers.read32(operational + USBCMD);
            registers.write32(operational + USBCMD, command & !RUN);
            if !wait(&mut *registers, clock, HALT_US, |r| {
                r.read32(operational + USBSTS) & HCH != 0
            }) {
                return Err(BlockError::Timeout);
            }
        }
        registers.write32(operational + USBCMD, HCRST);
        let reset = wait(&mut *registers, clock, RESET_US, |r| {
            r.read32(operational + USBCMD) & HCRST == 0 && r.read32(operational + USBSTS) & CNR == 0
        });
        if !reset {
            return Err(BlockError::Timeout);
        }
        if registers.read32(operational + PAGESIZE) & 1 == 0 {
            return Err(BlockError::Unsupported(
                "xHCI controller without 4 KiB pages",
            ));
        }
        let mut allocate = |bytes: usize, align: usize| -> Result<DmaBuffer, BlockError> {
            let buffer = dma.allocate(bytes, align)?;
            if !wide && buffer.physical() + bytes as u64 > 1 << 32 {
                return Err(BlockError::Unsupported(
                    "xHCI 32-bit controller with DMA above 4 GiB",
                ));
            }
            Ok(buffer)
        };
        registers.write32(operational + CONFIG, max_slots as u32);
        let mut dcbaa = allocate((max_slots + 1) * 8, 64)?;
        let scratchpad_count =
            (parameters2 >> 27 & 0x1f | (parameters2 >> 21 & 0x1f) << 5) as usize;
        let mut scratchpads = Vec::new();
        if scratchpad_count > 0 {
            let mut array = allocate(scratchpad_count * 8, 64)?;
            for n in 0..scratchpad_count {
                let page = allocate(4096, 4096)?;
                array.write(n * 8, page.physical());
                scratchpads.push(page);
            }
            dcbaa.write(0, array.physical());
            scratchpads.push(array);
        }
        registers.write64(operational + DCBAAP, dcbaa.physical());
        let commands = Ring::new(dma)?;
        registers.write64(operational + CRCR, commands.dequeue_pointer());
        let events = dma.allocate(RING_TRBS * TRB, 64)?;
        let mut event_table = dma.allocate(16, 64)?;
        event_table.write(0, events.physical());
        event_table.write(8, RING_TRBS as u32);
        registers.write32(runtime + IMAN, 1); // clear IP; IE stays off
        registers.write32(runtime + ERSTSZ, 1);
        registers.write64(runtime + ERDP, events.physical());
        registers.write64(runtime + ERSTBA, event_table.physical());
        registers.write32(operational + USBCMD, RUN);
        if !wait(&mut *registers, clock, HALT_US, |r| {
            r.read32(operational + USBSTS) & HCH == 0
        }) {
            return Err(BlockError::Timeout);
        }
        let mut slots = Vec::new();
        slots.resize_with(max_slots + 1, || None);
        Ok(Self {
            registers,
            clock,
            operational,
            runtime,
            doorbells,
            context_bytes,
            wide,
            max_slots,
            max_ports,
            port_major,
            dcbaa,
            _scratchpads: scratchpads,
            commands,
            events,
            _event_table: event_table,
            event_index: 0,
            event_cycle: true,
            slots,
            pending: Vec::new(),
            error: None,
            command_poisoned: false,
            location,
        })
    }

    fn doorbell(&mut self, slot: u8, target: u8) {
        fence(Ordering::SeqCst);
        self.registers
            .write32(self.doorbells + 4 * usize::from(slot), u32::from(target));
    }

    /// The next event on the ring, if the controller has posted one.
    fn next_event(&mut self) -> Option<Event> {
        let at = self.event_index * TRB;
        let control: u32 = self.events.read(at + 12);
        if (control & CYCLE != 0) != self.event_cycle {
            return None;
        }
        fence(Ordering::Acquire);
        let event = Event {
            parameter: self.events.read(at),
            status: self.events.read(at + 8),
            control,
        };
        self.event_index += 1;
        if self.event_index == RING_TRBS {
            self.event_index = 0;
            self.event_cycle = !self.event_cycle;
        }
        let dequeue = self.events.physical() + (self.event_index * TRB) as u64;
        self.registers.write64(self.runtime + ERDP, dequeue | EHB);
        Some(event)
    }

    /// Takes every posted event: transfer events wait in `pending`. A host
    /// system or host controller error (5.4.2) stops the controller for
    /// good.
    fn drain(&mut self) {
        let status = self.registers.read32(self.operational + USBSTS);
        if status & (HSE | HCE) != 0 && self.error.is_none() {
            self.error = Some(status);
        }
        while let Some(event) = self.next_event() {
            if event.kind() == TRANSFER_EVENT || event.kind() == COMMAND_COMPLETION {
                self.pending.push(event);
            }
        }
    }

    fn take(&mut self, wanted: impl Fn(&Event) -> bool) -> Option<Event> {
        let index = self.pending.iter().position(wanted)?;
        Some(self.pending.remove(index))
    }

    /// Waits up to `microseconds` for an event `wanted` accepts.
    fn wait_event(
        &mut self,
        microseconds: u64,
        wanted: impl Fn(&Event) -> bool,
    ) -> Result<Event, BlockError> {
        let deadline = self.clock.deadline(microseconds);
        loop {
            self.drain();
            if let Some(event) = self.take(&wanted) {
                return Ok(event);
            }
            if let Some(status) = self.error {
                return Err(BlockError::Device { status });
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Before any new command-dependent DMA mutation or doorbell. A late
    /// completion cannot establish a new command generation or undo poison.
    fn ready(&mut self) -> Result<(), BlockError> {
        self.drain();
        if let Some(status) = self.error {
            self.command_poisoned = true;
            return Err(BlockError::Device { status });
        }
        if self.command_poisoned {
            return Err(BlockError::Unsupported(
                "xHCI command completion unresolved",
            ));
        }
        Ok(())
    }

    fn command(&mut self, parameter: u64, status: u32, control: u32) -> Result<Event, BlockError> {
        self.ready()?;
        let address = self.commands.push(&[(parameter, status, control)])[0];
        self.doorbell(0, 0);
        let event = match self.wait_event(COMMAND_US, |e| {
            e.kind() == COMMAND_COMPLETION && e.parameter == address
        }) {
            Ok(event) => event,
            Err(error) => {
                self.command_poisoned = true;
                return Err(error);
            }
        };
        // wait_event may have observed both a completion and fatal USBSTS.
        // Neither permits new commands until the controller is reset.
        if let Some(status) = self.error {
            self.command_poisoned = true;
            return Err(BlockError::Device { status });
        }
        match event.code() {
            SUCCESS => Ok(event),
            status => Err(BlockError::Device { status }),
        }
    }

    fn port_offset(&self, port: u8) -> usize {
        self.operational + PORTSC + 0x10 * usize::from(port - 1)
    }

    fn write_port(&mut self, port: u8, bits: u32) {
        let at = self.port_offset(port);
        let current = self.registers.read32(at);
        self.registers.write32(at, current & PORT_KEEP | bits);
    }

    fn context(&self) -> usize {
        self.context_bytes
    }

    /// Enables a slot and addresses the device at `attachment`.
    fn address(
        &mut self,
        attachment: Attachment,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u8, (String, BlockError)> {
        let event = during("Enable Slot", self.command(0, 0, ENABLE_SLOT << 10))?;
        let slot = event.slot();
        if usize::from(slot) == 0 || usize::from(slot) > self.max_slots {
            return during(
                "Enable Slot",
                Err(BlockError::Unsupported("xHCI slot ID out of range")),
            );
        }
        let context = self.context();
        let allocation = format!("slot {slot} allocate contexts and EP0 ring");
        let output = during(allocation.clone(), dma.allocate(32 * context, 64))?;
        let mut input = during(allocation.clone(), dma.allocate(33 * context, 64))?;
        let control = during(
            allocation.clone(),
            dma.allocate(CONTROL_BYTES, CONTROL_BYTES),
        )?;
        if !self.wide
            && [output.physical(), input.physical(), control.physical()]
                .iter()
                .any(|address| address >> 32 != 0)
        {
            return during(
                allocation,
                Err(BlockError::Unsupported(
                    "xHCI 32-bit controller with DMA above 4 GiB",
                )),
            );
        }
        self.dcbaa.write(usize::from(slot) * 8, output.physical());
        let ring = during(allocation, Ring::new(dma))?;
        let max_packet: u32 = match attachment.speed {
            LOW_SPEED | FULL_SPEED => 8,
            HIGH_SPEED => 64,
            _ => 512,
        };
        let (tt_slot, tt_port) = attachment.translator.unwrap_or((0, 0));
        let slot_context = [
            attachment.route | u32::from(attachment.speed) << 20 | 1 << 27,
            u32::from(attachment.root_port) << 16,
            u32::from(tt_slot) | u32::from(tt_port) << 8,
            0,
        ];
        input.write(4, 0b11u32);
        for (n, word) in slot_context.iter().enumerate() {
            input.write(context + 4 * n, *word);
        }
        let ep0 = 2 * context;
        input.write(ep0 + 4, 3 << 1 | CONTROL_TYPE << 3 | max_packet << 16);
        input.write(ep0 + 8, ring.dequeue_pointer());
        input.write(ep0 + 16, 8u32);
        let mut endpoints: [Option<Transfer>; 32] = Default::default();
        endpoints[1] = Some(Transfer {
            ring,
            is_in: false,
            poisoned: false,
        });
        let input_address = input.physical();
        self.slots[usize::from(slot)] = Some(Slot {
            input,
            _output: output,
            context: slot_context,
            endpoints,
            control,
            speed: attachment.speed,
        });
        during(
            format!("slot {slot} Address Device"),
            self.command(
                input_address,
                0,
                ADDRESS_DEVICE << 10 | u32::from(slot) << 24,
            ),
        )?;
        // Address Device sends SET_ADDRESS with BSR=0. The xHC does not
        // time the device's recovery interval (xHCI 1.2b 4.6.5); USB 2.0
        // 9.2.6.3 permits it to ignore Setup packets for another 2 ms.
        self.clock.delay(ADDRESS_RECOVERY_US);
        Ok(slot)
    }

    fn slot(&mut self, slot: u8) -> Result<&mut Slot, BlockError> {
        self.slots
            .get_mut(usize::from(slot))
            .and_then(Option::as_mut)
            .ok_or(BlockError::Unsupported("xHCI slot not enabled"))
    }

    /// Clears the input context's control and endpoint words.
    fn clear_input(&mut self, slot: u8) -> Result<(), BlockError> {
        self.ready()?;
        let context = self.context();
        let input = &mut self.slot(slot)?.input;
        let bytes = input.len();
        input.bytes_mut()[..bytes.min(33 * context)].fill(0);
        Ok(())
    }

    /// Changes EP0's max packet size (Evaluate Context, 4.6.7).
    fn set_control_packet(&mut self, slot: u8, max_packet: u16) -> Result<(), BlockError> {
        self.clear_input(slot)?;
        let context = self.context();
        let input_address = {
            let state = self.slot(slot)?;
            state.input.write(4, 0b10u32);
            state
                .input
                .write(2 * context + 4, u32::from(max_packet) << 16);
            state.input.physical()
        };
        self.command(
            input_address,
            0,
            EVALUATE_CONTEXT << 10 | u32::from(slot) << 24,
        )?;
        Ok(())
    }

    /// Recovers a halted endpoint: Reset Endpoint, then its dequeue pointer
    /// moved past the failed TD (4.6.8, 4.6.10).
    fn recover(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.cancel(slot, dci)
    }

    /// Check controller/endpoint poison before modifying a buffer used by a
    /// previous failed transfer. This does not claim completion of a currently
    /// outstanding TD; its normal completion/cancellation must still be awaited.
    pub fn endpoint_ready(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        self.ready()?;
        let endpoint = self
            .slot(slot)?
            .endpoints
            .get(usize::from(dci))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported("xHCI endpoint not configured"))?;
        if endpoint.poisoned {
            return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
        }
        Ok(())
    }

    /// One control transfer on EP0; IN data is returned, OUT data sent.
    pub fn control(
        &mut self,
        slot: u8,
        request: [u8; 8],
        out: &[u8],
    ) -> Result<Vec<u8>, BlockError> {
        self.endpoint_ready(slot, 1)?;
        let length = usize::from(u16::from_le_bytes([request[6], request[7]]));
        let is_in = request[0] & 0x80 != 0;
        if length > CONTROL_BYTES || (!is_in && out.len() != length) {
            return Err(BlockError::Unsupported("control transfer length"));
        }
        let buffer = {
            let state = self.slot(slot)?;
            if state.endpoints[1]
                .as_ref()
                .is_some_and(|endpoint| endpoint.poisoned)
            {
                return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
            }
            if !is_in {
                state.control.bytes_mut()[..length].copy_from_slice(out);
            }
            state.control.physical()
        };
        let transfer_type = match (length, is_in) {
            (0, _) => 0,
            (_, false) => 2,
            (_, true) => 3,
        };
        let mut trbs = vec![(
            u64::from_le_bytes(request),
            8,
            SETUP << 10 | IDT | transfer_type << 16,
        )];
        let direction = if is_in { DIRECTION_IN } else { 0 };
        if length > 0 {
            trbs.push((buffer, length as u32, DATA << 10 | ISP | direction));
        }
        let status_direction = if length > 0 && is_in { 0 } else { DIRECTION_IN };
        trbs.push((0, 0, STATUS << 10 | IOC | status_direction));
        let addresses = {
            let state = self.slot(slot)?;
            let ring = &mut state.endpoints[1]
                .as_mut()
                .ok_or(BlockError::Unsupported("xHCI control endpoint"))?
                .ring;
            ring.push(&trbs)
        };
        self.doorbell(slot, 1);
        let status_address = *addresses.last().unwrap();
        let mut received = length;
        loop {
            let event = self.wait_event(CONTROL_US, |e| {
                e.kind() == TRANSFER_EVENT && e.slot() == slot && e.endpoint() == 1
            });
            let event = match event {
                Ok(event) => event,
                Err(error) => {
                    // A missing transfer completion leaves EP0 Running, not
                    // Halted. Only acknowledged Stop/Set Dequeue permits reuse;
                    // failed cancellation is reported and retains poison.
                    self.cancel(slot, 1)?;
                    return Err(error);
                }
            };
            match event.code() {
                SUCCESS if event.parameter == status_address => break,
                SUCCESS => {}
                SHORT_PACKET => received = length.saturating_sub(event.residual()),
                status => {
                    self.recover(slot, 1)?;
                    return Err(BlockError::Device { status });
                }
            }
        }
        if !is_in {
            return Ok(Vec::new());
        }
        let state = self.slot(slot)?;
        Ok(state.control.bytes()[..received].to_vec())
    }

    fn descriptor(
        &mut self,
        slot: u8,
        kind: u8,
        index: u8,
        length: u16,
    ) -> Result<Vec<u8>, BlockError> {
        let value = u16::from(kind) << 8 | u16::from(index);
        let language = if kind == STRING_DESCRIPTOR && index != 0 {
            LANGUAGE_EN_US
        } else {
            0
        };
        self.control(
            slot,
            setup(0x80, GET_DESCRIPTOR, value, language, length),
            &[],
        )
    }

    pub(crate) fn string(&mut self, slot: u8, index: u8) -> Option<String> {
        if index == 0 {
            return None;
        }
        let bytes = self.descriptor(slot, STRING_DESCRIPTOR, index, 255).ok()?;
        if bytes.len() < 2 || bytes[1] != STRING_DESCRIPTOR {
            return None;
        }
        let units: Vec<u16> = bytes[2..usize::from(bytes[0]).min(bytes.len())]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let text: String = char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
        Some(String::from(text.trim()))
    }

    /// Adds `endpoints` to `slot` (Configure Endpoint, 4.6.6), with the hub
    /// fields when `hub` is `Some((ports, think_time, multi_tt))`.
    pub fn configure(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        hub: Option<(u8, u8, bool)>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.ready()?;
        for endpoint in endpoints {
            if self.slot(slot)?.endpoints[usize::from(endpoint.dci())]
                .as_ref()
                .is_some_and(|endpoint| endpoint.poisoned)
            {
                return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
            }
        }
        self.clear_input(slot)?;
        let context = self.context();
        let speed = self.slot(slot)?.speed;
        let mut add = 1u32;
        let mut last = 1u8;
        for endpoint in endpoints {
            let dci = endpoint.dci();
            let ring = Ring::new(dma)?;
            let kind = match (endpoint.kind(), endpoint.is_in()) {
                (2, false) => 2,
                (3, false) => 3,
                (2, true) => 6,
                (3, true) => 7,
                _ => return Err(BlockError::Unsupported("isochronous or control endpoint")),
            };
            let max_packet = u32::from(endpoint.max_packet & 0x7ff);
            let burst = u32::from(endpoint.max_packet >> 11 & 3);
            let interval = match (endpoint.kind(), speed) {
                (3, HIGH_SPEED | SUPER_SPEED) => u32::from(endpoint.interval.clamp(1, 16) - 1),
                (3, _) => {
                    // Frames to a 2^n microframe exponent, 3..=10 (6.2.3.6).
                    let microframes = u32::from(endpoint.interval.max(1)) * 8;
                    (31 - microframes.leading_zeros()).clamp(3, 10)
                }
                _ => 0,
            };
            let payload = max_packet * (burst + 1);
            let average = if endpoint.kind() == 3 { payload } else { 3072 };
            let state = self.slot(slot)?;
            let at = (usize::from(dci) + 1) * context;
            state.input.write(at, interval << 16);
            state
                .input
                .write(at + 4, 3 << 1 | kind << 3 | burst << 8 | max_packet << 16);
            state.input.write(at + 8, ring.dequeue_pointer());
            state
                .input
                .write(at + 16, average | (payload & 0xffff) << 16);
            state.endpoints[usize::from(dci)] = Some(Transfer {
                ring,
                is_in: endpoint.is_in(),
                poisoned: false,
            });
            add |= 1 << dci;
            last = last.max(dci);
        }
        let input_address = {
            let state = self.slot(slot)?;
            let mut words = state.context;
            let entries = (words[0] >> 27).max(u32::from(last));
            words[0] = words[0] & !(0x1f << 27) | entries << 27;
            if let Some((ports, think_time, multi)) = hub {
                words[0] |= 1 << 26 | u32::from(multi) << 25;
                words[1] = words[1] & 0x00ff_ffff | u32::from(ports) << 24;
                words[2] = words[2] & !(3 << 16) | u32::from(think_time & 3) << 16;
            }
            state.context = words;
            state.input.write(4, add);
            for (n, word) in words.iter().enumerate() {
                state.input.write(context + 4 * n, *word);
            }
            state.input.physical()
        };
        self.command(
            input_address,
            0,
            CONFIGURE_ENDPOINT << 10 | u32::from(slot) << 24,
        )?;
        Ok(())
    }

    /// Queues one TD of `length` bytes at `buffer` on endpoint `dci` and
    /// rings its doorbell; the TRB's address names its completion.
    pub fn submit(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
    ) -> Result<u64, BlockError> {
        self.endpoint_ready(slot, dci)?;
        if length > MAX_TD || (buffer % MAX_TD as u64) as usize + length > MAX_TD {
            return Err(BlockError::Unsupported("TD crosses a 64 KiB boundary"));
        }
        let address = {
            let state = self.slot(slot)?;
            let transfer = state.endpoints[usize::from(dci)]
                .as_mut()
                .ok_or(BlockError::Unsupported("xHCI endpoint not configured"))?;
            if transfer.poisoned {
                return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
            }
            let direction = if transfer.is_in { ISP } else { 0 };
            transfer
                .ring
                .push(&[(buffer, length as u32, NORMAL << 10 | IOC | direction)])[0]
        };
        self.doorbell(slot, dci);
        Ok(address)
    }

    /// The completion of the TD at `trb` once it has one: the bytes moved,
    /// or the failure. A STALL leaves the endpoint halted for [`clear`].
    pub fn completed(
        &mut self,
        slot: u8,
        dci: u8,
        trb: u64,
        length: usize,
    ) -> Option<Result<usize, BlockError>> {
        if let Err(error) = self.endpoint_ready(slot, dci) {
            return Some(Err(error));
        }
        let event = self.take(|e| {
            e.kind() == TRANSFER_EVENT
                && e.slot() == slot
                && e.endpoint() == dci
                && e.parameter == trb
        });
        let Some(event) = event else {
            return self.error.map(|status| Err(BlockError::Device { status }));
        };
        Some(match event.code() {
            SUCCESS | SHORT_PACKET => Ok(length.saturating_sub(event.residual())),
            status => Err(BlockError::Device { status }),
        })
    }

    /// One TD, waited for.
    pub fn transfer(
        &mut self,
        slot: u8,
        dci: u8,
        buffer: u64,
        length: usize,
        microseconds: u64,
    ) -> Result<usize, BlockError> {
        let trb = self.submit(slot, dci, buffer, length)?;
        let deadline = self.clock.deadline(microseconds);
        loop {
            if let Some(result) = self.completed(slot, dci, trb, length) {
                return result;
            }
            if deadline.passed() {
                self.cancel(slot, dci)?;
                return Err(BlockError::Timeout);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Current connection of the slot's root port. Downstream hub-port loss
    /// is reported by transfer errors; hotplug enumeration is not performed.
    pub fn connected(&mut self, slot: u8) -> Result<bool, BlockError> {
        self.ready()?;
        let port = (self.slot(slot)?.context[1] >> 16 & 0xff) as u8;
        if port == 0 || port > self.max_ports {
            return Err(BlockError::Unsupported("xHCI invalid slot root port"));
        }
        let at = self.port_offset(port);
        Ok(self.registers.read32(at) & CCS != 0)
    }

    /// Abandons every outstanding TD on one exclusively owned
    /// endpoint. Running endpoints are stopped, halted endpoints reset, then
    /// Set TR Dequeue moves past the abandoned TDs (xHCI 1.2 4.6.9/4.6.10).
    /// Success acknowledges that their buffers are no longer hardware-owned.
    /// Failure permanently poisons submission to this endpoint: callers must
    /// retain the buffers and must not read, rewrite or recycle them. Device
    /// disconnect alone is not proof that controller DMA has stopped.
    pub fn cancel(&mut self, slot: u8, dci: u8) -> Result<(), BlockError> {
        if !(1..32).contains(&dci) {
            return Err(BlockError::Unsupported("cancel requires a valid endpoint"));
        }
        let context = self.context();
        let endpoint = self.slot(slot)?.endpoints[usize::from(dci)]
            .as_mut()
            .ok_or(BlockError::Unsupported("xHCI endpoint not configured"))?;
        if endpoint.poisoned {
            return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
        }
        // Set before issuing any command, so every error path retains poison.
        endpoint.poisoned = true;
        let pointer = endpoint.ring.dequeue_pointer();
        let target = u32::from(slot) << 24 | u32::from(dci) << 16;
        let state = |controller: &mut Self| -> Result<u32, BlockError> {
            fence(Ordering::Acquire);
            Ok(controller
                .slot(slot)?
                ._output
                .read::<u32>(usize::from(dci) * context)
                & 7)
        };
        let mut current = state(self)?;
        if current == ENDPOINT_RUNNING {
            // Running, including a ring whose TD just completed.
            match self.command(0, 0, STOP_ENDPOINT << 10 | target) {
                Ok(_) => {}
                // A STALL can race Stop Endpoint. Recheck the hardware state;
                // never treat an arbitrary Context State Error as acknowledgment.
                Err(BlockError::Device {
                    status: CONTEXT_STATE_ERROR,
                }) => {}
                Err(error) => return Err(error),
            }
            current = state(self)?;
        }
        if current == ENDPOINT_HALTED {
            // Halted.
            self.command(0, 0, RESET_ENDPOINT << 10 | target)?;
            current = state(self)?;
        }
        if current != ENDPOINT_STOPPED {
            // Stopped is the only state in which dequeue is legal.
            return Err(BlockError::Unsupported("xHCI endpoint did not stop"));
        }
        self.command(pointer, 0, SET_DEQUEUE << 10 | target)?;
        // Stop/Set Dequeue completion acknowledges abandonment. Drain also takes
        // stale transfer events posted while those commands were executing.
        self.drain();
        self.pending.retain(|event| {
            !(event.kind() == TRANSFER_EVENT && event.slot() == slot && event.endpoint() == dci)
        });
        self.slot(slot)?.endpoints[usize::from(dci)]
            .as_mut()
            .unwrap()
            .poisoned = false;
        Ok(())
    }

    /// Clears a halted bulk or interrupt endpoint on both sides.
    pub fn clear(&mut self, slot: u8, endpoint: &Endpoint) -> Result<(), BlockError> {
        self.recover(slot, endpoint.dci())?;
        let request = setup(0x02, CLEAR_FEATURE, 0, u16::from(endpoint.address), 0);
        self.control(slot, request, &[])?;
        Ok(())
    }

    /// Every device on the root ports and behind their USB 2.0 hubs; a
    /// device that fails to enumerate is reported and skipped.
    pub fn enumerate(
        &mut self,
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Vec<Device> {
        let mut devices = Vec::new();
        for port in 1..=self.max_ports {
            let location = format!("{} port {port}", self.location);
            crate::working(&location);
            match self.root_port(port) {
                Ok(Some(speed)) => {
                    let attachment = Attachment {
                        root_port: port,
                        route: 0,
                        tier: 0,
                        speed,
                        translator: None,
                    };
                    self.attach(attachment, location, dma, &mut devices, failures);
                }
                Ok(None) => {}
                Err(error) => failures.push((format!("{location} enable/reset root port"), error)),
            }
        }
        devices
    }

    /// A root port's device speed once the port is enabled, or `None` with
    /// nothing connected.
    fn root_port(&mut self, port: u8) -> Result<Option<u8>, BlockError> {
        let at = self.port_offset(port);
        if self.registers.read32(at) & PP == 0 {
            self.write_port(port, PP);
            self.clock.delay(20_000);
        }
        let portsc = self.registers.read32(at);
        if portsc & CCS == 0 {
            return Ok(None);
        }
        // Clear the connect change, so later changes are this driver's.
        self.write_port(port, portsc & PORT_CHANGES);
        if self.port_major[usize::from(port - 1)] != 3 {
            self.write_port(port, PR);
            let clock = self.clock;
            if !wait(&mut *self.registers, clock, PORT_RESET_US, |r| {
                r.read32(at) & PRC != 0
            }) {
                return Err(BlockError::Timeout);
            }
            self.write_port(port, PRC);
            self.clock.delay(RESET_RECOVERY_US);
        } else {
            let clock = self.clock;
            if !wait(&mut *self.registers, clock, PORT_RESET_US, |r| {
                r.read32(at) & PED != 0
            }) {
                return Err(BlockError::Timeout);
            }
        }
        let portsc = self.registers.read32(at);
        if portsc & PED == 0 {
            return Err(BlockError::Unsupported("root port did not enable"));
        }
        Ok(Some((portsc >> 10 & 0xf) as u8))
    }

    fn attach(
        &mut self,
        attachment: Attachment,
        location: String,
        dma: &mut dyn DmaAllocator,
        devices: &mut Vec<Device>,
        failures: &mut Vec<(String, BlockError)>,
    ) {
        match self.identify(attachment, location.clone(), dma) {
            Ok(device) if device.descriptor[4] == HUB_CLASS => {
                if let Err(error) = self.hub(&device, attachment, dma, devices, failures) {
                    failures.push((format!("{location} {} enumerate hub", device.name()), error));
                }
            }
            Ok(device) => devices.push(device),
            Err((operation, error)) => {
                let at = self.port_offset(attachment.root_port);
                let portsc = self.registers.read32(at);
                failures.push((
                    format!(
                        "{location} speed={} root-portsc={portsc:#010x} {operation}",
                        attachment.speed
                    ),
                    error,
                ));
            }
        }
    }

    fn identify(
        &mut self,
        attachment: Attachment,
        location: String,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Device, (String, BlockError)> {
        let slot = self.address(attachment, dma)?;
        let first = self.enumeration_descriptor(slot, DEVICE_DESCRIPTOR, 0, 8)?;
        if first.len() < 8 {
            return during(
                format!("slot {slot} device descriptor header"),
                Err(BlockError::Unsupported("short device descriptor")),
            );
        }
        let ep0 = u16::from(first[7]);
        let expected = match attachment.speed {
            LOW_SPEED | FULL_SPEED => 8,
            HIGH_SPEED => 64,
            _ => 512,
        };
        if attachment.speed == FULL_SPEED && ep0 != expected && [8, 16, 32, 64].contains(&ep0) {
            during(
                format!("slot {slot} Evaluate Context EP0 max_packet={ep0}"),
                self.set_control_packet(slot, ep0),
            )?;
        }
        let bytes = self.enumeration_descriptor(slot, DEVICE_DESCRIPTOR, 0, 18)?;
        let descriptor: [u8; 18] = during(
            format!("slot {slot} full device descriptor"),
            bytes
                .get(..18)
                .and_then(|b| b.try_into().ok())
                .ok_or(BlockError::Unsupported("short device descriptor")),
        )?;
        let identity = format!(
            "{:04x}:{:04x}",
            u16::from_le_bytes([descriptor[8], descriptor[9]]),
            u16::from_le_bytes([descriptor[10], descriptor[11]])
        );
        // The USB core's choice (Linux `usb_choose_configuration`): the first
        // configuration whose first interface has a standard class, so an
        // adapter that also offers CDC Ethernet after its vendor-specific
        // configuration (as Realtek RTL8153 adapters do) is used through it.
        let mut chosen = None;
        for index in 0..descriptor[17].max(1) {
            let configuration = self
                .configuration(slot, index)
                .map_err(|(operation, error)| (format!("{identity} {operation}"), error))?;
            if standard_class(&configuration) {
                chosen = Some(configuration);
                break;
            }
            chosen.get_or_insert(configuration);
        }
        let configuration = chosen.expect("at least one configuration is read");
        let manufacturer = self.string(slot, descriptor[14]);
        let product = self.string(slot, descriptor[15]);
        let serial = self.string(slot, descriptor[16]);
        Ok(Device {
            slot,
            speed: attachment.speed,
            location,
            descriptor,
            configuration,
            manufacturer,
            product,
            serial,
        })
    }

    /// Configuration descriptor `index`, whole.
    fn configuration(&mut self, slot: u8, index: u8) -> Result<Vec<u8>, (String, BlockError)> {
        let head = self.enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, index, 9)?;
        if head.len() < 9 {
            return during(
                format!("slot {slot} configuration {index} header"),
                Err(BlockError::Unsupported("short configuration descriptor")),
            );
        }
        let total = u16::from_le_bytes([head[2], head[3]]).min(CONTROL_BYTES as u16);
        self.enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, index, total)
    }

    fn enumeration_descriptor(
        &mut self,
        slot: u8,
        kind: u8,
        index: u8,
        length: u16,
    ) -> Result<Vec<u8>, (String, BlockError)> {
        during(
            format!("slot {slot} EP0 GET_DESCRIPTOR type={kind} index={index} length={length}"),
            self.descriptor(slot, kind, index, length),
        )
    }

    fn hub(
        &mut self,
        device: &Device,
        attachment: Attachment,
        dma: &mut dyn DmaAllocator,
        devices: &mut Vec<Device>,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<(), BlockError> {
        if attachment.speed == SUPER_SPEED {
            return Err(BlockError::Unsupported("SuperSpeed hubs"));
        }
        if attachment.tier + 1 > MAX_TIERS {
            return Err(BlockError::Unsupported("hub more than five tiers deep"));
        }
        let slot = device.slot;
        let hub = self.control(
            slot,
            setup(0xa0, GET_DESCRIPTOR, u16::from(HUB_DESCRIPTOR) << 8, 0, 9),
            &[],
        )?;
        if hub.len() < 7 || hub[1] != HUB_DESCRIPTOR {
            return Err(BlockError::Unsupported("hub descriptor"));
        }
        let ports = hub[2].min(15);
        let characteristics = u16::from_le_bytes([hub[3], hub[4]]);
        let power_good_us = u64::from(hub[5]) * 2000;
        // A multi-TT hub reports protocol 2 on its interface (11.23.1).
        let multi = interfaces(&device.configuration)
            .iter()
            .any(|interface| interface.class == HUB_CLASS && interface.protocol == 2);
        let think_time = (characteristics >> 5 & 3) as u8;
        let status = interfaces(&device.configuration)
            .into_iter()
            .find(|interface| interface.class == HUB_CLASS && interface.alternate == 0)
            .and_then(|interface| interface.endpoints.first().copied());
        let endpoints: Vec<Endpoint> = status.into_iter().collect();
        let tt_think = if attachment.speed == HIGH_SPEED {
            think_time
        } else {
            0
        };
        self.configure(slot, &endpoints, Some((ports, tt_think, multi)), dma)?;
        self.control(
            slot,
            setup(
                0,
                SET_CONFIGURATION,
                u16::from(device.configuration_value()),
                0,
                0,
            ),
            &[],
        )?;
        for port in 1..=ports {
            self.control(
                slot,
                setup(0x23, SET_FEATURE, PORT_POWER, u16::from(port), 0),
                &[],
            )?;
        }
        self.clock.delay(power_good_us.max(20_000));
        for port in 1..=ports {
            let location = format!("{}.{port}", device.location);
            crate::working(&location);
            match self.hub_port(slot, port) {
                Ok(Some(speed)) => {
                    let translator = match (speed, attachment.speed) {
                        (LOW_SPEED | FULL_SPEED, HIGH_SPEED) => Some((slot, port)),
                        _ => attachment.translator,
                    };
                    let child = Attachment {
                        root_port: attachment.root_port,
                        route: attachment.route | u32::from(port) << (4 * attachment.tier),
                        tier: attachment.tier + 1,
                        speed,
                        translator,
                    };
                    self.attach(child, location, dma, devices, failures);
                }
                Ok(None) => {}
                Err(error) => failures.push((location, error)),
            }
        }
        Ok(())
    }

    fn hub_port_status(&mut self, slot: u8, port: u8) -> Result<(u16, u16), BlockError> {
        let status = self.control(slot, setup(0xa3, GET_STATUS, 0, u16::from(port), 4), &[])?;
        if status.len() < 4 {
            return Err(BlockError::Unsupported("short hub port status"));
        }
        Ok((
            u16::from_le_bytes([status[0], status[1]]),
            u16::from_le_bytes([status[2], status[3]]),
        ))
    }

    /// A hub port's device speed once the port is reset and enabled.
    fn hub_port(&mut self, slot: u8, port: u8) -> Result<Option<u8>, BlockError> {
        let (status, _) = self.hub_port_status(slot, port)?;
        if status & 1 == 0 {
            return Ok(None);
        }
        let index = u16::from(port);
        self.control(
            slot,
            setup(0x23, CLEAR_FEATURE, C_PORT_CONNECTION, index, 0),
            &[],
        )?;
        self.control(slot, setup(0x23, SET_FEATURE, PORT_RESET, index, 0), &[])?;
        let deadline = self.clock.deadline(PORT_RESET_US);
        let status = loop {
            let (status, change) = self.hub_port_status(slot, port)?;
            if change & 1 << 4 != 0 && status & 1 << 4 == 0 {
                break status;
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            self.clock.delay(1000);
        };
        self.control(
            slot,
            setup(0x23, CLEAR_FEATURE, C_PORT_RESET, index, 0),
            &[],
        )?;
        self.clock.delay(RESET_RECOVERY_US);
        if status & 1 << 1 == 0 {
            return Err(BlockError::Unsupported("hub port did not enable"));
        }
        Ok(Some(if status & 1 << 9 != 0 {
            LOW_SPEED
        } else if status & 1 << 10 != 0 {
            HIGH_SPEED
        } else {
            FULL_SPEED
        }))
    }
}

/// Polls `ready` against the registers until it holds or time runs out.
fn wait(
    registers: &mut dyn Registers,
    clock: Clock,
    microseconds: u64,
    mut ready: impl FnMut(&mut dyn Registers) -> bool,
) -> bool {
    clock.wait(microseconds, || ready(registers))
}

/// The BIOS handoff (7.1.1): the OS Owned semaphore, then the SMIs off.
/// Firmware that never lets go loses ownership anyway, as other operating
/// systems do; its SMIs are disabled either way.
fn take_from_firmware(registers: &mut dyn Registers, at: usize, clock: Clock) {
    let header = registers.read32(at);
    registers.write32(at, header | OS_OWNED);
    if !wait(registers, clock, BIOS_HANDOFF_US, |r| {
        r.read32(at) & BIOS_OWNED == 0
    }) {
        let header = registers.read32(at);
        registers.write32(at, header & !BIOS_OWNED | OS_OWNED);
    }
    let control = registers.read32(at + 4);
    registers.write32(at + 4, control & !LEGACY_SMI_ENABLES | LEGACY_SMI_STATUS);
}

/// What the class drivers found on one controller.
#[derive(Default)]
pub struct Found {
    pub disks: Vec<storage::UsbDisk>,
    pub inputs: Vec<hid::UsbInput>,
    pub links: Vec<cdc::UsbNet>,
    /// Raw physical HCI transports; vendor firmware initialization is unverified.
    pub bluetooth: Vec<bluetooth::UsbHci>,
    /// Devices or interfaces no driver here takes, and why.
    pub unused: Vec<(String, &'static str)>,
    pub failures: Vec<(String, BlockError)>,
}

/// Starts the controller at `function`, enumerates its devices and binds
/// the class drivers.
pub fn attach(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Found, BlockError> {
    let bars = function.bars();
    // The capability, operational, runtime and doorbell registers all lie
    // in BAR 0, whatever its size (5.2.1): QEMU's is 16 KiB, a PC's 64 KiB
    // or more.
    let bytes = bars[0]
        .and_then(|bar| bar.memory())
        .map_or(0, |range| range.end - range.start);
    let registers = registers(handoff, bars[0], 0, bytes)?;
    function.enable();
    let address = function.address;
    let location = format!(
        "xhci {:04x}:{:02x}:{:02x}.{}",
        address.segment, address.bus, address.device, address.function
    );
    start(Box::new(registers), handoff.clock, dma, location)
}

/// Starts the controller behind `registers`, enumerates its devices and
/// binds the class drivers.
pub fn start(
    registers: Box<dyn Registers>,
    clock: Clock,
    dma: &mut dyn DmaAllocator,
    location: String,
) -> Result<Found, BlockError> {
    let mut controller = Controller::new(registers, clock, dma, location)?;
    let mut found = Found::default();
    let devices = controller.enumerate(dma, &mut found.failures);
    let shared: Shared = Rc::new(RefCell::new(controller));
    for device in devices {
        bind(&shared, device, dma, &mut found);
    }
    Ok(found)
}

/// Binds every interface of `device` a driver here takes: one
/// configuration, its endpoints configured together.
fn bind(shared: &Shared, device: Device, dma: &mut dyn DmaAllocator, found: &mut Found) {
    let all = interfaces(&device.configuration);
    let mut endpoints = Vec::new();
    let mut plans = Vec::new();
    // CDC data interfaces belong to their communications interface.
    for interface in all.iter().filter(|i| i.alternate == 0 && i.class != 10) {
        let plan = if interface.class == storage::CLASS {
            storage::plan(interface)
        } else if interface.class == hid::CLASS {
            hid::plan(interface)
        } else if interface.class == cdc::COMMUNICATIONS {
            cdc::plan(interface, &all)
        } else if interface.class == bluetooth::CLASS {
            bluetooth::Binding::new(&device, interface).map(Plan::Bluetooth)
        } else {
            Err("no class driver for this interface")
        };
        match plan {
            Ok(plan) => {
                endpoints.extend(plan.endpoints().iter().copied());
                plans.push((interface.clone(), plan));
            }
            Err(why) => found.unused.push((
                format!(
                    "{} interface {} ({:02x}/{:02x}/{:02x})",
                    device.location,
                    interface.number,
                    interface.class,
                    interface.subclass,
                    interface.protocol
                ),
                why,
            )),
        }
    }
    if plans.is_empty() {
        return;
    }
    let configured = {
        let mut controller = shared.borrow_mut();
        during(
            format!("slot {} Configure Endpoint", device.slot),
            controller.configure(device.slot, &endpoints, None, dma),
        )
        .and_then(|()| {
            let value = u16::from(device.configuration_value());
            during(
                format!("slot {} EP0 SET_CONFIGURATION value={value}", device.slot),
                controller.control(device.slot, setup(0, SET_CONFIGURATION, value, 0, 0), &[]),
            )
            .map(|_| ())
        })
    };
    if let Err((operation, error)) = configured {
        found.failures.push((
            format!("{} {} {operation}", device.location, device.name()),
            error,
        ));
        return;
    }
    for (interface, plan) in plans {
        let location = format!("{} interface {}", device.location, interface.number);
        crate::working(&location);
        let result = match plan {
            Plan::Storage(endpoints) => {
                storage::UsbDisk::new(shared.clone(), &device, &interface, endpoints, dma)
                    .map(|disk| found.disks.push(disk))
            }
            Plan::Hid(endpoint) => {
                hid::UsbInput::new(shared.clone(), &device, &interface, endpoint, dma).map(
                    |input| match input {
                        Some(input) => found.inputs.push(input),
                        None => found.unused.push((location.clone(), hid::NO_REPORTS)),
                    },
                )
            }
            Plan::Ethernet(plan) => cdc::UsbNet::new(shared.clone(), &device, plan, dma)
                .map(|link| found.links.push(link)),
            Plan::Bluetooth(binding) => {
                bluetooth::UsbHci::attach(shared.clone(), &device, binding, dma)
                    .map(|transport| found.bluetooth.push(transport))
            }
        };
        if let Err(error) = result {
            found.failures.push((location, error));
        }
    }
}

/// What a class driver will use of an interface.
pub enum Plan {
    /// Bulk IN, bulk OUT.
    Storage([Endpoint; 2]),
    /// The interrupt IN endpoint.
    Hid(Endpoint),
    /// A CDC Ethernet adapter's interfaces and endpoints.
    Ethernet(cdc::Binding),
    /// Legacy Bluetooth HCI interrupt and bulk endpoints.
    Bluetooth(bluetooth::Binding),
}

impl Plan {
    fn endpoints(&self) -> Vec<Endpoint> {
        match self {
            Self::Storage(endpoints) => endpoints.to_vec(),
            Self::Hid(endpoint) => vec![*endpoint],
            Self::Ethernet(binding) => binding.endpoints(),
            Self::Bluetooth(binding) => binding.endpoints(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::vec::Vec;

    /// A command/event DMA model with a device that needs the full
    /// SET_ADDRESS recovery interval before accepting its first Setup.
    struct AddressModel {
        commands: u64,
        command_index: usize,
        events: u64,
        event_index: usize,
        control_ring: u64,
        dcbaa: u64,
        output: u64,
        ready_at: u64,
        recovery_ticks: u64,
        address_code: u32,
        commands_seen: Vec<u32>,
        setup_seen: Vec<[u8; 8]>,
        early_setup: bool,
    }

    impl AddressModel {
        fn event(&mut self, parameter: u64, code: u32, kind: u32, endpoint: u8) {
            let address = self.events + (self.event_index * TRB) as u64;
            // SAFETY: these are aligned DMA words in the test's backing
            // allocation, which outlives the controller and this model.
            unsafe {
                (address as *mut u64).write_volatile(parameter);
                ((address + 8) as *mut u32).write_volatile(code << 24);
                ((address + 12) as *mut u32)
                    .write_volatile(1 << 24 | u32::from(endpoint) << 16 | kind << 10 | CYCLE);
            }
            self.event_index += 1;
        }
    }

    struct AddressRegisters(Rc<RefCell<AddressModel>>);

    impl Registers for AddressRegisters {
        fn read32(&mut self, _offset: usize) -> u32 {
            0
        }

        fn write32(&mut self, offset: usize, _value: u32) {
            let mut model = self.0.borrow_mut();
            if offset == 0x1000 {
                let address = model.commands + (model.command_index * TRB) as u64;
                // SAFETY: the command ring and the input context named by
                // Address Device belong to the live test DMA allocation.
                let (parameter, kind) = unsafe {
                    (
                        (address as *const u64).read_volatile(),
                        ((address + 12) as *const u32).read_volatile() >> 10 & 0x3f,
                    )
                };
                model.command_index += 1;
                model.commands_seen.push(kind);
                let code = if kind == ADDRESS_DEVICE {
                    // SAFETY: the live DCBAA slot points to the output context
                    // allocated by address() before publishing this command.
                    model.output = unsafe { ((model.dcbaa + 8) as *const u64).read_volatile() };
                    // SAFETY: EP0's dequeue pointer in the 32-byte input
                    // context points to this test controller's control ring.
                    model.control_ring =
                        unsafe { ((parameter + 2 * 32 + 8) as *const u64).read_volatile() & !0xf };
                    model.ready_at = Clock::ticks() + model.recovery_ticks;
                    model.address_code
                } else {
                    if matches!(kind, RESET_ENDPOINT | STOP_ENDPOINT) {
                        // SAFETY: EP0 state in the live 32-byte output context.
                        unsafe {
                            ((model.output + 32) as *mut u32).write_volatile(ENDPOINT_STOPPED);
                        }
                    }
                    if kind == SET_DEQUEUE {
                        model.control_ring = parameter & !0xf;
                    }
                    SUCCESS
                };
                model.event(address, code, COMMAND_COMPLETION, 0);
            } else if offset == 0x1004 {
                // This model runs one GET_DESCRIPTOR with Setup/Data/Status.
                let ring = model.control_ring;
                // SAFETY: the ring is initialized by control() before its
                // doorbell, in the test's still-live DMA allocation.
                let request = unsafe { (ring as *const u64).read_volatile().to_le_bytes() };
                model.setup_seen.push(request);
                model.early_setup = Clock::ticks() < model.ready_at;
                let (parameter, code) = if model.early_setup {
                    // SAFETY: failed transfer halts EP0 in the live context.
                    unsafe {
                        ((model.output + 32) as *mut u32).write_volatile(ENDPOINT_HALTED);
                    }
                    (ring, 4)
                } else {
                    (ring + 2 * TRB as u64, SUCCESS)
                };
                model.event(parameter, code, TRANSFER_EVENT, 1);
            }
        }
    }

    fn address_controller(
        dma: &mut dyn DmaAllocator,
        address_code: u32,
    ) -> (Controller, Rc<RefCell<AddressModel>>) {
        let commands = Ring::new(dma).unwrap();
        let events = dma.allocate(RING_TRBS * TRB, 64).unwrap();
        let clock = Clock {
            ticks_per_microsecond: 1_000,
        };
        let model = Rc::new(RefCell::new(AddressModel {
            commands: commands.buffer.physical(),
            command_index: 0,
            events: events.physical(),
            event_index: 0,
            control_ring: 0,
            dcbaa: 0,
            output: 0,
            ready_at: 0,
            recovery_ticks: ADDRESS_RECOVERY_US * clock.ticks_per_microsecond,
            address_code,
            commands_seen: Vec::new(),
            setup_seen: Vec::new(),
            early_setup: false,
        }));
        let controller = Controller {
            registers: Box::new(AddressRegisters(model.clone())),
            clock,
            operational: 0x40,
            runtime: 0x800,
            doorbells: 0x1000,
            context_bytes: 32,
            wide: true,
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
            slots: vec![None, None],
            pending: Vec::new(),
            error: None,
            command_poisoned: false,
            location: String::from("test xhci"),
        };
        model.borrow_mut().dcbaa = controller.dcbaa.physical();
        (controller, model)
    }

    #[test]
    fn the_first_setup_waits_for_set_address_recovery() {
        let mut backing = vec![0u64; 16 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the controller and all its DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + 128 * 1024) };
        let (mut controller, model) = address_controller(&mut dma, SUCCESS);
        let attachment = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: FULL_SPEED,
            translator: None,
        };
        let slot = controller.address(attachment, &mut dma).unwrap();
        let request = setup(
            0x80,
            GET_DESCRIPTOR,
            u16::from(DEVICE_DESCRIPTOR) << 8,
            0,
            8,
        );
        assert_eq!(controller.control(slot, request, &[]).unwrap().len(), 8);
        let state = model.borrow();
        assert_eq!(state.commands_seen, [ENABLE_SLOT, ADDRESS_DEVICE]);
        assert_eq!(state.setup_seen, [request]);
        assert!(!state.early_setup);
    }

    #[test]
    fn an_address_device_error_does_not_issue_a_setup() {
        let mut backing = vec![0u64; 16 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the controller and all its DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + 128 * 1024) };
        let (mut controller, model) = address_controller(&mut dma, 4);
        let attachment = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: FULL_SPEED,
            translator: None,
        };
        assert_eq!(
            controller
                .identify(attachment, String::from("port 1"), &mut dma)
                .unwrap_err(),
            (
                String::from("slot 1 Address Device"),
                BlockError::Device { status: 4 }
            )
        );
        let state = model.borrow();
        assert_eq!(state.commands_seen, [ENABLE_SLOT, ADDRESS_DEVICE]);
        assert!(state.setup_seen.is_empty());
    }

    #[test]
    fn descriptor_failure_retains_the_request_and_completion_code() {
        let mut backing = vec![0u64; 16 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the controller and all its DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + 128 * 1024) };
        let (mut controller, model) = address_controller(&mut dma, SUCCESS);
        let attachment = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: FULL_SPEED,
            translator: None,
        };
        let slot = controller.address(attachment, &mut dma).unwrap();
        // Model a descriptor transfer failing after successful addressing.
        model.borrow_mut().ready_at = u64::MAX;
        assert_eq!(
            controller
                .enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, 2, 9)
                .unwrap_err(),
            (
                String::from("slot 1 EP0 GET_DESCRIPTOR type=2 index=2 length=9"),
                BlockError::Device { status: 4 }
            )
        );
        let state = model.borrow();
        assert_eq!(
            state.setup_seen,
            [setup(0x80, GET_DESCRIPTOR, 0x0202, 0, 9)]
        );
        assert_eq!(
            state.commands_seen,
            [ENABLE_SLOT, ADDRESS_DEVICE, RESET_ENDPOINT, SET_DEQUEUE]
        );
    }

    #[test]
    fn completion_codes_are_named() {
        assert_eq!(
            explain(&BlockError::Device { status: 4 }),
            "USB transaction error (xHCI completion code 4)"
        );
        assert_eq!(
            explain(&BlockError::Device { status: 99 }),
            "error (xHCI completion code 99)"
        );
        assert_eq!(explain(&BlockError::Timeout), "device timeout");
    }

    #[test]
    fn configuration_descriptors_split_into_interfaces_with_their_endpoints() {
        let configuration = [
            9, 2, 32, 0, 1, 1, 0, 0x80, 50, // configuration
            9, 4, 0, 0, 2, 8, 6, 0x50, 0, // interface
            7, 5, 0x81, 2, 0, 2, 0, // bulk in
            7, 5, 0x02, 2, 0, 2, 0, // bulk out
        ];
        let found = interfaces(&configuration);
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].class, found[0].subclass, found[0].protocol),
            (8, 6, 0x50)
        );
        assert_eq!(found[0].endpoints[0].dci(), 3);
        assert_eq!(found[0].endpoints[1].dci(), 4);
        assert_eq!(found[0].endpoints[0].max_packet, 512);
    }

    #[test]
    fn a_vendor_specific_configuration_is_passed_over() {
        let vendor = [
            9, 2, 18, 0, 1, 1, 0, 0x80, 50, // configuration 1
            9, 4, 0, 0, 0, 0xff, 0xff, 0, 0, // vendor interface
        ];
        let ecm = [
            9, 2, 18, 0, 2, 2, 0, 0x80, 50, // configuration 2
            9, 4, 0, 0, 1, 2, 6, 0, 0, // CDC ECM communications interface
        ];
        assert!(!standard_class(&vendor));
        assert!(standard_class(&ecm));
        assert!(!standard_class(&vendor[..9]));
    }

    #[test]
    fn a_ring_wraps_through_its_link_trb_with_the_cycle_toggled() {
        let mut backing: Vec<u64> = vec![0; 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the vector outlives the allocator.
        let mut dma = unsafe { RegionAllocator::new(start..start + 8192) };
        let mut ring = Ring::new(&mut dma).unwrap();
        for _ in 0..RING_TRBS - 2 {
            ring.push(&[(0, 0, NORMAL << 10)]);
        }
        assert!(ring.cycle);
        let addresses = ring.push(&[(1, 0, NORMAL << 10), (2, 0, NORMAL << 10)]);
        assert_eq!(addresses[1], ring.buffer.physical());
        assert!(!ring.cycle);
        let link: u32 = ring.buffer.read((RING_TRBS - 1) * TRB + 12);
        assert_eq!(link, LINK << 10 | TOGGLE | CYCLE);
        let first: u32 = ring.buffer.read((RING_TRBS - 2) * TRB + 12);
        assert_eq!(first & CYCLE, CYCLE);
        let wrapped: u32 = ring.buffer.read(12);
        assert_eq!(wrapped & CYCLE, 0);
    }

    /// Hardware model enforces the endpoint state restrictions absent from the
    /// old address model: Stop accepts Running, Reset accepts Halted, Set Dequeue
    /// accepts Stopped. It can leave DMA active on command failure.
    struct CancelModel {
        commands: u64,
        command_index: usize,
        events: u64,
        event_index: usize,
        output: u64,
        rings: [u64; 32],
        indices: [usize; 32],
        active: [Option<(u64, u64, usize)>; 32],
        connected: bool,
        fail: Option<(u32, u32)>,
        silence: Option<u32>,
        race_halt: bool,
        stale: Option<u64>,
        seen: Vec<u32>,
        dequeues: Vec<u64>,
        setup: Vec<([u8; 8], Vec<u8>)>,
        incoming_events: alloc::collections::VecDeque<Vec<u8>>,
        incoming_acl: alloc::collections::VecDeque<Vec<u8>>,
        outgoing: Vec<Vec<u8>>,
        fatal_status: u32,
        fatal_on_command: Option<u32>,
        silence_transfer: Option<usize>,
        halt_transfer: Option<usize>,
    }
    impl CancelModel {
        fn state(&self, dci: usize) -> u32 {
            // SAFETY: output context is live aligned test DMA, exclusively
            // accessed by this model between controller operations.
            unsafe { ((self.output + dci as u64 * 32) as *const u32).read_volatile() & 7 }
        }
        fn set_state(&mut self, dci: usize, state: u32) {
            // SAFETY: same live context as state().
            unsafe {
                ((self.output + dci as u64 * 32) as *mut u32).write_volatile(state);
            }
        }
        fn event(&mut self, parameter: u64, code: u32, kind: u32, dci: u8, residual: usize) {
            let address = self.events + (self.event_index * TRB) as u64;
            // SAFETY: all three fields are in the still-live test event ring.
            unsafe {
                (address as *mut u64).write_volatile(parameter);
                ((address + 8) as *mut u32).write_volatile(code << 24 | residual as u32);
                ((address + 12) as *mut u32)
                    .write_volatile(1 << 24 | u32::from(dci) << 16 | kind << 10 | CYCLE);
            }
            self.event_index += 1;
        }
        fn receive(&mut self, dci: usize) {
            let queue = match dci {
                3 => &mut self.incoming_events,
                5 => &mut self.incoming_acl,
                _ => return,
            };
            if self.active[dci].is_none() || queue.is_empty() {
                return;
            }
            let bytes = queue.pop_front().unwrap();
            let (trb, buffer, length) = self.active[dci].take().unwrap();
            assert!(bytes.len() <= length);
            // SAFETY: submitted TD names exactly this live DMA allocation;
            // only the model owns it until the completion it posts below.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
            }
            self.event(
                trb,
                SHORT_PACKET,
                TRANSFER_EVENT,
                dci as u8,
                length - bytes.len(),
            );
        }
        fn command(&mut self) {
            let at = self.commands + (self.command_index * TRB) as u64;
            // SAFETY: the controller has published this command before ringing.
            let (parameter, control) = unsafe {
                (
                    (at as *const u64).read_volatile(),
                    ((at + 12) as *const u32).read_volatile(),
                )
            };
            self.command_index += 1;
            let kind = control >> 10 & 0x3f;
            let dci = (control >> 16 & 0x1f) as usize;
            self.seen.push(kind);
            if self.silence == Some(kind) {
                return;
            }
            let mut code = SUCCESS;
            if let Some((wanted, status)) = self.fail
                && kind == wanted
            {
                code = status;
            }
            if code == SUCCESS {
                match kind {
                    CONFIGURE_ENDPOINT => {
                        // SAFETY: Configure Endpoint points to the live input
                        // context, with enabled endpoint dequeue pointers.
                        let flags = unsafe { ((parameter + 4) as *const u32).read_volatile() };
                        for index in 2..32 {
                            if flags & (1 << index) != 0 {
                                self.rings[index] = unsafe {
                                    ((parameter + (index as u64 + 1) * 32 + 8) as *const u64)
                                        .read_volatile()
                                        & !0xf
                                };
                                self.indices[index] = 0;
                                self.set_state(index, 1);
                            }
                        }
                    }
                    STOP_ENDPOINT => {
                        if self.race_halt {
                            self.race_halt = false;
                            self.set_state(dci, 2);
                            code = 19;
                        } else if self.state(dci) == 1 {
                            self.set_state(dci, 3);
                            self.active[dci] = None;
                        } else {
                            code = 19;
                        }
                    }
                    RESET_ENDPOINT => {
                        if self.state(dci) == 2 {
                            self.set_state(dci, 3);
                            self.active[dci] = None;
                        } else {
                            code = 19;
                        }
                    }
                    SET_DEQUEUE => {
                        if self.state(dci) != 3 {
                            code = 19;
                        } else {
                            self.dequeues.push(parameter);
                            self.indices[dci] =
                                ((parameter & !0xf) - self.rings[dci]) as usize / TRB;
                            if let Some(stale) = self.stale.take() {
                                self.event(stale, 26, TRANSFER_EVENT, dci as u8, 0);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if self.fatal_on_command == Some(kind) {
                self.fatal_status = HSE;
            }
            self.event(at, code, COMMAND_COMPLETION, 0, 0);
        }
        fn transfer(&mut self, dci: usize) {
            let at = self.rings[dci] + (self.indices[dci] * TRB) as u64;
            // SAFETY: a doorbell publishes a live transfer ring entry and any
            // data buffer encoded by that entry.
            let (parameter, length) = unsafe {
                (
                    (at as *const u64).read_volatile(),
                    ((at + 8) as *const u32).read_volatile() as usize & 0x1ffff,
                )
            };
            self.set_state(dci, 1);
            if self.halt_transfer == Some(dci) {
                // A STALL leaves the failed TD at the hardware dequeue pointer.
                // Reset stops it, but only Set Dequeue abandons it; another
                // doorbell could otherwise resume this same TD.
                self.set_state(dci, ENDPOINT_HALTED);
                self.active[dci] = Some((at, parameter, length));
                self.event(at, STALL, TRANSFER_EVENT, dci as u8, 0);
                return;
            }
            if dci == 1 {
                let request = parameter.to_le_bytes();
                let length = usize::from(u16::from_le_bytes([request[6], request[7]]));
                let data = if length == 0 {
                    Vec::new()
                } else {
                    // SAFETY: the next Data TRB's buffer is live through this
                    // synchronous modeled control completion.
                    let buffer = unsafe { ((at + TRB as u64) as *const u64).read_volatile() };
                    unsafe { core::slice::from_raw_parts(buffer as *const u8, length).to_vec() }
                };
                self.setup.push((request, data));
                let trbs = if length == 0 { 2 } else { 3 };
                if self.silence_transfer == Some(dci) {
                    self.active[dci] = Some((at, 0, length));
                } else {
                    self.event(at + (trbs - 1) * TRB as u64, SUCCESS, TRANSFER_EVENT, 1, 0);
                }
                self.indices[dci] += trbs as usize;
            } else {
                self.indices[dci] += 1;
                if dci == 4 {
                    // SAFETY: the submitted bulk OUT buffer is live until the
                    // completion below acknowledges its bytes.
                    self.outgoing.push(unsafe {
                        core::slice::from_raw_parts(parameter as *const u8, length).to_vec()
                    });
                    if self.silence_transfer == Some(dci) {
                        self.active[dci] = Some((at, parameter, length));
                    } else {
                        self.event(at, SUCCESS, TRANSFER_EVENT, dci as u8, 0);
                    }
                } else {
                    self.active[dci] = Some((at, parameter, length));
                }
            }
        }
    }
    struct CancelRegisters(Rc<RefCell<CancelModel>>);
    impl Registers for CancelRegisters {
        fn read32(&mut self, offset: usize) -> u32 {
            let mut model = self.0.borrow_mut();
            if offset == 0x40 + PORTSC {
                return if model.connected { CCS } else { 0 };
            }
            if offset == 0x40 + USBSTS {
                model.receive(3);
                model.receive(5);
                return model.fatal_status;
            }
            0
        }
        fn write32(&mut self, offset: usize, value: u32) {
            if offset == 0x1000 {
                self.0.borrow_mut().command();
            } else if offset == 0x1004 {
                self.0.borrow_mut().transfer(value as usize);
            }
        }
    }
    fn cancellation_controller(
        dma: &mut dyn DmaAllocator,
    ) -> (Controller, Rc<RefCell<CancelModel>>) {
        let (mut controller, _) = address_controller(dma, SUCCESS);
        let slot = controller
            .address(
                Attachment {
                    root_port: 1,
                    speed: FULL_SPEED,
                    route: 0,
                    tier: 0,
                    translator: None,
                },
                dma,
            )
            .unwrap();
        assert_eq!(slot, 1);
        let state = controller.slots[1].as_ref().unwrap();
        let mut rings = [0; 32];
        rings[1] = state.endpoints[1].as_ref().unwrap().ring.buffer.physical();
        let model = Rc::new(RefCell::new(CancelModel {
            commands: controller.commands.buffer.physical(),
            command_index: controller.commands.index,
            events: controller.events.physical(),
            event_index: controller.event_index,
            output: state._output.physical(),
            rings,
            indices: [0; 32],
            active: [None; 32],
            connected: true,
            fail: None,
            silence: None,
            race_halt: false,
            stale: None,
            seen: Vec::new(),
            dequeues: Vec::new(),
            setup: Vec::new(),
            incoming_events: Default::default(),
            incoming_acl: Default::default(),
            outgoing: Vec::new(),
            fatal_status: 0,
            fatal_on_command: None,
            silence_transfer: None,
            halt_transfer: None,
        }));
        model.borrow_mut().set_state(1, 1);
        controller.registers = Box::new(CancelRegisters(model.clone()));
        // A short actual test deadline without pretending any completion happened.
        controller.clock.ticks_per_microsecond = 1;
        let endpoints = [
            Endpoint {
                address: 0x81,
                attributes: 3,
                max_packet: 16,
                interval: 1,
            },
            Endpoint {
                address: 0x82,
                attributes: 2,
                max_packet: 64,
                interval: 0,
            },
            Endpoint {
                address: 0x02,
                attributes: 2,
                max_packet: 64,
                interval: 0,
            },
        ];
        controller.configure(1, &endpoints, None, dma).unwrap();
        model.borrow_mut().seen.clear();
        (controller, model)
    }

    #[test]
    fn cancellation_stops_running_resets_halted_and_clears_late_events() {
        for initial in [1, 2, 3] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing is exclusive live DMA throughout this test.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(512, 512).unwrap();
            let trb = controller.submit(1, 3, buffer.physical(), 512).unwrap();
            model.borrow_mut().set_state(3, initial);
            model.borrow_mut().stale = Some(trb);
            let pointer = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .ring
                .dequeue_pointer();
            controller.cancel(1, 3).unwrap();
            let expected = match initial {
                1 => vec![STOP_ENDPOINT, SET_DEQUEUE],
                2 => vec![RESET_ENDPOINT, SET_DEQUEUE],
                _ => vec![SET_DEQUEUE],
            };
            assert_eq!(model.borrow().seen, expected);
            assert_eq!(model.borrow().dequeues, vec![pointer]);
            assert_eq!(controller.completed(1, 3, trb, 512), None);
            assert!(controller.submit(1, 3, buffer.physical(), 512).is_ok());
        }
    }

    #[test]
    fn cancellation_failure_keeps_dma_recorded_and_blocks_reuse() {
        for failure in [
            Some((STOP_ENDPOINT, 11)),
            Some((STOP_ENDPOINT, 19)),
            Some((SET_DEQUEUE, 17)),
            None,
        ] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives controller/model/DMA access.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(512, 512).unwrap();
            controller.submit(1, 3, buffer.physical(), 512).unwrap();
            model.borrow_mut().fail = failure;
            if failure.is_none() {
                model.borrow_mut().silence = Some(STOP_ENDPOINT);
            }
            assert!(controller.cancel(1, 3).is_err());
            assert!(
                controller.slots[1].as_ref().unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .poisoned
            );
            let commands = model.borrow().seen.len();
            assert!(controller.submit(1, 3, buffer.physical(), 512).is_err());
            assert!(controller.cancel(1, 3).is_err());
            let endpoint = Endpoint {
                address: 0x81,
                attributes: 3,
                max_packet: 16,
                interval: 1,
            };
            assert!(controller.clear(1, &endpoint).is_err());
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            assert_eq!(model.borrow().seen.len(), commands);
            if failure != Some((SET_DEQUEUE, 17)) {
                assert!(model.borrow().active[3].is_some());
                assert_eq!(model.borrow().state(3), 1);
            }
        }
    }

    #[test]
    fn cancellation_handles_completion_and_halt_races_without_resetting_running() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains exclusive and live through controller/model use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(512, 512).unwrap();
        let trb = controller.submit(1, 3, buffer.physical(), 512).unwrap();
        model.borrow_mut().event(trb, SUCCESS, TRANSFER_EVENT, 3, 0);
        assert_eq!(controller.completed(1, 3, trb, 512), Some(Ok(512)));
        controller.cancel(1, 3).unwrap(); // Empty ring still Running.
        model.borrow_mut().seen.clear();
        controller.submit(1, 3, buffer.physical(), 512).unwrap();
        model.borrow_mut().race_halt = true;
        controller.cancel(1, 3).unwrap();
        assert_eq!(
            model.borrow().seen,
            vec![STOP_ENDPOINT, RESET_ENDPOINT, SET_DEQUEUE]
        );
    }

    #[test]
    fn bluetooth_binds_real_xhci_queues_moves_packets_and_stops_on_disconnect() {
        use crate::usb::bluetooth::{FirmwareStatus, Packet, State};
        for scenario in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: this boot-lifetime-style allocation outlives every model DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = cancellation_controller(&mut dma);
            let shared: Shared = Rc::new(RefCell::new(controller));
            let device = Device {
                slot: 1,
                speed: FULL_SPEED,
                location: "modeled physical HCI".into(),
                descriptor: [
                    18, 1, 0, 2, 0xe0, 1, 1, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1,
                ],
                configuration: vec![
                    9, 2, 48, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3,
                    16, 0, 1, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0, 9, 4, 1, 0, 0,
                    0xe0, 1, 1, 0,
                ],
                manufacturer: None,
                product: None,
                serial: None,
            };
            let mut found = Found::default();
            bind(&shared, device, &mut dma, &mut found);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.bluetooth.len(), 1);
            if scenario == 0 {
                let count = model.borrow().seen.len();
                drop(found);
                assert_eq!(model.borrow().seen.len(), count);
                continue;
            }
            let mut hci = found.bluetooth.pop().unwrap();
            assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
            hci.submit_command(&[3, 0x0c, 0]).unwrap();
            assert_eq!(
                model.borrow().setup.last().unwrap(),
                &([0x20, 0, 0, 0, 0, 0, 3, 0], vec![3, 0x0c, 0])
            );
            assert!(hci.poll().unwrap().is_empty());
            model
                .borrow_mut()
                .incoming_events
                .push_back(vec![0x0e, 4, 1, 3, 0x0c, 0]);
            model
                .borrow_mut()
                .incoming_acl
                .push_back(vec![1, 0x20, 2, 0, 0xab, 0xcd]);
            assert_eq!(
                hci.poll().unwrap(),
                vec![
                    Packet::Event(vec![0x0e, 4, 1, 3, 0x0c, 0]),
                    Packet::Acl(vec![1, 0x20, 2, 0, 0xab, 0xcd])
                ]
            );
            hci.submit_acl(&[2, 0x20, 1, 0, 0x42]).unwrap();
            assert_eq!(model.borrow().outgoing, vec![vec![2, 0x20, 1, 0, 0x42]]);
            assert!(hci.poll().unwrap().is_empty()); // Leaves both IN TDs active.
            model.borrow_mut().connected = false;
            if scenario == 2 {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
            }
            let error = hci.poll().unwrap_err();
            assert_eq!(hci.state(), State::Failed);
            if scenario == 1 {
                assert_eq!(error.cleanup, None);
                assert_eq!(model.borrow().state(3), 3);
                assert_eq!(model.borrow().state(5), 3);
                assert!(model.borrow().active[3].is_none());
                assert!(model.borrow().active[5].is_none());
            } else {
                assert_eq!(error.cleanup, Some(BlockError::Device { status: 11 }));
                for dci in [3, 5] {
                    assert_eq!(model.borrow().state(dci), 1);
                    assert!(model.borrow().active[dci].is_some());
                    assert!(
                        shared.borrow().slots[1].as_ref().unwrap().endpoints[dci]
                            .as_ref()
                            .unwrap()
                            .poisoned
                    );
                }
                assert!(hci.poll().is_err());
            }
            let count = model.borrow().seen.len();
            drop(hci);
            assert_eq!(model.borrow().seen.len(), count); // Drop does not reset another device.
        }
    }

    #[test]
    fn unacknowledged_command_blocks_later_commands_and_dma_mutation_even_after_late_completion() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains exclusive/live through model and DMA use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let buffer = dma.allocate(512, 512).unwrap();
        controller.submit(1, 3, buffer.physical(), 512).unwrap();
        let timed_out = controller.commands.address();
        model.borrow_mut().silence = Some(STOP_ENDPOINT);
        assert_eq!(controller.cancel(1, 3), Err(BlockError::Timeout));
        assert!(controller.command_poisoned);
        let command_bytes = controller.commands.buffer.bytes().to_vec();
        let slot = controller.slots[1].as_ref().unwrap();
        let input = slot.input.bytes().to_vec();
        let control = slot.control.bytes().to_vec();
        let ring = slot.endpoints[5]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .bytes()
            .to_vec();
        let setup_count = model.borrow().setup.len();
        let command_count = model.borrow().seen.len();
        // A delayed old Stop acknowledgment cannot retroactively authorize reuse
        // of a command TRB, the shared input context, or EP0's control buffer.
        model.borrow_mut().silence = None;
        model.borrow_mut().set_state(3, 3);
        model
            .borrow_mut()
            .event(timed_out, SUCCESS, COMMAND_COMPLETION, 0, 0);
        assert!(controller.command(0, 0, ENABLE_SLOT << 10).is_err());
        assert!(
            controller
                .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
                .is_err()
        );
        let endpoint = Endpoint {
            address: 0x82,
            attributes: 2,
            max_packet: 64,
            interval: 0,
        };
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut dma)
                .is_err()
        );
        assert!(controller.submit(1, 5, buffer.physical(), 512).is_err());
        let slot = controller.slots[1].as_ref().unwrap();
        assert_eq!(slot.input.bytes(), input);
        assert_eq!(slot.control.bytes(), control);
        assert_eq!(
            slot.endpoints[5].as_ref().unwrap().ring.buffer.bytes(),
            ring
        );
        assert_eq!(controller.commands.buffer.bytes(), command_bytes);
        assert_eq!(model.borrow().setup.len(), setup_count);
        assert_eq!(model.borrow().seen.len(), command_count);
    }

    #[test]
    fn acknowledged_command_errors_stay_local_but_fatal_status_overrides_success() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive live test DMA through controller/model use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        model.borrow_mut().fail = Some((ENABLE_SLOT, CONTEXT_STATE_ERROR));
        assert!(matches!(
            controller.command(0, 0, ENABLE_SLOT << 10),
            Err(BlockError::Device {
                status: CONTEXT_STATE_ERROR
            })
        ));
        assert!(!controller.command_poisoned);
        model.borrow_mut().fail = None;
        assert!(controller.command(0, 0, ENABLE_SLOT << 10).is_ok());
        model.borrow_mut().fatal_on_command = Some(ENABLE_SLOT);
        assert!(matches!(
            controller.command(0, 0, ENABLE_SLOT << 10),
            Err(BlockError::Device { status: HSE })
        ));
        assert!(controller.command_poisoned);
        let count = model.borrow().seen.len();
        assert!(controller.command(0, 0, ENABLE_SLOT << 10).is_err());
        assert_eq!(model.borrow().seen.len(), count);
    }

    #[test]
    fn control_timeout_stops_running_ep0_and_retains_poison_if_stop_fails() {
        for fail_stop in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive test backing outlives all DMA/controller use.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            model.borrow_mut().silence_transfer = Some(1);
            if fail_stop {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
            }
            let result = controller.control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0]);
            if fail_stop {
                assert!(matches!(
                    result,
                    Err(BlockError::Unsupported("xHCI endpoint did not stop"))
                ));
                assert!(
                    controller.slots[1].as_ref().unwrap().endpoints[1]
                        .as_ref()
                        .unwrap()
                        .poisoned
                );
                assert!(model.borrow().active[1].is_some());
                let old = controller.slots[1]
                    .as_ref()
                    .unwrap()
                    .control
                    .bytes()
                    .to_vec();
                let count = model.borrow().setup.len();
                assert!(
                    controller
                        .control(1, setup(0x20, 0, 0, 0, 3), &[9, 8, 7])
                        .is_err()
                );
                assert_eq!(controller.slots[1].as_ref().unwrap().control.bytes(), old);
                assert_eq!(model.borrow().setup.len(), count);
            } else {
                assert_eq!(result, Err(BlockError::Timeout));
                assert_eq!(model.borrow().seen, vec![STOP_ENDPOINT, SET_DEQUEUE]);
                assert!(model.borrow().active[1].is_none());
                model.borrow_mut().silence_transfer = None;
                assert!(
                    controller
                        .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
                        .is_ok()
                );
            }
            assert!(!model.borrow().seen.contains(&RESET_ENDPOINT));
        }
    }

    #[test]
    fn bulk_timeout_stops_running_td_and_cannot_reuse_it_after_failed_cancel() {
        for fail_stop in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive test backing outlives all DMA/controller use.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = cancellation_controller(&mut dma);
            let buffer = dma.allocate(512, 512).unwrap();
            if fail_stop {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
            }
            let result = controller.transfer(1, 5, buffer.physical(), 512, 1);
            if fail_stop {
                assert!(matches!(
                    result,
                    Err(BlockError::Unsupported("xHCI endpoint did not stop"))
                ));
                assert!(model.borrow().active[5].is_some());
                let old = controller.slots[1].as_ref().unwrap().endpoints[5]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes()
                    .to_vec();
                assert!(controller.endpoint_ready(1, 5).is_err());
                assert!(
                    controller
                        .transfer(1, 5, buffer.physical(), 512, 1)
                        .is_err()
                );
                assert_eq!(
                    controller.slots[1].as_ref().unwrap().endpoints[5]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .bytes(),
                    old
                );
            } else {
                assert_eq!(result, Err(BlockError::Timeout));
                assert_eq!(model.borrow().seen, vec![STOP_ENDPOINT, SET_DEQUEUE]);
                assert!(model.borrow().active[5].is_none());
                model.borrow_mut().incoming_acl.push_back(vec![1, 2, 3]);
                assert_eq!(
                    controller.transfer(1, 5, buffer.physical(), 512, 1000),
                    Ok(3)
                );
                assert_eq!(&buffer.bytes()[..3], &[1, 2, 3]);
            }
            assert!(!model.borrow().seen.contains(&RESET_ENDPOINT));
        }
    }

    fn failed_stall_recovery(
        dma: &mut dyn DmaAllocator,
        buffer: u64,
        length: usize,
        dci: u8,
    ) -> (Controller, Rc<RefCell<CancelModel>>) {
        let (mut controller, model) = cancellation_controller(dma);
        model.borrow_mut().halt_transfer = Some(usize::from(dci));
        model.borrow_mut().fail = Some((SET_DEQUEUE, CONTEXT_STATE_ERROR));
        let result = if dci == 1 {
            controller
                .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
                .map(|_| ())
        } else {
            let trb = controller.submit(1, dci, buffer, length).unwrap();
            assert_eq!(
                controller.completed(1, dci, trb, length),
                Some(Err(BlockError::Device { status: STALL }))
            );
            controller.clear(1, &fixture_endpoint(dci))
        };
        assert_eq!(
            result,
            Err(BlockError::Device {
                status: CONTEXT_STATE_ERROR
            })
        );
        assert_eq!(model.borrow().seen, vec![RESET_ENDPOINT, SET_DEQUEUE]);
        assert_eq!(model.borrow().state(usize::from(dci)), ENDPOINT_STOPPED);
        assert_eq!(model.borrow().indices[usize::from(dci)], 0);
        assert!(model.borrow().dequeues.is_empty());
        assert!(!controller.command_poisoned);
        (controller, model)
    }

    fn fixture_endpoint(dci: u8) -> Endpoint {
        Endpoint {
            address: (dci / 2) | if dci & 1 != 0 { 0x80 } else { 0 },
            attributes: if dci == 3 { 3 } else { 2 },
            max_packet: if dci == 3 { 16 } else { 64 },
            interval: u8::from(dci == 3),
        }
    }

    #[test]
    fn halted_reset_with_failed_dequeue_refuses_endpoint_and_dma_reuse() {
        for dci in [1, 3, 4, 5] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives controller/model and every DMA buffer.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let buffer = dma.allocate(512, 512).unwrap();
            let (mut controller, model) =
                failed_stall_recovery(&mut dma, buffer.physical(), buffer.len(), dci);
            let slot = controller.slots[1].as_ref().unwrap();
            let control = slot.control.bytes().to_vec();
            let input = slot.input.bytes().to_vec();
            let transfer = slot.endpoints[usize::from(dci)].as_ref().unwrap();
            assert!(transfer.poisoned);
            let ring = transfer.ring.buffer.bytes().to_vec();
            let commands = controller.commands.buffer.bytes().to_vec();
            let seen = model.borrow().seen.len();
            let setup_count = model.borrow().setup.len();
            let old_index = model.borrow().indices[usize::from(dci)];
            assert!(controller.endpoint_ready(1, dci).is_err());
            assert!(controller.submit(1, dci, buffer.physical(), 512).is_err());
            assert!(
                controller
                    .completed(1, dci, buffer.physical(), 512)
                    .unwrap()
                    .is_err()
            );
            assert!(controller.cancel(1, dci).is_err());
            if dci == 1 {
                assert!(
                    controller
                        .control(1, setup(0x20, 0, 0, 0, 3), &[0; 3])
                        .is_err()
                );
                assert!(controller.recover(1, dci).is_err());
            } else {
                let endpoint = fixture_endpoint(dci);
                assert!(controller.clear(1, &endpoint).is_err());
                assert!(
                    controller
                        .configure(1, &[endpoint], None, &mut dma)
                        .is_err()
                );
            }
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(slot.control.bytes(), control);
            assert_eq!(slot.input.bytes(), input);
            assert_eq!(
                slot.endpoints[usize::from(dci)]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes(),
                ring
            );
            assert_eq!(controller.commands.buffer.bytes(), commands);
            assert_eq!(model.borrow().seen.len(), seen);
            assert_eq!(model.borrow().setup.len(), setup_count);
            assert_eq!(model.borrow().indices[usize::from(dci)], old_index);
            // An acknowledged Set Dequeue error poisons only its endpoint.
            let healthy = if dci == 5 { 3 } else { 5 };
            assert!(controller.endpoint_ready(1, healthy).is_ok());
            model.borrow_mut().fail = None;
            assert!(controller.command(0, 0, ENABLE_SLOT << 10).is_ok());
            assert!(!controller.command_poisoned);
        }
    }

    /// Shared class-driver regression fixture: a real submitted TD left
    /// unresolved by failed Running Stop or Halted Set Dequeue recovery.
    pub(crate) fn controller_with_unresolved_td(
        dma: &mut dyn DmaAllocator,
        buffer: u64,
        length: usize,
        dci: u8,
        halted: bool,
    ) -> Shared {
        if halted {
            let (controller, _) = failed_stall_recovery(dma, buffer, length, dci);
            return Rc::new(RefCell::new(controller));
        }
        let (mut controller, model) = cancellation_controller(dma);
        model.borrow_mut().silence_transfer = Some(usize::from(dci));
        model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
        if dci == 1 {
            assert!(
                controller
                    .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
                    .is_err()
            );
        } else {
            controller.submit(1, dci, buffer, length).unwrap();
            assert!(controller.cancel(1, dci).is_err());
        }
        assert!(model.borrow().active[usize::from(dci)].is_some());
        Rc::new(RefCell::new(controller))
    }
}
