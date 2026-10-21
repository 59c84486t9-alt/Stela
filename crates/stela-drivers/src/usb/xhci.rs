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
use super::{bluetooth, cdc, ethernet, hid, storage};
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

mod configuration;
mod endpoint;

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
pub const SUPER_SPEED_PLUS: u8 = 5;
const SS_ENDPOINT_COMPANION: u8 = 0x30;

const CONTROL_TYPE: u32 = 4;
const MAX_SLOTS: usize = 32;
const MAX_TIERS: u8 = 5;
/// The most one TD moves, and the boundary it must not cross.
pub const MAX_TD: usize = 64 * 1024;
const CONTROL_BYTES: usize = 4096;
/// Complete descriptor inventory per device, never a silently truncated prefix.
const CONFIGURATION_INVENTORY_BYTES: usize = 64 * 1024;

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

/// USB 3.x endpoint companion, retained with the endpoint it immediately follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuperSpeedCompanion {
    pub max_burst: u8,
    pub attributes: u8,
    pub bytes_per_interval: u16,
}

/// An endpoint as its descriptor describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: u8,
    pub attributes: u8,
    pub max_packet: u16,
    pub interval: u8,
    pub companion: Option<SuperSpeedCompanion>,
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

/// The interfaces of a configuration descriptor, in order.
pub fn interfaces(configuration: &[u8]) -> Vec<Interface> {
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut at = 0;
    let mut preceding_endpoint = false;
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
                        companion: None,
                    });
                }
            }
            _ => {
                if let Some(interface) = interfaces.last_mut() {
                    if d[1] == SS_ENDPOINT_COMPANION
                        && length == 6
                        && preceding_endpoint
                        && let Some(endpoint) = interface.endpoints.last_mut()
                    {
                        endpoint.companion = Some(SuperSpeedCompanion {
                            max_burst: d[2],
                            attributes: d[3],
                            bytes_per_interval: u16::from_le_bytes([d[4], d[5]]),
                        });
                    }
                    // Preserve the original bytes, including recognized companions.
                    interface.extra.push(d.to_vec());
                }
            }
        }
        preceding_endpoint = d[1] == ENDPOINT_DESCRIPTOR && length >= 7;
        at += length;
    }
    interfaces
}

/// A device the controller addressed, with what it said about itself.
#[derive(Clone, Debug)]
pub struct Device {
    /// Complete original PLA_TCR0 read; matching uses the donor's normalized
    /// version mask below while diagnostics retain every observed register bit.
    pub vendor_ethernet_tcr: Option<u32>,
    /// Read-only vendor Ethernet chip identity observed before configuration
    /// selection, matching Linux r8152's cfgselector preflight. None means no
    /// verified identity; product IDs alone never select a vendor backend.
    pub vendor_ethernet_revision: Option<u16>,
    pub slot: u8,
    pub speed: u8,
    /// Where it is: the controller's PCI function, root port and hub ports.
    pub location: String,
    pub descriptor: [u8; 18],
    /// Every complete configuration descriptor in GET_DESCRIPTOR index order.
    /// The descriptor's bConfigurationValue is independent of that index.
    pub configurations: Vec<Vec<u8>>,
    /// Selected configuration bytes; selection alone does not configure hardware.
    pub configuration: Vec<u8>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

impl Device {
    pub fn configuration_value(&self) -> u8 {
        self.configuration.get(5).copied().unwrap_or(0)
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
    /// Only an acknowledged Configure Endpoint permits transfer submission.
    enabled: bool,
}

struct Slot {
    input: DmaBuffer,
    _output: DmaBuffer,
    /// The slot context as software last set it.
    context: [u32; 4],
    endpoints: [Option<Transfer>; 32],
    control: DmaBuffer,
    speed: u8,
    /// None after an unresolved SET_CONFIGURATION; Some(0) is Address state.
    current_configuration: Option<u8>,
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
            enabled: true,
        });
        let input_address = input.physical();
        self.slots[usize::from(slot)] = Some(Slot {
            input,
            _output: output,
            context: slot_context,
            endpoints,
            control,
            speed: attachment.speed,
            current_configuration: Some(0),
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
        let state = self.slot(slot)?;
        if dci != 1 && !state.current_configuration.is_some_and(|value| value != 0) {
            return Err(BlockError::Unsupported(
                "USB device configuration is not acknowledged",
            ));
        }
        let endpoint = state
            .endpoints
            .get(usize::from(dci))
            .and_then(Option::as_ref)
            .ok_or(BlockError::Unsupported("xHCI endpoint not configured"))?;
        if endpoint.poisoned {
            return Err(BlockError::Unsupported("xHCI endpoint cancellation failed"));
        }
        if !endpoint.enabled {
            return Err(BlockError::Unsupported(
                "xHCI endpoint configuration is not acknowledged",
            ));
        }
        Ok(())
    }

    /// Cached device state, updated only by acknowledged standard requests.
    pub fn current_configuration(&mut self, slot: u8) -> Result<Option<u8>, BlockError> {
        self.ready()?;
        Ok(self.slot(slot)?.current_configuration)
    }

    /// Idempotent class-binding request. Repeating SET_CONFIGURATION, even with
    /// the same value, resets alternate settings and endpoint state (USB 9.4.7).
    pub fn set_configuration(&mut self, slot: u8, value: u8) -> Result<(), BlockError> {
        if self.current_configuration(slot)? == Some(value) {
            return Ok(());
        }
        self.control(
            slot,
            setup(0, SET_CONFIGURATION, u16::from(value), 0, 0),
            &[],
        )?;
        Ok(())
    }

    /// One control transfer on EP0; IN data is returned, OUT data sent.
    pub fn control(
        &mut self,
        slot: u8,
        request: [u8; 8],
        out: &[u8],
    ) -> Result<Vec<u8>, BlockError> {
        let configuration = request[0] == 0 && request[1] == SET_CONFIGURATION;
        if configuration {
            if request[3..] != [0; 5] || !out.is_empty() {
                return Err(BlockError::Unsupported("invalid SET_CONFIGURATION request"));
            }
            if self.slot(slot)?.endpoints[2..].iter().any(Option::is_some) {
                return Err(BlockError::Unsupported(
                    "USB configuration change requires endpoint teardown",
                ));
            }
        }
        // A timeout may occur after the device accepted the request; do not
        // preserve the old value or infer success from cancellation of EP0.
        self.endpoint_ready(slot, 1)?;
        if configuration {
            self.slot(slot)?.current_configuration = None;
        }
        let result = self.control_transfer(slot, request, out);
        if configuration && result.is_ok() {
            self.slot(slot)?.current_configuration = Some(request[2]);
        }
        result
    }

    fn control_transfer(
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
            if received != length {
                return Err(BlockError::Unsupported("short USB control OUT transfer"));
            }
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
        if !self
            .slot(slot)?
            .current_configuration
            .is_some_and(|value| value != 0)
        {
            return Err(BlockError::Unsupported(
                "USB device configuration is not acknowledged",
            ));
        }
        // Validate every endpoint and allocate every ring before publishing any
        // change. Existing rings may still be DMA-owned, even after a failure.
        let mut selected = 0u32;
        let speed = self.slot(slot)?.speed;
        let mut contexts = Vec::new();
        for endpoint in endpoints {
            let dci = endpoint.dci();
            if endpoint.address & 0x70 != 0
                || dci < 2
                || endpoint.max_packet & 0x7ff == 0
                || !matches!(endpoint.kind(), 2 | 3)
                || selected & (1 << dci) != 0
            {
                return Err(BlockError::Unsupported(
                    "invalid or duplicate xHCI endpoint",
                ));
            }
            if let Some(transfer) = &self.slot(slot)?.endpoints[usize::from(dci)] {
                return Err(BlockError::Unsupported(if transfer.poisoned {
                    "xHCI endpoint cancellation failed"
                } else {
                    "xHCI endpoint replacement requires teardown"
                }));
            }
            contexts.push(endpoint::Context::new(endpoint, speed)?);
            selected |= 1 << dci;
        }
        let mut rings = Vec::new();
        for _ in endpoints {
            rings.push(Ring::new(dma)?);
        }
        self.clear_input(slot)?;
        let context = self.context();
        let mut add = 1u32;
        let mut last = 1u8;
        for ((endpoint, ring), recipe) in endpoints.iter().zip(rings).zip(contexts) {
            let dci = endpoint.dci();
            let state = self.slot(slot)?;
            let at = (usize::from(dci) + 1) * context;
            state.input.write(at, recipe.info);
            state.input.write(at + 4, recipe.info2);
            state.input.write(at + 8, ring.dequeue_pointer());
            state.input.write(at + 16, recipe.tx_info);
            state.endpoints[usize::from(dci)] = Some(Transfer {
                ring,
                is_in: endpoint.is_in(),
                poisoned: false,
                enabled: false,
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
        let result = self.command(
            input_address,
            0,
            CONFIGURE_ENDPOINT << 10 | u32::from(slot) << 24,
        );
        // Retain rings on any error: a lost command completion may still leave
        // them reachable by the controller. Never expose an unacknowledged ring.
        for endpoint in endpoints {
            let transfer = self.slot(slot)?.endpoints[usize::from(endpoint.dci())]
                .as_mut()
                .unwrap();
            transfer.enabled = result.is_ok();
            transfer.poisoned = result.is_err();
        }
        result?;
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
            Ok(mut device) => {
                if let Err(error) = self.preflight_vendor_ethernet(&mut device) {
                    failures.push((format!("{location} RTL815x configuration preflight"), error));
                }
                if let Err(why) = configuration::select(&mut device) {
                    device.configuration.clear();
                    failures.push((
                        format!("{location} {} choose configuration", device.name()),
                        BlockError::Unsupported(why),
                    ));
                } else if device.descriptor[4] == HUB_CLASS
                    && let Err(error) = self.hub(&device, attachment, dma, devices, failures)
                {
                    failures.push((format!("{location} {} enumerate hub", device.name()), error));
                }
                // Selection failures still preserve the entire descriptor
                // inventory for diagnostics and future generic forwarding.
                devices.push(device);
            }
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

    fn preflight_vendor_ethernet(&mut self, device: &mut Device) -> Result<(), BlockError> {
        if ethernet::matches(&device.descriptor) {
            use ethernet::rtl815x::Revision;
            let bytes = self.control(device.slot, Revision::request(), &[])?;
            let revision = Revision::from_register(&bytes)?;
            device.vendor_ethernet_revision = Some(revision.0);
            device.vendor_ethernet_tcr = Some(u32::from_le_bytes(bytes.try_into().unwrap()));
        }
        Ok(())
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
        if descriptor[0] != 18 || descriptor[1] != DEVICE_DESCRIPTOR || descriptor[17] == 0 {
            return during(
                format!("{identity} slot {slot} device descriptor"),
                Err(BlockError::Unsupported(
                    "invalid USB device descriptor/configuration count",
                )),
            );
        }
        let configurations = self
            .configurations(slot, descriptor[17])
            .map_err(|(operation, error)| (format!("{identity} {operation}"), error))?;
        let manufacturer = self.string(slot, descriptor[14]);
        let product = self.string(slot, descriptor[15]);
        let serial = self.string(slot, descriptor[16]);
        let device = Device {
            vendor_ethernet_revision: None,
            vendor_ethernet_tcr: None,
            slot,
            speed: attachment.speed,
            location,
            descriptor,
            configurations,
            configuration: Vec::new(),
            manufacturer,
            product,
            serial,
        };
        Ok(device)
    }

    /// Read every descriptor index, retaining the complete original byte streams.
    fn configurations(
        &mut self,
        slot: u8,
        count: u8,
    ) -> Result<Vec<Vec<u8>>, (String, BlockError)> {
        if count == 0 {
            return during(
                format!("slot {slot} configuration inventory"),
                Err(BlockError::Unsupported("USB device has no configurations")),
            );
        }
        let mut configurations = Vec::new();
        let mut inventory_bytes = 0;
        for index in 0..count {
            let bytes = self.configuration(slot, index)?;
            inventory_bytes += bytes.len();
            if inventory_bytes > CONFIGURATION_INVENTORY_BYTES {
                return during(
                    format!("slot {slot} configuration {index}"),
                    Err(BlockError::Unsupported(
                        "USB configuration inventory exceeds 64 KiB",
                    )),
                );
            }
            if configurations
                .iter()
                .any(|previous: &Vec<u8>| previous[5] == bytes[5])
            {
                return during(
                    format!("slot {slot} configuration {index}"),
                    Err(BlockError::Unsupported("duplicate USB configuration value")),
                );
            }
            configurations.push(bytes);
        }
        Ok(configurations)
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
        let total = u16::from_le_bytes([head[2], head[3]]);
        if head[0] != 9
            || head[1] != CONFIGURATION_DESCRIPTOR
            || total < 9
            || usize::from(total) > CONTROL_BYTES
        {
            return during(
                format!("slot {slot} configuration {index} length={total}"),
                Err(BlockError::Unsupported(
                    "invalid or oversized USB configuration descriptor",
                )),
            );
        }
        let bytes = self.enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, index, total)?;
        during(
            format!(
                "slot {slot} configuration {index} value={} validate",
                head[5]
            ),
            configuration::validate(&bytes)
                .and_then(|()| {
                    if bytes[..9] != head[..9] {
                        Err("USB configuration header changed during enumeration")
                    } else {
                        Ok(())
                    }
                })
                .map_err(BlockError::Unsupported),
        )?;
        Ok(bytes)
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
        if matches!(attachment.speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
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
        let multi = interfaces(&device.configuration).iter().any(|interface| {
            interface.class == HUB_CLASS && interface.alternate == 0 && interface.protocol == 2
        });
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
        self.set_configuration(slot, device.configuration_value())?;
        self.configure(slot, &endpoints, Some((ports, tt_think, multi)), dma)?;
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
    pub vendor_links: Vec<ethernet::UsbEthernet>,
    /// Exact firmware request/target, format and device errors from vendor
    /// network attachment; never flattened to a generic unsupported status.
    pub vendor_failures: Vec<(String, ethernet::Error)>,
    pub disks: Vec<storage::UsbDisk>,
    pub inputs: Vec<hid::UsbInput>,
    pub links: Vec<cdc::UsbNet>,
    /// Raw physical HCI transports; vendor firmware initialization is unverified.
    pub bluetooth: Vec<bluetooth::UsbHci>,
    /// Devices or interfaces no driver here takes, and why.
    pub unused: Vec<(String, &'static str)>,
    pub failures: Vec<(String, BlockError)>,
    /// Descriptor inventory of all addressed devices, including hubs and devices
    /// without a supported class driver. Hardware state belongs to Controller.
    pub devices: Vec<Device>,
}

/// Starts the controller at `function`, enumerates its devices and binds
/// the class drivers.
pub fn attach(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Found, BlockError> {
    let firmware = crate::firmware::HandoffProvider::new(handoff.firmware.as_deref());
    attach_with_provider(function, handoff, dma, &firmware)
}

/// Attach while preserving the caller's firmware lookup/recording boundary.
pub fn attach_with_provider(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
    firmware: &dyn crate::firmware::Provider,
) -> Result<Found, BlockError> {
    let bars = function.bars();
    // The capability, operational, runtime and doorbell registers all lie
    // in BAR 0, whatever its size (5.2.1): QEMU's is 16 KiB, a PC's 64 KiB
    // or more.
    let bytes = bars[0]
        .and_then(|bar| bar.memory())
        .map_or(0, |range| range.end - range.start);
    let registers = registers(handoff, bars[0], 0, bytes)?;
    function.enable_polled();
    let address = function.address;
    let location = format!(
        "xhci {:04x}:{:02x}:{:02x}.{}",
        address.segment, address.bus, address.device, address.function
    );
    start_with_provider(Box::new(registers), handoff.clock, dma, location, firmware)
}

/// Starts the controller behind `registers`, enumerates its devices and
/// binds the class drivers.
pub fn start(
    registers: Box<dyn Registers>,
    clock: Clock,
    dma: &mut dyn DmaAllocator,
    location: String,
) -> Result<Found, BlockError> {
    start_with_provider(
        registers,
        clock,
        dma,
        location,
        &crate::firmware::HandoffProvider::new(None),
    )
}

/// Start with synchronously borrowed firmware. Class drivers retain only owned
/// evidence metadata after upload; no borrowed image escapes this call.
pub fn start_with_provider(
    registers: Box<dyn Registers>,
    clock: Clock,
    dma: &mut dyn DmaAllocator,
    location: String,
    firmware: &dyn crate::firmware::Provider,
) -> Result<Found, BlockError> {
    let mut controller = Controller::new(registers, clock, dma, location)?;
    let mut found = Found::default();
    let devices = controller.enumerate(dma, &mut found.failures);
    let shared: Shared = Rc::new(RefCell::new(controller));
    for device in &devices {
        bind_with_provider(&shared, device.clone(), dma, &mut found, firmware);
    }
    found.devices = devices;
    Ok(found)
}

/// Binds every interface of `device` a driver here takes: one
/// configuration, its endpoints configured together.
#[cfg(test)]
fn bind(shared: &Shared, device: Device, dma: &mut dyn DmaAllocator, found: &mut Found) {
    bind_with_provider(
        shared,
        device,
        dma,
        found,
        &crate::firmware::HandoffProvider::new(None),
    );
}

fn bind_with_provider(
    shared: &Shared,
    device: Device,
    dma: &mut dyn DmaAllocator,
    found: &mut Found,
    firmware: &dyn crate::firmware::Provider,
) {
    let all = interfaces(&device.configuration);
    let mut endpoints = Vec::new();
    let mut plans = Vec::new();
    // CDC data interfaces belong to their communications interface.
    for interface in all.iter().filter(|i| i.alternate == 0 && i.class != 10) {
        let plan = configuration::plan(&device, interface, &all);
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
        let value = device.configuration_value();
        during(
            format!("slot {} EP0 SET_CONFIGURATION value={value}", device.slot),
            controller.set_configuration(device.slot, value),
        )
        .and_then(|()| {
            during(
                format!("slot {} Configure Endpoint", device.slot),
                controller.configure(device.slot, &endpoints, None, dma),
            )
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
            Plan::VendorEthernet(binding) => {
                match ethernet::UsbEthernet::new(shared.clone(), &device, binding, dma, firmware) {
                    Ok(link) => found.vendor_links.push(link),
                    Err(error) => found.vendor_failures.push((location.clone(), error)),
                }
                Ok(())
            }
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
    /// A vendor Ethernet adapter with an implemented observed chip revision.
    VendorEthernet(ethernet::Binding),
    /// Legacy Bluetooth HCI interrupt and bulk endpoints.
    Bluetooth(bluetooth::Binding),
}

impl Plan {
    fn endpoints(&self) -> Vec<Endpoint> {
        match self {
            Self::Storage(endpoints) => endpoints.to_vec(),
            Self::Hid(endpoint) => vec![*endpoint],
            Self::Ethernet(binding) => binding.endpoints(),
            Self::VendorEthernet(binding) => binding.endpoints(),
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
        context_bytes: usize,
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
        script: Option<crate::usb::bluetooth::intel::tests::Script>,
        descriptors: Vec<(u8, u8, Vec<u8>)>,
        configuration_value: u8,
        configuration_seen_before_endpoints: Vec<u8>,
        short_control_out: bool,
        control_replies: alloc::collections::VecDeque<([u8; 8], Vec<u8>)>,
        stall_control: Option<u8>,
        silence_control: Option<u8>,
        short_bulk_out: bool,
        ethernet: Option<ethernet::rtl815x::tests::Model>,
        ethernet_upload: Option<ethernet::rtl815x::FirmwareModel>,
    }
    impl CancelModel {
        fn state(&self, dci: usize) -> u32 {
            // SAFETY: output context is live aligned test DMA, exclusively
            // accessed by this model between controller operations.
            unsafe {
                ((self.output + dci as u64 * self.context_bytes as u64) as *const u32)
                    .read_volatile()
                    & 7
            }
        }
        fn set_state(&mut self, dci: usize, state: u32) {
            // SAFETY: same live context as state().
            unsafe {
                ((self.output + dci as u64 * self.context_bytes as u64) as *mut u32)
                    .write_volatile(state);
            }
        }
        fn event(&mut self, parameter: u64, code: u32, kind: u32, dci: u8, residual: usize) {
            let cycle = u32::from((self.event_index / RING_TRBS).is_multiple_of(2));
            let address = self.events + ((self.event_index % RING_TRBS) * TRB) as u64;
            // SAFETY: all three fields are in the still-live test event ring.
            unsafe {
                (address as *mut u64).write_volatile(parameter);
                ((address + 8) as *mut u32).write_volatile(code << 24 | residual as u32);
                ((address + 12) as *mut u32)
                    .write_volatile(1 << 24 | u32::from(dci) << 16 | kind << 10 | cycle);
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
                        let value = self.configuration_value;
                        self.configuration_seen_before_endpoints.push(value);
                        // SAFETY: Configure Endpoint points to the live input
                        // context, with enabled endpoint dequeue pointers.
                        let flags = unsafe { ((parameter + 4) as *const u32).read_volatile() };
                        for index in 2..32 {
                            if flags & (1 << index) != 0 {
                                self.rings[index] = unsafe {
                                    ((parameter
                                        + (index as u64 + 1) * self.context_bytes as u64
                                        + 8) as *const u64)
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
        fn scripted(&mut self, bulk: bool, packet: &[u8]) {
            use crate::usb::bluetooth::Pipe;
            if let Some(script) = &mut self.script {
                for (pipe, event) in script.command(bulk, packet) {
                    match pipe {
                        Pipe::Event => &mut self.incoming_events,
                        Pipe::Acl => &mut self.incoming_acl,
                    }
                    .push_back(event);
                }
            }
        }
        fn transfer(&mut self, dci: usize) {
            self.indices[dci] %= RING_TRBS - 1;
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
                let mut received = length;
                let data = if length == 0 {
                    if request[0] == 0 && request[1] == SET_CONFIGURATION {
                        self.configuration_value = request[2];
                    }
                    Vec::new()
                } else {
                    // SAFETY: the next Data TRB's buffer is live through this
                    // synchronous modeled control completion.
                    let next = self.rings[dci]
                        + (((self.indices[dci] + 1) % (RING_TRBS - 1)) * TRB) as u64;
                    let buffer = unsafe { (next as *const u64).read_volatile() };
                    if request[0] == 0x80
                        && request[1] == GET_DESCRIPTOR
                        && let Some((_, _, bytes)) = self
                            .descriptors
                            .iter()
                            .find(|(kind, index, _)| (*kind, *index) == (request[3], request[2]))
                    {
                        received = bytes.len().min(length);
                        // SAFETY: buffer has the requested length and the
                        // device writes only that bounded response.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                buffer as *mut u8,
                                received,
                            );
                        }
                    }
                    if request[0] == 0xa1 && !self.control_replies.is_empty() {
                        let (expected, reply) = self.control_replies.pop_front().unwrap();
                        assert_eq!(request, expected);
                        received = reply.len();
                        assert!(received <= length);
                        // SAFETY: this synchronous device reply fits the live
                        // Data TRB allocation, retained through completion.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                reply.as_ptr(),
                                buffer as *mut u8,
                                received,
                            );
                        }
                    }
                    if request[1] == 5
                        && matches!(request[0], 0xc0 | 0x40)
                        && (self.ethernet.is_some() || self.ethernet_upload.is_some())
                    {
                        let output = if request[0] == 0x40 {
                            // SAFETY: Data TRB refers to the live control buffer.
                            unsafe { core::slice::from_raw_parts(buffer as *const u8, length) }
                        } else {
                            &[]
                        };
                        let reply = if let Some(ethernet) = &mut self.ethernet {
                            ethernet.request(request, output).unwrap()
                        } else {
                            self.ethernet_upload
                                .as_mut()
                                .unwrap()
                                .request(request, output)
                                .unwrap()
                        };
                        if request[0] == 0xc0 {
                            received = reply.len();
                            assert!(received <= length);
                            // SAFETY: reply is bounded by this TD's requested buffer.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    reply.as_ptr(),
                                    buffer as *mut u8,
                                    received,
                                );
                            }
                        }
                    }
                    if request[0] & 0x80 == 0 && self.short_control_out {
                        received = length - 1;
                    }
                    unsafe { core::slice::from_raw_parts(buffer as *const u8, length).to_vec() }
                };
                if request[0] & 0x80 == 0 && request[1] != SET_CONFIGURATION {
                    self.scripted(false, &data);
                }
                self.setup.push((request, data));
                let trbs = if length == 0 { 2 } else { 3 };
                if self.stall_control == Some(request[1]) {
                    self.set_state(dci, ENDPOINT_HALTED);
                    self.active[dci] = Some((at, 0, length));
                    self.event(at, STALL, TRANSFER_EVENT, dci as u8, 0);
                    return;
                }
                if self.silence_transfer == Some(dci) || self.silence_control == Some(request[1]) {
                    self.active[dci] = Some((at, 0, length));
                } else {
                    if received < length {
                        self.event(
                            self.rings[dci]
                                + (((self.indices[dci] + 1) % (RING_TRBS - 1)) * TRB) as u64,
                            SHORT_PACKET,
                            TRANSFER_EVENT,
                            1,
                            length - received,
                        );
                    }
                    self.event(
                        self.rings[dci]
                            + (((self.indices[dci] + trbs as usize - 1) % (RING_TRBS - 1)) * TRB)
                                as u64,
                        SUCCESS,
                        TRANSFER_EVENT,
                        1,
                        0,
                    );
                }
                self.indices[dci] += trbs as usize;
            } else {
                self.indices[dci] += 1;
                if dci == 4 {
                    // SAFETY: the submitted bulk OUT buffer is live until the
                    // completion below acknowledges its bytes.
                    let packet = unsafe {
                        core::slice::from_raw_parts(parameter as *const u8, length).to_vec()
                    };
                    self.scripted(true, &packet);
                    self.outgoing.push(packet);
                    if self.silence_transfer == Some(dci) {
                        self.active[dci] = Some((at, parameter, length));
                    } else {
                        let short = self.short_bulk_out && length != 0;
                        self.event(
                            at,
                            if short { SHORT_PACKET } else { SUCCESS },
                            TRANSFER_EVENT,
                            dci as u8,
                            usize::from(short),
                        );
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
    fn unconfigured_cancellation_controller(
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
            context_bytes: 32,
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
            script: None,
            descriptors: Vec::new(),
            configuration_value: 0,
            configuration_seen_before_endpoints: Vec::new(),
            short_control_out: false,
            control_replies: Default::default(),
            stall_control: None,
            silence_control: None,
            short_bulk_out: false,
            ethernet: None,
            ethernet_upload: None,
        }));
        model.borrow_mut().set_state(1, 1);
        controller.registers = Box::new(CancelRegisters(model.clone()));
        // A short actual test deadline without pretending any completion happened.
        controller.clock.ticks_per_microsecond = 1;
        (controller, model)
    }

    fn cancellation_controller(
        dma: &mut dyn DmaAllocator,
    ) -> (Controller, Rc<RefCell<CancelModel>>) {
        let (mut controller, model) = unconfigured_cancellation_controller(dma);
        controller.set_configuration(1, 1).unwrap();
        let endpoints = [
            Endpoint {
                address: 0x81,
                attributes: 3,
                max_packet: 16,
                interval: 1,
                companion: None,
            },
            Endpoint {
                address: 0x82,
                attributes: 2,
                max_packet: 64,
                interval: 0,
                companion: None,
            },
            Endpoint {
                address: 0x02,
                attributes: 2,
                max_packet: 64,
                interval: 0,
                companion: None,
            },
        ];
        controller.configure(1, &endpoints, None, dma).unwrap();
        model.borrow_mut().seen.clear();
        (controller, model)
    }

    fn cdc_device(ncm: Option<u8>) -> Device {
        let mut bytes = configuration::tests::ecm(42);
        if let Some(capabilities) = ncm {
            bytes[15] = cdc::NCM;
            bytes.splice(18..18, [6, 0x24, 0x1a, 0, 1, capabilities]);
        }
        let mut at = 0;
        while at < bytes.len() {
            let length = usize::from(bytes[at]);
            if bytes[at + 1] == ENDPOINT_DESCRIPTOR {
                // Reuse the model's actual event/ACL receive queues as the
                // CDC notification and data endpoints, respectively.
                if bytes[at + 3] & 3 == 3 {
                    bytes[at + 2] = 0x81;
                } else if bytes[at + 2] & 0x80 != 0 {
                    bytes[at + 2] = 0x82;
                }
            }
            at += length;
        }
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        configuration::validate(&bytes).unwrap();
        let mut device = configuration::tests::device(vec![bytes]);
        configuration::select(&mut device).unwrap();
        device
    }

    fn cdc_mac_descriptor() -> Vec<u8> {
        let mut bytes = vec![26, STRING_DESCRIPTOR];
        for unit in "025354000001".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn ncm_parameters() -> Vec<u8> {
        let mut bytes = vec![0; 28];
        bytes[..2].copy_from_slice(&28u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&32768u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2048u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&8u16.to_le_bytes());
        // Ethernet payload (14 bytes after its frame start) is 8-byte aligned.
        // The resulting frame start at 34 makes a 30-byte frame a 64-byte NTB.
        bytes[22..24].copy_from_slice(&0u16.to_le_bytes());
        bytes[24..26].copy_from_slice(&8u16.to_le_bytes());
        bytes
    }

    #[test]
    fn cdc_short_bulk_out_is_an_error_and_never_sends_a_terminating_zlp() {
        use crate::net::Link;
        for ncm in [None, Some(1)] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller(&mut dma);
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            if ncm.is_some() {
                model
                    .borrow_mut()
                    .control_replies
                    .push_back((setup(0xa1, 0x80, 0, 0, 28), ncm_parameters()));
            }
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, cdc_device(ncm), &mut dma, &mut found);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.links.len(), 1);
            let link = &mut found.links[0];
            let frame = vec![0x5a; if ncm.is_some() { 30 } else { 64 }];
            model.borrow_mut().short_bulk_out = true;
            assert!(link.transmit(&frame).is_err());
            assert_eq!(model.borrow().outgoing.len(), 1);
            assert_eq!(model.borrow().outgoing[0].len(), 64);
            model.borrow_mut().short_bulk_out = false;
            link.transmit(&frame).unwrap();
            assert_eq!(model.borrow().outgoing.len(), 3);
            assert_eq!(model.borrow().outgoing[1].len(), 64);
            assert!(model.borrow().outgoing[2].is_empty());
        }
    }

    #[test]
    fn ncm_binding_negotiates_before_alt_setting_and_moves_real_transfer_blocks() {
        use crate::net::{Link, Mac};
        let cases = [0, 1, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31]
            .into_iter()
            .flat_map(|capabilities| {
                [1u16, 3].into_iter().flat_map(move |formats| {
                    [16384u32, 32768]
                        .into_iter()
                        .map(move |in_max| (capabilities, formats, in_max))
                })
            });
        for (capabilities, formats, in_max) in cases {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller(&mut dma);
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            let mut parameters = ncm_parameters();
            parameters[2..4].copy_from_slice(&formats.to_le_bytes());
            parameters[4..8].copy_from_slice(&in_max.to_le_bytes());
            model
                .borrow_mut()
                .control_replies
                .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(
                &shared,
                cdc_device(Some(capabilities)),
                &mut dma,
                &mut found,
            );
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.links.len(), 1);
            let mut expected = vec![
                setup(0, SET_CONFIGURATION, 42, 0, 0),
                setup(0x80, GET_DESCRIPTOR, 0x301, LANGUAGE_EN_US, 255),
                setup(0xa1, 0x80, 0, 0, 28),
            ];
            if capabilities & 0x10 != 0 {
                expected.push(setup(0x21, 0x8a, 0, 0, 0));
            }
            if formats & 2 != 0 {
                expected.push(setup(0x21, 0x84, 0, 0, 0));
            }
            if in_max > 16384 {
                expected.push(setup(
                    0x21,
                    0x86,
                    0,
                    0,
                    if capabilities & 0x20 != 0 { 8 } else { 4 },
                ));
            }
            expected.push(setup(1, SET_INTERFACE, 3, 1, 0));
            if capabilities & 1 != 0 {
                expected.push(setup(0x21, 0x43, 0x0e, 0, 0));
            }
            assert_eq!(
                model
                    .borrow()
                    .setup
                    .iter()
                    .map(|(request, _)| *request)
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(model.borrow().control_replies.is_empty());
            let mut size = 16384u32.to_le_bytes().to_vec();
            if capabilities & 0x20 != 0 {
                size.extend_from_slice(&[0; 4]);
            }
            let model_ref = model.borrow();
            let size_command = model_ref
                .setup
                .iter()
                .find(|(request, _)| request[1] == 0x86);
            if in_max > 16384 {
                assert_eq!(size_command.unwrap().1, size);
            } else {
                assert!(size_command.is_none());
            }
            drop(model_ref);
            let link = &mut found.links[0];
            assert_eq!(link.mac(), Mac([2, 0x53, 0x54, 0, 0, 1]));
            let frame: Vec<_> = (0..30).collect();
            link.transmit(&frame).unwrap();
            let mut block = b"NCMH\x0c\x00\x00\x00\x40\x00\x10\x00\x00\x00\x00\x00NCM0\x10\x00\x00\x00\x22\x00\x1e\x00\x00\x00\x00\x00\x00\x00".to_vec();
            block.extend_from_slice(&frame);
            assert_eq!(model.borrow().outgoing, [block.clone(), Vec::new()]);
            model.borrow_mut().incoming_acl.push_back(block);
            assert_eq!(link.receive().unwrap(), Some(frame));
            assert_eq!(link.receive().unwrap(), None);
            // The next transfer is malformed and is dropped whole.
            model.borrow_mut().incoming_acl.push_back(b"NCMX".to_vec());
            assert_eq!(link.receive().unwrap(), None);
            for connected in [false, true] {
                model.borrow_mut().incoming_events.push_back(vec![
                    0xa1,
                    0,
                    u8::from(connected),
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
                assert_eq!(link.carrier(), connected);
            }
        }
    }

    #[test]
    fn ncm_mode_changes_require_real_status_acknowledgements_before_data_activation() {
        for request in [0x8a, 0x84] {
            for stall in [false, true] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: backing outlives all modeled controller/class DMA.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (controller, model) = unconfigured_cancellation_controller(&mut dma);
                model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
                let mut parameters = ncm_parameters();
                parameters[2] = 3;
                model
                    .borrow_mut()
                    .control_replies
                    .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
                if stall {
                    model.borrow_mut().stall_control = Some(request);
                } else {
                    model.borrow_mut().silence_control = Some(request);
                }
                let shared = Rc::new(RefCell::new(controller));
                let mut found = Found::default();
                bind(&shared, cdc_device(Some(0x31)), &mut dma, &mut found);
                assert!(found.links.is_empty());
                assert_eq!(found.failures.len(), 1);
                assert!(match &found.failures[0].1 {
                    BlockError::Device { status } => stall && *status == STALL,
                    BlockError::Timeout => !stall,
                    _ => false,
                });
                let model = model.borrow();
                assert_eq!(model.setup.last().unwrap().0, setup(0x21, request, 0, 0, 0));
                assert!(
                    !model
                        .setup
                        .iter()
                        .any(|(setup, _)| matches!(setup[1], SET_INTERFACE | 0x43 | 0x86))
                );
                assert!(model.outgoing.is_empty());
                assert!(model.active[1].is_none(), "failed EP0 TD must be cancelled");
                assert!(model.seen.contains(&SET_DEQUEUE));
            }
        }
    }

    #[test]
    fn malformed_parameters_and_short_size_commands_abort_before_ncm_data_activation() {
        for failure in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller(&mut dma);
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            let mut parameters = ncm_parameters();
            match failure {
                0 => parameters.truncate(22),
                1 => parameters[2] = 2,
                2 => model.borrow_mut().short_control_out = true,
                _ => unreachable!(),
            }
            model
                .borrow_mut()
                .control_replies
                .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, cdc_device(Some(0x21)), &mut dma, &mut found);
            assert_eq!(found.failures.len(), 1);
            assert!(found.links.is_empty());
            assert!(
                !model
                    .borrow()
                    .setup
                    .iter()
                    .any(|(request, _)| request[1] == SET_INTERFACE || request[1] == 0x43)
            );
            assert!(model.borrow().outgoing.is_empty());
        }
    }

    #[test]
    fn all_configuration_indices_travel_through_ep0_and_selection_uses_the_wire_value() {
        use configuration::tests::{device, ecm, vendor};
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains live and exclusive through all modeled DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        let originals = vec![vendor(9), ecm(42), vendor(5)];
        model.borrow_mut().descriptors = originals
            .iter()
            .enumerate()
            .map(|(index, bytes)| (CONFIGURATION_DESCRIPTOR, index as u8, bytes.clone()))
            .collect();
        let inventory = controller.configurations(1, 3).unwrap();
        assert_eq!(inventory, originals);
        let mut device = device(inventory);
        configuration::select(&mut device).unwrap();
        assert_eq!(device.configuration_value(), 42);
        assert_eq!(
            model
                .borrow()
                .setup
                .iter()
                .map(|(request, _)| request[2])
                .collect::<Vec<_>>(),
            vec![0, 0, 1, 1, 2, 2]
        );
        let all = interfaces(&device.configuration);
        let plan = configuration::plan(&device, &all[0], &all).unwrap();
        assert!(
            controller
                .configure(1, &plan.endpoints(), None, &mut dma)
                .is_err()
        );
        assert!(model.borrow().seen.is_empty());
        controller
            .set_configuration(1, device.configuration_value())
            .unwrap();
        controller
            .configure(1, &plan.endpoints(), None, &mut dma)
            .unwrap();
        assert_eq!(controller.current_configuration(1), Ok(Some(42)));
        assert_eq!(model.borrow().configuration_seen_before_endpoints, vec![42]);
        assert_eq!(
            model.borrow().setup.last().unwrap().0,
            setup(0, SET_CONFIGURATION, 42, 0, 0)
        );
        let requests = model.borrow().setup.len();
        controller.set_configuration(1, 42).unwrap(); // Another class binder must not reset the device.
        assert_eq!(model.borrow().setup.len(), requests);
        assert!(controller.set_configuration(1, 9).is_err());
        assert!(
            controller
                .control(1, setup(0, SET_CONFIGURATION, 42, 0, 0), &[])
                .is_err()
        );
        assert_eq!(model.borrow().setup.len(), requests);
        assert_eq!(controller.current_configuration(1), Ok(Some(42)));
    }

    #[test]
    fn descriptor_inventory_refuses_truncation_duplicate_values_and_silent_size_caps() {
        use configuration::tests::vendor;
        for scenario in 0..5 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive live test backing holds all rings and buffers.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            let mut bytes = vendor(7);
            match scenario {
                0 => {
                    bytes.pop();
                }
                1 => {
                    bytes[2..4].copy_from_slice(&4097u16.to_le_bytes());
                }
                2 => {
                    bytes[5] = 0;
                }
                3 => {
                    bytes[2..4].copy_from_slice(&8u16.to_le_bytes());
                }
                _ => {}
            }
            model.borrow_mut().descriptors = vec![
                (CONFIGURATION_DESCRIPTOR, 0, bytes.clone()),
                (CONFIGURATION_DESCRIPTOR, 1, bytes),
            ];
            let error = controller.configurations(1, 2).unwrap_err();
            assert!(matches!(error.1, BlockError::Unsupported(_)), "{error:?}");
            assert_eq!(controller.current_configuration(1), Ok(Some(0)));
            assert!(model.borrow().seen.is_empty());
            if scenario == 1 || scenario == 3 {
                assert_eq!(model.borrow().setup.len(), 1); // Reject before requesting capped/full bytes.
            }
        }
    }

    #[test]
    fn configuration_inventory_has_an_explicit_aggregate_resource_limit() {
        use configuration::tests::vendor;
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: this exclusive allocation remains live for every DMA access.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        for index in 0..17 {
            let mut bytes = vendor(index + 1);
            while bytes.len() < CONTROL_BYTES {
                bytes.extend_from_slice(&[2, 0x25]); // Preserved unknown class descriptors.
            }
            bytes[2..4].copy_from_slice(&(CONTROL_BYTES as u16).to_le_bytes());
            model
                .borrow_mut()
                .descriptors
                .push((CONFIGURATION_DESCRIPTOR, index, bytes));
        }
        assert_eq!(
            controller.configurations(1, 17).unwrap_err().1,
            BlockError::Unsupported("USB configuration inventory exceeds 64 KiB")
        );
        assert_eq!(model.borrow().setup.len(), 34);
        assert_eq!(controller.current_configuration(1), Ok(Some(0)));
        assert!(model.borrow().seen.is_empty());
    }

    #[test]
    fn unacknowledged_configuration_never_activates_endpoints_or_reuses_poisoned_ep0() {
        for scenario in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive backing outlives controller and hardware model.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            if scenario == 0 {
                model.borrow_mut().halt_transfer = Some(1);
            } else {
                model.borrow_mut().silence_transfer = Some(1);
                if scenario == 2 {
                    model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
                }
            }
            assert!(controller.set_configuration(1, 42).is_err());
            assert_eq!(controller.current_configuration(1), Ok(None));
            let endpoint = fixture_endpoint(3);
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
            let request_count = model.borrow().setup.len();
            model.borrow_mut().halt_transfer = None;
            model.borrow_mut().silence_transfer = None;
            if scenario == 2 {
                let ring = controller.slots[1].as_ref().unwrap().endpoints[1]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes()
                    .to_vec();
                assert!(controller.set_configuration(1, 42).is_err());
                assert_eq!(model.borrow().setup.len(), request_count);
                assert_eq!(
                    controller.slots[1].as_ref().unwrap().endpoints[1]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .bytes(),
                    ring
                );
            } else {
                controller.set_configuration(1, 42).unwrap();
                assert_eq!(controller.current_configuration(1), Ok(Some(42)));
            }
        }
    }

    #[test]
    fn failed_endpoint_configuration_retains_rings_without_exposing_or_replacing_them() {
        for missing_completion in [false, true] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing is live/exclusive through every retained DMA ring.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            controller.set_configuration(1, 42).unwrap();
            if missing_completion {
                model.borrow_mut().silence = Some(CONFIGURE_ENDPOINT);
            } else {
                model.borrow_mut().fail = Some((CONFIGURE_ENDPOINT, 7));
            }
            let endpoint = fixture_endpoint(3);
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert!(!transfer.enabled);
            assert!(transfer.poisoned);
            let address = transfer.ring.buffer.physical();
            let bytes = transfer.ring.buffer.bytes().to_vec();
            let commands = model.borrow().seen.len();
            assert!(controller.submit(1, 3, address, 16).is_err());
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert_eq!(transfer.ring.buffer.physical(), address);
            assert_eq!(transfer.ring.buffer.bytes(), bytes);
            assert_eq!(model.borrow().seen.len(), commands);
        }
    }

    #[test]
    fn acknowledged_zero_configuration_returns_to_address_state_without_endpoint_activation() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains live and exclusive through controller/model use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        controller.set_configuration(1, 42).unwrap();
        for malformed in [
            setup(0, SET_CONFIGURATION, 0x100, 0, 0),
            setup(0, SET_CONFIGURATION, 0, 1, 0),
            setup(0, SET_CONFIGURATION, 0, 0, 1),
        ] {
            assert!(controller.control(1, malformed, &[]).is_err());
        }
        assert_eq!(controller.current_configuration(1), Ok(Some(42)));
        assert_eq!(model.borrow().setup.len(), 1);
        controller.set_configuration(1, 0).unwrap();
        assert_eq!(controller.current_configuration(1), Ok(Some(0)));
        assert_eq!(model.borrow().configuration_value, 0);
        assert!(
            controller
                .configure(1, &[fixture_endpoint(3)], None, &mut dma)
                .is_err()
        );
        assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
        assert!(model.borrow().seen.is_empty());
    }

    #[test]
    fn refused_superspeed_plan_preserves_inventory_without_configuration_or_dma() {
        for streams in [false, true] {
            let mut configuration = vec![
                9, 2, 0, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 4, 0,
            ];
            if streams {
                configuration.extend_from_slice(&[6, SS_ENDPOINT_COMPANION, 0, 1, 0, 0]);
            }
            configuration.extend_from_slice(&[7, 5, 2, 2, 0, 4, 0]);
            if streams {
                configuration.extend_from_slice(&[6, SS_ENDPOINT_COMPANION, 0, 0, 0, 0]);
            }
            let total = configuration.len() as u16;
            configuration[2..4].copy_from_slice(&total.to_le_bytes());
            configuration::validate(&configuration).unwrap();
            let mut device = configuration::tests::device(vec![configuration.clone()]);
            device.speed = SUPER_SPEED;
            configuration::select(&mut device).unwrap();
            assert_eq!(device.configuration, configuration);
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing stays exclusive/live throughout model and controller access.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller(&mut dma);
            let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, device, &mut dma, &mut found);
            assert!(found.failures.is_empty());
            assert_eq!(found.unused.len(), 1);
            assert!(model.borrow().setup.is_empty() && model.borrow().seen.is_empty());
            let controller = shared.borrow();
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(slot.input.bytes(), input);
            assert!(slot.endpoints[2..].iter().all(Option::is_none));
            assert_eq!(slot.current_configuration, Some(0));
        }
    }

    #[test]
    fn superspeed_companions_reach_real_32_and_64_byte_controller_contexts() {
        for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
            for context in [32, 64] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: backing outlives every model and controller DMA object.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
                controller.set_configuration(1, 7).unwrap();
                controller.context_bytes = context;
                let slot = controller.slots[1].as_mut().unwrap();
                slot.speed = speed;
                slot.context[0] = slot.context[0] & !(15 << 20) | u32::from(speed) << 20;
                slot.input = dma.allocate(33 * context, 64).unwrap();
                slot._output = dma.allocate(32 * context, 64).unwrap();
                model.borrow_mut().output = slot._output.physical();
                model.borrow_mut().context_bytes = context;
                model.borrow_mut().set_state(1, 1);
                controller.dcbaa.write(8, slot._output.physical());
                let endpoints = [
                    Endpoint {
                        address: 0x81,
                        attributes: 2,
                        max_packet: 1024,
                        interval: 0,
                        companion: Some(SuperSpeedCompanion {
                            max_burst: 7,
                            attributes: 0,
                            bytes_per_interval: 0,
                        }),
                    },
                    Endpoint {
                        address: 0x02,
                        attributes: 3,
                        max_packet: 64,
                        interval: 4,
                        companion: Some(SuperSpeedCompanion {
                            max_burst: 3,
                            attributes: 0,
                            bytes_per_interval: 37,
                        }),
                    },
                ];
                controller.configure(1, &endpoints, None, &mut dma).unwrap();
                let slot = controller.slots[1].as_ref().unwrap();
                for (ep, expected) in endpoints.iter().zip([
                    [0, 1024 << 16 | 7 << 8 | 6 << 3 | 6, 3072],
                    [3 << 16, 64 << 16 | 3 << 8 | 3 << 3 | 6, 37 << 16 | 37],
                ]) {
                    let dci = usize::from(ep.dci());
                    let at = (dci + 1) * context;
                    assert_eq!(slot.input.read::<u32>(at), expected[0]);
                    assert_eq!(slot.input.read::<u32>(at + 4), expected[1]);
                    assert_eq!(slot.input.read::<u32>(at + 16), expected[2]);
                    let transfer = slot.endpoints[dci].as_ref().unwrap();
                    assert!(transfer.enabled);
                    assert_eq!(
                        slot.input.read::<u64>(at + 8) & !15,
                        model.borrow().rings[dci]
                    );
                    assert_eq!(model.borrow().state(dci), ENDPOINT_RUNNING);
                    // All unused/reserved words stay zero at either CSZ.
                    assert!(
                        slot.input.bytes()[at + 20..at + context]
                            .iter()
                            .all(|b| *b == 0)
                    );
                }
                assert_eq!(model.borrow().seen, [CONFIGURE_ENDPOINT]);
                assert_eq!(model.borrow().configuration_seen_before_endpoints, [7]);
                for ep in &endpoints {
                    controller.cancel(1, ep.dci()).unwrap();
                }
            }
        }
    }

    #[test]
    fn invalid_superspeed_companion_refuses_before_any_dma_publication() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains exclusive and live throughout model DMA use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        controller.set_configuration(1, 7).unwrap();
        controller.slots[1].as_mut().unwrap().speed = SUPER_SPEED;
        let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
        let commands = controller.commands.buffer.bytes().to_vec();
        let good = Endpoint {
            address: 0x81,
            attributes: 2,
            max_packet: 1024,
            interval: 0,
            companion: Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 0,
                bytes_per_interval: 0,
            }),
        };
        for companion in [
            None,
            Some(SuperSpeedCompanion {
                max_burst: 16,
                attributes: 0,
                bytes_per_interval: 0,
            }),
            Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 1,
                bytes_per_interval: 0,
            }),
            Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 0,
                bytes_per_interval: 1,
            }),
        ] {
            let mut bad = good;
            bad.address = 2;
            bad.companion = companion;
            // A valid endpoint first must not publish its ring before its invalid peer.
            assert!(
                controller
                    .configure(1, &[good, bad], None, &mut dma)
                    .is_err()
            );
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(slot.input.bytes(), input);
            assert_eq!(controller.commands.buffer.bytes(), commands);
            assert!(slot.endpoints[3].is_none() && slot.endpoints[4].is_none());
            assert!(model.borrow().seen.is_empty());
        }
        // The acknowledged EP0 lifecycle stays usable after descriptor refusal.
        controller.set_configuration(1, 9).unwrap();
        assert_eq!(controller.current_configuration(1), Ok(Some(9)));
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
                companion: None,
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
    fn short_control_out_after_status_ack_fails_without_poisoning_completed_endpoint() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all model DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        model.borrow_mut().short_control_out = true;
        let request = setup(0x40, 5, 0xe810, 0x0188, 4);
        assert_eq!(
            controller.control(1, request, &[0; 4]),
            Err(BlockError::Unsupported("short USB control OUT transfer"))
        );
        assert!(controller.endpoint_ready(1, 1).is_ok());
        assert_eq!(model.borrow().indices[1], 3);
        assert!(model.borrow().seen.is_empty());
        model.borrow_mut().short_control_out = false;
        assert!(controller.control(1, request, &[0; 4]).is_ok());
        assert_eq!(model.borrow().indices[1], 6);
        assert!(model.borrow().active[1].is_none());
    }

    #[test]
    fn rtl8152b_binds_real_xhci_dma_moves_aggregates_wraps_and_quiesces() {
        use crate::net::Link;
        for (revision, scenario) in [0x4c00, 0x4c10, 0x4800]
            .into_iter()
            .flat_map(|r| (0..4).map(move |s| (r, s)))
        {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives every controller/device/model DMA object.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            controller.slots[1].as_mut().unwrap().speed = HIGH_SPEED;
            model.borrow_mut().ethernet = Some(ethernet::rtl815x::tests::Model::new(revision));
            let configuration = vec![
                9, 2, 32, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 0, 2,
                0, 7, 5, 0x02, 2, 0, 2, 0,
            ];
            let mut device = configuration::tests::device(vec![configuration]);
            device.speed = HIGH_SPEED;
            device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x52, 0x81]);
            controller.preflight_vendor_ethernet(&mut device).unwrap();
            assert_eq!(device.vendor_ethernet_revision, Some(revision));
            assert_eq!(
                device.vendor_ethernet_tcr,
                Some((u32::from(revision) << 16) | 0x0800)
            );
            configuration::select(&mut device).unwrap();
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, device, &mut dma, &mut found);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.vendor_links.len(), 1);
            assert_eq!(model.borrow().configuration_seen_before_endpoints, [7]);
            let mut link = found.vendor_links.pop().unwrap();
            assert_eq!(link.mac().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
            assert!(link.carrier());
            for value in 0..300 {
                link.transmit(&[value as u8; 60]).unwrap();
            }
            assert_eq!(model.borrow().outgoing.len(), 300);
            let packet = model.borrow().outgoing[299].clone();
            assert_eq!(&packet[..8], &[60, 0, 0, 0xc0, 0, 0, 0, 0]);
            assert_eq!(&packet[8..], &[299u16 as u8; 60]);
            assert_eq!(link.receive().unwrap(), None);
            assert!(model.borrow().active[3].is_some());
            let mut aggregate = vec![0; 176];
            aggregate[..4].copy_from_slice(&64u32.to_le_bytes());
            aggregate[24..84].fill(0x5a);
            aggregate[88..92].copy_from_slice(&64u32.to_le_bytes());
            aggregate[112..172].fill(0x6a);
            model.borrow_mut().incoming_events.push_back(aggregate);
            assert_eq!(link.receive().unwrap(), Some(vec![0x5a; 60]));
            assert_eq!(link.receive().unwrap(), Some(vec![0x6a; 60]));
            assert_eq!(link.receive().unwrap(), None);
            match scenario {
                0 => {
                    model.borrow_mut().ethernet.as_mut().unwrap().link = false;
                    assert!(!link.carrier());
                    assert!(model.borrow().active[3].is_none());
                    model.borrow_mut().ethernet.as_mut().unwrap().link = true;
                    assert!(link.carrier());
                    link.transmit(&[1; 60]).unwrap();
                    link.stop().unwrap();
                    assert!(link.transmit(&[2; 60]).is_err());
                }
                1 => {
                    model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
                    assert!(link.stop().is_err());
                    assert!(model.borrow().active[3].is_some());
                    assert!(link.receive().is_err());
                    assert!(link.transmit(&[0; 60]).is_err());
                }
                2 => {
                    model.borrow_mut().connected = false;
                    assert!(!link.carrier());
                    assert!(link.receive().is_err());
                    assert!(link.transmit(&[0; 60]).is_err());
                    // Disconnect is not proof of DMA quiescence.
                    assert!(model.borrow().active[3].is_some());
                }
                _ => {
                    model.borrow_mut().halt_transfer = Some(4);
                    model.borrow_mut().fail = Some((SET_DEQUEUE, CONTEXT_STATE_ERROR));
                    assert!(link.transmit(&[0x77; 60]).is_err());
                    let state = model.borrow();
                    let at = state.rings[4] + (state.indices[4] * TRB) as u64;
                    // SAFETY: the failed TD remains in the live ring.
                    let (buffer, bytes) = unsafe {
                        (
                            (at as *const u64).read_volatile(),
                            ((at + 8) as *const u32).read_volatile() as usize & 0x1ffff,
                        )
                    };
                    drop(state);
                    // SAFETY: model performs no DMA here; hardware still owns
                    // this sentinel and the next attempt must not mutate it.
                    let before =
                        unsafe { core::slice::from_raw_parts(buffer as *const u8, bytes).to_vec() };
                    assert!(link.transmit(&[0x88; 60]).is_err());
                    assert_eq!(
                        unsafe { core::slice::from_raw_parts(buffer as *const u8, bytes) },
                        before
                    );
                }
            }
        }
    }

    #[test]
    fn rtl815x_firmware_uses_actual_ep0_dma_wrapping_and_poison_guards() {
        use ethernet::{
            firmware::{Firmware, tests::synthetic_upload},
            rtl815x::{Chip, FirmwareModel, Revision},
        };
        for revision in [
            0x5c10, 0x5c20, 0x5c30, 0x6010, 0x6400, 0x7030, 0x7410, 0x7420,
        ] {
            let bytes = synthetic_upload(revision);
            let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
            for fail in [false, true] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: backing outlives all real control/ring DMA and model access.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
                controller.set_configuration(1, 7).unwrap();
                model.borrow_mut().ethernet_upload = Some(FirmwareModel::new(revision, &bytes));
                let shared = Rc::new(RefCell::new(controller));
                let io = ethernet::HostControl {
                    controller: shared.clone(),
                    slot: 1,
                };
                let mut chip = Chip::probe(io, Revision(revision)).unwrap();
                if fail {
                    model.borrow_mut().silence_transfer = Some(1);
                    model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
                    assert!(chip.upload_firmware(&firmware, false).is_err());
                    assert!(shared.borrow_mut().endpoint_ready(1, 1).is_err());
                    let control = shared.borrow().slots[1]
                        .as_ref()
                        .unwrap()
                        .control
                        .bytes()
                        .to_vec();
                    let requests = model.borrow().setup.len();
                    assert!(chip.upload_firmware(&firmware, false).is_err());
                    assert_eq!(model.borrow().setup.len(), requests);
                    assert_eq!(
                        shared.borrow().slots[1].as_ref().unwrap().control.bytes(),
                        control
                    );
                } else {
                    chip.upload_firmware(&firmware, false).unwrap();
                    assert!(chip.carrier().is_err()); // Upload alone is not initialized PHY/MAC.
                    let state = model.borrow();
                    assert_eq!(state.configuration_value, 7);
                    assert!(state.configuration_seen_before_endpoints.is_empty());
                    assert!(
                        state
                            .setup
                            .iter()
                            .any(|(request, data)| request[0] == 0x40 && data.len() > 4)
                    );
                    assert!(state.setup.iter().all(|(_, data)| data.len() <= 512));
                    assert!(state.active[1].is_none());
                }
            }
        }
    }

    #[test]
    fn rtl8153_missing_exact_firmware_never_creates_a_native_link() {
        for revision in [
            0x5c10, 0x5c20, 0x5c30, 0x6010, 0x6400, 0x7030, 0x7410, 0x7420,
        ] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing remains exclusive/live through all controller DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            controller.slots[1].as_mut().unwrap().speed = HIGH_SPEED;
            let config = vec![
                9, 2, 32, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 0, 2,
                0, 7, 5, 2, 2, 0, 2, 0,
            ];
            let mut dev = configuration::tests::device(vec![config]);
            dev.speed = HIGH_SPEED;
            let is_8156 = ethernet::rtl815x::Revision(revision).is_8156();
            dev.descriptor[8..14].copy_from_slice(&[
                0xda,
                0x0b,
                if is_8156 { 0x56 } else { 0x53 },
                0x81,
                0x00,
                0x30,
            ]);
            dev.vendor_ethernet_revision = Some(revision);
            configuration::select(&mut dev).unwrap();
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, dev, &mut dma, &mut found);
            assert!(found.vendor_links.is_empty() && found.failures.is_empty());
            assert_eq!(found.vendor_failures.len(), 1);
            let ethernet::Error::Firmware { request, .. } = &found.vendor_failures[0].1 else {
                panic!("{:?}", found.vendor_failures)
            };
            assert_eq!(
                request.name,
                ethernet::rtl815x::Revision(revision).firmware().unwrap()
            );
            assert_eq!(
                request.hardware,
                if is_8156 {
                    "usb:0bda:8156:3000"
                } else {
                    "usb:0bda:8153:3000"
                }
            );
            assert_eq!(request.revision, format!("tcr-{revision:04x}"));
            assert!(model.borrow().active[3].is_none() && model.borrow().outgoing.is_empty());
        }
    }

    #[test]
    fn rtl8153_native_usb2_usb3_binding_uploads_exact_provider_and_retains_owned_receipt() {
        use crate::{
            firmware::{Catalog, Provenance, Provider, Resource, Target},
            net::Link,
        };
        use sha2::{Digest, Sha256};
        struct Recording {
            catalog: Catalog,
            requests: RefCell<Vec<(String, String, String)>>,
        }
        impl Provider for Recording {
            fn load(
                &self,
                requirement: crate::firmware::Requirement<'_>,
            ) -> Result<crate::firmware::Image<'_>, crate::firmware::Error> {
                self.requests.borrow_mut().push((
                    requirement.name.into(),
                    requirement.target.hardware.into(),
                    requirement.target.revision.into(),
                ));
                self.catalog.load(requirement)
            }
        }
        for (revision, speed) in [
            0x5c00, 0x5c10, 0x5c20, 0x5c30, 0x6000, 0x6010, 0x6400, 0x7020, 0x7030, 0x7400, 0x7410,
            0x7420,
        ]
        .into_iter()
        .flat_map(|revision| {
            [HIGH_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS].map(|speed| (revision, speed))
        }) {
            let image = if matches!(revision, 0x5c00 | 0x6000 | 0x7020 | 0x7400) {
                Vec::new()
            } else {
                ethernet::firmware::tests::synthetic_upload(revision)
            };
            let is_8156 = ethernet::rtl815x::Revision(revision).is_8156();
            let hardware_label = if is_8156 {
                "usb:0bda:8156:3000"
            } else {
                "usb:0bda:8153:3000"
            };
            let name = ethernet::rtl815x::Revision(revision).firmware();
            let revision_label = format!("tcr-{revision:04x}");
            let digest: [u8; 32] = Sha256::digest(&image).into();
            let catalog = if let Some(name) = name {
                Catalog::from_handoff(vec![Resource {
                    name,
                    target: Target {
                        driver: "usb-rtl815x",
                        hardware: hardware_label,
                        revision: &revision_label,
                        board: None,
                    },
                    provenance: Provenance {
                        source: "source-model-fixture",
                        revision: "immutable-test",
                        member: name,
                        license: "synthetic",
                    },
                    expected_length: image.len(),
                    expected_sha256: digest,
                    bytes: image.clone(),
                }])
                .unwrap()
            } else {
                Catalog::from_handoff(Vec::new()).unwrap()
            };
            let provider = Recording {
                catalog,
                requests: RefCell::new(Vec::new()),
            };
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: all DMA objects/model references die before this backing.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            controller.slots[1].as_mut().unwrap().speed = speed;
            model.borrow_mut().ethernet_upload =
                Some(ethernet::rtl815x::FirmwareModel::new(revision, &image));
            let mut configuration = vec![
                9, 2, 32, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 0, 2,
                0, 7, 5, 0x02, 2, 0, 2, 0,
            ];
            if speed >= SUPER_SPEED {
                configuration = vec![
                    9,
                    2,
                    44,
                    0,
                    1,
                    7,
                    0,
                    0x80,
                    50,
                    9,
                    4,
                    0,
                    0,
                    2,
                    0xff,
                    0,
                    0,
                    0,
                    7,
                    5,
                    0x81,
                    2,
                    0,
                    4,
                    0,
                    6,
                    SS_ENDPOINT_COMPANION,
                    7,
                    0,
                    0,
                    0,
                    7,
                    5,
                    2,
                    2,
                    0,
                    4,
                    0,
                    6,
                    SS_ENDPOINT_COMPANION,
                    7,
                    0,
                    0,
                    0,
                ];
            }
            let mut device = configuration::tests::device(vec![configuration]);
            device.speed = speed;
            device.descriptor[8..14].copy_from_slice(&[
                0xda,
                0x0b,
                if is_8156 { 0x56 } else { 0x53 },
                0x81,
                0x00,
                0x30,
            ]);
            controller.preflight_vendor_ethernet(&mut device).unwrap();
            configuration::select(&mut device).unwrap();
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind_with_provider(&shared, device, &mut dma, &mut found, &provider);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert!(
                found.vendor_failures.is_empty(),
                "{:?}",
                found.vendor_failures
            );
            assert_eq!(found.vendor_links.len(), 1);
            assert_eq!(
                provider.requests.borrow().len(),
                usize::from(name.is_some())
            );
            let mut link = found.vendor_links.pop().unwrap();
            if let Some(name) = name {
                let receipt = link.firmware.as_ref().unwrap();
                assert_eq!(receipt.request.name, name);
                assert_eq!(receipt.request.hardware, hardware_label);
                assert_eq!(receipt.request.revision, revision_label);
                assert_eq!(receipt.sha256, digest);
                assert_eq!(receipt.length, image.len());
                assert_eq!(receipt.source_revision, "immutable-test");
            } else {
                assert!(link.firmware.is_none());
            }
            drop(provider); // Actual native link must not borrow the image/catalog.
            assert!(link.carrier());
            link.transmit(&[0x5a; 1514]).unwrap();
            assert_eq!(model.borrow().outgoing[0].len(), 1522);
            assert_eq!(link.receive().unwrap(), None);
            if is_8156 {
                let hw = model.borrow();
                let (_, address, length) = hw.active[3].unwrap();
                assert_eq!(address & 0xffff, 0);
                assert_eq!(length, 49152);
            }
            let frames = if is_8156 {
                32
            } else if speed >= SUPER_SPEED {
                21
            } else {
                1
            };
            let frame_size = if frames >= 21 { 1500 } else { 60 };
            let mut aggregate = Vec::new();
            for value in 0..frames {
                let mut packet = vec![0; 24 + frame_size + 4];
                packet[..4].copy_from_slice(&((frame_size + 4) as u32).to_le_bytes());
                packet[24..24 + frame_size].fill(value as u8);
                aggregate.extend(packet);
                aggregate.resize(aggregate.len().next_multiple_of(8), 0);
            }
            if frames >= 21 {
                assert!(aggregate.len() > 16384);
            }
            model.borrow_mut().incoming_events.push_back(aggregate);
            for value in 0..frames {
                assert_eq!(link.receive().unwrap(), Some(vec![value as u8; frame_size]));
            }
            link.stop().unwrap();
            assert!(link.transmit(&[0; 60]).is_err());
        }
    }

    #[test]
    fn bluetooth_binds_real_xhci_queues_moves_packets_and_stops_on_disconnect() {
        use crate::usb::bluetooth::{FirmwareStatus, Packet, State};
        for scenario in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: this boot-lifetime-style allocation outlives every model DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller(&mut dma);
            let shared: Shared = Rc::new(RefCell::new(controller));
            let mut device = Device {
                vendor_ethernet_revision: None,
                vendor_ethernet_tcr: None,
                slot: 1,
                speed: FULL_SPEED,
                location: "modeled physical HCI".into(),
                descriptor: [
                    18, 1, 0, 2, 0xe0, 1, 1, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1,
                ],
                configurations: Vec::new(),
                configuration: vec![
                    9, 2, 48, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3,
                    16, 0, 1, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0, 9, 4, 1, 0, 0,
                    0xe0, 1, 1, 0,
                ],
                manufacturer: None,
                product: None,
                serial: None,
            };
            device.configurations = vec![device.configuration.clone()];
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
    fn intel_initializer_uses_actual_xhci_dma_and_reframes_bulk_after_acknowledged_stop() {
        use crate::usb::bluetooth::{FirmwareStatus, Packet, intel};
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive model DMA stays live through all host endpoints.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = unconfigured_cancellation_controller(&mut dma);
        let shared: Shared = Rc::new(RefCell::new(controller));
        let (device, catalog, script) = intel::tests::fixture();
        let mut found = Found::default();
        bind(&shared, device, &mut dma, &mut found);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        let mut hci = found.bluetooth.pop().unwrap();
        model.borrow_mut().script = Some(script);
        let report = intel::initialize(&mut hci, &catalog).unwrap();
        assert!(report.after.is_operational());
        assert!(model.borrow().script.as_ref().unwrap().steps.is_empty());
        assert_eq!(model.borrow().outgoing.len(), 6);
        assert!(model.borrow().outgoing.iter().all(|p| p[..2] == [9, 0xfc]));
        // Entry cancels the idle posted bulk IN via Running Stop -> Stopped
        // Set Dequeue. Exit follows its completed boot-event TD; no hardware
        // ownership remains to cancel before restoring ordinary ACL framing.
        assert_eq!(
            model
                .borrow()
                .seen
                .iter()
                .filter(|&&kind| kind == STOP_ENDPOINT)
                .count(),
            1
        );
        assert_eq!(model.borrow().dequeues.len(), 1);
        assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
        assert!(hci.poll().unwrap().is_empty());
        model
            .borrow_mut()
            .incoming_acl
            .push_back(vec![1, 0x20, 2, 0, 0xaa, 0xbb]);
        assert_eq!(
            hci.poll().unwrap(),
            vec![Packet::Acl(vec![1, 0x20, 2, 0, 0xaa, 0xbb])]
        );
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
            companion: None,
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
        // EP0 already completed the configuration request in this fixture.
        assert_eq!(
            model.borrow().indices[usize::from(dci)],
            if dci == 1 { 2 } else { 0 }
        );
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
            companion: None,
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
