//! xHCI host controllers (PCI class 0C0330) that the mount drives itself
//! after ExitBootServices, polled, for the host's USB keyboards, pointers,
//! disks, Ethernet adapters, Bluetooth controllers and audio devices.
//!
//! Evidence: eXtensible Host Controller Interface 1.2: initialization
//! (4.2), the USB Legacy Support capability and BIOS handoff (7.1), the
//! Supported Protocol capability (7.2), scratchpad buffers (4.20), device
//! slots and contexts (4.5, 6.2), the command, transfer and event rings
//! (4.9, 6.4, 6.5), root hub port reset (4.19), and USB 2.0 chapters 9 and
//! 11 for standard requests and hubs.
//!
//! One controller runs one command ring, one event ring on interrupter 0
//! (polled; its interrupt stays disabled). Ordinary endpoints use one transfer
//! ring; qualified SuperSpeed bulk endpoints may use primary stream arrays,
//! each nonzero stream owning its own transfer ring. Every ring is a single
//! 256-TRB segment closed by a Link TRB. A TD is
//! one TRB of at most 64 KiB that never crosses a 64 KiB boundary (the
//! buffers come from aligned DMA pages). Contexts are 32 or 64 bytes as
//! HCCPARAMS1.CSZ says; scratchpad pages are given when the controller
//! asks. Initial enumeration at attach visits every powered root port:
//! connections are debounced, then reset (USB 2 ports) or trained (USB 3
//! ports, warm-reset out of SS.Inactive or Compliance), with up to four
//! reset/enumeration attempts as in Linux `hub_port_init`. Supported USB2 and
//! SuperSpeed hub ports are powered, reset and enumerated with each slot's route
//! string and, for low- and full-speed devices behind a high-speed hub, its
//! single or multiple transaction translator. A STALL on a
//! control pipe resets the endpoint and fails the request; on a bulk or
//! interrupt pipe it also clears the device's halt (USB 2.0 9.4.5). Missing
//! transfer completions require acknowledged Stop Endpoint and Set TR Dequeue;
//! failed cancellation poisons the endpoint. An unresolved command completion or
//! fatal controller status prevents all later DMA/ring mutation until an
//! independently proven controller reset and fresh lifecycle publication.
//!
//! FS/HS and standard SuperSpeed isochronous service intervals, including hub
//! routes and actual USB2 transaction translators, use queued submit_iso /
//! completed_iso on xHCI 1.0+. Payloads fit one TRB/service and completion
//! ownership survives uncertain cancellation. Extended SSP payloads are refused.
//!
//! Hubs require observed healthy power and retained upstream current contracts:
//! actual root protocol/power selects the USB-standard default, and actual
//! configuration descriptors and hub status bound downstream current. Refused
//! rather than handled:
//! Extended SSP isochronous payloads, secondary stream arrays, hubs more than
//! five tiers deep, and controllers without 4 KiB pages. The retained [`Host`] explicitly
//! polls root events and hub bitmaps after attach and returns actual topology
//! changes. Old IDs remain tombstones; finite slot exhaustion is reported.
//! Controller save/restore requires observed U3 roots and acknowledged CSS/CRS;
//! reset-on-resume profiles require fresh lifecycle publication. Hub over-current
//! recovery remains a separate topology operation.
use super::{audio, bluetooth, cdc, ethernet, hid, storage};
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

mod bind;
mod configuration;
mod configure;
mod descriptor;
mod dma;
mod endpoint;
mod enumerate;
mod hardware;
mod hub;
mod identity;
mod iso;
mod lifecycle;
mod lpm;
mod memory;
#[cfg(test)]
pub(crate) mod model;
pub mod native;
mod power;
mod quirks;
pub mod renesas;
mod reset;
mod retirement;
mod ring;
mod slot_resources;
mod streams;
mod teardown;
mod transfer;

pub use bind::Plan;
use bind::bind_with_provider;
pub use descriptor::{Device, Endpoint, Interface, SuperSpeedCompanion, interfaces};
pub use identity::{DeviceAccess, SlotId};
pub use iso::{IsoCompletion, IsoSchedule, IsoStatus, IsoTransfer};
pub use lifecycle::{Changes, Host};
use ring::{Event, Ring};
pub use streams::StreamTransfer;
pub use transfer::{TransferCancellation, TransferTicket};

pub const CLASS: [u8; 3] = [0x0c, 0x03, 0x30];

// Capability registers.
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCSPARAMS3: usize = 0x0c;
const HCCPARAMS1: usize = 0x10;
const HCCPARAMS2: usize = 0x1c;
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
const PORT_REGISTERS: usize = 0x10;
// Interrupter 0.
const IMAN: usize = 0x20;
const ERSTSZ: usize = 0x28;
const ERSTBA: usize = 0x30;
const ERDP: usize = 0x38;

const RUN: u32 = 1;
const CRCR_ABORT: u32 = 1 << 2;
const CRCR_RUNNING: u32 = 1 << 3;
const HCRST: u32 = 1 << 1;
const HCH: u32 = 1;
const HSE: u32 = 1 << 2;
/// Events taken before ERDP moves within one batch (Linux `xhci_handle_events`).
const EVENTS_PER_DEQUEUE: usize = 128;
const CNR: u32 = 1 << 11;
const HCE: u32 = 1 << 12;
const EHB: u64 = 1 << 3;

const CCS: u32 = 1;
const PED: u32 = 1 << 1;
const PR: u32 = 1 << 4;
const PP: u32 = 1 << 9;
const PORT_CHANGES: u32 = 0x7f << 17;
/// PORTSC over-current active and its change, and hub.c's cool-down.
const OVER_CURRENT: u32 = 1 << 3;
const OVER_CURRENT_CHANGE: u32 = 1 << 20;
const OVER_CURRENT_COOLDOWN_US: u64 = 100_000;
const CSC: u32 = 1 << 17;
const WRC: u32 = 1 << 19;
const PRC: u32 = 1 << 21;
const WPR: u32 = 1 << 31;
/// PORTSC Port Link State and Port Speed fields (xHCI 5.4.8).
const PLS_SHIFT: u32 = 5;
const PLS_FIELD: u32 = 0xf;
pub(super) const PLS: u32 = PLS_FIELD << PLS_SHIFT;
const LINK_INACTIVE: u32 = 6;
const LINK_COMPLIANCE: u32 = 10;
const PORT_SPEED_SHIFT: u32 = 10;
const PORT_SPEED_FIELD: u32 = 0xf;
/// Hub port status and change bits (USB 2.0 11.24.2.7).
const HUB_PORT_CONNECTION: u16 = 1 << 0;
const HUB_PORT_ENABLE: u16 = 1 << 1;
const HUB_PORT_RESET: u16 = 1 << 4;
const HUB_PORT_LOW_SPEED: u16 = 1 << 9;
const HUB_PORT_HIGH_SPEED: u16 = 1 << 10;
/// PORTSC bits a write keeps: power and the wake enables.
const PORT_KEEP: u32 = PP | 0x7 << 25;

const LEGACY_SUPPORT: u32 = 1;
const SUPPORTED_PROTOCOL: u32 = 2;
const BIOS_OWNED: u32 = 1 << 16;
const OS_OWNED: u32 = 1 << 24;
/// USBLEGCTLSTS: the SMI enables, and the RW1C SMI status bits.
const LEGACY_SMI_ENABLES: u32 = 1 | 1 << 4 | 0x7 << 13;
const LEGACY_SMI_STATUS: u32 = 0x7 << 29;

pub(crate) const RING_TRBS: usize = 256;
pub(crate) const TRB: usize = 16;
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
pub(super) const CONFIGURE_ENDPOINT: u32 = 12;
const EVALUATE_CONTEXT: u32 = 13;
const RESET_ENDPOINT: u32 = 14;
pub(crate) const STOP_ENDPOINT: u32 = 15;
pub(crate) const SET_DEQUEUE: u32 = 16;
const NO_OP_COMMAND: u32 = 23;
const TRANSFER_EVENT: u32 = 32;
const COMMAND_COMPLETION: u32 = 33;

pub const SUCCESS: u32 = 1;
pub const STALL: u32 = 6;
pub const SHORT_PACKET: u32 = 13;
pub(crate) const CONTEXT_STATE_ERROR: u32 = 19;
const COMMAND_RING_STOPPED: u32 = 24;
const COMMAND_ABORTED: u32 = 25;
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
pub(crate) const SS_ENDPOINT_COMPANION: u8 = 0x30;

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
const QUIET_DRAINS: u8 = 64;
/// Linux xhci_abort_cmd_ring: CRR must clear within five seconds and the
/// Command Ring Stopped event follow within two.
const ABORT_US: u64 = 5_000_000;
const RING_STOP_US: u64 = 2_000_000;
const CONTROL_US: u64 = 5_000_000;
const PORT_RESET_US: u64 = 500_000;
const RESET_RECOVERY_US: u64 = 10_000;
/// A newly powered port's settle time before its first sample.
const PORT_POWER_US: u64 = 20_000;
/// Linux `hub_port_debounce`: a connection counts once it stays the same
/// for 100 ms, sampled every 25 ms, for at most two seconds.
const DEBOUNCE_STEP_US: u64 = 25_000;
const DEBOUNCE_STABLE_US: u64 = 100_000;
const DEBOUNCE_TIMEOUT_US: u64 = 2_000_000;
/// Linux `PORT_INIT_TRIES`: resets and enumerations a port gets.
const PORT_INIT_TRIES: usize = 4;
const ADDRESS_RECOVERY_US: u64 = 2_000;
const BIOS_HANDOFF_US: u64 = 1_000_000;

// bmRequestType: direction, type and recipient (USB 2.0 Table 9-2).
pub const DEVICE_TO_HOST: u8 = 0x80;
pub const TYPE_CLASS: u8 = 0x20;
pub const TYPE_VENDOR: u8 = 0x40;
pub const RECIPIENT_INTERFACE: u8 = 0x01;
pub const RECIPIENT_ENDPOINT: u8 = 0x02;
pub const RECIPIENT_OTHER: u8 = 0x03;

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
pub const INTERFACE_ASSOCIATION_DESCRIPTOR: u8 = 11;
const HUB_DESCRIPTOR: u8 = 0x29;
const HUB_CLASS: u8 = 9;
/// The multi-TT hub bDeviceProtocol (USB 2.0 11.23.1), and the interface
/// alternate setting that selects one TT per port.
const HUB_MULTI_TT: u8 = 2;
const MULTI_TT_ALTERNATE: u8 = 1;
/// Linux `USB_MAXCHILDREN`; an xHCI route string holds port 15 at most per
/// tier, so higher ports are routed as 15 (Linux `usb_alloc_dev`).
const MAX_HUB_PORTS: u8 = 31;
const MAX_ROUTE_PORT: u8 = 15;
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;
const C_PORT_CONNECTION: u16 = 16;
const C_PORT_RESET: u16 = 20;
pub(crate) const LANGUAGE_EN_US: u16 = 0x0409;

/// Register access, so the controller logic runs against a model in tests.
pub trait Registers {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    /// A 64-bit register, as two 32-bit writes, low half first (5.1).
    fn write64(&mut self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
    /// The bytes of register space from offset 0, when known.
    fn size(&self) -> Option<usize> {
        None
    }
}

/// A controller's memory BAR, whose size bounds every offset it reports.
struct Bar {
    mmio: Mmio,
    bytes: usize,
}

impl Registers for Bar {
    fn read32(&mut self, offset: usize) -> u32 {
        self.mmio.read32(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.mmio.write32(offset, value);
    }
    fn size(&self) -> Option<usize> {
        Some(self.bytes)
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

struct Transfer {
    ring: Ring,
    streams: Option<streams::Streams>,
    iso: Option<iso::Queue>,
    is_in: bool,
    /// A failed cancellation leaves hardware ownership unresolved.
    poisoned: bool,
    /// Only an acknowledged Configure Endpoint permits transfer submission.
    enabled: bool,
    /// Bulk and interrupt TDs submitted and not yet completed or cancelled.
    in_flight: usize,
}

struct Slot {
    generation: u64,
    /// Genuine parent retained by the physical topology at enumeration.
    parent_id: Option<SlotId>,
    /// Original physical descriptor inventory for topology reconciliation.
    inventory: Option<Device>,
    consumer: identity::Consumer,
    /// Consumer traffic is fenced while private lifecycle operations run.
    suspended: bool,
    attachment: Attachment,
    retiring: bool,
    input: memory::Buffer,
    _output: memory::Buffer,
    /// The slot context as software last set it.
    context: [u32; 4],
    endpoints: [Option<Transfer>; 32],
    /// Nonstream rings owned exclusively after successful endpoint retirement.
    /// Preserve the acknowledged producer pointer/cycle rather than restarting
    /// at an old TRB address or recycling the caller's backing DMA arena.
    retired_rings: [Option<Ring>; 32],
    control: memory::Buffer,
    speed: u8,
    /// None after an unresolved SET_CONFIGURATION; Some(0) is Address state.
    current_configuration: Option<u8>,
}

/// Where a device hangs off the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attachment {
    root_port: u8,
    route: u32,
    tier: u8,
    speed: u8,
    /// The high-speed hub slot and port a low- or full-speed device's
    /// transactions go through.
    translator: Option<(u8, u8)>,
    /// Actual hub slot/port, kept separately from the saturated route nibble.
    parent: Option<(u8, u8)>,
}

pub struct Controller {
    registers: Box<dyn Registers>,
    pub(crate) clock: Clock,
    operational: usize,
    runtime: usize,
    doorbells: usize,
    context_bytes: usize,
    dma_profile: dma::Profile,
    max_primary_streams: u32,
    stream_policy: streams::Policy,
    iso_caps: iso::Capabilities,
    hardware: hardware::State,
    quirks: quirks::Profile,
    max_slots: usize,
    max_ports: u8,
    /// Each root port's USB major revision from the Supported Protocol
    /// capabilities.
    port_major: Vec<u8>,
    /// USB 2 hardware LPM.
    lpm: lpm::Host,
    power: power::Ledger,
    native_memory: Option<Rc<memory::Native>>,
    dcbaa: memory::Buffer,
    _scratchpads: Vec<memory::Buffer>,
    commands: Ring,
    events: memory::Buffer,
    _event_table: memory::Buffer,
    event_index: usize,
    event_cycle: bool,
    slots: Vec<Option<Slot>>,
    slot_ownership: Vec<reset::Ownership>,
    retry_resources: slot_resources::Cache,
    /// A raw slot number never regains authority after its first retirement.
    /// Only the retirement owner can set this monotonic fence.
    legacy_slot_fenced: Vec<bool>,
    /// Transfer events that arrived while waiting for something else.
    pending: Vec<Event>,
    /// USBSTS once the controller reported a fatal error.
    error: Option<u32>,
    /// An unacknowledged command still owns its ring entry. Never wrap/reuse
    /// that entry or mutate command-dependent DMA without a controller reset.
    command_poisoned: bool,
    /// Linux CMD_RING_STATE_ABORTED: an abort got no Command Ring Stopped
    /// event, so the ring is not rung until a command times out.
    command_ring_stopped: bool,
    /// Events taken since ERDP last moved past them.
    unpublished: usize,
    /// Drains since USBSTS was last read.
    quiet_drains: u8,
    pub location: String,
}

/// What a command timeout left: its own completion, a restarted ring to wait
/// on, or a No Op standing in for the aborted command.
enum Timeout {
    Completed(Event),
    Waiting,
    Retired,
}

/// A controller shared by the class drivers of its devices.
pub type Shared = Rc<RefCell<Controller>>;

impl Controller {
    /// Takes the controller from firmware, resets it and starts it.
    #[cfg(test)]
    pub(crate) fn new(
        registers: Box<dyn Registers>,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
        location: String,
    ) -> Result<Self, BlockError> {
        Self::with_dma_profile(registers, clock, dma, location, dma::Profile::SPEC)
    }

    #[cfg(test)]
    fn with_dma_profile(
        registers: Box<dyn Registers>,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
        location: String,
        profile: dma::Profile,
    ) -> Result<Self, BlockError> {
        Self::with_hardware_profile(
            registers,
            clock,
            dma,
            location,
            hardware::Policy {
                dma: profile,
                ..Default::default()
            },
            || Ok(()),
        )
    }

    fn with_hardware_profile(
        registers: Box<dyn Registers>,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
        location: String,
        policy: hardware::Policy,
        after_reset: impl FnOnce() -> Result<(), BlockError>,
    ) -> Result<Self, BlockError> {
        Self::with_memory_profile(registers, clock, dma, location, policy, after_reset, None)
    }

    fn with_memory_profile(
        mut registers: Box<dyn Registers>,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
        location: String,
        policy: hardware::Policy,
        after_reset: impl FnOnce() -> Result<(), BlockError>,
        native_memory: Option<Rc<memory::Native>>,
    ) -> Result<Self, BlockError> {
        clock_ready(clock)?;
        let profile = policy.dma;
        let capability = registers.read32(0);
        let operational = (capability & 0xff) as usize;
        let parameters1 = registers.read32(HCSPARAMS1);
        let parameters2 = registers.read32(HCSPARAMS2);
        let parameters3 = registers.read32(HCSPARAMS3);
        let capabilities1 = registers.read32(HCCPARAMS1);
        let doorbells = (registers.read32(DBOFF) & !3) as usize;
        let runtime = (registers.read32(RTSOFF) & !0x1f) as usize;
        let profile = profile.capabilities(capabilities1 & 1 != 0);
        let context_bytes = if capabilities1 & 1 << 2 != 0 { 64 } else { 32 };
        let extended = ((capabilities1 >> 16) as usize) * 4;
        let max_ports = (parameters1 >> 24) as u8;
        let max_slots = ((parameters1 & 0xff) as usize).min(MAX_SLOTS);
        if max_slots == 0 || max_ports == 0 {
            return Err(BlockError::Unsupported(
                "xHCI controller without slots or ports",
            ));
        }
        // Every register the controller reports must lie inside its BAR.
        let size = registers.size().unwrap_or(usize::MAX);
        let outside = || BlockError::Unsupported("xHCI register outside its BAR");
        if operational + PORTSC + PORT_REGISTERS * usize::from(max_ports) > size
            || runtime + ERDP + 8 > size
            || doorbells + 4 * (max_slots + 1) > size
        {
            return Err(outside());
        }
        let mut port_major = vec![0u8; usize::from(max_ports)];
        let mut port_protocol = vec![0u32; usize::from(max_ports)];
        if extended != 0 {
            let mut at = extended;
            loop {
                if at + 4 > size {
                    return Err(outside());
                }
                let header = registers.read32(at);
                // Linux `xhci_find_next_ext_cap` stops at an absent device.
                if header == u32::MAX {
                    break;
                }
                let bytes = match header & 0xff {
                    LEGACY_SUPPORT => 8,
                    SUPPORTED_PROTOCOL => 12,
                    _ => 4,
                };
                if at + bytes > size {
                    return Err(outside());
                }
                match header & 0xff {
                    LEGACY_SUPPORT => take_from_firmware(&mut *registers, at, clock),
                    SUPPORTED_PROTOCOL => {
                        let ports = registers.read32(at + 8);
                        let (first, count) =
                            ((ports & 0xff) as usize, (ports >> 8 & 0xff) as usize);
                        for port in first.max(1)..(first + count).min(port_major.len() + 1) {
                            port_major[port - 1] = (header >> 24) as u8;
                            if header >> 24 == 2 {
                                port_protocol[port - 1] = ports;
                            }
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
        hardware::halt(&mut *registers, clock, operational, HALT_US)?;
        hardware::pre_reset(
            &mut *registers,
            operational,
            runtime,
            (parameters1 >> 8 & 0x7ff) as usize,
            policy.quirks,
        )?;
        hardware::reset(
            &mut *registers,
            clock,
            operational,
            profile.reset_settle_us(),
        )?;
        after_reset()?;
        if registers.read32(operational + PAGESIZE) & 1 == 0 {
            return Err(BlockError::Unsupported(
                "xHCI controller without 4 KiB pages",
            ));
        }
        let mut allocate = |bytes: usize, align: usize| {
            profile.allocate_memory(dma, bytes, align, native_memory.as_ref())
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
                array.write(n * 8, page.device_address());
                scratchpads.push(page);
            }
            dcbaa.write(0, array.device_address());
            scratchpads.push(array);
        }
        let commands = Ring::with_memory(dma, profile, native_memory.as_ref())?;
        let events = profile.allocate_memory(
            dma,
            profile.segment_bytes(),
            profile.segment_bytes(),
            native_memory.as_ref(),
        )?;
        let mut event_table = profile.allocate_memory(dma, 16, 64, native_memory.as_ref())?;
        event_table.write(0, events.device_address());
        event_table.write(8, RING_TRBS as u32);
        dcbaa.sync_dirty()?;
        for buffer in &scratchpads {
            buffer.sync_dirty()?;
        }
        commands.buffer.sync_dirty()?;
        events.sync_dirty()?;
        event_table.sync_dirty()?;
        // Native coherent polling must be qualified by the actual domain
        // before publishing any controller pointer or starting DMA.
        events.coherent_u32(12)?;
        // All buffers satisfy the same immutable aperture before any pointer
        // register is published, including the event and command segments.
        registers.write64(operational + DCBAAP, dcbaa.device_address());
        registers.write64(operational + CRCR, commands.dequeue_pointer());
        registers.write32(runtime + IMAN, 1); // clear IP; IE stays off
        registers.write32(runtime + ERSTSZ, 1);
        registers.write64(runtime + ERDP, events.device_address());
        registers.write64(runtime + ERSTBA, event_table.device_address());
        hardware::start(&mut *registers, clock, operational)?;
        let iso_caps =
            iso::Capabilities::new((capability >> 16) as u16, parameters2, capabilities1);
        let iso_caps = if capability >> 16 > 0x100 {
            iso_caps.extended(registers.read32(HCCPARAMS2))
        } else {
            iso_caps
        };
        let mut slots = Vec::new();
        slots.resize_with(max_slots + 1, || None);
        Ok(Self {
            registers,
            clock,
            operational,
            runtime,
            doorbells,
            context_bytes,
            dma_profile: profile,
            max_primary_streams: 1 << ((capabilities1 >> 12 & 0xf) + 1),
            stream_policy: policy.streams,
            iso_caps,
            hardware: hardware::State::Running,
            quirks: policy.quirks,
            max_slots,
            max_ports,
            port_major,
            lpm: lpm::Host::new((capability >> 16) as u16, parameters3 >> 16, port_protocol),
            native_memory,
            dcbaa,
            _scratchpads: scratchpads,
            commands,
            events,
            _event_table: event_table,
            event_index: 0,
            event_cycle: true,
            slot_ownership: vec![reset::Ownership::Vacant; slots.len()],
            legacy_slot_fenced: vec![false; slots.len()],
            retry_resources: slot_resources::Cache::new(slots.len()),
            power: power::Ledger::new(slots.len()),
            slots,
            pending: Vec::new(),
            error: None,
            command_poisoned: false,
            command_ring_stopped: false,
            unpublished: 0,
            quiet_drains: 0,
            location,
        })
    }

    fn sync_command_buffers(&self) -> Result<(), BlockError> {
        self.dcbaa.sync_dirty()?;
        for state in self.slots.iter().flatten() {
            for endpoint in state.endpoints.iter().flatten() {
                endpoint.ring.buffer.sync_dirty()?;
                if let Some(streams) = &endpoint.streams {
                    streams.sync_device()?;
                }
            }
            // Address/Configure may fetch these dequeues before the first TD.
            // Fresh and reinitialized rings must already show unowned TRBs.
            state.input.sync_dirty()?;
        }
        Ok(())
    }

    fn allocate(
        &self,
        dma: &mut dyn DmaAllocator,
        bytes: usize,
        align: usize,
    ) -> Result<memory::Buffer, BlockError> {
        self.dma_profile
            .allocate_memory(dma, bytes, align, self.native_memory.as_ref())
    }

    fn allocate_ring(&self, dma: &mut dyn DmaAllocator) -> Result<Ring, BlockError> {
        Ring::with_memory(dma, self.dma_profile, self.native_memory.as_ref())
    }

    fn doorbell(&mut self, slot: u8, target: u8) {
        fence(Ordering::SeqCst);
        self.registers
            .write32(self.doorbells + 4 * usize::from(slot), u32::from(target));
    }

    /// The next event on the ring, if the controller has posted one.
    fn next_event(&mut self) -> Option<Event> {
        let at = self.event_index * TRB;
        let control = match self.events.coherent_u32(at + 12) {
            Ok(control) => control,
            Err(_) => {
                self.command_poisoned = true;
                self.hardware = hardware::State::Failed;
                return None;
            }
        };
        if (control & CYCLE != 0) != self.event_cycle {
            return None;
        }
        fence(Ordering::Acquire);
        // SAFETY: this exact TRB's observed Cycle grants software ownership.
        // The controller cannot reuse it until the later ERDP publication.
        if unsafe { self.events.sync_cpu(at..at + TRB) }.is_err() {
            self.command_poisoned = true;
            self.hardware = hardware::State::Failed;
            return None;
        }
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
        // Linux xhci_handle_events moves ERDP once per batch, and every 128
        // events of a long one so the controller can go on posting.
        self.unpublished += 1;
        if self.unpublished == EVENTS_PER_DEQUEUE {
            self.publish_events();
        }
        Some(event)
    }

    /// Move ERDP past the events taken, clearing Event Handler Busy.
    fn publish_events(&mut self) {
        if self.unpublished == 0 {
            return;
        }
        self.unpublished = 0;
        let dequeue = self.events.device_address() + (self.event_index * TRB) as u64;
        self.registers.write64(self.runtime + ERDP, dequeue | EHB);
    }

    /// Whether the controller posted an event software has not taken, read
    /// from the event ring alone. An unreadable ring counts as posted so
    /// `next_event` fails it.
    fn event_posted(&self) -> bool {
        let at = self.event_index * TRB;
        !matches!(
            self.events.coherent_u32(at + 12),
            Ok(control) if (control & CYCLE != 0) != self.event_cycle
        )
    }

    /// A host system or host controller error (5.4.2) stops the controller
    /// for good.
    fn check_status(&mut self) {
        let status = self.registers.read32(self.operational + USBSTS);
        if status & (HSE | HCE) != 0 && self.error.is_none() {
            self.error = Some(status);
        }
    }

    /// Takes every posted event: transfer events wait in `pending`. USBSTS
    /// is read with each batch, as `xhci_irq` reads it per interrupt, and
    /// every `QUIET_DRAINS` drains that found the ring empty, for the fatal
    /// errors that post no event.
    fn drain(&mut self) {
        if self.hardware.ready().is_err() {
            return;
        }
        if !self.event_posted() {
            self.quiet_drains += 1;
            if self.quiet_drains < QUIET_DRAINS {
                return;
            }
        }
        self.quiet_drains = 0;
        self.check_status();
        while let Some(event) = self.next_event() {
            // A transfer event for a slot no longer enabled has no waiter.
            let stale = event.kind() == TRANSFER_EVENT
                && self.slot_ownership.get(usize::from(event.slot()))
                    != Some(&reset::Ownership::Enabled);
            if event.kind() == reset::PORT_STATUS_CHANGE {
                // Preserve one notification per physical root port until the
                // runtime owner checks actual PORTSC; commands never consume it.
                if let Some(old) = self
                    .pending
                    .iter_mut()
                    .find(|old| old.kind() == event.kind() && old.parameter == event.parameter)
                {
                    // Coalescing normal notifications must not hide a failed
                    // notification for that same physical port.
                    if event.code() != SUCCESS {
                        *old = event;
                    }
                } else {
                    self.pending.push(event);
                }
            } else if !stale && matches!(event.kind(), TRANSFER_EVENT | COMMAND_COMPLETION) {
                self.pending.push(event);
            }
        }
        self.publish_events();
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
        let deadline = self.clock.try_deadline(microseconds).map_err(|_| {
            BlockError::Unsupported("xHCI event timeout clock unavailable or duration out of range")
        })?;
        loop {
            self.drain();
            if let Some(memory) = &self.native_memory {
                memory.ready()?;
            }
            self.hardware.ready()?;
            if let Some(event) = self.take(&wanted) {
                return Ok(event);
            }
            if let Some(status) = self.error {
                return Err(BlockError::Device { status });
            }
            if deadline.passed() {
                // Quiet drains read no USBSTS: a controller that died
                // without an event is reported as such.
                self.check_status();
                if let Some(status) = self.error {
                    return Err(BlockError::Device { status });
                }
                return Err(BlockError::Timeout);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Before any new command-dependent DMA mutation or doorbell. A late
    /// completion cannot establish a new command generation or undo poison.
    fn ready(&mut self) -> Result<(), BlockError> {
        self.hardware.ready()?;
        if let Some(memory) = &self.native_memory {
            memory.ready()?;
        }
        self.drain();
        // Once per new command or publication, never per spin.
        self.check_status();
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
        self.sync_command_buffers()?;
        let address = self.commands.push(&[(parameter, status, control)])?[0];
        // Linux xhci_ring_cmd_db rings only a running command ring.
        if !self.command_ring_stopped {
            self.doorbell(0, 0);
        }
        let mut retired = false;
        let event = loop {
            match self.wait_event(COMMAND_US, |e| {
                e.kind() == COMMAND_COMPLETION && e.parameter == address
            }) {
                Ok(event) => break event,
                Err(BlockError::Timeout) => match self.command_timeout(address, control)? {
                    Timeout::Completed(event) => break event,
                    Timeout::Waiting => {}
                    Timeout::Retired => retired = true,
                },
                Err(error) => {
                    self.command_poisoned = true;
                    return Err(error);
                }
            }
        };
        // wait_event may have observed both a completion and fatal USBSTS.
        // Neither permits new commands until the controller is reset.
        if let Some(status) = self.error {
            self.command_poisoned = true;
            return Err(BlockError::Device { status });
        }
        // An aborted command turned No Op reports Command Ring Stopped.
        if retired {
            return Err(BlockError::Timeout);
        }
        match event.code() {
            SUCCESS => Ok(event),
            status => Err(BlockError::Device { status }),
        }
    }

    /// Linux xhci_handle_command_timeout for the one outstanding command.
    fn command_timeout(&mut self, address: u64, control: u32) -> Result<Timeout, BlockError> {
        // A Stop Endpoint the controller never answers means the host died.
        if control >> 10 & 0x3f == STOP_ENDPOINT {
            self.died();
            return Err(BlockError::Timeout);
        }
        let at = self.operational + CRCR;
        let low = self.registers.read32(at);
        if u64::from(low) | u64::from(self.registers.read32(at + 4)) << 32 == u64::MAX {
            self.died();
            return Err(BlockError::Timeout);
        }
        if self.command_ring_stopped || low & CRCR_RUNNING == 0 {
            // xhci_handle_stopped_cmd_ring: restart the ring and wait again.
            self.command_ring_stopped = false;
            self.doorbell(0, 0);
            return Ok(Timeout::Waiting);
        }
        // xhci_abort_cmd_ring. The upper half names the next command, so a
        // ring that stops before it is written keeps a valid pointer.
        self.registers
            .write64(at, self.commands.address() | u64::from(CRCR_ABORT));
        if hardware::handshake(
            &mut *self.registers,
            self.clock,
            self.operational,
            CRCR,
            CRCR_RUNNING,
            0,
            ABORT_US,
        )
        .is_err()
        {
            self.died();
            return Err(BlockError::Timeout);
        }
        match self.wait_event(RING_STOP_US, |e| {
            e.kind() == COMMAND_COMPLETION && e.code() == COMMAND_RING_STOPPED
        }) {
            Ok(_) => {}
            // xhci_cleanup_command_queue: the command is reported aborted.
            Err(BlockError::Timeout) => {
                self.command_ring_stopped = true;
                return Err(BlockError::Timeout);
            }
            Err(error) => {
                self.command_poisoned = true;
                return Err(error);
            }
        }
        // Its completion precedes Command Ring Stopped unless the controller
        // had not fetched it; a completion that raced the abort stands.
        match self.take(|e| e.kind() == COMMAND_COMPLETION && e.parameter == address) {
            Some(event) if event.code() == COMMAND_ABORTED => Err(BlockError::Timeout),
            Some(event) => Ok(Timeout::Completed(event)),
            None => {
                // xhci_handle_stopped_cmd_ring: it becomes a No Op, which the
                // restarted ring retires.
                self.commands.no_op(address)?;
                self.doorbell(0, 0);
                Ok(Timeout::Retired)
            }
        }
    }

    /// Linux xhci_halt and xhci_hc_died: no further command or transfer.
    fn died(&mut self) {
        self.command_poisoned = true;
        self.hardware = hardware::State::Died;
        let _ = hardware::halt(&mut *self.registers, self.clock, self.operational, HALT_US);
    }

    fn port_offset(&self, port: u8) -> usize {
        self.operational + PORTSC + PORT_REGISTERS * usize::from(port - 1)
    }

    fn write_port(&mut self, port: u8, bits: u32) {
        let at = self.port_offset(port);
        let current = self.registers.read32(at);
        self.registers.write32(at, current & PORT_KEEP | bits);
    }

    fn context(&self) -> usize {
        self.context_bytes
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
}

/// All fixed controller/port waits fit this interval. Caller-supplied budgets
/// also pass fallible admission at their actual submission boundary.
fn clock_ready(clock: Clock) -> Result<(), BlockError> {
    clock
        .check_duration(60_000_000)
        .map_err(|_| BlockError::Unsupported("xHCI requires an available calibrated clock"))
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
    /// Runtime topology owner, retained even for an empty/hub-only controller.
    /// Poll explicitly to obtain new class owners and permanently retired IDs.
    pub hosts: Vec<Host>,
    /// Native UAC2 owners; idle until an explicit PCM start request.
    pub audio: Vec<audio::UsbAudio>,
    pub vendor_links: Vec<ethernet::UsbEthernet>,
    /// Exact firmware request/target, format and device errors from vendor
    /// network attachment; never flattened to a generic unsupported status.
    pub vendor_failures: Vec<(String, ethernet::Error)>,
    pub disks: Vec<storage::UsbDisk>,
    /// Configured class owners, including readers with no ready media.
    pub storage: Vec<storage::UsbStorage>,
    pub inputs: Vec<hid::UsbInput>,
    pub links: Vec<cdc::UsbNet>,
    /// Raw physical HCI transports; vendor firmware initialization is unverified.
    pub bluetooth: Vec<bluetooth::UsbHci>,
    /// Retained pre-HCI upload evidence; never promoted to HCI without rebind.
    pub bootloaders: Vec<bluetooth::ath3k::UsbBootloader>,
    /// Devices or interfaces no driver here takes, and why.
    pub unused: Vec<(String, &'static str)>,
    pub failures: Vec<(String, BlockError)>,
    /// Descriptor inventory of all addressed devices, including hubs and devices
    /// without a supported class driver. Hardware state belongs to Controller.
    pub devices: Vec<Device>,
    /// Resident or uploaded Renesas firmware, bound to the actual PCI revision.
    pub controller_firmware: Option<renesas::Receipt>,
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
    attach_with_firmware_diagnostics(function, handoff, dma, firmware)
        .map_err(renesas::Error::transport)
}

/// Attach with the original exact-target firmware and controller errors. The
/// compatibility entry point retains its BlockError signature; callers that
/// need provider diagnostics can use this additive boundary directly.
pub fn attach_with_firmware_diagnostics(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
    firmware: &dyn crate::firmware::Provider,
) -> Result<Found, renesas::Error> {
    clock_ready(handoff.clock)?;
    let stream_policy = streams::pci_policy(function)?;
    let dma_profile = dma::Profile::pci(function.vendor, function.device);
    let quirks = quirks::Profile::pci(function)?;
    function.power_up(&handoff.clock)?;
    let controller_firmware = renesas::prepare(function, handoff.clock, firmware)?;
    let bars = function.bars();
    // The capability, operational, runtime and doorbell registers all lie
    // in BAR 0, whatever its size (5.2.1): QEMU's is 16 KiB, a PC's 64 KiB
    // or more.
    let bytes = bars[0]
        .and_then(|bar| bar.memory())
        .map_or(0, |range| range.end - range.start);
    let registers = Bar {
        mmio: registers(handoff, bars[0], 0, bytes)?,
        bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
    };
    function.enable_polled();
    let address = function.address;
    let location = format!(
        "xhci {:04x}:{:02x}:{:02x}.{}",
        address.segment, address.bus, address.device, address.function
    );
    let mut found = start_with_policies(
        Box::new(registers),
        handoff.clock,
        dma,
        location,
        firmware,
        hardware::Policy {
            streams: stream_policy,
            dma: dma_profile,
            quirks,
        },
        || quirks::after_reset(function, handoff.clock),
    )?;
    found.controller_firmware = controller_firmware;
    Ok(found)
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
    start_with_policies(
        registers,
        clock,
        dma,
        location,
        firmware,
        hardware::Policy::default(),
        || Ok(()),
    )
}

fn start_with_policies(
    registers: Box<dyn Registers>,
    clock: Clock,
    dma: &mut dyn DmaAllocator,
    location: String,
    firmware: &dyn crate::firmware::Provider,
    policy: hardware::Policy,
    after_reset: impl FnOnce() -> Result<(), BlockError>,
) -> Result<Found, BlockError> {
    let mut controller =
        Controller::with_hardware_profile(registers, clock, dma, location, policy, after_reset)?;
    // The policy came from this same actual PCI function before BAR access,
    // and applies only to the controller reset just completed above. No public
    // raw-register caller can supply a guessed PCI identity or enable streams.
    let mut found = Found::default();
    let devices = controller.enumerate(dma, &mut found.failures);
    let shared: Shared = Rc::new(RefCell::new(controller));
    for device in &devices {
        bind_with_provider(&shared, device.clone(), dma, &mut found, firmware);
    }
    found
        .hosts
        .push(Host::new(shared, &devices, dma, &mut found.failures));
    found.devices = devices;
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::model::*;
    use super::*;
    use crate::bus::dma::RegionAllocator;

    #[test]
    fn quiet_drains_read_usbsts_only_every_64th_or_with_events_like_xhci_irq() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all modeled controller DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = cancellation_controller(&mut dma);
        let reads = || model.borrow().status_reads;
        let before = reads();
        for _ in 1..QUIET_DRAINS {
            controller.drain();
        }
        assert_eq!(reads(), before);
        controller.drain();
        assert_eq!(reads(), before + 1);
        model.borrow_mut().event(0, SUCCESS, TRANSFER_EVENT, 3, 0);
        controller.drain();
        assert_eq!(reads(), before + 2);
    }

    #[test]
    fn unavailable_native_clock_refuses_before_any_controller_register_or_dma_effect() {
        struct Trap;
        impl Registers for Trap {
            fn read32(&mut self, _: usize) -> u32 {
                panic!("unavailable clock read controller")
            }
            fn write32(&mut self, _: usize, _: u32) {
                panic!("unavailable clock wrote controller")
            }
        }
        impl DmaAllocator for Trap {
            fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
                panic!("unavailable clock allocated DMA")
            }
        }
        for rate in [
            0,
            u64::MAX,
            u64::MAX / 60_000_000 + 1,
            (u64::MAX / 2) / 60_000_000 + 1,
        ] {
            let result = Controller::new(
                Box::new(Trap),
                Clock {
                    ticks_per_microsecond: rate,
                },
                &mut Trap,
                "unavailable-clock owner".into(),
            );
            assert!(matches!(
                result,
                Err(BlockError::Unsupported(
                    "xHCI requires an available calibrated clock"
                ))
            ));
        }
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
    fn timed_out_commands_are_aborted_like_linux() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive live test DMA through controller/model use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut c, model) = cancellation_controller(&mut dma);
        let stuck = |c: &mut Controller, reply| {
            {
                let mut model = model.borrow_mut();
                model.silence = Some(EVALUATE_CONTEXT);
                model.abort_reply = reply;
                model.seen.clear();
            }
            let result = c.command(0, 0, EVALUATE_CONTEXT << 10 | 1 << 24);
            model.borrow_mut().silence = None;
            result.map(|_| ())
        };
        // Aborted: the caller times out and the ring keeps serving commands.
        assert_eq!(stuck(&mut c, AbortReply::Aborted), Err(BlockError::Timeout));
        assert!(!c.command_poisoned && !c.command_ring_stopped);
        c.command(0, 0, EVALUATE_CONTEXT << 10 | 1 << 24).unwrap();
        // A completion that raced the abort stands.
        assert!(stuck(&mut c, AbortReply::Completed).is_ok());
        // An unfetched command becomes a No Op the restarted ring retires.
        assert_eq!(
            stuck(&mut c, AbortReply::Unfetched),
            Err(BlockError::Timeout)
        );
        assert_eq!(model.borrow().seen, [EVALUATE_CONTEXT, NO_OP_COMMAND]);
        // No Command Ring Stopped: the ring is rung again only once the next
        // command times out.
        assert_eq!(
            stuck(&mut c, AbortReply::Unstopped),
            Err(BlockError::Timeout)
        );
        assert!(c.command_ring_stopped && !c.command_poisoned);
        model.borrow_mut().seen.clear();
        c.command(0, 0, EVALUATE_CONTEXT << 10 | 1 << 24).unwrap();
        assert_eq!(model.borrow().seen, [EVALUATE_CONTEXT]);
        assert!(!c.command_ring_stopped);
        // CRR never clears: the host died.
        assert_eq!(stuck(&mut c, AbortReply::Ignored), Err(BlockError::Timeout));
        assert!(c.command_poisoned);
        assert!(matches!(c.hardware, hardware::State::Died));
        assert!(c.command(0, 0, EVALUATE_CONTEXT << 10 | 1 << 24).is_err());
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
}
