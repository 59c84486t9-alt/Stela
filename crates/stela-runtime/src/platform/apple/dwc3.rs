//! Synopsys DWC3 USB2 device-mode core, independently testable through DMA.
//!
//! Evidence: Linux a0ff06b3 `drivers/usb/dwc3/{core.h,gadget.c,ep0.c}`;
//! AppleUSBXDCI::sendEndpointCommand KC file 0x42ecd50 uses PAR0/PAR1/PAR2
//! at Apple offsets 0x808/804/800 and command at 0x80c. Apple's reg[2]
//! is the reg[0] aperture plus 0xc000, not a second register bank.
//! AppleUSBXDCIEventHandler::initRegisters (0x43063d4, writes at
//! 0x43065c0..0x43066dc) programs four-byte events into a 0x800-byte ring.
//! TI SPRUHJ7A tables 2-24..34 and 2-53 specify event status/parameters
//! and short-packet actions; non-stream completions have stream parameter 0.
//!
//! Stela handoff choice: disabled device, no connection, zero software
//! configuration, no transfers, four masked empty event buffers. This is
//! neither a captured iBoot image nor an assertion of Apple's reset values.
//! Identification is the declared DWC3 3.00a programming profile (0x5533300a),
//! 32 physical endpoints, four interrupt buffers, UTMI high-speed only, no
//! streams/hibernation/OTG/SuperSpeed. Endpoints are control EP0, bulk and
//! interrupt. The global configuration `AppleUSBXDCI::initDeviceController`
//! (0x42f97f0), `goOnBus` (0x42f4ef8) and `updateLPMPolicy` (0x43037f4)
//! program — GUCTL1, GUID, GTXFIFOPRIDEV, the DCFG speed maximum and LPM
//! capability, the DCTL LPM and U1/U2 fields, the wakeup and suspend event
//! enables — is retained where no modeled link observes it (the field
//! constants say why); other fields, offsets and widths refuse.
//!
//! GCTL.PRTCAPDIR selects the dual-role core's host (1) or device (2)
//! personality. `AppleT8112USBXHCI::start` read-modify-writes it to host at
//! KC file 0x4457644 whatever the port's role; the device driver selects
//! device again when it powers the core. Host mode idles the device
//! personality like a core reset; OTG and the reserved selection refuse.
//! The host personality's registers (`xhci`) occupy the core's first
//! 4 KiB; host interrupter n shares event buffer n's wire, and a GCTL core
//! soft reset resets both personalities. The Apple registers the host
//! driver programs around the core are `apple`'s.
mod apple;
mod regs;
pub mod xhci;

use super::{
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
    typec::Usb2Speed,
};
use crate::platform::{
    dma::{DmaError, Port},
    usb::{BusPeer, Function, MAX_PACKET, Reply, Token},
};
use alloc::{collections::VecDeque, string::String};
use regs::*;

const NAME: &str = "dwc3-device";
pub const PLATFORM_WINDOW_BASE: u64 = 0x20000;
pub const PLATFORM_WINDOW_STRIDE: u64 = 0x4000;
/// GUCTL1 fields the device driver sets (Linux `core.h` names):
/// DEV_L1_EXIT_BY_HW (24, `updateLPMPolicy`), DEV_FORCE_20_CLK_FOR_30_CLK
/// (26, `goOnBus`) and DEV_DECOUPLE_L1L2_EVT (31, `initDeviceController`,
/// KC 0x42fa004). They shape LPM exit, the SuperSpeed clock source and
/// suspend event reporting, none of which a high-speed link that never
/// enters L1 or suspend observes; they are retained only.
const GUCTL1_FIELDS: u32 = 1 << 24 | 1 << 26 | 1 << 31;
/// DCTL: run, soft reset, the LPM NYET threshold (23:20) and the
/// SuperSpeed U1/U2 accept/initiate enables (12:9), which no high-speed
/// link uses. Link state change requests, test modes, save/restore and
/// hibernation refuse.
const DCTL_FIELDS: u32 = RUN | RESET | 0xf << 20 | 0xf << 9;
/// DEVTEN: disconnect, reset, connect done, wakeup, suspend (EOPF) and
/// command complete. The host peer never suspends or resumes the bus, so
/// the wakeup and suspend events never occur.
const DEVTEN_FIELDS: u32 = 1 | 1 << 1 | 1 << 2 | 1 << 4 | 1 << 6 | 1 << 10;
/// DCFG: device speed (2:0), address, receive buffer count and LPM
/// capability. A SuperSpeed (4) or SuperSpeedPlus (5) maximum connects at
/// high speed, as on a core with no SuperSpeed link; full and low speed
/// refuse. With LPM capable the core would answer LPM tokens, which the
/// host peer never sends.
const DCFG_FIELDS: u32 = 7 | 0x7f << 3 | 0x1f << 17 | 1 << 22;
const MAX_PENDING_EVENTS: usize = 256;
const MAX_LINKS_PER_PACKET: usize = 8;
const FIFO_WORDS: u32 = 4096;
const CORE_RESET: u32 = 1 << 11;
const HALTED: u32 = 1 << 22;
const RX_EMPTY: u32 = 1 << 17;
/// EP0's largest configurable packet. Before Connect Done reports the
/// link speed, drivers configure EP0 for SuperSpeed's 512 bytes (Linux
/// `dwc3_gadget_ep0_desc`, `AppleUSBXDCI::initDeviceController` step 11),
/// then modify it to the connected speed's 64. The host peer's own
/// high-speed packets bound every transaction in between.
const MAX_PACKET_CONTROL: usize = 512;
/// DEPCFG parameter 0 burst size (25:22). Bursts are SuperSpeed-only; a
/// high-speed link never observes them, so a bulk endpoint's value is
/// retained only. Apple's driver sets 15 on every bulk endpoint.
const BURST: u32 = 0xf << 22;
const CMD_FAILURE: u32 = 1 << 12;
const PRTCAP: u32 = 3 << 12;
const PRTCAP_HOST: u32 = 1 << 12;
const PRTCAP_DEVICE: u32 = 2 << 12;

/// Minimal port boundary until the independent Type-C model lands. A new
/// connection generation is a detach: the driver ends its own transfers.
/// The provider must derive readiness from its actual PHY/role lifecycle.
pub trait PortState {
    fn generation(&self) -> u64;
    fn high_speed_device_ready(&self) -> bool;
}

#[derive(Clone, Copy)]
struct Ring {
    address: u64,
    size: u32,
    masked: bool,
    count: u32,
    producer: u32,
    asserted: bool,
}
impl Ring {
    const fn new() -> Self {
        Self {
            address: 0,
            size: 0,
            masked: true,
            count: 0,
            producer: 0,
            asserted: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Endpoint {
    parameters: [u32; 3],
    command: u32,
    configured: bool,
    resource: bool,
    stalled: bool,
    ring: usize,
    packet: usize,
    events: u32,
    active: Option<Transfer>,
    not_ready: bool,
}

#[derive(Clone, Copy)]
struct Transfer {
    trb: u64,
    done: u32,
}

#[derive(Clone, Copy)]
struct Event {
    ring: usize,
    value: u32,
}

/// Independent ordinary-domain controls. Clock/retained power pauses keep
/// configuration; quiesce inhibits DMA while MMIO remains available.
#[derive(Clone, Copy)]
struct Lifecycle {
    powered: bool,
    clocked: bool,
    quiesced: bool,
    reset: bool,
}

/// A controller DMA that failed: its I/O address, length and direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaFault {
    pub iova: u64,
    pub bytes: usize,
    pub write: bool,
    pub error: DmaError,
}

impl DmaFault {
    fn new(iova: u64, bytes: usize, write: bool, error: DmaError) -> Self {
        Self {
            iova,
            bytes,
            write,
            error,
        }
    }
}

pub struct Dwc3 {
    lifecycle: Lifecycle,
    phy_reset: bool,
    phy_ready: bool,
    phy_quiesced: bool,
    phy_clocked: bool,
    pending_phy_disconnect: bool,
    session_reset: bool,
    irqs: [AicInput; RINGS],
    rings: [Ring; RINGS],
    endpoints: [Endpoint; ENDPOINTS],
    pending: VecDeque<Event>,
    gctl: u32,
    usb2: u32,
    usb3: u32,
    tx_fifo: [u32; ENDPOINTS / 2],
    /// GTXFIFOPRIDEV: one DMA priority bit per TX FIFO. The model serves
    /// one transfer at a time, so priority orders nothing.
    tx_priority: u32,
    guid: u32,
    guctl1: u32,
    rx_fifo: u32,
    dcfg: u32,
    dctl: u32,
    devten: u32,
    enabled: u32,
    generic_parameter: u32,
    generic_command: u32,
    port_generation: u64,
    port_ready: bool,
    connected: bool,
    /// The DMA failure that poisoned the controller until software reset.
    poisoned: Option<DmaFault>,
    host: xhci::Xhci,
    apple: apple::Registers,
}

impl Dwc3 {
    /// IRQs are event-buffer wires, supplied by placement, never inferred from
    /// the event number. Production Apple routing still requires qualification.
    pub fn new(irqs: [AicInput; RINGS]) -> Self {
        Self {
            lifecycle: Lifecycle {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
            },
            phy_reset: false,
            phy_ready: false,
            phy_quiesced: false,
            phy_clocked: true,
            pending_phy_disconnect: false,
            session_reset: false,
            irqs,
            rings: [Ring::new(); RINGS],
            endpoints: [Endpoint::default(); ENDPOINTS],
            pending: VecDeque::new(),
            gctl: PRTCAP_DEVICE,
            usb2: 0,
            usb3: 0,
            tx_fifo: [0; ENDPOINTS / 2],
            rx_fifo: 0,
            tx_priority: 0,
            guid: 0,
            guctl1: 0,
            dcfg: 0,
            dctl: 0,
            devten: 0,
            enabled: 0,
            generic_parameter: 0,
            generic_command: 0,
            port_generation: 0,
            port_ready: false,
            connected: false,
            poisoned: None,
            host: xhci::Xhci::new(),
            apple: apple::Registers::default(),
        }
    }

    fn mmio_ready(&self) -> Result<(), &'static str> {
        self.mmio_ready_at(None)
    }

    /// Whether the AP register at `offset` (any, for `None`) is accessible.
    /// `AppleT8112USBXDCI::powerOn` (26A434 KC 0x43096e8) read-modify-writes
    /// GUSB2PHYCFG and GUSB3PIPECTL, clearing SUSPHY, at 0x430a380 and
    /// 0x430a5a4, before it clears the pipehandler's FORCE_CLAMP (0x430a774)
    /// and sets its RESET_N (0x430a91c): those two PHY configuration words
    /// complete, and keep what is written, while the physical ATC PHY reset
    /// is held. The drivers release that reset before core initialization
    /// and establish no other register's access while it is held, which
    /// stays unqualified, not a claim that physical reset makes the rest
    /// of MMIO inaccessible.
    fn mmio_ready_at(&self, offset: Option<u64>) -> Result<(), &'static str> {
        if !self.lifecycle.powered {
            return Err("DWC3 power domain is off");
        }
        if !self.lifecycle.clocked {
            return Err("DWC3 clock is gated");
        }
        if self.lifecycle.reset {
            return Err("DWC3 reset is asserted");
        }
        if self.phy_reset && !matches!(offset, Some(GUSB2PHYCFG | GUSB3PIPECTL)) {
            return Err("DWC3 MMIO while physical ATC PHY reset is held is unqualified");
        }
        Ok(())
    }

    fn activity_ready(&self) -> Result<(), &'static str> {
        self.mmio_ready()?;
        if self.lifecycle.quiesced {
            return Err("DWC3 DMA is quiesced");
        }
        if !self.phy_clocked {
            return Err("ATC PHY clock is gated");
        }
        if self.phy_quiesced {
            return Err("ATC PHY DMA is quiesced");
        }
        Ok(())
    }

    pub fn lifecycle_active(&self) -> bool {
        self.activity_ready().is_ok()
    }

    fn clock_running(&self) -> bool {
        self.lifecycle.powered
            && self.lifecycle.clocked
            && !self.lifecycle.reset
            && !self.phy_reset
            && self.phy_clocked
    }

    /// Inhibit both personalities without losing their rings or configuration.
    pub fn set_clock(&mut self, enabled: bool, access: &Access<'_>) {
        let before = self.clock_running();
        self.lifecycle.clocked = enabled;
        let after = self.clock_running();
        if before != after {
            self.host.set_clock(after, access.now);
        }
    }

    /// No DMA work runs concurrently with a machine boundary. Non-retained
    /// supply loss cancels both personalities using the ordinary reset image;
    /// already committed guest RAM bytes are never undone or completed again.
    pub fn set_power(&mut self, powered: bool, retention: bool, access: &mut Access<'_>) {
        let before = self.clock_running();
        if self.lifecycle.powered && !powered && !retention {
            self.reset(access);
        }
        self.lifecycle.powered = powered;
        let after = self.clock_running();
        if before != after {
            self.host.set_clock(after, access.now);
        }
    }

    pub fn set_quiesced(&mut self, quiesced: bool) {
        self.lifecycle.quiesced = quiesced;
    }

    pub fn set_reset(&mut self, asserted: bool, access: &mut Access<'_>) {
        let before = self.clock_running();
        let reset_before = self.lifecycle.reset || self.phy_reset;
        self.lifecycle.reset = asserted;
        if !reset_before && (self.lifecycle.reset || self.phy_reset) {
            self.reset(access);
        }
        let after = self.clock_running();
        if before != after {
            self.host.set_clock(after, access.now);
        }
    }

    /// Independent physical outputs from the actual PHY. Reset sources are
    /// ORed; neither a PMGR release nor a PHY release can clear the other.
    pub fn set_phy_state(
        &mut self,
        reset: bool,
        ready: bool,
        clocked: bool,
        quiesced: bool,
        access: &mut Access<'_>,
    ) -> bool {
        let changed = (
            self.phy_reset,
            self.phy_ready,
            self.phy_clocked,
            self.phy_quiesced,
        ) != (reset, ready, clocked, quiesced);
        let before = self.clock_running();
        let reset_before = self.lifecycle.reset || self.phy_reset;
        if self.phy_ready && !ready {
            // Keep an electrical falling edge until service, even if software
            // immediately restores the PHY before the next DMA boundary.
            self.pending_phy_disconnect = true;
            self.session_reset = true;
        }
        self.phy_reset = reset;
        self.phy_ready = ready;
        self.phy_clocked = clocked;
        self.phy_quiesced = quiesced;
        if !reset_before && (self.lifecycle.reset || self.phy_reset) {
            self.reset(access);
        }
        let after = self.clock_running();
        if before != after {
            self.host.set_clock(after, access.now);
        }
        changed
    }

    pub fn phy_ready(&self) -> bool {
        self.phy_ready
    }

    /// The adapter cancels its external peer session before further service.
    /// It retains its own retry flag if that cancellation reports failure.
    pub fn take_session_reset(&mut self) -> bool {
        core::mem::take(&mut self.session_reset)
    }

    fn error(offset: u64, direction: Direction, reason: &'static str) -> MmioError {
        refuse(NAME, offset, Width::Word, direction, reason)
    }

    fn queue(&mut self, ring: usize, value: u32) -> Result<(), &'static str> {
        if self.pending.len() == MAX_PENDING_EVENTS {
            return Err("DWC3 pending event capacity exhausted");
        }
        self.pending.push_back(Event { ring, value });
        Ok(())
    }

    fn device_event(&mut self, kind: u32) -> Result<(), &'static str> {
        if self.devten & (1 << kind) != 0 {
            self.queue(0, device_event(kind))?;
        }
        Ok(())
    }

    /// A core soft reset or a switch away from device mode: the device
    /// controller loses its transfers, transfer resources and queued events.
    fn release(&mut self) {
        for ep in &mut self.endpoints {
            ep.active = None;
            ep.resource = false;
            ep.stalled = false;
            ep.not_ready = false;
        }
        self.pending.clear();
        self.session_reset = true;
        self.dcfg &= !(0x7f << 3);
        self.connected = false;
    }

    /// A bus event (USB reset, detach, PHY reset, Run/Stop clear) leaves
    /// endpoint state to software: transfer resources stay assigned until
    /// Start Configuration, started transfers until End Transfer, and the
    /// driver itself zeroes DCFG.DevAddr and clears halts on USB reset
    /// (DWC3 databook "Initialization on USB Reset"; Linux
    /// `dwc3_gadget_reset_interrupt`). Only XferNotReady reporting rearms.
    fn bus_event(&mut self) {
        for ep in &mut self.endpoints {
            ep.not_ready = false;
        }
    }

    pub fn sync_port(&mut self, state: &impl PortState) -> Result<(), &'static str> {
        self.activity_ready()?;
        if self.pending_phy_disconnect {
            if self.connected {
                self.device_event(0)?;
                self.bus_event();
                self.connected = false;
            }
            self.host.attach(None);
            self.pending_phy_disconnect = false;
        }
        let ready = state.high_speed_device_ready();
        if self.port_generation != state.generation() || self.port_ready != ready {
            if self.connected {
                self.device_event(0)?;
            }
            self.bus_event();
            self.connected = false;
            self.port_generation = state.generation();
            self.port_ready = ready;
        }
        Ok(())
    }

    /// The DMA failure that poisoned the controller, if one did.
    pub fn dma_fault(&self) -> Option<DmaFault> {
        self.poisoned
    }

    /// Publish bounded queued events via this device's DART stream, before
    /// asserting a wire. Full rings backpressure without overwriting entries.
    /// An uncertain DMA failure poisons the controller until software reset;
    /// no payload or completion is retried behind the owner's back.
    pub fn flush(&mut self, port: &mut Port<'_, '_>) -> Result<(), &'static str> {
        self.activity_ready()?;
        if self.poisoned.is_some() {
            return Err("DWC3 requires reset after a DMA failure");
        }
        for _ in 0..self.pending.len() {
            let Some(event) = self.pending.front().copied() else {
                break;
            };
            let ring = &mut self.rings[event.ring];
            if ring.size == 0 || ring.count + EVENT_BYTES > ring.size {
                let blocked = self.pending.pop_front().unwrap();
                self.pending.push_back(blocked);
                continue;
            }
            let address = ring
                .address
                .checked_add(u64::from(ring.producer))
                .ok_or("DWC3 event address overflow")?;
            if let Err(error) = port.write(address, &event.value.to_le_bytes()) {
                self.poisoned = Some(DmaFault::new(
                    address,
                    event.value.to_le_bytes().len(),
                    true,
                    error,
                ));
                return Err("DWC3 event DMA fault; reset required");
            }
            ring.producer = (ring.producer + EVENT_BYTES) % ring.size;
            ring.count += EVENT_BYTES;
            self.pending.pop_front();
        }
        self.interrupts(port.access);
        Ok(())
    }

    /// Host personality work (a doorbell, events to post) waits for DMA.
    pub fn host_pending(&self) -> bool {
        self.lifecycle_active() && self.host.pending()
    }

    /// The system count at which the host personality next has work of
    /// its own: an event to post, or `function`'s endpoint to poll.
    pub fn host_deadline(&self, function: Option<&(dyn Function + '_)>) -> Option<u64> {
        if self.lifecycle_active() {
            self.host.deadline(function)
        } else {
            None
        }
    }

    /// Cables a USB2 function of `speed` to the host personality's root
    /// port, or nothing.
    pub fn attach_host_function(&mut self, speed: Option<Usb2Speed>) -> Result<(), &'static str> {
        self.activity_ready()?;
        self.host.attach(speed);
        Ok(())
    }

    /// The host personality's next trace line, for the boot log.
    pub fn take_host_trace(&mut self) -> Option<String> {
        self.host.take_trace()
    }

    /// The host personality's registers and event rings, while it runs or
    /// holds events.
    pub fn host_summary(&self) -> Option<String> {
        let wires: [bool; RINGS] = core::array::from_fn(|n| self.rings[n].asserted);
        self.host
            .summary()
            .map(|summary| alloc::format!("{summary} wires={wires:?}"))
    }

    /// Runs the host personality's commands and transfers, `function`
    /// being what is cabled to its port, and posts its events.
    pub fn service_host(
        &mut self,
        port: &mut Port<'_, '_>,
        function: Option<&mut (dyn Function + '_)>,
    ) -> Result<(), &'static str> {
        self.activity_ready()?;
        if self.poisoned.is_some() {
            return Err("DWC3 requires reset after a DMA failure");
        }
        self.host.service(port, function)?;
        self.interrupts(port.access);
        Ok(())
    }

    fn interrupts(&mut self, access: &mut Access<'_>) {
        for (n, (ring, irq)) in self.rings.iter_mut().zip(self.irqs).enumerate() {
            let level = ring.count != 0 && !ring.masked || self.host.interrupt(n);
            if ring.asserted != level {
                access.interrupts.set_level(Wire::Aic(irq), level);
                ring.asserted = level;
            }
        }
    }

    fn reset(&mut self, access: &mut Access<'_>) {
        for irq in self.irqs {
            access.interrupts.set_level(Wire::Aic(irq), false);
        }
        let mut host = core::mem::take(&mut self.host);
        host.reset("DWC3 core reset");
        let generation = self.port_generation;
        let ready = self.port_ready;
        let lifecycle = self.lifecycle;
        let phy = (
            self.phy_reset,
            self.phy_ready,
            self.phy_clocked,
            self.phy_quiesced,
        );
        *self = Self::new(self.irqs);
        self.port_generation = generation;
        self.port_ready = ready;
        self.lifecycle = lifecycle;
        (
            self.phy_reset,
            self.phy_ready,
            self.phy_clocked,
            self.phy_quiesced,
        ) = phy;
        self.host = host;
        self.session_reset = true;
    }

    fn endpoint_command(&mut self, n: usize, value: u32) -> Result<(), &'static str> {
        let command = value & 0xf;
        if !matches!(command, 1 | 2 | 4..=9) {
            return Err("unmodeled DWC3 endpoint command");
        }
        if value & CMDACT == 0 || value & !(0x7f_0000 | 0x800 | CMDACT | CMDIOC | 0xf) != 0 {
            return Err("DWC3 endpoint command reserved bits or CMDACT clear");
        }
        if command != 8 && value & (1 << 11) != 0 {
            return Err("DWC3 endpoint priority or clear-pending request is not modeled");
        }
        if command == 8 && value & (1 << 11) == 0 {
            return Err("DWC3 End Transfer requires ForceRM");
        }
        if value & CMDIOC != 0 && self.pending.len() == MAX_PENDING_EVENTS {
            return Err("DWC3 pending command event capacity exhausted");
        }
        let ep = &mut self.endpoints[n];
        let [p2, p1, p0] = ep.parameters;
        let mut failed = false;
        let mut result = value & !(CMDACT | 0x7f_0000);
        match command {
            1 => {
                let kind = (p0 >> 1) & 3;
                let packet = ((p0 >> 3) & 0x7ff) as usize;
                let ring = (p1 & 0x1f) as usize;
                // No stream/isochronous state can be discarded. An
                // interrupt endpoint's bInterval-1 (16..23) sets its
                // service interval, which only the host's polling observes.
                let interval = if kind == INTERRUPT { 0xff << 16 } else { 0 };
                let burst = if kind == 2 { BURST } else { 0 };
                if p2 != 0
                    || p0 & !((3 << 1) | (0x7ff << 3) | (0x1f << 17) | burst | (3 << 30)) != 0
                    || p0 >> 30 == 1
                    || p0 >> 30 == 3
                    || p1
                        & !((0x1f << 25)
                            | CFG_COMPLETE
                            | CFG_PROGRESS
                            | CFG_NOT_READY
                            | 0x1f
                            | interval)
                        != 0
                {
                    return Err("DWC3 endpoint streams, bursts or reserved configuration");
                }
                if !matches!(kind, 0 | 2 | INTERRUPT) || (kind == 0) != (n < 2) {
                    return Err("DWC3 models control EP0, bulk and interrupt endpoints only");
                }
                if packet == 0
                    || packet
                        > if n < 2 {
                            MAX_PACKET_CONTROL
                        } else {
                            MAX_PACKET
                        }
                    || ring >= RINGS
                    || (p1 >> 25) & 0x1f != n as u32
                    // Connect Done modifies EP0 with its SETUP transfer
                    // started (Linux `dwc3_gadget_conndone_interrupt`);
                    // only initialization requires an idle endpoint.
                    || (ep.active.is_some() && p0 >> 30 != 2)
                {
                    failed = true;
                } else {
                    ep.configured = true;
                    ep.ring = ring;
                    ep.packet = packet;
                    ep.events = p1 & (CFG_COMPLETE | CFG_PROGRESS | CFG_NOT_READY);
                }
            }
            2 => {
                if p0 != 1 || p1 != 0 || p2 != 0 {
                    return Err("DWC3 requires one transfer resource per endpoint");
                }
                if ep.configured && ep.active.is_none() {
                    ep.resource = true;
                } else {
                    failed = true;
                }
            }
            4 | 5 => {
                if n < 2 && (n != 0 || command == 5) {
                    return Err("DWC3 control stall is OUT-only and clears on SETUP");
                }
                if !ep.configured {
                    failed = true;
                } else {
                    ep.stalled = command == 4;
                }
            }
            6 => {
                if value & (0x7f << 16 | 1 << 11) != 0 {
                    return Err("DWC3 non-stream start requires zero command parameter/priority");
                }
                if p2 != 0 {
                    return Err("DWC3 transfer streams are not modeled");
                }
                let address = u64::from(p1) | u64::from(p0) << 32;
                if !ep.resource || ep.active.is_some() || !address.is_multiple_of(TRB_BYTES) {
                    failed = true;
                } else {
                    ep.active = Some(Transfer {
                        trb: address,
                        done: 0,
                    });
                    ep.not_ready = false;
                    result |= 1 << 16;
                }
            }
            7 | 8 => {
                if (value >> 16) & 0x7f != 1 || ep.active.is_none() {
                    failed = true;
                } else if command == 8 {
                    ep.active = None;
                    ep.not_ready = false;
                } else {
                    result |= 1 << 16;
                    ep.not_ready = false;
                }
            }
            9 => {
                let first = ((value >> 16) & 0x7f) as usize;
                if n != 0 || !matches!(first, 0 | 2) {
                    failed = true;
                } else if first == 0 && value & CMDIOC != 0 {
                    return Err("DWC3 initial Start Configuration requires polling");
                } else if self.endpoints[first..].iter().any(|ep| ep.active.is_some()) {
                    failed = true;
                } else {
                    for ep in &mut self.endpoints[first..] {
                        ep.resource = false;
                    }
                }
            }
            _ => unreachable!(),
        }
        if failed {
            result |= CMD_FAILURE;
        }
        self.endpoints[n].command = result;
        self.endpoints[n].not_ready = false;
        if value & CMDIOC != 0 {
            self.queue(
                self.endpoints[n].ring,
                ep_event(
                    n,
                    CMD_COMPLETE,
                    u32::from(failed),
                    command << 8 | ((result >> 16) & 0x7f),
                ),
            )?;
        }
        Ok(())
    }

    pub fn available(&self) -> bool {
        self.unavailable().is_none()
    }

    /// Why a host cannot reach the device personality now, if it cannot:
    /// the first unmet condition of [`Self::available`].
    pub fn unavailable(&self) -> Option<&'static str> {
        if let Err(why) = self.activity_ready() {
            return Some(why);
        }
        Some(if !self.phy_ready {
            "ATC PHY USB2 is not ready"
        } else if self.pending_phy_disconnect {
            "a PHY disconnect is pending service"
        } else if !self.port_ready {
            "the Type-C port is not ready"
        } else if self.dctl & RUN == 0 {
            "DCTL.RUN is clear"
        } else if self.gctl & (CORE_RESET | PRTCAP) != PRTCAP_DEVICE {
            "GCTL is not device mode out of core reset"
        } else if self.usb2 & (1 << 31) != 0 {
            "GUSB2PHYCFG.PHYSOFTRST is set"
        } else {
            return None;
        })
    }

    /// A transaction adapter whose borrow retains the actual DMA stream.
    pub fn peer<'a, 'b, 'c>(&'a mut self, dma: &'a mut Port<'b, 'c>) -> Peer<'a, 'b, 'c> {
        Peer {
            controller: self,
            dma,
        }
    }

    fn not_ready(
        &mut self,
        n: usize,
        token: Token,
        bytes: usize,
        active: bool,
    ) -> Result<Reply, &'static str> {
        let ep = self.endpoints[n];
        if !ep.not_ready
            && ep.events & CFG_NOT_READY != 0
            && self.pending.len() < MAX_PENDING_EVENTS
        {
            let phase = if n >= 2 || token == Token::Setup {
                0
            } else if bytes == 0 {
                2
            } else {
                1
            };
            self.queue(
                ep.ring,
                ep_event(n, XFER_NOT_READY, phase | if active { 8 } else { 0 }, 0),
            )?;
            self.endpoints[n].not_ready = true;
        }
        Ok(Reply::Nak)
    }

    fn packet(
        &mut self,
        n: usize,
        token: Token,
        data: &mut [u8],
        port: &mut Port<'_, '_>,
    ) -> Result<Reply, &'static str> {
        self.activity_ready()?;
        if self.poisoned.is_some() {
            return Err("DWC3 requires reset after a DMA failure");
        }
        if !self.connected || !self.available() {
            return Ok(Reply::Nak);
        }
        if n >= ENDPOINTS || self.enabled & (1 << n) == 0 {
            return Ok(Reply::Nak);
        }
        let mut ep = self.endpoints[n];
        if !ep.configured {
            return Ok(Reply::Nak);
        }
        if ep.stalled && token != Token::Setup {
            return Ok(Reply::Stall);
        }
        let Some(mut transfer) = ep.active else {
            return self.not_ready(n, token, data.len(), false);
        };
        if token == Token::Setup && self.endpoints[1].active.is_some() {
            return Err("DWC3 superseding control SETUP is not modeled");
        }
        if self.pending.len() == MAX_PENDING_EVENTS {
            return Ok(Reply::Nak);
        }
        let mut trb = [0u8; TRB_BYTES as usize];
        for links in 0..=MAX_LINKS_PER_PACKET {
            if let Err(error) = port.read(transfer.trb, &mut trb) {
                self.poisoned = Some(DmaFault::new(transfer.trb, trb.len(), false, error));
                return Err("DWC3 TRB DMA fault; reset required");
            }
            let ctrl = u32::from_le_bytes(trb[12..16].try_into().unwrap());
            if ctrl & HWO == 0 {
                return self.not_ready(n, token, data.len(), true);
            }
            let kind = (ctrl >> 4) & 0x3f;
            if kind == 8 {
                if ctrl & !(HWO | (0x3f << 4)) != 0 || trb[8..12] != [0; 4] {
                    return Err("DWC3 link TRB has unmodeled flags or size");
                }
                if links == MAX_LINKS_PER_PACKET {
                    return Err("DWC3 cyclic or excessive TRB links");
                }
                transfer.trb = u64::from_le_bytes(trb[..8].try_into().unwrap());
                transfer.done = 0;
                if !transfer.trb.is_multiple_of(TRB_BYTES) {
                    return Err("DWC3 unaligned link TRB");
                }
                continue;
            }
            break;
        }
        let buffer = u64::from_le_bytes(trb[..8].try_into().unwrap());
        let size = u32::from_le_bytes(trb[8..12].try_into().unwrap());
        let ctrl = u32::from_le_bytes(trb[12..16].try_into().unwrap());
        let kind = (ctrl >> 4) & 0x3f;
        if ctrl & !(HWO | LST | CHN | CSP | ISP | IOC | (0x3f << 4)) != 0 || size & !LENGTH != 0 {
            return Err("DWC3 unmodeled TRB flags, streams or status");
        }
        if n < 2 {
            if !matches!(kind, 2..=5)
                || (token == Token::Setup) != (kind == 2)
                || (kind == 2 && (n != 0 || data.len() != 8 || size != 8))
                || (matches!(kind, 3 | 4) && !data.is_empty())
            {
                return Err("DWC3 control token/TRB stage mismatch");
            }
        } else if kind != 1 {
            return Err("DWC3 bulk requires a normal TRB");
        }
        let remaining = (size & LENGTH)
            .checked_sub(transfer.done)
            .ok_or("DWC3 changed active TRB size")? as usize;
        let packet = if token == Token::Setup { 8 } else { ep.packet };
        if data.len() > packet {
            return Err("DWC3 transaction exceeds endpoint max packet");
        }
        let bytes = if token == Token::In {
            remaining.min(data.len())
        } else {
            data.len()
        };
        if bytes > remaining {
            return Err("DWC3 OUT packet exceeds TRB capacity");
        }
        let address = buffer
            .checked_add(u64::from(transfer.done))
            .ok_or("DWC3 payload address overflow")?;
        let short_packet = token == Token::Out && !matches!(kind, 3 | 4) && bytes < packet;
        if short_packet && ctrl & (CSP | CHN) == CSP | CHN {
            return Err("DWC3 short-packet chain fast-forward is not modeled");
        }
        let next_trb = transfer
            .trb
            .checked_add(TRB_BYTES)
            .ok_or("DWC3 TRB list address overflow")?;
        let result = if token == Token::In {
            port.read(address, &mut data[..bytes])
        } else {
            port.write(address, &data[..bytes])
        };
        if let Err(error) = result {
            let write = token != Token::In;
            self.poisoned = Some(DmaFault::new(address, bytes, write, error));
            return Err("DWC3 payload DMA fault; reset required");
        }
        transfer.done += bytes as u32;
        let short = short_packet;
        let complete = transfer.done == size & LENGTH || short;
        if complete {
            let residual = (size & LENGTH) - transfer.done;
            let mut completion = [0; 8];
            completion[..4].copy_from_slice(&residual.to_le_bytes());
            completion[4..].copy_from_slice(&(ctrl & !HWO).to_le_bytes());
            if let Err(error) = port.write(transfer.trb + 8, &completion) {
                self.poisoned = Some(DmaFault::new(
                    transfer.trb + 8,
                    completion.len(),
                    true,
                    error,
                ));
                return Err("DWC3 TRB completion DMA fault; reset required");
            }
            let last = ctrl & LST != 0 || (short && ctrl & CSP == 0);
            let event_kind = if last { XFER_COMPLETE } else { XFER_PROGRESS };
            let event_enable = if last { CFG_COMPLETE } else { CFG_PROGRESS };
            if ep.events & event_enable != 0
                && (last || ctrl & IOC != 0 || (short && ctrl & ISP != 0))
            {
                let status = if short { EV_SHORT } else { 0 }
                    | if ctrl & IOC != 0 { EV_IOC } else { 0 }
                    | if ctrl & LST != 0 { EV_LST } else { 0 };
                self.queue(ep.ring, ep_event(n, event_kind, status, 0))?;
            }
            ep.active = if last {
                None
            } else {
                Some(Transfer {
                    trb: next_trb,
                    done: 0,
                })
            };
        } else {
            ep.active = Some(transfer);
        }
        if token == Token::Setup {
            ep.stalled = false;
            self.endpoints[1].stalled = false;
        }
        ep.not_ready = false;
        self.endpoints[n] = ep;
        Ok(Reply::Ack(bytes))
    }
}

pub struct Peer<'a, 'b, 'c> {
    controller: &'a mut Dwc3,
    dma: &'a mut Port<'b, 'c>,
}
impl BusPeer for Peer<'_, '_, '_> {
    fn reset(&mut self) -> Result<(), &'static str> {
        let controller = &mut self.controller;
        if !controller.available() {
            return Err("DWC3 port or controller is not ready for USB2 reset");
        }
        controller.bus_event();
        controller.connected = true;
        controller.device_event(1)?;
        controller.device_event(2)?;
        Ok(())
    }
    fn packet(
        &mut self,
        endpoint: u8,
        token: Token,
        data: &mut [u8],
    ) -> Result<Reply, &'static str> {
        if endpoint & 0x70 != 0 || (token == Token::In) != (endpoint & 0x80 != 0) {
            return Err("invalid USB endpoint direction or reserved address bits");
        }
        let n = usize::from(endpoint & 0xf) * 2 + usize::from(token == Token::In);
        self.controller.packet(n, token, data, self.dma)
    }
}

impl MmioDevice for Dwc3 {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        self.mmio_ready_at(Some(offset))
            .map_err(|why| refuse(NAME, offset, width, Direction::Read, why))?;
        if offset < xhci::BYTES {
            return self
                .host
                .read(offset, width.bytes(), access.now)
                .map_err(|why| refuse(NAME, offset, width, Direction::Read, why));
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "DWC3 registers require aligned 32-bit accesses",
            ));
        }
        let value = match offset {
            GUCTL1 => self.guctl1,
            GUID => self.guid,
            GTXFIFOPRIDEV => self.tx_priority,
            GCTL => self.gctl,
            GSNPSID => 0x5533_300a,
            GHWPARAMS => (64 << 24) | (32 << 16) | (32 << 8),
            0xc144 => (RINGS as u32) << 15,
            0xc148 | 0xc150 | 0xc154 | 0xc158 => 0,
            0xc14c => (16 << 18) | (32 << 12) | (1 << 2),
            0xc15c => FIFO_WORDS | FIFO_WORDS << 16,
            GUSB2PHYCFG => self.usb2,
            GUSB3PIPECTL => self.usb3,
            GRXFIFOSIZ => self.rx_fifo,
            DCFG => self.dcfg,
            DCTL => self.dctl,
            DEVTEN => self.devten,
            DSTS => {
                RX_EMPTY
                    | if self.dctl & RUN == 0 { HALTED } else { 0 }
                    | if self.connected { 0 } else { 5 << 18 }
            }
            DGCMDPAR => self.generic_parameter,
            DGCMD => self.generic_command,
            DALEPENA => self.enabled,
            at if (GTXFIFOSIZ..GTXFIFOSIZ + 4 * (ENDPOINTS as u64 / 2)).contains(&at) => {
                self.tx_fifo[((at - GTXFIFOSIZ) / 4) as usize]
            }
            at if (GEVNT..GEVNT + STRIDE * RINGS as u64).contains(&at) => {
                let ring = self.rings[((at - GEVNT) / STRIDE) as usize];
                match (at - GEVNT) % STRIDE {
                    0 => ring.address as u32,
                    4 => (ring.address >> 32) as u32,
                    8 => ring.size | if ring.masked { INTMASK } else { 0 },
                    12 => ring.count,
                    _ => unreachable!(),
                }
            }
            at if (DEP..DEP + STRIDE * ENDPOINTS as u64).contains(&at) => {
                let ep = self.endpoints[((at - DEP) / STRIDE) as usize];
                match (at - DEP) % STRIDE {
                    12 => ep.command,
                    field => ep.parameters[(field / 4) as usize],
                }
            }
            at if apple::Registers::claims(at) => self
                .apple
                .read(at)
                .map_err(|why| Self::error(offset, Direction::Read, why))?,
            _ => {
                return Err(Self::error(
                    offset,
                    Direction::Read,
                    "unmodeled DWC3/Apple register",
                ));
            }
        };
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.mmio_ready_at(Some(offset))
            .map_err(|why| refuse(NAME, offset, width, Direction::Write, why))?;
        if offset < xhci::BYTES {
            let result = self.host.write(offset, width.bytes(), value, access.now);
            // This register bank has its own clock. Software RUN/STOP while
            // the PHY clock is off cannot restart the external bus clock.
            if !self.clock_running() {
                self.host.set_clock(false, access.now);
            }
            result.map_err(|why| refuse(NAME, offset, width, Direction::Write, why))?;
            self.interrupts(access);
            return Ok(());
        }
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "DWC3 registers require aligned 32-bit accesses",
            ));
        }
        let value = value as u32;
        let err = |why| Self::error(offset, Direction::Write, why);
        match offset {
            GCTL => {
                // GBLHIBERNATIONEN (bit 1), which AppleT8112USBXHCI::reset
                // sets, has no effect on a core built without hibernation
                // (GHWPARAMS1.EN_PWROPT): it is retained only.
                const GCTL_CONFIG: u32 =
                    0xfff8_0000 | (1 << 16) | PRTCAP | CORE_RESET | (1 << 10) | (3 << 6) | 0x1f;
                if value & !GCTL_CONFIG != 0
                    || !matches!(value & PRTCAP, PRTCAP_HOST | PRTCAP_DEVICE)
                    || value & (3 << 6) != 0
                    || value & (3 << 4) != 0
                {
                    return Err(err(
                        "DWC3 requires host or device mode, bus clock and documented configuration",
                    ));
                }
                if value & CORE_RESET != 0 || value & PRTCAP != PRTCAP_DEVICE {
                    self.release();
                }
                if value & CORE_RESET != 0 {
                    self.host.reset("GCTL core soft reset");
                    self.interrupts(access);
                }
                self.gctl = value;
            }
            GUSB2PHYCFG => {
                const USB2_CONFIG: u32 =
                    (3 << 30) | (1 << 17) | (0xf << 10) | (3 << 8) | (1 << 6) | (1 << 3);
                if value & !USB2_CONFIG != 0 {
                    return Err(err("DWC3 requires documented UTMI PHY configuration"));
                }
                if value & (1 << 31) != 0 {
                    self.bus_event();
                    self.connected = false;
                }
                self.usb2 = value;
            }
            GUSB3PIPECTL => {
                if value & !(1 << 31 | 1 << 17) != 0 {
                    return Err(err("DWC3 has no SuperSpeed PHY"));
                }
                self.usb3 = value;
            }
            DCFG => {
                if value & !DCFG_FIELDS != 0 || !matches!(value & 7, 0 | 4 | 5) {
                    return Err(err("DWC3 connects at high speed only, without streams"));
                }
                self.dcfg = value;
            }
            DCTL => {
                if value & !DCTL_FIELDS != 0 {
                    return Err(err(
                        "DWC3 link state change, test or save/restore request is not modeled",
                    ));
                }
                if value & RESET != 0 {
                    self.reset(access);
                } else {
                    if value & RUN == 0 {
                        self.bus_event();
                        self.connected = false;
                    }
                    self.dctl = value;
                }
            }
            DEVTEN => {
                if value & !DEVTEN_FIELDS != 0 {
                    return Err(err("DWC3 unmodeled device event enable"));
                }
                self.devten = value;
            }
            DALEPENA => self.enabled = value,
            DGCMDPAR => self.generic_parameter = value,
            DGCMD => {
                if value & CMDACT == 0 || value & !(CMDACT | CMDIOC | 0xff) != 0 {
                    return Err(err("invalid DWC3 generic command encoding"));
                }
                if value & 0xff != 0x0a {
                    return Err(err("only DWC3 all-FIFO flush is modeled"));
                }
                if self.endpoints.iter().any(|ep| ep.active.is_some()) {
                    return Err(err("DWC3 active FIFO flush requires transfer cancellation"));
                }
                if value & CMDIOC != 0 && self.devten & (1 << 10) != 0 {
                    self.queue(0, device_event(10)).map_err(err)?;
                }
                // DGCMD command type and IOC are write-only (SPRUHJ7A table 3-120).
                self.generic_command = 0;
            }
            GRXFIFOSIZ => {
                if value > FIFO_WORDS {
                    return Err(err("DWC3 RX FIFO exceeds declared RAM"));
                }
                self.rx_fifo = value;
            }
            at if (GTXFIFOSIZ..GTXFIFOSIZ + 4 * (ENDPOINTS as u64 / 2)).contains(&at) => {
                if (value >> 16) + (value & 0xffff) > FIFO_WORDS {
                    return Err(err("DWC3 TX FIFO exceeds declared RAM"));
                }
                self.tx_fifo[((at - GTXFIFOSIZ) / 4) as usize] = value;
            }
            at if (GEVNT..GEVNT + STRIDE * RINGS as u64).contains(&at) => {
                let index = ((at - GEVNT) / STRIDE) as usize;
                let ring = &mut self.rings[index];
                match (at - GEVNT) % STRIDE {
                    field @ (0 | 4) => {
                        if ring.count != 0 || self.pending.iter().any(|event| event.ring == index) {
                            return Err(err("cannot relocate a DWC3 ring with pending events"));
                        }
                        if field == 0 {
                            if value & 3 != 0 {
                                return Err(err("DWC3 event ring must be word aligned"));
                            }
                            ring.address = ring.address & !0xffff_ffff | u64::from(value);
                        } else {
                            ring.address = ring.address & 0xffff_ffff | u64::from(value) << 32;
                        }
                        ring.producer = 0;
                    }
                    8 => {
                        if value & !(INTMASK | 0xfffc) != 0 {
                            return Err(err(
                                "DWC3 event size must be a multiple of four; reserved bits",
                            ));
                        }
                        let size = value & 0xfffc;
                        if size != ring.size
                            && (ring.count != 0
                                || self.pending.iter().any(|event| event.ring == index))
                        {
                            return Err(err("cannot resize a DWC3 ring with pending events"));
                        }
                        if size != ring.size {
                            ring.producer = 0;
                        }
                        ring.size = size;
                        ring.masked = value & INTMASK != 0;
                    }
                    12 => {
                        if value & !0xfffc != 0 || value > ring.count {
                            return Err(err(
                                "DWC3 event acknowledgement exceeds pending byte count or is unaligned",
                            ));
                        }
                        ring.count -= value;
                    }
                    _ => unreachable!(),
                }
                self.interrupts(access);
            }
            at if (DEP..DEP + STRIDE * ENDPOINTS as u64).contains(&at) => {
                let index = ((at - DEP) / STRIDE) as usize;
                match (at - DEP) % STRIDE {
                    12 => self.endpoint_command(index, value).map_err(err)?,
                    field => self.endpoints[index].parameters[(field / 4) as usize] = value,
                }
            }
            GUCTL1 => {
                if value & !GUCTL1_FIELDS != 0 {
                    return Err(err("unmodeled DWC3 GUCTL1 fields"));
                }
                self.guctl1 = value;
            }
            // A software-defined identification word.
            GUID => self.guid = value,
            GTXFIFOPRIDEV => {
                if value >> (ENDPOINTS / 2) != 0 {
                    return Err(err("DWC3 TX FIFO priority names a FIFO the core lacks"));
                }
                self.tx_priority = value;
            }
            at if apple::Registers::claims(at) => self.apple.write(at, value).map_err(err)?,
            _ => return Err(err("read-only or unmodeled DWC3/Apple register")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::{dart::Dart, interrupt::InterruptLatch},
        dma::{Memory, tests::Ram},
    };
    use alloc::vec;
    const RAM: u64 = 0x1_0000_0000;
    const TRB: u64 = RAM + 0x1000;
    const PAYLOAD: u64 = RAM + 0x2000;
    const EVENTS: u64 = RAM + 0x4000;
    const DART_TCR: u64 = 0x1000;
    const DART_ENABLE: u64 = 0xc00;
    const SID: usize = 1;
    fn irqs() -> [AicInput; RINGS] {
        core::array::from_fn(|i| AicInput::new(0, 1031 + i as u16))
    }
    struct Attached(u64, bool);
    impl PortState for Attached {
        fn generation(&self) -> u64 {
            self.0
        }
        fn high_speed_device_ready(&self) -> bool {
            self.1
        }
    }
    fn write(dwc: &mut Dwc3, at: u64, value: u32, access: &mut Access<'_>) {
        dwc.write(at, Width::Word, u64::from(value), access)
            .unwrap();
    }
    fn configure(dwc: &mut Dwc3, n: usize, ring: usize, access: &mut Access<'_>) {
        let base = DEP + n as u64 * STRIDE;
        write(dwc, base, 0, access);
        write(
            dwc,
            base + 4,
            (n as u32) << 25 | CFG_COMPLETE | CFG_PROGRESS | CFG_NOT_READY | ring as u32,
            access,
        );
        let packet = if n < 2 { 64 } else { 512 };
        write(
            dwc,
            base + 8,
            packet << 3 | if n < 2 { 0 } else { 2 << 1 },
            access,
        );
        write(dwc, base + 12, CMDACT | 1, access);
        write(dwc, base + 8, 1, access);
        write(dwc, base + 4, 0, access);
        write(dwc, base + 12, CMDACT | 2, access);
    }
    fn start(dwc: &mut Dwc3, n: usize, address: u64, access: &mut Access<'_>) {
        let base = DEP + n as u64 * STRIDE;
        write(dwc, base, 0, access);
        write(dwc, base + 4, address as u32, access);
        write(dwc, base + 8, (address >> 32) as u32, access);
        write(dwc, base + 12, CMDACT | 6, access);
        assert_eq!(dwc.read(base + 12, Width::Word, access).unwrap() >> 16, 1);
    }
    fn trb(ram: &mut Ram, at: u64, bytes: u32, ctrl: u32) {
        let mut trb = [0; 16];
        trb[..8].copy_from_slice(&PAYLOAD.to_le_bytes());
        trb[8..12].copy_from_slice(&bytes.to_le_bytes());
        trb[12..].copy_from_slice(&ctrl.to_le_bytes());
        assert!(ram.write(at, &trb));
    }
    fn setup() -> (Dwc3, Dart, Ram, InterruptLatch) {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut dart = Dart::new(16, Some(AicInput::new(0, 1035)));
        write_dart(&mut dart, DART_ENABLE, 1 << SID, &mut access);
        write_dart(&mut dart, DART_TCR + SID as u64 * 4, 6, &mut access);
        let mut dwc = Dwc3::new(irqs());
        dwc.set_phy_state(false, true, true, false, &mut access);
        dwc.sync_port(&Attached(1, true)).unwrap();
        write(&mut dwc, DCTL, RUN, &mut access);
        let mut ram = Ram::new(RAM, 0x10000);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            dwc.peer(&mut port).reset().unwrap();
        }
        write(&mut dwc, GEVNT, EVENTS as u32, &mut access);
        write(&mut dwc, GEVNT + 4, (EVENTS >> 32) as u32, &mut access);
        write(&mut dwc, GEVNT + 8, 0x800, &mut access);
        write(&mut dwc, DALEPENA, u32::MAX, &mut access);
        (dwc, dart, ram, latch)
    }
    fn write_dart(dart: &mut Dart, at: u64, value: u32, access: &mut Access<'_>) {
        dart.write(at, Width::Word, u64::from(value), access)
            .unwrap();
    }
    #[test]
    fn a_host_command_completion_raises_its_interrupters_shared_wire() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let (erst, ring, commands) = (RAM + 0x8000, RAM + 0x9000, RAM + 0xa000);
        assert!(ram.write(erst, &ring.to_le_bytes()));
        assert!(ram.write(erst + 8, &16u64.to_le_bytes()));
        let command = (23u64 << 42) | 1 << 32; // No Op, cycle one
        assert!(ram.write(commands + 8, &command.to_le_bytes()));
        let mut access = Access::new(0, 0, &mut latch);
        // Interrupter 0 at runtime offset 0x20 (RTSOFF 0x440).
        write(&mut dwc, 0x468, 1, &mut access);
        write(&mut dwc, 0x478, ring as u32, &mut access);
        write(&mut dwc, 0x47c, (ring >> 32) as u32, &mut access);
        write(&mut dwc, 0x470, erst as u32, &mut access);
        write(&mut dwc, 0x474, (erst >> 32) as u32, &mut access);
        write(&mut dwc, 0x460, 2, &mut access);
        write(&mut dwc, 0x38, commands as u32 | 1, &mut access);
        write(&mut dwc, 0x3c, (commands >> 32) as u32, &mut access);
        write(&mut dwc, 0x20, 1 | 4, &mut access);
        write(&mut dwc, 0x4e0, 0, &mut access);
        assert!(dwc.host_pending());
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.service_host(&mut port, None).unwrap();
        assert!(!dwc.host_pending());
        assert!(latch.is_asserted(Wire::Aic(irqs()[0])));
    }

    #[test]
    fn lifecycle_keeps_partial_device_dma_on_clock_and_retained_power_and_cancels_reset_work() {
        for retention in [false, true] {
            let (mut dwc, mut dart, mut ram, mut latch) = setup();
            let mut access = Access::new(0, 0, &mut latch);
            configure(&mut dwc, 2, 0, &mut access);
            trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
            start(&mut dwc, 2, TRB, &mut access);
            let mut packet = [0x5a; 512];
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
                Ok(Reply::Ack(512))
            );
            assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
            dwc.set_clock(false, port.access);
            assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
            assert!(
                dwc.peer(&mut port)
                    .packet(1, Token::Out, &mut packet)
                    .is_err()
            );
            assert!(dwc.flush(&mut port).is_err());
            assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
            dwc.set_clock(true, port.access);
            dwc.set_quiesced(true);
            assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(RUN.into()));
            assert!(
                dwc.peer(&mut port)
                    .packet(1, Token::Out, &mut packet)
                    .is_err()
            );
            dwc.set_quiesced(false);
            dwc.set_power(false, retention, port.access);
            assert!(dwc.flush(&mut port).is_err());
            dwc.set_power(true, retention, port.access);
            let mut committed = [0; 512];
            assert!(port.memory.read(PAYLOAD, &mut committed));
            assert_eq!(committed, [0x5a; 512]);
            if retention {
                assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
                packet.fill(0xa5);
                assert_eq!(
                    dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
                    Ok(Reply::Ack(512))
                );
                dwc.flush(&mut port).unwrap();
                assert_eq!(dwc.rings[0].count, 4);
                assert!(port.memory.read(PAYLOAD + 512, &mut committed));
                assert_eq!(committed, [0xa5; 512]);
                // Another real, still-owned transfer is canceled by reset,
                // regardless of retention. Its committed prefix stays RAM.
                trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
                let mut port = Port {
                    iommu: &mut dart,
                    stream: SID,
                    memory: &mut ram,
                    access: &mut access,
                };
                start(&mut dwc, 2, TRB, port.access);
                assert_eq!(
                    dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
                    Ok(Reply::Ack(512))
                );
                dwc.set_reset(true, port.access);
                assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
                assert!(
                    dwc.peer(&mut port)
                        .packet(1, Token::Out, &mut packet)
                        .is_err()
                );
                dwc.set_reset(false, port.access);
                assert!(dwc.endpoints[2].active.is_none());
                assert!(dwc.pending.is_empty());
                assert_eq!(dwc.rings[0].count, 0);
                assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
                assert!(dwc.take_session_reset());
                assert!(!dwc.take_session_reset());
                assert!(port.memory.read(PAYLOAD, &mut committed));
                assert_eq!(committed, [0xa5; 512]);
                dwc.flush(&mut port).unwrap();
                let mut owned = [0; 4];
                assert!(port.memory.read(TRB + 12, &mut owned));
                assert_ne!(u32::from_le_bytes(owned) & HWO, 0);
            } else {
                assert!(dwc.endpoints[2].active.is_none());
                assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
                assert!(dwc.take_session_reset());
                assert_eq!(dwc.rings[0].address, 0);
            }
        }
    }

    #[test]
    fn software_core_reset_keeps_globals_readable_and_physical_reset_keeps_phy_configuration() {
        let (mut dwc, _, _, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        let gctl = dwc.gctl;
        write(&mut dwc, GCTL, gctl | CORE_RESET, &mut access);
        assert_eq!(dwc.read(GSNPSID, Width::Word, &mut access), Ok(0x5533_300a));
        assert_eq!(
            dwc.read(GCTL, Width::Word, &mut access),
            Ok((gctl | CORE_RESET).into())
        );
        write(&mut dwc, GUID, 0x1234, &mut access);
        assert_eq!(dwc.read(GUID, Width::Word, &mut access), Ok(0x1234));
        write(&mut dwc, GCTL, gctl, &mut access);
        dwc.set_phy_state(true, false, true, false, &mut access);
        // XDCI power-on clears SUSPHY in both PHY configuration words while
        // the PHY holds the reset; they keep it past the release.
        for offset in [GUSB2PHYCFG, GUSB3PIPECTL] {
            write(&mut dwc, offset, 0, &mut access);
            assert_eq!(dwc.read(offset, Width::Word, &mut access), Ok(0));
        }
        write(&mut dwc, GUSB2PHYCFG, 1 << 3, &mut access);
        for offset in [GSNPSID, GCTL, DCTL] {
            assert!(matches!(dwc.read(offset, Width::Word, &mut access),
                Err(MmioError::Unsupported { reason, .. }) if reason.contains("unqualified")));
        }
        assert!(
            matches!(dwc.write(GCTL, Width::Word, gctl.into(), &mut access),
            Err(MmioError::Unsupported { reason, .. }) if reason.contains("unqualified"))
        );
        dwc.set_phy_state(false, true, true, false, &mut access);
        assert_eq!(dwc.read(GSNPSID, Width::Word, &mut access), Ok(0x5533_300a));
        assert_eq!(dwc.read(GUSB2PHYCFG, Width::Word, &mut access), Ok(1 << 3));
    }

    #[test]
    fn phy_electrical_edges_preserve_transfer_resources_and_reset_sources_are_ored() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
        start(&mut dwc, 2, TRB, &mut access);
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.peer(&mut port).reset().unwrap();
        let mut packet = [0x37; 512];
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
            Ok(Reply::Ack(512))
        );
        dwc.pending.clear();
        dwc.devten = 1; // Disconnect event enabled.
        dwc.set_phy_state(false, false, true, false, port.access);
        dwc.set_phy_state(false, true, true, false, port.access);
        // Final-ready must not swallow the edge.
        assert_eq!(
            dwc.unavailable(),
            Some("a PHY disconnect is pending service")
        );
        assert!(dwc.take_session_reset());
        // Backpressure preserves both the connection and its pending edge.
        for _ in 0..MAX_PENDING_EVENTS {
            dwc.queue(0, 7).unwrap();
        }
        assert!(dwc.sync_port(&Attached(1, true)).is_err());
        assert!(dwc.connected);
        assert!(dwc.pending_phy_disconnect);
        dwc.pending.clear();
        dwc.sync_port(&Attached(1, true)).unwrap();
        assert!(!dwc.connected);
        assert_eq!(dwc.pending.len(), 1);
        assert_eq!(dwc.pending[0].value, device_event(0));
        assert!(dwc.endpoints[2].resource);
        assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
        dwc.peer(&mut port).reset().unwrap();
        packet.fill(0x73);
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
            Ok(Reply::Ack(512))
        );
        dwc.set_phy_state(true, false, true, false, port.access);
        dwc.set_reset(true, port.access);
        dwc.set_phy_state(false, true, true, false, port.access);
        assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
        dwc.set_reset(false, port.access);
        assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
        assert!(dwc.endpoints[2].active.is_none());
        assert!(!dwc.endpoints[2].resource);
        // Reversing the release order cannot clear the PHY's reset either.
        dwc.set_reset(true, port.access);
        dwc.set_phy_state(true, false, true, false, port.access);
        dwc.set_reset(false, port.access);
        assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
        dwc.set_phy_state(false, true, true, false, port.access);
        assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
        let mut committed = [0; 512];
        assert!(port.memory.read(PAYLOAD, &mut committed));
        assert_eq!(committed, [0x37; 512]);
        assert!(port.memory.read(PAYLOAD + 512, &mut committed));
        assert_eq!(committed, [0x73; 512]);
    }

    #[test]
    fn lifecycle_retains_real_host_rings_freezes_microframes_and_reset_prevents_stale_completion() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let (erst, ring, commands) = (RAM + 0x8000, RAM + 0x9000, RAM + 0xa000);
        ram.put_u64(erst, ring);
        ram.put_u64(erst + 8, 16);
        ram.put_u64(commands + 8, (23u64 << 42) | 1 << 32);
        let mut access = Access::new(0, 0, &mut latch);
        write(&mut dwc, 0x468, 1, &mut access);
        write(&mut dwc, 0x478, ring as u32, &mut access);
        write(&mut dwc, 0x47c, (ring >> 32) as u32, &mut access);
        write(&mut dwc, 0x470, erst as u32, &mut access);
        write(&mut dwc, 0x474, (erst >> 32) as u32, &mut access);
        write(&mut dwc, 0x460, 2, &mut access);
        write(&mut dwc, 0x38, commands as u32 | 1, &mut access);
        write(&mut dwc, 0x3c, (commands >> 32) as u32, &mut access);
        write(&mut dwc, 0x20, 1 | 4, &mut access);
        write(&mut dwc, 0x4e0, 0, &mut access);
        access.now = 15_000; // five microframes
        assert_eq!(dwc.read(0x440, Width::Word, &mut access), Ok(5));
        // The PHY clock freezes time without blocking the independently
        // clocked DWC register bank. Quiesce stops DMA only.
        dwc.set_phy_state(false, true, false, false, &mut access);
        access.now = 900_000;
        assert_eq!(dwc.read(0x440, Width::Word, &mut access), Ok(5));
        dwc.set_phy_state(false, true, true, true, &mut access);
        access.now = 915_000;
        assert_eq!(dwc.read(0x440, Width::Word, &mut access), Ok(10));
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(dwc.service_host(&mut port, None).is_err());
        dwc.set_phy_state(false, true, true, false, port.access);
        dwc.set_clock(false, port.access);
        port.access.now = 999_000;
        assert!(dwc.service_host(&mut port, None).is_err());
        let mut event = [0; 16];
        assert!(port.memory.read(ring, &mut event));
        assert_eq!(event, [0; 16]);
        dwc.set_clock(true, port.access);
        assert_eq!(dwc.read(0x440, Width::Word, port.access), Ok(10));
        dwc.service_host(&mut port, None).unwrap();
        assert!(port.memory.read(ring, &mut event));
        assert_eq!(
            u32::from_le_bytes(event[8..12].try_into().unwrap()) >> 24,
            1
        );
        dwc.set_power(false, true, port.access);
        assert!(dwc.read(0x440, Width::Word, port.access).is_err());
        port.access.now = 1_999_000;
        dwc.set_power(true, true, port.access);
        assert_eq!(dwc.read(0x440, Width::Word, port.access), Ok(10));
        // Queue another actual command; reset cancels it while preserving
        // the previous event already committed to guest RAM.
        assert!(
            port.memory
                .write(commands + 24, &((23u64 << 42) | 1 << 32).to_le_bytes())
        );
        write(&mut dwc, 0x4e0, 0, port.access);
        assert!(dwc.host_pending());
        dwc.set_reset(true, port.access);
        assert!(!dwc.host_pending());
        dwc.set_reset(false, port.access);
        dwc.service_host(&mut port, None).unwrap();
        let mut kept = [0; 16];
        assert!(port.memory.read(ring, &mut kept));
        assert_eq!(kept, event);
        assert!(port.memory.read(ring + 16, &mut kept));
        assert_eq!(kept, [0; 16]);
        assert_eq!(dwc.read(0x20, Width::Word, port.access), Ok(0));
        assert!(dwc.take_session_reset());
    }

    #[test]
    fn the_host_driver_selects_host_mode_which_idles_the_device() {
        let (mut dwc, _, _, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        dwc.connected = true;
        // AppleT8112USBXHCI::start: clear PRTCAPDIR, select host.
        let gctl = dwc.read(GCTL, Width::Word, &mut access).unwrap() as u32;
        write(&mut dwc, GCTL, gctl & !PRTCAP | PRTCAP_HOST, &mut access);
        assert_eq!(
            dwc.read(GCTL, Width::Word, &mut access),
            Ok(u64::from(PRTCAP_HOST))
        );
        assert!(!dwc.connected && !dwc.available());
        for reserved in [0, PRTCAP] {
            assert!(
                dwc.write(GCTL, Width::Word, u64::from(reserved), &mut access)
                    .is_err()
            );
        }
        write(&mut dwc, GCTL, PRTCAP_DEVICE, &mut access);
        assert_eq!(dwc.gctl, PRTCAP_DEVICE);
    }
    #[test]
    fn registers_commands_widths_and_failures_have_real_state() {
        let (mut dwc, _, _, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(dwc.read(GSNPSID, Width::Word, &mut access), Ok(0x5533_300a));
        assert!(dwc.read(GSNPSID, Width::Double, &mut access).is_err());
        assert_eq!(dwc.read(0xcd38, Width::Word, &mut access), Ok(0));
        assert!(dwc.read(0xcd44, Width::Word, &mut access).is_err());
        // initDeviceController's GUCTL1 and GUID accesses.
        assert_eq!(dwc.read(GUCTL1, Width::Word, &mut access), Ok(0));
        assert!(dwc.write(GUCTL1, Width::Word, 0x8000, &mut access).is_err());
        write(&mut dwc, GUCTL1, 1 << 31, &mut access);
        assert_eq!(dwc.read(GUCTL1, Width::Word, &mut access), Ok(1 << 31));
        write(&mut dwc, GUID, 0x1234_5678, &mut access);
        assert_eq!(dwc.read(GUID, Width::Word, &mut access), Ok(0x1234_5678));
        assert!(
            dwc.write(GTXFIFOPRIDEV, Width::Word, 1 << 16, &mut access)
                .is_err()
        );
        // A SuperSpeed maximum connects at high speed; full speed refuses.
        write(&mut dwc, DCFG, 4 | 1 << 22, &mut access);
        assert!(dwc.write(DCFG, Width::Word, 1, &mut access).is_err());
        // DCTL test control refuses; the LPM threshold is retained.
        assert!(
            dwc.write(DCTL, Width::Word, u64::from(RUN | 1 << 1), &mut access)
                .is_err()
        );
        write(&mut dwc, DCTL, RUN | 6 << 20, &mut access);
        write(&mut dwc, DCTL, RUN, &mut access);
        assert_eq!(dwc.dctl, RUN);
        write(&mut dwc, DEP + 12, CMDACT | 6, &mut access);
        assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, CMD_FAILURE);
        write(&mut dwc, DEVTEN, 1 << 10, &mut access);
        write(&mut dwc, DGCMD, CMDACT | CMDIOC | 0x0a, &mut access);
        assert_eq!(dwc.read(DGCMD, Width::Word, &mut access), Ok(0));
        assert_eq!(dwc.pending.front().unwrap().value, device_event(10));
        configure(&mut dwc, 2, 0, &mut access);
        write(&mut dwc, DEP + 2 * STRIDE + 12, CMDACT | 4, &mut access);
        assert!(dwc.endpoints[2].stalled);
        write(&mut dwc, DEP + 2 * STRIDE + 12, CMDACT | 5, &mut access);
        assert!(!dwc.endpoints[2].stalled);
        let command = dwc.endpoints[2].command;
        assert!(
            dwc.write(
                DEP + 2 * STRIDE + 12,
                Width::Word,
                u64::from(CMDACT | 3),
                &mut access
            )
            .is_err()
        );
        assert_eq!(dwc.endpoints[2].command, command);
        // An interrupt IN endpoint (EP 2 IN, number 5) with its interval;
        // the interval field is reserved on bulk endpoints.
        let base = DEP + 5 * STRIDE;
        write(&mut dwc, base, 0, &mut access);
        write(
            &mut dwc,
            base + 4,
            5 << 25 | CFG_COMPLETE | 3 << 16,
            &mut access,
        );
        write(&mut dwc, base + 8, 16 << 3 | INTERRUPT << 1, &mut access);
        write(&mut dwc, base + 12, CMDACT | 1, &mut access);
        assert_eq!(dwc.endpoints[5].command & CMD_FAILURE, 0);
        assert!(dwc.endpoints[5].configured);
        write(&mut dwc, base + 8, 16 << 3 | 2 << 1, &mut access);
        assert!(
            dwc.write(base + 12, Width::Word, u64::from(CMDACT | 1), &mut access)
                .is_err()
        );
        // A bulk endpoint retains its SuperSpeed burst; an interrupt
        // endpoint's burst field refuses.
        write(&mut dwc, base + 4, 5 << 25 | CFG_COMPLETE, &mut access);
        write(&mut dwc, base + 8, BURST | 512 << 3 | 2 << 1, &mut access);
        write(&mut dwc, base + 12, CMDACT | 1, &mut access);
        assert_eq!(dwc.endpoints[5].command & CMD_FAILURE, 0);
        write(
            &mut dwc,
            base + 8,
            BURST | 16 << 3 | INTERRUPT << 1,
            &mut access,
        );
        assert!(
            dwc.write(base + 12, Width::Word, u64::from(CMDACT | 1), &mut access)
                .is_err()
        );
    }

    #[test]
    fn ep0_configures_for_superspeed_then_modifies_to_the_connected_speed() {
        let (mut dwc, _, _, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        for (packet, action) in [(512, 0), (64, 2 << 30)] {
            write(&mut dwc, DEP, 0, &mut access);
            write(&mut dwc, DEP + 4, CFG_COMPLETE | CFG_NOT_READY, &mut access);
            write(&mut dwc, DEP + 8, action | packet << 3, &mut access);
            write(&mut dwc, DEP + 12, CMDACT | 1, &mut access);
            assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, 0);
            assert_eq!(dwc.endpoints[0].packet, packet as usize);
        }
        write(&mut dwc, DEP + 8, 1024 << 3, &mut access);
        write(&mut dwc, DEP + 12, CMDACT | 1, &mut access);
        assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, CMD_FAILURE);
    }
    #[test]
    fn bulk_dma_partial_short_and_events_precede_aic() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
        start(&mut dwc, 2, TRB, &mut access);
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut [0x5a; 512]),
            Ok(Reply::Ack(512))
        );
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut [0x6b; 7]),
            Ok(Reply::Ack(7))
        );
        assert_eq!(dwc.rings[0].count, 0);
        dwc.flush(&mut port).unwrap();
        assert_eq!(dwc.rings[0].count, 4);
        let mut back = [0; 16];
        port.read(TRB, &mut back).unwrap();
        assert_eq!(u32::from_le_bytes(back[8..12].try_into().unwrap()), 505);
        assert_eq!(u32::from_le_bytes(back[12..].try_into().unwrap()) & HWO, 0);
        let mut data = [0; 519];
        port.read(PAYLOAD, &mut data).unwrap();
        assert_eq!(data[..512], [0x5a; 512]);
        assert_eq!(data[512..], [0x6b; 7]);
        let mut event = [0; 4];
        port.read(EVENTS, &mut event).unwrap();
        assert_eq!(
            u32::from_le_bytes(event),
            ep_event(2, XFER_COMPLETE, EV_SHORT | EV_IOC | EV_LST, 0)
        );
        assert!(latch.take_aic_inputs().contains(&(irqs()[0], true)));
        let mut access = Access::new(0, 0, &mut latch);
        write(&mut dwc, GEVNT + 12, 4, &mut access);
        assert_eq!(latch.take_aic_inputs(), [(irqs()[0], false)]);
    }
    #[test]
    fn programmed_ring_wrap_mask_and_overflow_backpressure() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        write(&mut dwc, GEVNT + 8, 8 | INTMASK, &mut access);
        for value in [11, 22, 33] {
            dwc.queue(0, value).unwrap();
        }
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            dwc.flush(&mut port).unwrap();
        }
        assert_eq!(dwc.rings[0].count, 8);
        assert_eq!(dwc.pending.len(), 1);
        assert!(latch.take_aic_inputs().is_empty());
        let mut access = Access::new(0, 0, &mut latch);
        write(&mut dwc, GEVNT + 8, 8, &mut access);
        assert!(dwc.write(GEVNT + 12, Width::Word, 12, &mut access).is_err());
        assert_eq!(dwc.rings[0].count, 8);
        write(&mut dwc, GEVNT + 12, 4, &mut access);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            dwc.flush(&mut port).unwrap();
            let mut event = [0; 4];
            port.read(EVENTS, &mut event).unwrap();
            assert_eq!(u32::from_le_bytes(event), 33);
        }
        assert_eq!(dwc.rings[0].producer, 4);
        assert_eq!(dwc.rings[0].count, 8);
    }
    #[test]
    fn in_link_trbs_stall_update_end_and_detach_leaves_transfers_to_software() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 3, 0, &mut access);
        ram.put_u64(TRB, TRB + 16);
        assert!(ram.write(TRB + 8, &[0, 0, 0, 0, 0x81, 0, 0, 0]));
        trb(&mut ram, TRB + 16, 3, HWO | LST | IOC | 1 << 4);
        assert!(ram.write(PAYLOAD, b"abc"));
        start(&mut dwc, 3, TRB, &mut access);
        let mut bytes = [0; 512];
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                dwc.peer(&mut port).packet(0x81, Token::In, &mut bytes),
                Ok(Reply::Ack(3))
            );
        }
        assert_eq!(&bytes[..3], b"abc");
        trb(&mut ram, TRB, 512, HWO | LST | 1 << 4);
        start(&mut dwc, 3, TRB, &mut access);
        write(
            &mut dwc,
            DEP + 3 * STRIDE + 12,
            CMDACT | 7 | 1 << 16,
            &mut access,
        );
        assert!(dwc.endpoints[3].active.is_some());
        write(
            &mut dwc,
            DEP + 3 * STRIDE + 12,
            CMDACT | 8 | 1 << 11 | 1 << 16,
            &mut access,
        );
        assert!(dwc.endpoints[3].active.is_none());
        start(&mut dwc, 3, TRB, &mut access);
        dwc.sync_port(&Attached(2, false)).unwrap();
        // Detach leaves the started transfer to software's End Transfer.
        assert!(dwc.endpoints[3].active.is_some());
        assert!(dwc.endpoints[3].resource);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                dwc.peer(&mut port).packet(0x81, Token::In, &mut bytes),
                Ok(Reply::Nak)
            );
        }
        write(
            &mut dwc,
            DEP + 3 * STRIDE + 12,
            CMDACT | 8 | 1 << 11 | 1 << 16,
            &mut access,
        );
        assert!(dwc.endpoints[3].active.is_none());
        assert_eq!(dwc.endpoints[3].command & CMD_FAILURE, 0);
    }
    #[test]
    fn usb_reset_keeps_ep0_transfer_resources_for_the_next_setup_transfer() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 0, 0, &mut access);
        configure(&mut dwc, 1, 0, &mut access);
        trb(&mut ram, TRB, 8, HWO | LST | IOC | 2 << 4);
        start(&mut dwc, 0, TRB, &mut access);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            dwc.peer(&mut port).reset().unwrap();
        }
        // The SETUP transfer started before the reset is still armed.
        assert!(dwc.endpoints[0].active.is_some());
        // The driver ends it and restarts EP0 OUT on the same resource.
        write(
            &mut dwc,
            DEP + 12,
            CMDACT | 8 | 1 << 11 | 1 << 16,
            &mut access,
        );
        assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, 0);
        start(&mut dwc, 0, TRB, &mut access);
        assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, 0);
        // A detach and reattach also keeps the resource.
        write(
            &mut dwc,
            DEP + 12,
            CMDACT | 8 | 1 << 11 | 1 << 16,
            &mut access,
        );
        dwc.sync_port(&Attached(2, true)).unwrap();
        start(&mut dwc, 0, TRB, &mut access);
        // Only Start Configuration or a core reset releases it.
        write(
            &mut dwc,
            DEP + 12,
            CMDACT | 8 | 1 << 11 | 1 << 16,
            &mut access,
        );
        let gctl = dwc.gctl;
        write(&mut dwc, GCTL, gctl | CORE_RESET, &mut access);
        assert!(!dwc.endpoints[0].resource);
    }
    #[test]
    fn setup_data_status_trbs_and_zero_length_packet() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 0, 0, &mut access);
        configure(&mut dwc, 1, 0, &mut access);
        for (endpoint, token, kind, mut bytes) in [
            (0, Token::Setup, 2, vec![0x80, 6, 0, 1, 0, 0, 18, 0]),
            (0x80, Token::In, 5, vec![0; 18]),
            (0, Token::Out, 4, vec![]),
        ] {
            let n = usize::from(endpoint & 0xf) * 2 + usize::from(endpoint & 0x80 != 0);
            trb(&mut ram, TRB, bytes.len() as u32, HWO | LST | kind << 4);
            start(&mut dwc, n, TRB, &mut access);
            let length = bytes.len();
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                dwc.peer(&mut port).packet(endpoint, token, &mut bytes),
                Ok(Reply::Ack(length))
            );
        }
    }
    #[test]
    fn dart_fault_poisoning_and_software_reset_prevent_stale_completion() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, TRB, 512, HWO | LST | 1 << 4);
        start(&mut dwc, 2, TRB, &mut access);
        write_dart(&mut dart, DART_TCR + SID as u64 * 4, 0, &mut access);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            assert!(
                dwc.peer(&mut port)
                    .packet(1, Token::Out, &mut [1; 512])
                    .is_err()
            );
            assert!(dwc.flush(&mut port).is_err());
        }
        assert!(dwc.poisoned.is_some());
        assert_eq!(dwc.rings[0].count, 0);
        assert!(
            latch
                .take_aic_inputs()
                .iter()
                .any(|&(irq, level)| irq.irq == 1035 && level)
        );
        let mut access = Access::new(0, 0, &mut latch);
        write(&mut dwc, DCTL, RESET, &mut access);
        assert!(dwc.poisoned.is_none());
        assert!(dwc.endpoints.iter().all(|ep| ep.active.is_none()));
        assert_eq!(dwc.read(DCTL, Width::Word, &mut access), Ok(0));
    }
    #[test]
    fn translated_dma_crosses_pages_and_stops_at_dart_write_permission() {
        const IOVA: u64 = 0x20000000;
        const PAGE: u64 = 0x4000;
        const LEAVES: u64 = RAM + PAGE;
        const FRAME: u64 = RAM + 2 * PAGE;
        let entry = |pa: u64| ((pa >> 4) & 0x3f_ffff_fc00) | 1;
        for writable in [true, false] {
            let (mut dwc, mut dart, mut ram, mut latch) = setup();
            let mut access = Access::new(0, 0, &mut latch);
            ram.put_u64(RAM + 8 * (IOVA >> 25), entry(LEAVES));
            ram.put_u64(LEAVES, entry(FRAME) | 0xfff << 40);
            ram.put_u64(
                LEAVES + 8,
                entry(FRAME + PAGE) | 0xfff << 40 | if writable { 0 } else { 1 << 2 },
            );
            write_dart(
                &mut dart,
                0x1400 + SID as u64 * 4,
                ((RAM >> 14) << 2) as u32 | 1,
                &mut access,
            );
            write_dart(&mut dart, DART_TCR + SID as u64 * 4, 1, &mut access);
            configure(&mut dwc, 2, 0, &mut access);
            trb(&mut ram, FRAME + 0x1000, 512, HWO | LST | IOC | 1 << 4);
            ram.put_u64(FRAME + 0x1000, IOVA + PAGE - 16);
            write(&mut dwc, GEVNT, (IOVA + 0x100) as u32, &mut access);
            write(&mut dwc, GEVNT + 4, 0, &mut access);
            start(&mut dwc, 2, IOVA + 0x1000, &mut access);
            let result = {
                let mut port = Port {
                    iommu: &mut dart,
                    stream: SID,
                    memory: &mut ram,
                    access: &mut access,
                };
                let result = dwc.peer(&mut port).packet(1, Token::Out, &mut [0x7c; 512]);
                if result.is_ok() {
                    dwc.flush(&mut port).unwrap();
                }
                result
            };
            assert_eq!(
                &ram.bytes[(3 * PAGE - 16) as usize..(3 * PAGE) as usize],
                &[0x7c; 16]
            );
            if writable {
                assert_eq!(result, Ok(Reply::Ack(512)));
                assert_eq!(
                    &ram.bytes[(3 * PAGE) as usize..(3 * PAGE + 496) as usize],
                    &[0x7c; 496]
                );
                assert_eq!(dwc.rings[0].count, 4);
            } else {
                assert!(result.is_err());
                assert!(dwc.poisoned.is_some());
                assert_eq!(dwc.rings[0].count, 0);
                assert_eq!(
                    &ram.bytes[(3 * PAGE) as usize..(3 * PAGE + 496) as usize],
                    &[0; 496]
                );
            }
        }
    }

    #[test]
    fn host_enumeration_reaches_real_control_trb_dma_and_event_buffers() {
        use crate::platform::usb::host::Host;
        // A small synthetic guest driver: posts actual TRBs between host
        // steps. It supplies test descriptors; production has no descriptors.
        let device = vec![18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0, 1, 0, 1, 0, 0, 0, 1];
        let config = vec![
            9, 2, 32, 0, 1, 7, 0, 0x80, 50, 9, 4, 3, 0, 2, 0xff, 0xfe, 2, 0, 7, 5, 0x85, 2, 0, 2,
            0, 7, 5, 9, 2, 0, 2, 0,
        ];
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut host = Host::new();
        host.attach(1);
        {
            let mut access = Access::new(0, 0, &mut latch);
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            host.advance(&mut dwc.peer(&mut port), 0).unwrap();
        }
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 0, 0, &mut access);
        configure(&mut dwc, 1, 0, &mut access);
        trb(&mut ram, TRB, 8, HWO | LST | IOC | 2 << 4);
        start(&mut dwc, 0, TRB, &mut access);
        // (posted endpoint, phase): setup=0, data=1, status=2.
        let mut posted = (0, 0);
        let mut address = 0;
        let mut configuration = 0;
        let mut request = [0; 8];
        for step in 1..100 {
            let now = step * 24000;
            let mut access = Access::new(0, now, &mut latch);
            {
                let mut port = Port {
                    iommu: &mut dart,
                    stream: SID,
                    memory: &mut ram,
                    access: &mut access,
                };
                host.advance(&mut dwc.peer(&mut port), now).unwrap();
                dwc.flush(&mut port).unwrap();
            }
            if dwc.endpoints[posted.0].active.is_none() {
                let (n, kind, bytes) = match posted.1 {
                    0 => {
                        assert!(ram.read(PAYLOAD, &mut request));
                        let length = usize::from(u16::from_le_bytes([request[6], request[7]]));
                        if length == 0 {
                            (1, 3, vec![])
                        } else {
                            let mut response = match request[3] {
                                1 => device.clone(),
                                2 => config.clone(),
                                _ => panic!("unexpected fixture descriptor"),
                            };
                            response.truncate(length);
                            (1, 5, response)
                        }
                    }
                    1 => (0, 4, vec![]),
                    _ => {
                        if request[1] == 5 {
                            address = u16::from_le_bytes([request[2], request[3]]);
                            write(&mut dwc, DCFG, u32::from(address) << 3, &mut access);
                        }
                        if request[1] == 9 {
                            configuration = request[2];
                        }
                        (0, 2, vec![0; 8])
                    }
                };
                assert!(ram.write(PAYLOAD, &bytes));
                trb(
                    &mut ram,
                    TRB,
                    bytes.len() as u32,
                    HWO | LST | IOC | kind << 4,
                );
                start(&mut dwc, n, TRB, &mut access);
                posted = (
                    n,
                    if kind == 2 {
                        0
                    } else if kind == 5 {
                        1
                    } else {
                        2
                    },
                );
            }
            let count = dwc.rings[0].count;
            if count != 0 {
                write(&mut dwc, GEVNT + 12, count, &mut access);
            }
            if host.ready() {
                break;
            }
        }
        assert!(host.ready());
        assert_eq!(address, 1);
        assert_eq!(configuration, 7);
        assert_eq!(
            host.descriptors()
                .iter()
                .map(|d| d.bytes.clone())
                .collect::<alloc::vec::Vec<_>>(),
            [device, config]
        );
        assert!(dwc.rings[0].producer > 0);
        assert!(dwc.poisoned.is_none());
    }
    #[test]
    fn one_full_ring_does_not_block_another_interrupt_buffer() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        write(&mut dwc, GEVNT + 8, 4, &mut access);
        write(
            &mut dwc,
            GEVNT + STRIDE,
            (EVENTS + 0x800) as u32,
            &mut access,
        );
        write(
            &mut dwc,
            GEVNT + STRIDE + 4,
            ((EVENTS + 0x800) >> 32) as u32,
            &mut access,
        );
        write(&mut dwc, GEVNT + STRIDE + 8, 0x800, &mut access);
        dwc.queue(0, 11).unwrap();
        dwc.queue(0, 22).unwrap();
        dwc.queue(1, 33).unwrap();
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.flush(&mut port).unwrap();
        assert_eq!(dwc.rings[0].count, 4);
        assert_eq!(dwc.rings[1].count, 4);
        assert_eq!(dwc.pending.len(), 1);
        let mut back = [0; 4];
        port.read(EVENTS + 0x800, &mut back).unwrap();
        assert_eq!(u32::from_le_bytes(back), 33);
        let wires = latch.take_aic_inputs();
        assert!(wires.contains(&(irqs()[0], true)));
        assert!(wires.contains(&(irqs()[1], true)));
    }
    #[test]
    fn start_configuration_preserves_ep0_resources_and_short_events_have_no_fake_stream() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        for n in 0..3 {
            configure(&mut dwc, n, 0, &mut access);
        }
        write(&mut dwc, DEP + 12, CMDACT | 9 | 2 << 16, &mut access);
        assert!(dwc.endpoints[0].resource);
        assert!(dwc.endpoints[1].resource);
        assert!(!dwc.endpoints[2].resource);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, TRB, 512, HWO | IOC | 1 << 4);
        start(&mut dwc, 2, TRB, &mut access);
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut [1; 3]),
            Ok(Reply::Ack(3))
        );
        dwc.flush(&mut port).unwrap();
        let mut back = [0; 4];
        port.read(EVENTS, &mut back).unwrap();
        assert_eq!(
            u32::from_le_bytes(back),
            ep_event(2, XFER_COMPLETE, EV_SHORT | EV_IOC, 0)
        );
    }
    #[test]
    fn unowned_trb_reports_active_not_ready_once_and_update_rearms_it() {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, TRB, 512, LST | 1 << 4);
        start(&mut dwc, 2, TRB, &mut access);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            for _ in 0..2 {
                assert_eq!(
                    dwc.peer(&mut port).packet(1, Token::Out, &mut [1; 512]),
                    Ok(Reply::Nak)
                );
            }
            dwc.flush(&mut port).unwrap();
            let mut event = [0; 4];
            port.read(EVENTS, &mut event).unwrap();
            assert_eq!(u32::from_le_bytes(event), ep_event(2, XFER_NOT_READY, 8, 0));
        }
        assert_eq!(dwc.rings[0].count, 4);
        write(
            &mut dwc,
            DEP + 2 * STRIDE + 12,
            CMDACT | 7 | 1 << 16,
            &mut access,
        );
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                dwc.peer(&mut port).packet(1, Token::Out, &mut [1; 512]),
                Ok(Reply::Nak)
            );
            dwc.flush(&mut port).unwrap();
        }
        assert_eq!(dwc.rings[0].count, 8);
    }
}
