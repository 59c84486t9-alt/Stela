//! The DWC3 core's xHCI host personality: eXtensible Host Controller
//! Interface 1.1 (Intel, revision 1.2 of the specification): a two-port
//! root hub, device slots and their transfer rings (`slot`).
//!
//! The capability registers describe Stela's emulated core, matching the
//! device personality's profile: version 1.10, 64 device slots, four
//! interrupters (one per core interrupt wire, shared with the device event
//! buffer of the same number), 64-bit addressing, 32-byte contexts, port
//! power control and no scratchpad buffers. Port 1 is the USB 2.0 port and
//! port 2 the USB 3.0 port, each named by a Supported Protocol capability
//! (spec 7.2), as on a DWC3 dual-role core. A USB2 function the machine
//! attaches (a downstream-facing Type-C attach) connects to port 1; there
//! is no SuperSpeed PHY, so port 2 stays Disconnected (spec 4.19.1).
//!
//! Spec-defined behavior: USBCMD run/stop and reset complete at once (HCH
//! and CNR settle before the next read); save and restore state (CSS/CRS)
//! succeed with nothing lost, since this model retains its state; MFINDEX
//! counts 125 us microframes from the system counter while running, and
//! with USBCMD.EWE each wrap from 3FFFh to 0 posts an MFINDEX Wrap Event on
//! the primary interrupter (spec 4.14.2, 6.4.2.8). The
//! command ring runs from a doorbell 0 write until software stops or aborts
//! it, completing each command with a Command Completion Event (spec
//! 6.4.2.2): No Op, Get Port Bandwidth and the slot and endpoint commands
//! complete as specified (`slot`); commands whose capability is not
//! advertised fail with a TRB Error. Event rings of up to
//! 16 segments take events at the enqueue pointer with the producer cycle
//! state; IMAN.IP, ERDP.EHB and USBSTS.EINT latch, and an interrupter's
//! wire follows IP with IE and USBCMD.INTE; an event whose TRB set BEI
//! leaves IP alone. Interrupt moderation only delays interrupts, and this
//! model raises them at once.
//!
//! The USB2 port follows the USB2 root hub port state machine (spec
//! 4.19.1.2): a connection while powered sets CCS and CSC with the link in
//! Polling, the speed Low or Full until reset; PR completes at once,
//! enabling the port in U0 at the function's speed with PRC set and
//! resetting the function; PED written as one disables it; disconnection
//! clears CCS and PED and sets CSC. A link state write suspends an enabled
//! port to U3, and Resume then U0 bring it back with PLC set (spec
//! 4.15.2.3). A warm reset (PORTSC.WPR) of the disconnected USB3 port
//! completes at once: the link returns to RxDetect with PRC and WRC set
//! (spec 4.19.5.1, 5.4.8). A change bit set while running, then and only
//! then, posts a Port Status Change Event and sets USBSTS.PCD (spec
//! 4.19.2). PR of a disconnected port and WPR of the USB2 port (RsvdZ)
//! have no effect.
//!
//! Refused rather than modeled: features not advertised (light reset,
//! CEM, extended TBC, virtualization, streams, USB2 hardware LPM), port
//! test modes and port indicators. A full event ring holds further events
//! until software advances ERDP, rather than posting an Event Ring Full
//! Error.
mod slot;

use super::super::typec::Usb2Speed;
use crate::platform::{dma::Port, usb::Function};
use alloc::{boxed::Box, collections::VecDeque};
use slot::Slot;

/// Bytes of the core's address space the host registers occupy.
pub const BYTES: u64 = 0x1000;
const CAPLENGTH: u64 = 0x20;
const HCIVERSION: u32 = 0x0110;
const MAX_SLOTS: usize = 64;
pub const INTERRUPTERS: usize = 4;
const PORTS: usize = 2;
const ERST_MAX: u32 = 4;
const HCSPARAMS1: u32 = MAX_SLOTS as u32 | (INTERRUPTERS as u32) << 8 | (PORTS as u32) << 24;
/// IST of one frame and ERST Max; no scratchpad buffers.
const HCSPARAMS2: u32 = 1 | ERST_MAX << 4;
/// U1 and U2 device exit latencies (us).
const HCSPARAMS3: u32 = 0x0a | 0x07ff << 16;
const AC64: u32 = 1;
const PPC: u32 = 1 << 3;
const NSS: u32 = 1 << 7;
const EXTENDED: u64 = 0x600;
const HCCPARAMS1: u32 = AC64 | PPC | NSS | ((EXTENDED / 4) as u32) << 16;
const OPERATIONAL: u64 = CAPLENGTH;
const PORT_BASE: u64 = OPERATIONAL + 0x400;
const PORT_STRIDE: u64 = 0x10;
const RUNTIME: u64 = 0x440;
const INTERRUPTER_BASE: u64 = RUNTIME + 0x20;
const INTERRUPTER_STRIDE: u64 = 0x20;
const DOORBELLS: u64 = 0x4e0;
/// Two Supported Protocol capabilities: USB 2.0 port 1, USB 3.0 port 2.
const CAPABILITIES: [u32; 8] = [
    0x0200_0402,
    0x2042_5355, // "USB "
    1 | 1 << 8,
    0,
    0x0300_0002,
    0x2042_5355,
    2 | 1 << 8,
    0,
];

const RUN: u32 = 1;
const HCRST: u32 = 1 << 1;
const INTE: u32 = 1 << 2;
const HSEE: u32 = 1 << 3;
const LHCRST: u32 = 1 << 7;
const CSS: u32 = 1 << 8;
const CRS: u32 = 1 << 9;
const EWE: u32 = 1 << 10;
const EU3S: u32 = 1 << 11;
const USBCMD_KNOWN: u32 = RUN | HCRST | INTE | HSEE | LHCRST | CSS | CRS | EWE | EU3S;
const HCH: u32 = 1;
const HSE: u32 = 1 << 2;
const EINT: u32 = 1 << 3;
const PCD: u32 = 1 << 4;
const SRE: u32 = 1 << 10;
const USBSTS_CLEAR: u32 = HSE | EINT | PCD | SRE;
const RCS: u64 = 1;
const CS: u64 = 1 << 1;
const CA: u64 = 1 << 2;
const CRR: u64 = 1 << 3;

const CCS: u32 = 1;
const PED: u32 = 1 << 1;
const CSC: u32 = 1 << 17;
const PLC: u32 = 1 << 22;
const SPEED_SHIFT: u32 = 10;
const SPEED: u32 = 0xf << SPEED_SHIFT;
const FULL_SPEED: u32 = 1;
const LOW_SPEED: u32 = 2;
const HIGH_SPEED: u32 = 3;
const WRC: u32 = 1 << 19;
const PRC: u32 = 1 << 21;
const PR: u32 = 1 << 4;
const PLS_SHIFT: u32 = 5;
const PLS: u32 = 0xf << PLS_SHIFT;
const PP: u32 = 1 << 9;
const PIC: u32 = 3 << 14;
const LWS: u32 = 1 << 16;
const PORT_CHANGES: u32 = 0x7f << 17;
const WAKE: u32 = 7 << 25;
const WPR: u32 = 1 << 31;
const U0: u32 = 0;
const U3: u32 = 3;
const DISABLED: u32 = 4;
const RX_DETECT: u32 = 5;
const POLLING: u32 = 7;
const RESUME: u32 = 15;

const IP: u32 = 1;
const IE: u32 = 1 << 1;
const EHB: u64 = 1 << 3;

const TRB_BYTES: u64 = 16;
const CYCLE: u32 = 1;
const TOGGLE: u32 = 1 << 1;
const LINK: u32 = 6;
const ENABLE_SLOT: u32 = 9;
const DISABLE_SLOT: u32 = 10;
const ADDRESS_DEVICE: u32 = 11;
const CONFIGURE_ENDPOINT: u32 = 12;
const EVALUATE_CONTEXT: u32 = 13;
const RESET_ENDPOINT: u32 = 14;
const STOP_ENDPOINT: u32 = 15;
const SET_TR_DEQUEUE: u32 = 16;
const RESET_DEVICE: u32 = 17;
const GET_PORT_BANDWIDTH: u32 = 21;
const NO_OP: u32 = 23;
const COMMAND_COMPLETION: u32 = 33;
const PORT_STATUS_CHANGE: u32 = 34;
const MFINDEX_WRAP: u32 = 39;
const SUCCESS: u32 = 1;
const TRANSACTION_ERROR: u32 = 4;
const TRB_ERROR: u32 = 5;
const NO_SLOTS: u32 = 9;
const SLOT_NOT_ENABLED: u32 = 11;
const PARAMETER_ERROR: u32 = 17;
const CONTEXT_STATE_ERROR: u32 = 19;
const COMMAND_RING_STOPPED: u32 = 24;
/// Commands one doorbell may run before yielding: a ring software filled
/// without a Link TRB back cannot hold the engine.
const COMMANDS_PER_SERVICE: usize = 256;
const MAX_PENDING_EVENTS: usize = 256;
/// 24 MHz system counts per 125 us microframe.
const MICROFRAME: u64 = 3000;
/// Microframes from one MFINDEX wrap to the next.
const MFINDEX_PERIOD: u64 = 1 << 14;

#[derive(Clone, Copy, Default)]
struct Interrupter {
    iman: u32,
    imod: u32,
    erstsz: u32,
    erstba: u64,
    erdp: u64,
    /// The event ring's enqueue state, from the segment table.
    ring: Option<EventRing>,
    /// ERSTBA was written: the table is read before the next event.
    reload: bool,
}

#[derive(Clone, Copy)]
struct EventRing {
    segment: u32,
    base: u64,
    size: u32,
    index: u32,
    cycle: bool,
}

#[derive(Clone, Copy)]
struct Event {
    interrupter: usize,
    trb: [u32; 4],
    /// Whether posting sets IMAN.IP (clear for a TRB with BEI set).
    interrupt: bool,
}

#[derive(Clone)]
pub struct Xhci {
    usbcmd: u32,
    usbsts: u32,
    dnctrl: u32,
    config: u32,
    dcbaap: u64,
    command: u64,
    command_cycle: bool,
    command_running: bool,
    command_doorbell: bool,
    ports: [PortRegisters; PORTS],
    slots: [Option<Box<Slot>>; MAX_SLOTS],
    interrupters: [Interrupter; INTERRUPTERS],
    pending: VecDeque<Event>,
    /// Microframes counted when last halted, and the system count the run
    /// started at.
    mfindex: u64,
    started: Option<u64>,
    /// The microframe count of the next wrap event, while EWE is set.
    next_wrap: u64,
}

#[derive(Clone, Copy, Default)]
struct PortRegisters {
    portsc: u32,
    pmsc: u32,
    hlpmc: u32,
    /// The function cabled to the port, by its speed.
    attached: Option<Usb2Speed>,
    /// A port reset completed: the function resets before its next
    /// transaction.
    reset_function: bool,
}

impl PortRegisters {
    /// A device is connected and the port Enabled.
    fn enabled(&self) -> bool {
        self.portsc & (CCS | PED) == CCS | PED
    }

    /// The link is in U0: transfers may run.
    fn active(&self) -> bool {
        self.enabled() && (self.portsc & PLS) >> PLS_SHIFT == U0
    }
}

fn speed_id(speed: Usb2Speed) -> u32 {
    match speed {
        Usb2Speed::Low => LOW_SPEED,
        Usb2Speed::Full => FULL_SPEED,
        Usb2Speed::High => HIGH_SPEED,
    }
}

impl Default for Xhci {
    fn default() -> Self {
        Self::new()
    }
}

impl Xhci {
    /// The state after HCRST: halted, ports unpowered (PPC) and
    /// disconnected, no rings.
    pub fn new() -> Self {
        Self {
            usbcmd: 0,
            usbsts: HCH,
            dnctrl: 0,
            config: 0,
            dcbaap: 0,
            command: 0,
            command_cycle: false,
            command_running: false,
            command_doorbell: false,
            ports: [PortRegisters {
                portsc: DISABLED << PLS_SHIFT,
                ..PortRegisters::default()
            }; PORTS],
            slots: [const { None }; MAX_SLOTS],
            interrupters: [Interrupter::default(); INTERRUPTERS],
            pending: VecDeque::new(),
            mfindex: 0,
            started: None,
            next_wrap: 0,
        }
    }

    /// Doorbell or segment-table work waits for DMA.
    pub fn pending(&self) -> bool {
        self.command_doorbell
            || !self.pending.is_empty()
            || self.interrupters.iter().any(|i| i.reload)
            || self.usbsts & HCH == 0 && self.transfers_pending()
    }

    /// The system count at which the next MFINDEX Wrap Event falls due, or
    /// an endpoint that NAKed is due to be polled again.
    pub fn deadline(&self, function: Option<&(dyn Function + '_)>) -> Option<u64> {
        let transfers = self.started.and_then(|_| self.transfer_deadline(function));
        self.wrap_deadline().into_iter().chain(transfers).min()
    }

    fn wrap_deadline(&self) -> Option<u64> {
        let start = self.started.filter(|_| self.usbcmd & EWE != 0)?;
        let ahead = self.next_wrap.saturating_sub(self.mfindex);
        Some(start.saturating_add(ahead.saturating_mul(MICROFRAME)))
    }

    /// Cables `attached` to the USB2 port, or nothing.
    pub fn attach(&mut self, attached: Option<Usb2Speed>) -> Result<(), &'static str> {
        if self.ports[0].attached == attached {
            return Ok(());
        }
        let before = self.ports[0].portsc;
        self.ports[0].attached = attached;
        self.detect(0);
        self.changed(0, before)
    }

    /// Brings port `n`'s connection status in line with its cable.
    fn detect(&mut self, n: usize) {
        let port = &mut self.ports[n];
        let connected = port.portsc & CCS != 0;
        let powered = port.portsc & PP != 0;
        match port.attached {
            Some(speed) if powered && !connected => {
                let at_connect = if speed == Usb2Speed::Low {
                    LOW_SPEED
                } else {
                    FULL_SPEED
                };
                port.portsc = port.portsc & !(PLS | SPEED)
                    | CCS
                    | CSC
                    | POLLING << PLS_SHIFT
                    | at_connect << SPEED_SHIFT;
            }
            None if connected => {
                port.portsc =
                    port.portsc & !(CCS | PED | PR | PLS | SPEED) | CSC | RX_DETECT << PLS_SHIFT;
            }
            _ => {}
        }
    }

    /// A change bit that `portsc` did not have before posts a Port Status
    /// Change Event while running.
    fn changed(&mut self, n: usize, before: u32) -> Result<(), &'static str> {
        if self.ports[n].portsc & !before & PORT_CHANGES != 0 {
            self.usbsts |= PCD;
            if self.usbsts & HCH == 0 {
                self.post(0, Self::port_status_change(n))?;
            }
        }
        Ok(())
    }

    /// Interrupter `n`'s wire level.
    pub fn interrupt(&self, n: usize) -> bool {
        let i = &self.interrupters[n];
        self.usbcmd & INTE != 0 && i.iman & (IP | IE) == IP | IE
    }

    pub fn read(&mut self, offset: u64, bytes: u64, now: u64) -> Result<u64, &'static str> {
        let dword = |xhci: &mut Self, at: u64| xhci.read_dword(at, now);
        match bytes {
            1 | 2 if offset < CAPLENGTH => {
                let value = dword(self, offset & !3)?;
                let shift = (offset & 3) * 8;
                if (offset & 3) + bytes > 4 {
                    return Err("xHCI capability read crosses a register");
                }
                Ok(u64::from(value >> shift) & ((1 << (bytes * 8)) - 1))
            }
            4 if offset.is_multiple_of(4) => dword(self, offset).map(u64::from),
            8 if offset.is_multiple_of(8) => {
                let low = dword(self, offset)?;
                let high = dword(self, offset + 4)?;
                Ok(u64::from(low) | u64::from(high) << 32)
            }
            _ => Err("xHCI register access width or alignment is not architectural"),
        }
    }

    pub fn write(
        &mut self,
        offset: u64,
        bytes: u64,
        value: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        match bytes {
            4 if offset.is_multiple_of(4) => self.write_dword(offset, value as u32, now),
            8 if offset.is_multiple_of(8) => match self.qword(offset) {
                Some(()) => self.write_qword(offset, value),
                None => Err("64-bit write to a 32-bit xHCI register"),
            },
            _ => Err("xHCI register access width or alignment is not architectural"),
        }
    }

    /// Registers that are one 64-bit quantity.
    fn qword(&self, offset: u64) -> Option<()> {
        let op = offset.checked_sub(OPERATIONAL)?;
        if matches!(op, 0x18 | 0x30) {
            return Some(());
        }
        let rt = offset.checked_sub(INTERRUPTER_BASE)?;
        (rt < INTERRUPTER_STRIDE * INTERRUPTERS as u64
            && matches!(rt % INTERRUPTER_STRIDE, 0x10 | 0x18))
        .then_some(())
    }

    /// Microframes counted while running, at system count `now`.
    fn microframes(&self, now: u64) -> u64 {
        match self.started {
            Some(start) => self.mfindex + now.saturating_sub(start) / MICROFRAME,
            None => self.mfindex,
        }
    }

    fn mfindex(&self, now: u64) -> u32 {
        (self.microframes(now) % MFINDEX_PERIOD) as u32
    }

    fn read_dword(&mut self, offset: u64, now: u64) -> Result<u32, &'static str> {
        Ok(match offset {
            0x00 => CAPLENGTH as u32 | HCIVERSION << 16,
            0x04 => HCSPARAMS1,
            0x08 => HCSPARAMS2,
            0x0c => HCSPARAMS3,
            0x10 => HCCPARAMS1,
            0x14 => DOORBELLS as u32,
            0x18 => RUNTIME as u32,
            0x1c => 0,
            at if (OPERATIONAL..PORT_BASE).contains(&at) => match at - OPERATIONAL {
                0x00 => self.usbcmd,
                0x04 => self.usbsts,
                0x08 => 1, // 4 KiB pages
                0x14 => self.dnctrl,
                // CRCR reads zero but for Command Ring Running.
                0x18 => {
                    if self.command_running {
                        CRR as u32
                    } else {
                        0
                    }
                }
                0x1c => 0,
                0x30 => self.dcbaap as u32,
                0x34 => (self.dcbaap >> 32) as u32,
                0x38 => self.config,
                _ => return Err("reserved xHCI operational register"),
            },
            at if (PORT_BASE..PORT_BASE + PORT_STRIDE * PORTS as u64).contains(&at) => {
                let port = &self.ports[((at - PORT_BASE) / PORT_STRIDE) as usize];
                match (at - PORT_BASE) % PORT_STRIDE {
                    0x0 => port.portsc,
                    0x4 => port.pmsc,
                    0x8 => 0, // PORTLI: no link errors
                    _ => port.hlpmc,
                }
            }
            RUNTIME => self.mfindex(now),
            at if (INTERRUPTER_BASE
                ..INTERRUPTER_BASE + INTERRUPTER_STRIDE * INTERRUPTERS as u64)
                .contains(&at) =>
            {
                let i = &self.interrupters[((at - INTERRUPTER_BASE) / INTERRUPTER_STRIDE) as usize];
                match (at - INTERRUPTER_BASE) % INTERRUPTER_STRIDE {
                    0x00 => i.iman,
                    0x04 => i.imod,
                    0x08 => i.erstsz,
                    0x0c => 0,
                    0x10 => i.erstba as u32,
                    0x14 => (i.erstba >> 32) as u32,
                    0x18 => i.erdp as u32,
                    _ => (i.erdp >> 32) as u32,
                }
            }
            at if (DOORBELLS..DOORBELLS + 4 * (MAX_SLOTS as u64 + 1)).contains(&at) => 0,
            at if (EXTENDED..EXTENDED + 4 * CAPABILITIES.len() as u64).contains(&at) => {
                CAPABILITIES[((at - EXTENDED) / 4) as usize]
            }
            at if at < BYTES => return Err("reserved xHCI register"),
            _ => return Err("offset outside the xHCI register space"),
        })
    }

    fn write_qword(&mut self, offset: u64, value: u64) -> Result<(), &'static str> {
        if offset == OPERATIONAL + 0x18 {
            return self.write_crcr(value, true, true);
        }
        if offset == OPERATIONAL + 0x30 {
            self.dcbaap = value & !0x3f;
            return Ok(());
        }
        let rt = offset - INTERRUPTER_BASE;
        let i = &mut self.interrupters[(rt / INTERRUPTER_STRIDE) as usize];
        if rt % INTERRUPTER_STRIDE == 0x10 {
            i.erstba = value & !0x3f;
            i.reload = true;
        } else {
            Self::write_erdp(i, value);
        }
        Ok(())
    }

    fn write_erdp(i: &mut Interrupter, value: u64) {
        let ehb = if value & EHB != 0 { 0 } else { i.erdp & EHB };
        i.erdp = value & !0xf | value & 7 | ehb;
    }

    /// CRCR: the pointer and RCS while the ring is stopped; CS and CA stop
    /// or abort a running ring after its current command, which here has
    /// always completed.
    fn write_crcr(&mut self, value: u64, low: bool, high: bool) -> Result<(), &'static str> {
        if self.command_running {
            // Spec 4.6.1.1-2: with no command in progress, CS and CA both
            // stop the ring with a Command Ring Stopped event naming the
            // dequeue pointer (an abort would report Command Aborted for
            // the command it interrupted; commands here never pend).
            if value & (CS | CA) != 0 && low {
                self.command_running = false;
                self.command_doorbell = false;
                self.post(0, Self::completion(self.command, COMMAND_RING_STOPPED, 0))?;
            }
            return Ok(());
        }
        if low {
            self.command = self.command & !0xffff_ffff | value & 0xffff_ffc0;
            self.command_cycle = value & RCS != 0;
        }
        if high {
            self.command = self.command & 0xffff_ffff | value & !0xffff_ffff;
        }
        Ok(())
    }

    fn write_dword(&mut self, offset: u64, value: u32, now: u64) -> Result<(), &'static str> {
        match offset {
            at if at < CAPLENGTH => Err("xHCI capability registers are read-only"),
            at if (OPERATIONAL..PORT_BASE).contains(&at) => match at - OPERATIONAL {
                0x00 => self.write_usbcmd(value, now),
                0x04 => {
                    self.usbsts &= !(value & USBSTS_CLEAR);
                    Ok(())
                }
                0x08 => Err("xHCI PAGESIZE is read-only"),
                0x14 => {
                    self.dnctrl = value & 0xffff;
                    Ok(())
                }
                0x18 => self.write_crcr(u64::from(value), true, false),
                0x1c => self.write_crcr(u64::from(value) << 32, false, true),
                0x30 => {
                    self.dcbaap = self.dcbaap & !0xffff_ffff | u64::from(value & !0x3f);
                    Ok(())
                }
                0x34 => {
                    self.dcbaap = self.dcbaap & 0xffff_ffff | u64::from(value) << 32;
                    Ok(())
                }
                0x38 => {
                    if value & !0xff != 0 {
                        return Err("xHCI CONFIG U3E/CIE need capabilities not advertised");
                    }
                    if value as usize > MAX_SLOTS {
                        return Err("xHCI MaxSlotsEn exceeds MaxSlots");
                    }
                    self.config = value;
                    Ok(())
                }
                _ => Err("reserved xHCI operational register"),
            },
            at if (PORT_BASE..PORT_BASE + PORT_STRIDE * PORTS as u64).contains(&at) => {
                let n = ((at - PORT_BASE) / PORT_STRIDE) as usize;
                match (at - PORT_BASE) % PORT_STRIDE {
                    0x0 => self.write_portsc(n, value),
                    0x4 => {
                        if n == 0 && value & 0xf000_0000 != 0 {
                            return Err("xHCI USB2 port test modes are not modeled");
                        }
                        self.ports[n].pmsc = value;
                        Ok(())
                    }
                    0x8 => Err("xHCI PORTLI is read-only"),
                    _ => {
                        self.ports[n].hlpmc = value;
                        Ok(())
                    }
                }
            }
            RUNTIME => Err("xHCI MFINDEX is read-only"),
            at if (RUNTIME..INTERRUPTER_BASE).contains(&at) => {
                Err("reserved xHCI runtime register")
            }
            at if (INTERRUPTER_BASE
                ..INTERRUPTER_BASE + INTERRUPTER_STRIDE * INTERRUPTERS as u64)
                .contains(&at) =>
            {
                let n = ((at - INTERRUPTER_BASE) / INTERRUPTER_STRIDE) as usize;
                let i = &mut self.interrupters[n];
                match (at - INTERRUPTER_BASE) % INTERRUPTER_STRIDE {
                    0x00 => {
                        let ip = if value & IP != 0 { 0 } else { i.iman & IP };
                        i.iman = ip | value & IE;
                    }
                    0x04 => i.imod = value,
                    0x08 => {
                        if value & !0xffff != 0 || value > 1 << ERST_MAX {
                            return Err("xHCI ERSTSZ exceeds ERST Max");
                        }
                        i.erstsz = value;
                    }
                    0x0c => return Err("reserved xHCI interrupter register"),
                    0x10 => {
                        i.erstba = i.erstba & !0xffff_ffff | u64::from(value & !0x3f);
                        i.reload = true;
                    }
                    0x14 => {
                        i.erstba = i.erstba & 0xffff_ffff | u64::from(value) << 32;
                        i.reload = true;
                    }
                    0x18 => {
                        let erdp = i.erdp & !0xffff_ffff | u64::from(value);
                        Self::write_erdp(i, erdp);
                    }
                    _ => i.erdp = i.erdp & 0xffff_ffff | u64::from(value) << 32,
                }
                Ok(())
            }
            DOORBELLS => {
                if value & 0xff != 0 || value >> 16 != 0 {
                    return Err("xHCI host controller doorbell names a target");
                }
                self.command_running = true;
                self.command_doorbell = true;
                Ok(())
            }
            at if (DOORBELLS..DOORBELLS + 4 * (MAX_SLOTS as u64 + 1)).contains(&at) => {
                self.ring(((at - DOORBELLS) / 4) as usize, value)
            }
            at if at < BYTES => Err("read-only or reserved xHCI register"),
            _ => Err("offset outside the xHCI register space"),
        }
    }

    fn write_usbcmd(&mut self, value: u32, now: u64) -> Result<(), &'static str> {
        if value & !USBCMD_KNOWN != 0 {
            return Err("xHCI USBCMD feature not advertised (CEM, ETE, TSC, VTIO)");
        }
        if value & LHCRST != 0 {
            return Err("xHCI light reset is not advertised");
        }
        if value & HCRST != 0 {
            if self.usbsts & HCH == 0 {
                return Err("xHCI HCRST while running is undefined");
            }
            *self = Self::new();
            return Ok(());
        }
        if value & (CSS | CRS) != 0 && (self.usbsts & HCH == 0 || value & RUN != 0) {
            return Err("xHCI save/restore requires a halted controller");
        }
        // CSS/CRS complete at once: SSS and RSS never read set and no state
        // is lost, so SRE stays clear.
        let running = value & RUN != 0;
        match (self.started, running) {
            (None, true) => self.started = Some(now),
            (Some(_), false) => {
                self.mfindex = self.microframes(now);
                self.started = None;
            }
            _ => {}
        }
        if value & EWE != 0 && self.usbcmd & EWE == 0 {
            self.next_wrap = (self.microframes(now) / MFINDEX_PERIOD + 1) * MFINDEX_PERIOD;
        }
        if running {
            self.usbsts &= !HCH;
        } else {
            self.usbsts |= HCH;
        }
        self.usbcmd = value & (RUN | INTE | HSEE | EWE | EU3S);
        Ok(())
    }

    /// PORTSC (spec 4.19, 5.4.8).
    fn write_portsc(&mut self, n: usize, value: u32) -> Result<(), &'static str> {
        if value & PIC != 0 {
            return Err("xHCI port indicators are not advertised");
        }
        let usb3 = n == 1;
        let before = self.ports[n].portsc;
        let port = &mut self.ports[n];
        let mut portsc = before & !(value & PORT_CHANGES);
        portsc = portsc & !WAKE | value & WAKE;
        if value & PP == 0 {
            // Powered off: disconnected and disabled, with no change
            // reported.
            portsc &= !(PP | CCS | PED | PR | SPEED | PLS);
            portsc |= DISABLED << PLS_SHIFT;
        } else if portsc & PP == 0 {
            portsc |= PP;
            portsc = portsc & !PLS | RX_DETECT << PLS_SHIFT;
        }
        let pls = (portsc & PLS) >> PLS_SHIFT;
        // PED is RW1CS: writing one disables an enabled port.
        if value & PED != 0 && portsc & PED != 0 {
            portsc = portsc & !(PED | PLS) | POLLING << PLS_SHIFT;
        }
        // A reset of a connected port completes at once, enabling it.
        if value & PR != 0 && portsc & (PP | CCS) == PP | CCS {
            let speed = port.attached.map_or(0, speed_id);
            portsc = portsc & !(PLS | SPEED) | PED | PRC | U0 << PLS_SHIFT | speed << SPEED_SHIFT;
            port.reset_function = true;
        }
        if value & LWS != 0 && portsc & PP != 0 {
            let enabled = portsc & PED != 0;
            let link = |state: u32| portsc & !PLS | state << PLS_SHIFT;
            portsc = match (value & PLS) >> PLS_SHIFT {
                DISABLED if usb3 => link(DISABLED),
                RX_DETECT if usb3 => link(RX_DETECT),
                U3 if !usb3 && enabled && pls == U0 => link(U3),
                RESUME if !usb3 && enabled && pls == U3 => link(RESUME),
                U0 if !usb3 && enabled && matches!(pls, U3 | RESUME) => link(U0) | PLC,
                2 if !usb3 && enabled => {
                    return Err("xHCI USB2 L1 needs hardware LPM, which is not advertised");
                }
                // Other U0..U3 and resume writes apply to an Enabled port
                // in a state they lead from; elsewhere they do nothing.
                0..=3 | 15 => portsc,
                _ => return Err("xHCI port link state write is not defined for this port"),
            };
        }
        // A warm reset with no device ends in RxDetect at once.
        if usb3 && value & WPR != 0 && portsc & PP != 0 {
            portsc = portsc & !PLS | RX_DETECT << PLS_SHIFT | PRC | WRC;
        }
        self.ports[n].portsc = portsc;
        // A function cabled to a port that just gained power connects.
        self.detect(n);
        self.changed(n, before)
    }

    fn port_status_change(n: usize) -> [u32; 4] {
        [
            (n as u32 + 1) << 24,
            0,
            SUCCESS << 24,
            PORT_STATUS_CHANGE << 10,
        ]
    }

    fn completion(trb: u64, code: u32, slot: usize) -> [u32; 4] {
        [
            trb as u32,
            (trb >> 32) as u32,
            code << 24,
            COMMAND_COMPLETION << 10 | (slot as u32) << 24,
        ]
    }

    fn post(&mut self, interrupter: usize, trb: [u32; 4]) -> Result<(), &'static str> {
        if self.pending.len() == MAX_PENDING_EVENTS {
            return Err("xHCI pending event capacity exhausted");
        }
        self.pending.push_back(Event {
            interrupter,
            trb,
            interrupt: true,
        });
        Ok(())
    }

    /// Runs doorbelled commands and posts events through the core's DMA
    /// stream. A DMA fault is a host system error the guest cannot recover
    /// from in this model, so it stops the run.
    /// `function` is what is cabled to the USB2 port, if anything.
    pub fn service(
        &mut self,
        port: &mut Port<'_, '_>,
        mut function: Option<&mut (dyn Function + '_)>,
    ) -> Result<(), &'static str> {
        // Only a cabled function hears the bus.
        if self.ports[0].attached.is_none() {
            function = None;
        }
        if self.ports[0].reset_function {
            if let Some(f) = function.as_deref_mut() {
                f.reset()?;
            }
            self.ports[0].reset_function = false;
        }
        while self
            .wrap_deadline()
            .is_some_and(|deadline| port.access.now >= deadline)
        {
            self.next_wrap += MFINDEX_PERIOD;
            self.post(0, [0, 0, SUCCESS << 24, MFINDEX_WRAP << 10])?;
        }
        for n in 0..INTERRUPTERS {
            if self.interrupters[n].reload {
                // A new segment table starts a new ring, cycle state one.
                self.interrupters[n].ring = None;
                self.load_segment(port, n, 0)?;
                self.interrupters[n].reload = false;
            }
        }
        if self.command_doorbell && self.usbsts & HCH == 0 {
            self.command_doorbell = false;
            self.run_commands(port, function.as_deref_mut())?;
        }
        if self.usbsts & HCH == 0 {
            self.run_transfers(port, function)?;
        }
        while let Some(event) = self.pending.front().copied() {
            if !self.deliver(port, event)? {
                break;
            }
            self.pending.pop_front();
        }
        Ok(())
    }

    fn load_segment(
        &mut self,
        port: &mut Port<'_, '_>,
        n: usize,
        segment: u32,
    ) -> Result<(), &'static str> {
        let i = &mut self.interrupters[n];
        if i.erstsz == 0 {
            i.ring = None;
            return Ok(());
        }
        let mut entry = [0u8; 16];
        port.read(i.erstba + u64::from(segment) * 16, &mut entry)
            .map_err(|_| "xHCI event ring segment table DMA fault")?;
        let base = u64::from_le_bytes(entry[..8].try_into().unwrap()) & !0x3f;
        let size = u32::from_le_bytes(entry[8..12].try_into().unwrap()) & 0xffff;
        if !(16..=4096).contains(&size) {
            return Err("xHCI event ring segment size outside 16..4096 TRBs");
        }
        // The producer cycle flips when the ring wraps to its first segment.
        let cycle = match i.ring {
            Some(ring) if segment == 0 => !ring.cycle,
            Some(ring) => ring.cycle,
            None => true,
        };
        i.ring = Some(EventRing {
            segment,
            base,
            size,
            index: 0,
            cycle,
        });
        Ok(())
    }

    /// The address of segment `segment`'s first TRB in interrupter `n`'s
    /// segment table.
    fn segment_base(
        &self,
        port: &mut Port<'_, '_>,
        n: usize,
        segment: u32,
    ) -> Result<u64, &'static str> {
        let mut base = [0u8; 8];
        port.read(
            self.interrupters[n].erstba + u64::from(segment) * 16,
            &mut base,
        )
        .map_err(|_| "xHCI event ring segment table DMA fault")?;
        Ok(u64::from_le_bytes(base) & !0x3f)
    }

    /// Writes one event unless the ring is full; false leaves it pending.
    fn deliver(&mut self, port: &mut Port<'_, '_>, event: Event) -> Result<bool, &'static str> {
        let n = event.interrupter;
        let Some(ring) = self.interrupters[n].ring else {
            return Ok(false);
        };
        let at = ring.base + u64::from(ring.index) * TRB_BYTES;
        let last = ring.index + 1 == ring.size;
        let following = (ring.segment + 1) % self.interrupters[n].erstsz;
        // Full when the next enqueue position is software's dequeue pointer.
        let next = if last {
            self.segment_base(port, n, following)?
        } else {
            at + TRB_BYTES
        };
        if next == self.interrupters[n].erdp & !0xf {
            return Ok(false);
        }
        let mut trb = event.trb;
        trb[3] = trb[3] & !CYCLE | u32::from(ring.cycle);
        let mut bytes = [0u8; 16];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(trb) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        port.write(at, &bytes)
            .map_err(|_| "xHCI event ring DMA fault")?;
        if last {
            self.load_segment(port, n, following)?;
        } else if let Some(ring) = &mut self.interrupters[n].ring {
            ring.index += 1;
        }
        if event.interrupt {
            let i = &mut self.interrupters[n];
            i.erdp |= EHB;
            i.iman |= IP;
            self.usbsts |= EINT;
        }
        Ok(true)
    }

    fn run_commands(
        &mut self,
        port: &mut Port<'_, '_>,
        mut function: Option<&mut (dyn Function + '_)>,
    ) -> Result<(), &'static str> {
        for _ in 0..COMMANDS_PER_SERVICE {
            if !self.command_running {
                return Ok(());
            }
            let mut bytes = [0u8; 16];
            port.read(self.command, &mut bytes)
                .map_err(|_| "xHCI command ring DMA fault")?;
            let word = |n: usize| u32::from_le_bytes(bytes[n * 4..n * 4 + 4].try_into().unwrap());
            let control = word(3);
            if (control & CYCLE != 0) != self.command_cycle {
                return Ok(());
            }
            let parameter = u64::from(word(0)) | u64::from(word(1)) << 32;
            let kind = control >> 10 & 0x3f;
            if kind == LINK {
                if control & TOGGLE != 0 {
                    self.command_cycle = !self.command_cycle;
                }
                self.command = parameter & !0xf;
                continue;
            }
            let trb = self.command;
            self.command += TRB_BYTES;
            let slot = (control >> 24) as usize;
            let endpoint = (control >> 16 & 0x1f) as usize;
            let (code, slot) = match kind {
                NO_OP => (SUCCESS, 0),
                ENABLE_SLOT => {
                    if control >> 16 & 0x1f != 0 {
                        (TRB_ERROR, 0)
                    } else {
                        let enabled = self.config as usize;
                        match (0..enabled).find(|&s| self.slots[s].is_none()) {
                            Some(s) => {
                                self.slots[s] = Some(Slot::new());
                                (SUCCESS, s + 1)
                            }
                            None => (NO_SLOTS, 0),
                        }
                    }
                }
                DISABLE_SLOT => match self.slot(slot) {
                    Some(s) => {
                        self.slots[s] = None;
                        (SUCCESS, slot)
                    }
                    None => (SLOT_NOT_ENABLED, slot),
                },
                ADDRESS_DEVICE => {
                    let bsr = control & (1 << 9) != 0;
                    let input = parameter & !0xf;
                    let code =
                        self.address_device(port, function.as_deref_mut(), slot, input, bsr)?;
                    (code, slot)
                }
                CONFIGURE_ENDPOINT => {
                    let deconfigure = control & (1 << 9) != 0;
                    (
                        self.configure_endpoint(port, slot, parameter & !0xf, deconfigure)?,
                        slot,
                    )
                }
                EVALUATE_CONTEXT => (self.evaluate_context(port, slot, parameter & !0xf)?, slot),
                RESET_ENDPOINT => (self.reset_endpoint(port, slot, endpoint)?, slot),
                STOP_ENDPOINT => (self.stop_endpoint(port, slot, endpoint)?, slot),
                SET_TR_DEQUEUE => {
                    let stream = word(2) >> 16;
                    let code = self.set_dequeue(port, slot, endpoint, parameter, stream)?;
                    (code, slot)
                }
                RESET_DEVICE => (self.reset_device(port, slot)?, slot),
                GET_PORT_BANDWIDTH => {
                    if control >> 16 & 0xf == 0 || slot != 0 {
                        (TRB_ERROR, 0)
                    } else {
                        // Root hub: the context's byte n is port n's free
                        // bandwidth percentage; byte 0 is reserved.
                        let context = [0, 100, 100, 0];
                        port.write(parameter & !0xf, &context)
                            .map_err(|_| "xHCI port bandwidth context DMA fault")?;
                        (SUCCESS, 0)
                    }
                }
                // Force Event, Negotiate Bandwidth, Set LTV, Force Header,
                // Set/Get Extended Property and undefined types need
                // capabilities this controller does not advertise.
                _ => (TRB_ERROR, 0),
            };
            self.post(0, Self::completion(trb, code, slot))?;
        }
        self.command_doorbell = true;
        Ok(())
    }

    /// The zero-based index of enabled slot ID `id`.
    fn slot(&self, id: usize) -> Option<usize> {
        (1..=MAX_SLOTS)
            .contains(&id)
            .then(|| id - 1)
            .filter(|&s| self.slots[s].is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{
        bus::{Access, MmioDevice, Width},
        dart::Dart,
        interrupt::InterruptLatch,
    };
    use crate::platform::dma::{Memory, tests::Ram};

    const STOPPED_CODE: u32 = 26;

    const RAM: u64 = 0x1_0000_0000;
    const ERST: u64 = RAM;
    const EVENTS: u64 = RAM + 0x1000;
    const COMMANDS: u64 = RAM + 0x2000;

    fn rd(x: &mut Xhci, at: u64) -> u32 {
        x.read(at, 4, 0).unwrap() as u32
    }
    fn wr(x: &mut Xhci, at: u64, value: u32) {
        x.write(at, 4, u64::from(value), 0).unwrap();
    }
    fn service(x: &mut Xhci, ram: &mut Ram) {
        service_at(x, ram, 0);
    }
    fn service_at(x: &mut Xhci, ram: &mut Ram, now: u64) {
        service_with(x, ram, now, None);
    }
    fn service_with(
        x: &mut Xhci,
        ram: &mut Ram,
        now: u64,
        function: Option<&mut (dyn Function + '_)>,
    ) {
        let mut dart = Dart::new(16, None);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, now, &mut latch);
        // Stream 0 bypasses translation and the filter: IOVAs are physical.
        dart.write(0xc00, Width::Word, 1, &mut access).unwrap();
        dart.write(0x1000, Width::Word, 6, &mut access).unwrap();
        let mut port = Port {
            iommu: &mut dart,
            stream: 0,
            memory: ram,
            access: &mut access,
        };
        x.service(&mut port, function).unwrap();
    }
    fn trb(ram: &mut Ram, at: u64, words: [u32; 4]) {
        ram.put_u64(at, u64::from(words[0]) | u64::from(words[1]) << 32);
        ram.put_u64(at + 8, u64::from(words[2]) | u64::from(words[3]) << 32);
    }
    fn event(ram: &mut Ram, n: u64) -> [u32; 4] {
        let mut bytes = [0u8; 16];
        assert!(ram.read(EVENTS + n * TRB_BYTES, &mut bytes));
        core::array::from_fn(|w| u32::from_le_bytes(bytes[w * 4..w * 4 + 4].try_into().unwrap()))
    }

    #[test]
    fn capabilities_describe_a_two_port_root_hub_and_its_protocols() {
        let mut x = Xhci::new();
        assert_eq!(x.read(0, 1, 0), Ok(0x20));
        assert_eq!(x.read(2, 2, 0), Ok(0x0110));
        assert_eq!(rd(&mut x, 4), 64 | 4 << 8 | 2 << 24);
        let ecp = u64::from(rd(&mut x, 0x10) >> 16) * 4;
        assert_eq!(rd(&mut x, ecp) & 0xff, 2);
        assert_eq!(rd(&mut x, ecp + 4), u32::from_le_bytes(*b"USB "));
        assert_eq!(rd(&mut x, ecp + 8) & 0xffff, 0x0101);
        let next = ecp + u64::from(rd(&mut x, ecp) >> 8 & 0xff) * 4;
        assert_eq!(rd(&mut x, next) >> 24, 3);
        assert_eq!(rd(&mut x, next + 8) & 0xffff, 0x0102);
        assert!(x.write(0, 4, 0, 0).is_err());
        assert!(x.read(1, 4, 0).is_err());
    }

    #[test]
    fn run_halt_reset_and_mfindex_follow_usbcmd() {
        let mut x = Xhci::new();
        let sts = OPERATIONAL + 4;
        assert_eq!(rd(&mut x, sts), HCH);
        x.write(OPERATIONAL, 4, u64::from(RUN | INTE), 3000)
            .unwrap();
        assert_eq!(rd(&mut x, sts) & HCH, 0);
        assert_eq!(x.read(RUNTIME, 4, 3000 * 11), Ok(10));
        assert!(x.write(OPERATIONAL, 4, u64::from(HCRST), 0).is_err());
        x.write(OPERATIONAL, 4, 0, 3000 * 21).unwrap();
        assert_eq!(x.read(RUNTIME, 4, 1 << 40), Ok(20));
        wr(&mut x, OPERATIONAL + 0x38, 8);
        wr(&mut x, OPERATIONAL, CSS);
        wr(&mut x, OPERATIONAL, CRS);
        assert_eq!(rd(&mut x, sts) & SRE, 0);
        wr(&mut x, OPERATIONAL, HCRST);
        assert_eq!(rd(&mut x, OPERATIONAL + 0x38), 0);
        assert_eq!(rd(&mut x, OPERATIONAL), 0);
        assert!(x.write(OPERATIONAL, 4, u64::from(LHCRST), 0).is_err());
        assert!(x.write(OPERATIONAL + 0x38, 4, 65, 0).is_err());
    }

    #[test]
    fn ports_power_and_stay_disconnected() {
        let mut x = Xhci::new();
        let (usb2, usb3) = (PORT_BASE, PORT_BASE + PORT_STRIDE);
        assert_eq!(rd(&mut x, usb2), DISABLED << PLS_SHIFT);
        wr(&mut x, usb2, PP | PR);
        wr(&mut x, usb3, PP | WAKE);
        assert_eq!(rd(&mut x, usb2), PP | RX_DETECT << PLS_SHIFT);
        assert_eq!(rd(&mut x, usb3), PP | WAKE | RX_DETECT << PLS_SHIFT);
        wr(&mut x, usb3, PP | LWS | DISABLED << PLS_SHIFT);
        assert_eq!(rd(&mut x, usb3) & PLS, DISABLED << PLS_SHIFT);
        wr(&mut x, usb2, 0);
        assert_eq!(rd(&mut x, usb2), DISABLED << PLS_SHIFT);
        assert!(x.write(usb2, 4, u64::from(PP | 1 << 14), 0).is_err());
        assert!(x.write(usb2 + 4, 4, 1 << 28, 0).is_err());
        // WPR is RsvdZ on the USB2 port; halted, a change posts no event.
        wr(&mut x, usb2, PP | WPR);
        assert_eq!(rd(&mut x, usb2), PP | RX_DETECT << PLS_SHIFT);
        wr(&mut x, usb3, PP | WPR);
        assert_eq!(rd(&mut x, usb3), PP | PRC | WRC | RX_DETECT << PLS_SHIFT);
        assert_ne!(rd(&mut x, OPERATIONAL + 4) & PCD, 0);
        assert!(x.pending.is_empty());
        // The driver's write-back keeps WPR clear and clears the changes.
        wr(&mut x, usb3, PP | PRC | WRC);
        assert_eq!(rd(&mut x, usb3), PP | RX_DETECT << PLS_SHIFT);
    }

    #[test]
    fn a_running_controller_posts_port_changes_and_mfindex_wraps() {
        let mut ram = Ram::new(RAM, 0x4000);
        let mut x = Xhci::new();
        ram.put_u64(ERST, EVENTS);
        ram.put_u64(ERST + 8, 16);
        let i0 = INTERRUPTER_BASE;
        wr(&mut x, i0 + 8, 1);
        x.write(i0 + 0x18, 8, EVENTS, 0).unwrap();
        x.write(i0 + 0x10, 8, ERST, 0).unwrap();
        wr(&mut x, i0, IE);
        let period = MFINDEX_PERIOD * MICROFRAME;
        x.write(OPERATIONAL, 4, u64::from(RUN | INTE | EWE), 100)
            .unwrap();
        assert_eq!(x.deadline(None), Some(100 + period));
        wr(&mut x, PORT_BASE + PORT_STRIDE, PP | WPR);
        service_at(&mut x, &mut ram, period);
        assert_eq!(event(&mut ram, 0)[0] >> 24, 2);
        assert_eq!(event(&mut ram, 0)[3] >> 10 & 0x3f, PORT_STATUS_CHANGE);
        assert_eq!(event(&mut ram, 1), [0; 4]);
        service_at(&mut x, &mut ram, 100 + period);
        assert_eq!(event(&mut ram, 1)[2] >> 24, SUCCESS);
        assert_eq!(event(&mut ram, 1)[3] >> 10 & 0x3f, MFINDEX_WRAP);
        assert_eq!(x.read(RUNTIME, 4, 100 + period), Ok(0));
        assert_eq!(x.deadline(None), Some(100 + 2 * period));
        assert!(x.interrupt(0));
        // Halting stops the count and the wraps.
        x.write(OPERATIONAL, 4, u64::from(EWE), 100 + period + 3000)
            .unwrap();
        assert_eq!(x.deadline(None), None);
        assert_eq!(x.read(RUNTIME, 4, u64::MAX), Ok(1));
    }

    #[test]
    fn commands_complete_through_the_event_ring_and_raise_the_interrupter() {
        let mut ram = Ram::new(RAM, 0x4000);
        let mut x = Xhci::new();
        ram.put_u64(ERST, EVENTS);
        ram.put_u64(ERST + 8, 16);
        let i0 = INTERRUPTER_BASE;
        wr(&mut x, i0 + 8, 1);
        x.write(i0 + 0x18, 8, EVENTS, 0).unwrap();
        x.write(i0 + 0x10, 8, ERST, 0).unwrap();
        wr(&mut x, i0, IE);
        wr(&mut x, OPERATIONAL + 0x38, 2);
        x.write(OPERATIONAL + 0x18, 8, COMMANDS | RCS, 0).unwrap();
        wr(&mut x, OPERATIONAL, RUN | INTE);
        let cmd = |kind: u32, slot: u32| [0, 0, 0, kind << 10 | slot << 24 | CYCLE];
        trb(&mut ram, COMMANDS, cmd(NO_OP, 0));
        trb(&mut ram, COMMANDS + 16, cmd(ENABLE_SLOT, 0));
        // An input context adding the slot and EP0 on port 1, which has no
        // device.
        let input = RAM + 0x3000;
        ram.put_u64(input, 3 << 32);
        ram.put_u64(input + 0x20 + 4, 1 << 16);
        ram.put_u64(input + 0x40 + 4, u64::from(4u32 << 3 | 64 << 16));
        trb(
            &mut ram,
            COMMANDS + 32,
            [
                input as u32,
                (input >> 32) as u32,
                0,
                ADDRESS_DEVICE << 10 | 1 << 24 | CYCLE,
            ],
        );
        trb(&mut ram, COMMANDS + 48, cmd(12, 1));
        trb(&mut ram, COMMANDS + 64, cmd(DISABLE_SLOT, 1));
        trb(&mut ram, COMMANDS + 80, cmd(DISABLE_SLOT, 1));
        // A Link back to the start toggles the cycle, ending the ring.
        trb(
            &mut ram,
            COMMANDS + 96,
            [
                COMMANDS as u32,
                (COMMANDS >> 32) as u32,
                0,
                LINK << 10 | TOGGLE | CYCLE,
            ],
        );
        wr(&mut x, DOORBELLS, 0);
        assert!(x.pending());
        assert!(!x.interrupt(0));
        service(&mut x, &mut ram);
        let codes: alloc::vec::Vec<_> = (0..6)
            .map(|n| (event(&mut ram, n)[2] >> 24, event(&mut ram, n)[3] >> 24))
            .collect();
        assert_eq!(
            codes,
            [
                (SUCCESS, 0),
                (SUCCESS, 1),
                (TRANSACTION_ERROR, 1),
                (CONTEXT_STATE_ERROR, 1),
                (SUCCESS, 1),
                (SLOT_NOT_ENABLED, 1),
            ]
        );
        assert_eq!(event(&mut ram, 0)[0], COMMANDS as u32);
        assert_eq!(event(&mut ram, 0)[3] >> 10 & 0x3f, COMMAND_COMPLETION);
        assert_eq!(event(&mut ram, 0)[3] & CYCLE, 1);
        assert!(x.interrupt(0));
        assert_ne!(rd(&mut x, OPERATIONAL + 4) & EINT, 0);
        assert_ne!(rd(&mut x, i0 + 0x18) & EHB as u32, 0);
        assert_eq!(rd(&mut x, OPERATIONAL + 0x18), CRR as u32);
        // Acknowledge, then stop the ring: a Command Ring Stopped event.
        wr(&mut x, i0, IP | IE);
        x.write(i0 + 0x18, 8, (EVENTS + 6 * TRB_BYTES) | EHB, 0)
            .unwrap();
        assert!(!x.interrupt(0));
        wr(&mut x, OPERATIONAL + 0x18, CS as u32);
        service(&mut x, &mut ram);
        assert_eq!(event(&mut ram, 6)[2] >> 24, COMMAND_RING_STOPPED);
        assert_eq!(rd(&mut x, OPERATIONAL + 0x18), 0);
        assert!(x.write(DOORBELLS + 4, 4, 0, 0).is_err());
    }

    #[test]
    fn a_full_event_ring_holds_events_until_software_dequeues() {
        let mut ram = Ram::new(RAM, 0x4000);
        let mut x = Xhci::new();
        ram.put_u64(ERST, EVENTS);
        ram.put_u64(ERST + 8, 16);
        let i0 = INTERRUPTER_BASE;
        wr(&mut x, i0 + 8, 1);
        x.write(i0 + 0x18, 8, EVENTS, 0).unwrap();
        x.write(i0 + 0x10, 8, ERST, 0).unwrap();
        x.write(OPERATIONAL + 0x18, 8, COMMANDS | RCS, 0).unwrap();
        wr(&mut x, OPERATIONAL, RUN);
        for n in 0..20 {
            trb(&mut ram, COMMANDS + n * 16, [0, 0, 0, NO_OP << 10 | CYCLE]);
        }
        wr(&mut x, DOORBELLS, 0);
        service(&mut x, &mut ram);
        // 15 of a 16-TRB segment; the rest wait.
        assert_eq!(x.pending.len(), 5);
        x.write(i0 + 0x18, 8, EVENTS + 15 * TRB_BYTES, 0).unwrap();
        service(&mut x, &mut ram);
        assert_eq!(x.pending.len(), 0);
        // Wrapping to the segment start flips the producer cycle.
        assert_eq!(event(&mut ram, 15)[3] & CYCLE, 1);
        assert_eq!(event(&mut ram, 0)[3] & CYCLE, 0);
    }

    /// A controller running with one 16-TRB event segment, eight slots,
    /// a DCBAA and a command ring, its USB2 port powered.
    struct Bench {
        x: Xhci,
        ram: Ram,
        hid: crate::platform::usb::hid::Peripheral,
        now: u64,
        commands: u64,
        events: u64,
    }

    const DCBAA: u64 = RAM + 0x4000;
    const OUTPUT: u64 = RAM + 0x5000;
    const INPUT: u64 = RAM + 0x6000;
    const EP0_RING: u64 = RAM + 0x7000;
    const EP1_RING: u64 = RAM + 0x8000;
    const BUFFER: u64 = RAM + 0x9000;
    const PORTSC1: u64 = PORT_BASE;

    impl Bench {
        fn new() -> Self {
            let mut ram = Ram::new(RAM, 0x10000);
            let mut x = Xhci::new();
            ram.put_u64(ERST, EVENTS);
            ram.put_u64(ERST + 8, 64);
            ram.put_u64(DCBAA + 8, OUTPUT);
            let i0 = INTERRUPTER_BASE;
            wr(&mut x, i0 + 8, 1);
            x.write(i0 + 0x18, 8, EVENTS, 0).unwrap();
            x.write(i0 + 0x10, 8, ERST, 0).unwrap();
            wr(&mut x, i0, IE);
            wr(&mut x, OPERATIONAL + 0x38, 8);
            x.write(OPERATIONAL + 0x30, 8, DCBAA, 0).unwrap();
            x.write(OPERATIONAL + 0x18, 8, COMMANDS | RCS, 0).unwrap();
            wr(&mut x, OPERATIONAL, RUN | INTE);
            wr(&mut x, PORTSC1, PP);
            Self {
                x,
                ram,
                hid: crate::platform::usb::hid::Peripheral::new(),
                now: 0,
                commands: COMMANDS,
                events: 0,
            }
        }

        fn service(&mut self) {
            service_with(&mut self.x, &mut self.ram, self.now, Some(&mut self.hid));
        }

        /// The next event, which must exist.
        fn event(&mut self) -> [u32; 4] {
            let e = event(&mut self.ram, self.events);
            assert_eq!(e[3] & CYCLE, 1, "no event {}", self.events);
            self.events += 1;
            e
        }

        fn command(&mut self, words: [u32; 4]) -> [u32; 4] {
            trb(&mut self.ram, self.commands, words);
            self.commands += 16;
            wr(&mut self.x, DOORBELLS, 0);
            self.service();
            let e = self.event();
            assert_eq!(e[3] >> 10 & 0x3f, COMMAND_COMPLETION);
            e
        }

        fn context(&mut self, at: u64) -> [u32; 8] {
            let mut bytes = [0u8; 32];
            assert!(self.ram.read(at, &mut bytes));
            core::array::from_fn(|n| {
                u32::from_le_bytes(bytes[n * 4..n * 4 + 4].try_into().unwrap())
            })
        }

        fn put_context(&mut self, at: u64, words: [u32; 8]) {
            for (n, pair) in words.chunks(2).enumerate() {
                self.ram.put_u64(
                    at + 8 * n as u64,
                    u64::from(pair[0]) | u64::from(pair[1]) << 32,
                );
            }
        }
    }

    const NORMAL_TRB: u32 = 1 << 10;
    const SETUP_TRB: u32 = 2 << 10;
    const DATA_TRB: u32 = 3 << 10;
    const STATUS_TRB: u32 = 4 << 10;
    const TRB_IOC: u32 = 1 << 5;
    const TRB_IDT: u32 = 1 << 6;
    const TRB_ISP: u32 = 1 << 2;
    const TRB_IN: u32 = 1 << 16;
    const TRANSFER_EVENT: u32 = 32;

    fn setup_trb(packet: [u8; 8], transfer_type: u32) -> [u32; 4] {
        let p = u64::from_le_bytes(packet);
        [
            p as u32,
            (p >> 32) as u32,
            8,
            SETUP_TRB | TRB_IDT | transfer_type << 16 | CYCLE,
        ]
    }

    /// Attaches, resets and addresses the keyboard as slot 1, then runs
    /// SET_CONFIGURATION and configures its keyboard endpoint (DCI 3).
    fn enumerated() -> Bench {
        let mut b = Bench::new();
        b.x.attach(Some(Usb2Speed::Full)).unwrap();
        let portsc = rd(&mut b.x, PORTSC1);
        assert_eq!(portsc & (CCS | CSC | PED), CCS | CSC);
        assert_eq!(portsc & PLS, POLLING << PLS_SHIFT);
        b.service();
        assert_eq!(b.event()[3] >> 10 & 0x3f, PORT_STATUS_CHANGE);
        wr(&mut b.x, PORTSC1, PP | CSC | PR);
        let portsc = rd(&mut b.x, PORTSC1);
        assert_eq!(portsc & (CCS | PED | PRC | PR), CCS | PED | PRC);
        assert_eq!(portsc & SPEED, FULL_SPEED << SPEED_SHIFT);
        assert_eq!(portsc & PLS, U0 << PLS_SHIFT);
        b.service();
        assert_eq!(b.event()[0] >> 24, 1);
        wr(&mut b.x, PORTSC1, PP | PRC);
        let e = b.command([0, 0, 0, ENABLE_SLOT << 10 | CYCLE]);
        assert_eq!((e[2] >> 24, e[3] >> 24), (SUCCESS, 1));
        // Input context: add the slot and EP0; root port 1, one entry.
        b.put_context(INPUT, [0, 3, 0, 0, 0, 0, 0, 0]);
        b.put_context(INPUT + 0x20, [1 << 27 | 1 << 20, 1 << 16, 0, 0, 0, 0, 0, 0]);
        b.put_context(
            INPUT + 0x40,
            [
                0,
                3 << 1 | 4 << 3 | 64 << 16,
                EP0_RING as u32 | 1,
                (EP0_RING >> 32) as u32,
                8,
                0,
                0,
                0,
            ],
        );
        let input = INPUT as u32;
        let e = b.command([
            input,
            (INPUT >> 32) as u32,
            0,
            ADDRESS_DEVICE << 10 | 1 << 24 | CYCLE,
        ]);
        assert_eq!(e[2] >> 24, SUCCESS);
        let slot = b.context(OUTPUT);
        assert_eq!((slot[3] >> 27, slot[3] & 0xff), (2, 1));
        assert_eq!(b.context(OUTPUT + 0x20)[0] & 7, 1);
        // SET_CONFIGURATION 1: no data stage, status IN.
        trb(&mut b.ram, EP0_RING, setup_trb([0, 9, 1, 0, 0, 0, 0, 0], 0));
        trb(
            &mut b.ram,
            EP0_RING + 16,
            [0, 0, 0, STATUS_TRB | TRB_IN | TRB_IOC | CYCLE],
        );
        wr(&mut b.x, DOORBELLS + 4, 1);
        assert!(b.x.pending());
        b.service();
        let e = b.event();
        assert_eq!(e[3] >> 10 & 0x3f, TRANSFER_EVENT);
        assert_eq!(
            (e[0], e[2] >> 24, e[3] >> 16 & 0x1f),
            ((EP0_RING + 16) as u32, SUCCESS, 1)
        );
        // Configure the interrupt IN endpoint 0x81 (DCI 3), 1 ms interval.
        b.put_context(INPUT, [0, 1 | 1 << 3, 0, 0, 0, 0, 0, 0]);
        b.put_context(INPUT + 0x20, [3 << 27, 1 << 16, 0, 0, 0, 0, 0, 0]);
        b.put_context(
            INPUT + 0x20 * 4,
            [
                3 << 16,
                3 << 1 | 7 << 3 | 8 << 16,
                EP1_RING as u32 | 1,
                (EP1_RING >> 32) as u32,
                8,
                0,
                0,
                0,
            ],
        );
        let e = b.command([
            input,
            (INPUT >> 32) as u32,
            0,
            CONFIGURE_ENDPOINT << 10 | 1 << 24 | CYCLE,
        ]);
        assert_eq!(e[2] >> 24, SUCCESS);
        assert_eq!(b.context(OUTPUT)[3] >> 27, 3);
        assert_eq!(b.context(OUTPUT + 0x20 * 3)[0] & 7, 1);
        b
    }

    #[test]
    fn an_attached_keyboard_enumerates_and_reports_keys_through_its_rings() {
        let mut b = enumerated();
        // GET_DESCRIPTOR(device) with a 64-byte IN data stage: short.
        trb(
            &mut b.ram,
            EP0_RING + 32,
            setup_trb([0x80, 6, 0, 1, 0, 0, 64, 0], 3),
        );
        trb(
            &mut b.ram,
            EP0_RING + 48,
            [
                BUFFER as u32,
                (BUFFER >> 32) as u32,
                64,
                DATA_TRB | TRB_IN | TRB_ISP | CYCLE,
            ],
        );
        trb(
            &mut b.ram,
            EP0_RING + 64,
            [0, 0, 0, STATUS_TRB | TRB_IOC | CYCLE],
        );
        wr(&mut b.x, DOORBELLS + 4, 1);
        b.service();
        let short = b.event();
        assert_eq!((short[0], short[2] >> 24), ((EP0_RING + 48) as u32, 13));
        assert_eq!(short[2] & 0xff_ffff, 64 - 18);
        assert_eq!(b.event()[2] >> 24, SUCCESS);
        let mut device = [0u8; 18];
        assert!(b.ram.read(BUFFER, &mut device));
        assert_eq!(device[..2], [18, 1]);
        assert_eq!(device[8..10], [0x09, 0x12]);
        // The keyboard endpoint NAKs until a key goes down, and is polled
        // again only then, at its next interval.
        trb(
            &mut b.ram,
            EP1_RING,
            [
                BUFFER as u32,
                (BUFFER >> 32) as u32,
                8,
                NORMAL_TRB | TRB_IOC | TRB_ISP | CYCLE,
            ],
        );
        wr(&mut b.x, DOORBELLS + 4, 3);
        b.now = 1000;
        b.service();
        assert_eq!(event(&mut b.ram, b.events)[3] & CYCLE, 0);
        assert!(!b.x.pending());
        // The keyboard's default 500 ms idle rate repeats its report.
        assert_eq!(b.x.deadline(Some(&b.hid)), Some(125 * 96_000));
        b.hid
            .input(crate::platform::usb::hid::Input::Key {
                usage: 0x04,
                pressed: true,
            })
            .unwrap();
        assert_eq!(b.x.deadline(Some(&b.hid)), Some(1000 + 8 * MICROFRAME));
        b.now = 1000 + 8 * MICROFRAME;
        b.service();
        let e = b.event();
        assert_eq!(
            (e[0], e[2], e[3] >> 16 & 0x1f),
            (EP1_RING as u32, SUCCESS << 24, 3)
        );
        let mut report = [0u8; 8];
        assert!(b.ram.read(BUFFER, &mut report));
        assert_eq!(report, [0, 0, 4, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_stall_halts_ep0_until_reset_and_a_new_dequeue_pointer() {
        let mut b = enumerated();
        // GET_DESCRIPTOR(device qualifier): a full-speed device STALLs.
        trb(
            &mut b.ram,
            EP0_RING + 32,
            setup_trb([0x80, 6, 0, 6, 0, 0, 10, 0], 3),
        );
        trb(
            &mut b.ram,
            EP0_RING + 48,
            [
                BUFFER as u32,
                (BUFFER >> 32) as u32,
                10,
                DATA_TRB | TRB_IN | CYCLE,
            ],
        );
        trb(
            &mut b.ram,
            EP0_RING + 64,
            [0, 0, 0, STATUS_TRB | TRB_IOC | CYCLE],
        );
        wr(&mut b.x, DOORBELLS + 4, 1);
        b.service();
        let e = b.event();
        assert_eq!(
            (e[0], e[2] >> 24, e[2] & 0xff_ffff),
            ((EP0_RING + 48) as u32, 6, 10)
        );
        let ep0 = b.context(OUTPUT + 0x20);
        assert_eq!((ep0[0] & 7, ep0[2]), (2, (EP0_RING + 48) as u32 | 1));
        // A halted endpoint's doorbell does nothing; Set TR Dequeue needs
        // Stopped.
        wr(&mut b.x, DOORBELLS + 4, 1);
        assert!(!b.x.pending());
        let next = (EP0_RING + 80) as u32 | 1;
        let e = b.command([
            next,
            (EP0_RING >> 32) as u32,
            0,
            SET_TR_DEQUEUE << 10 | 1 << 16 | 1 << 24 | CYCLE,
        ]);
        assert_eq!(e[2] >> 24, CONTEXT_STATE_ERROR);
        let e = b.command([0, 0, 0, RESET_ENDPOINT << 10 | 1 << 16 | 1 << 24 | CYCLE]);
        assert_eq!(e[2] >> 24, SUCCESS);
        let e = b.command([
            next,
            (EP0_RING >> 32) as u32,
            0,
            SET_TR_DEQUEUE << 10 | 1 << 16 | 1 << 24 | CYCLE,
        ]);
        assert_eq!(e[2] >> 24, SUCCESS);
        assert_eq!(b.context(OUTPUT + 0x20)[0] & 7, 3);
        // The next request runs from the new dequeue pointer.
        trb(
            &mut b.ram,
            EP0_RING + 80,
            setup_trb([0x80, 8, 0, 0, 0, 0, 1, 0], 3),
        );
        trb(
            &mut b.ram,
            EP0_RING + 96,
            [
                BUFFER as u32,
                (BUFFER >> 32) as u32,
                1,
                DATA_TRB | TRB_IN | CYCLE,
            ],
        );
        trb(
            &mut b.ram,
            EP0_RING + 112,
            [0, 0, 0, STATUS_TRB | TRB_IOC | CYCLE],
        );
        wr(&mut b.x, DOORBELLS + 4, 1);
        b.service();
        assert_eq!(b.event()[2] >> 24, SUCCESS);
        let mut configuration = [0u8; 1];
        assert!(b.ram.read(BUFFER, &mut configuration));
        assert_eq!(configuration, [1]);
    }

    #[test]
    fn stopping_a_polled_endpoint_reports_its_started_td_first() {
        let mut b = enumerated();
        trb(
            &mut b.ram,
            EP1_RING,
            [
                BUFFER as u32,
                (BUFFER >> 32) as u32,
                8,
                NORMAL_TRB | TRB_IOC | CYCLE,
            ],
        );
        wr(&mut b.x, DOORBELLS + 4, 3);
        b.service();
        trb(
            &mut b.ram,
            b.commands,
            [0, 0, 0, STOP_ENDPOINT << 10 | 3 << 16 | 1 << 24 | CYCLE],
        );
        b.commands += 16;
        wr(&mut b.x, DOORBELLS, 0);
        b.service();
        // The Stopped event precedes the command's completion.
        let e = b.event();
        assert_eq!(
            (e[0], e[2] >> 24, e[2] & 0xff_ffff),
            (EP1_RING as u32, STOPPED_CODE, 8)
        );
        let stopped = b.event();
        assert_eq!(
            (stopped[2] >> 24, stopped[3] >> 10 & 0x3f),
            (SUCCESS, COMMAND_COMPLETION)
        );
        let ep = b.context(OUTPUT + 0x20 * 3);
        assert_eq!((ep[0] & 7, ep[2]), (3, EP1_RING as u32 | 1));
        let again = b.command([0, 0, 0, STOP_ENDPOINT << 10 | 3 << 16 | 1 << 24 | CYCLE]);
        assert_eq!(again[2] >> 24, CONTEXT_STATE_ERROR);
        // Disconnection clears the port; Disable Slot frees the slot.
        b.x.attach(None).unwrap();
        assert_eq!(rd(&mut b.x, PORTSC1) & (CCS | PED | CSC), CSC);
        b.service();
        assert_eq!(b.event()[3] >> 10 & 0x3f, PORT_STATUS_CHANGE);
        let e = b.command([0, 0, 0, DISABLE_SLOT << 10 | 1 << 24 | CYCLE]);
        assert_eq!(e[2] >> 24, SUCCESS);
    }
}
