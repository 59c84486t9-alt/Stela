//! A native high-speed USB Ethernet adapter: the CDC Ethernet Control
//! Model, whose frames the machine owner exchanges with a host link.
//!
//! Evidence: USB CDC 1.2 (class and functional descriptors, 5.2.3; the
//! Union descriptor, 5.2.3.2) and CDC ECM 1.2 (the Ethernet Networking
//! functional descriptor, 5.4; SET_ETHERNET_PACKET_FILTER, 6.2.4; the
//! NetworkConnection and ConnectionSpeedChange notifications, 6.3; data
//! interface alternate settings and frame delimiting by short packets,
//! 3.3-3.4). J473 macOS binds `AppleUSBECMControl` (KC `0x3230a9c`) to
//! interface class 2 subclass 6 and `AppleUSBECMData` (`0x322f628`) to the
//! data interface, class 10.
//!
//! The adapter reports a fixed 1 Gb/s link that is up while the data
//! interface's second alternate setting is selected. Its packet filter
//! (6.2.4) takes effect on received frames. It has [`MULTICAST_FILTERS`]
//! perfect multicast filters (wNumberMCFilters D15 clear):
//! SET_ETHERNET_MULTICAST_FILTERS (6.2.1) replaces the whole list, and
//! PACKET_TYPE_MULTICAST passes exactly the listed groups, while
//! ALL_MULTICAST passes every group. GET_ETHERNET_STATISTIC (6.2.5)
//! answers the counters [`STATISTICS`] advertises in bmEthernetStatistics,
//! each a wrapping 32-bit count since the device was configured; every
//! other selector, such as collisions or CRC errors on a medium the
//! adapter does not have, STALLs.
//!
//! Power-management pattern filters (6.2.2-6.2.3) exist to wake a
//! suspended host from a matching frame. The configuration has no remote
//! wakeup (bmAttributes D5 clear), so bNumberPowerFilters is 0 and both
//! requests STALL. J473 macOS sends neither those nor statistics requests:
//! the CDC and ECM drivers (KC `0x320d040..0x3236000`) issue only
//! SET_ETHERNET_MULTICAST_FILTERS (`setMulticastFilterGated` `0x3232ff4`,
//! when the list fits wNumberMCFilters) and SET_ETHERNET_PACKET_FILTER
//! (`0x323321c`).
//!
//! Frames longer than the 1514-byte maximum segment or shorter than the
//! Ethernet header are discarded and counted, never truncated. Each direction's queue holds at most
//! [`QUEUE_FRAMES`]; a frame arriving at a full queue is dropped and
//! counted, as a NIC's full ring drops.
use super::{
    BusPeer, Function, Reply, Token,
    control::{
        self, CLASS, CLEAR_FEATURE, Control, DEVICE, DEVICE_QUALIFIER, Descriptors, ENDPOINT,
        ENDPOINT_HALT, GET_INTERFACE, GET_STATUS, INTERFACE, Outcome, RECIPIENT_ENDPOINT,
        RECIPIENT_INTERFACE, Requests, SET_FEATURE, SET_INTERFACE, STANDARD, Setup, Stall,
    },
};
use alloc::{collections::VecDeque, format, string::String, vec, vec::Vec};
use stela_drivers::net::Mac;

const NOTIFY: u8 = 0x83;
const BULK_IN: u8 = 0x81;
const BULK_OUT: u8 = 0x02;
const HIGH_SPEED_PACKET: u16 = 512;
const FULL_SPEED_PACKET: u16 = 64;
const NOTIFY_PACKET: u16 = 16;
const CONTROL_INTERFACE: u16 = 0;
const DATA_INTERFACE: u16 = 1;
/// The Ethernet header: destination, source and EtherType.
const HEADER_BYTES: usize = 14;
/// The Ethernet maximum segment: header and payload, no FCS.
pub const MAX_SEGMENT: usize = 1514;
/// Frames each direction holds.
pub const QUEUE_FRAMES: usize = 64;
const LINK_BITS_PER_SECOND: u32 = 1_000_000_000;

const SET_ETHERNET_MULTICAST_FILTERS: u8 = 0x40;
const SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
const GET_ETHERNET_STATISTIC: u8 = 0x44;
/// Perfect multicast filters (wNumberMCFilters, ECM 5.4 table 3).
const MULTICAST_FILTERS: u16 = 32;

// Ethernet statistics feature selectors (ECM 6.2.5, table 9).
const XMIT_OK: u16 = 1;
const RCV_OK: u16 = 2;
const XMIT_ERROR: u16 = 3;
const RCV_ERROR: u16 = 4;
const RCV_NO_BUFFER: u16 = 5;
const DIRECTED_BYTES_XMIT: u16 = 6;
const DIRECTED_FRAMES_XMIT: u16 = 7;
const MULTICAST_BYTES_XMIT: u16 = 8;
const MULTICAST_FRAMES_XMIT: u16 = 9;
const BROADCAST_BYTES_XMIT: u16 = 10;
const BROADCAST_FRAMES_XMIT: u16 = 11;
const DIRECTED_BYTES_RCV: u16 = 12;
const DIRECTED_FRAMES_RCV: u16 = 13;
const MULTICAST_BYTES_RCV: u16 = 14;
const MULTICAST_FRAMES_RCV: u16 = 15;
const BROADCAST_BYTES_RCV: u16 = 16;
const BROADCAST_FRAMES_RCV: u16 = 17;
const TRANSMIT_QUEUE_LENGTH: u16 = 19;
/// bmEthernetStatistics: selector n is bit n - 1. Selectors 1-17 and 19.
const STATISTICS: u32 = 0x0005_ffff;
const NETWORK_CONNECTION: u8 = 0x00;
const CONNECTION_SPEED_CHANGE: u8 = 0x2a;

const PROMISCUOUS: u16 = 0x01;
const ALL_MULTICAST: u16 = 0x02;
const DIRECTED: u16 = 0x04;
const BROADCAST: u16 = 0x08;
const MULTICAST: u16 = 0x10;

/// Counters for the owner's diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub to_host: u64,
    pub to_guest: u64,
    /// Frames outside the Ethernet frame sizes, discarded.
    pub oversized: u64,
    pub filtered: u64,
    pub overflowed: u64,
}

/// The destination of a frame of at least [`HEADER_BYTES`].
fn destination(frame: &[u8]) -> Mac {
    Mac(*frame.first_chunk().unwrap())
}

/// Destination kinds, as [`Traffic`] indices.
const UNICAST: usize = 0;
const GROUP: usize = 1;
const EVERYONE: usize = 2;

/// One direction's frames and bytes by destination kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Traffic {
    /// Directed, multicast and broadcast: (bytes, frames).
    kinds: [(u64, u64); 3],
}

impl Traffic {
    fn count(&mut self, frame: &[u8]) {
        let destination = destination(frame);
        let kind = if destination == Mac::BROADCAST {
            EVERYONE
        } else if destination.is_multicast() {
            GROUP
        } else {
            UNICAST
        };
        let (bytes, frames) = &mut self.kinds[kind];
        *bytes += frame.len() as u64;
        *frames += 1;
    }
}

/// The counts GET_ETHERNET_STATISTIC reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Statistics {
    /// Guest frames sent on to the host network: XMIT.
    transmitted: Traffic,
    /// Frames the guest read in full: RCV.
    received: Traffic,
    /// Guest frames over the maximum segment, never sent.
    transmit_errors: u64,
    /// Host frames outside the Ethernet frame sizes, never delivered.
    receive_errors: u64,
    /// Host frames that met a full receive queue.
    no_buffer: u64,
}

struct State {
    mac: Mac,
    /// The data interface's alternate setting: 1 moves frames.
    alternate: u8,
    filter: u16,
    /// The multicast groups PACKET_TYPE_MULTICAST passes.
    multicast: Vec<Mac>,
    halted: [bool; 3],
    /// Notifications not yet sent, each one interrupt transfer.
    notifications: VecDeque<Vec<u8>>,
    /// The frame the host is sending, packet by packet.
    assembling: Vec<u8>,
    discarding: bool,
    /// Frames for the host, from the guest's point of view outbound.
    outbound: VecDeque<Vec<u8>>,
    /// Frames for the guest and how much of the first is sent.
    inbound: VecDeque<Vec<u8>>,
    sent: usize,
    /// The first inbound frame's last packet was full: a ZLP ends it.
    zero_length_due: bool,
    counters: Counters,
    statistics: Statistics,
}

pub struct Ecm {
    control: Control,
    state: State,
}

fn descriptors(mac: Mac) -> Descriptors {
    let device = [
        18,
        DEVICE,
        0x00,
        0x02,
        2, // communications device class
        0,
        0,
        control::EP0_PACKET as u8,
        0x09,
        0x12,
        0x02,
        0x00,
        0x00,
        0x01,
        1,
        2,
        3,
        1,
    ];
    let [segment_low, segment_high] = (MAX_SEGMENT as u16).to_le_bytes();
    let [filters_low, filters_high] = MULTICAST_FILTERS.to_le_bytes();
    let statistics = STATISTICS.to_le_bytes();
    let configuration = |bulk: u16, interval: u8| {
        let [low, high] = bulk.to_le_bytes();
        control::configuration(
            1,
            0,
            &[
                &[9, INTERFACE, 0, 0, 1, 2, 6, 0, 0],
                // Header (CDC 1.20), Union (control 0, data 1), Ethernet
                // Networking: MAC string 4, the statistics it counts,
                // 1514-byte segments, perfect multicast filters, no power
                // filters.
                &[5, 0x24, 0x00, 0x20, 0x01],
                &[5, 0x24, 0x06, 0, 1],
                &[
                    13,
                    0x24,
                    0x0f,
                    4,
                    statistics[0],
                    statistics[1],
                    statistics[2],
                    statistics[3],
                    segment_low,
                    segment_high,
                    filters_low,
                    filters_high,
                    0,
                ],
                &[7, ENDPOINT, NOTIFY, 3, NOTIFY_PACKET as u8, 0, interval],
                &[9, INTERFACE, 1, 0, 0, 10, 0, 0, 0],
                &[9, INTERFACE, 1, 1, 2, 10, 0, 0, 0],
                &[7, ENDPOINT, BULK_IN, 2, low, high, 0],
                &[7, ENDPOINT, BULK_OUT, 2, low, high, 0],
            ],
        )
    };
    let qualifier = [
        10,
        DEVICE_QUALIFIER,
        0x00,
        0x02,
        2,
        0,
        0,
        control::EP0_PACKET as u8,
        1,
        0,
    ];
    let [a, b, c, d, e, f] = mac.0;
    Descriptors {
        device,
        // High speed: 2^(9-1) microframes, 32 ms; full speed: 32 frames.
        configuration: configuration(HIGH_SPEED_PACKET, 9),
        other_speed: Some((qualifier, configuration(FULL_SPEED_PACKET, 32))),
        strings: vec![
            String::from("Stela"),
            String::from("Stela USB Ethernet"),
            format!("{a:02X}{b:02X}{c:02X}{d:02X}{e:02X}{f:02X}"),
            format!("{a:02X}{b:02X}{c:02X}{d:02X}{e:02X}{f:02X}"),
        ],
    }
}

fn notification(code: u8, value: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa1, code];
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&CONTROL_INTERFACE.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bytes.extend_from_slice(data);
    bytes
}

impl Ecm {
    /// The adapter whose station address is `mac`, a unicast address.
    pub fn new(mac: Mac) -> Result<Self, &'static str> {
        if mac.is_multicast() || mac.0 == [0; 6] {
            return Err("the USB Ethernet address must be a unicast address");
        }
        Ok(Self {
            control: Control::new(descriptors(mac)),
            state: State {
                mac,
                alternate: 0,
                filter: DIRECTED | BROADCAST | ALL_MULTICAST,
                multicast: Vec::new(),
                halted: [false; 3],
                notifications: VecDeque::new(),
                assembling: Vec::new(),
                discarding: false,
                outbound: VecDeque::new(),
                inbound: VecDeque::new(),
                sent: 0,
                zero_length_due: false,
                counters: Counters::default(),
                statistics: Statistics::default(),
            },
        })
    }

    /// Whether the guest has the link up (the data interface's active
    /// setting selected).
    pub fn up(&self) -> bool {
        self.control.configuration() != 0 && self.state.alternate == 1
    }

    pub fn counters(&self) -> Counters {
        self.state.counters
    }

    /// A frame from the host network for the guest. Dropped (and counted)
    /// while the link is down, when the packet filter excludes it, or when
    /// the queue is full.
    pub fn deliver(&mut self, frame: &[u8]) {
        let state = &mut self.state;
        if !(HEADER_BYTES..=MAX_SEGMENT).contains(&frame.len()) {
            state.counters.oversized += 1;
            state.statistics.receive_errors += 1;
            return;
        }
        let destination = destination(frame);
        let filter = state.filter;
        let passes = filter & PROMISCUOUS != 0
            || if destination == Mac::BROADCAST {
                filter & BROADCAST != 0
            } else if destination.is_multicast() {
                filter & ALL_MULTICAST != 0
                    || filter & MULTICAST != 0 && state.multicast.contains(&destination)
            } else {
                filter & DIRECTED != 0 && destination == state.mac
            };
        if !self.up() || !passes {
            self.state.counters.filtered += 1;
            return;
        }
        if self.state.inbound.len() >= QUEUE_FRAMES {
            self.state.counters.overflowed += 1;
            self.state.statistics.no_buffer += 1;
            return;
        }
        self.state.inbound.push_back(frame.to_vec());
    }

    /// Whether the guest's receive queue has room for another frame.
    pub fn has_room(&self) -> bool {
        self.state.inbound.len() < QUEUE_FRAMES
    }

    /// The next frame the guest sent, for the host network.
    pub fn take(&mut self) -> Option<Vec<u8>> {
        self.state.outbound.pop_front()
    }
}

impl State {
    fn select(&mut self, alternate: u8) {
        self.alternate = alternate;
        self.assembling.clear();
        self.discarding = false;
        self.inbound.clear();
        self.sent = 0;
        self.zero_length_due = false;
        self.halted[1] = false;
        self.halted[2] = false;
        self.notifications.clear();
        let connected = u16::from(alternate == 1);
        if connected == 1 {
            let speed = LINK_BITS_PER_SECOND.to_le_bytes();
            let mut speeds = speed.to_vec();
            speeds.extend_from_slice(&speed);
            self.notifications
                .push_back(notification(CONNECTION_SPEED_CHANGE, 0, &speeds));
        }
        self.notifications
            .push_back(notification(NETWORK_CONNECTION, connected, &[]));
    }

    fn halt(&mut self, endpoint: u8) -> Option<&mut bool> {
        match endpoint {
            NOTIFY => Some(&mut self.halted[0]),
            BULK_IN => Some(&mut self.halted[1]),
            BULK_OUT => Some(&mut self.halted[2]),
            _ => None,
        }
    }

    fn bulk_in(&mut self, packet: &mut [u8]) -> Reply {
        let Some(frame) = self.inbound.front() else {
            return Reply::Nak;
        };
        if self.zero_length_due {
            self.zero_length_due = false;
            self.inbound.pop_front();
            self.sent = 0;
            return Reply::Ack(0);
        }
        let n = (frame.len() - self.sent).min(packet.len());
        packet[..n].copy_from_slice(&frame[self.sent..self.sent + n]);
        self.sent += n;
        if self.sent == frame.len() {
            self.statistics.received.count(frame);
            // A frame ending on a full packet needs a ZLP to end it (3.3.1).
            if n == packet.len() {
                self.zero_length_due = true;
            } else {
                self.inbound.pop_front();
                self.sent = 0;
            }
            self.counters.to_guest += 1;
        }
        Reply::Ack(n)
    }

    fn bulk_out(&mut self, packet: &[u8], max: usize) -> Reply {
        if self.outbound.len() >= QUEUE_FRAMES {
            // The host retries until the owner drains the queue.
            return Reply::Nak;
        }
        if !self.discarding {
            if self.assembling.len() + packet.len() > MAX_SEGMENT {
                self.discarding = true;
                self.assembling.clear();
            } else {
                self.assembling.extend_from_slice(packet);
            }
        }
        // A short packet, or a ZLP, ends the frame.
        if packet.len() < max {
            if self.discarding || (1..HEADER_BYTES).contains(&self.assembling.len()) {
                // Longer than a segment, or shorter than an Ethernet header.
                self.counters.oversized += 1;
                self.statistics.transmit_errors += 1;
            } else if !self.assembling.is_empty() {
                self.statistics.transmitted.count(&self.assembling);
                self.outbound
                    .push_back(core::mem::take(&mut self.assembling));
                self.counters.to_host += 1;
            }
            self.discarding = false;
            self.assembling.clear();
        }
        Reply::Ack(packet.len())
    }
}

impl State {
    /// The 32-bit count of statistic `selector`, if bmEthernetStatistics
    /// advertises it.
    fn statistic(&self, selector: u16) -> Option<u32> {
        let s = &self.statistics;
        let (sent, received) = (&s.transmitted.kinds, &s.received.kinds);
        let total = |t: &Traffic| t.kinds.iter().map(|(_, frames)| frames).sum::<u64>();
        let value = match selector {
            XMIT_OK => total(&s.transmitted),
            RCV_OK => total(&s.received),
            XMIT_ERROR => s.transmit_errors,
            RCV_ERROR => s.receive_errors,
            RCV_NO_BUFFER => s.no_buffer,
            DIRECTED_BYTES_XMIT => sent[UNICAST].0,
            DIRECTED_FRAMES_XMIT => sent[UNICAST].1,
            MULTICAST_BYTES_XMIT => sent[GROUP].0,
            MULTICAST_FRAMES_XMIT => sent[GROUP].1,
            BROADCAST_BYTES_XMIT => sent[EVERYONE].0,
            BROADCAST_FRAMES_XMIT => sent[EVERYONE].1,
            DIRECTED_BYTES_RCV => received[UNICAST].0,
            DIRECTED_FRAMES_RCV => received[UNICAST].1,
            MULTICAST_BYTES_RCV => received[GROUP].0,
            MULTICAST_FRAMES_RCV => received[GROUP].1,
            BROADCAST_BYTES_RCV => received[EVERYONE].0,
            BROADCAST_FRAMES_RCV => received[EVERYONE].1,
            TRANSMIT_QUEUE_LENGTH => self.outbound.len() as u64,
            _ => return None,
        };
        debug_assert_ne!(STATISTICS >> (selector - 1) & 1, 0);
        Some(value as u32)
    }
}

impl Requests for State {
    fn configure(&mut self, _value: u8) -> Result<(), Stall> {
        self.alternate = 0;
        self.filter = DIRECTED | BROADCAST | ALL_MULTICAST;
        self.multicast.clear();
        self.statistics = Statistics::default();
        self.halted = [false; 3];
        self.notifications.clear();
        self.assembling.clear();
        self.inbound.clear();
        self.sent = 0;
        self.zero_length_due = false;
        Ok(())
    }

    fn request(&mut self, setup: Setup, data: &[u8]) -> Result<Outcome, Stall> {
        let read = setup.device_to_host();
        match (setup.kind(), setup.recipient(), setup.request, read) {
            (CLASS, RECIPIENT_INTERFACE, SET_ETHERNET_PACKET_FILTER, false)
                if setup.index == CONTROL_INTERFACE && setup.length == 0 =>
            {
                if setup.value & !0x1f != 0 {
                    return Err(Stall);
                }
                self.filter = setup.value;
                Ok(Outcome::Done)
            }
            // The whole list at once: wValue groups, six bytes each.
            (CLASS, RECIPIENT_INTERFACE, SET_ETHERNET_MULTICAST_FILTERS, false)
                if setup.index == CONTROL_INTERFACE
                    && setup.value <= MULTICAST_FILTERS
                    && data.len() == 6 * usize::from(setup.value) =>
            {
                let groups: Vec<Mac> = data.as_chunks::<6>().0.iter().copied().map(Mac).collect();
                if !groups.iter().all(|group| group.is_multicast()) {
                    return Err(Stall);
                }
                self.multicast = groups;
                Ok(Outcome::Done)
            }
            (CLASS, RECIPIENT_INTERFACE, GET_ETHERNET_STATISTIC, true)
                if setup.index == CONTROL_INTERFACE && setup.length == 4 =>
            {
                let count = self.statistic(setup.value).ok_or(Stall)?;
                Ok(Outcome::Data(count.to_le_bytes().to_vec()))
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_STATUS, true) if setup.index <= DATA_INTERFACE => {
                Ok(Outcome::Data(vec![0, 0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_INTERFACE, true) => match setup.index {
                CONTROL_INTERFACE => Ok(Outcome::Data(vec![0])),
                DATA_INTERFACE => Ok(Outcome::Data(vec![self.alternate])),
                _ => Err(Stall),
            },
            (STANDARD, RECIPIENT_INTERFACE, SET_INTERFACE, false) => {
                match (setup.index, setup.value) {
                    (CONTROL_INTERFACE, 0) => Ok(Outcome::Done),
                    (DATA_INTERFACE, alternate @ 0..=1) => {
                        self.select(alternate as u8);
                        Ok(Outcome::Done)
                    }
                    _ => Err(Stall),
                }
            }
            (STANDARD, RECIPIENT_ENDPOINT, GET_STATUS, true) => {
                let halted = *self.halt(setup.index as u8).ok_or(Stall)?;
                Ok(Outcome::Data(vec![u8::from(halted), 0]))
            }
            (STANDARD, RECIPIENT_ENDPOINT, CLEAR_FEATURE | SET_FEATURE, false)
                if setup.value == ENDPOINT_HALT =>
            {
                *self.halt(setup.index as u8).ok_or(Stall)? = setup.request == SET_FEATURE;
                Ok(Outcome::Done)
            }
            _ => Err(Stall),
        }
    }
}

impl BusPeer for Ecm {
    fn reset(&mut self) -> Result<(), &'static str> {
        self.control.reset(&mut self.state)?;
        self.state
            .configure(0)
            .map_err(|Stall| "USB Ethernet reset")
    }

    fn packet(
        &mut self,
        endpoint: u8,
        token: Token,
        data: &mut [u8],
    ) -> Result<Reply, &'static str> {
        if endpoint == 0 {
            return self.control.packet(token, data, &mut self.state);
        }
        if token == Token::Setup {
            return Err("SETUP to a non-control endpoint");
        }
        let configured = self.control.configuration() != 0;
        let active = configured && self.state.alternate == 1;
        let state = &mut self.state;
        if state.halt(endpoint).is_some_and(|halted| *halted) {
            return Ok(Reply::Stall);
        }
        Ok(match (endpoint, token) {
            (NOTIFY, Token::In) if configured => match state.notifications.pop_front() {
                Some(bytes) => {
                    let n = bytes.len().min(data.len());
                    data[..n].copy_from_slice(&bytes[..n]);
                    Reply::Ack(n)
                }
                None => Reply::Nak,
            },
            (BULK_IN, Token::In) if active => state.bulk_in(data),
            // The adapter sits on a high-speed port: 512-byte packets
            // delimit frames.
            (BULK_OUT, Token::Out) if active => {
                state.bulk_out(data, usize::from(HIGH_SPEED_PACKET))
            }
            _ => Reply::Stall,
        })
    }
}

impl Function for Ecm {
    fn set_time(&mut self, _now: u64) {}

    fn ready_at(&self, endpoint: u8) -> Option<u64> {
        let configured = self.control.configuration() != 0;
        let ready = match endpoint {
            NOTIFY => configured && !self.state.notifications.is_empty(),
            BULK_IN => self.up() && !self.state.inbound.is_empty(),
            _ => false,
        };
        ready.then_some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::dwc3::xhci::tests::host,
        usb::{
            Speed,
            control::{
                GET_DESCRIPTOR, SET_ADDRESS, SET_CONFIGURATION,
                tests::{setup, transfer},
            },
            hub::{Hub, Ports},
        },
    };
    use stela_drivers::net::Link;

    const MAC: Mac = Mac([0x02, 0x53, 0x54, 0x00, 0x00, 0x01]);

    fn adapter(up: bool) -> Ecm {
        let mut e = Ecm::new(MAC).unwrap();
        transfer(&mut e, setup(0, SET_ADDRESS, 3, 0, 0), &[]).unwrap();
        transfer(&mut e, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        if up {
            transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        }
        e
    }

    fn read(e: &mut Ecm, endpoint: u8) -> Option<Vec<u8>> {
        let mut packet = [0u8; 512];
        match e.packet(endpoint, Token::In, &mut packet).unwrap() {
            Reply::Ack(n) => Some(packet[..n].to_vec()),
            Reply::Nak => None,
            Reply::Stall => panic!("STALL on {endpoint:#x}"),
        }
    }

    fn frame(destination: Mac, length: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..length).map(|n| n as u8).collect();
        bytes[..6].copy_from_slice(&destination.0);
        bytes
    }

    #[test]
    fn descriptors_present_a_cdc_ethernet_control_model_adapter() {
        let mut e = adapter(false);
        let config = transfer(&mut e, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(config[4], 2, "two interfaces");
        assert_eq!(&config[9..18], &[9, INTERFACE, 0, 0, 1, 2, 6, 0, 0]);
        // The Ethernet Networking descriptor names string 4, the MAC.
        assert_eq!(&config[28..31], &[13, 0x24, 0x0f]);
        assert_eq!(config[31], 4);
        let mac = transfer(&mut e, setup(0x80, GET_DESCRIPTOR, 0x304, 0x409, 255), &[]).unwrap();
        assert_eq!(mac, control::string("025354000001"));
        assert!(Ecm::new(Mac::BROADCAST).is_err());
    }

    #[test]
    fn selecting_the_data_setting_raises_the_link_and_notifies_it() {
        let mut e = adapter(false);
        assert!(!e.up());
        assert_eq!(read(&mut e, NOTIFY), None);
        e.deliver(&frame(MAC, 60));
        assert_eq!(e.counters().filtered, 1);
        transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        assert!(e.up());
        assert_eq!(e.ready_at(NOTIFY), Some(0));
        let speed = read(&mut e, NOTIFY).unwrap();
        assert_eq!(&speed[..2], &[0xa1, CONNECTION_SPEED_CHANGE]);
        assert_eq!(&speed[8..12], &LINK_BITS_PER_SECOND.to_le_bytes());
        let link = read(&mut e, NOTIFY).unwrap();
        assert_eq!(link, [0xa1, NETWORK_CONNECTION, 1, 0, 0, 0, 0, 0]);
        let alternate = transfer(&mut e, setup(0x81, GET_INTERFACE, 0, 1, 1), &[]).unwrap();
        assert_eq!(alternate, [1]);
        transfer(&mut e, setup(0x01, SET_INTERFACE, 0, 1, 0), &[]).unwrap();
        assert_eq!(read(&mut e, NOTIFY).unwrap()[2], 0);
        assert!(transfer(&mut e, setup(0x01, SET_INTERFACE, 2, 1, 0), &[]).is_err());
    }

    #[test]
    fn frames_move_both_ways_delimited_by_short_packets() {
        let mut e = adapter(true);
        // Guest to host: 600 bytes as 512 + 88; 512 bytes as 512 + ZLP.
        let first = frame(Mac::BROADCAST, 600);
        for chunk in [&first[..512], &first[512..]] {
            let reply = e.packet(BULK_OUT, Token::Out, &mut chunk.to_vec());
            assert_eq!(reply, Ok(Reply::Ack(chunk.len())));
        }
        let second = frame(Mac::BROADCAST, 512);
        e.packet(BULK_OUT, Token::Out, &mut second.clone()).unwrap();
        assert_eq!(e.take(), Some(first));
        assert_eq!(e.take(), None);
        e.packet(BULK_OUT, Token::Out, &mut []).unwrap();
        assert_eq!(e.take(), Some(second));
        // An oversized frame is discarded whole.
        for _ in 0..3 {
            e.packet(BULK_OUT, Token::Out, &mut [0u8; 512]).unwrap();
        }
        e.packet(BULK_OUT, Token::Out, &mut [0u8; 10]).unwrap();
        assert_eq!((e.take(), e.counters().oversized), (None, 1));
        // Host to guest: a 1024-byte frame is 512, 512 and a ZLP.
        e.deliver(&frame(MAC, 1024));
        assert_eq!(e.ready_at(BULK_IN), Some(0));
        let sizes: Vec<usize> = (0..3)
            .map(|_| read(&mut e, BULK_IN).unwrap().len())
            .collect();
        assert_eq!(sizes, [512, 512, 0]);
        assert_eq!(read(&mut e, BULK_IN), None);
        assert_eq!(e.counters().to_guest, 1);
    }

    #[test]
    fn a_full_receive_queue_has_no_room_and_drops_the_next_frame() {
        let mut e = adapter(true);
        for _ in 0..QUEUE_FRAMES {
            assert!(e.has_room());
            e.deliver(&frame(MAC, 60));
        }
        assert!(!e.has_room());
        e.deliver(&frame(MAC, 60));
        assert_eq!(e.state.counters.overflowed, 1);
        assert_eq!(e.state.inbound.len(), QUEUE_FRAMES);
    }

    #[test]
    fn the_packet_filter_selects_received_frames() {
        let mut e = adapter(true);
        let other = Mac([0x02, 0, 0, 0, 0, 9]);
        e.deliver(&frame(other, 60));
        e.deliver(&frame(Mac([0x01, 0, 0x5e, 0, 0, 1]), 60));
        assert_eq!((e.counters().filtered, e.state.inbound.len()), (1, 1));
        // Directed only: multicast and broadcast stop.
        let directed = setup(0x21, SET_ETHERNET_PACKET_FILTER, DIRECTED, 0, 0);
        transfer(&mut e, directed, &[]).unwrap();
        e.deliver(&frame(Mac::BROADCAST, 60));
        assert_eq!(e.counters().filtered, 2);
        // Promiscuous: everything.
        let promiscuous = setup(0x21, SET_ETHERNET_PACKET_FILTER, PROMISCUOUS, 0, 0);
        transfer(&mut e, promiscuous, &[]).unwrap();
        e.deliver(&frame(other, 60));
        assert_eq!(e.state.inbound.len(), 2);
        // Unknown filter bits are refused.
        let unknown = setup(0x21, SET_ETHERNET_PACKET_FILTER, 0x20, 0, 0);
        assert!(transfer(&mut e, unknown, &[]).is_err());
    }

    #[test]
    fn multicast_filters_pass_exactly_the_listed_groups() {
        let mut e = adapter(true);
        let config = transfer(&mut e, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(&config[38..40], &MULTICAST_FILTERS.to_le_bytes());
        assert_eq!(config[40], 0, "no power filters");
        let listed = Mac([0x01, 0, 0x5e, 0, 0, 0xfb]);
        let other = Mac([0x33, 0x33, 0, 0, 0, 1]);
        let list = setup(0x21, SET_ETHERNET_MULTICAST_FILTERS, 1, 0, 6);
        transfer(&mut e, list, &listed.0).unwrap();
        let multicast = setup(0x21, SET_ETHERNET_PACKET_FILTER, DIRECTED | MULTICAST, 0, 0);
        transfer(&mut e, multicast, &[]).unwrap();
        e.deliver(&frame(listed, 60));
        e.deliver(&frame(other, 60));
        assert_eq!((e.state.inbound.len(), e.counters().filtered), (1, 1));
        // ALL_MULTICAST passes every group.
        let all = setup(0x21, SET_ETHERNET_PACKET_FILTER, ALL_MULTICAST, 0, 0);
        transfer(&mut e, all, &[]).unwrap();
        e.deliver(&frame(other, 60));
        assert_eq!(e.state.inbound.len(), 2);
        // Too many groups, a unicast group or a short list are refused.
        let too_many = setup(0x21, SET_ETHERNET_MULTICAST_FILTERS, 33, 0, 198);
        assert!(transfer(&mut e, too_many, &[0x01; 198]).is_err());
        assert!(transfer(&mut e, list, &MAC.0).is_err());
        let short = setup(0x21, SET_ETHERNET_MULTICAST_FILTERS, 2, 0, 6);
        assert!(transfer(&mut e, short, &listed.0).is_err());
        // An empty list clears it.
        let clear = setup(0x21, SET_ETHERNET_MULTICAST_FILTERS, 0, 0, 0);
        transfer(&mut e, clear, &[]).unwrap();
        assert!(e.state.multicast.is_empty());
    }

    #[test]
    fn statistics_count_frames_and_bytes_by_kind() {
        let mut e = adapter(true);
        let statistic = |e: &mut Ecm, selector: u16| {
            let bytes = transfer(e, setup(0xa1, GET_ETHERNET_STATISTIC, selector, 0, 4), &[]);
            u32::from_le_bytes(bytes.unwrap().try_into().unwrap())
        };
        // Guest to host: one broadcast frame, one too short to be one.
        e.packet(BULK_OUT, Token::Out, &mut frame(Mac::BROADCAST, 100))
            .unwrap();
        e.packet(BULK_OUT, Token::Out, &mut [0u8; 10]).unwrap();
        // Host to guest: one directed frame read in full, one oversized.
        e.deliver(&frame(MAC, 60));
        e.deliver(&[0u8; MAX_SEGMENT + 1]);
        read(&mut e, BULK_IN).unwrap();
        assert_eq!(statistic(&mut e, XMIT_OK), 1);
        assert_eq!(statistic(&mut e, BROADCAST_BYTES_XMIT), 100);
        assert_eq!(statistic(&mut e, BROADCAST_FRAMES_XMIT), 1);
        assert_eq!(statistic(&mut e, DIRECTED_FRAMES_XMIT), 0);
        assert_eq!(statistic(&mut e, XMIT_ERROR), 1);
        assert_eq!(statistic(&mut e, TRANSMIT_QUEUE_LENGTH), 1);
        assert_eq!(statistic(&mut e, RCV_OK), 1);
        assert_eq!(statistic(&mut e, DIRECTED_BYTES_RCV), 60);
        assert_eq!(statistic(&mut e, RCV_ERROR), 1);
        assert_eq!(statistic(&mut e, RCV_NO_BUFFER), 0);
        // Every advertised selector answers; the others STALL.
        for selector in 1..=29u16 {
            let request = setup(0xa1, GET_ETHERNET_STATISTIC, selector, 0, 4);
            let advertised = STATISTICS >> (selector - 1) & 1 != 0;
            assert_eq!(
                transfer(&mut e, request, &[]).is_ok(),
                advertised,
                "{selector}"
            );
        }
        // Power-management pattern filters are not offered.
        assert!(transfer(&mut e, setup(0x21, 0x41, 0, 0, 0), &[]).is_err());
        assert!(transfer(&mut e, setup(0xa1, 0x42, 0, 0, 2), &[]).is_err());
    }

    struct One(Ecm);
    impl Ports for One {
        fn count(&self) -> usize {
            1
        }
        fn speed(&self, _: usize) -> Speed {
            Speed::High
        }
        fn function(&mut self, _: usize) -> &mut dyn Function {
            &mut self.0
        }
        fn function_ref(&self, _: usize) -> &dyn Function {
            &self.0
        }
    }

    #[test]
    fn the_native_ecm_adapter_moves_frames_for_the_host() {
        let mac = Mac([0x02, 0x53, 0x54, 0, 0, 7]);
        let hub = Hub::new(One(Ecm::new(mac).unwrap()), "HUB").unwrap();
        let mut bench = host::bench(hub);
        let mut found = host::run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.links.len(), 1);
        let mut link = found.links.remove(0);
        assert_eq!(link.mac(), mac);
        assert!(link.carrier());
        assert!(bench.model.borrow().function.ports.0.up());
        // Host to network: a 1024-byte frame (two full packets and a ZLP).
        let mut frame = vec![0u8; 1024];
        frame[..6].copy_from_slice(&Mac::BROADCAST.0);
        frame[6..12].copy_from_slice(&mac.0);
        link.transmit(&frame).unwrap();
        assert_eq!(
            bench.model.borrow_mut().function.ports.0.take(),
            Some(frame.clone())
        );
        // Network to host.
        let mut inbound = vec![7u8; 600];
        inbound[..6].copy_from_slice(&mac.0);
        bench.model.borrow_mut().function.ports.0.deliver(&inbound);
        let mut received = None;
        for _ in 0..50 {
            if let Some(frame) = link.receive().unwrap() {
                received = Some(frame);
                break;
            }
        }
        assert_eq!(received, Some(inbound));
        assert!(link.transmit(&[0u8; 1515]).is_err());
    }
}
