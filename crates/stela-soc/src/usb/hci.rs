//! A native USB Bluetooth controller: the HCI USB transport, whose packets
//! the machine owner exchanges with a controller of the host.
//!
//! Evidence: Bluetooth Core v5.4 Vol 4 Part B 2 (class 0xE0/0x01/0x01, HCI
//! commands as class request 0 on the control pipe, events on interrupt IN,
//! ACL data on bulk IN and OUT) and Part E 5.4 (packet lengths) and 7.7.14
//! (Command Complete). J473 macOS binds no kernel driver: `bluetoothd`'s
//! `Found_USB_Dongle` (0x1000fc61c) opens the `IOUSBHostDevice` from user
//! space, takes vendor 0x0A12, 0x0A5C or a short list of pairs, ignores any
//! other, and `FoundBluetoothInterfaces` (0x1000ffde0) walks the interfaces
//! for the endpoints above.
//!
//! The function therefore carries CSR's generic HCI identity, 0x0A12:0x0001,
//! whatever the host's controller is: that identity promises the standard
//! HCI and no vendor protocol. A vendor command (OGF 0x3F) means something
//! else to every other vendor's controller, so none reaches the host's: the
//! function answers each with Command Complete, status Unknown HCI Command,
//! and counts it.
//!
//! The configuration also carries the standard synchronous interface (Vol 4
//! Part B 2.1.1): interface 1, alternate settings 0-5, each with an
//! isochronous IN and OUT endpoint of 0, 9, 17, 25, 33 and 49 bytes.
//! Host stacks require it: macOS's takes a controller only when interface 0
//! has the interrupt and bulk pipes and interface 1 has both isochronous
//! pipes in each of alternate settings 0-5. Isochronous data is not
//! transported: the endpoints answer no transaction, so a SCO link carries
//! no audio. The model never forms one.
//!
//! When the host lends no controller, the owner selects [`model::Model`]
//! with [`Hci::use_model`]: the same function then answers every command
//! itself, as a controller whose radio finds nothing in range.
//!
//! HCI headers frame every packet, so an OUT transfer may span USB packets.
//! An IN packet that ends one on a full USB packet is followed by a
//! zero-length one, which ends the host's transfer. A packet of a length the
//! headers do not agree with is discarded and counted, never truncated. Each
//! direction's queue holds at most [`QUEUE_PACKETS`]: OUT NAKs while it is
//! full, and [`Hci::has_room`] tells the owner to leave packets with the
//! host's controller.
use super::{
    BusPeer, Function, Reply, Token,
    control::{
        self, CLASS, CLEAR_FEATURE, Control, DEVICE, DEVICE_QUALIFIER, Descriptors, ENDPOINT,
        ENDPOINT_HALT, GET_INTERFACE, GET_STATUS, INTERFACE, Outcome, RECIPIENT_DEVICE,
        RECIPIENT_ENDPOINT, RECIPIENT_INTERFACE, Requests, SET_FEATURE, SET_INTERFACE, STANDARD,
        Setup, Stall,
    },
};
use crate::Result;
use alloc::{boxed::Box, collections::VecDeque, string::String, vec, vec::Vec};
use stela_contracts::refuse;
use stela_drivers::usb::bluetooth::MAX_ACL_PAYLOAD;

pub mod model;

const EVENTS: u8 = 0x81;
const ACL_IN: u8 = 0x82;
const ACL_OUT: u8 = 0x02;
const EVENT_PACKET: usize = 16;
const HIGH_SPEED_PACKET: u16 = 512;
const FULL_SPEED_PACKET: u16 = 64;
const INTERFACE_NUMBER: u16 = 0;
/// The synchronous interface and its endpoints.
const SCO_INTERFACE: u16 = 1;
const SCO_IN: u8 = 0x83;
const SCO_OUT: u8 = 0x03;
/// wMaxPacketSize of each alternate setting (Vol 4 Part B 2.1.1).
const SCO_PACKETS: [u8; 6] = [0, 9, 17, 25, 33, 49];
/// Packets each direction holds.
pub const QUEUE_PACKETS: usize = 64;
/// bRequest of an HCI command (Vol 4 Part B 2.2).
const HCI_COMMAND: u8 = 0;
/// A command's header: opcode and parameter length.
const COMMAND_HEADER: usize = 3;
/// An ACL packet's header: handle and flags, then data length.
const ACL_HEADER: usize = 4;
const VENDOR_GROUP: u16 = 0x3f;
const COMMAND_COMPLETE: u8 = 0x0e;
/// HCI error 0x01 (Vol 1 Part F 1.3).
const UNKNOWN_COMMAND: u8 = 0x01;

/// What the guest sent for the host's controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Command(Vec<u8>),
    Acl(Vec<u8>),
}

/// Counters for the owner's diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub commands: u64,
    /// Vendor commands answered here.
    pub vendor_refused: u64,
    pub acl_to_host: u64,
    pub events_to_guest: u64,
    pub acl_to_guest: u64,
    /// Packets whose lengths disagree with their headers, discarded.
    pub malformed: u64,
    pub overflowed: u64,
    /// Commands the model answered Unknown HCI Command, vendor ones among
    /// them.
    pub unknown: u64,
    /// ACL packets the model discarded: they named no connection.
    pub acl_discarded: u64,
}

/// One IN endpoint's packets, sent in USB packets.
#[derive(Debug, Clone, Default)]
struct Stream {
    queue: VecDeque<Vec<u8>>,
    sent: usize,
    zero_length_due: bool,
}

impl Stream {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn read(&mut self, data: &mut [u8], maximum: usize) -> Reply {
        let Some(packet) = self.queue.front() else {
            return Reply::Nak;
        };
        if self.zero_length_due {
            self.zero_length_due = false;
            self.queue.pop_front();
            self.sent = 0;
            return Reply::Ack(0);
        }
        let n = (packet.len() - self.sent).min(data.len()).min(maximum);
        data[..n].copy_from_slice(&packet[self.sent..self.sent + n]);
        self.sent += n;
        if self.sent == packet.len() {
            if n == maximum {
                self.zero_length_due = true;
            } else {
                self.queue.pop_front();
                self.sent = 0;
            }
        }
        Reply::Ack(n)
    }
}

#[derive(Debug, Clone)]
struct State {
    /// Halted: EVENTS, ACL_IN, ACL_OUT.
    halted: [bool; 3],
    /// The synchronous interface's alternate setting.
    sco_setting: u8,
    outbound: VecDeque<Outbound>,
    events: Stream,
    acl: Stream,
    assembling: Vec<u8>,
    counters: Counters,
    /// The controller model, when no host controller is behind the function.
    model: Option<Box<model::Model>>,
    /// The system count of the latest transactions.
    now: u64,
}

/// The function: its pipes and queues.
#[derive(Debug, Clone)]
pub struct Hci {
    control: Control,
    state: State,
}

fn descriptors() -> Descriptors {
    let device = [
        18,
        DEVICE,
        0x00,
        0x02,
        0xe0,
        0x01,
        0x01,
        control::EP0_PACKET as u8,
        0x12,
        0x0a,
        0x01,
        0x00,
        0x00,
        0x01,
        1,
        2,
        0,
        1,
    ];
    let configuration = |bulk: u16, interval: u8| {
        let [low, high] = bulk.to_le_bytes();
        let mut parts = vec![
            vec![9, INTERFACE, 0, 0, 3, 0xe0, 0x01, 0x01, 0],
            vec![7, ENDPOINT, EVENTS, 3, EVENT_PACKET as u8, 0, interval],
            vec![7, ENDPOINT, ACL_IN, 2, low, high, 0],
            vec![7, ENDPOINT, ACL_OUT, 2, low, high, 0],
        ];
        for (setting, &size) in SCO_PACKETS.iter().enumerate() {
            parts.push(vec![9, INTERFACE, 1, setting as u8, 2, 0xe0, 0x01, 0x01, 0]);
            for address in [SCO_IN, SCO_OUT] {
                // Isochronous, no synchronization, one packet a frame.
                parts.push(vec![7, ENDPOINT, address, 0x01, size, 0, interval]);
            }
        }
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        control::configuration(1, 0, &parts)
    };
    let qualifier = [
        10,
        DEVICE_QUALIFIER,
        0x00,
        0x02,
        0xe0,
        0x01,
        0x01,
        control::EP0_PACKET as u8,
        1,
        0,
    ];
    Descriptors {
        device,
        // High speed: 2^(4-1) microframes, 1 ms; full speed: 1 frame.
        configuration: configuration(HIGH_SPEED_PACKET, 4),
        other_speed: Some((qualifier, configuration(FULL_SPEED_PACKET, 1))),
        strings: vec![String::from("Stela"), String::from("Stela Bluetooth")],
    }
}

impl Hci {
    pub fn new() -> Self {
        Self {
            control: Control::new(descriptors()),
            state: State {
                halted: [false; 3],
                sco_setting: 0,
                outbound: VecDeque::new(),
                events: Stream::default(),
                acl: Stream::default(),
                assembling: Vec::new(),
                counters: Counters::default(),
                model: None,
                now: 0,
            },
        }
    }

    /// Whether the guest configured the function.
    pub fn up(&self) -> bool {
        self.control.configuration() != 0
    }

    pub fn counters(&self) -> Counters {
        self.state.counters
    }

    /// Whether both IN queues have room for a packet from the host's
    /// controller, which may hold one of each.
    pub fn has_room(&self) -> bool {
        let state = &self.state;
        state.events.queue.len() < QUEUE_PACKETS && state.acl.queue.len() < QUEUE_PACKETS
    }

    /// Answers every packet with a controller model whose BD_ADDR is
    /// `address`, from now on. Packets already queued for a host
    /// controller go to it.
    pub fn use_model(&mut self, address: [u8; 6]) {
        let state = &mut self.state;
        state.model = Some(Box::new(model::Model::new(address)));
        for packet in core::mem::take(&mut state.outbound) {
            match packet {
                Outbound::Command(bytes) => state.modeled_command(&bytes),
                Outbound::Acl(bytes) => state.modeled_acl(&bytes),
            }
        }
    }

    /// Whether the model answers.
    pub fn modeled(&self) -> bool {
        self.state.model.is_some()
    }

    /// Opcodes the model answered Unknown HCI Command that were not taken
    /// before, each once.
    pub fn take_unknown(&mut self) -> Vec<u16> {
        self.state
            .model
            .as_mut()
            .map(|model| model.take_unknown())
            .unwrap_or_default()
    }

    /// The next packet the guest sent for the host's controller.
    pub fn take(&mut self) -> Option<Outbound> {
        self.state.outbound.pop_front()
    }

    /// An event from the host's controller for the guest. Dropped (and
    /// counted) while the function is unconfigured or the queue is full.
    pub fn deliver_event(&mut self, packet: &[u8]) {
        if !self.up() {
            return;
        }
        self.state.event(packet.to_vec());
    }

    /// ACL data from the host's controller for the guest, dropped as an
    /// event is.
    pub fn deliver_acl(&mut self, packet: &[u8]) {
        if !self.up() {
            return;
        }
        let state = &mut self.state;
        if state.acl.queue.len() >= QUEUE_PACKETS {
            state.counters.overflowed += 1;
            return;
        }
        state.counters.acl_to_guest += 1;
        state.acl.queue.push_back(packet.to_vec());
    }
}

impl Default for Hci {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    fn event(&mut self, packet: Vec<u8>) {
        if self.events.queue.len() >= QUEUE_PACKETS {
            self.counters.overflowed += 1;
            return;
        }
        self.counters.events_to_guest += 1;
        self.events.queue.push_back(packet);
    }

    fn modeled_command(&mut self, packet: &[u8]) {
        let Some(model) = self.model.as_mut() else {
            return;
        };
        self.counters.commands += 1;
        if !model::implements(u16::from_le_bytes([packet[0], packet[1]])) {
            self.counters.unknown += 1;
        }
        let events = model.command(packet, self.now);
        events.into_iter().for_each(|e| self.event(e));
    }

    fn modeled_acl(&mut self, packet: &[u8]) {
        let Some(model) = self.model.as_mut() else {
            return;
        };
        self.counters.acl_discarded += 1;
        let events = model.acl(packet);
        events.into_iter().for_each(|e| self.event(e));
    }

    fn halt(&mut self, endpoint: u8) -> Option<&mut bool> {
        match endpoint {
            EVENTS => Some(&mut self.halted[0]),
            ACL_IN => Some(&mut self.halted[1]),
            ACL_OUT => Some(&mut self.halted[2]),
            _ => None,
        }
    }

    /// One HCI command from the control pipe.
    fn command(&mut self, packet: &[u8]) -> Result<(), Stall> {
        let &[low, high, length, ..] = packet else {
            return Err(Stall);
        };
        if packet.len() != COMMAND_HEADER + usize::from(length) {
            self.counters.malformed += 1;
            return Err(Stall);
        }
        let vendor = u16::from_le_bytes([low, high]) >> 10 == VENDOR_GROUP;
        if self.model.is_some() {
            self.counters.vendor_refused += u64::from(vendor);
            self.modeled_command(packet);
            return Ok(());
        }
        if vendor {
            self.counters.vendor_refused += 1;
            self.event(vec![COMMAND_COMPLETE, 4, 1, low, high, UNKNOWN_COMMAND]);
            return Ok(());
        }
        if self.outbound.len() >= QUEUE_PACKETS {
            return Err(Stall);
        }
        self.counters.commands += 1;
        self.outbound.push_back(Outbound::Command(packet.to_vec()));
        Ok(())
    }

    fn acl_out(&mut self, packet: &[u8]) -> Reply {
        if self.outbound.len() >= QUEUE_PACKETS {
            // The host retries until the owner drains the queue.
            return Reply::Nak;
        }
        self.assembling.extend_from_slice(packet);
        let Some(&[_, _, low, high]) = self.assembling.first_chunk() else {
            return Reply::Ack(packet.len());
        };
        let data = usize::from(u16::from_le_bytes([low, high]));
        if data > MAX_ACL_PAYLOAD {
            self.counters.malformed += 1;
            self.assembling.clear();
        } else if self.assembling.len() == ACL_HEADER + data {
            let packet = core::mem::take(&mut self.assembling);
            if self.model.is_some() {
                self.modeled_acl(&packet);
            } else {
                self.counters.acl_to_host += 1;
                self.outbound.push_back(Outbound::Acl(packet));
            }
        } else if self.assembling.len() > ACL_HEADER + data {
            self.counters.malformed += 1;
            self.assembling.clear();
        }
        Reply::Ack(packet.len())
    }
}

impl Requests for State {
    fn configure(&mut self, _value: u8) -> Result<(), Stall> {
        self.halted = [false; 3];
        self.sco_setting = 0;
        self.outbound.clear();
        self.events.clear();
        self.acl.clear();
        self.assembling.clear();
        Ok(())
    }

    fn request(&mut self, setup: Setup, data: &[u8]) -> Result<Outcome, Stall> {
        let read = setup.device_to_host();
        match (setup.kind(), setup.recipient(), setup.request, read) {
            // Vol 4 Part B 2.2 names the device; hosts also send it to the
            // interface.
            (CLASS, RECIPIENT_DEVICE | RECIPIENT_INTERFACE, HCI_COMMAND, false) => {
                self.command(data).map(|()| Outcome::Done)
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_STATUS, true)
                if setup.index == INTERFACE_NUMBER || setup.index == SCO_INTERFACE =>
            {
                Ok(Outcome::Data(vec![0, 0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_INTERFACE, true)
                if setup.index == SCO_INTERFACE =>
            {
                Ok(Outcome::Data(vec![self.sco_setting]))
            }
            (STANDARD, RECIPIENT_INTERFACE, SET_INTERFACE, false)
                if setup.index == SCO_INTERFACE && usize::from(setup.value) < SCO_PACKETS.len() =>
            {
                self.sco_setting = setup.value as u8;
                Ok(Outcome::Done)
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_INTERFACE, true)
                if setup.index == INTERFACE_NUMBER =>
            {
                Ok(Outcome::Data(vec![0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, SET_INTERFACE, false)
                if setup.index == INTERFACE_NUMBER && setup.value == 0 =>
            {
                Ok(Outcome::Done)
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

impl BusPeer for Hci {
    fn reset(&mut self) -> Result<()> {
        // A bus reset powers the controller up again.
        if let Some(model) = self.state.model.as_mut() {
            model.reset();
        }
        self.control.reset(&mut self.state)?;
        self.state
            .configure(0)
            .map_err(|Stall| refuse!("USB Bluetooth reset stalled"))
    }

    fn packet(&mut self, endpoint: u8, token: Token, data: &mut [u8]) -> Result<Reply> {
        if endpoint == 0 {
            return self.control.packet(token, data, &mut self.state);
        }
        if token == Token::Setup {
            return Err(refuse!("SETUP to a non-control endpoint"));
        }
        let configured = self.up();
        let state = &mut self.state;
        if state.halt(endpoint).is_some_and(|halted| *halted) {
            return Ok(Reply::Stall);
        }
        Ok(match (endpoint, token) {
            (EVENTS, Token::In) if configured => state.events.read(data, EVENT_PACKET),
            // The controller sits on a high-speed port.
            (ACL_IN, Token::In) if configured => {
                state.acl.read(data, usize::from(HIGH_SPEED_PACKET))
            }
            (ACL_OUT, Token::Out) if configured => state.acl_out(data),
            _ => Reply::Stall,
        })
    }
}

impl Function for Hci {
    fn set_time(&mut self, now: u64) {
        let state = &mut self.state;
        state.now = now;
        if let Some(model) = state.model.as_mut() {
            let events = model.advance(now);
            events.into_iter().for_each(|e| state.event(e));
        }
    }

    fn ready_at(&self, endpoint: u8) -> Option<u64> {
        if !self.up() {
            return None;
        }
        let state = &self.state;
        match endpoint {
            EVENTS if !state.events.queue.is_empty() => Some(0),
            // A procedure's end is an event then.
            EVENTS => state.model.as_ref().and_then(|model| model.deadline()),
            ACL_IN => (!state.acl.queue.is_empty()).then_some(0),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::control::{
        SET_ADDRESS, SET_CONFIGURATION,
        tests::{setup, transfer},
    };

    fn controller() -> Hci {
        let mut hci = Hci::new();
        transfer(&mut hci, setup(0, SET_ADDRESS, 1, 0, 0), &[]).unwrap();
        transfer(&mut hci, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        hci
    }

    fn command(hci: &mut Hci, packet: &[u8]) -> Result<(), ()> {
        let request = setup(0x20, HCI_COMMAND, 0, 0, packet.len() as u16);
        transfer(hci, request, packet).map(|_| ()).map_err(|_| ())
    }

    /// An IN transfer's packets until one is short.
    fn read(hci: &mut Hci, endpoint: u8, maximum: usize) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        loop {
            let mut buffer = vec![0; maximum];
            let Reply::Ack(n) = hci.packet(endpoint, Token::In, &mut buffer).unwrap() else {
                panic!("the endpoint had a packet to send");
            };
            packets.push(buffer[..n].to_vec());
            if n < maximum {
                return packets;
            }
        }
    }

    #[test]
    fn the_identity_is_a_generic_bluetooth_controller_macos_accepts() {
        let hci = Hci::new();
        let device = hci.control.descriptors.device;
        assert_eq!(device[4..7], [0xe0, 0x01, 0x01]);
        assert_eq!(device[8..12], [0x12, 0x0a, 0x01, 0x00]);
        let configuration = hci.control.descriptors.configuration;
        assert_eq!(configuration[9 + 4], 3, "interrupt, bulk IN and bulk OUT");
        assert_eq!(configuration[9 + 5..9 + 8], [0xe0, 0x01, 0x01]);
    }

    /// The walk a host stack makes before it takes the controller:
    /// interface 0 with interrupt IN, bulk IN and bulk OUT; interface 1 with
    /// an isochronous IN and OUT pipe in each of alternate settings 0-5.
    #[test]
    fn the_configuration_has_the_interfaces_bluetoothd_requires() {
        for configuration in [
            descriptors().configuration,
            descriptors().other_speed.unwrap().1,
        ] {
            assert_eq!(configuration[4], 2, "two interfaces");
            assert_eq!(
                usize::from(u16::from_le_bytes([configuration[2], configuration[3]])),
                configuration.len()
            );
            let mut at = 9;
            let mut interface = (0, 0);
            let mut pipes: Vec<((u8, u8), u8, u8, u16)> = Vec::new();
            while at < configuration.len() {
                let d = &configuration[at..at + usize::from(configuration[at])];
                match d[1] {
                    INTERFACE => interface = (d[2], d[3]),
                    ENDPOINT => {
                        pipes.push((interface, d[2], d[3] & 3, u16::from_le_bytes([d[4], d[5]])))
                    }
                    _ => panic!("unexpected descriptor"),
                }
                at += d.len();
            }
            let kinds = |i| -> Vec<(u8, u8)> {
                pipes
                    .iter()
                    .filter(|p| p.0 == i)
                    .map(|p| (p.1, p.2))
                    .collect()
            };
            assert_eq!(kinds((0, 0)), [(EVENTS, 3), (ACL_IN, 2), (ACL_OUT, 2)]);
            for (setting, size) in SCO_PACKETS.into_iter().enumerate() {
                assert_eq!(kinds((1, setting as u8)), [(SCO_IN, 1), (SCO_OUT, 1)]);
                assert!(
                    pipes
                        .iter()
                        .filter(|p| p.0 == (1, setting as u8))
                        .all(|p| p.3 == u16::from(size))
                );
            }
        }
        let mut hci = controller();
        let get = setup(0x81, GET_INTERFACE, 0, SCO_INTERFACE, 1);
        assert_eq!(transfer(&mut hci, get, &[]).unwrap(), [0]);
        transfer(
            &mut hci,
            setup(0x01, SET_INTERFACE, 5, SCO_INTERFACE, 0),
            &[],
        )
        .unwrap();
        assert_eq!(transfer(&mut hci, get, &[]).unwrap(), [5]);
        assert!(
            transfer(
                &mut hci,
                setup(0x01, SET_INTERFACE, 6, SCO_INTERFACE, 0),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn commands_reach_the_owner_and_vendor_commands_stop_here() {
        let mut hci = controller();
        // HCI_Reset.
        command(&mut hci, &[0x03, 0x0c, 0]).unwrap();
        assert_eq!(
            hci.take(),
            Some(Outbound::Command(vec![0x03, 0x0c, 0])),
            "a standard command"
        );
        // An opcode in OGF 0x3F, with one parameter.
        command(&mut hci, &[0x01, 0xfc, 1, 9]).unwrap();
        assert_eq!(hci.take(), None, "a vendor command stays here");
        assert_eq!(
            read(&mut hci, EVENTS, EVENT_PACKET),
            [vec![COMMAND_COMPLETE, 4, 1, 0x01, 0xfc, UNKNOWN_COMMAND]]
        );
        assert_eq!(hci.counters().commands, 1);
        assert_eq!(hci.counters().vendor_refused, 1);
        // Its length disagrees with its header.
        assert!(command(&mut hci, &[0x03, 0x0c, 2, 0]).is_err());
        assert_eq!(hci.counters().malformed, 1);
    }

    #[test]
    fn an_event_on_a_full_packet_ends_with_a_zero_length_one() {
        let mut hci = controller();
        assert_eq!(hci.ready_at(EVENTS), None);
        let event = [0x3e; 32];
        hci.deliver_event(&event);
        assert_eq!(hci.ready_at(EVENTS), Some(0));
        let packets = read(&mut hci, EVENTS, EVENT_PACKET);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[..2].concat(), event);
        assert!(packets[2].is_empty());
        assert_eq!(hci.ready_at(EVENTS), None);
        let mut buffer = [0; EVENT_PACKET];
        assert_eq!(
            hci.packet(EVENTS, Token::In, &mut buffer).unwrap(),
            Reply::Nak
        );
    }

    #[test]
    fn acl_data_moves_both_ways_in_usb_packets() {
        let mut hci = controller();
        let mut outbound = vec![1, 0, 0, 2];
        outbound.resize(ACL_HEADER + 512, 7);
        let (first, rest) = outbound.split_at(512);
        hci.packet(ACL_OUT, Token::Out, &mut first.to_vec())
            .unwrap();
        assert_eq!(hci.take(), None, "the header says more follows");
        hci.packet(ACL_OUT, Token::Out, &mut rest.to_vec()).unwrap();
        assert_eq!(hci.take(), Some(Outbound::Acl(outbound.clone())));
        hci.deliver_acl(&outbound);
        assert_eq!(read(&mut hci, ACL_IN, 512).concat(), outbound);
        // Longer than the transport carries: discarded, not truncated.
        hci.packet(ACL_OUT, Token::Out, &mut [1, 0, 0xff, 0xff])
            .unwrap();
        assert_eq!(hci.take(), None);
        assert_eq!(hci.counters().malformed, 1);
    }

    #[test]
    fn a_full_queue_pushes_back_and_a_reset_empties_them() {
        let mut hci = controller();
        for _ in 0..QUEUE_PACKETS {
            hci.deliver_event(&[0x0e, 0]);
        }
        assert!(!hci.has_room());
        hci.deliver_event(&[0x0e, 0]);
        assert_eq!(hci.counters().overflowed, 1);
        for _ in 0..QUEUE_PACKETS {
            hci.packet(ACL_OUT, Token::Out, &mut [1, 0, 0, 0]).unwrap();
        }
        assert_eq!(
            hci.packet(ACL_OUT, Token::Out, &mut [1, 0, 0, 0]).unwrap(),
            Reply::Nak
        );
        hci.reset().unwrap();
        assert!(hci.has_room());
        assert!(!hci.up());
        assert_eq!(hci.take(), None);
        hci.deliver_event(&[0x0e, 0]);
        assert_eq!(hci.ready_at(EVENTS), None, "unconfigured, it takes nothing");
    }

    #[test]
    fn the_model_answers_through_the_same_pipes() {
        let mut hci = controller();
        // Queued before the owner chose the model: the model takes it.
        command(&mut hci, &[0x03, 0x0c, 0]).unwrap();
        hci.use_model([1, 2, 3, 4, 5, 0x02]);
        assert!(hci.modeled());
        assert_eq!(hci.take(), None, "nothing reaches a host controller");
        assert_eq!(
            read(&mut hci, EVENTS, EVENT_PACKET),
            [vec![COMMAND_COMPLETE, 4, 1, 0x03, 0x0c, 0]]
        );
        // Read BD_ADDR.
        command(&mut hci, &[0x09, 0x10, 0]).unwrap();
        assert_eq!(
            read(&mut hci, EVENTS, EVENT_PACKET).concat(),
            [COMMAND_COMPLETE, 10, 1, 0x09, 0x10, 0, 1, 2, 3, 4, 5, 0x02]
        );
        // A vendor command is unknown to the model, and reported once.
        command(&mut hci, &[0x01, 0xfc, 1, 9]).unwrap();
        command(&mut hci, &[0x01, 0xfc, 1, 9]).unwrap();
        assert_eq!(read(&mut hci, EVENTS, EVENT_PACKET)[0][5], UNKNOWN_COMMAND);
        assert_eq!(read(&mut hci, EVENTS, EVENT_PACKET)[0][5], UNKNOWN_COMMAND);
        assert_eq!(hci.take_unknown(), [0xfc01]);
        assert_eq!(hci.counters().vendor_refused, 2);
        assert_eq!(hci.counters().unknown, 2);
        // ACL data gets its buffer back.
        hci.packet(ACL_OUT, Token::Out, &mut [1, 0, 1, 0, 7])
            .unwrap();
        assert_eq!(
            read(&mut hci, EVENTS, EVENT_PACKET),
            [vec![0x13, 5, 1, 1, 0, 1, 0]]
        );
        assert_eq!(hci.counters().acl_discarded, 1);
    }

    #[test]
    fn a_procedure_ends_when_the_system_count_reaches_it() {
        let mut hci = controller();
        hci.use_model([1, 2, 3, 4, 5, 0x02]);
        hci.set_time(100);
        // Inquiry for 1.28 s.
        command(&mut hci, &[0x01, 0x04, 5, 0x33, 0x8b, 0x9e, 1, 0]).unwrap();
        assert_eq!(read(&mut hci, EVENTS, EVENT_PACKET)[0][0], 0x0f);
        let end = 100 + crate::counter::FREQUENCY_HZ * 128 / 100;
        assert_eq!(hci.ready_at(EVENTS), Some(end));
        hci.set_time(end - 1);
        assert_eq!(hci.ready_at(EVENTS), Some(end));
        hci.set_time(end);
        assert_eq!(hci.ready_at(EVENTS), Some(0));
        assert_eq!(read(&mut hci, EVENTS, EVENT_PACKET), [vec![0x01, 1, 0]]);
        assert_eq!(hci.ready_at(EVENTS), None);
    }

    #[test]
    fn a_halted_endpoint_stalls_until_cleared() {
        let mut hci = controller();
        let halt = setup(0x02, SET_FEATURE, ENDPOINT_HALT, u16::from(ACL_IN), 0);
        transfer(&mut hci, halt, &[]).unwrap();
        let mut buffer = [0; 512];
        assert_eq!(
            hci.packet(ACL_IN, Token::In, &mut buffer).unwrap(),
            Reply::Stall
        );
        let clear = setup(0x02, CLEAR_FEATURE, ENDPOINT_HALT, u16::from(ACL_IN), 0);
        transfer(&mut hci, clear, &[]).unwrap();
        assert_eq!(
            hci.packet(ACL_IN, Token::In, &mut buffer).unwrap(),
            Reply::Nak
        );
    }
}
