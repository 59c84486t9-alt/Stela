//! A Bluetooth controller with no radio, behind the USB HCI function when the
//! host lends no controller of its own.
//!
//! Evidence: Bluetooth Core v5.4 Vol 4 Part E (HCI commands and events), Vol
//! 1 Part F (error codes) and Vol 2 Part C 3.3 (LMP feature bits). The
//! controller claims Core 5.0 for BR/EDR and LE and implements every command
//! its Supported Commands bitmap lists; it lists nothing else. Its radio finds
//! nothing in range, which is what the state machine says: an Inquiry ends
//! with no results after its length, a page or remote name request ends with
//! Page Timeout after the page timeout, an LE scan reports nothing, an LE
//! connection never completes until cancelled, and high duty cycle directed
//! advertising ends with Advertising Timeout. Every other opcode, vendor ones
//! among them, is answered Unknown HCI Command and recorded once for the
//! owner to report: that is the documented degraded response of a controller
//! without a radio, never a pretence of one.
//!
//! macOS bluetoothd (26A J473, `.stela/review/hci/NOTES.md`) sends a command
//! only when its Supported Commands bit is set (command table 0x100b9def8,
//! gate 0x10019618c), so the bitmap below decides what it asks.
//!
//! The controller never has a connection, so ACL data from the host names no
//! connection: it is discarded, counted, and its buffer returned with
//! Number Of Completed Packets, which keeps the host's flow control whole.
use crate::counter::FREQUENCY_HZ;
use alloc::{boxed::Box, vec, vec::Vec};
use stela_crypto::{Sha256, digest::Digest};

// Events (Vol 4 Part E 7.7).
const INQUIRY_COMPLETE: u8 = 0x01;
const CONNECTION_COMPLETE: u8 = 0x03;
const REMOTE_NAME_REQUEST_COMPLETE: u8 = 0x07;
const COMMAND_COMPLETE: u8 = 0x0e;
const COMMAND_STATUS: u8 = 0x0f;
const NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;
const LE_META: u8 = 0x3e;
const LE_CONNECTION_COMPLETE: u8 = 0x01;

// Error codes (Vol 1 Part F 1.3).
const SUCCESS: u8 = 0x00;
pub const UNKNOWN_COMMAND: u8 = 0x01;
const UNKNOWN_CONNECTION: u8 = 0x02;
const PAGE_TIMEOUT: u8 = 0x04;
const MEMORY_CAPACITY_EXCEEDED: u8 = 0x07;
const COMMAND_DISALLOWED: u8 = 0x0c;
const UNSUPPORTED_VALUE: u8 = 0x11;
const INVALID_PARAMETERS: u8 = 0x12;
const ADVERTISING_TIMEOUT: u8 = 0x3c;

/// System counts in one baseband slot, 625 us.
const SLOT: u64 = FREQUENCY_HZ * 625 / 1_000_000;
/// An Inquiry_Length unit, 1.28 s.
const INQUIRY_UNIT: u64 = 2048 * SLOT;
/// High duty cycle directed advertising lasts 1.28 s (Vol 6 Part B 4.4.2.4.3).
const DIRECTED_ADVERTISING: u64 = 2048 * SLOT;

/// Read Local Version Information: Core 5.0 for HCI and LMP. Company
/// identifier 0xFFFF names no company (Assigned Numbers 7.1): the model is
/// no vendor's firmware.
pub const HCI_VERSION: u8 = 0x09;
pub const LMP_VERSION: u8 = 0x09;
pub const COMPANY: u16 = 0xffff;
/// ACL buffers: the HCI maximum payload, and how many.
pub const ACL_LENGTH: u16 = 1021;
pub const ACL_BUFFERS: u16 = 8;
pub const LE_ACL_LENGTH: u16 = 251;
pub const LE_ACL_BUFFERS: u8 = 8;
pub const ACCEPT_LIST_SIZE: usize = 16;
/// LE states (Vol 4 Part E 7.8.27): advertising of every legacy kind,
/// scanning and initiating, alone and together (bits 0-17); none that needs
/// a connection.
const LE_STATES: u64 = 0x3_ffff;
/// LMP features page 0 (Vol 2 Part C 3.3): RSSI with inquiry results (30),
/// LE supported (38), extended inquiry response (48), simultaneous LE and
/// BR/EDR (49), secure simple pairing (51), erroneous data reporting (53),
/// extended features (63): those whose commands the model implements.
const LMP_FEATURES: u64 = 1 << 30 | 1 << 38 | 1 << 48 | 1 << 49 | 1 << 51 | 1 << 53 | 1 << 63;
const MAX_FEATURE_PAGE: u8 = 1;
const DEFAULT_EVENT_MASK: u64 = 0x0000_1fff_ffff_ffff;
const DEFAULT_LE_EVENT_MASK: u64 = 0x1f;
// Event mask bits.
const MASK_INQUIRY_COMPLETE: u64 = 1 << 0;
const MASK_CONNECTION_COMPLETE: u64 = 1 << 2;
const MASK_REMOTE_NAME: u64 = 1 << 6;
const MASK_LE_META: u64 = 1 << 61;
const LE_MASK_CONNECTION_COMPLETE: u64 = 1 << 0;

/// What a command returns: a Command Complete with these return parameters
/// after the status, or a Command Status.
#[derive(Clone, Copy)]
enum Returns {
    Complete(usize),
    Status,
    /// Host Number Of Completed Packets: an event only on error.
    Silent,
}

/// One implemented command: its Supported Commands octet and bit (Vol 4
/// Part E 6.27), its parameter length (`None`: variable) and what it returns.
struct Command {
    opcode: u16,
    octet: u8,
    bit: u8,
    parameters: Option<usize>,
    returns: Returns,
}

const fn command(opcode: u16, octet: u8, bit: u8, parameters: usize, returns: Returns) -> Command {
    Command {
        opcode,
        octet,
        bit,
        parameters: Some(parameters),
        returns,
    }
}

use Returns::{Complete, Status};

/// Every command the model implements. The octets and bits match bluetoothd's
/// own table entry for each opcode.
const COMMANDS: &[Command] = &[
    // Link control.
    command(0x0401, 0, 0, 5, Status),      // Inquiry
    command(0x0402, 0, 1, 0, Complete(0)), // Inquiry Cancel
    command(0x0405, 0, 4, 13, Status),     // Create Connection
    command(0x0406, 0, 5, 3, Status),      // Disconnect
    command(0x0408, 0, 7, 6, Complete(6)), // Create Connection Cancel
    command(0x0419, 2, 3, 10, Status),     // Remote Name Request
    command(0x041a, 2, 4, 6, Complete(6)), // Remote Name Request Cancel
    // Link policy.
    command(0x080e, 5, 3, 0, Complete(2)), // Read Default Link Policy Settings
    command(0x080f, 5, 4, 2, Complete(0)), // Write Default Link Policy Settings
    // Controller and baseband.
    command(0x0c01, 5, 6, 8, Complete(0)),   // Set Event Mask
    command(0x0c03, 5, 7, 0, Complete(0)),   // Reset
    command(0x0c13, 7, 0, 248, Complete(0)), // Write Local Name
    command(0x0c14, 7, 1, 0, Complete(248)), // Read Local Name
    command(0x0c15, 7, 2, 0, Complete(2)),   // Read Connection Accept Timeout
    command(0x0c16, 7, 3, 2, Complete(0)),   // Write Connection Accept Timeout
    command(0x0c17, 7, 4, 0, Complete(2)),   // Read Page Timeout
    command(0x0c18, 7, 5, 2, Complete(0)),   // Write Page Timeout
    command(0x0c19, 7, 6, 0, Complete(1)),   // Read Scan Enable
    command(0x0c1a, 7, 7, 1, Complete(0)),   // Write Scan Enable
    command(0x0c1b, 8, 0, 0, Complete(4)),   // Read Page Scan Activity
    command(0x0c1c, 8, 1, 4, Complete(0)),   // Write Page Scan Activity
    command(0x0c1d, 8, 2, 0, Complete(4)),   // Read Inquiry Scan Activity
    command(0x0c1e, 8, 3, 4, Complete(0)),   // Write Inquiry Scan Activity
    command(0x0c1f, 8, 4, 0, Complete(1)),   // Read Authentication Enable
    command(0x0c20, 8, 5, 1, Complete(0)),   // Write Authentication Enable
    command(0x0c23, 9, 0, 0, Complete(3)),   // Read Class Of Device
    command(0x0c24, 9, 1, 3, Complete(0)),   // Write Class Of Device
    command(0x0c25, 9, 2, 0, Complete(2)),   // Read Voice Setting
    command(0x0c26, 9, 3, 2, Complete(0)),   // Write Voice Setting
    command(0x0c31, 10, 5, 1, Complete(0)),  // Set Controller To Host Flow Control
    command(0x0c33, 10, 6, 7, Complete(0)),  // Host Buffer Size
    Command {
        opcode: 0x0c35, // Host Number Of Completed Packets
        octet: 10,
        bit: 7,
        parameters: None,
        returns: Returns::Silent,
    },
    command(0x0c42, 12, 4, 0, Complete(1)), // Read Inquiry Scan Type
    command(0x0c43, 12, 5, 1, Complete(0)), // Write Inquiry Scan Type
    command(0x0c44, 12, 6, 0, Complete(1)), // Read Inquiry Mode
    command(0x0c45, 12, 7, 1, Complete(0)), // Write Inquiry Mode
    command(0x0c46, 13, 0, 0, Complete(1)), // Read Page Scan Type
    command(0x0c47, 13, 1, 1, Complete(0)), // Write Page Scan Type
    command(0x0c51, 17, 0, 0, Complete(241)), // Read Extended Inquiry Response
    command(0x0c52, 17, 1, 241, Complete(0)), // Write Extended Inquiry Response
    command(0x0c55, 17, 5, 0, Complete(1)), // Read Simple Pairing Mode
    command(0x0c56, 17, 6, 1, Complete(0)), // Write Simple Pairing Mode
    command(0x0c58, 18, 0, 0, Complete(1)), // Read Inquiry Response Transmit Power Level
    command(0x0c5a, 18, 2, 0, Complete(1)), // Read Default Erroneous Data Reporting
    command(0x0c5b, 18, 3, 1, Complete(0)), // Write Default Erroneous Data Reporting
    command(0x0c63, 22, 2, 8, Complete(0)), // Set Event Mask Page 2
    command(0x0c6c, 24, 5, 0, Complete(2)), // Read LE Host Support
    command(0x0c6d, 24, 6, 2, Complete(0)), // Write LE Host Support
    // Informational.
    command(0x1001, 14, 3, 0, Complete(8)), // Read Local Version Information
    command(0x1002, 14, 4, 0, Complete(64)), // Read Local Supported Commands
    command(0x1003, 14, 5, 0, Complete(8)), // Read Local Supported Features
    command(0x1004, 14, 6, 1, Complete(10)), // Read Local Extended Features
    command(0x1005, 14, 7, 0, Complete(7)), // Read Buffer Size
    command(0x1009, 15, 1, 0, Complete(6)), // Read BD_ADDR
    // LE.
    command(0x2001, 25, 0, 8, Complete(0)), // LE Set Event Mask
    command(0x2002, 25, 1, 0, Complete(3)), // LE Read Buffer Size
    command(0x2003, 25, 2, 0, Complete(8)), // LE Read Local Supported Features
    command(0x2005, 25, 4, 6, Complete(0)), // LE Set Random Address
    command(0x2006, 25, 5, 15, Complete(0)), // LE Set Advertising Parameters
    command(0x2007, 25, 6, 0, Complete(1)), // LE Read Advertising Physical Channel Tx Power
    command(0x2008, 25, 7, 32, Complete(0)), // LE Set Advertising Data
    command(0x2009, 26, 0, 32, Complete(0)), // LE Set Scan Response Data
    command(0x200a, 26, 1, 1, Complete(0)), // LE Set Advertising Enable
    command(0x200b, 26, 2, 7, Complete(0)), // LE Set Scan Parameters
    command(0x200c, 26, 3, 2, Complete(0)), // LE Set Scan Enable
    command(0x200d, 26, 4, 25, Status),     // LE Create Connection
    command(0x200e, 26, 5, 0, Complete(0)), // LE Create Connection Cancel
    command(0x200f, 26, 6, 0, Complete(1)), // LE Read Filter Accept List Size
    command(0x2010, 26, 7, 0, Complete(0)), // LE Clear Filter Accept List
    command(0x2011, 27, 0, 7, Complete(0)), // LE Add Device To Filter Accept List
    command(0x2012, 27, 1, 7, Complete(0)), // LE Remove Device From Filter Accept List
    command(0x201c, 28, 3, 0, Complete(8)), // LE Read Supported States
];

/// Whether the model implements `opcode`.
pub fn implements(opcode: u16) -> bool {
    COMMANDS.iter().any(|c| c.opcode == opcode)
}

/// The Supported Commands bitmap: exactly [`COMMANDS`].
pub fn supported_commands() -> [u8; 64] {
    let mut bitmap = [0; 64];
    for command in COMMANDS {
        bitmap[usize::from(command.octet)] |= 1 << command.bit;
    }
    bitmap
}

/// A stable BD_ADDR for the board whose ECID is `ecid`: SHA-256 of a label
/// and the ECID, as a locally administered unicast address (IEEE 802 bits 0
/// and 1 of its most significant octet), so it can be no company's assigned
/// address. HCI order: the LAP's low octet first.
pub fn address(ecid: u64) -> [u8; 6] {
    let mut hash = Sha256::new();
    hash.update(b"Stela Bluetooth BD_ADDR");
    hash.update(ecid.to_le_bytes());
    let digest = hash.finalize();
    let mut address: [u8; 6] = digest[..6]
        .try_into()
        .expect("a SHA-256 digest has 6 bytes");
    address[5] = (address[5] & !0x01) | 0x02;
    // The LAPs 0x9E8B00-0x9E8B3F are inquiry access codes (Vol 2 Part B
    // 1.2), never a device's.
    if address[2] == 0x9e && address[1] == 0x8b && address[0] < 0x40 {
        address[0] |= 0x40;
    }
    address
}

fn u16_at(p: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([p[at], p[at + 1]])
}

fn bd_addr(p: &[u8], at: usize) -> [u8; 6] {
    p[at..at + 6].try_into().expect("a six-byte address")
}

fn event(code: u8, parameters: &[u8]) -> Vec<u8> {
    let mut packet = vec![code, parameters.len() as u8];
    packet.extend_from_slice(parameters);
    packet
}

/// Legacy advertising parameters (Vol 4 Part E 7.8.5).
#[derive(Debug, Clone, Copy, Default)]
struct Advertising {
    kind: u8,
    own_type: u8,
    peer_type: u8,
    peer: [u8; 6],
    filter_policy: u8,
}

/// An LE connection being initiated: it never completes.
#[derive(Debug, Clone, Copy)]
struct Initiating {
    filter_policy: u8,
    peer_type: u8,
    peer: [u8; 6],
}

/// The controller's state from power-on or Reset.
#[derive(Debug, Clone)]
struct Settings {
    event_mask: u64,
    le_event_mask: u64,
    link_policy: u16,
    local_name: [u8; 248],
    accept_timeout: u16,
    page_timeout: u16,
    scan_enable: u8,
    page_scan: [u8; 4],
    inquiry_scan: [u8; 4],
    authentication: u8,
    class: [u8; 3],
    voice: u16,
    inquiry_scan_type: u8,
    inquiry_mode: u8,
    page_scan_type: u8,
    eir: [u8; 241],
    simple_pairing: u8,
    erroneous_data: u8,
    le_host: u8,
    random_address: Option<[u8; 6]>,
    advertising: Advertising,
    advertising_data: [u8; 32],
    scan_response: [u8; 32],
    advertising_until: Option<Option<u64>>,
    scan_kind: u8,
    scan_own_type: u8,
    scan_filter_policy: u8,
    scanning: Option<u8>,
    accept_list: Vec<(u8, [u8; 6])>,
    /// When the running Inquiry ends.
    inquiry: Option<u64>,
    /// When the page to this address times out.
    page: Option<(u64, [u8; 6])>,
    name_request: Option<(u64, [u8; 6])>,
    initiating: Option<Initiating>,
}

impl Settings {
    fn new() -> Self {
        let interval = |interval: u16, window: u16| {
            let [a, b] = interval.to_le_bytes();
            let [c, d] = window.to_le_bytes();
            [a, b, c, d]
        };
        Self {
            event_mask: DEFAULT_EVENT_MASK,
            le_event_mask: DEFAULT_LE_EVENT_MASK,
            link_policy: 0,
            local_name: [0; 248],
            accept_timeout: 0x1f40,
            page_timeout: 0x2000,
            scan_enable: 0,
            page_scan: interval(0x0800, 0x0012),
            inquiry_scan: interval(0x1000, 0x0012),
            authentication: 0,
            class: [0; 3],
            voice: 0x0060,
            inquiry_scan_type: 0,
            inquiry_mode: 0,
            page_scan_type: 0,
            eir: [0; 241],
            simple_pairing: 0,
            erroneous_data: 0,
            le_host: 0,
            random_address: None,
            // ADV_IND with no filter: the defaults' kind.
            advertising: Advertising::default(),
            advertising_data: [0; 32],
            scan_response: [0; 32],
            advertising_until: None,
            scan_kind: 0,
            scan_own_type: 0,
            scan_filter_policy: 0,
            scanning: None,
            accept_list: Vec::new(),
            inquiry: None,
            page: None,
            name_request: None,
            initiating: None,
        }
    }

    /// Whether the filter accept list is in use (Vol 4 Part E 7.8.15).
    fn accept_list_in_use(&self) -> bool {
        (self.advertising_until.is_some() && self.advertising.filter_policy != 0)
            || (self.scanning.is_some() && self.scan_filter_policy == 1)
            || self.initiating.is_some_and(|i| i.filter_policy == 1)
    }

    fn random_address_missing(&self, own_type: u8) -> bool {
        own_type == 1 && self.random_address.is_none()
    }
}

/// The procedures a radio would carry out now: advertising (with its data
/// and scan response), LE scanning (kind and duplicate filter), BR/EDR scan
/// enable, inquiry, paging and initiating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Air {
    pub advertising: Option<([u8; 32], [u8; 32])>,
    pub scanning: Option<(u8, u8)>,
    pub scan_enable: u8,
    pub inquiring: bool,
    pub paging: bool,
    pub initiating: bool,
}

/// The controller.
#[derive(Debug, Clone)]
pub struct Model {
    address: [u8; 6],
    settings: Box<Settings>,
    /// Every unknown opcode seen, and those the owner has not taken.
    unknown: Vec<u16>,
    fresh: Vec<u16>,
    /// ACL packets that named no connection.
    pub discarded_acl: u64,
}

/// What one command answers at once, before any later event.
enum Answer {
    Complete(Vec<u8>),
    Status(u8),
    None,
}

impl Model {
    pub fn new(address: [u8; 6]) -> Self {
        Self {
            address,
            settings: Box::new(Settings::new()),
            unknown: Vec::new(),
            fresh: Vec::new(),
            discarded_acl: 0,
        }
    }

    pub fn address(&self) -> [u8; 6] {
        self.address
    }

    /// What the controller would put on the air if it had a radio.
    pub fn air(&self) -> Air {
        let s = &self.settings;
        Air {
            advertising: s
                .advertising_until
                .map(|_| (s.advertising_data, s.scan_response)),
            scanning: s.scanning.map(|duplicates| (s.scan_kind, duplicates)),
            scan_enable: s.scan_enable,
            inquiring: s.inquiry.is_some(),
            paging: s.page.is_some() || s.name_request.is_some(),
            initiating: s.initiating.is_some(),
        }
    }

    /// Power-on state; pending procedures end without events.
    pub fn reset(&mut self) {
        *self.settings = Settings::new();
    }

    /// Unknown opcodes not yet taken, each once per power of the board.
    pub fn take_unknown(&mut self) -> Vec<u16> {
        core::mem::take(&mut self.fresh)
    }

    /// The earliest system count at which a procedure ends.
    pub fn deadline(&self) -> Option<u64> {
        let s = &self.settings;
        [
            s.inquiry,
            s.page.map(|(at, _)| at),
            s.name_request.map(|(at, _)| at),
            s.advertising_until.flatten(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The events of procedures that ended by `now`.
    pub fn advance(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut events = Vec::new();
        let due = |at: Option<u64>| at.is_some_and(|at| at <= now);
        if due(self.settings.inquiry) {
            self.settings.inquiry = None;
            self.masked(
                &mut events,
                MASK_INQUIRY_COMPLETE,
                INQUIRY_COMPLETE,
                &[SUCCESS],
            );
        }
        if let Some((at, peer)) = self.settings.page
            && at <= now
        {
            self.settings.page = None;
            self.connection_complete(&mut events, PAGE_TIMEOUT, peer);
        }
        if let Some((at, peer)) = self.settings.name_request
            && at <= now
        {
            self.settings.name_request = None;
            self.name_complete(&mut events, PAGE_TIMEOUT, peer);
        }
        if due(self.settings.advertising_until.flatten()) {
            self.settings.advertising_until = None;
            let advertising = self.settings.advertising;
            self.le_connection_complete(
                &mut events,
                ADVERTISING_TIMEOUT,
                advertising.peer_type,
                advertising.peer,
            );
        }
        events
    }

    /// ACL data from the host: no connection takes it.
    pub fn acl(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        self.discarded_acl += 1;
        let handle = u16::from_le_bytes([packet[0], packet[1]]) & 0x0fff;
        // Handles above 0x0EFF are reserved: no buffer was taken.
        if handle > 0x0eff {
            return Vec::new();
        }
        let [low, high] = handle.to_le_bytes();
        vec![event(NUMBER_OF_COMPLETED_PACKETS, &[1, low, high, 1, 0])]
    }

    /// One command packet, header included, whose length its header
    /// already matches. Its events, in order.
    pub fn command(&mut self, packet: &[u8], now: u64) -> Vec<Vec<u8>> {
        let opcode = u16::from_le_bytes([packet[0], packet[1]]);
        let p = &packet[3..];
        let [low, high] = opcode.to_le_bytes();
        let mut later = Vec::new();
        let answer = match COMMANDS.iter().find(|c| c.opcode == opcode) {
            None => {
                if !self.unknown.contains(&opcode) {
                    self.unknown.push(opcode);
                    self.fresh.push(opcode);
                }
                Answer::Complete(vec![UNKNOWN_COMMAND])
            }
            Some(command) => {
                let length_ok = match command.parameters {
                    Some(length) => p.len() == length,
                    None => p
                        .first()
                        .is_some_and(|&n| p.len() == 1 + 4 * usize::from(n)),
                };
                let answer = if length_ok {
                    self.execute(opcode, p, now, &mut later)
                } else {
                    match command.returns {
                        Returns::Status => Answer::Status(INVALID_PARAMETERS),
                        _ => Answer::Complete(vec![INVALID_PARAMETERS]),
                    }
                };
                // An error's return parameters keep their length.
                match (answer, command.returns) {
                    (Answer::Complete(mut r), Returns::Complete(n)) => {
                        r.resize(1 + n, 0);
                        Answer::Complete(r)
                    }
                    (answer, _) => answer,
                }
            }
        };
        let mut events = Vec::with_capacity(1 + later.len());
        match answer {
            Answer::Complete(returns) => {
                let mut parameters = vec![1, low, high];
                parameters.extend_from_slice(&returns);
                events.push(event(COMMAND_COMPLETE, &parameters));
            }
            Answer::Status(status) => {
                events.push(event(COMMAND_STATUS, &[status, 1, low, high]));
            }
            Answer::None => {}
        }
        events.extend(later);
        events
    }

    fn masked(&self, events: &mut Vec<Vec<u8>>, bit: u64, code: u8, parameters: &[u8]) {
        if self.settings.event_mask & bit != 0 {
            events.push(event(code, parameters));
        }
    }

    fn connection_complete(&self, events: &mut Vec<Vec<u8>>, status: u8, peer: [u8; 6]) {
        let mut p = vec![status, 0, 0];
        p.extend_from_slice(&peer);
        // ACL link, no encryption.
        p.extend_from_slice(&[0x01, 0x00]);
        self.masked(events, MASK_CONNECTION_COMPLETE, CONNECTION_COMPLETE, &p);
    }

    fn name_complete(&self, events: &mut Vec<Vec<u8>>, status: u8, peer: [u8; 6]) {
        let mut p = vec![status];
        p.extend_from_slice(&peer);
        p.resize(1 + 6 + 248, 0);
        self.masked(events, MASK_REMOTE_NAME, REMOTE_NAME_REQUEST_COMPLETE, &p);
    }

    fn le_connection_complete(
        &self,
        events: &mut Vec<Vec<u8>>,
        status: u8,
        peer_type: u8,
        peer: [u8; 6],
    ) {
        let s = &self.settings;
        if s.event_mask & MASK_LE_META == 0 || s.le_event_mask & LE_MASK_CONNECTION_COMPLETE == 0 {
            return;
        }
        let mut p = vec![LE_CONNECTION_COMPLETE, status, 0, 0, 0, peer_type];
        p.extend_from_slice(&peer);
        // Interval, latency, supervision timeout, clock accuracy: unused.
        p.extend_from_slice(&[0; 7]);
        events.push(event(LE_META, &p));
    }

    fn execute(&mut self, opcode: u16, p: &[u8], now: u64, later: &mut Vec<Vec<u8>>) -> Answer {
        let ok = |returns: &[u8]| {
            let mut r = vec![SUCCESS];
            r.extend_from_slice(returns);
            Answer::Complete(r)
        };
        let fail = |status: u8| Answer::Complete(vec![status]);
        let byte = |limit: u8, store: &mut u8| {
            if p[0] > limit {
                fail(INVALID_PARAMETERS)
            } else {
                *store = p[0];
                ok(&[])
            }
        };
        let s = &mut *self.settings;
        match opcode {
            // Inquiry (7.1.1).
            0x0401 => {
                let lap = u32::from_le_bytes([p[0], p[1], p[2], 0]);
                if !(0x9e8b00..=0x9e8b3f).contains(&lap) || !(0x01..=0x30).contains(&p[3]) {
                    return Answer::Status(INVALID_PARAMETERS);
                }
                if s.inquiry.is_some() {
                    return Answer::Status(COMMAND_DISALLOWED);
                }
                s.inquiry = Some(now + u64::from(p[3]) * INQUIRY_UNIT);
                Answer::Status(SUCCESS)
            }
            // Inquiry Cancel: no Inquiry Complete follows.
            0x0402 => {
                s.inquiry = None;
                ok(&[])
            }
            // Create Connection: pages until the page timeout.
            0x0405 => {
                if s.page.is_some() {
                    return Answer::Status(COMMAND_DISALLOWED);
                }
                s.page = Some((now + u64::from(s.page_timeout) * SLOT, bd_addr(p, 0)));
                Answer::Status(SUCCESS)
            }
            // Disconnect: there is no connection.
            0x0406 => Answer::Status(UNKNOWN_CONNECTION),
            // Create Connection Cancel (7.1.7).
            0x0408 => {
                let peer = bd_addr(p, 0);
                match s.page {
                    Some((_, paging)) if paging == peer => {
                        s.page = None;
                        self.connection_complete(later, UNKNOWN_CONNECTION, peer);
                        ok(&peer)
                    }
                    _ => {
                        let mut r = vec![UNKNOWN_CONNECTION];
                        r.extend_from_slice(&peer);
                        Answer::Complete(r)
                    }
                }
            }
            // Remote Name Request: pages until the page timeout.
            0x0419 => {
                if s.name_request.is_some() {
                    return Answer::Status(COMMAND_DISALLOWED);
                }
                s.name_request = Some((now + u64::from(s.page_timeout) * SLOT, bd_addr(p, 0)));
                Answer::Status(SUCCESS)
            }
            0x041a => {
                let peer = bd_addr(p, 0);
                match s.name_request {
                    Some((_, asked)) if asked == peer => {
                        s.name_request = None;
                        self.name_complete(later, UNKNOWN_CONNECTION, peer);
                        ok(&peer)
                    }
                    _ => {
                        let mut r = vec![UNKNOWN_CONNECTION];
                        r.extend_from_slice(&peer);
                        Answer::Complete(r)
                    }
                }
            }
            0x080e => ok(&s.link_policy.to_le_bytes()),
            0x080f => {
                // Role switch, hold and sniff; park is gone.
                let policy = u16_at(p, 0);
                if policy > 0x0007 {
                    return fail(INVALID_PARAMETERS);
                }
                s.link_policy = policy;
                ok(&[])
            }
            0x0c01 => {
                s.event_mask = u64::from_le_bytes(p.try_into().expect("8 bytes"));
                ok(&[])
            }
            0x0c03 => {
                self.reset();
                ok(&[])
            }
            0x0c13 => {
                s.local_name.copy_from_slice(p);
                ok(&[])
            }
            0x0c14 => ok(&s.local_name),
            0x0c15 => ok(&s.accept_timeout.to_le_bytes()),
            0x0c16 => match u16_at(p, 0) {
                value @ 0x0001..=0xb540 => {
                    s.accept_timeout = value;
                    ok(&[])
                }
                _ => fail(INVALID_PARAMETERS),
            },
            0x0c17 => ok(&s.page_timeout.to_le_bytes()),
            0x0c18 => match u16_at(p, 0) {
                0 => fail(INVALID_PARAMETERS),
                value => {
                    s.page_timeout = value;
                    ok(&[])
                }
            },
            0x0c19 => ok(&[s.scan_enable]),
            0x0c1a => byte(3, &mut s.scan_enable),
            0x0c1b => ok(&s.page_scan),
            0x0c1c => scan_activity(p, &mut s.page_scan),
            0x0c1d => ok(&s.inquiry_scan),
            0x0c1e => scan_activity(p, &mut s.inquiry_scan),
            0x0c1f => ok(&[s.authentication]),
            0x0c20 => byte(1, &mut s.authentication),
            0x0c23 => ok(&s.class),
            0x0c24 => {
                s.class.copy_from_slice(p);
                ok(&[])
            }
            0x0c25 => ok(&s.voice.to_le_bytes()),
            0x0c26 => match u16_at(p, 0) {
                value @ 0..=0x03ff => {
                    s.voice = value;
                    ok(&[])
                }
                _ => fail(INVALID_PARAMETERS),
            },
            // The model sends the host no ACL data, so the host's buffers
            // and flow control have nothing to govern.
            0x0c31 => byte(3, &mut 0),
            0x0c33 => ok(&[]),
            // Host Number Of Completed Packets: the controller sent no data,
            // so there is nothing to credit; no event on success.
            0x0c35 => Answer::None,
            0x0c42 => ok(&[s.inquiry_scan_type]),
            0x0c43 => byte(1, &mut s.inquiry_scan_type),
            0x0c44 => ok(&[s.inquiry_mode]),
            0x0c45 => byte(2, &mut s.inquiry_mode),
            0x0c46 => ok(&[s.page_scan_type]),
            0x0c47 => byte(1, &mut s.page_scan_type),
            0x0c51 => ok(&s.eir),
            0x0c52 => {
                if p[0] > 1 {
                    return fail(INVALID_PARAMETERS);
                }
                s.eir.copy_from_slice(p);
                ok(&[])
            }
            0x0c55 => ok(&[s.simple_pairing]),
            0x0c56 => byte(1, &mut s.simple_pairing),
            // Transmit power: 0 dBm, a value; nothing is transmitted.
            0x0c58 => ok(&[0]),
            0x0c5a => ok(&[s.erroneous_data]),
            0x0c5b => byte(1, &mut s.erroneous_data),
            // Page 2 masks no event the model generates.
            0x0c63 => ok(&[]),
            0x0c6c => ok(&[s.le_host, 0]),
            // The second octet is unused since Core 4.1.
            0x0c6d => byte(1, &mut s.le_host),
            0x1001 => {
                let mut r = vec![HCI_VERSION, 0, 0, LMP_VERSION];
                r.extend_from_slice(&COMPANY.to_le_bytes());
                r.extend_from_slice(&[0, 0]);
                ok(&r)
            }
            0x1002 => ok(&supported_commands()),
            0x1003 => ok(&LMP_FEATURES.to_le_bytes()),
            0x1004 => {
                let features = match p[0] {
                    0 => LMP_FEATURES,
                    // Host features: SSP and LE as the host wrote them.
                    1 => u64::from(s.simple_pairing) | u64::from(s.le_host) << 1,
                    _ => return fail(INVALID_PARAMETERS),
                };
                let mut r = vec![p[0], MAX_FEATURE_PAGE];
                r.extend_from_slice(&features.to_le_bytes());
                ok(&r)
            }
            0x1005 => {
                // No synchronous buffers: SCO is not transported.
                let mut r = ACL_LENGTH.to_le_bytes().to_vec();
                r.push(0);
                r.extend_from_slice(&ACL_BUFFERS.to_le_bytes());
                r.extend_from_slice(&0u16.to_le_bytes());
                ok(&r)
            }
            0x1009 => ok(&self.address),
            0x2001 => {
                s.le_event_mask = u64::from_le_bytes(p.try_into().expect("8 bytes"));
                ok(&[])
            }
            0x2002 => {
                let [a, b] = LE_ACL_LENGTH.to_le_bytes();
                ok(&[a, b, LE_ACL_BUFFERS])
            }
            // No optional LE features.
            0x2003 => ok(&[0; 8]),
            0x2005 => {
                if s.advertising_until.is_some() || s.scanning.is_some() || s.initiating.is_some() {
                    return fail(COMMAND_DISALLOWED);
                }
                s.random_address = Some(bd_addr(p, 0));
                ok(&[])
            }
            0x2006 => {
                if s.advertising_until.is_some() {
                    return fail(COMMAND_DISALLOWED);
                }
                let (minimum, maximum) = (u16_at(p, 0), u16_at(p, 2));
                let kind = p[4];
                let directed_high = kind == 1;
                let intervals_ok = directed_high
                    || ((0x0020..=0x4000).contains(&minimum)
                        && (0x0020..=0x4000).contains(&maximum)
                        && minimum <= maximum);
                if kind > 4
                    || !intervals_ok
                    || p[6] > 1
                    || p[13] & 0x07 == 0
                    || p[13] > 0x07
                    || p[14] > 3
                    || p[5] > 3
                {
                    return fail(INVALID_PARAMETERS);
                }
                // Generated private addresses need LL privacy, which the
                // model does not claim.
                if p[5] > 1 {
                    return fail(UNSUPPORTED_VALUE);
                }
                s.advertising = Advertising {
                    kind,
                    own_type: p[5],
                    peer_type: p[6],
                    peer: bd_addr(p, 7),
                    filter_policy: p[14],
                };
                ok(&[])
            }
            0x2007 => ok(&[0]),
            0x2008 | 0x2009 => {
                if p[0] > 31 {
                    return fail(INVALID_PARAMETERS);
                }
                let store = if opcode == 0x2008 {
                    &mut s.advertising_data
                } else {
                    &mut s.scan_response
                };
                store.copy_from_slice(p);
                ok(&[])
            }
            0x200a => match p[0] {
                0 => {
                    s.advertising_until = None;
                    ok(&[])
                }
                1 => {
                    if s.random_address_missing(s.advertising.own_type) {
                        return fail(INVALID_PARAMETERS);
                    }
                    if s.advertising_until.is_none() {
                        s.advertising_until =
                            Some((s.advertising.kind == 1).then_some(now + DIRECTED_ADVERTISING));
                    }
                    ok(&[])
                }
                _ => fail(INVALID_PARAMETERS),
            },
            0x200b => {
                if s.scanning.is_some() {
                    return fail(COMMAND_DISALLOWED);
                }
                let (interval, window) = (u16_at(p, 1), u16_at(p, 3));
                if p[0] > 1
                    || !(0x0004..=0x4000).contains(&interval)
                    || !(0x0004..=0x4000).contains(&window)
                    || window > interval
                    || p[5] > 3
                    || p[6] > 3
                {
                    return fail(INVALID_PARAMETERS);
                }
                // Private address generation and extended filter policies
                // are optional features the model does not claim.
                if p[5] > 1 || p[6] > 1 {
                    return fail(UNSUPPORTED_VALUE);
                }
                (s.scan_kind, s.scan_own_type, s.scan_filter_policy) = (p[0], p[5], p[6]);
                ok(&[])
            }
            0x200c => match (p[0], p[1]) {
                (0, 0..=1) => {
                    s.scanning = None;
                    ok(&[])
                }
                (1, duplicates @ 0..=1) => {
                    if s.random_address_missing(s.scan_own_type) {
                        return fail(INVALID_PARAMETERS);
                    }
                    s.scanning = Some(duplicates);
                    ok(&[])
                }
                _ => fail(INVALID_PARAMETERS),
            },
            // LE Create Connection: initiates until cancelled.
            0x200d => {
                if s.initiating.is_some() {
                    return Answer::Status(COMMAND_DISALLOWED);
                }
                let (scan_interval, scan_window) = (u16_at(p, 0), u16_at(p, 2));
                let (minimum, maximum) = (u16_at(p, 13), u16_at(p, 15));
                let (latency, timeout) = (u16_at(p, 17), u16_at(p, 19));
                if !(0x0004..=0x4000).contains(&scan_interval)
                    || !(0x0004..=0x4000).contains(&scan_window)
                    || scan_window > scan_interval
                    || p[4] > 1
                    || p[5] > 3
                    || p[12] > 3
                    || !(0x0006..=0x0c80).contains(&minimum)
                    || !(0x0006..=0x0c80).contains(&maximum)
                    || minimum > maximum
                    || latency > 0x01f3
                    || !(0x000a..=0x0c80).contains(&timeout)
                {
                    return Answer::Status(INVALID_PARAMETERS);
                }
                if p[5] > 1 || p[12] > 1 {
                    return Answer::Status(UNSUPPORTED_VALUE);
                }
                if s.random_address_missing(p[12]) {
                    return Answer::Status(INVALID_PARAMETERS);
                }
                s.initiating = Some(Initiating {
                    filter_policy: p[4],
                    peer_type: p[5],
                    peer: bd_addr(p, 6),
                });
                Answer::Status(SUCCESS)
            }
            // LE Create Connection Cancel (7.8.13).
            0x200e => match s.initiating.take() {
                Some(initiating) => {
                    self.le_connection_complete(
                        later,
                        UNKNOWN_CONNECTION,
                        initiating.peer_type,
                        initiating.peer,
                    );
                    ok(&[])
                }
                None => fail(COMMAND_DISALLOWED),
            },
            0x200f => ok(&[ACCEPT_LIST_SIZE as u8]),
            0x2010 => {
                if s.accept_list_in_use() {
                    return fail(COMMAND_DISALLOWED);
                }
                s.accept_list.clear();
                ok(&[])
            }
            0x2011 | 0x2012 => {
                if s.accept_list_in_use() {
                    return fail(COMMAND_DISALLOWED);
                }
                if p[0] > 1 {
                    return fail(INVALID_PARAMETERS);
                }
                let entry = (p[0], bd_addr(p, 1));
                let present = s.accept_list.contains(&entry);
                if opcode == 0x2012 {
                    s.accept_list.retain(|e| *e != entry);
                } else if !present {
                    if s.accept_list.len() >= ACCEPT_LIST_SIZE {
                        return fail(MEMORY_CAPACITY_EXCEEDED);
                    }
                    s.accept_list.push(entry);
                }
                ok(&[])
            }
            0x201c => ok(&LE_STATES.to_le_bytes()),
            _ => unreachable!("every listed command has a case"),
        }
    }
}

/// Write Page or Inquiry Scan Activity (7.3.20, 7.3.22).
fn scan_activity(p: &[u8], store: &mut [u8; 4]) -> Answer {
    let (interval, window) = (u16_at(p, 0), u16_at(p, 2));
    if !(0x0012..=0x1000).contains(&interval)
        || interval % 2 != 0
        || !(0x0011..=0x1000).contains(&window)
        || window > interval
    {
        return Answer::Complete(vec![INVALID_PARAMETERS]);
    }
    store.copy_from_slice(p);
    Answer::Complete(vec![SUCCESS])
}

#[cfg(test)]
mod tests;
