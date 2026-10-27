// SPDX-License-Identifier: GPL-2.0-only
//! Source HBM1.0, whole-message credits and HostIF framing, with finite bounds.
use super::{Error, ReportKind, ReportLayout, Result, descriptor};
use alloc::{collections::VecDeque, vec::Vec};

pub(super) const MTU: usize = 124;
pub(super) const MAX_MESSAGE: usize = 16_384;
const MAX_FRAMES: usize = 256;
const MAX_INPUTS: usize = 64;
pub(super) const HID_GUID: [u8; 16] = [
    0x58, 0xcd, 0xae, 0x33, 0x79, 0xb6, 0x54, 0x4e, 0x9b, 0xd9, 0xa0, 0x4d, 0x34, 0xf0, 0xc2, 0x26,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampSupport {
    /// Firmware timestamps remain opaque firmware-domain data. No UTC/host
    /// synchronization message is sent without an actual native UTC service.
    FirmwareClockSynchronizationUnsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientProperties {
    pub address: u8,
    pub guid: [u8; 16],
    pub protocol_version: u8,
    pub max_connections: u8,
    pub fixed_address: u8,
    pub single_receive_buffer: u8,
    pub max_message_length: u32,
    pub dma_header: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirmwareIdentity {
    pub pci_revision: u8,
    pub observed_status: u32,
    /// Actual response's firmware maximum HBM minor/major bytes.
    pub hbm_firmware_max: [u8; 2],
    pub hid_client: ClientProperties,
    pub timestamps: TimestampSupport,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Device {
    pub id: u8,
    pub class: u8,
    pub product: u16,
    pub vendor: u16,
    pub hid_descriptor: Vec<u8>,
    pub report_descriptor: Vec<u8>,
    pub reports: Vec<ReportLayout>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputReport {
    pub hostif_command: u8,
    pub device_id: u8,
    pub bytes: Vec<u8>,
    pub flags: u8,
    /// Source does not define total_size inclusion semantics. Retain the
    /// observed value; actual outer/count/entry bounds control every access.
    pub aggregate_total_size: Option<u16>,
    pub aggregate_flags: Option<u8>,
    pub timestamps: TimestampSupport,
}
#[derive(Clone)]
pub(super) struct Frame {
    pub protocol: u8,
    pub management: u8,
    pub bytes: Vec<u8>,
}
/// Shared production client-message fragment encoder (no hardware authority).
pub(super) fn fragment_message(fw: u8, host: u8, bytes: &[u8]) -> Result<Vec<Frame>> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return Err(Error::Protocol("bounded nonempty client message"));
    }
    let count = bytes.len().div_ceil(MTU);
    Ok(bytes
        .chunks(MTU)
        .enumerate()
        .map(|(index, part)| {
            let word = u32::from(fw)
                | (u32::from(host) << 8)
                | ((part.len() as u32) << 16)
                | (u32::from(index + 1 == count) << 31);
            let mut body = word.to_le_bytes().to_vec();
            body.extend_from_slice(part);
            Frame {
                protocol: 1,
                management: 0,
                bytes: body,
            }
        })
        .collect())
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Idle,
    Start,
    Enum,
    Properties,
    Connect,
    Connected,
}
#[derive(Clone, Copy)]
struct Expected {
    command: u8,
    device: u8,
    report_id: Option<u8>,
}

pub(super) struct Engine {
    stage: Stage,
    addresses: Vec<u8>,
    property_index: usize,
    properties: Vec<ClientProperties>,
    pub client: Option<ClientProperties>,
    pub fw_max: [u8; 2],
    pub frames: VecDeque<Frame>,
    tx_message: Option<Vec<u8>>,
    tx_credit: bool,
    rx_credit: bool,
    rx_grant_pending: bool,
    tx_fragments_pending: usize,
    assembly: Vec<u8>,
    expected: Option<Expected>,
    pub response: Option<Vec<u8>>,
    pub devices: Vec<Device>,
    pub hid_ready: bool,
    pub inputs: VecDeque<InputReport>,
    disconnect_sent: bool,
    pub disconnected: bool,
    stop_sent: bool,
    pub stopped: bool,
}
impl Engine {
    pub fn new() -> Self {
        Self {
            stage: Stage::Idle,
            addresses: Vec::new(),
            property_index: 0,
            properties: Vec::new(),
            client: None,
            fw_max: [0; 2],
            frames: VecDeque::new(),
            tx_message: None,
            tx_credit: false,
            rx_credit: false,
            rx_grant_pending: false,
            tx_fragments_pending: 0,
            assembly: Vec::new(),
            expected: None,
            response: None,
            devices: Vec::new(),
            hid_ready: false,
            inputs: VecDeque::new(),
            disconnect_sent: false,
            disconnected: false,
            stop_sent: false,
            stopped: false,
        }
    }
    pub fn invalidate(&mut self) {
        // An old report/credit/descriptor cannot survive even a same-ID reset.
        *self = Self::new();
    }
    pub fn connected(&self) -> bool {
        self.stage == Stage::Connected && !self.disconnected
    }
    fn queue(&mut self, frame: Frame) -> Result<()> {
        if frame.bytes.len() > 128 || self.frames.len() >= MAX_FRAMES {
            return Err(Error::Protocol("bounded IPC transmit queue"));
        }
        self.frames.push_back(frame);
        Ok(())
    }
    pub fn management(&mut self, command: u8, bytes: &[u8]) -> Result<()> {
        self.queue(Frame {
            protocol: 3,
            management: command,
            bytes: bytes.to_vec(),
        })
    }
    fn message(&mut self, fw: u8, host: u8, bytes: &[u8], complete: bool) -> Result<()> {
        if bytes.len() > MTU {
            return Err(Error::Protocol("ISHTP fragment length"));
        }
        let word = u32::from(fw)
            | (u32::from(host) << 8)
            | ((bytes.len() as u32) << 16)
            | (u32::from(complete) << 31);
        let mut body = word.to_le_bytes().to_vec();
        body.extend_from_slice(bytes);
        self.queue(Frame {
            protocol: 1,
            management: 0,
            bytes: body,
        })
    }
    fn hbm(&mut self, bytes: &[u8]) -> Result<()> {
        self.message(0, 0, bytes, true)
    }
    pub fn start(&mut self) -> Result<()> {
        if self.stage != Stage::Idle {
            return Err(Error::Protocol("one HBM startup per epoch"));
        }
        self.stage = Stage::Start;
        self.hbm(&[1, 0, 0, 1])
    }
    fn next_property(&mut self) -> Result<()> {
        if self.property_index < self.addresses.len() {
            return self.hbm(&[5, self.addresses[self.property_index], 0, 0]);
        }
        let mut matching = self.properties.iter().filter(|p| p.guid == HID_GUID);
        let p = matching
            .next()
            .ok_or(Error::Requirement("actual HID client GUID not enumerated"))?
            .clone();
        if matching.next().is_some() {
            return Err(Error::Protocol("ambiguous HID client GUID"));
        }
        if p.protocol_version != 1
            || p.max_connections == 0
            || p.fixed_address != 0
            || p.single_receive_buffer != 0
            || p.max_message_length < 16
            || p.max_message_length as usize > MAX_MESSAGE
        {
            return Err(Error::Requirement("bounded ordinary HID client properties"));
        }
        self.client = Some(p);
        self.stage = Stage::Connect;
        self.hbm(&[6, self.client.as_ref().unwrap().address, 1, 0])
    }
    pub fn receive(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() < 4 || bytes.len() > 128 {
            return Err(Error::Protocol("ISHTP envelope length"));
        }
        let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let fw = word as u8;
        let host = (word >> 8) as u8;
        let n = ((word >> 16) & 0x1ff) as usize;
        if word & 0x7e00_0000 != 0 || n > MTU || n + 4 != bytes.len() || n == 0 {
            return Err(Error::Protocol("ISHTP reserved or length bits"));
        }
        let complete = word >> 31 != 0;
        let payload = &bytes[4..];
        if fw == 0 && host == 0 {
            if !complete {
                return Err(Error::Requirement("fragmented HBM unsupported"));
            }
            return self.receive_hbm(payload);
        }
        let client = self
            .client
            .as_ref()
            .ok_or(Error::Protocol("client before real enumeration"))?;
        if !self.connected() || fw != client.address || host != 1 || !self.rx_credit {
            return Err(Error::Protocol("uncredited or wrong client fragment"));
        }
        let bound = client.max_message_length as usize;
        if self
            .assembly
            .len()
            .checked_add(n)
            .is_none_or(|end| end > bound)
        {
            return Err(Error::Protocol("client reassembly overflow"));
        }
        self.assembly.extend_from_slice(payload);
        if complete {
            self.rx_credit = false;
            let message = core::mem::take(&mut self.assembly);
            self.hostif(&message)?;
            self.replenish()?;
        }
        Ok(())
    }
    fn receive_hbm(&mut self, b: &[u8]) -> Result<()> {
        let command = *b.first().ok_or(Error::Protocol("empty HBM"))?;
        match command {
            0x81 if self.stage == Stage::Start => {
                if b.len() != 4 || b[1] != 1 {
                    return Err(Error::Requirement(
                        "HBM1.0 resident firmware without loader capability",
                    ));
                }
                self.fw_max = [b[2], b[3]];
                self.stage = Stage::Enum;
                self.hbm(&[4, 0, 0, 0])
            }
            0x84 if self.stage == Stage::Enum => {
                if b.len() != 36 || b[1..4] != [0, 0, 0] || b[4] & 1 != 0 {
                    return Err(Error::Protocol("HBM enumeration bitmap"));
                }
                self.addresses = (1u16..256)
                    .filter(|a| b[4 + usize::from(*a) / 8] & (1 << (*a % 8)) != 0)
                    .map(|a| a as u8)
                    .collect();
                if self.addresses.is_empty() {
                    return Err(Error::Requirement("no enumerated firmware clients"));
                }
                self.stage = Stage::Properties;
                self.next_property()
            }
            0x85 if self.stage == Stage::Properties => {
                if b.len() != 32
                    || b[1] != self.addresses[self.property_index]
                    || b[2] != 0
                    || b[3] != 0
                {
                    return Err(Error::Protocol(
                        "HBM properties response correlation/status",
                    ));
                }
                let p = ClientProperties {
                    address: b[1],
                    guid: b[4..20].try_into().unwrap(),
                    protocol_version: b[20],
                    max_connections: b[21],
                    fixed_address: b[22],
                    single_receive_buffer: b[23],
                    max_message_length: u32::from_le_bytes(b[24..28].try_into().unwrap()),
                    dma_header: b[28],
                };
                if p.guid == HID_GUID && b[29..32] != [0, 0, 0] {
                    return Err(Error::Requirement("unknown HID client property extension"));
                }
                self.properties.push(p);
                self.property_index += 1;
                self.next_property()
            }
            0x86 if self.stage == Stage::Connect => {
                self.client_response(b)?;
                self.stage = Stage::Connected;
                self.replenish()
            }
            8 if self.connected() => {
                if b.len() != 8
                    || b[1] != self.client.as_ref().unwrap().address
                    || b[2] != 1
                    || b[3..] != [0; 5]
                    || self.tx_credit
                    || self.tx_fragments_pending != 0
                {
                    return Err(Error::Protocol("duplicate or wrong HBM credit"));
                }
                self.tx_credit = true;
                self.prepare_tx()
            }
            0x87 if self.disconnect_sent => {
                self.client_response(b)?;
                self.disconnected = true;
                self.rx_credit = false;
                Ok(())
            }
            0x82 if self.stop_sent => {
                if b != [0x82, 0, 0, 0] {
                    return Err(Error::Protocol("HBM stop response"));
                }
                self.stopped = true;
                Ok(())
            }
            0x11 | 0x91 | 0x12 | 0x92 => Err(Error::Requirement(
                "unsolicited DMA on mailbox-only client transport",
            )),
            _ => Err(Error::Protocol("unexpected HBM command/state")),
        }
    }
    fn client_response(&self, b: &[u8]) -> Result<()> {
        if b.len() != 4 || b[1] != self.client.as_ref().unwrap().address || b[2] != 1 {
            return Err(Error::Protocol("HBM client response address"));
        }
        if b[3] != 0 {
            return Err(Error::Status(b[3]));
        }
        Ok(())
    }
    pub fn replenish(&mut self) -> Result<()> {
        if self.connected()
            && !self.rx_credit
            && !self.rx_grant_pending
            && self.assembly.is_empty()
            && self.inputs.len() <= MAX_INPUTS - 32
            && !self.disconnect_sent
        {
            self.hbm(&[8, self.client.as_ref().unwrap().address, 1, 0, 0, 0, 0, 0])?;
            self.rx_grant_pending = true;
        }
        Ok(())
    }
    pub fn request_ready(&self) -> Result<()> {
        if !self.connected()
            || self.expected.is_some()
            || self.response.is_some()
            || self.tx_message.is_some()
            || self.inputs.len() > MAX_INPUTS - 32
            || self.disconnect_sent
        {
            return Err(Error::Requirement(
                "idle connected HID request with bounded receive capacity",
            ));
        }
        Ok(())
    }
    pub fn request(
        &mut self,
        command: u8,
        device: u8,
        report_id: Option<u8>,
        payload: &[u8],
    ) -> Result<()> {
        self.request_ready()?;
        let max = self.client.as_ref().unwrap().max_message_length as usize;
        let extra = usize::from(report_id.is_some());
        let size = payload.len() + extra;
        if size + 6 > max {
            return Err(Error::Protocol(
                "HostIF request exceeds actual client maximum",
            ));
        }
        let mut bytes = vec![command, device, 0, 0];
        bytes.extend_from_slice(&[0, 0]); // Original HostIF request size remains zero.
        if let Some(id) = report_id {
            bytes.push(id);
        }
        bytes.extend_from_slice(payload);
        self.expected = Some(Expected {
            command: command | 0x80,
            device,
            report_id,
        });
        self.tx_message = Some(bytes);
        self.prepare_tx()
    }
    fn prepare_tx(&mut self) -> Result<()> {
        if self.tx_credit
            && let Some(message) = self.tx_message.take()
        {
            let needed = message.len().div_ceil(MTU);
            if self.frames.len() + needed > MAX_FRAMES {
                return Err(Error::Protocol("whole-message transmit queue capacity"));
            }
            self.tx_credit = false;
            self.tx_fragments_pending = needed;
            let fw = self.client.as_ref().unwrap().address;
            for frame in fragment_message(fw, 1, &message)? {
                self.queue(frame)?;
            }
        }
        Ok(())
    }
    fn hostif(&mut self, b: &[u8]) -> Result<()> {
        let initial_inputs = self.inputs.len();
        let mut at = 0;
        while at < b.len() {
            let h = b
                .get(at..at + 6)
                .ok_or(Error::Protocol("truncated HostIF header"))?;
            let size = usize::from(u16::from_le_bytes([h[4], h[5]]));
            let end = at
                .checked_add(6 + size)
                .filter(|end| *end <= b.len())
                .ok_or(Error::Protocol("HostIF payload length"))?;
            let payload = &b[at + 6..end];
            if h[2] != 0 {
                return Err(Error::Status(h[2]));
            }
            match h[0] {
                command if command & 0x7f == 5 && self.hid_ready => {
                    self.input(command, h[1], h[3], payload, None, None)?
                }
                command if command & 0x7f == 6 && self.hid_ready => self.aggregate(payload)?,
                response if response & 0x80 != 0 => {
                    let e = self
                        .expected
                        .ok_or(Error::Protocol("uncorrelated HostIF response"))?;
                    if e.command != response
                        || e.device != h[1]
                        || h[3] != 0
                        || self.response.is_some()
                    {
                        return Err(Error::Protocol("HostIF response correlation"));
                    }
                    if matches!(response & 0x7f, 2 | 4) {
                        let kind = if response & 0x7f == 2 {
                            ReportKind::Feature
                        } else {
                            ReportKind::Input
                        };
                        let d = self.device(h[1])?;
                        let id = descriptor::validate(&d.reports, kind, payload)?;
                        if e.report_id != Some(id) {
                            return Err(Error::Protocol("HostIF requested report ID mismatch"));
                        }
                    }
                    self.response = Some(payload.to_vec());
                    self.expected = None;
                }
                _ => return Err(Error::Requirement("unsupported HostIF command/state")),
            }
            if self.inputs.len() - initial_inputs > 32 {
                return Err(Error::Requirement(
                    "at most32 input reports per complete client message",
                ));
            }
            at = end;
        }
        if at == 0 {
            return Err(Error::Protocol("empty HostIF message"));
        }
        Ok(())
    }
    fn device(&self, id: u8) -> Result<&Device> {
        self.devices
            .iter()
            .find(|d| d.id == id)
            .ok_or(Error::Protocol("unknown actual HID device ID"))
    }
    fn input(
        &mut self,
        command: u8,
        id: u8,
        flags: u8,
        b: &[u8],
        total: Option<u16>,
        aggregate_flags: Option<u8>,
    ) -> Result<()> {
        descriptor::validate(&self.device(id)?.reports, ReportKind::Input, b)?;
        if self.inputs.len() >= MAX_INPUTS {
            return Err(Error::Protocol("bounded HID input queue"));
        }
        self.inputs.push_back(InputReport {
            hostif_command: command,
            device_id: id,
            bytes: b.to_vec(),
            flags,
            aggregate_total_size: total,
            aggregate_flags,
            timestamps: TimestampSupport::FirmwareClockSynchronizationUnsupported,
        });
        Ok(())
    }
    fn aggregate(&mut self, b: &[u8]) -> Result<()> {
        if b.len() < 4 || b[2] == 0 || b[2] > 32 {
            return Err(Error::Protocol("bounded aggregated report header"));
        }
        let total = u16::from_le_bytes([b[0], b[1]]);
        let flags = b[3];
        let mut at = 4;
        for _ in 0..b[2] {
            let n = b
                .get(at..at + 2)
                .ok_or(Error::Protocol("truncated aggregate report size"))?;
            let size = usize::from(u16::from_le_bytes([n[0], n[1]]));
            if size < 6 {
                return Err(Error::Protocol(
                    "aggregate report smaller than HostIF header",
                ));
            }
            let end = at
                .checked_add(2 + size)
                .filter(|end| *end <= b.len())
                .ok_or(Error::Protocol("aggregate report bounds"))?;
            let h = &b[at + 2..at + 8];
            let payload = &b[at + 8..end];
            if h[0] & 0x7f != 5
                || h[2] != 0
                || usize::from(u16::from_le_bytes([h[4], h[5]])) != payload.len()
            {
                return Err(Error::Protocol("aggregate nested HostIF consistency"));
            }
            self.input(h[0], h[1], h[3], payload, Some(total), Some(flags))?;
            at = end;
        }
        if at != b.len() {
            return Err(Error::Protocol("aggregate trailing bytes/count mismatch"));
        }
        Ok(())
    }
    /// Called only after the actual native doorbell store and posted read.
    pub fn published(&mut self, frame: &Frame) -> Result<()> {
        if frame.protocol == 1 && frame.bytes.len() >= 4 {
            let h = u32::from_le_bytes(frame.bytes[..4].try_into().unwrap());
            if h & 0xffff == 0 && frame.bytes.get(4) == Some(&8) {
                if !self.rx_grant_pending || self.rx_credit {
                    return Err(Error::Protocol("RX credit publication state"));
                }
                self.rx_grant_pending = false;
                self.rx_credit = true;
            } else if h & 0xff00 == 0x100 {
                self.tx_fragments_pending = self
                    .tx_fragments_pending
                    .checked_sub(1)
                    .ok_or(Error::Protocol("TX publication state"))?;
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn credit_available(&self) -> bool {
        self.tx_credit
    }
    pub fn take_response(&mut self) -> Option<Vec<u8>> {
        self.response.take()
    }
    pub fn enumerate_devices(&mut self, b: &[u8]) -> Result<()> {
        let count = usize::from(
            *b.first()
                .ok_or(Error::Protocol("missing HID device count"))?,
        );
        if count == 0 || count > 32 || b.len() != 1 + 9 * count {
            return Err(Error::Protocol("HID device enumeration size/count"));
        }
        let mut devices = Vec::new();
        for p in b[1..].as_chunks::<9>().0 {
            let id = u32::from_le_bytes(p[..4].try_into().unwrap());
            let id = u8::try_from(id)
                .map_err(|_| Error::Requirement("HostIF cannot address 32-bit HID device ID"))?;
            if devices.iter().any(|d: &Device| d.id == id) {
                return Err(Error::Protocol("duplicate HID device ID"));
            }
            devices.push(Device {
                id,
                class: p[4],
                product: u16::from_le_bytes([p[5], p[6]]),
                vendor: u16::from_le_bytes([p[7], p[8]]),
                hid_descriptor: Vec::new(),
                report_descriptor: Vec::new(),
                reports: Vec::new(),
            });
        }
        self.devices = devices;
        Ok(())
    }
    pub fn disconnect(&mut self) -> Result<()> {
        if !self.connected() {
            self.disconnected = true;
            return Ok(());
        }
        self.disconnect_sent = true;
        self.tx_message = None;
        self.expected = None;
        self.response = None;
        self.hbm(&[7, self.client.as_ref().unwrap().address, 1, 0])
    }
    pub fn host_stop(&mut self) -> Result<()> {
        self.stop_sent = true;
        self.hbm(&[2, 0, 0, 0])
    }
}
