//! AFKEPV2 interface messages, independent of the service carried above them.
//!
//! Original AP `AFKEPInterfaceV2::handleMessage` (VA 0xfffffe00094c0f68)
//! and firmware 0x30044 agree on the 16-byte message header. Category 0 is
//! a report, 1 a command and 2 its response. The command's separate eight
//! bytes carry its sequence and reply budget; neither the transport sequence
//! nor the user context is that command sequence.
use super::super::rpc::Bus;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

const REPORT: u8 = 0;
const COMMAND: u8 = 1;
const RESPONSE: u8 = 2;
const PUBLISH: u8 = 0x11;
const OPEN: u8 = 0x12;
const CLOSE: u8 = 0x13;
const TERMINATE: u8 = 0x14;
const OFFLINE: i32 = 0xe000_02d7u32 as i32;
const OVERRUN: i32 = 0xe000_02e1u32 as i32;

/// A complete logical command, after AFKEPV2 framing and command-buffer DMA.
/// An error is a missing model effect; an i32 is an original wire status.
/// A refused handle/completion must leave its service effect uncommitted.
pub(crate) trait Service {
    fn handle(&mut self, packet_type: u8, payload: &[u8]) -> Result<(i32, Vec<u8>), &'static str>;

    /// Interface close/termination, distinct from kept CPU sleep.
    fn transport_closed(&mut self);

    fn pending(&self) -> bool {
        false
    }

    fn take_command(&mut self) -> Option<CommandRequest> {
        None
    }

    fn complete(
        &mut self,
        _cookie: u64,
        _status: i32,
        _payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        Err("DCP AFKEPV2 service has no local command completion owner")
    }
}

/// A service-owned local request. Cookie belongs solely to its completion
/// owner; the wire uses its independently allocated eight-bit sequence.
pub(crate) struct CommandRequest {
    pub cookie: u64,
    pub packet_type: u8,
    pub payload: Vec<u8>,
    pub reply_bytes: u32,
}

/// Publication is admitted only with a real service implementing its effects.
pub(crate) struct Descriptor {
    pub number: u16,
    pub name: String,
    /// A complete OSUnserialize document, including its terminator.
    pub properties: Vec<u8>,
}

#[derive(Default)]
struct Assembly {
    total: u32,
    bytes: Vec<u8>,
}

impl Assembly {
    fn push(&mut self, total: u32, payload: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        let length = usize::try_from(total).map_err(|_| "DCP AFKEPV2 message length overflow")?;
        if payload.len() > length {
            return Err("DCP AFKEPV2 fragment exceeds its logical message length");
        }
        // Both originals replace an unfinished assembly when a whole message
        // arrives, or when the declared total changes (AP 0x94c1110..11a0).
        if payload.len() == length {
            self.bytes.clear();
            self.total = 0;
            return Ok(Some(payload.to_vec()));
        }
        if self.total != total {
            self.bytes.clear();
            self.total = total;
        }
        if self.bytes.len() + payload.len() > length {
            return Err("DCP AFKEPV2 fragments exceed their logical message length");
        }
        self.bytes
            .try_reserve(payload.len())
            .map_err(|_| "DCP AFKEPV2 assembly allocation failed")?;
        self.bytes.extend_from_slice(payload);
        if self.bytes.len() == length {
            self.total = 0;
            Ok(Some(core::mem::take(&mut self.bytes)))
        } else {
            Ok(None)
        }
    }
}

struct Interface {
    descriptor: Descriptor,
    service: Box<dyn Service>,
    peer_open: bool,
    terminated: bool,
    next_sequence: u8,
    staged: Option<CommandRequest>,
    commands: BTreeMap<u8, u64>,
}

struct Received {
    number: u16,
    total: u32,
    fragment: Vec<u8>,
    packet: Vec<u8>,
}

/// Each interface owns its assembly; fragments from other interfaces may
/// interleave. Original receivers ignore outer sequence/flags, using the
/// repeated total length to reassemble (AP 0x94c34bc and 0x94c10d8).
#[derive(Default)]
pub(super) struct Interfaces {
    services: BTreeMap<u16, Interface>,
    assemblies: BTreeMap<u16, Assembly>,
    received: Option<Received>,
    next_service: u16,
}

impl Interfaces {
    pub fn register(
        &mut self,
        descriptor: Descriptor,
        service: Box<dyn Service>,
    ) -> Result<(), &'static str> {
        if descriptor.number == 0 || descriptor.name.contains('\0') {
            return Err("DCP AFKEPV2 publication has an invalid interface or name");
        }
        if self.services.contains_key(&descriptor.number) {
            return Err("DCP AFKEPV2 interface number is already registered");
        }
        self.services.insert(
            descriptor.number,
            Interface {
                descriptor,
                service,
                peer_open: false,
                terminated: false,
                next_sequence: 0,
                staged: None,
                commands: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub fn publications(&mut self) -> Vec<(u16, Vec<u8>)> {
        let mut reports = Vec::new();
        for (&number, interface) in &mut self.services {
            interface.terminated = false;
            interface.peer_open = false;
            let mut payload = alloc::vec![0; 32];
            // Original35f6c calls strlcpy32 (1e034):31 bytes plus NUL.
            // The complete interface-name remains in the property dictionary.
            let name = interface.descriptor.name.as_bytes();
            let count = name.len().min(31);
            payload[..count].copy_from_slice(&name[..count]);
            payload.extend_from_slice(&interface.descriptor.properties);
            reports.push((number, report(PUBLISH, &payload)));
        }
        reports
    }

    pub fn reset(&mut self) -> Result<(), &'static str> {
        // Cancellation is progress, not a rollback transaction: completed
        // callbacks stay removed if a later owner refuses. Close no session
        // until all cancellations succeed, so retry cannot close it twice.
        for interface in self.services.values_mut() {
            interface.cancel_commands()?;
        }
        self.assemblies.clear();
        self.received = None;
        for interface in self.services.values_mut() {
            interface.peer_open = false;
            interface.terminated = false;
            interface.service.transport_closed();
            interface.next_sequence = 0;
        }
        self.next_service = 0;
        Ok(())
    }

    pub fn idle(&self) -> bool {
        self.assemblies
            .values()
            .all(|assembly| assembly.bytes.is_empty())
    }

    pub fn quiescent(&self) -> bool {
        self.services
            .values()
            .all(|interface| interface.commands.is_empty() && interface.staged.is_none())
    }

    pub fn pending(&self) -> bool {
        self.services.values().any(|interface| {
            !interface.terminated
                && interface.commands.len() < 256
                && (interface.staged.is_some() || interface.service.pending())
        })
    }

    /// Publish one owned request at a time. No later producer can fail after
    /// an earlier publication was removed from its service. A round-robin
    /// cursor prevents a continuously active interface starving the others.
    pub fn commands(&mut self) -> Result<Vec<(u16, Vec<u8>)>, &'static str> {
        let candidate = self
            .services
            .range(self.next_service..)
            .chain(self.services.range(..self.next_service))
            .find(|(_, interface)| {
                !interface.terminated
                    && interface.commands.len() < 256
                    && (interface.staged.is_some() || interface.service.pending())
            })
            .map(|(&number, _)| number);
        let Some(number) = candidate else {
            return Ok(Vec::new());
        };
        let interface = self.services.get_mut(&number).expect("selected service");
        if interface.staged.is_none() {
            interface.staged = interface.service.take_command();
        }
        let Some(request) = &interface.staged else {
            return Ok(Vec::new());
        };
        // The repeated AFKEPV2 total includes its 24 message/command bytes.
        // Keep the producer-owned request on every validation refusal.
        request
            .payload
            .len()
            .checked_add(24)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or("DCP AFKEPV2 local command length overflow")?;
        let sequence = (0..=255)
            .map(|offset| interface.next_sequence.wrapping_add(offset))
            .find(|sequence| !interface.commands.contains_key(sequence))
            .expect("unoccupied command sequence");
        let mut packet = alloc::vec![0; 24];
        packet[8] = request.packet_type;
        packet[9] = COMMAND;
        packet[17] = sequence;
        packet[20..24].copy_from_slice(&request.reply_bytes.to_le_bytes());
        packet.extend_from_slice(&request.payload);
        interface.commands.insert(sequence, request.cookie);
        interface.staged = None;
        interface.next_sequence = sequence.wrapping_add(1);
        self.next_service = number.wrapping_add(1);
        Ok(alloc::vec![(number, packet)])
    }

    pub fn receive(
        &mut self,
        number: u16,
        total: u32,
        fragment: &[u8],
        bus: &mut dyn Bus,
        window: Option<u64>,
    ) -> Result<Option<Response>, &'static str> {
        if !self.received.as_ref().is_some_and(|received| {
            received.number == number && received.total == total && received.fragment == fragment
        }) {
            let Some(packet) = self
                .assemblies
                .entry(number)
                .or_default()
                .push(total, fragment)?
            else {
                return Ok(None);
            };
            self.received = Some(Received {
                number,
                total,
                fragment: fragment.to_vec(),
                packet,
            });
        }
        let received = self.received.as_ref().expect("complete packet");
        let result = Self::dispatch(&mut self.services, number, &received.packet, bus, window);
        if result.is_ok() {
            self.received = None;
        }
        result
    }

    fn dispatch(
        services: &mut BTreeMap<u16, Interface>,
        number: u16,
        packet: &[u8],
        bus: &mut dyn Bus,
        window: Option<u64>,
    ) -> Result<Option<Response>, &'static str> {
        let header: &[u8; 16] = packet
            .get(..16)
            .ok_or("DCP AFKEPV2 interface header is truncated")?
            .try_into()
            .expect("header");
        let packet_type = header[8];
        let interface = services.get_mut(&number);
        match header[9] {
            REPORT => {
                if packet_type == PUBLISH {
                    // Original unknown-interface publication creates an
                    // importer (AP94aca68). This native peer has no client
                    // owner for an AP-published service; do not drop its
                    // creation effect through the unmatched-report path.
                    return Err("DCP AFKEPV2 peer service publication has no importer owner");
                }
                let Some(interface) = interface else {
                    return Ok(None);
                };
                match packet_type {
                    OPEN if header[10] & 1 != 0 => {
                        if interface.terminated {
                            return Err("DCP AFKEPV2 open after interface termination");
                        }
                        interface.peer_open = true;
                    }
                    CLOSE if header[10] & 1 != 0 => {
                        interface.cancel_commands()?;
                        interface.peer_open = false;
                        interface.service.transport_closed();
                    }
                    TERMINATE => {
                        interface.cancel_commands()?;
                        interface.peer_open = false;
                        interface.terminated = true;
                        interface.service.transport_closed();
                    }
                    _ => return Err("DCP AFKEPV2 unmodeled interface report"),
                }
                Ok(None)
            }
            COMMAND => {
                let command = packet
                    .get(16..24)
                    .ok_or("DCP AFKEPV2 command header is truncated")?;
                let Some(interface) = interface.filter(|interface| !interface.terminated) else {
                    // Original handleUnknown (AP 0x94c2570) does not map
                    // unowned DMA buffers. Only the command sequence returns.
                    let mut response = alloc::vec![0; 24];
                    response[8] = packet_type;
                    response[9] = RESPONSE;
                    response[17] = command[1];
                    response[20..24].copy_from_slice(&OFFLINE.to_le_bytes());
                    return Ok(Some(Response {
                        bytes: response,
                        dma: None,
                    }));
                };
                let command = Command::decode(&packet[16..], bus, window)?;
                let (status, payload) = interface.service.handle(packet_type, &command.payload)?;
                Ok(Some(command.response(header, status, payload, window)))
            }
            RESPONSE => {
                if packet.len() < 24 {
                    return Err("DCP AFKEPV2 response header is truncated");
                }
                // Original 0x94c0628 removes the pending command by sequence;
                // unmatched responses at 0x94c069c never invoke a client.
                let Some(interface) = interface else {
                    return Ok(None);
                };
                let sequence = packet[17];
                let Some(&cookie) = interface.commands.get(&sequence) else {
                    return Ok(None);
                };
                if packet[16] & 1 != 0 {
                    return Err("DCP AFKEPV2 response supplies unrequested DMA buffers");
                }
                let status = i32::from_le_bytes(packet[20..24].try_into().expect("status"));
                interface
                    .service
                    .complete(cookie, status, packet[24..].to_vec())?;
                interface.commands.remove(&sequence);
                Ok(None)
            }
            _ => Err("DCP AFKEPV2 invalid interface message category"),
        }
    }
}

impl Interface {
    fn cancel_commands(&mut self) -> Result<(), &'static str> {
        // Original createErrorResponses (AP 0x94c04bc) settles each pending
        // command with OFFLINE before disconnect completes.
        if let Some(request) = &self.staged {
            self.service.complete(request.cookie, OFFLINE, Vec::new())?;
            self.staged = None;
        }
        while let Some((&sequence, &cookie)) = self.commands.first_key_value() {
            self.service.complete(cookie, OFFLINE, Vec::new())?;
            self.commands.remove(&sequence);
        }
        Ok(())
    }
}

pub(super) fn report(packet_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = alloc::vec![0; 16];
    result[8] = packet_type;
    result[10] = 1; // Internal report, delivered to handleInternalPacket.
    result.extend_from_slice(payload);
    result
}

fn address(window: Option<u64>, dva: u64) -> u64 {
    match window {
        Some(base) if dva < base => base + dva,
        _ => dva,
    }
}

/// A completed service effect and its deterministic transport writes. The
/// ring owner keeps this until input RPTR commits, so a DMA retry never
/// calls the service or appends the same fragment twice.
pub(super) struct Response {
    pub bytes: Vec<u8>,
    dma: Option<(u64, Vec<u8>)>,
}

impl Response {
    pub fn inline(bytes: Vec<u8>) -> Self {
        Self { bytes, dma: None }
    }

    pub fn write(&self, bus: &mut dyn Bus) -> Result<(), &'static str> {
        if let Some((address, bytes)) = &self.dma {
            bus.write(*address, bytes)?;
        }
        Ok(())
    }
}

#[cfg(test)]
impl core::ops::Deref for Response {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

struct Command {
    header: [u8; 8],
    buffers: Option<[u8; 24]>,
    payload: Vec<u8>,
}

impl Command {
    fn decode(packet: &[u8], bus: &mut dyn Bus, window: Option<u64>) -> Result<Self, &'static str> {
        let header: [u8; 8] = packet
            .get(..8)
            .ok_or("DCP AFKEPV2 command header is truncated")?
            .try_into()
            .expect("header");
        let mut payload = packet[8..].to_vec();
        let buffers = if header[0] & 1 != 0 {
            let buffers: [u8; 24] = payload
                .get(..24)
                .ok_or("DCP AFKEPV2 command DMA descriptors are truncated")?
                .try_into()
                .expect("buffers");
            let request_bytes = u32::from_le_bytes(buffers[20..24].try_into().expect("length"));
            if request_bytes != 0 {
                payload = Vec::new();
                payload
                    .try_reserve_exact(request_bytes as usize)
                    .map_err(|_| "DCP AFKEPV2 command allocation failed")?;
                payload.resize(request_bytes as usize, 0);
                let dva = u64::from_le_bytes(buffers[8..16].try_into().expect("DVA"));
                bus.read(address(window, dva), &mut payload)?;
            } else {
                payload = payload[24..].to_vec();
            }
            Some(buffers)
        } else {
            None
        };
        Ok(Self {
            header,
            buffers,
            payload,
        })
    }

    fn response(
        mut self,
        message: &[u8; 16],
        mut status: i32,
        mut payload: Vec<u8>,
        window: Option<u64>,
    ) -> Response {
        let mut dma = None;
        if let Some(mut buffers) = self.buffers {
            let maximum =
                u32::from_le_bytes(self.header[4..8].try_into().expect("budget")) as usize;
            let supplied = u32::from_le_bytes(buffers[16..20].try_into().expect("length"));
            if supplied != 0 {
                if payload.len() > maximum.min(supplied as usize) {
                    status = OVERRUN;
                } else {
                    let dva = u64::from_le_bytes(buffers[..8].try_into().expect("DVA"));
                    buffers[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                    dma = Some((address(window, dva), core::mem::take(&mut payload)));
                }
            }
            let mut bytes = buffers.to_vec();
            bytes.extend_from_slice(&payload);
            payload = bytes;
        }
        self.header[4..8].copy_from_slice(&status.to_le_bytes());
        let mut result = message.to_vec();
        // Generic DCPAVIPC completion passes context=0 (firmware 0x104364),
        // while the separate command sequence is returned unchanged.
        result[..8].fill(0);
        result[9] = RESPONSE;
        result[10..].fill(0);
        result.extend_from_slice(&self.header);
        result.extend_from_slice(&payload);
        Response { bytes: result, dma }
    }
}

#[cfg(test)]
mod tests;
