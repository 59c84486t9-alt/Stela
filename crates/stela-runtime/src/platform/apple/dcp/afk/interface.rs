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

    /// Actual interface close/termination, distinct from retained CPU sleep.
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
    pub name: &'static str,
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
        // Retain the producer-owned request on every validation refusal.
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
/// ring owner retains this until input RPTR commits, so a DMA retry never
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
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::RefCell;

    #[derive(Default)]
    struct Memory(BTreeMap<u64, u8>);

    impl Bus for Memory {
        fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
            for (offset, byte) in bytes.iter_mut().enumerate() {
                *byte = *self
                    .0
                    .get(&(address + offset as u64))
                    .ok_or("unmapped input")?;
            }
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), &'static str> {
            self.0.extend(
                bytes
                    .iter()
                    .enumerate()
                    .map(|(offset, &byte)| (address + offset as u64, byte)),
            );
            Ok(())
        }
    }

    #[derive(Default)]
    struct Effects {
        calls: usize,
        closes: usize,
    }

    struct Echo(Rc<RefCell<Effects>>);

    impl Service for Echo {
        fn handle(&mut self, kind: u8, payload: &[u8]) -> Result<(i32, Vec<u8>), &'static str> {
            assert_eq!(kind, 0xc0);
            self.0.borrow_mut().calls += 1;
            Ok((0, payload.iter().rev().copied().collect()))
        }
        fn transport_closed(&mut self) {
            self.0.borrow_mut().closes += 1;
        }
    }

    fn interfaces() -> (Interfaces, Rc<RefCell<Effects>>) {
        let effects = Rc::new(RefCell::new(Effects::default()));
        let mut interfaces = Interfaces::default();
        for number in [1, 7] {
            interfaces
                .register(
                    Descriptor {
                        number,
                        name: "service",
                        properties: b"<dict/>\0".to_vec(),
                    },
                    Box::new(Echo(effects.clone())),
                )
                .unwrap();
        }
        (interfaces, effects)
    }

    fn inline(sequence: u8) -> Vec<u8> {
        // Literal original layout: opaque context64, type, category,
        // flags/reserved, commandflags, commandsequence, reserved16, budget32.
        let mut bytes = alloc::vec![
            0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0xc0, 1, 0, 0, 0, 0, 0, 0, 0, sequence, 0, 0, 4, 0,
            0, 0
        ];
        bytes.extend_from_slice(b"data");
        bytes
    }

    fn receive(
        interfaces: &mut Interfaces,
        number: u16,
        bytes: &[u8],
        memory: &mut Memory,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        interfaces
            .receive(number, bytes.len() as u32, bytes, memory, None)?
            .map(|response| {
                response.write(memory)?;
                Ok(response.bytes)
            })
            .transpose()
    }

    #[derive(Default)]
    struct Producer {
        requests: alloc::collections::VecDeque<u64>,
        completions: Vec<(u64, i32, Vec<u8>)>,
    }
    struct Client(Rc<RefCell<Producer>>);
    impl Service for Client {
        fn handle(&mut self, _: u8, _: &[u8]) -> Result<(i32, Vec<u8>), &'static str> {
            Err("no incoming command contract")
        }
        fn transport_closed(&mut self) {}
        fn pending(&self) -> bool {
            !self.0.borrow().requests.is_empty()
        }
        fn take_command(&mut self) -> Option<CommandRequest> {
            self.0
                .borrow_mut()
                .requests
                .pop_front()
                .map(|cookie| CommandRequest {
                    cookie,
                    packet_type: 0xc0,
                    payload: cookie.to_le_bytes().to_vec(),
                    reply_bytes: 16,
                })
        }
        fn complete(
            &mut self,
            cookie: u64,
            status: i32,
            bytes: Vec<u8>,
        ) -> Result<(), &'static str> {
            self.0
                .borrow_mut()
                .completions
                .push((cookie, status, bytes));
            Ok(())
        }
    }

    #[test]
    fn local_publication_is_incremental_and_fair_across_service_owners() {
        let producer = Rc::new(RefCell::new(Producer::default()));
        producer.borrow_mut().requests.extend(10..14);
        let mut interfaces = Interfaces::default();
        for number in [1, 7] {
            interfaces
                .register(
                    Descriptor {
                        number,
                        name: "client",
                        properties: b"<dict/>\0".to_vec(),
                    },
                    Box::new(Client(producer.clone())),
                )
                .unwrap();
        }
        for (number, cookie) in [(1, 10u64), (7, 11), (1, 12), (7, 13)] {
            let packets = interfaces.commands().unwrap();
            assert_eq!(packets.len(), 1); // No later owner is consumed in this call.
            assert_eq!(packets[0].0, number);
            assert_eq!(&packets[0].1[24..], &cookie.to_le_bytes());
            assert_eq!(producer.borrow().requests.len(), (13 - cookie) as usize);
        }
        assert!(interfaces.commands().unwrap().is_empty());
        interfaces.reset().unwrap();
        assert_eq!(producer.borrow().completions.len(), 4);
    }

    #[test]
    fn local_sequences_correlate_out_of_order_and_apply_full_space_backpressure() {
        let producer = Rc::new(RefCell::new(Producer::default()));
        producer.borrow_mut().requests.extend(1000..1257);
        let mut interfaces = Interfaces::default();
        interfaces
            .register(
                Descriptor {
                    number: 7,
                    name: "client",
                    properties: b"<dict/>\0".to_vec(),
                },
                Box::new(Client(producer.clone())),
            )
            .unwrap();
        let mut packets = Vec::new();
        for sequence in 0..=255u8 {
            let mut next = interfaces.commands().unwrap();
            assert_eq!(next.len(), 1);
            assert_eq!(next[0].1[17], sequence);
            packets.push(next.pop().unwrap().1);
        }
        assert!(!interfaces.quiescent() && !interfaces.pending());
        assert!(interfaces.commands().unwrap().is_empty());
        assert_eq!(producer.borrow().requests.len(), 1);
        let mut memory = Memory::default();
        for sequence in [255u8, 1, 128, 0] {
            let mut response = packets[sequence as usize].clone();
            response[9] = RESPONSE;
            response[20..24].copy_from_slice(&(-31i32).to_le_bytes());
            response[16] = 1;
            assert!(receive(&mut interfaces, 7, &response, &mut memory).is_err());
            assert!(interfaces.services[&7].commands.contains_key(&sequence));
            response[16] = 0;
            receive(&mut interfaces, 7, &response, &mut memory).unwrap();
            receive(&mut interfaces, 7, &response, &mut memory).unwrap(); // Stale duplicate.
        }
        {
            let completed = &producer.borrow().completions;
            assert_eq!(
                completed.iter().map(|entry| entry.0).collect::<Vec<_>>(),
                [1255, 1001, 1128, 1000]
            );
            for (cookie, status, bytes) in completed {
                assert_eq!(*status, -31);
                assert_eq!(bytes, &cookie.to_le_bytes());
            }
        }
        assert!(interfaces.pending());
        let next = interfaces.commands().unwrap();
        assert_eq!(next[0].1[17], 0); // Wrapped allocation uses the released slot.
        receive(&mut interfaces, 7, &report(CLOSE, &[]), &mut memory).unwrap();
        assert!(interfaces.quiescent());
        assert_eq!(producer.borrow().completions.len(), 257);
        assert_eq!(
            producer
                .borrow()
                .completions
                .iter()
                .filter(|entry| entry.1 == OFFLINE)
                .count(),
            253
        );
        interfaces.reset().unwrap();
        assert_eq!(producer.borrow().completions.len(), 257);
    }

    #[test]
    fn commands_return_the_command_sequence_and_service_result_not_the_outer_context() {
        let (mut interfaces, effects) = interfaces();
        let mut memory = Memory::default();
        for sequence in [0x19, 0xfe, 0] {
            let response = receive(&mut interfaces, 7, &inline(sequence), &mut memory)
                .unwrap()
                .unwrap();
            assert_eq!(
                &response[..16],
                &[0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 2, 0, 0, 0, 0, 0, 0]
            );
            assert_eq!(&response[16..24], &[0, sequence, 0, 0, 0, 0, 0, 0]);
            assert_eq!(&response[24..], b"atad");
        }
        assert_eq!(effects.borrow().calls, 3);
    }

    #[test]
    fn fragments_are_per_interface_and_whole_packets_replace_old_partial_messages() {
        let (mut interfaces, effects) = interfaces();
        let mut memory = Memory::default();
        let packet = inline(0x32);
        assert!(
            interfaces
                .receive(1, 28, &packet[..10], &mut memory, None)
                .unwrap()
                .is_none()
        );
        assert!(
            interfaces
                .receive(7, 28, &packet[..19], &mut memory, None)
                .unwrap()
                .is_none()
        );
        assert!(!interfaces.idle() && effects.borrow().calls == 0);
        let reply = interfaces
            .receive(1, 28, &packet[10..], &mut memory, None)
            .unwrap()
            .unwrap();
        assert_eq!(&reply[24..], b"atad");
        receive(&mut interfaces, 7, &inline(0x54), &mut memory).unwrap();
        assert!(interfaces.idle());
        assert_eq!(effects.borrow().calls, 2);
        interfaces
            .receive(1, 29, &packet[..10], &mut memory, None)
            .unwrap();
        interfaces
            .receive(1, 28, &packet[..20], &mut memory, None)
            .unwrap();
        assert!(
            interfaces
                .receive(1, 28, &packet[20..], &mut memory, None)
                .unwrap()
                .is_some()
        );
        assert_eq!(effects.borrow().calls, 3);
    }

    #[test]
    fn dma_buffers_use_the_dart_window_and_return_updated_lengths() {
        let (mut interfaces, effects) = interfaces();
        let mut memory = Memory::default();
        let mut packet = inline(0x92);
        packet.truncate(24);
        packet[16] = 1;
        packet.extend_from_slice(&0x300u64.to_le_bytes());
        packet.extend_from_slice(&0x200u64.to_le_bytes());
        packet.extend_from_slice(&4u32.to_le_bytes());
        packet.extend_from_slice(&3u32.to_le_bytes());
        memory.write(0x8000_0200, b"abc").unwrap();
        let response = interfaces
            .receive(1, 48, &packet, &mut memory, Some(0x8000_0000))
            .unwrap()
            .unwrap();
        assert_eq!(&response[16..24], &[1, 0x92, 0, 0, 0, 0, 0, 0]);
        assert_eq!(response.len(), 48);
        assert_eq!(&response[40..44], &3u32.to_le_bytes());
        response.write(&mut memory).unwrap();
        let mut data = [0; 3];
        memory.read(0x8000_0300, &mut data).unwrap();
        assert_eq!(&data, b"cba");
        assert_eq!(effects.borrow().calls, 1);
        // An output budget smaller than the service result returns the
        // original overrun status without writing beyond the mapped buffer.
        packet[20] = 2;
        memory.write(0x8000_0300, b"---").unwrap();
        let response = interfaces
            .receive(1, 48, &packet, &mut memory, Some(0x8000_0000))
            .unwrap()
            .unwrap();
        assert_eq!(&response[20..24], &OVERRUN.to_le_bytes());
        memory.read(0x8000_0300, &mut data).unwrap();
        assert_eq!(&data, b"---");
    }

    #[test]
    fn unpublished_and_terminated_interfaces_return_offline_without_mapping_dma() {
        let (mut interfaces, effects) = interfaces();
        let mut memory = Memory::default();
        let mut packet = inline(0x61);
        packet[16] = 1; // No descriptors or mapped DMA memory.
        let response = receive(&mut interfaces, 99, &packet, &mut memory)
            .unwrap()
            .unwrap();
        assert_eq!(response.len(), 24);
        assert_eq!(&response[16..24], &[0, 0x61, 0, 0, 0xd7, 2, 0, 0xe0]);
        receive(&mut interfaces, 1, &report(TERMINATE, &[0]), &mut memory).unwrap();
        assert!(
            receive(&mut interfaces, 1, &packet, &mut memory)
                .unwrap()
                .is_some()
        );
        assert_eq!(effects.borrow().calls, 0);
        assert_eq!(effects.borrow().closes, 1);
        assert!(receive(&mut interfaces, 1, &report(OPEN, &[]), &mut memory).is_err());
    }

    #[test]
    fn actual_close_and_reset_release_sessions_but_unmatched_responses_do_not() {
        let (mut interfaces, effects) = interfaces();
        let mut memory = Memory::default();
        receive(&mut interfaces, 1, &report(OPEN, &[]), &mut memory).unwrap();
        assert!(interfaces.services[&1].peer_open);
        receive(&mut interfaces, 1, &report(CLOSE, &[]), &mut memory).unwrap();
        assert!(!interfaces.services[&1].peer_open);
        let mut packet = inline(0x18);
        packet[9] = RESPONSE;
        receive(&mut interfaces, 1, &packet, &mut memory).unwrap();
        assert_eq!(effects.borrow().closes, 1);
        interfaces
            .receive(7, 28, &packet[..5], &mut memory, None)
            .unwrap();
        interfaces.reset().unwrap();
        assert!(interfaces.idle());
        assert_eq!(effects.borrow().closes, 3);
        let publications = interfaces.publications();
        assert_eq!(
            publications.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            [1, 7]
        );
        assert_eq!(publications[0].1[8..11], [0x11, 0, 1]);
        assert_eq!(&publications[0].1[16..24], b"service\0");
        assert_eq!(&publications[0].1[48..], b"<dict/>\0");
    }

    #[test]
    fn bad_framing_or_dma_faults_do_not_execute_a_service() {
        let (mut interfaces, effects) = interfaces();
        let mut memory = Memory::default();
        let mut packet = inline(0);
        packet[9] = 3;
        assert!(receive(&mut interfaces, 1, &packet, &mut memory).is_err());
        packet[9] = COMMAND;
        packet[16] = 1;
        assert!(receive(&mut interfaces, 1, &packet, &mut memory).is_err());
        packet.truncate(24);
        packet.extend_from_slice(&[0; 24]);
        packet[44] = 1;
        assert_eq!(
            receive(&mut interfaces, 1, &packet, &mut memory),
            Err("unmapped input")
        );
        assert_eq!(effects.borrow().calls, 0);
    }
}
