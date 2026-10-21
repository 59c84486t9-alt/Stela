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
pub(crate) trait Service {
    fn handle(&mut self, packet_type: u8, payload: &[u8]) -> Result<(i32, Vec<u8>), &'static str>;

    /// Actual interface close/termination, distinct from retained CPU sleep.
    fn transport_closed(&mut self);
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
}

/// Each interface owns its assembly; fragments from other interfaces may
/// interleave. Original receivers ignore outer sequence/flags, using the
/// repeated total length to reassemble (AP 0x94c34bc and 0x94c10d8).
#[derive(Default)]
pub(super) struct Interfaces {
    services: BTreeMap<u16, Interface>,
    assemblies: BTreeMap<u16, Assembly>,
}

impl Interfaces {
    pub fn register(
        &mut self,
        descriptor: Descriptor,
        service: Box<dyn Service>,
    ) -> Result<(), &'static str> {
        if descriptor.number == 0 || descriptor.name.len() >= 32 || descriptor.name.contains('\0') {
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
            payload[..interface.descriptor.name.len()]
                .copy_from_slice(interface.descriptor.name.as_bytes());
            payload.extend_from_slice(&interface.descriptor.properties);
            reports.push((number, report(PUBLISH, &payload)));
        }
        reports
    }

    pub fn reset(&mut self) {
        self.assemblies.clear();
        for interface in self.services.values_mut() {
            interface.peer_open = false;
            interface.terminated = false;
            interface.service.transport_closed();
        }
    }

    pub fn idle(&self) -> bool {
        self.assemblies
            .values()
            .all(|assembly| assembly.bytes.is_empty())
    }

    pub fn receive(
        &mut self,
        number: u16,
        total: u32,
        fragment: &[u8],
        bus: &mut dyn Bus,
        window: Option<u64>,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let Some(packet) = self
            .assemblies
            .entry(number)
            .or_default()
            .push(total, fragment)?
        else {
            return Ok(None);
        };
        let header: &[u8; 16] = packet
            .get(..16)
            .ok_or("DCP AFKEPV2 interface header is truncated")?
            .try_into()
            .expect("header");
        let packet_type = header[8];
        let interface = self.services.get_mut(&number);
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
                        interface.peer_open = false;
                        interface.service.transport_closed();
                    }
                    TERMINATE => {
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
                    return Ok(Some(response));
                };
                let command = Command::decode(&packet[16..], bus, window)?;
                let (status, payload) = interface.service.handle(packet_type, &command.payload)?;
                command
                    .response(header, status, payload, bus, window)
                    .map(Some)
            }
            // No local commands are initiated. Original AP 0x94c069c logs
            // and drops an unmatched response without invoking a service.
            RESPONSE => {
                if packet.len() < 24 {
                    return Err("DCP AFKEPV2 response header is truncated");
                }
                Ok(None)
            }
            _ => Err("DCP AFKEPV2 invalid interface message category"),
        }
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
        bus: &mut dyn Bus,
        window: Option<u64>,
    ) -> Result<Vec<u8>, &'static str> {
        if let Some(mut buffers) = self.buffers {
            let maximum =
                u32::from_le_bytes(self.header[4..8].try_into().expect("budget")) as usize;
            let supplied = u32::from_le_bytes(buffers[16..20].try_into().expect("length"));
            if supplied != 0 {
                if payload.len() > maximum.min(supplied as usize) {
                    status = OVERRUN;
                } else {
                    let dva = u64::from_le_bytes(buffers[..8].try_into().expect("DVA"));
                    bus.write(address(window, dva), &payload)?;
                    buffers[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                    payload.clear();
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
        Ok(result)
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
        interfaces.receive(number, bytes.len() as u32, bytes, memory, None)
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
        interfaces.reset();
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
