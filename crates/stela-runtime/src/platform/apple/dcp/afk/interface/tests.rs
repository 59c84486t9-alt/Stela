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
                    name: "service".into(),
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
        0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0xc0, 1, 0, 0, 0, 0, 0, 0, 0, sequence, 0, 0, 4, 0, 0,
        0
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
    fn complete(&mut self, cookie: u64, status: i32, bytes: Vec<u8>) -> Result<(), &'static str> {
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
                    name: "client".into(),
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
                name: "client".into(),
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
fn peer_publication_refuses_without_inventing_an_importer_or_service_effect() {
    let (mut interfaces, effects) = interfaces();
    let mut memory = Memory::default();
    let mut payload = alloc::vec![0; 32];
    payload[..4].copy_from_slice(b"peer");
    payload.extend_from_slice(b"<dict/>\0");
    let publication = report(PUBLISH, &payload);
    for number in [1, 99] {
        assert_eq!(
            receive(&mut interfaces, number, &publication, &mut memory),
            Err("DCP AFKEPV2 peer service publication has no importer owner")
        );
    }
    assert_eq!(interfaces.services.len(), 2);
    assert_eq!((effects.borrow().calls, effects.borrow().closes), (0, 0));
    assert!(!interfaces.services[&1].peer_open);
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
fn close_and_reset_release_sessions_but_unmatched_responses_do_not() {
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
