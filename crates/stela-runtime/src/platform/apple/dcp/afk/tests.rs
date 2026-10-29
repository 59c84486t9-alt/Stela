use super::*;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use core::cell::Cell;

const WINDOW: u64 = 0x8_0000_0000;

#[derive(Default)]
struct Memory(BTreeMap<u64, u8>);

impl Bus for Memory {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        for (n, byte) in buffer.iter_mut().enumerate() {
            *byte = *self.0.get(&(address + n as u64)).unwrap_or(&0);
        }
        Ok(())
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), &'static str> {
        for (n, &byte) in data.iter().enumerate() {
            self.0.insert(address + n as u64, byte);
        }
        Ok(())
    }
}

fn started(memory: &mut Memory) -> Afk {
    let mut afk = Afk::new(0x20, "system", Some(WINDOW));
    let mut out = Vec::new();
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    // 0x100, not 8: the AP takes the 0x80-byte ring layout.
    assert_eq!(out[0], 0xa0 << 48 | 0x100);
    // GETBUF: 0x4000 bytes is 0x100 blocks, tagged with the endpoint.
    assert_eq!(out[1], 0x89 << 48 | 0x100 << 16 | 0x20);
    out.clear();
    afk.receive(message(GETBUF_ACK, 0x4000), &mut out).unwrap();
    assert!(out.is_empty() && afk.pending());
    afk.dma(memory, &mut out).unwrap();
    assert_eq!(
        out,
        [
            0x8a << 48 | 0x80 << 16 | 0x20,
            0x8b << 48 | 0x80 << 32 | 0x80 << 16 | 0x20,
        ]
    );
    // Each ring header gives bufsz + 0x180 == its size, as the AP checks.
    for ring in [0, 0x2000] {
        let mut size = [0u8; 4];
        memory.read(WINDOW + 0x4000 + ring, &mut size).unwrap();
        let mut format = [0u8; 4];
        memory
            .read(WINDOW + 0x4000 + ring + 4, &mut format)
            .unwrap();
        assert_eq!(u32::from_le_bytes(format), 0x0007_0006);
        assert_eq!(
            u64::from(u32::from_le_bytes(size)) + RING_HEADER,
            RING_BYTES
        );
    }
    out.clear();
    afk.receive(message(START, 0), &mut out).unwrap();
    assert_eq!(out, [START_ACK << 48]);
    assert!(afk.started());
    afk
}

#[test]
fn the_transport_comes_up_through_the_aps_buffer() {
    started(&mut Memory::default());
}

struct Counted(Rc<Cell<usize>>);

impl interface::Service for Counted {
    fn handle(&mut self, packet_type: u8, bytes: &[u8]) -> Result<(i32, Vec<u8>), &'static str> {
        assert_eq!(packet_type, 0xc0);
        self.0.set(self.0.get() + 1);
        Ok((0, bytes.iter().rev().copied().collect()))
    }
    fn transport_closed(&mut self) {}
}

fn service(memory: &mut Memory) -> (Afk, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    let mut afk = Afk::new(0x24, "service", Some(WINDOW));
    afk.register(
        interface::Descriptor {
            number: 7,
            name: "implemented-service".into(),
            properties: b"<dict/>\0".to_vec(),
        },
        Box::new(Counted(calls.clone())),
    )
    .unwrap();
    let mut out = Vec::new();
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    afk.receive(message(GETBUF_ACK, 0x4000), &mut out).unwrap();
    afk.dma(memory, &mut out).unwrap();
    afk.receive(message(START, 0), &mut out).unwrap();
    assert!(afk.pending());
    afk.dma(memory, &mut out).unwrap();
    assert_eq!(read_word(memory, WINDOW + 0x6000 + WPTR), 0x80);
    assert_eq!(
        read_word(memory, WINDOW + 0x6000 + RING_HEADER + 18) & 0xffff,
        7
    );
    assert_eq!(
        read_word(memory, WINDOW + 0x6000 + RING_HEADER + 32) & 0xff,
        0x11
    );
    memory
        .write(WINDOW + 0x6000 + RPTR, &0x80u32.to_le_bytes())
        .unwrap();
    (afk, calls)
}

fn command_entry(interface: u16, body: &[u8]) -> Vec<u8> {
    let mut packet = alloc::vec![0; 48];
    packet[..4].copy_from_slice(&QE_MAGIC.to_le_bytes());
    packet[4..8].copy_from_slice(&(32u32 + body.len() as u32).to_le_bytes());
    packet[16] = 0x91;
    packet[17] = 0xa5; // Original receivers ignore this reserved byte.
    packet[18..20].copy_from_slice(&interface.to_le_bytes());
    packet[20..24].copy_from_slice(&(24u32 + body.len() as u32).to_le_bytes());
    packet[24..32].fill(0xa5); // Opaque request context, not command ID.
    packet[32] = 0xc0;
    packet[33] = 1;
    packet[41] = 0x55; // Separate command correlation sequence.
    packet.extend_from_slice(body);
    packet
}

struct Initiator(Rc<Cell<u64>>, Rc<Cell<usize>>);
impl interface::Service for Initiator {
    fn handle(&mut self, _: u8, _: &[u8]) -> Result<(i32, Vec<u8>), &'static str> {
        Err("no incoming commands")
    }
    fn transport_closed(&mut self) {}
    fn pending(&self) -> bool {
        self.0.get() != 0
    }
    fn take_command(&mut self) -> Option<interface::CommandRequest> {
        let cookie = self.0.replace(0);
        (cookie != 0).then(|| interface::CommandRequest {
            cookie,
            packet_type: 0xc0,
            payload: alloc::vec![7],
            reply_bytes: 4,
        })
    }
    fn complete(&mut self, cookie: u64, status: i32, payload: Vec<u8>) -> Result<(), &'static str> {
        assert_eq!((cookie, status, payload.as_slice()), (1, 0, &[4][..]));
        self.1.set(self.1.get() + 1);
        Ok(())
    }
}

#[test]
fn pause_completion_waits_for_local_responses_and_preserves_new_queued_commands() {
    let mut memory = Memory::default();
    let mut afk = Afk::new(0x24, "bidirectional", Some(WINDOW));
    let queued = Rc::new(Cell::new(1));
    let completed = Rc::new(Cell::new(0));
    afk.register(
        interface::Descriptor {
            number: 9,
            name: "client".into(),
            properties: b"<dict/>\0".to_vec(),
        },
        Box::new(Initiator(queued.clone(), completed.clone())),
    )
    .unwrap();
    let mut out = Vec::new();
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    afk.receive(message(GETBUF_ACK, 0x4000), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    afk.receive(message(START, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    let rx = WINDOW + 0x6000;
    let tx = WINDOW + 0x4000;
    assert_eq!(read_word(&mut memory, rx + WPTR), 0x100); // Publish, then local command.
    memory.write(rx + RPTR, &0x100u32.to_le_bytes()).unwrap();
    queued.set(2);
    enqueue_internal(&mut memory, 0, 2);
    afk.receive(message(RECV, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(afk.peer, lifecycle::PeerState::Paused);
    assert!(afk.pause_completion && !afk.retained_idle());
    // The new producer request remains queued while the peer is paused.
    // A command already in flight is allowed to complete through the ring.
    let mut response = command_entry(9, &[4]);
    response[33] = 2;
    response[41] = 0;
    response[44..48].fill(0);
    memory.write(tx + RING_HEADER + 0x80, &response).unwrap();
    memory.write(tx + WPTR, &0x100u32.to_le_bytes()).unwrap();
    afk.receive(message(RECV, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(completed.get(), 1);
    assert_eq!(queued.get(), 2);
    assert!(!afk.pause_completion && afk.retained_idle());
    assert_eq!(read_word(&mut memory, rx + RING_HEADER + 0x100 + 24), 3); // PauseDone.
}

struct Cancelling {
    cookie: u64,
    queued: bool,
    fail: Rc<Cell<bool>>,
    effects: Rc<core::cell::RefCell<Vec<u64>>>,
}
impl interface::Service for Cancelling {
    fn handle(&mut self, _: u8, _: &[u8]) -> Result<(i32, Vec<u8>), &'static str> {
        Err("no incoming commands")
    }
    fn transport_closed(&mut self) {
        self.effects.borrow_mut().push(100 + self.cookie);
    }
    fn pending(&self) -> bool {
        self.queued
    }
    fn take_command(&mut self) -> Option<interface::CommandRequest> {
        core::mem::replace(&mut self.queued, false).then(|| interface::CommandRequest {
            cookie: self.cookie,
            packet_type: 0xc0,
            payload: alloc::vec![7],
            reply_bytes: 4,
        })
    }
    fn complete(&mut self, cookie: u64, status: i32, bytes: Vec<u8>) -> Result<(), &'static str> {
        assert_eq!(cookie, self.cookie);
        assert_eq!(status as u32, 0xe000_02d7);
        assert!(bytes.is_empty());
        if self.cookie == 2 && self.fail.replace(false) {
            return Err("cancellation temporarily unavailable");
        }
        self.effects.borrow_mut().push(cookie);
        Ok(())
    }
}

#[test]
fn shutdown_retries_cancellation_progress_before_closing_any_session() {
    let mut memory = Memory::default();
    let mut afk = Afk::new(0x24, "bidirectional", Some(WINDOW));
    let effects = Rc::new(core::cell::RefCell::new(Vec::new()));
    let fail = Rc::new(Cell::new(true));
    for (number, cookie) in [(7, 1), (9, 2)] {
        afk.register(
            interface::Descriptor {
                number,
                name: "cancelling".into(),
                properties: b"<dict/>\0".to_vec(),
            },
            Box::new(Cancelling {
                cookie,
                queued: true,
                fail: fail.clone(),
                effects: effects.clone(),
            }),
        )
        .unwrap();
    }
    let mut out = Vec::new();
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    afk.receive(message(GETBUF_ACK, 0x4000), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    afk.receive(message(START, 0), &mut out).unwrap();
    for _ in 0..3 {
        afk.dma(&mut memory, &mut out).unwrap();
    }
    assert!(!afk.interfaces.quiescent());
    // Queued input/output also belong to the unfinished shutdown until
    // cancellation succeeds; a refused callback must not discard them.
    afk.receive(message(RECV, 0), &mut out).unwrap();
    afk.reply = Some(Pending::new(7, alloc::vec![1]));
    let sequence = afk.sequence;
    out.clear();
    assert_eq!(
        afk.receive(message(SHUTDOWN, 0), &mut out),
        Err("cancellation temporarily unavailable")
    );
    assert!(afk.started() && out.is_empty());
    assert_eq!(&*effects.borrow(), &[1]); // Earlier completion stays settled.
    assert_eq!(afk.sequence, sequence);
    assert_eq!(afk.incoming.len(), 1);
    assert!(afk.reply.is_some());
    afk.receive(message(SHUTDOWN, 0), &mut out).unwrap();
    assert_eq!(&*effects.borrow(), &[1, 2, 101, 102]);
    assert_eq!(out, [message(SHUTDOWN_ACK, 0)]);
    assert_eq!(afk.state, State::Stopped);
    assert!(afk.interfaces.quiescent() && afk.retained_idle());
    assert!(afk.incoming.is_empty() && afk.reply.is_none());
    afk.start();
    afk.receive(message(INIT, 0x100), &mut Vec::new()).unwrap();
}

struct Fault<'a> {
    memory: &'a mut Memory,
    write: Option<u64>,
    read: Option<u64>,
}

impl Bus for Fault<'_> {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
        if self.read == Some(address) {
            return Err("injected DMA read fault");
        }
        self.memory.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), &'static str> {
        if self.write == Some(address) {
            return Err("injected DMA write fault");
        }
        self.memory.write(address, bytes)
    }
}

#[test]
fn completed_service_effects_survive_each_response_dma_and_pointer_fault() {
    let tx = WINDOW + 0x4000;
    let rx = WINDOW + 0x6000;
    for address in [
        WINDOW + 0x9000,
        tx + RPTR,
        rx + RING_HEADER + 0x80,
        rx + WPTR,
    ] {
        let mut memory = Memory::default();
        let (mut afk, calls) = service(&mut memory);
        let mut body = Vec::new();
        body.extend_from_slice(&0x9000u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(b"data");
        let mut entry = command_entry(7, &body);
        entry[40] = 1;
        entry[44..48].copy_from_slice(&4u32.to_le_bytes());
        memory.write(tx + RING_HEADER, &entry).unwrap();
        memory.write(tx + WPTR, &0x80u32.to_le_bytes()).unwrap();
        let mut out = Vec::new();
        afk.receive(message(RECV, 0), &mut out).unwrap();
        assert_eq!(
            afk.dma(
                &mut Fault {
                    memory: &mut memory,
                    write: Some(address),
                    read: None
                },
                &mut out
            ),
            Err("injected DMA write fault")
        );
        assert_eq!(calls.get(), 1);
        assert!(afk.pending() && !afk.retained_idle());
        // Repairing translation resumes kept transport writes, with no
        // duplicate service call or extra AP doorbell required.
        afk.dma(&mut memory, &mut out).unwrap();
        assert_eq!(calls.get(), 1);
        let mut result = [0; 4];
        memory.read(WINDOW + 0x9000, &mut result).unwrap();
        assert_eq!(&result, b"atad");
        assert_eq!(read_word(&mut memory, tx + RPTR), 0x80);
        assert_eq!(read_word(&mut memory, rx + WPTR), 0x100);
        assert_eq!(
            read_word(&mut memory, rx + RING_HEADER + 0x80 + 40) & 0xffff,
            0x5501
        );
        assert!(afk.retained_idle());
    }
}

#[test]
fn fragment_ack_and_final_request_dma_faults_preserve_the_assembled_packet() {
    for fail_final_read in [false, true] {
        let mut memory = Memory::default();
        let (mut afk, calls) = service(&mut memory);
        let tx = WINDOW + 0x4000;
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0x9000u64.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        memory.write(WINDOW + 0x9000, b"data").unwrap();
        let mut packet = command_entry(7, &body);
        packet[40] = 1;
        let logical = &packet[24..];
        let mut out = Vec::new();
        for (index, fragment) in [&logical[..19], &logical[19..]].into_iter().enumerate() {
            let pointer = index as u32 * 0x80;
            let mut entry = alloc::vec![0; 24];
            entry[..4].copy_from_slice(&QE_MAGIC.to_le_bytes());
            entry[4..8].copy_from_slice(&(8u32 + fragment.len() as u32).to_le_bytes());
            entry[18..20].copy_from_slice(&7u16.to_le_bytes());
            entry[20..24].copy_from_slice(&(logical.len() as u32).to_le_bytes());
            entry.extend_from_slice(fragment);
            memory
                .write(tx + RING_HEADER + u64::from(pointer), &entry)
                .unwrap();
            memory
                .write(tx + WPTR, &(pointer + 0x80).to_le_bytes())
                .unwrap();
            afk.receive(message(RECV, 0), &mut out).unwrap();
            if (index == 0 && !fail_final_read) || (index == 1 && fail_final_read) {
                let mut fault = Fault {
                    memory: &mut memory,
                    write: (!fail_final_read).then_some(tx + RPTR),
                    read: fail_final_read.then_some(WINDOW + 0x9000),
                };
                assert!(afk.dma(&mut fault, &mut out).is_err());
                assert_eq!(calls.get(), 0);
            }
            afk.dma(&mut memory, &mut out).unwrap();
        }
        assert_eq!(calls.get(), 1);
        assert_eq!(read_word(&mut memory, tx + RPTR), 0x100);
        assert!(afk.retained_idle());
    }
}

#[test]
fn variable_frames_wrap_and_credit_retries_never_reexecute_the_command() {
    let mut memory = Memory::default();
    let (mut afk, calls) = service(&mut memory);
    let tx = WINDOW + 0x4000;
    let rx = WINDOW + 0x6000;
    let body: Vec<_> = (0..=255).collect();
    let entry = command_entry(7, &body);
    let tail = DATA_BYTES - ENTRY_BLOCK;
    // The original enqueue leaves a size-bearing wrap marker in the
    // old tail, then writes the complete entry at the start of the ring.
    memory.write(tx + RPTR, &tail.to_le_bytes()).unwrap();
    memory.write(tx + WPTR, &0x180u32.to_le_bytes()).unwrap();
    memory
        .write(tx + RING_HEADER + u64::from(tail), &entry[..16])
        .unwrap();
    memory.write(tx + RING_HEADER, &entry).unwrap();
    memory.write(rx + RPTR, &0x100u32.to_le_bytes()).unwrap();
    memory.write(rx + WPTR, &tail.to_le_bytes()).unwrap();
    let mut out = Vec::new();
    afk.receive(message(RECV, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(read_word(&mut memory, tx + RPTR), 0x180);
    assert_eq!(read_word(&mut memory, rx + WPTR), tail);
    assert_eq!(out, [message(RECV, 0), message(FULL, 0)]);
    assert!(!afk.retained_idle());
    // A repeated doorbell while still full cannot invoke the service,
    // advance output, or emit a second FULL notification.
    out.clear();
    afk.receive(message(RECV, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert!(out.is_empty());
    assert_eq!(calls.get(), 1);
    memory.write(rx + RPTR, &0x400u32.to_le_bytes()).unwrap();
    afk.receive(message(SPACE, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(read_word(&mut memory, rx + WPTR), 0x180);
    assert_eq!(
        read_word(&mut memory, rx + RING_HEADER + u64::from(tail)),
        QE_MAGIC
    );
    let mut reply = alloc::vec![0; 304];
    memory.read(rx + RING_HEADER, &mut reply).unwrap();
    assert_eq!(reply[16], 1); // Publication used transport sequence zero.
    assert_eq!(&reply[24..32], &[0; 8]);
    assert_eq!(reply[33], 2);
    assert_eq!(reply[41], 0x55);
    assert_eq!(&reply[48..], body.iter().rev().copied().collect::<Vec<_>>());
    assert!(afk.retained_idle());
}

#[test]
fn large_outbound_messages_split_retain_order_and_keep_the_total_length() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    let bytes: Vec<_> = (0..20_000).map(|index| (index % 251) as u8).collect();
    afk.reply = Some(Pending::new(9, bytes.clone()));
    let rx = WINDOW + 0x6000;
    let mut out = Vec::new();
    let mut reconstructed = Vec::new();
    let mut expected_sequence = 0u8;
    for _ in 0..8 {
        if afk.retained_idle() {
            break;
        }
        afk.receive(message(SPACE, 0), &mut out).unwrap();
        afk.dma(&mut memory, &mut out).unwrap();
        let header = afk.header(&mut memory, rx).unwrap();
        let mut at = header[2];
        while at != header[3] {
            let mut entry = [0; 24];
            memory
                .read(rx + RING_HEADER + u64::from(at), &mut entry)
                .unwrap();
            let size = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            let block = entry_block(size).unwrap();
            if at + block > DATA_BYTES {
                at = 0;
                memory.read(rx + RING_HEADER, &mut entry).unwrap();
            }
            assert_eq!(entry[16], expected_sequence);
            expected_sequence = expected_sequence.wrapping_add(1);
            assert_eq!(entry[18..20], 9u16.to_le_bytes());
            assert_eq!(entry[20..24], 20_000u32.to_le_bytes());
            let mut body = alloc::vec![0; (size - 8) as usize];
            memory
                .read(rx + RING_HEADER + u64::from(at) + 24, &mut body)
                .unwrap();
            reconstructed.extend_from_slice(&body);
            at = advance(at, block);
        }
        memory.write(rx + RPTR, &header[3].to_le_bytes()).unwrap();
    }
    assert!(afk.retained_idle());
    assert_eq!(reconstructed, bytes);
    assert_eq!(expected_sequence, 3);
}

#[test]
fn a_retained_assembly_is_ram_and_survives_transport_pause() {
    let mut memory = Memory::default();
    let (mut afk, calls) = service(&mut memory);
    let packet = command_entry(7, b"data");
    let tx = WINDOW + 0x4000;
    let mut out = Vec::new();
    for (pointer, fragment) in [(0u32, &packet[24..29]), (0x100, &packet[29..])] {
        let size = fragment.len() as u32 + 8;
        let mut entry = alloc::vec![0; 24];
        entry[..4].copy_from_slice(&QE_MAGIC.to_le_bytes());
        entry[4..8].copy_from_slice(&size.to_le_bytes());
        entry[18..20].copy_from_slice(&7u16.to_le_bytes());
        entry[20..24].copy_from_slice(&28u32.to_le_bytes());
        entry.extend_from_slice(fragment);
        memory
            .write(tx + RING_HEADER + u64::from(pointer), &entry)
            .unwrap();
        memory
            .write(tx + WPTR, &(pointer + 0x80).to_le_bytes())
            .unwrap();
        afk.receive(message(RECV, 0), &mut out).unwrap();
        afk.dma(&mut memory, &mut out).unwrap();
        if pointer == 0 {
            assert_eq!(calls.get(), 0);
            assert!(afk.retained_idle());
            assert!(afk.check_reset().is_err());
            enqueue_internal(&mut memory, 0x80, 2);
            afk.receive(message(RECV, 0), &mut out).unwrap();
            afk.dma(&mut memory, &mut out).unwrap();
            assert_eq!(afk.peer, lifecycle::PeerState::Paused);
            assert!(afk.retained_idle());
        }
    }
    assert_eq!(calls.get(), 1);
}

#[test]
fn an_ap_entry_refuses_and_records_what_it_was() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    // The AP writes a command entry on channel 3 at rptr 0.
    let at = WINDOW + 0x4000 + RING_HEADER;
    let mut qe = Vec::new();
    for value in [QE_MAGIC, 0x40, 3, 3] {
        qe.extend_from_slice(&value.to_le_bytes());
    }
    memory.write(at, &qe).unwrap();
    memory.write(at + 32 + 5, &[0x30, 0xc0, 0]).unwrap();
    let mut out = Vec::new();
    memory
        .write(WINDOW + 0x4000 + WPTR, &0x80u32.to_le_bytes())
        .unwrap();
    afk.receive(message(RECV, 0x80_0000), &mut out).unwrap();
    assert!(afk.dma(&mut memory, &mut out).is_err());
    assert_eq!(
        afk.seen.pop_back(),
        Some(Event::Entry(Entry {
            channel: 3,
            kind: 3,
            size: 0x40,
            category: Some(0x30),
            subtype: Some(0xc0),
        }))
    );
}

#[test]
fn empty_and_credit_doorbells_do_not_read_an_entry() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    let mut out = Vec::new();
    for code in [RECV, SEND] {
        afk.receive(message(code, 0x80_0000), &mut out).unwrap();
        afk.dma(&mut memory, &mut out).unwrap();
    }
    assert!(out.is_empty());
    afk.receive(message(FULL, 0x40), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(out, [message(SPACE, 0)]);
    out.clear();
    afk.receive(message(SPACE, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert!(!afk.pending() && out.is_empty());
}

fn enqueue_internal(memory: &mut Memory, pointer: u32, opcode: u8) -> u32 {
    let ring = WINDOW + 0x4000;
    let at = ring + RING_HEADER + u64::from(pointer);
    let mut bytes = [0; 28];
    bytes[..4].copy_from_slice(&0x2050_4f49u32.to_le_bytes());
    bytes[4] = 12;
    bytes[16] = 0x79; // AP sequence is unrelated to the DCP's counter.
    bytes[20] = 4;
    bytes[24] = opcode;
    memory.write(at, &bytes).unwrap();
    let next = advance(pointer, ENTRY_BLOCK);
    memory.write(ring + WPTR, &next.to_le_bytes()).unwrap();
    next
}

fn read_word(memory: &mut Memory, at: u64) -> u32 {
    let mut bytes = [0; 4];
    memory.read(at, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn lifecycle_requests_and_completions_drain_and_reply_over_the_real_ring() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    let mut pointer = 0;
    for opcode in [2, 3, 4, 5] {
        pointer = enqueue_internal(&mut memory, pointer, opcode);
    }
    let mut out = Vec::new();
    afk.receive(message(RECV, 0x80_0000), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(read_word(&mut memory, WINDOW + 0x4000 + RPTR), 0x200);
    let rx = WINDOW + 0x6000;
    assert_eq!(read_word(&mut memory, rx + WPTR), 0x100);
    for (offset, sequence, opcode) in [(0, 0, 3), (0x80, 1, 5)] {
        let mut actual = [0; 28];
        memory.read(rx + RING_HEADER + offset, &mut actual).unwrap();
        assert_eq!(
            u32::from_le_bytes(actual[..4].try_into().unwrap()),
            0x2050_4f49
        );
        assert_eq!(&actual[4..16], &[12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            &actual[16..],
            &[sequence, 0, 0, 0, 4, 0, 0, 0, opcode, 0, 0, 0]
        );
    }
    assert_eq!(afk.peer, lifecycle::PeerState::Running);
    assert!(afk.reply.is_none());
    assert_eq!(out, [message(RECV, 0); 6]); // Four consumed, two enqueued.
}

#[test]
fn lifecycle_pointers_and_sequence_wrap_without_touching_the_ring_header() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    let last = DATA_BYTES - ENTRY_BLOCK;
    let tx = WINDOW + 0x4000;
    let rx = WINDOW + 0x6000;
    memory.write(tx + RPTR, &last.to_le_bytes()).unwrap();
    memory.write(rx + RPTR, &0x80u32.to_le_bytes()).unwrap();
    memory.write(rx + WPTR, &last.to_le_bytes()).unwrap();
    enqueue_internal(&mut memory, last, 4);
    afk.sequence = 255;
    let mut out = Vec::new();
    afk.receive(message(SEND, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(read_word(&mut memory, tx + RPTR), 0);
    assert_eq!(read_word(&mut memory, rx + WPTR), 0);
    assert_eq!(read_word(&mut memory, rx), DATA_BYTES);
    assert_eq!(afk.sequence, 0);
    assert_eq!(
        read_word(&mut memory, rx + RING_HEADER + u64::from(last) + 16),
        255
    );
}

#[test]
fn full_transmit_ring_preserves_the_reply_and_resumes_in_order_on_credit() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    let rx = WINDOW + 0x6000;
    memory.write(rx + RPTR, &0x80u32.to_le_bytes()).unwrap();
    let next = enqueue_internal(&mut memory, 0, 2);
    enqueue_internal(&mut memory, next, 4);
    let mut out = Vec::new();
    afk.receive(message(FULL, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(out, [message(RECV, 0), message(FULL, 0)]);
    assert_eq!(read_word(&mut memory, WINDOW + 0x4000 + RPTR), 0x80);
    assert_eq!(read_word(&mut memory, rx + WPTR), 0);
    assert_eq!(afk.peer, lifecycle::PeerState::Paused);
    // AP frees two blocks, allowing both replies. SPACE resumes DMA.
    memory.write(rx + RPTR, &0x180u32.to_le_bytes()).unwrap();
    out.clear();
    afk.receive(message(SPACE, 0), &mut out).unwrap();
    afk.dma(&mut memory, &mut out).unwrap();
    assert_eq!(read_word(&mut memory, rx + WPTR), 0x100);
    assert_eq!(read_word(&mut memory, rx + RING_HEADER + 24), 3);
    assert_eq!(read_word(&mut memory, rx + RING_HEADER + 0x80 + 24), 5);
    assert_eq!(
        out,
        [
            message(RECV, 0),
            message(RECV, 0),
            message(RECV, 0),
            message(SPACE, 0)
        ]
    );
    assert!(!afk.receive_full && !afk.transmit_full && afk.reply.is_none());
}

#[test]
fn an_unknown_internal_command_preserves_the_input_entry() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    enqueue_internal(&mut memory, 0, 1);
    let mut out = Vec::new();
    afk.receive(message(RECV, 0), &mut out).unwrap();
    assert_eq!(
        afk.dma(&mut memory, &mut out),
        Err("DCP AFKEPV2 unknown internal command")
    );
    assert_eq!(read_word(&mut memory, WINDOW + 0x4000 + RPTR), 0);
    assert_eq!(read_word(&mut memory, WINDOW + 0x6000 + WPTR), 0);
    assert!(out.is_empty());
}

#[test]
fn version_query_and_command_states_match_the_table() {
    let mut afk = Afk::new(0x20, "system", None);
    let mut out = Vec::new();
    afk.receive(message(VERSION, 0), &mut out).unwrap();
    assert_eq!(out, [message(VERSION_ACK, 0x100)]);
    out.clear();
    for code in [RECV, SEND, FULL, SPACE, SHUTDOWN, GETBUF_ACK, START] {
        assert!(afk.receive(message(code, 0), &mut out).is_err());
    }
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    out.clear();
    assert!(afk.receive(message(VERSION, 0), &mut out).is_err());
    assert!(afk.receive(message(SHUTDOWN, 0), &mut out).is_err());
    for code in [
        INIT_ACK,
        START_ACK,
        GETBUF,
        INIT_TX,
        INIT_RX,
        VERSION_ACK,
        SHUTDOWN_ACK,
        0x8d,
        0x8e,
        0x99,
    ] {
        assert!(afk.receive(message(code, 0), &mut out).is_err());
    }
    assert!(out.is_empty());
    assert_eq!(kind(0xff85_0000_0000_0000), RECV);
}

#[test]
fn malformed_ring_headers_refuse_before_reading_entries() {
    let mut memory = Memory::default();
    let mut afk = started(&mut memory);
    let mut out = Vec::new();
    memory
        .write(WINDOW + 0x4000 + WPTR, &0x2000u32.to_le_bytes())
        .unwrap();
    afk.receive(message(RECV, 0), &mut out).unwrap();
    assert_eq!(
        afk.dma(&mut memory, &mut out),
        Err("DCP AFK ring pointer lies outside the ring")
    );
    memory
        .write(WINDOW + 0x4000 + WPTR, &0u32.to_le_bytes())
        .unwrap();
    memory
        .write(WINDOW + 0x4000 + 4, &0u32.to_le_bytes())
        .unwrap();
    afk.receive(message(RECV, 0), &mut out).unwrap();
    assert_eq!(
        afk.dma(&mut memory, &mut out),
        Err("DCP AFK ring header size or format changed")
    );
}

#[test]
fn out_of_order_messages_refuse_and_shutdown_resets() {
    let mut afk = Afk::new(0x2a, "dptx port", None);
    let mut out = Vec::new();
    assert!(afk.receive(message(START, 0), &mut out).is_err());
    assert!(afk.receive(message(SEND, 0), &mut out).is_err());
    assert!(afk.receive(message(GETBUF_ACK, 0), &mut out).is_err());
    assert!(afk.receive(message(0x99, 0), &mut out).is_err());
    assert!(afk.receive(message(INIT, 8), &mut out).is_err());
    assert!(out.is_empty());
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    assert!(afk.receive(message(INIT, 0x100), &mut out).is_err());
    out.clear();
    assert!(afk.receive(message(SHUTDOWN, 0), &mut out).is_err());
    afk.state = State::Started { buffer: 0x4000 };
    afk.peer = lifecycle::PeerState::Paused;
    afk.reply = Some(Pending::new(
        0,
        lifecycle::Command::PauseDone.packet(0)[8..].to_vec(),
    ));
    afk.transmit_full = true;
    afk.receive_full = true;
    afk.receive(message(SHUTDOWN, 0), &mut out).unwrap();
    assert_eq!(out, [SHUTDOWN_ACK << 48]);
    assert_eq!(afk.peer, lifecycle::PeerState::Running);
    assert!(afk.reply.is_none() && !afk.transmit_full && !afk.receive_full);
    assert!(afk.receive(message(INIT, 0x100), &mut out).is_err());
    afk.start();
    afk.receive(message(INIT, 0x100), &mut out).unwrap();
    assert_eq!(afk.seen.front(), Some(&Event::Received(START << 48)));
}
