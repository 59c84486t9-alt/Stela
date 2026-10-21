//! The AFK ring-buffer transport the DCP's EPIC endpoints (0x20 system,
//! 0x24 DPAV, 0x2a DPTX port) run over RTKit, coprocessor side.
//!
//! Public description (both are AP-side implementations of the same
//! protocol): Asahi Linux `drivers/gpu/drm/apple/afk.c`/`afk.h` and m1n1
//! `src/afk.c`, `proxyclient/m1n1/fw/afk/rbep.py`.
//!
//! Both original peers use the same 17-row state table (AppleFirmwareKit
//! file `0x1119c58`, DCP restore firmware VA `0x706148`). The message type
//! is the byte `[55:48]`; the low 48 bits depend on the command:
//!
//! | Type | Accepted state / effect |
//! | --- | --- |
//! | 0x90 VERSION | ready; reply 0x91 with version 0x100 |
//! | 0x80 INIT | ready; reply 0xa0 then request memory with 0x89 |
//! | 0xa1 GETBUF_ACK | awaiting memory; low48 is its DVA; initialize and register rings |
//! | 0xa3 START | registered; reply 0x86 and enter started |
//! | 0x85 / 0xa2 doorbell | started; inspect the shared queue headers, ignoring payload |
//! | 0xa8 FULL | started; drain AP queue then reply 0xa7 SPACE |
//! | 0xa7 SPACE | started; retry replies waiting for transmit space |
//! | 0xc0 SHUTDOWN | started; release transport and reply 0xc1 |
//!
//! The remaining rows answer a flow this coprocessor never initiates:
//! 0xa0 in state2, 0x89 in state3, 0x8d/0x8e in state4, 0x8a/0x8b in
//! state5, 0x86 in state7 and 0xc1 in state6. They explicitly refuse in
//! this coprocessor-owned-buffer flow. Unknown and out-of-state commands
//! refuse without acknowledging. The ready state corresponds to the
//! firmware's state1 (the endpoint has started), memory request to state4,
//! registered to state7 and running to state8.
//!
//! Ring registration is relative to the *receiver*: 0x8a names its
//! transmit ring and 0x8b its receive ring (`_afk_msgr_handle_q_reg`,
//! kernel VA `0xfffffe00094c6910`). The sender uses these same ranges for
//! receive and transmit respectively (`_afk_msgr_send_register_queues`,
//! kernel `0xfffffe00094c5c0c`, DCP `0x2c660`). A doorbell signals either
//! ring: enqueue, read-pointer update and reset all signal through
//! `_buffer_signal_standard` (`0xfffffe00094c7224`), whose trailing
//! arguments are incidental register contents for the latter two paths.
//! Both 0x85 and 0xa2 dispatch to the same handler; its first operation
//! reads the receiver's receive-ring pointers (`0xfffffe00094c7468`,
//! DCP `0x2e2c0`). Equal pointers mean empty, including a credit-only bell.
//!
//! A ring starts with a header the coprocessor writes: the data size, the
//! read pointer and the write pointer, one layout block each. Both sides
//! of the 26A434 messenger pick the block from the peer's INIT word: low
//! 16 bits of 8 select 0x40-byte blocks (Linux `struct
//! afk_ringbuffer_header`), anything else 0x80-byte blocks. The DCP
//! firmware (`ipad14dcp` restore image, 0x2df40..0x2df6c) answers INIT
//! with `INIT_ACK` 0x100 whatever the AP sent, so the AP's
//! `_afk_msgr_handle_ready_ack` (AppleFirmwareKit 0x24c32c0) always takes
//! the 0x80-byte layout and `_iop_ringbuffer_init_ex` (0x24c1ce4) checks
//! `bufsz + 0x180` is the ring's size. The initializer also writes
//! `0x00070006` at header+4 (kernel `0xfffffe00094c5da8`, DCP `0x2c804`):
//! its high half selects the modern entry layout. A zero header+4 selects
//! the legacy size/channel/type/magic order, not the magic-first order.
//! Entries are a 16-byte `afk_qe`
//! (`' POI'` magic, size, channel, type) and an EPIC header, aligned to the
//! layout's 0x80 bytes.
//!
//! EPIC services are announced by the coprocessor (an `EPIC_SUBTYPE_ANNOUNCE`
//! report on a new channel, `afk_recv_handle_init`); the AP only talks to an
//! announced channel. This model brings the transport up and announces no
//! service: the DCP model drives its one display through the IOMFB link and
//! programs no DPTX PHY, DP AV or system service the AP would serve.
//! AFKEPV2 also has interface-zero lifecycle packets independent of those
//! services: Pause/PauseDone (2/3) and Unpause/UnpauseDone (4/5).
//! They run over queue channel/type zero, with an eight-byte AFKEPV2 header
//! and four-byte internal command. Those packets are modeled; service
//! traffic to any unpublished interface refuses by name.
mod lifecycle;

use super::rpc::Bus;
use alloc::collections::VecDeque;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const TYPE_SHIFT: u32 = 48;
pub const INIT: u64 = 0x80;
pub const INIT_ACK: u64 = 0xa0;
pub const GETBUF: u64 = 0x89;
pub const GETBUF_ACK: u64 = 0xa1;
pub const INIT_TX: u64 = 0x8a;
pub const INIT_RX: u64 = 0x8b;
pub const START: u64 = 0xa3;
pub const START_ACK: u64 = 0x86;
/// Both doorbell codes invoke the same queue-not-empty handler.
pub const SEND: u64 = 0xa2;
pub const RECV: u64 = 0x85;
pub const FULL: u64 = 0xa8;
pub const SPACE: u64 = 0xa7;
pub const VERSION: u64 = 0x90;
pub const VERSION_ACK: u64 = 0x91;
pub const SHUTDOWN: u64 = 0xc0;
pub const SHUTDOWN_ACK: u64 = 0xc1;

/// `GETBUF` and `INIT_TX`/`INIT_RX` count bytes in 64-byte units, whatever
/// the ring layout (`_afk_msgr_handle_q_reg` decodes `(word >> 10) &
/// 0x3fffc0`).
const BLOCK_SHIFT: u32 = 6;
/// The buffer the coprocessor asks for: two rings of half of it each. A
/// `GETBUF` size is a 16-bit byte count once shifted (Linux `afk_getbuf`).
pub const BUFFER_BYTES: u64 = 0x4000;
const RING_BYTES: u64 = BUFFER_BYTES / 2;
/// The ring the AP writes (`INIT_TX`) and the one the coprocessor writes.
const TX_RING: u64 = 0;
const RX_RING: u64 = RING_BYTES;
/// The `INIT_ACK` the DCP firmware sends, which selects 0x80-byte blocks.
const INIT_ACK_VALUE: u64 = 0x100;
/// An INIT whose low 16 bits are this asks for 0x40-byte blocks.
const SMALL_LAYOUT: u64 = 8;
/// The ring header: size, read pointer, write pointer, a 0x80-byte block each.
pub const RING_HEADER: u64 = 0x180;
const RPTR: u64 = 0x80;
const WPTR: u64 = 0x100;
/// `afk_qe.magic`, `' POI'` little-endian.
const QE_MAGIC: u32 = 0x2050_4f49;
/// `iop_ringbuffer_init_ex` initializes the format word alongside the size.
/// Its high half selects the magic/size/channel/type entry layout. With a
/// zero format the AP instead writes size/channel/type/magic.
const RING_FORMAT: u32 = 0x0007_0006;
const ENTRY_BLOCK: u32 = 0x80;
const DATA_BYTES: u32 = (RING_BYTES - RING_HEADER) as u32;

/// The message type of an AFK word.
pub fn kind(word: u64) -> u64 {
    (word >> TYPE_SHIFT) & 0xff
}

fn message(kind: u64, value: u64) -> u64 {
    kind << TYPE_SHIFT | value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The transport endpoint is ready for INIT (firmware state 1).
    Ready,
    /// Shutdown completed; endpoint start must rearm the transport.
    Stopped,
    /// `GETBUF` sent; waiting for the buffer.
    Asked,
    /// Rings described; waiting for `START`.
    Described {
        buffer: u64,
    },
    Started {
        buffer: u64,
    },
}

/// What an AFK endpoint saw, for the display log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A mailbox word from the AP.
    Received(u64),
    /// A ring entry the AP wrote.
    Entry(Entry),
    /// Both ring headers at a doorbell (AP transmit first), including their
    /// format words. The mailbox payload is not a write pointer.
    Doorbell { tx: [u32; 4], rx: [u32; 4] },
    /// The full AFKEPV2 header and internal command received on interface zero.
    Lifecycle([u8; lifecycle::PACKET_BYTES]),
}

/// A ring entry the AP wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub channel: u32,
    pub kind: u32,
    pub size: u32,
    /// The EPIC sub-header's category and type, when the entry holds one.
    pub category: Option<u8>,
    pub subtype: Option<u16>,
}

/// One AFK endpoint of the coprocessor.
pub struct Afk {
    /// The endpoint's RTKit number and service name, for refusals and the
    /// display log.
    pub endpoint: u8,
    pub name: &'static str,
    state: State,
    /// The DART window base for a `truncate-dvas` coprocessor.
    window: Option<u64>,
    /// AP words whose handling needs the buffer.
    incoming: VecDeque<u64>,
    peer: lifecycle::PeerState,
    reply: Option<lifecycle::Command>,
    sequence: u8,
    transmit_full: bool,
    receive_full: bool,
    /// What the endpoint saw, drained by the coprocessor's log.
    pub(super) seen: VecDeque<Event>,
}

impl Afk {
    pub fn new(endpoint: u8, name: &'static str, window: Option<u64>) -> Self {
        Self {
            endpoint,
            name,
            state: State::Ready,
            window,
            incoming: VecDeque::new(),
            peer: lifecycle::PeerState::default(),
            reply: None,
            sequence: 0,
            transmit_full: false,
            receive_full: false,
            seen: VecDeque::new(),
        }
    }

    /// RTKit enabled the endpoint, starting the messenger again after shutdown.
    pub fn start(&mut self) {
        if self.state == State::Stopped {
            self.state = State::Ready;
        }
    }

    fn tag(&self) -> u64 {
        u64::from(self.endpoint)
    }

    fn bus(&self, dva: u64) -> u64 {
        match self.window {
            Some(base) if dva < base => base + dva,
            _ => dva,
        }
    }

    pub fn started(&self) -> bool {
        matches!(self.state, State::Started { .. })
    }

    pub fn pending(&self) -> bool {
        !self.incoming.is_empty()
    }

    pub(super) fn retained_idle(&self) -> bool {
        !self.pending() && self.reply.is_none()
    }

    /// The AP sent `word`; what needs no memory is answered at once.
    pub fn receive(&mut self, word: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.seen.push_back(Event::Received(word));
        match (kind(word), self.state) {
            (_, State::Stopped) => Err("DCP AFK message after shutdown before endpoint restart"),
            // The firmware would lay its rings out in 0x40-byte blocks while
            // its `INIT_ACK` tells the AP 0x80; no 26A434 AP asks for that.
            (INIT, State::Ready) if word & 0xffff == SMALL_LAYOUT => {
                Err("DCP AFK INIT asks for the 0x40-byte ring layout")
            }
            (INIT, State::Ready) => {
                self.state = State::Asked;
                outbox.push(message(INIT_ACK, INIT_ACK_VALUE));
                outbox.push(message(
                    GETBUF,
                    (BUFFER_BYTES >> BLOCK_SHIFT) << 16 | self.tag(),
                ));
                Ok(())
            }
            (VERSION, State::Ready) => {
                outbox.push(message(VERSION_ACK, INIT_ACK_VALUE));
                Ok(())
            }
            (VERSION, _) => Err("DCP AFK version query after initialization"),
            (INIT, _) => Err("DCP AFK INIT on an endpoint already started"),
            (GETBUF_ACK, State::Asked) | (RECV | SEND | FULL | SPACE, State::Started { .. }) => {
                self.incoming.push_back(word);
                Ok(())
            }
            (GETBUF_ACK, _) => Err("DCP AFK GETBUF_ACK without a GETBUF"),
            (START, State::Described { buffer }) => {
                self.state = State::Started { buffer };
                outbox.push(message(START_ACK, 0));
                Ok(())
            }
            (START, _) => Err("DCP AFK START before both rings were described"),
            (RECV | SEND | FULL | SPACE, _) => {
                Err("DCP AFK queue notification on an endpoint that has not started")
            }
            (SHUTDOWN, State::Started { .. }) => {
                self.state = State::Stopped;
                self.incoming.clear();
                self.peer = lifecycle::PeerState::default();
                self.reply = None;
                self.sequence = 0;
                self.transmit_full = false;
                self.receive_full = false;
                outbox.push(message(SHUTDOWN_ACK, 0));
                Ok(())
            }
            (SHUTDOWN, _) => Err("DCP AFK SHUTDOWN on an endpoint that has not started"),
            (INIT_ACK | START_ACK | GETBUF | INIT_TX | INIT_RX | VERSION_ACK | SHUTDOWN_ACK, _) => {
                Err(
                    "DCP AFK response or queue registration is not pending in the coprocessor-owned-buffer flow",
                )
            }
            (0x8d | 0x8e, _) => Err("DCP AFK unsolicited AP-owned buffer is unsupported"),
            _ => Err("DCP AFK unknown message type"),
        }
    }

    /// Handle the queued words that need the AP's buffer.
    pub fn dma(&mut self, bus: &mut dyn Bus, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        while let Some(word) = self.incoming.pop_front() {
            match (kind(word), self.state) {
                (GETBUF_ACK, State::Asked) => {
                    let buffer = self.bus(word & 0xffff_ffff_ffff);
                    for ring in [TX_RING, RX_RING] {
                        let mut header = [0u8; RING_HEADER as usize];
                        header[0..4].copy_from_slice(
                            &u32::try_from(RING_BYTES - RING_HEADER)
                                .expect("ring size")
                                .to_le_bytes(),
                        );
                        header[4..8].copy_from_slice(&RING_FORMAT.to_le_bytes());
                        bus.write(buffer + ring, &header)?;
                    }
                    for (kind, ring) in [(INIT_TX, TX_RING), (INIT_RX, RX_RING)] {
                        outbox.push(message(
                            kind,
                            (ring >> BLOCK_SHIFT) << 32
                                | (RING_BYTES >> BLOCK_SHIFT) << 16
                                | self.tag(),
                        ));
                    }
                    self.state = State::Described { buffer };
                }
                (RECV | SEND | FULL | SPACE, State::Started { buffer }) => {
                    let tx = self.header(bus, buffer + TX_RING)?;
                    let rx = self.header(bus, buffer + RX_RING)?;
                    self.seen.push_back(Event::Doorbell { tx, rx });
                    self.validate_header(tx)?;
                    self.validate_header(rx)?;
                    if kind(word) == SPACE {
                        self.transmit_full = false;
                    }
                    self.receive_full |= kind(word) == FULL;
                    self.drain(bus, buffer, tx, outbox)?;
                    let after = self.header(bus, buffer + TX_RING)?;
                    if self.receive_full && after[2] == after[3] {
                        outbox.push(message(SPACE, 0));
                        self.receive_full = false;
                    }
                }
                _ => return Err("DCP AFK queued message no longer matches the endpoint"),
            }
        }
        Ok(())
    }

    fn header(&self, bus: &mut dyn Bus, ring: u64) -> Result<[u32; 4], &'static str> {
        let mut fields = [0; 4];
        for (field, offset) in fields.iter_mut().zip([0, 4, RPTR, WPTR]) {
            let mut word = [0; 4];
            bus.read(ring + offset, &mut word)?;
            *field = u32::from_le_bytes(word);
        }
        Ok(fields)
    }

    fn validate_header(&self, fields: [u32; 4]) -> Result<(), &'static str> {
        if u64::from(fields[0]) != RING_BYTES - RING_HEADER || fields[1] != RING_FORMAT {
            return Err("DCP AFK ring header size or format changed");
        }
        if fields[2..]
            .iter()
            .any(|&p| u64::from(p) >= RING_BYTES - RING_HEADER)
        {
            return Err("DCP AFK ring pointer lies outside the ring");
        }
        if fields[2..].iter().any(|p| p % ENTRY_BLOCK != 0) {
            return Err("DCP AFK ring pointer is not entry-block aligned");
        }
        Ok(())
    }

    /// Keep one reply pending when the AP has not released transmit credit;
    /// stop consuming requests until it can be published, preserving order.
    fn drain(
        &mut self,
        bus: &mut dyn Bus,
        buffer: u64,
        mut tx: [u32; 4],
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        loop {
            if !self.flush_reply(bus, buffer, outbox)? || tx[2] == tx[3] {
                return Ok(());
            }
            let entry = self.entry(bus, buffer)?;
            self.seen.push_back(Event::Entry(entry));
            if entry.channel != 0 || entry.kind != 0 || entry.size != lifecycle::PACKET_BYTES as u32
            {
                return Err("DCP AFK AP ring entry is not a supported AFKEPV2 lifecycle packet");
            }
            let mut packet = [0; lifecycle::PACKET_BYTES];
            bus.read(
                buffer + TX_RING + RING_HEADER + u64::from(tx[2]) + 16,
                &mut packet,
            )?;
            self.seen.push_back(Event::Lifecycle(packet));
            let command = lifecycle::Command::decode(&packet)?;
            tx[2] = next_pointer(tx[2]);
            bus.write(buffer + TX_RING + RPTR, &tx[2].to_le_bytes())?;
            self.reply = self.peer.receive(command);
            // Read-pointer updates signal the same symmetric doorbell as
            // enqueue, even when this command has no response.
            outbox.push(message(RECV, 0));
        }
    }

    fn flush_reply(
        &mut self,
        bus: &mut dyn Bus,
        buffer: u64,
        outbox: &mut Vec<u64>,
    ) -> Result<bool, &'static str> {
        let Some(reply) = self.reply else {
            return Ok(true);
        };
        let ring = buffer + RX_RING;
        let header = self.header(bus, ring)?;
        self.validate_header(header)?;
        let next = next_pointer(header[3]);
        if next == header[2] {
            if !self.transmit_full {
                outbox.push(message(FULL, 0));
                self.transmit_full = true;
            }
            return Ok(false);
        }
        let mut block = [0; ENTRY_BLOCK as usize];
        block[..4].copy_from_slice(&QE_MAGIC.to_le_bytes());
        block[4..8].copy_from_slice(&(lifecycle::PACKET_BYTES as u32).to_le_bytes());
        block[16..16 + lifecycle::PACKET_BYTES].copy_from_slice(&reply.packet(self.sequence));
        bus.write(ring + RING_HEADER + u64::from(header[3]), &block)?;
        bus.write(ring + WPTR, &next.to_le_bytes())?;
        self.sequence = self.sequence.wrapping_add(1);
        self.reply = None;
        self.transmit_full = false;
        outbox.push(message(RECV, 0));
        Ok(true)
    }

    /// The entry at the AP ring's read pointer.
    fn entry(&self, bus: &mut dyn Bus, buffer: u64) -> Result<Entry, &'static str> {
        let ring = buffer + TX_RING;
        let mut word = [0u8; 4];
        bus.read(ring + RPTR, &mut word)?;
        let rptr = u64::from(u32::from_le_bytes(word));
        if rptr + 16 > RING_BYTES - RING_HEADER {
            return Err("DCP AFK ring read pointer lies outside the ring");
        }
        let mut qe = [0u8; 16];
        bus.read(ring + RING_HEADER + rptr, &mut qe)?;
        let field = |at: usize| u32::from_le_bytes(qe[at..at + 4].try_into().expect("4 bytes"));
        if field(0) != QE_MAGIC {
            return Err("DCP AFK ring entry lacks the queue-entry magic");
        }
        let size = field(4);
        // The EPIC header (16 bytes) then its sub-header, whose category
        // is byte 5 and type bytes 6..8 (Linux `struct epic_sub_hdr`).
        let mut sub = [0u8; 8];
        let epic = if u64::from(size) >= 16 + 8
            && rptr + 16 + 16 + 8 <= RING_BYTES - RING_HEADER
            && bus
                .read(ring + RING_HEADER + rptr + 16 + 16, &mut sub)
                .is_ok()
        {
            Some((sub[5], u16::from_le_bytes([sub[6], sub[7]])))
        } else {
            None
        };
        Ok(Entry {
            channel: field(8),
            kind: field(12),
            size,
            category: epic.map(|(category, _)| category),
            subtype: epic.map(|(_, subtype)| subtype),
        })
    }
}

fn next_pointer(pointer: u32) -> u32 {
    let next = pointer + ENTRY_BLOCK;
    if next == DATA_BYTES { 0 } else { next }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

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
        let next = next_pointer(pointer);
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
        afk.reply = Some(lifecycle::Command::PauseDone);
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
}
