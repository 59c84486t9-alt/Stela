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
//! AFKEPV2 services are published by report0x11 on a nonzero interface.
//! A real implemented service must be registered before
//! initialization; its publication, commands and session lifetime then share
//! this transport. Service metadata never substitutes for its implementation.
//! AFKEPV2 also has interface-zero lifecycle packets independent of those
//! services: Pause/PauseDone (2/3) and Unpause/UnpauseDone (4/5).
//! They run over queue channel/type zero, with an eight-byte AFKEPV2 header
//! and four-byte internal command. Nonzero interfaces carry the common
//! sixteen-byte interface header, with per-interface split-message assembly,
//! separate command sequence/status and optional request/reply DMA buffers.
//! Unpublished commands receive the original offline status without DMA.
pub(crate) mod interface;
mod lifecycle;

use super::rpc::Bus;
use alloc::boxed::Box;
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
    /// First fragment of a published report or command response.
    Sent {
        interface: u16,
        bytes: u32,
        packet_type: u8,
        category: u8,
        command_sequence: Option<u8>,
        status: Option<i32>,
    },
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

/// One accepted input entry. Service effects/fragment assembly are already
/// committed in native RAM; only idempotent transport writes may be retried.
struct Accepted {
    next: u32,
    response: Option<(u16, interface::Response)>,
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
    accepted: Option<Accepted>,
    reply: Option<Pending>,
    outgoing: VecDeque<Pending>,
    interfaces: interface::Interfaces,
    sequence: u8,
    transmit_full: bool,
    receive_full: bool,
    pause_completion: bool,
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
            accepted: None,
            reply: None,
            outgoing: VecDeque::new(),
            interfaces: interface::Interfaces::default(),
            sequence: 0,
            transmit_full: false,
            receive_full: false,
            pause_completion: false,
            seen: VecDeque::new(),
        }
    }

    /// Install an implemented service before the endpoint starts. No service
    /// is announced without its command and lifecycle owner.
    pub(crate) fn register(
        &mut self,
        descriptor: interface::Descriptor,
        service: Box<dyn interface::Service>,
    ) -> Result<(), &'static str> {
        if self.state != State::Ready {
            return Err("DCP AFKEPV2 register after transport initialization");
        }
        self.interfaces.register(descriptor, service)
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
        self.accepted.is_some()
            || !self.incoming.is_empty()
            || (!self.transmit_full
                && (self.reply.is_some()
                    || !self.outgoing.is_empty()
                    || (self.peer == lifecycle::PeerState::Running && self.interfaces.pending())))
    }

    /// Partial messages are retained RAM, not queued DMA work. The CPU may
    /// stop with one assembled prefix and finish it after retained wake.
    pub(super) fn retained_idle(&self) -> bool {
        self.incoming.is_empty()
            && self.accepted.is_none()
            && self.reply.is_none()
            && self.outgoing.is_empty()
            && self.interfaces.quiescent()
            && !self.pause_completion
    }

    pub(super) fn check_reset(&self) -> Result<(), &'static str> {
        if !self.retained_idle() || !self.interfaces.idle() || self.interfaces.pending() {
            return Err("DCP physical reset with owned AFKEPV2 work or fragments");
        }
        Ok(())
    }

    pub(super) fn reset(&mut self) -> Result<(), &'static str> {
        self.check_reset()?;
        self.interfaces.reset()?;
        self.state = State::Ready;
        self.peer = lifecycle::PeerState::default();
        self.sequence = 0;
        self.transmit_full = false;
        self.receive_full = false;
        self.pause_completion = false;
        Ok(())
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
                self.outgoing.extend(
                    self.interfaces
                        .publications()
                        .into_iter()
                        .map(|(interface, bytes)| Pending::new(interface, bytes)),
                );
                Ok(())
            }
            (START, _) => Err("DCP AFK START before both rings were described"),
            (RECV | SEND | FULL | SPACE, _) => {
                Err("DCP AFK queue notification on an endpoint that has not started")
            }
            (SHUTDOWN, State::Started { .. }) => {
                // Cancellation may refuse after earlier completions committed.
                // Keep the transport retryable until every owner has settled.
                self.interfaces.reset()?;
                self.state = State::Stopped;
                self.incoming.clear();
                self.peer = lifecycle::PeerState::default();
                self.accepted = None;
                self.reply = None;
                self.outgoing.clear();
                self.pause_completion = false;
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
        if self.incoming.is_empty()
            && let State::Started { buffer } = self.state
        {
            let tx = self.header(bus, buffer + TX_RING)?;
            self.validate_header(tx)?;
            self.drain(bus, buffer, tx, outbox)?;
        }
        while let Some(word) = self.incoming.front().copied() {
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
            self.incoming.pop_front();
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
            if let Some(accepted) = &self.accepted {
                if let Some((_, response)) = &accepted.response {
                    response.write(bus)?;
                }
                bus.write(buffer + TX_RING + RPTR, &accepted.next.to_le_bytes())?;
                let accepted = self.accepted.take().expect("accepted input");
                tx[2] = accepted.next;
                self.reply = accepted
                    .response
                    .map(|(number, response)| Pending::new(number, response.bytes));
                // Published RPTR survives later failures, as does this doorbell
                // through ASC's independently committed firmware outbox.
                outbox.push(message(RECV, 0));
            }
            if self.reply.is_none() && self.outgoing.is_empty() {
                if self.pause_completion && self.interfaces.quiescent() {
                    self.pause_completion = false;
                    self.reply = Some(Pending::new(
                        0,
                        lifecycle::Command::PauseDone.packet(0)[8..].to_vec(),
                    ));
                } else if self.peer == lifecycle::PeerState::Running && tx[2] == tx[3] {
                    self.outgoing.extend(
                        self.interfaces
                            .commands()?
                            .into_iter()
                            .map(|(interface, bytes)| Pending::new(interface, bytes)),
                    );
                }
            }
            if !self.flush_reply(bus, buffer, outbox)? || tx[2] == tx[3] {
                return Ok(());
            }
            let entry = self.entry(bus, buffer)?;
            self.seen.push_back(Event::Entry(entry));
            if entry.channel != 0 || entry.kind != 0 {
                return Err("DCP AFK queue entry does not carry AFKEPV2 framing");
            }
            let block = entry_block(entry.size)?;
            let pointer = if tx[2] + block > DATA_BYTES { 0 } else { tx[2] };
            let next = advance(pointer, block);
            // A producer must publish all of a frame before advancing WPTR.
            if pointer < tx[3] && next != 0 && next > tx[3] {
                return Err("DCP AFK entry extends beyond the published write pointer");
            }
            let mut packet = alloc::vec![0; entry.size as usize];
            bus.read(
                buffer + TX_RING + RING_HEADER + u64::from(pointer) + 16,
                &mut packet,
            )?;
            let header = packet
                .get(..8)
                .ok_or("DCP AFKEPV2 packet header is truncated")?;
            let interface = u16::from_le_bytes(header[2..4].try_into().expect("interface"));
            let total = u32::from_le_bytes(header[4..8].try_into().expect("length"));
            let response = if interface == 0 {
                let packet: [u8; lifecycle::PACKET_BYTES] = packet
                    .as_slice()
                    .try_into()
                    .map_err(|_| "DCP AFKEPV2 internal packet length is not four bytes")?;
                self.seen.push_back(Event::Lifecycle(packet));
                let command = lifecycle::Command::decode(&packet)?;
                let response = self.peer.receive(command);
                if command == lifecycle::Command::Pause && !self.interfaces.quiescent() {
                    self.pause_completion = true;
                    None
                } else {
                    if command == lifecycle::Command::Unpause {
                        self.pause_completion = false;
                    }
                    response.map(|command| {
                        (
                            0,
                            interface::Response::inline(command.packet(0)[8..].to_vec()),
                        )
                    })
                }
            } else {
                self.interfaces
                    .receive(interface, total, &packet[8..], bus, self.window)?
                    .map(|response| (interface, response))
            };
            self.accepted = Some(Accepted { next, response });
        }
    }

    fn flush_reply(
        &mut self,
        bus: &mut dyn Bus,
        buffer: u64,
        outbox: &mut Vec<u64>,
    ) -> Result<bool, &'static str> {
        if self.reply.is_none() {
            self.reply = self.outgoing.pop_front();
        }
        let Some(reply) = &self.reply else {
            return Ok(true);
        };
        let ring = buffer + RX_RING;
        let header = self.header(bus, ring)?;
        self.validate_header(header)?;
        // Leave one ring block unused so equal pointers always mean empty.
        // Oversized logical messages split above the ring, each fragment
        // repeating its logical total as the original sender does.
        let remaining = &reply.bytes[reply.offset..];
        let maximum = DATA_BYTES - ENTRY_BLOCK;
        let split = reply.bytes.len() > (maximum - 24) as usize;
        let capacity = if header[3] < header[2] {
            header[2] - header[3] - ENTRY_BLOCK
        } else {
            let tail = DATA_BYTES - header[3] - if header[2] == 0 { ENTRY_BLOCK } else { 0 };
            let head = header[2].saturating_sub(ENTRY_BLOCK);
            tail.max(head)
        };
        let limit = if split {
            maximum.min(capacity)
        } else {
            maximum
        };
        let count = remaining.len().min(limit.saturating_sub(24) as usize);
        let size = u32::try_from(count + 8).expect("ring-sized fragment");
        let block = entry_block(size)?;
        let tail_fits = header[3] + block <= DATA_BYTES && advance(header[3], block) != header[2];
        let write = if header[3] >= header[2] && !tail_fits {
            0
        } else {
            header[3]
        };
        let next = advance(write, block);
        let available = count != 0
            && if header[3] < header[2] {
                block < header[2] - header[3]
            } else if write == 0 && header[3] != 0 {
                block < header[2]
            } else {
                next != header[2]
            };
        if !available {
            if !self.transmit_full {
                outbox.push(message(FULL, 0));
                self.transmit_full = true;
            }
            return Ok(false);
        }
        let mut bytes = alloc::vec![0; block as usize];
        bytes[..4].copy_from_slice(&QE_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        bytes[16] = self.sequence;
        bytes[18..20].copy_from_slice(&reply.interface.to_le_bytes());
        bytes[20..24].copy_from_slice(&(reply.bytes.len() as u32).to_le_bytes());
        bytes[24..24 + count].copy_from_slice(&remaining[..count]);
        if write != header[3] {
            bus.write(ring + RING_HEADER + u64::from(header[3]), &bytes[..16])?;
        }
        bus.write(ring + RING_HEADER + u64::from(write), &bytes)?;
        bus.write(ring + WPTR, &next.to_le_bytes())?;
        if reply.offset == 0 && reply.interface != 0 && reply.bytes.len() >= 16 {
            let response = reply.bytes[9] == 2 && reply.bytes.len() >= 24;
            self.seen.push_back(Event::Sent {
                interface: reply.interface,
                bytes: reply.bytes.len() as u32,
                packet_type: reply.bytes[8],
                category: reply.bytes[9],
                command_sequence: (matches!(reply.bytes[9], 1 | 2) && reply.bytes.len() >= 24)
                    .then(|| reply.bytes[17]),
                status: response
                    .then(|| i32::from_le_bytes(reply.bytes[20..24].try_into().expect("status"))),
            });
        }
        self.sequence = self.sequence.wrapping_add(1);
        let reply = self.reply.as_mut().expect("pending reply");
        reply.offset += count;
        if reply.offset == reply.bytes.len() {
            self.reply = None;
        }
        self.transmit_full = false;
        outbox.push(message(RECV, 0));
        // A split message owns the transmit stream until all fragments leave.
        self.flush_reply(bus, buffer, outbox)
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
        // The declared endpoint uses AFKEPV2: eight transport bytes,
        // then the sixteen-byte interface header. The packet type/category
        // are the first two bytes after the interface context64. Keep the
        // legacy EPIC diagnostic layout for explicitly refused nonzero
        // queue channels; it must not describe V2 packets as legacy EPIC.
        let mut sub = [0u8; 8];
        let epic = if size >= 24 && rptr + 40 <= RING_BYTES - RING_HEADER {
            bus.read(ring + RING_HEADER + rptr + 32, &mut sub)?;
            if field(8) == 0 && field(12) == 0 {
                Some((sub[1], u16::from(sub[0])))
            } else {
                Some((sub[5], u16::from_le_bytes([sub[6], sub[7]])))
            }
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

struct Pending {
    interface: u16,
    bytes: Vec<u8>,
    offset: usize,
}

impl Pending {
    fn new(interface: u16, bytes: Vec<u8>) -> Self {
        Self {
            interface,
            bytes,
            offset: 0,
        }
    }
}

fn entry_block(size: u32) -> Result<u32, &'static str> {
    let block = size
        .checked_add(16)
        .and_then(|size| size.checked_next_multiple_of(ENTRY_BLOCK))
        .ok_or("DCP AFK queue entry length overflow")?;
    if block >= DATA_BYTES {
        return Err("DCP AFK queue entry cannot fit in its ring");
    }
    Ok(block)
}

fn advance(pointer: u32, bytes: u32) -> u32 {
    let next = pointer + bytes;
    if next == DATA_BYTES { 0 } else { next }
}

fn next_pointer(pointer: u32) -> u32 {
    let next = pointer + ENTRY_BLOCK;
    if next == DATA_BYTES { 0 } else { next }
}

#[cfg(test)]
mod tests {
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
        fn handle(
            &mut self,
            packet_type: u8,
            bytes: &[u8],
        ) -> Result<(i32, Vec<u8>), &'static str> {
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
                name: "implemented-service",
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
        fn complete(
            &mut self,
            cookie: u64,
            status: i32,
            payload: Vec<u8>,
        ) -> Result<(), &'static str> {
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
                name: "client",
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
        fn complete(
            &mut self,
            cookie: u64,
            status: i32,
            bytes: Vec<u8>,
        ) -> Result<(), &'static str> {
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
                    name: "cancelling",
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
            // Repairing translation resumes retained transport writes, with no
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
}
