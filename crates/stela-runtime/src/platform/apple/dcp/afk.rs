//! The AFK ring-buffer transport the DCP's EPIC endpoints (0x20 system,
//! 0x24 DPAV, 0x2a DPTX port) run over RTKit, coprocessor side.
//!
//! Public description (both are AP-side implementations of the same
//! protocol): Asahi Linux `drivers/gpu/drm/apple/afk.c`/`afk.h` and m1n1
//! `src/afk.c`, `proxyclient/m1n1/fw/afk/rbep.py`. A message's type is
//! bits `[63:48]`:
//!
//! | Type | Direction | Meaning |
//! | --- | --- | --- |
//! | 0x80 `INIT` | AP | start the endpoint; 26A434 sends 0x100 |
//! | 0xa0 `INIT_ACK` | coprocessor | the endpoint is alive; `[15:0]` picks the ring layout |
//! | 0x89 `GETBUF` | coprocessor | lend me `[31:16]` 64-byte blocks, tag `[15:0]` |
//! | 0xa1 `GETBUF_ACK` | AP | the buffer's DVA in `[47:0]` |
//! | 0x8a `INIT_TX` / 0x8b `INIT_RX` | coprocessor | the AP-to-coprocessor / coprocessor-to-AP ring at block `[47:32]`, `[31:16]` blocks, tag `[15:0]` |
//! | 0xa3 `START` | AP | both rings accepted |
//! | 0x86 `START_ACK` | coprocessor | started |
//! | 0xa2 `SEND` / 0x85 `RECV` | AP / coprocessor | a ring's new write pointer in `[31:0]` |
//! | 0xc0 `SHUTDOWN` / 0xc1 `SHUTDOWN_ACK` | AP / coprocessor | stop |
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
//! `bufsz + 0x180` is the ring's size. Entries are a 16-byte `afk_qe`
//! (`' POI'` magic, size, channel, type) and an EPIC header, aligned to the
//! layout's 0x80 bytes.
//!
//! EPIC services are announced by the coprocessor (an `EPIC_SUBTYPE_ANNOUNCE`
//! report on a new channel, `afk_recv_handle_init`); the AP only talks to an
//! announced channel. This model brings the transport up and announces no
//! service: the DCP model drives its one display through the IOMFB link and
//! programs no DPTX PHY, DP AV or system service the AP would serve. An entry
//! the AP still sends refuses by name, with its channel, type and EPIC
//! category recorded in the display log.
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
pub const SEND: u64 = 0xa2;
pub const RECV: u64 = 0x85;
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

/// The message type of an AFK word.
pub fn kind(word: u64) -> u64 {
    word >> TYPE_SHIFT
}

fn message(kind: u64, value: u64) -> u64 {
    kind << TYPE_SHIFT | value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not started by the AP.
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
    /// What the endpoint saw, drained by the coprocessor's log.
    pub(super) seen: VecDeque<Event>,
}

impl Afk {
    pub fn new(endpoint: u8, name: &'static str, window: Option<u64>) -> Self {
        Self {
            endpoint,
            name,
            state: State::Stopped,
            window,
            incoming: VecDeque::new(),
            seen: VecDeque::new(),
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

    /// The AP sent `word`; what needs no memory is answered at once.
    pub fn receive(&mut self, word: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.seen.push_back(Event::Received(word));
        match (kind(word), self.state) {
            // The firmware would lay its rings out in 0x40-byte blocks while
            // its `INIT_ACK` tells the AP 0x80; no 26A434 AP asks for that.
            (INIT, State::Stopped) if word & 0xffff == SMALL_LAYOUT => {
                Err("DCP AFK INIT asks for the 0x40-byte ring layout")
            }
            (INIT, State::Stopped) => {
                self.state = State::Asked;
                outbox.push(message(INIT_ACK, INIT_ACK_VALUE));
                outbox.push(message(
                    GETBUF,
                    (BUFFER_BYTES >> BLOCK_SHIFT) << 16 | self.tag(),
                ));
                Ok(())
            }
            (INIT, _) => Err("DCP AFK INIT on an endpoint already started"),
            (GETBUF_ACK, State::Asked) | (SEND, State::Started { .. }) => {
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
            (SEND, _) => Err("DCP AFK SEND on an endpoint that has not started"),
            (SHUTDOWN, _) => {
                self.state = State::Stopped;
                self.incoming.clear();
                outbox.push(message(SHUTDOWN_ACK, 0));
                Ok(())
            }
            _ => Err("DCP AFK message type is not one the AP sends"),
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
                (SEND, State::Started { buffer }) => {
                    let entry = self.entry(bus, buffer)?;
                    self.seen.push_back(Event::Entry(entry));
                    return Err(
                        "DCP AFK endpoint announces no EPIC service, but the AP sent a ring entry",
                    );
                }
                _ => return Err("DCP AFK queued message no longer matches the endpoint"),
            }
        }
        Ok(())
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
        afk.receive(message(SEND, 0x80), &mut out).unwrap();
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
        afk.receive(message(SHUTDOWN, 0), &mut out).unwrap();
        assert_eq!(out, [SHUTDOWN_ACK << 48]);
        afk.receive(message(INIT, 0x100), &mut out).unwrap();
        assert_eq!(afk.seen.front(), Some(&Event::Received(START << 48)));
    }
}
