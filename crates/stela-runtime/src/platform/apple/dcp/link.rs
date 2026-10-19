//! The 26A434 `AppleDCPLinkService` wire protocol carried on RTKit endpoint
//! 0x37 of the `dcpext` coprocessor: the mailbox message word, and the
//! request header the AP and the DCP exchange through the shared region.
//!
//! Cited by kernel file offset (fileset VA = offset + 0xfffffe0007004000):
//! `link_send_message_priv` (0x3d7d4b4) packs the message word, `rpc_caller`/
//! `rpc_caller_gated` (0x3d7b004, 0x3d7cc3c) pack the request header into the
//! shared memory and `rpc_callee_gated` (0x3d7d830) services the reverse
//! direction. The DCP terminates at the AP boundary: the model answers the
//! AP's host calls (the "A" tags) and issues the callbacks (the "D" tags) a
//! real coprocessor would, without running `ipad14dcp` firmware.
//!
//! ## Message word (both directions)
//!
//! `link_send_message_priv` builds a 64-bit word from the message type, an
//! optional stream and the payload length:
//!
//! - bits `[1:0]`  type: 0 heap handshake, 1 state transition, 2 RPC message;
//! - bit  `6`      ACK/nested gating (`rpc_caller_gated` checks `& 0xc3 == 0x42`);
//! - bit  `8`      a stream index is present (`bfi x10, x8, #8, #1`);
//! - bits `[15:10]` the stream index (`ubfiz x9, x9, #10, #6`);
//! - bits `[63:16]` the payload length or offset.
//!
//! ## Request header (in the shared region, `rpc_caller_gated` 0x3d7cde4)
//!
//! 12 bytes, then the input then the output:
//!
//! - `[0:4]`   the method tag, a four-character code in a little-endian word
//!   (`A401` is `0x4134_3031`; its bytes spell the code reversed);
//! - `[4:8]`   the input length (LE `u32`);
//! - `[8:12]`  the output length (LE `u32`);
//! - `[12 ..]` the input, then the output, each slot advanced to a `0x40`
//!   multiple (`rpc_caller_gated` rounds `w25` up by `w8 = align - 1`).

/// The RTKit endpoint number of the IOMFB link service (DCPEXTEndpoint24,
/// personality `AppleDCPLinkServiceSoC`).
pub const IOMFB_ENDPOINT: u8 = 0x37;

const TYPE: u64 = 0x3;
const ACK: u64 = 1 << 6;
const STREAM_PRESENT: u64 = 1 << 8;
const STREAM_SHIFT: u32 = 10;
const STREAM: u64 = 0x3f << STREAM_SHIFT;
const LENGTH_SHIFT: u32 = 16;

/// The header occupies 12 bytes before the input payload.
pub const HEADER_BYTES: u32 = 12;
/// Each payload slot is advanced to this alignment.
pub const SLOT_ALIGN: u32 = 0x40;

/// One link message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Type 0: the AP announces its shared heap increment (`link_state_init`
    /// sends `(heap << 16) | 0x40`).
    Heap,
    /// Type 1: a state transition (`link_state_ready`, the init-state acks
    /// the AP's `message_handler` routes by bits `[7:6]`).
    State,
    /// Type 2: an RPC message carried in the shared region's streams.
    Message,
}

impl Kind {
    fn code(self) -> u64 {
        match self {
            Kind::Heap => 0,
            Kind::State => 1,
            Kind::Message => 2,
        }
    }

    fn of(code: u64) -> Option<Self> {
        match code {
            0 => Some(Kind::Heap),
            1 => Some(Kind::State),
            2 => Some(Kind::Message),
            _ => None,
        }
    }
}

/// A decoded link message word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Word {
    pub kind: Kind,
    pub ack: bool,
    pub stream: Option<u8>,
    /// The payload length (type 2) or the state/heap field (types 0, 1).
    pub length: u64,
}

impl Word {
    /// Decode a message word, or `None` for a type the protocol does not use.
    pub fn decode(word: u64) -> Option<Self> {
        let kind = Kind::of(word & TYPE)?;
        let stream = (word & STREAM_PRESENT != 0).then(|| ((word & STREAM) >> STREAM_SHIFT) as u8);
        Some(Self {
            kind,
            ack: word & ACK != 0,
            stream,
            length: word >> LENGTH_SHIFT,
        })
    }

    /// Encode this message to its 64-bit word.
    pub fn encode(self) -> u64 {
        let mut word = self.kind.code() | (self.length << LENGTH_SHIFT);
        if self.ack {
            word |= ACK;
        }
        if let Some(stream) = self.stream {
            word |= STREAM_PRESENT | (u64::from(stream) << STREAM_SHIFT);
        }
        word
    }
}

/// A parsed request header from the shared region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The method tag, a four-character code in a little-endian word.
    pub tag: u32,
    pub input_len: u32,
    pub output_len: u32,
}

impl Request {
    /// Parse the 12-byte header at the start of `bytes`.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header = bytes.get(..HEADER_BYTES as usize)?;
        let word = |range: core::ops::Range<usize>| {
            u32::from_le_bytes(header[range].try_into().expect("4 bytes"))
        };
        Some(Self {
            tag: word(0..4),
            input_len: word(4..8),
            output_len: word(8..12),
        })
    }

    /// The method's four-character code, the tag word's bytes reversed
    /// (`0x4134_3031` is `"A401"`).
    pub fn code(&self) -> [u8; 4] {
        let [a, b, c, d] = self.tag.to_le_bytes();
        [d, c, b, a]
    }

    /// The byte range of the input payload within the request's slot.
    pub fn input(&self) -> core::ops::Range<usize> {
        let start = HEADER_BYTES as usize;
        start..start + self.input_len as usize
    }

    /// The byte range of the output payload, after the input.
    pub fn output(&self) -> core::ops::Range<usize> {
        let start = HEADER_BYTES as usize + self.input_len as usize;
        start..start + self.output_len as usize
    }

    /// The bytes one request occupies: header, input and output, advanced to
    /// the slot alignment (`rpc_caller_gated`'s `link_shared_alloc`).
    pub fn slot_bytes(&self) -> u32 {
        (HEADER_BYTES + self.input_len + self.output_len).next_multiple_of(SLOT_ALIGN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_and_ready_words_match_the_driver() {
        // link_state_init: (heap << 16) | 0x40, a type-0 ACK message.
        let heap = Word::decode(0x40 | (0x1000 << 16)).unwrap();
        assert_eq!(heap.kind, Kind::Heap);
        assert!(heap.ack);
        assert_eq!(heap.stream, None);
        assert_eq!(heap.length, 0x1000);
        // link_state_ready: type 1 with a marker in the length field.
        let ready = Word::decode(0x0004_0000_0000_0001).unwrap();
        assert_eq!(ready.kind, Kind::State);
        assert_eq!(ready.encode(), 0x0004_0000_0000_0001);
    }

    #[test]
    fn a_message_word_round_trips_with_its_stream_and_length() {
        let word = Word {
            kind: Kind::Message,
            ack: true,
            stream: Some(2),
            length: 0x1d3c,
        };
        let encoded = word.encode();
        assert_eq!(encoded & TYPE, 2);
        assert_eq!(encoded & ACK, ACK);
        assert_eq!((encoded & STREAM) >> STREAM_SHIFT, 2);
        assert_eq!(Word::decode(encoded), Some(word));
    }

    #[test]
    fn a_header_parses_its_tag_code_and_payload_ranges() {
        // A401 start_signal: tag 0x41343031, in 0, out 4.
        let mut bytes = alloc::vec![0u8; 0x40];
        bytes[0..4].copy_from_slice(&0x4134_3031u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&4u32.to_le_bytes());
        let request = Request::parse(&bytes).unwrap();
        assert_eq!(&request.code(), b"A401");
        assert_eq!(request.input(), 12..12);
        assert_eq!(request.output(), 12..16);
        assert_eq!(request.slot_bytes(), SLOT_ALIGN);

        // A407 swap_submit_dcp: in 0x1d30, out 0xc rounds to three slots.
        let mut swap = alloc::vec![0u8; 16];
        swap[0..4].copy_from_slice(&u32::from_le_bytes(*b"704A").to_le_bytes());
        swap[4..8].copy_from_slice(&0x1d30u32.to_le_bytes());
        swap[8..12].copy_from_slice(&0xcu32.to_le_bytes());
        let swap = Request::parse(&swap).unwrap();
        assert_eq!(&swap.code(), b"A407");
        assert_eq!(
            swap.slot_bytes(),
            (12 + 0x1d30 + 0xc as u32).next_multiple_of(0x40)
        );
    }
}
