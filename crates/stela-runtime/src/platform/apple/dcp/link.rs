//! The 26A434 `AppleDCPLinkService` wire protocol on RTKit endpoint 0x37 of
//! the `dcpext` coprocessor: the mailbox message word, the shared region's
//! layout and the call header. Both sides run the same link library; the
//! AP's copy is cited by kernel file offset (fileset VA = offset +
//! 0xfffffe0007004000).
//!
//! ## Message word (`link_send_message_priv` 0x3d7d4b4)
//!
//! - bits `[1:0]` type: 0 link set-up, 1 ready, 2 RPC;
//! - bits `[7:6]` subtype: for type 0, 0 is the coprocessor's hello and 1
//!   the AP's region announcement; for type 2, 0 is a call and 1 its answer;
//! - bit `8` the stream's owner: the side whose `link_state +0x70` is set,
//!   0 on the AP, so a stream the AP opens has owner 0 and one the
//!   coprocessor opens owner 1 (the sender ORs in the stream's own owner);
//! - bit `9` the call opens its stream (`rpc_caller` passes the
//!   newly-claimed flag of `link_get_stream_by_thread_id_gated` 0x3d7d134);
//! - bits `[15:10]` the stream index, below [`STREAMS`]
//!   (`link_get_stream_by_stream_uid_gated` 0x3d7ed20 panics otherwise);
//! - type 2: bits `[31:16]` the payload's offset in the sender's stream
//!   buffer, `[47:32]` its length and `[63:48]` a token the answer echoes;
//!   type 0 and 1: bits `[63:16]` their value.
//!
//! A type-2 call must carry a length (`link_send_message_priv` panics
//! otherwise). An answer is the call's word with bit 0 and the subtype
//! cleared, subtype 1 set and offset and length zero
//! (`rpc_callee_gated` 0x3d7dad0: `word & 0xff3e | 0x40 | token << 48`);
//! `rpc_caller_gated` (0x3d7cc3c) refuses an answer with a payload.
//!
//! ## Bring-up
//!
//! The coprocessor says hello with its interface version (type 0, subtype
//! 0, value [`VERSION`], checked by the AP's handler 0x3d7e47c when the
//! `iomfb_version_check` boot-arg is set). The AP's `link_state_init`
//! (0x3d7c7a0) writes the [`RegionHeader`] at the start of its region and
//! announces the region's DVA (type 0, subtype 1). The coprocessor answers
//! ready (type 1): bits `[47:16]` the interface CRC the AP compares with its
//! own and panics on, bits `[63:48]` the payload alignment both sides then
//! allocate with (the AP keeps it at `link_state +0x48`, at least 4).
//!
//! ## Shared region (`AppleDCPLinkService::start` 0x3d7b470 allocates
//! 0xc0000 bytes; its gated `$_0` 0x3d7ddf0 lays them out)
//!
//! Each side owns [`STREAMS`] streams of two 0x8000-byte buffers: one it
//! writes its calls and nested calls into, one the other side writes the
//! calls nested inside them. The AP writes the lower half, the coprocessor
//! the upper; the rest is shared variables.
//!
//! | Offset | Writer | Contents |
//! | --- | --- | --- |
//! | 0x00000 + i·0x8000 | AP | AP stream i: the AP's calls |
//! | 0x20000 + i·0x8000 | AP | coprocessor stream i: the AP's calls nested in its calls |
//! | 0x40000 + i·0x8000 | coprocessor | coprocessor stream i: its calls |
//! | 0x60000 + i·0x8000 | coprocessor | AP stream i: its calls nested in the AP's |
//! | 0x80000 | both | shared variables (0x40000 bytes) |
//!
//! ## Call payload (`rpc_caller_gated`, `rpc_callee_gated` 0x3d7d830)
//!
//! A 12-byte header (the method tag as a big-endian four-character code in
//! a little-endian word, the input length, the output length), the input,
//! then room for the output, which the callee writes in place. The length
//! in the message word is exactly `12 + input + output`.

/// The RTKit endpoint of the IOMFB link service (DCPEXTEndpoint24,
/// personality `AppleDCPLinkServiceSoC`).
pub const IOMFB_ENDPOINT: u8 = 0x37;

/// The interface version of the 26A434 link library (the AP's global at
/// kernel file offset 0x5bd9bd8).
pub const VERSION: u32 = 211;
/// The payload alignment the coprocessor announces. The AP allocates its
/// calls at multiples of it; the interface leaves the value to the
/// coprocessor (the AP only raises one below 4), and 0x40 is a cache line.
pub const ALIGNMENT: u16 = 0x40;

/// Streams per side.
pub const STREAMS: u8 = 4;
/// One stream buffer.
pub const STREAM_BYTES: u32 = 0x8000;
/// The whole region the AP allocates.
pub const REGION_BYTES: u64 = 0xc0000;
const AP_CALLS: u64 = 0;
const AP_NESTED: u64 = 0x20000;
const DCP_CALLS: u64 = 0x40000;
const DCP_NESTED: u64 = 0x60000;
/// The shared-variable area and its size.
pub const SHARED: u64 = 0x80000;
pub const SHARED_BYTES: u64 = 0x40000;

/// The call header's size.
pub const HEADER_BYTES: u32 = 12;

const TYPE: u64 = 0x3;
const SUBTYPE_SHIFT: u32 = 6;
const OWNER: u64 = 1 << 8;
const OPENS: u64 = 1 << 9;
const INDEX_SHIFT: u32 = 10;
const INDEX: u64 = 0x3f << INDEX_SHIFT;
const VALUE_SHIFT: u32 = 16;
const OFFSET_SHIFT: u32 = 16;
const LENGTH_SHIFT: u32 = 32;
const TOKEN_SHIFT: u32 = 48;
const FIELD: u64 = 0xffff;

/// The interface CRC the AP checks the ready message against: CRC-32 of
/// the version's four bytes, extended by the empty interface string the
/// 26A434 AP hashes after them (handler 0x3d7e528).
pub fn interface_crc() -> u32 {
    crate::payload::gpt::crc32(&VERSION.to_le_bytes())
}

/// Which side owns a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Owner {
    Ap,
    Dcp,
}

/// One stream, by owner and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stream {
    pub owner: Owner,
    pub index: u8,
}

impl Stream {
    /// The region offset of the buffer the owner writes its calls into.
    pub fn calls(self) -> u64 {
        let base = match self.owner {
            Owner::Ap => AP_CALLS,
            Owner::Dcp => DCP_CALLS,
        };
        base + u64::from(self.index) * u64::from(STREAM_BYTES)
    }

    /// The region offset of the buffer the other side writes the calls it
    /// nests inside the owner's into.
    pub fn nested(self) -> u64 {
        let base = match self.owner {
            Owner::Ap => DCP_NESTED,
            Owner::Dcp => AP_NESTED,
        };
        base + u64::from(self.index) * u64::from(STREAM_BYTES)
    }

    /// The region offset of the buffer `writer` writes its calls on this
    /// stream into.
    pub fn buffer_of(self, writer: Owner) -> u64 {
        if writer == self.owner {
            self.calls()
        } else {
            self.nested()
        }
    }
}

/// A decoded message word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Word {
    /// The coprocessor's hello with its interface version.
    Hello { version: u64 },
    /// The AP's region announcement with the region's DVA.
    Region { dva: u64 },
    /// Ready, with the interface CRC and the payload alignment.
    Ready { crc: u32, alignment: u16 },
    /// An RPC call or answer.
    Rpc(Rpc),
}

/// A type-2 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rpc {
    pub answer: bool,
    pub stream: Stream,
    pub opens: bool,
    pub offset: u16,
    pub length: u16,
    pub token: u16,
}

impl Word {
    /// Decode a word, or say why it is not one the link library sends.
    pub fn decode(word: u64) -> Result<Self, &'static str> {
        let subtype = (word >> SUBTYPE_SHIFT) & 3;
        match (word & TYPE, subtype) {
            (0, 0) => Ok(Word::Hello {
                version: word >> VALUE_SHIFT,
            }),
            (0, 1) => Ok(Word::Region {
                dva: word >> VALUE_SHIFT,
            }),
            (0, _) => Err("DCP link set-up message has an unknown subtype"),
            (1, _) => Ok(Word::Ready {
                crc: (word >> VALUE_SHIFT) as u32,
                alignment: (word >> TOKEN_SHIFT) as u16,
            }),
            (2, 0 | 1) => {
                let index = ((word & INDEX) >> INDEX_SHIFT) as u8;
                if index >= STREAMS {
                    return Err("DCP link message names a stream past the fourth");
                }
                Ok(Word::Rpc(Rpc {
                    answer: subtype == 1,
                    stream: Stream {
                        owner: if word & OWNER != 0 {
                            Owner::Dcp
                        } else {
                            Owner::Ap
                        },
                        index,
                    },
                    opens: word & OPENS != 0,
                    offset: (word >> OFFSET_SHIFT & FIELD) as u16,
                    length: (word >> LENGTH_SHIFT & FIELD) as u16,
                    token: (word >> TOKEN_SHIFT) as u16,
                }))
            }
            (2, _) => Err("DCP link RPC message has an unknown subtype"),
            _ => Err("DCP link message type 3 is not one the link library sends"),
        }
    }

    /// The word the coprocessor sends: every word it sends outside a
    /// stream carries its own owner bit, as `link_send_message_priv` ORs
    /// in `link_state +0x70`.
    pub fn encode(self) -> u64 {
        match self {
            Word::Hello { version } => OWNER | version << VALUE_SHIFT,
            Word::Region { dva } => 1 << SUBTYPE_SHIFT | dva << VALUE_SHIFT,
            Word::Ready { crc, alignment } => {
                1 | OWNER | u64::from(crc) << VALUE_SHIFT | u64::from(alignment) << TOKEN_SHIFT
            }
            Word::Rpc(rpc) => {
                let mut word = 2
                    | u64::from(rpc.answer) << SUBTYPE_SHIFT
                    | u64::from(rpc.stream.index) << INDEX_SHIFT
                    | u64::from(rpc.offset) << OFFSET_SHIFT
                    | u64::from(rpc.length) << LENGTH_SHIFT
                    | u64::from(rpc.token) << TOKEN_SHIFT;
                if rpc.stream.owner == Owner::Dcp {
                    word |= OWNER;
                }
                if rpc.opens {
                    word |= OPENS;
                }
                word
            }
        }
    }
}

impl Rpc {
    /// The answer to this call, as `rpc_callee_gated` forms it.
    pub fn answer(self) -> Self {
        Rpc {
            answer: true,
            offset: 0,
            length: 0,
            ..self
        }
    }
}

/// The 16 bytes `link_state_init` writes at the start of the region: the
/// DVA and size of the heap the AP lends the coprocessor (64 MiB under the
/// `iomfb_add_heap_in_ios` boot-arg, else none) and a constant 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionHeader {
    pub heap: u64,
    pub heap_bytes: u32,
    pub version: u32,
}

impl RegionHeader {
    pub const BYTES: usize = 16;

    pub fn parse(bytes: &[u8; Self::BYTES]) -> Result<Self, &'static str> {
        let header = Self {
            heap: u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes")),
            heap_bytes: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            version: u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes")),
        };
        if header.version != 4 {
            return Err("DCP link region header is not link_state_init's version 4");
        }
        Ok(header)
    }
}

/// A call's 12-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub tag: [u8; 4],
    pub input: u32,
    pub output: u32,
}

impl Header {
    pub fn parse(bytes: &[u8; HEADER_BYTES as usize]) -> Self {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        Self {
            tag: word(0).to_be_bytes(),
            input: word(4),
            output: word(8),
        }
    }

    pub fn bytes(&self) -> [u8; HEADER_BYTES as usize] {
        let mut bytes = [0; HEADER_BYTES as usize];
        bytes[0..4].copy_from_slice(&u32::from_be_bytes(self.tag).to_le_bytes());
        bytes[4..8].copy_from_slice(&self.input.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.output.to_le_bytes());
        bytes
    }

    /// The whole payload: header, input and output, or `None` when it does
    /// not fit a message word's length field.
    pub fn length(&self) -> Option<u16> {
        HEADER_BYTES
            .checked_add(self.input)?
            .checked_add(self.output)
            .and_then(|length| u16::try_from(length).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_crc_is_the_26a434_value() {
        assert_eq!(interface_crc(), 0x15a5_c96b);
    }

    #[test]
    fn set_up_words_match_the_ap_library() {
        // link_state_init: 0x40 | dva << 16, from the AP (owner 0).
        assert_eq!(
            Word::decode(0x40 | 0x8_0123_4000 << 16),
            Ok(Word::Region { dva: 0x8_0123_4000 })
        );
        assert_eq!(Word::Region { dva: 0x4000 }.encode(), 0x40 | 0x4000 << 16);
        // The coprocessor's hello and ready carry its owner bit.
        assert_eq!(Word::Hello { version: 211 }.encode(), 0x100 | 211 << 16);
        let ready = Word::Ready {
            crc: 0x15a5_c96b,
            alignment: 0x40,
        };
        assert_eq!(ready.encode(), 0x0040_15a5_c96b_0101);
        assert_eq!(Word::decode(ready.encode()), Ok(ready));
        // The AP's own link_state_ready word (sent only by owner 1).
        assert_eq!(
            Word::decode(1 | 4 << 48),
            Ok(Word::Ready {
                crc: 0,
                alignment: 4
            })
        );
    }

    #[test]
    fn an_rpc_word_round_trips_and_answers_as_rpc_callee_gated_does() {
        let call = Rpc {
            answer: false,
            stream: Stream {
                owner: Owner::Ap,
                index: 2,
            },
            opens: true,
            offset: 0x1c0,
            length: 0x1d48,
            token: 0,
        };
        let word = Word::Rpc(call).encode();
        assert_eq!(word, 2 | 1 << 9 | 2 << 10 | 0x1c0 << 16 | 0x1d48 << 32);
        assert_eq!(Word::decode(word), Ok(Word::Rpc(call)));
        // word & 0xff3e | 0x40 | token << 48
        assert_eq!(Word::Rpc(call.answer()).encode(), word & 0xff3e | 0x40);
        let callback = Rpc {
            stream: Stream {
                owner: Owner::Dcp,
                index: 3,
            },
            token: 0x1234,
            ..call
        };
        let word = Word::Rpc(callback).encode();
        assert_eq!(word & 0x100, 0x100);
        assert_eq!(
            Word::Rpc(callback.answer()).encode(),
            word & 0xff3e | 0x40 | 0x1234 << 48
        );
        assert!(Word::decode(2 | 4 << 10).is_err());
        assert!(Word::decode(2 | 2 << 6).is_err());
        assert!(Word::decode(3).is_err());
    }

    #[test]
    fn stream_buffers_follow_the_start_layout() {
        let ap = |index| Stream {
            owner: Owner::Ap,
            index,
        };
        let dcp = |index| Stream {
            owner: Owner::Dcp,
            index,
        };
        assert_eq!(ap(0).calls(), 0);
        assert_eq!(ap(3).calls(), 0x18000);
        assert_eq!(ap(1).nested(), 0x68000);
        assert_eq!(dcp(1).calls(), 0x48000);
        assert_eq!(dcp(2).nested(), 0x30000);
        assert_eq!(dcp(2).buffer_of(Owner::Ap), 0x30000);
        assert_eq!(ap(2).buffer_of(Owner::Dcp), 0x70000);
        assert!(dcp(3).calls() + u64::from(STREAM_BYTES) <= DCP_NESTED);
        assert_eq!(SHARED + SHARED_BYTES, REGION_BYTES);
    }

    #[test]
    fn a_header_is_a_big_endian_tag_in_a_little_endian_word() {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&0x4134_3031u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&4u32.to_le_bytes());
        let header = Header::parse(&bytes);
        assert_eq!(&header.tag, b"A401");
        assert_eq!((header.input, header.output), (0, 4));
        assert_eq!(header.bytes(), bytes);
        assert_eq!(header.length(), Some(16));
        let huge = Header {
            input: 0xfff8,
            ..header
        };
        assert_eq!(huge.length(), None);
    }

    #[test]
    fn the_region_header_is_link_state_inits() {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&0x8_1000_0000u64.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x400_0000u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&4u32.to_le_bytes());
        let header = RegionHeader::parse(&bytes).unwrap();
        assert_eq!(header.heap_bytes, 0x400_0000);
        bytes[12] = 5;
        assert!(RegionHeader::parse(&bytes).is_err());
    }
}
