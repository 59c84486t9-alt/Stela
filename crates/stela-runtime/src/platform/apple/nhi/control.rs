//! Thunderbolt control packets at the checksummed raw-frame boundary.
//!
//! Original Read/Write constructors at b061518/b06ec98 emit big-endian
//! fields and CRC32C; Reset and Error use the same framing. See the original
//! address/source matrix in `docs/research/usb4-acio.md`. This codec supplies
//! no register values, routing decisions, reset completion or acknowledgments.
use crate::checksum::crc32c;
use alloc::vec::Vec;

const ROUTE_MASK: u64 = (1 << 54) - 1;
const REPLY: u32 = 1 << 31;
const ROUTE_HIGH: u32 = (1 << 22) - 1;
const ADDRESS_RESERVED: u32 = 7 << 29;
const MAX_BYTES: usize = 256;
const MAX_DATA_WORDS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Size,
    Checksum,
    Header,
    Address,
    Body,
    Framing,
    UnsupportedPdf(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub route: u64,
    pub reply: bool,
}
impl Header {
    fn words(self) -> Result<[u32; 2], Error> {
        if self.route & !ROUTE_MASK != 0 {
            return Err(Error::Header);
        }
        Ok([
            (self.route >> 32) as u32 | if self.reply { REPLY } else { 0 },
            self.route as u32,
        ])
    }
    fn decode(high: u32, low: u32) -> Result<Self, Error> {
        if high & !(ROUTE_HIGH | REPLY) != 0 {
            return Err(Error::Header);
        }
        Ok(Self {
            route: u64::from(high & ROUTE_HIGH) << 32 | u64::from(low),
            reply: high & REPLY != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Space {
    Hop = 0,
    Adapter = 1,
    Router = 2,
    Counter = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    /// Dword offset in the selected configuration space.
    pub offset: u16,
    pub length: u8,
    pub port: u8,
    pub space: Space,
    pub sequence: u8,
}
impl Address {
    fn word(self) -> Result<u32, Error> {
        if self.offset > 0x1fff
            || self.length > MAX_DATA_WORDS
            || self.port > 63
            || self.sequence > 3
        {
            return Err(Error::Address);
        }
        Ok(u32::from(self.offset)
            | u32::from(self.length) << 13
            | u32::from(self.port) << 19
            | (self.space as u32) << 25
            | u32::from(self.sequence) << 27)
    }
    fn decode(word: u32) -> Result<Self, Error> {
        if word & ADDRESS_RESERVED != 0 {
            return Err(Error::Address);
        }
        let address = Self {
            offset: (word & 0x1fff) as u16,
            length: ((word >> 13) & 63) as u8,
            port: ((word >> 19) & 63) as u8,
            space: match word >> 25 & 3 {
                0 => Space::Hop,
                1 => Space::Adapter,
                2 => Space::Router,
                _ => Space::Counter,
            },
            sequence: ((word >> 27) & 3) as u8,
        };
        address.word()?;
        Ok(address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Read {
        address: Address,
        data: Vec<u32>,
    },
    Write {
        address: Address,
        data: Vec<u32>,
    },
    Error {
        code: u8,
        port: u8,
        acknowledgement: u8,
    },
    NotificationAck,
    Plug {
        port: u8,
        unplug: bool,
    },
    Reset,
}
impl Body {
    pub fn pdf(&self) -> u8 {
        match self {
            Self::Read { .. } => 1,
            Self::Write { .. } => 2,
            Self::Error { .. } => 3,
            Self::NotificationAck => 4,
            Self::Plug { .. } => 5,
            Self::Reset => 9,
        }
    }
    fn words(&self, reply: bool) -> Result<Vec<u32>, Error> {
        match self {
            Self::Read { address, data } | Self::Write { address, data } => {
                let has_data = matches!(self, Self::Read { .. }) == reply;
                let expected = if has_data {
                    usize::from(address.length)
                } else {
                    0
                };
                if data.len() != expected {
                    return Err(Error::Body);
                }
                let mut words = Vec::with_capacity(1 + data.len());
                words.push(address.word()?);
                words.extend_from_slice(data);
                Ok(words)
            }
            Self::Error {
                code,
                port,
                acknowledgement,
            } => {
                if *port > 63 || *acknowledgement > 3 {
                    return Err(Error::Body);
                }
                Ok(vec![
                    u32::from(*code) | u32::from(*port) << 8 | u32::from(*acknowledgement) << 30,
                ])
            }
            Self::Plug { port, unplug } => {
                if *port > 63 {
                    return Err(Error::Body);
                }
                Ok(vec![u32::from(*port) | u32::from(*unplug) << 31])
            }
            Self::NotificationAck | Self::Reset => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub body: Body,
}

/// Raw control-frame bytes including their checksum. SOF is supplied by the
/// transmitter; original AP requests use the PDF, router responses use zero.
/// Keeping it explicit avoids confusing a valid reply's SOF with its EOF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub sof: u8,
    pub eof: u8,
}
impl Packet {
    pub fn encode(&self, sof: u8) -> Result<Encoded, Error> {
        let eof = self.body.pdf();
        if sof != 0 && sof != eof {
            return Err(Error::Framing);
        }
        let mut bytes = Vec::new();
        for word in self
            .header
            .words()?
            .into_iter()
            .chain(self.body.words(self.header.reply)?)
        {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        if bytes.len() + 4 > MAX_BYTES {
            return Err(Error::Size);
        }
        bytes.extend_from_slice(&crc32c(&bytes).to_be_bytes());
        Ok(Encoded { bytes, sof, eof })
    }
    pub fn decode(bytes: &[u8], sof: u8, eof: u8) -> Result<Self, Error> {
        if !(12..=MAX_BYTES).contains(&bytes.len()) || !bytes.len().is_multiple_of(4) {
            return Err(Error::Size);
        }
        if sof != 0 && sof != eof {
            return Err(Error::Framing);
        }
        let payload = &bytes[..bytes.len() - 4];
        let word = |n: usize| u32::from_be_bytes(bytes[n * 4..n * 4 + 4].try_into().unwrap());
        if crc32c(payload) != word(bytes.len() / 4 - 1) {
            return Err(Error::Checksum);
        }
        let header = Header::decode(word(0), word(1))?;
        let words = payload.len() / 4;
        let body = match eof {
            1 | 2 => {
                if words < 3 {
                    return Err(Error::Body);
                }
                let address = Address::decode(word(2))?;
                let has_data = (eof == 1) == header.reply;
                if words
                    != 3 + if has_data {
                        usize::from(address.length)
                    } else {
                        0
                    }
                {
                    return Err(Error::Body);
                }
                let data = (3..words).map(word).collect();
                if eof == 1 {
                    Body::Read { address, data }
                } else {
                    Body::Write { address, data }
                }
            }
            3 if words == 3 => {
                let fields = word(2);
                if fields & 0x3fff_c000 != 0 {
                    return Err(Error::Body);
                }
                Body::Error {
                    code: fields as u8,
                    port: ((fields >> 8) & 63) as u8,
                    acknowledgement: (fields >> 30) as u8,
                }
            }
            4 if words == 2 => Body::NotificationAck,
            5 if words == 3 => {
                let fields = word(2);
                if fields & 0x7fff_ffc0 != 0 {
                    return Err(Error::Body);
                }
                Body::Plug {
                    port: (fields & 63) as u8,
                    unplug: fields >> 31 != 0,
                }
            }
            9 if words == 2 => Body::Reset,
            1..=5 | 9 => return Err(Error::Body),
            pdf => return Err(Error::UnsupportedPdf(pdf)),
        };
        Ok(Self { header, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address() -> Address {
        Address {
            offset: 0,
            length: 1,
            port: 0,
            space: Space::Router,
            sequence: 0,
        }
    }
    fn packet(reply: bool, body: Body) -> Packet {
        Packet {
            header: Header { route: 0, reply },
            body,
        }
    }
    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |c: u8| match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    _ => panic!("bad fixture"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }
    #[test]
    fn original_table_fixtures_fix_endianness_crc_and_read_direction() {
        // Calculated independently using the original table at cc231e0.
        let request_bytes = bytes("0000000000000000040020002fc967ac");
        let request = packet(
            false,
            Body::Read {
                address: address(),
                data: vec![],
            },
        );
        assert_eq!(request.encode(1).unwrap().bytes, request_bytes);
        assert_eq!(Packet::decode(&request_bytes, 1, 1).unwrap(), request);
        let response_bytes = bytes("800000000000000004002000112233443feac9d7");
        let response = packet(
            true,
            Body::Read {
                address: address(),
                data: vec![0x11223344],
            },
        );
        assert_eq!(response.encode(0).unwrap().bytes, response_bytes);
        assert_eq!(Packet::decode(&response_bytes, 0, 1).unwrap(), response);
        assert_eq!(
            packet(false, Body::Reset).encode(9).unwrap().bytes,
            bytes("00000000000000008c28b28a")
        );
    }
    #[test]
    fn write_fields_and_payload_are_not_truncated_or_reinterpreted() {
        let address = Address {
            offset: 0x123,
            length: 2,
            port: 35,
            space: Space::Adapter,
            sequence: 3,
        };
        let request = packet(
            false,
            Body::Write {
                address,
                data: vec![0xdeadbeef, 0x01020304],
            },
        );
        let wire = request.encode(2).unwrap();
        assert_eq!(
            wire.bytes,
            bytes("00000000000000001b184123deadbeef0102030482137f9c")
        );
        assert_eq!(Packet::decode(&wire.bytes, 2, 2).unwrap(), request);
        let response = packet(
            true,
            Body::Write {
                address,
                data: vec![],
            },
        );
        let wire = response.encode(0).unwrap();
        assert_eq!(wire.bytes.len(), 16);
        assert_eq!(Packet::decode(&wire.bytes, 0, 2).unwrap(), response);
        assert!(
            packet(
                true,
                Body::Write {
                    address,
                    data: vec![1, 2]
                }
            )
            .encode(0)
            .is_err()
        );
    }
    #[test]
    fn framing_corruption_and_reserved_fields_are_explicit_errors() {
        let request = packet(
            false,
            Body::Read {
                address: address(),
                data: vec![],
            },
        );
        let wire = request.encode(1).unwrap();
        for i in 0..wire.bytes.len() {
            let mut damaged = wire.bytes.clone();
            damaged[i] ^= 1;
            assert_eq!(Packet::decode(&damaged, 1, 1), Err(Error::Checksum));
        }
        assert_eq!(Packet::decode(&wire.bytes, 2, 1), Err(Error::Framing));
        let mut reserved = wire.bytes.clone();
        reserved[0] = 1;
        let crc = crc32c(&reserved[..12]);
        reserved[12..].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(Packet::decode(&reserved, 1, 1), Err(Error::Header));
        reserved = wire.bytes.clone();
        reserved[8] |= 0x20;
        let crc = crc32c(&reserved[..12]);
        reserved[12..].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(Packet::decode(&reserved, 1, 1), Err(Error::Address));
        assert_eq!(
            Packet::decode(&wire.bytes, 0, 8),
            Err(Error::UnsupportedPdf(8))
        );
        assert_eq!(Packet::decode(&wire.bytes[..15], 1, 1), Err(Error::Size));
        assert_eq!(Packet::decode(&wire.bytes, 0, 9), Err(Error::Body));
    }
    #[test]
    fn notifications_and_acknowledgements_preserve_wire_error_fields() {
        for body in [
            Body::Error {
                code: 7,
                port: 63,
                acknowledgement: 3,
            },
            Body::Plug {
                port: 17,
                unplug: true,
            },
            Body::NotificationAck,
        ] {
            let packet = packet(true, body);
            let wire = packet.encode(0).unwrap();
            if wire.eof == 3 {
                assert_eq!(&wire.bytes[8..12], &[0xc0, 0, 0x3f, 7]);
            }
            if wire.eof == 5 {
                assert_eq!(&wire.bytes[8..12], &[0x80, 0, 0, 17]);
            }
            assert_eq!(
                Packet::decode(&wire.bytes, wire.sof, wire.eof).unwrap(),
                packet
            );
        }
        let mut bad = packet(false, Body::Reset);
        bad.header.route = 1 << 54;
        assert_eq!(bad.encode(9), Err(Error::Header));
        assert_eq!(
            packet(
                false,
                Body::Error {
                    code: 0,
                    port: 64,
                    acknowledgement: 0
                }
            )
            .encode(3),
            Err(Error::Body)
        );
    }
    #[test]
    fn maximum_data_frame_and_zero_length_have_distinct_valid_encodings() {
        let mut addr = address();
        addr.length = 60;
        addr.offset = 8191;
        addr.port = 63;
        addr.sequence = 3;
        let mut request = packet(
            false,
            Body::Write {
                address: addr,
                data: (0..60).collect(),
            },
        );
        request.header.route = (1 << 54) - 1;
        let wire = request.encode(2).unwrap();
        assert_eq!(wire.bytes.len(), 256);
        assert_eq!(Packet::decode(&wire.bytes, 2, 2).unwrap(), request);
        addr.length = 0;
        let empty = packet(
            false,
            Body::Write {
                address: addr,
                data: vec![],
            },
        );
        assert_eq!(empty.encode(2).unwrap().bytes.len(), 16);
        addr.length = 61;
        assert_eq!(
            packet(
                false,
                Body::Read {
                    address: addr,
                    data: vec![]
                }
            )
            .encode(1),
            Err(Error::Address)
        );
    }
}
