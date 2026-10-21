// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Bounded raw NHI configuration packets adapted from Linux ctl.c/tb_msgs.h.
//! Wire dwords and CRC are big endian; the DMA descriptor is little endian.
use alloc::vec::Vec;

pub const FRAME_BYTES: usize = 256;
pub const MAX_CONFIG_WORDS: usize = (FRAME_BYTES - 4 - 12) / 4;
const ROUTE_MASK: u64 = (1 << 54) - 1;
const ROUTE_HIGH_MASK: u32 = (1 << 22) - 1;
const REPLY: u32 = 1 << 31;
const ADDRESS_LIMIT: u16 = 1 << 13;
const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Read = 1,
    Write = 2,
    Error = 3,
    NotifyAck = 4,
    Event = 5,
    Reset = 9,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Error),
            4 => Ok(Self::NotifyAck),
            5 => Ok(Self::Event),
            9 => Ok(Self::Reset),
            _ => Err(Error::UnsupportedPacket(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Space {
    Hops = 0,
    Port = 1,
    Router = 2,
    Counters = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Route,
    Address,
    Length,
    Sequence,
    Checksum,
    Header,
    FrameMarkers,
    UnexpectedReply,
    UnsupportedPacket(u8),
}

/// A validated router route; upper reserved bits are never silently truncated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route(u64);
impl Route {
    pub fn new(raw: u64) -> Result<Self, Error> {
        if raw & !ROUTE_MASK != 0 {
            return Err(Error::Route);
        }
        Ok(Self(raw))
    }
    pub fn raw(self) -> u64 {
        self.0
    }
    fn header(self) -> [u32; 2] {
        [(self.0 >> 32) as u32, self.0 as u32]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub port: u8,
    pub space: Space,
    pub offset: u16,
    pub words: u8,
}
impl Address {
    fn validate(self) -> Result<(), Error> {
        if self.port >= 64
            || self.offset >= ADDRESS_LIMIT
            || usize::from(self.words) > MAX_CONFIG_WORDS
            || self.words == 0
            || self
                .offset
                .checked_add(u16::from(self.words))
                .is_none_or(|end| end > ADDRESS_LIMIT)
        {
            return Err(Error::Address);
        }
        Ok(())
    }
    fn word(self, sequence: u8) -> u32 {
        u32::from(self.offset)
            | (u32::from(self.words) << 13)
            | (u32::from(self.port) << 19)
            | ((self.space as u32) << 25)
            | (u32::from(sequence) << 27)
    }
}

/// An encoded raw-control frame, including its actual four-byte CRC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub kind: PacketType,
    pub bytes: Vec<u8>,
}

fn encode(kind: PacketType, words: &[u32]) -> Result<Encoded, Error> {
    if words.len() * 4 + 4 > FRAME_BYTES {
        return Err(Error::Length);
    }
    let mut bytes = Vec::with_capacity(words.len() * 4 + 4);
    for word in words {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bytes.extend_from_slice(&crc32c(&bytes).to_be_bytes());
    Ok(Encoded { kind, bytes })
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (CRC32C_POLYNOMIAL & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// One exact outstanding operation. A transport must stop accepting replies
/// after cancellation and drain/reset before reusing an ambiguous sequence.
/// Serialize requests across the entire control channel: error packets lack
/// an address/sequence and can originate at an intermediate router.
#[derive(Clone, Debug)]
pub struct Request {
    route: Route,
    kind: PacketType,
    address: Option<Address>,
    sequence: u8,
    frame: Encoded,
}

impl Request {
    pub fn read(route: Route, address: Address, sequence: u8) -> Result<Self, Error> {
        Self::configuration(route, address, sequence, None)
    }
    pub fn write(
        route: Route,
        address: Address,
        sequence: u8,
        data: &[u32],
    ) -> Result<Self, Error> {
        if data.len() != usize::from(address.words) {
            return Err(Error::Length);
        }
        Self::configuration(route, address, sequence, Some(data))
    }
    fn configuration(
        route: Route,
        address: Address,
        sequence: u8,
        data: Option<&[u32]>,
    ) -> Result<Self, Error> {
        address.validate()?;
        if sequence > 3 {
            return Err(Error::Sequence);
        }
        let header = route.header();
        let mut words = vec![header[0], header[1], address.word(sequence)];
        let kind = if let Some(data) = data {
            words.extend_from_slice(data);
            PacketType::Write
        } else {
            PacketType::Read
        };
        Ok(Self {
            route,
            kind,
            address: Some(address),
            sequence,
            frame: encode(kind, &words)?,
        })
    }
    pub fn reset(route: Route) -> Self {
        Self {
            route,
            kind: PacketType::Reset,
            address: None,
            sequence: 0,
            frame: encode(PacketType::Reset, &route.header()).expect("fixed header"),
        }
    }
    pub fn frame(&self) -> &Encoded {
        &self.frame
    }

    /// A reply's reported upstream port need not equal the request port.
    /// Route, sequence, space, offset, length, exact framing and CRC must match.
    pub fn reply(&self, frame: &Received<'_>) -> Result<Reply, Error> {
        let words = frame.words()?;
        if words.len() < 2 || words[0] & !ROUTE_HIGH_MASK != REPLY {
            return Err(Error::Header);
        }
        let route =
            Route::new((u64::from(words[0] & ROUTE_HIGH_MASK) << 32) | u64::from(words[1]))?;
        if frame.kind == PacketType::Error {
            if words.len() != 3 {
                return Err(Error::Length);
            }
            if asynchronous_error(words[2] as u8) {
                return Err(Error::UnexpectedReply);
            }
            // A real error may originate at an upstream router on the path.
            return Ok(Reply::ControllerError {
                route,
                port: ((words[2] >> 8) & 63) as u8,
                code: words[2] as u8,
                packet_group: (words[2] >> 30) as u8,
                raw: words[2],
            });
        }
        if route != self.route {
            return Err(Error::UnexpectedReply);
        }
        if frame.kind != self.kind {
            return Err(Error::UnexpectedReply);
        }
        let Some(address) = self.address else {
            if words.len() != 2 {
                return Err(Error::Length);
            }
            return Ok(Reply::Reset);
        };
        let expected = 3 + if self.kind == PacketType::Read {
            usize::from(address.words)
        } else {
            0
        };
        if words.len() != expected {
            return Err(Error::Length);
        }
        let value = words[2];
        if value >> 29 != 0
            || ((value >> 27) & 3) != u32::from(self.sequence)
            || value & 0x1fff != u32::from(address.offset)
            || (value >> 13) & 63 != u32::from(address.words)
            || (value >> 25) & 3 != address.space as u32
        {
            return Err(Error::UnexpectedReply);
        }
        Ok(Reply::Configuration {
            upstream_port: ((value >> 19) & 63) as u8,
            data: words[3..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Configuration {
        upstream_port: u8,
        data: Vec<u32>,
    },
    ControllerError {
        route: Route,
        port: u8,
        code: u8,
        packet_group: u8,
        raw: u32,
    },
    Reset,
}

/// Raw received NHI control packet. DMA-completion ownership is established
/// by the ring before constructing this bounded view.
pub struct Received<'a> {
    pub kind: PacketType,
    pub sof: u8,
    pub bytes: &'a [u8],
}
impl Received<'_> {
    fn words(&self) -> Result<Vec<u32>, Error> {
        if self.sof != 0 {
            return Err(Error::FrameMarkers);
        }
        if self.bytes.len() < 12
            || self.bytes.len() > FRAME_BYTES
            || !self.bytes.len().is_multiple_of(4)
        {
            return Err(Error::Length);
        }
        let (data, checksum) = self.bytes.split_at(self.bytes.len() - 4);
        if crc32c(data).to_be_bytes() != checksum {
            return Err(Error::Checksum);
        }
        Ok(data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_be_bytes(*b))
            .collect())
    }
    pub fn event(&self) -> Result<PlugEvent, Error> {
        if self.kind != PacketType::Event {
            return Err(Error::UnexpectedReply);
        }
        let words = self.words()?;
        if words.len() != 3 || words[2] & 0x7fff_ffc0 != 0 {
            return Err(Error::Header);
        }
        Ok(PlugEvent {
            route: Route::new((u64::from(words[0] & ROUTE_HIGH_MASK) << 32) | u64::from(words[1]))?,
            port: (words[2] & 63) as u8,
            unplug: words[2] >> 31 != 0,
            header_flags: (words[0] >> 22) as u16,
        })
    }

    /// Notifications are delivered to the connection manager, never used as
    /// successful completion of the outstanding configuration request.
    pub fn notification_error(&self) -> Result<Option<NotificationError>, Error> {
        if self.kind != PacketType::Error {
            return Ok(None);
        }
        let words = self.words()?;
        if words.len() != 3 {
            return Err(Error::Header);
        }
        let code = words[2] as u8;
        if !asynchronous_error(code) {
            return Ok(None);
        }
        Ok(Some(NotificationError {
            header_flags: (words[0] >> 22) as u16,
            route: Route::new((u64::from(words[0] & ROUTE_HIGH_MASK) << 32) | u64::from(words[1]))?,
            port: ((words[2] >> 8) & 63) as u8,
            code,
            packet_group: (words[2] >> 30) as u8,
            raw: words[2],
        }))
    }
}

/// An actual asynchronous router notification, separate from request replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationError {
    pub route: Route,
    pub port: u8,
    pub code: u8,
    pub packet_group: u8,
    pub raw: u32,
    pub header_flags: u16,
}
impl NotificationError {
    pub fn acknowledgement(self) -> Result<Encoded, Error> {
        if !asynchronous_error(self.code) {
            return Err(Error::UnexpectedReply);
        }
        encode(PacketType::NotifyAck, &self.route.header())
    }
}

fn asynchronous_error(code: u8) -> bool {
    matches!(code, 1 | 12 | 13 | 32..=39)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlugEvent {
    pub route: Route,
    pub port: u8,
    pub unplug: bool,
    /// Actual high header bits, preserved without inventing reply-marker
    /// requirements for asynchronous hotplug events.
    pub header_flags: u16,
}
impl PlugEvent {
    pub fn acknowledgement(self) -> Result<Encoded, Error> {
        if self.port >= 64 {
            return Err(Error::Address);
        }
        let h = self.route.header();
        encode(
            PacketType::Error,
            &[
                h[0],
                h[1],
                7 | (u32::from(self.port) << 8) | ((if self.unplug { 3 } else { 2 }) << 30),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(request: &Request, data: &[u32], upstream: u8) -> Encoded {
        let h = request.route.header();
        let mut words = vec![h[0] | REPLY, h[1]];
        if let Some(address) = request.address {
            words
                .push((address.word(request.sequence) & !(63 << 19)) | (u32::from(upstream) << 19));
        }
        words.extend_from_slice(data);
        encode(request.kind, &words).unwrap()
    }

    #[test]
    fn crc32c_matches_independent_standard_vector_and_wire_dword_order() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        let r = Request::read(
            Route::new(0x12_3456_789a).unwrap(),
            Address {
                port: 5,
                space: Space::Port,
                offset: 0x123,
                words: 2,
            },
            3,
        )
        .unwrap();
        assert_eq!(
            &r.frame.bytes[..8],
            &[0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a]
        );
        assert_eq!(
            &r.frame.bytes[8..12],
            &(0x1800_0000u32 | 1 << 25 | 5 << 19 | 2 << 13 | 0x123).to_be_bytes()
        );
    }
    #[test]
    fn request_bounds_never_truncate_route_port_length_sequence_or_offset() {
        assert_eq!(Route::new(1 << 54), Err(Error::Route));
        let route = Route::new(0).unwrap();
        for (port, offset, words) in [
            (64, 0, 1),
            (0, 8192, 1),
            (0, 8191, 2),
            (0, 0, 0),
            (0, 0, 61),
        ] {
            assert!(
                Request::read(
                    route,
                    Address {
                        port,
                        space: Space::Router,
                        offset,
                        words
                    },
                    0
                )
                .is_err()
            );
        }
        assert!(
            Request::read(
                route,
                Address {
                    port: 0,
                    space: Space::Router,
                    offset: 0,
                    words: 1
                },
                4
            )
            .is_err()
        );
        let a = Address {
            port: 0,
            space: Space::Router,
            offset: 0,
            words: 60,
        };
        assert_eq!(
            Request::write(route, a, 0, &[0; 60])
                .unwrap()
                .frame
                .bytes
                .len(),
            256
        );
        assert!(Request::write(route, a, 0, &[0; 59]).is_err());
    }
    #[test]
    fn reply_match_checks_all_ownership_fields_but_allows_real_upstream_port() {
        let r = Request::read(
            Route::new(0x30201).unwrap(),
            Address {
                port: 1,
                space: Space::Port,
                offset: 9,
                words: 2,
            },
            2,
        )
        .unwrap();
        let valid = response(&r, &[0xdead_beef, 0xaabb_ccdd], 7);
        let received = Received {
            kind: valid.kind,
            sof: 0,
            bytes: &valid.bytes,
        };
        assert_eq!(
            r.reply(&received),
            Ok(Reply::Configuration {
                upstream_port: 7,
                data: vec![0xdead_beef, 0xaabb_ccdd]
            })
        );
        for bit in [0, 13, 25, 27, 29] {
            let mut words = received.words().unwrap();
            words[2] ^= 1 << bit;
            let bad = encode(valid.kind, &words).unwrap();
            assert!(
                r.reply(&Received {
                    kind: bad.kind,
                    sof: 0,
                    bytes: &bad.bytes
                })
                .is_err()
            );
        }
        for bit in [0, 22, 30, 31] {
            let mut words = received.words().unwrap();
            words[0] ^= 1 << bit;
            let bad = encode(valid.kind, &words).unwrap();
            assert!(
                r.reply(&Received {
                    kind: bad.kind,
                    sof: 0,
                    bytes: &bad.bytes
                })
                .is_err()
            );
        }
        for index in 0..valid.bytes.len() {
            let mut bytes = valid.bytes.clone();
            bytes[index] ^= 0x80;
            assert!(
                r.reply(&Received {
                    kind: valid.kind,
                    sof: 0,
                    bytes: &bytes
                })
                .is_err()
            );
        }
        assert_eq!(
            r.reply(&Received {
                kind: valid.kind,
                sof: 1,
                bytes: &valid.bytes
            }),
            Err(Error::FrameMarkers)
        );
    }
    #[test]
    fn real_error_is_preserved_and_cannot_become_a_successful_read() {
        let route = Route::new(7).unwrap();
        let request = Request::read(
            route,
            Address {
                port: 0,
                space: Space::Router,
                offset: 1,
                words: 1,
            },
            0,
        )
        .unwrap();
        let e = encode(PacketType::Error, &[REPLY, 7, 0x8000_090f]).unwrap();
        assert_eq!(
            request.reply(&Received {
                kind: e.kind,
                sof: 0,
                bytes: &e.bytes
            }),
            Ok(Reply::ControllerError {
                route,
                port: 9,
                code: 15,
                packet_group: 2,
                raw: 0x8000_090f
            })
        );
        let e = encode(PacketType::Error, &[REPLY, 8, 0xf]).unwrap();
        assert!(matches!(
            request.reply(&Received {
                kind: e.kind,
                sof: 0,
                bytes: &e.bytes
            }),
            Ok(Reply::ControllerError {
                route: Route(8),
                ..
            })
        ));
        for code in [1, 12, 13, 32, 33, 34, 35, 36, 37, 38, 39] {
            for flags in [0, REPLY, 0xabc0_0000] {
                let e = encode(PacketType::Error, &[flags, 8, code]).unwrap();
                let received = Received {
                    kind: e.kind,
                    sof: 0,
                    bytes: &e.bytes,
                };
                assert!(request.reply(&received).is_err());
                let notice = received.notification_error().unwrap().unwrap();
                assert_eq!(notice.code, code as u8);
                assert_eq!(notice.header_flags, (flags >> 22) as u16);
                let ack = notice.acknowledgement().unwrap();
                assert_eq!(ack.kind, PacketType::NotifyAck);
                assert_eq!(&ack.bytes[..8], &[0, 0, 0, 0, 0, 0, 0, 8]);
                assert_eq!(ack.bytes.len(), 12);
            }
        }
    }
    #[test]
    fn plug_event_ack_preserves_actual_route_port_and_hotplug_group() {
        for unplug in [false, true] {
            let event = encode(
                PacketType::Event,
                &[REPLY, 0x201, 6 | if unplug { 1 << 31 } else { 0 }],
            )
            .unwrap();
            let actual = Received {
                kind: event.kind,
                sof: 0,
                bytes: &event.bytes,
            }
            .event()
            .unwrap();
            assert_eq!(
                actual,
                PlugEvent {
                    route: Route::new(0x201).unwrap(),
                    port: 6,
                    unplug,
                    header_flags: 512,
                }
            );
            let ack = actual.acknowledgement().unwrap();
            assert_eq!(&ack.bytes[..8], &[0, 0, 0, 0, 0, 0, 2, 1]);
            let word = u32::from_be_bytes(ack.bytes[8..12].try_into().unwrap());
            assert_eq!(word, 7 | 6 << 8 | if unplug { 3 << 30 } else { 2 << 30 });
        }
    }

    #[test]
    #[ignore = "requires hash-pinned unchanged Linux C helper trace"]
    fn unchanged_linux_config_frames_match_rust_wire_bytes() {
        extern crate std;
        use std::{env, fs};
        let path = env::var("STELA_THUNDERBOLT_CONFIG_ORACLE").expect("set oracle trace path");
        let trace = fs::read_to_string(path).unwrap();
        let mut count = 0;
        for line in trace.lines() {
            let f: Vec<_> = line.split_ascii_whitespace().collect();
            let number = |i: usize| f[i].parse::<u64>().unwrap();
            let (frame, at) = match f[0] {
                "C" => {
                    let route = Route::new(number(1)).unwrap();
                    let space = match number(2) {
                        0 => Space::Hops,
                        1 => Space::Port,
                        2 => Space::Router,
                        3 => Space::Counters,
                        _ => panic!("space"),
                    };
                    let address = Address {
                        space,
                        port: number(3) as u8,
                        offset: number(4) as u16,
                        words: number(5) as u8,
                    };
                    let sequence = number(6) as u8;
                    let request = if number(7) == 0 {
                        Request::read(route, address, sequence).unwrap()
                    } else {
                        let route_index = [
                            0,
                            1,
                            0x010203040506,
                            0xffffffff,
                            0x100000000,
                            0x3fffffffffffff,
                            0x3fffff00000000,
                        ]
                        .iter()
                        .position(|v| *v == route.raw())
                        .unwrap();
                        let data: Vec<u32> = (0..u32::from(address.words))
                            .map(|j| {
                                0x10203040
                                    ^ j.wrapping_mul(0x01010101)
                                    ^ ((route_index as u32) << 28)
                                    ^ (u32::from(address.port) << 16)
                                    ^ (u32::from(sequence) << 8)
                                    ^ (space as u32)
                            })
                            .collect();
                        Request::write(route, address, sequence, &data).unwrap()
                    };
                    (request.frame().clone(), 8)
                }
                "P" => (
                    PlugEvent {
                        route: Route::new(number(1)).unwrap(),
                        port: number(2) as u8,
                        unplug: number(3) != 0,
                        header_flags: 0,
                    }
                    .acknowledgement()
                    .unwrap(),
                    4,
                ),
                _ => panic!("record"),
            };
            assert_eq!(frame.kind as u64, number(at));
            assert_eq!(number(at), number(at + 1));
            assert_eq!(frame.bytes.len() as u64, number(at + 2));
            let bytes: Vec<u8> = f[at + 3]
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(frame.bytes, bytes, "{line}");
            count += 1;
        }
        assert_eq!(count, 5432);
    }
}
