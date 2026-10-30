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
    IcmEvent = 10,
    IcmCommand = 11,
    IcmResponse = 12,
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
            10 => Ok(Self::IcmEvent),
            11 => Ok(Self::IcmCommand),
            12 => Ok(Self::IcmResponse),
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

/// An encoded raw-control frame, including its four-byte CRC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub kind: PacketType,
    pub bytes: Vec<u8>,
}

pub(super) fn encode(kind: PacketType, words: &[u32]) -> Result<Encoded, Error> {
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

pub(super) fn crc32c(bytes: &[u8]) -> u32 {
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

/// An asynchronous router notification, separate from request replies.
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
    /// High header bits, preserved without inventing reply-marker
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
mod tests;
