//! Byte encoding for the proposed guest Metal frontend/native driver boundary.
//!
//! A decoded message is untrusted data, never authorization or execution proof.
//! The actual IOUserClient/transport must authenticate its task, resolve handles
//! in that connection and retain real memory/device ownership. No transport,
//! device registration, command submission or completion is supplied here.
use core::num::NonZeroU64;

pub mod identity;

pub const HEADER_BYTES: usize = 32;
const MAGIC: [u8; 4] = *b"STGP";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const RESPONSE_FLAG: u16 = 1;

/// Typed operations describe a wire vocabulary, not available driver features.
/// The dispatcher must refuse operations lacking actual backend admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Operation {
    Negotiate = 1,
    DeviceInfo = 2,
    CreateBuffer = 3,
    ImportMemory = 4,
    DestroyResource = 5,
    CreatePipeline = 6,
    CreateQueue = 7,
    Submit = 8,
    QueryFence = 9,
    WaitFence = 10,
    Present = 11,
}

impl Operation {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Negotiate),
            2 => Ok(Self::DeviceInfo),
            3 => Ok(Self::CreateBuffer),
            4 => Ok(Self::ImportMemory),
            5 => Ok(Self::DestroyResource),
            6 => Ok(Self::CreatePipeline),
            7 => Ok(Self::CreateQueue),
            8 => Ok(Self::Submit),
            9 => Ok(Self::QueryFence),
            10 => Ok(Self::WaitFence),
            11 => Ok(Self::Present),
            _ => Err(Error::UnknownOperation(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    Truncated,
    Magic,
    Version { major: u16, minor: u16 },
    UnknownOperation(u16),
    UnknownFlags(u16),
    Length,
    TooLarge,
    RequestId,
    Connection,
    OutputLength,
}

/// The connection's actual negotiated message ceiling, including the header.
/// Large code/data travels through separately registered bounded resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    max_bytes: u32,
}

impl Limits {
    pub const fn new(max_bytes: u32) -> Result<Self, Error> {
        if max_bytes < HEADER_BYTES as u32 {
            Err(Error::InvalidLimit)
        } else {
            Ok(Self { max_bytes })
        }
    }
}

/// Numeric IDs are scoped by a real registered connection; equality is not a
/// task credential. Only the first negotiation request may omit a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub operation: Operation,
    pub direction: Direction,
    pub connection: Option<NonZeroU64>,
    pub request_id: NonZeroU64,
}

impl Header {
    fn validate(self) -> Result<(), Error> {
        if self.connection.is_none()
            && !(self.operation == Operation::Negotiate && self.direction == Direction::Request)
        {
            return Err(Error::Connection);
        }
        Ok(())
    }

    /// Encodes one complete frame. Every fallible check precedes the first
    /// output write. Payload encoding/validation belongs to its typed operation.
    pub fn encode(self, payload: &[u8], output: &mut [u8], limits: Limits) -> Result<(), Error> {
        self.validate()?;
        let bytes = HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(Error::TooLarge)?;
        let bytes = u32::try_from(bytes).map_err(|_| Error::TooLarge)?;
        if bytes > limits.max_bytes {
            return Err(Error::TooLarge);
        }
        if output.len() != bytes as usize {
            return Err(Error::OutputLength);
        }
        let flags = match self.direction {
            Direction::Request => 0,
            Direction::Response => RESPONSE_FLAG,
        };
        output[..4].copy_from_slice(&MAGIC);
        output[4..6].copy_from_slice(&MAJOR.to_le_bytes());
        output[6..8].copy_from_slice(&MINOR.to_le_bytes());
        output[8..10].copy_from_slice(&(self.operation as u16).to_le_bytes());
        output[10..12].copy_from_slice(&flags.to_le_bytes());
        output[12..16].copy_from_slice(&bytes.to_le_bytes());
        output[16..24].copy_from_slice(&self.connection.map_or(0, NonZeroU64::get).to_le_bytes());
        output[24..32].copy_from_slice(&self.request_id.get().to_le_bytes());
        output[HEADER_BYTES..].copy_from_slice(payload);
        Ok(())
    }
}

/// A borrowed, length-checked frame. Its payload is still unvalidated and must
/// not select memory/PCI resources or report successful GPU work by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn decode(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() < HEADER_BYTES {
            return Err(Error::Truncated);
        }
        if bytes.len() > limits.max_bytes as usize {
            return Err(Error::TooLarge);
        }
        if bytes[..4] != MAGIC {
            return Err(Error::Magic);
        }
        let u16_at = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let u64_at = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let (major, minor) = (u16_at(4), u16_at(6));
        // No compatible-minor behavior is defined yet. Refuse new semantics.
        if major != MAJOR || minor != MINOR {
            return Err(Error::Version { major, minor });
        }
        let operation = Operation::decode(u16_at(8))?;
        let flags = u16_at(10);
        let direction = match flags {
            0 => Direction::Request,
            RESPONSE_FLAG => Direction::Response,
            _ => return Err(Error::UnknownFlags(flags)),
        };
        if u32_at(12) as usize != bytes.len() {
            return Err(Error::Length);
        }
        let header = Header {
            operation,
            direction,
            connection: NonZeroU64::new(u64_at(16)),
            request_id: NonZeroU64::new(u64_at(24)).ok_or(Error::RequestId)?,
        };
        header.validate()?;
        Ok(Self {
            header,
            payload: &bytes[HEADER_BYTES..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            operation: Operation::Submit,
            direction: Direction::Request,
            connection: NonZeroU64::new(0x0807_0605_0403_0201),
            request_id: NonZeroU64::new(0x100f_0e0d_0c0b_0a09).unwrap(),
        }
    }
    fn limits() -> Limits {
        Limits::new(64).unwrap()
    }

    #[test]
    fn independent_wire_vector_and_unaligned_input() {
        let expected = [
            b'S', b'T', b'G', b'P', 1, 0, 0, 0, 8, 0, 0, 0, 35, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, 11, 12, 13, 14, 15, 16, 0xab, 0xcd, 0xef,
        ];
        let mut output = [0; 35];
        header()
            .encode(&[0xab, 0xcd, 0xef], &mut output, limits())
            .unwrap();
        assert_eq!(output, expected);
        let mut unaligned = [0; 36];
        unaligned[1..].copy_from_slice(&expected);
        let decoded = Frame::decode(&unaligned[1..], limits()).unwrap();
        assert_eq!(decoded.header, header());
        assert_eq!(decoded.payload, &[0xab, 0xcd, 0xef]);
    }

    #[test]
    fn rejects_unknown_semantics_and_malformed_lengths() {
        let mut valid = [0; HEADER_BYTES];
        header().encode(&[], &mut valid, limits()).unwrap();
        for size in 0..HEADER_BYTES {
            assert_eq!(
                Frame::decode(&valid[..size], limits()),
                Err(Error::Truncated)
            );
        }
        for (offset, value, error) in [
            (0, 0, Error::Magic),
            (4, 2, Error::Version { major: 2, minor: 0 }),
            (6, 1, Error::Version { major: 1, minor: 1 }),
            (8, 255, Error::UnknownOperation(255)),
            (10, 2, Error::UnknownFlags(2)),
            (12, 31, Error::Length),
        ] {
            let mut bad = valid;
            bad[offset] = value;
            assert_eq!(Frame::decode(&bad, limits()), Err(error));
        }
        let mut bad = valid;
        bad[16..24].fill(0);
        assert_eq!(Frame::decode(&bad, limits()), Err(Error::Connection));
        let mut bad = valid;
        bad[24..32].fill(0);
        assert_eq!(Frame::decode(&bad, limits()), Err(Error::RequestId));
        let mut trailing = [0; HEADER_BYTES + 1];
        trailing[..HEADER_BYTES].copy_from_slice(&valid);
        assert_eq!(Frame::decode(&trailing, limits()), Err(Error::Length));
        assert_eq!(Frame::decode(&[0; 65], limits()), Err(Error::TooLarge));
        assert_eq!(Limits::new(31), Err(Error::InvalidLimit));
    }

    #[test]
    fn every_single_byte_mutation_is_refused_or_has_one_canonical_encoding() {
        let mut valid = [0; HEADER_BYTES];
        header().encode(&[], &mut valid, limits()).unwrap();
        for at in 0..HEADER_BYTES {
            for value in 0..=u8::MAX {
                let mut input = valid;
                input[at] = value;
                if let Ok(frame) = Frame::decode(&input, limits()) {
                    let mut encoded = [0; HEADER_BYTES];
                    frame
                        .header
                        .encode(frame.payload, &mut encoded, limits())
                        .unwrap();
                    assert_eq!(encoded, input);
                }
            }
        }
    }

    #[test]
    fn negotiation_and_response_connection_rules_and_failure_atomicity() {
        let mut initial = header();
        initial.operation = Operation::Negotiate;
        initial.connection = None;
        let mut output = [0; HEADER_BYTES];
        initial.encode(&[], &mut output, limits()).unwrap();
        assert_eq!(Frame::decode(&output, limits()).unwrap().header, initial);
        let mut reply = initial;
        reply.direction = Direction::Response;
        output.fill(0xa5);
        assert_eq!(
            reply.encode(&[], &mut output, limits()),
            Err(Error::Connection)
        );
        assert_eq!(output, [0xa5; HEADER_BYTES]);
        reply.connection = NonZeroU64::new(1);
        reply.encode(&[], &mut output, limits()).unwrap();
        assert_eq!(output[10..12], [1, 0]);
        assert_eq!(Frame::decode(&output, limits()).unwrap().header, reply);
        output.fill(0xa5);
        assert_eq!(
            header().encode(&[1], &mut output, limits()),
            Err(Error::OutputLength)
        );
        assert_eq!(output, [0xa5; HEADER_BYTES]);
        assert_eq!(
            header().encode(&[0; 33], &mut output, limits()),
            Err(Error::TooLarge)
        );
        assert_eq!(output, [0xa5; HEADER_BYTES]);
    }
}
