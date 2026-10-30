//! Original endpoint-4 kind/size encoding, not a class1 PMP allocation reply.
use crate::Result;
use stela_contracts::refuse;

pub const ENDPOINT: u8 = 4;
pub const REQUEST_BYTES: u64 = 0x48000;
pub const BUFFER_REQUEST: u64 = 0x0014_8000_0000_0000;
pub const UPDATE: u64 = 1 << 54;
pub const REGISTERED: u64 = 2 << 54;
pub const READY: u64 = 12 << 52;
const ADDRESS_BITS: u32 = 44;
const ADDRESS_MASK: u64 = (1 << ADDRESS_BITS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffer {
    /// Source SBFX, keeping the sign extension of bit43.
    pub bus: u64,
    pub bytes: u64,
}

/// Source102e0b8..102e0c4 and the independent AP b66a67c..b66a688.
pub fn kind(payload: u64) -> u8 {
    let primary = (payload >> 54) & 3;
    if primary == 3 {
        ((payload >> 52) & 15) as u8
    } else {
        primary as u8
    }
}

pub fn buffer(payload: u64) -> Result<Buffer> {
    if kind(payload) != 0 {
        return Err(refuse!("IOReporting message is not a buffer reply"));
    }
    let units = (payload >> 44) & 255;
    let shift = match (payload >> 52) & 3 {
        0 => 0, // Source's explicit no-size encoding, not an assumed page.
        1 => 12,
        2 => 20,
        3 => 21,
        _ => unreachable!(),
    };
    let bytes = if shift == 0 { 0 } else { units << shift };
    Ok(Buffer {
        bus: (((payload & ADDRESS_MASK) << (64 - ADDRESS_BITS)) as i64 >> (64 - ADDRESS_BITS))
            as u64,
        bytes,
    })
}

/// Source102e2b4..102e2fc rounds to pages below1MiB, MiB otherwise.
/// The caller supplies the mapping's published bus address.
pub fn advertisement(buffer: Buffer) -> Result<u64> {
    let shift = if buffer.bytes < 1 << 20 { 12 } else { 20 };
    let granule = 1u64 << shift;
    let units = buffer.bytes / granule + u64::from(!buffer.bytes.is_multiple_of(granule));
    if units > 255 {
        return Err(refuse!("IOReporting buffer exceeds its source size field"));
    }
    let sign_extended =
        (((buffer.bus & ADDRESS_MASK) << (64 - ADDRESS_BITS)) as i64 >> (64 - ADDRESS_BITS)) as u64;
    if sign_extended != buffer.bus {
        return Err(refuse!("IOReporting bus address exceeds signed44 encoding"));
    }
    Ok((if shift == 12 { 1u64 } else { 2u64 }) << 52 | units << 44 | buffer.bus & ADDRESS_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_request_size_and_both_kind_encodings_stay_distinct() {
        assert_eq!(
            buffer(BUFFER_REQUEST),
            Ok(Buffer {
                bus: 0,
                bytes: REQUEST_BYTES
            })
        );
        assert_eq!(kind(UPDATE), 1);
        assert_eq!(kind(REGISTERED), 2);
        assert_eq!(kind(READY), 12);
        assert!(buffer(READY).is_err());
        assert_eq!(buffer(7 << 44).unwrap().bytes, 0);
        assert_eq!(buffer((3 << 52) | (7 << 44)).unwrap().bytes, 7 << 21);
    }

    #[test]
    fn advertisement_rounding_and_signed_addresses_match_source_fields() {
        for (bytes, encoded_bytes) in [
            (0x48000, 0x48000),
            (4097, 8192),
            (1 << 20, 1 << 20),
            ((1 << 20) + 1, 2 << 20),
        ] {
            let original = Buffer {
                bus: 0xffff_f800_0000_1000,
                bytes,
            };
            let encoded = advertisement(original).unwrap();
            assert_eq!(
                buffer(encoded),
                Ok(Buffer {
                    bytes: encoded_bytes,
                    ..original
                })
            );
        }
        assert!(
            advertisement(Buffer {
                bus: 1 << 44,
                bytes: 4096
            })
            .is_err()
        );
        assert!(
            advertisement(Buffer {
                bus: 0x1000,
                bytes: 256 << 20
            })
            .is_err()
        );
    }
}
