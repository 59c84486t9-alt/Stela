//! The AP-facing variable record layout, with native getter ownership separate.
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

pub const MAGIC: u32 = 0x494f5262;
pub const HEADER_BYTES: u64 = 16;
pub const RECORD_HEADER_BYTES: usize = 0x50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Scalar,
    Pairs(u32),
    Scalars(u32),
    States { count: u32, descriptions: u16 },
}
impl Layout {
    pub fn kind(self) -> u32 {
        match self {
            Self::Scalar => 1,
            Self::Pairs(_) => 2,
            Self::Scalars(_) => 3,
            Self::States { .. } => 4,
        }
    }
    pub fn count(self) -> u32 {
        match self {
            Self::Scalar => 1,
            Self::Pairs(n) | Self::Scalars(n) | Self::States { count: n, .. } => n,
        }
    }
    pub fn stride(self) -> u64 {
        match self {
            Self::Scalar => 8,
            Self::Pairs(_) => 24,
            Self::Scalars(_) => 16,
            Self::States { .. } => 40,
        }
    }
    pub fn bytes(self) -> u64 {
        RECORD_HEADER_BYTES as u64
            + self.stride() * u64::from(self.count())
            + if let Self::States { descriptions, .. } = self {
                16 * u64::from(descriptions)
            } else {
                0
            }
    }
    pub fn from_header(header: &[u8; RECORD_HEADER_BYTES]) -> Result<Self> {
        let n = u32::from_le_bytes(header[0x48..0x4c].try_into().unwrap());
        Ok(
            match u32::from_le_bytes(header[8..12].try_into().unwrap()) {
                1 => Self::Scalar,
                2 => Self::Pairs(n),
                3 => Self::Scalars(n),
                4 => Self::States {
                    count: n,
                    descriptions: u16::from_le_bytes(header[0x4e..0x50].try_into().unwrap()),
                },
                _ => {
                    return Err(refuse!(
                        "IOReporting record kind is not one of the source four layouts"
                    ));
                }
            },
        )
    }
}

/// Owned source C-string content, truncated like the original16-byte fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name([u8; 16]);
impl Name {
    pub fn new(bytes: &[u8]) -> Self {
        let n = bytes
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(bytes.len())
            .min(15);
        let mut name = [0; 16];
        name[..n].copy_from_slice(&bytes[..n]);
        Self(name)
    }
}

#[derive(Clone)]
pub struct Metadata {
    pub channel: u64,
    pub category: u32,
    pub name: Name,
    pub group: Name,
    pub unit: u64,
    pub layout: Layout,
    pub descriptions: Vec<[u8; 16]>,
}
impl Metadata {
    pub fn header(&self) -> Result<[u8; RECORD_HEADER_BYTES]> {
        let expected = if let Layout::States { descriptions, .. } = self.layout {
            usize::from(descriptions)
        } else {
            0
        };
        if self.descriptions.len() != expected {
            return Err(refuse!(
                "IOReporting description storage differs from its actual layout"
            ));
        }
        let mut bytes = [0; RECORD_HEADER_BYTES];
        bytes[..8].copy_from_slice(&self.channel.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.layout.kind().to_le_bytes());
        bytes[12..16].copy_from_slice(&self.category.to_le_bytes());
        bytes[0x10..0x20].copy_from_slice(&self.name.0);
        bytes[0x20..0x30].copy_from_slice(&self.group.0);
        bytes[0x30..0x38].copy_from_slice(&self.unit.to_le_bytes());
        // Native ABI choice: AP-ignored private getter/context slots are zero.
        // The typed live getter remains owned out-of-band. These are
        // not claimed original literal zeros and never expose host pointers.
        bytes[0x48..0x4c].copy_from_slice(&self.layout.count().to_le_bytes());
        if let Layout::States { descriptions, .. } = self.layout {
            bytes[0x4e..0x50].copy_from_slice(&descriptions.to_le_bytes());
        }
        Ok(bytes)
    }
}

/// Original1007d40..1007dd0 counter channel ID arithmetic. The input is the
/// incremented global counter-registration ordinal, not a group number.
pub fn counter_channel(ordinal: u64) -> u64 {
    const TENTHS: u64 = 0xcccc_cccc_cccc_cccd;
    const HUNDREDTHS: u64 = 0x28f5_c28f_5c28_f5c3;
    const PREFIX: u64 = 0x504d_5043_5400_0030;
    let high = |a: u64, b: u64| ((u128::from(a) * u128::from(b)) >> 64) as u64;
    let tens = high(ordinal, TENTHS) >> 3;
    let upper = (high(ordinal >> 2, HUNDREDTHS).wrapping_shl(14) & 0xffff_ffff_ffff_0000)
        .wrapping_add(0x30_0000)
        | PREFIX;
    let lower = ordinal
        .wrapping_sub(tens.wrapping_mul(10))
        .wrapping_add(tens.wrapping_shl(8))
        .wrapping_add(0x3000);
    upper | lower
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_source_layouts_include_padding_and_state_descriptions() {
        for (layout, bytes) in [
            (Layout::Scalar, 0x58),
            (Layout::Pairs(2), 0x80),
            (Layout::Scalars(2), 0x70),
            (
                Layout::States {
                    count: 2,
                    descriptions: 3,
                },
                0xd0,
            ),
        ] {
            let mut header = [0; RECORD_HEADER_BYTES];
            header[8..12].copy_from_slice(&layout.kind().to_le_bytes());
            header[0x48..0x4c].copy_from_slice(&layout.count().to_le_bytes());
            header[0x4e..0x50].copy_from_slice(&3u16.to_le_bytes());
            assert_eq!(Layout::from_header(&header), Ok(layout));
            assert_eq!(layout.bytes(), bytes);
        }
        assert_eq!(
            Layout::Pairs(u32::MAX).bytes(),
            0x50 + 24 * u64::from(u32::MAX)
        );
    }

    #[test]
    fn channel_names_categories_and_native_private_slots_have_distinct_ownership() {
        let metadata = Metadata {
            channel: counter_channel(1),
            category: 2,
            name: Name::new(b"Grp0 Hits"),
            group: Name::new(b"DSID Stats"),
            unit: 0x0900_8200_0000_0000,
            layout: Layout::Scalar,
            descriptions: Vec::new(),
        };
        let header = metadata.header().unwrap();
        assert_eq!(&header[0x10..0x1a], b"Grp0 Hits\0");
        assert_eq!(&header[0x20..0x2b], b"DSID Stats\0");
        assert_eq!(&header[0x38..0x48], &[0; 16]);
        assert_eq!(counter_channel(1), 0x504d_5043_5430_3031);
        assert_eq!(counter_channel(10), 0x504d_5043_5430_3130);
        assert_eq!(
            Name::new(b"1234567890123456789"),
            Name::new(b"123456789012345")
        );
        assert_eq!(Name::new(b"a\0ignored"), Name::new(b"a"));
        let mut invalid = metadata;
        invalid.descriptions.push([1; 16]);
        assert!(invalid.header().is_err());
    }
}
