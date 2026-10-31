//! Kernel-collection chained fixups (`DYLD_CHAINED_PTR_64_KERNEL_CACHE`),
//! which XNU applies to an auxiliary collection when it slides and signs it.
//!
//! Layouts follow XNU `EXTERNAL_HEADERS/mach-o/fixup-chains.h` at
//! `xnu-12377.121.6`: each pointer is
//! `target:30 cacheLevel:2 diversity:16 addrDiv:1 key:2 next:12 isAuth:1`,
//! `next` counting 4-byte strides to the following pointer in its page.
use alloc::{collections::BTreeMap, vec, vec::Vec};

use super::fit;
use crate::Result;
use stela_contracts::{refuse, require};

use crate::kernel_collection::PAGE_BYTES;

const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
const HEADER_BYTES: usize = 28;
const STRIDE: u64 = 4;
const TARGET_LIMIT: u64 = 1 << 30;
const NEXT_LIMIT: u64 = 0xfff;

/// The collection a pointer's target lies in, by XNU's cache level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    Boot = 0,
    Auxiliary = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature {
    pub key: u8,
    pub address_diversity: bool,
    pub diversity: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pointer {
    pub level: Level,
    /// Bytes from the level's base.
    pub target: u64,
    pub signature: Option<Signature>,
}

impl Pointer {
    fn encode(self, next: u64) -> Result<u64> {
        require!(
            self.target < TARGET_LIMIT,
            "a pointer target {target:#x} past the 1 GiB a kernel-collection fixup reaches",
            target = self.target
        );
        let mut raw = self.target | (self.level as u64) << 30 | next << 51;
        if let Some(signature) = self.signature {
            require!(
                signature.key < 4,
                "pointer authentication key {key}",
                key = signature.key
            );
            raw |= u64::from(signature.diversity) << 32
                | u64::from(signature.address_diversity) << 48
                | u64::from(signature.key) << 49
                | 1 << 63;
        }
        Ok(raw)
    }
}

/// A collection segment, in the order of the header's segment commands.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    pub address: u64,
    pub size: u64,
}

/// Writes each pointer's chained form into `image`, which holds the
/// collection from address 0, and returns the `LC_DYLD_CHAINED_FIXUPS`
/// payload. `header` is the address of the collection's Mach-O header, which
/// segment offsets count from.
pub fn encode(
    image: &mut [u8],
    header: u64,
    segments: &[Segment],
    pointers: &BTreeMap<u64, Pointer>,
) -> Result<Vec<u8>> {
    let starts = HEADER_BYTES.next_multiple_of(8);
    let mut payload = vec![0u8; starts];
    payload.extend(fit::<u32, _>(segments.len(), "the segment count")?.to_le_bytes());
    let offsets = payload.len();
    payload.resize(offsets + 4 * segments.len(), 0);
    for (index, segment) in segments.iter().enumerate() {
        let range = segment.address..segment.address + segment.size;
        if pointers.range(range.clone()).next().is_none() {
            continue;
        }
        let pages = segment.size.div_ceil(PAGE_BYTES);
        let mut page_starts =
            vec![DYLD_CHAINED_PTR_START_NONE; fit(pages, "a segment's page count")?];
        let mut chain = pointers.range(range).peekable();
        while let Some((&address, pointer)) = chain.next() {
            let offset = address - segment.address;
            require!(
                address.is_multiple_of(STRIDE) && offset % PAGE_BYTES <= PAGE_BYTES - 8,
                "a pointer at {address:#x} is misaligned or crosses a page",
                address
            );
            let page: usize = fit(offset / PAGE_BYTES, "a pointer's page")?;
            if page_starts[page] == DYLD_CHAINED_PTR_START_NONE {
                page_starts[page] = (offset % PAGE_BYTES) as u16;
            }
            let next = match chain.peek() {
                Some(&(&following, _))
                    if (following - segment.address) / PAGE_BYTES == page as u64 =>
                {
                    require!(
                        following - address >= 8,
                        "pointers at {address:#x} and {following:#x} overlap",
                        address,
                        following
                    );
                    (following - address) / STRIDE
                }
                _ => 0,
            };
            require!(next <= NEXT_LIMIT, "a chain step past its page");
            let slot: usize = fit(address, "a pointer's collection offset")?;
            image
                .get_mut(slot..slot + 8)
                .ok_or(refuse!("a pointer past the collection"))?
                .copy_from_slice(&pointer.encode(next)?.to_le_bytes());
        }
        payload.resize(payload.len().next_multiple_of(8), 0);
        let start = payload.len();
        let offset: u32 = fit(start - starts, "a segment's chain start offset")?;
        payload[offsets + 4 * index..offsets + 4 * index + 4]
            .copy_from_slice(&offset.to_le_bytes());
        let size = 22 + 2 * page_starts.len();
        payload.extend(fit::<u32, _>(size, "a segment's chain starts size")?.to_le_bytes());
        payload.extend(fit::<u16, _>(PAGE_BYTES, "the page size")?.to_le_bytes());
        payload.extend(DYLD_CHAINED_PTR_64_KERNEL_CACHE.to_le_bytes());
        payload.extend(segment.address.wrapping_sub(header).to_le_bytes());
        payload.extend(0u32.to_le_bytes());
        payload.extend(fit::<u16, _>(page_starts.len(), "a segment's page count")?.to_le_bytes());
        payload.extend(page_starts.iter().flat_map(|start| start.to_le_bytes()));
    }
    payload.resize(payload.len().next_multiple_of(8), 0);
    let end: u32 = fit(payload.len(), "the fixup chains' size")?;
    let header_fields = [
        0,
        fit(starts, "the chain starts offset")?,
        end,
        end,
        0,
        DYLD_CHAINED_IMPORT,
        0,
    ];
    for (index, field) in header_fields.into_iter().enumerate() {
        payload[4 * index..4 * index + 4].copy_from_slice(&field.to_le_bytes());
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn chains_pointers_within_each_page() -> Result<()> {
        let mut image = vec![0u8; 0x10000];
        let segments = [
            Segment {
                address: 0,
                size: 0x8000,
            },
            Segment {
                address: 0x8000,
                size: 0x4000,
            },
            Segment {
                address: 0xc000,
                size: 0x4000,
            },
        ];
        let plain = Pointer {
            level: Level::Auxiliary,
            target: 0x8010,
            signature: None,
        };
        let signed = Pointer {
            level: Level::Boot,
            target: 0x1234,
            signature: Some(Signature {
                key: 2,
                address_diversity: true,
                diversity: 0xbeef,
            }),
        };
        let pointers = BTreeMap::from([
            (0x10, plain),
            (0x30, signed),
            (0x4008, plain),
            (0xc000, plain),
        ]);
        let payload = encode(&mut image, 0x8000, &segments, &pointers)?;

        let first = u64::from_le_bytes(image[0x10..0x18].try_into()?);
        assert_eq!(first, 0x8010 | 3 << 30 | 8 << 51);
        let second = u64::from_le_bytes(image[0x30..0x38].try_into()?);
        assert_eq!(second, 0x1234 | 0xbeef << 32 | 1 << 48 | 2 << 49 | 1 << 63);
        // The next page starts a chain of its own.
        let third = u64::from_le_bytes(image[0x4008..0x4010].try_into()?);
        assert_eq!(third, 0x8010 | 3 << 30);

        let starts = word(&payload, 4) as usize;
        assert_eq!(word(&payload, 8) as usize, payload.len());
        assert_eq!(word(&payload, 20), DYLD_CHAINED_IMPORT);
        assert_eq!(word(&payload, starts), 3);
        let first_segment = starts + word(&payload, starts + 4) as usize;
        assert_eq!(
            word(&payload, starts + 8),
            0,
            "the middle segment has no pointers"
        );
        assert_eq!(
            &payload[first_segment + 4..first_segment + 6],
            &0x4000u16.to_le_bytes()
        );
        assert_eq!(
            &payload[first_segment + 6..first_segment + 8],
            &8u16.to_le_bytes()
        );
        assert_eq!(
            u64::from_le_bytes(payload[first_segment + 8..first_segment + 16].try_into()?),
            0u64.wrapping_sub(0x8000)
        );
        assert_eq!(
            &payload[first_segment + 20..first_segment + 26],
            &[2, 0, 0x10, 0, 8, 0]
        );
        Ok(())
    }

    #[test]
    fn refuses_unreachable_targets_and_page_crossings() {
        let segments = [Segment {
            address: 0,
            size: 0x8000,
        }];
        let far = Pointer {
            level: Level::Auxiliary,
            target: TARGET_LIMIT,
            signature: None,
        };
        let mut image = vec![0u8; 0x8000];
        assert!(encode(&mut image, 0, &segments, &BTreeMap::from([(0, far)])).is_err());
        let near = Pointer { target: 0, ..far };
        assert!(encode(&mut image, 0, &segments, &BTreeMap::from([(0x3ffc, near)])).is_err());
    }
}
