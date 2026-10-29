//! Original GFX FTAB selection, independent of the emulated GPU identity.
//!
//! J314s 26A434 LLB e59d8/e5bf8 -> 2cc9c -> c09c4 and iBoot
//! 10e2c0 -> 3d75c -> e4248 select gfxf/rgfx using the physical SoC
//! revision getter. Neither the GPU family nor its identification register
//! establishes the selected member. Parsing/selection grants no execution,
//! hardware reset state, signature authenticity or startup completion.
#[cfg(test)]
use super::super::power::t6000::identity::Image;
#[cfg(test)]
use crate::Result;
#[cfg(test)]
use stela_contracts::refuse;
#[cfg(test)]
use stela_crypto::{Sha256, digest::Digest};

#[cfg(test)]
const HEADER: usize = 0x30;
#[cfg(test)]
const ENTRY: usize = 0x10;
#[cfg(test)]
const MAX_ENTRIES: usize = 32;
#[cfg(test)]
const MAGIC: &[u8; 8] = b"rkosftab";

/// The immutable source identity carried into a native program binding.
/// Hashes describe the accepted bytes, not a behavior-dispatch key.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    pub container_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub tag: [u8; 4],
    pub offset: u32,
    pub bytes: u32,
    pub revision: u8,
}

/// A complete borrowed FTAB from the loader's immutable decoded input.
/// The expected digest binds it to the caller's preserved input receipt.
/// Image4 authentication and validation of a changed source remain the
/// loader/registry's independent obligations.
#[cfg(test)]
pub struct Ftab<'a> {
    bytes: &'a [u8],
    digest: [u8; 32],
    count: usize,
}

#[cfg(test)]
pub struct Selected<'a> {
    payload: &'a [u8],
    source: Source,
}
#[cfg(test)]
impl Selected<'_> {
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
    pub fn source(&self) -> Source {
        self.source
    }
}
#[cfg(test)]
impl<'a> Ftab<'a> {
    pub fn read(bytes: &'a [u8], expected_sha256: [u8; 32]) -> Result<Self> {
        let header = bytes
            .get(..HEADER)
            .ok_or(refuse!("GFX FTAB header is truncated"))?;
        if &header[0x20..0x28] != MAGIC {
            return Err(refuse!("GFX firmware input is not an FTAB"));
        }
        let count = u32::from_le_bytes(header[0x28..0x2c].try_into().unwrap()) as usize;
        if count > MAX_ENTRIES {
            return Err(refuse!(
                "GFX FTAB exceeds the original 32-entry selector capacity"
            ));
        }
        bytes
            .get(..HEADER + count * ENTRY)
            .ok_or(refuse!("GFX FTAB entry table is truncated"))?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != expected_sha256 {
            return Err(refuse!(
                "GFX FTAB bytes do not match the preserved input identity"
            ));
        }
        Ok(Self {
            bytes,
            digest,
            count,
        })
    }

    /// The source wrapper selects instance0 without strict instance filtering.
    /// It calls the physical revision getter even for a one-entry table.
    /// `Image::revision` keeps full-word knownness and the source's special
    /// discriminator8f rule; an omitted input cannot become revision0.
    pub fn select_t6000(&self, identity: &Image) -> Result<Selected<'a>> {
        let revision = identity.revision().map_err(|_| {
            refuse!("GFX FTAB selection requires complete physical revision inputs")
        })?;
        let target = (0x6130_0000u32
            .wrapping_add((u32::from(revision) << 20) & 0x0f00_0000)
            .wrapping_add((u32::from(revision) & 0xf) << 16))
            | 0x3030;
        let mut best = 0u32;
        for index in 0..self.count {
            let entry = &self.bytes[HEADER + index * ENTRY..HEADER + (index + 1) * ENTRY];
            let tag = u32::from_be_bytes(entry[..4].try_into().unwrap());
            if self.count == 1 || tag == target {
                best = tag;
                break;
            }
            // Original c0f58/e4f64 compares only the top two bytes.
            // Equal revision preserves the first encountered candidate;
            // low16 instance/suffix bytes do not break this fallback tie.
            if tag >> 16 > best >> 16 && tag >> 16 <= target >> 16 {
                best = tag;
            }
        }
        if best == 0 {
            return Err(refuse!(
                "GFX FTAB has no member selected by the physical revision"
            ));
        }
        // Original e5c18/10e2e0 performs a second scan and takes the first
        // exact matching entry. Unselected payload extents are not consumed.
        for index in 0..self.count {
            let entry = &self.bytes[HEADER + index * ENTRY..HEADER + (index + 1) * ENTRY];
            let tag: [u8; 4] = entry[..4].try_into().unwrap();
            if u32::from_be_bytes(tag) != best {
                continue;
            }
            let offset = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            let bytes = u32::from_le_bytes(entry[8..12].try_into().unwrap());
            let end = u64::from(offset) + u64::from(bytes);
            let end = usize::try_from(end)
                .map_err(|_| refuse!("GFX selected FTAB extent exceeds host size"))?;
            let payload = self
                .bytes
                .get(offset as usize..end)
                .ok_or(refuse!("GFX selected FTAB payload is truncated"))?;
            return Ok(Selected {
                payload,
                source: Source {
                    container_sha256: self.digest,
                    payload_sha256: Sha256::digest(payload).into(),
                    tag,
                    offset,
                    bytes,
                    revision,
                },
            });
        }
        Err(refuse!(
            "GFX FTAB selected tag disappeared from its immutable table"
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::apple::power::t6000::identity::{Input, Observation, Register};
    use alloc::{vec, vec::Vec};

    pub(crate) fn identity(revision: u32, discriminator: u32) -> Image {
        Image::new(Input::Captured(vec![
            Observation {
                register: Register::Revision,
                value: revision,
                known: u32::MAX,
            },
            Observation {
                register: Register::Discriminator,
                value: discriminator,
                known: u32::MAX,
            },
        ]))
        .unwrap()
    }
    pub(crate) fn image(tags: &[[u8; 4]]) -> Vec<u8> {
        let start = HEADER + tags.len() * ENTRY;
        let mut bytes = vec![0; start + tags.len() * 4];
        bytes[0x20..0x28].copy_from_slice(MAGIC);
        bytes[0x28..0x2c].copy_from_slice(&(tags.len() as u32).to_le_bytes());
        for (i, tag) in tags.iter().enumerate() {
            let at = HEADER + i * ENTRY;
            bytes[at..at + 4].copy_from_slice(tag);
            bytes[at + 4..at + 8].copy_from_slice(&((start + i * 4) as u32).to_le_bytes());
            bytes[at + 8..at + 12].copy_from_slice(&4u32.to_le_bytes());
            bytes[start + i * 4..start + (i + 1) * 4].copy_from_slice(tag);
        }
        bytes
    }
    fn parse(bytes: &[u8]) -> Ftab<'_> {
        Ftab::read(bytes, Sha256::digest(bytes).into()).unwrap()
    }
    #[test]
    fn physical_revision_and_discriminator_select_exact_or_floor_without_gpu_inference() {
        let bytes = image(&[*b"c000", *b"a000", *b"b000"]);
        let ftab = parse(&bytes);
        for (raw, expected) in [
            (0, *b"a000"),
            (0x10, *b"b000"),
            (0x12, *b"b000"),
            (0x20, *b"c000"),
            (0x70, *b"c000"),
        ] {
            let selected = ftab.select_t6000(&identity(raw, 0)).unwrap();
            assert_eq!(selected.source().tag, expected);
            assert_eq!(selected.payload(), expected);
            assert_eq!(
                selected.source().revision,
                ((raw & 0x70) | ((raw >> 1) & 7)) as u8
            );
            assert_eq!(
                selected.source().container_sha256,
                Sha256::digest(&bytes)[..]
            );
            assert_eq!(
                selected.source().payload_sha256,
                Sha256::digest(expected)[..]
            );
        }
        assert_eq!(
            ftab.select_t6000(&identity(0x20, 0x8f << 14))
                .unwrap()
                .source()
                .tag,
            *b"a000"
        );
        let unknown = Image::new(Input::Captured(Vec::new())).unwrap();
        assert!(ftab.select_t6000(&unknown).is_err());
        let partial = Image::new(Input::Captured(vec![
            Observation {
                register: Register::Revision,
                value: 0x20,
                known: 0x70,
            },
            Observation {
                register: Register::Discriminator,
                value: 0,
                known: u32::MAX,
            },
        ]))
        .unwrap();
        assert!(ftab.select_t6000(&partial).is_err());
    }
    #[test]
    fn source_order_ties_exact_priority_single_entry_and_zero_selection_are_preserved() {
        for (tags, raw, expected) in [
            (vec![*b"b099", *b"b011"], 0x12, Some(*b"b099")),
            (vec![*b"b099", *b"b000"], 0x10, Some(*b"b000")),
            (vec![*b"b000", *b"b000"], 0x10, Some(*b"b000")),
            (vec![*b"z999"], 0, Some(*b"z999")),
            (vec![*b"b000", *b"c000"], 0, None),
            (vec![[0; 4]], 0, None),
            (vec![], 0, None),
        ] {
            let bytes = image(&tags);
            let ftab = parse(&bytes);
            assert_eq!(
                ftab.select_t6000(&identity(raw, 0))
                    .ok()
                    .map(|s| s.source().tag),
                expected
            );
            let unknown = Image::new(Input::Captured(Vec::new())).unwrap();
            assert!(ftab.select_t6000(&unknown).is_err());
        }
    }
    #[test]
    fn whole_table_and_selected_extent_are_checked_before_exposing_payload() {
        let original = image(&[*b"a000", *b"b000"]);
        for size in 0..HEADER + 2 * ENTRY {
            assert!(
                Ftab::read(&original[..size], Sha256::digest(&original[..size]).into()).is_err()
            );
        }
        assert!(Ftab::read(&original, [0; 32]).is_err());
        let mut bad = original.clone();
        bad[0x20] ^= 1;
        assert!(Ftab::read(&bad, Sha256::digest(&bad).into()).is_err());
        bad = original.clone();
        bad[0x28..0x2c].copy_from_slice(&33u32.to_le_bytes());
        assert!(Ftab::read(&bad, Sha256::digest(&bad).into()).is_err());
        bad = original;
        // An unrelated invalid payload does not replace source selection.
        bad[HEADER + ENTRY + 4..HEADER + ENTRY + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        bad[HEADER + ENTRY + 8..HEADER + ENTRY + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&bad).select_t6000(&identity(0, 0)).is_ok());
        assert!(parse(&bad).select_t6000(&identity(0x10, 0)).is_err());
    }
}
