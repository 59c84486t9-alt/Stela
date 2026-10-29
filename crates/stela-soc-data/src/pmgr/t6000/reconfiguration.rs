//! Original T6000 iBootData profile and RCfg input ownership.
//!
//! The native LLB resolves this relative-offset container before compiling its
//! reconfiguration programs. These bytes supply source rows, not emitted SRAM,
//! a hardware trigger, native retirement or initial physical register values.
use alloc::{collections::BTreeSet, vec::Vec};

const MAGIC: u32 = 0xb001_da1a;
const RCFG: u32 = 0x5243_6667;
const HEADER_BYTES: usize = 0x100;
const PROFILE_BYTES: usize = 24;
const SECTION_BYTES: usize = 16;
pub const ROW_BYTES: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Header,
    Format,
    Extent,
    Alignment,
    DuplicateProfile,
    DuplicateSection,
    DuplicateRecord,
    MissingProfile,
    MissingSection,
    MissingRecord,
    Rows,
    Revision,
}

/// Native chip/revision/query selection; no field comes from a default DT
/// revision, host model name or an observed later operating-system state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Profile {
    pub chip: u32,
    pub revision: u32,
    pub selector: u32,
}

struct Selected {
    profile: Profile,
    sections: usize,
    count: usize,
}

/// Borrowed original image. It cannot be replaced while any returned program
/// is borrowed, and every extent is checked against these same bytes.
pub struct Image<'a> {
    bytes: &'a [u8],
    profiles: Vec<Selected>,
}

/// Original source rows only. A continuation row can hold operands rather than
/// another opcode; consumers must implement the native handler's row ownership
/// and conditional nesting before interpreting or emitting any effects.
#[derive(Debug, Clone, Copy)]
pub struct Program<'a> {
    offset: usize,
    bytes: &'a [u8],
}
impl<'a> Program<'a> {
    pub fn offset(self) -> usize {
        self.offset
    }
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn rows(self) -> &'a [[u8; ROW_BYTES]] {
        // Construction checks the complete row extent, with no discarded tail.
        self.bytes.as_chunks::<ROW_BYTES>().0
    }
}

impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_BYTES || u32_at(bytes, 0)? != MAGIC {
            return Err(Error::Header);
        }
        // LLB c70e8..c70f8 accepts format 1 and a zero high version word.
        if u32_at(bytes, 8)? != 1 || u32_at(bytes, 12)? != 0 {
            return Err(Error::Format);
        }
        let name = usize::try_from(u32_at(bytes, 0x10)?).map_err(|_| Error::Extent)?;
        let length = usize::try_from(u32_at(bytes, 0x14)?).map_err(|_| Error::Extent)?;
        // Native c716c..c71a4 bounds the name to its first 256 bytes.
        if !(0x20..=0xff).contains(&name)
            || !(1..=0x80).contains(&length)
            || name.checked_add(length).ok_or(Error::Extent)? > HEADER_BYTES
        {
            return Err(Error::Header);
        }
        let list = relative(bytes, u64::from(u32_at(bytes, 0x1c)?), 16)?;
        let start = u64_at(list, 0)?;
        let end = u64_at(list, 8)?;
        let length = end.checked_sub(start).ok_or(Error::Extent)?;
        if length % 8 != 0 {
            return Err(Error::Extent);
        }
        let list = relative(bytes, start, length)?;
        let mut profiles = Vec::new();
        let mut seen = BTreeSet::new();
        for offset in list.as_chunks::<8>().0 {
            let row = relative(bytes, u64::from_le_bytes(*offset), PROFILE_BYTES as u64)?;
            let profile = Profile {
                chip: u32_at(row, 0)?,
                revision: u32_at(row, 4)?,
                selector: u32_at(row, 8)?,
            };
            if !seen.insert(profile) {
                return Err(Error::DuplicateProfile);
            }
            let count = u32_at(row, 12)? as usize;
            let sections = u64_at(row, 16)?;
            let section_rows = relative(bytes, sections, count as u64 * SECTION_BYTES as u64)?;
            let mut tags = BTreeSet::new();
            for section in section_rows.as_chunks::<SECTION_BYTES>().0 {
                if !tags.insert(u32_at(section, 0)?) {
                    return Err(Error::DuplicateSection);
                }
                let records = u32_at(section, 4)?;
                let record_rows = relative(
                    bytes,
                    u64_at(section, 8)?,
                    u64::from(records) * SECTION_BYTES as u64,
                )?;
                let mut ids = BTreeSet::new();
                for record in record_rows.as_chunks::<SECTION_BYTES>().0 {
                    if !ids.insert(u32_at(record, 0)?) {
                        return Err(Error::DuplicateRecord);
                    }
                    relative(bytes, u64_at(record, 8)?, u64::from(u32_at(record, 4)?))?;
                }
            }
            profiles.push(Selected {
                profile,
                sections: usize::try_from(sections).map_err(|_| Error::Extent)?,
                count,
            });
        }
        Ok(Self { bytes, profiles })
    }

    #[cfg(test)]
    pub fn profiles(&self) -> impl Iterator<Item = Profile> + '_ {
        self.profiles.iter().map(|selected| selected.profile)
    }

    /// Native kind 0's chip/raw-revision/query 0, RCfg record 0 route. Other
    /// source kinds use different inputs and are not substituted on failure.
    pub fn t6000(&self, revision: u32) -> Result<Program<'a>, Error> {
        if !matches!(revision, 0x10 | 0x20 | 0x21) {
            return Err(Error::Revision);
        }
        self.program(
            Profile {
                chip: 0x6000,
                revision,
                selector: 0,
            },
            0,
        )
    }

    pub fn program(&self, profile: Profile, record: u32) -> Result<Program<'a>, Error> {
        let selected = self
            .profiles
            .iter()
            .find(|selected| selected.profile == profile)
            .ok_or(Error::MissingProfile)?;
        let sections = &self.bytes[selected.sections..][..selected.count * SECTION_BYTES];
        let section = sections
            .as_chunks::<SECTION_BYTES>()
            .0
            .iter()
            .find(|row| u32_at(*row, 0) == Ok(RCFG))
            .ok_or(Error::MissingSection)?;
        let rows = relative(
            self.bytes,
            u64_at(section, 8)?,
            u64::from(u32_at(section, 4)?) * SECTION_BYTES as u64,
        )?;
        let selected = rows
            .as_chunks::<SECTION_BYTES>()
            .0
            .iter()
            .find(|row| u32_at(*row, 0) == Ok(record))
            .ok_or(Error::MissingRecord)?;
        let length = u64::from(u32_at(selected, 4)?);
        if length == 0 || length % ROW_BYTES as u64 != 0 {
            return Err(Error::Rows);
        }
        let offset = u64_at(selected, 8)?;
        Ok(Program {
            offset: usize::try_from(offset).map_err(|_| Error::Extent)?,
            bytes: relative(self.bytes, offset, length)?,
        })
    }
}

fn relative(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], Error> {
    if offset & 3 != 0 {
        return Err(Error::Alignment);
    }
    let offset = usize::try_from(offset).map_err(|_| Error::Extent)?;
    // Native c7584 rejects offset == total extent even for an empty view.
    if offset >= bytes.len() {
        return Err(Error::Extent);
    }
    let length = usize::try_from(length).map_err(|_| Error::Extent)?;
    bytes
        .get(offset..offset.checked_add(length).ok_or(Error::Extent)?)
        .ok_or(Error::Extent)
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let word = bytes.get(offset..offset + 4).ok_or(Error::Extent)?;
    Ok(u32::from_le_bytes(
        word.try_into().map_err(|_| Error::Extent)?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let word = bytes.get(offset..offset + 8).ok_or(Error::Extent)?;
    Ok(u64::from_le_bytes(
        word.try_into().map_err(|_| Error::Extent)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn image() -> Vec<u8> {
        let mut bytes = vec![0x55; 0x238];
        for (offset, value) in [
            (0, MAGIC),
            (8, 1),
            (12, 0),
            (0x10, 0x40),
            (0x14, 0x80),
            (0x1c, 0x100),
            (0x120, 0x6000),
            (0x124, 0x20),
            (0x128, 0),
            (0x12c, 1),
            (0x138, RCFG),
            (0x13c, 1),
            (0x148, 0),
            (0x14c, 2 * ROW_BYTES as u32),
        ] {
            put32(&mut bytes, offset, value);
        }
        for (offset, value) in [
            (0x100, 0x110),
            (0x108, 0x118),
            (0x110, 0x120),
            (0x130, 0x138),
            (0x140, 0x148),
            (0x150, 0x200),
        ] {
            put64(&mut bytes, offset, value);
        }
        bytes
    }

    #[test]
    fn selects_exact_native_profile_and_keeps_whole_original_rows() {
        let bytes = image();
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(
            image.profiles().collect::<Vec<_>>(),
            [Profile {
                chip: 0x6000,
                revision: 0x20,
                selector: 0
            }]
        );
        let program = image.t6000(0x20).unwrap();
        assert_eq!(program.offset, 0x200);
        assert_eq!(program.bytes(), &bytes[0x200..0x230]);
        assert_eq!(program.rows().len(), 2);
        assert_eq!(program.rows()[1], [0x55; ROW_BYTES]);
        assert_eq!(image.t6000(0).unwrap_err(), Error::Revision);
        assert_eq!(image.t6000(0x10).unwrap_err(), Error::MissingProfile);
        let mut profile = Profile {
            chip: 0x6000,
            revision: 0x20,
            selector: 0,
        };
        assert_eq!(image.program(profile, 1).unwrap_err(), Error::MissingRecord);
        profile.selector = 1;
        assert_eq!(
            image.program(profile, 0).unwrap_err(),
            Error::MissingProfile
        );
    }

    #[test]
    fn rejects_unknown_formats_duplicate_evidence_and_invalid_whole_extents() {
        for (offset, value, expected) in [
            (8, 2, Error::Format),
            (12, 1, Error::Format),
            (0x10, 0x1f, Error::Header),
            (0x14, 0, Error::Header),
            (0x14, 0x81, Error::Header),
            (0x1c, 0x101, Error::Alignment),
            (0x12c, u32::MAX, Error::Extent),
            (0x13c, u32::MAX, Error::Extent),
            (0x14c, 0x39, Error::Extent),
        ] {
            let mut bytes = image();
            put32(&mut bytes, offset, value);
            assert!(matches!(Image::parse(&bytes), Err(error) if error == expected));
        }
        let mut bytes = image();
        put64(&mut bytes, 0x108, 0x120);
        put64(&mut bytes, 0x118, 0x120);
        assert!(matches!(Image::parse(&bytes), Err(Error::DuplicateProfile)));
        let mut bytes = image();
        put32(&mut bytes, 0x12c, 2);
        let section = bytes[0x138..0x148].to_vec();
        bytes[0x148..0x158].copy_from_slice(&section);
        assert!(matches!(Image::parse(&bytes), Err(Error::DuplicateSection)));
        let mut bytes = image();
        put32(&mut bytes, 0x13c, 2);
        let record = bytes[0x148..0x158].to_vec();
        bytes[0x158..0x168].copy_from_slice(&record);
        assert!(matches!(Image::parse(&bytes), Err(Error::DuplicateRecord)));
        let mut bytes = image();
        put32(&mut bytes, 0x14c, 0x2f);
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(image.t6000(0x20).unwrap_err(), Error::Rows);
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_IBOOTDATA, STELA_TEST_PMGR_M1_LLB"]
    fn original_all_revision_routes_and_isp_guard_preserve_native_execution_obligation() {
        use sha2::{Digest, Sha256};
        let data = std::fs::read(
            std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").expect("original J314s iBootData"),
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095"
        );
        let llb =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").expect("original J314s LLB"))
                .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (lo, hi, digest) in [
            (
                0xc7008,
                0xc7874,
                "7c4be570688426cac5768d1f8031aaa8c11873005818514af31a415b265b455b",
            ),
            (
                0x129ec,
                0x12b78,
                "fe7eb58de885d83353af1be4c26e1adf78cc59fd3ef896eb6b0a01dbd46b0bae",
            ),
            (
                0x130c0,
                0x13158,
                "0d229e53903886850285e3b562e4d5fc6f5f642415bf60f4393544e151a6803a",
            ),
            (
                0x49cf8,
                0x49ec8,
                "4ca1681418263284fad051ca708f422005def5d7f9149d46e422c67b2fe34c70",
            ),
            (
                0x240100,
                0x242100,
                "be49bc42a73b4af32744f24cb486a81aa3c4d96782a4adc75f17bcdf6ea82ad1",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        let image = Image::parse(&data).unwrap();
        assert_eq!(image.profiles().count(), 3);
        for revision in [0x10, 0x20, 0x21] {
            let program = image.t6000(revision).unwrap();
            assert_eq!(program.offset, 0x4000);
            assert_eq!(program.rows().len(), 17739);
            assert_eq!(
                hex::encode(Sha256::digest(program.bytes())),
                "20975d766b7d5bc14ee81c764073359d80fdae6e276523b3f7055e1957ca8e76"
            );
        }
        for mask in [8, 0x40, 0x40000] {
            let mut ids = BTreeSet::new();
            let mut groups = BTreeSet::new();
            let mut shared = 0;
            // Complete original descriptor extents, not just seq6/ISP.
            assert_eq!((0x242100 - 0x240380) / 64, 118);
            for row in llb[0x240380..0x242100].as_chunks::<64>().0 {
                if u32_at(row, 0x3c).unwrap() & mask == 0 {
                    continue;
                }
                assert!(ids.insert(u32_at(row, 0).unwrap()));
                groups.insert(u32_at(row, 4).unwrap());
                shared += usize::from(u32_at(row, 0x38).unwrap() == 1);
            }
            assert_eq!(ids.len(), 72);
            assert_eq!(shared, 27);
            assert_eq!(groups, (0..10).collect());
        }
        // Input row provenance. No row is treated as an executed MMIO store.
        assert_eq!(u32_at(&data, 0x1f240), Ok(0xab0006));
        assert_eq!(u64_at(&data, 0x1f248), Ok(0x2000));
        assert_eq!(u32_at(&data, 0x1f250), Ok(1));
        assert_eq!(u32_at(&data, 0x1f258), Ok(0x200006));
        assert_eq!(u64_at(&data, 0x1f260), Ok(0x28e5803a8));
        assert_eq!(u32_at(&data, 0x1f268), Ok(0x30f));
        assert_eq!(u32_at(&data, 0x1f270), Ok(0x250006));
        assert_eq!(u64_at(&data, 0x1f288 + 8), Ok(0xf0));
        assert_eq!(u64_at(&data, 0x1f288 + 16), Ok(0xf0));
        // Native value1 polarity and execute/skip dispatch. A caller
        // cannot transfer the opposite predicate from another generation.
        for (offset, opcode) in [
            (0x1311c, 0xea13011f), // TST feature word, mask
            (0x13120, 0x1a9f17e0), // CSET EQ for source operand1
            (0x12ae0, 0x7100067f), // predicate == 1
            (0x12ae8, 0x94000024), // execute nested source row
            (0x12af0, 0x97ffff6b), // otherwise skip while preserving nesting
        ] {
            assert_eq!(u32_at(&llb, offset), Ok(opcode));
        }
        assert_eq!(u64_at(&llb, 0x1ae790), Ok(0x20600201));
        // Physical PS values, trigger events and native terminal semantics are
        // absent from this input type.
    }
}
