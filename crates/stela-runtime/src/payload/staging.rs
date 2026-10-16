//! The staging partition's layout: a header naming each verified member and
//! where its bytes start, then the members, each on a 1 MiB boundary.
//!
//! Stela writes the header last. A partition whose header is missing or
//! damaged holds no usable payload, so an interrupted copy is never mistaken
//! for a complete one.
use super::{PayloadError, PayloadManifest, ReadAt, gpt::crc32};
use alloc::{string::String, vec, vec::Vec};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 16] = b"STELA-STAGING\0\0\x01";
/// The header area; members start after it.
pub const HEADER_BYTES: u64 = 1024 * 1024;
const PREFIX_BYTES: usize = 24;
pub const MEMBER_ALIGNMENT: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub name: String,
    /// Byte offset from the start of the staging partition.
    pub offset: u64,
}

/// What the header records: the manifest of the staged members alone, and
/// where each one is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub schema_version: u32,
    /// SHA-256 of the source payload manifest the copy was made from.
    pub source_manifest_sha256: String,
    pub manifest: PayloadManifest,
    pub extents: Vec<Extent>,
}

impl Header {
    /// Lay out `manifest`'s members in order after the header area.
    pub fn plan(manifest: PayloadManifest, source_manifest_sha256: String) -> Self {
        let mut offset = HEADER_BYTES;
        let extents = manifest
            .members
            .iter()
            .map(|member| {
                let extent = Extent {
                    name: member.name.clone(),
                    offset,
                };
                offset = (offset + member.bytes).div_ceil(MEMBER_ALIGNMENT) * MEMBER_ALIGNMENT;
                extent
            })
            .collect();
        Self {
            schema_version: 1,
            source_manifest_sha256,
            manifest,
            extents,
        }
    }

    /// The bytes the partition needs.
    pub fn total_bytes(&self) -> u64 {
        self.manifest
            .members
            .iter()
            .zip(&self.extents)
            .map(|(member, extent)| {
                (extent.offset + member.bytes).div_ceil(MEMBER_ALIGNMENT) * MEMBER_ALIGNMENT
            })
            .max()
            .unwrap_or(HEADER_BYTES)
    }

    /// The header area's bytes: magic, JSON length, JSON CRC-32, JSON.
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        let json = serde_json::to_vec(self).map_err(|_| PayloadError::Manifest("encode"))?;
        if (PREFIX_BYTES + json.len()) as u64 > HEADER_BYTES {
            return Err(PayloadError::Manifest("staging header exceeds its area"));
        }
        let mut bytes = vec![0u8; HEADER_BYTES as usize];
        bytes[..16].copy_from_slice(MAGIC);
        bytes[16..20].copy_from_slice(&(json.len() as u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&crc32(&json).to_le_bytes());
        bytes[PREFIX_BYTES..PREFIX_BYTES + json.len()].copy_from_slice(&json);
        Ok(bytes)
    }

    /// Parse a header area. `Ok(None)` means nothing complete is staged.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, PayloadError> {
        if bytes.len() < PREFIX_BYTES || &bytes[..16] != MAGIC {
            return Ok(None);
        }
        let length = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let json = bytes
            .get(PREFIX_BYTES..PREFIX_BYTES + length)
            .ok_or(PayloadError::Manifest("staging header overruns"))?;
        if crc32(json) != u32::from_le_bytes(bytes[20..24].try_into().unwrap()) {
            return Err(PayloadError::Manifest("staging header CRC mismatch"));
        }
        let header: Self =
            serde_json::from_slice(json).map_err(|_| PayloadError::Manifest("staging header"))?;
        header.manifest.validate()?;
        let expected = Self::plan(
            header.manifest.clone(),
            header.source_manifest_sha256.clone(),
        );
        if header.schema_version != 1 || expected.extents != header.extents {
            return Err(PayloadError::Manifest(
                "staging extents disagree with the manifest",
            ));
        }
        Ok(Some(header))
    }
}

/// Read a staged copy back through any byte-addressed view of the
/// partition, such as the host block driver after boot services end.
pub struct StagedSource<R: ReadAt> {
    reader: R,
    header: Header,
}

impl<R: ReadAt> StagedSource<R> {
    pub fn open(mut reader: R) -> Result<Self, PayloadError> {
        let mut bytes = vec![0u8; HEADER_BYTES as usize];
        reader.read_at(0, &mut bytes).map_err(PayloadError::io)?;
        let header = Header::decode(&bytes)?.ok_or(PayloadError::Manifest("nothing is staged"))?;
        if header.total_bytes() > reader.len() {
            return Err(PayloadError::Manifest(
                "staged members exceed the partition",
            ));
        }
        Ok(Self { reader, header })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }
}

pub struct StagedMember<'a, R: ReadAt> {
    reader: &'a mut R,
    next: u64,
    remaining: u64,
}

impl<R: ReadAt> super::MemberRead for StagedMember<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, PayloadError> {
        let count = (buffer.len() as u64).min(self.remaining) as usize;
        self.reader
            .read_at(self.next, &mut buffer[..count])
            .map_err(PayloadError::io)?;
        self.next += count as u64;
        self.remaining -= count as u64;
        Ok(count)
    }
}

impl<R: ReadAt> super::PayloadSource for StagedSource<R> {
    type Reader<'a>
        = StagedMember<'a, R>
    where
        Self: 'a;

    fn manifest(&self) -> &PayloadManifest {
        &self.header.manifest
    }

    fn open(&mut self, name: &str) -> Result<Self::Reader<'_>, PayloadError> {
        let (member, extent) = self
            .header
            .manifest
            .members
            .iter()
            .zip(&self.header.extents)
            .find(|(member, _)| member.name == name)
            .ok_or(PayloadError::Manifest("member is not staged"))?;
        Ok(StagedMember {
            reader: &mut self.reader,
            next: extent.offset,
            remaining: member.bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{PayloadSource, copy_verified, tests::Memory, tests::manifest};

    #[test]
    fn staged_members_are_aligned_and_read_back_verified() {
        let (manifest, contents) = manifest();
        let header = Header::plan(manifest.clone(), "ab".repeat(32));
        assert_eq!(header.extents[0].offset, HEADER_BYTES);
        for extent in &header.extents {
            assert_eq!(extent.offset % MEMBER_ALIGNMENT, 0);
        }
        let mut disk = vec![0u8; header.total_bytes() as usize];
        assert!(Header::decode(&disk).unwrap().is_none());
        for (extent, (_, data)) in header.extents.iter().zip(&contents) {
            disk[extent.offset as usize..][..data.len()].copy_from_slice(data);
        }
        disk[..HEADER_BYTES as usize].copy_from_slice(&header.encode().unwrap());
        let mut source = StagedSource::open(Memory(disk.clone())).unwrap();
        assert_eq!(source.manifest(), &manifest);
        let mut buffer = vec![0u8; 7];
        for (name, data) in &contents {
            let member = manifest.member(name).unwrap().clone();
            let mut copied = Vec::new();
            copy_verified(&mut source, &member, &mut buffer, |chunk| {
                copied.extend_from_slice(chunk);
                Ok::<(), ()>(())
            })
            .unwrap();
            assert_eq!(&copied, data);
        }
        // A changed byte, header or extent is caught.
        let mut changed = disk.clone();
        changed[HEADER_BYTES as usize] ^= 1;
        let mut source = StagedSource::open(Memory(changed)).unwrap();
        let member = manifest.members[0].clone();
        assert!(copy_verified(&mut source, &member, &mut buffer, |_| Ok::<(), ()>(())).is_err());
        let mut damaged = disk.clone();
        damaged[40] ^= 1;
        assert!(StagedSource::open(Memory(damaged)).is_err());
        let mut moved = header.clone();
        moved.extents[0].offset += MEMBER_ALIGNMENT;
        let mut relocated = disk.clone();
        relocated[..HEADER_BYTES as usize].copy_from_slice(&moved.encode().unwrap());
        assert!(StagedSource::open(Memory(relocated)).is_err());
        assert!(StagedSource::open(Memory(disk[..HEADER_BYTES as usize + 10].to_vec())).is_err());
    }
}
