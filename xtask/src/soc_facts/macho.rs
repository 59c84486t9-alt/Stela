//! The Mach-O structure the extractor reads (`<mach-o/loader.h>`): 64-bit
//! segments and sections, and a fileset's entries, so that every code word
//! has a virtual address, a file offset and an owning image.
use anyhow::{Context, Result, ensure};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const HEADER_BYTES: usize = 32;
const LC_SEGMENT_64: u32 = 0x19;
const LC_FILESET_ENTRY: u32 = 0x8000_0035;
const VM_PROT_EXECUTE: u32 = 4;
const SEGMENT_COMMAND_BYTES: usize = 72;
const SECTION_BYTES: usize = 80;
const NAME_BYTES: usize = 16;

#[derive(Debug, Clone)]
pub struct Section {
    pub segment: String,
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct Segment {
    pub address: u64,
    pub offset: u64,
    pub file_size: u64,
    pub executable: bool,
}

/// A fileset entry: its identifier and the file offset of its header.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Image {
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub entries: Vec<Entry>,
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("Mach-O truncated in a 32-bit field")?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .context("Mach-O truncated in a 64-bit field")?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}

fn name_at(data: &[u8], offset: usize) -> Result<String> {
    let bytes = data
        .get(offset..offset + NAME_BYTES)
        .context("Mach-O truncated in a name")?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(NAME_BYTES);
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn c_string(data: &[u8], offset: usize) -> String {
    let tail = data.get(offset..).unwrap_or_default();
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

/// The 64-bit Mach-O header at `base` in `data`.
pub fn parse(data: &[u8], base: usize) -> Result<Image> {
    ensure!(
        u32_at(data, base)? == MH_MAGIC_64,
        "not a 64-bit Mach-O at {base:#x}"
    );
    let commands = u32_at(data, base + 16)? as usize;
    let mut offset = base + HEADER_BYTES;
    let mut image = Image::default();
    for _ in 0..commands {
        let command = u32_at(data, offset)?;
        let size = u32_at(data, offset + 4)? as usize;
        ensure!(size >= 8, "Mach-O load command of {size} bytes");
        match command {
            LC_SEGMENT_64 => {
                image.segments.push(Segment {
                    address: u64_at(data, offset + 24)?,
                    offset: u64_at(data, offset + 40)?,
                    file_size: u64_at(data, offset + 48)?,
                    executable: u32_at(data, offset + 60)? & VM_PROT_EXECUTE != 0,
                });
                let sections = u32_at(data, offset + 64)? as usize;
                for index in 0..sections {
                    let at = offset + SEGMENT_COMMAND_BYTES + index * SECTION_BYTES;
                    image.sections.push(Section {
                        name: name_at(data, at)?,
                        segment: name_at(data, at + NAME_BYTES)?,
                        address: u64_at(data, at + 32)?,
                        size: u64_at(data, at + 40)?,
                        offset: u64::from(u32_at(data, at + 48)?),
                    });
                }
            }
            LC_FILESET_ENTRY => {
                let name_offset = u32_at(data, offset + 24)? as usize;
                image.entries.push(Entry {
                    name: c_string(data, offset + name_offset),
                    offset: u64_at(data, offset + 16)?,
                });
            }
            _ => {}
        }
        offset += size;
    }
    Ok(image)
}

impl Image {
    pub fn section(&self, segment: &str, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.segment == segment && section.name == name)
    }

    /// The file offset of virtual address `address`.
    pub fn file_offset(&self, address: u64) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| (s.address..s.address + s.file_size).contains(&address))
            .map(|s| s.offset + (address - s.address))
    }

    /// The executable segments' (address, file offset, bytes).
    pub fn code(&self) -> Vec<(u64, u64, u64)> {
        self.segments
            .iter()
            .filter(|segment| segment.executable && segment.file_size != 0)
            .map(|segment| (segment.address, segment.offset, segment.file_size))
            .collect()
    }
}

/// Every 32-bit word of the executable segments as (address, file offset,
/// word).
pub fn words<'a>(image: &Image, data: &'a [u8]) -> impl Iterator<Item = (u64, u64, u32)> + 'a {
    image
        .code()
        .into_iter()
        .flat_map(move |(address, offset, bytes)| {
            let start = offset as usize;
            let end = (start + bytes as usize).min(data.len());
            data[start..end]
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
                .map(move |(index, word)| {
                    let step = 4 * index as u64;
                    (address + step, offset + step, u32::from_le_bytes(*word))
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(name: &str, address: u64, offset: u64, bytes: u64, protection: u32) -> Vec<u8> {
        let mut command = Vec::new();
        command.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        command.extend_from_slice(&(SEGMENT_COMMAND_BYTES as u32).to_le_bytes());
        let mut name_bytes = [0u8; NAME_BYTES];
        name_bytes[..name.len()].copy_from_slice(name.as_bytes());
        command.extend_from_slice(&name_bytes);
        for value in [address, bytes, offset, bytes] {
            command.extend_from_slice(&value.to_le_bytes());
        }
        for value in [protection, protection, 0, 0] {
            command.extend_from_slice(&value.to_le_bytes());
        }
        command
    }

    #[test]
    fn executable_segments_give_each_word_its_address_and_offset() {
        let text = segment("__TEXT_EXEC", 0x1000, 0x100, 8, VM_PROT_EXECUTE | 1);
        let data_segment = segment("__DATA", 0x2000, 0x108, 4, 3);
        let mut file = Vec::new();
        for value in [MH_MAGIC_64, 0x0100_000c, 0, 2, 2, 144, 0, 0] {
            file.extend_from_slice(&value.to_le_bytes());
        }
        file.extend(text);
        file.extend(data_segment);
        file.resize(0x100, 0);
        file.extend_from_slice(&0xd503_201fu32.to_le_bytes());
        file.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        file.extend_from_slice(&7u32.to_le_bytes());
        let image = parse(&file, 0).unwrap();
        assert_eq!(image.file_offset(0x2000), Some(0x108));
        let words: Vec<_> = words(&image, &file).collect();
        assert_eq!(
            words,
            vec![(0x1000, 0x100, 0xd503_201f), (0x1004, 0x104, 0xd65f_03c0)]
        );
        assert!(parse(&file, 4).is_err());
    }
}
