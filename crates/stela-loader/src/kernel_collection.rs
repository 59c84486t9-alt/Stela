//! Arm64 kernel collections (`MH_FILESET`) and the standalone boot monitors
//! (`MH_EXECUTE` SPTM and TXM) that load beside them.
//!
//! Load-command layouts follow public XNU `EXTERNAL_HEADERS/mach-o/loader.h`
//! at `xnu-12377.121.6`: `LC_SEGMENT_64`, `LC_UNIXTHREAD` and
//! `LC_FILESET_ENTRY`. A boot loader copies each segment's file bytes to
//! `load base + (vmaddr - lowest vmaddr)` and zero-fills the rest of
//! `vmsize`, as Asahi m1n1 `proxyclient/m1n1/macho.py` `prepare_image` does.
use super::thread_state::{Arm64UnixThread, unix_thread};
use crate::Result;
use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
use object::macho;
use serde::Serialize;
use stela_contracts::{refuse, require};

const MACH_HEADER_64_BYTES: usize = 32;
const SEGMENT_COMMAND_64_BYTES: usize = 72;
const FILESET_ENTRY_COMMAND_BYTES: usize = 32;
const SEGMENT_NAME_BYTES: usize = 16;
/// `LC_FILESET_ENTRY` is `0x35 | LC_REQ_DYLD`.
const LC_FILESET_ENTRY: u32 = macho::LC_FILESET_ENTRY;
/// The arm64 kernel page; segment and region boundaries are multiples of it.
pub const PAGE_BYTES: u64 = 0x4000;
const MAX_LOAD_COMMAND_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub max_protection: u32,
    pub initial_protection: u32,
}

impl Segment {
    pub fn vm_end(&self) -> u64 {
        self.vm_address + self.vm_size
    }
}

/// One image inside a fileset, such as `com.apple.kernel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilesetEntry {
    pub id: String,
    pub vm_address: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelCollection {
    pub file_type: u32,
    pub cpu_subtype: u32,
    pub uuid: Option<String>,
    pub segments: Vec<Segment>,
    pub fileset_entries: Vec<FilesetEntry>,
    pub thread: Arm64UnixThread,
    /// Lowest segment `vmaddr`; the image's load base maps here.
    pub vm_base: u64,
    /// End of the highest segment.
    pub vm_end: u64,
}

fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(refuse!("truncated Mach-O field"))?
            .try_into()
            .unwrap(),
    ))
}

fn quad(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(refuse!("truncated Mach-O field"))?
            .try_into()
            .unwrap(),
    ))
}

fn fixed_name(bytes: &[u8]) -> Result<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(core::str::from_utf8(&bytes[..end])
        .map_err(|_| refuse!("Mach-O name is not UTF-8"))?
        .to_owned())
}

impl KernelCollection {
    /// Parse an `MH_FILESET` kernel collection.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_kind(bytes, macho::MH_FILESET)
    }

    /// Parse an `MH_EXECUTE` boot image such as SPTM or TXM.
    pub fn parse_executable(bytes: &[u8]) -> Result<Self> {
        Self::parse_kind(bytes, macho::MH_EXECUTE)
    }

    fn parse_kind(bytes: &[u8], expected_type: u32) -> Result<Self> {
        require!(
            word(bytes, 0)? == macho::MH_MAGIC_64,
            "not a little-endian 64-bit Mach-O"
        );
        require!(
            word(bytes, 4)? == macho::CPU_TYPE_ARM64,
            "not an arm64 Mach-O"
        );
        let cpu_subtype = word(bytes, 8)?;
        let file_type = word(bytes, 12)?;
        require!(
            file_type == expected_type,
            "Mach-O file type {file_type} is not the expected {expected_type}",
            file_type,
            expected_type
        );
        let command_count = word(bytes, 16)? as usize;
        let commands_bytes = word(bytes, 20)? as usize;
        require!(
            commands_bytes <= MAX_LOAD_COMMAND_BYTES,
            "load commands exceed 1 MiB"
        );
        let commands = bytes
            .get(MACH_HEADER_64_BYTES..MACH_HEADER_64_BYTES + commands_bytes)
            .ok_or(refuse!("load commands extend past the file"))?;
        let mut segments = vec![];
        let mut fileset_entries = vec![];
        let mut thread = None;
        let mut uuid = None;
        let mut offset = 0;
        for _ in 0..command_count {
            let command = word(commands, offset)?;
            let size = word(commands, offset + 4)? as usize;
            require!(
                size >= 8 && size.is_multiple_of(8),
                "malformed load command size {size}",
                size
            );
            let raw = commands
                .get(offset..offset + size)
                .ok_or(refuse!("load command extends past sizeofcmds"))?;
            match command {
                macho::LC_SEGMENT_64 => segments.push(segment(raw)?),
                LC_FILESET_ENTRY => fileset_entries.push(fileset_entry(raw)?),
                macho::LC_UNIXTHREAD => {
                    require!(thread.is_none(), "duplicate LC_UNIXTHREAD");
                    thread = Some(unix_thread(raw)?);
                }
                macho::LC_UUID => {
                    uuid = Some(hex::encode(raw.get(8..24).ok_or(refuse!("short LC_UUID"))?))
                }
                _ => {}
            }
            offset += size;
        }
        require!(
            offset == commands_bytes,
            "load commands do not fill sizeofcmds"
        );
        let thread = thread.ok_or(refuse!("image has no LC_UNIXTHREAD entry point"))?;
        require!(!segments.is_empty(), "image has no segments");
        let mut ordered: Vec<&Segment> = segments.iter().filter(|s| s.vm_size > 0).collect();
        ordered.sort_by_key(|s| s.vm_address);
        for pair in ordered.windows(2) {
            require!(
                pair[0].vm_end() <= pair[1].vm_address,
                "segments {first} and {second} overlap",
                first = pair[0].name,
                second = pair[1].name
            );
        }
        for segment in &segments {
            require!(
                segment.file_size <= segment.vm_size,
                "segment {name} file bytes exceed its VM size",
                name = segment.name
            );
            let end = segment
                .file_offset
                .checked_add(segment.file_size)
                .ok_or(refuse!("segment file range overflows"))?;
            require!(
                end <= bytes.len() as u64,
                "segment {name} extends past the file",
                name = segment.name
            );
        }
        let vm_base = ordered
            .first()
            .ok_or(refuse!("image has no mapped segments"))?
            .vm_address;
        let vm_end = ordered.iter().map(|s| s.vm_end()).max().unwrap_or(vm_base);
        let collection = Self {
            file_type,
            cpu_subtype,
            uuid,
            segments,
            fileset_entries,
            thread,
            vm_base,
            vm_end,
        };
        collection
            .segment_containing(collection.thread.pc)
            .ok_or(refuse!("entry point lies outside every segment"))?;
        Ok(collection)
    }

    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }

    pub fn segment_containing(&self, address: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .find(|s| (s.vm_address..s.vm_end()).contains(&address))
    }

    pub fn fileset_entry(&self, id: &str) -> Option<&FilesetEntry> {
        self.fileset_entries.iter().find(|e| e.id == id)
    }

    /// Bytes from the load base to the end of the highest segment.
    pub fn image_bytes(&self) -> u64 {
        self.vm_end - self.vm_base
    }

    /// Entry PC relative to the load base.
    pub fn entry_offset(&self) -> u64 {
        self.thread.pc - self.vm_base
    }

    /// Physical address of a linked virtual address for an image whose load
    /// base is placed at `load_base`.
    pub fn physical_address(&self, load_base: u64, address: u64) -> Result<u64> {
        require!(
            (self.vm_base..self.vm_end).contains(&address),
            "{address:#x} lies outside the image",
            address
        );
        Ok(load_base + (address - self.vm_base))
    }

    /// The image as it lies in memory from its load base: every segment's
    /// file bytes at its VM offset, with zero fill elsewhere.
    pub fn memory_image(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let length = self.image_bytes() as usize;
        let mut image = vec![0u8; length];
        for segment in &self.segments {
            let source = &bytes
                [segment.file_offset as usize..(segment.file_offset + segment.file_size) as usize];
            let start = (segment.vm_address - self.vm_base) as usize;
            image[start..start + source.len()].copy_from_slice(source);
        }
        Ok(image)
    }

    /// Byte range from the load base covering `first` through `last`.
    pub fn span(&self, first: &str, last: &str) -> Result<core::ops::Range<u64>> {
        let start = self
            .segment(first)
            .ok_or_else(|| refuse!("image has no segment {first}", first))?;
        let end = self
            .segment(last)
            .ok_or_else(|| refuse!("image has no segment {last}", last))?;
        if end.vm_end() < start.vm_address {
            return Err(refuse!("segment {last} precedes {first}", last, first).into());
        }
        Ok(start.vm_address - self.vm_base..end.vm_end() - self.vm_base)
    }
}

fn segment(raw: &[u8]) -> Result<Segment> {
    require!(raw.len() >= SEGMENT_COMMAND_64_BYTES, "short LC_SEGMENT_64");
    Ok(Segment {
        name: fixed_name(&raw[8..8 + SEGMENT_NAME_BYTES])?,
        vm_address: quad(raw, 24)?,
        vm_size: quad(raw, 32)?,
        file_offset: quad(raw, 40)?,
        file_size: quad(raw, 48)?,
        max_protection: word(raw, 56)?,
        initial_protection: word(raw, 60)?,
    })
}

fn fileset_entry(raw: &[u8]) -> Result<FilesetEntry> {
    require!(
        raw.len() >= FILESET_ENTRY_COMMAND_BYTES,
        "short LC_FILESET_ENTRY"
    );
    let id_offset = word(raw, 24)? as usize;
    require!(
        (FILESET_ENTRY_COMMAND_BYTES..raw.len()).contains(&id_offset),
        "fileset entry id lies outside its command"
    );
    let id = raw[id_offset..]
        .split(|&b| b == 0)
        .next()
        .ok_or(refuse!("fileset entry id is not terminated"))?;
    Ok(FilesetEntry {
        id: core::str::from_utf8(id)
            .map_err(|_| refuse!("fileset entry id is not UTF-8"))?
            .to_owned(),
        vm_address: quad(raw, 8)?,
        file_offset: quad(raw, 16)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use anyhow::Result;

    pub(crate) struct Builder {
        file_type: u32,
        commands: Vec<Vec<u8>>,
        body: Vec<u8>,
    }

    pub(crate) const BASE: u64 = 0xfffffe0007004000;

    impl Builder {
        pub(crate) fn new(file_type: u32) -> Self {
            Self {
                file_type,
                commands: vec![],
                body: vec![],
            }
        }

        pub(crate) fn segment(mut self, name: &str, vm_size: u64, file: &[u8]) -> Self {
            let file_offset = self.body.len() as u64;
            let vm_address = BASE + file_offset;
            let mut raw = vec![];
            raw.extend(macho::LC_SEGMENT_64.to_le_bytes());
            raw.extend((SEGMENT_COMMAND_64_BYTES as u32).to_le_bytes());
            let mut segname = [0u8; 16];
            segname[..name.len()].copy_from_slice(name.as_bytes());
            raw.extend(segname);
            for value in [vm_address, vm_size, file_offset, file.len() as u64] {
                raw.extend(value.to_le_bytes());
            }
            raw.extend([5u32, 5, 0, 0].iter().flat_map(|v| v.to_le_bytes()));
            self.commands.push(raw);
            self.body.extend(file);
            self.body.resize(file_offset as usize + vm_size as usize, 0);
            self
        }

        pub(crate) fn fileset(mut self, id: &str, vm_address: u64) -> Self {
            let mut raw = vec![];
            raw.extend(LC_FILESET_ENTRY.to_le_bytes());
            let size = (FILESET_ENTRY_COMMAND_BYTES + id.len() + 1).next_multiple_of(8);
            raw.extend((size as u32).to_le_bytes());
            raw.extend(vm_address.to_le_bytes());
            raw.extend((vm_address - BASE).to_le_bytes());
            raw.extend((FILESET_ENTRY_COMMAND_BYTES as u32).to_le_bytes());
            raw.extend(0u32.to_le_bytes());
            raw.extend(id.as_bytes());
            raw.resize(size, 0);
            self.commands.push(raw);
            self
        }

        pub(crate) fn thread(mut self, pc: u64) -> Self {
            let mut raw = vec![];
            raw.extend(macho::LC_UNIXTHREAD.to_le_bytes());
            raw.extend(288u32.to_le_bytes());
            raw.extend(6u32.to_le_bytes());
            raw.extend(68u32.to_le_bytes());
            raw.extend([0u8; 32 * 8]);
            raw.extend(pc.to_le_bytes());
            raw.extend([0u8; 8]);
            self.commands.push(raw);
            self
        }

        /// The header and load commands occupy the first page, which the
        /// first segment must therefore cover.
        pub(crate) fn build(self) -> Vec<u8> {
            let commands: Vec<u8> = self.commands.concat();
            let mut out = vec![];
            for value in [
                macho::MH_MAGIC_64,
                macho::CPU_TYPE_ARM64,
                0xc000_0002,
                self.file_type,
                self.commands.len() as u32,
                commands.len() as u32,
                0,
                0,
            ] {
                out.extend(value.to_le_bytes());
            }
            out.extend(commands);
            assert!(out.len() <= self.body.len());
            let mut body = self.body;
            body[..out.len()].copy_from_slice(&out);
            body
        }
    }

    pub(crate) fn fileset_fixture() -> Vec<u8> {
        Builder::new(macho::MH_FILESET)
            .segment("__TEXT", 0x4000, &[0; 0x4000])
            .segment("__TEXT_EXEC", 0x4000, &[0xaa; 0x10])
            .segment("__LINKEDIT", 0x4000, &[0xbb; 0x20])
            .fileset("com.apple.kernel", BASE + 0x4000)
            .thread(BASE + 0x4008)
            .build()
    }

    #[test]
    fn reads_segments_fileset_entries_and_entry() -> Result<()> {
        let bytes = fileset_fixture();
        let kc = KernelCollection::parse(&bytes)?;
        assert_eq!(kc.segments.len(), 3);
        assert_eq!(kc.vm_base, BASE);
        assert_eq!(kc.image_bytes(), 0xc000);
        assert_eq!(kc.entry_offset(), 0x4008);
        assert_eq!(
            kc.segment_containing(kc.thread.pc).unwrap().name,
            "__TEXT_EXEC"
        );
        assert_eq!(
            kc.fileset_entry("com.apple.kernel").map(|e| e.file_offset),
            Some(0x4000)
        );
        assert_eq!(
            kc.physical_address(0x8_0000_0000, BASE + 0x4008)?,
            0x8_0000_4008
        );
        assert!(kc.physical_address(0x8_0000_0000, BASE + 0xc000).is_err());
        assert_eq!(kc.span("__TEXT_EXEC", "__LINKEDIT")?, 0x4000..0xc000);
        let image = kc.memory_image(&bytes)?;
        assert_eq!(image.len(), 0xc000);
        assert_eq!(&image[0x4000..0x4010], &[0xaa; 0x10]);
        assert_eq!(image[0x4010], 0);
        assert!(KernelCollection::parse_executable(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn rejects_missing_entry_and_out_of_range_segments() {
        let no_thread = Builder::new(macho::MH_FILESET)
            .segment("__TEXT", 0x4000, &[0; 0x4000])
            .build();
        assert!(KernelCollection::parse(&no_thread).is_err());
        let outside = Builder::new(macho::MH_EXECUTE)
            .segment("__TEXT", 0x4000, &[0; 0x4000])
            .thread(BASE + 0x8000)
            .build();
        assert!(KernelCollection::parse_executable(&outside).is_err());
        let mut truncated = fileset_fixture();
        truncated.truncate(0x8008);
        assert!(KernelCollection::parse(&truncated).is_err());
    }
}
