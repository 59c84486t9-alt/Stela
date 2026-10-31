//! The Mach-O load commands an auxiliary collection and its kexts carry,
//! as XNU `EXTERNAL_HEADERS/mach-o/loader.h` at `xnu-12377.121.6` lays them
//! out.
use super::fit;
use crate::Result;
use alloc::vec::Vec;
use object::macho;

pub const HEADER_BYTES: usize = 32;
const SEGMENT_BYTES: usize = 72;
const SECTION_BYTES: usize = 80;
const UUID_BYTES: usize = 24;
const SYMTAB_BYTES: usize = 24;
const DYSYMTAB_BYTES: usize = 80;
const LINKEDIT_DATA_BYTES: usize = 16;
const FILESET_ENTRY_BYTES: usize = 32;
pub const NLIST_BYTES: usize = 16;

pub fn segment_bytes(sections: usize) -> usize {
    SEGMENT_BYTES + SECTION_BYTES * sections
}

pub fn fileset_entry_bytes(id: &str) -> usize {
    (FILESET_ENTRY_BYTES + id.len() + 1).next_multiple_of(8)
}

/// A kext's header with its five segments and `sections` sections.
pub fn kext_header_bytes(sections: usize) -> usize {
    HEADER_BYTES
        + 5 * SEGMENT_BYTES
        + SECTION_BYTES * sections
        + SYMTAB_BYTES
        + DYSYMTAB_BYTES
        + UUID_BYTES
}

/// A collection's header with its `segments` segments, `sections` sections
/// and one fileset entry per id.
pub fn fileset_header_bytes<'a>(
    segments: usize,
    sections: usize,
    ids: impl Iterator<Item = &'a str>,
) -> usize {
    HEADER_BYTES
        + UUID_BYTES
        + SEGMENT_BYTES * segments
        + SECTION_BYTES * sections
        + LINKEDIT_DATA_BYTES
        + ids.map(fileset_entry_bytes).sum::<usize>()
}

pub struct SegmentCommand<'a> {
    pub name: &'a str,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: u32,
    pub sections: Vec<SectionCommand<'a>>,
}

pub struct SectionCommand<'a> {
    pub name: &'a str,
    pub segment: &'a str,
    pub address: u64,
    pub size: u64,
    pub file_offset: u32,
    pub align: u32,
    pub flags: u32,
}

#[derive(Default)]
pub struct Commands {
    bytes: Vec<u8>,
    count: u32,
}

pub fn name16(name: &str) -> [u8; 16] {
    let mut field = [0; 16];
    field[..name.len()].copy_from_slice(name.as_bytes());
    field
}

impl Commands {
    fn begin(&mut self, command: u32, size: usize) -> Result<()> {
        self.count += 1;
        self.bytes.extend(command.to_le_bytes());
        self.bytes
            .extend(fit::<u32, _>(size, "a load command's size")?.to_le_bytes());
        Ok(())
    }

    fn words(&mut self, words: &[u32]) {
        self.bytes
            .extend(words.iter().flat_map(|word| word.to_le_bytes()));
    }

    pub fn segment(&mut self, segment: &SegmentCommand<'_>) -> Result<()> {
        self.begin(macho::LC_SEGMENT_64, segment_bytes(segment.sections.len()))?;
        self.bytes.extend(name16(segment.name));
        for value in [
            segment.address,
            segment.size,
            segment.file_offset,
            segment.file_size,
        ] {
            self.bytes.extend(value.to_le_bytes());
        }
        self.words(&[
            segment.protection,
            segment.protection,
            fit(segment.sections.len(), "a segment's section count")?,
            0,
        ]);
        for section in &segment.sections {
            self.bytes.extend(name16(section.name));
            self.bytes.extend(name16(section.segment));
            self.bytes.extend(section.address.to_le_bytes());
            self.bytes.extend(section.size.to_le_bytes());
            self.words(&[
                section.file_offset,
                section.align,
                0,
                0,
                section.flags,
                0,
                0,
                0,
            ]);
        }
        Ok(())
    }

    pub fn uuid(&mut self, uuid: [u8; 16]) -> Result<()> {
        self.begin(macho::LC_UUID, UUID_BYTES)?;
        self.bytes.extend(uuid);
        Ok(())
    }

    /// `LC_SYMTAB` and the `LC_DYSYMTAB` that partitions it into `locals`
    /// then `externals`, with nothing undefined.
    pub fn symbols(
        &mut self,
        symbols: u32,
        strings: u32,
        locals: u32,
        externals: u32,
        string_bytes: u32,
    ) -> Result<()> {
        self.begin(macho::LC_SYMTAB, SYMTAB_BYTES)?;
        self.words(&[symbols, locals + externals, strings, string_bytes]);
        self.begin(macho::LC_DYSYMTAB, DYSYMTAB_BYTES)?;
        self.words(&[0, locals, locals, externals, locals + externals, 0]);
        self.words(&[0; 12]);
        Ok(())
    }

    pub fn chained_fixups(&mut self, offset: u32, size: u32) -> Result<()> {
        self.begin(macho::LC_DYLD_CHAINED_FIXUPS, LINKEDIT_DATA_BYTES)?;
        self.words(&[offset, size]);
        Ok(())
    }

    pub fn fileset_entry(&mut self, id: &str, address: u64, file_offset: u64) -> Result<()> {
        let size = fileset_entry_bytes(id);
        let start = self.bytes.len();
        self.begin(macho::LC_FILESET_ENTRY, size)?;
        self.bytes.extend(address.to_le_bytes());
        self.bytes.extend(file_offset.to_le_bytes());
        self.words(&[
            fit(FILESET_ENTRY_BYTES, "the fileset entry name offset")?,
            0,
        ]);
        self.bytes.extend(id.as_bytes());
        self.bytes.resize(start + size, 0);
        Ok(())
    }

    /// The Mach-O header followed by the commands.
    pub fn finish(self, file_type: u32, cpu_subtype: u32, flags: u32) -> Result<Vec<u8>> {
        let mut image = Vec::with_capacity(HEADER_BYTES + self.bytes.len());
        for word in [
            macho::MH_MAGIC_64,
            macho::CPU_TYPE_ARM64,
            cpu_subtype,
            file_type,
            self.count,
            fit(self.bytes.len(), "the load commands' size")?,
            flags,
            0,
        ] {
            image.extend(word.to_le_bytes());
        }
        image.extend(self.bytes);
        Ok(image)
    }
}
