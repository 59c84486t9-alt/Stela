//! The code entries an arm64 Mach-O image names in its own metadata, read
//! from the process's memory where the image is mapped, for ahead-of-time
//! translation (`super::ahead`): its entry point (`LC_MAIN`), function
//! starts (`LC_FUNCTION_STARTS`), symbols defined in executable sections
//! (`LC_SYMTAB`) and the functions its compact unwind tables
//! (`__TEXT,__unwind_info`) describe. Formats follow Apple's
//! `<mach-o/loader.h>`, `<mach-o/nlist.h>` and `<mach-o/compact_unwind_encoding.h>`.
//!
//! Every count and offset is bounded before it is used; a malformed or
//! unreadable image yields the entries read so far. Entries are candidates:
//! translating one never executes it, and a wrong one costs only time.
use std::ops::Range;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const HEADER_BYTES: usize = 32;
const LOAD_COMMAND_BYTES: usize = 8;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_MAIN: u32 = 0x8000_0028;
const SEGMENT_COMMAND_BYTES: usize = 72;
const SECTION_BYTES: usize = 80;
const NLIST_BYTES: usize = 16;
/// `n_type` bits: a debugging entry, and the type field with its
/// defined-in-section value.
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
/// Section attributes of code.
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const TEXT_SEGMENT: &[u8] = b"__TEXT";
const LINKEDIT_SEGMENT: &[u8] = b"__LINKEDIT";
const UNWIND_SECTION: &[u8] = b"__unwind_info";
/// `unwind_info_section_header` and its first-level index entries.
const UNWIND_VERSION: u32 = 1;
const UNWIND_HEADER_BYTES: usize = 28;
const UNWIND_INDEX_BYTES: usize = 12;
const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;
const UNWIND_REGULAR_ENTRY_BYTES: usize = 8;
const UNWIND_COMPRESSED_ENTRY_BYTES: usize = 4;
const UNWIND_COMPRESSED_OFFSET_MASK: u32 = 0x00ff_ffff;
/// The most load-command bytes, symbols and table bytes read from one
/// image.
const MAX_COMMAND_BYTES: usize = 1 << 20;
const MAX_SYMBOLS: usize = 1 << 21;
const MAX_TABLE_BYTES: usize = 64 << 20;
/// Pages searched below an address for its image's header: images whose
/// `__TEXT` is larger are found from a lower address.
pub(super) const MAX_SEARCH_PAGES: u64 = 1 << 14;
/// The page the header search steps by: an image's header starts a page.
pub(super) const SEARCH_PAGE: u64 = 4096;

/// Reads `buffer.len()` bytes of memory at an address, or fails.
pub(super) trait Memory {
    fn read(&self, address: u64, buffer: &mut [u8]) -> bool;

    fn bytes(&self, address: u64, length: usize) -> Option<Vec<u8>> {
        let mut bytes = vec![0; length];
        self.read(address, &mut bytes).then_some(bytes)
    }

    fn u32(&self, address: u64) -> Option<u32> {
        let mut word = [0; 4];
        self.read(address, &mut word)
            .then(|| u32::from_le_bytes(word))
    }
}

/// An image's executable range and the entries it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Image {
    /// Where its `__TEXT` segment is mapped.
    pub(super) text: Range<u64>,
    /// Its code entries, ascending and unique, inside its code sections.
    pub(super) entries: Vec<u64>,
}

/// The header of the image mapped at or below `address`: the first page
/// at or below it, at most [`MAX_SEARCH_PAGES`] down, that starts with an
/// arm64 Mach-O header; the search stops at an unreadable page. Each page
/// searched is passed to `searched`.
pub(super) fn find_header(
    memory: &impl Memory,
    address: u64,
    mut searched: impl FnMut(u64),
) -> Option<u64> {
    let mut page = address & !(SEARCH_PAGE - 1);
    for _ in 0..MAX_SEARCH_PAGES {
        searched(page);
        let magic = memory.u32(page)?;
        if magic == MH_MAGIC_64 && memory.u32(page + 4) == Some(CPU_TYPE_ARM64) {
            return Some(page);
        }
        page = page.checked_sub(SEARCH_PAGE)?;
    }
    None
}

/// Little-endian fields of a byte slice, `None` past its end.
fn field<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    field(bytes, at).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    field(bytes, at).map(u64::from_le_bytes)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    field(bytes, at).map(u16::from_le_bytes)
}

fn name(bytes: &[u8], at: usize) -> &[u8] {
    let raw = bytes.get(at..at + 16).unwrap_or_default();
    &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())]
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    address: u64,
    bytes: u64,
    file_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct Section {
    /// Its one-based index in the image, as `n_sect` names it.
    index: u8,
    address: u64,
    bytes: u64,
    code: bool,
}

/// The image whose header is mapped at `header`.
pub(super) fn read(memory: &impl Memory, header: u64) -> Option<Image> {
    let fixed = memory.bytes(header, HEADER_BYTES)?;
    if u32_at(&fixed, 0)? != MH_MAGIC_64 || u32_at(&fixed, 4)? != CPU_TYPE_ARM64 {
        return None;
    }
    let count = u32_at(&fixed, 16)? as usize;
    let size = u32_at(&fixed, 20)? as usize;
    if size > MAX_COMMAND_BYTES {
        return None;
    }
    let commands = memory.bytes(header + HEADER_BYTES as u64, size)?;
    let mut text = None;
    let mut linkedit = None;
    let mut sections = Vec::new();
    let mut unwind = None;
    let mut function_starts = None;
    let mut symtab = None;
    let mut main = None;
    let mut at = 0;
    for _ in 0..count {
        let command = u32_at(&commands, at)?;
        let length = u32_at(&commands, at + 4)? as usize;
        if length < LOAD_COMMAND_BYTES || at + length > commands.len() {
            return None;
        }
        let body = &commands[at..at + length];
        match command {
            LC_SEGMENT_64 => {
                let segment = Segment {
                    address: u64_at(body, 24)?,
                    bytes: u64_at(body, 32)?,
                    file_offset: u64_at(body, 40)?,
                };
                let segment_name = name(body, 8);
                if segment_name == TEXT_SEGMENT {
                    text = Some(segment);
                } else if segment_name == LINKEDIT_SEGMENT {
                    linkedit = Some(segment);
                }
                let section_count = u32_at(body, 64)? as usize;
                for index in 0..section_count {
                    let section = SEGMENT_COMMAND_BYTES + index * SECTION_BYTES;
                    let flags = u32_at(body, section + 64)?;
                    let parsed = Section {
                        index: u8::try_from(sections.len() + 1).unwrap_or(u8::MAX),
                        address: u64_at(body, section + 32)?,
                        bytes: u64_at(body, section + 40)?,
                        code: flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0,
                    };
                    if segment_name == TEXT_SEGMENT && name(body, section) == UNWIND_SECTION {
                        unwind = Some(parsed);
                    }
                    sections.push(parsed);
                }
            }
            LC_FUNCTION_STARTS => function_starts = Some((u32_at(body, 8)?, u32_at(body, 12)?)),
            LC_SYMTAB => symtab = Some((u32_at(body, 8)?, u32_at(body, 12)?)),
            LC_MAIN => main = Some(u64_at(body, 8)?),
            _ => {}
        }
        at += length;
    }
    let text = text?;
    let slide = header.wrapping_sub(text.address);
    let code: Vec<Section> = sections.iter().copied().filter(|s| s.code).collect();
    let in_code = |address: u64| {
        code.iter()
            .any(|s| address >= s.address && address - s.address < s.bytes)
    };
    // Linkedit data offsets are file offsets: dyld reads them at
    // `linkedit.vmaddr + offset - linkedit.fileoff`, in a shared cache too.
    let linkedit_address = |offset: u32| {
        linkedit.map(|l| {
            l.address
                .wrapping_add(u64::from(offset))
                .wrapping_sub(l.file_offset)
                .wrapping_add(slide)
        })
    };
    let mut entries = Vec::new();
    if let Some(offset) = main {
        entries.push(text.address.wrapping_add(offset));
    }
    if let Some((offset, size)) = function_starts
        && (size as usize) <= MAX_TABLE_BYTES
        && let Some(bytes) = linkedit_address(offset).and_then(|a| memory.bytes(a, size as usize))
    {
        entries.extend(function_starts_of(&bytes, text.address));
    }
    if let Some((offset, symbols)) = symtab
        && (symbols as usize) <= MAX_SYMBOLS
        && let Some(bytes) =
            linkedit_address(offset).and_then(|a| memory.bytes(a, symbols as usize * NLIST_BYTES))
    {
        for symbol in bytes.as_chunks::<NLIST_BYTES>().0 {
            let kind = symbol[4];
            let section = symbol[5];
            if kind & N_STAB == 0
                && kind & N_TYPE == N_SECT
                && code.iter().any(|s| s.index == section)
            {
                entries.push(u64_at(symbol, 8)?);
            }
        }
    }
    if let Some(section) = unwind
        && (section.bytes as usize) <= MAX_TABLE_BYTES
        && let Some(bytes) =
            memory.bytes(section.address.wrapping_add(slide), section.bytes as usize)
    {
        entries.extend(unwind_functions(&bytes, text.address));
    }
    let mut entries: Vec<u64> = entries
        .into_iter()
        .filter(|&address| address & 3 == 0 && in_code(address))
        .map(|address| address.wrapping_add(slide))
        .collect();
    entries.sort_unstable();
    entries.dedup();
    Some(Image {
        text: header..header.saturating_add(text.bytes),
        entries,
    })
}

/// `LC_FUNCTION_STARTS`: ULEB128 deltas, the first from `text`, ending at
/// a zero delta.
fn function_starts_of(bytes: &[u8], text: u64) -> Vec<u64> {
    let mut starts = Vec::new();
    let mut address = text;
    let mut delta = 0u64;
    let mut shift = 0;
    for &byte in bytes {
        if shift >= 64 {
            break;
        }
        delta |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 != 0 {
            continue;
        }
        if delta == 0 {
            break;
        }
        address = address.wrapping_add(delta);
        starts.push(address);
        delta = 0;
        shift = 0;
    }
    starts
}

/// The functions a compact unwind section describes: each first-level
/// index entry's function offset (from the image's base, `text`) and each
/// second-level entry's.
fn unwind_functions(bytes: &[u8], text: u64) -> Vec<u64> {
    let mut functions = Vec::new();
    let Some(version) = u32_at(bytes, 0) else {
        return functions;
    };
    if version != UNWIND_VERSION || bytes.len() < UNWIND_HEADER_BYTES {
        return functions;
    }
    let (Some(index_offset), Some(index_count)) = (u32_at(bytes, 20), u32_at(bytes, 24)) else {
        return functions;
    };
    // The last index entry only bounds the one before it.
    for entry in 0..index_count.saturating_sub(1) as usize {
        let at = index_offset as usize + entry * UNWIND_INDEX_BYTES;
        let (Some(function), Some(page)) = (u32_at(bytes, at), u32_at(bytes, at + 4)) else {
            break;
        };
        functions.push(text + u64::from(function));
        let page = page as usize;
        let (Some(kind), Some(entries_offset), Some(count)) = (
            u32_at(bytes, page),
            u16_at(bytes, page + 4),
            u16_at(bytes, page + 6),
        ) else {
            continue;
        };
        let first = page + usize::from(entries_offset);
        for index in 0..usize::from(count) {
            let offset = match kind {
                UNWIND_SECOND_LEVEL_REGULAR => {
                    u32_at(bytes, first + index * UNWIND_REGULAR_ENTRY_BYTES)
                }
                UNWIND_SECOND_LEVEL_COMPRESSED => {
                    u32_at(bytes, first + index * UNWIND_COMPRESSED_ENTRY_BYTES)
                        .map(|entry| function + (entry & UNWIND_COMPRESSED_OFFSET_MASK))
                }
                _ => None,
            };
            match offset {
                Some(offset) => functions.push(text + u64::from(offset)),
                None => break,
            }
        }
    }
    functions
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Sparse memory of whole pages.
    #[derive(Default)]
    pub(in crate::hosted::translations) struct Pages(pub BTreeMap<u64, Vec<u8>>);

    impl Pages {
        pub(in crate::hosted::translations) fn write(&mut self, address: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().enumerate() {
                let at = address + index as u64;
                let page = self
                    .0
                    .entry(at & !(SEARCH_PAGE - 1))
                    .or_insert_with(|| vec![0; SEARCH_PAGE as usize]);
                page[(at & (SEARCH_PAGE - 1)) as usize] = *byte;
            }
        }
    }

    impl Memory for Pages {
        fn read(&self, address: u64, buffer: &mut [u8]) -> bool {
            for (index, byte) in buffer.iter_mut().enumerate() {
                let at = address + index as u64;
                match self.0.get(&(at & !(SEARCH_PAGE - 1))) {
                    Some(page) => *byte = page[(at & (SEARCH_PAGE - 1)) as usize],
                    None => return false,
                }
            }
            true
        }
    }

    fn uleb(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn segment(name: &[u8], address: u64, bytes: u64, file: u64, sections: &[Vec<u8>]) -> Vec<u8> {
        let mut command = Vec::new();
        command.extend(LC_SEGMENT_64.to_le_bytes());
        command.extend(
            ((SEGMENT_COMMAND_BYTES + sections.len() * SECTION_BYTES) as u32).to_le_bytes(),
        );
        let mut padded = [0u8; 16];
        padded[..name.len()].copy_from_slice(name);
        command.extend(padded);
        for value in [address, bytes, file, bytes] {
            command.extend(value.to_le_bytes());
        }
        command.extend(
            [7u32, 5, sections.len() as u32, 0]
                .iter()
                .flat_map(|v| v.to_le_bytes()),
        );
        for section in sections {
            command.extend(section);
        }
        command
    }

    fn section(name: &[u8], address: u64, bytes: u64, flags: u32) -> Vec<u8> {
        let mut out = [0u8; SECTION_BYTES];
        out[..name.len()].copy_from_slice(name);
        out[16..22].copy_from_slice(TEXT_SEGMENT);
        out[32..40].copy_from_slice(&address.to_le_bytes());
        out[40..48].copy_from_slice(&bytes.to_le_bytes());
        out[64..68].copy_from_slice(&flags.to_le_bytes());
        out.to_vec()
    }

    /// An image whose unslid `__TEXT` is at 0x1_0000_0000 with code at
    /// +0x1000..+0x2000, mapped at `header`, its linkedit at +0x8000 (file
    /// offset 0x8000).
    pub(in crate::hosted::translations) fn image(memory: &mut Pages, header: u64) {
        const TEXT: u64 = 0x1_0000_0000;
        let linkedit = header + 0x8000;
        let mut starts = Vec::new();
        for delta in [0x1000u64, 0x40, 0x80] {
            uleb(delta, &mut starts);
        }
        starts.push(0);
        memory.write(linkedit, &starts);
        // One defined code symbol, one debugging entry, one data symbol.
        let mut symbols = Vec::new();
        for (kind, section, value) in [
            (N_SECT | 1, 1u8, TEXT + 0x1100),
            (N_STAB, 1, TEXT + 0x1200),
            (N_SECT, 2, TEXT + 0x1300),
        ] {
            symbols.extend(0u32.to_le_bytes());
            symbols.extend([kind, section, 0, 0]);
            symbols.extend(value.to_le_bytes());
        }
        memory.write(linkedit + 0x100, &symbols);
        // Compact unwind: one index entry (and the bounding one), one
        // compressed page with two functions.
        let mut unwind = Vec::new();
        for value in [UNWIND_VERSION, 0, 0, 0, 0, UNWIND_HEADER_BYTES as u32, 2] {
            unwind.extend(value.to_le_bytes());
        }
        let page = UNWIND_HEADER_BYTES + 2 * UNWIND_INDEX_BYTES;
        for value in [0x1400u32, page as u32, 0, 0x2000, 0, 0] {
            unwind.extend(value.to_le_bytes());
        }
        unwind.extend(UNWIND_SECOND_LEVEL_COMPRESSED.to_le_bytes());
        unwind.extend(12u16.to_le_bytes());
        unwind.extend(2u16.to_le_bytes());
        unwind.extend([0u8; 4]);
        unwind.extend(0x10u32.to_le_bytes());
        unwind.extend(0x0300_0020u32.to_le_bytes());
        memory.write(header + 0x3000, &unwind);
        let mut commands = Vec::new();
        commands.extend(segment(
            TEXT_SEGMENT,
            TEXT,
            0x4000,
            0,
            &[
                section(b"__text", TEXT + 0x1000, 0x1000, S_ATTR_PURE_INSTRUCTIONS),
                section(b"__const", TEXT + 0x2000, 0x1000, 0),
                section(UNWIND_SECTION, TEXT + 0x3000, unwind.len() as u64, 0),
            ],
        ));
        commands.extend(segment(
            LINKEDIT_SEGMENT,
            TEXT + 0x8000,
            0x1000,
            0x8000,
            &[],
        ));
        commands.extend(LC_FUNCTION_STARTS.to_le_bytes());
        commands.extend(16u32.to_le_bytes());
        commands.extend(0x8000u32.to_le_bytes());
        commands.extend((starts.len() as u32).to_le_bytes());
        commands.extend(LC_SYMTAB.to_le_bytes());
        commands.extend(24u32.to_le_bytes());
        commands.extend(0x8100u32.to_le_bytes());
        commands.extend(3u32.to_le_bytes());
        commands.extend([0u8; 8]);
        commands.extend(LC_MAIN.to_le_bytes());
        commands.extend(24u32.to_le_bytes());
        commands.extend(0x1800u64.to_le_bytes());
        commands.extend(0u64.to_le_bytes());
        let mut fixed = Vec::new();
        for value in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            2,
            5,
            commands.len() as u32,
            0,
            0,
        ] {
            fixed.extend(value.to_le_bytes());
        }
        memory.write(header, &fixed);
        memory.write(header + HEADER_BYTES as u64, &commands);
        // The code and the rest of the text pages are mapped.
        memory.write(header + 0x1000, &[0; 0x2000]);
        memory.write(header + 0x3fff, &[0]);
    }

    #[test]
    fn an_images_entries_come_from_its_main_function_starts_symbols_and_unwind_tables() {
        let mut memory = Pages::default();
        let header = 0x2_3450_0000;
        image(&mut memory, header);
        let found = find_header(&memory, header + 0x1234, |_| {});
        assert_eq!(found, Some(header));
        let image = read(&memory, header).unwrap();
        assert_eq!(image.text, header..header + 0x4000);
        let offsets: Vec<u64> = image.entries.iter().map(|e| e - header).collect();
        // main 0x1800; starts 0x1000, 0x1040, 0x10c0; symbol 0x1100 (not
        // the debugging or data ones); unwind 0x1400, 0x1410, 0x1420.
        assert_eq!(
            offsets,
            [
                0x1000, 0x1040, 0x10c0, 0x1100, 0x1400, 0x1410, 0x1420, 0x1800
            ]
        );
    }

    #[test]
    fn the_header_search_stops_at_unreadable_memory_and_malformed_images_yield_nothing() {
        let mut memory = Pages::default();
        memory.write(0x5000, &[1; 8]);
        let mut searched = Vec::new();
        assert_eq!(
            find_header(&memory, 0x5010, |page| searched.push(page)),
            None
        );
        assert_eq!(searched, [0x5000, 0x4000]);
        let mut fixed = Vec::new();
        for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2, 1, 0x40, 0, 0] {
            fixed.extend(value.to_le_bytes());
        }
        memory.write(0x5000, &fixed);
        // A command longer than the commands.
        memory.write(0x5020, &[0x19, 0, 0, 0, 0xff, 0, 0, 0]);
        assert_eq!(read(&memory, 0x5000), None);
        assert!(function_starts_of(&[0x80, 0x80, 0x80], 0x1000).is_empty());
        assert!(unwind_functions(&[1, 0, 0, 0], 0).is_empty());
    }
}
