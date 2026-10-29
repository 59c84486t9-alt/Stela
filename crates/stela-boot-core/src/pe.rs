//! Bounded inventory of the firmware-loaded PE32+ image. Reads address
//! loaded RVAs, never file offsets. The callback must read from the kept
//! UEFI allocation; bounds are checked here before every callback.
use alloc::vec::Vec;

pub const PAGE: usize = 4096;
const DOS_HEADER: usize = 64;
const PE_HEADER: usize = 24;
const OPTIONAL_HEADER: usize = 112;
const SECTION_HEADER: usize = 40;
const EXECUTE: u32 = 0x2000_0000;
const READ: u32 = 0x4000_0000;
const WRITE: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub start: usize,
    /// Exact readable source length, with no rounded source access.
    pub bytes: usize,
    /// Allocation length for a private copy; its tail must be zeroed.
    pub mapped_bytes: usize,
    pub end: usize,
}

/// Nonallocating: safe to call before the pristine static-state snapshot.
pub fn loaded_extent(start: usize, bytes: u64) -> Result<Extent, &'static str> {
    let bytes = usize::try_from(bytes).map_err(|_| "loaded image length exceeds usize")?;
    if start == 0 || !start.is_multiple_of(PAGE) || bytes == 0 || bytes > isize::MAX as usize {
        return Err("loaded image has invalid base or length");
    }
    let mapped_bytes = bytes
        .checked_next_multiple_of(PAGE)
        .filter(|&length| length <= isize::MAX as usize)
        .ok_or("loaded image rounded length overflows")?;
    let end = start
        .checked_add(mapped_bytes)
        .ok_or("loaded image address extent overflows")?;
    Ok(Extent {
        start,
        bytes,
        mapped_bytes,
        end,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct Section {
    pub first: usize,
    pub end: usize,
    pub executable: bool,
    pub writable: bool,
}

struct Reader<F> {
    bytes: usize,
    read: F,
}

impl<F: FnMut(usize, &mut [u8])> Reader<F> {
    fn extent(&self, first: usize, bytes: usize) -> Result<usize, &'static str> {
        first
            .checked_add(bytes)
            .filter(|&end| end <= self.bytes)
            .ok_or("loaded image PE field is out of bounds")
    }

    fn array<const N: usize>(&mut self, first: usize) -> Result<[u8; N], &'static str> {
        self.extent(first, N)?;
        let mut bytes = [0; N];
        (self.read)(first, &mut bytes);
        Ok(bytes)
    }

    fn half(&mut self, first: usize) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(self.array(first)?))
    }

    fn word(&mut self, first: usize) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.array(first)?))
    }
}

/// Parse metadata through short bounded copies, avoiding a shared Rust slice
/// over the live image's writable statics while allocating the inventory.
pub fn sections(
    bytes: usize,
    read: impl FnMut(usize, &mut [u8]),
) -> Result<Vec<Section>, &'static str> {
    let mut image = Reader { bytes, read };
    image.extent(0, DOS_HEADER)?;
    if image.half(0)? != 0x5a4d {
        return Err("loaded image has no DOS signature");
    }
    let pe = image.word(0x3c)? as usize;
    if pe < DOS_HEADER {
        return Err("loaded image PE header overlaps DOS header");
    }
    let optional = image.extent(pe, PE_HEADER)?;
    if image.word(pe)? != 0x4550 || image.half(pe + 4)? != 0x8664 {
        return Err("loaded image is not x86-64 PE");
    }
    let count = usize::from(image.half(pe + 6)?);
    let optional_bytes = usize::from(image.half(pe + 20)?);
    if count == 0 || image.half(pe + 22)? & 2 == 0 || optional_bytes < OPTIONAL_HEADER {
        return Err("loaded image has no complete executable PE32+ headers");
    }
    let table = image.extent(optional, optional_bytes)?;
    if image.half(optional)? != 0x20b || image.half(optional + 68)? != 10 {
        return Err("loaded image is not a PE32+ EFI application");
    }
    let directories = image.word(optional + 108)? as usize;
    if directories
        .checked_mul(8)
        .is_none_or(|size| size > optional_bytes - OPTIONAL_HEADER)
    {
        return Err("loaded image data directories escape optional header");
    }
    let alignment = image.word(optional + 32)? as usize;
    let file_alignment = image.word(optional + 36)? as usize;
    if !alignment.is_power_of_two()
        || alignment < PAGE
        || !file_alignment.is_power_of_two()
        || !(512..=65536).contains(&file_alignment)
        || file_alignment > alignment
    {
        return Err("loaded image requires supported page-aligned section geometry");
    }
    let image_bytes = image.word(optional + 56)? as usize;
    let headers = image.word(optional + 60)? as usize;
    let table_end = image.extent(
        table,
        count
            .checked_mul(SECTION_HEADER)
            .ok_or("loaded image section table size overflows")?,
    )?;
    if image_bytes == 0
        || !image_bytes.is_multiple_of(alignment)
        || image_bytes > bytes
        || headers < table_end
        || headers > image_bytes
        || !headers.is_multiple_of(file_alignment)
    {
        return Err("loaded image header or image geometry is invalid");
    }
    let mut previous = headers
        .checked_next_multiple_of(alignment)
        .ok_or("loaded image header alignment overflows")?;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        // The complete table extent was checked above.
        let section = table + index * SECTION_HEADER;
        let virtual_size = image.word(section + 8)? as usize;
        let first = image.word(section + 12)? as usize;
        let raw_size = image.word(section + 16)? as usize;
        let raw_offset = image.word(section + 20)? as usize;
        let flags = image.word(section + 36)?;
        if !first.is_multiple_of(alignment)
            || first > image_bytes
            || !raw_size.is_multiple_of(file_alignment)
            || (raw_size != 0 && !raw_offset.is_multiple_of(file_alignment))
            || raw_offset
                .checked_add(raw_size)
                .is_none_or(|end| end > u32::MAX as usize)
        {
            return Err("loaded image section alignment or file geometry is invalid");
        }
        let size = virtual_size.max(raw_size);
        if size == 0 {
            continue;
        }
        let end = first
            .checked_add(size)
            .and_then(|end| end.checked_next_multiple_of(PAGE))
            .filter(|&end| end <= image_bytes)
            .ok_or("loaded image section escapes loaded image")?;
        let executable = flags & EXECUTE != 0;
        let writable = flags & WRITE != 0;
        if first < previous || flags & READ == 0 || (executable && writable) {
            return Err("loaded image section overlaps or has unsupported access rights");
        }
        sections.push(Section {
            first,
            end,
            executable,
            writable,
        });
        previous = end;
    }
    if sections.is_empty() {
        return Err("loaded image has no mapped sections");
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const OPTIONAL: usize = 0x98;
    const TABLE: usize = OPTIONAL + 240;

    fn half(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn word(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn pe() -> Vec<u8> {
        let mut bytes = vec![0; 5 * PAGE];
        half(&mut bytes, 0, 0x5a4d);
        word(&mut bytes, 0x3c, 0x80);
        word(&mut bytes, 0x80, 0x4550);
        for (at, value) in [
            (0x84, 0x8664),
            (0x86, 3),
            (0x94, 240),
            (0x96, 2),
            (OPTIONAL, 0x20b),
            (OPTIONAL + 68, 10),
        ] {
            half(&mut bytes, at, value);
        }
        for (at, value) in [
            (OPTIONAL + 32, PAGE as u32),
            (OPTIONAL + 36, 512),
            (OPTIONAL + 56, 5 * PAGE as u32),
            (OPTIONAL + 60, 512),
            (OPTIONAL + 108, 16),
        ] {
            word(&mut bytes, at, value);
        }
        for (index, flags) in [READ | EXECUTE, READ, READ | WRITE].into_iter().enumerate() {
            let section = TABLE + index * SECTION_HEADER;
            word(&mut bytes, section + 8, PAGE as u32 - 5);
            word(&mut bytes, section + 12, (index as u32 + 1) * PAGE as u32);
            word(&mut bytes, section + 16, PAGE as u32);
            word(&mut bytes, section + 20, 512 + index as u32 * PAGE as u32);
            word(&mut bytes, section + 36, flags);
        }
        bytes
    }
    fn parse(bytes: &[u8]) -> Result<Vec<Section>, &'static str> {
        sections(bytes.len(), |first, out| {
            out.copy_from_slice(&bytes[first..first + out.len()])
        })
    }

    #[test]
    fn source_extent_is_checked_without_reading_or_rounding_source_accesses() {
        assert_eq!(
            loaded_extent(0x100000, 4097),
            Ok(Extent {
                start: 0x100000,
                bytes: 4097,
                mapped_bytes: 8192,
                end: 0x102000,
            })
        );
        for (base, bytes) in [
            (0, 4096),
            (1, 4096),
            (4096, 0),
            (usize::MAX & !(PAGE - 1), PAGE as u64),
            (PAGE, u64::MAX),
            (PAGE, isize::MAX as u64),
        ] {
            assert!(loaded_extent(base, bytes).is_err());
        }
    }

    #[test]
    fn complete_inventory_keeps_rva_geometry_and_distinct_page_rights() {
        let sections = parse(&pe()).unwrap();
        assert_eq!(
            sections,
            vec![
                Section {
                    first: PAGE,
                    end: 2 * PAGE,
                    executable: true,
                    writable: false
                },
                Section {
                    first: 2 * PAGE,
                    end: 3 * PAGE,
                    executable: false,
                    writable: false
                },
                Section {
                    first: 3 * PAGE,
                    end: 4 * PAGE,
                    executable: false,
                    writable: true
                },
            ]
        );
        let mut zero_virtual_size = pe();
        word(&mut zero_virtual_size, TABLE + 8, 0);
        assert_eq!(parse(&zero_virtual_size).unwrap(), sections);
    }

    #[test]
    fn every_header_truncation_refuses_before_out_of_bounds_callback() {
        let valid = pe();
        for length in 0..TABLE + 3 * SECTION_HEADER {
            let bytes = &valid[..length];
            assert!(parse(bytes).is_err(), "length={length}");
        }
        let mut reads = 0;
        let result = sections(63, |_, _| reads += 1);
        assert!(result.is_err());
        assert_eq!(reads, 0);
    }

    #[test]
    fn malformed_headers_sections_and_conflicting_rights_refuse() {
        for (at, value) in [
            (0, 0),
            (0x3c, u32::MAX),
            (0x3c, 32),
            (0x80, 0),
            (0x84, 0x3aa64),
            (0x94, 111),
            (OPTIONAL, 0x10b),
            (OPTIONAL + 32, 512),
            (OPTIONAL + 32, 6144),
            (OPTIONAL + 36, 1024 * 1024),
            (OPTIONAL + 56, 6 * PAGE as u32),
            (OPTIONAL + 56, 3 * PAGE as u32),
            (OPTIONAL + 60, 0),
            (OPTIONAL + 108, 17),
            (TABLE + 8, u32::MAX),
            (TABLE + 12, 1),
            (TABLE + 12, 0),
            (TABLE + 16, 1),
            (TABLE + 20, 1),
            (TABLE + 36, READ | WRITE | EXECUTE),
            (TABLE + 36, EXECUTE),
            (TABLE + SECTION_HEADER + 12, PAGE as u32),
        ] {
            let mut invalid = pe();
            word(&mut invalid, at, value);
            assert!(parse(&invalid).is_err(), "field={at:#x} value={value:#x}");
        }
    }
}
