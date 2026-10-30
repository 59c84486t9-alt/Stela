//! Auxiliary kernel collections: kexts linked against the boot kernel
//! collection into the `MH_FILESET` XNU loads beside it.
//!
//! Apple builds these with `kernelmanagerd`, which only runs on macOS, and
//! no available linker links arm64e kernel code with authenticated
//! pointers, so Stela links the kexts' relocatable objects itself. The
//! layout is the one XNU `xnu-12377.121.6` and Apple's collections use:
//!
//! - Segments run from address 0: the writable `__PRELINK_INFO` and
//!   `__DATA`, then the read-only `__TEXT` (the collection's header),
//!   `__PRELINK_TEXT` (each kext's header and `__TEXT`), `__DATA_CONST` and
//!   `__RECEIPT_INFO`, then the executable `__TEXT_EXEC`, then `__LINKEDIT`.
//!   The file starts with `__TEXT`.
//! - Each kext is an `MH_KEXT_BUNDLE` fileset entry whose segments lie inside
//!   the collection's, each starting on a page.
//! - Pointers are `DYLD_CHAINED_PTR_64_KERNEL_CACHE` fixups to cache level 3
//!   (this collection) or 0 (the boot collection), which XNU slides and signs.
//! - `__PRELINK_INFO,__info` holds each kext's `Info.plist` with its
//!   placement, the collection's UUID and the boot collection's, which XNU
//!   checks against the one it booted.
//! - `__RECEIPT_INFO,__aux_kc_receipt` holds the [`receipt`].
mod boot;
mod commands;
mod fixups;
mod prelink;
mod receipt;
mod relocatable;
mod unit;

use std::collections::BTreeMap;
use std::iter;

use crate::Result;
use ::object::macho;
use stela_contracts::{refuse, require};

use crate::kernel_collection::PAGE_BYTES;
use boot::BootCollection;
use commands::{Commands, SectionCommand, SegmentCommand};
use prelink::{Entry, Placement};
use unit::{Region, Unit};

/// A kext to link into the collection.
pub struct Kext<'a> {
    /// The bundle's `Info.plist`.
    pub info: &'a [u8],
    /// Its executable's arm64e relocatable objects.
    pub objects: Vec<&'a [u8]>,
    /// The bundle's path in the installed system, where the kernel expects
    /// to find it.
    pub bundle_path: String,
}

/// The collection's segments by index, in address order.
const SEGMENTS: [(&str, u32); 8] = [
    ("__PRELINK_INFO", 3),
    ("__DATA", 3),
    ("__TEXT", 1),
    ("__PRELINK_TEXT", 1),
    ("__DATA_CONST", 1),
    ("__RECEIPT_INFO", 1),
    ("__TEXT_EXEC", 5),
    ("__LINKEDIT", 1),
];
/// First, so that no kext symbol, `kmod_info` above all, lies at address 0.
const PRELINK_INFO: usize = 0;
const DATA: usize = 1;
const TEXT: usize = 2;
const PRELINK_TEXT: usize = 3;
const DATA_CONST: usize = 4;
const RECEIPT_INFO: usize = 5;
const TEXT_EXEC: usize = 6;
const LINKEDIT: usize = 7;

/// `MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_DYLIB_IN_CACHE`, as Apple's
/// collections mark their kexts.
const KEXT_FLAGS: u32 = 0x8000_0085;

#[derive(Debug, Clone, Copy, Default)]
struct Segment {
    address: u64,
    size: u64,
    file_offset: u64,
}

struct Symbols {
    offset: u32,
    count: u32,
    locals: u32,
    strings: u32,
    string_bytes: u32,
}

/// Links `kexts` against the boot collection `boot` into an auxiliary
/// collection.
pub fn link(boot: &[u8], kexts: &[Kext<'_>]) -> Result<Vec<u8>> {
    require!(
        !kexts.is_empty(),
        "an auxiliary collection holds at least one kext"
    );
    let boot = BootCollection::parse(boot)?;
    let mut units = kexts
        .iter()
        .map(|kext| Unit::new(kext, &boot))
        .collect::<Result<Vec<_>>>()?;
    for (index, unit) in units.iter().enumerate() {
        require!(
            units[..index]
                .iter()
                .all(|other| other.identifier != unit.identifier),
            "{kext} is listed twice",
            kext = unit.identifier
        );
    }
    let receipt = receipt::encode(kexts.iter().zip(&units))?;
    let uuid = unit::uuid(
        [&boot.uuid[..], &receipt[..]]
            .into_iter()
            .chain(units.iter().map(|unit| &unit.uuid[..])),
    );

    let widest: Vec<Entry<'_>> = units
        .iter()
        .map(|unit| Entry {
            info: &unit.info,
            bundle_path: unit.bundle_path,
            placement: Placement::WIDEST,
        })
        .collect();
    let info_bound = prelink::info(&widest, uuid, boot.uuid)?.len() as u64;
    let header_bytes = commands::fileset_header_bytes(
        SEGMENTS.len(),
        2,
        units.iter().map(|unit| unit.identifier.as_str()),
    ) as u64;
    let mut segments = [Segment::default(); SEGMENTS.len()];
    let mut cursor = 0;
    for (index, segment) in segments.iter_mut().enumerate().take(LINKEDIT) {
        let start = cursor;
        cursor = match index {
            DATA => place(&mut units, Region::Data, cursor),
            PRELINK_INFO => cursor + info_bound,
            TEXT => cursor + header_bytes,
            PRELINK_TEXT => place(&mut units, Region::Text, cursor),
            DATA_CONST => place(&mut units, Region::DataConst, cursor),
            RECEIPT_INFO => cursor + receipt.len() as u64,
            TEXT_EXEC => place(&mut units, Region::TextExec, cursor),
            _ => unreachable!("__LINKEDIT is laid out last"),
        }
        .next_multiple_of(PAGE_BYTES);
        segment.address = start;
        segment.size = cursor - start;
    }
    segments[LINKEDIT].address = cursor;
    let mut file_offset = 0;
    for index in iter::once(TEXT).chain((0..SEGMENTS.len()).filter(|&index| index != TEXT)) {
        segments[index].file_offset = file_offset;
        file_offset += segments[index].size;
    }
    let mapped = segments;
    let file_of = |index: usize, address: u64| -> Result<u64> {
        let segment = mapped[index];
        require!(
            (segment.address..=segment.address + segment.size).contains(&address),
            "{address:#x} lies outside {segment}",
            address,
            segment = SEGMENTS[index].0
        );
        Ok(segment.file_offset + address - segment.address)
    };

    let mut pointers = BTreeMap::new();
    for unit in &mut units {
        unit.relocate(boot.base(), &mut pointers)?;
    }
    let entries = units
        .iter()
        .map(|unit| {
            let text = &unit.ranges[Region::Text as usize];
            Ok(Entry {
                info: &unit.info,
                bundle_path: unit.bundle_path,
                placement: Placement {
                    load: text.start,
                    size: text.end - text.start,
                    kmod_info: unit.kmod_info()?,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let info = prelink::info(&entries, uuid, boot.uuid)?;
    require!(
        info.len() as u64 <= info_bound,
        "the prelink info outgrew its bound"
    );

    let mut image = vec![0u8; fit(segments[LINKEDIT].address, "the collection's mapped size")?];
    let write = |image: &mut [u8], address: u64, bytes: &[u8]| -> Result<()> {
        let start: usize = fit(address, "a pointer's collection offset")?;
        image[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    };
    for unit in &units {
        for section in &unit.sections {
            write(&mut image, section.address, &section.bytes)?;
        }
    }
    write(&mut image, segments[PRELINK_INFO].address, &info)?;
    write(&mut image, segments[RECEIPT_INFO].address, &receipt)?;
    let fixup_segments: Vec<fixups::Segment> = segments
        .iter()
        .take(LINKEDIT)
        .map(|segment| fixups::Segment {
            address: segment.address,
            size: segment.size,
        })
        .chain(iter::once(fixups::Segment {
            address: segments[LINKEDIT].address,
            size: 0,
        }))
        .collect();
    let mut linkedit = fixups::encode(
        &mut image,
        segments[TEXT].address,
        &fixup_segments,
        &pointers,
    )?;
    let fixup_bytes: u32 = fit(linkedit.len(), "the fixup chains' size")?;
    let linkedit_offset = segments[LINKEDIT].file_offset;
    let mut symbols = Vec::with_capacity(units.len());
    for unit in &units {
        symbols.push(symbol_table(unit, &mut linkedit, linkedit_offset)?);
    }
    linkedit.resize(linkedit.len().next_multiple_of(8), 0);
    segments[LINKEDIT].size = (linkedit.len() as u64).next_multiple_of(PAGE_BYTES);
    let linkedit_command = SegmentCommand {
        name: SEGMENTS[LINKEDIT].0,
        address: segments[LINKEDIT].address,
        size: segments[LINKEDIT].size,
        file_offset: linkedit_offset,
        file_size: linkedit.len() as u64,
        protection: SEGMENTS[LINKEDIT].1,
        sections: Vec::new(),
    };

    for (unit, symbols) in units.iter().zip(&symbols) {
        let mut header = Commands::default();
        let order = unit.section_order();
        for region in Region::ALL {
            let range = &unit.ranges[region as usize];
            let mut sections = Vec::new();
            for &index in &order {
                let section = &unit.sections[index];
                if section.region == region {
                    sections.push(SectionCommand {
                        name: &section.name,
                        segment: region.name(),
                        address: section.address,
                        size: section.bytes.len() as u64,
                        file_offset: fit(
                            file_of(holder(region), section.address)?,
                            "a section's file offset",
                        )?,
                        align: section.align,
                        flags: section.flags,
                    });
                }
            }
            header.segment(&SegmentCommand {
                name: region.name(),
                address: range.start,
                size: range.end - range.start,
                file_offset: file_of(holder(region), range.start)?,
                file_size: range.end - range.start,
                protection: region.protection(),
                sections,
            })?;
        }
        header.segment(&linkedit_command)?;
        header.symbols(
            symbols.offset,
            symbols.strings,
            symbols.locals,
            symbols.count - symbols.locals,
            symbols.string_bytes,
        )?;
        header.uuid(unit.uuid)?;
        let header = header.finish(macho::MH_KEXT_BUNDLE, boot.cpu_subtype(), KEXT_FLAGS)?;
        require!(
            header.len() == commands::kext_header_bytes(unit.sections.len()),
            "a kext header of unplanned size"
        );
        write(
            &mut image,
            unit.ranges[Region::Text as usize].start,
            &header,
        )?;
    }

    let mut header = Commands::default();
    header.uuid(uuid)?;
    for (index, segment) in segments.iter().enumerate() {
        if index == LINKEDIT {
            header.segment(&linkedit_command)?;
            continue;
        }
        let (name, protection) = SEGMENTS[index];
        let contents = match index {
            PRELINK_INFO => Some(("__info", info.len())),
            RECEIPT_INFO => Some(("__aux_kc_receipt", receipt.len())),
            _ => None,
        };
        header.segment(&SegmentCommand {
            name,
            address: segment.address,
            size: segment.size,
            file_offset: segment.file_offset,
            file_size: segment.size,
            protection,
            sections: contents
                .map(|(section, size)| SectionCommand {
                    name: section,
                    segment: name,
                    address: segment.address,
                    size: size as u64,
                    file_offset: segment.file_offset as u32,
                    align: 0,
                    flags: 0,
                })
                .into_iter()
                .collect(),
        })?;
    }
    header.chained_fixups(
        fit(linkedit_offset, "the __LINKEDIT file offset")?,
        fixup_bytes,
    )?;
    for unit in &units {
        let address = unit.ranges[Region::Text as usize].start;
        header.fileset_entry(&unit.identifier, address, file_of(PRELINK_TEXT, address)?)?;
    }
    let header = header.finish(macho::MH_FILESET, boot.cpu_subtype(), 0)?;
    require!(
        header.len() as u64 == header_bytes,
        "a collection header of unplanned size"
    );
    write(&mut image, segments[TEXT].address, &header)?;

    let linkedit_start: usize = fit(linkedit_offset, "the __LINKEDIT file offset")?;
    let mut file = vec![0u8; linkedit_start + linkedit.len()];
    for segment in &segments[..LINKEDIT] {
        let (from, to) = (
            fit(segment.address, "a segment's address")?,
            fit(segment.file_offset, "a segment's file offset")?,
        );
        let size: usize = fit(segment.size, "a segment's size")?;
        file[to..to + size].copy_from_slice(&image[from..from + size]);
    }
    file[linkedit_start..].copy_from_slice(&linkedit);
    Ok(file)
}

/// The collection segment a kext region lies in.
/// `value` narrowed to the type of the `field` that holds it, refused when
/// the collection outgrows that field.
fn fit<T: TryFrom<V>, V: Copy + stela_contracts::refusal::ToValue>(
    value: V,
    field: &'static str,
) -> Result<T> {
    T::try_from(value)
        .map_err(|_| refuse!("{field} {value:#x} overflows its field", field, value).into())
}

fn holder(region: Region) -> usize {
    match region {
        Region::Text => PRELINK_TEXT,
        Region::TextExec => TEXT_EXEC,
        Region::Data => DATA,
        Region::DataConst => DATA_CONST,
    }
}

/// Assigns `region`'s sections of every kext their addresses from `cursor`,
/// each kext's starting on a page, and returns where they end.
fn place(units: &mut [Unit<'_>], region: Region, mut cursor: u64) -> u64 {
    for unit in units {
        let start = cursor.next_multiple_of(PAGE_BYTES);
        cursor = start;
        if region == Region::Text {
            cursor += commands::kext_header_bytes(unit.sections.len()) as u64;
        }
        for index in unit.section_order() {
            let section = &mut unit.sections[index];
            if section.region == region {
                section.address = cursor.next_multiple_of(1 << section.align);
                cursor = section.address + section.bytes.len() as u64;
            }
        }
        unit.ranges[region as usize] = start..cursor;
    }
    cursor
}

/// Appends a kext's symbols and their names to the collection's
/// `__LINKEDIT`, which starts at `base` in the file.
fn symbol_table(unit: &Unit<'_>, linkedit: &mut Vec<u8>, base: u64) -> Result<Symbols> {
    let order = unit.section_order();
    let entries = unit.symbols()?;
    linkedit.resize(linkedit.len().next_multiple_of(8), 0);
    let offset = base + linkedit.len() as u64;
    let mut strings = vec![b' ', 0];
    let mut table = Vec::with_capacity(entries.len() * commands::NLIST_BYTES);
    let mut locals = 0;
    for (name, external, section, address) in &entries {
        let ordinal = order
            .iter()
            .position(|index| index == section)
            .ok_or(refuse!("a symbol in no section"))?
            + 1;
        table.extend(fit::<u32, _>(strings.len(), "the symbol strings' size")?.to_le_bytes());
        table.push(macho::N_SECT | if *external { macho::N_EXT } else { 0 });
        table.push(fit(ordinal, "a symbol's section ordinal")?);
        table.extend(0u16.to_le_bytes());
        table.extend(address.to_le_bytes());
        strings.extend(name.as_bytes());
        strings.push(0);
        locals += u32::from(!*external);
    }
    linkedit.extend(table);
    let string_offset = base + linkedit.len() as u64;
    strings.resize(strings.len().next_multiple_of(8), 0);
    let string_bytes: u32 = fit(strings.len(), "the symbol strings' size")?;
    linkedit.extend(strings);
    Ok(Symbols {
        offset: fit(offset, "the symbol table's file offset")?,
        count: fit(entries.len(), "the symbol count")?,
        locals,
        strings: fit(string_offset, "the string table's file offset")?,
        string_bytes,
    })
}

#[cfg(test)]
mod tests;
