//! MH_PRELOAD validation using the shared object reader and ARM thread ABI.
use super::{Limits, SegmentMap};
use crate::{
    kernel_collection::Segment as ImageSegment,
    thread_state::{Arm64UnixThread, unix_thread},
};
use alloc::{collections::BTreeSet, string::String, vec, vec::Vec};
use anyhow::{Context, Result, bail, ensure};
use object::{
    LittleEndian, macho,
    read::macho::{LoadCommandVariant, MachHeader, Segment},
};
use serde::Serialize;
use stela_runtime::sha256;

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub segment_index: usize,
    pub name: String,
    pub virtual_address: u64,
    pub bytes: u64,
    pub file_offset: u64,
    pub alignment: u32,
    pub flags: u32,
    pub reserved: [u32; 3],
}
pub(super) struct Layout {
    pub cpu_subtype: u32,
    pub header_flags: u32,
    pub uuid: Option<String>,
    pub thread: Arm64UnixThread,
    pub segments: Vec<SegmentMap>,
    pub sections: Vec<Section>,
    pub vm_base: u64,
    pub image_bytes: u64,
    pub alignment: u64,
}

pub(super) fn end(start: u64, bytes: u64) -> Result<u64> {
    start
        .checked_add(bytes)
        .context("coprocessor image range overflows")
}
pub(super) fn file_bytes(data: &[u8], offset: u64, bytes: u64) -> Result<&[u8]> {
    data.get(usize::try_from(offset)?..usize::try_from(end(offset, bytes)?)?)
        .context("coprocessor file range exceeds input")
}
fn name(data: &[u8]) -> Result<String> {
    let n = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    ensure!(
        data[n..].iter().all(|&b| b == 0),
        "nonzero bytes after Mach-O name terminator"
    );
    Ok(core::str::from_utf8(&data[..n])?.into())
}
fn overlaps(a: u64, bytes: u64, b: u64, size: u64) -> bool {
    bytes != 0 && size != 0 && a < b + size && b < a + bytes
}

pub(super) fn parse(data: &[u8], limits: Limits) -> Result<Layout> {
    ensure!(
        data.get(..4) == Some(&[0xcf, 0xfa, 0xed, 0xfe]),
        "coprocessor requires thin little-endian Mach-O64"
    );
    let e = LittleEndian;
    let header = macho::MachHeader64::<LittleEndian>::parse(data, 0)?;
    ensure!(
        header.cputype(e) == macho::CPU_TYPE_ARM64
            && matches!(header.cpusubtype(e) & !macho::CPU_SUBTYPE_MASK, 0 | 2),
        "unsupported coprocessor CPU type/subtype"
    );
    ensure!(
        header.filetype(e) == macho::MH_PRELOAD,
        "coprocessor requires MH_PRELOAD"
    );
    ensure!(
        header.sizeofcmds(e) <= limits.command_bytes && header.ncmds(e) <= header.sizeofcmds(e) / 8,
        "coprocessor load-command bounds exceed limits"
    );
    ensure!(
        header.flags(e) & !(macho::MH_NOUNDEFS | macho::MH_PIE) == 0 && header.reserved.get(e) == 0,
        "unsupported coprocessor Mach-O header flags/reserved word"
    );
    let mut commands = header.load_commands(e, data, 0)?;
    let mut consumed = 0u64;
    let mut singletons = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut segments: Vec<SegmentMap> = vec![];
    let mut sections: Vec<Section> = vec![];
    let mut thread = None;
    let mut uuid = None;
    let mut alignment = 4;
    while let Some(command) = commands.next()? {
        let id = command.cmd();
        ensure!(
            command.cmdsize().is_multiple_of(8),
            "unaligned coprocessor load command"
        );
        consumed += u64::from(command.cmdsize());
        if id != macho::LC_SEGMENT_64 {
            ensure!(
                singletons.insert(id),
                "duplicate coprocessor load command {id:#x}"
            );
        }
        match command.variant()? {
            LoadCommandVariant::Segment64(s, section_data) => {
                ensure!(
                    segments.len() < limits.segments,
                    "coprocessor segment limit exceeded"
                );
                let segment = ImageSegment {
                    name: name(&s.segname)?,
                    vm_address: s.vmaddr.get(e),
                    vm_size: s.vmsize.get(e),
                    file_offset: s.fileoff.get(e),
                    file_size: s.filesize.get(e),
                    max_protection: s.maxprot.get(e),
                    initial_protection: s.initprot.get(e),
                };
                ensure!(
                    names.insert(segment.name.clone()),
                    "duplicate coprocessor segment name"
                );
                ensure!(
                    s.flags.get(e) & !(macho::SG_NORELOC | macho::SG_READ_ONLY) == 0,
                    "unsupported coprocessor segment flags"
                );
                ensure!(
                    segment.max_protection & !7 == 0
                        && segment.initial_protection & !segment.max_protection == 0,
                    "invalid coprocessor segment protection"
                );
                ensure!(
                    segment.file_size <= segment.vm_size,
                    "coprocessor file extent exceeds segment VM"
                );
                let vm_end = end(segment.vm_address, segment.vm_size)?;
                let file_end = end(segment.file_offset, segment.file_size)?;
                let file = file_bytes(data, segment.file_offset, segment.file_size)?;
                for previous in &segments {
                    let p = &previous.segment;
                    ensure!(
                        !overlaps(segment.vm_address, segment.vm_size, p.vm_address, p.vm_size),
                        "overlapping coprocessor segments"
                    );
                    ensure!(
                        !overlaps(
                            segment.file_offset,
                            segment.file_size,
                            p.file_offset,
                            p.file_size
                        ),
                        "overlapping coprocessor file segments"
                    );
                }
                let ss = s.sections(e, section_data)?;
                ensure!(
                    section_data.len() == ss.len() * 80,
                    "coprocessor segment/section size mismatch"
                );
                let mut section_names = BTreeSet::new();
                for section in ss {
                    ensure!(
                        sections.len() < limits.sections,
                        "coprocessor section limit exceeded"
                    );
                    let sec = Section {
                        segment_index: segments.len(),
                        name: name(&section.sectname)?,
                        virtual_address: section.addr.get(e),
                        bytes: section.size.get(e),
                        file_offset: u64::from(section.offset.get(e)),
                        alignment: section.align.get(e),
                        flags: section.flags.get(e),
                        reserved: [
                            section.reserved1.get(e),
                            section.reserved2.get(e),
                            section.reserved3.get(e),
                        ],
                    };
                    ensure!(
                        section.segname == s.segname && section_names.insert(sec.name.clone()),
                        "coprocessor section ownership/name mismatch"
                    );
                    ensure!(
                        sec.alignment < 63
                            && sec.virtual_address.is_multiple_of(1u64 << sec.alignment),
                        "coprocessor section alignment is invalid"
                    );
                    alignment = alignment.max(1u64 << sec.alignment);
                    ensure!(
                        sec.virtual_address >= segment.vm_address
                            && end(sec.virtual_address, sec.bytes)? <= vm_end,
                        "coprocessor section exceeds segment"
                    );
                    ensure!(
                        section.nreloc.get(e) == 0
                            && section.reloff.get(e) == 0
                            && sec.flags & (macho::S_ATTR_EXT_RELOC | macho::S_ATTR_LOC_RELOC) == 0,
                        "coprocessor legacy section relocations are not qualified"
                    );
                    for prior in sections
                        .iter()
                        .filter(|p| p.segment_index == segments.len())
                    {
                        ensure!(
                            !overlaps(
                                sec.virtual_address,
                                sec.bytes,
                                prior.virtual_address,
                                prior.bytes
                            ),
                            "overlapping coprocessor sections"
                        );
                    }
                    let zero = matches!(
                        sec.flags & macho::SECTION_TYPE,
                        macho::S_ZEROFILL | macho::S_GB_ZEROFILL
                    );
                    ensure!(
                        matches!(
                            sec.flags & macho::SECTION_TYPE,
                            macho::S_REGULAR
                                | macho::S_ZEROFILL
                                | macho::S_GB_ZEROFILL
                                | macho::S_CSTRING_LITERALS
                                | macho::S_4BYTE_LITERALS
                                | macho::S_8BYTE_LITERALS
                                | macho::S_16BYTE_LITERALS
                                | macho::S_MOD_INIT_FUNC_POINTERS
                                | macho::S_MOD_TERM_FUNC_POINTERS
                        ),
                        "unsupported coprocessor section type"
                    );
                    if zero && sec.bytes != 0 {
                        ensure!(
                            sec.file_offset == 0
                                && sec.virtual_address >= segment.vm_address + segment.file_size,
                            "coprocessor zero-fill section overlaps file-backed bytes"
                        );
                    }
                    if sec.bytes != 0 && !zero {
                        ensure!(
                            sec.file_offset >= segment.file_offset
                                && end(sec.file_offset, sec.bytes)? <= file_end
                                && sec.virtual_address - segment.vm_address
                                    == sec.file_offset - segment.file_offset,
                            "coprocessor section file/VM coordinates disagree"
                        );
                    }
                    ensure!(
                        !matches!(
                            sec.flags & macho::SECTION_TYPE,
                            macho::S_THREAD_LOCAL_ZEROFILL
                                | macho::S_THREAD_LOCAL_REGULAR
                                | macho::S_THREAD_LOCAL_VARIABLES
                                | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
                                | macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
                        ),
                        "coprocessor thread-local section loading is not qualified"
                    );
                    ensure!(
                        sec.name == "__chain_starts" || sec.reserved == [0; 3],
                        "unsupported coprocessor section reserved fields"
                    );
                    sections.push(sec);
                }
                segments.push(SegmentMap {
                    segment,
                    flags: s.flags.get(e),
                    file_sha256: sha256(file),
                });
            }
            LoadCommandVariant::Thread(_, _) => {
                ensure!(
                    id == macho::LC_UNIXTHREAD,
                    "coprocessor requires LC_UNIXTHREAD rather than LC_THREAD"
                );
                thread = Some(unix_thread(command.raw_data())?);
            }
            LoadCommandVariant::Uuid(u) => {
                ensure!(
                    command.cmdsize() == 24,
                    "invalid coprocessor LC_UUID extent"
                );
                uuid = Some(hex::encode(u.uuid));
            }
            LoadCommandVariant::Symtab(_) | LoadCommandVariant::Dysymtab(_) => {
                let expected = if id == macho::LC_SYMTAB { 24 } else { 80 };
                ensure!(
                    command.cmdsize() == expected
                        && command.raw_data()[8..].iter().all(|&b| b == 0),
                    "coprocessor nonempty symbol/legacy relocation tables are not qualified"
                );
            }
            _ => bail!("unsupported coprocessor load command {id:#x}"),
        }
    }
    ensure!(
        consumed == u64::from(header.sizeofcmds(e)),
        "coprocessor commands do not fill sizeofcmds"
    );
    let thread = thread.context("coprocessor has no LC_UNIXTHREAD")?;
    let vm_base = segments
        .iter()
        .filter(|s| s.segment.vm_size != 0)
        .map(|s| s.segment.vm_address)
        .min()
        .context("coprocessor has no mapped segment")?;
    let vm_end = segments
        .iter()
        .filter(|s| s.segment.vm_size != 0)
        .map(|s| s.segment.vm_end())
        .max()
        .unwrap();
    ensure!(
        vm_end - vm_base <= limits.image_bytes && vm_end > vm_base,
        "coprocessor VM footprint exceeds limit"
    );
    ensure!(
        segments
            .iter()
            .any(|s| s.segment.initial_protection & 4 != 0
                && thread.pc >= s.segment.vm_address
                && end(thread.pc, 4)
                    .is_ok_and(|end| end <= s.segment.vm_address + s.segment.file_size)),
        "coprocessor entry is not a file-backed executable instruction"
    );
    ensure!(thread.pc.is_multiple_of(4), "unaligned coprocessor entry");
    Ok(Layout {
        cpu_subtype: header.cpusubtype(e),
        header_flags: header.flags(e),
        uuid,
        thread,
        segments,
        sections,
        vm_base,
        image_bytes: vm_end - vm_base,
        alignment,
    })
}
