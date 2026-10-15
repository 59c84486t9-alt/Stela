//! Inspect kernel-collection images while preserving collection-relative offsets.
//! Embedded images are not standalone files and must not be sliced blindly.
use anyhow::{Context, Result, ensure};
use object::{LittleEndian, macho, read::macho::MachHeader};
use serde::Serialize;
use std::collections::BTreeSet;
use stela_core::sha256;

use super::thread_state::{Arm64UnixThread, unix_thread};

const LOAD_COMMAND_HEADER_BYTES: u32 = 8;
const MAX_LOAD_COMMAND_COUNT: u32 = 65536;
const MACH_HEADER64_BYTES: usize = std::mem::size_of::<macho::MachHeader64<LittleEndian>>();

fn range(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset.checked_add(size).context("fileset range overflow")?;
    data.get(usize::try_from(offset)?..usize::try_from(end)?)
        .context("fileset range exceeds container")
}
fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .context("truncated Mach-O field")?
            .try_into()?,
    ))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8)
            .context("truncated Mach-O field")?
            .try_into()?,
    ))
}
fn name(data: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(data.split(|b| *b == 0).next().unwrap_or_default())?.to_owned())
}
fn command_string(data: &[u8], offset: usize, minimum: usize) -> Result<String> {
    ensure!(
        offset >= minimum && offset < data.len(),
        "invalid load-command string offset"
    );
    let bytes = &data[offset..];
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .context("unterminated load-command string")?;
    ensure!(end > 0, "empty load-command string");
    name(&bytes[..end])
}

#[derive(Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub segment: String,
    pub vm_address: u64,
    pub bytes: u64,
    pub file_offset: u64,
    pub flags: u32,
    pub zero_fill: bool,
    pub instructions: bool,
    pub sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Segment {
    pub name: String,
    pub vm_address: u64,
    pub vm_bytes: u64,
    pub file_offset: u64,
    pub file_bytes: u64,
    pub initial_protection: u32,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub vm_address: u64,
    pub header_offset: u64,
}

#[derive(Debug, Serialize)]
pub struct Image {
    pub id: String,
    pub header_offset: u64,
    pub header_sha256: String,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dependencies: Vec<String>,
    pub fileset_entries: Vec<Entry>,
    pub symbol_count: u32,
    pub symbol_table_file_offset: Option<u64>,
    pub string_table_file_offset: Option<u64>,
    pub string_table_bytes: Option<u64>,
    pub function_starts_file_offset: Option<u64>,
    pub function_starts_bytes: Option<u64>,
    pub unhandled_load_commands: Vec<u32>,
}

fn image(data: &[u8], offset: u64, id: String) -> Result<Image> {
    let header = range(data, offset, 32)?;
    ensure!(
        u32_at(header, 0)? == 0xfeedfacf,
        "only little-endian 64-bit Mach-O collections are supported"
    );
    let count = u32_at(header, 16)? as usize;
    let size = u32_at(header, 20)? as usize;
    ensure!(
        count <= MAX_LOAD_COMMAND_COUNT as usize
            && count <= size / LOAD_COMMAND_HEADER_BYTES as usize,
        "invalid Mach-O load-command count"
    );
    let commands = range(
        data,
        offset.checked_add(32).context("header overflow")?,
        size as u64,
    )?;
    let mut result = Image {
        id,
        header_offset: offset,
        header_sha256: sha256(range(data, offset, 32 + size as u64)?),
        cpu_type: u32_at(header, 4)?,
        cpu_subtype: u32_at(header, 8)?,
        file_type: u32_at(header, 12)?,
        segments: vec![],
        sections: vec![],
        dependencies: vec![],
        fileset_entries: vec![],
        symbol_count: 0,
        symbol_table_file_offset: None,
        string_table_file_offset: None,
        string_table_bytes: None,
        function_starts_file_offset: None,
        function_starts_bytes: None,
        unhandled_load_commands: vec![],
    };
    let mut position = 0usize;
    for _ in 0..count {
        let command = u32_at(commands, position)?;
        let length = u32_at(commands, position + 4)? as usize;
        ensure!(
            length >= 8 && length.is_multiple_of(8),
            "invalid load-command size"
        );
        let end = position
            .checked_add(length)
            .context("load-command overflow")?;
        let body = commands
            .get(position..end)
            .context("load command exceeds declared table")?;
        match command {
            0x19 => {
                ensure!(body.len() >= 72, "truncated LC_SEGMENT_64");
                let vm_address = u64_at(body, 24)?;
                let vm_bytes = u64_at(body, 32)?;
                let file_offset = u64_at(body, 40)?;
                let file_bytes = u64_at(body, 48)?;
                ensure!(file_bytes <= vm_bytes, "segment file bytes exceed VM bytes");
                vm_address
                    .checked_add(vm_bytes)
                    .context("segment VM range overflow")?;
                range(data, file_offset, file_bytes)?;
                let segment_name = name(&body[8..24])?;
                let segment_file_offset = file_offset;
                let segment_file_end = file_offset
                    .checked_add(file_bytes)
                    .context("segment file range overflow")?;
                let sections = u32_at(body, 64)? as usize;
                ensure!(
                    sections <= (body.len() - 72) / 80,
                    "truncated segment section table"
                );
                result.segments.push(Segment {
                    name: segment_name.clone(),
                    vm_address,
                    vm_bytes,
                    file_offset,
                    file_bytes,
                    initial_protection: u32_at(body, 60)?,
                });
                for index in 0..sections {
                    let section = &body[72 + index * 80..72 + (index + 1) * 80];
                    let section_name = name(&section[..16])?;
                    let segment = name(&section[16..32])?;
                    let address = u64_at(section, 32)?;
                    let bytes = u64_at(section, 40)?;
                    let file_offset = u64::from(u32_at(section, 48)?);
                    let flags = u32_at(section, 64)?;
                    let zero_fill = matches!(flags & 0xff, 1 | 0xc | 0x12);
                    let instructions = flags & 0x80000400 != 0;
                    ensure!(segment == segment_name, "section/segment name mismatch");
                    ensure!(
                        address >= vm_address
                            && address
                                .checked_add(bytes)
                                .is_some_and(|end| end <= vm_address + vm_bytes),
                        "section exceeds segment VM range"
                    );
                    let hash = if zero_fill {
                        None
                    } else {
                        ensure!(
                            bytes == 0
                                || (file_offset >= segment_file_offset
                                    && file_offset
                                        .checked_add(bytes)
                                        .is_some_and(|end| end <= segment_file_end)),
                            "section exceeds segment file range"
                        );
                        Some(sha256(range(data, file_offset, bytes)?))
                    };
                    result.sections.push(Section {
                        name: section_name,
                        segment,
                        vm_address: address,
                        bytes,
                        file_offset,
                        flags,
                        zero_fill,
                        instructions,
                        sha256: hash,
                    });
                }
            }
            0x80000035 => {
                ensure!(body.len() >= 32, "truncated LC_FILESET_ENTRY");
                let header_offset = u64_at(body, 16)?;
                range(data, header_offset, 32)?;
                result.fileset_entries.push(Entry {
                    id: command_string(body, u32_at(body, 24)? as usize, 32)?,
                    vm_address: u64_at(body, 8)?,
                    header_offset,
                });
            }
            0x2 => {
                ensure!(
                    body.len() >= 24 && result.symbol_table_file_offset.is_none(),
                    "invalid or duplicate symbol table"
                );
                let symoff = u64::from(u32_at(body, 8)?);
                let count = u32_at(body, 12)?;
                let stroff = u64::from(u32_at(body, 16)?);
                let strsize = u64::from(u32_at(body, 20)?);
                range(data, symoff, u64::from(count) * 16)?;
                range(data, stroff, strsize)?;
                result.symbol_count = count;
                result.symbol_table_file_offset = Some(symoff);
                result.string_table_file_offset = Some(stroff);
                result.string_table_bytes = Some(strsize);
            }
            0x26 => {
                ensure!(
                    body.len() >= 16 && result.function_starts_file_offset.is_none(),
                    "invalid or duplicate function starts"
                );
                let offset = u64::from(u32_at(body, 8)?);
                let bytes = u64::from(u32_at(body, 12)?);
                range(data, offset, bytes)?;
                result.function_starts_file_offset = Some(offset);
                result.function_starts_bytes = Some(bytes);
            }
            0xc | 0x80000018 | 0x8000001f | 0x80000023 => {
                ensure!(body.len() >= 24, "truncated dylib dependency");
                result
                    .dependencies
                    .push(command_string(body, u32_at(body, 8)? as usize, 24)?);
            }
            _ => result.unhandled_load_commands.push(command),
        }
        position = end;
    }
    ensure!(
        position == commands.len(),
        "load-command count disagrees with table size"
    );
    Ok(result)
}

#[derive(Debug, Serialize)]
pub struct FileSet {
    pub schema_version: u32,
    pub container_sha256: String,
    pub container_bytes: usize,
    pub root: Image,
    pub images: Vec<Image>,
    pub executable_section_bytes: u64,
    pub unique_executable_file_bytes: u64,
    pub limits: String,
}

pub fn inspect(data: &[u8]) -> Result<FileSet> {
    let root = image(data, 0, "collection".into())?;
    ensure!(root.file_type == 0xc, "expected MH_FILESET");
    let mut ids = BTreeSet::new();
    let mut offsets = BTreeSet::new();
    let mut images = vec![];
    for entry in &root.fileset_entries {
        ensure!(
            entry.header_offset != 0
                && ids.insert(&entry.id)
                && offsets.insert(entry.header_offset),
            "duplicate/recursive fileset entry"
        );
        let child = image(data, entry.header_offset, entry.id.clone())?;
        ensure!(
            child.file_type != 0xc,
            "nested filesets require a separate parser"
        );
        ensure!(
            child.cpu_type == root.cpu_type,
            "mixed CPU types in fileset"
        );
        images.push(child);
    }
    ensure!(!images.is_empty(), "fileset has no embedded images");
    let mut ranges = vec![];
    let mut executable_section_bytes = 0u64;
    for section in images
        .iter()
        .flat_map(|i| &i.sections)
        .filter(|s| s.instructions && !s.zero_fill)
    {
        executable_section_bytes = executable_section_bytes
            .checked_add(section.bytes)
            .context("section byte count overflow")?;
        ranges.push((section.file_offset, section.file_offset + section.bytes));
    }
    ranges.sort_unstable();
    let mut unique = 0;
    let mut previous = None;
    for (start, end) in ranges {
        match previous {
            Some((a, b)) if start <= b => previous = Some((a, b.max(end))),
            Some((a, b)) => {
                unique += b - a;
                previous = Some((start, end));
            }
            None => previous = Some((start, end)),
        }
    }
    if let Some((a, b)) = previous {
        unique += b - a;
    }
    Ok(FileSet { schema_version:1,container_sha256:sha256(data),container_bytes:data.len(),root,images,executable_section_bytes,unique_executable_file_bytes:unique,limits:"Collection-relative section inventory only. Unknown load commands remain listed; no relocations, authenticated pointers, dependencies, translation, or boot behavior are resolved.".into() })
}

/// Original root command metadata, separate from the schema-1 inventory.
/// `command_file_offset` is collection-relative. `thread.pc` stays image-linked;
/// serialized x0/SP/CPSR are not observed firmware or process execution state.
#[derive(Debug, Clone, Serialize)]
pub struct RootThreadMetadata {
    pub command_file_offset: u64,
    pub thread: Arm64UnixThread,
}

/// Read an optional ARM64 root descriptor without scanning collection contents.
/// None means metadata absence; this does not validate segments, load addresses,
/// signatures, relocations, architectural entry state or execution admission.
/// Unrelated commands retain their existing inventory treatment in `inspect`.
pub fn root_thread_metadata(data: &[u8]) -> Result<Option<RootThreadMetadata>> {
    ensure!(
        data.get(..std::mem::size_of::<u32>()) == Some(macho::MH_MAGIC_64.to_le_bytes().as_slice()),
        "expected little-endian 64-bit Mach-O fileset root"
    );
    let endian = LittleEndian;
    let header = macho::MachHeader64::<LittleEndian>::parse(data, 0)?;
    ensure!(
        header.filetype(endian) == macho::MH_FILESET,
        "expected MH_FILESET root"
    );
    ensure!(
        header.cputype(endian) == macho::CPU_TYPE_ARM64,
        "root thread metadata requires ARM64"
    );
    ensure!(
        header.ncmds(endian) <= MAX_LOAD_COMMAND_COUNT
            && header.ncmds(endian) <= header.sizeofcmds(endian) / LOAD_COMMAND_HEADER_BYTES,
        "invalid Mach-O load-command count"
    );
    let mut commands = header.load_commands(endian, data, 0)?;
    let mut consumed = 0u64;
    let mut result = None;
    while let Some(command) = commands.next()? {
        ensure!(
            command.cmdsize() >= LOAD_COMMAND_HEADER_BYTES
                && command.cmdsize().is_multiple_of(LOAD_COMMAND_HEADER_BYTES),
            "invalid load-command size"
        );
        let command_file_offset = MACH_HEADER64_BYTES as u64 + consumed;
        consumed = consumed
            .checked_add(u64::from(command.cmdsize()))
            .context("load-command extent overflow")?;
        match command.cmd() {
            macho::LC_UNIXTHREAD => {
                ensure!(result.is_none(), "duplicate LC_UNIXTHREAD");
                result = Some(RootThreadMetadata {
                    command_file_offset,
                    thread: unix_thread(command.raw_data())?,
                });
            }
            macho::LC_THREAD | macho::LC_MAIN => {
                anyhow::bail!("unsupported fileset root entry convention")
            }
            _ => {}
        }
    }
    ensure!(
        consumed == u64::from(header.sizeofcmds(endian)),
        "load-command count disagrees with table size"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut data = vec![0u8; 160];
        for (index, value) in [0xfeedfacfu32, 0x0100000c, 2, 0xc, 1, 40, 0, 0]
            .iter()
            .enumerate()
        {
            data[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        data[32..36].copy_from_slice(&0x80000035u32.to_le_bytes());
        data[36..40].copy_from_slice(&40u32.to_le_bytes());
        data[48..56].copy_from_slice(&128u64.to_le_bytes());
        data[56..60].copy_from_slice(&32u32.to_le_bytes());
        data[64..70].copy_from_slice(b"image\0");
        for (index, value) in [0xfeedfacfu32, 0x0100000c, 2, 2, 0, 0, 0, 0]
            .iter()
            .enumerate()
        {
            data[128 + index * 4..132 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        data
    }
    #[test]
    fn keeps_collection_offsets_and_rejects_bad_command_and_child_ranges() -> Result<()> {
        let data = fixture();
        let report = inspect(&data)?;
        assert_eq!(report.images[0].header_offset, 128);
        let mut bad = data.clone();
        bad[48..56].copy_from_slice(&159u64.to_le_bytes());
        assert!(inspect(&bad).is_err());
        let mut bad = data;
        bad[36..40].copy_from_slice(&7u32.to_le_bytes());
        assert!(inspect(&bad).is_err());
        Ok(())
    }
    #[test]
    fn empty_sections_may_have_zero_offsets_but_nonempty_sections_stay_in_segment() {
        let mut data = fixture();
        data.resize(316, 0);
        data[144..148].copy_from_slice(&1u32.to_le_bytes());
        data[148..152].copy_from_slice(&152u32.to_le_bytes());
        data[160..164].copy_from_slice(&0x19u32.to_le_bytes());
        data[164..168].copy_from_slice(&152u32.to_le_bytes());
        data[168..174].copy_from_slice(b"__TEXT");
        data[184..192].copy_from_slice(&0x4000u64.to_le_bytes());
        data[192..200].copy_from_slice(&4u64.to_le_bytes());
        data[200..208].copy_from_slice(&312u64.to_le_bytes());
        data[224..228].copy_from_slice(&1u32.to_le_bytes());
        data[232..238].copy_from_slice(b"__text");
        data[248..254].copy_from_slice(b"__TEXT");
        data[264..272].copy_from_slice(&0x4000u64.to_le_bytes());
        assert!(inspect(&data).is_ok());
        data[208..216].copy_from_slice(&4u64.to_le_bytes());
        data[272..280].copy_from_slice(&4u64.to_le_bytes());
        assert!(inspect(&data).is_err()); // offset 0 lies outside file range 312..316
        data[280..284].copy_from_slice(&312u32.to_le_bytes());
        assert!(inspect(&data).is_ok());
    }

    const TEST_THREAD_COMMAND_BYTES: usize = 288;
    const TEST_THREAD_PC_OFFSET: usize = 272;
    const TEST_THREAD_FLAVOR_OFFSET: usize = 8;
    const TEST_THREAD_COUNT_OFFSET: usize = 12;
    const TEST_WORD_BYTES: usize = std::mem::size_of::<u32>();
    const TEST_REGISTER_BYTES: usize = std::mem::size_of::<u64>();

    fn thread_command(pc: u64) -> Vec<u8> {
        let mut command = vec![0; TEST_THREAD_COMMAND_BYTES];
        for (offset, value) in [
            (0, macho::LC_UNIXTHREAD),
            (TEST_WORD_BYTES, TEST_THREAD_COMMAND_BYTES as u32),
            (TEST_THREAD_FLAVOR_OFFSET, 6),
            (TEST_THREAD_COUNT_OFFSET, 68),
        ] {
            command[offset..offset + TEST_WORD_BYTES].copy_from_slice(&value.to_le_bytes());
        }
        command[TEST_THREAD_PC_OFFSET..TEST_THREAD_PC_OFFSET + TEST_REGISTER_BYTES]
            .copy_from_slice(&pc.to_le_bytes());
        command
    }

    fn root_commands(commands: &[Vec<u8>]) -> Vec<u8> {
        let mut data = fixture()[..MACH_HEADER64_BYTES].to_vec();
        let bytes = commands.iter().map(Vec::len).sum::<usize>();
        data[16..20].copy_from_slice(&(commands.len() as u32).to_le_bytes());
        data[20..24].copy_from_slice(&(bytes as u32).to_le_bytes());
        for command in commands {
            data.extend_from_slice(command);
        }
        data
    }

    #[test]
    fn root_metadata_keeps_original_descriptor_and_schema_one_inventory() -> Result<()> {
        const CHILD_HEADER_OFFSET: usize = 512;
        const UNKNOWN_OPTIONAL_COMMAND: u32 = 0x7fff_ff00;
        let original = fixture();
        let mut child = original[32..72].to_vec();
        child[16..24].copy_from_slice(&(CHILD_HEADER_OFFSET as u64).to_le_bytes());
        let thread = thread_command(0xffff_fe00_09eb_4480);
        let unknown = [
            UNKNOWN_OPTIONAL_COMMAND.to_le_bytes(),
            LOAD_COMMAND_HEADER_BYTES.to_le_bytes(),
        ]
        .concat();
        let mut data = root_commands(&[child, thread.clone(), unknown]);
        data.resize(CHILD_HEADER_OFFSET, 0);
        data.extend_from_slice(&original[128..160]);
        let before = serde_json::to_value(inspect(&data)?)?;
        assert_eq!(before["schema_version"], 1);
        assert_eq!(
            before["root"]["unhandled_load_commands"],
            serde_json::json!([macho::LC_UNIXTHREAD, UNKNOWN_OPTIONAL_COMMAND])
        );
        assert!(before["root"].get("thread").is_none());
        let metadata = root_thread_metadata(&data)?.context("missing root descriptor")?;
        assert_eq!(
            metadata.command_file_offset,
            (MACH_HEADER64_BYTES + 40) as u64
        );
        assert_eq!(metadata.thread.pc, 0xffff_fe00_09eb_4480);
        assert_eq!(metadata.thread.sp, 0);
        assert_eq!(metadata.thread.cpsr, 0);
        assert_eq!(metadata.thread.raw_command_sha256, sha256(&thread));
        assert_eq!(metadata.thread.raw_command_hex, hex::encode(&thread));
        assert_eq!(serde_json::to_value(inspect(&data)?)?, before);
        assert!(root_thread_metadata(&original)?.is_none());
        Ok(())
    }

    #[test]
    fn root_metadata_rejects_ambiguous_or_malformed_commands() {
        let command = thread_command(0x1000);
        assert!(root_thread_metadata(&root_commands(&[command.clone(), command.clone()])).is_err());
        for id in [macho::LC_THREAD, macho::LC_MAIN] {
            let mut wrong = command.clone();
            wrong[..TEST_WORD_BYTES].copy_from_slice(&id.to_le_bytes());
            assert!(root_thread_metadata(&root_commands(&[wrong])).is_err());
        }
        for (offset, value) in [
            (TEST_THREAD_FLAVOR_OFFSET, 7u32),
            (TEST_THREAD_COUNT_OFFSET, 67u32),
        ] {
            let mut wrong = command.clone();
            wrong[offset..offset + TEST_WORD_BYTES].copy_from_slice(&value.to_le_bytes());
            assert!(root_thread_metadata(&root_commands(&[wrong])).is_err());
        }
        for size in [7u32, 280, 289, 296] {
            let mut wrong = command.clone();
            wrong[TEST_WORD_BYTES..2 * TEST_WORD_BYTES].copy_from_slice(&size.to_le_bytes());
            assert!(root_thread_metadata(&root_commands(&[wrong])).is_err());
        }
        let data = root_commands(&[command]);
        for length in 0..data.len() {
            assert!(
                root_thread_metadata(&data[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = data.clone();
        trailing.extend_from_slice(&[0; LOAD_COMMAND_HEADER_BYTES as usize]);
        let bytes = (trailing.len() - MACH_HEADER64_BYTES) as u32;
        trailing[20..24].copy_from_slice(&bytes.to_le_bytes());
        assert!(root_thread_metadata(&trailing).is_err());
        let mut wrong_count = data.clone();
        wrong_count[16..20].copy_from_slice(&MAX_LOAD_COMMAND_COUNT.to_le_bytes());
        assert!(root_thread_metadata(&wrong_count).is_err());
        let mut wrong_cpu = data;
        wrong_cpu[4..8].copy_from_slice(&macho::CPU_TYPE_X86_64.to_le_bytes());
        assert!(root_thread_metadata(&wrong_cpu).is_err());
    }

    #[test]
    #[ignore = "requires STELA_FILESET_ENTRY_IMAGE pointing at the original local pinned kernel"]
    fn original_kernel_root_thread_metadata_is_bounded_and_source_pinned() -> Result<()> {
        use std::io::Read;
        const PINNED_IMAGE_BYTES: u64 = 81_444_864;
        const MAX_PINNED_HEADER_BYTES: usize = 0x4000;
        const PINNED_HEADER_SHA256: &str =
            "a06902539fabdb1df3a2c79636c776284883a8f22014bbb23fc55f38b929442b";
        const PINNED_COMMAND_SHA256: &str =
            "9cb4944caf00c180887edf293f486418692278577bc97f51d701b67516095f72";
        let path = std::env::var_os("STELA_FILESET_ENTRY_IMAGE")
            .context("set STELA_FILESET_ENTRY_IMAGE")?;
        let mut file = std::fs::File::open(path)?;
        ensure!(
            file.metadata()?.len() == PINNED_IMAGE_BYTES,
            "pinned image size mismatch"
        );
        let mut header = vec![0; MACH_HEADER64_BYTES];
        file.read_exact(&mut header)?;
        let commands = u32_at(&header, 20)? as usize;
        ensure!(
            commands <= MAX_PINNED_HEADER_BYTES - MACH_HEADER64_BYTES,
            "pinned command table exceeds bound"
        );
        header.resize(MACH_HEADER64_BYTES + commands, 0);
        file.read_exact(&mut header[MACH_HEADER64_BYTES..])?;
        ensure!(
            sha256(&header) == PINNED_HEADER_SHA256,
            "pinned header/load-command identity mismatch"
        );
        let metadata =
            root_thread_metadata(&header)?.context("missing original root descriptor")?;
        assert_eq!(metadata.command_file_offset, 0x50);
        assert_eq!(metadata.thread.raw_command_sha256, PINNED_COMMAND_SHA256);
        assert_eq!(metadata.thread.pc, 0xffff_fe00_09eb_4480);
        assert_eq!(metadata.thread.x[16], 0xffff_fe00_09ea_c000);
        assert_eq!(metadata.thread.x[0], 0);
        assert_eq!(metadata.thread.sp, 0);
        assert_eq!(metadata.thread.cpsr, 0);
        // These serialized zeros and linked PC are metadata, never live boot state.
        Ok(())
    }
}
