//! Validated, unslid guest mappings and unresolved loader work for one thin image.
//! This module neither maps host memory nor resolves imports, fixups or signatures.
use object::{
    LittleEndian, macho,
    read::macho::{LoadCommandData, LoadCommandVariant, MachHeader, Segment},
};
use serde::Serialize;
use stela_core::sha256;
use std::{collections::BTreeSet, error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum PlanError {
    Malformed(String),
    UnsupportedFormat,
    UnsupportedCpu { cpu_type: u32, cpu_subtype: u32 },
    UnsupportedFileType(u32),
    UnsupportedRequiredCommand(u32),
    UnsupportedSegmentLayout { name: String, flags: u32 },
    UnsupportedEntryConvention,
}
impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed Mach-O: {detail}"),
            Self::UnsupportedFormat => f.write_str("load planning requires one thin little-endian 64-bit Mach-O slice"),
            Self::UnsupportedCpu { cpu_type, cpu_subtype } => write!(f, "unsupported CPU type {cpu_type:#x}, subtype {cpu_subtype:#x}; expected arm64 or arm64e"),
            Self::UnsupportedFileType(kind) => write!(f, "unsupported Mach-O file type {kind:#x} for requested executable/library planning mode"),
            Self::UnsupportedRequiredCommand(command) => write!(f, "unsupported required load command {command:#x}"),
            Self::UnsupportedSegmentLayout { name, flags } => write!(f, "unsupported segment layout {name:?}, flags {flags:#x}"),
            Self::UnsupportedEntryConvention => f.write_str("executable requires a single LC_MAIN entry; thread-state entry loading is unsupported"),
        }
    }
}
impl Error for PlanError {}
impl From<object::Error> for PlanError {
    fn from(value: object::Error) -> Self {
        Self::Malformed(value.to_string())
    }
}
type Result<T> = std::result::Result<T, PlanError>;
fn invalid(message: impl Into<String>) -> PlanError {
    PlanError::Malformed(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRange {
    pub offset: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestRange {
    pub address: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct SegmentPlan {
    pub name: String,
    pub guest: GuestRange,
    /// File bytes map at `guest.address`; the rest of the segment is zero-filled.
    pub file: FileRange,
    pub zero_fill: GuestRange,
    pub maximum_protection: u32,
    pub initial_protection: u32,
    pub flags: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    pub command: u32,
    pub name: String,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct Payload {
    pub command: u32,
    pub role: String,
    pub file: FileRange,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct OpaqueCommand {
    pub command: u32,
    pub bytes_hex: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct EntryPoint {
    /// LC_MAIN entryoff: offset from the preferred image (__TEXT) address.
    pub image_offset: u64,
    /// Resolved offset in the selected thin slice.
    pub file_offset: u64,
    pub guest_address: u64,
    pub stack_size: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct LoadPlan {
    pub schema_version: u32,
    pub file_type: u32,
    pub dylib_identity: Option<Dependency>,
    pub slice_sha256: String,
    pub slice_bytes: u64,
    pub cpu_type: u32,
    /// Includes the high-byte capability flags; do not normalize away arm64e ABI versions.
    pub cpu_subtype: u32,
    pub architecture: String,
    pub header_flags: u32,
    pub segments: Vec<SegmentPlan>,
    pub entry: Option<EntryPoint>,
    pub dependencies: Vec<Dependency>,
    pub dylinker: Option<String>,
    pub rpaths: Vec<String>,
    /// Bounded payloads only; their contents have not been interpreted or applied.
    pub payloads: Vec<Payload>,
    /// Optional commands whose semantics are deliberately deferred, including unknown commands.
    pub deferred_commands: Vec<OpaqueCommand>,
    pub execution_supported: bool,
    pub unresolved_requirements: Vec<String>,
}

/// Original ARM_THREAD_STATE64 descriptor, not a complete guest PSTATE/context.
/// PC is a preferred virtual address; the process loader must relocate it and
/// replace the serialized SP with its separately validated KernelArgs stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Arm64UnixThread {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
    pub flavor: u32,
    pub count: u32,
    pub raw_command_sha256: String,
    pub raw_command_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DynamicLinkerPlan {
    /// `entry` remains absent: LC_UNIXTHREAD is not an LC_MAIN C-call entry.
    pub image: LoadPlan,
    pub thread: Arm64UnixThread,
    pub install_name: String,
}

struct PlannedImage {
    image: LoadPlan,
    thread: Option<Arm64UnixThread>,
    install_name: Option<String>,
}
impl LoadPlan {
    pub fn executable_entry(&self) -> Result<&EntryPoint> {
        self.entry
            .as_ref()
            .ok_or(PlanError::UnsupportedEntryConvention)
    }
}
fn checked_end(start: u64, bytes: u64, role: &str) -> Result<u64> {
    start
        .checked_add(bytes)
        .ok_or_else(|| invalid(format!("{role} range overflow")))
}
fn file_bytes(data: &[u8], offset: u64, bytes: u64) -> Result<&[u8]> {
    let end = checked_end(offset, bytes, "file")?;
    let start = usize::try_from(offset).map_err(|_| invalid("file offset exceeds host size"))?;
    let end = usize::try_from(end).map_err(|_| invalid("file extent exceeds host size"))?;
    data.get(start..end)
        .ok_or_else(|| invalid("file extent exceeds slice"))
}
fn text(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| invalid("non-UTF-8 Mach-O name"))
}
fn command_string(
    command: LoadCommandData<'_, LittleEndian>,
    value: macho::LcStr<LittleEndian>,
    minimum: u32,
) -> Result<String> {
    if value.offset.get(LittleEndian) < minimum {
        return Err(invalid("load-command string overlaps fixed fields"));
    }
    let name = text(command.string(LittleEndian, value)?)?;
    if name.is_empty() {
        return Err(invalid("empty load-command string"));
    }
    Ok(name)
}
fn overlaps(a: u64, a_bytes: u64, b: u64, b_bytes: u64) -> bool {
    a_bytes != 0 && b_bytes != 0 && a < b + b_bytes && b < a + a_bytes
}
fn payload(data: &[u8], command: u32, role: &str, offset: u32, bytes: u32) -> Result<Payload> {
    let file = FileRange {
        offset: u64::from(offset),
        bytes: u64::from(bytes),
    };
    let hash = sha256(file_bytes(data, file.offset, file.bytes)?);
    Ok(Payload {
        command,
        role: role.into(),
        file,
        sha256: hash,
    })
}

/// Plan one standalone executable slice. Use `super::split_slices` to select a fat
/// image first; all returned offsets are relative to the selected thin slice.
/// Success proves only structural planning, never process execution readiness.
pub fn plan(data: &[u8]) -> Result<LoadPlan> {
    Ok(plan_kind(data, macho::MH_EXECUTE)?.image)
}

/// Plan a dylib without inventing an executable entry or running initializers.
pub fn plan_library(data: &[u8]) -> Result<LoadPlan> {
    Ok(plan_kind(data, macho::MH_DYLIB)?.image)
}

/// Plan a thin classic arm64/arm64e dynamic linker with one reviewed kernel
/// thread-entry descriptor. This does not map, rebase or execute dyld.
pub fn plan_dynamic_linker(data: &[u8]) -> Result<DynamicLinkerPlan> {
    let planned = plan_kind(data, macho::MH_DYLINKER)?;
    Ok(DynamicLinkerPlan {
        image: planned.image,
        thread: planned
            .thread
            .ok_or_else(|| invalid("MH_DYLINKER requires LC_UNIXTHREAD"))?,
        install_name: planned
            .install_name
            .ok_or_else(|| invalid("MH_DYLINKER requires LC_ID_DYLINKER"))?,
    })
}

fn unix_thread(raw: &[u8]) -> Result<Arm64UnixThread> {
    // XNU ARM_THREAD_STATE64=6 has 68 uint32 words (272 bytes). Reject extra
    // flavors/trailing bytes rather than interpreting arbitrary thread state.
    if raw.len() != 288 {
        return Err(invalid("LC_UNIXTHREAD requires exactly 288 bytes"));
    }
    let word = |offset| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
    let flavor = word(8);
    let count = word(12);
    if flavor != 6 || count != 68 {
        return Err(invalid(
            "LC_UNIXTHREAD requires ARM_THREAD_STATE64 flavor 6/count 68",
        ));
    }
    let state = &raw[16..];
    let register = |offset| u64::from_le_bytes(state[offset..offset + 8].try_into().unwrap());
    Ok(Arm64UnixThread {
        x: std::array::from_fn(|index| register(index * 8)),
        sp: register(248),
        pc: register(256),
        cpsr: word(280),
        pad: word(284),
        flavor,
        count,
        raw_command_sha256: sha256(raw),
        raw_command_hex: hex::encode(raw),
    })
}

fn plan_kind(data: &[u8], expected_type: u32) -> Result<PlannedImage> {
    if data.get(..4) != Some(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return Err(PlanError::UnsupportedFormat);
    }
    let endian = LittleEndian;
    let header = macho::MachHeader64::<LittleEndian>::parse(data, 0)?;
    let cpu_type = header.cputype(endian);
    let cpu_subtype = header.cpusubtype(endian);
    if cpu_type != macho::CPU_TYPE_ARM64 || !matches!(cpu_subtype & !macho::CPU_SUBTYPE_MASK, 0 | 2)
    {
        return Err(PlanError::UnsupportedCpu {
            cpu_type,
            cpu_subtype,
        });
    }
    if header.filetype(endian) != expected_type {
        return Err(PlanError::UnsupportedFileType(header.filetype(endian)));
    }
    if header.ncmds(endian) > header.sizeofcmds(endian) / 8 {
        return Err(invalid("load-command count exceeds table"));
    }
    let mut commands = header.load_commands(endian, data, 0)?;
    let mut segments: Vec<SegmentPlan> = vec![];
    let mut dependencies = vec![];
    let mut dylib_identity = None;
    let mut dylinker = None;
    let mut rpaths = vec![];
    let mut payloads = vec![];
    let mut deferred_commands = vec![];
    let mut entry = None;
    let mut thread = None;
    let mut install_name = None;
    let mut consumed = 0u64;
    let mut singleton_commands = BTreeSet::new();
    while let Some(command) = commands.next()? {
        let id = command.cmd();
        if !command.cmdsize().is_multiple_of(8) {
            return Err(invalid("64-bit load command is not 8-byte aligned"));
        }
        consumed += u64::from(command.cmdsize());
        match command.variant()? {
            LoadCommandVariant::Segment64(segment, section_data) => {
                let name = text(segment.name())?;
                let vmaddr = segment.vmaddr.get(endian);
                let vmsize = segment.vmsize.get(endian);
                let fileoff = segment.fileoff.get(endian);
                let filesize = segment.filesize.get(endian);
                let maxprot = segment.maxprot.get(endian);
                let initprot = segment.initprot.get(endian);
                let flags = segment.flags.get(endian);
                if flags & (macho::SG_HIGHVM | macho::SG_FVMLIB | macho::SG_PROTECTED_VERSION_1)
                    != 0
                {
                    return Err(PlanError::UnsupportedSegmentLayout { name, flags });
                }
                if flags & !(macho::SG_NORELOC | macho::SG_READ_ONLY) != 0 {
                    return Err(PlanError::UnsupportedSegmentLayout { name, flags });
                }
                if maxprot & !7 != 0 || initprot & !maxprot != 0 {
                    return Err(invalid("invalid segment protections"));
                }
                if filesize > vmsize {
                    return Err(invalid("segment file extent exceeds VM extent"));
                }
                let vmend = checked_end(vmaddr, vmsize, "segment VM")?;
                let fileend = checked_end(fileoff, filesize, "segment file")?;
                file_bytes(data, fileoff, filesize)?;
                for prior in &segments {
                    if overlaps(vmaddr, vmsize, prior.guest.address, prior.guest.bytes) {
                        return Err(invalid("overlapping segment VM extents"));
                    }
                    if overlaps(fileoff, filesize, prior.file.offset, prior.file.bytes) {
                        return Err(invalid("overlapping segment file extents"));
                    }
                }
                let sections = segment.sections(endian, section_data)?;
                if section_data.len() != sections.len() * 80 {
                    return Err(invalid("segment size disagrees with section count"));
                }
                let mut section_ranges = vec![];
                for section in sections {
                    if section.segname != segment.segname {
                        return Err(invalid("section/segment names disagree"));
                    }
                    let address = section.addr.get(endian);
                    let bytes = section.size.get(endian);
                    let end = checked_end(address, bytes, "section VM")?;
                    let alignment = section.align.get(endian);
                    if alignment >= 64 || !address.is_multiple_of(1u64 << alignment) {
                        return Err(invalid("invalid or unsatisfied section alignment"));
                    }
                    if address < vmaddr || end > vmend {
                        return Err(invalid("section exceeds segment VM extent"));
                    }
                    let zerofill = matches!(
                        section.flags.get(endian) & macho::SECTION_TYPE,
                        macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL
                    );
                    if bytes != 0 {
                        if section_ranges
                            .iter()
                            .any(|&(start, len)| overlaps(start, len, address, bytes))
                        {
                            return Err(invalid("overlapping section VM extents"));
                        }
                        section_ranges.push((address, bytes));
                        // Segment commands define the initial mapping. Apple ld
                        // can start a zero-fill section inside the final padded
                        // file page; it has no independent file extent. Do not
                        // reject that layout or overwrite mapped file bytes.
                        if !zerofill {
                            let offset = u64::from(section.offset.get(endian));
                            if offset < fileoff
                                || checked_end(offset, bytes, "section file")? > fileend
                                || address - vmaddr != offset - fileoff
                            {
                                return Err(invalid(
                                    "section file/VM mapping disagrees with segment",
                                ));
                            }
                        }
                    }
                }
                segments.push(SegmentPlan {
                    name,
                    guest: GuestRange {
                        address: vmaddr,
                        bytes: vmsize,
                    },
                    file: FileRange {
                        offset: fileoff,
                        bytes: filesize,
                    },
                    zero_fill: GuestRange {
                        address: vmaddr + filesize,
                        bytes: vmsize - filesize,
                    },
                    maximum_protection: maxprot,
                    initial_protection: initprot,
                    flags,
                });
            }
            LoadCommandVariant::EntryPoint(main) => {
                if expected_type == macho::MH_DYLINKER {
                    return Err(invalid("MH_DYLINKER cannot declare LC_MAIN"));
                }
                if expected_type != macho::MH_EXECUTE {
                    return Err(invalid("MH_DYLIB cannot declare LC_MAIN"));
                }
                if entry.is_some() || command.cmdsize() != 24 {
                    return Err(invalid("duplicate or incorrectly sized LC_MAIN"));
                }
                entry = Some((main.entryoff.get(endian), main.stacksize.get(endian)));
            }
            LoadCommandVariant::Thread(_, _) => {
                if expected_type != macho::MH_DYLINKER {
                    return Err(PlanError::UnsupportedEntryConvention);
                }
                if id != macho::LC_UNIXTHREAD {
                    return Err(invalid("MH_DYLINKER requires LC_UNIXTHREAD, not LC_THREAD"));
                }
                if thread.is_some() {
                    return Err(invalid("duplicate LC_UNIXTHREAD"));
                }
                thread = Some(unix_thread(command.raw_data())?);
            }
            LoadCommandVariant::IdDylib(dylib) => {
                if expected_type != macho::MH_DYLIB {
                    return Err(invalid("MH_EXECUTE cannot declare LC_ID_DYLIB"));
                }
                if dylib_identity.is_some() {
                    return Err(invalid("duplicate LC_ID_DYLIB"));
                }
                dylib_identity = Some(Dependency {
                    command: id,
                    name: command_string(command, dylib.dylib.name, 24)?,
                    timestamp: dylib.dylib.timestamp.get(endian),
                    current_version: dylib.dylib.current_version.get(endian),
                    compatibility_version: dylib.dylib.compatibility_version.get(endian),
                });
            }
            LoadCommandVariant::Dylib(dylib) => dependencies.push(Dependency {
                command: id,
                name: command_string(command, dylib.dylib.name, 24)?,
                timestamp: dylib.dylib.timestamp.get(endian),
                current_version: dylib.dylib.current_version.get(endian),
                compatibility_version: dylib.dylib.compatibility_version.get(endian),
            }),
            LoadCommandVariant::LoadDylinker(linker) => {
                if expected_type == macho::MH_DYLINKER {
                    return Err(invalid("MH_DYLINKER cannot declare LC_LOAD_DYLINKER"));
                }
                if expected_type != macho::MH_EXECUTE {
                    return Err(invalid("MH_DYLIB cannot declare LC_LOAD_DYLINKER"));
                }
                if dylinker.is_some() {
                    return Err(invalid("duplicate LC_LOAD_DYLINKER"));
                }
                dylinker = Some(command_string(command, linker.name, 12)?);
            }
            LoadCommandVariant::IdDylinker(linker) if expected_type == macho::MH_DYLINKER => {
                if install_name.is_some() || command.cmdsize() > 4112 {
                    return Err(invalid("duplicate or oversized LC_ID_DYLINKER"));
                }
                let name = command_string(command, linker.name, 12)?;
                if name.len() > 4096 {
                    return Err(invalid("LC_ID_DYLINKER name exceeds 4096 bytes"));
                }
                install_name = Some(name);
            }
            LoadCommandVariant::Rpath(path) => rpaths.push(command_string(command, path.path, 12)?),
            LoadCommandVariant::LinkeditData(info) => {
                if command.cmdsize() != 16 || !singleton_commands.insert(id) {
                    return Err(invalid("duplicate or incorrectly sized linkedit payload"));
                }
                let role = match id {
                    macho::LC_CODE_SIGNATURE => "code_signature",
                    macho::LC_DYLD_CHAINED_FIXUPS => "chained_fixups",
                    macho::LC_DYLD_EXPORTS_TRIE => "exports_trie",
                    macho::LC_FUNCTION_STARTS => "function_starts",
                    _ => "linkedit_metadata",
                };
                payloads.push(payload(
                    data,
                    id,
                    role,
                    info.dataoff.get(endian),
                    info.datasize.get(endian),
                )?);
            }
            LoadCommandVariant::DyldInfo(info) => {
                if command.cmdsize() != 48 || !singleton_commands.insert(macho::LC_DYLD_INFO) {
                    return Err(invalid("duplicate or incorrectly sized dyld info"));
                }
                for (role, offset, bytes) in [
                    ("rebase", info.rebase_off, info.rebase_size),
                    ("bind", info.bind_off, info.bind_size),
                    ("weak_bind", info.weak_bind_off, info.weak_bind_size),
                    ("lazy_bind", info.lazy_bind_off, info.lazy_bind_size),
                    ("export", info.export_off, info.export_size),
                ] {
                    payloads.push(payload(
                        data,
                        id,
                        role,
                        offset.get(endian),
                        bytes.get(endian),
                    )?);
                }
            }
            LoadCommandVariant::EncryptionInfo64(info) => {
                if command.cmdsize() != 24 || !singleton_commands.insert(id) {
                    return Err(invalid("duplicate or incorrectly sized encryption info"));
                }
                payloads.push(payload(
                    data,
                    id,
                    "encrypted_range",
                    info.cryptoff.get(endian),
                    info.cryptsize.get(endian),
                )?);
                deferred_commands.push(OpaqueCommand {
                    command: id,
                    bytes_hex: hex::encode(command.raw_data()),
                });
            }
            LoadCommandVariant::Other if id & macho::LC_REQ_DYLD != 0 => {
                return Err(PlanError::UnsupportedRequiredCommand(id));
            }
            _ => {
                if id & macho::LC_REQ_DYLD != 0 {
                    return Err(PlanError::UnsupportedRequiredCommand(id));
                }
                deferred_commands.push(OpaqueCommand {
                    command: id,
                    bytes_hex: hex::encode(command.raw_data()),
                });
            }
        }
    }
    if consumed != u64::from(header.sizeofcmds(endian)) {
        return Err(invalid("load-command count disagrees with declared size"));
    }
    // Apple dyld validates __TEXT.fileoff == 0 and resolves LC_MAIN as
    // preferredLoadAddress() + entryoff (MachOAnalyzer::validMain). A raw file
    // lookup is wrong if an executable segment's VM/file layout has a gap.
    let text_segments: Vec<_> = segments.iter().filter(|s| s.name == "__TEXT").collect();
    if text_segments.len() != 1 {
        return Err(invalid("executable requires exactly one __TEXT segment"));
    }
    let text_segment = text_segments[0];
    if text_segment.file.offset != 0
        || text_segment.file.bytes < 32 + u64::from(header.sizeofcmds(endian))
    {
        return Err(invalid(
            "__TEXT must contain the header and load commands at file offset zero",
        ));
    }
    let entry = if expected_type == macho::MH_EXECUTE {
        let (image_offset, stack_size) = entry.ok_or(PlanError::UnsupportedEntryConvention)?;
        let guest_address =
            checked_end(text_segment.guest.address, image_offset, "LC_MAIN address")?;
        let mappings: Vec<_> = segments
            .iter()
            .filter(|s| {
                s.initial_protection & macho::VM_PROT_EXECUTE != 0
                    && s.file.bytes != 0
                    && guest_address >= s.guest.address
                    && guest_address - s.guest.address < s.file.bytes
            })
            .collect();
        if mappings.len() != 1 {
            return Err(invalid(
                "LC_MAIN does not identify exactly one file-backed executable address",
            ));
        }
        let mapping = mappings[0];
        let file_offset = mapping.file.offset + (guest_address - mapping.guest.address);
        if !guest_address.is_multiple_of(4) {
            return Err(invalid("LC_MAIN guest address is not instruction aligned"));
        }
        if mapping.file.offset + mapping.file.bytes - file_offset < 4 {
            return Err(invalid("LC_MAIN has no complete file-backed instruction"));
        }
        Some(EntryPoint {
            image_offset,
            file_offset,
            guest_address,
            stack_size,
        })
    } else if expected_type == macho::MH_DYLIB {
        if dylib_identity.is_none() {
            return Err(invalid("MH_DYLIB requires LC_ID_DYLIB"));
        }
        None
    } else {
        let descriptor = thread
            .as_ref()
            .ok_or_else(|| invalid("MH_DYLINKER requires LC_UNIXTHREAD"))?;
        if install_name.is_none() {
            return Err(invalid("MH_DYLINKER requires LC_ID_DYLINKER"));
        }
        if !descriptor.pc.is_multiple_of(4) {
            return Err(invalid("LC_UNIXTHREAD PC is not instruction aligned"));
        }
        let required = macho::VM_PROT_READ | macho::VM_PROT_EXECUTE;
        let mappings = segments
            .iter()
            .filter(|s| {
                s.initial_protection & required == required
                    && descriptor.pc >= s.guest.address
                    && descriptor.pc - s.guest.address < s.file.bytes
            })
            .collect::<Vec<_>>();
        if mappings.len() != 1 {
            return Err(invalid(
                "LC_UNIXTHREAD PC does not identify exactly one file-backed readable executable address",
            ));
        }
        let mapping = mappings[0];
        if mapping.file.bytes - (descriptor.pc - mapping.guest.address) < 4 {
            return Err(invalid(
                "LC_UNIXTHREAD PC has no complete file-backed instruction",
            ));
        }
        None
    };
    for item in &payloads {
        if item.file.bytes != 0
            && !segments.iter().any(|s| {
                item.file.offset >= s.file.offset
                    && item.file.offset + item.file.bytes <= s.file.offset + s.file.bytes
            })
        {
            return Err(invalid(
                "loader payload is not contained in a file-backed segment",
            ));
        }
    }
    let mut unresolved_requirements = vec![
        "native instruction translation and control-flow dispatch".into(),
        "guest virtual memory, page-size policy and protection enforcement".into(),
        "Apple process/thread ABI, stack, exceptions and system calls".into(),
    ];
    if dylinker.is_some() || !dependencies.is_empty() || !rpaths.is_empty() {
        unresolved_requirements
            .push("dyld/shared-cache loading, dependency resolution and initializers".into());
    }
    if payloads.iter().any(|p| {
        matches!(
            p.role.as_str(),
            "chained_fixups" | "rebase" | "bind" | "weak_bind" | "lazy_bind"
        )
    }) {
        unresolved_requirements.push(
            "rebase/bind/chained-fixup interpretation, including authenticated pointers".into(),
        );
    }
    if payloads.iter().any(|p| p.role == "code_signature") {
        unresolved_requirements
            .push("code-signature validation and platform signing policy".into());
    }
    if payloads.iter().any(|p| p.role == "encrypted_range") {
        unresolved_requirements.push("encrypted-input handling and cryptid policy".into());
    }
    if !deferred_commands.is_empty() {
        unresolved_requirements.push("semantics of preserved deferred load commands".into());
    }
    if cpu_subtype & !macho::CPU_SUBTYPE_MASK == 2 {
        unresolved_requirements
            .push("arm64e pointer-authentication ABI and CPU-subtype capability policy".into());
    }
    Ok(PlannedImage {
        thread,
        install_name,
        image: LoadPlan {
            schema_version: 2,
            file_type: expected_type,
            dylib_identity,
            slice_sha256: sha256(data),
            slice_bytes: data.len() as u64,
            cpu_type,
            cpu_subtype,
            architecture: if cpu_subtype & !macho::CPU_SUBTYPE_MASK == 2 {
                "arm64e"
            } else {
                "arm64"
            }
            .into(),
            header_flags: header.flags(endian),
            segments,
            entry,
            dependencies,
            dylinker,
            rpaths,
            payloads,
            deferred_commands,
            execution_supported: false,
            unresolved_requirements,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u64 = 0x1_0000_0000;
    fn u32_put(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64_put(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn segment(
        name: &[u8],
        address: u64,
        vmbytes: u64,
        offset: u64,
        filebytes: u64,
        prot: u32,
    ) -> Vec<u8> {
        let mut command = vec![0; 72];
        u32_put(&mut command, 0, 0x19);
        u32_put(&mut command, 4, 72);
        command[8..8 + name.len()].copy_from_slice(name);
        u64_put(&mut command, 24, address);
        u64_put(&mut command, 32, vmbytes);
        u64_put(&mut command, 40, offset);
        u64_put(&mut command, 48, filebytes);
        u32_put(&mut command, 56, prot);
        u32_put(&mut command, 60, prot);
        command
    }
    fn main_command(offset: u64) -> Vec<u8> {
        let mut command = vec![0; 24];
        u32_put(&mut command, 0, 0x8000_0028);
        u32_put(&mut command, 4, 24);
        u64_put(&mut command, 8, offset);
        u64_put(&mut command, 16, 0x20000);
        command
    }
    fn string_command(id: u32, fixed: usize, name: &[u8]) -> Vec<u8> {
        let size = (fixed + name.len() + 1).next_multiple_of(8);
        let mut command = vec![0; size];
        u32_put(&mut command, 0, id);
        u32_put(&mut command, 4, size as u32);
        u32_put(&mut command, 8, fixed as u32);
        command[fixed..fixed + name.len()].copy_from_slice(name);
        command
    }
    fn image(commands: Vec<Vec<u8>>) -> Vec<u8> {
        let mut data = vec![0u8; 0x1200];
        for (index, value) in [
            0xfeedfacf,
            0x0100000c,
            0x80000002,
            2,
            commands.len() as u32,
            commands.iter().map(|c| c.len() as u32).sum(),
            0x200000,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            u32_put(&mut data, index * 4, value);
        }
        let mut at = 32;
        for command in commands {
            data[at..at + command.len()].copy_from_slice(&command);
            at += command.len();
        }
        data[0x1004..0x1008].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
        data
    }
    fn commands() -> Vec<Vec<u8>> {
        vec![
            segment(b"__PAGEZERO", 0, BASE, 0, 0, 0),
            segment(b"__TEXT", BASE, 0x2000, 0, 0x1100, 5),
            segment(b"__DATA", BASE + 0x2000, 0x1000, 0x1100, 0x100, 3),
            main_command(0x1004),
        ]
    }
    fn unix_thread_command(pc: u64) -> Vec<u8> {
        let mut command = vec![0; 288];
        u32_put(&mut command, 0, macho::LC_UNIXTHREAD);
        u32_put(&mut command, 4, 288);
        u32_put(&mut command, 8, 6);
        u32_put(&mut command, 12, 68);
        for index in 0..31 {
            u64_put(
                &mut command,
                16 + index * 8,
                0xfedc_ba98_7654_3210u64.rotate_left(index as u32),
            );
        }
        u64_put(&mut command, 264, u64::MAX - 7);
        u64_put(&mut command, 272, pc);
        u32_put(&mut command, 280, 0xf123_4567);
        u32_put(&mut command, 284, 0x89ab_cdef);
        command
    }
    fn dynamic_linker_commands() -> Vec<Vec<u8>> {
        vec![
            segment(b"__TEXT", 0, 0x2000, 0, 0x1100, 5),
            segment(b"__DATA", 0x2000, 0x1000, 0x1100, 0x100, 3),
            unix_thread_command(0x1004),
            string_command(macho::LC_ID_DYLINKER, 12, b"/usr/lib/dyld"),
        ]
    }
    fn dynamic_linker_image(commands: Vec<Vec<u8>>) -> Vec<u8> {
        let mut data = image(commands);
        u32_put(&mut data, 12, macho::MH_DYLINKER);
        data
    }

    #[test]
    fn dynamic_linker_preserves_raw_thread_state_with_zero_based_text_and_no_main_entry() {
        let items = dynamic_linker_commands();
        let raw = items[2].clone();
        let input = dynamic_linker_image(items);
        let result = plan_dynamic_linker(&input).unwrap();
        assert_eq!(result.image.file_type, macho::MH_DYLINKER);
        assert_eq!(result.image.architecture, "arm64e");
        assert_eq!(result.image.segments[0].guest.address, 0);
        assert_eq!(result.install_name, "/usr/lib/dyld");
        assert_eq!(result.image.slice_sha256, sha256(&input));
        assert!(result.image.entry.is_none());
        assert!(result.image.dylinker.is_none());
        assert!(result.image.dylib_identity.is_none());
        assert!(!result.image.execution_supported);
        for index in 0..31 {
            assert_eq!(
                result.thread.x[index],
                0xfedc_ba98_7654_3210u64.rotate_left(index as u32)
            );
        }
        assert_eq!(result.thread.sp, u64::MAX - 7);
        assert_eq!(result.thread.pc, 0x1004);
        assert_eq!(result.thread.cpsr, 0xf123_4567);
        assert_eq!(result.thread.pad, 0x89ab_cdef);
        assert_eq!((result.thread.flavor, result.thread.count), (6, 68));
        assert_eq!(result.thread.raw_command_sha256, sha256(&raw));
        assert_eq!(hex::decode(&result.thread.raw_command_hex).unwrap(), raw);
        let json = serde_json::to_value(result).unwrap();
        assert_eq!(json["image"]["entry"], serde_json::Value::Null);
        assert_eq!(json["thread"]["pc"], 0x1004);
        assert_eq!(json["thread"]["x"].as_array().unwrap().len(), 31);
        assert!(matches!(
            plan(&input),
            Err(PlanError::UnsupportedFileType(7))
        ));
        assert!(matches!(
            plan_library(&input),
            Err(PlanError::UnsupportedFileType(7))
        ));
    }

    #[test]
    fn dynamic_linker_accepts_only_reviewed_cpu_profiles_and_file_type() {
        for subtype in [0, 2, 0x8000_0002] {
            let mut input = dynamic_linker_image(dynamic_linker_commands());
            u32_put(&mut input, 8, subtype);
            assert_eq!(
                plan_dynamic_linker(&input).unwrap().image.cpu_subtype,
                subtype
            );
        }
        for subtype in [1, 12, 0x8000_000c] {
            let mut input = dynamic_linker_image(dynamic_linker_commands());
            u32_put(&mut input, 8, subtype);
            assert!(matches!(
                plan_dynamic_linker(&input),
                Err(PlanError::UnsupportedCpu { .. })
            ));
        }
        let mut input = dynamic_linker_image(dynamic_linker_commands());
        u32_put(&mut input, 4, macho::CPU_TYPE_X86_64);
        assert!(matches!(
            plan_dynamic_linker(&input),
            Err(PlanError::UnsupportedCpu { .. })
        ));
        assert!(matches!(
            plan_dynamic_linker(&image(commands())),
            Err(PlanError::UnsupportedFileType(2))
        ));
    }

    #[test]
    fn dynamic_linker_declines_missing_duplicate_mixed_and_non_unix_entries() {
        for remove in [2, 3] {
            let mut items = dynamic_linker_commands();
            items.remove(remove);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        for command in [
            unix_thread_command(0x1004),
            main_command(0x1004),
            string_command(macho::LC_ID_DYLINKER, 12, b"/usr/lib/dyld"),
            string_command(macho::LC_LOAD_DYLINKER, 12, b"/usr/lib/dyld"),
            string_command(macho::LC_ID_DYLIB, 24, b"libwrong.dylib"),
        ] {
            let mut items = dynamic_linker_commands();
            items.push(command.clone());
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
            let mut items = dynamic_linker_commands();
            items.insert(0, command);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        let mut items = dynamic_linker_commands();
        u32_put(&mut items[2], 0, macho::LC_THREAD);
        assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        // Existing execute/library modes keep declining every thread entry.
        for kind in [macho::MH_EXECUTE, macho::MH_DYLIB] {
            let mut items = commands();
            items[3] = unix_thread_command(BASE + 0x1004);
            let mut input = image(items);
            u32_put(&mut input, 12, kind);
            let result = if kind == macho::MH_EXECUTE {
                plan(&input)
            } else {
                plan_library(&input)
            };
            assert_eq!(result.unwrap_err(), PlanError::UnsupportedEntryConvention);
        }
    }

    #[test]
    fn dynamic_linker_rejects_unknown_counts_trailing_flavors_and_truncations() {
        for (offset, value) in [
            (8, 0),
            (8, 1),
            (8, 7),
            (12, 0),
            (12, 67),
            (12, 69),
            (12, u32::MAX),
        ] {
            let mut items = dynamic_linker_commands();
            u32_put(&mut items[2], offset, value);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        for size in [8, 16, 280, 296, 576] {
            let mut items = dynamic_linker_commands();
            items[2].resize(size, 0);
            u32_put(&mut items[2], 4, size as u32);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        let input = dynamic_linker_image(dynamic_linker_commands());
        for length in [0, 4, 31, 100, 32 + 72 + 72 + 287] {
            assert!(plan_dynamic_linker(&input[..length]).is_err());
        }
    }

    #[test]
    fn dynamic_linker_entry_requires_complete_readable_executable_file_bytes() {
        for pc in [0x1005, 0x1100, 0x2000, u64::MAX - 3] {
            let mut items = dynamic_linker_commands();
            items[2] = unix_thread_command(pc);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        let mut items = dynamic_linker_commands();
        items[2] = unix_thread_command(0x10fc);
        assert!(plan_dynamic_linker(&dynamic_linker_image(items.clone())).is_ok());
        // The final aligned address has only three original instruction bytes.
        u64_put(&mut items[0], 48, 0x10ff);
        assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        for protection in [0, 1, 3, 4] {
            let mut items = dynamic_linker_commands();
            u32_put(&mut items[0], 56, protection);
            u32_put(&mut items[0], 60, protection);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        // Serialized PC is a VM address, not a file offset or image-relative LC_MAIN.
        let mut items = dynamic_linker_commands();
        items.push(segment(b"__CODE", 0x4000, 0x1000, 0x1200, 0x100, 5));
        items[2] = unix_thread_command(0x4004);
        let mut input = dynamic_linker_image(items);
        input.resize(0x1300, 0);
        assert_eq!(plan_dynamic_linker(&input).unwrap().thread.pc, 0x4004);
    }

    #[test]
    fn dynamic_linker_install_name_is_bounded_terminated_utf8_and_outside_fixed_fields() {
        for name in [b"".as_slice(), b"\xff".as_slice()] {
            let mut items = dynamic_linker_commands();
            items[3] = string_command(macho::LC_ID_DYLINKER, 12, name);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        for offset in [0, 8, 32, u32::MAX] {
            let mut items = dynamic_linker_commands();
            u32_put(&mut items[3], 8, offset);
            assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        }
        let mut items = dynamic_linker_commands();
        items[3][12..].fill(b'x');
        assert!(plan_dynamic_linker(&dynamic_linker_image(items)).is_err());
        let mut items = dynamic_linker_commands();
        items[3] = string_command(macho::LC_ID_DYLINKER, 12, &vec![b'x'; 4097]);
        let mut input = image(vec![]);
        input.resize(0x3000, 0);
        // Oversized identity must decline even when the image itself contains it.
        u64_put(&mut items[0], 32, 0x3000);
        u64_put(&mut items[0], 48, 0x3000);
        items.remove(1);
        u32_put(&mut input, 12, macho::MH_DYLINKER);
        u32_put(&mut input, 16, items.len() as u32);
        u32_put(&mut input, 20, items.iter().map(|x| x.len() as u32).sum());
        let mut at = 32;
        for command in items {
            input[at..at + command.len()].copy_from_slice(&command);
            at += command.len();
        }
        assert!(plan_dynamic_linker(&input).is_err());
    }
    #[test]
    fn plans_unslid_arm64e_mapping_zero_fill_and_image_relative_entry() {
        let input = image(commands());
        let result = plan(&input).unwrap();
        assert_eq!(result.architecture, "arm64e");
        assert_eq!(result.cpu_subtype, 0x80000002);
        assert_eq!(result.entry.as_ref().unwrap().file_offset, 0x1004);
        assert_eq!(result.entry.as_ref().unwrap().image_offset, 0x1004);
        assert_eq!(result.entry.as_ref().unwrap().guest_address, BASE + 0x1004);
        assert_eq!(result.entry.as_ref().unwrap().stack_size, 0x20000);
        assert_eq!(
            result.segments[1].zero_fill,
            GuestRange {
                address: BASE + 0x1100,
                bytes: 0xf00
            }
        );
        assert_eq!(result.segments[2].initial_protection, 3);
        assert_eq!(result.slice_sha256, sha256(&input));
        assert!(!result.execution_supported);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["entry"]["guest_address"], BASE + 0x1004);
    }
    #[test]
    fn plans_dylib_identity_without_inventing_an_entry_and_rejects_mixed_conventions() {
        let identity = string_command(macho::LC_ID_DYLIB, 24, b"@rpath/libfixture.dylib");
        let mut items = commands();
        items.pop();
        items.push(identity.clone());
        let mut input = image(items.clone());
        u32_put(&mut input, 12, macho::MH_DYLIB);
        let result = plan_library(&input).unwrap();
        assert_eq!(result.file_type, macho::MH_DYLIB);
        assert_eq!(
            result.dylib_identity.unwrap().name,
            "@rpath/libfixture.dylib"
        );
        assert!(result.entry.is_none());
        assert!(plan(&input).is_err());
        assert!(plan_library(&image(commands())).is_err());
        items.push(identity);
        let mut duplicate = image(items);
        u32_put(&mut duplicate, 12, macho::MH_DYLIB);
        assert!(plan_library(&duplicate).is_err());
        let mut missing = commands();
        missing.pop();
        let mut missing = image(missing);
        u32_put(&mut missing, 12, macho::MH_DYLIB);
        assert!(plan_library(&missing).is_err());
        let mut with_main = commands();
        with_main.push(string_command(macho::LC_ID_DYLIB, 24, b"lib.dylib"));
        let mut with_main = image(with_main);
        u32_put(&mut with_main, 12, macho::MH_DYLIB);
        assert!(plan_library(&with_main).is_err());
    }
    #[test]
    fn preserves_dependencies_fixups_signatures_and_optional_unknown_commands() {
        let mut items = commands();
        items.push(string_command(0xc, 24, b"/usr/lib/libSystem.B.dylib"));
        items.push(string_command(0x80000018, 24, b"@rpath/optional.dylib"));
        items.push(string_command(0xe, 12, b"/usr/lib/dyld"));
        items.push(string_command(
            0x8000001c,
            12,
            b"@executable_path/../Frameworks",
        ));
        for id in [0x80000034, 0x1d] {
            let mut command = vec![0; 16];
            u32_put(&mut command, 0, id);
            u32_put(&mut command, 4, 16);
            u32_put(&mut command, 8, 0x1100);
            u32_put(&mut command, 12, 16);
            items.push(command);
        }
        items.push(vec![0x77, 0, 0, 0, 8, 0, 0, 0]);
        let report = plan(&image(items)).unwrap();
        assert_eq!(report.dependencies[0].name, "/usr/lib/libSystem.B.dylib");
        assert_eq!(report.dependencies[1].command, 0x80000018);
        assert_eq!(report.dylinker.as_deref(), Some("/usr/lib/dyld"));
        assert_eq!(report.rpaths, ["@executable_path/../Frameworks"]);
        assert_eq!(report.payloads[0].role, "chained_fixups");
        assert_eq!(
            report.payloads[0].file,
            FileRange {
                offset: 0x1100,
                bytes: 16
            }
        );
        assert_eq!(report.payloads[1].role, "code_signature");
        assert_eq!(report.deferred_commands[0].command, 0x77);
        assert_eq!(report.deferred_commands[0].bytes_hex, "7700000008000000");
        assert!(
            report
                .unresolved_requirements
                .iter()
                .any(|r| r.contains("fixup"))
        );
        assert!(
            report
                .unresolved_requirements
                .iter()
                .any(|r| r.contains("signing"))
        );
        assert!(!report.execution_supported);
    }
    #[test]
    fn resolves_lc_main_through_vm_layout_instead_of_treating_it_as_file_offset() {
        let mut items = commands();
        items[3] = main_command(0x4004);
        items.push(segment(b"__CODE", BASE + 0x4000, 0x1000, 0x1200, 0x100, 5));
        let mut data = image(items);
        data.resize(0x1300, 0);
        let result = plan(&data).unwrap();
        assert_eq!(result.entry.as_ref().unwrap().image_offset, 0x4004);
        assert_eq!(result.entry.as_ref().unwrap().guest_address, BASE + 0x4004);
        assert_eq!(result.entry.as_ref().unwrap().file_offset, 0x1204);
        let mut items = commands();
        u64_put(&mut items[1], 40, 0x1000);
        u64_put(&mut items[1], 48, 0x100);
        assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
        let mut items = commands();
        items[1][8..24].fill(0);
        items[1][8..14].copy_from_slice(b"__CODE");
        assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
    }
    #[test]
    fn preserves_legacy_dyld_ranges_and_rejects_image_identity_commands() {
        let mut items = commands();
        let mut command = vec![0; 48];
        u32_put(&mut command, 0, 0x80000022);
        u32_put(&mut command, 4, 48);
        for index in 0..5 {
            u32_put(&mut command, 8 + index * 8, 0x1100 + index as u32 * 8);
            u32_put(&mut command, 12 + index * 8, 8);
        }
        items.push(command);
        let result = plan(&image(items)).unwrap();
        assert_eq!(result.payloads.len(), 5);
        assert_eq!(
            result
                .payloads
                .iter()
                .map(|p| p.role.as_str())
                .collect::<Vec<_>>(),
            ["rebase", "bind", "weak_bind", "lazy_bind", "export"]
        );
        let mut items = commands();
        items.push(string_command(0xd, 24, b"this-is-an-executable"));
        assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
    }
    #[test]
    fn rejects_unknown_required_commands_and_unsupported_cpu_or_entry_conventions() {
        let mut items = commands();
        items.push(vec![0x77, 0, 0, 0x80, 8, 0, 0, 0]);
        assert_eq!(
            plan(&image(items)).unwrap_err(),
            PlanError::UnsupportedRequiredCommand(0x80000077)
        );
        let mut data = image(commands());
        u32_put(&mut data, 4, 0x01000007);
        assert!(matches!(plan(&data), Err(PlanError::UnsupportedCpu { .. })));
        u32_put(&mut data, 4, 0x0100000c);
        u32_put(&mut data, 8, 1);
        assert!(matches!(plan(&data), Err(PlanError::UnsupportedCpu { .. })));
        let mut items = commands();
        items.pop();
        assert_eq!(
            plan(&image(items)).unwrap_err(),
            PlanError::UnsupportedEntryConvention
        );
        let mut data = image(commands());
        u32_put(&mut data, 12, 6);
        assert_eq!(plan(&data).unwrap_err(), PlanError::UnsupportedFileType(6));
        assert_eq!(
            plan(&[0xca, 0xfe, 0xba, 0xbe]).unwrap_err(),
            PlanError::UnsupportedFormat
        );
    }
    #[test]
    fn rejects_overlapping_extents_overflow_and_invalid_protections() {
        for (offset, value) in [(24, BASE + 0x80), (40, 0x1080)] {
            let mut items = commands();
            u64_put(&mut items[2], offset, value);
            assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
        }
        let mut items = commands();
        u64_put(&mut items[1], 24, u64::MAX - 4);
        assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
        for (offset, value) in [(56, 8), (60, 7)] {
            let mut items = commands();
            u32_put(&mut items[1], offset, value);
            assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
        }
        let mut items = commands();
        u64_put(&mut items[1], 48, 0x2001);
        assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
        let mut items = commands();
        u32_put(&mut items[1], 68, 1);
        assert!(matches!(
            plan(&image(items)),
            Err(PlanError::UnsupportedSegmentLayout { .. })
        ));
    }
    #[test]
    fn rejects_ambiguous_nonexecutable_unaligned_and_zerofill_entries() {
        let mut items = commands();
        items.push(main_command(0x1004));
        assert!(matches!(plan(&image(items)), Err(PlanError::Malformed(_))));
        for offset in [0x2004, 0x1005, 0x1100, 0x1200, 0x10ff] {
            let mut items = commands();
            items[3] = main_command(offset);
            assert!(
                matches!(plan(&image(items)), Err(PlanError::Malformed(_))),
                "entry offset {offset:#x}"
            );
        }
    }
    #[test]
    fn rejects_truncated_commands_bad_strings_and_unmapped_payloads() {
        let mut data = image(commands());
        u32_put(&mut data, 20, 248);
        assert!(plan(&data).is_err());
        let mut items = commands();
        let mut bad = string_command(0xc, 24, b"lib.dylib");
        u32_put(&mut bad, 8, 8);
        items.push(bad);
        assert!(plan(&image(items)).is_err());
        let mut items = commands();
        let mut bad = string_command(0xc, 24, b"lib.dylib");
        bad[24..].fill(b'x');
        items.push(bad);
        assert!(plan(&image(items)).is_err());
        let mut items = commands();
        let mut command = vec![0; 16];
        u32_put(&mut command, 0, 0x80000034);
        u32_put(&mut command, 4, 16);
        u32_put(&mut command, 8, 0x1200);
        u32_put(&mut command, 12, 8);
        items.push(command);
        assert!(plan(&image(items)).is_err());
    }
    #[test]
    fn validates_sections_against_exact_segment_file_to_vm_mapping() {
        let mut items = commands();
        items[1].resize(152, 0);
        u32_put(&mut items[1], 4, 152);
        u32_put(&mut items[1], 64, 1);
        items[1][72..78].copy_from_slice(b"__text");
        items[1][88..94].copy_from_slice(b"__TEXT");
        u64_put(&mut items[1], 104, BASE + 0x1004);
        u64_put(&mut items[1], 112, 4);
        u32_put(&mut items[1], 120, 0x1004);
        assert!(plan(&image(items.clone())).is_ok());
        u32_put(&mut items[1], 124, 3);
        assert!(plan(&image(items.clone())).is_err());
        u32_put(&mut items[1], 124, 64);
        assert!(plan(&image(items.clone())).is_err());
        u32_put(&mut items[1], 124, 2);
        assert!(plan(&image(items.clone())).is_ok());
        u32_put(&mut items[1], 120, 0x1008);
        assert!(plan(&image(items.clone())).is_err());
        u32_put(&mut items[1], 136, 1);
        assert!(plan(&image(items.clone())).is_ok());
        u64_put(&mut items[1], 104, BASE + 0x1100);
        assert!(plan(&image(items)).is_ok());
    }
    #[test]
    fn zero_fill_sections_may_start_inside_segment_file_padding() {
        let mut items = commands();
        items[2].resize(152, 0);
        u32_put(&mut items[2], 4, 152);
        u32_put(&mut items[2], 64, 1);
        items[2][72..77].copy_from_slice(b"__bss");
        items[2][88..94].copy_from_slice(b"__DATA");
        u64_put(&mut items[2], 104, BASE + 0x2008);
        u64_put(&mut items[2], 112, 0x200);
        // S_ZEROFILL has no section file extent. The segment still maps
        // fileoff..filesize verbatim, then allocates its remaining VM tail.
        u32_put(&mut items[2], 120, u32::MAX);
        u32_put(&mut items[2], 136, macho::S_ZEROFILL);
        let mut input = image(items.clone());
        input[0x1108] = 0xa5;
        let result = plan(&input).unwrap();
        assert_eq!(result.segments[2].file.offset, 0x1100);
        assert_eq!(result.segments[2].file.bytes, 0x100);
        assert_eq!(result.segments[2].zero_fill.address, BASE + 0x2100);
        assert_eq!(result.segments[2].zero_fill.bytes, 0xf00);
        // Section bounds remain constrained by their segment, including BSS.
        u64_put(&mut items[2], 112, 0x1000);
        assert!(plan(&image(items)).is_err());
    }
}
