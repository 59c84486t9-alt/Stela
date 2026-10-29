//! The validated, unslid segment mappings and pending loader work of one image.
use object::{
    LittleEndian, macho,
    read::macho::{LoadCommandData, LoadCommandVariant, MachHeader, Segment},
};
use serde::Serialize;
use std::{collections::BTreeSet, error::Error, fmt};
use stela_formats::sha256;

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

pub use super::thread_state::Arm64UnixThread;

#[derive(Debug, Clone, Serialize)]
pub struct DynamicLinkerPlan {
    /// `entry` remains absent: LC_UNIXTHREAD is not an LC_MAIN C-call entry.
    pub image: LoadPlan,
    /// Serialized SP is not the process stack: the loader supplies validated KernelArgs.
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

/// Plan a thin arm64/arm64e dynamic linker with one thread-entry command.
/// Nothing is mapped, rebased or run.
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

fn plan_kind(data: &[u8], expected_type: u32) -> Result<PlannedImage> {
    let endian = LittleEndian;
    let header = header(data, expected_type)?;
    let cpu_type = header.cputype(endian);
    let cpu_subtype = header.cpusubtype(endian);
    let commands = Commands::read(data, header, expected_type)?;
    let entry = commands.entry_point(header, expected_type)?;
    for item in &commands.payloads {
        if item.file.bytes != 0
            && !commands.segments.iter().any(|s| {
                item.file.offset >= s.file.offset
                    && item.file.offset + item.file.bytes <= s.file.offset + s.file.bytes
            })
        {
            return Err(invalid(
                "loader payload is not contained in a file-backed segment",
            ));
        }
    }
    let unresolved_requirements = commands.unresolved_requirements(cpu_subtype);
    let Commands {
        segments,
        dependencies,
        dylib_identity,
        dylinker,
        rpaths,
        payloads,
        deferred_commands,
        thread,
        install_name,
        ..
    } = commands;
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

/// The thin arm64 or arm64e header of a Mach-O of `expected_type`.
fn header(data: &[u8], expected_type: u32) -> Result<&macho::MachHeader64<LittleEndian>> {
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
    Ok(header)
}

/// What an image's load commands declare.
#[derive(Default)]
struct Commands {
    segments: Vec<SegmentPlan>,
    dependencies: Vec<Dependency>,
    dylib_identity: Option<Dependency>,
    dylinker: Option<String>,
    rpaths: Vec<String>,
    payloads: Vec<Payload>,
    deferred_commands: Vec<OpaqueCommand>,
    /// LC_MAIN's entry offset and stack size.
    main: Option<(u64, u64)>,
    thread: Option<Arm64UnixThread>,
    install_name: Option<String>,
    singleton_commands: BTreeSet<u32>,
}

impl Commands {
    fn read(
        data: &[u8],
        header: &macho::MachHeader64<LittleEndian>,
        expected_type: u32,
    ) -> Result<Self> {
        let endian = LittleEndian;
        let mut load_commands = header.load_commands(endian, data, 0)?;
        let mut commands = Self::default();
        let mut consumed = 0u64;
        while let Some(command) = load_commands.next()? {
            if !command.cmdsize().is_multiple_of(8) {
                return Err(invalid("64-bit load command is not 8-byte aligned"));
            }
            consumed += u64::from(command.cmdsize());
            commands.command(data, command, expected_type)?;
        }
        if consumed != u64::from(header.sizeofcmds(endian)) {
            return Err(invalid("load-command count disagrees with declared size"));
        }
        Ok(commands)
    }

    fn command(
        &mut self,
        data: &[u8],
        command: LoadCommandData<'_, LittleEndian>,
        expected_type: u32,
    ) -> Result<()> {
        let endian = LittleEndian;
        let id = command.cmd();
        match command.variant()? {
            LoadCommandVariant::Segment64(segment, section_data) => {
                let planned = segment_plan(data, segment, section_data, &self.segments)?;
                self.segments.push(planned);
            }
            LoadCommandVariant::EntryPoint(main) => {
                if expected_type == macho::MH_DYLINKER {
                    return Err(invalid("MH_DYLINKER cannot declare LC_MAIN"));
                }
                if expected_type != macho::MH_EXECUTE {
                    return Err(invalid("MH_DYLIB cannot declare LC_MAIN"));
                }
                if self.main.is_some() || command.cmdsize() != 24 {
                    return Err(invalid("duplicate or incorrectly sized LC_MAIN"));
                }
                self.main = Some((main.entryoff.get(endian), main.stacksize.get(endian)));
            }
            LoadCommandVariant::Thread(_, _) => {
                if expected_type != macho::MH_DYLINKER {
                    return Err(PlanError::UnsupportedEntryConvention);
                }
                if id != macho::LC_UNIXTHREAD {
                    return Err(invalid("MH_DYLINKER requires LC_UNIXTHREAD, not LC_THREAD"));
                }
                if self.thread.is_some() {
                    return Err(invalid("duplicate LC_UNIXTHREAD"));
                }
                self.thread = Some(
                    super::thread_state::unix_thread(command.raw_data())
                        .map_err(|error| invalid(error.to_string()))?,
                );
            }
            LoadCommandVariant::IdDylib(dylib) => {
                if expected_type != macho::MH_DYLIB {
                    return Err(invalid("MH_EXECUTE cannot declare LC_ID_DYLIB"));
                }
                if self.dylib_identity.is_some() {
                    return Err(invalid("duplicate LC_ID_DYLIB"));
                }
                self.dylib_identity = Some(dependency(command, &dylib.dylib)?);
            }
            LoadCommandVariant::Dylib(dylib) => {
                self.dependencies.push(dependency(command, &dylib.dylib)?);
            }
            LoadCommandVariant::LoadDylinker(linker) => {
                if expected_type == macho::MH_DYLINKER {
                    return Err(invalid("MH_DYLINKER cannot declare LC_LOAD_DYLINKER"));
                }
                if expected_type != macho::MH_EXECUTE {
                    return Err(invalid("MH_DYLIB cannot declare LC_LOAD_DYLINKER"));
                }
                if self.dylinker.is_some() {
                    return Err(invalid("duplicate LC_LOAD_DYLINKER"));
                }
                self.dylinker = Some(command_string(command, linker.name, 12)?);
            }
            LoadCommandVariant::IdDylinker(linker) if expected_type == macho::MH_DYLINKER => {
                if self.install_name.is_some() || command.cmdsize() > 4112 {
                    return Err(invalid("duplicate or oversized LC_ID_DYLINKER"));
                }
                let name = command_string(command, linker.name, 12)?;
                if name.len() > 4096 {
                    return Err(invalid("LC_ID_DYLINKER name exceeds 4096 bytes"));
                }
                self.install_name = Some(name);
            }
            LoadCommandVariant::Rpath(path) => {
                self.rpaths.push(command_string(command, path.path, 12)?);
            }
            LoadCommandVariant::LinkeditData(info) => {
                if command.cmdsize() != 16 || !self.singleton_commands.insert(id) {
                    return Err(invalid("duplicate or incorrectly sized linkedit payload"));
                }
                let role = match id {
                    macho::LC_CODE_SIGNATURE => "code_signature",
                    macho::LC_DYLD_CHAINED_FIXUPS => "chained_fixups",
                    macho::LC_DYLD_EXPORTS_TRIE => "exports_trie",
                    macho::LC_FUNCTION_STARTS => "function_starts",
                    _ => "linkedit_metadata",
                };
                self.payloads.push(payload(
                    data,
                    id,
                    role,
                    info.dataoff.get(endian),
                    info.datasize.get(endian),
                )?);
            }
            LoadCommandVariant::DyldInfo(info) => {
                if command.cmdsize() != 48 || !self.singleton_commands.insert(macho::LC_DYLD_INFO) {
                    return Err(invalid("duplicate or incorrectly sized dyld info"));
                }
                for (role, offset, bytes) in [
                    ("rebase", info.rebase_off, info.rebase_size),
                    ("bind", info.bind_off, info.bind_size),
                    ("weak_bind", info.weak_bind_off, info.weak_bind_size),
                    ("lazy_bind", info.lazy_bind_off, info.lazy_bind_size),
                    ("export", info.export_off, info.export_size),
                ] {
                    self.payloads.push(payload(
                        data,
                        id,
                        role,
                        offset.get(endian),
                        bytes.get(endian),
                    )?);
                }
            }
            LoadCommandVariant::EncryptionInfo64(info) => {
                if command.cmdsize() != 24 || !self.singleton_commands.insert(id) {
                    return Err(invalid("duplicate or incorrectly sized encryption info"));
                }
                self.payloads.push(payload(
                    data,
                    id,
                    "encrypted_range",
                    info.cryptoff.get(endian),
                    info.cryptsize.get(endian),
                )?);
                self.deferred_commands.push(OpaqueCommand {
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
                self.deferred_commands.push(OpaqueCommand {
                    command: id,
                    bytes_hex: hex::encode(command.raw_data()),
                });
            }
        }
        Ok(())
    }

    /// The executable's LC_MAIN entry, after checking that `__TEXT` holds the
    /// header and that a library or dynamic linker declares its identity.
    fn entry_point(
        &self,
        header: &macho::MachHeader64<LittleEndian>,
        expected_type: u32,
    ) -> Result<Option<EntryPoint>> {
        // Apple dyld validates __TEXT.fileoff == 0 and resolves LC_MAIN as
        // preferredLoadAddress() + entryoff (MachOAnalyzer::validMain). A raw file
        // lookup is wrong if an executable segment's VM/file layout has a gap.
        let text_segments: Vec<_> = self
            .segments
            .iter()
            .filter(|s| s.name == "__TEXT")
            .collect();
        if text_segments.len() != 1 {
            return Err(invalid("executable requires exactly one __TEXT segment"));
        }
        let text_segment = text_segments[0];
        if text_segment.file.offset != 0
            || text_segment.file.bytes < 32 + u64::from(header.sizeofcmds(LittleEndian))
        {
            return Err(invalid(
                "__TEXT must contain the header and load commands at file offset zero",
            ));
        }
        if expected_type == macho::MH_EXECUTE {
            self.main_entry(text_segment).map(Some)
        } else if expected_type == macho::MH_DYLIB {
            if self.dylib_identity.is_none() {
                return Err(invalid("MH_DYLIB requires LC_ID_DYLIB"));
            }
            Ok(None)
        } else {
            self.check_thread_entry()?;
            Ok(None)
        }
    }

    fn main_entry(&self, text_segment: &SegmentPlan) -> Result<EntryPoint> {
        let (image_offset, stack_size) = self.main.ok_or(PlanError::UnsupportedEntryConvention)?;
        let guest_address =
            checked_end(text_segment.guest.address, image_offset, "LC_MAIN address")?;
        let mappings: Vec<_> = self
            .segments
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
        Ok(EntryPoint {
            image_offset,
            file_offset,
            guest_address,
            stack_size,
        })
    }

    /// A dynamic linker's thread entry names one readable, executable and
    /// file-backed instruction.
    fn check_thread_entry(&self) -> Result<()> {
        let descriptor = self
            .thread
            .as_ref()
            .ok_or_else(|| invalid("MH_DYLINKER requires LC_UNIXTHREAD"))?;
        if self.install_name.is_none() {
            return Err(invalid("MH_DYLINKER requires LC_ID_DYLINKER"));
        }
        if !descriptor.pc.is_multiple_of(4) {
            return Err(invalid("LC_UNIXTHREAD PC is not instruction aligned"));
        }
        let required = macho::VM_PROT_READ | macho::VM_PROT_EXECUTE;
        let mappings = self
            .segments
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
        Ok(())
    }

    /// What loading the image needs that the plan leaves to later stages.
    fn unresolved_requirements(&self, cpu_subtype: u32) -> Vec<String> {
        let mut unresolved = vec![
            "native instruction translation and control-flow dispatch".into(),
            "guest virtual memory, page-size policy and protection enforcement".into(),
            "Apple process/thread ABI, stack, exceptions and system calls".into(),
        ];
        if self.dylinker.is_some() || !self.dependencies.is_empty() || !self.rpaths.is_empty() {
            unresolved
                .push("dyld/shared-cache loading, dependency resolution and initializers".into());
        }
        let payloads = &self.payloads;
        if payloads.iter().any(|p| {
            matches!(
                p.role.as_str(),
                "chained_fixups" | "rebase" | "bind" | "weak_bind" | "lazy_bind"
            )
        }) {
            unresolved.push(
                "rebase/bind/chained-fixup interpretation, including authenticated pointers".into(),
            );
        }
        if payloads.iter().any(|p| p.role == "code_signature") {
            unresolved.push("code-signature validation and platform signing policy".into());
        }
        if payloads.iter().any(|p| p.role == "encrypted_range") {
            unresolved.push("encrypted-input handling and cryptid policy".into());
        }
        if !self.deferred_commands.is_empty() {
            unresolved.push("semantics of preserved deferred load commands".into());
        }
        if cpu_subtype & !macho::CPU_SUBTYPE_MASK == 2 {
            unresolved
                .push("arm64e pointer-authentication ABI and CPU-subtype capability policy".into());
        }
        unresolved
    }
}

fn dependency(
    command: LoadCommandData<'_, LittleEndian>,
    dylib: &macho::Dylib<LittleEndian>,
) -> Result<Dependency> {
    let endian = LittleEndian;
    Ok(Dependency {
        command: command.cmd(),
        name: command_string(command, dylib.name, 24)?,
        timestamp: dylib.timestamp.get(endian),
        current_version: dylib.current_version.get(endian),
        compatibility_version: dylib.compatibility_version.get(endian),
    })
}

/// One LC_SEGMENT_64, checked against its sections and the segments before it.
fn segment_plan(
    data: &[u8],
    segment: &macho::SegmentCommand64<LittleEndian>,
    section_data: &[u8],
    prior_segments: &[SegmentPlan],
) -> Result<SegmentPlan> {
    let endian = LittleEndian;
    let name = text(segment.name())?;
    let vmaddr = segment.vmaddr.get(endian);
    let vmsize = segment.vmsize.get(endian);
    let fileoff = segment.fileoff.get(endian);
    let filesize = segment.filesize.get(endian);
    let maxprot = segment.maxprot.get(endian);
    let initprot = segment.initprot.get(endian);
    let flags = segment.flags.get(endian);
    if flags & (macho::SG_HIGHVM | macho::SG_FVMLIB | macho::SG_PROTECTED_VERSION_1) != 0 {
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
    for prior in prior_segments {
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
        if bytes == 0 {
            continue;
        }
        if section_ranges
            .iter()
            .any(|&(start, len)| overlaps(start, len, address, bytes))
        {
            return Err(invalid("overlapping section VM extents"));
        }
        section_ranges.push((address, bytes));
        // Segment commands define the initial mapping. Apple ld can start a
        // zero-fill section inside the final padded file page; it has no
        // independent file extent. Do not reject that layout or overwrite
        // mapped file bytes.
        if !zerofill {
            let offset = u64::from(section.offset.get(endian));
            if offset < fileoff
                || checked_end(offset, bytes, "section file")? > fileend
                || address - vmaddr != offset - fileoff
            {
                return Err(invalid("section file/VM mapping disagrees with segment"));
            }
        }
    }
    Ok(SegmentPlan {
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
    })
}

#[cfg(test)]
mod tests;
