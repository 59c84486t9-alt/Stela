//! Bounded lookup in unchanged original Apple cache images, never extracted dylibs.
//!
//! dyld fd8d0c4d52320ebf64db34f3cb280310d905c5ae MachOLoaded.cpp::getExportsTrie
//! uses __LINKEDIT.vmaddr + (dataoff - __LINKEDIT.fileoff). FunctionStarts.cpp
//! specifies positive ULEB deltas from __TEXT, a zero terminator and zero padding.
//! Unsupported terminal semantics remain visible; no resolver or PAC operation runs.
use super::{
    exports::{self, RawTerminal},
    shared_cache::{extent, file_identity, hash_file, same_file},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

const MAX_METADATA: u64 = 64 * 1024 * 1024;
const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;
const MAX_CODE: u64 = 1024 * 1024;
const PIN: &str = "fd8d0c4d52320ebf64db34f3cb280310d905c5ae";
fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing unsigned {key}"))
}
fn word(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .context("truncated cache/Mach-O word")?
            .try_into()?,
    ))
}
fn wide(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated cache/Mach-O word")?
            .try_into()?,
    ))
}
fn uuid(b: &[u8]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
fn fixed_string(b: &[u8]) -> Result<String> {
    let n = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    ensure!(b[n..].iter().all(|x| *x == 0), "nonzero fixed-name padding");
    Ok(std::str::from_utf8(&b[..n])?.to_owned())
}
fn read_at(f: &mut File, length: u64, offset: u64, size: u64) -> Result<Vec<u8>> {
    extent(offset, size, length)?;
    ensure!(size <= MAX_METADATA, "read exceeds metadata budget");
    let mut b = vec![0; usize::try_from(size)?];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut b)?;
    Ok(b)
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceSpan {
    pub source_cache_index: usize,
    pub source_cache_path: PathBuf,
    pub source_sha256: String,
    pub cache_uuid: String,
    pub file_offset: u64,
    pub preferred_address: u64,
    pub bytes: u64,
}
#[derive(Clone)]
struct Mapping {
    source: usize,
    address: u64,
    size: u64,
    offset: u64,
    protection: u32,
}
struct Source {
    path: PathBuf,
    file: File,
    identity: Metadata,
    receipt: Value,
    header: Vec<u8>,
    hashed: bool,
}
struct Reader {
    sources: Vec<Source>,
    mappings: Vec<Mapping>,
    bytes_read: u64,
    preferred: u64,
    slide: u64,
}
impl Reader {
    fn open(set: &Value, cache_base: u64) -> Result<Self> {
        ensure!(
            set["kind"] == "dyld_shared_cache_set_manifest",
            "expected original cache-set manifest"
        );
        let files = set["files"]
            .as_array()
            .context("missing original cache files")?;
        ensure!(
            !files.is_empty() && files.len() <= 256,
            "cache file count exceeds bounded profile"
        );
        let mut sources = Vec::new();
        let mut mappings = Vec::new();
        let mut total = 0u64;
        let mut bytes_read = 0u64;
        let mut paths = BTreeSet::new();
        let mut uuids = BTreeSet::new();
        for (index, v) in files.iter().enumerate() {
            ensure!(
                number(v, "index")? == index as u64,
                "noncanonical cache indices"
            );
            let path = PathBuf::from(v["path"].as_str().context("missing cache path")?);
            ensure!(paths.insert(path.clone()), "duplicate cache source path");
            let before = path.symlink_metadata()?;
            ensure!(
                before.file_type().is_file() && !before.file_type().is_symlink(),
                "cache source must be a regular nonsymlink file"
            );
            ensure!(
                before.len() == number(v, "file_bytes")? && before.len() <= 32 * 1024 * 1024 * 1024,
                "cache source size differs or exceeds budget"
            );
            ensure!(
                file_identity(&before) == v["source_identity"],
                "cache source identity differs from manifest"
            );
            total = total
                .checked_add(before.len())
                .context("cache size overflow")?;
            ensure!(
                total <= 64 * 1024 * 1024 * 1024,
                "cache set exceeds byte budget"
            );
            let mut file = File::open(&path)?;
            ensure!(
                same_file(&before, &file.metadata()?),
                "cache source changed before opening"
            );
            let prefix = read_at(&mut file, before.len(), 0, 24)?;
            let header_bytes = u64::from(word(&prefix, 16)?);
            ensure!(
                (460..=4096).contains(&header_bytes) && header_bytes.is_multiple_of(8),
                "unsupported modern cache header"
            );
            let header = read_at(&mut file, before.len(), 0, header_bytes)?;
            ensure!(
                header.starts_with(b"dyld_v1  arm64e\0") && header[15] == 0,
                "original cache export profile requires arm64e"
            );
            let id = uuid(&header[88..104]);
            ensure!(
                v["header"]["uuid"] == id
                    && v["header"]["header_sha256"] == stela_core::sha256(&header),
                "cache header/UUID identity differs from manifest"
            );
            ensure!(uuids.insert(id), "duplicate cache UUID");
            ensure!(
                header[400..416].iter().all(|b| *b == 0),
                "separate symbols-cache profile unsupported"
            );
            let count = u64::from(word(&header, 20)?);
            ensure!(count > 0 && count <= 4096, "invalid mapping count");
            let raw = read_at(&mut file, before.len(), header_bytes, count * 32)?;
            ensure!(
                wide(&raw, 16)? == 0 && wide(&raw, 8)? >= header_bytes + count * 32,
                "first cache mapping must cover original header and mapping table"
            );
            ensure!(
                index == 0 || word(&header, 396)? == 0,
                "nested subcache references are unsupported"
            );
            bytes_read = bytes_read
                .checked_add(24 + header_bytes + count * 32)
                .context("metadata budget overflow")?;
            let given = v["mappings"].as_array().context("missing cache mappings")?;
            ensure!(
                given.len() == count as usize,
                "mapping count differs from manifest"
            );
            let mut physical = Vec::new();
            for (b, g) in raw.as_chunks::<32>().0.iter().zip(given) {
                let address = wide(b, 0)?;
                let size = wide(b, 8)?;
                let offset = wide(b, 16)?;
                let max = word(b, 24)?;
                let protection = word(b, 28)?;
                ensure!(
                    size > 0 && max & !7 == 0 && protection & !max == 0,
                    "invalid cache mapping protection/size"
                );
                address
                    .checked_add(size)
                    .context("cache VM extent overflow")?;
                extent(offset, size, before.len())?;
                ensure!(
                    (address, size, offset, u64::from(max), u64::from(protection))
                        == (
                            number(g, "address")?,
                            number(g, "size")?,
                            number(g, "file_offset")?,
                            number(g, "max_protection")?,
                            number(g, "initial_protection")?
                        ),
                    "mapping differs from original source table"
                );
                physical.push((offset, size));
                mappings.push(Mapping {
                    source: index,
                    address,
                    size,
                    offset,
                    protection,
                });
            }
            physical.sort_unstable();
            for p in physical.windows(2) {
                ensure!(
                    p[0].0 + p[0].1 <= p[1].0,
                    "overlapping source file mappings"
                );
            }
            sources.push(Source {
                path,
                file,
                identity: before,
                receipt: v.clone(),
                header,
                hashed: false,
            });
        }
        ensure!(bytes_read <= MAX_METADATA, "cache metadata exceeds budget");
        mappings.sort_by_key(|m| m.address);
        for p in mappings.windows(2) {
            ensure!(
                p[0].address + p[0].size <= p[1].address,
                "overlapping cache VM mappings"
            );
        }
        let preferred = wide(&sources[0].header, 224)?;
        let region = wide(&sources[0].header, 232)?;
        let end = preferred
            .checked_add(region)
            .context("shared region overflow")?;
        ensure!(
            region > 0 && mappings[0].address == preferred,
            "invalid shared-region base/size"
        );
        for m in &mappings {
            ensure!(
                m.address >= preferred && m.address + m.size <= end,
                "mapping outside original shared region"
            );
        }
        ensure!(
            cache_base.is_multiple_of(16384) && preferred.is_multiple_of(16384),
            "cache base must be 16KiB aligned"
        );
        let slide = cache_base
            .checked_sub(preferred)
            .context("negative cache slides unsupported")?;
        ensure!(
            slide <= wide(&sources[0].header, 240)?,
            "cache slide exceeds declared maximum"
        );
        end.checked_add(slide)
            .context("slid shared region overflow")?;
        let mut r = Self {
            sources,
            mappings,
            bytes_read,
            preferred,
            slide,
        };
        r.verify_references()?;
        Ok(r)
    }
    fn file_read(&mut self, index: usize, offset: u64, size: u64) -> Result<Vec<u8>> {
        self.bytes_read = self
            .bytes_read
            .checked_add(size)
            .context("metadata budget overflow")?;
        ensure!(
            self.bytes_read <= MAX_METADATA,
            "cache metadata/code reads exceed budget"
        );
        let s = &mut self.sources[index];
        if !s.hashed {
            ensure!(
                s.receipt["source_sha256"] == hash_file(&mut s.file)?,
                "cache source SHA256 differs from manifest"
            );
            s.hashed = true;
        }
        read_at(&mut s.file, s.identity.len(), offset, size)
    }
    fn verify_references(&mut self) -> Result<()> {
        let count = u64::from(word(&self.sources[0].header, 396)?);
        ensure!(
            count + 1 == self.sources.len() as u64,
            "missing/extra declared cache sibling"
        );
        // The selected modern profile has v2 suffix records (header cacheSubType available).
        let offset = u64::from(word(&self.sources[0].header, 392)?);
        let refs = self.file_read(0, offset, count * 56)?;
        let main = &self.sources[0].path;
        for (index, b) in refs.as_chunks::<56>().0.iter().enumerate() {
            let suffix = fixed_string(&b[24..56])?;
            ensure!(
                suffix.starts_with('.') && !suffix.contains(['/', '\\']) && !suffix.contains(".."),
                "unsafe cache suffix"
            );
            let mut name = main
                .file_name()
                .context("cache source has no filename")?
                .to_os_string();
            name.push(&suffix);
            let s = &self.sources[index + 1];
            ensure!(
                s.path
                    == main
                        .parent()
                        .context("cache source has no parent")?
                        .join(name)
                    && s.receipt["declared_file_suffix"] == suffix,
                "cache sibling path differs from original reference"
            );
            ensure!(
                uuid(&b[..16]) == uuid(&s.header[88..104]),
                "cache sibling UUID differs from original reference"
            );
            let first = self
                .mappings
                .iter()
                .filter(|m| m.source == index + 1)
                .map(|m| m.address)
                .min()
                .context("sibling has no mapping")?;
            ensure!(
                self.preferred.checked_add(wide(b, 16)?) == Some(first),
                "cache sibling VM offset differs from original reference"
            );
        }
        Ok(())
    }
    fn image_address(&mut self, path: &str) -> Result<u64> {
        let offset = u64::from(word(&self.sources[0].header, 448)?);
        let count = u64::from(word(&self.sources[0].header, 452)?);
        ensure!(
            count > 0 && count <= 1_000_000,
            "invalid original cache image count"
        );
        let table = self.file_read(0, offset, count * 32)?;
        let mut found = None;
        for b in table.as_chunks::<32>().0 {
            let at = u64::from(word(b, 24)?);
            let n = self.sources[0].identity.len().saturating_sub(at).min(4097);
            let bytes = self.file_read(0, at, n)?;
            let end = bytes
                .iter()
                .position(|b| *b == 0)
                .context("unterminated original image path")?;
            ensure!(end <= 4096, "excessive original image path");
            let name = std::str::from_utf8(&bytes[..end])?;
            if name == path {
                ensure!(found.is_none(), "duplicate original image path");
                found = Some(wide(b, 0)?);
            }
        }
        found.context("image path absent from original cache image table")
    }
    fn vm(&mut self, address: u64, size: u64) -> Result<(Vec<u8>, Vec<SourceSpan>)> {
        ensure!(
            size <= MAX_PAYLOAD,
            "cache VM read exceeds bounded payload limit"
        );
        address
            .checked_add(size)
            .context("cache read VM overflow")?;
        let mut result = Vec::with_capacity(usize::try_from(size)?);
        let mut spans = Vec::new();
        let mut at = address;
        while (result.len() as u64) < size {
            let m = self
                .mappings
                .iter()
                .find(|m| m.address <= at && at < m.address + m.size)
                .context("cache VM read reaches unmapped gap")?
                .clone();
            ensure!(m.protection & 1 != 0, "cache VM source is not readable");
            let n = (size - result.len() as u64).min(m.address + m.size - at);
            let offset = m.offset + (at - m.address);
            result.extend(self.file_read(m.source, offset, n)?);
            let s = &self.sources[m.source];
            spans.push(SourceSpan {
                source_cache_index: m.source,
                source_cache_path: s.path.clone(),
                source_sha256: s.receipt["source_sha256"]
                    .as_str()
                    .context("missing cache SHA256")?
                    .into(),
                cache_uuid: uuid(&s.header[88..104]),
                file_offset: offset,
                preferred_address: at,
                bytes: n,
            });
            at += n;
        }
        Ok((result, spans))
    }
    fn finish(&mut self) -> Result<Vec<Value>> {
        let mut receipts = Vec::new();
        for s in &mut self.sources {
            ensure!(
                same_file(&s.identity, &s.file.metadata()?)
                    && same_file(&s.identity, &s.path.symlink_metadata()?),
                "cache source changed during inspection"
            );
            if s.hashed {
                ensure!(
                    s.receipt["source_sha256"] == hash_file(&mut s.file)?,
                    "cache source bytes changed during inspection"
                );
                receipts.push(json!({"path":s.path,"source_sha256":s.receipt["source_sha256"],"source_identity":file_identity(&s.identity),"uuid":uuid(&s.header[88..104])}));
            }
            let after_path = s.path.symlink_metadata()?;
            ensure!(
                after_path.file_type().is_file()
                    && !after_path.file_type().is_symlink()
                    && same_file(&s.identity, &s.file.metadata()?)
                    && same_file(&s.identity, &after_path),
                "cache source changed during final identity/hash verification"
            );
        }
        Ok(receipts)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageRange {
    pub name: String,
    pub address: u64,
    pub bytes: u64,
    pub file_offset: u64,
    pub file_bytes: u64,
    pub max_protection: u32,
    pub initial_protection: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct CodeRange {
    pub segment: String,
    pub section: String,
    pub address: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct CachedExport {
    pub name: String,
    pub flags: u64,
    pub terminal: RawTerminal,
    pub preferred_address: Option<u64>,
    pub address: Option<u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct FunctionExtent {
    pub name: String,
    pub preferred_address: u64,
    pub address: u64,
    pub bytes: u64,
    pub boundary: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct CodeSnapshot {
    pub extent: FunctionExtent,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub source_spans: Vec<SourceSpan>,
    pub sources: Vec<Value>,
    pub complete_binary_verified: bool,
}
#[derive(Serialize)]
pub struct CachedImage {
    pub kind: &'static str,
    pub source_pin: &'static str,
    pub image_path: String,
    pub image_uuid: String,
    pub header_address: u64,
    pub header_and_commands_sha256: String,
    pub preferred_cache_base: u64,
    pub cache_base: u64,
    pub preferred_base: u64,
    pub load_base: u64,
    pub segments: Vec<ImageRange>,
    pub executable_ranges: Vec<CodeRange>,
    pub exports: Vec<CachedExport>,
    pub function_starts: Vec<u64>,
    pub exports_payload: Value,
    pub function_starts_payload: Value,
    pub sources: Vec<Value>,
    pub complete_binary_verified: bool,
    pub cache_fixups_applied: bool,
    #[serde(skip)]
    reader: Reader,
}
impl CachedImage {
    pub fn lookup(&self, name: &str) -> Result<Option<&CachedExport>> {
        match self.exports.binary_search_by(|e| e.name.as_str().cmp(name)) {
            Ok(index) => {
                let e = &self.exports[index];
                ensure!(
                    e.address.is_some(),
                    "unsupported cache export semantics for {name}: {:?}",
                    e.terminal
                );
                Ok(Some(e))
            }
            Err(_) => Ok(None),
        }
    }
    pub fn function_extent(&self, name: &str) -> Result<FunctionExtent> {
        let e = self.lookup(name)?.context("export not found")?;
        ensure!(
            matches!(e.terminal, RawTerminal::Regular { .. }),
            "absolute export is not a function"
        );
        let start = e
            .preferred_address
            .context("export has no preferred address")?;
        let index = self
            .function_starts
            .binary_search(&start)
            .map_err(|_| anyhow::anyhow!("export is not an exact LC_FUNCTION_STARTS entry"))?;
        let section = self
            .executable_ranges
            .iter()
            .find(|r| r.address <= start && start < r.address + r.bytes)
            .context("function start not inside an executable instruction section")?;
        let section_end = section
            .address
            .checked_add(section.bytes)
            .context("instruction section extent overflow")?;
        let next = self.function_starts.get(index + 1).copied();
        let (end, boundary) = match next {
            Some(n) if n <= section_end => (n, "next_function_start"),
            _ => (section_end, "instruction_section_end"),
        };
        let bytes = end
            .checked_sub(start)
            .context("function boundary reversed")?;
        ensure!(
            bytes > 0 && bytes <= MAX_CODE && bytes.is_multiple_of(4),
            "function extent exceeds aligned bounded code profile"
        );
        Ok(FunctionExtent {
            name: name.into(),
            preferred_address: start,
            address: e.address.context("export has no address")?,
            bytes,
            boundary: boundary.into(),
        })
    }
    pub fn snapshot_function(&mut self, name: &str) -> Result<CodeSnapshot> {
        let extent = self.function_extent(name)?;
        let (bytes, source_spans) = self.reader.vm(extent.preferred_address, extent.bytes)?;
        for span in &source_spans {
            let mapping = self
                .reader
                .mappings
                .iter()
                .find(|m| {
                    m.source == span.source_cache_index
                        && m.address <= span.preferred_address
                        && span.preferred_address < m.address + m.size
                })
                .context("code snapshot source mapping unavailable")?;
            ensure!(
                mapping.protection & 4 != 0,
                "code snapshot source mapping is not executable"
            );
        }
        let sources = self.reader.finish()?;
        Ok(CodeSnapshot {
            sha256: stela_core::sha256(&bytes),
            extent,
            bytes,
            source_spans,
            sources,
            complete_binary_verified: false,
        })
    }
}
#[derive(Clone, Copy)]
struct Payload {
    offset: u64,
    size: u64,
    command: u32,
}
fn payload_vm(link: &ImageRange, p: Payload) -> Result<u64> {
    let relative = p
        .offset
        .checked_sub(link.file_offset)
        .context("linkedit payload precedes declared __LINKEDIT.fileoff")?;
    extent(relative, p.size, link.file_bytes)?;
    extent(relative, p.size, link.bytes)?;
    link.address
        .checked_add(relative)
        .context("linkedit VM address overflow")
}
fn function_starts(bytes: &[u8], base: u64, text_end: u64) -> Result<Vec<u64>> {
    let mut at = 0;
    let mut address = base;
    let mut starts = Vec::new();
    while at < bytes.len() {
        let mut delta = 0u64;
        let mut terminated = false;
        for i in 0..10 {
            let b = *bytes.get(at).context("truncated function-start ULEB")?;
            at += 1;
            let part = u64::from(b & 0x7f);
            ensure!(i != 9 || part <= 1, "function-start ULEB overflow");
            delta |= part << (i * 7);
            if b & 0x80 == 0 {
                ensure!(i == 0 || part != 0, "noncanonical function-start ULEB");
                terminated = true;
                break;
            }
        }
        ensure!(terminated, "function-start ULEB exceeds ten bytes");
        if delta == 0 {
            ensure!(
                bytes[at..].iter().all(|b| *b == 0),
                "nonzero function-start padding"
            );
            return Ok(starts);
        }
        address = address
            .checked_add(delta)
            .context("function-start address overflow")?;
        ensure!(
            address < text_end && address.is_multiple_of(4),
            "function start outside aligned __TEXT extent"
        );
        starts.push(address);
        ensure!(
            starts.len() <= 1_000_000,
            "function-start count exceeds budget"
        );
    }
    bail!("function-start stream lacks zero terminator")
}
/// Inspect one image from a previously acquired original set. `cache_base` is
/// the shared-region load base, not the selected image's __TEXT load address.
pub fn read(set: &Value, image_path: &str, cache_base: u64) -> Result<CachedImage> {
    ensure!(
        image_path.starts_with('/') && image_path.len() <= 4096,
        "invalid original image path"
    );
    let mut reader = Reader::open(set, cache_base)?;
    let address = reader.image_address(image_path)?;
    let records = set["images"]
        .as_array()
        .context("missing set image records")?;
    let matches = records
        .iter()
        .filter(|v| v["path"] == image_path)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "missing/duplicate selected image receipt"
    );
    let record = matches[0];
    ensure!(
        number(record, "address")? == address,
        "selected image address differs from original image table"
    );
    let (header, _) = reader.vm(address, 32)?;
    ensure!(
        word(&header, 0)? == 0xfeedfacf
            && word(&header, 4)? == 0x0100000c
            && word(&header, 8)? & 0xffffff == 2,
        "cached image must be little-endian ARM64e Mach-O"
    );
    ensure!(
        matches!(word(&header, 12)?, 6 | 7),
        "unsupported cached Mach-O file type"
    );
    let count = word(&header, 16)?;
    let size = u64::from(word(&header, 20)?);
    ensure!(
        count > 0 && count <= 4096 && size <= 1024 * 1024 && u64::from(count) * 8 <= size,
        "invalid cached Mach-O command budget"
    );
    let (commands, _) = reader.vm(
        address
            .checked_add(32)
            .context("command address overflow")?,
        size,
    )?;
    let hash = stela_core::sha256(&[header, commands.clone()].concat());
    ensure!(
        record["header_and_commands_sha256"] == hash,
        "cached Mach-O header differs from set manifest"
    );
    let mut segments = Vec::new();
    let mut executable_ranges = Vec::new();
    let mut modern = None;
    let mut legacy = None;
    let mut functions = None;
    let mut image_uuid = None;
    let mut at = 0;
    for _ in 0..count {
        let command = word(&commands, at)?;
        let n = usize::try_from(word(&commands, at + 4)?)?;
        ensure!(
            n >= 8 && n.is_multiple_of(8),
            "invalid cached Mach-O command alignment"
        );
        let end = at.checked_add(n).context("command size overflow")?;
        let b = commands
            .get(at..end)
            .context("command exceeds declared extent")?;
        match command {
            0x19 => {
                ensure!(n >= 72, "truncated cached segment");
                let section_count = usize::try_from(word(b, 64)?)?;
                ensure!(
                    72 + section_count * 80 == n,
                    "invalid segment section extent"
                );
                let s = ImageRange {
                    name: fixed_string(&b[8..24])?,
                    address: wide(b, 24)?,
                    bytes: wide(b, 32)?,
                    file_offset: wide(b, 40)?,
                    file_bytes: wide(b, 48)?,
                    max_protection: word(b, 56)?,
                    initial_protection: word(b, 60)?,
                };
                let send = s
                    .address
                    .checked_add(s.bytes)
                    .context("segment VM overflow")?;
                s.file_offset
                    .checked_add(s.file_bytes)
                    .context("segment file extent overflow")?;
                ensure!(
                    s.bytes > 0
                        && s.file_bytes <= s.bytes
                        && s.max_protection & !7 == 0
                        && s.initial_protection & !s.max_protection == 0,
                    "invalid cached segment bounds/protections"
                );
                for sec in b[72..].as_chunks::<80>().0 {
                    let name = fixed_string(&sec[..16])?;
                    ensure!(
                        fixed_string(&sec[16..32])? == s.name,
                        "section segment name mismatch"
                    );
                    let start = wide(sec, 32)?;
                    let len = wide(sec, 40)?;
                    let secend = start.checked_add(len).context("section VM overflow")?;
                    ensure!(
                        start >= s.address && secend <= send,
                        "section exceeds segment VM"
                    );
                    if word(sec, 64)? & 0xc0000000 != 0 {
                        ensure!(
                            s.initial_protection & 4 != 0,
                            "instruction section in nonexecutable segment"
                        );
                        if len > 0 {
                            executable_ranges.push(CodeRange {
                                segment: s.name.clone(),
                                section: name,
                                address: start,
                                bytes: len,
                            });
                        }
                    }
                }
                segments.push(s);
            }
            0x1b => {
                ensure!(
                    n == 24 && image_uuid.is_none(),
                    "invalid/duplicate cached LC_UUID"
                );
                image_uuid = Some(uuid(&b[8..24]));
            }
            0x80000033 | 0x26 => {
                ensure!(n == 16, "invalid cached linkedit command size");
                let target = if command == 0x26 {
                    &mut functions
                } else {
                    &mut modern
                };
                ensure!(target.is_none(), "duplicate cached linkedit payload");
                *target = Some(Payload {
                    offset: u64::from(word(b, 8)?),
                    size: u64::from(word(b, 12)?),
                    command,
                });
            }
            0x22 | 0x80000022 => {
                ensure!(
                    n == 48 && legacy.is_none(),
                    "invalid/duplicate cached legacy dyld info"
                );
                legacy = Some(Payload {
                    offset: u64::from(word(b, 40)?),
                    size: u64::from(word(b, 44)?),
                    command,
                });
            }
            _ => {}
        }
        at = end;
    }
    ensure!(
        at == commands.len(),
        "cached commands do not fill sizeofcmds"
    );
    let image_uuid = image_uuid.context("cached image lacks UUID")?;
    ensure!(
        record["mach_o"]["uuid"] == image_uuid,
        "cached image UUID differs from receipt"
    );
    executable_ranges.sort_by_key(|r| r.address);
    for pair in executable_ranges.windows(2) {
        ensure!(
            pair[0].address + pair[0].bytes <= pair[1].address,
            "overlapping executable instruction sections"
        );
    }
    let texts = segments
        .iter()
        .filter(|s| s.name == "__TEXT")
        .collect::<Vec<_>>();
    let links = segments
        .iter()
        .filter(|s| s.name == "__LINKEDIT")
        .collect::<Vec<_>>();
    ensure!(
        texts.len() == 1 && links.len() == 1,
        "cached image requires one __TEXT and __LINKEDIT"
    );
    let text = texts[0];
    let link = links[0];
    ensure!(
        text.address == address && text.initial_protection & 5 == 5,
        "cached header is not executable/readable __TEXT base"
    );
    let preferred_base = text.address;
    let load_base = preferred_base
        .checked_add(reader.slide)
        .context("image load base overflow")?;
    let mut exports_payload = json!({"status":"absent"});
    let mut definitions = Vec::new();
    if let Some(p) = modern.or(legacy) {
        ensure!(p.size <= MAX_PAYLOAD, "cached export trie exceeds budget");
        let vm = payload_vm(link, p)?;
        let (bytes, spans) = reader.vm(vm, p.size)?;
        exports_payload = json!({"status":"present","command":p.command,"original_dataoff":p.offset,"preferred_address":vm,"bytes":p.size,"sha256":stela_core::sha256(&bytes),"source_spans":spans});
        if !bytes.is_empty() {
            for raw in exports::parse_trie(&bytes)? {
                let (preferred, address) = match raw.terminal {
                    RawTerminal::Regular { value } => {
                        let preferred =
                            u64::try_from(i128::from(preferred_base) + i128::from(value as i64))
                                .context("cached regular export overflow")?;
                        ensure!(
                            reader
                                .mappings
                                .iter()
                                .any(|m| m.address <= preferred && preferred < m.address + m.size),
                            "regular cache export outside original mappings"
                        );
                        (
                            Some(preferred),
                            Some(
                                preferred
                                    .checked_add(reader.slide)
                                    .context("slid export overflow")?,
                            ),
                        )
                    }
                    RawTerminal::Absolute { value } => (Some(value), Some(value)),
                    _ => (None, None),
                };
                definitions.push(CachedExport {
                    name: raw.name,
                    flags: raw.flags,
                    terminal: raw.terminal,
                    preferred_address: preferred,
                    address,
                });
            }
        }
    }
    let mut starts = Vec::new();
    let mut function_starts_payload = json!({"status":"absent"});
    if let Some(p) = functions {
        ensure!(
            p.size <= MAX_PAYLOAD,
            "function-start payload exceeds budget"
        );
        let vm = payload_vm(link, p)?;
        let (bytes, spans) = reader.vm(vm, p.size)?;
        function_starts_payload = json!({"status":"present","original_dataoff":p.offset,"preferred_address":vm,"bytes":p.size,"sha256":stela_core::sha256(&bytes),"source_spans":spans});
        if !bytes.is_empty() {
            starts = function_starts(&bytes, preferred_base, text.address + text.bytes)?;
        }
    }
    let sources = reader.finish()?;
    Ok(CachedImage {
        kind: "original_cached_image_exports",
        source_pin: PIN,
        image_path: image_path.into(),
        image_uuid,
        header_address: address,
        header_and_commands_sha256: hash,
        preferred_cache_base: reader.preferred,
        cache_base,
        preferred_base,
        load_base,
        segments,
        executable_ranges,
        exports: definitions,
        function_starts: starts,
        exports_payload,
        function_starts_payload,
        sources,
        complete_binary_verified: false,
        cache_fixups_applied: false,
        reader,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u64 = 0x180000000;
    const IMAGE: u64 = BASE + 0x1000;
    const NAME: &str = "/usr/lib/fixture.dylib";
    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn uleb(mut v: u64) -> Vec<u8> {
        let mut b = Vec::new();
        loop {
            let n = (v & 127) as u8;
            v >>= 7;
            b.push(n | if v != 0 { 128 } else { 0 });
            if v == 0 {
                return b;
            }
        }
    }
    fn trie() -> Vec<u8> {
        // Two independent terminals: ordinary _abs and an unrelated reexport.
        let mut a = vec![0];
        a.extend(uleb(0x400));
        let mut z = vec![8, 1];
        z.extend(b"_elsewhere\0");
        let mut b = vec![0, 2];
        b.extend(b"_abs\0");
        b.push(19);
        b.extend(b"_reexport\0");
        b.push((19 + 2 + a.len()) as u8);
        assert_eq!(b.len(), 19);
        b.push(a.len() as u8);
        b.extend(a);
        b.push(0);
        b.push(z.len() as u8);
        b.extend(z);
        b.push(0);
        b
    }
    fn fixture(directory: &std::path::Path) -> (PathBuf, Value) {
        let path = directory.join("cache");
        let mut b = vec![0; 0x8000];
        b[..15].copy_from_slice(b"dyld_v1  arm64e");
        put32(&mut b, 16, 552);
        put32(&mut b, 20, 2);
        b[88..104].fill(0x12);
        put64(&mut b, 224, BASE);
        put64(&mut b, 232, 0xc000);
        put64(&mut b, 240, 0x20000000);
        for (at, va, off, prot) in [(552, BASE, 0, 5), (584, BASE + 0x8000, 0x4000, 1)] {
            put64(&mut b, at, va);
            put64(&mut b, at + 8, 0x4000);
            put64(&mut b, at + 16, off);
            put32(&mut b, at + 24, prot);
            put32(&mut b, at + 28, prot);
        }
        put32(&mut b, 448, 0x3000);
        put32(&mut b, 452, 1);
        put64(&mut b, 0x3000, IMAGE);
        put32(&mut b, 0x3018, 0x3040);
        b[0x3040..0x3040 + NAME.len()].copy_from_slice(NAME.as_bytes());
        let h = &mut b[0x1000..];
        put32(h, 0, 0xfeedfacf);
        put32(h, 4, 0x0100000c);
        put32(h, 8, 0x80000002);
        put32(h, 12, 6);
        put32(h, 16, 6);
        put32(h, 20, 328);
        put32(h, 24, 0x80000000);
        let mut at = 32;
        put32(h, at, 0x19);
        put32(h, at + 4, 152);
        h[at + 8..at + 14].copy_from_slice(b"__TEXT");
        put64(h, at + 24, IMAGE);
        put64(h, at + 32, 0x1000);
        put64(h, at + 40, 0x1000);
        put64(h, at + 48, 0x1000);
        put32(h, at + 56, 5);
        put32(h, at + 60, 5);
        put32(h, at + 64, 1);
        h[at + 72..at + 78].copy_from_slice(b"__text");
        h[at + 88..at + 94].copy_from_slice(b"__TEXT");
        put64(h, at + 104, IMAGE + 0x400);
        put64(h, at + 112, 0x80);
        put32(h, at + 136, 0x80000000);
        at += 152;
        put32(h, at, 0x19);
        put32(h, at + 4, 72);
        h[at + 8..at + 18].copy_from_slice(b"__LINKEDIT");
        put64(h, at + 24, BASE + 0x8000);
        put64(h, at + 32, 0x4000);
        put64(h, at + 40, 0x8000);
        put64(h, at + 48, 0x4000);
        put32(h, at + 56, 1);
        put32(h, at + 60, 1);
        at += 72;
        put32(h, at, 0x1b);
        put32(h, at + 4, 24);
        h[at + 8..at + 24].fill(0x34);
        at += 24;
        put32(h, at, 0xd);
        put32(h, at + 4, 48);
        put32(h, at + 8, 24);
        h[at + 24..at + 24 + NAME.len()].copy_from_slice(NAME.as_bytes());
        at += 48;
        let t = trie();
        put32(h, at, 0x80000033);
        put32(h, at + 4, 16);
        put32(h, at + 8, 0x8100);
        put32(h, at + 12, t.len() as u32);
        at += 16;
        put32(h, at, 0x26);
        put32(h, at + 4, 16);
        put32(h, at + 8, 0x8200);
        put32(h, at + 12, 8);
        at += 16;
        assert_eq!(at, 360);
        let code = hex::decode("1f0000710054805ac0035fd6").unwrap();
        b[0x1400..0x140c].copy_from_slice(&code);
        b[0x4100..0x4100 + t.len()].copy_from_slice(&t);
        b[0x4200..0x4208].copy_from_slice(&[0x80, 8, 12, 12, 0, 0, 0, 0]);
        std::fs::write(&path, b).unwrap();
        let set = super::super::shared_cache::manifest_set(&path).unwrap();
        (path, set)
    }
    #[test]
    fn original_linkedit_bias_lookup_unsupported_isolation_and_complete_code_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let (_, set) = fixture(d.path());
        let mut image = read(&set, NAME, BASE + 0x4000).unwrap();
        assert_eq!(image.exports.len(), 2);
        assert_eq!(image.exports_payload["preferred_address"], BASE + 0x8100);
        assert_eq!(
            image.function_starts,
            [IMAGE + 0x400, IMAGE + 0x40c, IMAGE + 0x418]
        );
        assert_eq!(
            image.lookup("_abs").unwrap().unwrap().address,
            Some(IMAGE + 0x4400)
        );
        assert!(image.lookup("_absent").unwrap().is_none());
        assert!(
            image
                .lookup("_reexport")
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
        let code = image.snapshot_function("_abs").unwrap();
        assert_eq!(code.extent.bytes, 12);
        assert_eq!(code.extent.boundary, "next_function_start");
        assert_eq!(code.source_spans[0].file_offset, 0x1400);
        assert_eq!(hex::encode(code.bytes), "1f0000710054805ac0035fd6");
        assert!(!code.complete_binary_verified);
        assert_eq!(
            serde_json::to_value(image).unwrap()["cache_fixups_applied"],
            false
        );
    }
    #[test]
    fn cache_source_and_receipt_changes_cannot_authorize_reads() {
        let d = tempfile::tempdir().unwrap();
        let (path, set) = fixture(d.path());
        let mut forged = set.clone();
        forged["files"][0]["mappings"][0]["address"] = json!(BASE + 4);
        assert!(read(&forged, NAME, BASE).is_err());
        let mut forged = set.clone();
        forged["images"][0]["address"] = json!(IMAGE + 4);
        assert!(read(&forged, NAME, BASE).is_err());
        let mut forged = set.clone();
        forged["files"][0]["source_sha256"] = json!("00".repeat(32));
        assert!(read(&forged, NAME, BASE).is_err());
        let mut b = std::fs::read(&path).unwrap();
        b[0x1400] ^= 1;
        std::fs::write(&path, b).unwrap();
        assert!(read(&set, NAME, BASE).is_err());
    }
    #[test]
    fn rejects_code_snapshot_after_source_mutation() {
        let d = tempfile::tempdir().unwrap();
        let (path, set) = fixture(d.path());
        let mut image = read(&set, NAME, BASE).unwrap();
        let mut b = std::fs::read(&path).unwrap();
        b[0x1400] ^= 1;
        std::fs::write(&path, b).unwrap();
        assert!(image.snapshot_function("_abs").is_err());
    }
    #[test]
    fn bounds_slides_and_requires_declared_original_image() {
        let d = tempfile::tempdir().unwrap();
        let (_, set) = fixture(d.path());
        for base in [BASE - 0x4000, BASE + 4, BASE + 0x20004000] {
            assert!(read(&set, NAME, base).is_err());
        }
        assert!(read(&set, "/usr/lib/missing", BASE).is_err());
    }
    #[test]
    fn linkedit_bias_requires_declared_file_and_vm_extents() {
        let link = ImageRange {
            name: "__LINKEDIT".into(),
            address: 0x9000,
            bytes: 0x100,
            file_offset: 0x500,
            file_bytes: 0x80,
            max_protection: 1,
            initial_protection: 1,
        };
        assert_eq!(
            payload_vm(
                &link,
                Payload {
                    offset: 0x510,
                    size: 8,
                    command: 0
                }
            )
            .unwrap(),
            0x9010
        );
        for (offset, size) in [(0x4ff, 1), (0x57f, 2), (u64::MAX, 2)] {
            assert!(
                payload_vm(
                    &link,
                    Payload {
                        offset,
                        size,
                        command: 0
                    }
                )
                .is_err()
            );
        }
    }
    #[test]
    fn function_start_stream_bounds_overflow_alignment_and_padding() {
        assert_eq!(
            function_starts(&[4, 4, 0, 0], 0x1000, 0x1010).unwrap(),
            [0x1004, 0x1008]
        );
        for b in [
            vec![4],
            vec![4, 0, 1],
            vec![0x80],
            vec![0x80, 0, 0],
            vec![3, 0],
            vec![16, 0],
            vec![0xff; 11],
        ] {
            assert!(function_starts(&b, 0x1000, 0x1010).is_err());
        }
        assert!(function_starts(&[4, 0], u64::MAX - 1, u64::MAX).is_err());
    }
    #[test]
    fn no_arbitrary_function_prefix_or_nonexecutable_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let (_, set) = fixture(d.path());
        let mut image = read(&set, NAME, BASE).unwrap();
        image.function_starts.clear();
        assert!(image.snapshot_function("_abs").is_err());
        let mut image = read(&set, NAME, BASE).unwrap();
        image.reader.mappings[0].protection = 1;
        assert!(image.snapshot_function("_abs").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn does_not_follow_replacement_cache_symlink() {
        let d = tempfile::tempdir().unwrap();
        let (path, set) = fixture(d.path());
        let replacement = d.path().join("replacement");
        std::fs::rename(&path, &replacement).unwrap();
        std::os::unix::fs::symlink(replacement, &path).unwrap();
        assert!(read(&set, NAME, BASE).is_err());
    }
}
