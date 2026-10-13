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
    collections::{BTreeMap, BTreeSet},
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
    image_addresses: Option<BTreeMap<String, u64>>,
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
            image_addresses: None,
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
        if self.image_addresses.is_none() {
            let offset = u64::from(word(&self.sources[0].header, 448)?);
            let count = u64::from(word(&self.sources[0].header, 452)?);
            ensure!(
                count > 0 && count <= 1_000_000,
                "invalid original cache image count"
            );
            let table = self.file_read(0, offset, count * 32)?;
            let mut addresses = BTreeMap::new();
            for b in table.as_chunks::<32>().0 {
                let at = u64::from(word(b, 24)?);
                let n = self.sources[0].identity.len().saturating_sub(at).min(4097);
                let bytes = self.file_read(0, at, n)?;
                let end = bytes
                    .iter()
                    .position(|b| *b == 0)
                    .context("unterminated original image path")?;
                ensure!(end <= 4096, "excessive original image path");
                let name = std::str::from_utf8(&bytes[..end])?.to_owned();
                ensure!(
                    name.starts_with('/'),
                    "nonabsolute original cache image path"
                );
                ensure!(
                    addresses.insert(name, wide(b, 0)?).is_none(),
                    "duplicate original image path"
                );
            }
            self.image_addresses = Some(addresses);
        }
        self.image_addresses
            .as_ref()
            .and_then(|m| m.get(path))
            .copied()
            .context("image path absent from original cache image table")
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
pub struct DylibIdentity {
    pub name: String,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}
/// Effective linkage flags, independent in dylib_use_command. `kind` below
/// remains the original load-command kind retained by the manifest inventory.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyAttributes {
    pub modern: bool,
    pub flags: u32,
    pub weak_link: bool,
    pub reexport: bool,
    pub upward: bool,
    pub delayed_init: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    pub attributes: DependencyAttributes,
    pub name: String,
    pub kind: String,
    pub library_ordinal: usize,
    pub load_command_index: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}
fn dylib_identity(command: &[u8]) -> Result<DylibIdentity> {
    ensure!(command.len() >= 24, "truncated cached dylib command");
    let offset = usize::try_from(word(command, 8)?)?;
    ensure!(
        offset >= 24 && offset < command.len(),
        "invalid cached dylib name offset"
    );
    if word(command, 12)? == 0x1a741800 {
        ensure!(
            command.len() >= 28 && offset == 28,
            "marked dylib_use_command requires complete 28-byte header and nameoff28"
        );
        ensure!(
            word(command, 24)? & !0xf == 0,
            "unknown dylib_use_command flags"
        );
        ensure!(
            matches!(
                word(command, 0)?,
                0xc | 0x80000018 | 0x8000001f | 0x80000023
            ),
            "marked dylib_use_command on unsupported command kind"
        );
    }
    let tail = &command[offset..];
    let length = tail
        .iter()
        .take(4097)
        .position(|b| *b == 0)
        .context("unterminated/excessive cached dylib name")?;
    ensure!(length > 0, "empty cached dylib name");
    let name = std::str::from_utf8(&tail[..length])?.to_owned();
    Ok(DylibIdentity {
        name,
        timestamp: word(command, 12)?,
        current_version: word(command, 16)?,
        compatibility_version: word(command, 20)?,
    })
}
fn dependency_attributes(command: &[u8]) -> Result<DependencyAttributes> {
    let modern = word(command, 12)? == 0x1a741800;
    let flags = if modern {
        ensure!(
            command.len() >= 28 && word(command, 8)? == 28,
            "invalid modern dependency header"
        );
        let flags = word(command, 24)?;
        ensure!(flags & !0xf == 0, "unknown dylib_use_command flags");
        flags
    } else {
        match word(command, 0)? {
            0x80000018 => 1,
            0x8000001f => 2,
            0x80000023 => 4,
            0xc | 0x20 => 0,
            _ => bail!("unsupported dependency command"),
        }
    };
    Ok(DependencyAttributes {
        modern,
        flags,
        weak_link: flags & 1 != 0,
        reexport: flags & 2 != 0,
        upward: flags & 4 != 0,
        delayed_init: flags & 8 != 0,
    })
}
fn original_dependency_receipt(dependency: &Dependency) -> Value {
    json!({"name":dependency.name,"kind":dependency.kind,"library_ordinal":dependency.library_ordinal,
        "load_command_index":dependency.load_command_index,"timestamp":dependency.timestamp,
        "current_version":dependency.current_version,"compatibility_version":dependency.compatibility_version})
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
    pub dylib_identity: Option<DylibIdentity>,
    pub dependencies: Vec<Dependency>,
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
    #[cfg(test)]
    reader: Option<Reader>,
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
    // Direct-reader verification helper; production snapshots use CacheResolver.
    #[cfg(test)]
    fn snapshot_function(&mut self, name: &str) -> Result<CodeSnapshot> {
        let extent = self.function_extent(name)?;
        snapshot(
            self.reader
                .as_mut()
                .context("cached metadata has no owned reader")?,
            extent,
        )
    }
}
fn snapshot(reader: &mut Reader, extent: FunctionExtent) -> Result<CodeSnapshot> {
    let (bytes, source_spans) = reader.vm(extent.preferred_address, extent.bytes)?;
    for span in &source_spans {
        let mapping = reader
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
    let sources = reader.finish()?;
    Ok(CodeSnapshot {
        sha256: stela_core::sha256(&bytes),
        extent,
        bytes,
        source_spans,
        sources,
        complete_binary_verified: false,
    })
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
pub(crate) fn function_starts(bytes: &[u8], base: u64, text_end: u64) -> Result<Vec<u64>> {
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
    let mut resolver = CacheResolver::new(set, cache_base)?;
    resolver.load(image_path)?;
    let mut image = resolver
        .images
        .remove(image_path)
        .context("selected image unavailable")?;
    image.sources = resolver.reader.finish()?;
    #[cfg(test)]
    {
        image.reader = Some(resolver.reader);
    }
    Ok(image)
}
fn read_image(
    reader: &mut Reader,
    record: &Value,
    image_path: &str,
    cache_base: u64,
) -> Result<CachedImage> {
    ensure!(
        image_path.starts_with('/') && image_path.len() <= 4096,
        "invalid original image path"
    );
    let address = reader.image_address(image_path)?;
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
    let mut identity = None;
    let mut dependencies = Vec::new();
    let mut at = 0;
    for command_index in 0..count {
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
                    s.file_bytes <= s.bytes
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
            0xd => {
                ensure!(identity.is_none(), "duplicate cached LC_ID_DYLIB");
                identity = Some(dylib_identity(b)?);
            }
            0x20 => bail!("LC_LAZY_LOAD_DYLIB is outside the reviewed cache lookup profile"),
            0xc | 0x80000018 | 0x8000001f | 0x80000023 => {
                let d = dylib_identity(b)?;
                let kind = match command {
                    0xc => "load_dylib",
                    0x80000018 => "load_weak_dylib",
                    0x8000001f => "reexport_dylib",
                    _ => "load_upward_dylib",
                };
                dependencies.push(Dependency {
                    attributes: dependency_attributes(b)?,
                    name: d.name,
                    kind: kind.into(),
                    library_ordinal: dependencies.len() + 1,
                    load_command_index: command_index,
                    timestamp: d.timestamp,
                    current_version: d.current_version,
                    compatibility_version: d.compatibility_version,
                });
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
    ensure!(
        serde_json::to_value(&identity)? == record["mach_o"]["dylib_identity"],
        "cached install identity differs from receipt"
    );
    ensure!(
        serde_json::to_value(
            dependencies
                .iter()
                .map(original_dependency_receipt)
                .collect::<Vec<_>>()
        )? == record["mach_o"]["dependencies"],
        "cached dependency order/metadata differs from receipt"
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
        dylib_identity: identity,
        dependencies,
        segments,
        executable_ranges,
        exports: definitions,
        function_starts: starts,
        exports_payload,
        function_starts_payload,
        sources: Vec::new(),
        complete_binary_verified: false,
        cache_fixups_applied: false,
        #[cfg(test)]
        reader: None,
    })
}

/// One ordinary definition reached through static two-level/reexport lookup.
/// `weak_definition` is metadata; this lookup performs no global coalescing.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderDefinition {
    pub provider_image: String,
    pub provider_symbol: String,
    pub image_uuid: String,
    pub header_and_commands_sha256: String,
    pub preferred_base: u64,
    pub load_base: u64,
    pub preferred_address: u64,
    pub address: u64,
    pub flags: u64,
    pub weak_definition: bool,
    pub terminal: RawTerminal,
}
#[derive(Debug, Clone, Serialize)]
pub struct LookupStep {
    pub image: String,
    pub symbol: String,
    pub action: String,
    pub dependency: Option<Dependency>,
    pub target_symbol: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedExport {
    pub kind: &'static str,
    pub requester_image: String,
    pub requested_symbol: String,
    pub weak_import: bool,
    pub cache_base: u64,
    pub definition: Option<ProviderDefinition>,
    pub route: Vec<LookupStep>,
    pub sources: Vec<Value>,
    pub complete_binary_verified: bool,
}
struct Search {
    weak_import: bool,
    active: BTreeSet<(String, String)>,
    completed: BTreeMap<(String, String), Option<ProviderDefinition>>,
    route: Vec<LookupStep>,
    visits: usize,
}
impl Search {
    fn step(
        &mut self,
        image: &str,
        symbol: &str,
        action: &str,
        dependency: Option<Dependency>,
        target_symbol: Option<String>,
    ) -> Result<()> {
        ensure!(
            self.route.len() < 4096,
            "cache lookup route exceeds bounded budget"
        );
        self.route.push(LookupStep {
            image: image.into(),
            symbol: symbol.into(),
            action: action.into(),
            dependency,
            target_symbol,
        });
        Ok(())
    }
}
/// Shared opened originals and memoized image metadata. No cache pages, fixups,
/// resolver code, initializers or host symbols are instantiated by this context.
pub struct CacheResolver {
    reader: Reader,
    records: BTreeMap<String, Value>,
    images: BTreeMap<String, CachedImage>,
    cache_base: u64,
}
impl CacheResolver {
    pub fn new(set: &Value, cache_base: u64) -> Result<Self> {
        let mut reader = Reader::open(set, cache_base)?;
        let records = set["images"]
            .as_array()
            .context("missing cache image receipts")?;
        ensure!(
            !records.is_empty() && records.len() <= 1_000_000,
            "cache image receipt count exceeds budget"
        );
        let mut by_path: BTreeMap<String, Value> = BTreeMap::new();
        for record in records {
            let path = record["path"]
                .as_str()
                .context("cache image receipt has no path")?;
            ensure!(
                by_path.insert(path.into(), record.clone()).is_none(),
                "duplicate cache image receipt path"
            );
        }
        let first = by_path.keys().next().context("cache image table empty")?;
        reader.image_address(first)?;
        let original = reader
            .image_addresses
            .as_ref()
            .context("original image table unavailable")?;
        ensure!(
            original.len() == by_path.len(),
            "cache image receipt set differs from original table"
        );
        for (path, address) in original {
            ensure!(
                by_path.get(path).and_then(|v| v["address"].as_u64()) == Some(*address),
                "cache image receipt differs from original path/address table"
            );
        }
        Ok(Self {
            reader,
            records: by_path,
            images: BTreeMap::new(),
            cache_base,
        })
    }
    fn load(&mut self, path: &str) -> Result<()> {
        if self.images.contains_key(path) {
            return Ok(());
        }
        ensure!(
            self.images.len() < 256,
            "cache lookup image count exceeds budget"
        );
        let record = self
            .records
            .get(path)
            .context("dependency absent from original cache image table")?;
        let image = read_image(&mut self.reader, record, path, self.cache_base)?;
        self.images.insert(path.into(), image);
        Ok(())
    }
    pub fn image(&mut self, path: &str) -> Result<&CachedImage> {
        self.load(path)?;
        self.images
            .get(path)
            .context("cached image metadata unavailable")
    }
    fn provider(&mut self, dependency: &Dependency) -> Result<bool> {
        ensure!(
            dependency.name.starts_with('/'),
            "nonabsolute cached dependency needs unimplemented path resolution"
        );
        if !self.records.contains_key(&dependency.name) {
            return Ok(false);
        }
        self.load(&dependency.name)?;
        let image = &self.images[&dependency.name];
        ensure!(
            image.dylib_identity.as_ref().map(|id| id.name.as_str())
                == Some(dependency.name.as_str()),
            "cache dependency install identity mismatch"
        );
        Ok(true)
    }
    fn walk(
        &mut self,
        image_path: &str,
        symbol: &str,
        search: &mut Search,
    ) -> Result<Option<ProviderDefinition>> {
        search.visits += 1;
        ensure!(
            search.visits <= 4096 && search.active.len() < 64,
            "cache symbol lookup exceeds recursion/work budget"
        );
        let key = (image_path.to_owned(), symbol.to_owned());
        ensure!(
            !search.active.contains(&key),
            "cyclic cache reexport lookup for {image_path}:{symbol}"
        );
        if let Some(done) = search.completed.get(&key).cloned() {
            search.step(image_path, symbol, "memoized_result", None, None)?;
            return Ok(done);
        }
        search.active.insert(key.clone());
        self.load(image_path)?;
        let image = &self.images[image_path];
        // No nlist fallback: this reviewed profile requires an original trie.
        ensure!(
            image.exports_payload["status"] == "present",
            "cache lookup requires original export trie; legacy symbol-table fallback unsupported"
        );
        let local = image
            .exports
            .binary_search_by(|e| e.name.as_str().cmp(symbol))
            .ok()
            .map(|n| image.exports[n].clone());
        let dependencies = image.dependencies.clone();
        let found = if let Some(export) = local {
            match &export.terminal {
                RawTerminal::Regular { .. } | RawTerminal::Absolute { .. } => {
                    search.step(image_path, symbol, "local_definition", None, None)?;
                    Some(ProviderDefinition {
                        provider_image: image_path.into(),
                        provider_symbol: symbol.into(),
                        image_uuid: image.image_uuid.clone(),
                        header_and_commands_sha256: image.header_and_commands_sha256.clone(),
                        preferred_base: image.preferred_base,
                        load_base: image.load_base,
                        preferred_address: export
                            .preferred_address
                            .context("definition lacks preferred address")?,
                        address: export.address.context("definition lacks address")?,
                        flags: export.flags,
                        weak_definition: export.flags & 4 != 0,
                        terminal: export.terminal,
                    })
                }
                RawTerminal::Reexport {
                    library_ordinal,
                    import_name,
                } => {
                    let index = usize::try_from(*library_ordinal)
                        .context("reexport ordinal overflows host size")?;
                    ensure!(
                        index > 0 && index <= dependencies.len(),
                        "cache reexport ordinal out of dependency range"
                    );
                    let dependency = dependencies[index - 1].clone();
                    let target = if import_name.is_empty() {
                        symbol
                    } else {
                        import_name.as_str()
                    };
                    search.step(
                        image_path,
                        symbol,
                        "terminal_reexport",
                        Some(dependency.clone()),
                        Some(target.into()),
                    )?;
                    if self.provider(&dependency)? {
                        self.walk(&dependency.name, target, search)?
                    } else {
                        search.step(
                            image_path,
                            symbol,
                            "missing_explicit_provider",
                            Some(dependency),
                            Some(target.into()),
                        )?;
                        ensure!(
                            search.weak_import,
                            "strong cache reexport provider is absent"
                        );
                        None
                    }
                }
                _ => bail!(
                    "unsupported cache export semantics for {image_path}:{symbol}: {:?}",
                    export.terminal
                ),
            }
        } else {
            search.step(image_path, symbol, "local_absent", None, None)?;
            let mut result = None;
            for dependency in dependencies.into_iter().filter(|d| d.attributes.reexport) {
                search.step(
                    image_path,
                    symbol,
                    "dependency_reexport",
                    Some(dependency.clone()),
                    Some(symbol.into()),
                )?;
                if self.provider(&dependency)? {
                    if let Some(found) = self.walk(&dependency.name, symbol, search)? {
                        result = Some(found);
                        break;
                    }
                } else {
                    search.step(
                        image_path,
                        symbol,
                        "missing_implicit_provider",
                        Some(dependency),
                        Some(symbol.into()),
                    )?;
                }
            }
            result
        };
        search.active.remove(&key);
        search.completed.insert(key, found.clone());
        Ok(found)
    }
    pub fn resolve(
        &mut self,
        image_path: &str,
        symbol: &str,
        weak_import: bool,
    ) -> Result<ResolvedExport> {
        ensure!(
            !symbol.is_empty() && symbol.len() <= 4096 && !symbol.contains('\0'),
            "invalid cache lookup symbol"
        );
        let mut search = Search {
            weak_import,
            active: BTreeSet::new(),
            completed: BTreeMap::new(),
            route: Vec::new(),
            visits: 0,
        };
        let definition = self.walk(image_path, symbol, &mut search)?;
        let sources = self.reader.finish()?;
        Ok(ResolvedExport {
            kind: "original_cached_export_resolution",
            requester_image: image_path.into(),
            requested_symbol: symbol.into(),
            weak_import,
            cache_base: self.cache_base,
            definition,
            route: search.route,
            sources,
            complete_binary_verified: false,
        })
    }
    pub fn snapshot_resolved_function(
        &mut self,
        resolved: &ResolvedExport,
    ) -> Result<CodeSnapshot> {
        ensure!(
            resolved.cache_base == self.cache_base,
            "resolved export belongs to another cache placement"
        );
        let definition = resolved
            .definition
            .as_ref()
            .context("cannot snapshot missing export")?;
        self.load(&definition.provider_image)?;
        let image = &self.images[&definition.provider_image];
        let current = image
            .lookup(&definition.provider_symbol)?
            .context("resolved provider symbol disappeared")?;
        ensure!(
            definition.image_uuid == image.image_uuid
                && definition.header_and_commands_sha256 == image.header_and_commands_sha256
                && current.address == Some(definition.address)
                && current.preferred_address == Some(definition.preferred_address)
                && current.flags == definition.flags
                && current.terminal == definition.terminal,
            "resolved definition differs from verified provider metadata"
        );
        snapshot(
            &mut self.reader,
            image.function_extent(&definition.provider_symbol)?,
        )
    }
}
// Unit-test shorthand; production lookups share one CacheResolver per batch.
#[cfg(test)]
fn resolve(
    set: &Value,
    image_path: &str,
    symbol: &str,
    cache_base: u64,
    weak_import: bool,
) -> Result<ResolvedExport> {
    CacheResolver::new(set, cache_base)?.resolve(image_path, symbol, weak_import)
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
    struct ImageSpec<'a> {
        path: &'a str,
        entries: Vec<(&'a str, u8, Vec<u8>)>,
        dependencies: Vec<(u32, &'a str)>,
    }
    fn raw_trie(entries: &[(&str, u8, Vec<u8>)]) -> Vec<u8> {
        let leaves = entries
            .iter()
            .map(|(_, flags, rest)| {
                let mut payload = vec![*flags];
                payload.extend(rest);
                let mut leaf = uleb(payload.len() as u64);
                leaf.extend(payload);
                leaf.push(0);
                leaf
            })
            .collect::<Vec<_>>();
        let mut size = 2;
        loop {
            let mut next = 2;
            let mut offset = size;
            for ((name, _, _), leaf) in entries.iter().zip(&leaves) {
                next += name.len() + 1 + uleb(offset as u64).len();
                offset += leaf.len();
            }
            if next == size {
                break;
            }
            size = next;
        }
        let mut bytes = vec![0, entries.len() as u8];
        let mut offset = size;
        for ((name, _, _), leaf) in entries.iter().zip(&leaves) {
            bytes.extend(name.as_bytes());
            bytes.push(0);
            bytes.extend(uleb(offset as u64));
            offset += leaf.len();
        }
        for leaf in leaves {
            bytes.extend(leaf);
        }
        bytes
    }
    fn regular(name: &str, flags: u8) -> (&str, u8, Vec<u8>) {
        (name, flags, uleb(0x400))
    }
    fn reexport<'a>(name: &'a str, ordinal: u64, target: &str) -> (&'a str, u8, Vec<u8>) {
        let mut b = uleb(ordinal);
        b.extend(target.as_bytes());
        b.push(0);
        (name, 8, b)
    }
    fn graph_fixture(directory: &std::path::Path, specs: &[ImageSpec<'_>]) -> Value {
        assert!(!specs.is_empty() && specs.len() <= 3);
        let (path, _) = fixture(directory);
        let mut bytes = std::fs::read(&path).unwrap();
        let template = bytes[0x1000..0x1000 + 360].to_vec();
        bytes[0x1000..0x4000].fill(0);
        put32(&mut bytes, 448, 0x7000);
        put32(&mut bytes, 452, specs.len() as u32);
        for (index, spec) in specs.iter().enumerate() {
            let file_offset = 0x1000 + index * 0x1000;
            let address = BASE + file_offset as u64;
            let mut image = template.clone();
            put64(&mut image, 56, address);
            put64(&mut image, 72, file_offset as u64);
            put64(&mut image, 136, address + 0x400);
            image[264..280].fill(0x40 + index as u8);
            image[304..328].fill(0);
            assert!(spec.path.len() < 24);
            image[304..304 + spec.path.len()].copy_from_slice(spec.path.as_bytes());
            for (command, name) in &spec.dependencies {
                let size = (24 + name.len() + 1 + 7) & !7;
                let mut b = vec![0; size];
                put32(&mut b, 0, *command);
                put32(&mut b, 4, size as u32);
                put32(&mut b, 8, 24);
                b[24..24 + name.len()].copy_from_slice(name.as_bytes());
                image.extend(b);
            }
            put32(&mut image, 16, 6 + spec.dependencies.len() as u32);
            let size = image.len() - 32;
            put32(&mut image, 20, size as u32);
            let trie = raw_trie(&spec.entries);
            let trie_offset = 0x5000 + index * 0x400;
            assert!(trie.len() < 0x400);
            put32(&mut image, 336, (trie_offset + 0x4000) as u32);
            put32(&mut image, 340, trie.len() as u32);
            let starts_offset = 0x6000 + index * 16;
            put32(&mut image, 352, (starts_offset + 0x4000) as u32);
            bytes[file_offset..file_offset + image.len()].copy_from_slice(&image);
            bytes[file_offset + 0x400..file_offset + 0x40c]
                .copy_from_slice(&hex::decode("1f0000710054805ac0035fd6").unwrap());
            bytes[trie_offset..trie_offset + trie.len()].copy_from_slice(&trie);
            bytes[starts_offset..starts_offset + 8].copy_from_slice(&[0x80, 8, 12, 12, 0, 0, 0, 0]);
            put64(&mut bytes, 0x7000 + index * 32, address);
            put32(
                &mut bytes,
                0x7018 + index * 32,
                (0x7100 + index * 64) as u32,
            );
            bytes[0x7100 + index * 64..0x7100 + index * 64 + spec.path.len()]
                .copy_from_slice(spec.path.as_bytes());
        }
        std::fs::write(&path, bytes).unwrap();
        super::super::shared_cache::manifest_set(&path).unwrap()
    }
    #[test]
    fn reexport_lookup_local_priority_dependency_order_and_weak_definition_metadata() {
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[
                ImageSpec {
                    path: "/main",
                    entries: vec![regular("_local", 0)],
                    dependencies: vec![(0xc, "/ordinary"), (0x8000001f, "/forward")],
                },
                ImageSpec {
                    path: "/ordinary",
                    entries: vec![regular("_abs", 0)],
                    dependencies: vec![],
                },
                ImageSpec {
                    path: "/forward",
                    entries: vec![regular("_abs", 4), regular("_local", 0)],
                    dependencies: vec![],
                },
            ],
        );
        let mut context = CacheResolver::new(&set, BASE + 0x4000).unwrap();
        let local = context.resolve("/main", "_local", false).unwrap();
        assert_eq!(local.definition.unwrap().provider_image, "/main");
        assert_eq!(local.route.len(), 1);
        let result = context.resolve("/main", "_abs", false).unwrap();
        let definition = result.definition.as_ref().unwrap();
        assert_eq!(definition.provider_image, "/forward");
        assert!(definition.weak_definition);
        assert_eq!(definition.address, BASE + 0x7400);
        let edge = result
            .route
            .iter()
            .find_map(|s| s.dependency.as_ref())
            .unwrap();
        assert_eq!(edge.library_ordinal, 2);
        assert!(result.route.iter().all(|s| s.image != "/ordinary"));
        let snapshot = context.snapshot_resolved_function(&result).unwrap();
        assert_eq!(snapshot.extent.bytes, 12);
        assert_eq!(snapshot.extent.address, BASE + 0x7400);
        assert_eq!(
            context.image("/main").unwrap().dependencies[0].kind,
            "load_dylib"
        );
    }
    #[test]
    fn explicit_reexports_use_all_dependency_ordinals_and_preserve_renaming() {
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[
                ImageSpec {
                    path: "/main",
                    entries: vec![reexport("_alias", 1, "_target"), reexport("_same", 2, "")],
                    dependencies: vec![(0xc, "/ordinary"), (0x8000001f, "/forward")],
                },
                ImageSpec {
                    path: "/ordinary",
                    entries: vec![regular("_target", 0)],
                    dependencies: vec![],
                },
                ImageSpec {
                    path: "/forward",
                    entries: vec![("_same", 2, uleb(123))],
                    dependencies: vec![],
                },
            ],
        );
        let mut context = CacheResolver::new(&set, BASE + 0x4000).unwrap();
        let alias = context.resolve("/main", "_alias", false).unwrap();
        let found = alias.definition.unwrap();
        assert_eq!(found.provider_image, "/ordinary");
        assert_eq!(found.provider_symbol, "_target");
        let same = context.resolve("/main", "_same", false).unwrap();
        let found = same.definition.as_ref().unwrap();
        assert_eq!(found.address, 123);
        assert_eq!(found.preferred_address, 123);
        assert!(context.snapshot_resolved_function(&same).is_err());
    }
    #[test]
    fn missing_provider_and_missing_symbol_are_explicit_and_never_zero_definitions() {
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[ImageSpec {
                path: "/main",
                entries: vec![reexport("_missing", 1, ""), reexport("_bad_ordinal", 2, "")],
                dependencies: vec![(0xc, "/missing")],
            }],
        );
        let mut context = CacheResolver::new(&set, BASE).unwrap();
        assert!(
            context
                .resolve("/main", "_missing", false)
                .unwrap_err()
                .to_string()
                .contains("strong")
        );
        let weak = context.resolve("/main", "_missing", true).unwrap();
        assert!(weak.definition.is_none());
        assert_eq!(
            weak.route.last().unwrap().action,
            "missing_explicit_provider"
        );
        assert!(
            context
                .resolve("/main", "_bad_ordinal", true)
                .unwrap_err()
                .to_string()
                .contains("ordinal")
        );
        assert!(
            context
                .resolve("/main", "_absent", false)
                .unwrap()
                .definition
                .is_none()
        );
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[
                ImageSpec {
                    path: "/main",
                    entries: vec![],
                    dependencies: vec![(0x8000001f, "/missing"), (0x8000001f, "/forward")],
                },
                ImageSpec {
                    path: "/forward",
                    entries: vec![regular("_abs", 0)],
                    dependencies: vec![],
                },
            ],
        );
        let result = resolve(&set, "/main", "_abs", BASE, false).unwrap();
        assert_eq!(result.definition.unwrap().provider_image, "/forward");
        assert!(
            result
                .route
                .iter()
                .any(|s| s.action == "missing_implicit_provider")
        );
    }
    #[test]
    fn reexport_cycles_decline_but_renamed_revisit_can_reach_a_definition() {
        for cycle in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let set = graph_fixture(
                d.path(),
                &[
                    ImageSpec {
                        path: "/main",
                        entries: vec![reexport("_a", 1, "_b"), regular("_c", 0)],
                        dependencies: vec![(0xc, "/forward")],
                    },
                    ImageSpec {
                        path: "/forward",
                        entries: vec![reexport("_b", 1, if cycle { "_a" } else { "_c" })],
                        dependencies: vec![(0xc, "/main")],
                    },
                ],
            );
            let result = resolve(&set, "/main", "_a", BASE, false);
            if cycle {
                assert!(result.unwrap_err().to_string().contains("cyclic"));
            } else {
                assert_eq!(result.unwrap().definition.unwrap().provider_symbol, "_c");
            }
        }
    }
    #[test]
    fn dag_absence_is_memoized_and_local_unsupported_terminal_stops_fallback() {
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[
                ImageSpec {
                    path: "/main",
                    entries: vec![("_tlv", 1, uleb(0x400))],
                    dependencies: vec![(0x8000001f, "/a"), (0x8000001f, "/b")],
                },
                ImageSpec {
                    path: "/a",
                    entries: vec![],
                    dependencies: vec![(0x8000001f, "/b")],
                },
                ImageSpec {
                    path: "/b",
                    entries: vec![regular("_tlv", 0)],
                    dependencies: vec![],
                },
            ],
        );
        let mut context = CacheResolver::new(&set, BASE).unwrap();
        let absent = context.resolve("/main", "_absent", false).unwrap();
        assert!(absent.definition.is_none());
        assert!(absent.route.iter().any(|s| s.action == "memoized_result"));
        assert!(
            context
                .resolve("/main", "_tlv", false)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
    }
    #[test]
    fn declared_provider_path_does_not_replace_its_install_identity() {
        let d = tempfile::tempdir().unwrap();
        let _ = graph_fixture(
            d.path(),
            &[
                ImageSpec {
                    path: "/main",
                    entries: vec![reexport("_abs", 1, "")],
                    dependencies: vec![(0xc, "/provider")],
                },
                ImageSpec {
                    path: "/provider",
                    entries: vec![regular("_abs", 0)],
                    dependencies: vec![],
                },
            ],
        );
        let path = d.path().join("cache");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0x2000 + 304..0x2000 + 328].fill(0);
        bytes[0x2000 + 304..0x2000 + 310].copy_from_slice(b"/other");
        std::fs::write(&path, bytes).unwrap();
        let set = super::super::shared_cache::manifest_set(&path).unwrap();
        assert!(
            resolve(&set, "/main", "_abs", BASE, false)
                .unwrap_err()
                .to_string()
                .contains("install identity")
        );
    }

    #[test]
    fn modern_dependency_flags_are_independent_and_override_legacy_command_attributes() {
        for command_kind in [0xc, 0x80000018, 0x8000001f, 0x80000023] {
            for flags in 0..16 {
                let mut command = vec![0; 40];
                put32(&mut command, 0, command_kind);
                put32(&mut command, 4, 40);
                put32(&mut command, 8, 28);
                put32(&mut command, 12, 0x1a741800);
                put32(&mut command, 16, 0x10203);
                put32(&mut command, 20, 0x10000);
                put32(&mut command, 24, flags);
                command[28..31].copy_from_slice(b"/a\0");
                let identity = dylib_identity(&command).unwrap();
                assert_eq!(identity.name, "/a");
                assert_eq!(identity.current_version, 0x10203);
                assert_eq!(identity.compatibility_version, 0x10000);
                let attributes = dependency_attributes(&command).unwrap();
                assert!(attributes.modern);
                assert_eq!(attributes.flags, flags);
                assert_eq!(attributes.weak_link, flags & 1 != 0);
                assert_eq!(attributes.reexport, flags & 2 != 0);
                assert_eq!(attributes.upward, flags & 4 != 0);
                assert_eq!(attributes.delayed_init, flags & 8 != 0);
            }
        }
        for (kind, flags) in [
            (0xc, 0),
            (0x80000018, 1),
            (0x8000001f, 2),
            (0x80000023, 4),
            (0x20, 0),
        ] {
            let mut command = vec![0; 32];
            put32(&mut command, 0, kind);
            put32(&mut command, 8, 24);
            command[24..27].copy_from_slice(b"/a\0");
            let attributes = dependency_attributes(&command).unwrap();
            assert!(!attributes.modern);
            assert_eq!(attributes.flags, flags);
        }
    }
    #[test]
    fn modern_dependency_header_bounds_reserved_flags_and_names_are_checked() {
        let mut command = vec![0; 40];
        put32(&mut command, 0, 0xc);
        put32(&mut command, 8, 28);
        put32(&mut command, 12, 0x1a741800);
        command[28..31].copy_from_slice(b"/a\0");
        for offset in [24, 27, 32, 40] {
            let mut bad = command.clone();
            put32(&mut bad, 8, offset);
            assert!(dylib_identity(&bad).is_err());
        }
        for length in 24..=28 {
            assert!(dylib_identity(&command[..length]).is_err());
        }
        let mut bad = command.clone();
        put32(&mut bad, 24, 0x10);
        assert!(dylib_identity(&bad).is_err());
        assert!(dependency_attributes(&bad).is_err());
        let mut bad = command.clone();
        bad[28..].fill(b'x');
        assert!(dylib_identity(&bad).is_err());
        let mut bad = command.clone();
        bad[28] = 0xff;
        assert!(dylib_identity(&bad).is_err());
        let mut bad = command.clone();
        put32(&mut bad, 0, 0xd);
        assert!(dylib_identity(&bad).is_err());
    }
    #[test]
    fn modern_load_dylib_reexport_flag_drives_wholesale_lookup_without_changing_ordinals() {
        for flags in [0, 2, 3, 12, 14] {
            let d = tempfile::tempdir().unwrap();
            let _ = graph_fixture(
                d.path(),
                &[
                    ImageSpec {
                        path: "/main",
                        entries: vec![],
                        dependencies: vec![(0xc, "/forward")],
                    },
                    ImageSpec {
                        path: "/forward",
                        entries: vec![regular("_abs", 0)],
                        dependencies: vec![],
                    },
                ],
            );
            let path = d.path().join("cache");
            let mut bytes = std::fs::read(&path).unwrap();
            let at = 0x1000 + 360;
            let size = word(&bytes, at + 4).unwrap() as usize;
            bytes[at + 24..at + size].fill(0);
            put32(&mut bytes, at + 8, 28);
            put32(&mut bytes, at + 12, 0x1a741800);
            put32(&mut bytes, at + 24, flags);
            bytes[at + 28..at + 36].copy_from_slice(b"/forward");
            std::fs::write(&path, bytes).unwrap();
            let set = super::super::shared_cache::manifest_set(&path).unwrap();
            let mut resolver = CacheResolver::new(&set, BASE).unwrap();
            let dependency = resolver.image("/main").unwrap().dependencies[0].clone();
            let result = resolver.resolve("/main", "_abs", false).unwrap();
            assert_eq!(result.definition.is_some(), flags & 2 != 0);
            if flags & 2 != 0 {
                assert_eq!(result.definition.unwrap().provider_image, "/forward");
            } else {
                assert!(result.route.iter().all(|step| step.dependency.is_none()));
            }
            assert_eq!(dependency.kind, "load_dylib");
            assert_eq!(dependency.library_ordinal, 1);
            assert_eq!(dependency.attributes.flags, flags);
            assert_eq!(dependency.attributes.reexport, flags & 2 != 0);
        }
    }

    #[test]
    fn rejects_legacy_lazy_dependencies_instead_of_assigning_modern_ordinals() {
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[ImageSpec {
                path: "/main",
                entries: vec![regular("_abs", 0)],
                dependencies: vec![(0x20, "/legacy")],
            }],
        );
        let error = CacheResolver::new(&set, BASE)
            .unwrap()
            .resolve("/main", "_abs", false)
            .unwrap_err();
        assert!(error.to_string().contains("LC_LAZY_LOAD_DYLIB"));
    }

    #[test]
    fn refuses_forged_resolution_source_identity_and_modern_dependency_attributes() {
        let d = tempfile::tempdir().unwrap();
        let set = graph_fixture(
            d.path(),
            &[ImageSpec {
                path: "/main",
                entries: vec![regular("_abs", 0)],
                dependencies: vec![],
            }],
        );
        let mut context = CacheResolver::new(&set, BASE).unwrap();
        let mut result = context.resolve("/main", "_abs", false).unwrap();
        result.definition.as_mut().unwrap().address += 4;
        assert!(context.snapshot_resolved_function(&result).is_err());
        let mut command = vec![0; 32];
        put32(&mut command, 8, 24);
        command[24..27].copy_from_slice(b"/a\0");
        put32(&mut command, 12, 0x1a741800);
        assert!(dylib_identity(&command).is_err());
        put32(&mut command, 12, 0);
        put32(&mut command, 8, 16);
        assert!(dylib_identity(&command).is_err());
        let mut forged = set.clone();
        forged["images"] = json!([]);
        assert!(CacheResolver::new(&forged, BASE).is_err());
    }

    #[test]
    fn empty_original_segment_and_section_remain_metadata_without_code_coverage() {
        for (file_bytes, section_bytes, accepted) in [(0, 0, true), (1, 0, false), (0, 1, false)] {
            let directory = tempfile::tempdir().unwrap();
            let (path, _) = fixture(directory.path());
            let mut bytes = std::fs::read(&path).unwrap();
            let mut segment = vec![0; 152];
            put32(&mut segment, 0, 0x19);
            put32(&mut segment, 4, 152);
            segment[8..20].copy_from_slice(b"__DATA_CONST");
            put64(&mut segment, 24, IMAGE + 0x800);
            put64(&mut segment, 40, 0x280);
            put64(&mut segment, 48, file_bytes);
            put32(&mut segment, 56, 3);
            put32(&mut segment, 60, 3);
            put32(&mut segment, 64, 1);
            segment[72..79].copy_from_slice(b"__empty");
            segment[88..100].copy_from_slice(b"__DATA_CONST");
            put64(&mut segment, 104, IMAGE + 0x800);
            put64(&mut segment, 112, section_bytes);
            put32(&mut segment, 136, 6); // Empty non-lazy pointer section, as in original caches.
            let command_end = 0x1000 + 32 + word(&bytes, 0x1000 + 20).unwrap() as usize;
            bytes[command_end..command_end + segment.len()].copy_from_slice(&segment);
            let commands = word(&bytes, 0x1000 + 16).unwrap() + 1;
            put32(&mut bytes, 0x1000 + 16, commands);
            let command_bytes = word(&bytes, 0x1000 + 20).unwrap() + segment.len() as u32;
            put32(&mut bytes, 0x1000 + 20, command_bytes);
            std::fs::write(&path, bytes).unwrap();
            let set = super::super::shared_cache::manifest_set(&path).unwrap();
            let result = read(&set, NAME, BASE);
            if accepted {
                let image = result.unwrap();
                let empty = image
                    .segments
                    .iter()
                    .find(|s| s.name == "__DATA_CONST")
                    .unwrap();
                assert_eq!(
                    (
                        empty.bytes,
                        empty.file_bytes,
                        empty.file_offset,
                        empty.max_protection,
                        empty.initial_protection
                    ),
                    (0, 0, 0x280, 3, 3)
                );
                assert!(
                    image
                        .executable_ranges
                        .iter()
                        .all(|range| range.section != "__empty")
                );
                assert_eq!(
                    image.lookup("_abs").unwrap().unwrap().address,
                    Some(IMAGE + 0x400)
                );
            } else {
                assert!(result.is_err());
            }
        }
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
        image.reader.as_mut().unwrap().mappings[0].protection = 1;
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
