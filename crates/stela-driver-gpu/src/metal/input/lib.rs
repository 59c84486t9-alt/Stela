//! Hosted, local C ownership boundary around the one canonical Metal parser.
//! This is input validation, never LLVM verification or a Metal device facade.
extern crate alloc;
#[path = "../library.rs"]
pub mod library;

use core::{mem, ptr, slice};
use library::{Air, Library};
use stela_crypto::{Sha256, digest::Digest};

const ABI: u32 = 1;
const MTLB: u32 = 1;
const RAW: u32 = 2;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: u32 = 256;
const OK: u32 = 0;
const INVALID: u32 = 1;
const ABI_MISMATCH: u32 = 2;
const LIMIT: u32 = 3;
const PARSE: u32 = 4;
const ALLOCATION: u32 = 5;
const INDEX: u32 = 6;
const NOT_ARCHIVE: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Limits {
    pub size: u32,
    pub abi: u32,
    pub kind: u32,
    pub max_entries: u32,
    pub max_bytes: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub size: u32,
    pub abi: u32,
    pub status: u32,
    pub parser_kind: u32,
    pub offset: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Info {
    pub size: u32,
    pub abi: u32,
    pub kind: u32,
    pub entry_count: u32,
    pub original_bytes: u64,
    pub original_sha256: [u8; 32],
    pub platform: u32,
    pub format_major: u32,
    pub format_minor: u32,
    pub library_kind: u32,
    pub target_os: u32,
    pub minimum_os_major: u32,
    pub minimum_os_minor: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    pub size: u32,
    pub abi: u32,
    pub kind: u32,
    pub air_major: u32,
    pub air_minor: u32,
    pub language_major: u32,
    pub language_minor: u32,
    pub reserved: u32,
    pub module_offset: u64,
    pub module_bytes: u64,
    pub module_sha256: [u8; 32],
}
/// Canonical tag counts/ranges; absence is (0,0,0), ENDT-only groups have
/// zero tags and four original bytes. This does not assert tag semantics.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryMetadata {
    pub size: u32,
    pub abi: u32,
    pub function_tags: u32,
    pub public_tags: u32,
    pub private_tags: u32,
    pub header_tags: u32,
    pub function_offset: u64,
    pub function_bytes: u64,
    pub public_offset: u64,
    pub public_bytes: u64,
    pub private_offset: u64,
    pub private_bytes: u64,
    pub header_offset: u64,
    pub header_bytes: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct View {
    pub size: u32,
    pub abi: u32,
    pub bytes: *const u8,
    pub length: u64,
    pub original_offset: u64,
}
struct OwnedEntry {
    name: String,
    info: Entry,
    metadata: EntryMetadata,
}
pub struct Input {
    bytes: Vec<u8>,
    info: Info,
    entries: Vec<OwnedEntry>,
}

fn parser_kind(kind: library::ErrorKind) -> u32 {
    use library::ErrorKind as K;
    match kind {
        K::Truncated => 1,
        K::Overflow => 2,
        K::Magic => 3,
        K::Version => 4,
        K::FileSize => 5,
        K::SectionOverlap => 6,
        K::FunctionCount => 7,
        K::TagSize => 8,
        K::DuplicateTag(_) => 9,
        K::MissingTag(_) => 10,
        K::Terminator => 11,
        K::Name => 12,
        K::Metadata => 13,
        K::Hash => 14,
        K::Bitcode => 15,
        K::Allocation => 16,
        K::ResourceLimit => 17,
    }
}
#[derive(Clone, Copy, Debug)]
struct Failure {
    status: u32,
    kind: u32,
    offset: u64,
}
impl From<library::Error> for Failure {
    fn from(e: library::Error) -> Self {
        Self {
            status: match e.kind {
                library::ErrorKind::Allocation => ALLOCATION,
                library::ErrorKind::ResourceLimit => LIMIT,
                _ => PARSE,
            },
            kind: parser_kind(e.kind),
            offset: e.offset as u64,
        }
    }
}
fn failure(status: u32) -> Failure {
    Failure {
        status,
        kind: 0,
        offset: 0,
    }
}
fn header<T>(size: u32, abi: u32) -> Result<(), Failure> {
    if size as usize != mem::size_of::<T>() || abi != ABI {
        Err(failure(ABI_MISMATCH))
    } else {
        Ok(())
    }
}
fn tag_facts(tags: Option<library::Tags<'_>>) -> Result<(u32, u64, u64), Failure> {
    let Some(tags) = tags else {
        return Ok((0, 0, 0));
    };
    let range = tags.range();
    let mut count = 0u32;
    for tag in tags {
        tag?;
        count = count.checked_add(1).ok_or_else(|| failure(LIMIT))?;
    }
    Ok((count, range.start as u64, range.len() as u64))
}
fn snapshot(data: &[u8], limits: Limits) -> Result<Input, Failure> {
    if limits.max_bytes == 0
        || limits.max_bytes > MAX_BYTES
        || limits.max_entries == 0
        || limits.max_entries > MAX_ENTRIES
        || !matches!(limits.kind, MTLB | RAW)
    {
        return Err(failure(INVALID));
    }
    if data.is_empty() || data.len() as u64 > limits.max_bytes {
        return Err(failure(LIMIT));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(data.len())
        .map_err(|_| failure(ALLOCATION))?;
    bytes.extend_from_slice(data);
    let mut info = Info {
        size: mem::size_of::<Info>() as u32,
        abi: ABI,
        kind: limits.kind,
        entry_count: 0,
        original_bytes: bytes.len() as u64,
        original_sha256: Sha256::digest(&bytes).into(),
        platform: 0,
        format_major: 0,
        format_minor: 0,
        library_kind: 0,
        target_os: 0,
        minimum_os_major: 0,
        minimum_os_minor: 0,
    };
    let mut entries = Vec::new();
    if limits.kind == MTLB {
        let archive = Library::parse_bounded(&bytes, limits.max_entries as usize)?;
        let header = tag_facts(archive.header_extensions)?;
        let h = archive.header;
        info.platform = h.platform.into();
        info.format_major = h.format.major.into();
        info.format_minor = h.format.minor.into();
        info.library_kind = h.kind.into();
        info.target_os = h.target_os.into();
        info.minimum_os_major = h.minimum_os.major.into();
        info.minimum_os_minor = h.minimum_os.minor.into();
        entries
            .try_reserve_exact(archive.functions().len())
            .map_err(|_| failure(ALLOCATION))?;
        for entry in archive.functions() {
            if entry.name.len() > 4096 || entries.iter().any(|e: &OwnedEntry| e.name == entry.name)
            {
                return Err(failure(INVALID));
            }
            let mut name = String::new();
            name.try_reserve_exact(entry.name.len())
                .map_err(|_| failure(ALLOCATION))?;
            name.push_str(entry.name);
            let range = entry.module_range();
            let function = tag_facts(Some(entry.tags))?;
            let public = tag_facts(entry.public_metadata)?;
            let private = tag_facts(entry.private_metadata)?;
            entries.push(OwnedEntry {
                name,
                metadata: EntryMetadata {
                    size: mem::size_of::<EntryMetadata>() as u32,
                    abi: ABI,
                    function_tags: function.0,
                    public_tags: public.0,
                    private_tags: private.0,
                    header_tags: header.0,
                    function_offset: function.1,
                    function_bytes: function.2,
                    public_offset: public.1,
                    public_bytes: public.2,
                    private_offset: private.1,
                    private_bytes: private.2,
                    header_offset: header.1,
                    header_bytes: header.2,
                },
                info: Entry {
                    size: mem::size_of::<Entry>() as u32,
                    abi: ABI,
                    kind: entry.kind.into(),
                    air_major: entry.air_version.major.into(),
                    air_minor: entry.air_version.minor.into(),
                    language_major: entry.language_version.major.into(),
                    language_minor: entry.language_version.minor.into(),
                    reserved: 0,
                    module_offset: range.start as u64,
                    module_bytes: range.len() as u64,
                    module_sha256: *entry.digest,
                },
            });
        }
        info.entry_count = entries.len() as u32;
    } else {
        Air::parse(&bytes)?;
    }
    Ok(Input {
        bytes,
        info,
        entries,
    })
}
impl Input {
    fn entry(&self, index: u32) -> Result<&OwnedEntry, Failure> {
        if self.info.kind != MTLB {
            return Err(failure(NOT_ARCHIVE));
        }
        self.entries
            .get(index as usize)
            .ok_or_else(|| failure(INDEX))
    }
    fn air(&self, index: u32) -> Result<&[u8], Failure> {
        if self.info.kind == RAW {
            if index != 0 {
                return Err(failure(INDEX));
            }
            return Ok(Air::parse(&self.bytes)?.bitcode);
        }
        let entry = self.entry(index)?;
        // Use the canonical selected-entry hash/framing check, not a second parser.
        let archive = Library::parse(&self.bytes)?;
        let function = &archive.functions()[index as usize];
        debug_assert_eq!(function.name, entry.name);
        Ok(function.air()?.bitcode)
    }
}
fn finish(error: *mut Error, result: Result<(), Failure>) -> u32 {
    let f = result.err().unwrap_or(failure(OK));
    if !error.is_null() {
        // SAFETY: each exported caller guarantees complete writable error storage.
        unsafe {
            error.write(Error {
                size: mem::size_of::<Error>() as u32,
                abi: ABI,
                status: f.status,
                parser_kind: f.kind,
                offset: f.offset,
            })
        };
    }
    f.status
}

/// # Safety
/// Valid readable limits/input and writable empty owning output/error slots;
/// disjoint storage, exact indicated bounds, no concurrent mutation/destruction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_open(
    limits: *const Limits,
    data: *const u8,
    length: u64,
    output: *mut *mut Input,
    error: *mut Error,
) -> u32 {
    finish(
        error,
        (|| {
            if limits.is_null() || output.is_null() || data.is_null() {
                return Err(failure(INVALID));
            }
            // SAFETY: caller supplies complete limits/output records.
            let limits = unsafe { *limits };
            header::<Limits>(limits.size, limits.abi)?;
            if length == 0
                || length > limits.max_bytes
                || length > MAX_BYTES
                || length > isize::MAX as u64
            {
                return Err(failure(LIMIT));
            }
            // SAFETY: the caller supplies a complete, writable output slot.
            if !unsafe { *output }.is_null() {
                return Err(failure(INVALID));
            }
            // SAFETY: bounded caller-owned immutable input for this call only.
            let input = snapshot(
                unsafe { slice::from_raw_parts(data, length as usize) },
                limits,
            )?;
            // A process OOM/panic never unwinds through C: the isolated helper fails.
            // SAFETY: the caller supplies a complete, writable output slot, checked empty above.
            unsafe { output.write(Box::into_raw(Box::new(input))) };
            Ok(())
        })(),
    )
}

/// # Safety
/// Live kept input and disjoint complete initialized output/error records;
/// no destruction may race this call or subsequent borrowed-view use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_info(
    input: *const Input,
    out: *mut Info,
    error: *mut Error,
) -> u32 {
    finish(
        error,
        (|| {
            if input.is_null() || out.is_null() {
                return Err(failure(INVALID));
            }
            // SAFETY: complete caller-owned output header, kept immutable input.
            let (i, o) = unsafe { (&*input, &*out) };
            header::<Info>(o.size, o.abi)?;
            // SAFETY: `out` is the caller's complete record, whose header was checked above.
            unsafe { out.write(i.info) };
            Ok(())
        })(),
    )
}
/// # Safety
/// Same storage/lifetime contract as stela_metal_input_info.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_entry(
    input: *const Input,
    index: u32,
    out: *mut Entry,
    error: *mut Error,
) -> u32 {
    finish(
        error,
        (|| {
            if input.is_null() || out.is_null() {
                return Err(failure(INVALID));
            }
            // SAFETY: `input` is a live handle and `out` a complete caller-owned record,
            // per this function's contract.
            let (i, o) = unsafe { (&*input, &*out) };
            header::<Entry>(o.size, o.abi)?;
            let value = i.entry(index)?.info;
            // SAFETY: `out` is the caller's complete record, whose header was checked above.
            unsafe { out.write(value) };
            Ok(())
        })(),
    )
}
/// # Safety
/// Same storage/lifetime contract as stela_metal_input_info. Facts are from the
/// canonical parser, not reflection validation; raw AIR has no archive facts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_entry_metadata(
    input: *const Input,
    index: u32,
    out: *mut EntryMetadata,
    error: *mut Error,
) -> u32 {
    finish(
        error,
        (|| {
            if input.is_null() || out.is_null() {
                return Err(failure(INVALID));
            }
            // SAFETY: `input` is a live handle and `out` a complete caller-owned record,
            // per this function's contract.
            let (i, o) = unsafe { (&*input, &*out) };
            header::<EntryMetadata>(o.size, o.abi)?;
            let value = i.entry(index)?.metadata;
            // SAFETY: `out` is the caller's complete record, whose header was checked above.
            unsafe { out.write(value) };
            Ok(())
        })(),
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewKind {
    Name,
    Air,
    Original,
}
unsafe fn view(
    input: *const Input,
    index: u32,
    out: *mut View,
    error: *mut Error,
    kind: ViewKind,
) -> u32 {
    finish(
        error,
        (|| {
            if input.is_null() || out.is_null() {
                return Err(failure(INVALID));
            }
            // SAFETY: `input` is a live handle and `out` a complete caller-owned record,
            // per this function's contract.
            let (i, o) = unsafe { (&*input, &*out) };
            header::<View>(o.size, o.abi)?;
            let bytes = match kind {
                ViewKind::Name => i.entry(index)?.name.as_bytes(),
                ViewKind::Air => i.air(index)?,
                ViewKind::Original => &i.bytes,
            };
            // SAFETY: `out` is the caller's complete record, whose header was checked above.
            unsafe {
                out.write(View {
                    size: mem::size_of::<View>() as u32,
                    abi: ABI,
                    bytes: bytes.as_ptr(),
                    length: bytes.len() as u64,
                    original_offset: if kind == ViewKind::Name {
                        u64::MAX
                    } else {
                        (bytes.as_ptr().addr() - i.bytes.as_ptr().addr()) as u64
                    },
                })
            };
            Ok(())
        })(),
    )
}
/// # Safety
/// Same storage/lifetime contract as stela_metal_input_info; returned name is
/// borrowed UTF-8 (not NUL terminated), immutable until input destruction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_name(
    input: *const Input,
    index: u32,
    out: *mut View,
    error: *mut Error,
) -> u32 {
    // SAFETY: the caller upholds `stela_metal_input_info`'s contract, which is `view`'s.
    unsafe { view(input, index, out, error, ViewKind::Name) }
}
/// # Safety
/// Same storage/lifetime contract as stela_metal_input_info. Raw byte framing is
/// not LLVM semantic verification; use the real shared inspector before objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_air(
    input: *const Input,
    index: u32,
    out: *mut View,
    error: *mut Error,
) -> u32 {
    // SAFETY: the caller upholds `stela_metal_input_info`'s contract, which is `view`'s.
    unsafe { view(input, index, out, error, ViewKind::Air) }
}
/// # Safety
/// Same storage/lifetime contract as stela_metal_input_info. The entire original
/// container/wrapper is borrowed without stripping unknown fields or framing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_original(
    input: *const Input,
    out: *mut View,
    error: *mut Error,
) -> u32 {
    // SAFETY: the caller upholds `stela_metal_input_info`'s contract, which is `view`'s.
    unsafe { view(input, 0, out, error, ViewKind::Original) }
}
/// # Safety
/// Slot is null or writable and uniquely owns its live handle. All borrowed
/// views/accesses have ended; no concurrent call, copied owner or foreign handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_metal_input_destroy(slot: *mut *mut Input) {
    if !slot.is_null() {
        // SAFETY: the caller passes a writable slot that uniquely owns its handle.
        let input = unsafe { slot.replace(ptr::null_mut()) };
        if !input.is_null() {
            // SAFETY: the slot held the handle `stela_metal_input_open` boxed; no borrowed view
            // outlives it.
            unsafe { drop(Box::from_raw(input)) };
        }
    }
}

#[cfg(test)]
mod tests;
