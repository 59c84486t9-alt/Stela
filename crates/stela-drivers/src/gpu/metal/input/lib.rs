//! Hosted, local C ownership boundary around the one canonical Metal parser.
//! This is input validation, never LLVM verification or a Metal device facade.
extern crate alloc;
#[path = "../library.rs"]
pub mod library;

use core::{mem, ptr, slice};
use library::{Air, Library};
use sha2::{Digest, Sha256};

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
mod tests {
    use super::*;
    fn limits(kind: u32) -> Limits {
        Limits {
            size: mem::size_of::<Limits>() as u32,
            abi: ABI,
            kind,
            max_entries: 8,
            max_bytes: 4096,
        }
    }
    fn tag(out: &mut Vec<u8>, key: &[u8; 4], value: &[u8]) {
        out.extend_from_slice(key);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
    }
    // Original synthetic MTLB framing; its bytes are not LLVM IR.
    fn archive(duplicate: bool) -> Vec<u8> {
        archive_metadata(duplicate, None, None, None, None)
    }
    fn archive_metadata(
        duplicate: bool,
        function: Option<&[u8; 4]>,
        public: Option<&[u8; 4]>,
        private: Option<&[u8; 4]>,
        header: Option<&[u8; 4]>,
    ) -> Vec<u8> {
        let module = b"BC\xc0\xde0123";
        let mut records = Vec::new();
        for _ in 0..if duplicate { 2 } else { 1 } {
            let mut r = vec![0; 4];
            for (key, value) in [
                (b"NAME", b"kernel\0".as_slice()),
                (b"TYPE", &[2]),
                (b"HASH", Sha256::digest(module).as_slice()),
                (b"MDSZ", &8u64.to_le_bytes()),
                (b"OFFT", &[0; 24]),
                (b"VERS", &[2, 0, 9, 0, 4, 0, 1, 0]),
            ] {
                tag(&mut r, key, value);
            }
            if let Some(key) = function {
                tag(&mut r, key, b"fact");
            }
            r.extend_from_slice(b"ENDT");
            let size = r.len() as u32;
            r[..4].copy_from_slice(&size.to_le_bytes());
            records.extend_from_slice(&r);
        }
        let mut data = vec![0; 88];
        data[..4].copy_from_slice(b"MTLB");
        data[6] = 2;
        data[8] = 9;
        data[24..32].copy_from_slice(&88u64.to_le_bytes());
        data[32..40].copy_from_slice(&(records.len() as u64).to_le_bytes());
        data.extend_from_slice(&(if duplicate { 2u32 } else { 1u32 }).to_le_bytes());
        data.extend_from_slice(&records);
        if let Some(key) = header {
            tag(&mut data, key, b"identity");
            data.extend_from_slice(b"ENDT");
        }
        for (field, key) in [(40, public), (56, private)] {
            let start = data.len() as u64;
            data[field..field + 8].copy_from_slice(&start.to_le_bytes());
            if let Some(key) = key {
                let mut group = vec![0; 4];
                if key != b"NONE" {
                    tag(&mut group, key, b"fact");
                }
                group.extend_from_slice(b"ENDT");
                let size = group.len() as u32;
                group[..4].copy_from_slice(&size.to_le_bytes());
                data[field + 8..field + 16].copy_from_slice(&(group.len() as u64).to_le_bytes());
                data.extend_from_slice(&group);
            }
        }
        let code = data.len() as u64;
        data[72..80].copy_from_slice(&code.to_le_bytes());
        data[80..88].copy_from_slice(&8u64.to_le_bytes());
        data.extend_from_slice(module);
        let size = data.len() as u64;
        data[16..24].copy_from_slice(&size.to_le_bytes());
        data
    }
    fn empty_view() -> View {
        View {
            size: mem::size_of::<View>() as u32,
            abi: ABI,
            bytes: ptr::null(),
            length: 0,
            original_offset: 0,
        }
    }
    #[test]
    fn owned_snapshot_and_local_c_abi_keep_bytes_after_source_mutation() {
        let mut source = b"BC\xc0\xde0123".to_vec();
        let mut input = ptr::null_mut();
        let mut view = empty_view();
        // SAFETY: exact readable input and disjoint initialized owning outputs.
        unsafe {
            assert_eq!(
                stela_metal_input_open(
                    &limits(RAW),
                    source.as_ptr(),
                    source.len() as u64,
                    &mut input,
                    ptr::null_mut()
                ),
                OK
            );
            source.fill(0);
            assert_eq!(
                stela_metal_input_air(input, 0, &mut view, ptr::null_mut()),
                OK
            );
            assert_eq!(
                slice::from_raw_parts(view.bytes, view.length as usize),
                b"BC\xc0\xde0123"
            );
            assert_eq!(
                stela_metal_input_name(input, 0, &mut view, ptr::null_mut()),
                NOT_ARCHIVE
            );
            assert_eq!(
                slice::from_raw_parts(view.bytes, view.length as usize),
                b"BC\xc0\xde0123"
            );
            stela_metal_input_destroy(&mut input);
            assert!(input.is_null());
            stela_metal_input_destroy(&mut input);
            stela_metal_input_destroy(ptr::null_mut());
        }
    }
    #[test]
    fn archive_entries_use_original_ranges_and_selected_digest() {
        let bytes = archive(false);
        let input = snapshot(&bytes, limits(MTLB)).unwrap();
        assert_eq!(input.entries[0].name, "kernel");
        assert_eq!(input.entries[0].info.kind, 2);
        assert_eq!(input.entries[0].info.language_minor, 1);
        assert_eq!(input.air(0).unwrap(), b"BC\xc0\xde0123");
        let start = input.entries[0].info.module_offset as usize;
        assert_eq!(&input.bytes[start..], input.air(0).unwrap());
        let mut view = empty_view();
        // SAFETY: live immutable owner and disjoint complete output record.
        unsafe {
            assert_eq!(
                stela_metal_input_original(&input, &mut view, ptr::null_mut()),
                OK
            );
            assert_eq!(view.original_offset, 0);
            assert_eq!(
                slice::from_raw_parts(view.bytes, view.length as usize),
                bytes
            );
        }
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let input = snapshot(&corrupt, limits(MTLB)).unwrap();
        assert_eq!(input.air(0).unwrap_err().kind, 14);
        assert_eq!(
            snapshot(&archive(true), limits(MTLB)).err().unwrap().status,
            INVALID
        );
    }
    #[test]
    fn limits_abi_and_failures_never_publish_handles_or_overwrite_views() {
        let data = b"BC\xc0\xde0123";
        let mut input = ptr::null_mut();
        let mut bad = limits(RAW);
        bad.abi = ABI + 1;
        let mut error = Error {
            size: 0,
            abi: 0,
            status: 0,
            parser_kind: 0,
            offset: 0,
        };
        // SAFETY: complete local initialized slots and bounded source.
        unsafe {
            assert_eq!(
                stela_metal_input_open(&bad, data.as_ptr(), 8, &mut input, &mut error),
                ABI_MISMATCH
            );
            assert!(input.is_null());
            assert_eq!(error.status, ABI_MISMATCH);
            bad = limits(RAW);
            bad.max_bytes = 7;
            assert_eq!(
                stela_metal_input_open(&bad, data.as_ptr(), 8, &mut input, &mut error),
                LIMIT
            );
            assert!(input.is_null());
            bad = limits(RAW);
            assert_eq!(
                stela_metal_input_open(&bad, data.as_ptr(), u64::MAX, &mut input, &mut error),
                LIMIT
            );
            assert_eq!(
                stela_metal_input_open(&bad, ptr::null(), 8, &mut input, &mut error),
                INVALID
            );
            assert_eq!(
                stela_metal_input_open(&bad, data.as_ptr(), 8, &mut input, &mut error),
                OK
            );
            let original = input;
            assert_eq!(
                stela_metal_input_open(&bad, data.as_ptr(), 8, &mut input, &mut error),
                INVALID
            );
            assert_eq!(input, original);
            let mut view = empty_view();
            view.abi = 99;
            view.length = 123;
            assert_eq!(
                stela_metal_input_air(input, 0, &mut view, &mut error),
                ABI_MISMATCH
            );
            assert_eq!(view.length, 123);
            view.abi = ABI;
            assert_eq!(
                stela_metal_input_air(input, 1, &mut view, &mut error),
                INDEX
            );
            assert_eq!(view.length, 123);
            stela_metal_input_destroy(&mut input);
        }
        for end in 0..archive(false).len() {
            assert!(snapshot(&archive(false)[..end], limits(MTLB)).is_err());
        }
    }

    fn empty_metadata() -> EntryMetadata {
        EntryMetadata {
            size: mem::size_of::<EntryMetadata>() as u32,
            abi: ABI,
            function_tags: 0,
            public_tags: 0,
            private_tags: 0,
            header_tags: 0,
            function_offset: 0,
            function_bytes: 0,
            public_offset: 0,
            public_bytes: 0,
            private_offset: 0,
            private_bytes: 0,
            header_offset: 0,
            header_bytes: 0,
        }
    }
    #[test]
    fn metadata_facts_keep_unknown_tags_original_ranges_and_absence() {
        let bytes = archive_metadata(
            false,
            Some(b"FUTR"),
            Some(b"CNST"),
            Some(b"DEBI"),
            Some(b"UUID"),
        );
        let parsed = Library::parse(&bytes).unwrap();
        let input = snapshot(&bytes, limits(MTLB)).unwrap();
        let mut facts = empty_metadata();
        // SAFETY: `input` is a live local handle and `facts` a complete local record.
        unsafe {
            assert_eq!(
                stela_metal_input_entry_metadata(&input, 0, &mut facts, ptr::null_mut()),
                OK
            );
        }
        assert_eq!(
            (
                facts.function_tags,
                facts.public_tags,
                facts.private_tags,
                facts.header_tags
            ),
            (7, 1, 1, 1)
        );
        for (offset, len, tags) in [
            (
                facts.function_offset,
                facts.function_bytes,
                Some(parsed.functions()[0].tags),
            ),
            (
                facts.public_offset,
                facts.public_bytes,
                parsed.functions()[0].public_metadata,
            ),
            (
                facts.private_offset,
                facts.private_bytes,
                parsed.functions()[0].private_metadata,
            ),
            (
                facts.header_offset,
                facts.header_bytes,
                parsed.header_extensions,
            ),
        ] {
            let range = tags.unwrap().range();
            assert_eq!((offset as usize, len as usize), (range.start, range.len()));
            assert_eq!(&input.bytes[range.end - 4..range.end], b"ENDT");
        }
        let prior = facts;
        // SAFETY: `input` is a live local handle and `facts` a complete local record.
        unsafe {
            assert_eq!(
                stela_metal_input_entry_metadata(&input, 1, &mut facts, ptr::null_mut()),
                INDEX
            );
            assert_eq!(facts, prior);
            facts.abi = 99;
            assert_eq!(
                stela_metal_input_entry_metadata(&input, 0, &mut facts, ptr::null_mut()),
                ABI_MISMATCH
            );
            assert_eq!(facts.function_tags, 7);
            facts.abi = ABI;
            let raw = snapshot(b"BC\xc0\xde0123", limits(RAW)).unwrap();
            assert_eq!(
                stela_metal_input_entry_metadata(&raw, 0, &mut facts, ptr::null_mut()),
                NOT_ARCHIVE
            );
            assert_eq!(facts, prior);
        }
        let absent = snapshot(&archive(false), limits(MTLB)).unwrap().entries[0].metadata;
        assert_eq!(
            (
                absent.function_tags,
                absent.public_bytes,
                absent.private_bytes,
                absent.header_bytes
            ),
            (6, 0, 0, 0)
        );
        let empty = snapshot(
            &archive_metadata(false, None, Some(b"NONE"), Some(b"NONE"), None),
            limits(MTLB),
        )
        .unwrap()
        .entries[0]
            .metadata;
        assert_eq!(
            (
                empty.public_tags,
                empty.private_tags,
                empty.public_bytes,
                empty.private_bytes
            ),
            (0, 0, 4, 4)
        );
        assert!(empty.public_offset > 0 && empty.private_offset > empty.public_offset);
    }

    // Deny/count large allocations in THIS test thread only; production allocation
    // remains normal hosted Rust. No allocation may reach even this denial point
    // for an otherwise framed large-count table exceeding the caller's entry cap.
    struct TestAllocator;
    std::thread_local! {
        static DENY_LARGE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        static DENIED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    #[global_allocator]
    static ALLOCATOR: TestAllocator = TestAllocator;
    // SAFETY: every call forwards to `System`, or returns null to refuse.
    unsafe impl std::alloc::GlobalAlloc for TestAllocator {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            if layout.size() >= 1024 * 1024 && DENY_LARGE.try_with(|v| v.get()).unwrap_or(false) {
                let _ = DENIED.try_with(|v| v.set(v.get() + 1));
                return ptr::null_mut();
            }
            // SAFETY: the caller guarantees a nonzero size, as `GlobalAlloc::alloc` requires.
            unsafe { std::alloc::System.alloc(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: the caller passes a block from this allocator with `layout`, as `dealloc` requires.
            unsafe {
                std::alloc::System.dealloc(pointer, layout);
            }
        }
        unsafe fn realloc(
            &self,
            pointer: *mut u8,
            layout: std::alloc::Layout,
            size: usize,
        ) -> *mut u8 {
            if size >= 1024 * 1024 && DENY_LARGE.try_with(|v| v.get()).unwrap_or(false) {
                let _ = DENIED.try_with(|v| v.set(v.get() + 1));
                return ptr::null_mut();
            }
            // SAFETY: the caller passes a block from this allocator with `layout`, as `realloc`
            // requires.
            unsafe { std::alloc::System.realloc(pointer, layout, size) }
        }
    }
    #[test]
    fn function_budget_precedes_table_allocation_and_keeps_c_limit_status() {
        // A million minimal framed slots would request >100MiB of Function storage.
        // They need not parse: resource refusal must precede both reserve and tags.
        let count = 1_000_000usize;
        let mut bytes = vec![0; 88 + 4 + count * 8];
        bytes[..4].copy_from_slice(b"MTLB");
        bytes[6] = 2;
        let size = bytes.len() as u64;
        bytes[16..24].copy_from_slice(&size.to_le_bytes());
        bytes[24..32].copy_from_slice(&88u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&((count * 8) as u64).to_le_bytes());
        for field in [40, 56, 72] {
            bytes[field..field + 8].copy_from_slice(&size.to_le_bytes());
        }
        bytes[88..92].copy_from_slice(&(count as u32).to_le_bytes());
        DENIED.set(0);
        DENY_LARGE.set(true);
        let result = Library::parse_bounded(&bytes, 256);
        DENY_LARGE.set(false);
        assert_eq!(
            DENIED.get(),
            0,
            "function table reserve was attempted before the limit"
        );
        let error = result.unwrap_err();
        assert_eq!(
            error,
            library::Error {
                offset: 88,
                kind: library::ErrorKind::ResourceLimit
            }
        );
        let failure = Failure::from(error);
        assert_eq!(
            (failure.status, failure.kind, failure.offset),
            (LIMIT, 17, 88)
        );
        let mut low = limits(MTLB);
        low.max_entries = 1;
        assert_eq!(snapshot(&archive(true), low).err().unwrap().status, LIMIT);
        assert!(Library::parse(&archive(false)).is_ok());
    }
}
