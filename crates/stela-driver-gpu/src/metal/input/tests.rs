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
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
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
