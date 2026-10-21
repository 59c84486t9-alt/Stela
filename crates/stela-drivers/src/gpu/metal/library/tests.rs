use super::*;
use alloc::{vec, vec::Vec};

fn tag(out: &mut Vec<u8>, name: &[u8; 4], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
}

fn u64_field(out: &mut [u8], at: usize, value: usize) {
    out[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

/// An original synthetic container. Its payload is only LLVM framing, not a
/// valid shader; AIR semantics are the LLVM reader/compiler's responsibility.
fn fixture(duplicate: bool) -> Vec<u8> {
    let mut module = vec![];
    for word in [LLVM_WRAPPER_MAGIC, 0, 20, 8, u32::MAX] {
        module.extend_from_slice(&word.to_le_bytes());
    }
    module.extend_from_slice(b"BC\xc0\xde\0\0\0\0");
    module.resize(32, 0);
    let mut entry = vec![0; 4];
    tag(&mut entry, b"NAME", b"kernel\0");
    if duplicate {
        tag(&mut entry, b"NAME", b"second\0");
    }
    tag(&mut entry, b"TYPE", &[2]);
    tag(&mut entry, b"HASH", &Sha256::digest(&module));
    tag(&mut entry, b"MDSZ", &(module.len() as u64).to_le_bytes());
    tag(&mut entry, b"OFFT", &[0; 24]);
    tag(&mut entry, b"VERS", &[2, 0, 8, 0, 4, 0, 0, 0]);
    tag(&mut entry, b"FUTR", &[0xa7, 0xb8, 0xc9]);
    entry.extend_from_slice(b"ENDT");
    let size = entry.len();
    entry[..4].copy_from_slice(&(size as u32).to_le_bytes());
    let mut data = vec![0; HEADER_BYTES];
    data[..4].copy_from_slice(b"MTLB");
    data[4..6].copy_from_slice(&0x8001u16.to_le_bytes());
    data[6..8].copy_from_slice(&2u16.to_le_bytes());
    data[8..10].copy_from_slice(&9u16.to_le_bytes());
    data[11] = 0x81;
    data[12] = 26;
    u64_field(&mut data, 24, HEADER_BYTES);
    u64_field(&mut data, 32, size);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&entry);
    // Header extension is not part of the four principal section spans.
    tag(&mut data, b"UUID", &[0x42; 16]);
    data.extend_from_slice(b"ENDT");
    let public = data.len();
    data.extend_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(b"ENDT");
    u64_field(&mut data, 40, public);
    u64_field(&mut data, 48, 8);
    let private = data.len();
    data.extend_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(b"ENDT");
    u64_field(&mut data, 56, private);
    u64_field(&mut data, 64, 8);
    let code = data.len();
    data.extend_from_slice(&module);
    u64_field(&mut data, 72, code);
    u64_field(&mut data, 80, module.len());
    let file_size = data.len();
    u64_field(&mut data, 16, file_size);
    data
}

#[test]
fn original_sections_and_unknown_tags_are_preserved() {
    let data = fixture(false);
    let library = Library::parse(&data).unwrap();
    assert_eq!(library.header.platform, 0x8001);
    assert_eq!(library.header.format, Version { major: 2, minor: 9 });
    assert_eq!(
        library.header.minimum_os,
        Version {
            major: 26,
            minor: 0
        }
    );
    let function = &library.functions()[0];
    assert_eq!(function.name, "kernel");
    assert_eq!(function.kind, 2);
    assert_eq!(function.air_version, Version { major: 2, minor: 8 });
    let future = function
        .tags
        .into_iter()
        .find(|tag| tag.as_ref().unwrap().name == *b"FUTR")
        .unwrap()
        .unwrap();
    assert_eq!(future.value, &[0xa7, 0xb8, 0xc9]);
    let uuid = library.header_extensions.unwrap().next().unwrap().unwrap();
    assert_eq!(uuid.name, *b"UUID");
    assert_eq!(uuid.value, &[0x42; 16]);
    assert!(function.public_metadata.unwrap().next().is_none());
    let air = function.air().unwrap();
    assert_eq!(air.cpu_type, Some(u32::MAX));
    assert_eq!(air.bitcode, b"BC\xc0\xde\0\0\0\0");
    let bitcode_at = function.module_offset + LLVM_WRAPPER_BYTES;
    assert_eq!(air.bitcode.as_ptr(), data[bitcode_at..].as_ptr());
}

#[test]
fn every_truncated_prefix_and_duplicate_required_tag_is_rejected() {
    let data = fixture(false);
    for end in 0..data.len() {
        assert!(Library::parse(&data[..end]).is_err(), "prefix {end}");
    }
    assert!(
        matches!(Library::parse(&fixture(true)).unwrap_err().kind, ErrorKind::DuplicateTag(tag) if tag == *b"NAME")
    );
}

#[test]
fn payload_integrity_is_checked_when_selected() {
    let mut data = fixture(false);
    let module_at = Library::parse(&data).unwrap().functions()[0].module_offset;
    data[module_at + 24] ^= 1;
    let library = Library::parse(&data).unwrap();
    let failure = library.functions()[0].air().unwrap_err();
    assert_eq!(failure, error(module_at, ErrorKind::Hash));
}

#[test]
fn overlapping_out_of_bounds_and_overflowed_sections_fail() {
    let mut data = fixture(false);
    let public = u64_at(&data, 40).unwrap();
    data[72..80].copy_from_slice(&public.to_le_bytes());
    assert_eq!(
        Library::parse(&data).unwrap_err().kind,
        ErrorKind::SectionOverlap
    );
    for field in [24, 32, 40, 48, 56, 64, 72, 80] {
        let mut data = fixture(false);
        data[field..field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Library::parse(&data).is_err(), "field {field}");
    }
}

#[test]
fn wrapper_offsets_versions_padding_and_magic_are_checked() {
    let data = fixture(false);
    let function = Library::parse(&data).unwrap().functions()[0];
    assert!(Air::parse(b"BC\xc0\xde").is_ok());
    for (at, word) in [(0, 0), (4, 1), (8, 0), (8, u32::MAX), (12, u32::MAX)] {
        let mut module = function.module.to_vec();
        module[at..at + 4].copy_from_slice(&word.to_le_bytes());
        assert!(Air::parse(&module).is_err(), "wrapper field {at}");
    }
    let mut module = function.module.to_vec();
    module[31] = 1;
    assert_eq!(Air::parse(&module).unwrap_err().kind, ErrorKind::Bitcode);
    let mut module = function.module.to_vec();
    module[20] = 0;
    assert_eq!(Air::parse(&module).unwrap_err().kind, ErrorKind::Bitcode);
}

#[test]
fn malformed_tag_and_metadata_offsets_never_escape_their_sections() {
    let base = fixture(false);
    let function = Library::parse(&base).unwrap().functions()[0];
    for name in [*b"OFFT", *b"VERS", *b"HASH", *b"MDSZ"] {
        let mut data = base.clone();
        let tag = function
            .tags
            .into_iter()
            .find(|tag| tag.as_ref().unwrap().name == name)
            .unwrap()
            .unwrap();
        data[tag.offset + 4..tag.offset + 6].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(Library::parse(&data).is_err());
    }
    let tag = function
        .tags
        .into_iter()
        .find(|tag| tag.as_ref().unwrap().name == *b"OFFT")
        .unwrap()
        .unwrap();
    for field in [0, 8, 16] {
        let mut data = base.clone();
        data[tag.offset + 6 + field..tag.offset + 14 + field]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Library::parse(&data).is_err());
    }
    let mut data = base.clone();
    data[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        Library::parse(&data).unwrap_err().kind,
        ErrorKind::FunctionCount
    );
}

#[test]
fn bounded_mutations_cannot_panic_or_allocate_from_an_unchecked_count() {
    let base = fixture(false);
    let mut random = 0x51ae_17d3u32;
    for _ in 0..10_000 {
        random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = random as usize % base.len();
        let mut data = base.clone();
        data[index] ^= (random >> 24) as u8 | 1;
        if let Ok(library) = Library::parse(&data) {
            for function in library.functions() {
                let _ = function.air();
            }
        }
    }
}
