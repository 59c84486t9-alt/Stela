use super::*;
use crate::load_plan::{Dependency, EntryPoint, FileRange, GuestRange, Payload, SegmentPlan};

fn pointer(raw: u64, format: u16, imports: u32, preferred: u64, loaded: u64) -> Result<(u64, u64)> {
    let (decoded, next) = decode_pointer(raw, format, imports, preferred, loaded, false)?;
    match decoded {
        Pointer::Rebase(value) => Ok((value, next)),
        _ => bail!("test expected an unauthenticated rebase"),
    }
}

const BASE: u64 = 0x100000000;
const PAYLOAD: usize = 0x5000;
const SLOT: usize = 0x1028;
const RECORD: usize = 44;

fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn refresh(data: &[u8], image: &mut LoadPlan) {
    image.slice_sha256 = stela_formats::sha256(data);
    image.slice_bytes = data.len() as u64;
    for payload in &mut image.payloads {
        let start = payload.file.offset as usize;
        payload.sha256 = stela_formats::sha256(&data[start..start + payload.file.bytes as usize]);
    }
}
fn raw(format: u16, target: u64, high: u8, next: u64) -> u64 {
    let shift = if matches!(format, 1 | 9 | 12) { 43 } else { 36 };
    target | (u64::from(high) << shift) | (next << 51)
}
fn fixture(format: u16) -> (Vec<u8>, LoadPlan) {
    let mut data = vec![0u8; 0x6000];
    let header = &mut data[PAYLOAD..];
    put32(header, 4, 28);
    put32(header, 8, 68);
    put32(header, 12, 68);
    put32(header, 20, 1);
    put32(header, 28, 3);
    put32(header, 36, 16); // segment 1 record, relative to starts-in-image
    put32(header, RECORD, 24);
    put16(header, RECORD + 4, 4096);
    put16(header, RECORD + 6, format);
    put64(header, RECORD + 8, 0x4000);
    put16(header, RECORD + 20, 1);
    put16(header, RECORD + 22, 0x28);
    let target = if matches!(format, 1 | 2) {
        BASE + 0x4120
    } else {
        0x4120
    };
    put64(&mut data, SLOT, raw(format, target, 0, 0));
    let segment = |name: &str, guest, file, size| SegmentPlan {
        name: name.into(),
        guest: GuestRange {
            address: guest,
            bytes: size,
        },
        file: FileRange {
            offset: file,
            bytes: size,
        },
        zero_fill: GuestRange {
            address: guest + size,
            bytes: 0,
        },
        maximum_protection: 3,
        initial_protection: 3,
        flags: 0,
    };
    let mut image = LoadPlan {
        schema_version: 1,
        slice_sha256: String::new(),
        slice_bytes: 0,
        cpu_type: 0x100000c,
        cpu_subtype: if matches!(format, 1 | 9 | 12) { 2 } else { 0 },
        architecture: if matches!(format, 1 | 9 | 12) {
            "arm64e".into()
        } else {
            "arm64".into()
        },
        header_flags: 0,
        file_type: 2,
        dylib_identity: None,
        segments: vec![
            segment("__TEXT", BASE, 0, 0x1000),
            segment("__DATA", BASE + 0x4000, 0x1000, 0x4000),
            segment("__LINKEDIT", BASE + 0x8000, PAYLOAD as u64, 0x1000),
        ],
        entry: Some(EntryPoint {
            image_offset: 0,
            file_offset: 0,
            guest_address: BASE,
            stack_size: 0,
        }),
        dependencies: vec![],
        dylinker: None,
        rpaths: vec![],
        payloads: vec![Payload {
            command: COMMAND,
            role: "chained_fixups".into(),
            file: FileRange {
                offset: PAYLOAD as u64,
                bytes: 68,
            },
            sha256: String::new(),
        }],
        deferred_commands: vec![],
        execution_supported: false,
        unresolved_requirements: vec![],
    };
    refresh(&data, &mut image);
    (data, image)
}
fn imports(data: &mut [u8], image: &mut LoadPlan, format: u32, bits: u64, symbol: &[u8]) {
    let size = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => unreachable!(),
    };
    let symbols = 68 + size;
    let header = &mut data[PAYLOAD..];
    put32(header, 12, symbols as u32);
    put32(header, 16, 1);
    put32(header, 20, format);
    put64(header, 68, bits);
    header[symbols..symbols + symbol.len()].copy_from_slice(symbol);
    image.payloads[0].file.bytes = (symbols + symbol.len()) as u64;
    refresh(data, image);
}
fn error(data: &[u8], image: &LoadPlan) -> String {
    format!("{:#}", plan(data, image, BASE).unwrap_err())
}

#[test]
fn all_five_formats_relocate_slots_and_targets_in_both_directions() {
    for format in [1, 2, 6, 9, 12] {
        let (data, image) = fixture(format);
        for loaded in [BASE - 0x100000, BASE, BASE + 0x300000] {
            let planned = plan(&data, &image, loaded).unwrap();
            assert_eq!(planned.preferred_base, BASE);
            assert_eq!(planned.load_base, loaded);
            assert_eq!(planned.pointer_formats, [format]);
            assert_eq!(
                planned.rebases,
                [RebaseFixup {
                    segment_index: 1,
                    file_offset: SLOT as u64,
                    guest_address: loaded + 0x4028,
                    raw: u64_at(&data, SLOT).unwrap(),
                    value: loaded + 0x4120,
                    pointer_format: format
                }]
            );
        }
    }
}

#[test]
fn preserves_high8_bits_and_full_target_width() {
    for format in [1, 2, 6, 9, 12] {
        for high in [0u8, 1, 0x7f, 0xff] {
            let (mut data, mut image) = fixture(format);
            let target = if matches!(format, 1 | 2) {
                BASE + 0x4120
            } else {
                0x4120
            };
            put64(&mut data, SLOT, raw(format, target, high, 0));
            refresh(&data, &mut image);
            for loaded in [BASE - 0x100000, BASE + 0x100000] {
                let planned = plan(&data, &image, loaded).unwrap();
                assert_eq!(
                    planned.rebases[0].value,
                    (u64::from(high) << 56) + loaded + 0x4120
                );
            }
        }
    }
}

#[test]
fn walks_four_or_eight_byte_stride_and_supports_16k_pages() {
    for format in [1, 2, 6, 9, 12] {
        let (mut data, mut image) = fixture(format);
        let stride = if matches!(format, 1 | 9 | 12) { 8 } else { 4 };
        let gap = if stride == 8 { 16 } else { 12 };
        let target = if matches!(format, 1 | 2) { BASE } else { 0 };
        put64(
            &mut data,
            SLOT,
            raw(format, target + 0x4120, 0, gap / stride),
        );
        put64(
            &mut data,
            SLOT + gap as usize,
            raw(format, target + 0x4130, 0, 0),
        );
        put16(&mut data, PAYLOAD + RECORD + 4, 16384);
        refresh(&data, &mut image);
        let planned = plan(&data, &image, BASE).unwrap();
        assert_eq!(planned.rebases.len(), 2);
        assert_eq!(planned.rebases[1].file_offset, SLOT as u64 + gap);
        assert_eq!(planned.rebases[1].value, BASE + 0x4130);
    }
}

#[test]
fn empty_payload_absence_and_no_start_pages_are_explicit() {
    let (mut data, mut image) = fixture(6);
    put16(&mut data, PAYLOAD + RECORD + 22, 0xffff);
    refresh(&data, &mut image);
    let planned = plan(&data, &image, BASE).unwrap();
    assert!(planned.rebases.is_empty());
    assert_eq!(planned.pointer_formats, [6]);
    image.payloads.clear();
    let planned = plan(&data, &image, BASE + 0x100000).unwrap();
    assert!(planned.rebases.is_empty() && planned.pointer_formats.is_empty());
}

#[test]
fn validates_all_import_metadata_even_without_bind_slots() {
    for format in [1, 2, 3] {
        for ordinal in [0u64, 1, if format == 3 { 0xfffd } else { 0xfd }] {
            let (mut data, mut image) = fixture(6);
            image.dependencies.push(Dependency {
                command: 0xc,
                name: "libFixture.dylib".into(),
                timestamp: 0,
                current_version: 0,
                compatibility_version: 0,
            });
            imports(&mut data, &mut image, format, ordinal, b"_fixture\0");
            assert_eq!(plan(&data, &image, BASE).unwrap().rebases.len(), 1);
        }
    }
    for (format, bits, symbol, message) in [
        (1, 2, &b"_valid\0"[..], "library ordinal"),
        (1, 0xfc, &b"_valid\0"[..], "library ordinal"),
        (1, 100 << 9, &b"_valid\0"[..], "symbol offset"),
        (1, 0, &b"missing-nul"[..], "unterminated"),
        (1, 0, &b"\0"[..], "empty"),
        (3, 1 << 17, &b"_valid\0"[..], "reserved"),
    ] {
        let (mut data, mut image) = fixture(6);
        imports(&mut data, &mut image, format, bits, symbol);
        assert!(error(&data, &image).contains(message));
    }
}

#[test]
fn rejects_bind_and_auth_without_fabricating_plain_pointers() {
    for format in [1, 2, 6, 9, 12] {
        let (mut data, mut image) = fixture(format);
        imports(&mut data, &mut image, 1, 0, b"_fixture\0");
        put64(
            &mut data,
            SLOT,
            1 << if matches!(format, 1 | 9 | 12) { 62 } else { 63 },
        );
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("unsupported chained-fixup bind"));
        put64(
            &mut data,
            SLOT,
            (1 << if matches!(format, 1 | 9 | 12) { 62 } else { 63 }) | 1,
        );
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("ordinal 1 exceeds imports"));
    }
    for format in [1, 9, 12] {
        let (mut data, mut image) = fixture(format);
        put64(&mut data, SLOT, (1 << 63) | 0x4120);
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("unsupported authenticated"));
    }
}

#[test]
fn rejects_bad_headers_record_tables_and_unsupported_formats() {
    for (offset, value, message) in [
        (0, 1, "header version"),
        (4, 20, "header table offsets"),
        (8, 40, "segment table overlaps"),
        (12, 0xffff, "header table offsets"),
        (20, 0, "imports format"),
        (24, 1, "symbols format"),
        (28, 4, "segment count mismatch"),
        (36, 4, "record overlaps"),
        (RECORD, 0xffff, "record size"),
        (RECORD + 8, 0x8000, "segment offset"),
        (RECORD + 16, 1, "max_valid_pointer"),
    ] {
        let (mut data, mut image) = fixture(6);
        put32(&mut data, PAYLOAD + offset, value);
        refresh(&data, &mut image);
        assert!(
            error(&data, &image).contains(message),
            "offset={offset} error={}",
            error(&data, &image)
        );
    }
    for (offset, value, message) in [
        (4, 8192, "page size"),
        (6, 7, "pointer format"),
        (20, 0xffff, "page-start table"),
        (22, 0x8001, "multi-start"),
        (22, 0x29, "misaligned"),
    ] {
        let (mut data, mut image) = fixture(6);
        put16(&mut data, PAYLOAD + RECORD + offset, value);
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains(message));
    }
}

#[test]
fn rejects_page_escape_partial_slots_and_overlapping_writes() {
    for start in [4092u16, 4096] {
        let (mut data, mut image) = fixture(6);
        put16(&mut data, PAYLOAD + RECORD + 22, start);
        refresh(&data, &mut image);
        assert!(error(&data, &image).contains("slot escapes page"));
    }
    let (mut data, mut image) = fixture(6);
    put64(&mut data, SLOT, raw(6, 0x4120, 0, 1));
    refresh(&data, &mut image);
    assert!(error(&data, &image).contains("overlapping/duplicate chained-fixup file slots"));
    let (data, mut image) = fixture(6);
    image.segments[1].file.bytes = 0x2c;
    assert!(error(&data, &image).contains("not fully file-backed"));
    let (mut data, mut image) = fixture(6);
    put64(&mut data, SLOT, raw(6, 0x4120, 0, 0xfff));
    refresh(&data, &mut image);
    assert!(error(&data, &image).contains("slot escapes page"));
}

#[test]
fn duplicate_records_payloads_and_changed_identities_fail() {
    let (mut data, mut image) = fixture(6);
    image.payloads.push(image.payloads[0].clone());
    assert!(error(&data, &image).contains("duplicate chained-fixup payloads"));
    image.payloads.pop();
    data[SLOT] ^= 1;
    assert!(error(&data, &image).contains("image identity"));
    refresh(&data, &mut image);
    image.payloads[0].sha256 = "0".repeat(64);
    assert!(error(&data, &image).contains("payload differs"));
    refresh(&data, &mut image);
    put32(&mut data, PAYLOAD + 40, 16); // second metadata use of segment 1 record
    refresh(&data, &mut image);
    assert!(error(&data, &image).contains("duplicate chained-fixup segment records"));
}

#[test]
fn target_slide_and_offset_overflows_fail_without_wrapping() {
    for format in [1, 2] {
        let (mut data, mut image) = fixture(format);
        put64(&mut data, SLOT, 0);
        refresh(&data, &mut image);
        assert!(
            format!("{:#}", plan(&data, &image, BASE - 1).unwrap_err())
                .contains("target slide overflows")
        );
    }
    for format in [6, 9, 12] {
        let (data, image) = fixture(format);
        assert!(
            format!("{:#}", plan(&data, &image, u64::MAX - 16).unwrap_err())
                .contains("slide overflows")
                || format!("{:#}", plan(&data, &image, u64::MAX - 16).unwrap_err())
                    .contains("offset target overflows")
        );
    }
}

#[test]
fn pointer_bit_boundaries_reserved_fields_and_target_overflow_are_checked() {
    for format in [1, 2, 6, 9, 12] {
        let width = if matches!(format, 1 | 9 | 12) { 43 } else { 36 };
        let target = (1u64 << width) - 1;
        let encoded = raw(format, target, 0xa7, 0);
        let preferred = if matches!(format, 1 | 2) { 0 } else { BASE };
        assert_eq!(
            pointer(encoded, format, 0, preferred, 0).unwrap(),
            ((0xa7u64 << 56) | target, 0)
        );
    }
    for format in [2, 6] {
        assert!(
            format!("{:#}", pointer(1 << 44, format, 0, BASE, BASE).unwrap_err())
                .contains("reserved")
        );
    }
    for format in [6, 9, 12] {
        assert!(
            format!(
                "{:#}",
                pointer(raw(format, 32, 0, 0), format, 0, BASE, u64::MAX - 16).unwrap_err()
            )
            .contains("offset target overflows")
        );
    }
}

fn bind_raw(format: u16, import_index: u32, addend: i64, next: u64) -> u64 {
    if matches!(format, 1 | 9 | 12) {
        (1 << 62) | u64::from(import_index) | (((addend as u64) & 0x7ffff) << 32) | (next << 51)
    } else {
        (1 << 63) | u64::from(import_index) | (((addend as u64) & 0xff) << 24) | (next << 51)
    }
}

#[test]
fn decodes_all_bind_formats_import_addends_weak_flags_and_signed_extrema() {
    for pointer_format in [1, 2, 6, 9, 12] {
        let inline: &[i64] = if matches!(pointer_format, 1 | 9 | 12) {
            &[-262144, -1, 0, 1, 262143]
        } else {
            &[0, 1, 127, 128, 255]
        };
        for import_format in [1, 2, 3] {
            let table_addends: &[i64] = match import_format {
                1 => &[0],
                2 => &[i32::MIN as i64, -1, 0, i32::MAX as i64],
                _ => &[i64::MIN, -1, 0, i64::MAX],
            };
            for table_addend in table_addends {
                for inline_addend in inline {
                    let (mut data, mut image) = fixture(pointer_format);
                    let weak_bit = if import_format == 3 { 16 } else { 8 };
                    imports(
                        &mut data,
                        &mut image,
                        import_format,
                        1 << weak_bit,
                        b"_fixture\0",
                    );
                    match import_format {
                        2 => put32(&mut data, PAYLOAD + 72, *table_addend as u32),
                        3 => put64(&mut data, PAYLOAD + 76, *table_addend as u64),
                        _ => (),
                    }
                    let raw = bind_raw(pointer_format, 0, *inline_addend, 0);
                    put64(&mut data, SLOT, raw);
                    refresh(&data, &mut image);
                    let combined = i128::from(*table_addend) + i128::from(*inline_addend);
                    if let Ok(combined) = i64::try_from(combined) {
                        let decoded = decode(&data, &image, BASE + 0x100000).unwrap();
                        assert_eq!(
                            decoded.imports,
                            [Import {
                                library_ordinal: 0,
                                weak: true,
                                name: "_fixture".into(),
                                addend: *table_addend
                            }]
                        );
                        assert_eq!(
                            decoded.binds,
                            [BindFixup {
                                segment_index: 1,
                                file_offset: SLOT as u64,
                                guest_address: BASE + 0x104028,
                                raw,
                                pointer_format,
                                import_index: 0,
                                inline_addend: *inline_addend,
                                addend: combined
                            }]
                        );
                        assert!(decoded.rebases.is_empty());
                        assert_eq!(decoded.pointer_formats, [pointer_format]);
                        assert!(error(&data, &image).contains("unsupported chained-fixup bind"));
                    } else {
                        assert!(
                            format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                                .contains("bind addend overflows i64")
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_bind_rebase_chain_shares_slot_validation_and_retains_import_order() {
    for format in [1, 2, 6, 9, 12] {
        let (mut data, mut image) = fixture(format);
        imports(&mut data, &mut image, 1, 0, b"_fixture\0");
        let next = if matches!(format, 1 | 9 | 12) { 1 } else { 2 };
        let base = if matches!(format, 1 | 2) { BASE } else { 0 };
        put64(&mut data, SLOT, raw(format, base + 0x4120, 0, next));
        put64(&mut data, SLOT + 8, bind_raw(format, 0, 0, next));
        put64(&mut data, SLOT + 16, raw(format, base + 0x4130, 0, 0));
        refresh(&data, &mut image);
        let decoded = decode(&data, &image, BASE - 0x100000).unwrap();
        assert_eq!(decoded.rebases.len(), 2);
        assert_eq!(decoded.rebases[0].value, BASE - 0x100000 + 0x4120);
        assert_eq!(decoded.binds[0].file_offset, SLOT as u64 + 8);
        assert_eq!(decoded.rebases[1].file_offset, SLOT as u64 + 16);
        assert_eq!(decoded.imports[0].name, "_fixture");
        // A bind does not stop validation of later slots in the chain.
        put64(&mut data, SLOT + 8, bind_raw(format, 0, 0, 0xfff));
        refresh(&data, &mut image);
        assert!(
            format!("{:#}", decode(&data, &image, BASE).unwrap_err()).contains("slot escapes page")
        );
    }
}

#[test]
fn import_suffix_names_and_addend_records_keep_original_indices() {
    let (mut data, mut image) = fixture(6);
    let payload = &mut data[PAYLOAD..];
    put32(payload, 12, 84); // two eight-byte import/addend records
    put32(payload, 16, 2);
    put32(payload, 20, 2);
    put32(payload, 68, 1 << 9); // import 0 points to suffix "fixture"
    put32(payload, 72, (-7i32) as u32);
    put32(payload, 76, 1 << 8); // import 1 is weak and names "_fixture"
    put32(payload, 80, 11);
    payload[84..93].copy_from_slice(b"_fixture\0");
    image.payloads[0].file.bytes = 93;
    put64(&mut data, SLOT, bind_raw(6, 1, 255, 0));
    refresh(&data, &mut image);
    let decoded = decode(&data, &image, BASE).unwrap();
    assert_eq!(
        decoded.imports,
        [
            Import {
                library_ordinal: 0,
                weak: false,
                name: "fixture".into(),
                addend: -7
            },
            Import {
                library_ordinal: 0,
                weak: true,
                name: "_fixture".into(),
                addend: 11
            }
        ]
    );
    assert_eq!(decoded.binds[0].import_index, 1);
    assert_eq!(decoded.binds[0].inline_addend, 255);
    assert_eq!(decoded.binds[0].addend, 266);
}

#[test]
fn decoded_bind_reserved_bits_ordinals_pac_and_symbol_text_still_fail() {
    for format in [1, 2, 6, 9, 12] {
        let (mut data, mut image) = fixture(format);
        imports(&mut data, &mut image, 1, 0, b"_fixture\0");
        let reserved = match format {
            1 | 9 => 16,
            12 => 24,
            _ => 32,
        };
        put64(&mut data, SLOT, bind_raw(format, 0, 0, 0) | (1 << reserved));
        refresh(&data, &mut image);
        assert!(
            format!("{:#}", decode(&data, &image, BASE).unwrap_err()).contains("reserved bits")
        );
        put64(&mut data, SLOT, bind_raw(format, 1, 0, 0));
        refresh(&data, &mut image);
        assert!(
            format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                .contains("ordinal 1 exceeds imports")
        );
        if matches!(format, 1 | 9 | 12) {
            put64(&mut data, SLOT, bind_raw(format, 0, 0, 0) | (1 << 63));
            refresh(&data, &mut image);
            assert!(
                format!("{:#}", decode(&data, &image, BASE).unwrap_err())
                    .contains("unsupported authenticated")
            );
        }
    }
    let (mut data, mut image) = fixture(6);
    imports(&mut data, &mut image, 1, 0, &[0xff, 0]);
    assert!(format!("{:#}", decode(&data, &image, BASE).unwrap_err()).contains("non-UTF-8"));
}

fn auth_raw(
    _format: u16,
    target_or_ordinal: u32,
    bind: bool,
    key: u64,
    diversity: u16,
    address_diversity: bool,
    next: u64,
) -> u64 {
    (1 << 63)
        | (u64::from(bind) << 62)
        | u64::from(target_or_ordinal)
        | (u64::from(diversity) << 32)
        | (u64::from(address_diversity) << 48)
        | (key << 49)
        | (next << 51)
}
#[test]
fn authenticated_rebases_preserve_all_metadata_and_always_use_image_relative_targets() {
    use stela_contracts::pauth::Key;
    for format in [1, 9, 12] {
        for (key, domain) in [(0, Key::Ia), (1, Key::Ib), (2, Key::Da), (3, Key::Db)] {
            for diversity in [0, 0x1234, u16::MAX] {
                for address_diversity in [false, true] {
                    let (mut data, mut image) = fixture(format);
                    let raw = auth_raw(
                        format,
                        u32::MAX,
                        false,
                        key,
                        diversity,
                        address_diversity,
                        0,
                    );
                    put64(&mut data, SLOT, raw);
                    refresh(&data, &mut image);
                    assert!(error(&data, &image).contains("unsupported authenticated"));
                    let decoded = decode_authenticated(&data, &image, BASE + 0x100000).unwrap();
                    assert!(
                        decoded.rebases.is_empty()
                            && decoded.binds.is_empty()
                            && decoded.authenticated_binds.is_empty()
                    );
                    assert_eq!(
                        decoded.authenticated_rebases,
                        [AuthenticatedRebaseFixup {
                            segment_index: 1,
                            file_offset: SLOT as u64,
                            guest_address: BASE + 0x104028,
                            raw,
                            target: BASE + 0x100000 + u64::from(u32::MAX),
                            pointer_format: format,
                            authentication: Authentication {
                                key: domain,
                                diversity,
                                address_diversity
                            },
                        }]
                    );
                }
            }
        }
        let (mut data, mut image) = fixture(format);
        put64(&mut data, SLOT, auth_raw(format, 1, false, 0, 0, false, 0));
        refresh(&data, &mut image);
        assert!(decode_authenticated(&data, &image, u64::MAX).is_err());
    }
}
#[test]
fn authenticated_binds_keep_table_addends_reserved_bits_and_ordinal_checks() {
    for format in [1, 9, 12] {
        let (mut data, mut image) = fixture(format);
        imports(&mut data, &mut image, 2, 0, b"_fixture\0");
        put32(&mut data, PAYLOAD + 72, (-7i32) as u32);
        let raw = auth_raw(format, 0, true, 2, 0xffff, true, 0);
        put64(&mut data, SLOT, raw);
        refresh(&data, &mut image);
        let decoded = decode_authenticated(&data, &image, BASE).unwrap();
        assert!(
            decoded.rebases.is_empty()
                && decoded.authenticated_rebases.is_empty()
                && decoded.binds.is_empty()
        );
        assert_eq!(decoded.authenticated_binds[0].addend, -7);
        assert_eq!(
            decoded.authenticated_binds[0].authentication.key,
            stela_contracts::pauth::Key::Da
        );
        assert_eq!(
            decoded.authenticated_binds[0].authentication.diversity,
            u16::MAX
        );
        let context = stela_engine::pauth::Context::new(
            1,
            stela_engine::pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
        );
        assert!(decoded.sign_rebases(&context).is_err());
        for changed in [raw | 1, raw | (1 << if format == 12 { 24 } else { 16 })] {
            put64(&mut data, SLOT, changed);
            refresh(&data, &mut image);
            assert!(decode_authenticated(&data, &image, BASE).is_err());
        }
    }
}
#[test]
fn mixed_authenticated_chain_is_complete_and_signing_never_strips_or_invents_keys() {
    use stela_engine::pauth::Context;
    use stela_engine::pauth::Keys;
    let (mut data, mut image) = fixture(12);
    put64(&mut data, SLOT, raw(12, 0x4120, 0, 1));
    put64(
        &mut data,
        SLOT + 8,
        auth_raw(12, 0x4130, false, 0, 0x1234, true, 1),
    );
    put64(
        &mut data,
        SLOT + 16,
        auth_raw(12, 0x4140, false, 2, 0, false, 0),
    );
    refresh(&data, &mut image);
    let decoded = decode_authenticated(&data, &image, BASE).unwrap();
    assert_eq!(decoded.rebases.len(), 1);
    assert_eq!(decoded.authenticated_rebases.len(), 2);
    let ib_only = Context::new(7, Keys::from_ib_words(1, 2));
    assert!(decoded.sign_rebases(&ib_only).is_err());
    let full = Context::new(7, Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]));
    let signed = decoded.sign_rebases(&full).unwrap();
    assert_eq!(signed.rebases.len(), 1);
    assert_eq!(signed.address_space, 7);
    assert_eq!(signed.authenticated_rebases[0].modifier, 0x1234000100004030);
    for record in &signed.authenticated_rebases {
        let result = full
            .authenticate(
                record.fixup.authentication.key,
                record.value,
                record.modifier,
            )
            .unwrap();
        assert!(result.authenticated);
        assert_eq!(result.pointer, record.fixup.target);
    }
    // Null handling belongs to dyld's helper, not the PAC instruction.
    let mut null = decoded.clone();
    null.rebases.clear();
    null.authenticated_rebases.truncate(1);
    null.authenticated_rebases[0].target = 0;
    assert_eq!(
        null.sign_rebases(&ib_only).unwrap().authenticated_rebases[0].value,
        0
    );
    assert_ne!(full.sign(stela_contracts::pauth::Key::Ia, 0, 0).unwrap(), 0);
    assert_eq!(
        Authentication {
            key: stela_contracts::pauth::Key::Ia,
            diversity: 0x4321,
            address_diversity: true
        }
        .modifier(0xeeee123456789abc),
        0x4321123456789abc
    );
}

#[test]
fn library_metadata_needs_no_entry_and_legacy_plan_json_remains_unchanged() {
    let (data, mut image) = fixture(6);
    image.file_type = 6;
    image.entry = None;
    image.dylib_identity = Some(Dependency {
        command: 0xd,
        name: "@rpath/libFixture.dylib".into(),
        timestamp: 0,
        current_version: 0,
        compatibility_version: 0,
    });
    let decoded = decode(&data, &image, BASE).unwrap();
    assert_eq!(decoded.rebases.len(), 1);
    assert!(decoded.imports.is_empty() && decoded.binds.is_empty());
    let legacy = serde_json::to_value(plan(&data, &image, BASE).unwrap()).unwrap();
    let object = legacy.as_object().unwrap();
    assert_eq!(object.len(), 4);
    for field in ["preferred_base", "load_base", "pointer_formats", "rebases"] {
        assert!(object.contains_key(field));
    }
    assert!(!object.contains_key("imports") && !object.contains_key("binds"));
}
