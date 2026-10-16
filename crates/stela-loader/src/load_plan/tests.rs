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
    // The final aligned address has only three bytes of instructions.
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
