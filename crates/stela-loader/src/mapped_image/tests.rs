use super::*;

#[test]
fn raw_kernel_mapping_preserves_unfixed_data_and_delays_read_only_flags() -> Result<()> {
    use load_plan::{FileRange, GuestRange, Payload, SegmentPlan};
    let data = vec![0x71; 16];
    let plan = LoadPlan {
        schema_version: 1,
        file_type: 7,
        dylib_identity: None,
        slice_sha256: stela_runtime::sha256(&data),
        slice_bytes: 16,
        cpu_type: 0x100000c,
        cpu_subtype: 0x80000002,
        architecture: "arm64e".into(),
        header_flags: 0,
        segments: vec![
            SegmentPlan {
                name: "__TEXT".into(),
                guest: GuestRange {
                    address: 0,
                    bytes: 0x4000,
                },
                file: FileRange {
                    offset: 0,
                    bytes: 4,
                },
                zero_fill: GuestRange {
                    address: 4,
                    bytes: 0x3ffc,
                },
                maximum_protection: 5,
                initial_protection: 5,
                flags: 0,
            },
            SegmentPlan {
                name: "__DATA_CONST".into(),
                guest: GuestRange {
                    address: 0x4000,
                    bytes: 0x4000,
                },
                file: FileRange {
                    offset: 4,
                    bytes: 12,
                },
                zero_fill: GuestRange {
                    address: 0x400c,
                    bytes: 0x3ff4,
                },
                maximum_protection: 3,
                initial_protection: 3,
                flags: 16,
            },
        ],
        entry: None,
        dependencies: vec![],
        dylinker: None,
        rpaths: vec![],
        payloads: vec![],
        deferred_commands: vec![],
        execution_supported: false,
        unresolved_requirements: vec![],
    };
    let base = 0x410000000000;
    let fixed = prepare_segments(&data, &plan, base, &[])?;
    assert!(!fixed.specs[1].writable);
    let raw = prepare_raw_segments(&data, &plan, base)?;
    assert!(raw.specs[1].writable);
    assert_eq!(raw.specs[1].initial_bytes, data[4..]);
    assert_eq!(raw.data_limits.len(), 1);
    assert!(raw.data_limits[0].writable);
    assert_eq!(raw.code[0], (base, data[..4].to_vec()));
    let mut memory = OwnedMemory::map_with_data_limits(raw.specs, raw.data_limits)?;
    memory.write(base + 0x4000, &[1, 2, 3, 4])?;
    memory.protect_data(base + 0x4000, 0x4000, true, false)?;
    assert_eq!(memory.read_snapshot(base + 0x4000, 4)?, [1, 2, 3, 4]);
    assert!(memory.write(base + 0x4000, &[9]).is_err());
    assert_eq!(data, [0x71; 16]);
    let mut legacy = plan;
    legacy.payloads.push(Payload {
        command: 0x80000022,
        role: "rebase".into(),
        file: FileRange {
            offset: 0,
            bytes: 1,
        },
        sha256: stela_runtime::sha256(&data[..1]),
    });
    assert!(prepare_segments(&data, &legacy, base, &[]).is_err());
    assert!(prepare_raw_segments(&data, &legacy, base).is_ok());
    Ok(())
}

#[test]
fn placement_preserves_offsets_for_both_slide_directions_without_wrapping() {
    assert_eq!(
        relocated(0x1_0000_1234, 0x1_0000_0000, 0x400_0000_0000).unwrap(),
        0x400_0000_1234
    );
    assert_eq!(
        relocated(0x400_0000_1234, 0x400_0000_0000, 0x1_0000_0000).unwrap(),
        0x1_0000_1234
    );
    assert_eq!(relocated(0x8000, 0x10000, 0x10000).unwrap(), 0x8000);
    assert!(relocated(0, 0x10000, 0).is_err());
    assert!(relocated(u64::MAX, 0, 1).is_err());
}
