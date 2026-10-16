use super::*;
fn thin(cpu: u32, subtype: u32) -> Vec<u8> {
    let mut data = vec![];
    for value in [0xfeedfacf, cpu, subtype, 2, 0, 0, 0, 0] {
        data.extend(value.to_le_bytes());
    }
    data
}
#[test]
fn reads_arm64e_and_fat_slices_and_rejects_bad_ranges() -> Result<()> {
    let arm = thin(0x0100000c, 0x80000002);
    assert_eq!(inspect(&arm, "arm")?[0].architecture, "arm64e");
    let intel = thin(0x01000007, 3);
    let mut fat = vec![];
    for value in [
        0xcafebabeu32,
        2,
        0x0100000c,
        2,
        48,
        32,
        0,
        0x01000007,
        3,
        80,
        32,
        0,
    ] {
        fat.extend(value.to_be_bytes());
    }
    fat.extend(arm);
    fat.extend(intel);
    let slices = inspect(&fat, "universal")?;
    assert_eq!(slices.len(), 2);
    assert_eq!(slices[1].architecture, "x86_64");
    fat[36..40].copy_from_slice(&4096u32.to_be_bytes());
    assert!(inspect(&fat, "broken").is_err());
    Ok(())
}
#[test]
fn new_apple_subtypes_are_named_without_becoming_baseline_execution() -> Result<()> {
    for (subtype, label) in [(0x8000000c, "arm64e.x1"), (0x8000007f, "arm64-subtype-127")] {
        let bytes = thin(0x0100000c, subtype);
        assert_eq!(inspect(&bytes, "own-subtype")?[0].architecture, label);
        assert!(
            matches!(load_plan::plan(&bytes), Err(load_plan::PlanError::UnsupportedCpu { cpu_subtype, .. }) if cpu_subtype == subtype)
        );
    }
    Ok(())
}
#[test]
fn containers_and_parse_errors_are_visible() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("dyld_shared_cache_arm64e"),
        b"dyld_v1 arm64e",
    )?;
    std::fs::write(root.path().join("broken"), [0xcf, 0xfa, 0xed, 0xfe])?;
    let inv = scan(root.path(), "test")?;
    assert_eq!(inv.issues.len(), 1);
    assert_eq!(inv.excluded_containers.len(), 1);
    Ok(())
}
