use super::*;

#[test]
fn identical_export_keeps_real_mtime_while_changed_payload_invalidates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("captured-units.bin");
    write_export(&path, b"complete first captured cohort");
    let past = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567_890);
    fs::File::open(&path).unwrap().set_modified(past).unwrap();
    let stable = fs::metadata(&path).unwrap().modified().unwrap();
    write_export(&path, b"complete first captured cohort");
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), stable);
    write_export(&path, b"changed full source/object/header/compiler capture");
    assert_eq!(
        fs::read(&path).unwrap(),
        b"changed full source/object/header/compiler capture"
    );
    assert_ne!(fs::metadata(&path).unwrap().modified().unwrap(), stable);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn exporting_through_a_metadata_leaf_symlink_never_modifies_its_target() {
    let directory = tempfile::tempdir().unwrap();
    let foreign = directory.path().join("foreign.bin");
    fs::write(&foreign, b"foreign metadata retained").unwrap();
    let path = directory.path().join("captured-units.bin");
    std::os::unix::fs::symlink(&foreign, &path).unwrap();
    assert!(std::panic::catch_unwind(|| write_export(&path, b"new owned metadata")).is_err());
    assert_eq!(fs::read(&foreign).unwrap(), b"foreign metadata retained");
}
