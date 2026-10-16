use super::*;
fn inventory() -> Inventory {
    Inventory {
        schema_version: 1,
        build: "fixture".into(),
        root: ".".into(),
        artifacts: vec![Artifact {
            id: "a".into(),
            path: "a".into(),
            sha256: "hash".into(),
            architecture: "arm64".into(),
            slice_offset: 0,
            text_bytes: 4,
        }],
        issues: vec![],
        excluded_containers: vec![],
    }
}
#[test]
fn rejects_skipped_stages_and_changed_evidence() -> Result<()> {
    let mut p = Progress::new(inventory(), b"inventory")?;
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), "compiler report")?;
    assert!(p.record("a", Stage::Verified, file.path()).is_err());
    p.record("a", Stage::Lifted, file.path())?;
    assert_eq!(p.report()?["stages"]["lifted"], 1);
    assert!(p.report()?["whole_os_coverage"].is_null());
    std::fs::write(file.path(), "different report")?;
    assert!(p.report().is_err());
    Ok(())
}
