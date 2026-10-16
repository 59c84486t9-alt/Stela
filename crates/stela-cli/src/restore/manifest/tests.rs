use super::*;
#[test]
fn filters_restore_models_and_preserves_opaque_digest_metadata() -> Result<()> {
    let bytes = include_bytes!("../../../tests/fixtures/restore.plist");
    let report = inspect(bytes, Some("TestMac1,1"))?;
    assert_eq!(report.identities.len(), 1);
    assert_eq!(report.identities[0].components["OS"].path, "os.dmg.aea");
    assert_eq!(
        report.identities[0].components["OS"]
            .declared_hash_method
            .as_deref(),
        Some("sha2-384")
    );
    assert_eq!(
        report.identities[0].components_without_paths,
        vec!["Opaque"]
    );
    assert!(inspect(bytes, Some("MissingMac")).is_err());
    for bad in ["../a", "/absolute", "a//b", "a\\b", "C:/a", "a/./b"] {
        assert!(!safe_member(bad));
    }
    Ok(())
}
