use std::{
    path::Path,
    process::{Command, Output},
};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stela"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn inventory_to_ledger_preserves_scope_and_protects_existing_work() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("root");
    std::fs::create_dir(&tree).unwrap();
    let mut arm = vec![];
    for word in [0xfeedfacfu32, 0x0100000c, 2, 2, 0, 0, 0, 0] {
        arm.extend(word.to_le_bytes());
    }
    std::fs::write(tree.join("fixture"), arm).unwrap();
    std::fs::write(tree.join("dyld_shared_cache_arm64e"), b"dyld_v1 arm64e").unwrap();
    let inventory = cli(dir.path(), &["inventory", "root", "--build", "FIXTURE"]);
    assert!(
        inventory.status.success(),
        "{}",
        String::from_utf8_lossy(&inventory.stderr)
    );
    assert!(
        !cli(dir.path(), &["inventory", "root", "--build", "FIXTURE"])
            .status
            .success()
    );
    assert!(
        cli(dir.path(), &["progress", "init", ".stela/inventory.json"])
            .status
            .success()
    );
    let output = cli(dir.path(), &["progress", "status"]);
    assert!(output.status.success());
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["arm64_slices"], 1);
    assert_eq!(status["stages"]["verified"], 0);
    assert_eq!(status["excluded_containers"], 1);
    assert!(status["whole_os_coverage"].is_null());
    assert!(
        !cli(dir.path(), &["progress", "init", ".stela/inventory.json"])
            .status
            .success()
    );
}
