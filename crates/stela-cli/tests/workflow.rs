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

#[test]
fn first_use_cache_is_reused_and_invalid_instructions_do_not_compile() {
    let dir = tempfile::tempdir().unwrap();
    let code: Vec<_> = [0xd2800540u32, 0xd65f03c0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    std::fs::write(dir.path().join("leaf.arm64"), code).unwrap();
    for expected in [false, true] {
        let output = cli(dir.path(), &["prepare-leaf", "leaf.arm64"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["cache_hit"], expected);
        assert_eq!(report["manifest"]["verified"], false);
    }
    std::fs::write(dir.path().join("invalid.arm64"), [0, 0, 0, 0]).unwrap();
    assert!(
        !cli(
            dir.path(),
            &[
                "compile-leaf",
                "invalid.arm64",
                "--output-dir",
                "invalid-output"
            ]
        )
        .status
        .success()
    );
    assert!(!dir.path().join("invalid-output").exists());
}

#[test]
fn restore_manifest_and_extraction_enforce_limits_crc_and_existing_outputs() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("fixture.ipsw")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("BuildManifest.plist", options).unwrap();
    zip.write_all(include_bytes!("../../../tests/fixtures/restore.plist"))
        .unwrap();
    zip.start_file("kernelcache.fixture", options).unwrap();
    zip.write_all(b"fixturekernel").unwrap();
    zip.finish().unwrap();
    let report = cli(
        dir.path(),
        &[
            "image-manifest",
            "fixture.ipsw",
            "--model",
            "TestMac1,1",
            "--output",
            "manifest.json",
        ],
    );
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["product_build"], "FIXTURE");
    assert!(
        !cli(
            dir.path(),
            &[
                "extract-image",
                "fixture.ipsw",
                "--member",
                "kernelcache.fixture",
                "--output",
                "small",
                "--max-bytes",
                "2"
            ]
        )
        .status
        .success()
    );
    assert!(!dir.path().join("small").exists());
    let extracted = cli(
        dir.path(),
        &[
            "extract-image",
            "fixture.ipsw",
            "--member",
            "kernelcache.fixture",
            "--output",
            "kernel",
        ],
    );
    assert!(
        extracted.status.success(),
        "{}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(
        std::fs::read(dir.path().join("kernel")).unwrap(),
        b"fixturekernel"
    );
    assert!(
        !cli(
            dir.path(),
            &[
                "extract-image",
                "fixture.ipsw",
                "--member",
                "kernelcache.fixture",
                "--output",
                "kernel"
            ]
        )
        .status
        .success()
    );
    assert!(
        !cli(
            dir.path(),
            &[
                "extract-image",
                "fixture.ipsw",
                "--member",
                "../kernel",
                "--output",
                "escape"
            ]
        )
        .status
        .success()
    );
    let mut corrupt = std::fs::read(dir.path().join("fixture.ipsw")).unwrap();
    let position = corrupt
        .windows(13)
        .position(|w| w == b"fixturekernel")
        .unwrap();
    corrupt[position] ^= 1;
    std::fs::write(dir.path().join("corrupt.ipsw"), corrupt).unwrap();
    assert!(
        !cli(
            dir.path(),
            &[
                "extract-image",
                "corrupt.ipsw",
                "--member",
                "kernelcache.fixture",
                "--output",
                "bad-kernel"
            ]
        )
        .status
        .success()
    );
    assert!(!dir.path().join("bad-kernel").exists());
}
