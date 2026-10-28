use std::{
    path::Path,
    process::{Command, Output},
};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stela-dev"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn executable_plan_selects_apple_slices_and_preserves_guest_identity() {
    fn image(subtype: u32) -> Vec<u8> {
        let mut data = vec![0; 4096];
        let header = [0xfeedfacfu32, 0x0100000c, subtype, 2, 2, 96, 0, 0];
        for (index, word) in header.into_iter().enumerate() {
            data[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        data[32..36].copy_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
        data[36..40].copy_from_slice(&72u32.to_le_bytes());
        data[40..46].copy_from_slice(b"__TEXT");
        data[56..64].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
        data[64..72].copy_from_slice(&4096u64.to_le_bytes());
        data[80..88].copy_from_slice(&4096u64.to_le_bytes());
        data[88..92].copy_from_slice(&5u32.to_le_bytes());
        data[92..96].copy_from_slice(&5u32.to_le_bytes());
        data[104..108].copy_from_slice(&0x80000028u32.to_le_bytes()); // LC_MAIN
        data[108..112].copy_from_slice(&24u32.to_le_bytes());
        data[112..120].copy_from_slice(&512u64.to_le_bytes());
        data[512..516].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
        data
    }
    let dir = tempfile::tempdir().unwrap();
    let arm64 = image(0);
    let arm64e = image(0x80000002);
    let mut fat = vec![0; 12288];
    fat[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    fat[4..8].copy_from_slice(&2u32.to_be_bytes());
    for (index, subtype) in [0u32, 0x80000002].into_iter().enumerate() {
        let offset = 8 + index * 20;
        for (field, word) in [0x0100000c, subtype, (index as u32 + 1) * 4096, 4096, 12]
            .into_iter()
            .enumerate()
        {
            fat[offset + field * 4..offset + field * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
    }
    fat[4096..8192].copy_from_slice(&arm64);
    fat[8192..].copy_from_slice(&arm64e);
    std::fs::write(dir.path().join("universal"), &fat).unwrap();
    assert!(
        !cli(dir.path(), &["plan-executable", "universal"])
            .status
            .success()
    );
    let output = cli(
        dir.path(),
        &["plan-executable", "universal", "--architecture", "arm64e"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["container_sha256"], stela_runtime::sha256(&fat));
    assert_eq!(report["slice_offset"], 8192);
    assert_eq!(
        report["plan"]["slice_sha256"],
        stela_runtime::sha256(&arm64e)
    );
    assert_eq!(report["plan"]["cpu_subtype"], 0x80000002u32);
    assert_eq!(report["plan"]["entry"]["guest_address"], 0x1_0000_0200u64);
    assert_eq!(report["plan"]["execution_supported"], false);
    std::fs::write(dir.path().join("arm64"), arm64).unwrap();
    assert!(
        !cli(
            dir.path(),
            &["plan-executable", "arm64", "--architecture", "arm64e"]
        )
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
    zip.write_all(include_bytes!(
        "../../stela-cli/tests/fixtures/restore.plist"
    ))
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
