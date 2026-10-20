use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use stela_loader::mount_interface;

const LOADER: &str = "esp/EFI/BOOT/BOOTX64.EFI";

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stela"))
        .args(args)
        .output()
        .unwrap()
}

/// A `stela.efi` stand-in: a PE stub with this tree's mount interface.
fn stela_image(tag: &[u8]) -> Vec<u8> {
    let mut image = b"MZ".to_vec();
    image.extend_from_slice(tag);
    image.extend_from_slice(&mount_interface::marker(mount_interface::CURRENT));
    image
}

/// An empty ESP, a `stela.efi` and an ARM source beside it.
fn esp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("esp")).unwrap();
    fs::write(dir.path().join("stela.efi"), stela_image(b"stela")).unwrap();
    fs::write(dir.path().join("source.bin"), [0xc0, 0x03, 0x5f, 0xd6]).unwrap();
    dir
}

fn install(dir: &Path, extra: &[&str]) -> Output {
    let esp = dir.join("esp");
    let image = dir.join("stela.efi");
    let mut args = vec![
        "efi",
        "install",
        "--esp",
        esp.to_str().unwrap(),
        "--image",
        image.to_str().unwrap(),
    ];
    args.extend(extra);
    cli(&args)
}

fn install_with_source(dir: &Path) -> Output {
    let source = dir.join("source.bin");
    install(
        dir,
        &["--source", source.to_str().unwrap(), "--options", "--trace"],
    )
}

fn uninstall(dir: &Path) -> Output {
    cli(&[
        "efi",
        "uninstall",
        "--esp",
        dir.join("esp").to_str().unwrap(),
    ])
}

#[test]
fn install_makes_stela_the_removable_media_loader_with_its_files() {
    let dir = esp();
    let output = install_with_source(dir.path());
    assert!(output.status.success(), "{output:?}");
    let esp = dir.path().join("esp");
    assert_eq!(
        fs::read(dir.path().join(LOADER)).unwrap(),
        stela_image(b"stela")
    );
    assert_eq!(
        fs::read(esp.join("EFI/stela/stela.cfg")).unwrap(),
        b"--trace"
    );
    assert_eq!(
        fs::read(esp.join("EFI/stela/source.bin")).unwrap(),
        [0xc0, 0x03, 0x5f, 0xd6]
    );
}

#[test]
fn reinstalling_replaces_stelas_loader_and_keeps_omitted_files() {
    let dir = esp();
    assert!(install_with_source(dir.path()).status.success());
    fs::write(dir.path().join("stela.efi"), stela_image(b"newer")).unwrap();
    let output = install(dir.path(), &[]);
    assert!(output.status.success(), "{output:?}");
    let esp = dir.path().join("esp");
    assert_eq!(
        fs::read(dir.path().join(LOADER)).unwrap(),
        stela_image(b"newer")
    );
    assert_eq!(
        fs::read(esp.join("EFI/stela/stela.cfg")).unwrap(),
        b"--trace"
    );
    assert!(esp.join("EFI/stela/source.bin").is_file());
}

#[test]
fn another_loader_is_refused_and_left_unchanged() {
    let dir = esp();
    let loader = dir.path().join(LOADER);
    fs::create_dir_all(loader.parent().unwrap()).unwrap();
    fs::write(&loader, b"MZopencore").unwrap();
    let output = install_with_source(dir.path());
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("another loader"), "{error}");
    assert_eq!(fs::read(&loader).unwrap(), b"MZopencore");
    assert!(!dir.path().join("esp/EFI/stela").exists());
    // Uninstall leaves a loader that is not Stela's.
    assert!(uninstall(dir.path()).status.success());
    assert_eq!(fs::read(&loader).unwrap(), b"MZopencore");
}

#[test]
fn install_refuses_an_image_that_is_not_stela_or_a_missing_source() {
    let dir = esp();
    fs::write(dir.path().join("stela.efi"), b"MZother").unwrap();
    let output = install_with_source(dir.path());
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a stela.efi"));
    assert!(!dir.path().join(LOADER).exists());
    let dir = esp();
    let output = install(dir.path(), &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pass --source"));
}

#[test]
fn uninstall_removes_exactly_what_install_added() {
    let dir = esp();
    let other = dir.path().join("esp/EFI/BOOT/other.efi");
    assert!(install_with_source(dir.path()).status.success());
    fs::write(&other, b"MZother").unwrap();
    let output = uninstall(dir.path());
    assert!(output.status.success(), "{output:?}");
    assert!(!dir.path().join(LOADER).exists());
    assert!(!dir.path().join("esp/EFI/stela").exists());
    // A directory that still holds something else stays.
    assert!(other.is_file());
    // A second uninstall finds nothing to do.
    assert!(uninstall(dir.path()).status.success());
}
