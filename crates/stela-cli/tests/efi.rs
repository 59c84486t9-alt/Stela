use plist::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/opencore-config.plist"
);

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stela"))
        .args(args)
        .output()
        .unwrap()
}

/// An ESP with the fixture configuration, one existing tool, a PE stub and
/// an ARM source beside it.
fn esp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let oc = dir.path().join("esp/EFI/OC");
    fs::create_dir_all(oc.join("Tools")).unwrap();
    fs::copy(FIXTURE, oc.join("config.plist")).unwrap();
    fs::write(oc.join("Tools/OpenShell.efi"), b"MZshell").unwrap();
    fs::write(dir.path().join("stela.efi"), b"MZstela").unwrap();
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

fn config(dir: &Path) -> Value {
    Value::from_file(dir.join("esp/EFI/OC/config.plist")).unwrap()
}

fn tools(config: &mut Value) -> &mut Vec<Value> {
    config
        .as_dictionary_mut()
        .and_then(|root| root.get_mut("Misc"))
        .and_then(Value::as_dictionary_mut)
        .and_then(|misc| misc.get_mut("Tools"))
        .and_then(Value::as_array_mut)
        .unwrap()
}

fn path(entry: &Value) -> &str {
    entry
        .as_dictionary()
        .and_then(|entry| entry.get("Path"))
        .and_then(Value::as_string)
        .unwrap()
}

#[test]
fn install_adds_one_real_path_tool_and_keeps_every_other_key() {
    let dir = esp();
    let source = dir.path().join("source.bin");
    let output = install(
        dir.path(),
        &[
            "--source",
            source.to_str().unwrap(),
            "--options",
            "--entry 0x100000",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let esp = dir.path().join("esp");
    assert_eq!(
        fs::read(esp.join("EFI/OC/Tools/Stela.efi")).unwrap(),
        b"MZstela"
    );
    assert_eq!(
        fs::read(esp.join("EFI/stela/source.bin")).unwrap(),
        fs::read(&source).unwrap()
    );
    assert_eq!(
        fs::read_to_string(esp.join("EFI/stela/stela.cfg")).unwrap(),
        "--entry 0x100000"
    );
    assert_eq!(
        fs::read(esp.join("EFI/stela/config.plist.backup")).unwrap(),
        fs::read(FIXTURE).unwrap()
    );

    let mut installed = config(dir.path());
    let entry = tools(&mut installed).remove(0);
    let entry = entry.as_dictionary().unwrap();
    for (key, value) in [
        ("Name", Value::from("macOS (Stela)")),
        ("Path", "Stela.efi".into()),
        ("Flavour", "Auto".into()),
        ("Enabled", true.into()),
        ("Auxiliary", false.into()),
        ("RealPath", true.into()),
        ("TextMode", false.into()),
    ] {
        assert_eq!(entry.get(key), Some(&value), "{key}");
    }
    assert_eq!(installed, Value::from_file(FIXTURE).unwrap());
}

#[test]
fn reinstalling_replaces_the_entry_in_place_and_keeps_omitted_files() {
    let dir = esp();
    let source = dir.path().join("source.bin");
    let source = source.to_str().unwrap();
    assert!(
        install(dir.path(), &["--source", source, "--options", "a"])
            .status
            .success()
    );
    // Move the entry behind the shell, as a user might in a configurator.
    let mut moved = config(dir.path());
    tools(&mut moved).swap(0, 1);
    moved
        .to_file_xml(dir.path().join("esp/EFI/OC/config.plist"))
        .unwrap();
    fs::write(dir.path().join("stela.efi"), b"MZnewer").unwrap();

    let output = install(dir.path(), &[]);
    assert!(output.status.success(), "{output:?}");
    let mut installed = config(dir.path());
    let paths: Vec<&str> = tools(&mut installed).iter().map(path).collect();
    assert_eq!(paths, ["OpenShell.efi", "Stela.efi"]);
    let esp = dir.path().join("esp");
    assert_eq!(
        fs::read(esp.join("EFI/OC/Tools/Stela.efi")).unwrap(),
        b"MZnewer"
    );
    assert_eq!(
        fs::read_to_string(esp.join("EFI/stela/stela.cfg")).unwrap(),
        "a"
    );
    assert!(esp.join("EFI/stela/source.bin").is_file());
}

#[test]
fn uninstall_removes_exactly_what_install_added() {
    let dir = esp();
    let source = dir.path().join("source.bin");
    let output = install(
        dir.path(),
        &["--source", source.to_str().unwrap(), "--options", ""],
    );
    assert!(output.status.success(), "{output:?}");
    let esp = dir.path().join("esp");
    let output = cli(&["efi", "uninstall", "--esp", esp.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");

    assert_eq!(config(dir.path()), Value::from_file(FIXTURE).unwrap());
    assert!(!esp.join("EFI/stela").exists());
    assert!(!esp.join("EFI/OC/Tools/Stela.efi").exists());
    assert!(esp.join("EFI/OC/Tools/OpenShell.efi").is_file());
    // A second uninstall finds nothing and changes nothing.
    let output = cli(&["efi", "uninstall", "--esp", esp.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(config(dir.path()), Value::from_file(FIXTURE).unwrap());
}

#[test]
fn install_refuses_a_vaulted_config_or_a_missing_source() {
    let dir = esp();
    let output = install(dir.path(), &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--source"));

    let path = dir.path().join("esp/EFI/OC/config.plist");
    let vaulted = fs::read_to_string(FIXTURE)
        .unwrap()
        .replace("<string>Optional</string>", "<string>Secure</string>");
    fs::write(&path, &vaulted).unwrap();
    let source = dir.path().join("source.bin");
    let output = install(dir.path(), &["--source", source.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Vault is Secure"));
    assert_eq!(fs::read_to_string(&path).unwrap(), vaulted);
    assert!(!dir.path().join("esp/EFI/stela").exists());
}
