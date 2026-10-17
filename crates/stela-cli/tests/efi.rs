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
    // The backup is still the configuration from before the first install.
    assert_eq!(
        fs::read(esp.join("EFI/stela/config.plist.backup")).unwrap(),
        fs::read(FIXTURE).unwrap()
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

    assert_eq!(config_bytes(dir.path()), fs::read(FIXTURE).unwrap());
    assert!(!esp.join("EFI/stela").exists());
    assert!(!esp.join("EFI/OC/Tools/Stela.efi").exists());
    assert!(esp.join("EFI/OC/Tools/OpenShell.efi").is_file());
    // A second uninstall finds nothing and changes nothing.
    let output = cli(&["efi", "uninstall", "--esp", esp.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(config_bytes(dir.path()), fs::read(FIXTURE).unwrap());
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

const FULL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/opencore-config-full.plist"
);

/// An ESP like `esp()` whose configuration is `config`.
fn esp_with(config: &[u8]) -> tempfile::TempDir {
    let dir = esp();
    fs::write(dir.path().join("esp/EFI/OC/config.plist"), config).unwrap();
    dir
}

fn install_with_source(dir: &Path) -> Output {
    let source = dir.join("source.bin");
    install(dir, &["--source", source.to_str().unwrap()])
}

fn uninstall(dir: &Path) -> Output {
    let esp = dir.join("esp");
    cli(&["efi", "uninstall", "--esp", esp.to_str().unwrap()])
}

fn config_bytes(dir: &Path) -> Vec<u8> {
    fs::read(dir.join("esp/EFI/OC/config.plist")).unwrap()
}

/// `before` with `block` inserted right after the line that opens
/// `Misc.Tools`.
fn with_block(before: &str, block: &str, newline: &str) -> String {
    let key = before.find("<key>Tools</key>").unwrap();
    let open = key + before[key..].find("<array>").unwrap() + "<array>".len() + newline.len();
    format!("{}{block}{}", &before[..open], &before[open..])
}

/// The entry's lines as `install` writes them at `indent`.
fn entry_lines(indent: &str, unit: &str, newline: &str) -> String {
    let fields = [
        ("Arguments", "<string></string>"),
        ("Auxiliary", "<false/>"),
        ("Comment", "<string>Stela ARM macOS mount</string>"),
        ("Enabled", "<true/>"),
        ("Flavour", "<string>Auto</string>"),
        ("FullNvramAccess", "<false/>"),
        ("Name", "<string>macOS (Stela)</string>"),
        ("Path", "<string>Stela.efi</string>"),
        ("RealPath", "<true/>"),
        ("TextMode", "<false/>"),
    ];
    let mut text = format!("{indent}<dict>{newline}");
    for (key, value) in fields {
        text += &format!("{indent}{unit}<key>{key}</key>{newline}{indent}{unit}{value}{newline}");
    }
    text + &format!("{indent}</dict>{newline}")
}

/// Install changes nothing but the inserted entry lines, a second install
/// changes nothing, and uninstall restores every byte.
fn round_trip(original: &[u8], indent: &str, unit: &str, newline: &str) {
    let dir = esp_with(original);
    let output = install_with_source(dir.path());
    assert!(output.status.success(), "{output:?}");
    let installed = config_bytes(dir.path());
    let text = String::from_utf8(original.to_vec()).unwrap();
    assert_eq!(
        String::from_utf8(installed.clone()).unwrap(),
        with_block(&text, &entry_lines(indent, unit, newline), newline)
    );
    assert_eq!(
        fs::read(dir.path().join("esp/EFI/stela/config.plist.backup")).unwrap(),
        original
    );
    assert!(install(dir.path(), &[]).status.success());
    assert_eq!(config_bytes(dir.path()), installed);
    let output = uninstall(dir.path());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(config_bytes(dir.path()), original);
    assert!(!dir.path().join("esp/EFI/stela").exists());
}

#[test]
fn install_inserts_only_the_entry_lines_and_uninstall_restores_every_byte() {
    let original = fs::read(FULL).unwrap();
    round_trip(&original, "\t\t\t", "\t", "\n");
}

#[test]
fn the_entry_follows_the_files_own_indentation_and_line_endings() {
    let spaced = fs::read_to_string(FULL)
        .unwrap()
        .replace('\t', "    ")
        .replace('\n', "\r\n");
    round_trip(spaced.as_bytes(), "            ", "    ", "\r\n");
}

#[test]
fn an_empty_tools_array_is_opened_and_restored_exactly() {
    let full = fs::read_to_string(FULL).unwrap();
    let start = full.find("\t\t<key>Tools</key>\n\t\t<array>").unwrap();
    let end = full[start..].find("\t\t</array>\n").unwrap() + start + "\t\t</array>\n".len();
    let empty = format!(
        "{}\t\t<key>Tools</key>\n\t\t<array/>\n{}",
        &full[..start],
        &full[end..]
    );
    let dir = esp_with(empty.as_bytes());
    assert!(install_with_source(dir.path()).status.success());
    let installed = String::from_utf8(config_bytes(dir.path())).unwrap();
    assert!(installed.contains(&format!(
        "\t\t<array>\n{}\t\t</array>",
        entry_lines("\t\t\t", "\t", "\n")
    )));
    assert!(uninstall(dir.path()).status.success());
    assert_eq!(config_bytes(dir.path()), empty.as_bytes());
}

#[test]
fn uninstall_after_other_edits_removes_only_the_entry_and_keeps_the_backup() {
    let original = fs::read_to_string(FULL).unwrap();
    let dir = esp_with(original.as_bytes());
    assert!(install_with_source(dir.path()).status.success());
    // The user changes the picker timeout afterwards.
    let edited = String::from_utf8(config_bytes(dir.path()))
        .unwrap()
        .replace("<integer>5</integer>", "<integer>10</integer>");
    fs::write(dir.path().join("esp/EFI/OC/config.plist"), &edited).unwrap();
    let output = uninstall(dir.path());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(config_bytes(dir.path())).unwrap(),
        original.replace("<integer>5</integer>", "<integer>10</integer>")
    );
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("kept_backup"), "{report}");
    assert_eq!(
        fs::read(dir.path().join("esp/EFI/stela/config.plist.backup")).unwrap(),
        original.as_bytes()
    );
}

#[test]
fn unusable_configs_are_refused_without_quoting_them() {
    let full = fs::read_to_string(FULL).unwrap();
    for (config, reason) in [
        (b"bplist00\x01\x02".to_vec(), "binary property list"),
        (vec![0xff, 0xfe, 0x00], "not UTF-8"),
        (
            full.replace("</plist>", "").into_bytes(),
            "cannot be changed safely",
        ),
        (
            full.replacen("<true/>", "<true>", 1).into_bytes(),
            "cannot be changed safely",
        ),
        (
            full.replace("<key>Tools</key>", "<key>Tools-off</key>")
                .into_bytes(),
            "no Misc.Tools array",
        ),
        (
            full.replacen("<!-- Tools", "<![CDATA[x]]><!-- Tools", 1)
                .into_bytes(),
            "cannot be changed safely",
        ),
    ] {
        let dir = esp_with(&config);
        let output = install_with_source(dir.path());
        assert!(!output.status.success(), "{reason}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(reason), "{reason}: {stderr}");
        for secret in ["SYNTHETIC-MLB-NOT-REAL", "SYNTHETIC-SERIAL", "keepsyms"] {
            assert!(!stderr.contains(secret), "{reason} quoted the config");
        }
        assert_eq!(config_bytes(dir.path()), config, "{reason}");
        assert!(!dir.path().join("esp/EFI/stela").exists(), "{reason}");
    }
}
