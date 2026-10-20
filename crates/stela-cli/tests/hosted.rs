//! End to end: after `stela install-system` into a fresh home directory,
//! `stela PROGRAM` runs an arm64 program, a `#!` script and an app bundle
//! with no options, explains what it cannot run, and `stela apps` makes and
//! removes a launcher.
//!
//! It needs the 26A434 guest roots ([`support::guest`]) and `xcrun clang`;
//! without them it says so and checks nothing.
mod support {
    pub mod guest;
}

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::guest::guest_roots;
const HELLO: &str = r#"#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    printf("hello from arm64:");
    for (int i = 1; i < argc; i++) printf(" %s", argv[i]);
    const char *bundle = getenv("__CFBundleIdentifier");
    if (bundle) printf(" (bundle %s)", bundle);
    printf("\n");
    return 3;
}
"#;

/// A program that runs another by the path it is given, as `execv` does.
const EXEC: &str = r#"#include <unistd.h>
int main(int argc, char **argv) { execv(argv[1], argv + 1); return 127; }
"#;

fn compile(directory: &Path, name: &str, flags: &[&str]) -> Option<PathBuf> {
    compile_source(directory, name, HELLO, flags)
}

fn compile_source(directory: &Path, name: &str, text: &str, flags: &[&str]) -> Option<PathBuf> {
    let source = directory.join(format!("{name}.c"));
    std::fs::write(&source, text).ok()?;
    let output = directory.join(name);
    Command::new("xcrun")
        .arg("clang")
        .args(flags)
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .ok()?
        .success()
        .then_some(output)
}

/// `stela ARGS` with `home` as the home directory, in `directory`.
fn stela(home: &Path, directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stela"))
        .args(arguments)
        .current_dir(directory)
        .env("HOME", home)
        .env_remove("STELA_GUEST_ROOT")
        .env_remove("__CFBundleIdentifier")
        .output()
        .unwrap()
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn arm64_programs_run_with_no_options_after_the_system_files_are_installed() {
    let Some(roots) = guest_roots() else {
        eprintln!("skipped: no 26A434 guest roots (see this test's documentation)");
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join("home");
    let programs = work.path().join("programs");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&programs).unwrap();
    let Some(hello) = compile(&programs, "hello", &["-arch", "arm64e", "-O1"]) else {
        eprintln!("skipped: xcrun clang cannot build arm64e programs here");
        return;
    };
    compile(&programs, "intel", &["-arch", "x86_64"]).unwrap();
    compile(
        &programs,
        "unsigned",
        &["-arch", "arm64", "-Wl,-no_adhoc_codesign"],
    )
    .unwrap();

    // Nothing installed: the error names the one command that installs it.
    let output = stela(&home, &programs, &["./hello"]);
    let (_, error) = text(&output);
    assert!(!output.status.success());
    assert!(error.contains("stela install-system --ipsw"), "{error}");

    let mut install = vec!["install-system"];
    for root in &roots {
        install.extend(["--import", root.to_str().unwrap()]);
    }
    let output = stela(&home, &programs, &install);
    assert!(output.status.success(), "{:?}", text(&output));
    let installed = home.join("Library/Application Support/Stela/26A434");
    assert!(installed.join("receipt.json").is_file());
    let output = stela(&home, &programs, &["install-system"]);
    assert!(
        text(&output).0.contains("are installed"),
        "{:?}",
        text(&output)
    );

    // A path, with its own arguments and exit status.
    let output = stela(&home, &programs, &["./hello", "a", "--help"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: a --help\n",
        "{:?}",
        text(&output)
    );
    assert_eq!(output.status.code(), Some(3));
    let output = stela(&home, &programs, &["run", hello.to_str().unwrap(), "b"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: b\n",
        "{:?}",
        text(&output)
    );

    // A #! script runs its interpreter (/bin/echo's arm64e slice).
    let script = programs.join("script");
    std::fs::write(&script, "#!/bin/echo from\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let output = stela(&home, &programs, &["./script", "x"]);
    assert_eq!(text(&output).0, "from ./script x\n", "{:?}", text(&output));

    // An app bundle starts as LaunchServices starts it.
    let app = programs.join("Hello.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    std::fs::copy(&hello, app.join("Contents/MacOS/hello")).unwrap();
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>CFBundleExecutable</key><string>hello</string>\
         <key>CFBundleIdentifier</key><string>com.example.hello</string>\
         <key>CFBundlePackageType</key><string>APPL</string>\
         </dict></plist>\n",
    )
    .unwrap();
    let output = stela(&home, &programs, &["Hello.app", "doc.txt"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: doc.txt (bundle com.example.hello)\n",
        "{:?}",
        text(&output)
    );

    // What Stela cannot run is explained before anything runs.
    let output = stela(&home, &programs, &["./intel"]);
    assert!(
        text(&output).1.contains("Intel program (x86_64)"),
        "{:?}",
        text(&output)
    );
    let output = stela(&home, &programs, &["./unsigned"]);
    assert!(
        text(&output).1.contains("not code-signed"),
        "{:?}",
        text(&output)
    );
    let output = stela(&home, &programs, &["hello"]);
    assert!(
        text(&output).1.contains("use ./hello"),
        "{:?}",
        text(&output)
    );

    // The guest's own execve of a relative name stays relative: no PATH
    // lookup.
    compile_source(&programs, "exec", EXEC, &["-arch", "arm64e"]).unwrap();
    let output = stela(&home, &programs, &["./exec", "hello", "y"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: y\n",
        "{:?}",
        text(&output)
    );

    // A launcher for the arm64-only app, then nothing left after uninstall.
    let scan = [
        "apps",
        "--scan",
        programs.to_str().unwrap(),
        "--no-register",
    ];
    let output = stela(&home, &programs, &scan);
    assert!(output.status.success(), "{:?}", text(&output));
    let launcher = home.join("Applications/Stela/Hello.app");
    assert!(
        text(&output).0.contains("Added launcher"),
        "{:?}",
        text(&output)
    );
    assert!(launcher.join("Contents/MacOS/hello").is_file());
    let verified = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&launcher)
        .status()
        .unwrap();
    assert!(verified.success());
    let output = stela(&home, &programs, &["apps", "--list"]);
    assert!(text(&output).0.contains("opens"), "{:?}", text(&output));
    let output = stela(&home, &programs, &["apps", "--uninstall", "--no-register"]);
    assert!(output.status.success(), "{:?}", text(&output));
    assert!(!home.join("Applications/Stela").exists());
    assert!(
        app.join("Contents/MacOS/hello").is_file(),
        "the original is kept"
    );

    let output = stela(&home, &programs, &["install-system", "--remove"]);
    assert!(output.status.success());
    assert!(!installed.exists());
}
