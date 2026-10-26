//! `stela-launcher`: the native x86_64 program inside each launcher bundle
//! `stela apps` makes. Its bundle's `Info.plist` names the original app
//! (`StelaLauncher.Target`) and the `stela` executable
//! (`StelaLauncher.Stela`). As an AppKit app it receives the open-document
//! and URL events LaunchServices sends at launch, then runs `stela run
//! TARGET` with the documents' paths and the URLs as arguments; later
//! events start another hosted launch with theirs. It ends when the last
//! hosted launch ends, stops them when quit, appends their output to
//! `~/Library/Logs/Stela/<name>.log` and shows the end of that log when one
//! fails. See `docs/design/hosted-cli.md`.
// Elsewhere the launcher only refuses to run; its tests still check the logic.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[cfg(target_os = "macos")]
mod appkit;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The `Info.plist` key that marks a launcher, and its fields.
const MARKER: &str = "StelaLauncher";
const MARKER_TARGET: &str = "Target";
const MARKER_STELA: &str = "Stela";
/// The log folder below the home directory.
const LOGS: &str = "Library/Logs/Stela";
/// The log lines an alert shows.
const ALERT_LINES: usize = 12;
/// The log bytes read for them.
const ALERT_BYTES: u64 = 8 * 1024;
/// The argument old LaunchServices versions add, which is no document.
const PROCESS_SERIAL_PREFIX: &str = "-psn_";

/// What this launcher starts, from its own bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Launcher {
    /// The launcher's name, as Finder shows it.
    name: String,
    /// The original app.
    target: PathBuf,
    /// The `stela` executable.
    stela: PathBuf,
    /// Where the hosted launches' output goes.
    log: PathBuf,
}

/// The launcher of the bundle holding `executable` (`Contents/MacOS/NAME`).
fn launcher(executable: &Path, home: Option<&Path>) -> Result<Launcher, String> {
    let contents = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("this launcher is not inside an app bundle")?;
    let info = plist::Value::from_file(contents.join("Info.plist"))
        .map_err(|error| format!("this launcher's Info.plist cannot be read: {error}"))?;
    let marker = info
        .as_dictionary()
        .and_then(|info| info.get(MARKER))
        .and_then(plist::Value::as_dictionary)
        .ok_or("this launcher's Info.plist names no app; run `stela apps` again")?;
    let field = |key: &str| {
        marker
            .get(key)
            .and_then(plist::Value::as_string)
            .map(PathBuf::from)
            .ok_or_else(|| format!("this launcher's Info.plist has no {MARKER}.{key}"))
    };
    let name = contents
        .parent()
        .and_then(Path::file_stem)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Stela launcher".into());
    let home = home.ok_or("HOME is not set")?;
    Ok(Launcher {
        log: home.join(LOGS).join(format!("{name}.log")),
        target: field(MARKER_TARGET)?,
        stela: field(MARKER_STELA)?,
        name,
    })
}

/// Why the launcher cannot start its app, if it cannot.
fn check(launcher: &Launcher) -> Result<(), String> {
    if !launcher.stela.is_file() {
        return Err(format!(
            "Stela is not at {} any more. Run `stela apps` to update this launcher.",
            launcher.stela.display()
        ));
    }
    if !launcher.target.is_dir() {
        return Err(format!(
            "{} is gone. Run `stela apps` to update the launchers.",
            launcher.target.display()
        ));
    }
    Ok(())
}

/// The arguments the launcher itself was started with (`open --args`),
/// without LaunchServices' process serial number.
fn initial_arguments(arguments: impl Iterator<Item = OsString>) -> Vec<OsString> {
    arguments
        .filter(|argument| {
            !argument
                .to_str()
                .is_some_and(|text| text.starts_with(PROCESS_SERIAL_PREFIX))
        })
        .collect()
}

/// The command that runs the original with `arguments`.
fn command(launcher: &Launcher, arguments: &[OsString]) -> std::process::Command {
    let mut command = std::process::Command::new(&launcher.stela);
    command.arg("run").arg(&launcher.target).args(arguments);
    command
}

/// The last lines of the log, for an alert.
fn tail(log: &Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(log) else {
        return String::new();
    };
    let length = file.metadata().map_or(0, |metadata| metadata.len());
    let _ = file.seek(SeekFrom::Start(length.saturating_sub(ALERT_BYTES)));
    let mut bytes = vec![];
    let _ = file.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(ALERT_LINES)..].join("\n")
}

#[cfg(target_os = "macos")]
fn main() {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let launcher = std::env::current_exe()
        .map_err(|error| error.to_string())
        .and_then(|executable| launcher(&executable, home.as_deref()))
        .and_then(|launcher| check(&launcher).map(|()| launcher));
    match launcher {
        Ok(launcher) => {
            let arguments = initial_arguments(std::env::args_os().skip(1));
            appkit::run(launcher, arguments)
        }
        Err(message) => {
            appkit::alert("This Stela launcher cannot start its app", &message);
            std::process::exit(1)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("stela-launcher runs only on macOS");
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(work: &Path, marker: Option<(&str, &str)>) -> PathBuf {
        let contents = work.join("Foo.app/Contents");
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        let mut info = plist::Dictionary::new();
        if let Some((target, stela)) = marker {
            let mut fields = plist::Dictionary::new();
            fields.insert(MARKER_TARGET.into(), target.into());
            fields.insert(MARKER_STELA.into(), stela.into());
            info.insert(MARKER.into(), plist::Value::Dictionary(fields));
        }
        plist::Value::Dictionary(info)
            .to_file_xml(contents.join("Info.plist"))
            .unwrap();
        contents.join("MacOS/Foo")
    }

    #[test]
    fn the_launcher_reads_its_app_and_stela_from_its_bundle() {
        let work = tempfile::tempdir().unwrap();
        let executable = bundle(
            work.path(),
            Some(("/Applications/Foo.app", "/usr/local/bin/stela")),
        );
        let launcher = launcher(&executable, Some(Path::new("/Users/u"))).unwrap();
        assert_eq!(
            launcher,
            Launcher {
                name: "Foo".into(),
                target: "/Applications/Foo.app".into(),
                stela: "/usr/local/bin/stela".into(),
                log: "/Users/u/Library/Logs/Stela/Foo.log".into(),
            }
        );
        let message = check(&launcher).unwrap_err();
        assert!(message.contains("stela apps"), "{message}");
        let command = command(&launcher, &["/tmp/a.txt".into()]);
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(arguments, ["run", "/Applications/Foo.app", "/tmp/a.txt"]);
    }

    #[test]
    fn a_bundle_without_the_marker_is_explained() {
        let work = tempfile::tempdir().unwrap();
        let executable = bundle(work.path(), None);
        let message = launcher(&executable, Some(Path::new("/Users/u"))).unwrap_err();
        assert!(message.contains("stela apps"), "{message}");
    }

    #[test]
    fn launch_services_serial_numbers_are_no_documents() {
        let arguments = initial_arguments(
            ["-psn_0_12345", "/tmp/a.txt"]
                .into_iter()
                .map(OsString::from),
        );
        assert_eq!(arguments, ["/tmp/a.txt"]);
    }

    #[test]
    fn alerts_show_the_end_of_the_log() {
        let work = tempfile::tempdir().unwrap();
        let log = work.path().join("Foo.log");
        let text: String = (0..40).map(|line| format!("line {line}\n")).collect();
        std::fs::write(&log, text).unwrap();
        let tail = tail(&log);
        assert!(
            tail.starts_with("line 28") && tail.ends_with("line 39"),
            "{tail}"
        );
        assert_eq!(super::tail(&work.path().join("missing")), "");
    }
}
