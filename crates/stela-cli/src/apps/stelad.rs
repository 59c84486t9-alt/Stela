//! `stela stelad`: the per-user service launchd starts on demand
//! (`docs/design/hosted-cli.md#stelad`). Each pass tells the user about the
//! apps that met unsupported operations, keeps the launchers in sync, and
//! serves the translation store: it proves the translations processes left
//! in the spool and translates the installed arm64-only apps and their
//! libraries ahead of time. It exits when a pass finds nothing to do.
use super::{Environment, Record, Stelad, sync};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use stela_runtime::hosted::translations::{Config, service};

/// `stelad`'s state below the Stela support directory.
pub(super) const STATE: &str = "stelad.json";
/// The lock one `stelad` at a time holds, beside it.
const LOCK: &str = "stelad.lock";
/// Passes one run makes at most, should work keep arriving.
const MAX_PASSES: usize = 16;
/// The most of the unsupported-operations log one pass reads: a longer
/// growth is read from its end.
const MAX_LOG_READ: u64 = 1 << 20;
/// Apps one pass posts a notification for at most.
const MAX_NOTIFIED_APPS: usize = 3;
/// The folders of an app bundle whose Mach-O files are translated, and how
/// deep below them they are looked for.
const CODE_FOLDERS: [&str; 2] = ["Contents/MacOS", "Contents/Frameworks"];
const CODE_DEPTH: usize = 8;
/// The first four bytes of a 64-bit Mach-O file and of a fat file.
const MACH_O_MAGICS: [[u8; 4]; 3] = [
    0xfeed_facf_u32.to_le_bytes(),
    0xcafe_babe_u32.to_be_bytes(),
    0xcafe_babf_u32.to_be_bytes(),
];
const OSASCRIPT: &str = "/usr/bin/osascript";
/// The bundle suffix that names an app in a reported program or image path.
const APP_SUFFIX: &str = ".app/";
/// What follows the program and pid in a log entry of an unsupported
/// operation (`hosted::unsupported`: `TIME PROGRAM[PID] unsupported KIND:
/// OPERATION (at IMAGE+OFFSET); FAILURE`); notes about a run have none.
const REPORT_MARK: &str = "] unsupported ";

/// What `stelad` keeps between runs.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct State {
    /// The bytes of the unsupported-operations log already read.
    unsupported_offset: u64,
}

impl Stelad {
    pub(crate) fn run(self) -> Result<()> {
        let environment = Environment::service()?;
        let Some(_lock) = lock(&environment)? else {
            return Ok(());
        };
        for _ in 0..MAX_PASSES {
            if !pass(&environment)? {
                break;
            }
        }
        Ok(())
    }
}

/// Hold `stelad`'s lock, or `None` when another run holds it.
fn lock(environment: &Environment) -> Result<Option<std::fs::File>> {
    let path = environment.state.with_file_name(LOCK);
    std::fs::create_dir_all(path.parent().context("no support folder")?)?;
    let file = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    // SAFETY: flock on an open descriptor has no other preconditions.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    Ok(locked.then_some(file))
}

/// One pass: whether it found anything to do.
fn pass(environment: &Environment) -> Result<bool> {
    let mut busy = notify(environment)?;
    let mut record = Record::read(&environment.record)?;
    if !record.paused {
        let changes = sync(environment, &mut record, &[], &[], false)?;
        record.write(&environment.record)?;
        changes.print(true, &record);
        busy |= !changes.lines.is_empty();
    }
    if let Some(config) = Config::from_environment() {
        let images: Vec<PathBuf> = record
            .launchers
            .iter()
            .flat_map(|entry| code_files(&entry.target))
            .collect();
        // The Mac the launchers' runs model, so the translations match them.
        let model = crate::run::model(None);
        let report = service::serve(config, &images, &model)?;
        if report != service::Report::default() {
            println!(
                "stelad: {} spooled translations, {} image files translated ({} unchanged), \
                 {} blocks; {} proven, {} records written, {} evicted",
                report.spooled,
                report.images,
                report.unchanged,
                report.blocks,
                report.proven,
                report.records,
                report.evicted
            );
        }
        busy |= report.spooled != 0 || report.images != 0;
    }
    Ok(busy)
}

/// The Mach-O files of the app bundle at `app` that hold code.
fn code_files(app: &Path) -> Vec<PathBuf> {
    fn walk(folder: &Path, depth: usize, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(folder) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        paths.sort();
        for path in paths {
            // Framework version links name files found through their
            // targets.
            if path.is_symlink() {
                continue;
            }
            if path.is_dir() {
                if depth > 1 {
                    walk(&path, depth - 1, found);
                }
            } else if mach_o(&path) {
                found.push(path);
            }
        }
    }
    let mut found = vec![];
    for folder in CODE_FOLDERS {
        walk(&app.join(folder), CODE_DEPTH, &mut found);
    }
    found
}

/// Whether the file at `path` starts as a 64-bit or fat Mach-O file does.
fn mach_o(path: &Path) -> bool {
    let mut magic = [0; 4];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok_and(|()| MACH_O_MAGICS.contains(&magic))
}

/// Post a notification for each app (up to [`MAX_NOTIFIED_APPS`]) the
/// unsupported-operations log names in the lines written since the last
/// pass: whether there were any.
fn notify(environment: &Environment) -> Result<bool> {
    let mut state: State = std::fs::read(&environment.state)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let Ok(mut log) = std::fs::File::open(&environment.unsupported) else {
        return Ok(false);
    };
    let length = log.metadata()?.len();
    if length < state.unsupported_offset {
        // A new log.
        state.unsupported_offset = 0;
    }
    if length == state.unsupported_offset {
        return Ok(false);
    }
    let start = state
        .unsupported_offset
        .max(length.saturating_sub(MAX_LOG_READ));
    let mut bytes = vec![];
    log.seek(SeekFrom::Start(start))?;
    log.take(length - start).read_to_end(&mut bytes)?;
    // Only whole lines; a line being written is read next time.
    let Some(end) = bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map(|end| end + 1)
    else {
        return Ok(false);
    };
    for (app, count) in unsupported_apps(&String::from_utf8_lossy(&bytes[..end]))
        .into_iter()
        .take(MAX_NOTIFIED_APPS)
    {
        post(environment, &app, count);
    }
    state.unsupported_offset = start + end as u64;
    std::fs::create_dir_all(environment.state.parent().context("no support folder")?)?;
    stela_runtime::write_json(&environment.state, &state)?;
    Ok(true)
}

/// The apps named by the program (else the image) paths of the
/// unsupported-operation entries of `lines`, with how many entries name
/// each, in the order they first appear.
fn unsupported_apps(lines: &str) -> Vec<(String, usize)> {
    let mut apps: Vec<(String, usize)> = vec![];
    for line in lines.lines().filter(|line| line.contains(REPORT_MARK)) {
        let Some(end) = line.find(APP_SUFFIX) else {
            continue;
        };
        let bundle = &line[..end];
        let name = bundle
            .rfind('/')
            .map_or(bundle, |slash| &bundle[slash + 1..]);
        match apps.iter_mut().find(|(app, _)| app == name) {
            Some((_, count)) => *count += 1,
            None => apps.push((name.to_owned(), 1)),
        }
    }
    apps
}

/// Tell the user that `app` met `count` unsupported operations. The text
/// reaches the script as arguments, never as script source.
fn post(environment: &Environment, app: &str, count: usize) {
    let message = format!(
        "{app} used {count} operation{} Stela does not support yet; {} lists {}.",
        if count == 1 { "" } else { "s" },
        environment.unsupported.display(),
        if count == 1 { "it" } else { "them" }
    );
    println!("stelad: {message}");
    if !environment.register {
        return;
    }
    let _ = Command::new(OSASCRIPT)
        .args([
            "-e",
            "on run argv",
            "-e",
            "display notification (item 1 of argv) with title \"Stela\" subtitle (item 2 of argv)",
            "-e",
            "end run",
        ])
        .arg(&message)
        .arg(app)
        .output();
}

#[cfg(test)]
mod tests {
    use super::super::tests::{ARM64, app, environment};
    use super::*;

    #[test]
    fn reported_lines_name_their_apps_once_with_a_count() {
        let lines = "2026-10-20T15:00:00Z /Applications/Foo.app/Contents/MacOS/Foo[12] \
                     unsupported instruction: MRS (at /Applications/Foo.app/Contents/MacOS/Foo+0x1234); \
                     EXC_BAD_INSTRUCTION (SIGILL) at the instruction\n\
                     2026-10-20T15:00:01Z /usr/bin/true[13] unsupported BSD system call: 999 \
                     (at /usr/lib/libSystem.B.dylib+0x10); it fails with ENOSYS and SIGSYS\n\
                     2026-10-20T15:00:02Z /Users/u/Bar Baz.app/Contents/MacOS/Bar[14] note: no MTE\n\
                     2026-10-20T15:00:03Z /Users/u/Bar Baz.app/Contents/MacOS/Bar[14] unsupported \
                     Mach trap: -99 (at /Users/u/Bar Baz.app/Contents/Frameworks/X.framework/X+0x8); \
                     it returns 0x10000003\n\
                     2026-10-20T15:00:04Z /Applications/Foo.app/Contents/MacOS/Foo[15] \
                     unsupported BSD system call: 998 (at /usr/lib/libSystem.B.dylib+0x99); \
                     it fails with ENOSYS and SIGSYS\n";
        assert_eq!(
            unsupported_apps(lines),
            [("Foo".to_owned(), 2), ("Bar Baz".to_owned(), 1)]
        );
    }

    #[test]
    fn only_new_whole_lines_of_the_log_are_read() -> Result<()> {
        let work = tempfile::tempdir()?;
        let environment = environment(work.path());
        assert!(!notify(&environment)?, "no log yet");
        std::fs::create_dir_all(&environment.logs)?;
        let line = "T /Applications/Foo.app/Contents/MacOS/Foo[1] unsupported instruction: X\n";
        std::fs::write(&environment.unsupported, format!("{line}partial"))?;
        assert!(notify(&environment)?);
        let offset = |environment: &Environment| -> Result<u64> {
            let state: State = serde_json::from_slice(&std::fs::read(&environment.state)?)?;
            Ok(state.unsupported_offset)
        };
        assert_eq!(offset(&environment)?, line.len() as u64);
        assert!(!notify(&environment)?, "the partial line waits");
        std::fs::write(&environment.unsupported, "new\n")?;
        assert!(notify(&environment)?, "a shorter log is a new one");
        assert_eq!(offset(&environment)?, 4);
        Ok(())
    }

    #[test]
    fn an_apps_code_files_are_its_mach_o_files_without_framework_links() -> Result<()> {
        let work = tempfile::tempdir()?;
        let arm = app(work.path(), "Arm", ARM64)?;
        let framework = arm.join("Contents/Frameworks/K.framework");
        let versions = framework.join("Versions/A");
        std::fs::create_dir_all(&versions)?;
        std::fs::copy(arm.join("Contents/MacOS/Arm"), versions.join("K"))?;
        std::os::unix::fs::symlink("Versions/A/K", framework.join("K"))?;
        std::fs::write(versions.join("Info.plist"), b"<plist/>")?;
        assert_eq!(
            code_files(&arm),
            [arm.join("Contents/MacOS/Arm"), versions.join("K")]
        );
        Ok(())
    }
}
