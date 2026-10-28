//! Intel macOS launcher and per-user service implementation.
#[path = "agent.rs"]
mod agent;
#[path = "launcher.rs"]
mod launcher;
#[path = "stelad.rs"]
mod stelad;

use super::{Apps, Stelad};

use crate::bundle::AppBundle;
use crate::guest_system;
use crate::run::program::Architectures;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use stela_runtime::hosted::translations::{Config, service};

/// The system-wide applications folder.
const APPLICATIONS: &str = "/Applications";
/// The per-user applications folder below the home directory.
const USER_APPLICATIONS: &str = "Applications";
/// The launchers' folder inside it.
const LAUNCHERS: &str = "Stela";
/// Stela's log folder below the home directory.
const LOGS: &str = "Library/Logs/Stela";
/// The unsupported-operations log in it
/// (`docs/design/runtime.md#unsupported-operations`).
const UNSUPPORTED_LOG: &str = "unsupported.log";
/// The record below the Stela support directory.
const RECORD: &str = "apps.json";
const RECORD_SCHEMA: u32 = 1;
/// Stela's preferences below its support directory: the Mac every hosted
/// run models unless told otherwise.
const PREFERENCES: &str = "preferences.json";
/// What `--model` takes to return to the default board.
const DEFAULT_MODEL_WORD: &str = "default";
/// The launcher program built with `stela`, found beside it.
const LAUNCHER_PROGRAM: &str = "stela-launcher";
/// How deep below a scanned folder apps are looked for: the folder itself
/// and its plain subfolders (`/Applications/Utilities`).
const SCAN_DEPTH: usize = 2;

/// Where launchers come from and go, and whether the system is told.
#[derive(Debug, Clone)]
pub(crate) struct Environment {
    /// Folders scanned for apps.
    scan: Vec<PathBuf>,
    /// `~/Applications/Stela`.
    launchers: PathBuf,
    /// The record.
    record: PathBuf,
    /// `~/Library/LaunchAgents`.
    agents: PathBuf,
    /// `~/Library/Logs/Stela`.
    logs: PathBuf,
    /// The unsupported-operations log processes append to, in `logs`.
    unsupported: PathBuf,
    /// Stela's preferences, beside the record.
    preferences: PathBuf,
    /// `stelad`'s state, beside the record.
    state: PathBuf,
    /// The translation store's spool, when the store is on.
    spool: Option<PathBuf>,
    /// The `stela` executable launchers run.
    stela: PathBuf,
    /// The launcher program copied into each launcher.
    launcher_program: PathBuf,
    /// Register with LaunchServices and launchd.
    register: bool,
}

impl Environment {
    fn new(scan: &[PathBuf], register: bool) -> Result<Self> {
        let home = guest_system::home()?;
        let support = guest_system::support_directory()?;
        let stela = std::env::current_exe()?;
        let scan = if scan.is_empty() {
            vec![PathBuf::from(APPLICATIONS), home.join(USER_APPLICATIONS)]
        } else {
            scan.to_vec()
        };
        Ok(Self {
            scan,
            launchers: home.join(USER_APPLICATIONS).join(LAUNCHERS),
            record: support.join(RECORD),
            agents: home.join(agent::AGENTS),
            logs: home.join(LOGS),
            unsupported: home.join(LOGS).join(UNSUPPORTED_LOG),
            preferences: support.join(PREFERENCES),
            state: support.join(stelad::STATE),
            spool: Config::from_environment().map(|config| service::spool_directory(&config)),
            launcher_program: stela.with_file_name(LAUNCHER_PROGRAM),
            stela,
            register,
        })
    }

    fn of(command: &Apps) -> Result<Self> {
        Self::new(&command.scan, !command.no_register)
    }

    /// `stelad`'s, which tells launchd only when `HOME` is the user's own
    /// home directory, the one launchd's GUI domain loads agents from.
    fn service() -> Result<Self> {
        let home = guest_system::home()?;
        Self::new(
            &[],
            launchd_home().is_some_and(|own| same_file(&own, &home)),
        )
    }
}

/// Stela's preferences (`preferences.json`).
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Preferences {
    /// The Mac hosted runs model, by product type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
}

impl Preferences {
    fn read(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
}

/// The Mac the user chose for hosted runs (`stela apps --model`), if any.
pub(crate) fn preferred_model() -> Option<String> {
    let path = guest_system::support_directory().ok()?.join(PREFERENCES);
    Preferences::read(&path).model
}

/// Set the Mac hosted runs model to `model` (`default` for the default
/// board), which must be one Stela models.
fn set_model(environment: &Environment, model: &str, dry_run: bool) -> Result<()> {
    let chosen = (model != DEFAULT_MODEL_WORD).then(|| model.to_owned());
    if let Some(model) = &chosen {
        ensure!(
            stela_runtime::hosted::hardware::models().any(|known| known == model),
            "Stela models no Mac {model:?}; the models are {}",
            stela_runtime::hosted::hardware::models()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let shown = chosen
        .as_deref()
        .unwrap_or(stela_runtime::hosted::hardware::DEFAULT_MODEL);
    println!(
        "{} {shown} in hosted runs without --model or STELA_MODEL",
        if dry_run { "Would model" } else { "Modeling" }
    );
    if dry_run {
        return Ok(());
    }
    let mut preferences = Preferences::read(&environment.preferences);
    preferences.model = chosen;
    std::fs::create_dir_all(
        environment
            .preferences
            .parent()
            .context("no support folder")?,
    )?;
    stela_runtime::write_json(&environment.preferences, &preferences)
}

/// The calling user's home directory in the user database.
fn launchd_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getuid has no pointer arguments or caller preconditions.
    let uid = unsafe { libc::getuid() };
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: entry and found are writable out-parameters, and buffer owns
        // the supplied writable byte range through this synchronous lookup.
        // The reentrant API keeps returned strings in this caller-owned buffer.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || found.is_null() {
            return None;
        }
        // SAFETY: a successful lookup with nonnull found initialized entry.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_dir.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r placed the NUL-terminated home directory in buffer,
        // which remains live and unmodified until the path is copied below.
        let directory = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
        return Some(PathBuf::from(std::ffi::OsStr::from_bytes(
            directory.to_bytes(),
        )));
    }
}

/// Whether `a` and `b` name the same existing file.
fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b)
}

/// Install `stelad` for `stela install-system`: its LaunchAgent, which
/// replaces the launcher agent of earlier versions.
pub(crate) fn install_service(dry_run: bool) -> Result<()> {
    let environment = Environment::service()?;
    if dry_run {
        println!("Would install {}", agent::path(&environment).display());
        return Ok(());
    }
    for line in agent::install(&environment)? {
        println!("{line}");
    }
    if let Ok(mut record) = Record::read(&environment.record)
        && record.agent.take().is_some()
    {
        record.write(&environment.record)?;
    }
    Ok(())
}

/// Remove `stelad` for `stela install-system --remove`: its LaunchAgent
/// (and the launcher agent's), and the store's service marker and spool,
/// so processes prove their own translations again.
pub(crate) fn remove_service(dry_run: bool) -> Result<()> {
    let environment = Environment::service()?;
    if dry_run {
        println!("Would remove {}", agent::path(&environment).display());
        return Ok(());
    }
    for plist in agent::remove(&environment)? {
        println!("Removed {}", plist.display());
    }
    if let Some(config) = Config::from_environment() {
        service::set_served(&config, false)?;
    }
    if let Some(spool) = &environment.spool
        && spool.is_dir()
    {
        std::fs::remove_dir_all(spool)
            .with_context(|| format!("cannot remove {}", spool.display()))?;
    }
    if let Ok(mut record) = Record::read(&environment.record)
        && record.agent.take().is_some()
    {
        record.write(&environment.record)?;
    }
    Ok(())
}

/// One launcher Stela made.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Entry {
    /// The launcher bundle.
    launcher: PathBuf,
    /// The app it opens.
    target: PathBuf,
    /// Added with `--add` rather than found by the scan.
    explicit: bool,
    /// What the launcher was made from; a change rebuilds it.
    fingerprint: String,
}

/// `apps.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    schema_version: u32,
    launchers: Vec<Entry>,
    /// The launcher agent's property list, when an earlier version's
    /// `--watch` installed it; installing `stelad` replaces it.
    agent: Option<PathBuf>,
    /// Set by `--uninstall` while `stelad` is installed: its sync makes no
    /// launchers until `stela apps` runs again.
    #[serde(default)]
    paused: bool,
    /// Apps whose launcher `--remove` removed: the scan skips them until
    /// `--add` names them again.
    #[serde(default)]
    excluded: Vec<PathBuf>,
    /// The folders Stela created for the launchers, outermost first, which
    /// `--uninstall` removes when they are empty.
    #[serde(default)]
    created: Vec<PathBuf>,
}

impl Record {
    fn read(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                schema_version: RECORD_SCHEMA,
                ..Self::default()
            });
        }
        let record: Self = stela_runtime::read_json(path)
            .with_context(|| format!("{} is not Stela's app record", path.display()))?;
        ensure!(
            record.schema_version == RECORD_SCHEMA,
            "{} was written by another version of stela",
            path.display()
        );
        Ok(record)
    }

    /// Note the folders up to `folder` that do not exist yet, before they
    /// are created.
    fn note_folders(&mut self, folder: &Path) {
        let mut missing = vec![];
        let mut current = Some(folder);
        while let Some(path) = current
            && !path.exists()
        {
            missing.push(path.to_owned());
            current = path.parent();
        }
        for path in missing.into_iter().rev() {
            if !self.created.contains(&path) {
                self.created.push(path);
            }
        }
    }

    fn write(&self, path: &Path) -> Result<()> {
        if self.launchers.is_empty()
            && self.agent.is_none()
            && !self.paused
            && self.excluded.is_empty()
            && self.created.is_empty()
        {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            return Ok(());
        }
        std::fs::create_dir_all(path.parent().context("record has no folder")?)?;
        stela_runtime::write_json(path, self)
    }
}

/// An app found to need a launcher.
struct Wanted {
    bundle: AppBundle,
    explicit: bool,
}

/// Whether the app at `path` runs only under Stela here.
fn arm64_only(bundle: &AppBundle) -> bool {
    bundle
        .executable()
        .and_then(|executable| Architectures::of(&executable))
        .is_ok_and(|architectures| architectures.arm64_only())
}

/// The app bundles in `folder` and its plain subfolders, skipping `skip`.
fn scan(folder: &Path, depth: usize, skip: &Path, found: &mut Vec<AppBundle>) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if path == skip || path.is_symlink() {
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "app") {
            if let Ok(bundle) = AppBundle::open(&path) {
                found.push(bundle);
            }
        } else if depth > 1 && path.is_dir() {
            scan(&path, depth - 1, skip, found);
        }
    }
}

/// The launcher path for `bundle`: its own name, or with its folder's name
/// when another wanted app has that name.
fn launcher_path(environment: &Environment, bundle: &AppBundle, taken: &[PathBuf]) -> PathBuf {
    let plain = environment.launchers.join(format!("{}.app", bundle.name()));
    if !taken.contains(&plain) {
        return plain;
    }
    let folder = bundle
        .path
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    environment
        .launchers
        .join(format!("{} ({folder}).app", bundle.name()))
}

/// What a sync did.
#[derive(Debug, Default)]
struct Changes {
    lines: Vec<String>,
    warnings: Vec<String>,
}

impl Changes {
    fn print(&self, quiet: bool, record: &Record) {
        for line in &self.lines {
            println!("{line}");
        }
        for warning in &self.warnings {
            eprintln!("warning: {warning}");
        }
        if quiet {
            return;
        }
        if record.launchers.is_empty() {
            println!(
                "No arm64-only apps found. Universal and Intel apps run natively; `stela apps \
                 --add PATH.app` adds an arm64-only app kept elsewhere."
            );
        } else if self.lines.is_empty() {
            list(record);
        }
    }
}

fn list(record: &Record) {
    for entry in &record.launchers {
        println!(
            "{} opens {} under Stela",
            entry.launcher.display(),
            entry.target.display()
        );
    }
    if let Some(agent) = &record.agent {
        println!("Kept in sync by {}", agent.display());
    }
}

/// Bring the launchers in line with the apps: `add` and the scan's arm64-only
/// apps get one, `remove` and apps gone or no longer arm64-only lose theirs.
fn sync(
    environment: &Environment,
    record: &mut Record,
    add: &[PathBuf],
    remove: &[String],
    dry_run: bool,
) -> Result<Changes> {
    let mut changes = Changes::default();
    let mut wanted: Vec<Wanted> = vec![];
    for path in add {
        ensure!(
            AppBundle::is_bundle(path),
            "{} is not an app bundle",
            path.display()
        );
        let bundle = AppBundle::open(path)?;
        let architectures = Architectures::of(&bundle.executable()?)?;
        if !architectures.arm64() {
            bail!(
                "{} is not an arm64 app ({}); Stela runs arm64 apps",
                bundle.name(),
                architectures.names()
            );
        }
        if architectures.x86_64() {
            bail!(
                "{} runs natively on this Mac ({}); open it directly",
                bundle.name(),
                architectures.names()
            );
        }
        record.excluded.retain(|excluded| *excluded != bundle.path);
        wanted.push(Wanted {
            bundle,
            explicit: true,
        });
    }
    for entry in record.launchers.iter().filter(|entry| entry.explicit) {
        if wanted
            .iter()
            .any(|wanted| wanted.bundle.path == entry.target)
        {
            continue;
        }
        if let Ok(bundle) = AppBundle::open(&entry.target)
            && arm64_only(&bundle)
        {
            wanted.push(Wanted {
                bundle,
                explicit: true,
            });
        }
    }
    let mut found = vec![];
    for folder in &environment.scan {
        scan(folder, SCAN_DEPTH, &environment.launchers, &mut found);
    }
    for bundle in found {
        if arm64_only(&bundle)
            && !record.excluded.contains(&bundle.path)
            && !wanted
                .iter()
                .any(|wanted| wanted.bundle.path == bundle.path)
        {
            wanted.push(Wanted {
                bundle,
                explicit: false,
            });
        }
    }
    let removed = |target: &Path, launcher: &Path| {
        remove.iter().any(|name| {
            Path::new(name) == target
                || std::path::absolute(name).is_ok_and(|path| path == target)
                || launcher
                    .file_stem()
                    .is_some_and(|stem| stem == name.as_str())
                || target.file_stem().is_some_and(|stem| stem == name.as_str())
        })
    };
    for name in remove {
        let known = record
            .launchers
            .iter()
            .any(|entry| removed(&entry.target, &entry.launcher));
        ensure!(known, "Stela made no launcher for {name}");
    }
    for entry in &record.launchers {
        if removed(&entry.target, &entry.launcher) && !record.excluded.contains(&entry.target) {
            record.excluded.push(entry.target.clone());
        }
    }
    wanted.retain(|wanted| {
        !record.launchers.iter().any(|entry| {
            entry.target == wanted.bundle.path && removed(&entry.target, &entry.launcher)
        })
    });
    // Launchers whose app is no longer wanted go first, so their names free up.
    let mut kept = vec![];
    for entry in std::mem::take(&mut record.launchers) {
        if wanted
            .iter()
            .any(|wanted| wanted.bundle.path == entry.target)
        {
            kept.push(entry);
            continue;
        }
        if !launcher::is_ours(&entry.launcher, &entry.target) {
            changes.warnings.push(format!(
                "{} is no longer Stela's launcher; left as it is",
                entry.launcher.display()
            ));
            continue;
        }
        changes.lines.push(format!(
            "{} launcher {} ({} is gone, no longer arm64-only, or was removed)",
            if dry_run { "Would remove" } else { "Removed" },
            entry.launcher.display(),
            entry.target.display()
        ));
        if !dry_run {
            launcher::remove(environment, &entry.launcher)?;
        }
    }
    let program_digest = launcher::program_digest(environment)?;
    // Kept launchers keep their names; a new one takes a free name.
    let mut taken: Vec<PathBuf> = kept.iter().map(|entry| entry.launcher.clone()).collect();
    for wanted in &wanted {
        let earlier = kept
            .iter()
            .find(|entry| entry.target == wanted.bundle.path)
            .cloned();
        let path = match &earlier {
            Some(entry) => entry.launcher.clone(),
            None => launcher_path(environment, &wanted.bundle, &taken),
        };
        let fingerprint = launcher::fingerprint(environment, &wanted.bundle, &program_digest)?;
        let current = earlier.as_ref().is_some_and(|entry| {
            entry.fingerprint == fingerprint && launcher::is_ours(&path, &entry.target)
        });
        if current {
            continue;
        }
        if earlier.is_none() && path.exists() && !launcher::is_ours(&path, &wanted.bundle.path) {
            changes.warnings.push(format!(
                "{} exists and is not Stela's; no launcher for {}",
                path.display(),
                wanted.bundle.path.display()
            ));
            continue;
        }
        if earlier.is_none() {
            taken.push(path.clone());
        }
        let verb = match (&earlier, dry_run) {
            (None, true) => "Would add",
            (None, false) => "Added",
            (Some(_), true) => "Would update",
            (Some(_), false) => "Updated",
        };
        if !dry_run {
            record.note_folders(&environment.launchers);
            launcher::create(environment, &wanted.bundle, &path)?;
        }
        changes.lines.push(format!(
            "{verb} launcher {} for {}",
            path.display(),
            wanted.bundle.path.display()
        ));
        kept.retain(|entry| entry.target != wanted.bundle.path);
        kept.push(Entry {
            launcher: path,
            target: wanted.bundle.path.clone(),
            explicit: wanted.explicit,
            fingerprint,
        });
    }
    kept.sort_by(|a, b| a.launcher.cmp(&b.launcher));
    record.launchers = kept;
    Ok(changes)
}

/// Remove every launcher in the record that is still Stela's with its log,
/// an earlier version's launcher agent with its log, the record, and the
/// folders Stela created when they are then empty. While `stelad` is
/// installed, the record stays to pause its sync.
fn uninstall(environment: &Environment, record: &mut Record, dry_run: bool) -> Result<()> {
    let verb = if dry_run { "Would remove" } else { "Removed" };
    let mut logs = vec![];
    if let Some(plist) = record.agent.clone() {
        println!("{verb} {}", plist.display());
        if !dry_run {
            agent::remove_legacy(environment)?;
            record.agent = None;
        }
    }
    for entry in std::mem::take(&mut record.launchers) {
        if !launcher::is_ours(&entry.launcher, &entry.target) {
            eprintln!(
                "warning: {} is no longer Stela's launcher; left as it is",
                entry.launcher.display()
            );
            continue;
        }
        println!("{verb} {}", entry.launcher.display());
        if let Some(name) = entry.launcher.file_stem() {
            logs.push(
                environment
                    .logs
                    .join(format!("{}.log", name.to_string_lossy())),
            );
        }
        if !dry_run {
            launcher::remove(environment, &entry.launcher)?;
        }
    }
    if dry_run {
        return Ok(());
    }
    for log in logs.iter().filter(|log| log.is_file()) {
        std::fs::remove_file(log)?;
    }
    let empty =
        |folder: &Path| std::fs::read_dir(folder).is_ok_and(|mut entries| entries.next().is_none());
    if empty(&environment.logs) {
        std::fs::remove_dir(&environment.logs)?;
    }
    for folder in std::mem::take(&mut record.created).iter().rev() {
        if empty(folder) {
            std::fs::remove_dir(folder)?;
            println!("{verb} {}", folder.display());
        }
    }
    record.excluded.clear();
    record.paused = agent::path(environment).is_file();
    record.write(&environment.record)
}

impl Apps {
    pub(crate) fn run(self) -> Result<()> {
        let environment = Environment::of(&self)?;
        let mut record = Record::read(&environment.record)?;
        if self.list {
            if record.launchers.is_empty() {
                println!("Stela has made no launchers; `stela apps` makes them.");
            }
            list(&record);
            return Ok(());
        }
        if self.uninstall {
            return uninstall(&environment, &mut record, self.dry_run);
        }
        if let Some(model) = &self.model {
            return set_model(&environment, model, self.dry_run);
        }
        let changes = sync(
            &environment,
            &mut record,
            &self.add,
            &self.remove,
            self.dry_run,
        )?;
        if !self.dry_run {
            record.paused = false;
            record.write(&environment.record)?;
        }
        changes.print(self.quiet, &record);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bundle::tests::{info, make};
    use crate::run::program::tests::thin;
    use plist::Value;

    pub(crate) use crate::run::program::CPU_TYPE_X86_64 as X86_64;
    pub(crate) use stela_runtime::hosted::hardware::CPU_TYPE_ARM64 as ARM64;

    /// An app `name` in `folder` whose executable is a Mach-O of `cpu`.
    pub(crate) fn app(folder: &Path, name: &str, cpu: u32) -> Result<PathBuf> {
        let path = folder.join(format!("{name}.app"));
        let mut document = plist::Dictionary::new();
        document.insert("CFBundleTypeName".into(), "Text".into());
        document.insert("LSHandlerRank".into(), "Owner".into());
        make(
            &path,
            info(&[
                ("CFBundleExecutable", name.into()),
                ("CFBundleIdentifier", format!("com.example.{name}").into()),
                ("CFBundleName", name.into()),
                ("CFBundleIconFile", "AppIcon".into()),
                (
                    "CFBundleDocumentTypes",
                    Value::Array(vec![Value::Dictionary(document)]),
                ),
            ]),
            &thin(cpu, 0),
        )?;
        std::fs::create_dir_all(path.join("Contents/Resources"))?;
        std::fs::write(path.join("Contents/Resources/AppIcon.icns"), b"icns")?;
        Ok(path)
    }

    pub(crate) fn environment(work: &Path) -> Environment {
        Environment {
            scan: vec![work.join("Applications")],
            launchers: work.join("home/Applications/Stela"),
            record: work.join("home/Library/Application Support/Stela/apps.json"),
            agents: work.join("home/Library/LaunchAgents"),
            logs: work.join("home/Library/Logs/Stela"),
            unsupported: work.join("home/Library/Logs/Stela/unsupported.log"),
            preferences: work.join("home/Library/Application Support/Stela/preferences.json"),
            state: work.join("home/Library/Application Support/Stela/stelad.json"),
            spool: Some(work.join("home/Library/Caches/stela/translations/v1/spool")),
            stela: PathBuf::from("/usr/local/bin/stela"),
            // Any signable Mach-O stands in for the launcher program.
            launcher_program: PathBuf::from("/usr/bin/true"),
            register: false,
        }
    }

    #[test]
    fn only_arm64_only_apps_get_launchers_and_gone_apps_lose_them() -> Result<()> {
        let work = tempfile::tempdir()?;
        let applications = work.path().join("Applications");
        let utilities = applications.join("Utilities");
        std::fs::create_dir_all(&utilities)?;
        let arm = app(&applications, "Arm", ARM64)?;
        app(&applications, "Intel", X86_64)?;
        let tool = app(&utilities, "Tool", ARM64)?;
        let environment = environment(work.path());
        let mut record = Record::read(&environment.record)?;
        let dry = sync(&environment, &mut record.clone(), &[], &[], true)?;
        assert_eq!(dry.lines.len(), 2, "{:?}", dry.lines);
        assert!(!environment.launchers.exists(), "a dry run changes nothing");
        let changes = sync(&environment, &mut record, &[], &[], false)?;
        assert_eq!(changes.lines.len(), 2, "{:?}", changes.lines);
        let targets: Vec<&Path> = record
            .launchers
            .iter()
            .map(|e| e.target.as_path())
            .collect();
        assert_eq!(targets, [arm.as_path(), tool.as_path()]);
        assert!(environment.launchers.join("Arm.app").is_dir());
        assert!(!environment.launchers.join("Intel.app").exists());
        record.write(&environment.record)?;
        assert_eq!(Record::read(&environment.record)?, record);
        // A second sync changes nothing; a gone app loses its launcher.
        assert!(
            sync(&environment, &mut record, &[], &[], false)?
                .lines
                .is_empty()
        );
        std::fs::remove_dir_all(&tool)?;
        let changes = sync(&environment, &mut record, &[], &[], false)?;
        assert_eq!(changes.lines.len(), 1, "{:?}", changes.lines);
        assert!(!environment.launchers.join("Tool.app").exists());
        uninstall(&environment, &mut record, false)?;
        assert!(!environment.launchers.exists() && !environment.record.exists());
        assert!(
            !environment.launchers.parent().unwrap().exists(),
            "the folders Stela created go too"
        );
        assert!(
            arm.join("Contents/Info.plist").is_file(),
            "originals are kept"
        );
        Ok(())
    }

    #[test]
    fn a_changed_app_rebuilds_its_launcher_and_foreign_bundles_are_left_alone() -> Result<()> {
        let work = tempfile::tempdir()?;
        let applications = work.path().join("Applications");
        std::fs::create_dir_all(&applications)?;
        let arm = app(&applications, "Arm", ARM64)?;
        let environment = environment(work.path());
        let mut record = Record::default();
        sync(&environment, &mut record, &[], &[], false)?;
        let mut info = AppBundle::open(&arm)?.info;
        info.insert("CFBundleShortVersionString".into(), "2.0".into());
        Value::Dictionary(info).to_file_xml(arm.join("Contents/Info.plist"))?;
        let changes = sync(&environment, &mut record, &[], &[], false)?;
        assert!(
            changes.lines[0].starts_with("Updated"),
            "{:?}",
            changes.lines
        );
        // Someone else's bundle where a launcher would go is never replaced.
        let other = app(&applications, "Other", ARM64)?;
        let foreign = environment.launchers.join("Other.app");
        std::fs::create_dir_all(foreign.join("Contents"))?;
        std::fs::write(foreign.join("Contents/Info.plist"), b"mine")?;
        let changes = sync(&environment, &mut record, &[], &[], false)?;
        assert_eq!(changes.warnings.len(), 1, "{:?}", changes.warnings);
        assert_eq!(std::fs::read(foreign.join("Contents/Info.plist"))?, b"mine");
        assert!(!record.launchers.iter().any(|entry| entry.target == other));
        uninstall(&environment, &mut record, false)?;
        assert!(foreign.is_dir(), "uninstall keeps what Stela did not make");
        Ok(())
    }

    #[test]
    fn apps_kept_elsewhere_are_added_and_removed_by_name() -> Result<()> {
        let work = tempfile::tempdir()?;
        let elsewhere = work.path().join("Downloads");
        std::fs::create_dir_all(&elsewhere)?;
        let arm = app(&elsewhere, "Arm", ARM64)?;
        let intel = app(&elsewhere, "Intel", X86_64)?;
        let environment = environment(work.path());
        let mut record = Record::default();
        let message = sync(&environment, &mut record, &[intel], &[], false)
            .unwrap_err()
            .to_string();
        assert!(message.contains("not an arm64 app"), "{message}");
        sync(
            &environment,
            &mut record,
            std::slice::from_ref(&arm),
            &[],
            false,
        )?;
        assert!(record.launchers[0].explicit);
        // Explicit apps stay without being named again.
        sync(&environment, &mut record, &[], &[], false)?;
        assert_eq!(record.launchers.len(), 1);
        assert!(sync(&environment, &mut record, &[], &["Nothing".into()], false).is_err());
        sync(&environment, &mut record, &[], &["Arm".into()], false)?;
        assert!(record.launchers.is_empty());
        assert!(!environment.launchers.join("Arm.app").exists());
        Ok(())
    }

    #[test]
    fn a_removed_app_stays_removed_until_it_is_added_again() -> Result<()> {
        let work = tempfile::tempdir()?;
        let applications = work.path().join("Applications");
        std::fs::create_dir_all(&applications)?;
        let arm = app(&applications, "Arm", ARM64)?;
        let environment = environment(work.path());
        let mut record = Record::default();
        sync(&environment, &mut record, &[], &[], false)?;
        sync(
            &environment,
            &mut record,
            &[],
            &[arm.display().to_string()],
            false,
        )?;
        assert!(record.launchers.is_empty() && record.excluded == [arm.clone()]);
        sync(&environment, &mut record, &[], &[], false)?;
        assert!(record.launchers.is_empty(), "the scan skips it");
        sync(
            &environment,
            &mut record,
            std::slice::from_ref(&arm),
            &[],
            false,
        )?;
        assert_eq!(record.launchers.len(), 1);
        assert!(record.excluded.is_empty());
        Ok(())
    }

    #[test]
    fn uninstalling_the_launchers_pauses_stelads_sync_and_replaces_the_launcher_agent() -> Result<()>
    {
        let work = tempfile::tempdir()?;
        let applications = work.path().join("Applications");
        std::fs::create_dir_all(&applications)?;
        app(&applications, "Arm", ARM64)?;
        let environment = environment(work.path());
        let mut record = Record {
            schema_version: RECORD_SCHEMA,
            agent: Some(agent::legacy_path(&environment)),
            ..Record::default()
        };
        agent::install(&environment)?;
        sync(&environment, &mut record, &[], &[], false)?;
        uninstall(&environment, &mut record, false)?;
        assert!(record.launchers.is_empty() && record.agent.is_none());
        assert_eq!(
            Record::read(&environment.record)?,
            Record {
                schema_version: RECORD_SCHEMA,
                paused: true,
                ..Record::default()
            },
            "the record stays while stelad is installed"
        );
        Ok(())
    }

    #[test]
    fn the_modeled_mac_is_one_preference_and_only_a_known_one() -> Result<()> {
        let work = tempfile::tempdir()?;
        let environment = environment(work.path());
        let model = stela_runtime::hosted::hardware::models()
            .find(|model| *model != stela_runtime::hosted::hardware::DEFAULT_MODEL)
            .expect("another board");
        set_model(&environment, model, true)?;
        assert!(
            !environment.preferences.exists(),
            "a dry run changes nothing"
        );
        set_model(&environment, model, false)?;
        assert_eq!(
            Preferences::read(&environment.preferences).model.as_deref(),
            Some(model)
        );
        assert!(set_model(&environment, "Mac0,0", false).is_err());
        set_model(&environment, DEFAULT_MODEL_WORD, false)?;
        assert_eq!(Preferences::read(&environment.preferences).model, None);
        Ok(())
    }

    #[test]
    fn same_named_apps_get_launchers_named_by_their_folder() -> Result<()> {
        let work = tempfile::tempdir()?;
        let applications = work.path().join("Applications");
        let beta = applications.join("Beta");
        std::fs::create_dir_all(&beta)?;
        app(&applications, "Arm", ARM64)?;
        app(&beta, "Arm", ARM64)?;
        let environment = environment(work.path());
        let mut record = Record::default();
        sync(&environment, &mut record, &[], &[], false)?;
        let names: Vec<String> = record
            .launchers
            .iter()
            .map(|entry| entry.launcher.file_name().unwrap().to_string_lossy().into())
            .collect();
        assert_eq!(names, ["Arm (Beta).app", "Arm.app"]);
        Ok(())
    }

    #[test]
    fn a_kept_launcher_keeps_its_name_when_a_same_named_app_is_added() -> Result<()> {
        let work = tempfile::tempdir()?;
        let applications = work.path().join("Applications");
        let elsewhere = work.path().join("Downloads");
        std::fs::create_dir_all(&applications)?;
        std::fs::create_dir_all(&elsewhere)?;
        let scanned = app(&applications, "Arm", ARM64)?;
        let added = app(&elsewhere, "Arm", ARM64)?;
        let environment = environment(work.path());
        let mut record = Record::default();
        sync(&environment, &mut record, &[], &[], false)?;
        let changes = sync(
            &environment,
            &mut record,
            std::slice::from_ref(&added),
            &[],
            false,
        )?;
        assert!(changes.warnings.is_empty(), "{:?}", changes.warnings);
        let launchers: Vec<(&Path, &Path)> = record
            .launchers
            .iter()
            .map(|entry| (entry.launcher.as_path(), entry.target.as_path()))
            .collect();
        assert_eq!(
            launchers,
            [
                (
                    environment.launchers.join("Arm (Downloads).app").as_path(),
                    added.as_path()
                ),
                (
                    environment.launchers.join("Arm.app").as_path(),
                    scanned.as_path()
                ),
            ]
        );
        Ok(())
    }
}
