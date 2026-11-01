//! Upstream sources: the git submodules in `third_party/`, each at the
//! commit its gitlink pins. `fetch` checks each one out shallowly, limited to
//! the patterns in `third_party/<name>.sparse` where that file exists, and
//! applies Stela's series from `third_party/patches/<name>/` as commits on
//! the local branch `stela`. `export` writes a submodule's commits since its
//! pin back to that series, each file keeping its short name while its
//! commit's subject stays the same.
use super::support::capture;
use crate::tools::{self, exec};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// The series applied last and the commit it produced, in the submodule's
/// git directory.
const STATE: &str = "stela-series";

/// The committer of the series commits `checkout` applies.
const COMMITTER_EMAIL: &str = "stela@localhost";

struct Submodule {
    name: String,
    /// The checkout, relative to the repository root.
    path: String,
    url: String,
    /// The commit the superproject's gitlink pins.
    pin: String,
}

impl Submodule {
    fn directory(&self) -> PathBuf {
        tools::root().join(&self.path)
    }

    fn patches_directory(&self) -> PathBuf {
        tools::root().join("third_party/patches").join(&self.name)
    }

    /// Non-cone sparse-checkout patterns, or `None` for the whole tree.
    fn sparse(&self) -> Result<Option<String>> {
        let path = tools::root()
            .join("third_party")
            .join(format!("{}.sparse", self.name));
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(
                text.lines()
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(|line| format!("{line}\n"))
                    .collect(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| path.display().to_string()),
        }
    }

    fn patches(&self) -> Result<Vec<PathBuf>> {
        let mut patches = match fs::read_dir(self.patches_directory()) {
            Ok(entries) => entries
                .map(|entry| Ok(entry?.path()))
                .collect::<Result<Vec<_>>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        patches.retain(|path| path.extension().is_some_and(|e| e == "patch"));
        patches.sort();
        Ok(patches)
    }

    /// Binds the pin, sparse scope and patch series.
    fn series(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(self.pin.as_bytes());
        digest.update(self.sparse()?.unwrap_or_default().as_bytes());
        for patch in self.patches()? {
            digest.update(patch.file_name().unwrap().as_encoded_bytes());
            digest.update(Sha256::digest(fs::read(&patch)?));
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    fn git(&self) -> Command {
        git(&self.directory())
    }

    /// Whether the checkout has a commit, which a fetch stopped before its
    /// first checkout leaves it without.
    fn checked_out(&self) -> Result<bool> {
        Ok(self
            .git()
            .args(["rev-parse", "--verify", "-q", "HEAD"])
            .stdout(Stdio::null())
            .status()?
            .success())
    }

    fn head(&self) -> Result<String> {
        Ok(capture(self.git().args(["rev-parse", "HEAD"]))?
            .trim()
            .to_owned())
    }

    fn state_path(&self) -> Result<PathBuf> {
        let directory = capture(self.git().args(["rev-parse", "--absolute-git-dir"]))?;
        Ok(Path::new(directory.trim()).join(STATE))
    }

    fn state(&self) -> Result<Option<(String, String)>> {
        let Ok(text) = fs::read_to_string(self.state_path()?) else {
            return Ok(None);
        };
        Ok(text
            .trim()
            .split_once(' ')
            .map(|(series, head)| (series.to_owned(), head.to_owned())))
    }

    fn record(&self, series: &str) -> Result<()> {
        fs::write(self.state_path()?, format!("{series} {}\n", self.head()?))?;
        Ok(())
    }

    /// Whether the checkout already holds the pinned commit.
    fn has_pin(&self) -> Result<bool> {
        Ok(self
            .git()
            .args(["cat-file", "-e", &format!("{}^{{commit}}", self.pin)])
            .stderr(Stdio::null())
            .status()?
            .success())
    }

    /// Refuses a gitlink that names a commit `checkout` made by applying the
    /// series: no clone can fetch it. `git commit -a` or `git add` records one
    /// when the index has lost `hold_pin`'s flag.
    fn ensure_upstream_pin(&self) -> Result<()> {
        let committer = capture(
            self.git()
                .args(["log", "-1", "--format=%ce", &self.pin, "--"]),
        )?;
        ensure!(
            committer.trim() != COMMITTER_EMAIL,
            "{} pins {}, a local commit of Stela's patch series; restore its upstream pin \
             with `git update-index --cacheinfo 160000,<pin>,{}`",
            self.path,
            self.pin,
            self.path
        );
        Ok(())
    }

    /// Keeps `git commit -a` and `git add` from recording the checkout's HEAD,
    /// a local commit of the series, as the gitlink. The flag lives in the
    /// index, so each fetch sets it again; a new pin goes in with
    /// `git update-index --cacheinfo`.
    fn hold_pin(&self) -> Result<()> {
        exec(git(tools::root()).args(["update-index", "--assume-unchanged", "--", &self.path]))
    }

    /// Commits or tracked edits that `export` has not written to the series.
    /// A checkout at its bare pin, as `git submodule update` leaves it, has none.
    fn unexported(&self) -> Result<bool> {
        let dirty = !capture(
            self.git()
                .args(["status", "--porcelain", "--untracked-files=no"]),
        )?
        .is_empty();
        let head = self.head()?;
        let recorded = self.state()?.map(|(_, head)| head);
        Ok(dirty || (head != self.pin && recorded.as_ref() != Some(&head)))
    }
}

fn git(directory: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(directory);
    command
}

fn submodules() -> Result<Vec<Submodule>> {
    let root = tools::root();
    let config = |key: &str| -> Result<String> {
        Ok(
            capture(git(root).args(["config", "-f", ".gitmodules", "--get", key]))?
                .trim()
                .to_owned(),
        )
    };
    let paths = capture(git(root).args([
        "config",
        "-f",
        ".gitmodules",
        "--get-regexp",
        r"^submodule\..*\.path$",
    ]))?;
    let mut submodules = Vec::new();
    for line in paths.lines() {
        let (key, path) = line.split_once(' ').context("malformed .gitmodules")?;
        let name = key
            .strip_prefix("submodule.")
            .and_then(|key| key.strip_suffix(".path"))
            .context("malformed .gitmodules")?;
        // The gitlink in the index, as `git submodule update` reads it.
        let entry = capture(git(root).args(["ls-files", "--stage", "--", path]))?;
        let pin = entry
            .strip_prefix("160000 ")
            .and_then(|entry| entry.split_whitespace().next())
            .with_context(|| format!("{path} is not a submodule in the index"))?;
        submodules.push(Submodule {
            name: name.to_owned(),
            path: path.to_owned(),
            url: config(&format!("submodule.{name}.url"))?,
            pin: pin.to_owned(),
        });
    }
    Ok(submodules)
}

/// Creates the checkout the way `git submodule update --init` would, but
/// sparse before anything is checked out, then moves its git directory
/// into the superproject's.
fn initialize(submodule: &Submodule) -> Result<()> {
    let root = tools::root();
    let url = format!("submodule.{}.url", submodule.name);
    if !git(root)
        .args(["config", "--get", &url])
        .stdout(Stdio::null())
        .status()?
        .success()
    {
        exec(git(root).args(["submodule", "init", "--", &submodule.path]))?;
    }
    let directory = submodule.directory();
    fs::create_dir_all(&directory)?;
    exec(git(&directory).args(["init", "-q"]))?;
    // Pinned sources hash and build the same on every host.
    exec(git(&directory).args(["config", "core.autocrlf", "false"]))?;
    exec(git(&directory).args(["remote", "add", "origin", &submodule.url]))?;
    first_checkout(submodule)
}

fn first_checkout(submodule: &Submodule) -> Result<()> {
    checkout(submodule)?;
    exec(git(tools::root()).args(["submodule", "absorbgitdirs", "--", &submodule.path]))
}

/// Checks out the pin with its sparse scope and applies the series, fetching
/// from the URL `.gitmodules` names now.
fn checkout(submodule: &Submodule) -> Result<()> {
    println!("GPU source {}: {}", submodule.name, submodule.pin);
    exec(git(tools::root()).args(["submodule", "sync", "-q", "--", &submodule.path]))?;
    match submodule.sparse()? {
        Some(patterns) => {
            let mut sparse = submodule
                .git()
                .args(["sparse-checkout", "set", "--no-cone", "--stdin"])
                .stdin(Stdio::piped())
                .spawn()?;
            sparse
                .stdin
                .take()
                .unwrap()
                .write_all(patterns.as_bytes())?;
            ensure!(sparse.wait()?.success(), "git sparse-checkout failed");
        }
        None => exec(submodule.git().args(["sparse-checkout", "disable"]))?,
    }
    if !submodule.has_pin()? {
        exec(submodule.git().args([
            "fetch",
            "-q",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            &submodule.pin,
        ]))?;
    }
    exec(
        submodule
            .git()
            .args(["checkout", "-q", "-f", "-B", "stela", &submodule.pin]),
    )?;
    let patches = submodule.patches()?;
    if !patches.is_empty() {
        let applied = exec(
            submodule
                .git()
                .args(["-c", "user.name=Stela", "-c"])
                .arg(format!("user.email={COMMITTER_EMAIL}"))
                .args(["am", "-q", "--3way", "--committer-date-is-author-date"])
                .args(&patches),
        );
        if applied.is_err() {
            // Leave the checkout at its pin, with no `am` left to block the next.
            exec(submodule.git().args(["am", "--abort"]))?;
        }
        applied
            .with_context(|| format!("third_party/patches/{} no longer applies", submodule.name))?;
    }
    submodule.record(&submodule.series()?)
}

/// Installs the pinned tools, then checks out every submodule at its pin with
/// Stela's series.
pub fn fetch(force: bool) -> Result<()> {
    super::toolchain::install()?;
    for submodule in submodules()? {
        submodule.hold_pin()?;
        if !submodule.directory().join(".git").exists() {
            initialize(&submodule)?;
            continue;
        }
        if !submodule.checked_out()? {
            first_checkout(&submodule)?;
            continue;
        }
        if submodule.has_pin()? {
            submodule.ensure_upstream_pin()?;
        }
        let unexported = submodule.unexported()?;
        if !unexported && submodule.state()? == Some((submodule.series()?, submodule.head()?)) {
            continue;
        }
        ensure!(
            force || !unexported,
            "{} has commits or edits not in third_party/patches/{}; run `cargo xtask gpu export` \
             or pass --force to discard them",
            submodule.path,
            submodule.name
        );
        checkout(&submodule)?;
    }
    Ok(())
}

/// Writes each submodule's commits since its pin to its patch series.
pub fn export() -> Result<()> {
    for submodule in submodules()? {
        // A submodule never checked out has nothing to export.
        if !submodule.directory().join(".git").exists() {
            continue;
        }
        ensure!(
            capture(
                submodule
                    .git()
                    .args(["status", "--porcelain", "--untracked-files=no"])
            )?
            .is_empty(),
            "{} has uncommitted edits; commit them first",
            submodule.path
        );
        ensure!(
            submodule
                .git()
                .args(["merge-base", "--is-ancestor", &submodule.pin, "HEAD"])
                .status()?
                .success(),
            "{} is not based on its pinned commit {}",
            submodule.path,
            submodule.pin
        );
        let patches = submodule.patches_directory();
        let mut names = HashMap::new();
        for patch in submodule.patches()? {
            names.insert(subject(&patch)?, name(&patch));
            fs::remove_file(patch)?;
        }
        if submodule.head()? != submodule.pin {
            fs::create_dir_all(&patches)?;
            exec(
                submodule
                    .git()
                    .args([
                        "format-patch",
                        "-q",
                        "--no-numbered",
                        "--numbered-files",
                        "--zero-commit",
                        // Abbreviated blob names grow with the checkout.
                        "--full-index",
                        "--no-signature",
                    ])
                    .arg("-o")
                    .arg(&patches)
                    .arg(format!("{}..HEAD", submodule.pin)),
            )?;
            for number in 1.. {
                let patch = patches.join(number.to_string());
                if !patch.exists() {
                    break;
                }
                let subject = subject(&patch)?;
                let name = names.remove(&subject).unwrap_or_else(|| slug(&subject));
                fs::rename(patch, patches.join(format!("{number:04}-{name}.patch")))?;
            }
        } else if patches.is_dir() {
            fs::remove_dir(&patches)?;
        }
        submodule.record(&submodule.series()?)?;
    }
    Ok(())
}

/// A patch's subject, unfolded and without `[PATCH]`.
fn subject(patch: &Path) -> Result<String> {
    let text = fs::read_to_string(patch)?;
    let mut lines = text
        .lines()
        .skip_while(|line| !line.starts_with("Subject: "));
    let first = lines
        .next()
        .with_context(|| format!("{} has no subject", patch.display()))?;
    let mut subject = first["Subject: ".len()..]
        .trim_start_matches("[PATCH] ")
        .to_owned();
    for line in lines.take_while(|line| line.starts_with(' ')) {
        subject.push_str(line);
    }
    Ok(subject)
}

/// A patch file's name between its number and extension, which `export`
/// keeps while the commit's subject stays the same.
fn name(patch: &Path) -> String {
    let file = patch.file_stem().unwrap().to_string_lossy();
    file.split_once('-')
        .map_or(&*file, |(_, name)| name)
        .to_owned()
}

/// A new patch's name: the first three words of its subject's summary.
fn slug(subject: &str) -> String {
    let summary = subject
        .split_once(": ")
        .map_or(subject, |(_, summary)| summary);
    summary
        .replace('\'', "")
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .take(3)
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

/// Each submodule's origin, pin, checked-out commit and series, for receipts.
pub fn origins() -> Result<Value> {
    submodules()?
        .iter()
        .map(|submodule| {
            let patches = submodule
                .patches()?
                .iter()
                .map(|patch| tools::binding(patch))
                .collect::<Result<Vec<_>>>()?;
            Ok(json!({
                "name": submodule.name, "url": submodule.url, "pin": submodule.pin,
                "head": submodule.head()?, "patches": patches,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopped_first_fetch_is_a_checkout_without_a_commit() {
        let directory = tempfile::tempdir().unwrap();
        let submodule = Submodule {
            name: "stopped".into(),
            path: directory.path().to_str().unwrap().into(),
            url: String::new(),
            pin: String::new(),
        };
        exec(submodule.git().args(["init", "-q"])).unwrap();
        assert!(!submodule.checked_out().unwrap());
        exec(submodule.git().args([
            "-c",
            "user.name=Stela",
            "-c",
            "user.email=stela@localhost",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "first",
        ]))
        .unwrap();
        assert!(submodule.checked_out().unwrap());
    }

    #[test]
    fn names_follow_subjects() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let patch = directory.path().join("0002-stela-compilers.patch");
        fs::write(
            &patch,
            "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n\
             Subject: [PATCH] meson: build Stela's shader compiler libraries without API\n \
             drivers\n\n---\n",
        )?;
        assert_eq!(
            subject(&patch)?,
            "meson: build Stela's shader compiler libraries without API drivers"
        );
        assert_eq!(name(&patch), "stela-compilers");
        assert_eq!(slug(&subject(&patch)?), "build-stelas-shader");
        assert_eq!(slug("brw: Add Xe3P (GFX_VERx10 == 350)"), "add-xe3p-gfx");
        Ok(())
    }
}
