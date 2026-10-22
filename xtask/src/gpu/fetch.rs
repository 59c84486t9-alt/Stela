//! Pinned upstream GPU sources. Each origin in `gpu/sources.json` is a shallow
//! sparse checkout under `.tools/gpu/src/<name>` with Stela's patch series
//! from `gpu/patches/<name>` applied as commits on its pinned revision. Every
//! imported file is linked into `gpu/<to>`, so the ports keep their relative
//! include paths and an edit through a link lands in that checkout, where
//! `cargo xtask gpu export` turns its commits back into the patch series.
use super::support::{capture, tool};
use crate::tools::{self, exec};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

/// The patch series applied last, and the checkout commit it produced.
const STATE: &str = "stela-series";

struct Import {
    from: String,
    to: String,
    excluded: Vec<String>,
}

struct Origin {
    name: String,
    url: String,
    commit: String,
    imports: Vec<Import>,
    wraps: Vec<String>,
}

fn gpu() -> PathBuf {
    tools::root().join("crates/stela-drivers/src/gpu")
}

fn checkout(name: &str) -> PathBuf {
    tools::root().join(".tools/gpu/src").join(name)
}

fn origins() -> Result<Vec<Origin>> {
    let manifest: Value = serde_json::from_slice(&fs::read(gpu().join("sources.json"))?)?;
    ensure!(
        manifest["schema"] == 2,
        "unsupported gpu/sources.json schema"
    );
    let text = |value: &Value| -> Result<String> {
        value
            .as_str()
            .map(str::to_owned)
            .context("gpu/sources.json: expected a string")
    };
    let texts = |value: &Value| -> Result<Vec<String>> {
        value
            .as_array()
            .map_or(Ok(Vec::new()), |values| values.iter().map(text).collect())
    };
    let mut origins = Vec::new();
    for source in manifest["sources"]
        .as_array()
        .context("gpu/sources.json: sources")?
    {
        let mut imports = Vec::new();
        for import in source["imports"].as_array().context("imports")? {
            imports.push(Import {
                from: text(&import["from"])?,
                to: text(&import["to"])?,
                excluded: texts(&import["excluded"])?,
            });
        }
        origins.push(Origin {
            name: text(&source["name"])?,
            url: text(&source["url"])?,
            commit: text(&source["commit"])?,
            imports,
            wraps: texts(&source["wraps"])?,
        });
    }
    Ok(origins)
}

fn git(directory: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(directory);
    command
}

/// Non-cone sparse patterns: each import, minus its exclusions.
fn sparse_patterns(origin: &Origin) -> String {
    let mut patterns = String::new();
    for import in &origin.imports {
        let base = if import.from == "." {
            String::new()
        } else {
            format!("/{}", import.from)
        };
        patterns.push_str(if base.is_empty() { "/*" } else { &base });
        patterns.push('\n');
        for excluded in &import.excluded {
            patterns.push_str(&format!("!{base}/{excluded}\n"));
        }
    }
    patterns
}

fn patches(origin: &Origin) -> Result<Vec<PathBuf>> {
    let directory = gpu().join("patches").join(&origin.name);
    let mut patches = match fs::read_dir(&directory) {
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

/// Binds the pinned revision, sparse scope and patch series.
fn series(origin: &Origin) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(origin.commit.as_bytes());
    digest.update(sparse_patterns(origin).as_bytes());
    for patch in patches(origin)? {
        digest.update(patch.file_name().unwrap().as_encoded_bytes());
        digest.update(Sha256::digest(fs::read(&patch)?));
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn head(directory: &Path) -> Result<String> {
    Ok(capture(git(directory).args(["rev-parse", "HEAD"]))?
        .trim()
        .to_owned())
}

fn state(directory: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(directory.join(".git").join(STATE)).ok()?;
    let (series, head) = text.trim().split_once(' ')?;
    Some((series.to_owned(), head.to_owned()))
}

fn record(directory: &Path, series: &str) -> Result<()> {
    let head = head(directory)?;
    fs::write(
        directory.join(".git").join(STATE),
        format!("{series} {head}\n"),
    )?;
    Ok(())
}

/// Commits or tracked edits made since the series was last applied or exported.
fn unexported(directory: &Path) -> Result<bool> {
    let Some((_, recorded)) = state(directory) else {
        return Ok(true);
    };
    let dirty = !capture(git(directory).args(["status", "--porcelain", "--untracked-files=no"]))?
        .is_empty();
    Ok(dirty || head(directory)? != recorded)
}

fn acquire(origin: &Origin, force: bool) -> Result<()> {
    let directory = checkout(&origin.name);
    let series = series(origin)?;
    if directory.join(".git").is_dir() {
        if state(&directory).is_some_and(|(applied, _)| applied == series)
            && !unexported(&directory)?
        {
            return Ok(());
        }
        ensure!(
            force || !unexported(&directory)?,
            "{} has commits or edits not in gpu/patches/{}; run `cargo xtask gpu export` \
             or pass --force to discard them",
            directory.display(),
            origin.name
        );
    } else {
        fs::create_dir_all(&directory)?;
        exec(git(&directory).args(["init", "-q"]))?;
        exec(git(&directory).args(["remote", "add", "origin", &origin.url]))?;
    }
    println!("GPU source {}: {}", origin.name, origin.commit);
    let mut sparse = git(&directory)
        .args(["sparse-checkout", "set", "--no-cone", "--stdin"])
        .stdin(Stdio::piped())
        .spawn()?;
    sparse
        .stdin
        .take()
        .unwrap()
        .write_all(sparse_patterns(origin).as_bytes())?;
    ensure!(sparse.wait()?.success(), "git sparse-checkout failed");
    if !git(&directory)
        .args(["cat-file", "-e", &format!("{}^{{commit}}", origin.commit)])
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        exec(git(&directory).args([
            "fetch",
            "-q",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            &origin.commit,
        ]))?;
    }
    exec(git(&directory).args(["checkout", "-q", "-B", "stela", &origin.commit]))?;
    exec(git(&directory).args(["reset", "-q", "--hard", &origin.commit]))?;
    let patches = patches(origin)?;
    if !patches.is_empty() {
        exec(
            git(&directory)
                .args(["-c", "user.name=Stela", "-c", "user.email=stela@localhost"])
                .args(["am", "-q", "--3way", "--committer-date-is-author-date"])
                .args(&patches),
        )
        .with_context(|| format!("gpu/patches/{} no longer applies", origin.name))?;
    }
    record(&directory, &series)
}

fn wraps(origin: &Origin) -> Result<()> {
    let directory = checkout(&origin.name);
    let missing = origin
        .wraps
        .iter()
        .filter(|wrap| {
            let wrap = directory.join("subprojects").join(format!("{wrap}.wrap"));
            fs::read_to_string(wrap).ok().is_none_or(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("directory = "))
                    .is_none_or(|name| !directory.join("subprojects").join(name).is_dir())
            })
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    exec(
        Command::new(tool("meson", "generators/bin")?)
            .args(["subprojects", "download", "--sourcedir"])
            .arg(&directory)
            .args(missing),
    )
}

fn relative(from: &Path, to: &Path) -> PathBuf {
    let from = from.components().collect::<Vec<_>>();
    let to = to.components().collect::<Vec<_>>();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut path = PathBuf::new();
    for _ in common..from.len() {
        path.push(Component::ParentDir);
    }
    path.extend(&to[common..]);
    path
}

/// `target` relative to `directory`, with `..` resolved lexically.
fn resolve(directory: &Path, target: &Path) -> PathBuf {
    let mut path = PathBuf::new();
    for component in directory.join(target).components() {
        match component {
            Component::ParentDir => {
                path.pop();
            }
            component => path.push(component),
        }
    }
    path
}

/// Upstream files never linked: Git refuses symlinked attribute and ignore
/// files, and Meson's download cache is not a source.
fn skipped(name: &std::ffi::OsStr) -> bool {
    [
        ".git",
        ".gitignore",
        ".gitattributes",
        ".mailmap",
        "packagecache",
        ".wraplock",
        "__pycache__",
    ]
    .iter()
    .any(|skipped| name == *skipped)
}

fn link_tree(source: &Path, destination: &Path, linked: &mut BTreeSet<PathBuf>) -> Result<()> {
    if source.is_dir() {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            // An upstream link into an excluded path has nothing to link.
            if !skipped(&entry.file_name()) && entry.path().exists() {
                link_tree(&entry.path(), &destination.join(entry.file_name()), linked)?;
            }
        }
        return Ok(());
    }
    let parent = destination.parent().unwrap();
    fs::create_dir_all(parent)?;
    let target = relative(parent, source);
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_symlink() => {
            if fs::read_link(destination)? != target {
                fs::remove_file(destination)?;
                std::os::unix::fs::symlink(&target, destination)?;
            }
        }
        Ok(_) => bail!(
            "{} is a Stela file where {} links an upstream file",
            destination.display(),
            source.display()
        ),
        Err(_) => std::os::unix::fs::symlink(&target, destination)?,
    }
    linked.insert(destination.to_owned());
    Ok(())
}

/// Remove links into the checkouts that the current imports no longer make.
fn prune(directory: &Path, sources: &Path, linked: &BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            prune(&path, sources, linked)?;
        } else if metadata.is_symlink()
            && !linked.contains(&path)
            && resolve(path.parent().unwrap(), &fs::read_link(&path)?).starts_with(sources)
        {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn link(origins: &[Origin]) -> Result<()> {
    let gpu = gpu();
    let mut linked = BTreeSet::new();
    for origin in origins {
        let directory = checkout(&origin.name);
        for import in &origin.imports {
            let source = if import.from == "." {
                directory.clone()
            } else {
                directory.join(&import.from)
            };
            ensure!(source.exists(), "{} is missing", source.display());
            link_tree(&source, &gpu.join(&import.to), &mut linked)?;
        }
    }
    let sources = tools::root().join(".tools/gpu/src");
    let roots = origins
        .iter()
        .flat_map(|origin| &origin.imports)
        .map(|import| gpu.join(&import.to))
        .filter(|root| root.is_dir())
        .collect::<BTreeSet<_>>();
    for root in roots {
        prune(&root, &sources, &linked)?;
    }
    Ok(())
}

/// Acquire every pinned origin, apply its patches and link its imports.
pub fn fetch(force: bool) -> Result<()> {
    let origins = origins()?;
    for origin in &origins {
        acquire(origin, force)?;
        wraps(origin)?;
    }
    link(&origins)
}

/// Write each checkout's commits since its pinned revision to its patch series.
pub fn export() -> Result<()> {
    for origin in origins()? {
        let directory = checkout(&origin.name);
        ensure!(
            directory.join(".git").is_dir(),
            "run `cargo xtask gpu fetch` first"
        );
        ensure!(
            capture(git(&directory).args(["status", "--porcelain", "--untracked-files=no"]))?
                .is_empty(),
            "{} has uncommitted edits; commit them first",
            directory.display()
        );
        let patches = gpu().join("patches").join(&origin.name);
        for patch in self::patches(&origin)? {
            fs::remove_file(patch)?;
        }
        if head(&directory)? != origin.commit {
            fs::create_dir_all(&patches)?;
            exec(
                git(&directory)
                    .args([
                        "format-patch",
                        "-q",
                        "--no-numbered",
                        "--zero-commit",
                        // Abbreviated blob names grow with the checkout.
                        "--full-index",
                        "--no-signature",
                    ])
                    .arg("-o")
                    .arg(&patches)
                    .arg(format!("{}..HEAD", origin.commit)),
            )?;
        }
        record(&directory, &series(&origin)?)?;
    }
    Ok(())
}
