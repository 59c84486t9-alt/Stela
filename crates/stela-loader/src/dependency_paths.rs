//! Expansion of `@loader_path`, `@executable_path` and `@rpath` into guest paths,
//! following dyld's `Loader.cpp`. Purely lexical: no filesystem access.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::collections::BTreeSet;

const MAX_GUEST_PATH_BYTES: usize = 4096;
const MAX_RPATHS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RPath {
    /// Absolute guest filename of the image that declares this LC_RPATH.
    pub owner: String,
    pub value: String,
}

#[derive(Debug)]
pub struct PathContext<'a> {
    /// Absolute guest filename of the main executable.
    pub executable: &'a str,
    /// Absolute guest filename of the requesting image.
    pub loader: &'a str,
    /// Requester's LC_RPATHs in load-command order, then nearest ancestor's,
    /// continuing through the main executable. Owners retain their own anchors.
    pub rpaths: &'a [RPath],
}

fn checked_path(path: &str) -> Result<()> {
    ensure!(!path.as_bytes().contains(&0), "guest path contains NUL");
    ensure!(
        path.len() <= MAX_GUEST_PATH_BYTES,
        "guest path exceeds length limit"
    );
    Ok(())
}

/// Normalize an absolute lexical guest path without clamping escaped `..`.
/// This does not inspect or resolve filesystem symlinks.
pub fn normalize_guest_path(path: &str) -> Result<String> {
    checked_path(path)?;
    ensure!(path.starts_with('/'), "guest path must be absolute");
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                ensure!(
                    components.pop().is_some(),
                    "guest path escapes virtual root"
                );
            }
            component => components.push(component),
        }
    }
    Ok(format!("/{}", components.join("/")))
}

fn directory(filename: &str) -> Result<String> {
    let normalized = normalize_guest_path(filename)?;
    let (directory, _) = normalized
        .rsplit_once('/')
        .context("guest image path has no directory")?;
    Ok(if directory.is_empty() {
        "/".into()
    } else {
        directory.into()
    })
}

fn token_suffix<'a>(path: &'a str, token: &str) -> Option<&'a str> {
    path.strip_prefix(token)
        .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
}

fn append(base: &str, suffix: &str) -> Result<String> {
    let length = base
        .len()
        .checked_add(suffix.len())
        .context("expanded guest path length overflow")?;
    ensure!(
        length <= MAX_GUEST_PATH_BYTES,
        "expanded guest path exceeds length limit"
    );
    normalize_guest_path(&format!("{base}{suffix}"))
}

fn expand_without_rpath(path: &str, executable_dir: &str, loader_dir: &str) -> Result<String> {
    checked_path(path)?;
    if path.starts_with('/') {
        return normalize_guest_path(path);
    }
    if let Some(suffix) = token_suffix(path, "@loader_path") {
        return append(loader_dir, suffix);
    }
    if let Some(suffix) = token_suffix(path, "@executable_path") {
        return append(executable_dir, suffix);
    }
    if path.starts_with('@') {
        bail!("unsupported guest path token in {path:?}");
    }
    bail!("bare relative guest dependency path is unsupported: {path:?}")
}

/// Expand one install name into ordered, deduplicated absolute guest paths.
///
/// `ctx.rpaths` must already represent the requesting image's load chain in
/// nearest-first order. Each LC_RPATH's `@loader_path` uses its defining owner;
/// `@executable_path` always uses the main executable. Recursive `@rpath`
/// declarations and bare relative paths are explicit unsupported cases.
/// An empty result means an `@rpath` request had no declared search directories.
/// Lexical containment does not authorize following host filesystem symlinks.
pub fn candidates(name: &str, ctx: &PathContext<'_>) -> Result<Vec<String>> {
    checked_path(name)?;
    ensure!(
        ctx.rpaths.len() <= MAX_RPATHS,
        "guest rpath count exceeds limit"
    );
    let executable_dir = directory(ctx.executable)?;
    let loader_dir = directory(ctx.loader)?;
    let Some(suffix) = token_suffix(name, "@rpath") else {
        return Ok(vec![expand_without_rpath(
            name,
            &executable_dir,
            &loader_dir,
        )?]);
    };
    ensure!(
        suffix.starts_with('/') && suffix.len() > 1,
        "@rpath dependency requires a nonempty suffix"
    );
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for rpath in ctx.rpaths {
        checked_path(&rpath.value)?;
        ensure!(
            token_suffix(&rpath.value, "@rpath").is_none(),
            "recursive @rpath LC_RPATH is unsupported"
        );
        let owner_dir = directory(&rpath.owner)?;
        let expanded = expand_without_rpath(&rpath.value, &executable_dir, &owner_dir)?;
        let candidate = append(&expanded, suffix)?;
        if seen.insert(candidate.clone()) {
            result.push(candidate);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
