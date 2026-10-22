//! Each Linux environment's `compat/overlay.yaml` maps Stela's shadows onto
//! the upstream headers they replace. Every shadow must be mapped, and each
//! mapping records the upstream header its shadow was written against, so an
//! upstream update that changes a shadowed header stops until it is reviewed.
use crate::tools;
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeSet, fs, path::Path};
use stela_runtime::sha256;

/// Environments with a shadow overlay, relative to the GPU source tree.
const ENVIRONMENTS: &[&str] = &["compat"];
/// Headers Linux's arch tree and build supply rather than `include/`, and the
/// adapters' trap helper.
const ADDITIONS: &[&str] = &["asm/", "generated/", "unsupported.h"];
const ENTRY: &str = "  - {type: file, name: ";

/// Verify every overlay; with `update`, record the current upstream headers
/// as reviewed instead of reporting them.
pub fn check(update: bool) -> Result<()> {
    let gpu = tools::root().join("crates/stela-drivers/src/gpu");
    let mut changed = Vec::new();
    for environment in ENVIRONMENTS {
        let compat = gpu.join(environment);
        let path = compat.join("overlay.yaml");
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let mut mapped = BTreeSet::new();
        let mut lines = Vec::new();
        for line in text.lines() {
            let Some(entry) = line.strip_prefix(ENTRY) else {
                lines.push(line.to_owned());
                continue;
            };
            let (name, rest) = entry
                .split_once(", external-contents: ")
                .with_context(|| format!("malformed overlay entry: {line}"))?;
            let (shadow, recorded) = rest
                .split_once("} # sha256:")
                .with_context(|| format!("overlay entry without a review digest: {line}"))?;
            ensure!(
                compat.join(shadow).is_file(),
                "{environment}: missing shadow {shadow}"
            );
            let upstream = compat.join(name);
            let bytes = fs::read(&upstream)
                .with_context(|| format!("{environment}: {shadow} shadows missing {name}"))?;
            let digest = sha256(&bytes);
            if digest != recorded {
                changed.push(format!("{environment}/{shadow} ({name})"));
            }
            ensure!(
                mapped.insert(shadow.to_owned()),
                "{environment}: {shadow} is mapped twice"
            );
            lines.push(format!(
                "{ENTRY}{name}, external-contents: {shadow}}} # sha256:{digest}"
            ));
        }
        for shadow in headers(&compat)? {
            ensure!(
                mapped.contains(&shadow) || ADDITIONS.iter().any(|a| shadow.starts_with(a)),
                "{environment}/{shadow} is not in overlay.yaml, so upstream code would not see it"
            );
        }
        if update {
            fs::write(&path, lines.join("\n") + "\n")?;
        }
    }
    if !update && !changed.is_empty() {
        bail!(
            "upstream changed the headers these shadows replace; update each shadow, \
             then record the review with `cargo xtask gpu shadows --update`:\n  {}",
            changed.join("\n  ")
        );
    }
    Ok(())
}

/// Every header under `compat`, relative to it.
fn headers(compat: &Path) -> Result<Vec<String>> {
    let mut headers = Vec::new();
    let mut pending = vec![compat.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "h") {
                let relative = path
                    .strip_prefix(compat)?
                    .to_str()
                    .context("non-UTF-8 path")?;
                headers.push(relative.to_owned());
            }
        }
    }
    Ok(headers)
}
