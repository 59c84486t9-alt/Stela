//! The hosted process's requirement matrix: render
//! `stela_runtime::hosted_registry::requirements` into its document and its counts
//! into the README, or with `check` fail if either is stale.
use crate::tools::root;
use anyhow::{Context, Result, bail};
use std::fs;
use stela_runtime::hosted_registry::requirements;

const DOCUMENT: &str = "docs/research/hosted-requirements.md";
const DOCUMENT_START: &str = "<!-- stela-hosted-requirements:start -->";
const DOCUMENT_END: &str = "<!-- stela-hosted-requirements:end -->";
const README: &str = "README.md";
const README_START: &str = "<!-- stela-hosted-progress:start -->";
const README_END: &str = "<!-- stela-hosted-progress:end -->";

/// `text` with the part between `start` and `end` replaced by `body`.
fn replace(text: &str, start: &str, end: &str, body: &str, path: &str) -> Result<String> {
    let (before, rest) = text
        .split_once(start)
        .with_context(|| format!("{path} has no {start} marker"))?;
    let (_, after) = rest
        .split_once(end)
        .with_context(|| format!("{path} has no {end} marker"))?;
    Ok(format!("{before}{start}\n{body}{end}{after}"))
}

fn rendered() -> Result<[(String, String, String); 2]> {
    let rows = requirements::matrix();
    let readme_body = format!(
        "{}\nRows are the kernel services an unchanged 26A434 process requests: every call \
         site in the guest shared cache and dyld, and every kernel-served MIG routine. Partial \
         rows earn no credit. [Hosted requirements]({DOCUMENT})\n",
        requirements::render_summary(&rows)
    );
    let mut files = Vec::new();
    for (path, start, end, body) in [
        (
            DOCUMENT,
            DOCUMENT_START,
            DOCUMENT_END,
            requirements::render(&rows),
        ),
        (README, README_START, README_END, readme_body),
    ] {
        let full = root().join(path);
        let old = fs::read_to_string(&full).with_context(|| format!("cannot read {path}"))?;
        let new = replace(&old, start, end, &body, path)?;
        files.push((full.display().to_string(), old, new));
    }
    Ok(files.try_into().expect("two files"))
}

pub fn run(check: bool) -> Result<()> {
    for (path, old, new) in rendered()? {
        if old == new {
            continue;
        }
        if check {
            bail!("{path} is stale; run `cargo xtask progress`");
        }
        fs::write(&path, new)?;
        println!("updated {path}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_matrix_and_readme_are_current() -> Result<()> {
        for (path, old, new) in rendered()? {
            assert!(old == new, "{path} is stale; run `cargo xtask progress`");
        }
        Ok(())
    }

    #[test]
    fn replacement_keeps_the_text_around_the_markers() -> Result<()> {
        let text = "a\n<!-- s -->\nold\n<!-- e -->\nb\n";
        assert_eq!(
            replace(text, "<!-- s -->", "<!-- e -->", "new\n", "x")?,
            "a\n<!-- s -->\nnew\n<!-- e -->\nb\n"
        );
        assert!(replace("none", "<!-- s -->", "<!-- e -->", "", "x").is_err());
        Ok(())
    }
}
