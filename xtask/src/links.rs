//! The tree's references: every relative Markdown link names a tracked file
//! (and, with `#anchor`, one of its headings), every repository path a
//! Markdown file names in backticks exists, and every `cargo xtask` task
//! the Markdown files and Rust sources name is one xtask has.
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The top-level directories whose paths backticks are checked under.
const PATH_ROOTS: [&str; 3] = ["crates/", "docs/", "xtask/"];

pub fn run() -> Result<()> {
    let root = root();
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*.md", "*.rs"])
        .output()
        .context("git ls-files")?;
    ensure!(output.status.success(), "git ls-files failed");
    let files: Vec<PathBuf> = String::from_utf8(output.stdout)?
        .split('\0')
        .filter(|name| !name.is_empty() && !name.starts_with("third_party/"))
        .map(PathBuf::from)
        .collect();
    let problems = check(root, &files, &tasks())?;
    if !problems.is_empty() {
        bail!(
            "{} stale references:\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }
    Ok(())
}

/// The tasks xtask builds only on other hosts.
const OTHER_HOSTS: [&str; 1] = ["bench"];

/// xtask's task names.
fn tasks() -> BTreeSet<String> {
    use clap::CommandFactory;
    crate::Cli::command()
        .get_subcommands()
        .flat_map(|task| {
            std::iter::once(task.get_name().to_owned())
                .chain(task.get_all_aliases().map(str::to_owned))
        })
        .chain(OTHER_HOSTS.map(str::to_owned))
        .collect()
}

/// The problems in `files`, paths relative to `root`.
fn check(root: &Path, files: &[PathBuf], tasks: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut anchors: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut problems = Vec::new();
    for file in files {
        let text = fs::read_to_string(root.join(file))
            .with_context(|| format!("reading {}", file.display()))?;
        for (line, task) in xtask_tasks(&text) {
            if !tasks.contains(&task) {
                problems.push(format!(
                    "{}:{line}: `cargo xtask {task}` is no xtask task",
                    file.display()
                ));
            }
        }
        if file.extension().is_none_or(|extension| extension != "md") {
            continue;
        }
        for (line, prose) in prose_lines(&text) {
            for target in links(prose) {
                if let Some(problem) = check_link(root, file, &target, &mut anchors)? {
                    problems.push(format!("{}:{line}: {problem}", file.display()));
                }
            }
            // A line that links to another repository names its files.
            if prose.contains("://") {
                continue;
            }
            for path in code_spans(prose).filter_map(repository_path) {
                let problem = match path.contains('#') {
                    // From the root, as the backticks name it.
                    true => check_link(root, Path::new(""), path, &mut anchors)?,
                    false => {
                        (!root.join(path).exists()).then(|| format!("`{path}` does not exist"))
                    }
                };
                if let Some(problem) = problem {
                    problems.push(format!("{}:{line}: {problem}", file.display()));
                }
            }
        }
    }
    Ok(problems)
}

/// A relative link's problem: a missing file or heading.
fn check_link(
    root: &Path,
    file: &Path,
    target: &str,
    anchors: &mut BTreeMap<PathBuf, BTreeSet<String>>,
) -> Result<Option<String>> {
    if target.contains("://") || target.starts_with("mailto:") {
        return Ok(None);
    }
    let (path, anchor) = match target.split_once('#') {
        Some((path, anchor)) => (path, Some(anchor)),
        None => (target, None),
    };
    let linked = if path.is_empty() {
        file.to_path_buf()
    } else {
        normalize(&file.parent().unwrap_or(Path::new("")).join(path))
    };
    if !root.join(&linked).exists() {
        return Ok(Some(format!("link {target} names no file")));
    }
    let Some(anchor) = anchor else {
        return Ok(None);
    };
    if linked.extension().is_none_or(|extension| extension != "md") {
        return Ok(None);
    }
    if !anchors.contains_key(&linked) {
        let text = fs::read_to_string(root.join(&linked))?;
        anchors.insert(linked.clone(), headings(&text));
    }
    Ok((!anchors[&linked].contains(anchor))
        .then(|| format!("link {target} names no heading of {}", linked.display())))
}

/// `path` without `.` and with each `..` taken back.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// The lines outside fenced code blocks, numbered from 1.
fn prose_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut fenced = false;
    text.lines().enumerate().filter_map(move |(index, line)| {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            return None;
        }
        (!fenced).then_some((index + 1, line))
    })
}

/// The targets of a line's `[text](target)` links, outside code spans.
fn links(line: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut code = false;
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'`' => code = !code,
            b']' if !code && bytes.get(index + 1) == Some(&b'(') => {
                if let Some(end) = line[index + 2..].find(')') {
                    let target = line[index + 2..index + 2 + end].trim();
                    let target = target.split_whitespace().next().unwrap_or("");
                    let target = target.trim_start_matches('<').trim_end_matches('>');
                    if !target.is_empty() {
                        targets.push(target.to_owned());
                    }
                    index += end + 2;
                }
            }
            _ => {}
        }
        index += 1;
    }
    targets
}

/// A line's inline code spans.
fn code_spans(line: &str) -> impl Iterator<Item = &str> {
    line.split('`').skip(1).step_by(2)
}

/// A code span that names a repository path: one under [`PATH_ROOTS`],
/// without wildcards or placeholders, its `:line` suffix dropped.
fn repository_path(span: &str) -> Option<&str> {
    if !PATH_ROOTS.iter().any(|root| span.starts_with(root))
        || span.contains(['*', '<', '>', '{', '}', '$', ' ', '…'])
        || span.contains("...")
    {
        return None;
    }
    let path = span.split_once(':').map_or(span, |(path, _)| path);
    Some(path.trim_end_matches('/'))
}

/// GitHub's anchors for a Markdown file's headings.
fn headings(text: &str) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors = BTreeSet::new();
    for (_, line) in prose_lines(text) {
        let Some(title) = line.strip_prefix('#') else {
            continue;
        };
        let title = title.trim_start_matches('#');
        if !title.starts_with(' ') {
            continue;
        }
        let slug = slug(title.trim());
        let count = seen.entry(slug.clone()).or_default();
        anchors.insert(match *count {
            0 => slug,
            n => format!("{slug}-{n}"),
        });
        *count += 1;
    }
    anchors
}

/// A heading's anchor as GitHub makes it: lower case, spaces as hyphens,
/// without punctuation other than `-` and `_`.
fn slug(title: &str) -> String {
    title
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// The tasks a text names after `cargo xtask`, with their line numbers. A
/// task wrapped onto the next line, past its comment markers, counts too.
fn xtask_tasks(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut tasks = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let next = lines.get(index + 1).map_or("", |next| {
            next.trim_start()
                .trim_start_matches(['/', '!', '#', '*'])
                .trim_start()
        });
        let line = match line.strip_suffix("cargo xtask") {
            Some(_) => format!("{line} {next}"),
            None => (*line).to_owned(),
        };
        for (at, _) in line.match_indices("cargo xtask ") {
            let task: String = line[at + "cargo xtask ".len()..]
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            if !task.is_empty() {
                tasks.push((index + 1, task));
            }
        }
    }
    tasks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headings_take_githubs_anchors() {
        let anchors =
            headings("# Boot route\n## `stela setup` & you\n# Boot route\n```\n# not\n```\n");
        let expected = ["boot-route", "boot-route-1", "stela-setup--you"];
        assert_eq!(anchors, expected.map(String::from).into());
    }

    #[test]
    fn links_and_paths_outside_code_are_read() {
        assert_eq!(
            links("See [a](b.md#c) and `[x](y)` or [d](<e f.md> \"title\")."),
            ["b.md#c", "e"]
        );
        let spans: Vec<_> = code_spans("`crates/a.rs:28` and `docs/*.md`").collect();
        assert_eq!(spans, ["crates/a.rs:28", "docs/*.md"]);
        assert_eq!(repository_path("crates/a.rs:28"), Some("crates/a.rs"));
        assert_eq!(repository_path("docs/*.md"), None);
        assert_eq!(repository_path("src/a.rs"), None);
    }

    #[test]
    fn missing_files_headings_paths_and_tasks_are_reported() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join("docs/design"))?;
        fs::write(root.path().join("docs/design/system.md"), "# Boot route\n")?;
        fs::write(
            root.path().join("docs/guide.md"),
            "[ok](design/system.md#boot-route) [gone](design/system.md#boot-route-is-unselected)\n\
             [missing](design/none.md) [web](https://example.com/x.md)\n\
             `docs/design/system.md` `crates/stela-runtime/examples/leaf.rs`\n\
             `docs/design/system.md#boot-route` `docs/design/system.md#gone`\n\
             [upstream](https://example.com/docs) holds `docs/hw/soc.md`\n\
             Run `cargo xtask check`, not `cargo xtask dit-audit`.\n",
        )?;
        // A Rust comment's task, wrapped onto its next line.
        fs::write(
            root.path().join("target.rs"),
            "/// `cargo xtask\n/// sve-audit` checks\n",
        )?;
        let files = ["docs/guide.md", "docs/design/system.md", "target.rs"].map(PathBuf::from);
        let tasks = ["check".to_owned()].into();
        let problems = check(root.path(), &files, &tasks)?;
        assert_eq!(problems.len(), 6, "{problems:#?}");
        for expected in [
            "boot-route-is-unselected",
            "none.md",
            "leaf.rs",
            "system.md#gone",
            "dit-audit",
            "target.rs:1: `cargo xtask sve-audit`",
        ] {
            assert!(problems.iter().any(|p| p.contains(expected)), "{expected}");
        }
        Ok(())
    }
}
