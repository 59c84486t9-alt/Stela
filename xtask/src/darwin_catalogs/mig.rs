//! The kernel-served MIG routines: the subsystems the kernel registers for
//! its objects (`osfmk/kern/ipc_kobject.c` `mig_e[]`, with the
//! configuration guard of each conditional entry), read from their
//! `osfmk/**/*.defs` preprocessed as the kernel build preprocesses them
//! (`KERNEL_SERVER`, arm64 LP64). MIG names a subsystem's server structure
//! `<ServerPrefix><name>_subsystem` and numbers its `routine`,
//! `simpleroutine` and `skip` statements consecutively from its base; a
//! request's message id is that number.
use anyhow::{Context, Result, bail, ensure};
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

/// The kernel's subsystem registry, its definitions tree, and the
/// preprocessor definitions of the kernel's MIG build for its own objects,
/// with the `IOKIT` configuration option (`config/MASTER`) that
/// `device.defs` serves its routines under. (The kernel build's `KERNEL`
/// would rename routines to their in-kernel symbols; the catalog keeps the
/// names user space sends by.)
const REGISTRY: &str = "osfmk/kern/ipc_kobject.c";
const REGISTRY_TABLE: &str = "mig_e[] = {";
const DEFS_DIRECTORY: &str = "osfmk";
const DEFINES: &[&str] = &[
    "-DKERNEL_SERVER=1",
    "-DIOKIT=1",
    "-D__arm64__=1",
    "-D__LP64__=1",
];
const KERNEL_SERVER: &str = "KernelServer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Routine {
    pub(super) id: u32,
    pub(super) subsystem: String,
    pub(super) name: String,
    pub(super) simple: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Subsystem {
    pub(super) name: String,
    /// The server structure `mig_e[]` names.
    pub(super) symbol: String,
    /// The configuration option the registry entry is conditional on.
    pub(super) guard: Option<String>,
    pub(super) base: u32,
    /// One past the last numbered statement.
    pub(super) end: u32,
    pub(super) source: String,
}

/// Preprocess one definitions file.
fn preprocess(xnu: &Path, file: &Path) -> Result<String> {
    let output = Command::new("clang")
        .args(["-E", "-P", "-x", "c", "-undef"])
        .args(DEFINES)
        .arg(format!("-I{}", xnu.join("osfmk").display()))
        .arg(format!("-I{}", xnu.join("bsd").display()))
        .arg(file)
        .output()
        .context("cannot run clang to preprocess MIG definitions")?;
    ensure!(
        output.status.success(),
        "clang cannot preprocess {}: {}",
        file.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// MIG's tokens: identifiers and numbers, and single punctuation marks.
fn tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (index, byte) in text.bytes().enumerate() {
        let word = byte.is_ascii_alphanumeric() || byte == b'_';
        match (word, start) {
            (true, None) => start = Some(index),
            (false, Some(from)) => {
                tokens.push(&text[from..index]);
                start = None;
            }
            _ => {}
        }
        if !word && !byte.is_ascii_whitespace() {
            tokens.push(&text[index..=index]);
        }
    }
    if let Some(from) = start {
        tokens.push(&text[from..]);
    }
    tokens
}

/// The file's `ServerPrefix`, which prefixes its server structure's name.
fn server_prefix(tokens: &[&str]) -> String {
    tokens
        .windows(3)
        .find(|window| window[0].eq_ignore_ascii_case("serverprefix") && window[2] == ";")
        .map_or_else(String::new, |window| window[1].to_owned())
}

/// The registry's entries: each server structure and the guard of the
/// `#if`/`#ifdef` block it sits in.
pub(super) fn registry(source: &str) -> Result<Vec<(String, Option<String>)>> {
    let start = source
        .find(REGISTRY_TABLE)
        .with_context(|| format!("{REGISTRY} has no {REGISTRY_TABLE}"))?;
    let body = &source[start + REGISTRY_TABLE.len()..];
    let end = body.find("};").context("unterminated mig_e[]")?;
    let mut guard: Option<String> = None;
    let mut entries = Vec::new();
    for line in body[..end].lines().map(str::trim) {
        if let Some(condition) = line
            .strip_prefix("#ifdef")
            .or_else(|| line.strip_prefix("#if"))
        {
            guard = Some(condition.trim().to_owned());
        } else if line.starts_with("#endif") {
            guard = None;
        } else if line.starts_with('#') {
            bail!("{REGISTRY}: unexpected directive {line:?} in mig_e[]");
        } else if let Some(at) = line.find('&') {
            let symbol: String = line[at + 1..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            ensure!(!symbol.is_empty(), "{REGISTRY}: entry {line:?}");
            entries.push((symbol, guard.clone()));
        }
    }
    ensure!(!entries.is_empty(), "{REGISTRY}: empty mig_e[]");
    Ok(entries)
}

/// The kernel-served subsystem one preprocessed file declares, with its
/// routines; `None` for a file that declares no subsystem or one the kernel
/// is the client of.
pub(super) fn parse(source: &str, text: &str) -> Result<Option<(Subsystem, Vec<Routine>)>> {
    let tokens = tokens(text);
    let mut cursor = 0;
    let mut subsystem: Option<Subsystem> = None;
    let mut routines = Vec::new();
    while cursor < tokens.len() {
        match tokens[cursor] {
            "subsystem" => {
                ensure!(subsystem.is_none(), "{source} declares two subsystems");
                let end = tokens[cursor..]
                    .iter()
                    .position(|token| *token == ";")
                    .context("unterminated subsystem statement")?
                    + cursor;
                let statement = &tokens[cursor + 1..end];
                ensure!(
                    statement.len() >= 2,
                    "short subsystem statement in {source}"
                );
                let base: u32 = statement[statement.len() - 1]
                    .parse()
                    .with_context(|| format!("subsystem base in {source}"))?;
                let name = statement[statement.len() - 2].to_owned();
                if !statement.contains(&KERNEL_SERVER) {
                    return Ok(None);
                }
                subsystem = Some(Subsystem {
                    symbol: format!("{}{name}_subsystem", server_prefix(&tokens)),
                    name,
                    guard: None,
                    base,
                    end: base,
                    source: source.to_owned(),
                });
                cursor = end + 1;
            }
            keyword @ ("routine" | "simpleroutine") => {
                let Some(current) = subsystem.as_mut() else {
                    bail!("{source}: a routine precedes the subsystem statement");
                };
                let name = tokens.get(cursor + 1).context("routine without a name")?;
                ensure!(
                    name.chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_'),
                    "{source}: routine name {name:?}"
                );
                routines.push(Routine {
                    id: current.end,
                    subsystem: current.name.clone(),
                    name: (*name).to_owned(),
                    simple: keyword == "simpleroutine",
                });
                current.end += 1;
                cursor += 2;
            }
            "skip" if tokens.get(cursor + 1) == Some(&";") => {
                let Some(current) = subsystem.as_mut() else {
                    bail!("{source}: a skip precedes the subsystem statement");
                };
                current.end += 1;
                cursor += 2;
            }
            _ => cursor += 1,
        }
    }
    Ok(subsystem.map(|subsystem| (subsystem, routines)))
}

fn definition_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("cannot list {}", directory.display()))?
    {
        let path = entry?.path();
        if path.is_dir() {
            definition_files(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "defs")
        {
            files.push(path);
        }
    }
    Ok(())
}

/// Every subsystem the kernel registers and its routines, by base.
pub(super) fn collect(xnu: &Path) -> Result<(Vec<Subsystem>, Vec<Routine>)> {
    let registry_source =
        std::fs::read(xnu.join(REGISTRY)).with_context(|| format!("cannot read {REGISTRY}"))?;
    let registered = registry(&String::from_utf8_lossy(&registry_source))?;
    let mut files = Vec::new();
    definition_files(&xnu.join(DEFS_DIRECTORY), &mut files)?;
    files.sort();
    let mut subsystems: Vec<Subsystem> = Vec::new();
    let mut routines = Vec::new();
    for file in files {
        let raw = std::fs::read_to_string(&file).unwrap_or_default();
        if !raw.contains("subsystem") {
            continue;
        }
        let source = file
            .strip_prefix(xnu)
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();
        let text = preprocess(xnu, &file)?;
        let Some((mut subsystem, rows)) = parse(&source, &text)? else {
            continue;
        };
        let Some((_, guard)) = registered
            .iter()
            .find(|(symbol, _)| *symbol == subsystem.symbol)
        else {
            continue;
        };
        ensure!(
            subsystems
                .iter()
                .all(|known| known.symbol != subsystem.symbol),
            "{} is defined twice",
            subsystem.symbol
        );
        subsystem.guard.clone_from(guard);
        subsystems.push(subsystem);
        routines.extend(rows);
    }
    for (symbol, _) in &registered {
        ensure!(
            subsystems
                .iter()
                .any(|subsystem| subsystem.symbol == *symbol),
            "{REGISTRY} registers {symbol}, which no definitions file declares"
        );
    }
    subsystems.sort_by_key(|subsystem| subsystem.base);
    for pair in subsystems.windows(2) {
        ensure!(
            pair[0].end <= pair[1].base,
            "MIG subsystems {} and {} overlap",
            pair[0].name,
            pair[1].name
        );
    }
    routines.sort_by_key(|routine| routine.id);
    Ok((subsystems, routines))
}

pub(super) fn render(subsystems: &[Subsystem], routines: &[Routine]) -> String {
    let mut text = String::from(
        "//! The pinned kernel-served MIG catalog, generated by `cargo xtask\n\
         //! darwin-catalogs` from xnu's `osfmk/kern/ipc_kobject.c` `mig_e[]`\n\
         //! and the `osfmk/**/*.defs` it names, preprocessed with\n\
         //! `KERNEL_SERVER` for arm64 LP64. Do not edit by hand.\n\
         //!\n\
         //! Each subsystem is its name, the configuration guard of its\n\
         //! registry entry, base message id, one past its last numbered\n\
         //! statement, and source; each routine is its message id,\n\
         //! subsystem, name and whether it is a `simpleroutine` (no reply).\n\
         use super::{Routine, Subsystem};\n\n\
         pub(super) const SUBSYSTEMS: &[Subsystem] = &[\n",
    );
    for subsystem in subsystems {
        let _ = writeln!(
            text,
            "    Subsystem {{ name: {:?}, guard: {:?}, base: {}, end: {}, source: {:?} }},",
            subsystem.name, subsystem.guard, subsystem.base, subsystem.end, subsystem.source
        );
    }
    text.push_str("];\n\npub(super) const ROUTINES: &[Routine] = &[\n");
    for routine in routines {
        let _ = writeln!(
            text,
            "    Routine {{ id: {}, subsystem: {:?}, name: {:?}, simple: {} }},",
            routine.id, routine.subsystem, routine.name, routine.simple
        );
    }
    text.push_str("];\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_number_from_the_base_and_skips_count() {
        let text = "subsystem\n KernelServer\n task 3400;\nimport <x.h>;\n\
                    routine task_create(target : task_t);\nskip;\n\
                    simpleroutine\n task_notify(a : int);\n";
        let (subsystem, routines) = parse("task.defs", text).unwrap().unwrap();
        assert_eq!(
            (subsystem.name.as_str(), subsystem.base, subsystem.end),
            ("task", 3400, 3403)
        );
        assert_eq!(subsystem.symbol, "task_subsystem");
        assert_eq!(routines.len(), 2);
        assert_eq!(
            (routines[0].id, routines[0].name.as_str()),
            (3400, "task_create")
        );
        assert_eq!((routines[1].id, routines[1].simple), (3402, true));
        // A subsystem the kernel calls out through is not kernel-served.
        assert!(
            parse("exc.defs", "subsystem KernelUser exc 2400;")
                .unwrap()
                .is_none()
        );
        let (exc, _) = parse(
            "exc.defs",
            "subsystem KernelServer exc 2400; ServerPrefix catch_;",
        )
        .unwrap()
        .unwrap();
        assert_eq!(exc.symbol, "catch_exc_subsystem");
    }

    #[test]
    fn registry_entries_keep_their_guards() {
        let source = "static struct mig_kern_subsystem *mig_e[] = {\n\
                      \t(const struct mig_kern_subsystem *)&task_subsystem,\n\
                      #ifdef VM32_SUPPORT\n\
                      \t(const struct mig_kern_subsystem *)&vm32_map_subsystem,\n\
                      #endif\n\
                      };";
        assert_eq!(
            registry(source).unwrap(),
            [
                ("task_subsystem".to_owned(), None),
                (
                    "vm32_map_subsystem".to_owned(),
                    Some("VM32_SUPPORT".to_owned())
                ),
            ]
        );
    }
}
