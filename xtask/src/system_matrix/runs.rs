//! Per-chip runs of the runtime's unit tests. `cargo xtask progress` runs
//! `cargo test -p stela-runtime --lib` once for each chip but the default,
//! with `STELA_TEST_CHIP` naming it, and records in [`LEDGER`] the tests
//! that passed after building their CPU or machine for that chip: the
//! runtime's `machine::test_chip` logs each caller's test name to
//! `STELA_TEST_CHIP_LOG`. A test that fixes its chip, or builds no machine,
//! is never credited. The ledger names the digest of the sources it ran, and
//! a stale ledger is refused.
use super::{CHIPS, DEFAULT_CHIP};
use crate::tools::{cargo, root};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Stdio,
};
use stela_runtime::sha256;

pub const LEDGER: &str = "isa/system-chip-test-runs.json";
/// The sources whose behavior the runs observe.
const TREES: [&str; 2] = ["crates/stela-runtime/src", "crates/stela-compiler/src"];
/// Only the runtime's tests consult the test chip.
const RUNTIME_SOURCE: &str = "crates/stela-runtime/src/";

/// Each chip's credited tests, by libtest name.
pub struct Runs {
    chips: BTreeMap<String, BTreeSet<String>>,
}

impl Runs {
    /// Whether the cited test `path#function` passed on `chip` after
    /// consulting it.
    pub fn credits(&self, chip: &str, test: &str) -> bool {
        let Some(name) = libtest_name(test) else {
            return false;
        };
        self.chips
            .get(chip)
            .is_some_and(|credited| credited.contains(&name))
    }
}

/// The libtest name of a cited runtime test: `machine/engine/system.rs#f`
/// is `machine::engine::system::tests::f`.
fn libtest_name(test: &str) -> Option<String> {
    let (path, function) = test.split_once('#')?;
    let module = path.strip_prefix(RUNTIME_SOURCE)?.strip_suffix(".rs")?;
    let module = module
        .strip_suffix("/mod")
        .unwrap_or(module)
        .replace('/', "::");
    Some(if module == "lib" {
        format!("tests::{function}")
    } else {
        format!("{module}::tests::{function}")
    })
}

/// SHA-256 over every source file of [`TREES`], each as its path and digest.
pub fn digest() -> Result<String> {
    fn walk(directory: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, files)?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    for tree in TREES {
        walk(&root().join(tree), &mut files)?;
    }
    files.sort();
    let mut listing = String::new();
    for file in files {
        let relative = file.strip_prefix(root())?.display().to_string();
        listing.push_str(&format!("{relative}\0{}\n", sha256(&fs::read(&file)?)));
    }
    Ok(sha256(listing.as_bytes()))
}

/// Run the runtime's tests on every chip but the default and render the
/// ledger.
pub fn run() -> Result<String> {
    let directory = tempfile::tempdir()?;
    let mut chips = serde_json::Map::new();
    for chip in CHIPS.iter().filter(|chip| chip.name != DEFAULT_CHIP) {
        let log = directory.path().join(chip.name);
        let output = cargo()
            .args([
                "test",
                "-p",
                "stela-runtime",
                "--lib",
                "--",
                "--color",
                "never",
            ])
            .env("STELA_TEST_CHIP", chip.name)
            .env("STELA_TEST_CHIP_LOG", &log)
            .stderr(Stdio::inherit())
            .output()
            .context("cannot run the runtime's tests")?;
        let stdout = String::from_utf8(output.stdout)?;
        let mut passed = BTreeSet::new();
        let mut failed = BTreeSet::new();
        for line in stdout.lines() {
            let Some(rest) = line.strip_prefix("test ") else {
                continue;
            };
            if let Some(name) = rest.strip_suffix(" ... ok") {
                passed.insert(name.to_owned());
            } else if let Some(name) = rest.strip_suffix(" ... FAILED") {
                failed.insert(name.to_owned());
            }
        }
        ensure!(
            !passed.is_empty(),
            "the runtime's tests on {} reported no results",
            chip.name
        );
        let consulted: BTreeSet<String> = fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        let credited: Vec<&String> = passed.intersection(&consulted).collect();
        chips.insert(
            chip.name.to_owned(),
            json!({
                "passed": passed.len(),
                "failed": failed,
                "credited": credited,
            }),
        );
    }
    let ledger = json!({
        "schema_version": 1,
        "kind": "system_chip_test_runs",
        "command": "cargo test -p stela-runtime --lib, with STELA_TEST_CHIP naming the chip \
                    and STELA_TEST_CHIP_LOG collecting the tests that consulted it",
        "sources": { "trees": TREES, "sha256": digest()? },
        "chips": chips,
    });
    Ok(serde_json::to_string_pretty(&ledger)? + "\n")
}

/// Read the committed ledger, refusing it when the sources have changed.
pub fn read() -> Result<Runs> {
    let text = fs::read_to_string(root().join(LEDGER))
        .with_context(|| format!("cannot read {LEDGER}; run `cargo xtask progress`"))?;
    parse(&text, &digest()?)
}

pub(super) fn parse(text: &str, digest: &str) -> Result<Runs> {
    let ledger: Value = serde_json::from_str(text).with_context(|| format!("invalid {LEDGER}"))?;
    ensure!(
        ledger["sources"]["sha256"] == digest,
        "{LEDGER} is stale: the runtime or compiler sources changed; run `cargo xtask progress`"
    );
    let mut chips = BTreeMap::new();
    for (chip, run) in ledger["chips"]
        .as_object()
        .with_context(|| format!("{LEDGER} has no chips"))?
    {
        ensure!(
            CHIPS.iter().any(|known| known.name == chip),
            "{LEDGER} names unknown chip {chip}"
        );
        let credited = run["credited"]
            .as_array()
            .with_context(|| format!("{LEDGER} {chip} has no credited tests"))?
            .iter()
            .filter_map(|name| name.as_str().map(str::to_owned))
            .collect();
        chips.insert(chip.clone(), credited);
    }
    Ok(Runs { chips })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cited_tests_map_to_their_libtest_names() {
        assert_eq!(
            libtest_name("crates/stela-runtime/src/machine/engine/system.rs#f").as_deref(),
            Some("machine::engine::system::tests::f")
        );
        assert_eq!(
            libtest_name("crates/stela-runtime/src/machine.rs#g").as_deref(),
            Some("machine::tests::g")
        );
        assert_eq!(
            libtest_name("crates/stela-compiler/src/block/system.rs#h"),
            None
        );
    }

    #[test]
    fn a_ledger_credits_only_its_chips_tests_and_only_while_current() -> Result<()> {
        let text = r#"{"sources":{"sha256":"d"},"chips":{"apple-m6":{"credited":
            ["machine::engine::tests::t"]}}}"#;
        let runs = parse(text, "d")?;
        let test = "crates/stela-runtime/src/machine/engine.rs#t";
        assert!(runs.credits("apple-m6", test));
        assert!(!runs.credits("apple-m5", test));
        assert!(!runs.credits("apple-m6", "crates/stela-runtime/src/machine/engine.rs#u"));
        assert!(parse(text, "e").is_err());
        Ok(())
    }
}
