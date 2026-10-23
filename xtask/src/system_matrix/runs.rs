//! Per-chip runs of the runtime's unit tests. `cargo xtask progress` runs
//! `cargo test -p stela-runtime --lib` once for each chip but the historical
//! M2 registry baseline, with `STELA_TEST_CHIP` naming it, and records in [`LEDGER`] the tests
//! that passed after building their CPU or machine for that chip: the
//! runtime's `machine::test_chip` logs each caller's test name to
//! `STELA_TEST_CHIP_LOG`. A test that fixes its chip, or builds no machine,
//! is never credited. A test of [`CHIP_INDEPENDENT`] code holds on every
//! chip. The ledger names the digest of the sources it ran, and a stale
//! ledger is refused.
use super::{CHIPS, REGISTRY_BASE_CHIP};
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
const TREES: [&str; 3] = [
    "crates/stela-runtime/src",
    "crates/stela-drivers/src",
    "crates/stela-compiler/src",
];
/// Only the runtime's tests consult the test chip.
const RUNTIME_SOURCE: &str = "crates/stela-runtime/src/";
/// Cited tests whose code cannot name a chip, so that their pass holds on
/// every chip: the compiler, which depends on no crate that defines one
/// (the engine replaces a form the chip lacks before compiling it), the
/// reset derivation, which reads only the profile that generation builds
/// for each chip, the vGIC CPU interface, which takes no chip (every PE's
/// is the same model), and the activity monitors' counting, which takes
/// only a clock.
const CHIP_INDEPENDENT: [&str; 5] = [
    "crates/stela-compiler/src/",
    "xtask/src/system_matrix/resets.rs#",
    "crates/stela-runtime/src/machine/vgic",
    "crates/stela-runtime/src/machine/caches.rs#",
    "crates/stela-runtime/src/machine/amu.rs#",
];

/// Each chip's credited tests, by libtest name.
pub struct Runs {
    chips: BTreeMap<String, BTreeSet<String>>,
}

impl Runs {
    /// Whether the cited test `path#function` passed on `chip` after
    /// consulting it.
    pub fn credits(&self, chip: &str, test: &str) -> bool {
        if CHIP_INDEPENDENT.iter().any(|code| test.starts_with(code)) {
            return self.chips.contains_key(chip);
        }
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
    digest_trees(root(), &TREES)
}

fn digest_trees(source_root: &Path, trees: &[&str]) -> Result<String> {
    fn walk(directory: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            // Native driver generators may leave caches next to their sources.
            // These are derived files/locks, not inputs observed by runtime tests.
            if ["__pycache__", "packagecache", ".wraplock"]
                .iter()
                .any(|name| entry.file_name() == *name)
            {
                continue;
            }
            // A link, such as the GPU build's Mesa subproject, is digested
            // by its target's name; the tree it names is not followed.
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(&path, files)?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    for tree in trees {
        walk(&source_root.join(tree), &mut files)?;
    }
    files.sort();
    let mut listing = String::new();
    for file in files {
        let relative = file.strip_prefix(source_root)?.display().to_string();
        let contents = match fs::read_link(&file) {
            Ok(target) => [b"link\0", target.as_os_str().as_encoded_bytes()].concat(),
            Err(_) => fs::read(&file)?,
        };
        listing.push_str(&format!("{relative}\0{}\n", sha256(&contents)));
    }
    Ok(sha256(listing.as_bytes()))
}

/// Runtime tests without an override retain their historical M2 scope.
fn rerun_chips() -> impl Iterator<Item = &'static super::Chip> {
    CHIPS.iter().filter(|chip| chip.name != REGISTRY_BASE_CHIP)
}

/// Run the runtime's tests on every chip but the registry baseline and render the
/// ledger.
pub fn run() -> Result<String> {
    let directory = tempfile::tempdir()?;
    let mut chips = serde_json::Map::new();
    for chip in rerun_chips() {
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
        "{LEDGER} is stale: the runtime, driver or compiler sources changed; run `cargo xtask progress`"
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
    fn native_source_changes_invalidate_the_ledger_but_generator_caches_do_not() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let driver = temporary.path().join("drivers/vendor");
        fs::create_dir_all(&driver)?;
        fs::write(driver.join("shader.c"), "unsigned shader;\n")?;
        let before = digest_trees(temporary.path(), &["drivers"])?;
        fs::create_dir(driver.join("__pycache__"))?;
        fs::write(driver.join("__pycache__/generator.pyc"), b"cache")?;
        fs::create_dir(driver.join("packagecache"))?;
        fs::write(driver.join("packagecache/archive.tar.gz"), b"archive")?;
        fs::write(driver.join(".wraplock"), b"")?;
        assert_eq!(before, digest_trees(temporary.path(), &["drivers"])?);
        fs::write(driver.join("shader.c"), "unsigned shader = 1;\n")?;
        assert_ne!(before, digest_trees(temporary.path(), &["drivers"])?);
        Ok(())
    }

    #[test]
    fn a_link_is_digested_by_its_target_name_not_followed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let upstream = temporary.path().join("upstream");
        let link = temporary.path().join("drivers/subproject");
        fs::create_dir_all(temporary.path().join("drivers"))?;
        fs::create_dir(&upstream)?;
        // A dangling link inside the linked tree is never read.
        std::os::unix::fs::symlink("missing", upstream.join("dangling"))?;
        std::os::unix::fs::symlink("../upstream", &link)?;
        let before = digest_trees(temporary.path(), &["drivers"])?;
        fs::write(upstream.join("source.c"), "unsigned upstream;\n")?;
        assert_eq!(before, digest_trees(temporary.path(), &["drivers"])?);
        fs::remove_file(&link)?;
        std::os::unix::fs::symlink("../elsewhere", &link)?;
        assert_ne!(before, digest_trees(temporary.path(), &["drivers"])?);
        Ok(())
    }

    #[test]
    fn primary_m1_gets_a_real_rerun_without_relabeling_the_m2_baseline() {
        let names: Vec<_> = rerun_chips().map(|chip| chip.name).collect();
        assert_eq!(
            names,
            ["apple-m1", "apple-m3", "apple-m4", "apple-m5", "apple-m6"]
        );
        assert!(names.contains(&super::super::DEFAULT_CHIP));
        assert!(!names.contains(&REGISTRY_BASE_CHIP));
    }

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
        let compiler = "crates/stela-compiler/src/block/system.rs#h";
        assert!(runs.credits("apple-m6", compiler));
        assert!(!runs.credits("apple-m5", compiler), "a chip without a run");
        assert!(!runs.credits("apple-m6", "xtask/src/system_matrix/assess.rs#t"));
        Ok(())
    }

    #[test]
    fn chip_independent_code_cannot_name_a_chip() -> Result<()> {
        // The compiler depends on no workspace crate, and the reset
        // derivation never mentions a chip.
        let lock = fs::read_to_string(root().join("Cargo.lock"))?;
        let package = lock
            .split("[[package]]")
            .find(|package| package.contains("\nname = \"stela-compiler\"\n"))
            .context("Cargo.lock has no stela-compiler")?;
        let dependencies = package
            .split_once("dependencies = [")
            .map_or("", |(_, list)| list.split(']').next().unwrap_or_default());
        assert!(!dependencies.contains("\"stela-"), "{dependencies}");
        let resets = fs::read_to_string(root().join("xtask/src/system_matrix/resets.rs"))?;
        assert!(!resets.to_lowercase().contains("chip"));
        Ok(())
    }
}
