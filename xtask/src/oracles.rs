//! Run input-backed ignored tests and record each result with its inputs.
use crate::tools;
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Args)]
pub struct Oracles {
    /// List declared tests and missing inputs without building or running them.
    #[arg(long)]
    list: bool,
    /// Select package/function IDs or source paths containing this text.
    #[arg(long)]
    only: Option<String>,
    /// JSON report (default: .stela/oracles/<Unix timestamp>/report.json).
    #[arg(long)]
    output: Option<PathBuf>,
    /// Stop an individual test after this many seconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    package: String,
    test: String,
    source: PathBuf,
    kind: Kind,
    #[serde(default)]
    inputs: Vec<String>,
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    outputs: Vec<String>,
    #[serde(default)]
    programs: Vec<PathBuf>,
    #[serde(default)]
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Oracle,
    Isolation,
    Manual,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: u32,
    started_unix_seconds: u64,
    revision: String,
    working_tree_dirty: bool,
    list_only: bool,
    host_os: &'static str,
    host_arch: &'static str,
    error: Option<String>,
    build_stdout: Option<PathBuf>,
    build_stderr: Option<PathBuf>,
    tests: Vec<TestResult>,
}

#[derive(Debug, Serialize)]
struct TestResult {
    package: String,
    test: String,
    source: PathBuf,
    status: &'static str,
    reason: String,
    elapsed_ms: u128,
    inputs: Vec<Input>,
    stdout: Option<PathBuf>,
    stderr: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct Input {
    variable: String,
    kind: &'static str,
    path: Option<PathBuf>,
    bytes: Option<u64>,
    sha256: Option<String>,
}

#[derive(Debug)]
struct Binary {
    package: String,
    executable: PathBuf,
    ignored: Vec<String>,
}

impl Oracles {
    pub fn run(self) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let started = now.as_secs();
        let output = self.output.clone().unwrap_or_else(|| {
            tools::root().join(format!(".stela/oracles/{}/report.json", now.as_nanos()))
        });
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let report_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .with_context(|| format!("creating a new oracle report {}", output.display()))?;
        let logs = parent.join(format!("logs-{}", now.as_nanos()));
        fs::create_dir(&logs)?;
        let mut report = Report {
            schema: 1,
            started_unix_seconds: started,
            revision: git(&["rev-parse", "HEAD"])?,
            working_tree_dirty: !git(&["status", "--porcelain", "--untracked-files=no"])?
                .is_empty(),
            list_only: self.list,
            host_os: env::consts::OS,
            host_arch: env::consts::ARCH,
            error: None,
            build_stdout: None,
            build_stderr: None,
            tests: Vec::new(),
        };
        let result = self.collect(&mut report, &logs);
        if let Err(error) = &result {
            report.error = Some(format!("{error:#}"));
            for test in &mut report.tests {
                if test.status == "pending" {
                    test.status = "not_run";
                    test.reason = "run aborted; see the report error".into();
                }
            }
        }
        serde_json::to_writer_pretty(report_file, &report)?;
        println!("Oracle report: {}", output.display());
        result?;
        let failed = report
            .tests
            .iter()
            .filter(|test| test.status == "failed" || test.status == "timeout")
            .count();
        ensure!(
            failed == 0,
            "{failed} oracle tests failed; see {}",
            output.display()
        );
        Ok(())
    }

    fn collect(&self, report: &mut Report, directory: &Path) -> Result<()> {
        let entries: Vec<Entry> = serde_json::from_str(include_str!("oracles/manifest.json"))?;
        validate(&entries)?;
        let mut ready = Vec::new();
        for entry in entries.into_iter().filter(|entry| {
            self.only.as_ref().is_none_or(|filter| {
                format!("{}::{}", entry.package, entry.test).contains(filter)
                    || entry.source.to_string_lossy().contains(filter)
            })
        }) {
            let mut test = TestResult {
                package: entry.package.clone(),
                test: entry.test.clone(),
                source: entry.source.clone(),
                status: "skipped",
                reason: String::new(),
                elapsed_ms: 0,
                inputs: Vec::new(),
                stdout: None,
                stderr: None,
            };
            match readiness(&entry, |name| env::var_os(name)) {
                Err(reason) => test.reason = reason,
                Ok(paths) => {
                    test.status = if self.list { "ready" } else { "pending" };
                    for binding in paths {
                        test.inputs.push(identity(binding, self.list)?);
                    }
                    ready.push((entry, report.tests.len()));
                }
            }
            println!(
                "{} {}::{} {}",
                test.status, test.package, test.test, test.reason
            );
            report.tests.push(test);
        }
        ensure!(
            !report.tests.is_empty(),
            "no oracle entries match the requested filter"
        );
        if self.list || ready.is_empty() {
            return Ok(());
        }
        let packages: BTreeSet<_> = ready
            .iter()
            .map(|(entry, _)| entry.package.as_str())
            .collect();
        report.build_stdout = Some(directory.join("build.stdout.jsonl"));
        report.build_stderr = Some(directory.join("build.stderr.log"));
        let binaries = binaries(&packages, directory)?;
        for (entry, index) in ready {
            match selected_test(&entry, &binaries)? {
                None => {
                    report.tests[index].status = "skipped";
                    report.tests[index].reason =
                        "test is not compiled on this host with these features".into();
                }
                Some((binary, name)) => {
                    run_test(
                        &mut report.tests[index],
                        binary,
                        name,
                        directory,
                        index,
                        Duration::from_secs(self.timeout_secs),
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn validate(entries: &[Entry]) -> Result<()> {
    let mut keys = BTreeSet::new();
    for entry in entries {
        ensure!(
            keys.insert((&entry.package, &entry.test)),
            "duplicate oracle selector {}::{}",
            entry.package,
            entry.test
        );
        ensure!(
            !entry.package.is_empty() && !entry.test.is_empty(),
            "empty oracle selector"
        );
        if entry.kind == Kind::Oracle {
            ensure!(
                entry
                    .inputs
                    .iter()
                    .chain(&entry.values)
                    .chain(&entry.outputs)
                    .all(|name| name.starts_with("STELA_")
                        && name.bytes().all(|byte| byte.is_ascii_uppercase()
                            || byte.is_ascii_digit()
                            || byte == b'_')),
                "invalid oracle input name in {}",
                entry.test
            );
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum BindingKind {
    Path,
    Value,
    Output,
    Program,
}

#[derive(Debug)]
struct Binding {
    variable: String,
    value: std::ffi::OsString,
    kind: BindingKind,
}

fn readiness(
    entry: &Entry,
    mut variable: impl FnMut(&str) -> Option<std::ffi::OsString>,
) -> std::result::Result<Vec<Binding>, String> {
    if entry.kind != Kind::Oracle {
        return Err(format!("{:?}: {}", entry.kind, entry.reason));
    }
    let mut bindings = Vec::new();
    for (names, kind) in [
        (&entry.inputs, BindingKind::Path),
        (&entry.values, BindingKind::Value),
        (&entry.outputs, BindingKind::Output),
    ] {
        for name in names {
            let value = variable(name)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("missing {name}"))?;
            let path = Path::new(&value);
            match kind {
                BindingKind::Path if !path.exists() => {
                    return Err(format!("{name}: input does not exist: {}", path.display()));
                }
                BindingKind::Output if path.exists() => {
                    return Err(format!("{name}: output already exists: {}", path.display()));
                }
                _ => {}
            }
            bindings.push(Binding {
                variable: name.clone(),
                value,
                kind,
            });
        }
    }
    for program in &entry.programs {
        if !program.is_file() {
            return Err(format!("missing program {}", program.display()));
        }
        bindings.push(Binding {
            variable: "program".into(),
            value: program.as_os_str().to_owned(),
            kind: BindingKind::Program,
        });
    }
    Ok(bindings)
}

fn identity(binding: Binding, list: bool) -> Result<Input> {
    let Binding {
        variable,
        value,
        kind,
    } = binding;
    if matches!(kind, BindingKind::Value) {
        let bytes = value.as_encoded_bytes();
        return Ok(Input {
            variable,
            kind: "value",
            path: None,
            bytes: Some(bytes.len() as u64),
            sha256: Some(format!("{:x}", Sha256::digest(bytes))),
        });
    }
    let path = PathBuf::from(value);
    if matches!(kind, BindingKind::Output) {
        return Ok(Input {
            variable,
            kind: "output",
            path: Some(path),
            bytes: None,
            sha256: None,
        });
    }
    let metadata = fs::metadata(&path)?;
    Ok(Input {
        variable,
        kind: if matches!(kind, BindingKind::Program) {
            "program"
        } else {
            "path"
        },
        bytes: metadata.is_file().then_some(metadata.len()),
        sha256: if list || !metadata.is_file() {
            None
        } else {
            Some(digest(&path)?)
        },
        path: Some(path),
    })
}

fn binaries(packages: &BTreeSet<&str>, directory: &Path) -> Result<Vec<Binary>> {
    let metadata = tools::cargo()
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .output()?;
    ensure!(metadata.status.success(), "cargo metadata failed");
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let package_names: BTreeMap<_, _> = metadata["packages"]
        .as_array()
        .context("cargo metadata packages")?
        .iter()
        .filter_map(|package| {
            Some((
                package["id"].as_str()?.to_owned(),
                package["name"].as_str()?.to_owned(),
            ))
        })
        .collect();
    let mut build = tools::cargo();
    build.args([
        "test",
        "--all-features",
        "--locked",
        "--no-run",
        "--message-format=json",
    ]);
    for package in packages {
        build.args(["-p", package]);
    }
    let output = build.output()?;
    fs::write(directory.join("build.stdout.jsonl"), &output.stdout)?;
    fs::write(directory.join("build.stderr.log"), &output.stderr)?;
    ensure!(
        output.status.success(),
        "oracle test build failed; see {}",
        directory.join("build.stderr.log").display()
    );
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if value["reason"] != "compiler-artifact" || value["profile"]["test"] != true {
            continue;
        }
        let Some(executable) = value["executable"].as_str().map(PathBuf::from) else {
            continue;
        };
        let Some(package) = value["package_id"]
            .as_str()
            .and_then(|id| package_names.get(id))
        else {
            continue;
        };
        if !packages.contains(package.as_str()) || !seen.insert(executable.clone()) {
            continue;
        }
        let listed = Command::new(&executable)
            .args(["--list", "--ignored", "--format=terse"])
            .output()?;
        ensure!(
            listed.status.success(),
            "listing ignored tests in {} failed",
            executable.display()
        );
        let ignored = String::from_utf8(listed.stdout)?
            .lines()
            .filter_map(|line| line.strip_suffix(": test").map(str::to_owned))
            .collect();
        result.push(Binary {
            package: package.clone(),
            executable,
            ignored,
        });
    }
    Ok(result)
}

fn selected_test<'a>(
    entry: &Entry,
    binaries: &'a [Binary],
) -> Result<Option<(&'a Binary, &'a str)>> {
    let mut found = None;
    for binary in binaries
        .iter()
        .filter(|binary| binary.package == entry.package)
    {
        for name in &binary.ignored {
            if name == &entry.test || name.rsplit("::").next() == Some(entry.test.as_str()) {
                ensure!(
                    found.is_none(),
                    "ambiguous oracle selector {}::{}",
                    entry.package,
                    entry.test
                );
                found = Some((binary, name.as_str()));
            }
        }
    }
    Ok(found)
}

fn run_test(
    test: &mut TestResult,
    binary: &Binary,
    name: &str,
    directory: &Path,
    index: usize,
    timeout: Duration,
) -> Result<()> {
    let stdout = directory.join(format!("{index}.stdout.log"));
    let stderr = directory.join(format!("{index}.stderr.log"));
    let started = Instant::now();
    let mut child = Command::new(&binary.executable)
        .current_dir(tools::root())
        .args([
            "--ignored",
            "--exact",
            name,
            "--test-threads=1",
            "--format=pretty",
        ])
        .stdout(fs::File::create(&stdout)?)
        .stderr(fs::File::create(&stderr)?)
        .spawn()
        .with_context(|| format!("starting oracle {name}"))?;
    let status = tools::wait(&mut child, timeout)?;
    test.elapsed_ms = started.elapsed().as_millis();
    test.test = name.to_owned();
    test.stdout = Some(stdout.clone());
    test.stderr = Some(stderr);
    match status {
        None => {
            test.status = "timeout";
            test.reason = "test exceeded its deadline".into();
        }
        Some(status) if status.success() && ran_one_test(&fs::read_to_string(stdout)?) => {
            test.status = "passed";
        }
        Some(status) => {
            test.status = "failed";
            test.reason = format!("{status}; expected one passing test");
        }
    }
    println!("{} {}::{}", test.status, test.package, test.test);
    Ok(())
}

fn ran_one_test(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
}

fn digest(path: &Path) -> Result<String> {
    let mut input = BufReader::new(fs::File::open(path)?);
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn git(args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .args(args)
        .current_dir(tools::root())
        .output()?;
    ensure!(output.status.success(), "git {args:?} failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: Kind) -> Entry {
        Entry {
            package: "fixture".into(),
            test: "oracle".into(),
            source: "fixture.rs".into(),
            kind,
            inputs: vec!["STELA_ORACLE".into()],
            values: Vec::new(),
            outputs: Vec::new(),
            programs: Vec::new(),
            reason: "child process".into(),
        }
    }

    #[test]
    fn missing_inputs_and_isolation_children_are_not_ready() {
        assert!(
            readiness(&entry(Kind::Oracle), |_| None)
                .unwrap_err()
                .contains("STELA_ORACLE")
        );
        assert!(
            readiness(&entry(Kind::Isolation), |_| panic!(
                "isolation child must not inspect inputs"
            ))
            .is_err()
        );
        let directory = tempfile::tempdir().unwrap();
        let ready = readiness(&entry(Kind::Oracle), |_| Some(directory.path().into())).unwrap();
        assert_eq!(Path::new(&ready[0].value), directory.path());
    }

    #[test]
    fn prerequisite_kinds_enforce_distinct_path_rules() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("fresh");
        let mut declared = entry(Kind::Oracle);
        declared.inputs.clear();
        declared.values = vec!["STELA_VALUE".into()];
        declared.outputs = vec!["STELA_OUTPUT".into()];
        let lookup = |name: &str| {
            Some(if name == "STELA_VALUE" {
                "42".into()
            } else {
                output.as_os_str().to_owned()
            })
        };
        let ready = readiness(&declared, lookup).unwrap();
        let value = identity(ready.into_iter().next().unwrap(), false).unwrap();
        assert_eq!(value.kind, "value");
        assert!(value.path.is_none());
        assert_eq!(value.bytes, Some(2));
        assert!(value.sha256.is_some());
        fs::create_dir(&output).unwrap();
        assert!(
            readiness(&declared, lookup)
                .unwrap_err()
                .contains("already exists")
        );
    }

    #[test]
    fn pass_requires_one_executed_test() {
        assert!(!ran_one_test(
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"
        ));
        assert!(!ran_one_test(
            "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out"
        ));
        assert!(ran_one_test(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
        ));
    }

    #[test]
    fn selectors_require_one_compiled_test() {
        let binaries = vec![Binary {
            package: "fixture".into(),
            executable: "a".into(),
            ignored: vec!["a::oracle".into(), "b::oracle".into()],
        }];
        assert!(selected_test(&entry(Kind::Oracle), &binaries).is_err());
        assert!(selected_test(&entry(Kind::Oracle), &[]).unwrap().is_none());
    }

    #[test]
    fn manifest_covers_every_ignored_test_in_tracked_sources() {
        let entries: Vec<Entry> =
            serde_json::from_str(include_str!("oracles/manifest.json")).unwrap();
        let declared: BTreeSet<_> = entries
            .iter()
            .map(|entry| (entry.package.clone(), entry.test.clone()))
            .collect();
        let files = git(&["ls-files", "--", "crates/**/*.rs", "xtask/**/*.rs"]).unwrap();
        let mut observed = BTreeSet::new();
        for file in files.lines() {
            let text = fs::read_to_string(tools::root().join(file)).unwrap();
            let package = if file.starts_with("xtask/") {
                "xtask"
            } else {
                file.split('/').nth(1).unwrap()
            };
            for (offset, _) in text.match_indices(concat!("#[", "ignore")) {
                let function = &text[offset..];
                let start = function.find("fn ").expect("ignored test function") + 3;
                let function = &function[start..];
                let end = function.find('(').expect("test parameters");
                observed.insert((package.to_owned(), function[..end].trim().to_owned()));
            }
        }
        assert_eq!(
            declared, observed,
            "update oracle metadata when ignored tests change"
        );
    }

    #[test]
    fn manifest_has_unique_selectors_and_valid_prerequisites() {
        let entries: Vec<Entry> =
            serde_json::from_str(include_str!("oracles/manifest.json")).unwrap();
        validate(&entries).unwrap();
    }
}
