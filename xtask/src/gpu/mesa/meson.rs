//! The Stela compiler build as Meson configured it: the targets
//! `src/stela/meson.build` defines, its tests and the files they read.
use super::capture;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Deserialize)]
struct Target {
    name: String,
    defined_in: PathBuf,
    filename: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Test {
    pub name: String,
    cmd: Vec<PathBuf>,
    env: BTreeMap<String, String>,
    workdir: Option<PathBuf>,
    suite: Vec<String>,
}

impl Test {
    /// The test's command and environment, followed by `args`.
    pub fn command<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(&self, args: I) -> Command {
        let mut command = Command::new(&self.cmd[0]);
        command.args(&self.cmd[1..]).args(args).envs(&self.env);
        if let Some(directory) = &self.workdir {
            command.current_dir(directory);
        }
        command
    }
}

pub(super) struct Build {
    directory: PathBuf,
    /// Each target's name and outputs, relative to `directory`.
    targets: BTreeMap<String, Vec<PathBuf>>,
    tests: Vec<Test>,
}

/// The files a build read: its archives, and its sources and headers under
/// `gpu` outside the Mesa tree `source`, which is bound separately.
pub(super) struct Inputs {
    pub archives: Vec<PathBuf>,
    pub external: Vec<PathBuf>,
}

impl Build {
    pub fn load(directory: &Path, definition: &Path) -> Result<Self> {
        let introspect = |name: &str| -> Result<Vec<u8>> {
            let path = directory.join("meson-info").join(name);
            fs::read(&path).with_context(|| format!("cannot read {}", path.display()))
        };
        let definition = fs::canonicalize(definition)?;
        let mut targets = BTreeMap::new();
        for target in serde_json::from_slice::<Vec<Target>>(&introspect("intro-targets.json")?)? {
            if fs::canonicalize(&target.defined_in)? != definition {
                continue;
            }
            let outputs = target
                .filename
                .iter()
                .map(|path| Ok(path.strip_prefix(directory)?.to_owned()))
                .collect::<Result<_>>()?;
            ensure!(
                targets.insert(target.name.clone(), outputs).is_none(),
                "Meson defines {} twice",
                target.name
            );
        }
        ensure!(!targets.is_empty(), "Meson defines no Stela targets");
        let tests = serde_json::from_slice::<Vec<Test>>(&introspect("intro-tests.json")?)?;
        ensure!(
            tests.iter().all(|test| !test.cmd.is_empty()),
            "Meson test without a command"
        );
        Ok(Self {
            directory: directory.to_owned(),
            targets,
            tests,
        })
    }

    /// Every output Stela's Meson definition builds.
    pub fn outputs(&self) -> impl Iterator<Item = &Path> {
        self.targets.values().flatten().map(PathBuf::as_path)
    }

    /// Whether Stela's Meson definition builds this file.
    pub fn builds(&self, path: &Path) -> bool {
        self.outputs()
            .any(|output| self.directory.join(output) == path)
    }

    /// Whether this configuration builds the named target.
    pub fn defines(&self, name: &str) -> bool {
        self.targets.contains_key(name)
    }

    /// An executable Stela's Meson definition builds in this configuration.
    pub fn executable(&self, name: &str) -> Result<PathBuf> {
        match self.targets.get(name).map(Vec::as_slice) {
            Some([output]) => Ok(self.directory.join(output)),
            _ => anyhow::bail!("Meson defines no executable {name}"),
        }
    }

    pub fn command(&self, name: &str) -> Result<Command> {
        Ok(Command::new(self.executable(name)?))
    }

    /// The tests in a Stela suite, which Meson prefixes with its project.
    pub fn suite<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Test> {
        self.tests.iter().filter(move |test| {
            test.suite
                .iter()
                .any(|suite| suite.strip_prefix("mesa:") == Some(name))
        })
    }

    /// Asks ninja which archives and files the built outputs read: the
    /// transitive inputs of each output, and the headers each object included.
    pub fn inputs(&self, ninja: &Path, gpu: &Path, source: &Path) -> Result<Inputs> {
        let tool = |name: &str, args: Vec<&OsStr>| {
            capture(
                Command::new(ninja)
                    .arg("-C")
                    .arg(&self.directory)
                    .args(["-t", name])
                    .args(args),
            )
        };
        let inputs = tool("inputs", self.outputs().map(Path::as_os_str).collect())?;
        let (objects, files): (Vec<_>, Vec<_>) =
            inputs.lines().partition(|line| line.ends_with(".o"));
        let deps = tool("deps", objects.iter().map(OsStr::new).collect())?;
        let headers = deps.lines().filter_map(|line| line.strip_prefix("    "));
        let gpu = fs::canonicalize(gpu)?;
        let source = fs::canonicalize(source)?;
        let mut archives = BTreeSet::new();
        let mut external = BTreeSet::new();
        for file in files.into_iter().chain(headers) {
            if file.ends_with(".a") {
                archives.insert(self.directory.join(file));
                continue;
            }
            // Upstream files link into their pinned checkouts, outside `gpu`.
            let path = fs::canonicalize(self.directory.join(file))
                .with_context(|| format!("ninja names a missing input {file}"))?;
            if path.starts_with(&gpu) && !path.starts_with(&source) {
                external.insert(path);
            }
        }
        ensure!(!archives.is_empty(), "ninja names no archive inputs");
        Ok(Inputs {
            archives: archives.into_iter().collect(),
            external: external.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn introspection_selects_the_stela_definition_and_suites() {
        let temp = tempfile::tempdir().unwrap();
        let build = temp.path().join("build");
        let info = build.join("meson-info");
        fs::create_dir_all(&info).unwrap();
        let stela = temp.path().join("stela.build");
        let other = temp.path().join("other.build");
        fs::write(&stela, "").unwrap();
        fs::write(&other, "").unwrap();
        let target = |name: &str, defined_in: &Path| {
            json!({"name": name, "type": "executable", "defined_in": defined_in,
                   "filename": [build.join("src").join(name)]})
        };
        fs::write(
            info.join("intro-targets.json"),
            json!([target("probe", &stela), target("upstream", &other)]).to_string(),
        )
        .unwrap();
        let test = |name: &str, suite: &[&str]| {
            json!({"name": name, "cmd": [build.join("src/probe"), "--mode"], "env": {"A": "1"},
                   "workdir": null, "suite": suite, "timeout": 30})
        };
        fs::write(
            info.join("intro-tests.json"),
            json!([
                test("plain", &["mesa:stela"]),
                test("input", &["mesa:stela", "mesa:stela-air-input"]),
                test("upstream", &["mesa:intel"]),
            ])
            .to_string(),
        )
        .unwrap();
        let loaded = Build::load(&build, &stela).unwrap();
        assert_eq!(
            loaded.outputs().collect::<Vec<_>>(),
            [Path::new("src/probe")]
        );
        assert_eq!(loaded.executable("probe").unwrap(), build.join("src/probe"));
        assert!(loaded.defines("probe") && !loaded.defines("upstream"));
        assert!(loaded.executable("upstream").is_err());
        let names = |suite| {
            loaded
                .suite(suite)
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(names("stela"), ["plain", "input"]);
        assert_eq!(names("stela-air-input"), ["input"]);
        let command = loaded
            .suite("stela-air-input")
            .next()
            .unwrap()
            .command(["x"]);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [OsStr::new("--mode"), OsStr::new("x")]
        );
        assert!(Build::load(&build, &other).is_ok());
        fs::write(info.join("intro-targets.json"), "[]").unwrap();
        assert!(Build::load(&build, &stela).is_err());
    }
}
