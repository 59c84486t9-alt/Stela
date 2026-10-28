//! macOS application bundles as LaunchServices reads them: the
//! `Contents/Info.plist` keys that name the executable, its identity, its
//! launch environment and the system version it needs.
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::path::{Path, PathBuf};

const INFO: &str = "Contents/Info.plist";
const EXECUTABLES: &str = "Contents/MacOS";

/// One application bundle.
#[derive(Debug, Clone)]
pub(crate) struct AppBundle {
    /// The bundle directory, absolute.
    pub(crate) path: PathBuf,
    pub(crate) info: Dictionary,
}

impl AppBundle {
    /// Whether `path` is a bundle directory: one with `Contents/Info.plist`.
    pub(crate) fn is_bundle(path: &Path) -> bool {
        path.is_dir() && path.join(INFO).is_file()
    }

    pub(crate) fn open(path: &Path) -> Result<Self> {
        let path = std::path::absolute(path)?;
        let info = Value::from_file(path.join(INFO))
            .with_context(|| format!("{} has no readable {INFO}", path.display()))?
            .into_dictionary()
            .with_context(|| format!("{}'s {INFO} is not a dictionary", path.display()))?;
        Ok(Self { path, info })
    }

    /// The `Info.plist` path.
    pub(crate) fn info_path(&self) -> PathBuf {
        self.path.join(INFO)
    }

    pub(crate) fn string(&self, key: &str) -> Option<&str> {
        self.info.get(key).and_then(Value::as_string)
    }

    /// `CFBundleIdentifier`.
    pub(crate) fn identifier(&self) -> Option<&str> {
        self.string("CFBundleIdentifier")
    }

    /// The bundle's file name without `.app`, as Finder shows it.
    pub(crate) fn name(&self) -> String {
        self.path
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// `Contents/MacOS/<CFBundleExecutable>`.
    pub(crate) fn executable(&self) -> Result<PathBuf> {
        let name = self
            .string("CFBundleExecutable")
            .with_context(|| format!("{} names no CFBundleExecutable", self.path.display()))?;
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "{} names an invalid CFBundleExecutable {name:?}",
            self.path.display()
        );
        let executable = self.path.join(EXECUTABLES).join(name);
        ensure!(
            executable.is_file(),
            "{} has no executable {}",
            self.path.display(),
            executable.display()
        );
        Ok(executable)
    }

    /// `LSEnvironment`'s string values, which LaunchServices adds to the
    /// environment of the app it starts.
    pub(crate) fn environment(&self) -> Vec<(String, String)> {
        self.info
            .get("LSEnvironment")
            .and_then(Value::as_dictionary)
            .map(|variables| {
                variables
                    .iter()
                    .filter_map(|(key, value)| Some((key.clone(), value.as_string()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `LSMinimumSystemVersion`.
    pub(crate) fn minimum_system_version(&self) -> Option<&str> {
        self.string("LSMinimumSystemVersion")
    }
}

/// Whether the dotted version `have` is at least `need`, numerically
/// component by component (missing components are 0).
pub(crate) fn version_at_least(have: &str, need: &str) -> bool {
    let parse = |text: &str| -> Vec<u64> {
        text.trim()
            .split('.')
            .map(|part| part.trim().parse().unwrap_or(0))
            .collect()
    };
    let (have, need) = (parse(have), parse(need));
    for index in 0..have.len().max(need.len()) {
        let (a, b) = (
            have.get(index).copied().unwrap_or(0),
            need.get(index).copied().unwrap_or(0),
        );
        if a != b {
            return a > b;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A bundle at `path` with `info` and an executable `body`.
    pub(crate) fn make(path: &Path, info: Dictionary, body: &[u8]) -> Result<()> {
        std::fs::create_dir_all(path.join(EXECUTABLES))?;
        if let Some(name) = info.get("CFBundleExecutable").and_then(Value::as_string) {
            std::fs::write(path.join(EXECUTABLES).join(name), body)?;
        }
        Value::Dictionary(info).to_file_xml(path.join(INFO))?;
        Ok(())
    }

    pub(crate) fn info(entries: &[(&str, Value)]) -> Dictionary {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect()
    }

    #[test]
    fn bundle_records_identity_and_launch_environment() -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("Hello World.app");
        let mut environment = Dictionary::new();
        environment.insert("HELLO".into(), "world".into());
        environment.insert("IGNORED".into(), Value::Integer(1.into()));
        make(
            &path,
            info(&[
                ("CFBundleExecutable", "hello".into()),
                ("CFBundleIdentifier", "com.example.hello".into()),
                ("LSMinimumSystemVersion", "14.0".into()),
                ("LSEnvironment", Value::Dictionary(environment)),
            ]),
            b"\xcf\xfa\xed\xfe",
        )?;
        assert!(AppBundle::is_bundle(&path));
        assert!(!AppBundle::is_bundle(work.path()));
        let bundle = AppBundle::open(&path)?;
        assert_eq!(bundle.name(), "Hello World");
        assert_eq!(bundle.identifier(), Some("com.example.hello"));
        assert_eq!(bundle.executable()?, path.join("Contents/MacOS/hello"));
        assert_eq!(bundle.environment(), [("HELLO".into(), "world".into())]);
        assert_eq!(bundle.minimum_system_version(), Some("14.0"));
        Ok(())
    }

    #[test]
    fn bundle_requires_contents_macos_executable() -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("Bad.app");
        make(&path, info(&[("CFBundleExecutable", "../x".into())]), b"")?;
        assert!(AppBundle::open(&path)?.executable().is_err());
        Ok(())
    }

    #[test]
    fn versions_compare_by_number() {
        assert!(version_at_least("27.0.1", "27"));
        assert!(version_at_least("27.0.1", "26.4"));
        assert!(version_at_least("27.0.1", "27.0.1"));
        assert!(!version_at_least("27.0.1", "27.1"));
        assert!(!version_at_least("27.0.1", "28.0"));
        assert!(version_at_least("27.10", "27.9"));
    }
}
