//! What `stela run` is asked to run, resolved before exec: a path, a bare
//! name looked up in `PATH` as `execvp` looks it up, or an app bundle,
//! whose executable starts as LaunchServices starts it. Files that are not
//! arm64 programs are explained here rather than failing inside exec.
use crate::bundle::{self, AppBundle};
use crate::guest_system::PINNED_VERSION;
use anyhow::{Result, anyhow, bail};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use stela_runtime::hosted::{
    activation,
    hardware::{CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64},
    memory::PAGE_BYTES,
};

const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
const CPU_TYPE_X86: u32 = 7;
pub(crate) const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_POWERPC: u32 = 18;
const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;
const CPU_SUBTYPE_X86_64_H: u32 = 8;
/// The environment variable LaunchServices names a started app's bundle in.
const BUNDLE_IDENTIFIER_VARIABLE: &str = "__CFBundleIdentifier";

/// The Mach-O slices of a file, as (CPU type, subtype) pairs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Architectures(pub(crate) Vec<(u32, u32)>);

impl Architectures {
    /// The slices of the Mach-O at `path`; empty when it is none.
    pub(crate) fn of(path: &Path) -> Result<Self> {
        Ok(Self(activation::slices(&head(path)?)))
    }

    pub(crate) fn arm64(&self) -> bool {
        self.0.iter().any(|&(cpu, _)| cpu == CPU_TYPE_ARM64)
    }

    pub(crate) fn x86_64(&self) -> bool {
        self.0.iter().any(|&(cpu, _)| cpu == CPU_TYPE_X86_64)
    }

    /// Runs only under Stela on an Intel Mac: arm64 and no x86_64 slice.
    pub(crate) fn arm64_only(&self) -> bool {
        self.arm64() && !self.x86_64()
    }

    /// The architectures' names, as `lipo -archs` prints them.
    pub(crate) fn names(&self) -> String {
        self.0
            .iter()
            .map(|&(cpu, subtype)| name(cpu, subtype))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn name(cpu: u32, subtype: u32) -> String {
    match (cpu, subtype & !CPU_SUBTYPE_MASK) {
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) => "arm64e".into(),
        (CPU_TYPE_ARM64, _) => "arm64".into(),
        (CPU_TYPE_ARM64_32, _) => "arm64_32".into(),
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H) => "x86_64h".into(),
        (CPU_TYPE_X86_64, _) => "x86_64".into(),
        (CPU_TYPE_X86, _) => "i386".into(),
        (CPU_TYPE_ARM, _) => "arm".into(),
        (CPU_TYPE_POWERPC, _) => "ppc".into(),
        (CPU_TYPE_POWERPC64, _) => "ppc64".into(),
        _ => format!("CPU type {cpu:#x}"),
    }
}

/// The first bytes of the file at `path`: exec's first page.
fn head(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut head = vec![];
    std::fs::File::open(path)
        .map_err(|error| anyhow!("cannot read {}: {error}", path.display()))?
        .take(PAGE_BYTES)
        .read_to_end(&mut head)?;
    Ok(head)
}

/// A program resolved for exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The path exec runs.
    pub(crate) program: PathBuf,
    /// Its argv[0] unless the command gives one.
    pub(crate) argv0: OsString,
    /// Variables added to the inherited environment.
    pub(crate) environment: Vec<(OsString, OsString)>,
}

impl Target {
    /// `program` exactly as named, as `execve` takes its path.
    pub(crate) fn path(program: &Path) -> Self {
        Self {
            program: program.to_owned(),
            argv0: program.as_os_str().to_owned(),
            environment: vec![],
        }
    }
}

/// `path` under the first root holding it, else the host's own.
pub(crate) fn guest_path(roots: &[PathBuf], path: &Path) -> PathBuf {
    match path.strip_prefix("/") {
        Ok(relative) => roots
            .iter()
            .map(|root| root.join(relative))
            .find(|candidate| candidate.exists())
            .unwrap_or_else(|| path.to_owned()),
        Err(_) => path.to_owned(),
    }
}

/// Resolve what `stela run PROGRAM` names, with `search` as `PATH`.
pub(crate) fn resolve(roots: &[PathBuf], program: &Path, search: Option<&OsStr>) -> Result<Target> {
    let name = program.as_os_str().as_bytes();
    let bare = !name.contains(&b'/') && name != b"." && name != b"..";
    if bare && !AppBundle::is_bundle(program) {
        return search_path(roots, program, search);
    }
    if AppBundle::is_bundle(program) {
        return app(program);
    }
    let file = guest_path(roots, program);
    if file.is_dir() {
        bail!(
            "{} is a directory, not a program or an app bundle",
            program.display()
        );
    }
    if !file.exists() {
        bail!("{}: no such file", program.display());
    }
    Ok(Target::path(program))
}

/// `execvp`'s lookup of a name without a slash: each `PATH` entry, under the
/// guest roots first.
fn search_path(roots: &[PathBuf], name: &Path, search: Option<&OsStr>) -> Result<Target> {
    let found = search
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .map(|directory| {
            if directory.as_os_str().is_empty() {
                name.to_owned()
            } else {
                directory.join(name)
            }
        })
        .find(|candidate| {
            let file = guest_path(roots, candidate);
            file.is_file()
                && file
                    .metadata()
                    .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        });
    match found {
        Some(program) => Ok(Target {
            program,
            argv0: name.as_os_str().to_owned(),
            environment: vec![],
        }),
        None if name.is_file() => bail!(
            "{0} is not in PATH; to run the file in this directory, use ./{0}",
            name.display()
        ),
        None => bail!(
            "{}: no such program in PATH, and not a stela command (see `stela --help`)",
            name.display()
        ),
    }
}

/// An app bundle's executable, as LaunchServices starts it: argv[0] its
/// absolute path, the environment with the bundle's `LSEnvironment` and
/// identifier.
fn app(path: &Path) -> Result<Target> {
    let bundle = AppBundle::open(path)?;
    if let Some(minimum) = bundle.minimum_system_version()
        && !bundle::version_at_least(PINNED_VERSION, minimum)
    {
        bail!(
            "{} needs macOS {minimum} or later, and Stela runs macOS {PINNED_VERSION}",
            bundle.name()
        );
    }
    let executable = bundle.executable()?;
    let mut environment: Vec<(OsString, OsString)> = bundle
        .environment()
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    if let Some(identifier) = bundle.identifier() {
        environment.push((BUNDLE_IDENTIFIER_VARIABLE.into(), identifier.into()));
    }
    Ok(Target {
        argv0: executable.as_os_str().to_owned(),
        program: executable,
        environment,
    })
}

/// Why exec refuses the host file `file` (named `program`), from the
/// activator's errno, as advice.
pub(crate) fn not_runnable(program: &Path, file: &Path, errno: i32) -> anyhow::Error {
    let name = program.display();
    if errno == activation::EBADARCH {
        let architectures = Architectures::of(file).unwrap_or_default();
        return if architectures.x86_64() {
            anyhow!(
                "{name} is an Intel program ({}); it runs natively on this Mac, without stela",
                architectures.names()
            )
        } else {
            anyhow!(
                "{name} is built for {}, not arm64; Stela runs arm64 programs",
                architectures.names()
            )
        };
    }
    anyhow!(
        "{name} is not a program Stela can run: it is neither a Mach-O executable, a #! \
         script nor an app bundle"
    )
}

/// `execve`'s permission check on the host file: some execute bit.
pub(crate) fn check_executable(program: &Path, file: &Path) -> Result<()> {
    let mode = file.metadata()?.permissions().mode();
    if mode & 0o111 == 0 {
        bail!(
            "{0} is not executable; make it so with `chmod +x {0}`",
            program.display()
        );
    }
    Ok(())
}

/// The advice for an executable without a code signature.
pub(crate) fn unsigned(program: &Path) -> anyhow::Error {
    anyhow!(
        "{0} is not code-signed, and arm64 macOS runs only signed code. Sign it ad hoc with \
         `codesign -s - {0}` (on a copy you own) and run it again",
        program.display()
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bundle::tests::{info, make};

    /// A thin Mach-O header of `cpu` and `subtype`.
    pub(crate) fn thin(cpu: u32, subtype: u32) -> Vec<u8> {
        let mut head = 0xfeed_facfu32.to_le_bytes().to_vec();
        head.extend(cpu.to_le_bytes());
        head.extend(subtype.to_le_bytes());
        head.resize(64, 0);
        head
    }

    fn executable(path: &Path, bytes: &[u8]) -> Result<()> {
        std::fs::write(path, bytes)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn architectures_are_named_and_arm64_only_is_found() -> Result<()> {
        let work = tempfile::tempdir()?;
        let arm64e = work.path().join("arm64e");
        executable(&arm64e, &thin(CPU_TYPE_ARM64, 0x8000_0002))?;
        let architectures = Architectures::of(&arm64e)?;
        assert_eq!(architectures.names(), "arm64e");
        assert!(architectures.arm64_only());
        let mut fat = 0xcafe_babeu32.to_be_bytes().to_vec();
        fat.extend(2u32.to_be_bytes());
        for cpu in [CPU_TYPE_X86_64, CPU_TYPE_ARM64] {
            fat.extend(cpu.to_be_bytes());
            fat.extend([0; 16]);
        }
        let universal = work.path().join("universal");
        executable(&universal, &fat)?;
        let architectures = Architectures::of(&universal)?;
        assert_eq!(architectures.names(), "x86_64, arm64");
        assert!(architectures.arm64() && !architectures.arm64_only());
        let text = work.path().join("text");
        executable(&text, b"hello")?;
        assert_eq!(Architectures::of(&text)?, Architectures::default());
        Ok(())
    }

    #[test]
    fn intel_and_other_files_are_explained() -> Result<()> {
        let work = tempfile::tempdir()?;
        let intel = work.path().join("intel");
        executable(&intel, &thin(CPU_TYPE_X86_64, 3))?;
        let message = not_runnable(&intel, &intel, activation::EBADARCH).to_string();
        assert!(message.contains("Intel program (x86_64)"), "{message}");
        let ppc = work.path().join("ppc");
        executable(&ppc, &thin(CPU_TYPE_POWERPC64, 0))?;
        let message = not_runnable(&ppc, &ppc, activation::EBADARCH).to_string();
        assert!(message.contains("built for ppc64"), "{message}");
        let message = not_runnable(&ppc, &ppc, activation::ENOEXEC).to_string();
        assert!(message.contains("neither a Mach-O"), "{message}");
        let plain = work.path().join("plain");
        std::fs::write(&plain, b"#!/bin/sh\n")?;
        let message = check_executable(&plain, &plain).unwrap_err().to_string();
        assert!(message.contains("chmod +x"), "{message}");
        assert!(unsigned(&plain).to_string().contains("codesign -s -"));
        Ok(())
    }

    #[test]
    fn bare_names_are_looked_up_in_path_under_the_roots_first() -> Result<()> {
        let work = tempfile::tempdir()?;
        let root = work.path().join("root");
        let host_bin = work.path().join("host/bin");
        std::fs::create_dir_all(root.join(host_bin.strip_prefix("/")?))?;
        std::fs::create_dir_all(&host_bin)?;
        executable(&host_bin.join("tool"), b"host")?;
        executable(
            &root.join(host_bin.strip_prefix("/")?).join("guest"),
            b"guest",
        )?;
        std::fs::write(host_bin.join("plain"), b"not executable")?;
        let search = std::env::join_paths([work.path().join("missing"), host_bin.clone()])?;
        let roots = [root.clone()];
        let target = resolve(&roots, Path::new("tool"), Some(&search))?;
        assert_eq!(target.program, host_bin.join("tool"));
        assert_eq!(target.argv0, "tool");
        assert_eq!(
            resolve(&roots, Path::new("guest"), Some(&search))?.program,
            host_bin.join("guest")
        );
        let message = resolve(&roots, Path::new("plain"), Some(&search))
            .unwrap_err()
            .to_string();
        assert!(message.contains("not a stela command"), "{message}");
        let message = resolve(&roots, Path::new("nothing"), None)
            .unwrap_err()
            .to_string();
        assert!(message.contains("no such program in PATH"), "{message}");
        Ok(())
    }

    #[test]
    fn paths_resolve_as_given_and_directories_are_refused() -> Result<()> {
        let work = tempfile::tempdir()?;
        let tool = work.path().join("tool");
        executable(&tool, b"x")?;
        let target = resolve(&[], &tool, None)?;
        assert_eq!(
            (target.program.clone(), target.argv0),
            (tool.clone(), tool.into())
        );
        assert!(resolve(&[], work.path(), None).is_err());
        assert!(resolve(&[], &work.path().join("missing"), None).is_err());
        Ok(())
    }

    #[test]
    fn app_bundles_start_their_executable_as_launch_services_does() -> Result<()> {
        let work = tempfile::tempdir()?;
        let app = work.path().join("Hello.app");
        let mut variables = plist::Dictionary::new();
        variables.insert("GREETING".into(), "hi".into());
        make(
            &app,
            info(&[
                ("CFBundleExecutable", "hello".into()),
                ("CFBundleIdentifier", "com.example.hello".into()),
                ("LSEnvironment", plist::Value::Dictionary(variables)),
            ]),
            &thin(CPU_TYPE_ARM64, 0),
        )?;
        let target = resolve(&[], &app, None)?;
        let executable = app.join("Contents/MacOS/hello");
        assert_eq!(target.program, executable);
        assert_eq!(target.argv0, executable.into_os_string());
        assert_eq!(
            target.environment,
            [
                ("GREETING".into(), "hi".into()),
                (
                    BUNDLE_IDENTIFIER_VARIABLE.into(),
                    "com.example.hello".into()
                )
            ]
        );
        let newer = work.path().join("Newer.app");
        make(
            &newer,
            info(&[
                ("CFBundleExecutable", "newer".into()),
                ("LSMinimumSystemVersion", "28.0".into()),
            ]),
            b"",
        )?;
        let message = resolve(&[], &newer, None).unwrap_err().to_string();
        assert!(message.contains("needs macOS 28.0"), "{message}");
        Ok(())
    }
}
