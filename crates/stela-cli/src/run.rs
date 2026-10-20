//! `stela run PROGRAM [ARGS...]` (and `stela PROGRAM [ARGS...]`): exec an
//! unchanged arm64e Mach-O as the arm64 kernel would, in this process, and
//! exit with its status. A `#!` script runs its interpreter as exec does,
//! and an app bundle its executable as LaunchServices starts it
//! (`run::program`). The guest's own `execve` comes back here, through
//! `--argv0`, in the same host process.
//!
//! The guest roots are `--root`, else `STELA_GUEST_ROOT`, else the guest
//! system `stela install-system` installed (`guest_system`).
//!
//! Exec's inputs are read here: the executable's arm64e slice (arm64 when
//! it has none), its load commands and code signature, and the dynamic
//! linker its `LC_LOAD_DYLINKER` names. Both paths, like every read-only
//! lookup the process makes, resolve under the guest roots first (see
//! `stela_runtime::hosted`); dyld finds and maps the shared cache there
//! itself. Everything after is the hosted runtime's.
#[cfg(test)]
#[path = "../tests/support/guest.rs"]
mod guest;
pub(crate) mod program;

use crate::guest_system;
use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use program::guest_path;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use stela_loader::{code_signature, load_plan, split_slices};
use stela_runtime::hosted::activation::{self, Activator};
use stela_runtime::hosted::hardware::{CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64};
use stela_runtime::hosted::{self, Dylinker, Launch, Signature};
use stela_runtime::machine::Chip;

/// The help heading of the developer options.
const ADVANCED: &str = "Advanced options";

#[derive(Args)]
pub(crate) struct Run {
    /// The program: an arm64 Mach-O, a #! script or an app bundle (.app),
    /// by path, or a name looked up in PATH.
    program: PathBuf,
    /// Its arguments.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<OsString>,
    /// A guest system root (repeatable, searched in order) instead of the
    /// installed system files: read-only lookups of absolute paths that
    /// exist under it resolve there.
    #[arg(long, help_heading = ADVANCED)]
    root: Vec<PathBuf>,
    /// The new image's argv[0], when it is not the program path (as
    /// `execve` passes it).
    #[arg(long, hide = true)]
    argv0: Option<OsString>,
    /// The arm64 slice exec chose by subtype (as `posix_spawn`'s binary
    /// preferences choose it), instead of the regular grading.
    #[arg(long, hide = true)]
    cpu_subtype: Option<u32>,
    /// Print every serviced call to standard error.
    #[arg(long, help_heading = ADVANCED)]
    trace: bool,
    /// Print the serviced-call counts when the program exits.
    #[arg(long, help_heading = ADVANCED)]
    statistics: bool,
}

/// The CPU subtype of a thin Mach-O slice, capability bits included.
fn cpu_subtype(slice: &[u8]) -> Result<u32> {
    let word = slice.get(8..12).context("the slice has no Mach header")?;
    Ok(u32::from_le_bytes(word.try_into()?))
}

/// The slice exec would choose on an arm64e machine: the one of
/// `subtype` when exec chose by subtype, else the regular grading.
fn select_slice(data: &[u8], subtype: Option<u32>) -> Result<(u64, &[u8])> {
    let slices = split_slices(data)?;
    let kind = |slice: &[u8]| -> Option<(u32, u32)> {
        let word = |at: usize| Some(u32::from_le_bytes(slice.get(at..at + 4)?.try_into().ok()?));
        Some((word(4)?, word(8)? & !CPU_SUBTYPE_MASK))
    };
    if let Some(subtype) = subtype {
        return slices
            .iter()
            .find(|(_, slice)| kind(slice) == Some((CPU_TYPE_ARM64, subtype & !CPU_SUBTYPE_MASK)))
            .copied()
            .with_context(|| format!("the file has no arm64 slice of subtype {subtype}"));
    }
    let arm64e = slices
        .iter()
        .find(|(_, slice)| kind(slice) == Some((CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)));
    let arm64 = slices
        .iter()
        .find(|(_, slice)| kind(slice).is_some_and(|(cpu, _)| cpu == CPU_TYPE_ARM64));
    arm64e
        .or(arm64)
        .copied()
        .context("the file has no arm64 slice")
}

fn image(path: &Path, slice_offset: u64, plan: &load_plan::LoadPlan) -> hosted::exec::Image {
    hosted::exec::Image {
        path: path.to_owned(),
        segments: plan
            .segments
            .iter()
            .map(|segment| hosted::exec::Segment {
                name: segment.name.clone(),
                address: segment.guest.address,
                bytes: segment.guest.bytes,
                file_offset: slice_offset + segment.file.offset,
                file_bytes: segment.file.bytes,
                initial: hosted::memory::Protection::from_mach_o(segment.initial_protection),
                maximum: hosted::memory::Protection::from_mach_o(segment.maximum_protection),
            })
            .collect(),
    }
}

/// The slice's code signature; `None` when it is unsigned.
fn signature(slice: &[u8]) -> Result<Option<Signature>> {
    let Some(signature) = code_signature::read(slice)? else {
        return Ok(None);
    };
    let blob = |magic: u32, body: Option<Vec<u8>>| {
        body.map(|body| {
            let mut blob = magic.to_be_bytes().to_vec();
            blob.extend((body.len() as u32 + 8).to_be_bytes());
            blob.extend(body);
            blob
        })
    };
    Ok(Some(Signature {
        directory_flags: signature.flags,
        platform: signature.platform,
        hash_type: signature.hash_type,
        cdhash: signature.cdhash,
        identifier: signature.identifier,
        team_identifier: signature.team_identifier,
        entitlements: blob(0xfade_7171, signature.entitlements),
        der_entitlements: blob(0xfade_7172, signature.der_entitlements),
        apple_signed: signature.apple_signed,
    }))
}

/// The image exec activates.
struct Activated {
    /// The host file holding it.
    file: PathBuf,
    /// The path exec reports (`executable_path=`).
    path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    data: Vec<u8>,
}

/// The image exec activates for `program` and its argv: the program
/// itself, or the interpreter its `#!` line names with the line's tokens,
/// the script path and the arguments after argv[0].
fn activate(roots: &[PathBuf], program: &Path, argv: Vec<Vec<u8>>) -> Result<Activated> {
    let file = guest_path(roots, program);
    let data = std::fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
    let head = &data[..data.len().min(hosted::memory::PAGE_BYTES as usize)];
    let activator = activation::activator(head);
    // A file that is no program at all is explained as such first.
    if activator.is_ok() {
        program::check_executable(program, &file)?;
    }
    let tokens = match activator {
        Ok(Activator::MachO) => {
            return Ok(Activated {
                file,
                path: program.as_os_str().as_bytes().to_vec(),
                argv,
                data,
            });
        }
        Ok(Activator::Interpreter(tokens)) => tokens,
        Err(errno) => return Err(program::not_runnable(program, &file, errno)),
    };
    let interpreter = PathBuf::from(OsStr::from_bytes(&tokens[0]));
    let mut interpreted = tokens;
    interpreted.push(program.as_os_str().as_bytes().to_vec());
    interpreted.extend(argv.into_iter().skip(1));
    let file = guest_path(roots, &interpreter);
    let data = std::fs::read(&file).with_context(|| {
        format!(
            "{}'s interpreter {} cannot be read",
            program.display(),
            interpreter.display()
        )
    })?;
    if data.starts_with(b"#!") {
        bail!(
            "{}: nested interpreters are not executed (ENOEXEC)",
            interpreter.display()
        );
    }
    Ok(Activated {
        file,
        path: interpreter.as_os_str().as_bytes().to_vec(),
        argv: interpreted,
        data,
    })
}

/// A run the hosted runtime could not continue, introduced for people: the
/// runtime's own text says which call it refused and why.
fn stopped(program: &Path, error: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "{0} stopped: it asked for something Stela's hosted macOS does not support yet.\n\n    \
         {error:#}\n\nStela refuses what it cannot do faithfully instead of guessing. `stela run \
         --trace {0}` shows the calls before it; the indented line is what to report.",
        program.display()
    )
}

impl Run {
    /// `stela PROGRAM [ARGS...]`: the program and its arguments, every
    /// option at its default.
    pub(crate) fn shorthand(words: Vec<OsString>) -> Result<Self> {
        let mut words = words.into_iter();
        let program = words.next().context("no program named")?;
        Ok(Self {
            program: program.into(),
            arguments: words.collect(),
            root: vec![],
            argv0: None,
            cpu_subtype: None,
            trace: false,
            statistics: false,
        })
    }

    /// The host command that activates another guest image here, with the
    /// roots this run chose.
    fn reexec(&self, roots: &[PathBuf]) -> Result<Vec<OsString>> {
        let mut command = vec![std::env::current_exe()?.into_os_string(), "run".into()];
        for root in roots {
            command.push("--root".into());
            command.push(root.clone().into_os_string());
        }
        if self.trace {
            command.push("--trace".into());
        }
        if self.statistics {
            command.push("--statistics".into());
        }
        Ok(command)
    }

    /// Whether exec could start `program` with the host's files alone:
    /// without guest system files, a program Stela could not run anyway
    /// is the better message.
    fn check_runnable(&self) -> Result<()> {
        let target = program::resolve(&[], &self.program, std::env::var_os("PATH").as_deref())?;
        let activated = activate(&[], &target.program, vec![])?;
        let (_, slice) = select_slice(&activated.data, self.cpu_subtype)?;
        if signature(slice)?.is_none() {
            return Err(program::unsigned(Path::new(OsStr::from_bytes(
                &activated.path,
            ))));
        }
        Ok(())
    }

    pub(crate) fn run(self) -> Result<()> {
        let roots = match guest_system::roots(&self.root) {
            Ok(roots) => roots,
            Err(missing) => {
                self.check_runnable()?;
                return Err(missing);
            }
        };
        // The guest's own `execve` (`--argv0`) names a path, as the kernel
        // takes it: relative to the working directory, never a PATH lookup
        // or a bundle.
        let target = match &self.argv0 {
            Some(_) => program::Target::path(&self.program),
            None => program::resolve(&roots, &self.program, std::env::var_os("PATH").as_deref())?,
        };
        let argv0 = self.argv0.clone().unwrap_or(target.argv0);
        let mut argv = vec![argv0.as_bytes().to_vec()];
        argv.extend(
            self.arguments
                .iter()
                .map(|argument| argument.as_bytes().to_vec()),
        );
        let Activated {
            file: program_file,
            path: program,
            argv,
            data,
        } = activate(&roots, &target.program, argv)?;
        let shown = Path::new(OsStr::from_bytes(&program));
        let (slice_offset, slice) = select_slice(&data, self.cpu_subtype)?;
        let plan = load_plan::plan(slice)?;
        let signature = signature(slice)?.ok_or_else(|| program::unsigned(shown))?;
        let dylinker_path = plan
            .dylinker
            .as_deref()
            .context("the executable names no LC_LOAD_DYLINKER")?;
        let dylinker_file = guest_path(&roots, Path::new(dylinker_path));
        let dylinker_data = std::fs::read(&dylinker_file)
            .with_context(|| format!("cannot read {}", dylinker_file.display()))?;
        let (dylinker_offset, dylinker_slice) = select_slice(&dylinker_data, None)?;
        let dylinker_plan = load_plan::plan_dynamic_linker(dylinker_slice)?;
        let environment: Vec<Vec<u8>> = std::env::vars_os()
            .filter(|(key, _)| !target.environment.iter().any(|(added, _)| added == key))
            .chain(target.environment.iter().cloned())
            .map(|(key, value)| {
                let mut entry = key.as_bytes().to_vec();
                entry.push(b'=');
                entry.extend(value.as_bytes());
                entry
            })
            .collect();
        let launch = Launch {
            chip: Chip::AppleM2,
            executable: image(&program_file, slice_offset, &plan),
            slice_offset,
            cpu_subtype: cpu_subtype(slice)?,
            executable_path: program.clone(),
            signature,
            dylinker: Dylinker {
                image: image(&dylinker_file, dylinker_offset, &dylinker_plan.image),
                entry: dylinker_plan.thread.pc,
            },
            kernel_versions: guest_system::kernel_versions(&roots)?,
            roots: roots.clone(),
            reexec: self.reexec(&roots)?,
            argv,
            environment,
            trace: self.trace,
        };
        let report = hosted::run(launch).map_err(|error| stopped(&target.program, error))?;
        if self.statistics {
            for (name, count) in &report.calls {
                eprintln!("stela: {count:>8} {name}");
            }
            eprintln!("stela: {:>8} shared-region pages slid", report.slid_pages);
        }
        report.termination.end_host_process()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shorthand_runs_the_program_with_every_option_at_its_default() -> Result<()> {
        let run = Run::shorthand(vec!["./hello".into(), "--help".into(), "x".into()])?;
        assert_eq!(run.program, Path::new("./hello"));
        assert_eq!(run.arguments, ["--help", "x"]);
        assert!(run.root.is_empty() && !run.trace && !run.statistics);
        assert!(Run::shorthand(vec![]).is_err());
        Ok(())
    }

    #[test]
    fn child_images_get_the_chosen_roots_explicitly() -> Result<()> {
        let run = Run::shorthand(vec!["hello".into()])?;
        let command = run.reexec(&[PathBuf::from("/guest")])?;
        assert_eq!(
            command[1..],
            ["run", "--root", "/guest"].map(OsString::from)
        );
        Ok(())
    }

    #[test]
    fn a_stopped_run_shows_the_refusal_and_how_to_trace_it() {
        let message = stopped(
            Path::new("./hello"),
            anyhow!("BSD system call frob (999) is not implemented by the hosted kernel"),
        )
        .to_string();
        assert!(
            message.contains("    BSD system call frob (999)"),
            "{message}"
        );
        assert!(message.contains("stela run --trace ./hello"), "{message}");
    }

    /// The exec security state of an image's arm64e slice: its security
    /// config and IPC space policy, or `None` when it is unsigned.
    fn security(data: &[u8]) -> Result<Option<(u32, u32)>> {
        let (_, slice) = select_slice(data, None)?;
        let jop = hosted::pe::UserJop::of_subtype(cpu_subtype(slice)?);
        let Some(signature) = signature(slice)? else {
            return Ok(None);
        };
        Ok(Some((
            signature.security_config(false)?,
            signature.ipc_space_policy(jop)?,
        )))
    }

    #[test]
    fn exec_security_follows_the_signature_and_entitlements_of_26a434_images() -> Result<()> {
        let Some(roots) = guest::guest_roots() else {
            eprintln!("skipped: no 26A434 guest roots (see tests/support/guest.rs)");
            return Ok(());
        };
        let root = &roots[0];
        // Platform binaries take restrictions version 3 and the platform
        // IPC policy; hardened processes their version and guard objects,
        // legacy names included; plugin hosts (library validation off, or
        // a hardening-exception identity) opt out of Mach hardening.
        for (path, config, policy) in [
            ("bin/ls", 0x18, 0x407),
            ("usr/bin/plutil", 0x2_0118, 0x407),
            ("usr/sbin/mDNSResponder", 0x2_0119, 0x407),
            ("usr/sbin/securityd", 0x58, 0x407),
            ("usr/sbin/coreaudiod", 0x1_0018, 0x487),
            // aa grants disable-library-validation as false.
            ("usr/bin/aa", 0x18, 0x407),
            ("bin/bash", 0x18, 0x487),
        ] {
            let data = std::fs::read(root.join(path))?;
            assert_eq!(security(&data)?, Some((config, policy)), "{path}");
        }
        Ok(())
    }

    #[test]
    fn exec_security_of_third_party_and_unsigned_images() -> Result<()> {
        let work = tempfile::tempdir()?;
        let source = work.path().join("main.c");
        std::fs::write(&source, "int main(void) { return 0; }\n")?;
        let build = |name: &str, flags: &[&str]| -> Option<PathBuf> {
            let output = work.path().join(name);
            std::process::Command::new("xcrun")
                .args(["clang", "-arch", "arm64e"])
                .args(flags)
                .arg(&source)
                .arg("-o")
                .arg(&output)
                .status()
                .ok()?
                .success()
                .then_some(output)
        };
        let Some(hardened) = build("hardened", &[]) else {
            eprintln!("skipped: xcrun clang cannot build arm64e programs here");
            return Ok(());
        };
        let signed = std::process::Command::new("codesign")
            .args(["--force", "--sign", "-", "--options", "runtime"])
            .arg(&hardened)
            .status()?;
        assert!(signed.success());
        // Hardened runtime alone: no restrictions version, the enhanced V0
        // IPC policy.
        assert_eq!(security(&std::fs::read(&hardened)?)?, Some((0, 0x103)));
        let unsigned = build("unsigned", &["-Wl,-no_adhoc_codesign"]).unwrap();
        assert_eq!(security(&std::fs::read(&unsigned)?)?, None);
        Ok(())
    }
}
