//! `stela run PROGRAM [ARGS...]`: exec an unchanged arm64e Mach-O as the
//! arm64 kernel would, in this process, and exit with its status. A `#!`
//! script runs its interpreter as exec does. The guest's own `execve`
//! comes back here, through `--argv0`, in the same host process.
//!
//! Exec's inputs are read here: the executable's arm64e slice (arm64 when
//! it has none), its load commands and code signature, and the dynamic
//! linker its `LC_LOAD_DYLINKER` names. Both paths, like every read-only
//! lookup the process makes, resolve under the guest roots first (see
//! `stela_runtime::hosted`); dyld finds and maps the shared cache there
//! itself. Everything after is the hosted runtime's.
use anyhow::{Context, Result, bail};
use clap::Args;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use stela_loader::{code_signature, load_plan, split_slices};
use stela_runtime::hosted::activation::{self, Activator};
use stela_runtime::hosted::{self, Dylinker, Launch, Signature, Termination};
use stela_runtime::machine::Chip;

/// `CPU_TYPE_ARM64` and the arm64e subtype, without capability bits.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;

#[derive(Args)]
pub(crate) struct Run {
    /// The arm64e executable.
    program: PathBuf,
    /// Its arguments after argv[0].
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<OsString>,
    /// A guest system root (repeatable, searched in order): read-only
    /// lookups of absolute paths that exist under it resolve there.
    #[arg(long)]
    root: Vec<PathBuf>,
    /// The new image's argv[0], when it is not the program path (as
    /// `execve` passes it).
    #[arg(long)]
    argv0: Option<OsString>,
    /// The arm64 slice exec chose by subtype (as `posix_spawn`'s binary
    /// preferences choose it), instead of the regular grading.
    #[arg(long)]
    cpu_subtype: Option<u32>,
    /// Print every serviced call to standard error.
    #[arg(long)]
    trace: bool,
    /// Print the serviced-call counts when the program exits.
    #[arg(long)]
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

fn signature(slice: &[u8]) -> Result<Signature> {
    let Some(signature) = code_signature::read(slice)? else {
        bail!("the executable is unsigned: arm64 exec admits only signed images");
    };
    let blob = |magic: u32, body: Option<Vec<u8>>| {
        body.map(|body| {
            let mut blob = magic.to_be_bytes().to_vec();
            blob.extend((body.len() as u32 + 8).to_be_bytes());
            blob.extend(body);
            blob
        })
    };
    Ok(Signature {
        directory_flags: signature.flags,
        platform: signature.platform,
        hash_type: signature.hash_type,
        cdhash: signature.cdhash,
        identifier: signature.identifier,
        team_identifier: signature.team_identifier,
        entitlements: blob(0xfade_7171, signature.entitlements),
        der_entitlements: blob(0xfade_7172, signature.der_entitlements),
        apple_signed: signature.apple_signed,
    })
}

/// `path` under the first root holding it, else the host's own.
fn guest_path(roots: &[PathBuf], path: &Path) -> PathBuf {
    match path.strip_prefix("/") {
        Ok(relative) => roots
            .iter()
            .map(|root| root.join(relative))
            .find(|candidate| candidate.exists())
            .unwrap_or_else(|| path.to_owned()),
        Err(_) => path.to_owned(),
    }
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
    let tokens = match activation::activator(head) {
        Ok(Activator::MachO) => {
            return Ok(Activated {
                file,
                path: program.as_os_str().as_bytes().to_vec(),
                argv,
                data,
            });
        }
        Ok(Activator::Interpreter(tokens)) => tokens,
        Err(errno) => bail!("{} cannot be executed: errno {errno}", program.display()),
    };
    let interpreter = PathBuf::from(OsStr::from_bytes(&tokens[0]));
    let mut interpreted = tokens;
    interpreted.push(program.as_os_str().as_bytes().to_vec());
    interpreted.extend(argv.into_iter().skip(1));
    let file = guest_path(roots, &interpreter);
    let data = std::fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
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

impl Run {
    /// The host command that activates another guest image here.
    fn reexec(&self) -> Result<Vec<OsString>> {
        let mut command = vec![std::env::current_exe()?.into_os_string(), "run".into()];
        for root in &self.root {
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

    pub(crate) fn run(self) -> Result<()> {
        let argv0 = self
            .argv0
            .clone()
            .unwrap_or_else(|| self.program.clone().into_os_string());
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
        } = activate(&self.root, &self.program, argv)?;
        let (slice_offset, slice) = select_slice(&data, self.cpu_subtype)?;
        let plan = load_plan::plan(slice)?;
        let signature = signature(slice)?;
        let dylinker_path = plan
            .dylinker
            .as_deref()
            .context("the executable names no LC_LOAD_DYLINKER")?;
        let dylinker_file = guest_path(&self.root, Path::new(dylinker_path));
        let dylinker_data = std::fs::read(&dylinker_file)
            .with_context(|| format!("cannot read {}", dylinker_file.display()))?;
        let (dylinker_offset, dylinker_slice) = select_slice(&dylinker_data, None)?;
        let dylinker_plan = load_plan::plan_dynamic_linker(dylinker_slice)?;
        let environment = std::env::vars_os()
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
            executable_path: program,
            signature,
            dylinker: Dylinker {
                image: image(&dylinker_file, dylinker_offset, &dylinker_plan.image),
                entry: dylinker_plan.thread.pc,
            },
            roots: self.root.clone(),
            reexec: self.reexec()?,
            argv,
            environment,
            trace: self.trace,
        };
        let report = hosted::run(launch)?;
        if self.statistics {
            for (name, count) in &report.calls {
                eprintln!("stela: {count:>8} {name}");
            }
            eprintln!("stela: {:>8} shared-region pages slid", report.slid_pages);
        }
        let Termination::Exited(status) = report.termination;
        std::process::exit(status & 0xff)
    }
}
