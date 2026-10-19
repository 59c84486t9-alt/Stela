//! `stela run PROGRAM [ARGS...]`: exec an unchanged arm64e Mach-O as the
//! arm64 kernel would, in this process, and exit with its status.
//!
//! Exec's inputs are read here: the executable's arm64e slice (arm64 when
//! it has none), its load commands and code signature, and the dynamic
//! linker its `LC_LOAD_DYLINKER` names. Both paths, like every read-only
//! lookup the process makes, resolve under the guest roots first (see
//! `stela_runtime::hosted`); dyld finds and maps the shared cache there
//! itself. Everything after is the hosted runtime's.
use anyhow::{Context, Result, bail};
use clap::Args;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use stela_loader::{code_signature, load_plan, split_slices};
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
    /// Print every serviced call to standard error.
    #[arg(long)]
    trace: bool,
    /// Print the serviced-call counts when the program exits.
    #[arg(long)]
    statistics: bool,
}

/// The slice exec would choose on an arm64e machine.
fn select_slice(data: &[u8]) -> Result<(u64, &[u8])> {
    let slices = split_slices(data)?;
    let kind = |slice: &[u8]| -> Option<(u32, u32)> {
        let word = |at: usize| Some(u32::from_le_bytes(slice.get(at..at + 4)?.try_into().ok()?));
        Some((word(4)?, word(8)? & !CPU_SUBTYPE_MASK))
    };
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

impl Run {
    pub(crate) fn run(self) -> Result<()> {
        let program_file = guest_path(&self.root, &self.program);
        let data = std::fs::read(&program_file)
            .with_context(|| format!("cannot read {}", program_file.display()))?;
        let (slice_offset, slice) = select_slice(&data)?;
        let plan = load_plan::plan(slice)?;
        let signature = signature(slice)?;
        let dylinker_path = plan
            .dylinker
            .as_deref()
            .context("the executable names no LC_LOAD_DYLINKER")?;
        let dylinker_file = guest_path(&self.root, Path::new(dylinker_path));
        let dylinker_data = std::fs::read(&dylinker_file)
            .with_context(|| format!("cannot read {}", dylinker_file.display()))?;
        let (dylinker_offset, dylinker_slice) = select_slice(&dylinker_data)?;
        let dylinker_plan = load_plan::plan_dynamic_linker(dylinker_slice)?;
        let program = self.program.as_os_str().as_bytes().to_vec();
        let mut argv = vec![program.clone()];
        argv.extend(
            self.arguments
                .iter()
                .map(|argument| argument.as_bytes().to_vec()),
        );
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
            executable_path: program,
            signature,
            dylinker: Dylinker {
                image: image(&dylinker_file, dylinker_offset, &dylinker_plan.image),
                entry: dylinker_plan.thread.pc,
            },
            roots: self.root.clone(),
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
