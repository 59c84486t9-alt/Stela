//! Repository development tasks: `cargo xtask <task>`.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod amx;
mod boot;
mod check;
mod dist;
mod gpu;
mod guest;
mod links;
mod oracles;
mod pages;
mod restore_dry_run;
mod sysregs;
mod tools;

#[derive(Parser)]
#[command(about = "Stela development tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Check formatting, run strict host and freestanding Clippy, then test.
    Check {
        /// Format sources before checking.
        #[arg(long)]
        fix: bool,
        /// Also build and check the complete NVIDIA/NVK UEFI image.
        #[arg(long)]
        nvk: bool,
        /// Run check lanes, build jobs, and tests one at a time.
        #[arg(long)]
        low_memory: bool,
    },
    /// Build the release `stela` with its matching `stela.efi` embedded.
    Dist {
        /// Include the NVIDIA/NVK rendering stack and guest components.
        #[arg(long)]
        nvk: bool,
    },
    /// Check the Markdown files' links and paths and the `cargo xtask` tasks
    /// the tree names.
    Links,
    /// Run ignored oracle tests whose declared inputs are present and write a dated report.
    Oracles(oracles::Oracles),
    /// Build, run and debug the UEFI mount in x86 QEMU.
    #[command(subcommand)]
    Boot(boot::Command),
    /// Build native GPU components and report their remaining platform imports.
    #[command(subcommand)]
    Gpu(gpu::Command),
    /// Build the ARM64e components Stela installs in macOS: the StelaGPU
    /// kext's objects, against `third_party/xnu`.
    Guest,
    /// Compare Stela's AMX model with the corsix/amx emulator on QEMU.
    AmxReference(amx::AmxReference),
    /// Disassemble, size and time the native AMX kernels against the model.
    AmxKernels(amx::kernels::AmxKernels),
    /// Drive the whole restore host against the real IPSW, natively, with
    /// every request restored can make, and check each answer.
    RestoreDryRun(restore_dry_run::RestoreDryRun),
    /// Generate the System register accessors from Arm's AARCHMRS.
    Sysregs(sysregs::Sysregs),
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Check {
            fix,
            nvk,
            low_memory,
        } => check::run(fix, nvk, low_memory).map(|()| ExitCode::SUCCESS),
        Task::Dist { nvk } => dist::run(nvk).map(|()| ExitCode::SUCCESS),
        Task::Links => links::run().map(|()| ExitCode::SUCCESS),
        Task::Oracles(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::Boot(command) => boot::run(command),
        Task::Gpu(command) => gpu::run(command).map(|()| ExitCode::SUCCESS),
        Task::Guest => guest::run().map(|()| ExitCode::SUCCESS),
        Task::AmxReference(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxKernels(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::RestoreDryRun(task) => task.run(),
        Task::Sysregs(task) => task.run().map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_process_tasks_are_unknown() {
        for task in ["bench", "census", "darwin-catalogs"] {
            let error = Cli::try_parse_from(["xtask", task, "--help"])
                .err()
                .unwrap();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{task}"
            );
        }
    }
}
