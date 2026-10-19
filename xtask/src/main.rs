//! Repository development tasks: `cargo xtask <task>`.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod amx;
mod bench;
mod boot;
mod check;
mod darwin_catalogs;
mod differential;
mod dit;
mod hosted_matrix;
mod oracle;
mod progress;
mod soc_facts;
mod system_matrix;
mod tools;

#[derive(Parser)]
#[command(about = "Stela development tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Check formatting, run strict hosted and freestanding Clippy, then test.
    Check {
        /// Format sources before checking.
        #[arg(long)]
        fix: bool,
    },
    /// Build, run and debug the UEFI mount in x86 QEMU.
    #[command(subcommand)]
    Boot(boot::Command),
    /// Compare native translations with the QEMU original, form by form.
    Differential(differential::Differential),
    /// Time unchanged real-program functions in the process engines, against
    /// a baseline build (release builds only).
    Bench(bench::Bench),
    /// Compare Stela's AMX model with the corsix/amx emulator on QEMU.
    AmxReference(amx::AmxReference),
    /// Disassemble, size and time the native AMX kernels against the model.
    AmxKernels(amx::kernels::AmxKernels),
    /// Derive the system platform requirement matrix from the pinned AARCHMRS.
    SystemMatrix(system_matrix::SystemMatrix),
    /// Generate the BSD system-call and Mach-trap catalogs from xnu sources.
    DarwinCatalogs(darwin_catalogs::DarwinCatalogs),
    /// Derive the per-SoC facts of a universal macOS IPSW's SPTM, TXM,
    /// kernelcache and DeviceTree builds.
    SocFacts(soc_facts::SocFacts),
    /// Audit the native code of Arm's data-independent-time instructions
    /// against Intel's data operand independent timing list.
    DitAudit(dit::DitAudit),
    /// Merge the instruction and system registries into their matrices and
    /// the README.
    Progress {
        /// Fail instead of writing when either file is stale.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Check { fix } => check::run(fix).map(|()| ExitCode::SUCCESS),
        Task::Boot(command) => boot::run(command),
        Task::Differential(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::Bench(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxReference(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxKernels(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::SystemMatrix(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::DarwinCatalogs(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::SocFacts(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::DitAudit(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::Progress { check } => progress::run(check)
            .and_then(|()| system_matrix::assess::run(check))
            .and_then(|()| hosted_matrix::run(check))
            .map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::FAILURE
    })
}
