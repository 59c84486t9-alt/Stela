//! Repository development tasks: `cargo xtask <task>`.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

// The UEFI binary cannot run libtest. Exercise its platform-independent
// UART text and panic capture in the shared host test gate instead.
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/bundle/source.rs"]
mod boot_bundle_source;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/bundle/live_tree.rs"]
mod boot_live_tree;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/cpu/msr.rs"]
#[allow(
    dead_code,
    reason = "host tests exercise CPUID gates; RDMSR and WRMSR require CPL0"
)]
mod boot_msr;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/apic.rs"]
#[allow(
    dead_code,
    reason = "host tests exercise admission; APIC delivery requires CPL0"
)]
mod boot_native_apic;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_memory.rs"]
mod boot_native_memory;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/host/profile.rs"]
mod boot_native_profile;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/topology.rs"]
#[allow(dead_code, reason = "the GS worker constructor runs only in UEFI")]
mod boot_topology;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/xstate.rs"]
#[allow(
    dead_code,
    reason = "descriptor and interrupt-stack capture runs only in UEFI"
)]
mod boot_xstate;

#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_irq/ioapic.rs"]
#[allow(
    dead_code,
    reason = "host tests exercise route planning; IOAPIC programming requires CPL0"
)]
mod boot_ioapic;
#[cfg(all(test, feature = "fetched-sources"))]
#[path = "../../crates/stela-boot/src/native_irq/crs.rs"]
mod boot_irq_crs;

mod amx;
mod boot;
mod check;
mod dist;
mod gpu;
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
    },
    /// Build the release `stela` with its matching `stela.efi` embedded.
    Dist,
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
        Task::Check { fix } => check::run(fix).map(|()| ExitCode::SUCCESS),
        Task::Dist => dist::run().map(|()| ExitCode::SUCCESS),
        Task::Links => links::run().map(|()| ExitCode::SUCCESS),
        Task::Oracles(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::Boot(command) => boot::run(command),
        Task::Gpu(command) => gpu::run(command).map(|()| ExitCode::SUCCESS),
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
