//! Repository development tasks: `cargo xtask <task>`.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

// The UEFI binary cannot run libtest. Exercise its platform-independent
// UART text and panic capture in the shared hosted gate instead.
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/bundle/source.rs"]
mod boot_bundle_source;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/entropy.rs"]
#[allow(dead_code)] // UEFI-only protocol selection is absent in this hosted harness.
mod boot_entropy;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/bundle/live_tree.rs"]
mod boot_live_tree;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/cpu/msr.rs"]
#[allow(dead_code)] // Hosted tests run only the CPUID gates; RDMSR/WRMSR need CPL0.
mod boot_msr;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/apic.rs"]
#[allow(dead_code)] // Only pure directed-INIT admission tests execute hosted.
mod boot_native_apic;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_smp/bootstrap/early.rs"]
#[allow(dead_code)] // Record/gate tests run hosted; actual assembly is inspected in UEFI.
mod boot_native_early;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_memory.rs"]
mod boot_native_memory;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/host/profile.rs"]
mod boot_native_profile;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_dma/requester.rs"]
#[allow(dead_code)]
mod boot_requester;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/topology.rs"]
#[allow(dead_code)] // Actual GS-owner constructor is UEFI-only.
mod boot_topology;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_dma/vtd.rs"]
#[allow(dead_code)]
mod boot_vtd;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/xstate.rs"]
#[allow(dead_code)] // Actual descriptor/IST capture and entry execute only in UEFI.
mod boot_xstate;

#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_irq/ioapic.rs"]
#[allow(dead_code)]
mod boot_ioapic;
#[cfg(all(test, feature = "fetched-sources"))]
#[path = "../../crates/stela-boot/src/native_irq/crs.rs"]
mod boot_irq_crs;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_irq/madt.rs"]
#[allow(dead_code)]
mod boot_madt;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_clock/pm.rs"]
#[allow(dead_code)] // Only pure FADT/counter tests run hosted; port I/O is UEFI-only.
mod boot_native_clock_pm;

mod agx_isa;
mod amx;
// The bench runs the hosted engine, which only an Intel Mac has
// (`stela_runtime::hosted`).
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod bench;
mod boot;
mod check;
mod darwin_catalogs;
mod dist;
mod gpu;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod hosted_platform;
mod links;
mod pages;
mod restore_dry_run;
mod tools;
mod xml;

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
    /// Build the release `stela` with its matching `stela.efi` embedded.
    Dist,
    /// Check the Markdown files' links and paths and the `cargo xtask` tasks
    /// the tree names.
    Links,
    /// Build, run and debug the UEFI mount in x86 QEMU.
    #[command(subcommand)]
    Boot(boot::Command),
    /// Build native GPU components and report their remaining platform imports.
    #[command(subcommand)]
    Gpu(gpu::Command),
    /// Time unchanged real-program functions in the process engines, against
    /// a baseline build (release builds only); `bench hosted` times
    /// same-source programs natively and as hosted processes.
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    Bench(bench::Bench),
    /// Compare Stela's AMX model with the corsix/amx emulator on QEMU.
    AmxReference(amx::AmxReference),
    /// Disassemble, size and time the native AMX kernels against the model.
    AmxKernels(amx::kernels::AmxKernels),
    /// Generate the BSD system-call and Mach-trap catalogs from xnu sources.
    DarwinCatalogs(darwin_catalogs::DarwinCatalogs),
    /// Generate the AGX2 shader ISA tables from Mesa's AGX2.xml.
    AgxIsa(agx_isa::AgxIsa),
    /// Drive the whole restore host against the real IPSW, natively, with
    /// every request restored can make, and check each answer.
    RestoreDryRun(restore_dry_run::RestoreDryRun),
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Check { fix } => check::run(fix).map(|()| ExitCode::SUCCESS),
        Task::Dist => dist::run().map(|()| ExitCode::SUCCESS),
        Task::Links => links::run().map(|()| ExitCode::SUCCESS),
        Task::Boot(command) => boot::run(command),
        Task::Gpu(command) => gpu::run(command).map(|()| ExitCode::SUCCESS),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        Task::Bench(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxReference(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxKernels(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::DarwinCatalogs(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AgxIsa(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::RestoreDryRun(task) => task.run(),
    };
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::FAILURE
    })
}
