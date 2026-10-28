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
#[path = "../../crates/stela-boot/src/engine/console_lines.rs"]
mod boot_console;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_dma/dmar.rs"]
mod boot_dmar;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/entropy.rs"]
#[allow(dead_code)] // UEFI-only protocol selection is absent in this hosted harness.
mod boot_entropy;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/bundle/live_tree.rs"]
mod boot_live_tree;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/firmware/pe.rs"]
mod boot_loaded_image;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/apic.rs"]
#[allow(dead_code)] // Only pure directed-INIT admission tests execute hosted.
mod boot_native_apic;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_smp/canonical/bindings.rs"]
mod boot_native_bindings;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_smp/firmware/record.rs"]
mod boot_native_capture;
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
#[path = "../../crates/stela-boot/src/native_smp/topology.rs"]
#[allow(dead_code)] // Includes UEFI capability checks unused by hosted topology tests.
mod boot_native_topology;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/paging/controls.rs"]
mod boot_paging_controls;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/host/ram.rs"]
mod boot_ram;
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
#[cfg(test)]
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

mod amx;
// The bench runs the hosted engine, which only an Intel Mac has
// (`stela_runtime::hosted`).
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod bench;
mod boot;
mod census;
mod check;
mod darwin_catalogs;
mod gpu;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod hosted_platform;
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
    /// Check formatting, run strict hosted and freestanding Clippy, then test.
    Check {
        /// Format sources before checking.
        #[arg(long)]
        fix: bool,
    },
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
    /// Drive the whole restore host against the real IPSW, natively, with
    /// every request restored can make, and check each answer.
    RestoreDryRun(restore_dry_run::RestoreDryRun),
    /// Generate the System register accessors from Arm's AARCHMRS.
    Sysregs(sysregs::Sysregs),
    /// Generate the hosted call-site census from a macOS restore image.
    Census(census::Census),
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Check { fix } => check::run(fix).map(|()| ExitCode::SUCCESS),
        Task::Boot(command) => boot::run(command),
        Task::Gpu(command) => gpu::run(command).map(|()| ExitCode::SUCCESS),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        Task::Bench(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxReference(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxKernels(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::DarwinCatalogs(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::RestoreDryRun(task) => task.run(),
        Task::Sysregs(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::Census(task) => task.run().map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::FAILURE
    })
}
