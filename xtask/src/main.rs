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
#[path = "../../crates/stela-boot/src/native_smp/canonical/bindings.rs"]
mod boot_native_bindings;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_memory.rs"]
mod boot_native_memory;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/engine/host/ram.rs"]
mod boot_ram;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_dma/requester.rs"]
#[allow(dead_code)]
mod boot_requester;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_dma/vtd.rs"]
#[allow(dead_code)]
mod boot_vtd;

#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_irq/ioapic.rs"]
#[allow(dead_code)]
mod boot_ioapic;
#[cfg(test)]
#[path = "../../crates/stela-boot/src/native_irq/madt.rs"]
#[allow(dead_code)]
mod boot_madt;

mod agx_isa;
mod agx_observe;
mod amx;
mod bench;
mod boot;
mod check;
mod darwin_catalogs;
mod differential;
mod dit;
mod floor_audit;
mod gpu;
mod hosted_matrix;
mod oracle;
mod progress;
mod restore_dry_run;
mod soc_facts;
mod system_matrix;
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
    /// Build, run and debug the UEFI mount in x86 QEMU.
    #[command(subcommand)]
    Boot(boot::Command),
    /// Build native GPU components and report their remaining platform imports.
    #[command(subcommand)]
    Gpu(gpu::Command),
    /// Compare native translations with the QEMU original, form by form.
    Differential(differential::Differential),
    /// Time unchanged real-program functions in the process engines, against
    /// a baseline build (release builds only); `bench hosted` times
    /// same-source programs natively and as hosted processes.
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
    /// Generate the AGX2 shader ISA tables from Mesa's AGX2.xml.
    AgxIsa(agx_isa::AgxIsa),
    /// Consolidate a boot run's `--agx-observe` log into a per-command-type
    /// field-confirmation report.
    AgxObserve(agx_observe::AgxObserve),
    /// Audit the native code of Arm's data-independent-time instructions
    /// against Intel's data operand independent timing list.
    DitAudit(dit::DitAudit),
    /// Check that code compiled for the x86-64-v2 host floor uses only v2
    /// instructions and compiles wherever a larger tier does.
    FloorAudit(floor_audit::FloorAudit),
    /// Drive the whole restore host against the real IPSW, natively, with
    /// every request restored can make, and check each answer.
    RestoreDryRun(restore_dry_run::RestoreDryRun),
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
        Task::Gpu(command) => gpu::run(command).map(|()| ExitCode::SUCCESS),
        Task::Differential(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::Bench(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxReference(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AmxKernels(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::SystemMatrix(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::DarwinCatalogs(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::SocFacts(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AgxIsa(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::AgxObserve(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::DitAudit(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::FloorAudit(task) => task.run().map(|()| ExitCode::SUCCESS),
        Task::RestoreDryRun(task) => task.run(),
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
