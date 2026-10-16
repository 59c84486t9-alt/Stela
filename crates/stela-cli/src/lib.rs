//! The `stela` command line: compile, run and inspect original ARM code.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod args;
mod compile;
mod dyld_entry;
mod execute;
mod images;
mod input;
mod loader;
mod macho;
mod restore;

#[derive(Parser)]
#[command(
    name = "stela",
    version,
    about = "Native x86 macOS recompilation research tools"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Report detected x86 capabilities and the named SIMD output catalog.
    CpuInfo,
    /// AOT-compile a raw ARM64 leaf region with internal branches into x86.
    CompileLeaf(compile::CompileLeaf),
    /// Compile one native block with explicit guest-address exits.
    CompileBlock(compile::CompileBlock),
    /// Prepare a supported leaf function on demand; reuse an exact cached AOT.
    PrepareLeaf(compile::PrepareLeaf),
    /// Execute trusted raw code through bounded native block dispatch.
    RunBlocks(execute::RunBlocks),
    /// Map a trusted image's initial segments and probe its translated entry.
    RunMappedImage(execute::RunMappedImage),
    /// Bind explicit Apple images and probe cross-image native entry execution.
    RunLinkedImages(execute::RunLinkedImages),
    /// Probe a reviewed original-dyld startup prefix with owned arguments.
    ProbeDyldEntry(execute::ProbeDyldEntry),
    /// Validate an Apple executable's guest mappings and unresolved loader work.
    PlanExecutable(loader::PlanExecutable),
    /// Validate and plan supported chained rebases without mapping or execution.
    PlanFixups(loader::PlanFixups),
    /// Discover Apple image dependencies inside an explicit guest filesystem.
    DiscoverImages(loader::DiscoverImages),
    /// Inventory standalone Mach-O files in an extracted filesystem.
    Inventory(loader::Inventory),
    /// Track per-build translation stages and hashed evidence.
    #[command(subcommand)]
    Progress(loader::ProgressCommand),
    /// Discover and fetch restore images directly from Apple's public feed.
    #[command(subcommand)]
    Images(images::ImagesCommand),
    /// Inspect BuildManifest identities and model-specific component paths.
    ImageManifest(images::ImageManifest),
    /// Extract one named ZIP member with a size limit and hash receipt.
    ExtractImage(images::ExtractImage),
    /// Inspect bounded AEA1/profile-1 acquisition metadata, without key bodies.
    InspectAea(images::InspectAea),
    /// Fetch the public Apple FCS recipient key named by AEA1 metadata.
    FetchAeaKey(images::FetchAeaKey),
}

impl Command {
    fn run(self) -> anyhow::Result<()> {
        match self {
            Self::CpuInfo => compile::cpu_info(),
            Self::CompileLeaf(command) => command.run(),
            Self::CompileBlock(command) => command.run(),
            Self::PrepareLeaf(command) => command.run(),
            Self::RunBlocks(command) => command.run(),
            Self::RunMappedImage(command) => command.run(),
            Self::RunLinkedImages(command) => command.run(),
            Self::ProbeDyldEntry(command) => command.run(),
            Self::PlanExecutable(command) => command.run(),
            Self::PlanFixups(command) => command.run(),
            Self::DiscoverImages(command) => command.run(),
            Self::Inventory(command) => command.run(),
            Self::Progress(command) => command.run(),
            Self::Images(command) => command.run(),
            Self::ImageManifest(command) => command.run(),
            Self::ExtractImage(command) => command.run(),
            Self::InspectAea(command) => command.run(),
            Self::FetchAeaKey(command) => command.run(),
        }
    }
}

/// Parse the command line and run it, reporting errors on stderr.
pub fn main() -> ExitCode {
    match Cli::parse().command.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
