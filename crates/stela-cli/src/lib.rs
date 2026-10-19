//! The `stela` command line: compile, run and inspect original ARM code.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod apfs;
mod args;
mod boot;
pub mod compile;
mod dyld_entry;
pub mod efi;
mod execute;
mod images;
mod input;
mod loader;
pub mod registry;
pub mod restore;
mod run;
mod setup;

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
    /// Compile one native block.
    CompileBlock(compile::CompileBlock),
    /// Prepare a supported leaf function on demand; reuse an exact cached AOT.
    PrepareLeaf(compile::PrepareLeaf),
    /// Run raw code through native block dispatch.
    RunBlocks(execute::RunBlocks),
    /// Map a trusted image's initial segments and probe its translated entry.
    RunMappedImage(execute::RunMappedImage),
    /// Bind a set of images and run from an entry point.
    RunLinkedImages(execute::RunLinkedImages),
    /// Run original dyld's startup prefix.
    ProbeDyldEntry(execute::ProbeDyldEntry),
    /// Run an unchanged arm64e program as a hosted Darwin process.
    Run(run::Run),
    /// Validate an Apple executable's guest mappings and unresolved loader work.
    PlanExecutable(loader::PlanExecutable),
    /// Validate and plan supported chained rebases without mapping or execution.
    PlanFixups(loader::PlanFixups),
    /// Discover image dependencies inside a guest filesystem.
    DiscoverImages(loader::DiscoverImages),
    /// Inventory standalone Mach-O files in an extracted filesystem.
    Inventory(loader::Inventory),
    /// Track per-build translation progress.
    #[command(subcommand)]
    Progress(loader::ProgressCommand),
    /// Discover and fetch restore images directly from Apple's public feed.
    #[command(subcommand)]
    Images(images::ImagesCommand),
    /// Inspect BuildManifest identities and model-specific component paths.
    ImageManifest(images::ImageManifest),
    /// Extract one named ZIP member with a size limit and hash receipt.
    ExtractImage(images::ExtractImage),
    /// Decode a plaintext IM4P payload, such as a kernelcache or DeviceTree.
    DecodeIm4p(images::DecodeIm4p),
    /// Inspect AEA1 envelope metadata (never key material).
    InspectAea(images::InspectAea),
    /// Fetch the public Apple FCS recipient key named by AEA1 metadata.
    FetchAeaKey(images::FetchAeaKey),
    /// Decrypt an AEA1 archive, such as an IPSW disk image, with its fetched key.
    DecryptAea(images::DecryptAea),
    /// Copy selected guest files out of a decrypted disk image.
    ExtractGuestFiles(images::ExtractGuestFiles),
    /// Inspect APFS images with Stela's own reader.
    #[command(subcommand)]
    Apfs(apfs::ApfsCommand),
    /// Prepare the kernel boot bundle that the UEFI mount loads.
    #[command(subcommand)]
    Boot(boot::BootCommand),
    /// Prepare an OpenCore USB to install macOS 27 with Stela, or undo it.
    Setup(setup::Setup),
    /// Add the UEFI mount to an OpenCore EFI folder, or remove it.
    #[command(subcommand)]
    Efi(efi::EfiCommand),
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
            Self::Run(command) => command.run(),
            Self::PlanExecutable(command) => command.run(),
            Self::PlanFixups(command) => command.run(),
            Self::DiscoverImages(command) => command.run(),
            Self::Inventory(command) => command.run(),
            Self::Progress(command) => command.run(),
            Self::Images(command) => command.run(),
            Self::ImageManifest(command) => command.run(),
            Self::ExtractImage(command) => command.run(),
            Self::DecodeIm4p(command) => command.run(),
            Self::InspectAea(command) => command.run(),
            Self::FetchAeaKey(command) => command.run(),
            Self::DecryptAea(command) => command.run(),
            Self::ExtractGuestFiles(command) => command.run(),
            Self::Apfs(command) => command.run(),
            Self::Boot(command) => command.run(),
            Self::Setup(command) => command.run(),
            Self::Efi(command) => command.run(),
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
