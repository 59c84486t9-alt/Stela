//! Development commands for translating code, inspecting images, probing
//! execution, and preparing boot and installation media.
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use stela_cli::{apfs, boot, efi, restore};

mod args;
mod compile;
mod dyld_entry;
mod execute;
mod images;
mod input;
mod loader;

#[derive(Parser)]
#[command(
    name = "stela-dev",
    version,
    about = "Stela's research and development commands",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report detected x86 capabilities and the named SIMD output catalog.
    CpuInfo,
    /// AOT-compile a raw ARM64 leaf region with internal branches into x86.
    CompileLeaf(compile::CompileLeaf),
    /// Compile one native block.
    CompileBlock(compile::CompileBlock),
    /// Prepare a leaf function, reusing a matching cached translation.
    PrepareLeaf(compile::PrepareLeaf),
    /// Run raw code through native block dispatch.
    RunBlocks(execute::RunBlocks),
    /// Map a trusted image's initial segments and probe its translated entry.
    RunMappedImage(execute::RunMappedImage),
    /// Bind a set of images and run from an entry point.
    RunLinkedImages(execute::RunLinkedImages),
    /// Run original dyld's startup prefix.
    ProbeDyldEntry(execute::ProbeDyldEntry),
    /// Validate an Apple executable's guest mappings and unresolved loader work.
    PlanExecutable(loader::PlanExecutable),
    /// Validate and plan supported chained rebases without mapping or execution.
    PlanFixups(loader::PlanFixups),
    /// Discover image dependencies inside a guest filesystem.
    DiscoverImages(loader::DiscoverImages),
    /// Discover and fetch restore images directly from Apple's public feed.
    #[command(subcommand)]
    Images(images::ImagesCommand),
    /// Inspect BuildManifest identities and model-specific component paths.
    ImageManifest(images::ImageManifest),
    /// Extract one named ZIP member with a size limit and hash receipt.
    ExtractImage(images::ExtractImage),
    /// Decode a plaintext IM4P payload, such as a kernelcache or DeviceTree.
    DecodeIm4p(images::DecodeIm4p),
    /// Inspect AEA1 envelope metadata.
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
    /// Write the install medium `stela setup --target` puts on the USB (the
    /// full IPSW in pieces, with its inventory) to a mounted FAT32 volume,
    /// such as a disk image for a QEMU run.
    InstallMedium(stela_cli::InstallMedium),
    /// Make stela.efi an EFI partition's boot loader, or remove it.
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
            Self::PlanExecutable(command) => command.run(),
            Self::PlanFixups(command) => command.run(),
            Self::DiscoverImages(command) => command.run(),
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
            Self::InstallMedium(command) => command.run(),
            Self::Efi(command) => command.run(),
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn every_development_command_parses() {
        Cli::command().debug_assert();
        let help = Cli::command().render_help().to_string();
        for command in [
            "compile-block",
            "decrypt-aea",
            "boot",
            "efi",
            "install-medium",
        ] {
            assert!(help.contains(command), "{command}: {help}");
        }
    }
}
