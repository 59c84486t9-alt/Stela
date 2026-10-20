//! The `stela` command line: run arm64 macOS programs and apps on an
//! Intel Mac, and compile, run and inspect original ARM code.
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::process::ExitCode;

mod apfs;
mod apps;
mod args;
mod boot;
mod boot_log;
mod bundle;
pub mod compile;
mod dyld_entry;
pub mod efi;
mod execute;
mod guest_system;
mod images;
mod input;
mod loader;
pub mod registry;
pub mod restore;
mod run;
mod setup;

/// The help's closing examples.
const EXAMPLES: &str = "Examples:
  stela install-system          Install the macOS 27 system files programs run against (once)
  stela ./hello                 Run an arm64 program or #! script
  stela /Applications/Foo.app   Run an app's arm64 executable
  stela apps                    Add launchers for arm64-only apps to ~/Applications/Stela

The research and development commands are described in docs/development.md.";

#[derive(Parser)]
#[command(
    name = "stela",
    version,
    about = "Run arm64 macOS programs and apps on an Intel Mac",
    override_usage = "stela PROGRAM [ARGS]...\n       stela <COMMAND>",
    after_help = EXAMPLES,
    allow_external_subcommands = true,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Run an arm64 program, #! script or app bundle (the same as `stela
    /// PROGRAM`).
    Run(run::Run),
    /// Install the macOS 27 system files arm64 programs run against, from
    /// its restore image (IPSW).
    InstallSystem(guest_system::InstallSystem),
    /// Make native launchers in ~/Applications/Stela for arm64-only apps, so
    /// they open from Finder, the Dock and Open With.
    Apps(apps::Apps),
    /// Prepare an OpenCore USB to install macOS 27 with Stela, or undo it.
    Setup(setup::Setup),
    /// Print the boot log stela.efi keeps on a machine-state partition, from a
    /// disk image or a raw partition.
    BootLog(boot_log::BootLog),
    /// A program to run: `stela PROGRAM [ARGS]...`.
    #[command(external_subcommand)]
    Program(Vec<OsString>),
    /// Report detected x86 capabilities and the named SIMD output catalog.
    #[command(hide = true)]
    CpuInfo,
    /// AOT-compile a raw ARM64 leaf region with internal branches into x86.
    #[command(hide = true)]
    CompileLeaf(compile::CompileLeaf),
    /// Compile one native block.
    #[command(hide = true)]
    CompileBlock(compile::CompileBlock),
    /// Prepare a supported leaf function on demand; reuse an exact cached AOT.
    #[command(hide = true)]
    PrepareLeaf(compile::PrepareLeaf),
    /// Run raw code through native block dispatch.
    #[command(hide = true)]
    RunBlocks(execute::RunBlocks),
    /// Map a trusted image's initial segments and probe its translated entry.
    #[command(hide = true)]
    RunMappedImage(execute::RunMappedImage),
    /// Bind a set of images and run from an entry point.
    #[command(hide = true)]
    RunLinkedImages(execute::RunLinkedImages),
    /// Run original dyld's startup prefix.
    #[command(hide = true)]
    ProbeDyldEntry(execute::ProbeDyldEntry),
    /// Validate an Apple executable's guest mappings and unresolved loader work.
    #[command(hide = true)]
    PlanExecutable(loader::PlanExecutable),
    /// Validate and plan supported chained rebases without mapping or execution.
    #[command(hide = true)]
    PlanFixups(loader::PlanFixups),
    /// Discover image dependencies inside a guest filesystem.
    #[command(hide = true)]
    DiscoverImages(loader::DiscoverImages),
    /// Inventory standalone Mach-O files in an extracted filesystem.
    #[command(hide = true)]
    Inventory(loader::Inventory),
    /// Track per-build translation progress.
    #[command(subcommand, hide = true)]
    Progress(loader::ProgressCommand),
    /// Discover and fetch restore images directly from Apple's public feed.
    #[command(subcommand, hide = true)]
    Images(images::ImagesCommand),
    /// Inspect BuildManifest identities and model-specific component paths.
    #[command(hide = true)]
    ImageManifest(images::ImageManifest),
    /// Extract one named ZIP member with a size limit and hash receipt.
    #[command(hide = true)]
    ExtractImage(images::ExtractImage),
    /// Decode a plaintext IM4P payload, such as a kernelcache or DeviceTree.
    #[command(hide = true)]
    DecodeIm4p(images::DecodeIm4p),
    /// Inspect AEA1 envelope metadata (never key material).
    #[command(hide = true)]
    InspectAea(images::InspectAea),
    /// Fetch the public Apple FCS recipient key named by AEA1 metadata.
    #[command(hide = true)]
    FetchAeaKey(images::FetchAeaKey),
    /// Decrypt an AEA1 archive, such as an IPSW disk image, with its fetched key.
    #[command(hide = true)]
    DecryptAea(images::DecryptAea),
    /// Copy selected guest files out of a decrypted disk image.
    #[command(hide = true)]
    ExtractGuestFiles(images::ExtractGuestFiles),
    /// Inspect APFS images with Stela's own reader.
    #[command(subcommand, hide = true)]
    Apfs(apfs::ApfsCommand),
    /// Prepare the kernel boot bundle that the UEFI mount loads.
    #[command(subcommand, hide = true)]
    Boot(boot::BootCommand),
    /// Write the install medium `stela setup --target` puts on the USB (the
    /// full IPSW in pieces, with its inventory) to a mounted FAT32 volume,
    /// such as a disk image for a QEMU run.
    #[command(hide = true)]
    InstallMedium(setup::InstallMedium),
    /// Add the UEFI mount to an OpenCore EFI folder, or remove it.
    #[command(subcommand, hide = true)]
    Efi(efi::EfiCommand),
}

impl Command {
    fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Run(command) => command.run(),
            Self::InstallSystem(command) => command.run(),
            Self::Apps(command) => command.run(),
            Self::Setup(command) => command.run(),
            Self::BootLog(command) => command.run(),
            Self::Program(words) => run::Run::shorthand(words)?.run(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(words: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("stela").chain(words.iter().copied()))
            .unwrap()
            .command
    }

    #[test]
    fn a_first_word_that_is_no_command_is_the_program_with_its_own_arguments() {
        let Command::Program(words) = parse(&["./hello", "--help", "-v"]) else {
            panic!("not a program");
        };
        assert_eq!(words, ["./hello", "--help", "-v"]);
        assert!(matches!(parse(&["run", "./hello"]), Command::Run(_)));
        assert!(matches!(parse(&["apps"]), Command::Apps(_)));
    }

    #[test]
    fn the_help_shows_the_simple_usage_and_hides_the_research_commands() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("stela PROGRAM [ARGS]..."), "{help}");
        assert!(help.contains("install-system") && help.contains("apps"));
        assert!(!help.contains("compile-block") && !help.contains("decrypt-aea"));
        Cli::command().debug_assert();
    }
}
