//! The `stela` command line: prepare a USB that boots Stela to install macOS
//! on a PC, compile, run and inspect original ARM code, and, on an Intel Mac,
//! run arm64 macOS programs and apps.
use clap::{Parser, Subcommand};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use std::ffi::OsString;
use std::process::ExitCode;

mod apfs;
// Running arm64 programs needs the hosted runtime, which only an Intel Mac
// has (`stela_runtime::hosted`).
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod apps;
mod args;
mod boot;
mod boot_log;
#[cfg(any(test, all(target_os = "macos", target_arch = "x86_64")))]
mod bundle;
pub mod compile;
mod dyld_entry;
pub mod efi;
mod execute;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod guest_system;
mod images;
mod input;
mod loader;
mod progress;
pub mod restore;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod run;
mod setup;

/// The help's closing examples.
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const EXAMPLES: &str = "Examples:
  stela install-system          Install the macOS 27 system files programs run against (once)
  stela ./hello                 Run an arm64 program or #! script
  stela /Applications/Foo.app   Run an app's arm64 executable
  stela apps                    Add launchers for arm64-only apps to ~/Applications/Stela

The research and development commands are described in docs/development.md.";
#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
const EXAMPLES: &str = "Examples:
  stela setup --usb DIR --fetch Prepare a USB that boots Stela to install macOS 27

Running arm64 programs and apps needs an Intel Mac. The research and
development commands are described in docs/development.md.";

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const ABOUT: &str = "Run arm64 macOS programs and apps on an Intel Mac";
#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
const ABOUT: &str = "Prepare a USB that boots Stela to install macOS on a PC";

#[derive(Parser)]
#[cfg_attr(
    all(target_os = "macos", target_arch = "x86_64"),
    command(
        override_usage = "stela PROGRAM [ARGS]...\n       stela <COMMAND>",
        allow_external_subcommands = true
    )
)]
#[command(
    name = "stela",
    version,
    about = ABOUT,
    after_help = EXAMPLES,
    arg_required_else_help = true
)]
#[cfg_attr(windows, allow(dead_code))]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[cfg_attr(windows, allow(dead_code))]
pub(crate) enum Command {
    /// Run an arm64 program, #! script or app bundle (the same as `stela
    /// PROGRAM`).
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    Run(run::Run),
    /// Install the macOS 27 system files arm64 programs run against, from
    /// its restore image (IPSW).
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    InstallSystem(guest_system::InstallSystem),
    /// Make native launchers in ~/Applications/Stela for arm64-only apps, so
    /// they open from Finder, the Dock and Open With.
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    Apps(apps::Apps),
    /// Create a macOS installer USB interactively, or manage an existing USB.
    Setup(Box<setup::Setup>),
    /// Print the boot log stela.efi keeps on a machine-state partition, from a
    /// disk image or a raw partition.
    BootLog(boot_log::BootLog),
    /// A program to run: `stela PROGRAM [ARGS]...`.
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    #[command(external_subcommand)]
    Program(Vec<OsString>),
    /// The per-user service launchd starts: launchers, translations ahead
    /// of time and unsupported-operation notifications.
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    #[command(hide = true)]
    Stelad(apps::Stelad),
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
    /// Make stela.efi an EFI partition's boot loader, or remove it.
    #[command(subcommand, hide = true)]
    Efi(efi::EfiCommand),
}

// Windows ships only the installer; the commands stay for other hosts and tests.
#[cfg_attr(windows, allow(dead_code))]
impl Command {
    fn run(self) -> anyhow::Result<()> {
        match self {
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            Self::Run(command) => command.run(),
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            Self::InstallSystem(command) => command.run(),
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            Self::Apps(command) => command.run(),
            Self::Setup(command) => command.run(),
            Self::BootLog(command) => command.run(),
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            Self::Program(words) => run::Run::shorthand(words)?.run(),
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            Self::Stelad(command) => command.run(),
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

/// Parse the command line and run it, reporting errors on stderr.
pub fn main() -> ExitCode {
    #[cfg(windows)]
    let result = installer();
    #[cfg(not(windows))]
    let result = commands();
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{} {error:#}",
                console::style("error:").for_stderr().red().bold()
            );
            ExitCode::FAILURE
        }
    };
    setup::hold_window(code == ExitCode::SUCCESS);
    code
}

#[cfg(not(windows))]
fn commands() -> anyhow::Result<()> {
    Cli::parse().command.run()
}

/// `stela.exe` is the installer alone: running it opens the setup wizard, and
/// its arguments are setup's own flags. The research commands and running
/// arm64 programs belong to other hosts.
#[cfg(windows)]
#[derive(Parser)]
#[command(name = "stela", version, about = ABOUT)]
struct Installer {
    #[command(flatten)]
    setup: setup::Setup,
}

#[cfg(windows)]
fn installer() -> anyhow::Result<()> {
    Installer::parse().setup.run()
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
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    fn a_first_word_that_is_no_command_is_the_program_with_its_own_arguments() {
        let Command::Program(words) = parse(&["./hello", "--help", "-v"]) else {
            panic!("not a program");
        };
        assert_eq!(words, ["./hello", "--help", "-v"]);
        assert!(matches!(parse(&["run", "./hello"]), Command::Run(_)));
        assert!(matches!(parse(&["apps"]), Command::Apps(_)));
        assert!(matches!(parse(&["stelad"]), Command::Stelad(_)));
    }

    #[test]
    #[cfg(windows)]
    fn the_windows_executable_is_the_installer_alone() {
        // No arguments opens the wizard; setup's own flags stay scriptable.
        Installer::command()
            .try_get_matches_from(["stela"])
            .unwrap();
        let scripted = Installer::command()
            .try_get_matches_from(["stela", "--ipsw", "a.ipsw", "--profile"])
            .unwrap();
        assert!(scripted.get_flag("profile") && scripted.contains_id("ipsw"));
        assert!(Installer::try_parse_from(["stela", "setup"]).is_err());
        assert!(Installer::try_parse_from(["stela", "boot-log"]).is_err());
        let help = Installer::command().render_help().to_string();
        assert!(!help.contains("Commands:"), "{help}");
        Installer::command().debug_assert();
    }

    #[test]
    fn the_help_shows_the_simple_usage_and_hides_the_research_commands() {
        let help = Cli::command().render_help().to_string();
        if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            assert!(help.contains("stela PROGRAM [ARGS]..."), "{help}");
            assert!(help.contains("install-system") && help.contains("apps"));
        } else {
            assert!(
                help.contains("setup") && !help.contains("install-system"),
                "{help}"
            );
        }
        assert!(!help.contains("compile-block") && !help.contains("decrypt-aea"));
        assert!(!help.contains("stelad"));
        Cli::command().debug_assert();
    }

    #[test]
    fn portable_commands_dispatch_without_a_hosted_runtime() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let app = directory.path().join("Test.app");
        bundle::tests::make(&app, bundle::tests::info(&[]), &[])?;
        assert_eq!(
            bundle::AppBundle::open(&app)?.info_path(),
            app.join("Contents/Info.plist")
        );
        let missing = directory.path().join("missing.img");
        let error = parse(&["boot-log", missing.to_str().unwrap()])
            .run()
            .unwrap_err();
        assert!(error.to_string().contains("cannot open"), "{error:#}");
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(matches!(
            parse(&["setup", "--usb", missing.to_str().unwrap(), "--dry-run"]),
            Command::Setup(_)
        ));
        Ok(())
    }

    #[test]
    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    fn hosted_commands_reject_the_platform_before_accessing_inputs() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing");
        let missing = missing.to_str().unwrap();
        for words in [
            vec![
                "run",
                "--root",
                missing,
                "--fp-profile-output",
                missing,
                missing,
            ],
            vec![missing, "--help"],
            vec!["apps", "--scan", missing, "--add", missing, "--no-register"],
            vec!["apps", "--uninstall"],
            vec!["apps", "--model", "unknown"],
            vec!["stelad"],
            vec!["install-system", "--import", missing],
            vec!["install-system", "--remove"],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("stela").chain(words.iter().copied())).is_err(),
                "{words:?}"
            );
        }
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn setup_without_a_usb_enters_the_wizard_and_preserves_test_options() {
        assert!(matches!(parse(&["setup"]), Command::Setup(_)));
        assert!(matches!(
            parse(&["setup", "--ipsw", "local.ipsw", "--profile"]),
            Command::Setup(_)
        ));
    }
}
