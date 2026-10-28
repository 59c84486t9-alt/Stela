//! The `stela` command line: prepare a USB that boots Stela to install macOS
//! on a PC and, on an Intel Mac, run arm64 macOS programs and apps. The
//! research and development commands are `stela-dev`'s (crates/stela-dev),
//! which uses this library's boot-bundle, loader, restore-image and APFS
//! modules.
use clap::{Parser, Subcommand};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use std::ffi::OsString;
use std::process::ExitCode;

pub mod apfs;
// Running arm64 programs needs the hosted runtime, which only an Intel Mac
// has (`stela_runtime::hosted`).
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod apps;
pub mod args;
pub mod boot;
mod boot_log;
#[cfg(any(test, all(target_os = "macos", target_arch = "x86_64")))]
mod bundle;
pub mod efi;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod guest_system;
mod progress;
pub mod restore;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod run;
mod setup;

pub use setup::InstallMedium;

/// The help's closing examples.
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const EXAMPLES: &str = "Examples:
  stela install-system          Install the macOS 27 system files programs run against (once)
  stela ./hello                 Run an arm64 program or #! script
  stela /Applications/Foo.app   Run an app's arm64 executable
  stela apps                    Add launchers for arm64-only apps to ~/Applications/Stela

The research and development commands are stela-dev's (docs/development.md).";
#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
const EXAMPLES: &str = "Examples:
  stela setup --usb DIR --fetch Prepare a USB that boots Stela to install macOS 27

Running arm64 programs and apps needs an Intel Mac. The research and
development commands are stela-dev's (docs/development.md).";

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
    fn the_help_shows_the_simple_usage_and_the_research_commands_are_absent() {
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
        assert!(!help.contains("compile-block") && !help.contains("stelad"));
        for command in ["compile-block", "boot", "efi", "install-medium", "cpu-info"] {
            assert!(
                Cli::try_parse_from(["stela", command, "--help"]).is_err(),
                "{command}"
            );
        }
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
