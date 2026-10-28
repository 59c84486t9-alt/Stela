//! The `stela` command line prepares a USB that boots Stela to install macOS
//! on a PC and reads the boot log. Research and development commands belong to
//! `stela-dev`, which uses this library's boot-bundle and restore-image tools.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

pub mod apfs;
pub mod args;
pub mod boot;
mod boot_log;
pub mod efi;
mod progress;
pub mod restore;
mod setup;

pub use setup::InstallMedium;

const EXAMPLES: &str = "Examples:
  stela setup --usb DIR --fetch Prepare a USB that boots Stela to install macOS

The research and development commands are stela-dev's (docs/development.md).";
const ABOUT: &str = "Prepare a USB that boots Stela to install macOS on a PC";

#[derive(Parser)]
#[command(
    name = "stela",
    version,
    about = ABOUT,
    after_help = EXAMPLES,
    arg_required_else_help = true
)]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows runs Installer directly; the shared command grammar remains covered by tests"
    )
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows runs Installer directly; the shared command grammar remains covered by tests"
    )
)]
pub(crate) enum Command {
    /// Create a macOS installer USB interactively, or manage an existing USB.
    Setup(Box<setup::Setup>),
    /// Print the boot log stela.efi keeps on a machine-state partition, from a
    /// disk image or a raw partition.
    BootLog(boot_log::BootLog),
}

// Windows ships the direct installer; other hosts expose these subcommands.
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows runs Installer directly; the shared command grammar remains covered by tests"
    )
)]
impl Command {
    fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Setup(command) => command.run(),
            Self::BootLog(command) => command.run(),
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
/// its arguments are `stela setup`'s own flags and commands.
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
    #[cfg(windows)]
    fn windows_executable_exposes_installer_commands() {
        // No arguments opens the wizard; setup's own flags and commands stay
        // scriptable.
        Installer::command()
            .try_get_matches_from(["stela"])
            .unwrap();
        let scripted = Installer::command()
            .try_get_matches_from(["stela", "--ipsw", "a.ipsw", "--profile"])
            .unwrap();
        assert!(scripted.get_flag("profile") && scripted.contains_id("ipsw"));
        Installer::try_parse_from(["stela", "status", "--usb", "E:\\"]).unwrap();
        assert!(Installer::try_parse_from(["stela", "setup"]).is_err());
        assert!(Installer::try_parse_from(["stela", "install-system"]).is_err());
        let help = Installer::command().render_help().to_string();
        assert!(
            help.contains("status") && !help.contains("install-system"),
            "{help}"
        );
        Installer::command().debug_assert();
    }

    #[test]
    fn help_lists_shipped_commands() {
        let help = Cli::command().render_help().to_string();
        assert!(
            help.contains("setup") && help.contains("boot-log"),
            "{help}"
        );
        assert!(
            !help.contains("install-system") && !help.contains("apps"),
            "{help}"
        );
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
    fn portable_commands_dispatch() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
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
    fn removed_commands_are_rejected_without_accessing_inputs() -> anyhow::Result<()> {
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

    #[test]
    fn setup_actions_are_subcommands_that_take_only_their_own_options() {
        let usb = ["--usb", "/Volumes/STELA"];
        for words in [
            &["status"][..],
            &["doctor"],
            &["repair", "--ipsw", "a.ipsw", "--erase-target"],
            &["update", "stela", "--efi", "stela.efi"],
            &["update", "os", "--fetch", "--install-image", "online"],
            &["rollback", "--dry-run"],
            &["uninstall"],
            &["nvram", "next-boot", "recovery", "--install", "macOS"],
            &["nvram", "reset", "--nor", "sdc3"],
            &["state", "backup", "state.bin"],
            &["state", "restore", "state.bin", "--nor", "sdc3"],
            &["boot-log"],
            &["configure", "--no-tss", "--chooser-timeout", "0"],
            &["host-firmware", "install", "package"],
            &[
                "host-firmware",
                "fetch",
                "requests.json",
                "--cache",
                "cache",
            ],
        ] {
            let line = ["stela", "setup"].into_iter().chain(words.iter().copied());
            Cli::try_parse_from(line.chain(usb))
                .unwrap_or_else(|error| panic!("{words:?}: {error}"));
        }
        // Each action takes neither creation's flags nor another action's.
        for words in [
            &["status", "--target", "sdc2"][..],
            &["rollback", "--ipsw", "a.ipsw"],
            &["configure", "--tss", "--no-tss"],
            &["state", "backup", "state.bin", "--chooser-timeout", "0"],
            &["--target", "sdc2", "status"],
            &["status", "repair"],
        ] {
            let line = ["stela", "setup"].into_iter().chain(words.iter().copied());
            assert!(Cli::try_parse_from(line.chain(usb)).is_err(), "{words:?}");
        }
    }
}
