//! Repository development tasks: `cargo xtask <task>`.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod boot;
mod check;
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
    /// Build, run and debug the freestanding Multiboot mount in x86 QEMU.
    #[command(subcommand)]
    Boot(boot::Command),
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Check { fix } => check::run(fix).map(|()| ExitCode::SUCCESS),
        Task::Boot(command) => boot::run(command),
    };
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::FAILURE
    })
}
