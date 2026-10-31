//! Native ARM macOS entry point for the independent GPU maintenance installer.
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    match stela_gpu_maintenance::Gpu::parse().run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
