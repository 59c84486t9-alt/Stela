//! Native GPU build tasks. Compiling a core is distinct from linking its
//! platform port into Stela or executing work on a physical GPU.
use anyhow::Result;
use clap::Subcommand;

mod mesa;
mod nvidia;
mod support;

#[derive(Subcommand)]
pub enum Command {
    /// Build NVIDIA, AMD and Intel shader compiler libraries for this host
    /// without Vulkan/OpenGL frontends, and run the native codegen probes.
    Compilers {
        /// Maximum parallel native compiler processes.
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..))]
        jobs: u16,
    },
    /// Compile NVIDIA's resource-manager and display cores as x86-64 ELF
    /// reference objects, retaining unresolved platform imports in a receipt.
    Nvidia {
        /// Maximum parallel native compiler processes.
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..))]
        jobs: u16,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Compilers { jobs } => mesa::build(jobs),
        Command::Nvidia { jobs } => nvidia::build(jobs),
    }
}
