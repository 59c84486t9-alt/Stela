//! Native GPU build tasks. Compiling a core is distinct from linking its
//! platform port into Stela or executing work on a physical GPU.
use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

mod macos;
mod mesa;
mod nvidia;
mod support;

#[derive(Subcommand)]
pub enum Command {
    /// Compile the macOS-facing IOKit helper against kernel headers for
    /// arm64e, arm64 and x86-64; inspect its remaining IOKit service imports.
    Macos,
    /// Build NVIDIA, AMD and Intel shader compiler libraries for this host
    /// without Vulkan/OpenGL frontends, and run the native codegen probes.
    Compilers {
        /// Maximum parallel native compiler processes.
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..))]
        jobs: u16,
        /// Fail if any fixture target reports an unsupported compiler path.
        /// This still does not establish physical GPU or Metal support.
        #[arg(long)]
        require_all_targets: bool,
        /// Also compile the shared AIR frontend and its vendor codegen probes
        /// against this native LLVM 23 shared library. No GPU work is submitted.
        #[arg(long)]
        llvm_library: Option<PathBuf>,
    },
    /// Compile NVIDIA's resource-manager and display cores for native Stela
    /// or as Linux reference objects, retaining unresolved platform imports.
    Nvidia {
        #[arg(long, value_enum, default_value_t = nvidia::Target::Stela)]
        target: nvidia::Target,
        /// Maximum parallel native compiler processes.
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..))]
        jobs: u16,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Macos => macos::build(),
        Command::Compilers {
            jobs,
            require_all_targets,
            llvm_library,
        } => mesa::build(jobs, require_all_targets, llvm_library.as_deref()),
        Command::Nvidia { jobs, target } => nvidia::build(jobs, target),
    }
}
