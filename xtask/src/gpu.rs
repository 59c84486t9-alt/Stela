//! Native GPU build tasks. Compiling a core is distinct from linking its
//! platform port into Stela or executing work on a physical GPU.
use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

mod macos;
mod mesa;
mod nvidia;
mod support;

/// An explicit input-owner qualification, never a physical GPU capability.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum AirFpProfile {
    #[default]
    Ieee,
    #[value(name = "apple-32023.922-air2.9-msl4.1")]
    Apple32023Air29Msl41,
}

impl AirFpProfile {
    fn name(self) -> &'static str {
        match self {
            Self::Ieee => "ieee",
            Self::Apple32023Air29Msl41 => "apple-32023.922-air2.9-msl4.1",
        }
    }

    fn kind(self) -> u32 {
        match self {
            Self::Ieee => 0,
            Self::Apple32023Air29Msl41 => 1,
        }
    }
}

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
        /// Enable the retained AMD LLVM backend using matching LLVM 23
        /// development files located by this llvm-config executable.
        #[arg(long, requires = "llvm_library")]
        llvm_config: Option<PathBuf>,
        /// Also compile these unchanged raw AIR bitcode inputs through each
        /// vendor probe. Repeat for multiple inputs; no GPU work is submitted.
        #[arg(long, requires_all = ["llvm_library", "entry"])]
        air_input: Vec<PathBuf>,
        /// Exact entry point in every supplied raw AIR input.
        #[arg(long, requires = "air_input")]
        entry: Option<String>,
        /// Qualified floating-point profile for the unchanged raw AIR inputs.
        /// Selection requires independent compiler provenance; metadata alone
        /// does not authenticate the selected private compiler profile.
        #[arg(long, value_enum, requires = "air_input")]
        air_fp_profile: Option<AirFpProfile>,
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
            llvm_config,
            air_input,
            entry,
            air_fp_profile,
        } => mesa::build(
            jobs,
            require_all_targets,
            llvm_library.as_deref(),
            llvm_config.as_deref(),
            &air_input,
            entry.as_deref(),
            air_fp_profile.unwrap_or_default(),
        ),
        Command::Nvidia { jobs, target } => nvidia::build(jobs, target),
    }
}
