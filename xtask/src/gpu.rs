//! Native GPU build tasks. Compiling a core is distinct from linking its
//! platform port into Stela or executing work on a physical GPU.
use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[cfg(test)]
mod amd;
pub mod fetch;
#[cfg(test)]
mod intel;
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
    /// Check out each pinned upstream GPU source under `.tools/gpu/src`,
    /// apply Stela's patch series and link the imported files into `gpu/`.
    Fetch {
        /// Discard commits and edits in a checkout that were never exported.
        #[arg(long)]
        force: bool,
    },
    /// Write each upstream checkout's commits back to its patch series.
    Export,
    /// Build the IOKit kernel helper and separate user-space Metal library
    /// objects for arm64e, arm64 and x86-64. No driver is installed or loaded.
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
        /// Qualify the bounded threadgroup fixtures: original Apple module,
        /// LLVM static WG64 module, then LLVM dynamic WG64 module. This is
        /// offline shader/packet checking, never GPU execution.
        #[arg(long, num_args = 3, requires = "llvm_library", value_names = ["APPLE", "STATIC", "DYNAMIC"])]
        threadgroup_inputs: Vec<PathBuf>,
        /// Qualify unchanged triangle VS/FS and sampled-texture AIR inputs.
        /// Textures currently must refuse explicitly; no GPU work is submitted.
        #[arg(long, num_args = 2, requires = "llvm_library", value_names = ["TRIANGLE", "TEXTURE"])]
        render_inputs: Vec<PathBuf>,
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
        Command::Fetch { force } => fetch::fetch(force),
        Command::Export => fetch::export(),
        Command::Macos => macos::build(),
        Command::Compilers {
            jobs,
            require_all_targets,
            llvm_library,
            llvm_config,
            air_input,
            entry,
            air_fp_profile,
            threadgroup_inputs,
            render_inputs,
        } => mesa::build(mesa::BuildOptions {
            jobs,
            require_all_targets,
            llvm_library: llvm_library.as_deref(),
            llvm_config: llvm_config.as_deref(),
            air_inputs: &air_input,
            entry: entry.as_deref(),
            fp_profile: air_fp_profile.unwrap_or_default(),
            threadgroup_inputs: &threadgroup_inputs,
            render_inputs: &render_inputs,
        }),
        Command::Nvidia { jobs, target } => nvidia::build(jobs, target),
    }
}
