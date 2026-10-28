//! Native GPU build tasks. Compiling a core is distinct from linking its
//! platform port into Stela or executing work on a physical GPU.
use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

pub mod fetch;
mod macos;
mod mesa;
mod nvidia;
mod support;
mod toolchain;

/// Floating-point semantics required by the supplied AIR input.
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
    /// Install the pinned build tools under `.tools/gpu`, then check out each
    /// upstream submodule in `third_party/` at its pinned commit, sparsely
    /// where it has a pattern file, with Stela's patch series.
    Fetch {
        /// Discard commits and edits in a submodule that were never exported.
        #[arg(long)]
        force: bool,
    },
    /// Write each submodule's commits since its pin to its patch series.
    Export,
    /// Build the IOKit kernel helper and separate user-space Metal library
    /// objects for arm64e, arm64 and x86-64. No driver is installed or loaded.
    Macos,
    /// Run the finite library/function object contract on this macOS host,
    /// using a real host Metal device and caller-supplied admitted archive.
    /// This creates no Stela device/pipeline and submits no GPU work.
    MetalLibraryTest {
        #[arg(long)]
        metallib: PathBuf,
        #[arg(long)]
        entry: String,
        /// Matching host LLVM 23 shared library; no compiler is downloaded.
        #[arg(long)]
        llvm_library: PathBuf,
    },
    /// Build NVIDIA, AMD and Intel shader compiler libraries for this host
    /// without Vulkan/OpenGL frontends, with Stela's compiler targets, and run
    /// their Meson tests.
    Compilers {
        /// Maximum parallel native compiler processes.
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..))]
        jobs: u16,
        /// Fail if any fixture target reports an unsupported compiler path.
        /// This still does not establish physical GPU or Metal support.
        #[arg(long)]
        require_all_targets: bool,
        /// Also compile the shared AIR frontend and its tests against this
        /// native LLVM 23 shared library. No GPU work is submitted.
        #[arg(long)]
        llvm_library: Option<PathBuf>,
        /// Enable the AMD LLVM backend using matching LLVM 23
        /// development files located by this llvm-config executable.
        #[arg(long, requires = "llvm_library")]
        llvm_config: Option<PathBuf>,
        /// Also compile these unchanged raw AIR bitcode inputs through each
        /// vendor compiler test. Repeat for multiple inputs; no GPU work is
        /// submitted.
        #[arg(long, requires_all = ["llvm_library", "entry"])]
        air_input: Vec<PathBuf>,
        /// Exact entry point in every supplied raw AIR input.
        #[arg(long, requires = "air_input")]
        entry: Option<String>,
        /// Floating-point profile for the unchanged raw AIR inputs.
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
        Command::MetalLibraryTest {
            metallib,
            entry,
            llvm_library,
        } => macos::test_library(macos::LibraryTestOptions {
            metallib: &metallib,
            entry: &entry,
            llvm_library: &llvm_library,
        }),
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
