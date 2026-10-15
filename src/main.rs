use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{fs::File, path::PathBuf};
use stela_core::{Progress, Stage, read_json, write_json};
mod apple;
mod containers;
mod corpus_progress;
mod dyld_entry;
mod image;
mod linked_benchmark;
mod macho;

#[derive(Parser)]
#[command(
    name = "stela",
    version,
    about = "Native x86 macOS recompilation research tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report detected x86 capabilities and the named SIMD output catalog.
    CpuInfo,
    /// Benchmark the known linked-image fixture in a release build.
    BenchmarkLinkedImages {
        input: PathBuf,
        #[arg(long)]
        library: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Discover Apple image dependencies inside an explicit guest filesystem.
    DiscoverImages {
        input: PathBuf,
        #[arg(long)]
        guest_root: PathBuf,
        #[arg(long)]
        guest_path: Option<String>,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
        #[arg(long, value_parser = parse_address)]
        image_base: Option<u64>,
        #[arg(long, default_value = "0x50000000000", value_parser = parse_address)]
        library_base: u64,
        #[arg(long, default_value = "0x10000000000", value_parser = parse_address)]
        library_stride: u64,
    },
    /// Bind explicit Apple images and probe cross-image native entry execution.
    RunLinkedImages {
        input: PathBuf,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
        #[arg(long, value_parser = parse_address)]
        image_base: Option<u64>,
        #[arg(long, value_parser = parse_library, conflicts_with = "guest_root")]
        library: Vec<LibraryInput>,
        #[arg(long)]
        guest_root: Option<PathBuf>,
        #[arg(long, requires = "guest_root")]
        guest_path: Option<String>,
        #[arg(long, requires = "guest_root", value_parser = parse_address)]
        library_base: Option<u64>,
        #[arg(long, requires = "guest_root", value_parser = parse_address)]
        library_stride: Option<u64>,
        #[arg(long, requires = "guest_root")]
        allow_unresolved_unused_dependencies: bool,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, default_value = "0xffff0000", value_parser = parse_address)]
        stop_pc: u64,
        #[arg(long, default_value_t = 10000)]
        block_budget: usize,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
        #[arg(long, default_value = "0x80000000000", value_parser = parse_address)]
        stack_base: u64,
        #[arg(long, default_value_t = 65536)]
        stack_bytes: u64,
        #[arg(long, value_parser = parse_memory_query)]
        read_memory: Vec<MemoryQuery>,
    },
    /// Map a trusted image's initial segments and probe its translated entry.
    RunMappedImage {
        input: PathBuf,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
        #[arg(long, value_parser = parse_address)]
        image_base: Option<u64>,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, default_value = "0xffff0000", value_parser = parse_address)]
        stop_pc: u64,
        #[arg(long, default_value_t = 10000)]
        block_budget: usize,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
        #[arg(long, default_value = "0x70000000000", value_parser = parse_address)]
        stack_base: u64,
        #[arg(long, default_value_t = 65536)]
        stack_bytes: u64,
        #[arg(long, value_parser = parse_memory_query)]
        read_memory: Vec<MemoryQuery>,
    },
    /// Validate and plan supported chained rebases without mapping or execution.
    PlanFixups {
        input: PathBuf,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
        #[arg(long, value_parser = parse_address)]
        image_base: Option<u64>,
        /// Plan authenticated rebases under explicit IA/IB/DA/DB process keys.
        #[arg(long)]
        software_pauth_keys: Option<PathBuf>,
    },
    /// Compile one native block with explicit guest-address exits.
    CompileBlock {
        input: PathBuf,
        /// Select native host features or an explicit portable AOT tier.
        #[arg(long,default_value="native",value_parser=parse_cpu_target)]
        cpu_target: stela_compiler::TargetCpu,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        #[arg(long)]
        output_dir: PathBuf,
        /// Emit explicit software PAuth helper boundaries; preparation needs no keys.
        #[arg(long)]
        software_pauth: bool,
        /// Prepare reviewed clock helper boundaries without executing a clock service.
        #[arg(long, requires = "software_pauth")]
        software_clock: bool,
        /// Prepare guest TPIDRRO_EL0 reads without supplying a thread context.
        #[arg(long)]
        thread_registers: bool,
    },
    /// Execute trusted raw code through bounded native block dispatch.
    #[command(group(clap::ArgGroup::new("software_pauth_context").args(["software_pauth_ib_key", "software_pauth_keys"])))]
    RunBlocks {
        input: PathBuf,
        /// Select native host features or an explicit portable AOT tier.
        #[arg(long,default_value="native",value_parser=parse_cpu_target)]
        cpu_target: stela_compiler::TargetCpu,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        #[arg(long, value_parser = parse_address)]
        entry: Option<u64>,
        #[arg(long, value_parser = parse_address)]
        stop_pc: Option<u64>,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, default_value_t = 10000)]
        block_budget: usize,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
        /// Opt into software IB/SP authentication with explicit {low,high} test keys.
        #[arg(long)]
        software_pauth_ib_key: Option<PathBuf>,
        /// Explicit IA/IB/DA/DB low/high key pairs for the software ARM profile.
        #[arg(long)]
        software_pauth_keys: Option<PathBuf>,
        /// Owned data mappings for trusted raw-code execution.
        #[arg(long)]
        memory: Option<PathBuf>,
        /// Service reviewed Darwin data-only mprotect calls over owned mappings.
        #[arg(long)]
        data_vm_services: bool,
        /// Complete the declared unavailable Darwin cross-architecture service.
        #[arg(long)]
        crossarch_services: bool,
        /// Supply host kernel entropy through bounded owned-memory copyout.
        #[arg(long)]
        entropy_services: bool,
        /// Service ordinary Mach VM protection using owned current-task data pages.
        #[arg(long, requires = "memory")]
        mach_vm_services: bool,
        /// Explicit immutable guest ARM CSR active flags; never inferred from host policy.
        #[arg(long)]
        csr_active_configuration: Option<u32>,
        /// Own host Mach bootstrap rights behind guest port names (macOS only).
        #[arg(long)]
        mach_port_services: bool,
        /// Own current-host thread identity, Mach bootstrap rights and guest ARM TSD.
        #[arg(
            long,
            requires = "guest_vm_max_address",
            conflicts_with = "mach_port_services"
        )]
        thread_services: bool,
        /// Explicit guest vm_map_max for ARM TSD sanitization; never inferred from host RAM.
        #[arg(long, requires = "thread_services", value_parser = parse_address)]
        guest_vm_max_address: Option<u64>,
        /// Map the modern ARM page-size commpage; arm64 user pages stay 16 KiB.
        #[arg(long, value_parser = parse_arm_kernel_page_shift)]
        arm_commpage_kernel_page_shift: Option<stela_runtime::commpage::KernelPageSize>,
        #[arg(long, requires = "memory", value_parser = parse_memory_query)]
        read_memory: Vec<MemoryQuery>,
        /// Explicit finite replay for one reviewed virtual-counter read.
        #[arg(long, requires = "software_pauth_context")]
        clock_snapshot: Option<PathBuf>,
        /// Explicitly declare legacy commpage kernel tracing disabled.
        #[arg(long, requires = "clock_snapshot")]
        disabled_kdebug: bool,
        /// Explicit opaque legacy DYLD_FLAGS for a process with hardware TPRO disabled.
        #[arg(long, requires = "clock_snapshot", value_parser = parse_address)]
        opaque_dyld_flags: Option<u64>,
    },
    /// Probe trusted executable entry code; dyld/process setup remains unresolved.
    ProbeImageEntry {
        input: PathBuf,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
        #[arg(long, default_value = "0xffff0000", value_parser = parse_address)]
        stop_pc: u64,
        #[arg(long, default_value_t = 10000)]
        block_budget: usize,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
    },
    /// Validate an Apple executable's guest mappings and unresolved loader work.
    PlanExecutable {
        input: PathBuf,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
    },
    /// Plan a classic Apple dynamic linker's original UNIXTHREAD entry.
    PlanDynamicLinker {
        input: PathBuf,
        #[arg(long, value_parser = ["arm64", "arm64e"])]
        architecture: Option<String>,
    },
    /// Probe a reviewed original-dyld startup prefix with owned arguments.
    ProbeDyldEntry {
        input: PathBuf,
        #[arg(long)]
        executable: PathBuf,
        /// Byte-array argv, environment and extra apple entries; no host environment inheritance.
        #[arg(long)]
        arguments: Option<PathBuf>,
        #[arg(long, default_value = "0x40000000000", value_parser = parse_address)]
        dyld_slide: u64,
        #[arg(long, default_value = "0x60000000000", value_parser = parse_address)]
        image_base: u64,
        #[arg(long, default_value = "0x80000000000", value_parser = parse_address)]
        stack_base: u64,
        #[arg(long, default_value_t = 65536)]
        stack_bytes: u64,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
        /// Opt into software IB/SP authentication; alone, stop after the first PACIBSP.
        #[arg(long)]
        software_pauth_ib_key: Option<PathBuf>,
        /// Run the reviewed clock bootstrap through mach_continuous_time's return.
        #[arg(long, requires = "software_pauth_ib_key")]
        bootstrap_clock: bool,
        /// Explicit replay {counter,sleep_ticks}; otherwise use the validated Darwin host clock.
        #[arg(long, requires = "bootstrap_clock")]
        clock_snapshot: Option<PathBuf>,
    },
    /// Inspect kernel collection images using collection-relative offsets.
    FilesetManifest {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decode a bare plaintext kernel IM4P payload into a bounded output file.
    DecodeIm4p {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 512 * 1024 * 1024)]
        max_input_bytes: u64,
        #[arg(long, default_value_t = 1024 * 1024 * 1024)]
        max_output_bytes: u64,
    },
    /// Inspect BuildManifest identities and model-specific component paths.
    ImageManifest {
        image: PathBuf,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Extract one named ZIP member with a size limit and hash receipt.
    ExtractImage {
        image: PathBuf,
        #[arg(long)]
        member: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024)]
        max_bytes: u64,
    },
    /// Export Mach-O text slices, symbols and bounded leaf-decoder recognition.
    BinaryText { input: PathBuf },
    /// Inventory an Apple ARM dyld shared-cache file without extracting dylibs.
    SharedCacheManifest {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        with_subcaches: bool,
        #[arg(long, requires = "with_subcaches")]
        apple_map: Option<PathBuf>,
    },
    /// Decode original cache slide chains, retaining unresolved authentication.
    PlanCacheFixups {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = parse_address)]
        cache_base: Option<u64>,
        #[arg(long, default_value_t = 32)]
        samples: usize,
    },
    /// Briefly map an original cache read-only and compare its original VM views.
    ProbeCacheMappings {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = parse_address)]
        cache_base: Option<u64>,
    },
    /// Discover static code paths and prepare shared AOT/JIT artifacts without execution.
    DiscoverCode {
        input: PathBuf,
        #[arg(long)]
        architecture: Option<String>,
        /// Require MH_DYLINKER and seed its typed LC_UNIXTHREAD PC instead of LC_MAIN.
        #[arg(long, conflicts_with = "guest_base")]
        dynamic_linker: bool,
        /// Prepare software PAuth helper boundaries without executing or supplying keys.
        #[arg(long)]
        software_pauth: bool,
        /// Prepare reviewed clock helper boundaries without executing a clock service.
        #[arg(long, requires = "software_pauth")]
        software_clock: bool,
        /// Prepare guest TPIDRRO_EL0 reads without supplying a thread context.
        #[arg(long)]
        thread_registers: bool,
        /// Treat input as raw code registered at this address instead of a Mach-O.
        #[arg(long, value_parser = parse_address)]
        guest_base: Option<u64>,
        #[arg(long, value_parser = parse_address)]
        entry: Vec<u64>,
        /// Include declared LC_FUNCTION_STARTS roots as well as the image entry.
        #[arg(long)]
        function_starts: bool,
        #[arg(long, default_value_t = 128)]
        block_budget: usize,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read typed exports and function boundaries from an unchanged cache image.
    CacheExports {
        input: PathBuf,
        #[arg(long)]
        image: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = parse_address)]
        cache_base: Option<u64>,
    },
    /// Resolve named exports through original cache dependency and reexport metadata.
    ResolveCacheExports {
        input: PathBuf,
        #[arg(long)]
        image: String,
        #[arg(long, required = true)]
        symbol: Vec<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = parse_address)]
        cache_base: Option<u64>,
        #[arg(long)]
        weak_import: bool,
    },
    /// Execute complete original cached register-only functions against case inputs.
    ProbeCachedFunctions {
        input: PathBuf,
        #[arg(long)]
        image: String,
        #[arg(long, value_parser = parse_cached_function, required = true)]
        function: Vec<macho::cached_functions::FunctionInput>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = parse_address)]
        cache_base: Option<u64>,
        #[arg(long, default_value = "0x220000100000", value_parser = parse_address)]
        stop_pc: u64,
        #[arg(long, default_value_t = 128)]
        block_budget: usize,
        #[arg(long, default_value = ".stela/cache/blocks-v1")]
        cache_dir: PathBuf,
        /// Prepare static paths before running; unresolved targets still use JIT.
        #[arg(long)]
        aot: bool,
    },
    /// Inspect bounded AEA1/profile-1 acquisition metadata, without key bodies.
    InspectAea { input: PathBuf },
    /// Fetch the public Apple FCS recipient key named by AEA1 metadata.
    FetchAeaKey {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Measure actual isolated native emission over pinned ARM instruction words.
    #[command(alias = "instruction-progress")]
    CorpusProgress {
        input: PathBuf,
        #[arg(long)]
        fileset_manifest: Option<PathBuf>,
    },
    /// Prepare a supported leaf function on demand; reuse an exact cached AOT.
    PrepareLeaf {
        input: PathBuf,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        #[arg(long, default_value = ".stela/cache/leaf-v1")]
        cache_dir: PathBuf,
    },
    /// AOT-compile a raw ARM64 leaf region with internal branches into x86.
    CompileLeaf {
        input: PathBuf,
        /// Select native host features or an explicit portable AOT tier.
        #[arg(long,default_value="native",value_parser=parse_cpu_target)]
        cpu_target: stela_compiler::TargetCpu,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        /// Compile for an explicit guest execution profile.
        #[arg(long, requires_all = ["svl_bytes", "svcr"], value_parser = [stela_compiler::extended::PROFILE_ID, stela_compiler::extended::DECLARED_PROFILE_ID])]
        guest_profile: Option<String>,
        /// Streaming vector length in bytes: 16, 32, 64, 128 or 256.
        #[arg(long, requires = "guest_profile", value_parser = parse_scalable_vector_length)]
        svl_bytes: Option<stela_compiler::aarch64::scalable::VectorLength>,
        /// Explicit initial SVCR bits: streaming mode is bit0, ZA enable is bit1.
        #[arg(long, requires = "guest_profile", value_parser = parse_scalable_mode)]
        svcr: Option<stela_compiler::aarch64::scalable::ScalableMode>,
        /// Explicit architectural feature declaration; repeat for each V2 feature.
        #[arg(long, requires = "guest_profile")]
        guest_feature: Vec<String>,
        /// Explicit maximum streaming vector length for the V2 guest profile.
        #[arg(long, requires = "guest_profile", value_parser = parse_scalable_vector_length)]
        max_svl_bytes: Option<stela_compiler::aarch64::scalable::VectorLength>,
        /// Explicit V2 ZT0 permission: true or false.
        #[arg(long, requires = "guest_profile", num_args = 1)]
        zt0_enabled: Option<bool>,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Discover and fetch restore images directly from Apple's public feed.
    Images {
        #[command(subcommand)]
        command: Images,
    },
    /// List ZIP members without extracting or mounting an IPSW.
    InspectImage { image: PathBuf },
    /// Inventory standalone Mach-O files in an extracted filesystem.
    Inventory {
        root: PathBuf,
        #[arg(long)]
        build: String,
        #[arg(long, default_value = ".stela/inventory.json")]
        output: PathBuf,
    },
    /// Track per-build translation stages and hashed evidence.
    Progress {
        #[command(subcommand)]
        command: ProgressCommand,
    },
}

fn parse_scalable_vector_length(
    value: &str,
) -> Result<stela_compiler::aarch64::scalable::VectorLength, String> {
    let bytes = value.parse::<usize>().map_err(|error| error.to_string())?;
    stela_compiler::aarch64::scalable::VectorLength::from_bytes(bytes)
        .ok_or_else(|| "SVL bytes must be one of 16, 32, 64, 128 or 256".into())
}

fn parse_scalable_mode(
    value: &str,
) -> Result<stela_compiler::aarch64::scalable::ScalableMode, String> {
    let bits = value.parse::<u64>().map_err(|error| error.to_string())?;
    stela_compiler::aarch64::scalable::ScalableMode::from_svcr(bits)
        .ok_or_else(|| "SVCR must be in 0..=3".into())
}

/// Validate declared guest specialization before reading or compiling input.
fn compile_leaf_profile(
    id: Option<&str>,
    length: Option<stela_compiler::aarch64::scalable::VectorLength>,
    mode: Option<stela_compiler::aarch64::scalable::ScalableMode>,
    feature_names: &[String],
    max_length: Option<stela_compiler::aarch64::scalable::VectorLength>,
    zt0_enabled: Option<bool>,
) -> Result<Option<stela_compiler::extended::ScalableProfile>> {
    use stela_compiler::{
        aarch64::scalable::{features::ScalableFeatures, profile::ScalableControls},
        extended::{DECLARED_PROFILE_ID, PROFILE_ID, ScalableProfile},
    };
    let Some(id) = id else {
        ensure!(
            length.is_none()
                && mode.is_none()
                && feature_names.is_empty()
                && max_length.is_none()
                && zt0_enabled.is_none(),
            "scalable options require an explicit guest profile"
        );
        return Ok(None);
    };
    let length = length.context("guest profile requires an explicit SVL")?;
    let mode = mode.context("guest profile requires an initial SVCR")?;
    let profile = match id {
        PROFILE_ID => {
            ensure!(
                feature_names.is_empty() && max_length.is_none() && zt0_enabled.is_none(),
                "V1 profile does not accept V2 feature or control options"
            );
            ScalableProfile::new(length, mode)
        }
        DECLARED_PROFILE_ID => {
            ensure!(
                !feature_names.is_empty(),
                "V2 profile requires explicit guest features"
            );
            let features =
                ScalableFeatures::checked_from_names(feature_names.iter().map(String::as_str))?;
            let controls = ScalableControls::new(
                max_length.context("V2 profile requires an explicit maximum SVL")?,
                zt0_enabled.context("V2 profile requires explicit ZT0 permission")?,
            );
            ScalableProfile::new_with_features(length, mode, features, controls)?
        }
        _ => anyhow::bail!("unknown guest profile {id:?}"),
    };
    Ok(Some(profile))
}

fn parse_address(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|e| e.to_string())
}

fn parse_cached_function(value: &str) -> Result<macho::cached_functions::FunctionInput, String> {
    let (symbol, cases) = value.split_once('=').ok_or("expected SYMBOL=CASES_JSON")?;
    if symbol.is_empty() || symbol.len() > 4096 || cases.is_empty() {
        return Err("expected a bounded nonempty symbol and case-file path".into());
    }
    Ok(macho::cached_functions::FunctionInput {
        symbol: symbol.into(),
        cases: cases.into(),
    })
}

#[derive(Debug, Clone)]
struct MemoryQuery {
    address: u64,
    bytes: usize,
}

#[derive(Debug, Clone)]
struct LibraryInput {
    path: PathBuf,
    base: u64,
}
fn parse_library(value: &str) -> Result<LibraryInput, String> {
    let (path, base) = value
        .rsplit_once('@')
        .ok_or("expected LIBRARY_PATH@ADDRESS")?;
    if path.is_empty() {
        return Err("library path is empty".into());
    }
    Ok(LibraryInput {
        path: path.into(),
        base: parse_address(base)?,
    })
}

fn parse_arm_kernel_page_shift(
    value: &str,
) -> Result<stela_runtime::commpage::KernelPageSize, String> {
    use stela_runtime::commpage::KernelPageSize;
    match value {
        "12" => Ok(KernelPageSize::FourKiB),
        "14" => Ok(KernelPageSize::SixteenKiB),
        _ => Err("ARM kernel page shift must be 12 or 14; arm64 user shift is 14".into()),
    }
}

fn parse_cpu_target(value: &str) -> Result<stela_compiler::TargetCpu, String> {
    if value == "native" {
        Ok(stela_compiler::TargetCpu::detect())
    } else {
        value.parse()
    }
}

fn parse_memory_query(value: &str) -> Result<MemoryQuery, String> {
    let (address, bytes) = value.split_once(':').ok_or("expected ADDRESS:BYTES")?;
    let address = parse_address(address)?;
    let bytes = usize::try_from(parse_address(bytes)?).map_err(|error| error.to_string())?;
    if bytes as u64 > stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES {
        return Err("memory snapshot exceeds image memory limit".into());
    }
    Ok(MemoryQuery { address, bytes })
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RegisterInput {
    x: [u64; 31],
    #[serde(default)]
    sp: u64,
    #[serde(default)]
    nzcv: u32,
    #[serde(default)]
    reserved: u32,
    /// Little-endian low/high 64-bit limbs of each architectural V register.
    #[serde(default)]
    v: [[u64; 2]; 32],
    #[serde(default)]
    fpcr: u32,
    #[serde(default)]
    fpsr: u32,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PauthKeyInput {
    low: u64,
    high: u64,
}

fn block_profile(
    software_pauth: bool,
    software_clock: bool,
    thread_registers: bool,
) -> stela_compiler::block::BlockProfile {
    use stela_compiler::block::BlockProfile;
    match (software_pauth, software_clock, thread_registers) {
        (_, true, true) => BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
        (_, true, false) => BlockProfile::AppleArm64eSoftwarePauthClockV1,
        (true, false, true) => BlockProfile::AppleArm64eSoftwarePauthThreadV1,
        (true, false, false) => BlockProfile::AppleArm64eSoftwarePauthV1,
        (false, false, true) => BlockProfile::DarwinArm64ThreadV1,
        (false, false, false) => BlockProfile::Ordinary,
    }
}

fn pauth_context(
    path: &std::path::Path,
    address_space: u64,
) -> Result<stela_runtime::pauth::Context> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "software PAuth key input exceeds 4096 bytes"
    );
    let keys: PauthKeyInput = serde_json::from_slice(&bytes)?;
    Ok(stela_runtime::pauth::Context::new(
        address_space,
        stela_runtime::pauth::Keys::from_ib_words(keys.low, keys.high),
    ))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PauthKeysInput {
    ia: PauthKeyInput,
    ib: PauthKeyInput,
    da: PauthKeyInput,
    db: PauthKeyInput,
}

fn pauth_all_keys_context(
    path: &std::path::Path,
    address_space: u64,
) -> Result<stela_runtime::pauth::Context> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "software PAuth keys input exceeds 4096 bytes"
    );
    let keys: PauthKeysInput = serde_json::from_slice(&bytes)?;
    Ok(stela_runtime::pauth::Context::new(
        address_space,
        stela_runtime::pauth::Keys::from_words(
            [keys.ia.low, keys.ia.high],
            [keys.ib.low, keys.ib.high],
            [keys.da.low, keys.da.high],
            [keys.db.low, keys.db.high],
        ),
    ))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemoryInput {
    regions: Vec<RawMemoryRegionInput>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemoryRegionInput {
    guest_address: u64,
    virtual_bytes: u64,
    initial_bytes: Option<Vec<u8>>,
    initial_file: Option<RawMemoryFileInput>,
    readable: bool,
    writable: bool,
    maximum_readable: Option<bool>,
    maximum_writable: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemoryFileInput {
    path: PathBuf,
    #[serde(default)]
    offset: u64,
    bytes: u64,
    sha256: String,
}

fn raw_initial_bytes(
    region: &RawMemoryRegionInput,
    directory: &std::path::Path,
) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    ensure!(
        region.initial_bytes.is_none() || region.initial_file.is_none(),
        "raw memory must select inline bytes or a file, not both"
    );
    if let Some(source) = &region.initial_file {
        ensure!(
            source.bytes <= region.virtual_bytes
                && source.bytes <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
            "raw memory file bytes exceed region or input bound"
        );
        let end = source
            .offset
            .checked_add(source.bytes)
            .context("raw memory file extent overflow")?;
        let mut file = File::open(directory.join(&source.path))?;
        ensure!(
            file.metadata()?.is_file(),
            "raw memory source must be an ordinary file"
        );
        ensure!(
            end <= file.metadata()?.len(),
            "raw memory file extent exceeds source"
        );
        let mut bytes = vec![0; usize::try_from(source.bytes)?];
        file.seek(SeekFrom::Start(source.offset))?;
        file.read_exact(&mut bytes)?;
        ensure!(
            stela_core::sha256(&bytes) == source.sha256,
            "raw memory file hash differs"
        );
        Ok(bytes)
    } else {
        let bytes = region.initial_bytes.clone().unwrap_or_default();
        ensure!(
            bytes.len() as u64 <= region.virtual_bytes,
            "raw initial bytes exceed region"
        );
        Ok(bytes)
    }
}
fn raw_memory(path: Option<&std::path::Path>) -> Result<stela_runtime::memory::OwnedMemory> {
    use std::io::Read;
    let Some(path) = path else {
        return stela_runtime::memory::OwnedMemory::map(vec![]);
    };
    let mut bytes = Vec::new();
    File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "raw memory input exceeds 4 MiB"
    );
    let input: RawMemoryInput = serde_json::from_slice(&bytes)?;
    ensure!(
        input.regions.len() <= 1024,
        "raw memory region count exceeds 1024"
    );
    let mut limits = Vec::new();
    let mut specs = Vec::new();
    let mut total = 0u64;
    for r in input.regions {
        total = total
            .checked_add(r.virtual_bytes)
            .context("raw memory extent overflow")?;
        ensure!(
            total <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
            "raw memory exceeds input bound"
        );
        let initial_bytes = raw_initial_bytes(
            &r,
            path.parent().unwrap_or_else(|| std::path::Path::new(".")),
        )?;
        if r.maximum_readable.is_some() || r.maximum_writable.is_some() {
            limits.push(stela_runtime::memory::DataProtectionLimit {
                guest_address: r.guest_address,
                readable: r.maximum_readable.unwrap_or(r.readable),
                writable: r.maximum_writable.unwrap_or(r.writable),
            });
        }
        specs.push(stela_runtime::memory::MemoryRegionSpec {
            guest_address: r.guest_address,
            virtual_bytes: r.virtual_bytes,
            initial_bytes,
            readable: r.readable,
            writable: r.writable,
            executable: false,
        });
    }
    stela_runtime::memory::OwnedMemory::map_with_data_limits(specs, limits)
}
fn memory_hashes(memory: &stela_runtime::memory::OwnedMemory) -> Result<Vec<serde_json::Value>> {
    memory.regions().iter().filter(|r| r.readable).map(|r| Ok(serde_json::json!({
        "address":r.guest_address,"bytes":r.virtual_bytes,
        "sha256":stela_core::sha256(&memory.read_snapshot(r.guest_address, usize::try_from(r.virtual_bytes)?)?),
    }))).collect()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockSnapshotInput {
    counter: u64,
    sleep_ticks: u64,
}

fn clock_snapshot(path: &std::path::Path) -> Result<stela_runtime::clock::Snapshot> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "clock snapshot input exceeds 4096 bytes"
    );
    let input: ClockSnapshotInput = serde_json::from_slice(&bytes)?;
    let snapshot = stela_runtime::clock::Snapshot {
        counter: input.counter,
        sleep_ticks: input.sleep_ticks,
    };
    snapshot.awake_ticks()?;
    Ok(snapshot)
}

fn register_json(state: &stela_compiler::GuestState) -> serde_json::Value {
    serde_json::json!({"x":state.x,"sp":state.sp,"nzcv":state.nzcv,"reserved":state.reserved,
        "v":state.v,"fpcr":state.fpcr,"fpsr":state.fpsr})
}

fn apple_slice<'a>(
    data: &'a [u8],
    path: &std::path::Path,
    architecture: Option<&str>,
) -> Result<(u64, &'a [u8])> {
    let artifacts = macho::inspect(data, &path.display().to_string())?;
    let slices = macho::split_slices(data)?;
    let selected: Vec<_> = artifacts
        .iter()
        .zip(slices)
        .filter(|(artifact, _)| {
            matches!(artifact.architecture.as_str(), "arm64" | "arm64e")
                && architecture.is_none_or(|wanted| wanted == artifact.architecture)
        })
        .collect();
    ensure!(
        selected.len() == 1,
        "expected exactly one matching Apple executable slice, found {}; select --architecture arm64 or arm64e",
        selected.len()
    );
    Ok(selected[0].1)
}

#[derive(Subcommand)]
enum Images {
    List {
        #[arg(long)]
        model: Option<String>,
    },
    Fetch {
        /// Omit to select the newest unambiguous version in Apple's catalog.
        #[arg(long)]
        build: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = ".stela/images")]
        output_dir: PathBuf,
        /// Resolve the image and destination without downloading it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ProgressCommand {
    Init {
        inventory: PathBuf,
        #[arg(long, default_value = ".stela/progress.json")]
        ledger: PathBuf,
    },
    Status {
        #[arg(long, default_value = ".stela/progress.json")]
        ledger: PathBuf,
    },
    Record {
        id: String,
        #[arg(long)]
        stage: Stage,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long, default_value = ".stela/progress.json")]
        ledger: PathBuf,
    },
}

fn write_new_report(output: &std::path::Path, report: &mut serde_json::Value) -> Result<()> {
    use std::io::Write;
    ensure!(
        !output.try_exists()?,
        "report exists; choose a new --output path"
    );
    report["cli_executable_sha256"] = serde_json::json!(stela_core::sha256(&std::fs::read(
        std::env::current_exe()?
    )?));
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut pending, report)?;
    pending.write_all(b"\n")?;
    pending.as_file().sync_all()?;
    pending
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    Ok(())
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::CpuInfo => {
            use stela_compiler::{
                TargetCpu,
                x86_64::isa::{ShiftOpcode, SimdOpcode},
            };
            let opcodes: Vec<_> = SimdOpcode::ALL
                .iter()
                .map(|opcode| {
                    serde_json::json!({
                        "mnemonic": opcode.mnemonic(), "opcode_bytes": opcode.encoding(),
                        "minimum_target": opcode.requires().id(),
                        "available_on_host": opcode.requires().supported(),
                        "lowering_enabled": true,
                    })
                })
                .collect();
            let shifts: Vec<_> = ShiftOpcode::ALL
                .iter()
                .map(|opcode| {
                    serde_json::json!({
                        "mnemonic":opcode.mnemonic(), "opcode_bytes":[0x66,0x0f,opcode.opcode()],
                        "modrm_group":opcode.group(), "minimum_target":TargetCpu::Baseline.id(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "detected_target": TargetCpu::detect().id(),
                    "baseline": TargetCpu::Baseline.id(),
                    "atomic_load16": TargetCpu::detect().supports(TargetCpu::AtomicLoad16),
                    "cx16": TargetCpu::detect().supports(TargetCpu::Cx16),
                    "cx8": TargetCpu::detect().supports(TargetCpu::Cx8),
                    "simd_opcodes": opcodes,
                    "simd_immediate_shifts": shifts,
                    "scope": "Named legacy SIMD output forms; scalar encoding recipes remain in x86_64 modules. Catalog membership is not input ISA coverage.",
                }))?
            );
        }
        Command::BenchmarkLinkedImages {
            input,
            library,
            output,
        } => {
            linked_benchmark::run(&input, &library, &output)?;
        }
        Command::DiscoverImages {
            input,
            guest_root,
            guest_path,
            architecture,
            image_base,
            library_base,
            library_stride,
        } => {
            let discovery = macho::dependency_graph::discover(
                &input,
                macho::dependency_graph::DiscoveryOptions {
                    guest_root,
                    guest_path,
                    architecture,
                    image_base,
                    library_base,
                    library_stride,
                },
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"kind":"dependency_discovery",
                "graph":discovery.graph,"complete_binary_verified":false}))?
            );
        }
        Command::RunLinkedImages {
            input,
            architecture,
            image_base,
            library,
            guest_root,
            guest_path,
            library_base,
            library_stride,
            allow_unresolved_unused_dependencies,
            state,
            stop_pc,
            block_budget,
            cache_dir,
            stack_base,
            stack_bytes,
            read_memory,
        } => {
            use macho::{
                linked_images::{ImageInput, LinkedImages},
                mapped_image::StackSpec,
            };
            use stela_runtime::blocks::ThreadState;
            ensure!(
                library.len() < 32,
                "linked image set exceeds 32-image limit"
            );
            ensure!(
                block_budget <= 1_000_000 && stop_pc.is_multiple_of(4),
                "research block budget or return-address alignment is invalid"
            );
            let total = read_memory.iter().try_fold(0u64, |total, query| {
                total
                    .checked_add(query.bytes as u64)
                    .context("snapshot byte count overflow")
            })?;
            ensure!(
                total <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
                "combined memory snapshots exceed image memory limit"
            );
            let provided_state = state.is_some();
            let registers: RegisterInput = if let Some(path) = state {
                read_json(&path)?
            } else {
                RegisterInput::default()
            };
            ensure!(
                registers.nzcv & !0xf0000000 == 0,
                "only NZCV bits31:28 are supported"
            );
            ensure!(
                !provided_state || registers.sp.is_multiple_of(16),
                "research entry SP must be 16-byte aligned"
            );
            let stack = StackSpec {
                base: stack_base,
                bytes: stack_bytes,
            };
            let (mut images, dependency_graph) = if let Some(guest_root) = guest_root {
                let discovery = macho::dependency_graph::discover(
                    &input,
                    macho::dependency_graph::DiscoveryOptions {
                        guest_root,
                        guest_path,
                        architecture,
                        image_base,
                        library_base: library_base.unwrap_or(0x50000000000),
                        library_stride: library_stride.unwrap_or(0x10000000000),
                    },
                )?;
                ensure!(
                    discovery.graph.complete_dependency_graph
                        || allow_unresolved_unused_dependencies,
                    "dependency graph has {} unresolved edges; trusted entry research requires explicit --allow-unresolved-unused-dependencies",
                    discovery.graph.unresolved_dependencies
                );
                let loaded = LinkedImages::load_discovered(
                    discovery.inputs,
                    cache_dir,
                    stack,
                    &discovery.links,
                )?;
                (loaded, Some(discovery.graph))
            } else {
                let mut inputs = Vec::new();
                for (path, base) in std::iter::once((input, image_base))
                    .chain(library.into_iter().map(|lib| (lib.path, Some(lib.base))))
                {
                    let container = std::fs::read(&path)?;
                    let (slice_offset, slice) =
                        apple_slice(&container, &path, architecture.as_deref())?;
                    inputs.push(ImageInput {
                        data: slice.to_vec(),
                        container_sha256: stela_core::sha256(&container),
                        slice_offset,
                        load_base: base,
                    });
                }
                (LinkedImages::load(inputs, cache_dir, stack)?, None)
            };
            ensure!(
                images
                    .regions()
                    .iter()
                    .all(|region| stop_pc < region.guest_address
                        || stop_pc - region.guest_address >= region.virtual_bytes),
                "return address overlaps image memory"
            );
            let mut thread = ThreadState {
                pc: stela_compiler::GuestAddress(images.entry()),
                registers: stela_compiler::GuestState {
                    x: registers.x,
                    sp: if provided_state {
                        registers.sp
                    } else {
                        images.stack().initial_sp
                    },
                    nzcv: registers.nzcv,
                    reserved: registers.reserved,
                    v: registers.v,
                    fpcr: registers.fpcr,
                    fpsr: registers.fpsr,
                },
            };
            thread.registers.x[30] = stop_pc;
            let initial_state = register_json(&thread.registers);
            // SAFETY: This command explicitly assumes trusted research entry code
            // and ABI state; every supplied image and the stack remain owned while
            // serialized dispatch runs. Pending launch/initializer work is excluded.
            let outcome = unsafe {
                images.run(
                    &mut thread,
                    Some(stela_compiler::GuestAddress(stop_pc)),
                    block_budget,
                )?
            };
            let memory = read_memory.iter().map(|query| -> Result<serde_json::Value> {
                Ok(serde_json::json!({"address":query.address,"bytes_hex":hex::encode(images.read_snapshot(query.address,query.bytes)?)}))
            }).collect::<Result<Vec<_>>>()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind":"linked_macho_entry_probe","images":images.images(),"mapped_entry":images.entry(),
                "dependency_graph":dependency_graph,"unresolved_unused_dependencies_allowed":allow_unresolved_unused_dependencies,
                    "memory_regions":images.regions(),"guard_segments_not_reserved":images.guards(),"stack":images.stack(),
                    "host_execute":false,"initial_state":initial_state,"state":register_json(&thread.registers),
                    "pc":thread.pc.0,"outcome":outcome,"memory":memory,
                    "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                    "complete_binary_verified":false
                }))?
            );
        }
        Command::PlanFixups {
            input,
            architecture,
            image_base,
            software_pauth_keys,
        } => {
            let data = std::fs::read(&input)?;
            let (slice_offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
            let file_type = u32::from_le_bytes(
                bytes
                    .get(12..16)
                    .context("truncated Mach header")?
                    .try_into()?,
            );
            let plan = match file_type {
                6 => macho::load_plan::plan_library(bytes)?,
                7 => macho::load_plan::plan_dynamic_linker(bytes)?.image,
                _ => macho::load_plan::plan(bytes)?,
            };
            let preferred = plan
                .segments
                .iter()
                .find(|segment| segment.name == "__TEXT")
                .context("missing preferred image base")?
                .guest
                .address;
            let load_base = image_base.unwrap_or(preferred);
            let (fixups, decoded_fixups) = if let Some(path) = software_pauth_keys.as_deref() {
                let context = pauth_all_keys_context(path, 1)?;
                let decoded = macho::chained_fixups::decode_authenticated(bytes, &plan, load_base)?;
                (
                    serde_json::to_value(decoded.sign_rebases(&context)?)?,
                    Some(decoded),
                )
            } else {
                (
                    serde_json::to_value(macho::chained_fixups::plan(bytes, &plan, load_base)?)?,
                    None,
                )
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind":"chained_fixup_plan","container_sha256":stela_core::sha256(&data),
                    "slice_offset":slice_offset,"plan":plan,"fixups":fixups,"decoded_fixups":decoded_fixups,
                    "fixups_applied":false,"native_executed":false,"complete_binary_verified":false
                }))?
            );
        }
        Command::RunMappedImage {
            input,
            architecture,
            image_base,
            state,
            stop_pc,
            block_budget,
            cache_dir,
            stack_base,
            stack_bytes,
            read_memory,
        } => {
            use macho::mapped_image::{MappedImage, StackSpec};
            use stela_runtime::blocks::ThreadState;
            ensure!(
                block_budget <= 1_000_000 && stop_pc.is_multiple_of(4),
                "research block budget or return-address alignment is invalid"
            );
            let snapshot_total = read_memory.iter().try_fold(0u64, |total, query| {
                total
                    .checked_add(query.bytes as u64)
                    .context("snapshot byte count overflow")
            })?;
            ensure!(
                snapshot_total <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
                "combined memory snapshots exceed image memory limit"
            );
            let provided_state = state.is_some();
            let registers: RegisterInput = if let Some(path) = state {
                serde_json::from_slice(&std::fs::read(path)?)?
            } else {
                RegisterInput::default()
            };
            ensure!(
                registers.nzcv & !0xf0000000 == 0,
                "only NZCV bits31:28 are supported"
            );
            ensure!(
                !provided_state || registers.sp.is_multiple_of(16),
                "research entry SP must be 16-byte aligned"
            );
            let data = std::fs::read(&input)?;
            let (slice_offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
            let mut image = MappedImage::load(
                bytes,
                cache_dir,
                Some(StackSpec {
                    base: stack_base,
                    bytes: stack_bytes,
                }),
                image_base,
            )?;
            ensure!(
                image
                    .regions()
                    .iter()
                    .all(|region| stop_pc < region.guest_address
                        || stop_pc - region.guest_address >= region.virtual_bytes),
                "return address overlaps image memory"
            );
            let mut thread = ThreadState {
                pc: stela_compiler::GuestAddress(image.mapped_entry()),
                registers: stela_compiler::GuestState {
                    x: registers.x,
                    sp: registers.sp,
                    nzcv: registers.nzcv,
                    reserved: registers.reserved,
                    v: registers.v,
                    fpcr: registers.fpcr,
                    fpsr: registers.fpsr,
                },
            };
            if !provided_state {
                thread.registers.sp = image.stack().context("missing research stack")?.initial_sp;
            }
            thread.registers.x[30] = stop_pc;
            let initial_state = register_json(&thread.registers);
            // SAFETY: Explicit research execution assumes trusted entry code,
            // suitable caller-supplied ABI state and data that needs no pending
            // fixup/import. Owned mappings stay alive throughout serialized dispatch.
            let outcome = unsafe {
                image.run(
                    &mut thread,
                    Some(stela_compiler::GuestAddress(stop_pc)),
                    block_budget,
                )?
            };
            let memory = read_memory
                .iter()
                .map(|query| -> Result<serde_json::Value> {
                    Ok(serde_json::json!({"address":query.address,
                    "bytes_hex":hex::encode(image.read_snapshot(query.address,query.bytes)?)}))
                })
                .collect::<Result<Vec<_>>>()?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"kind":"mapped_macho_entry_probe",
                "container_sha256":stela_core::sha256(&data),"slice_offset":slice_offset,"plan":image.plan(),
                "memory_regions":image.regions(),"guard_segments_not_reserved":image.unreserved_guards(),
                "fixups":image.fixups(),"image_base":image.fixups().load_base,"mapped_entry":image.mapped_entry(),
                "applied_rebases":image.fixups().rebases.len(),
                "host_execute":false,"stack":image.stack(),"initial_state":initial_state,
                "state":register_json(&thread.registers),"pc":thread.pc.0,"outcome":outcome,"memory":memory,
                "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "complete_binary_verified":false})
                )?
            );
        }
        Command::CompileBlock {
            input,
            cpu_target,
            guest_base,
            output_dir,
            software_pauth,
            software_clock,
            thread_registers,
        } => {
            let source = std::fs::read(&input)?;
            let window = &source[..source
                .len()
                .min(stela_compiler::block::MAX_BLOCK_INSTRUCTIONS * 4)];
            let profile = block_profile(software_pauth, software_clock, thread_registers);
            let compiled = stela_compiler::block::compile_for_target(
                window,
                stela_compiler::GuestAddress(guest_base),
                profile,
                cpu_target,
            )?;
            ensure!(
                !output_dir.exists(),
                "output directory exists; choose a new one"
            );
            std::fs::create_dir_all(&output_dir)?;
            std::fs::write(output_dir.join("native.bin"), &compiled.native.x86_64_code)?;
            let manifest = serde_json::json!({"schema_version":1,"kind":"raw_arm64_block_aot","target_cpu":cpu_target.id(),
                "source_bytes":compiled.source_bytes,"source_sha256":stela_core::sha256(&source[..compiled.source_bytes]),
                "guest_base":guest_base,"abi":profile.abi(),
                "native_sha256":stela_core::sha256(&compiled.native.x86_64_code),
                "native_bytes":compiled.native.x86_64_code.len(),"source_map":compiled.native.source_map,
                "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "verified":false});
            write_json(&output_dir.join("manifest.json"), &manifest)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::RunBlocks {
            input,
            cpu_target,
            guest_base,
            entry,
            stop_pc,
            state,
            block_budget,
            cache_dir,
            software_pauth_ib_key,
            software_pauth_keys,
            memory: memory_path,
            data_vm_services,
            crossarch_services,
            entropy_services,
            mach_vm_services,
            csr_active_configuration,
            mach_port_services,
            thread_services,
            guest_vm_max_address,
            arm_commpage_kernel_page_shift,
            read_memory,
            clock_snapshot: clock_snapshot_path,
            disabled_kdebug,
            opaque_dyld_flags,
        } => {
            use stela_runtime::blocks::{BlockRuntime, ThreadState};
            const ADDRESS_SPACE_ID: u64 = 1;
            ensure!(
                block_budget <= 1_000_000,
                "research block budget exceeds 1,000,000"
            );
            let registers: RegisterInput = if let Some(path) = state {
                serde_json::from_slice(&std::fs::read(path)?)?
            } else {
                RegisterInput::default()
            };
            ensure!(
                registers.nzcv & !0xf0000000 == 0,
                "only architectural NZCV bits31:28 are supported"
            );
            let mut thread = ThreadState {
                pc: stela_compiler::GuestAddress(entry.unwrap_or(guest_base)),
                registers: stela_compiler::GuestState {
                    x: registers.x,
                    sp: registers.sp,
                    nzcv: registers.nzcv,
                    reserved: registers.reserved,
                    v: registers.v,
                    fpcr: registers.fpcr,
                    fpsr: registers.fpsr,
                },
            };
            let source = std::fs::read(input)?;
            let source_hash = stela_core::sha256(&source);
            let context = if let Some(path) = software_pauth_keys.as_deref() {
                Some(pauth_all_keys_context(path, ADDRESS_SPACE_ID)?)
            } else {
                software_pauth_ib_key
                    .as_deref()
                    .map(|path| pauth_context(path, ADDRESS_SPACE_ID))
                    .transpose()?
            };
            ensure!(
                !mach_vm_services || mach_port_services || thread_services,
                "Mach VM services require an owned Mach port or thread context"
            );
            let mut memory = raw_memory(memory_path.as_deref())?;
            let memory_before = memory_hashes(&memory)?;
            let commpage = arm_commpage_kernel_page_shift
                .map(|kernel| stela_runtime::commpage::Context::new(ADDRESS_SPACE_ID, kernel))
                .transpose()?;
            let snapshot_total = read_memory.iter().try_fold(0usize, |total, q| {
                total
                    .checked_add(q.bytes)
                    .context("memory snapshot overflow")
            })?;
            ensure!(
                snapshot_total <= 1024 * 1024,
                "memory snapshots exceed 1 MiB"
            );
            let mut clock = clock_snapshot_path
                .as_deref()
                .map(|path| -> Result<_> {
                    let snapshot = clock_snapshot(path)?;
                    stela_runtime::clock::Context::new_with_commpage(
                        ADDRESS_SPACE_ID,
                        Box::new(stela_runtime::clock::ReplaySource::new(vec![
                            snapshot, snapshot,
                        ])?),
                        stela_runtime::commpage::legacy::Configuration {
                            kdebug: disabled_kdebug
                                .then_some(stela_runtime::commpage::legacy::KdebugState::Disabled),
                            dyld_flags: opaque_dyld_flags.map(|value| {
                                stela_runtime::commpage::legacy::DyldFlags {
                                    value,
                                    thread_protection:
                                        stela_runtime::commpage::legacy::ThreadProtection::Disabled,
                                }
                            }),
                        },
                    )
                })
                .transpose()?;
            let mut runtime = BlockRuntime::new_for_target(
                ADDRESS_SPACE_ID,
                cache_dir,
                block_profile(context.is_some(), clock.is_some(), thread_services),
                cpu_target,
            );
            runtime.register_code(stela_compiler::GuestAddress(guest_base), source)?;
            // SAFETY: This explicit research command accepts trusted guest code
            // and caller-provided direct native RAM addresses under its documented ABI.
            let mut mach_ports = mach_port_services
                .then(|| stela_runtime::mach::HostPorts::new(ADDRESS_SPACE_ID))
                .transpose()?;
            let mut thread_context = if thread_services {
                Some(stela_runtime::thread::Context::native(
                    ADDRESS_SPACE_ID,
                    stela_runtime::thread::VmMaximum::new(
                        guest_vm_max_address
                            .context("thread services require explicit guest VM maximum")?,
                    )?,
                )?)
            } else {
                None
            };
            let csr_policy = csr_active_configuration
                .map(stela_runtime::darwin::csr::ArmSecurityPolicy::new)
                .transpose()?;
            let service_run = unsafe {
                if data_vm_services
                    || mach_port_services
                    || thread_services
                    || crossarch_services
                    || csr_policy.is_some()
                    || mach_vm_services
                    || entropy_services
                {
                    stela_runtime::darwin::run_services(
                        &mut runtime,
                        &mut thread,
                        stop_pc.map(stela_compiler::GuestAddress),
                        block_budget,
                        &mut memory,
                        stela_runtime::darwin::ExecutionServices {
                            pauth: context.as_ref(),
                            clock: clock.as_mut(),
                            data_vm: data_vm_services,
                            crossarch: crossarch_services,
                            mach_vm: mach_vm_services,
                            csr: csr_policy.as_ref(),
                            entropy: entropy_services,
                            mach_ports: mach_ports.as_mut(),
                            thread: thread_context.as_mut(),
                        },
                    )?
                } else {
                    let outcome = if let Some(clock) = &mut clock {
                        runtime.run_with_clock(
                            &mut thread,
                            stop_pc.map(stela_compiler::GuestAddress),
                            block_budget,
                            context
                                .as_ref()
                                .context("clock replay requires software PAC context")?,
                            clock,
                        )?
                    } else if let Some(context) = &context {
                        runtime.run_with_pauth(
                            &mut thread,
                            stop_pc.map(stela_compiler::GuestAddress),
                            block_budget,
                            context,
                        )?
                    } else {
                        runtime.run(
                            &mut thread,
                            stop_pc.map(stela_compiler::GuestAddress),
                            block_budget,
                        )?
                    };
                    stela_runtime::darwin::ServiceRunOutcome::unserviced(outcome)
                }
            };
            let memory_after = memory_hashes(&memory)?;
            let memory_reads = read_memory.iter().map(|q| -> Result<_> { Ok(serde_json::json!({
                "address":q.address,"bytes":q.bytes,"hex":hex::encode(memory.read_snapshot(q.address,q.bytes)?)
            })) }).collect::<Result<Vec<_>>>()?;
            let memory_report = serde_json::json!({"memory_regions":memory.regions(),"memory_before":memory_before,
                "memory_after":memory_after,"memory_reads":memory_reads});
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"kind":"native_block_run",
                "source_sha256":source_hash,"guest_base":guest_base,"pc":thread.pc.0,"state":register_json(&thread.registers),
                "outcome":service_run.execution,"abi":runtime.profile().abi(),"target_cpu":runtime.target_cpu().id(),"memory":memory_report,
                "mach_port_profile":(mach_port_services || thread_services).then_some(stela_runtime::mach::HOST_PORT_PROFILE),
                "mach_port_events":service_run.mach_services,"mach_port_rights":mach_ports.as_ref()
                    .or_else(|| thread_context.as_ref().map(|thread| thread.ports())).map(|ports| ports.rights()),
                "thread_context":thread_context.as_ref().map(|context| context.snapshot()),
                "thread_service_events":service_run.thread_services,
                "crossarch_service_profile":crossarch_services.then_some(stela_runtime::darwin::crossarch::PROFILE_ID),
                "crossarch_service_events":service_run.crossarch_services,
                "csr_service_profile":csr_policy.as_ref().map(|_| stela_runtime::darwin::csr::PROFILE_ID),
                "csr_active_configuration":csr_policy.as_ref().map(|policy| policy.active_configuration()),
                "csr_service_events":service_run.csr_services,
                "entropy_service_profile":entropy_services.then_some(stela_runtime::darwin::entropy::PROFILE_ID),
                "entropy_service_events":service_run.entropy_services,
                "mach_vm_service_profile":mach_vm_services.then_some(stela_runtime::darwin::mach_vm::PROFILE_ID),
                "mach_vm_service_events":service_run.mach_vm_services,
                "page_size_commpage":commpage.as_ref().map(|page| -> Result<_> { Ok(serde_json::json!({
                    "profile_id":page.profile_id(),"address_space":page.address_space(),
                    "region":page.region(),"supported_fields":page.supported_fields(),
                    "page_sha256":stela_core::sha256(&page.snapshot_bytes()?)
                })) }).transpose()?,
                "data_vm_profile":data_vm_services.then_some(stela_runtime::darwin::DATA_VM_PROFILE),"data_vm_events":service_run.services,
                "software_pauth_profile":context.as_ref().map(|context| context.profile_id()),
                "clock":clock.as_ref().map(|clock| -> Result<_> { Ok(serde_json::json!({
                    "snapshot":clock.snapshot(),"events":clock.events(),"profile_id":clock.profile_id(),
                    "source_id":clock.source_id(),"frequency":clock.frequency(),"region":clock.region(),
                    "legacy_configuration":clock.legacy_configuration(),
                    "legacy_commpage_profile":clock.legacy_configuration().profile_id(),
                    "page_sha256":clock.snapshot_bytes(0, stela_runtime::clock::GUEST_BYTES).map(|bytes| stela_core::sha256(&bytes))?
                })) }).transpose()?,
                "pauth_source_sha256":stela_core::sha256(include_bytes!("../crates/stela-runtime/src/pauth.rs")),
                "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "complete_binary_verified":false}))?
            );
        }
        Command::ProbeImageEntry {
            input,
            architecture,
            stop_pc,
            block_budget,
            cache_dir,
        } => {
            use stela_runtime::blocks::{BlockRuntime, ThreadState};
            ensure!(
                block_budget <= 1_000_000,
                "research block budget exceeds 1,000,000"
            );
            let data = std::fs::read(&input)?;
            let (slice_offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
            let image = macho::block_image::BlockImage::from_slice(bytes)?;
            let mut runtime = BlockRuntime::new(1, cache_dir);
            let mut executable_regions = Vec::new();
            for region in image.regions() {
                ensure!(
                    stop_pc < region.guest_address()
                        || stop_pc >= region.guest_address() + region.bytes().len() as u64,
                    "research return address overlaps executable source"
                );
                let generation = runtime.register_code(
                    stela_compiler::GuestAddress(region.guest_address()),
                    region.bytes().to_vec(),
                )?;
                executable_regions.push(serde_json::json!({"segment":region.segment_name(),
                    "guest_address":region.guest_address(),"file_offset":region.file_offset(),
                    "source_bytes":region.bytes().len(),"source_sha256":stela_core::sha256(region.bytes()),
                    "mapping_generation":generation}));
            }
            let mut thread = ThreadState {
                pc: stela_compiler::GuestAddress(image.plan().executable_entry()?.guest_address),
                registers: Default::default(),
            };
            thread.registers.x[30] = stop_pc;
            // SAFETY: Research entry probing requires trusted code whose data
            // references satisfy the direct-RAM ABI. No dyld/process setup is supplied.
            let outcome = unsafe {
                runtime.run(
                    &mut thread,
                    Some(stela_compiler::GuestAddress(stop_pc)),
                    block_budget,
                )?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"kind":"macho_entry_block_probe",
                "container_sha256":stela_core::sha256(&data),"slice_offset":slice_offset,"plan":image.plan(),
                "executable_regions":executable_regions,
                "pc":thread.pc.0,"state":register_json(&thread.registers),"outcome":outcome,
                "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "complete_binary_verified":false})
                )?
            );
        }
        Command::PlanExecutable {
            input,
            architecture,
        } => {
            let data = std::fs::read(&input)?;
            let (offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
            let plan = macho::load_plan::plan(bytes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind": "macho_executable_load_plan", "container_sha256": stela_core::sha256(&data),
                    "slice_offset": offset, "plan": plan
                }))?
            );
        }
        Command::PlanDynamicLinker {
            input,
            architecture,
        } => {
            let data = std::fs::read(&input)?;
            let (offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
            let plan = macho::load_plan::plan_dynamic_linker(bytes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind":"macho_dynamic_linker_load_plan", "container_sha256":stela_core::sha256(&data),
                    "slice_offset":offset, "plan":plan, "native_executed":false,
                    "complete_binary_verified":false
                }))?
            );
        }
        Command::ProbeDyldEntry {
            input,
            executable,
            arguments,
            dyld_slide,
            image_base,
            stack_base,
            stack_bytes,
            cache_dir,
            software_pauth_ib_key,
            bootstrap_clock,
            clock_snapshot: clock_snapshot_path,
        } => {
            let arguments = arguments
                .map(|path| -> Result<_> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) })
                .transpose()?
                .unwrap_or_default();
            let report = dyld_entry::probe(
                &input,
                &executable,
                &arguments,
                dyld_entry::Options {
                    dyld_slide,
                    image_base,
                    stack_base,
                    stack_bytes,
                    cache_dir,
                    software_pauth_ib_key,
                    bootstrap_clock,
                    clock_snapshot: clock_snapshot_path
                        .as_deref()
                        .map(clock_snapshot)
                        .transpose()?,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::FilesetManifest { input, output } => {
            ensure!(
                !output.exists(),
                "report exists; choose a new --output path"
            );
            let report = crate::macho::fileset::inspect(&std::fs::read(input)?)?;
            write_json(&output, &report)?;
            eprintln!(
                "{} embedded images, {} unique instruction-section bytes; {}",
                report.images.len(),
                report.unique_executable_file_bytes,
                output.display()
            );
        }
        Command::DecodeIm4p {
            input,
            output,
            max_input_bytes,
            max_output_bytes,
        } => {
            use std::io::Read;
            ensure!(max_input_bytes < u64::MAX, "invalid input limit");
            let mut bytes = vec![];
            File::open(input)?
                .take(max_input_bytes + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= max_input_bytes,
                "input exceeds --max-input-bytes"
            );
            let mut receipt_path = output.as_os_str().to_owned();
            receipt_path.push(".json");
            let receipt_path = PathBuf::from(receipt_path);
            ensure!(
                !output.exists() && !receipt_path.exists(),
                "output or receipt exists"
            );
            let parent = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            std::fs::create_dir_all(parent)?;
            let mut pending = tempfile::NamedTempFile::new_in(parent)?;
            let receipt = crate::containers::decode_kernel(&bytes, &mut pending, max_output_bytes)?;
            pending.as_file().sync_all()?;
            pending.persist_noclobber(output).map_err(|e| e.error)?;
            write_json(&receipt_path, &receipt)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::ImageManifest {
            image: input,
            model,
            output,
        } => {
            ensure!(
                !output.exists(),
                "report exists; choose a new --output path"
            );
            let report = image::manifest(&input, model.as_deref())?;
            write_json(&output, &report)?;
            eprintln!(
                "macOS {} build {}: {} matching identities; {}",
                report.product_version,
                report.product_build,
                report.identities.len(),
                output.display()
            );
        }
        Command::ExtractImage {
            image: input,
            member,
            output,
            max_bytes,
        } => {
            let report = image::extract(&input, &member, &output, max_bytes)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::CorpusProgress {
            input,
            fileset_manifest,
        } => {
            let report = corpus_progress::measure(&input, fileset_manifest.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::InspectAea { input } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&apple::aea::inspect(&input)?)?
            );
        }
        Command::SharedCacheManifest {
            input,
            output,
            with_subcaches,
            apple_map,
        } => {
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            let mut report = if with_subcaches {
                macho::shared_cache::manifest_set(&input)?
            } else {
                macho::shared_cache::manifest(&input)?
            };
            if let Some(path) = apple_map {
                report["apple_map_verification"] =
                    macho::shared_cache::verify_apple_map(&report, &path)?;
            }
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,
                "images":report["images"].as_array().map(Vec::len),
                "source_sha256":report["source_sha256"], "complete_binary_verified":false})
            );
        }
        Command::PlanCacheFixups {
            input,
            output,
            cache_base,
            samples,
        } => {
            ensure!(samples <= 256, "cache fixup samples must be at most 256");
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            let set = macho::shared_cache::manifest_set(&input)?;
            let preferred = set["files"][0]["header"]["shared_region_start"]
                .as_u64()
                .context("cache shared-region base is unavailable")?;
            let mut report =
                macho::shared_cache_slide::plan(&set, cache_base.unwrap_or(preferred), samples)?;
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,"kind":report["kind"],
                "complete_binary_verified":false,"fixups_applied":false})
            );
        }
        Command::ProbeCacheMappings {
            input,
            output,
            cache_base,
        } => {
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            // SAFETY: this developer command operates on trusted, serialized
            // acquisition files that the caller keeps unchanged until it exits.
            // The probe checks hashes/identities, but does not lock the inodes.
            let mut report = unsafe { macho::shared_cache_memory::probe(&input, cache_base)? };
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,"mappings":report["mapping_count"],
                "image_headers_verified":report["image_headers_verified"],"complete_binary_verified":false})
            );
        }
        Command::FetchAeaKey { input, output } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&apple::aea::fetch_key(&input, &output)?)?
            );
        }
        Command::DiscoverCode {
            input,
            architecture,
            dynamic_linker,
            software_pauth,
            software_clock,
            thread_registers,
            guest_base,
            entry,
            function_starts,
            block_budget,
            cache_dir,
            output,
        } => {
            use std::io::Read;
            use stela_compiler::GuestAddress;
            use stela_runtime::blocks::BlockRuntime;
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            let mut data = Vec::new();
            std::fs::File::open(&input)?
                .take(256 * 1024 * 1024 + 1)
                .read_to_end(&mut data)?;
            ensure!(
                data.len() <= 256 * 1024 * 1024,
                "code-discovery input exceeds 256 MiB"
            );
            let mut runtime = BlockRuntime::new_with_profile(
                0x534f_5245_414f_5401,
                cache_dir,
                block_profile(software_pauth, software_clock, thread_registers),
            );
            let mut regions = Vec::new();
            let mut roots = entry;
            let provenance;
            if let Some(base) = guest_base {
                ensure!(
                    architecture.is_none() && !function_starts && !dynamic_linker,
                    "raw discovery has no Mach-O architecture or function-start metadata"
                );
                let generation = runtime.register_code(GuestAddress(base), data.clone())?;
                regions.push(
                    serde_json::json!({"guest_address":base,"source_bytes":data.len(),
                    "source_sha256":stela_core::sha256(&data),"mapping_generation":generation}),
                );
                if roots.is_empty() {
                    roots.push(base);
                }
                provenance =
                    serde_json::json!({"format":"raw","source_sha256":stela_core::sha256(&data)});
            } else {
                let (slice_offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
                let image = if dynamic_linker {
                    macho::block_image::BlockImage::from_dynamic_linker_slice(bytes)?
                } else {
                    macho::block_image::BlockImage::from_slice(bytes)?
                };
                let thread_entry = if dynamic_linker {
                    Some(macho::load_plan::plan_dynamic_linker(bytes)?.thread)
                } else {
                    None
                };
                let sources = image.discovery_sources(bytes, function_starts)?;
                roots.extend(sources.roots);
                for region in sources.regions {
                    let generation = runtime.register_code(
                        GuestAddress(region.guest_address()),
                        region.bytes().to_vec(),
                    )?;
                    regions.push(serde_json::json!({"segment":region.segment_name(),
                        "guest_address":region.guest_address(),"file_offset":region.file_offset(),
                        "source_bytes":region.bytes().len(),"source_sha256":stela_core::sha256(region.bytes()),
                        "mapping_generation":generation}));
                }
                provenance = serde_json::json!({"format":"macho","slice_offset":slice_offset,
                    "plan":image.plan(),"data_in_code":sources.data_in_code,
                    "function_start_count":sources.function_start_count,
                    "thread_entry":thread_entry});
            }
            let mut seen = std::collections::BTreeSet::new();
            roots.retain(|root| seen.insert(*root));
            let roots: Vec<_> = roots.into_iter().map(GuestAddress).collect();
            let discovery = runtime.discover(&roots, block_budget)?;
            let mut report = serde_json::json!({"schema_version":1,"kind":"apple_code_discovery_aot_preparation",
                "input":input,"container_sha256":stela_core::sha256(&data),"provenance":provenance,
                "executable_regions":regions,"discovery":discovery,
                "abi":runtime.profile().abi(),
                "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "discovery_source_sha256":stela_core::sha256(include_bytes!("../crates/stela-runtime/src/blocks.rs")),
                "metadata_source_sha256":stela_core::sha256(include_bytes!("macho/block_image.rs")),
                "native_executed":false,"complete_binary_verified":false});
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,"native_executed":false,"complete_binary_verified":false})
            );
        }
        Command::CacheExports {
            input,
            image,
            output,
            cache_base,
        } => {
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            let set = macho::shared_cache::manifest_set(&input)?;
            let preferred = set["files"][0]["header"]["shared_region_start"]
                .as_u64()
                .context("cache shared-region base is unavailable")?;
            let exports =
                macho::shared_cache_exports::read(&set, &image, cache_base.unwrap_or(preferred))?;
            let mut report = serde_json::to_value(exports)?;
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,"complete_binary_verified":false})
            );
        }
        Command::ResolveCacheExports {
            input,
            image,
            symbol,
            output,
            cache_base,
            weak_import,
        } => {
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            ensure!(
                !symbol.is_empty() && symbol.len() <= 64,
                "resolve requires 1..64 symbols"
            );
            let mut names = std::collections::BTreeSet::new();
            for name in &symbol {
                ensure!(
                    !name.is_empty() && name.len() <= 4096 && names.insert(name),
                    "symbols must be distinct bounded nonempty names"
                );
            }
            let set = macho::shared_cache::manifest_set(&input)?;
            let preferred = set["files"][0]["header"]["shared_region_start"]
                .as_u64()
                .context("cache shared-region base is unavailable")?;
            let base = cache_base.unwrap_or(preferred);
            let mut resolver = macho::shared_cache_exports::CacheResolver::new(&set, base)?;
            let mut resolutions = Vec::with_capacity(symbol.len());
            for name in symbol {
                resolutions.push(resolver.resolve(&image, &name, weak_import)?);
            }
            let mut report = serde_json::json!({
                "schema_version":1,"kind":"original_shared_cache_export_resolution_batch",
                "source_sha256":set["source_sha256"],"image_path":image,
                "cache_base":base,"weak_import":weak_import,"resolutions":resolutions,
                "cache_fixups_applied":false,"complete_binary_verified":false
            });
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,"complete_binary_verified":false})
            );
        }
        Command::ProbeCachedFunctions {
            input,
            image,
            function,
            output,
            cache_base,
            stop_pc,
            block_budget,
            cache_dir,
            aot,
        } => {
            ensure!(
                !output.try_exists()?,
                "report exists; choose a new --output path"
            );
            let mut report = macho::cached_functions::probe(
                &input,
                &image,
                cache_base,
                &function,
                macho::cached_functions::ProbeOptions {
                    stop_pc,
                    block_budget,
                    cache_dir: &cache_dir,
                    aot,
                },
            )?;
            write_new_report(&output, &mut report)?;
            println!(
                "{}",
                serde_json::json!({"report":output,"total_cases":report["total_cases"],
                "complete_binary_verified":false})
            );
        }
        Command::BinaryText { input } => {
            use stela_compiler::Lifter;
            let bytes = std::fs::read(&input)?;
            let slices = crate::macho::text_slices(&bytes, &input.display().to_string())?;
            let mut output = vec![];
            for slice in slices {
                let arm = matches!(slice.artifact.architecture.as_str(), "arm64" | "arm64e");
                let mut recognized = 0;
                let mut words = 0;
                if arm {
                    for section in &slice.sections {
                        let data = hex::decode(&section.data_hex)?;
                        for (index, word) in data.as_chunks::<4>().0.iter().enumerate() {
                            let pc = section
                                .guest_address
                                .checked_add(index as u64 * 4)
                                .context("text address overflow")?;
                            words += 1;
                            if stela_compiler::aarch64::Decoder
                                .lift(stela_compiler::GuestAddress(pc), u32::from_le_bytes(*word))
                                .is_ok()
                            {
                                recognized += 1;
                            }
                        }
                    }
                }
                output.push(serde_json::json!({"slice": slice, "arm64_text_words": words, "recognized_leaf_words": recognized,
                    "compiler_source_sha256": stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                    "note": "Word recognition is not function translation, reachability, or verified application coverage."}));
            }
            println!("{}", serde_json::to_string(&output)?);
        }
        Command::PrepareLeaf {
            input,
            guest_base,
            cache_dir,
        } => {
            let source = std::fs::read(input)?;
            let prepared = stela_runtime::prepare_leaf(
                &source,
                stela_compiler::GuestAddress(guest_base),
                &cache_dir,
            )?;
            println!("{}", serde_json::to_string_pretty(&prepared)?);
        }
        Command::CompileLeaf {
            input,
            cpu_target,
            guest_base,
            guest_profile,
            svl_bytes,
            svcr,
            guest_feature,
            max_svl_bytes,
            zt0_enabled,
            output_dir,
        } => {
            let profile = compile_leaf_profile(
                guest_profile.as_deref(),
                svl_bytes,
                svcr,
                &guest_feature,
                max_svl_bytes,
                zt0_enabled,
            )?;
            let source = std::fs::read(&input)?;
            let block = if let Some(profile) = profile {
                stela_compiler::extended::compile_for_profile(
                    &source,
                    stela_compiler::GuestAddress(guest_base),
                    profile,
                    cpu_target,
                )?
            } else {
                stela_compiler::compile_for_target(
                    &source,
                    stela_compiler::GuestAddress(guest_base),
                    cpu_target,
                )?
            };
            ensure!(
                !output_dir.exists(),
                "output directory exists; choose a new one"
            );
            if let Some(parent) = output_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(&output_dir)?;
            std::fs::write(output_dir.join("native.bin"), &block.x86_64_code)?;
            let mut manifest = serde_json::json!({
                "schema_version": 1,
                "kind": "raw_arm64_leaf_aot",
                "target_cpu":cpu_target.id(),
                "source_sha256": stela_core::sha256(&source),
                "guest_base": guest_base,
                "guest_instructions": source.len() / 4,
                "native_sha256": stela_core::sha256(&block.x86_64_code),
                "native_bytes": block.x86_64_code.len(),
                "source_map": block.source_map,
                "abi": stela_compiler::NATIVE_ABI,
                "compiler_source_sha256": stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "verified": false,
            });
            if let Some(profile) = profile {
                manifest["schema_version"] = serde_json::json!(2);
                manifest["abi"] = serde_json::json!(stela_compiler::context::CONTEXT_LEAF_ABI);
                manifest["execution_profile"] = serde_json::json!({
                    "id": profile.id(),
                    "svl_bytes": profile.vector_length().bytes(),
                    "svcr": profile.mode().svcr(),
                });
                if let Some(features) = profile.declared_features() {
                    let controls = profile.controls();
                    let execution = &mut manifest["execution_profile"];
                    execution["features"] = serde_json::json!(features.names());
                    execution["max_svl_bytes"] =
                        serde_json::json!(controls.max_vector_length().bytes());
                    execution["zt0_enabled"] = serde_json::json!(controls.zt0_enabled());
                    execution["dit"] = serde_json::json!(
                        profile
                            .required_dit()
                            .context("V2 profile requires a DIT declaration")?
                    );
                }
                manifest["entry_prefix_bytes"] =
                    serde_json::json!(stela_compiler::extended::CONTEXT_WRAPPER_BYTES);
            }
            write_json(&output_dir.join("manifest.json"), &manifest)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::Images { command } => match command {
            Images::List { model } => {
                let mut images = crate::apple::catalog()?;
                if let Some(model) = model {
                    images.retain(|i| i.models.contains(&model));
                }
                println!("{}", serde_json::to_string_pretty(&images)?);
            }
            Images::Fetch {
                build,
                model,
                output_dir,
                dry_run,
            } => {
                let images = crate::apple::catalog()?;
                let image = crate::apple::select(&images, build.as_deref(), model.as_deref())?;
                // Use a synthesized filename, never a remote path component.
                ensure!(
                    image.build.bytes().all(|c| c.is_ascii_alphanumeric()),
                    "invalid build identifier"
                );
                ensure!(
                    image
                        .version
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'.'),
                    "invalid version identifier"
                );
                let output = output_dir.join(format!(
                    "UniversalMac_{}_{}_Restore.ipsw",
                    image.version, image.build
                ));
                if dry_run {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"image": image, "destination": output, "downloaded": false})
                        )?
                    );
                } else {
                    let receipt = crate::apple::download(&image, &output)?;
                    println!("{}", serde_json::to_string_pretty(&receipt)?);
                    eprintln!("Saved {}", output.display());
                }
            }
        },
        Command::InspectImage { image } => {
            let mut archive = zip::ZipArchive::new(File::open(image)?)?;
            let mut members = vec![];
            for i in 0..archive.len() {
                let file = archive.by_index(i)?;
                members.push(serde_json::json!({"name": file.name(), "bytes": file.size(), "compressed_bytes": file.compressed_size()}));
            }
            println!("{}", serde_json::to_string_pretty(&members)?);
        }
        Command::Inventory {
            root,
            build,
            output,
        } => {
            ensure!(
                !output.exists(),
                "inventory already exists; use a new output path for each scan"
            );
            let inventory = crate::macho::scan(&root, &build)?;
            write_json(&output, &inventory)?;
            eprintln!(
                "{} slices, {} scan errors, {} excluded containers; {}",
                inventory.artifacts.len(),
                inventory.issues.len(),
                inventory.excluded_containers.len(),
                output.display()
            );
            ensure!(
                inventory.issues.is_empty(),
                "inventory saved but scan was incomplete; inspect its issues before using it"
            );
        }
        Command::Progress { command } => match command {
            ProgressCommand::Init { inventory, ledger } => {
                ensure!(
                    !ledger.exists(),
                    "ledger exists; choose another --ledger to preserve progress"
                );
                let bytes = std::fs::read(inventory)?;
                let inventory = serde_json::from_slice(&bytes)?;
                write_json(&ledger, &Progress::new(inventory, &bytes)?)?;
                eprintln!("Created {}", ledger.display());
            }
            ProgressCommand::Status { ledger } => {
                let progress: Progress = read_json(&ledger)?;
                println!("{}", serde_json::to_string_pretty(&progress.report()?)?);
            }
            ProgressCommand::Record {
                id,
                stage,
                evidence,
                ledger,
            } => {
                let mut progress: Progress = read_json(&ledger)?;
                progress
                    .report()
                    .context("existing evidence validation failed")?;
                progress.record(&id, stage, &evidence)?;
                write_json(&ledger, &progress)?;
            }
        },
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod register_state_tests {
    use super::*;

    #[test]
    fn research_state_json_retains_vector_bits_and_fp_status() -> Result<()> {
        let mut state = stela_compiler::GuestState::default();
        state.v[0] = [u64::MAX, 0x7ff8000000001234];
        state.v[31] = [0x0123456789abcdef, 0xfedcba9876543210];
        state.fpcr = 0x03c00000;
        state.fpsr = 0x0800009f;
        let input: RegisterInput = serde_json::from_value(register_json(&state))?;
        assert_eq!(input.v, state.v);
        assert_eq!(input.fpcr, state.fpcr);
        assert_eq!(input.fpsr, state.fpsr);
        // Scalar-only older inputs are accepted with explicitly zero initial SIMD state.
        let scalar: RegisterInput = serde_json::from_value(serde_json::json!({"x":([0u64;31])}))?;
        assert_eq!(scalar.v, [[0; 2]; 32]);
        assert_eq!((scalar.fpcr, scalar.fpsr), (0, 0));
        Ok(())
    }

    #[test]
    fn research_state_rejects_truncated_vectors_and_unknown_fields() {
        for value in [
            serde_json::json!({"x":([0u64;31]),"v":[[0,0]]}),
            serde_json::json!({"x":([0u64;31]),"fpcrr":0}),
        ] {
            assert!(serde_json::from_value::<RegisterInput>(value).is_err());
        }
    }
}

#[cfg(test)]
mod clock_cli_tests {
    use super::*;

    #[test]
    fn full_pauth_keys_and_owned_memory_cli_inputs_are_explicit_and_strict() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let path = folder.path().join("keys.json");
        let valid = r#"{"ia":{"low":1,"high":2},"ib":{"low":3,"high":4},"da":{"low":5,"high":6},"db":{"low":7,"high":8}}"#;
        std::fs::write(&path, valid)?;
        let context = pauth_all_keys_context(&path, 92)?;
        assert_eq!(context.address_space(), 92);
        for key in [
            stela_runtime::pauth::Key::Ia,
            stela_runtime::pauth::Key::Ib,
            stela_runtime::pauth::Key::Da,
            stela_runtime::pauth::Key::Db,
        ] {
            assert!(context.has_key(key));
        }
        for invalid in [
            r#"{"low":1,"high":2}"#,
            r#"{"ia":{"low":1,"high":2},"ib":{"low":3,"high":4},"da":{"low":5,"high":6}}"#,
        ] {
            std::fs::write(&path, invalid)?;
            assert!(pauth_all_keys_context(&path, 92).is_err());
        }
        let mut padded = valid.to_owned();
        padded.push_str(&" ".repeat(4096 - valid.len()));
        std::fs::write(&path, &padded)?;
        assert!(pauth_all_keys_context(&path, 92).is_ok());
        padded.push(' ');
        std::fs::write(&path, padded)?;
        assert!(pauth_all_keys_context(&path, 92).is_err());
        assert!(
            Cli::try_parse_from([
                "stela",
                "run-blocks",
                "code.arm64",
                "--software-pauth-keys",
                "keys.json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "stela",
                "run-blocks",
                "code.arm64",
                "--software-pauth-keys",
                "keys.json",
                "--software-pauth-ib-key",
                "ib.json"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "stela",
                "run-blocks",
                "code.arm64",
                "--software-pauth-keys",
                "keys.json",
                "--clock-snapshot",
                "clock.json"
            ])
            .is_ok()
        );
        let memory = folder.path().join("memory.json");
        std::fs::write(&memory, r#"{"regions":[]}"#)?;
        assert!(raw_memory(Some(&memory))?.regions().is_empty());
        for invalid in [
            r#"{"regions":[],"extra":1}"#,
            r#"{"regions":[{"guest_address":0,"virtual_bytes":4096,"initial_bytes":[],"readable":true,"writable":false,"executable":true}]}"#,
        ] {
            std::fs::write(&memory, invalid)?;
            assert!(raw_memory(Some(&memory)).is_err());
        }
        std::fs::write(&memory, vec![b' '; 4 * 1024 * 1024 + 1])?;
        assert!(raw_memory(Some(&memory)).is_err());
        let payload = folder.path().join("payload.bin");
        std::fs::write(&payload, [9, 8, 7, 6, 5, 4])?;
        let region = serde_json::json!({"guest_address":0,"virtual_bytes":4096,
            "readable":true,"writable":false,
            "initial_file":{"path":"payload.bin","offset":2,"bytes":3,
                "sha256":stela_core::sha256(&[7,6,5])}});
        let parsed: RawMemoryRegionInput = serde_json::from_value(region.clone())?;
        assert_eq!(raw_initial_bytes(&parsed, folder.path())?, [7, 6, 5]);
        for change in [
            serde_json::json!({"offset":5}),
            serde_json::json!({"offset":u64::MAX}),
            serde_json::json!({"bytes":4097}),
            serde_json::json!({"sha256":"wrong"}),
            serde_json::json!({"path":"missing.bin"}),
        ] {
            let mut invalid = region.clone();
            for (key, value) in change.as_object().unwrap() {
                invalid["initial_file"][key] = value.clone();
            }
            let parsed = serde_json::from_value(invalid)?;
            assert!(raw_initial_bytes(&parsed, folder.path()).is_err());
        }
        let mut conflicting = region;
        conflicting["initial_bytes"] = serde_json::json!([]);
        assert!(raw_initial_bytes(&serde_json::from_value(conflicting)?, folder.path()).is_err());
        Ok(())
    }

    #[test]
    fn clock_flags_require_their_explicit_parent_profiles() {
        for args in [
            vec![
                "stela",
                "run-blocks",
                "code",
                "--clock-snapshot",
                "clock.json",
            ],
            vec![
                "stela",
                "probe-dyld-entry",
                "dyld",
                "--executable",
                "app",
                "--bootstrap-clock",
            ],
            vec![
                "stela",
                "probe-dyld-entry",
                "dyld",
                "--executable",
                "app",
                "--clock-snapshot",
                "clock.json",
            ],
            vec![
                "stela",
                "compile-block",
                "code",
                "--output-dir",
                "out",
                "--software-clock",
            ],
            vec![
                "stela",
                "discover-code",
                "code",
                "--output",
                "out",
                "--software-clock",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "stela",
                "probe-dyld-entry",
                "dyld",
                "--executable",
                "app",
                "--software-pauth-ib-key",
                "key.json",
                "--bootstrap-clock",
                "--clock-snapshot",
                "clock.json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "stela",
                "compile-block",
                "code",
                "--output-dir",
                "out",
                "--software-pauth",
                "--software-clock"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "stela",
                "discover-code",
                "code",
                "--output",
                "out",
                "--software-pauth",
                "--software-clock"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "stela",
                "run-blocks",
                "code",
                "--software-pauth-ib-key",
                "key.json",
                "--clock-snapshot",
                "clock.json"
            ])
            .is_ok()
        );
        assert_eq!(
            block_profile(true, true, false),
            stela_compiler::block::BlockProfile::AppleArm64eSoftwarePauthClockV1
        );
        assert_eq!(
            block_profile(true, false, false),
            stela_compiler::block::BlockProfile::AppleArm64eSoftwarePauthV1
        );
        assert_eq!(
            block_profile(false, false, false),
            stela_compiler::block::BlockProfile::Ordinary
        );
    }

    #[test]
    fn thread_register_preparation_flags_select_distinct_profiles_without_context() {
        use stela_compiler::block::BlockProfile;
        for args in [
            vec![
                "stela",
                "compile-block",
                "code",
                "--output-dir",
                "out",
                "--thread-registers",
            ],
            vec![
                "stela",
                "discover-code",
                "code",
                "--output",
                "out",
                "--thread-registers",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        assert_eq!(
            block_profile(false, false, true),
            BlockProfile::DarwinArm64ThreadV1
        );
        assert_eq!(
            block_profile(true, false, true),
            BlockProfile::AppleArm64eSoftwarePauthThreadV1
        );
        assert_eq!(
            block_profile(true, true, true),
            BlockProfile::AppleArm64eSoftwarePauthClockThreadV1
        );
    }

    #[test]
    fn disabled_tracing_requires_an_explicit_clock_context() {
        assert!(Cli::try_parse_from(["stela", "run-blocks", "code", "--disabled-kdebug"]).is_err());
        assert!(
            Cli::try_parse_from([
                "stela",
                "run-blocks",
                "code",
                "--disabled-kdebug",
                "--clock-snapshot",
                "clock.json",
                "--software-pauth-keys",
                "keys.json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["stela", "run-blocks", "code", "--crossarch-services"]).is_ok()
        );
    }

    #[test]
    fn snapshot_input_is_strict_bounded_and_validated() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("clock.json");
        for input in [
            r#"{"counter":10,"sleep_ticks":11}"#,
            r#"{"counter":-1,"sleep_ticks":0}"#,
            r#"{"counter":10}"#,
            r#"{"counter":10,"sleep_ticks":0,"frequency":1}"#,
            r#"{"counter":10,"counter":11,"sleep_ticks":0}"#,
        ] {
            std::fs::write(&path, input)?;
            assert!(clock_snapshot(&path).is_err());
        }
        let valid = r#"{"counter":130,"sleep_ticks":40}"#;
        let mut boundary = valid.to_owned();
        boundary.extend(std::iter::repeat_n(' ', 4096 - valid.len()));
        std::fs::write(&path, &boundary)?;
        assert_eq!(
            clock_snapshot(&path)?,
            stela_runtime::clock::Snapshot {
                counter: 130,
                sleep_ticks: 40
            }
        );
        boundary.push(' ');
        std::fs::write(&path, boundary)?;
        assert!(clock_snapshot(&path).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod cpu_target_cli_tests {
    use super::*;

    #[test]
    fn cpu_selectors_keep_native_and_explicit_capabilities_distinct() {
        use stela_compiler::TargetCpu;
        assert_eq!(parse_cpu_target("native"), Ok(TargetCpu::detect()));
        assert_eq!(
            parse_cpu_target("baseline+popcnt+bmi1+aes+sha"),
            Ok(TargetCpu::Baseline
                .with_popcnt()
                .with_bmi1()
                .with_aes()
                .with_sha())
        );
        for invalid in ["native+aes", "baseline+sha+aes", "baseline+bmi1+bmi1"] {
            assert!(parse_cpu_target(invalid).is_err(), "{invalid}");
        }
    }
}

#[cfg(test)]
mod scalable_profile_cli_tests {
    use super::*;

    fn resolve(extra: &[&str]) -> Result<Option<stela_compiler::extended::ScalableProfile>> {
        let mut args = vec!["stela", "compile-leaf", "input.bin", "--output-dir", "out"];
        args.extend_from_slice(extra);
        let Command::CompileLeaf {
            guest_profile,
            svl_bytes,
            svcr,
            guest_feature,
            max_svl_bytes,
            zt0_enabled,
            ..
        } = Cli::try_parse_from(args)?.command
        else {
            anyhow::bail!("expected compile-leaf");
        };
        compile_leaf_profile(
            guest_profile.as_deref(),
            svl_bytes,
            svcr,
            &guest_feature,
            max_svl_bytes,
            zt0_enabled,
        )
    }

    #[test]
    fn existing_profile_identity_and_rejected_metadata() -> Result<()> {
        assert_eq!(resolve(&[])?, None);
        let original = [
            "--guest-profile",
            "apple-sme2-streaming-v1",
            "--svl-bytes",
            "64",
            "--svcr",
            "1",
        ];
        let profile = resolve(&original)?.unwrap();
        assert_eq!(profile.declared_features(), None);
        assert_eq!(profile.required_dit(), None);
        for extra in [
            vec!["--guest-feature", "FEAT_SME"],
            vec!["--max-svl-bytes", "64"],
            vec!["--zt0-enabled", "false"],
        ] {
            let mut args = original.to_vec();
            args.extend(extra);
            assert!(resolve(&args).is_err());
        }
        Ok(())
    }

    #[test]
    fn declared_profile_requires_and_preserves_explicit_metadata() -> Result<()> {
        let original = [
            "--guest-profile",
            "sme-streaming-v2",
            "--svl-bytes",
            "32",
            "--svcr",
            "2",
        ];
        for suffix in [
            vec![],
            vec!["--guest-feature", "FEAT_SME"],
            vec!["--guest-feature", "FEAT_SME", "--max-svl-bytes", "128"],
        ] {
            let mut args = original.to_vec();
            args.extend(suffix);
            assert!(resolve(&args).is_err());
        }
        let mut args = original.to_vec();
        args.extend([
            "--guest-feature",
            "FEAT_SME2",
            "--guest-feature",
            "FEAT_SME",
            "--max-svl-bytes",
            "128",
            "--zt0-enabled",
            "false",
        ]);
        let profile = resolve(&args)?.unwrap();
        assert_eq!(profile.features().names(), ["FEAT_SME", "FEAT_SME2"]);
        assert_eq!(profile.controls().max_vector_length().bytes(), 128);
        assert!(!profile.controls().zt0_enabled());
        assert_eq!(profile.required_dit(), Some(false));
        assert!(!profile.mode().streaming());
        assert!(profile.mode().za_enabled());
        Ok(())
    }
}
