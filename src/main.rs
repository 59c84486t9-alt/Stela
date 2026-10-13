use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use stela_core::{Progress, Stage, read_json, write_json};
use std::{fs::File, path::PathBuf};
mod apple;
mod containers;
mod corpus_progress;
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
    },
    /// Compile one native block with explicit guest-address exits.
    CompileBlock {
        input: PathBuf,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Execute trusted raw code through bounded native block dispatch.
    RunBlocks {
        input: PathBuf,
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
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
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
}

fn register_json(state: &stela_compiler::GuestState) -> serde_json::Value {
    serde_json::json!({"x":state.x,"sp":state.sp,"nzcv":state.nzcv,"reserved":state.reserved})
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
        } => {
            let data = std::fs::read(&input)?;
            let (slice_offset, bytes) = apple_slice(&data, &input, architecture.as_deref())?;
            let plan = macho::load_plan::plan(bytes)?;
            let preferred = plan
                .segments
                .iter()
                .find(|segment| segment.name == "__TEXT")
                .context("missing preferred image base")?
                .guest
                .address;
            let fixups =
                macho::chained_fixups::plan(bytes, &plan, image_base.unwrap_or(preferred))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind":"chained_fixup_plan","container_sha256":stela_core::sha256(&data),
                    "slice_offset":slice_offset,"plan":plan,"fixups":fixups,"complete_binary_verified":false
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
            guest_base,
            output_dir,
        } => {
            let source = std::fs::read(&input)?;
            let window = &source[..source
                .len()
                .min(stela_compiler::block::MAX_BLOCK_INSTRUCTIONS * 4)];
            let compiled = stela_compiler::block::compile(
                window,
                stela_compiler::GuestAddress(guest_base),
            )?;
            ensure!(
                !output_dir.exists(),
                "output directory exists; choose a new one"
            );
            std::fs::create_dir_all(&output_dir)?;
            std::fs::write(output_dir.join("native.bin"), &compiled.native.x86_64_code)?;
            let manifest = serde_json::json!({"schema_version":1,"kind":"raw_arm64_block_aot",
                "source_bytes":compiled.source_bytes,"source_sha256":stela_core::sha256(&source[..compiled.source_bytes]),
                "guest_base":guest_base,"abi":stela_compiler::block::BLOCK_ABI,
                "native_sha256":stela_core::sha256(&compiled.native.x86_64_code),
                "native_bytes":compiled.native.x86_64_code.len(),"source_map":compiled.native.source_map,
                "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "verified":false});
            write_json(&output_dir.join("manifest.json"), &manifest)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::RunBlocks {
            input,
            guest_base,
            entry,
            stop_pc,
            state,
            block_budget,
            cache_dir,
        } => {
            use stela_runtime::blocks::{BlockRuntime, ThreadState};
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
                },
            };
            let source = std::fs::read(input)?;
            let source_hash = stela_core::sha256(&source);
            let mut runtime = BlockRuntime::new(1, cache_dir);
            runtime.register_code(stela_compiler::GuestAddress(guest_base), source)?;
            // SAFETY: This explicit research command accepts trusted guest code
            // and caller-provided direct native RAM addresses under its documented ABI.
            let outcome = unsafe {
                runtime.run(
                    &mut thread,
                    stop_pc.map(stela_compiler::GuestAddress),
                    block_budget,
                )?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"kind":"native_block_run",
                "source_sha256":source_hash,"guest_base":guest_base,"pc":thread.pc.0,"state":register_json(&thread.registers),
                "outcome":outcome,"abi":stela_compiler::block::BLOCK_ABI,
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
                                .lift(
                                    stela_compiler::GuestAddress(pc),
                                    u32::from_le_bytes(*word),
                                )
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
            guest_base,
            output_dir,
        } => {
            let source = std::fs::read(&input)?;
            let block =
                stela_compiler::compile(&source, stela_compiler::GuestAddress(guest_base))?;
            ensure!(
                !output_dir.exists(),
                "output directory exists; choose a new one"
            );
            if let Some(parent) = output_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(&output_dir)?;
            std::fs::write(output_dir.join("native.bin"), &block.x86_64_code)?;
            let manifest = serde_json::json!({
                "schema_version": 1,
                "kind": "raw_arm64_leaf_aot",
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
