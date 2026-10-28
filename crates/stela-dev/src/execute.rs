//! Native execution of raw code, mapped images and original dyld.
use crate::{args::*, compile::block_profile, dyld_entry, input::*};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::PathBuf;
use stela_loader as macho;
use stela_runtime::read_json;

#[derive(Args)]
pub(crate) struct RunLinkedImages {
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
}

#[derive(Args)]
pub(crate) struct RunMappedImage {
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
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("software_pauth_context").args(["software_pauth_ib_key", "software_pauth_keys"])))]
pub(crate) struct RunBlocks {
    input: PathBuf,
    /// Use the host's CPU features, or a portable feature tier.
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
    /// Enable software IB/SP authentication with the given {low, high} key.
    #[arg(long)]
    software_pauth_ib_key: Option<PathBuf>,
    /// Explicit IA/IB/DA/DB low/high key pairs for the software ARM profile.
    #[arg(long)]
    software_pauth_keys: Option<PathBuf>,
    /// Owned data mappings for trusted raw-code execution.
    #[arg(long)]
    memory: Option<PathBuf>,
    /// Darwin services to handle on guest traps, comma separated.
    #[arg(long, value_enum, value_delimiter = ',')]
    services: Vec<Service>,
    /// Guest ARM CSR active flags for this execution context.
    #[arg(long)]
    csr_active_configuration: Option<u32>,
    /// Guest process ID, shared by the thread and its task.
    #[arg(long)]
    guest_process_id: Option<u32>,
    /// Guest vm_map_max used to sanitize ARM thread-specific data.
    #[arg(long, value_parser = parse_address)]
    guest_vm_max_address: Option<u64>,
    /// Map the modern ARM page-size commpage; arm64 user pages stay 16 KiB.
    #[arg(long, value_parser = parse_arm_kernel_page_shift)]
    arm_commpage_kernel_page_shift: Option<stela_runtime::commpage::KernelPageSize>,
    #[arg(long, requires = "memory", value_parser = parse_memory_query)]
    read_memory: Vec<MemoryQuery>,
    /// Replay this virtual-counter sample for clock reads.
    #[arg(long, requires = "software_pauth_context")]
    clock_snapshot: Option<PathBuf>,
    /// Explicitly declare legacy commpage kernel tracing disabled.
    #[arg(long, requires = "clock_snapshot")]
    disabled_kdebug: bool,
    /// Explicit opaque legacy DYLD_FLAGS for a process with hardware TPRO disabled.
    #[arg(long, requires = "clock_snapshot", value_parser = parse_address)]
    opaque_dyld_flags: Option<u64>,
}

/// Darwin trap services that `run-blocks` can own for the guest.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Service {
    /// Data-only mprotect of guest mappings.
    DataVm,
    /// The cross-architecture query, answered as unavailable.
    Crossarch,
    /// The shared-region query, answered as absent.
    AbsentSharedRegion,
    /// Host entropy copied into guest memory.
    Entropy,
    /// Mach VM protection of guest data pages.
    MachVm,
    /// Anonymous guest data allocation through Mach map calls.
    MachVmMap,
    /// Host Mach bootstrap rights behind guest port names.
    MachPorts,
    /// Current-host thread identity, Mach rights and guest TSD.
    Thread,
}

#[derive(Args)]
pub(crate) struct ProbeDyldEntry {
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
    /// Run the clock bootstrap until mach_continuous_time returns.
    #[arg(long, requires = "software_pauth_ib_key")]
    bootstrap_clock: bool,
    /// Explicit replay {counter,sleep_ticks}; otherwise use the validated Darwin host clock.
    #[arg(long, requires = "bootstrap_clock")]
    clock_snapshot: Option<PathBuf>,
}

impl RunLinkedImages {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
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
        } = self;
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
                discovery.graph.complete_dependency_graph || allow_unresolved_unused_dependencies,
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
                    macho::select_slice(&container, &path, architecture.as_deref())?;
                inputs.push(ImageInput {
                    data: slice.to_vec(),
                    container_sha256: stela_formats::sha256(&container),
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
        // SAFETY: the user vouches for the entry code and its ABI state. Every
        // image and the stack stay mapped while dispatch runs, and no pending
        // loader work is executed.
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
                "compiler_source_sha256":stela_compiler::SOURCE_SHA256,
                "complete_binary_verified":false
            }))?
        );
        Ok(())
    }
}

impl RunMappedImage {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
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
        } = self;
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
        let (slice_offset, bytes) = macho::select_slice(&data, &input, architecture.as_deref())?;
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
        // SAFETY: the user vouches for the entry code, its ABI state, and data
        // that needs no pending fixups or imports. The mappings stay alive
        // throughout dispatch.
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
            serde_json::to_string_pretty(&serde_json::json!({"kind":"mapped_macho_entry_probe",
            "container_sha256":stela_formats::sha256(&data),"slice_offset":slice_offset,"plan":image.plan(),
            "memory_regions":image.regions(),"guard_segments_not_reserved":image.unreserved_guards(),
            "fixups":image.fixups(),"image_base":image.fixups().load_base,"mapped_entry":image.mapped_entry(),
            "applied_rebases":image.fixups().rebases.len(),
            "host_execute":false,"stack":image.stack(),"initial_state":initial_state,
            "state":register_json(&thread.registers),"pc":thread.pc.0,"outcome":outcome,"memory":memory,
            "compiler_source_sha256":stela_compiler::SOURCE_SHA256,
            "complete_binary_verified":false}))?
        );
        Ok(())
    }
}

impl RunBlocks {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
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
            services,
            csr_active_configuration,
            guest_process_id,
            guest_vm_max_address,
            arm_commpage_kernel_page_shift,
            read_memory,
            clock_snapshot: clock_snapshot_path,
            disabled_kdebug,
            opaque_dyld_flags,
        } = self;
        use stela_runtime::blocks::{BlockRuntime, ThreadState};
        const ADDRESS_SPACE_ID: u64 = 1;
        let enabled = |service| services.contains(&service);
        let data_vm_services = enabled(Service::DataVm);
        let crossarch_services = enabled(Service::Crossarch);
        let absent_shared_region_services = enabled(Service::AbsentSharedRegion);
        let entropy_services = enabled(Service::Entropy);
        let mach_vm_services = enabled(Service::MachVm);
        let mach_vm_map_services = enabled(Service::MachVmMap);
        let mach_port_services = enabled(Service::MachPorts);
        let thread_services = enabled(Service::Thread);
        ensure!(
            !(mach_port_services && thread_services),
            "thread services own their Mach ports"
        );
        ensure!(
            thread_services || (guest_process_id.is_none() && guest_vm_max_address.is_none()),
            "guest process ID and VM maximum configure thread services"
        );
        ensure!(
            memory_path.is_some() || !(mach_vm_services || mach_vm_map_services),
            "Mach VM services require --memory"
        );
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
        let source_hash = stela_formats::sha256(&source);
        let context = if let Some(path) = software_pauth_keys.as_deref() {
            Some(pauth_all_keys_context(path, ADDRESS_SPACE_ID)?)
        } else {
            software_pauth_ib_key
                .as_deref()
                .map(|path| pauth_context(path, ADDRESS_SPACE_ID))
                .transpose()?
        };
        ensure!(
            !(mach_vm_services || mach_vm_map_services) || mach_port_services || thread_services,
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
        let mut mach_ports = mach_port_services
            .then(|| stela_runtime::mach::HostPorts::new(ADDRESS_SPACE_ID))
            .transpose()?;
        let mut thread_context = if thread_services {
            let maximum = stela_runtime::thread::VmMaximum::new(
                guest_vm_max_address
                    .context("thread services require explicit guest VM maximum")?,
            )?;
            Some(if let Some(pid) = guest_process_id {
                let process =
                    std::rc::Rc::new(stela_runtime::process::Context::new(ADDRESS_SPACE_ID, pid)?);
                stela_runtime::thread::Context::native_in_process(process, maximum)?
            } else {
                stela_runtime::thread::Context::native(ADDRESS_SPACE_ID, maximum)?
            })
        } else {
            None
        };
        let csr_policy = csr_active_configuration
            .map(stela_runtime::darwin::csr::ArmSecurityPolicy::new)
            .transpose()?;
        // SAFETY: this command runs caller-trusted code against its private
        // memory, registers and service contexts. Those resources remain
        // exclusively borrowed until dispatch and trap handling return.
        let service_run = unsafe {
            if !services.is_empty() || csr_policy.is_some() {
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
                        absent_shared_region: absent_shared_region_services,
                        mach_vm: mach_vm_services,
                        mach_vm_map: mach_vm_map_services,
                        csr: csr_policy.as_ref(),
                        entropy: entropy_services,
                        mach_ports: mach_ports.as_mut(),
                        thread: thread_context.as_mut(),
                        ..Default::default()
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
        let clock_report = clock.as_ref().map(|clock| -> Result<_> { Ok(serde_json::json!({
                "snapshot":clock.snapshot(),"events":clock.events(),"profile_id":clock.profile_id(),
                "source_id":clock.source_id(),"frequency":clock.frequency(),"region":clock.region(),
                "legacy_configuration":clock.legacy_configuration(),
                "legacy_commpage_profile":clock.legacy_configuration().profile_id(),
                "page_sha256":clock.snapshot_bytes(0, stela_runtime::clock::GUEST_BYTES).map(|bytes| stela_formats::sha256(&bytes))?
            })) }).transpose()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"kind":"native_block_run",
            "source_sha256":source_hash,"guest_base":guest_base,"pc":thread.pc.0,"state":register_json(&thread.registers),
            "outcome":service_run.execution,"abi":runtime.profile().abi(),"target_cpu":runtime.target_cpu().id(),"memory":memory_report,
            "mach_port_profile":(mach_port_services || thread_services).then_some(stela_runtime::mach::HOST_PORT_PROFILE),
            "mach_port_events":service_run.mach_services,"mach_port_rights":mach_ports.as_ref()
                .or_else(|| thread_context.as_ref().map(|thread| thread.ports())).map(|ports| ports.rights()),
            "thread_context":thread_context.as_ref().map(|context| context.snapshot()),
            "process_service_profile":thread_context.as_ref().and_then(|thread| thread.process())
                .map(|_| stela_runtime::process::PROFILE_ID),
            "process_service_events":service_run.process_services,
            "thread_service_events":service_run.thread_services,
            "crossarch_service_profile":crossarch_services.then_some(stela_runtime::darwin::crossarch::PROFILE_ID),
            "crossarch_service_events":service_run.crossarch_services,
            "shared_region_service_profile":absent_shared_region_services.then_some(stela_runtime::darwin::shared_region::PROFILE_ID),
            "shared_region_service_events":service_run.shared_region_services,
            "csr_service_profile":csr_policy.as_ref().map(|_| stela_runtime::darwin::csr::PROFILE_ID),
            "csr_active_configuration":csr_policy.as_ref().map(|policy| policy.active_configuration()),
            "csr_service_events":service_run.csr_services,
            "entropy_service_profile":entropy_services.then_some(stela_runtime::darwin::entropy::PROFILE_ID),
            "entropy_service_events":service_run.entropy_services,
            "mach_vm_service_profile":mach_vm_services.then_some(stela_runtime::darwin::mach_vm::PROFILE_ID),
            "mach_vm_service_events":service_run.mach_vm_services,
            "mach_vm_map_service_profile":mach_vm_map_services.then_some(stela_runtime::darwin::mach_vm::map::PROFILE_ID),
            "mach_vm_map_service_events":service_run.mach_vm_map_services,
            "page_size_commpage":commpage.as_ref().map(|page| -> Result<_> { Ok(serde_json::json!({
                "profile_id":page.profile_id(),"address_space":page.address_space(),
                "region":page.region(),"supported_fields":page.supported_fields(),
                "page_sha256":stela_formats::sha256(&page.snapshot_bytes()?)
            })) }).transpose()?,
            "data_vm_profile":data_vm_services.then_some(stela_runtime::darwin::DATA_VM_PROFILE),"data_vm_events":service_run.services,
            "software_pauth_profile":context.as_ref().map(|context| context.profile_id()),
            "clock":clock_report,
            "compiler_source_sha256":stela_compiler::SOURCE_SHA256,
            "complete_binary_verified":false}))?
        );
        Ok(())
    }
}

impl ProbeDyldEntry {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
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
        } = self;
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Cli, Command, execute::Service};
    use clap::Parser;

    #[test]
    fn services_parse_as_one_comma_separated_list() {
        let cli = Cli::try_parse_from([
            "stela",
            "run-blocks",
            "raw.bin",
            "--services",
            "thread,entropy",
            "--guest-process-id",
            "42",
        ])
        .unwrap();
        let Command::RunBlocks(crate::execute::RunBlocks {
            services,
            guest_process_id,
            ..
        }) = cli.command
        else {
            panic!("expected run-blocks command");
        };
        assert!(services == [Service::Thread, Service::Entropy]);
        assert_eq!(guest_process_id, Some(42));
        assert!(
            Cli::try_parse_from(["stela", "run-blocks", "raw.bin", "--services", "unknown"])
                .is_err()
        );
    }

    #[test]
    fn tracing_requires_clock_context() {
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
    }
}
