//! UEFI application that runs an ARM image on the shared compiler and runtime.
//!
//! The firmware, or a boot manager such as OpenCore, starts `stela.efi`. It
//! reads `\EFI\stela\stela.cfg` and the original ARM bytes in
//! `\EFI\stela\source.bin` from its own volume, leaves boot services,
//! installs its own page tables and runs the image on `SoftwareEl1Machine`.
//! A `stela.cfg` that starts with `--system` instead runs the image on the
//! system-mode engine (`docs/design/system.md#system-mode-execution`).
//! With `\EFI\stela\choices.cfg` beside it, the startup choices (`choice`)
//! pick the option line first.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::{vec, vec::Vec};
use core::{arch::asm, panic::PanicInfo};
use stela_compiler::{GuestAddress, GuestState, TargetCpu};
use stela_runtime::{
    blocks::{
        InitializedRamRegion, PhysicalRamRange, SoftwareEl1Config, SoftwareEl1Machine,
        SoftwareEl1Profile, SoftwareEl1Request, SourceRamDeclaration, SourceRamPermissions,
        StopReason, ThreadState, ZeroedRamExtent,
    },
    system::{
        state::{El1Registers, PSTATE_EL1H, SystemState},
        translation_controls::RegisterValues,
    },
};
use uefi::{
    Status,
    boot::{AllocateType, MemoryType},
};
mod choice;
mod console;
mod engine;
mod firmware;
mod handoff;
mod heap;
mod la57;
mod layout;
mod output;
mod paging;
mod payload;
mod selection;
mod serial;
mod storage;
mod system;
mod tables;
#[global_allocator]
pub(crate) static ALLOCATOR: heap::Heap = heap::Heap::new();
/// Large enough for a J473AP boot bundle (about 135 MB) read whole.
const HEAP_BYTES: usize = 384 * 1024 * 1024;
/// What this build reads, for `stela setup` to check before installing it
/// (`stela_loader::mount_interface`).
#[used]
static MOUNT_INTERFACE: [u8; stela_loader::mount_interface::MARKER_BYTES] =
    stela_loader::mount_interface::marker(stela_loader::mount_interface::CURRENT);

#[derive(Debug)]
struct Options {
    source_pa: u64,
    region_bytes: u64,
    entry: u64,
    stop: Option<u64>,
    budget: usize,
    x: [u64; 31],
    sp: u64,
    address_space: u64,
    pstate: u64,
    sp_el0: u64,
    elr: Option<u64>,
    spsr: Option<u64>,
    sctlr: u64,
    zero_pa: Option<u64>,
    zero_bytes: Option<u64>,
    zero_capacity: Option<u64>,
}
fn number(value: &str) -> Result<u64, &'static str> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| "invalid hex option")
    } else {
        value.parse().map_err(|_| "invalid decimal option")
    }
}
impl Options {
    fn parse(command: &str) -> Result<Self, &'static str> {
        let mut options = Self {
            source_pa: 0x100000,
            region_bytes: 0x100000,
            entry: 0x100000,
            stop: None,
            budget: 64,
            x: [0; 31],
            sp: 0,
            address_space: 1,
            pstate: PSTATE_EL1H | stela_runtime::system::pstate::DAIF_MASK,
            sp_el0: 0,
            elr: None,
            spsr: None,
            sctlr: 0,
            zero_pa: None,
            zero_bytes: None,
            zero_capacity: None,
        };
        let mut arguments = command.split_ascii_whitespace();
        while let Some(name) = arguments.next() {
            let value = number(arguments.next().ok_or("missing boot option value")?)?;
            match name {
                "--source-pa" => options.source_pa = value,
                "--sp" => options.sp = value,
                "--address-space" => options.address_space = value,
                "--pstate" => options.pstate = value,
                "--sp-el0" => options.sp_el0 = value,
                "--elr" => options.elr = Some(value),
                "--spsr" => options.spsr = Some(value),
                "--sctlr" => options.sctlr = value,
                "--zero-pa" => options.zero_pa = Some(value),
                "--zero-bytes" => options.zero_bytes = Some(value),
                "--zero-capacity" => options.zero_capacity = Some(value),
                "--region-bytes" => options.region_bytes = value,
                "--entry" => options.entry = value,
                "--stop" => options.stop = Some(value),
                "--budget" => {
                    options.budget = usize::try_from(value).map_err(|_| "budget overflow")?
                }
                register if register.starts_with("--x") => {
                    let index: usize = register[3..]
                        .parse()
                        .map_err(|_| "invalid initial register")?;
                    *options
                        .x
                        .get_mut(index)
                        .ok_or("initial register outside X0-X30")? = value;
                }
                _ => return Err("unknown boot option"),
            }
        }
        if options.budget == 0
            || options.budget > 1_000_000
            || options.region_bytes < 16
            || options
                .source_pa
                .checked_add(options.region_bytes)
                .is_none()
            || !options.entry.is_multiple_of(4)
        {
            return Err("invalid bounded initial machine declaration");
        }
        match (options.zero_pa, options.zero_bytes, options.zero_capacity) {
            (None, None, None) => {}
            (Some(pa), Some(bytes), Some(capacity))
                if bytes != 0 && bytes <= capacity && pa.checked_add(capacity).is_some() => {}
            _ => return Err("incomplete or invalid explicit zero RAM declaration"),
        }
        Ok(options)
    }
}
#[uefi::entry]
fn main() -> Status {
    // Before any Rust state exists: the system engine runs from this copy.
    system::take_snapshot();
    // Referenced, so the linker keeps the marker setup reads.
    core::hint::black_box(&MOUNT_INTERFACE);
    serial::initialize();
    output::arguments(format_args!("STELA UEFI MOUNT\n"));
    let heap = uefi::boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        HEAP_BYTES / paging::PAGE,
    )
    .unwrap_or_else(|_| output::fatal("firmware has no memory for the heap"));
    // SAFETY: fresh LOADER_DATA pages that Stela owns for the whole boot,
    // initialized before any allocation.
    unsafe { ALLOCATOR.initialize(heap.as_ptr(), HEAP_BYTES) };
    let mut volume = firmware::volume().unwrap_or_else(|e| output::fatal(e));
    let options = firmware::options(&mut volume).unwrap_or_else(|e| output::fatal(e));
    let options = choice::choose(&mut volume, options);
    if options.starts_with(b"--system") {
        system::boot(options, volume);
    }
    // Install mode needs no ARM image; `take_over` checks it is present.
    let source = firmware::source(&mut volume).ok();
    drop(volume);
    let (mut handoff, tables) =
        firmware::take_over(options, source).unwrap_or_else(|e| output::fatal(e));
    if let Some(screen) = handoff.screen {
        console::install(screen);
        output::arguments(format_args!("STELA UEFI MOUNT\n"));
    }
    // SAFETY: boot services have ended; the new tables map the image, heap,
    // both stacks and every RAM byte in use.
    unsafe {
        asm!("cli", options(nomem, nostack));
        if let Err(error) = paging::activate(tables) {
            output::fatal(error);
        }
        asm!(
            "mov rsp, {top}",
            "call {run}",
            "ud2",
            top = in(reg) handoff.stack_top,
            run = sym run,
            in("rdi") &raw mut handoff,
            options(noreturn),
        )
    }
}

/// Run the mount on Stela's own stack.
extern "sysv64" fn run(handoff: &mut firmware::Handoff) -> ! {
    output::arguments(format_args!(
        "ACTUAL HEAP bytes={HEAP_BYTES} native={:?} ram={:?}\n",
        handoff.native, handoff.ram
    ));
    // SAFETY: one CPU with interrupts disabled; the arenas are reserved RAM
    // under Stela's own tables, disjoint from everything else in use.
    let observed =
        match unsafe { stela_runtime::freestanding::install(&handoff.native, &handoff.ram) } {
            Ok(value) => value,
            Err(error) => {
                output::arguments(format_args!("mount refusal: {error:?}\n"));
                output::fatal("platform qualification failed")
            }
        };
    output::arguments(format_args!("ACTUAL CPU {observed:?}\n"));
    if let Some(storage) = handoff.storage.take() {
        storage.run();
    }
    let options = match core::str::from_utf8(&handoff.options)
        .map_err(|_| "stela.cfg is not UTF-8")
        .and_then(storage::split)
        .and_then(|(_, _, rest)| Options::parse(&rest))
    {
        Ok(v) => v,
        Err(e) => output::fatal(e),
    };
    let original = &handoff.source[..];
    if original.len() as u64 > options.region_bytes {
        output::fatal("original module exceeds declared RAM region");
    }
    let source_hash = stela_runtime::sha256(original);
    output::arguments(format_args!(
        "SOURCE bytes={} sha256={} options={options:?}\n",
        original.len(),
        source_hash
    ));
    let mut registers = GuestState {
        sp: options.sp,
        ..Default::default()
    };
    registers.x = options.x;
    let mut declared_capacity = vec![PhysicalRamRange {
        source_pa: options.source_pa,
        bytes: options.region_bytes,
    }];
    let mut zeroed = Vec::new();
    if let (Some(pa), Some(bytes), Some(capacity)) =
        (options.zero_pa, options.zero_bytes, options.zero_capacity)
    {
        declared_capacity.push(PhysicalRamRange {
            source_pa: pa,
            bytes: capacity,
        });
        zeroed.push(ZeroedRamExtent {
            source_pa: pa,
            bytes,
            permissions: SourceRamPermissions {
                readable: true,
                writable: true,
                executable: false,
            },
        });
    }
    let config = SoftwareEl1Config {
        profile: SoftwareEl1Profile::PlatformV1,
        ram: SourceRamDeclaration {
            address_space: options.address_space,
            target: TargetCpu::Baseline,
            declared_capacity,
            initialized: Vec::new(),
        },
        thread: ThreadState {
            pc: GuestAddress(options.entry),
            registers,
        },
        system: match SystemState::new(
            options.pstate,
            options.sp_el0,
            El1Registers::new(
                options.elr.unwrap_or(options.entry),
                options.spsr.unwrap_or(options.pstate),
                0,
                0,
                0,
            ),
        ) {
            Ok(v) => v,
            Err(e) => {
                output::arguments(format_args!("system declaration refusal: {e:?}\n"));
                output::fatal("invalid initial system")
            }
        },
        translation: RegisterValues {
            sctlr_el1: options.sctlr,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            mair_el1: 0,
        },
    };
    let region = InitializedRamRegion {
        range: PhysicalRamRange {
            source_pa: options.source_pa,
            bytes: options.region_bytes,
        },
        file_prefix: original.to_vec(),
        file_sha256: source_hash,
        permissions: SourceRamPermissions {
            readable: true,
            writable: true,
            executable: true,
        },
    };
    output::arguments(format_args!(
        "INITIAL ARCHITECTURAL THREAD {:?}\nINITIAL SYSTEM {:?}\nINITIAL TRANSLATION {:?}\n",
        config.thread, config.system, config.translation
    ));
    let machine = match SoftwareEl1Machine::new_with_regions(config, zeroed, vec![region]) {
        Ok(v) => v,
        Err(e) => {
            output::arguments(format_args!("machine refusal: {e:?}\n"));
            output::fatal("original machine construction failed")
        }
    };
    let result = machine.run_to_shutdown(SoftwareEl1Request {
        stop_pc: options.stop.map(GuestAddress),
        block_budget: options.budget,
    });
    let report = match result {
        Ok(v) => v,
        Err(e) => {
            output::arguments(format_args!("canonical run failure: {e:?}\n"));
            output::fatal("original runtime declined or poisoned")
        }
    };
    output::arguments(format_args!(
        "RESULT stop={} pc={:#x} x0={:#x} x1={:#x} x2={:#x} compiler={} accounting={:?}\n",
        report.stop,
        report.thread.pc.0,
        report.thread.registers.x[0],
        report.thread.registers.x[1],
        report.thread.registers.x[2],
        report.compiler_source_sha256,
        report.accounting
    ));
    output::arguments(format_args!(
        "FINAL ARCHITECTURAL THREAD {:?}\nFINAL SYSTEM {:?}\nFINAL TRANSLATION {:?}\nDECLARED CAPACITY {:?}\n",
        report.thread, report.system, report.translation, report.declared_capacity
    ));
    for region in &report.initialized_ram {
        output::arguments(format_args!(
            "INITIAL RAM range={:?} permissions={:?} sha256={} zero={} prefix={:?}\n",
            region.range,
            region.permissions,
            region.sha256,
            region.zero_initialized,
            region.file_prefix
        ));
    }
    for (name, observation) in [
        ("NATIVE", &report.native_observation),
        ("MEMORY", &report.memory_observation),
        ("SYSTEM", &report.system_observation),
        ("SYSTEM EFFECT", &report.system_effect_observation),
        ("CONTEXT", &report.context_observation),
    ] {
        if let Some(value) = observation {
            output::arguments(format_args!("{name} OBSERVATION {value}\n"));
        }
    }
    for artifact in &report.resident_artifacts {
        match serde_json::to_string(artifact) {
            Ok(json) => output::arguments(format_args!("RESIDENT STANDARD MANIFEST {json}\n")),
            Err(e) => {
                output::arguments(format_args!("manifest output refusal: {e}\n"));
                output::fatal("standard manifest serialization failed")
            }
        }
    }
    if let Some(value) = &report.register_observation {
        output::arguments(format_args!("REGISTER OBSERVATION {value}\n"));
    }
    if let Some(value) = &report.memory_write_observation {
        output::arguments(format_args!("WRITE OBSERVATION {value}\n"));
    }
    if let Some(value) = &report.memory_pair_read_observation {
        output::arguments(format_args!("PAIR OBSERVATION {value}\n"));
    }
    for range in &report.ram {
        output::arguments(format_args!(
            "RAM pa={:#x} bytes={} actual_sha256={:?}\n",
            range.source_pa, range.bytes, range.sha256
        ));
    }
    match stela_runtime::freestanding::verify() {
        Ok(observed) => output::arguments(format_args!(
            "POST SHUTDOWN ACTUAL CPU/STORAGE {observed:?}\n"
        )),
        Err(error) => {
            output::arguments(format_args!("post-shutdown storage failure: {error:?}\n"));
            output::fatal("storage retirement or controls failed")
        }
    }
    if matches!(report.accounting.reason, StopReason::StopAddress)
        && report.accounting.blocks_executed > 0
        && report.accounting.compiled_blocks > 0
        && !report.resident_artifacts.is_empty()
    {
        output::arguments(format_args!(
            "STELA NATIVE COMPONENT REACHED REQUESTED STOP; MACOS BOOT/INSTALLATION UNVERIFIED\n"
        ));
        output::terminate(0x10)
    }
    output::fatal("requested native component completion was not reached")
}
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // No allocator, formatting of caller-supplied values, Rust lock, unwind,
    // poison recovery or continuation is allowed on this terminal path.
    output::panic(info)
}
