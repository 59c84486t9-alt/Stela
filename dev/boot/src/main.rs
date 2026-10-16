//! Bounded x86-QEMU development mount of the real shared compiler/runtime.
//! Original ARM bytes arrive as a loader module; the canonical SoftwareEl1Machine
//! owns RAM, source, PE, compilation/cache, NativeImage and precise settlement.
//! A component stop is not installation, intact macOS boot or platform closure.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::{vec, vec::Vec};
use core::{arch::global_asm, cell::UnsafeCell, fmt::Write, panic::PanicInfo};
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
mod heap;
mod multiboot;
mod paging;
mod serial;
global_asm!(include_str!("entry.S"), options(att_syntax));
#[global_allocator]
static ALLOCATOR: heap::Heap = heap::Heap::new();
const HEAP_BYTES: usize = 64 * 1024 * 1024;
#[repr(align(4096))]
struct HeapStorage(UnsafeCell<[u8; HEAP_BYTES]>);
// SAFETY: no access outside once-only BSP heap initialization and the real
// allocator's mutually exclusive raw extent ownership. No shared byte refs exist.
unsafe impl Sync for HeapStorage {}
static HEAP: HeapStorage = HeapStorage(UnsafeCell::new([0; HEAP_BYTES]));

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
        let mut arguments = command.split_ascii_whitespace().peekable();
        // QEMU's Multiboot transport prefixes its kernel filename. It selects
        // no runtime behavior and is not a source/application identity key.
        if arguments.peek().is_some_and(|v| !v.starts_with("--")) {
            arguments.next();
        }
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
#[unsafe(no_mangle)]
pub extern "C" fn stela_boot_main(address: u32, magic: u32) -> ! {
    serial::initialize();
    paging::fatal_interrupts();
    serial::arguments(format_args!("STELA DEVELOPMENT MOUNT entry={magic:08x}\n"));
    // SAFETY: this entry is reached only through our trusted Multiboot bootstrap.
    let transport = match unsafe { multiboot::Transport::read(address, magic) } {
        Ok(value) => value,
        Err(error) => serial::fatal(error),
    };
    serial::arguments(format_args!("ACTUAL TRANSPORT {transport:?}\n"));
    if let Err(error) = unsafe { paging::install(&transport) } {
        serial::fatal(error);
    }
    // SAFETY: final supervisor RW+NX image mapping owns this full static heap;
    // BSP/IF/fatal NMI/SMI-off/nonmigration obligations precede every allocation.
    unsafe {
        ALLOCATOR.initialize(HEAP.0.get().cast::<u8>(), HEAP_BYTES);
    }
    serial::arguments(format_args!(
        "ACTUAL HEAP base={:#x} bytes={} native={:?} ram={:?}\n",
        HEAP.0.get() as usize,
        HEAP_BYTES,
        paging::native_arenas(),
        paging::ram_arenas()
    ));
    let observed = match unsafe {
        stela_runtime::freestanding::install(&paging::native_arenas(), &paging::ram_arenas())
    } {
        Ok(value) => value,
        Err(error) => {
            serial::arguments(format_args!("mount refusal: {error:?}\n"));
            serial::fatal("actual platform qualification failed")
        }
    };
    serial::arguments(format_args!("ACTUAL CPU {observed:?}\n"));
    let options = match transport.command().and_then(Options::parse) {
        Ok(v) => v,
        Err(e) => serial::fatal(e),
    };
    let original = transport.source();
    if original.len() as u64 > options.region_bytes {
        serial::fatal("original module exceeds declared RAM region");
    }
    let source_hash = stela_core::sha256(original);
    serial::arguments(format_args!(
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
                serial::arguments(format_args!("system declaration refusal: {e:?}\n"));
                serial::fatal("invalid initial system")
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
    serial::arguments(format_args!(
        "INITIAL ARCHITECTURAL THREAD {:?}\nINITIAL SYSTEM {:?}\nINITIAL TRANSLATION {:?}\n",
        config.thread, config.system, config.translation
    ));
    let machine = match SoftwareEl1Machine::new_with_regions(config, zeroed, vec![region]) {
        Ok(v) => v,
        Err(e) => {
            serial::arguments(format_args!("machine refusal: {e:?}\n"));
            serial::fatal("original machine construction failed")
        }
    };
    let result = machine.run_to_shutdown(SoftwareEl1Request {
        stop_pc: options.stop.map(GuestAddress),
        block_budget: options.budget,
    });
    let report = match result {
        Ok(v) => v,
        Err(e) => {
            serial::arguments(format_args!("canonical run failure: {e:?}\n"));
            serial::fatal("original runtime declined or poisoned")
        }
    };
    serial::arguments(format_args!(
        "RESULT stop={} pc={:#x} x0={:#x} x1={:#x} x2={:#x} compiler={} accounting={:?}\n",
        report.stop,
        report.thread.pc.0,
        report.thread.registers.x[0],
        report.thread.registers.x[1],
        report.thread.registers.x[2],
        report.compiler_source_sha256,
        report.accounting
    ));
    serial::arguments(format_args!(
        "FINAL ARCHITECTURAL THREAD {:?}\nFINAL SYSTEM {:?}\nFINAL TRANSLATION {:?}\nDECLARED CAPACITY {:?}\n",
        report.thread, report.system, report.translation, report.declared_capacity
    ));
    for region in &report.initialized_ram {
        serial::arguments(format_args!(
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
            serial::arguments(format_args!("{name} OBSERVATION {value}\n"));
        }
    }
    for artifact in &report.resident_artifacts {
        match serde_json::to_string(artifact) {
            Ok(json) => serial::arguments(format_args!("RESIDENT STANDARD MANIFEST {json}\n")),
            Err(e) => {
                serial::arguments(format_args!("manifest output refusal: {e}\n"));
                serial::fatal("standard manifest serialization failed")
            }
        }
    }
    if let Some(value) = &report.register_observation {
        serial::arguments(format_args!("REGISTER OBSERVATION {value}\n"));
    }
    if let Some(value) = &report.memory_write_observation {
        serial::arguments(format_args!("WRITE OBSERVATION {value}\n"));
    }
    if let Some(value) = &report.memory_pair_read_observation {
        serial::arguments(format_args!("PAIR OBSERVATION {value}\n"));
    }
    for range in &report.ram {
        serial::arguments(format_args!(
            "RAM pa={:#x} bytes={} actual_sha256={:?}\n",
            range.source_pa, range.bytes, range.sha256
        ));
    }
    match stela_runtime::freestanding::verify() {
        Ok(observed) => serial::arguments(format_args!(
            "POST SHUTDOWN ACTUAL CPU/STORAGE {observed:?}\n"
        )),
        Err(error) => {
            serial::arguments(format_args!("post-shutdown storage failure: {error:?}\n"));
            serial::fatal("actual storage retirement or controls failed")
        }
    }
    if matches!(report.accounting.reason, StopReason::StopAddress)
        && report.accounting.blocks_executed > 0
        && report.accounting.compiled_blocks > 0
        && !report.resident_artifacts.is_empty()
    {
        serial::arguments(format_args!(
            "STELA NATIVE COMPONENT REACHED REQUESTED STOP; MACOS BOOT/INSTALLATION UNVERIFIED\n"
        ));
        serial::terminate(0x10)
    }
    serial::fatal("requested native component completion was not reached")
}
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // No allocator, formatting of caller-supplied values, Rust lock, unwind,
    // poison recovery or continuation is allowed on this terminal path.
    let _ = serial::Serial.write_str("\nSTELA PANIC");
    if let Some(location) = info.location() {
        let _ = serial::Serial.write_str(" ");
        let _ = serial::Serial.write_str(location.file());
    }
    let _ = serial::Serial.write_str("\n");
    serial::terminate(0x11)
}
