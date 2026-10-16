//! System mode, engine phase: runs in the Stela window after the loader has
//! switched to LA57. It never touches identity addresses again; host physical
//! memory is reached through the physmap.
mod host;
mod interrupts;

use crate::{
    console,
    handoff::{Handoff, MAGIC},
    layout, output,
};
use alloc::vec::Vec;
use core::{
    arch::x86_64::{__cpuid, __cpuid_count},
    sync::atomic::{AtomicU64, Ordering},
};
use host::{BareHost, Config, RamRange};
use stela_compiler::TargetCpu;
use stela_runtime::machine::{
    Cpu, CpuProfile, Event, Machine, NoDevices, Stop, exception::Pstate,
    registers::encodings::DCZID_EL0,
};

/// Apple T8112 DRAM base (Asahi Linux T8112 notes; the DeviceTree `/memory`).
const DRAM_BASE: u64 = 0x8_0000_0000;
const DEFAULT_RAM: u64 = 4 << 30;
const LARGE: u64 = 2 * 1024 * 1024;
/// Synchronous exceptions and returns logged before the log goes quiet;
/// interrupts are logged up to `REPORTED_INTERRUPTS`.
const REPORTED_EVENTS: u64 = 24;
const REPORTED_INTERRUPTS: u64 = 64;

struct Options {
    dram_base: u64,
    ram_bytes: u64,
    load: u64,
    entry: u64,
    x0: u64,
    budget: u64,
}

fn number(value: &str) -> Result<u64, &'static str> {
    match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(&hex.replace('_', ""), 16),
        None => value.parse(),
    }
    .map_err(|_| "invalid number in system options")
}

impl Options {
    fn parse(text: &str) -> Result<Self, &'static str> {
        let mut options = Self {
            dram_base: DRAM_BASE,
            ram_bytes: DEFAULT_RAM,
            load: DRAM_BASE,
            entry: DRAM_BASE,
            x0: 0,
            budget: 0,
        };
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some("--system") {
            return Err("system options must start with --system");
        }
        while let Some(name) = words.next() {
            let value = number(words.next().ok_or("missing system option value")?)?;
            match name {
                "--dram-base" => options.dram_base = value,
                "--ram-bytes" => options.ram_bytes = value,
                "--load" => options.load = value,
                "--entry" => options.entry = value,
                "--x0" => options.x0 = value,
                "--budget" => options.budget = value,
                _ => return Err("unknown system option"),
            }
        }
        if !options.dram_base.is_multiple_of(LARGE) || options.ram_bytes < LARGE {
            return Err("guest DRAM base must be 2 MiB aligned and hold at least 2 MiB");
        }
        Ok(options)
    }
}

/// The host CPU's compiler target, from CPUID.
fn target() -> TargetCpu {
    let (basic, extended) = (__cpuid(1), __cpuid_count(7, 0));
    let (ssse3, sse41, sse42) = (
        basic.ecx & (1 << 9) != 0,
        basic.ecx & (1 << 19) != 0,
        basic.ecx & (1 << 20) != 0,
    );
    let mut target = match (ssse3, sse41, sse42) {
        (true, true, true) => TargetCpu::Sse42,
        (true, true, false) => TargetCpu::Sse41,
        (true, false, _) => TargetCpu::Ssse3,
        _ => TargetCpu::Baseline,
    };
    for (present, with) in [
        (
            basic.ecx & (1 << 1) != 0,
            TargetCpu::with_pclmulqdq as fn(_) -> _,
        ),
        (basic.ecx & (1 << 23) != 0, TargetCpu::with_popcnt),
        (basic.ecx & (1 << 25) != 0, TargetCpu::with_aes),
        (basic.ecx & (1 << 13) != 0, TargetCpu::with_cx16),
        (basic.edx & (1 << 8) != 0, TargetCpu::with_cx8),
        // 16-byte SSE loads are atomic on CPUs that implement AVX.
        (basic.ecx & (1 << 28) != 0, TargetCpu::with_atomic_load16),
        (extended.ebx & (1 << 3) != 0, TargetCpu::with_bmi1),
        (extended.ebx & (1 << 29) != 0, TargetCpu::with_sha),
    ] {
        if present {
            target = with(target);
        }
    }
    target
}

/// Assign guest DRAM from the free host ranges, lowest first.
fn guest_ram(handoff: &Handoff, options: &Options) -> Result<Vec<RamRange>, &'static str> {
    let mut ranges = Vec::new();
    let mut assigned = 0;
    for region in &handoff.guest[..handoff.guest_count] {
        if assigned == options.ram_bytes {
            break;
        }
        let bytes = region.bytes.min(options.ram_bytes - assigned);
        ranges.push(RamRange {
            guest: options.dram_base + assigned,
            host: region.physical,
            bytes,
        });
        assigned += bytes;
    }
    if assigned < options.ram_bytes {
        output::arguments(format_args!(
            "guest DRAM requested={:#x} available={assigned:#x}\n",
            options.ram_bytes
        ));
        return Err("not enough free host RAM for the requested guest DRAM");
    }
    Ok(ranges)
}

fn profile() -> CpuProfile {
    CpuProfile {
        // Stela's own test kernel reads no identification register; DC ZVA
        // block size follows the architecture's 64-byte example value.
        name: "stela-test-kernel",
        counter_frequency: 24_000_000,
        fixed: alloc::vec![(DCZID_EL0, 4)],
    }
}

static EVENTS: AtomicU64 = AtomicU64::new(0);
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn report(event: &Event) {
    let count = EVENTS.fetch_add(1, Ordering::Relaxed);
    let interrupt = matches!(
        event,
        Event::Exception { vector, .. } if *vector != stela_runtime::machine::exception::Vector::Synchronous
    );
    let quiet = if interrupt {
        INTERRUPTS.fetch_add(1, Ordering::Relaxed) >= REPORTED_INTERRUPTS
    } else {
        count >= REPORTED_EVENTS
    };
    if quiet {
        return;
    }
    match event {
        Event::Exception {
            vector,
            from_el,
            syndrome,
            return_address,
            fault_address,
        } => output::arguments(format_args!(
            "EXCEPTION {vector:?} from=EL{from_el} esr={syndrome:#x} elr={return_address:#x} far={}\n",
            match fault_address {
                Some(address) => alloc::format!("{address:#x}"),
                None => "-".into(),
            }
        )),
        Event::Return { to_el, pc } => {
            output::arguments(format_args!("ERET to=EL{to_el} pc={pc:#x}\n"))
        }
    }
}

/// Engine-phase entry, called by the loader on the window stack.
pub extern "sysv64" fn entry(handoff: u64) -> ! {
    // SAFETY: the first engine code; interrupts are off and nothing else runs.
    unsafe { interrupts::install() };
    // SAFETY: the loader wrote the handoff page and passed its physmap address.
    let handoff = unsafe { &*(handoff as *const Handoff) };
    if handoff.magic != MAGIC {
        output::fatal("engine handoff has the wrong magic");
    }
    // SAFETY: the window heap is reserved for this allocator and still unused.
    unsafe { crate::ALLOCATOR.initialize(layout::HEAP as *mut u8, handoff.heap.bytes as usize) };
    if let Some(screen) = handoff.screen {
        console::install(screen.relocated(layout::physical(screen.base as u64) as usize));
    }
    output::arguments(format_args!(
        "STELA SYSTEM ENGINE window={:#x} tsc_hz={} guest_ranges={}\n",
        layout::WINDOW,
        handoff.tsc_hz,
        handoff.guest_count
    ));
    // SAFETY: the options were left allocated by the loader.
    let text = unsafe {
        core::slice::from_raw_parts(
            layout::physical(handoff.options.physical) as *const u8,
            handoff.options.bytes as usize,
        )
    };
    let options = match core::str::from_utf8(text)
        .map_err(|_| "stela.cfg is not UTF-8")
        .and_then(Options::parse)
    {
        Ok(options) => options,
        Err(error) => output::fatal(error),
    };
    let ram = match guest_ram(handoff, &options) {
        Ok(ram) => ram,
        Err(error) => output::fatal(error),
    };
    for range in &ram {
        output::arguments(format_args!(
            "GUEST DRAM pa={:#x} bytes={:#x} host={:#x}\n",
            range.guest, range.bytes, range.host
        ));
    }
    let config = Config {
        ram,
        pool_physical: handoff.pool.physical,
        pool_bytes: handoff.pool.bytes,
        window: handoff.window,
        code_physical: handoff.code.physical,
        code_bytes: handoff.code.bytes,
        tsc_hz: handoff.tsc_hz,
        apic_base: handoff.apic_base,
    };
    // SAFETY: once, with interrupts off.
    if let Err(error) = unsafe { host::install(config) } {
        output::fatal(error);
    }
    let (_, _, _, apic_hz) = host::statistics();
    // SAFETY: the guest image was left allocated by the loader.
    let source = unsafe {
        core::slice::from_raw_parts(
            layout::physical(handoff.source.physical) as *const u8,
            handoff.source.bytes as usize,
        )
    };
    let mut bare = BareHost;
    if !stela_runtime::machine::Host::write_ram(&mut bare, options.load, source) {
        output::fatal("guest image does not fit guest DRAM at its load address");
    }
    let target = target();
    output::arguments(format_args!(
        "GUEST IMAGE pa={:#x} bytes={} sha256={} entry={:#x} x0={:#x} target={} apic_hz={apic_hz}\n",
        options.load,
        source.len(),
        stela_runtime::sha256(source),
        options.entry,
        options.x0,
        target.id(),
    ));
    let mut cpu = Cpu::new(options.entry, Pstate::RESET_EL1);
    cpu.state.x[0] = options.x0;
    let mut machine = Machine::new(cpu, bare, NoDevices, profile(), target);
    let started = host::rdtsc();
    let stop = machine.run(options.budget);
    let seconds = (host::rdtsc() - started) as f64 / handoff.tsc_hz as f64;
    finish(&machine, stop, seconds)
}

fn finish(machine: &Machine<BareHost, NoDevices>, stop: Stop, seconds: f64) -> ! {
    let cpu = &machine.cpu;
    let (fills, resets, stray, _) = host::statistics();
    output::arguments(format_args!(
        "STATISTICS {:?} shadow_fills={fills} shadow_resets={resets} stray_interrupts={stray} events={} seconds={seconds:.3}\n",
        machine.statistics,
        EVENTS.load(Ordering::Relaxed),
    ));
    output::arguments(format_args!(
        "FINAL pc={:#x} el={} sp={:#x} daif={:#x} nzcv={:#x} elr={:#x} spsr={:#x} esr={:#x} far={:#x} vbar={:#x}\n",
        cpu.pc,
        cpu.pstate.el,
        cpu.state.sp,
        cpu.pstate.daif,
        cpu.state.nzcv,
        cpu.system.elr,
        cpu.system.spsr,
        cpu.system.esr,
        cpu.system.far,
        cpu.system.vbar,
    ));
    for (index, pair) in cpu.state.x.chunks(4).enumerate() {
        output::arguments(format_args!("X{}:", index * 4));
        for value in pair {
            output::arguments(format_args!(" {value:#018x}"));
        }
        output::arguments(format_args!("\n"));
    }
    match stop {
        Stop::Idle => {
            output::arguments(format_args!("STOP idle: WFI with no wake source\n"));
            output::terminate(0x10)
        }
        Stop::Budget => {
            output::arguments(format_args!("STOP budget\n"));
            output::terminate(0x14)
        }
        Stop::Unsupported(requirement) => {
            output::arguments(format_args!("STOP UNSUPPORTED {requirement}\n"));
            output::terminate(0x13)
        }
    }
}
