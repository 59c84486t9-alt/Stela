//! System mode, engine phase: runs in the Stela window after the loader has
//! switched to LA57. Host physical memory is reached through the physmap.
//! The one use of identity addresses is `--preboot`: before the host is
//! installed, Stela's storage drivers, which address registers and DMA pages
//! by identity, read the installed system from the disk through the
//! loader's identity map and its uncached device mappings.

pub(crate) mod bundle;
mod display;
mod host;
mod interrupts;

use crate::{
    console,
    handoff::{Handoff, MAGIC},
    layout, output,
};
use alloc::{string::String, vec::Vec};
use core::{
    arch::x86_64::{__cpuid, __cpuid_count},
    sync::atomic::{AtomicU64, Ordering},
};
use host::{BareHost, Config, RamRange};
use stela_compiler::TargetCpu;
use stela_runtime::machine::{
    Chip, Cpu, CpuProfile, Event, Machine, Stop,
    apple::{AicInput, AicLayout, AppleDevices, ConsoleBusy, ConsoleSink, Range},
    exception::Pstate,
    registers::encodings::DCZID_EL0,
    soc,
    system::Register,
};
use stela_runtime::pc::storage::Target;

/// Apple T8112 DRAM base (Asahi Linux T8112 notes; the DeviceTree `/memory`).
const DRAM_BASE: u64 = 0x8_0000_0000;
const DEFAULT_RAM: u64 = 4 << 30;
const LARGE: u64 = 2 * 1024 * 1024;
/// Synchronous exceptions and returns logged before the log goes quiet;
/// interrupts are logged up to `REPORTED_INTERRUPTS`. A guarded level's
/// synchronous exceptions other than SVC, which its monitor otherwise
/// handles without a trace, are always logged.
const REPORTED_EVENTS: u64 = 24;
const REPORTED_INTERRUPTS: u64 = 64;
const ESR_EC_SHIFT: u32 = 26;
/// ESR EC of an SVC from AArch64 state.
const EC_SVC64: u64 = 0x15;

struct Options {
    dram_base: u64,
    /// `--dram-base` was given; otherwise a bundle's own base applies.
    dram_explicit: bool,
    ram_bytes: u64,
    load: u64,
    entry: u64,
    x0: u64,
    budget: u64,
    /// Load the boot bundle the loader read instead of `source.bin`.
    bundle: bool,
    /// Build the boot bundle from the installed system on this APFS
    /// partition instead (`SERIAL:GUID`).
    preboot: Option<Target>,
    /// Answer device accesses no model implements and list them
    /// (`Machine::begin_survey`): research runs only.
    survey: bool,
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
            dram_explicit: false,
            ram_bytes: DEFAULT_RAM,
            load: DRAM_BASE,
            entry: DRAM_BASE,
            x0: 0,
            budget: 0,
            bundle: false,
            preboot: None,
            survey: false,
        };
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some("--system") {
            return Err("system options must start with --system");
        }
        while let Some(name) = words.next() {
            if name == "--bundle" {
                words.next().ok_or("missing bundle directory")?;
                options.bundle = true;
                continue;
            }
            if name == "--survey" {
                options.survey = true;
                continue;
            }
            if name == "--preboot" {
                let target = words.next().ok_or("missing Preboot disk")?;
                options.preboot = Some(target.parse()?);
                options.bundle = true;
                continue;
            }
            let value = number(words.next().ok_or("missing system option value")?)?;
            match name {
                "--dram-base" => {
                    options.dram_base = value;
                    options.dram_explicit = true;
                }
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

/// Stela's own test kernel reads no identification register; its DC ZVA
/// block is Stela's choice of 64 bytes.
fn test_profile() -> CpuProfile {
    CpuProfile {
        name: "stela-test-kernel",
        chip: Chip::DEFAULT,
        counter_frequency: 24_000_000,
        fixed: alloc::vec![(DCZID_EL0, 4)],
        processors: Vec::new(),
    }
}

/// The profile of the board the bundle's DeviceTree describes
/// (`machine::soc::board`), with cpu0 running with EL2 as a VHE host. The
/// ID_AA64* and CTR_EL0 registers advertise what this engine implements,
/// capped at the chip's features (`machine::identification`); MIDR, MPIDR and
/// DCZID are the board's own values. Every other identification read refuses.
fn board_profile(board: &soc::Board, target: TargetCpu) -> CpuProfile {
    let chip = board.cpus.chip;
    let mut fixed = stela_runtime::machine::identification::derive(chip, target, true);
    // 64-byte DC ZVA blocks, enabled: XNU `osfmk/arm64/bzero.s` zeroes with
    // `dc zva` in fixed 64-byte steps.
    fixed.push((DCZID_EL0, 4));
    CpuProfile {
        name: chip.name(),
        chip,
        counter_frequency: 24_000_000,
        fixed,
        processors: board.cpus.processors.clone(),
    }
}

/// The guest's console UART, shown line by line as `GUEST| ...`.
#[derive(Default)]
struct GuestConsole(Vec<u8>);

impl ConsoleSink for GuestConsole {
    fn transmit(&mut self, byte: u8) -> Result<(), ConsoleBusy> {
        if byte == b'\n' || self.0.len() == 200 {
            output::arguments(format_args!(
                "GUEST| {}\n",
                String::from_utf8_lossy(&self.0)
            ));
            self.0.clear();
        } else if byte != b'\r' {
            self.0.push(byte);
        }
        Ok(())
    }
}

/// J473AP placement from Apple's DeviceTree (26A434 `DeviceTree.j473ap`):
/// `/arm-io` maps child 0 to PA 0x2_0000_0000; `uart0` is `reg` 0x35200000
/// +0x4000 with AIC input 739 and `wdt` is `reg` 0x3d2b0000 +0x4000 with AIC
/// input 379. Used when no DeviceTree is loaded (the test kernel).
const ARM_IO: u64 = 0x2_0000_0000;
const J473_UART: (u64, u64, u32) = (0x3520_0000, 0x4000, 739);
const J473_WDT: (u64, u64, u32) = (0x3d2b_0000, 0x4000, 379);
/// `aic` `reg` 0x3b0c0000, and NR_IRQ derived from that DeviceTree as below.
const J473_AIC: (u64, u16) = (0x3b0c_0000, 1152);
/// The J473AP AIC2 event register's offset from the core block: Linux
/// `arch/arm64/boot/dts/apple/t8112.dtsi` gives the `aic` second `reg` at
/// 0x3b0c8000, as the AIC2 model documents; the ADT has no
/// `aic-iack-offset`. A loaded DeviceTree's board takes its SoC's offset
/// (`machine::soc`).
const J473_AIC_EVENT: u64 = 0x8000;
/// The J473AP ADT `aic` `#shared-timestamps`.
const J473_AIC_TIMESTAMPS: u8 = 16;

/// The modeled board devices: the console UART, the watchdog and the AIC2,
/// placed as the board's DeviceTree places them (`machine::soc::board`).
/// `aic-timebase` has no public register description and no model, so its
/// accesses stop explicitly.
fn devices(
    board: Option<&soc::Board>,
    read_only_region: Option<(u64, u64)>,
    now: u64,
) -> Result<AppleDevices, String> {
    let fixed = |(offset, bytes, irq): (u64, u64, u32)| soc::Device {
        physical: ARM_IO + offset,
        bytes,
        irq,
    };
    let (uart, wdt, aic) = match board {
        Some(board) => (board.uart, board.watchdog, board.aic),
        None => (
            fixed(J473_UART),
            fixed(J473_WDT),
            soc::InterruptController {
                physical: ARM_IO + J473_AIC.0,
                inputs: J473_AIC.1,
                layout: AicLayout::aic2(J473_AIC_EVENT, J473_AIC_TIMESTAMPS),
            },
        ),
    };
    let place = |device: soc::Device| {
        (
            Range {
                physical: device.physical,
                bytes: device.bytes,
            },
            AicInput::new(0, device.irq as u16),
        )
    };
    let (uart, wdt) = (place(uart), place(wdt));
    let mut devices = AppleDevices::new();
    devices
        .add_uart(GuestConsole::default(), &[uart.0], Some(uart.1))
        .map_err(|error| alloc::format!("UART placement: {error:?}"))?;
    devices
        .add_watchdog(&[wdt.0], Some(wdt.1), now)
        .map_err(|error| alloc::format!("watchdog placement: {error:?}"))?;
    devices.add_aic(aic.physical, aic.inputs, aic.layout)?;
    for block in board.map_or(&[][..], |board| &board.lockdown) {
        let range = Range {
            physical: block.physical,
            bytes: block.bytes,
        };
        devices
            .add_lockdown(block.name, block.control, range)
            .map_err(|error| alloc::format!("{} placement: {error:?}", block.name))?;
    }
    if let Some(board) = board {
        let mpidrs: Vec<u64> = board.cpus.processors.iter().map(|pe| pe.mpidr).collect();
        devices.add_fast_ipi(&mpidrs);
    }
    let mut darts = Vec::new();
    for dart in board.map_or(&[][..], |board| &board.darts) {
        let range = Range {
            physical: dart.physical,
            bytes: dart.bytes,
        };
        let irq = AicInput::new(0, dart.irq as u16);
        let placed = devices
            .add_dart(range, usize::from(dart.streams), Some(irq))
            .map_err(|error| alloc::format!("DART placement: {error:?}"))?;
        darts.push(placed);
    }
    if let Some(aes) = board.and_then(|board| board.aes) {
        let [block, key_disable] = aes
            .ranges
            .map(|(physical, bytes)| Range { physical, bytes });
        // No per-installation UID1 key is provisioned yet: the engine
        // reports every hardware key disabled.
        devices.add_aes(
            [block, key_disable],
            aes.version,
            Some(AicInput::new(0, aes.irq as u16)),
            (darts[aes.iommu], aes.stream as usize),
            None,
        )?;
    }
    if let Some(states) = board.and_then(|board| board.power_states.as_ref()) {
        let blocks: Vec<Range> = states
            .blocks
            .iter()
            .map(|&(physical, bytes)| Range { physical, bytes })
            .collect();
        devices.add_power_states(&blocks, &states.registers)?;
        output::arguments(format_args!(
            "DEVICES pmgr power-states={} blocks={}\n",
            states.registers.len(),
            blocks.len()
        ));
    }
    let memory_controller = board.and_then(|board| board.memory_controller.as_ref());
    if let Some(controller) = memory_controller {
        devices.add_memory_controller(
            &controller.apertures,
            controller.layout,
            read_only_region,
        )?;
    }
    output::arguments(format_args!(
        "DEVICES uart={:#x}+{:#x} irq={} wdt={:#x}+{:#x} irq={} aic={:#x} nr_irq={} \
         lockdown-blocks={} amcc-apertures={} darts={} aes={} aic-timebase=unplaced\n",
        uart.0.physical,
        uart.0.bytes,
        uart.1.irq,
        wdt.0.physical,
        wdt.0.bytes,
        wdt.1.irq,
        aic.physical,
        aic.inputs,
        board.map_or(0, |board| board.lockdown.len()),
        memory_controller.map_or(0, |controller| controller.apertures.len()),
        darts.len(),
        board.and_then(|board| board.aes).is_some()
    ));
    Ok(devices)
}

static EVENTS: AtomicU64 = AtomicU64::new(0);
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn report(event: &Event) {
    let count = EVENTS.fetch_add(1, Ordering::Relaxed);
    let interrupt = matches!(
        event,
        Event::Exception { vector, .. } if *vector != stela_runtime::machine::exception::Vector::Synchronous
    );
    let guarded_fault = matches!(
        event,
        Event::Exception { vector, from_guarded: true, syndrome, .. }
            if *vector == stela_runtime::machine::exception::Vector::Synchronous
                && syndrome >> ESR_EC_SHIFT != EC_SVC64
    );
    let quiet = if guarded_fault {
        false
    } else if interrupt {
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
            from_guarded,
            syndrome,
            return_address,
            fault_address,
        } => output::arguments(format_args!(
            "EXCEPTION {vector:?} from={}{from_el} esr={syndrome:#x} elr={return_address:#x} far={}\n",
            level_name(*from_guarded),
            match fault_address {
                Some(address) => alloc::format!("{address:#x}"),
                None => "-".into(),
            }
        )),
        Event::Return { to_el, guarded, pc } => output::arguments(format_args!(
            "ERET to={}{to_el} pc={pc:#x}\n",
            level_name(*guarded)
        )),
        Event::Guarded {
            enter,
            el,
            guarded,
            pc,
        } => output::arguments(format_args!(
            "{} now={}{el} pc={pc:#x}\n",
            if *enter { "GENTER" } else { "GEXIT" },
            level_name(*guarded)
        )),
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
    let mut options = match core::str::from_utf8(text)
        .map_err(|_| "stela.cfg is not UTF-8")
        .and_then(Options::parse)
    {
        Ok(options) => options,
        Err(error) => output::fatal(error),
    };
    // Before the host is installed, while the loader's identity map is live.
    let built = options.preboot.as_ref().map(|target| {
        let storage = handoff
            .storage
            .handoff()
            .unwrap_or_else(|| output::fatal("the loader found no storage controllers"));
        bundle::from_disk(&storage, target).unwrap_or_else(|error| {
            output::arguments(format_args!("preboot refusal: {error}\n"));
            output::fatal("no boot bundle could be built from the Preboot volume")
        })
    });
    // A bundle runs at the DRAM base it was prepared for, its SoC's.
    if options.bundle && !options.dram_explicit {
        let files = &handoff.files[..handoff.file_count];
        options.dram_base = match bundle::dram_base(files, built.as_deref()) {
            Ok(base) if base.is_multiple_of(LARGE) => base,
            Ok(_) => output::fatal("the bundle's DRAM base is not 2 MiB aligned"),
            Err(error) => {
                output::arguments(format_args!("bundle refusal: {error}\n"));
                output::fatal("the boot bundle's DRAM base could not be read")
            }
        };
    }
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
    let mut bare = BareHost;
    let target = target();
    let mut read_only_region = None;
    // A bundle's kernel gets a framebuffer the size of the firmware's mode.
    let mut display = handoff
        .screen
        .filter(|_| options.bundle)
        .and_then(|screen| {
            let screen = screen.relocated(layout::physical(screen.base as u64) as usize);
            display::Display::new(screen, options.dram_base + options.ram_bytes)
        });
    let (entry, x0) = if options.bundle {
        let files = &handoff.files[..handoff.file_count];
        let framebuffer = display.as_ref().map(display::Display::framebuffer);
        let (dram_base, ram_bytes) = (options.dram_base, options.ram_bytes);
        let loaded = match &built {
            Some(built) => bundle::load_built(&mut bare, built, dram_base, ram_bytes, framebuffer),
            None => bundle::load(&mut bare, files, dram_base, ram_bytes, framebuffer),
        };
        let loaded = match loaded {
            Ok(loaded) => loaded,
            Err(error) => {
                output::arguments(format_args!("bundle refusal: {error}\n"));
                output::fatal("the boot bundle could not be loaded")
            }
        };
        output::arguments(format_args!(
            "BUNDLE regions={} patched={} kept={:?} dram_base={:#x}\n",
            loaded.regions, loaded.patches, loaded.kept, loaded.dram_base
        ));
        read_only_region = loaded.read_only_region;
        (loaded.pc, loaded.x0)
    } else {
        // SAFETY: the guest image was left allocated by the loader.
        let source = unsafe {
            core::slice::from_raw_parts(
                layout::physical(handoff.source.physical) as *const u8,
                handoff.source.bytes as usize,
            )
        };
        if !stela_runtime::machine::Host::write_ram(&mut bare, options.load, source) {
            output::fatal("guest image does not fit guest DRAM at its load address");
        }
        output::arguments(format_args!(
            "GUEST IMAGE pa={:#x} bytes={} sha256={}\n",
            options.load,
            source.len(),
            stela_runtime::sha256(source),
        ));
        (options.entry, options.x0)
    };
    let tree = options.bundle.then(|| match &built {
        Some(built) => built
            .iter()
            .find(|(name, _)| name == "devicetree.adt")
            .map(|(_, bytes)| bytes.as_slice()),
        None => handoff.files[..handoff.file_count]
            .iter()
            .find(|file| file.name() == "devicetree.adt")
            .map(|file| {
                // SAFETY: the loader left every bundle file allocated.
                unsafe {
                    core::slice::from_raw_parts(
                        layout::physical(file.contents.physical) as *const u8,
                        file.contents.bytes as usize,
                    )
                }
            }),
    });
    let tree = match tree {
        Some(None) => output::fatal("the boot bundle has no devicetree.adt"),
        Some(Some(tree)) => Some(tree),
        None => None,
    };
    let board = tree.map(|tree| {
        soc::board(tree).unwrap_or_else(|error| {
            output::arguments(format_args!("board refusal: {error}\n"));
            output::fatal("the board could not be modeled")
        })
    });
    let profile = match &board {
        Some(board) => board_profile(board, target),
        None => test_profile(),
    };
    // The real kernelcache starts SPTM at EL2: it writes TPIDR_EL2 and keeps
    // its per-CPU pointer in TPIDR_GL2. HCR_EL2.E2H is RES1 on this profile
    // (SPTM installs its vectors through VBAR_EL1 before it ORs TGE and E2H
    // into HCR_EL2, which reaches VBAR_EL2 only with E2H already set); the
    // other HCR_EL2 bits reset to 0. Stela's test kernel runs at EL1.
    let el = if options.bundle { 2 } else { 1 };
    output::arguments(format_args!(
        "ENTRY pc={entry:#x} x0={x0:#x} el={el} mmu=off profile={} target={} apic_hz={apic_hz}\n",
        profile.name,
        target.id(),
    ));
    let mut cpu = Cpu::of(profile.chip, entry, Pstate::reset(el));
    cpu.state.x[0] = x0;
    // FP/SIMD is not trapped at hand-off (CPTR_EL2.FPEN = 0b11): SPTM uses
    // FP/SIMD before it writes CPTR_EL2, and public XNU `start.s` notes that
    // a monitor sets CPACR up for its client. Inferred hand-off value.
    cpu.registers.set(Register::CPTR_EL2, 0, 0b11 << 20);
    if el == 1 {
        // An EL1 entry gets the EL2 state boot firmware leaves for its
        // client: the physical counter and timer are not trapped
        // (CNTHCTL_EL2.EL1PCTEN, EL1PTEN with E2H set).
        cpu.registers
            .set(Register::CNTHCTL_EL2, 0, 1 << 10 | 1 << 11);
    }
    let now = stela_runtime::machine::Host::counter(&mut bare);
    let devices = match devices(board.as_ref(), read_only_region, now) {
        Ok(devices) => devices,
        Err(error) => {
            output::arguments(format_args!("device refusal: {error}\n"));
            output::fatal("the board devices could not be placed")
        }
    };
    let mut machine = Machine::new(cpu, bare, devices, profile, target);
    if options.survey {
        output::arguments(format_args!(
            "SURVEY RUN: device accesses without a model read 0 and drop writes; \
             the guest's behavior is unverified\n"
        ));
        machine.begin_survey();
    }
    let started = host::rdtsc();
    let stop = run(
        &mut machine,
        options.budget,
        display.as_mut(),
        handoff.tsc_hz,
    );
    let seconds = (host::rdtsc() - started) as f64 / handoff.tsc_hz as f64;
    finish(&mut machine, stop, seconds)
}

fn level_name(guarded: bool) -> &'static str {
    if guarded { "GL" } else { "EL" }
}

/// Blocks between checks of whether the screen or a heartbeat is due.
const SLICE: u64 = 1 << 18;

/// Seconds between heartbeats, which locate a guest that runs without output.
const BEAT_SECONDS: u64 = 10;

/// Run up to `budget` blocks (0: no limit), showing the guest framebuffer
/// about twice a second and at the stop, and reporting the PE's position
/// every [`BEAT_SECONDS`].
fn run(
    machine: &mut Machine<BareHost, AppleDevices>,
    budget: u64,
    mut display: Option<&mut display::Display>,
    tsc_hz: u64,
) -> Stop {
    let mut shown = host::rdtsc();
    let mut beat = (
        shown,
        host::native_ticks(),
        machine.statistics.blocks,
        machine.statistics.compiled,
        machine.statistics.chained,
        (
            machine.statistics.exceptions,
            machine.statistics.interrupts,
            machine.statistics.waits,
        ),
    );
    // The PE's call chain at each slice end since the last heartbeat, and
    // how many of those were at EL0.
    let mut samples: Vec<[u64; CHAIN]> = Vec::new();
    let mut user = 0;
    let mut beats = 0u64;
    loop {
        let slice = machine.statistics.blocks + SLICE;
        let limit = if budget == 0 {
            slice
        } else {
            budget.min(slice)
        };
        let stop = machine.run(limit);
        let sliced = matches!(stop, Stop::Budget) && limit != budget;
        let now = host::rdtsc();
        if let Some(display) = display.as_deref_mut()
            && (!sliced || now - shown >= tsc_hz / 2)
        {
            display.show(&mut machine.host);
            shown = host::rdtsc();
        }
        if !sliced {
            return stop;
        }
        let (pc, frame) = (machine.cpu.pc, machine.cpu.state.x[29]);
        samples.push(call_chain(machine, pc, frame));
        user += u32::from(machine.cpu.pstate.el == 0);
        if now - beat.0 >= BEAT_SECONDS * tsc_hz {
            let (native, blocks) = (host::native_ticks(), machine.statistics.blocks);
            let elapsed = now - beat.0;
            let cpu = &machine.cpu;
            let compiled = machine.statistics.compiled;
            // Ticks per block, the share spent in compiled code, the blocks
            // compiled since the last beat, code discards so far, the share
            // of blocks entered through a chain, and the exceptions,
            // interrupts and waits since the last beat.
            let statistics = &machine.statistics;
            let chained = statistics.chained;
            let events = (
                statistics.exceptions,
                statistics.interrupts,
                statistics.waits,
            );
            output::arguments(format_args!(
                "BEAT blocks={blocks} pc={:#x} {}{} lr={:#x} ticks/block={} native={}% \
                 compiled={} discards={} chained={}% exceptions={} interrupts={} waits={}\n",
                cpu.pc,
                level_name(cpu.pstate.guarded),
                cpu.pstate.el,
                cpu.state.x[30],
                elapsed / (blocks - beat.2).max(1),
                (native - beat.1) * 100 / elapsed.max(1),
                compiled - beat.3,
                machine.statistics.code_discards,
                (chained - beat.4) * 100 / (blocks - beat.2).max(1),
                events.0 - beat.5.0,
                events.1 - beat.5.1,
                events.2 - beat.5.2,
            ));
            beat = (now, native, blocks, compiled, chained, events);
            sample_report(&mut samples, user);
            timer_report(machine);
            survey_report(machine);
            user = 0;
            beats += 1;
            if beats.is_multiple_of(SUSPENSION_BEATS) {
                suspension_report(machine);
            }
        }
    }
}

/// The PC and return addresses a call chain sample keeps.
const CHAIN: usize = 6;

/// `pc` and the return addresses of the frame records from `frame`,
/// without their PACs; zero past the chain's end.
fn call_chain<const N: usize>(
    machine: &mut Machine<BareHost, AppleDevices>,
    pc: u64,
    mut frame: u64,
) -> [u64; N] {
    let mut chain = [0; N];
    chain[0] = pc;
    for slot in &mut chain[1..] {
        let mut record = [0u8; 16];
        if frame == 0 || !frame.is_multiple_of(8) || !machine.read_virtual(frame, &mut record) {
            break;
        }
        let link = u64::from_le_bytes(record[8..].try_into().expect("8 bytes"));
        *slot = machine.strip_instruction_pointer(link);
        frame = u64::from_le_bytes(record[..8].try_into().expect("8 bytes"));
    }
    chain
}

/// Heartbeats between reports of the suspended guest threads.
const SUSPENSION_BEATS: u64 = 6;

/// The return addresses a suspended thread's chain keeps.
const SUSPENSION_CHAIN: usize = 12;

/// The suspended guest threads grouped by where they wait: each distinct
/// chain of the link register and the frame records, with its thread count
/// and the seconds since the most recent of them stopped. A guest that idles
/// without progress shows here the wait it never leaves.
fn suspension_report(machine: &mut Machine<BareHost, AppleDevices>) {
    const SHOWN: usize = 32;
    use stela_runtime::machine::engine::Host;
    let now = machine.host.counter();
    let frequency = machine.cpu.read(Register::CNTFRQ_EL0).max(1);
    let suspended: Vec<_> = machine.suspended().values().copied().collect();
    let mut chains: Vec<([u64; SUSPENSION_CHAIN], u64)> = suspended
        .iter()
        .map(|suspension| {
            let link = machine.strip_instruction_pointer(suspension.link);
            (call_chain(machine, link, suspension.frame), suspension.at)
        })
        .collect();
    chains.sort_unstable();
    // Each chain's thread count and the latest suspension among them.
    let mut groups: Vec<(u64, usize, [u64; SUSPENSION_CHAIN])> = chains
        .chunk_by(|a, b| a.0 == b.0)
        .map(|run| {
            (
                run.iter().map(|&(_, at)| at).max().unwrap_or(0),
                run.len(),
                run[0].0,
            )
        })
        .collect();
    groups.sort_unstable_by(|a, b| b.cmp(a));
    output::arguments(format_args!(
        "SUSPENDED threads={} chains={}\n",
        suspended.len(),
        groups.len()
    ));
    for (at, count, chain) in groups.into_iter().take(SHOWN) {
        output::arguments(format_args!(
            "SUSPENSION x{count} age={}s",
            now.saturating_sub(at) / frequency
        ));
        for address in chain.into_iter().take_while(|&address| address != 0) {
            output::arguments(format_args!(" {address:#x}"));
        }
        output::arguments(format_args!("\n"));
    }
}

/// The share of the heartbeat's slice-end samples at EL0 and the call
/// chains they found most often, which show where a guest without output
/// spends its time.
fn sample_report(samples: &mut Vec<[u64; CHAIN]>, user: u32) {
    const SHOWN: usize = 3;
    samples.sort_unstable();
    let mut counts: Vec<(usize, [u64; CHAIN])> = samples
        .chunk_by(|a, b| a == b)
        .map(|run| (run.len(), run[0]))
        .collect();
    counts.sort_unstable_by(|a, b| b.cmp(a));
    output::arguments(format_args!("SAMPLES el0={user}/{}\n", samples.len()));
    for (count, chain) in counts.into_iter().take(SHOWN) {
        output::arguments(format_args!("SAMPLE x{count}"));
        for address in chain.into_iter().take_while(|&address| address != 0) {
            output::arguments(format_args!(" {address:#x}"));
        }
        output::arguments(format_args!("\n"));
    }
    samples.clear();
}

/// The counter, PSTATE.DAIF and each generic timer's CTL and CVAL, which
/// show why a PE that should sleep in WFI does not.
fn timer_report(machine: &mut Machine<BareHost, AppleDevices>) {
    use stela_runtime::machine::{engine::Host, timer::CHANNELS};
    let now = machine.host.counter();
    let cpu = &machine.cpu;
    output::arguments(format_args!(
        "TIMERS now={now:#x} daif={:#x}",
        cpu.pstate.daif
    ));
    for channel in CHANNELS {
        output::arguments(format_args!(
            " {:?}={:#x}/{:#x}",
            channel.control,
            channel.read_control(cpu, now),
            cpu.read(channel.compare)
        ));
    }
    output::arguments(format_args!("\n"));
}

/// The instruction words that most often left compiled code for the engine.
fn exit_report(machine: &Machine<BareHost, AppleDevices>) {
    const SHOWN: usize = 16;
    let mut words: Vec<_> = machine
        .exit_words()
        .iter()
        .map(|(&word, &count)| (count, word))
        .collect();
    words.sort_unstable_by(|a, b| b.cmp(a));
    for (count, word) in words.into_iter().take(SHOWN) {
        output::arguments(format_args!("EXIT {word:#010x} x{count}\n"));
    }
}

/// The frame records from X29 (each the caller's X29 and the return
/// address, Arm's AAPCS64 frame chain) and the stack words above SP, read
/// through the stopped PE's translation, so that a guest's own panic or
/// wait path can be located.
fn stack_report(machine: &mut Machine<BareHost, AppleDevices>) {
    let mut frame = machine.cpu.state.x[29];
    for depth in 0..16 {
        let mut record = [0u8; 16];
        if frame == 0 || !frame.is_multiple_of(8) || !machine.read_virtual(frame, &mut record) {
            break;
        }
        let next = u64::from_le_bytes(record[..8].try_into().expect("8 bytes"));
        let link = u64::from_le_bytes(record[8..].try_into().expect("8 bytes"));
        output::arguments(format_args!("FRAME {depth} fp={frame:#x} lr={link:#x}\n"));
        frame = next;
    }
    let sp = machine.cpu.state.sp;
    for line in 0..32u64 {
        let mut bytes = [0u8; 16];
        if !machine.read_virtual(sp + line * 16, &mut bytes) {
            break;
        }
        output::arguments(format_args!("STACK {:#x}:", sp + line * 16));
        for byte in bytes {
            output::arguments(format_args!(" {byte:02x}"));
        }
        output::arguments(format_args!("  "));
        for byte in bytes {
            let shown = if byte.is_ascii_graphic() || byte == b' ' {
                byte
            } else {
                b'.'
            };
            output::arguments(format_args!("{}", char::from(shown)));
        }
        output::arguments(format_args!("\n"));
    }
    text_report(machine);
}

/// The text a general-purpose register points to, when it reads as at least
/// eight printable characters: a guest's panic message often sits in one at
/// a stop, while the console that would print it is off.
fn text_report(machine: &mut Machine<BareHost, AppleDevices>) {
    const LIMIT: usize = 512;
    for register in 0..29 {
        let address = machine.cpu.state.x[register];
        let mut text = Vec::new();
        'read: while text.len() < LIMIT {
            let mut chunk = [0u8; 16];
            if !machine.read_virtual(address.wrapping_add(text.len() as u64), &mut chunk) {
                break;
            }
            for byte in chunk {
                if byte == 0 || !(byte.is_ascii_graphic() || b" \t\n".contains(&byte)) {
                    break 'read;
                }
                text.push(byte);
            }
        }
        if text.len() >= 8 {
            let text = core::str::from_utf8(&text).expect("ASCII");
            output::arguments(format_args!("TEXT x{register} {address:#x}: {text:?}\n"));
        }
    }
}

/// Each device register a survey answered for the first time since the last
/// report: guest PA, width, direction, the PC and link register that first
/// reached it, its count so far, the last value written and the refusal it replaced.
fn survey_report(machine: &mut Machine<BareHost, AppleDevices>) {
    for record in machine.take_survey() {
        output::arguments(format_args!(
            "SURVEY pa={:#x} bytes={} {} pc={:#x} lr={:#x} count={} value={:#x}: {}\n",
            record.physical,
            record.bytes,
            if record.write { "write" } else { "read" },
            record.pc,
            record.link,
            record.count,
            record.value,
            record.detail
        ));
    }
}

fn finish(machine: &mut Machine<BareHost, AppleDevices>, stop: Stop, seconds: f64) -> ! {
    survey_report(machine);
    stack_report(machine);
    let cpu = &machine.cpu;
    // The exception registers of the EL the run ended at.
    let bank = if cpu.pstate.el == 2 {
        [
            Register::ELR_EL2,
            Register::SPSR_EL2,
            Register::ESR_EL2,
            Register::FAR_EL2,
            Register::VBAR_EL2,
        ]
    } else {
        [
            Register::ELR_EL1,
            Register::SPSR_EL1,
            Register::ESR_EL1,
            Register::FAR_EL1,
            Register::VBAR_EL1,
        ]
    };
    let (fills, resets, stray, _) = host::statistics();
    output::arguments(format_args!(
        "STATISTICS {:?} shadow_fills={fills} shadow_resets={resets} stray_interrupts={stray} events={} seconds={seconds:.3}\n",
        machine.statistics,
        EVENTS.load(Ordering::Relaxed),
    ));
    exit_report(machine);
    output::arguments(format_args!(
        "FINAL pc={:#x} el={} sp={:#x} daif={:#x} nzcv={:#x} elr={:#x} spsr={:#x} esr={:#x} far={:#x} vbar={:#x}\n",
        cpu.pc,
        cpu.pstate.el,
        cpu.state.sp,
        cpu.pstate.daif,
        cpu.state.nzcv,
        cpu.read(bank[0]),
        cpu.read(bank[1]),
        cpu.read(bank[2]),
        cpu.read(bank[3]),
        cpu.read(bank[4]),
    ));
    for (entry, reads, writes) in cpu.apple.impdef.used() {
        output::arguments(format_args!(
            "IMPDEF {} {:?} reads={reads} writes={writes}: {}\n",
            entry.name, entry.class, entry.evidence
        ));
    }
    for (index, pair) in cpu.state.x.chunks(4).enumerate() {
        output::arguments(format_args!("X{}:", index * 4));
        for value in pair {
            output::arguments(format_args!(" {value:#018x}"));
        }
        output::arguments(format_args!("\n"));
    }
    match stop {
        Stop::Idle => {
            output::arguments(format_args!(
                "STOP idle: every PE is off or waits with no wake source\n"
            ));
            output::terminate(0x10)
        }
        Stop::Reset(reason) => {
            output::arguments(format_args!("STOP reset: {reason}\n"));
            output::terminate(0x15)
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
