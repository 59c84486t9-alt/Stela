//! System mode, engine phase: runs in the Stela window after the loader has
//! switched to LA57. Host physical memory is reached through the physmap.
//! The one use of identity addresses is `--preboot`: before the host is
//! installed, Stela's storage drivers, which address registers and DMA pages
//! by identity, read the installed system from the disk through the
//! loader's identity map and its uncached device mappings.
mod adt;
pub(crate) mod bundle;
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
    apple::{AicInput, AppleDevices, ConsoleBusy, ConsoleSink, Range},
    exception::Pstate,
    registers::encodings::DCZID_EL0,
    soc::{self, Processor},
    system::Register,
};
use stela_runtime::pc::storage::Target;

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

/// The profile of the board the bundle's DeviceTree describes: its chip and
/// PEs from `/chosen` `chip-id`, `/product` `product-soc-name` and `/cpus`
/// (`machine::soc`), with cpu0 running with EL2 as a VHE host. The ID_AA64*
/// and CTR_EL0 registers advertise what this engine implements, capped at the
/// chip's features (`machine::identification`); MIDR, MPIDR and DCZID are the
/// board's own values. Every other identification read refuses.
fn board_profile(tree: &[u8], target: TargetCpu) -> Result<(CpuProfile, soc::Board), String> {
    let root = adt::Node::root(tree).ok_or("DeviceTree has no root")?;
    let chip_id = root
        .child("chosen")
        .and_then(|chosen| chosen.first_u32("chip-id"))
        .ok_or("DeviceTree has no /chosen chip-id")?;
    let soc_name = root
        .child("product")
        .and_then(|product| product.property("product-soc-name"))
        .and_then(|name| core::str::from_utf8(name).ok())
        .map(|name| name.trim_end_matches('\0'))
        .ok_or("DeviceTree has no /product product-soc-name")?;
    let cpus = root.child("cpus").ok_or("DeviceTree has no /cpus")?;
    // Every node of /cpus with a cluster-type is a PE.
    let mut found = Vec::new();
    cpus.visit(&mut |node| {
        if let Some(cluster_type) = node.property("cluster-type") {
            found.push((cluster_type.first().copied(), node.first_u32("reg")));
        }
    })
    .ok_or("DeviceTree walk failed")?;
    let processors = found
        .into_iter()
        .map(|found| match found {
            (Some(cluster_type), Some(reg)) => Ok(Processor { cluster_type, reg }),
            _ => Err("a /cpus node has no reg or an empty cluster-type"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let board = soc::board(chip_id, soc_name, &processors)?;
    let mut fixed = stela_runtime::machine::identification::derive(board.chip, target, true);
    // 64-byte DC ZVA blocks, enabled: XNU `osfmk/arm64/bzero.s` zeroes with
    // `dc zva` in fixed 64-byte steps.
    fixed.push((DCZID_EL0, 4));
    let profile = CpuProfile {
        name: board.chip.name(),
        chip: board.chip,
        counter_frequency: 24_000_000,
        fixed,
        processors: board.processors.clone(),
    };
    Ok((profile, board))
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

/// The AIC's guest PA and NR_IRQ: one more than the highest `interrupts`
/// value of any node whose `interrupt-parent` is the AIC's phandle.
fn aic_placement(tree: &[u8]) -> Result<(u64, u16), String> {
    let root = adt::Node::root(tree).ok_or("DeviceTree has no root")?;
    let io = root.child("arm-io").ok_or("DeviceTree has no /arm-io")?;
    let aic = io.child("aic").ok_or("DeviceTree has no /arm-io/aic")?;
    if !compatible(&aic, "aic,2") {
        return Err("/arm-io/aic is not aic,2, the modeled interrupt controller".into());
    }
    let phandle = aic
        .first_u32("AAPL,phandle")
        .ok_or("/arm-io/aic has no phandle")?;
    let (offset, _) = aic
        .pairs("reg")
        .and_then(|reg| reg.first().copied())
        .ok_or("/arm-io/aic has no reg")?;
    let ranges = io.ranges().ok_or("/arm-io has no ranges")?;
    let physical = ranges
        .iter()
        .find(|(child, _, size)| (*child..child + size).contains(&offset))
        .map(|(child, parent, _)| parent + (offset - child))
        .ok_or("/arm-io/aic lies outside /arm-io ranges")?;
    let mut highest = None;
    root.visit(&mut |node| {
        if node.first_u32("interrupt-parent") == Some(phandle)
            && let Some(cells) = node.cells32("interrupts")
        {
            highest = cells.into_iter().chain(highest).max();
        }
    })
    .ok_or("DeviceTree walk failed")?;
    let highest = highest.ok_or("no node names the AIC as its interrupt parent")?;
    let count = u16::try_from(highest + 1).map_err(|_| "AIC interrupt number above 65534")?;
    Ok((physical, count))
}

/// Whether a node's `compatible` list names `model`.
fn compatible(node: &adt::Node, model: &str) -> bool {
    node.property("compatible").is_some_and(|list| {
        list.split(|byte| *byte == 0)
            .any(|entry| entry == model.as_bytes())
    })
}

/// A device node's first `reg` range in guest PA and its AIC input, read
/// from the DeviceTree. The node must be compatible with `model`, the
/// device the engine models for it.
fn placement(tree: &[u8], name: &str, model: &str) -> Result<(Range, AicInput), String> {
    let root = adt::Node::root(tree).ok_or("DeviceTree has no root")?;
    let io = root.child("arm-io").ok_or("DeviceTree has no /arm-io")?;
    let node = io
        .child(name)
        .ok_or_else(|| alloc::format!("DeviceTree has no /arm-io/{name}"))?;
    if !compatible(&node, model) {
        return Err(alloc::format!(
            "/arm-io/{name} is not {model}, the modeled device"
        ));
    }
    let (offset, bytes) = node
        .pairs("reg")
        .and_then(|reg| reg.first().copied())
        .ok_or_else(|| alloc::format!("/arm-io/{name} has no reg"))?;
    let ranges = io.ranges().ok_or("/arm-io has no ranges")?;
    let physical = ranges
        .iter()
        .find(|(child, _, size)| (*child..child + size).contains(&offset))
        .map(|(child, parent, _)| parent + (offset - child))
        .ok_or_else(|| alloc::format!("/arm-io/{name} lies outside /arm-io ranges"))?;
    let irq = node
        .first_u32("interrupts")
        .ok_or_else(|| alloc::format!("/arm-io/{name} has no interrupts"))?;
    Ok((Range { physical, bytes }, AicInput::new(0, irq as u16)))
}

/// The modeled board devices: the console UART, the watchdog and the AIC2.
/// `aic-timebase` has no public register description and no model, so its
/// accesses stop explicitly.
fn devices(tree: Option<(&[u8], &soc::Board)>, now: u64) -> Result<AppleDevices, String> {
    let fixed = |(offset, bytes, irq): (u64, u64, u32)| {
        (
            Range {
                physical: ARM_IO + offset,
                bytes,
            },
            AicInput::new(0, irq as u16),
        )
    };
    let (uart, wdt, aic) = match tree {
        Some((tree, _)) => (
            placement(tree, "uart0", "uart-1,samsung")?,
            placement(tree, "wdt", "wdt,s5l8960x")?,
            aic_placement(tree)?,
        ),
        None => (
            fixed(J473_UART),
            fixed(J473_WDT),
            (ARM_IO + J473_AIC.0, J473_AIC.1),
        ),
    };
    let mut devices = AppleDevices::new();
    devices
        .add_uart(GuestConsole::default(), &[uart.0], Some(uart.1))
        .map_err(|error| alloc::format!("UART placement: {error:?}"))?;
    devices
        .add_watchdog(&[wdt.0], Some(wdt.1), now)
        .map_err(|error| alloc::format!("watchdog placement: {error:?}"))?;
    let event = match tree {
        Some((_, board)) => board
            .aic2_event
            .ok_or("the SoC's AIC2 event register offset is unknown")?,
        None => J473_AIC_EVENT,
    };
    devices.add_aic(aic.0, aic.1, event)?;
    output::arguments(format_args!(
        "DEVICES uart={:#x}+{:#x} irq={} wdt={:#x}+{:#x} irq={} aic={:#x} nr_irq={} \
         aic-timebase=unplaced\n",
        uart.0.physical,
        uart.0.bytes,
        uart.1.irq,
        wdt.0.physical,
        wdt.0.bytes,
        wdt.1.irq,
        aic.0,
        aic.1
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
        Event::Guarded { entered, pc } => output::arguments(format_args!(
            "{} pc={pc:#x}\n",
            if *entered {
                "GENTER now=GL1"
            } else {
                "GEXIT now=EL"
            }
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
    let (entry, x0) = if options.bundle {
        let files = &handoff.files[..handoff.file_count];
        let loaded = match &built {
            Some(built) => {
                bundle::load_built(&mut bare, built, options.dram_base, options.ram_bytes)
            }
            None => bundle::load(&mut bare, files, options.dram_base, options.ram_bytes),
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
    let (profile, board) = match tree {
        Some(tree) => match board_profile(tree, target) {
            Ok((profile, board)) => (profile, Some(board)),
            Err(error) => {
                output::arguments(format_args!("board refusal: {error}\n"));
                output::fatal("the board's processors could not be modeled")
            }
        },
        None => (test_profile(), None),
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
    let devices = match devices(tree.zip(board.as_ref()), now) {
        Ok(devices) => devices,
        Err(error) => {
            output::arguments(format_args!("device refusal: {error}\n"));
            output::fatal("the board devices could not be placed")
        }
    };
    let mut machine = Machine::new(cpu, bare, devices, profile, target);
    let started = host::rdtsc();
    let stop = machine.run(options.budget);
    let seconds = (host::rdtsc() - started) as f64 / handoff.tsc_hz as f64;
    finish(&machine, stop, seconds)
}

fn finish(machine: &Machine<BareHost, AppleDevices>, stop: Stop, seconds: f64) -> ! {
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
