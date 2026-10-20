//! System mode, engine phase: runs in the Stela window after the loader has
//! switched to LA57. Host physical memory is reached through the physmap.
//! The one use of identity addresses is `--preboot`: before the host is
//! installed, Stela's storage drivers, which address registers and DMA pages
//! by identity, read the installed system from the disk through the
//! loader's identity map and its uncached device mappings.

pub(crate) mod bundle;
mod display;
mod erase;
mod host;
mod input;
pub(crate) mod install;
mod interrupts;
mod network;
mod nor;
mod power;
mod restore;
mod speculation;
mod storage;
pub(crate) mod translations;

use crate::{
    console,
    handoff::{Handoff, MAGIC},
    layout, output,
};
use alloc::{string::String, vec::Vec};
use core::{
    arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count},
    },
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use host::{BareHost, Config, RamRange};
use stela_compiler::TargetCpu;
use stela_loader::{
    boot_bundle,
    boot_selection::{self, BootVolume},
    installed, recovery,
};
use stela_runtime::machine::apple::WallClock;
use stela_runtime::machine::{
    Chip, Cpu, CpuProfile, Event, Machine, PeerState, Stop, Transition,
    apple::{AicInput, AicLayout, AppleDevices, ConsoleBusy, ConsoleSink, Range},
    exception::Pstate,
    identification::Speculation,
    registers::encodings::DCZID_EL0,
    soc,
    system::Register,
};
use stela_runtime::pc::{gpt::Guid, storage::Target};
use stela_runtime::restore::store::Verify;

/// The user-facing restore: `--install MANIFEST` names the install medium's
/// `payload.json`, `--install-source GUID` the FAT32 partition holding it.
pub const INSTALL_OPTION: &str = "--install";
const INSTALL_SOURCE_OPTION: &str = "--install-source";
/// The restore host checks the payload's recorded hashes only as the
/// restore reads each block, instead of reading every member whole before
/// StartRestore (`restore::store::Verify::OnRead`).
pub const VERIFY_ON_READ_OPTION: &str = "--verify-on-read";
/// Stop at the first unsupported device access instead of answering it as
/// the SoC does (docs/design/runtime.md "Unsupported operations").
pub const STRICT_OPTION: &str = "--strict";
/// The install restores with the inventory's Update identity, over the
/// installed system and keeping its data, instead of erasing the target.
pub const UPDATE_RESTORE_OPTION: &str = "--update-restore";

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
    /// The NVRAM boot volume the loader chose (`--boot-volume`), naming the
    /// Preboot disk's container and volume group.
    boot_volume: Option<BootVolume>,
    /// NVRAM asked for a safe-mode boot (`--safe-boot`).
    safe_boot: bool,
    /// NVRAM chose a staged macOS update (`--upgrade`): build from the
    /// Preboot disk's Update volume.
    upgrade: bool,
    /// NVRAM chose a recoveryOS the Preboot disk holds: its Recovery
    /// volume's paired copy (`--paired-recovery`) or its RecoveryOSContainer's
    /// System Recovery (`--system-recovery`), built from the disk
    /// (`stela_loader::recovery`).
    recovery: Option<recovery::Kind>,
    /// One host partition backing all ANS namespaces.
    storage: Option<Target>,
    /// The host partition holding the NOR flash image (`--nor`); the
    /// `--storage` partition itself keeps it in its tail.
    nor: Option<Target>,
    restore: bool,
    restore_source: Option<Target>,
    restore_manifest: bool,
    restore_identity: Option<usize>,
    /// The install medium's `payload.json` (`--install`), whose directory
    /// holds its pieces: a restore with Apple's stock options.
    install: Option<String>,
    /// The install medium's partition, by its unique GUID alone.
    install_source: Option<Guid>,
    /// Check the payload's recorded hashes as blocks are read
    /// (`--verify-on-read`), not every member before StartRestore.
    verify_on_read: bool,
    /// Restore with the inventory's Update identity (`--update-restore`).
    update_restore: bool,
    /// Answer device accesses no model implements and list them
    /// (`Machine::begin_survey`): research runs only.
    survey: bool,
    /// Leap the counter over waits of every PE (`--idle-skip`;
    /// `Machine::set_idle_skip`): boot and install runs, not interactive use.
    idle_skip: bool,
    /// Cable the native USB keyboard and pointer to the last USB-C
    /// controller and feed it the host's virtio-input devices (`--input`).
    input: bool,
    /// The user opted in to Apple's signing server (`--tss`, `stela setup
    /// --tss`): the restore host may send this machine's ECID and component
    /// hashes to gs.apple.com for the recoveryOS LocalPolicy, over the host
    /// network (`network::HostNetwork`). Off by default.
    tss: bool,
    /// The machine's ECID for a bundle built from the Preboot volume
    /// (`--ecid HEX`, nonzero; `boot_bundle::Options::ecid`).
    ecid: Option<u64>,
    /// POST once to this `http://` URL at start and report the reply
    /// (`--network-check URL`).
    network_check: Option<String>,
    /// Whole host disks, by serial, that the guest sees as USB mass
    /// storage behind the native hub (`--usb-storage SERIAL`, repeatable).
    usb_storage: Vec<String>,
    /// Give the guest a USB Ethernet adapter bridged to a host network
    /// adapter of its own (`--guest-network`; `network::GuestNetwork`).
    guest_network: bool,
    /// Advertise and log the SEP `sks`/`pnon`/`scrd` services whose contracts
    /// are not recovered (`--sep-observe`): each request is recorded and
    /// refused by name, never answered. A diagnostic mode.
    sep_observe: bool,
    /// Record each GFX firmware work command and derive its fields
    /// (`--agx-observe`): the command is logged and still refused by name,
    /// never completed. A diagnostic mode.
    agx_observe: bool,
    /// Stop every PE at the first unsupported operation (`--strict`)
    /// instead of answering it as the SoC or its firmware does and
    /// reporting it (docs/design/runtime.md "Unsupported operations").
    /// Restore studies (`--restore-study`) are strict whatever this says;
    /// `cargo xtask boot run` passes it unless `--graceful`.
    strict: bool,
    /// Stop when a PE reaches one of these guest PCs (`--break`), with the
    /// stop's report.
    breakpoints: Vec<u64>,
    /// Log, without stopping, when a PE reaches one of these guest PCs
    /// (`--trace`; `Machine::set_traces`).
    traces: Vec<u64>,
    /// Log, without stopping, every device access in these physical ranges
    /// (`--watch BASE,BYTES`; `Machine::set_watches`).
    watches: Vec<(u64, u64)>,
    /// Guest virtual ranges the stop's report shows (`--dump BASE,BYTES`).
    dumps: Vec<(Base, u64)>,
}

/// Where a `--dump` range starts: a guest virtual address, or the stopped
/// PE's general register `xN` plus or minus an offset (`x21`, `x22+0x4000`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    Address(u64),
    Register(usize, i64),
}

impl Base {
    fn parse(text: &str) -> Result<Self, &'static str> {
        let Some(register) = text.strip_prefix('x') else {
            return Ok(Self::Address(number(text)?));
        };
        let (index, offset) = match register.find(['+', '-']) {
            Some(at) => {
                let magnitude = number(&register[at + 1..])? as i64;
                let sign = if register.as_bytes()[at] == b'-' {
                    -1
                } else {
                    1
                };
                (&register[..at], sign * magnitude)
            }
            None => (register, 0),
        };
        match index.parse() {
            Ok(index) if index < 31 => Ok(Self::Register(index, offset)),
            _ => Err("a dump register is x0 to x30"),
        }
    }

    fn resolve(self, x: &[u64; 31]) -> u64 {
        match self {
            Self::Address(address) => address,
            Self::Register(index, offset) => x[index].wrapping_add_signed(offset),
        }
    }
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
            boot_volume: None,
            safe_boot: false,
            upgrade: false,
            recovery: None,
            storage: None,
            nor: None,
            restore: false,
            restore_source: None,
            restore_manifest: false,
            restore_identity: None,
            install: None,
            install_source: None,
            verify_on_read: false,
            update_restore: false,
            survey: false,
            idle_skip: false,
            input: false,
            tss: false,
            ecid: None,
            network_check: None,
            usb_storage: Vec::new(),
            guest_network: false,
            sep_observe: false,
            agx_observe: false,
            strict: false,
            breakpoints: Vec::new(),
            traces: Vec::new(),
            watches: Vec::new(),
            dumps: Vec::new(),
        };
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some("--system") {
            return Err("system options must start with --system");
        }
        while let Some(name) = words.next() {
            if name == "--restore-study" {
                options.restore = true;
                continue;
            }
            if name == "--restore-source" {
                let target = words
                    .next()
                    .ok_or("missing restore source partition")?
                    .parse()?;
                if options.restore_source.replace(target).is_some() {
                    return Err("duplicate restore source");
                }
                continue;
            }
            if name == "--restore-manifest" {
                words.next().ok_or("missing restore manifest path")?;
                if options.restore_manifest {
                    return Err("duplicate restore manifest");
                }
                options.restore_manifest = true;
                continue;
            }
            if name == INSTALL_OPTION {
                let path = words.next().ok_or("missing install medium manifest")?;
                if options.install.replace(String::from(path)).is_some() {
                    return Err("duplicate install medium");
                }
                continue;
            }
            if name == INSTALL_SOURCE_OPTION {
                let guid = words
                    .next()
                    .ok_or("missing install medium partition")?
                    .parse()?;
                if options.install_source.replace(guid).is_some() {
                    return Err("duplicate install medium partition");
                }
                continue;
            }
            if name == "--restore-identity" {
                let index = number(words.next().ok_or("missing restore identity index")?)?;
                if options
                    .restore_identity
                    .replace(usize::try_from(index).map_err(|_| "restore identity too large")?)
                    .is_some()
                {
                    return Err("duplicate restore identity");
                }
                continue;
            }
            if name == "--bundle" {
                words.next().ok_or("missing bundle directory")?;
                options.bundle = true;
                continue;
            }
            if name == "--survey" {
                options.survey = true;
                continue;
            }
            if name == VERIFY_ON_READ_OPTION {
                options.verify_on_read = true;
                continue;
            }
            if name == UPDATE_RESTORE_OPTION {
                options.update_restore = true;
                continue;
            }
            if name == "--idle-skip" {
                options.idle_skip = true;
                continue;
            }
            if name == "--input" {
                options.input = true;
                continue;
            }
            if name == "--tss" {
                options.tss = true;
                continue;
            }
            if name == "--usb-storage" {
                let serial = words.next().ok_or("missing USB storage disk serial")?;
                if options.usb_storage.iter().any(|other| other == serial) {
                    return Err("duplicate USB storage disk");
                }
                options.usb_storage.push(String::from(serial));
                continue;
            }
            if name == "--guest-network" {
                options.guest_network = true;
                continue;
            }
            if name == "--network-check" {
                let url = words.next().ok_or("missing network check URL")?;
                network::split_url(url)?;
                if options.network_check.replace(String::from(url)).is_some() {
                    return Err("duplicate network check");
                }
                continue;
            }
            if name == "--ecid" {
                let ecid = number(words.next().ok_or("missing ECID")?)?;
                if ecid == 0 || options.ecid.replace(ecid).is_some() {
                    return Err("--ecid takes one nonzero ECID");
                }
                continue;
            }
            if name == "--sep-observe" {
                options.sep_observe = true;
                continue;
            }
            if name == "--agx-observe" {
                options.agx_observe = true;
                continue;
            }
            if name == STRICT_OPTION {
                options.strict = true;
                continue;
            }
            if name == "--storage" {
                let target = words
                    .next()
                    .ok_or("missing ANS storage partition")?
                    .parse()?;
                if options.storage.replace(target).is_some() {
                    return Err("system mode accepts exactly one ANS backing partition");
                }
                continue;
            }
            if name == "--nor" {
                let target = words.next().ok_or("missing NOR partition")?.parse()?;
                if options.nor.replace(target).is_some() {
                    return Err("duplicate NOR partition");
                }
                continue;
            }
            if name == "--preboot" {
                let target = words.next().ok_or("missing Preboot disk")?;
                options.preboot = Some(target.parse()?);
                options.bundle = true;
                continue;
            }
            if name == "--watch" {
                let range = words.next().ok_or("missing watch range")?;
                let (base, bytes) = range.split_once(',').ok_or("a watch is BASE,BYTES")?;
                options.watches.push((number(base)?, number(bytes)?));
                continue;
            }
            if name == boot_selection::BOOT_VOLUME_OPTION {
                let value = words.next().ok_or("missing boot volume")?;
                let volume = BootVolume::parse(value.as_bytes())
                    .map_err(|_| "--boot-volume is not TYPE:PARTITION:GROUP")?;
                if options.boot_volume.replace(volume).is_some() {
                    return Err("duplicate boot volume");
                }
                continue;
            }
            if name == boot_selection::SAFE_BOOT_OPTION {
                options.safe_boot = true;
                continue;
            }
            if name == boot_selection::UPGRADE_OPTION {
                options.upgrade = true;
                continue;
            }
            let kind = match name {
                boot_selection::PAIRED_RECOVERY_OPTION => Some(recovery::Kind::Paired),
                boot_selection::SYSTEM_RECOVERY_OPTION => Some(recovery::Kind::System),
                _ => None,
            };
            if let Some(kind) = kind {
                if options.recovery.replace(kind).is_some() {
                    return Err("--paired-recovery and --system-recovery name one recoveryOS");
                }
                continue;
            }
            if name == "--dump" {
                let range = words.next().ok_or("missing dump range")?;
                let (base, bytes) = range.split_once(',').ok_or("a dump is BASE,BYTES")?;
                options.dumps.push((Base::parse(base)?, number(bytes)?));
                continue;
            }
            let value = number(words.next().ok_or("missing system option value")?)?;
            match name {
                "--break" => options.breakpoints.push(value),
                "--trace" => options.traces.push(value),
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
        let restore_inputs = options.restore_source.is_some()
            || options.restore_manifest
            || options.restore_identity.is_some();
        if options.restore
            && (!options.bundle
                || options.preboot.is_some()
                || options.storage.is_none()
                || options.restore_source.is_none()
                || !options.restore_manifest
                || options.restore_identity.is_none()
                || options.survey)
        {
            return Err(
                "--restore-study requires --bundle, --storage, --restore-source, --restore-manifest and --restore-identity; refuses --preboot/--survey",
            );
        }
        if !options.restore && restore_inputs {
            return Err("restore inputs require explicit --restore-study");
        }
        if options.install.is_some() != options.install_source.is_some() {
            return Err("--install and --install-source name the install medium together");
        }
        if options.install.is_some()
            && (!options.bundle
                || options.preboot.is_some()
                || options.storage.is_none()
                || options.nor.is_none()
                || options.restore
                || options.survey)
        {
            return Err(
                "--install requires --bundle, --storage and --nor; refuses --restore-study, --preboot and --survey",
            );
        }
        if options.update_restore && options.install.is_none() {
            return Err("--update-restore applies to --install");
        }
        if options.verify_on_read && options.install.is_none() && !options.restore {
            return Err("--verify-on-read applies to --install and --restore-study");
        }
        if options.install.is_some() && !options.tss {
            return Err(
                "--install needs --tss: the restore personalizes the recoveryOS LocalPolicy with Apple's signing server",
            );
        }
        if options.preboot.is_none()
            && (options.boot_volume.is_some()
                || options.safe_boot
                || options.upgrade
                || options.recovery.is_some())
        {
            return Err(
                "--boot-volume, --safe-boot, --upgrade, --paired-recovery and --system-recovery \
                 choose a --preboot boot",
            );
        }
        if options.upgrade && (options.recovery.is_some() || options.safe_boot) {
            return Err("--upgrade is neither a safe-mode boot nor a recoveryOS");
        }
        if options.recovery.is_some() && options.safe_boot {
            return Err("a recoveryOS boot is not a safe-mode boot");
        }
        if !options.dram_base.is_multiple_of(LARGE) || options.ram_bytes < LARGE {
            return Err("guest DRAM base must be 2 MiB aligned and hold at least 2 MiB");
        }
        Ok(options)
    }
}

/// The host CPU's compiler target, from CPUID, after setting Intel's data
/// operand independent timing mode where the CPU has it ([`enable_doit`]).
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
    // SAFETY: once on the one CPU, before any guest code runs.
    if unsafe { enable_doit(extended.edx) } {
        target = target.with_doit();
    }
    target
}

/// CPUID.(EAX=07H,ECX=0):EDX bit 29: IA32_ARCH_CAPABILITIES exists.
const CPUID_ARCH_CAPABILITIES: u32 = 1 << 29;
const IA32_ARCH_CAPABILITIES: u32 = 0x10a;
/// IA32_ARCH_CAPABILITIES bit 12: IA32_UARCH_MISC_CTL.DOITM exists.
const ARCH_CAPABILITIES_DOITM: u64 = 1 << 12;
const IA32_UARCH_MISC_CTL: u32 = 0x1b01;
/// IA32_UARCH_MISC_CTL bit 0: data operand independent timing mode.
const UARCH_MISC_CTL_DOITM: u64 = 1;

/// Set Intel's data operand independent timing mode where the CPU
/// enumerates it, and whether it is now set (Intel, "Data Operand
/// Independent Timing Instruction Guidance"). Stela runs guest code on this
/// CPU alone. Without the control there is no guarantee Stela can
/// establish: AMD documents none, and the Intel cores before Ice Lake and
/// Gracemont that always behave so are not told apart. The engine then
/// advertises no FEAT_DIT (`TargetCpu::data_independent_timing_target`).
///
/// # Safety
/// Ring 0, with no other code depending on IA32_UARCH_MISC_CTL.
unsafe fn enable_doit(leaf7_edx: u32) -> bool {
    if leaf7_edx & CPUID_ARCH_CAPABILITIES == 0 {
        return false;
    }
    // SAFETY: CPUID enumerates the MSR; ring 0.
    if unsafe { read_msr(IA32_ARCH_CAPABILITIES) } & ARCH_CAPABILITIES_DOITM == 0 {
        return false;
    }
    // SAFETY: IA32_ARCH_CAPABILITIES enumerates the control; ring 0.
    unsafe {
        let control = read_msr(IA32_UARCH_MISC_CTL);
        write_msr(IA32_UARCH_MISC_CTL, control | UARCH_MISC_CTL_DOITM);
        read_msr(IA32_UARCH_MISC_CTL) & UARCH_MISC_CTL_DOITM != 0
    }
}

/// # Safety
/// Ring 0, and the CPU implements `msr`.
unsafe fn read_msr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: the caller's contract.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    u64::from(high) << 32 | u64::from(low)
}

/// # Safety
/// Ring 0, the CPU implements `msr` and `value` is valid for it.
unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: the caller's contract.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags));
    }
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
/// The CSV fields disclose the host's `speculation` guarantees.
fn board_profile(board: &soc::Board, target: TargetCpu, speculation: Speculation) -> CpuProfile {
    let chip = board.cpus.chip;
    let mut fixed = stela_runtime::machine::identification::derive(chip, target, true, speculation);
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
/// What is plugged into the board's USB-C connectors: a restore host on the
/// first, and on the last the native hub with the keyboard and pointer and
/// the `usb` disks and Ethernet adapter.
struct Cables {
    restore: bool,
    input: bool,
    usb: stela_runtime::machine::apple::UsbCables,
    /// The firmware's GOP mode, for the DCP display coprocessor's scanout.
    screen: Option<console::Framebuffer>,
}

/// The system counter at placement and the host's wall time at it.
struct Clock {
    now: u64,
    wall: Option<WallClock>,
}

/// The host disks the board's devices keep: the internal SSD's backing
/// (`--storage`) and the SEP's state on the machine-state partition
/// (`--nor`).
struct Disks {
    backing: Option<alloc::boxed::Box<dyn stela_runtime::pc::block::BlockDevice>>,
    sep_state: Option<stela_runtime::machine::apple::sep_state::Location>,
    /// Advertise and log the SEP `sks`/`pnon`/`scrd` services (`--sep-observe`).
    sep_observe: bool,
    /// Record the GFX firmware work commands and derive their fields
    /// (`--agx-observe`); each is still refused by name.
    agx_observe: bool,
}

/// The board's devices. `reset` is the entry point a boot bundle hands off
/// to, on which boot firmware locks every PE's RVBAR.
fn devices<'f>(
    board: Option<&soc::Board>,
    read_only_region: Option<(u64, u64)>,
    reset: Option<u64>,
    clock: Clock,
    disks: Disks,
    mut cables: Cables,
    firmware: &dyn Fn(&str) -> Option<&'f [u8]>,
) -> Result<(AppleDevices, Option<stela_runtime::machine::apple::UsbId>), String> {
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
        .add_watchdog_with_side(
            wdt.0,
            board.and_then(|b| b.watchdog_side.as_ref()),
            Some(wdt.1),
            clock.now,
        )
        .map_err(|error| alloc::format!("watchdog placement: {error:?}"))?;
    devices.add_aic(aic.physical, aic.inputs, aic.layout)?;
    if let Some(board) = board
        && let Some(gpio) = &board.gpio
    {
        let selects: Vec<u32> = board.spi_nor.iter().filter_map(|spi| spi.select).collect();
        let interrupts: Vec<u32> = board
            .i2cs
            .iter()
            .flat_map(|controller| &controller.targets)
            .filter_map(|target| target.interrupt)
            .collect();
        devices.add_gpio(gpio, &selects, &interrupts)?;
    }
    for aux in board.map_or(&[][..], |board| &board.aux_gpios) {
        devices.add_aux_gpio(aux)?;
    }
    if let Some(spi) = board.and_then(|board| board.spi_nor.as_ref()) {
        devices.add_spi_nor(spi)?;
    }
    let Disks {
        backing,
        sep_state,
        sep_observe,
        agx_observe,
    } = disks;
    match (board.and_then(|b| b.ans.as_ref()), backing) {
        (Some(ans), Some(backing)) => devices.add_ans(ans, backing)?,
        (Some(_), None) => return Err("a visible ANS2 requires --storage SERIAL:GUID".into()),
        (None, Some(_)) => {
            return Err(
                "--storage was supplied but this DeviceTree exposes no modeled ANS2".into(),
            );
        }
        (None, None) => (),
    }
    if let Some(smc) = board.and_then(|b| b.smc.as_ref()) {
        devices.add_smc(smc)?;
    }
    if let Some(pmp) = board.and_then(|b| b.pmp.as_ref()) {
        devices.add_pmp(pmp)?;
    }
    for spmi in board.map_or(&[][..], |board| &board.spmis) {
        devices.add_spmi(spmi, clock.wall)?;
    }
    for &physical in board.map_or(&[][..], |board| &board.coresight) {
        devices
            .add_coresight_lock(physical)
            .map_err(|error| alloc::format!("CoreSight lock placement: {error:?}"))?;
    }
    for block in board.map_or(&[][..], |board| &board.lockdown) {
        let range = Range {
            physical: block.physical,
            bytes: block.bytes,
        };
        let rvbar = block.cpu.zip(reset);
        devices
            .add_lockdown(block.name, block.control, range, rvbar)
            .map_err(|error| alloc::format!("{} placement: {error:?}", block.name))?;
    }
    if let Some(board) = board {
        let mpidrs: Vec<u64> = board.cpus.processors.iter().map(|pe| pe.mpidr).collect();
        devices.add_fast_ipi(&mpidrs);
        if let Some((physical, clusters)) = board.cpu_start {
            devices.add_cpu_start(physical, clusters, &mpidrs)?;
        }
    }
    for controller in board.map_or(&[][..], |board| &board.i2cs) {
        devices.add_i2c(controller, firmware)?;
    }
    for phy in board.map_or(&[][..], |board| &board.typec_phys) {
        devices
            .add_atc_phy(phy)
            .map_err(|error| alloc::format!("ATC PHY placement: {error:?}"))?;
    }
    let mut darts = Vec::new();
    for dart in board.map_or(&[][..], |board| &board.darts) {
        let ranges: Vec<_> = dart
            .instances
            .iter()
            .map(|instance| Range {
                physical: instance.physical,
                bytes: instance.bytes,
            })
            .collect();
        let irq = AicInput::new(0, dart.irq as u16);
        let placed = devices
            .add_dart_group(&ranges, usize::from(dart.streams), Some(irq), dart.apf)
            .map_err(|error| alloc::format!("DART placement: {error:?}"))?;
        if let Some((physical, bytes)) = dart.smmu {
            devices
                .add_dart_smmu(Range { physical, bytes })
                .map_err(|error| alloc::format!("DART SMMU placement: {error:?}"))?;
        }
        darts.push(placed);
    }
    // The dcpext display coprocessor and its register apertures, presenting
    // to the GOP framebuffer, mastering through its DART and reading swap
    // surfaces through the display pipe's; it needs a scanout, so it is
    // placed only when the firmware gave Stela a mode.
    if let Some(dcp) = board.and_then(|board| board.dcp.as_ref())
        && let Some(screen) = cables.screen
    {
        let screen = screen.relocated(layout::physical(screen.base as u64) as usize);
        let range = |(physical, bytes): (u64, u64)| Range { physical, bytes };
        devices.add_dcpext(
            range(dcp.wrapper),
            dcp.interrupts,
            dcp.quiesced,
            alloc::boxed::Box::new(display::GopScanout::new(screen)),
            (darts[dcp.iommu][0], dcp.stream as usize),
            dcp.window,
            dcp.surface
                .map(|(iommu, stream)| (darts[iommu][0], stream as usize)),
        )?;
        let regions: Vec<(&'static str, Range)> = dcp
            .regions
            .iter()
            .map(|&(name, reg)| (name, range(reg)))
            .collect();
        devices.add_display(&regions)?;
    }
    if let Some(sep) = board.and_then(|board| board.sep) {
        use stela_runtime::machine::apple::AscLines;
        let ranges = sep
            .ranges
            .map(|(physical, bytes)| Range { physical, bytes });
        let lines = AscLines::from_interrupts(sep.irqs.map(|irq| AicInput::new(0, irq as u16)));
        let ecid = sep
            .ecid
            .ok_or("SEP needs /chosen unique-chip-id (the machine ECID); none in the tree")?;
        let state = match sep_state {
            Some(location) => {
                output::arguments(format_args!("SEP state on the machine-state partition\n"));
                location
            }
            None => {
                // Without `--nor` no host partition holds it: the roots
                // and anti-replay store last this power cycle.
                output::arguments(format_args!(
                    "SEP state volatile: nonces end at power-off\n"
                ));
                stela_runtime::machine::apple::sep_state::Location::Volatile
            }
        };
        devices.add_sep(
            ranges,
            lines,
            (darts[sep.iommu][0], sep.stream as usize),
            alloc::boxed::Box::new(bundle::entropy),
            stela_runtime::machine::apple::SepProvisioning {
                security: sep.security,
                ecid,
                observe: sep_observe,
                state,
            },
        )?;
    }
    let mut restore_usb = None;
    let usbs = board.map_or(0, |board| board.usbs.len());
    for (index, usb) in board.iter().flat_map(|board| &board.usbs).enumerate() {
        // The controller's stream translates through the group's first TRAD
        // instance, as SEP and AES masters do; per-instance selection is the
        // bus master's contract (`soc::Iommu`).
        let id = devices.add_usb(usb, darts[usb.iommu][0])?;
        // The native keyboard and pointer plug into the last connector
        // (J473AP usb-drd1), the Mac being the downstream-facing port.
        let hub = cables.input || !cables.usb.disks.is_empty() || cables.usb.network.is_some();
        if hub && index + 1 == usbs && index != 0 {
            let disks = cables.usb.disks.len();
            let network = cables.usb.network;
            devices.attach_input(usb.port, core::mem::take(&mut cables.usb))?;
            output::arguments(format_args!(
                "INPUT attached to USB-C port {} with {disks} USB disks, network={network:?}\n",
                usb.port
            ));
        }
        // The first controller (J473AP usb-drd0, the back-left connector) is
        // the one a restore host or the native client uses; the others are
        // left uncabled.
        if index != 0 {
            continue;
        }
        if cables.restore {
            // A restore host is cabled to this connector from power-on: it
            // is the USB host and sources VBUS, so the Mac is a USB2 device.
            // The connector's HPM die and controller observe the same cable.
            use stela_runtime::machine::apple::typec::{
                Attached, DataRole, Orientation, Usb2Speed,
            };
            let host = Attached {
                orientation: Orientation::Normal,
                role: DataRole::Ufp,
                source: false,
                vbus: true,
                speed: Usb2Speed::High,
            };
            devices.set_connection(usb.port, Some(host))?;
            restore_usb = Some(id);
        } else {
            devices.usb_client(id)?.query_type()?;
        }
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
            (darts[aes.iommu][0], aes.stream as usize),
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
    if let Some(board) = board {
        for (bank, instances) in board.darts.iter().zip(&darts) {
            let mut domains = Vec::new();
            for id in &bank.power_gates {
                let supplies = board
                    .power_states
                    .as_ref()
                    .and_then(|states| states.devices.iter().find(|(device, _)| device == id))
                    .map(|(_, addresses)| addresses)
                    .ok_or_else(|| {
                        alloc::format!("DART power gate ID {id:#x} has no PMGR state")
                    })?;
                domains.extend_from_slice(supplies);
            }
            domains.sort_unstable();
            domains.dedup();
            // One supply powers every TRAD instance of the DT DART.
            for &dart in instances {
                devices.connect_dart_power(dart, &domains, bank.retention)?;
            }
        }
    }
    for bank in board.map_or(&[][..], |b| &b.bridges) {
        devices.add_bridge(
            bank.physical,
            &bank.fields,
            bank.header,
            &bank.configs,
            bank.axi,
        )?;
    }
    if let Some(bank) = board.and_then(|b| b.soc_dpe.as_ref()) {
        devices.add_soc_dpe(bank.physical, &bank.samples)?;
    }
    for bank in board.map_or(&[][..], |board| &board.power_banks) {
        devices.add_soc_power(bank.physical, bank.kind)?;
    }
    if let Some(bank) = board.and_then(|board| board.wake_masks.as_ref()) {
        devices.add_wake_masks(bank.physical, bank.valid, bank.smc_wake)?;
    }
    for bank in board.map_or(&[][..], |board| &board.performance) {
        devices.add_performance_counters(bank.physical, &bank.selectors)?;
    }
    for bank in board.map_or(&[][..], |board| &board.energy) {
        devices.add_cpu_energy(bank.physical, bank.cpm)?;
    }
    for (index, cluster) in board
        .map_or(&[][..], |board| &board.clusters)
        .iter()
        .enumerate()
    {
        let events = board
            .and_then(|b| b.cluster_events.get(index))
            .ok_or("CPU cluster has no DT event selection")?;
        // The board validated each CPM word against the translated DT reg.
        devices.add_cpm_power(cluster.base + 0x40000, cluster.counter_map)?;
        devices.add_cpu_cluster(
            cluster.base,
            cluster.dvmr,
            cluster.pstates,
            cluster.counter_capacity,
            cluster.counter_map,
            events,
        )?;
    }
    if let Some((physical, _)) = board.and_then(|board| board.aon_fuses) {
        devices.add_aon_fuses(physical)?;
    }
    let memory_controller = board.and_then(|board| board.memory_controller.as_ref());
    let memory_cache = board.and_then(|board| board.memory_cache.as_ref());
    if let Some(controller) = memory_controller {
        devices.add_memory_controller(
            &controller.apertures,
            controller.layout,
            read_only_region,
            memory_cache.map(|mcc| mcc.cache),
        )?;
    }
    if let Some(mcc) = memory_cache {
        let (physical, bytes, channels) = mcc.channels;
        devices.add_memory_channels(
            Range { physical, bytes },
            channels,
            mcc.ptd.physical,
            &mcc.ptd.ranges,
        )?;
        output::arguments(format_args!(
            "DEVICES mcc cache={}MiB ways={} dcs-channels={channels} ptd={:#x} ptd-ranges={}\n",
            mcc.cache.bytes >> 20,
            mcc.cache.ways,
            mcc.ptd.physical,
            mcc.ptd.ranges.len()
        ));
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
    // Last: the `sgx` window spans other banks (gfx-asc, a PMGR fabric
    // bridge) and owns only the bytes they leave.
    if let Some(gfx) = board.and_then(|b| b.gfx.as_ref()) {
        devices.add_gfx(gfx, agx_observe)?;
    }
    if cables.restore && restore_usb.is_none() {
        return Err("restore study requires a DT-placed USB device".into());
    }
    Ok((devices, restore_usb))
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
        let defaults = boot_bundle::Options {
            ecid: options.ecid,
            ..boot_bundle::Options::default()
        };
        let result = if options.upgrade {
            bundle::upgrade_from_disk(&storage, target, options.boot_volume, &defaults)
        } else if let Some(kind) = options.recovery {
            bundle::recovery_from_disk(&storage, target, kind, options.boot_volume, &defaults)
        } else {
            let request = installed::Request {
                volume: options.boot_volume,
                ..installed::Request::default()
            };
            let mut defaults = defaults;
            if options.safe_boot {
                defaults.boot_args.push_str(" -x");
            }
            bundle::from_disk(&storage, target, &request, &defaults)
        };
        result.unwrap_or_else(|error| {
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
    // The translation store the loader read, and its partition when the
    // pack can be rewritten.
    let translation_store = handoff.files[..handoff.file_count]
        .iter()
        .find(|file| file.name() == translations::FILE)
        .and_then(|file| translations::install(bundle::contents(file)))
        .filter(|_| handoff.storage.present);
    // `--nor` naming the `--storage` partition keeps the machine state in
    // that partition's tail (`pc::machine_state`): one device, split below.
    let state_in_storage = options.nor.is_some() && options.nor == options.storage;
    let targets: Vec<&Target> = options
        .storage
        .iter()
        .chain(options.restore_source.iter())
        .chain(options.nor.iter().filter(|_| !state_in_storage))
        .collect();
    let wants_network = options.tss || options.network_check.is_some();
    let (services, medium, host_input, host_network, usb_disks, guest_network) = if targets
        .is_empty()
        && options.install_source.is_none()
        && !options.input
        && !wants_network
        && options.usb_storage.is_empty()
        && !options.guest_network
        && translation_store.is_none()
    {
        (Vec::new(), None, None, None, Vec::new(), None)
    } else {
        let storage_handoff = handoff
            .storage
            .handoff()
            .unwrap_or_else(|| output::fatal("the loader found no storage controllers"));
        // SAFETY: before host::install, with sole ownership of DMA/controllers.
        let storage::Opened {
            services,
            medium,
            store,
            inputs,
            mut links,
            usb_disks,
        } = unsafe {
            storage::open(
                &storage_handoff,
                &targets,
                options.install_source,
                translation_store,
                &options.usb_storage,
            )
        }
        .unwrap_or_else(|error| {
            output::arguments(format_args!("host storage refusal: {error}\n"));
            output::fatal("host storage could not be opened")
        });
        if let Some(store) = store {
            translations::set_partition(store);
        }
        // The guest's adapter is its own: the mount's client keeps the
        // first one.
        let guest_network = options.guest_network.then(|| {
            network::GuestNetwork::open(&mut links, wants_network).unwrap_or_else(|error| {
                output::arguments(format_args!("guest network refusal: {error}\n"));
                output::fatal("the guest network could not be opened")
            })
        });
        let network = wants_network.then(|| {
            network::HostNetwork::open(links, storage_handoff.clock).unwrap_or_else(|error| {
                output::arguments(format_args!("host network refusal: {error}\n"));
                output::fatal("the host network could not be opened")
            })
        });
        (
            services,
            medium,
            options.input.then(|| input::HostInput::new(inputs)),
            network,
            usb_disks,
            guest_network,
        )
    };
    let mut host_network = host_network;
    if let (Some(url), Some(network)) = (&options.network_check, host_network.as_mut()) {
        let (host, path) = network::split_url(url).unwrap_or_else(|error| output::fatal(error));
        // Any HTTP status proves the path end to end; only a transport
        // failure (link, DHCP, DNS, TCP, malformed reply) fails the check.
        match network.post(host, path, "text/plain", b"") {
            Ok(_) | Err(stela_runtime::net::NetError::Status(_)) => {
                output::arguments(format_args!("NETWORK CHECK passed\n"))
            }
            Err(_) => output::fatal("the network check failed"),
        }
    }
    // The restore client's signing-server transport (`restore::tss`)
    // takes `host_network` below; it lives for the whole run.
    let mut services = services.into_iter();
    let backing = options.storage.as_ref().map(|_| services.next().unwrap());
    let source = options
        .restore_source
        .as_ref()
        .map(|_| services.next().unwrap());
    // The restore host's IPSW: the study's raw extent, or the install
    // medium's pieces, found through FAT32 and joined.
    let source = match (source, medium) {
        (Some(partition), _) => Some(
            restore::inventory(handoff)
                .and_then(|manifest| restore::Source::extent(partition, manifest.source.bytes)),
        ),
        (None, Some(partition)) => Some(restore::inventory(handoff).and_then(|manifest| {
            let path = options.install.as_deref().unwrap_or_default();
            let directory = path
                .rsplit_once('\\')
                .map_or("", |(directory, _)| directory);
            let hashes = restore::inventory_file(handoff, crate::system::INSTALL_PIECES_FILE)
                .ok_or("the install medium's piece hashes were not loaded")?;
            install::open(partition, &manifest, directory, hashes).map(restore::Source::new)
        })),
        (None, None) => None,
    }
    .map(|source| {
        source.unwrap_or_else(|error| {
            output::arguments(format_args!("restore source refusal: {error}\n"));
            output::fatal("the restore source could not be opened")
        })
    });
    let (backing, nor) = match backing {
        Some(partition) if state_in_storage => {
            let (namespace, state) = nor::split(partition);
            (Some(namespace), Some(state))
        }
        backing => (
            backing,
            options.nor.as_ref().map(|_| services.next().unwrap()),
        ),
    };
    // recoveryOS boots on a Mac's internal disk layout: refuse a namespace
    // without the iBootSystemContainer it aborts without, before it runs.
    let recovery = options.bundle
        && bundle::enters_recovery_os(&handoff.files[..handoff.file_count], built.as_deref())
            .unwrap_or_else(|error| {
                output::arguments(format_args!("bundle refusal: {error}\n"));
                output::fatal("the boot bundle's OS environment could not be read")
            });
    let backing = match backing {
        Some(namespace) if recovery => {
            let mut bytes = bundle::Bytes::new(namespace);
            if let Err(error) = stela_runtime::apfs::require_system_container(&mut bytes) {
                output::arguments(format_args!("recoveryOS refusal: {error}\n"));
                output::fatal(
                    "recoveryOS needs the internal disk's iBootSystemContainer with its xART \
                     volume, which the restore creates",
                );
            }
            Some(bytes.into_inner())
        }
        None if recovery => output::fatal("recoveryOS needs the internal disk (--storage)"),
        backing => backing,
    };
    let nor = nor.map(nor::HostNor::open);
    let (mut host_nor, nor_image, nvram, sep_state) = match nor {
        Some((host_nor, image, nvram, sep_state)) => {
            (Some(host_nor), Some(image), Some(nvram), Some(sep_state))
        }
        None => (None, None, None, None),
    };
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
    let apic_hz = host::statistics().apic_hz;
    let mut bare = BareHost;
    let target = target();
    let speculation = speculation::probe();
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
            Some(built) => {
                bundle::load_built(&mut bare, built, dram_base, ram_bytes, framebuffer, nvram)
            }
            None => bundle::load(&mut bare, files, dram_base, ram_bytes, framebuffer, nvram),
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
    let mut board = tree.map(|tree| {
        soc::board(tree).unwrap_or_else(|error| {
            output::arguments(format_args!("board refusal: {error}\n"));
            output::fatal("the board could not be modeled")
        })
    });
    if let Some(image) = nor_image {
        match board.as_mut().and_then(|board| board.spi_nor.as_mut()) {
            Some(spi) => spi.image = image,
            None => output::fatal("--nor was supplied but this DeviceTree exposes no modeled NOR"),
        }
    }
    let profile = match &board {
        Some(board) => board_profile(board, target, speculation),
        None => test_profile(),
    };
    // The real kernelcache starts SPTM at EL2: it writes TPIDR_EL2 and keeps
    // its per-CPU pointer in TPIDR_GL2. HCR_EL2.E2H is RES1 on this profile
    // (SPTM installs its vectors through VBAR_EL1 before it ORs TGE and E2H
    // into HCR_EL2, which reaches VBAR_EL2 only with E2H already set); the
    // other HCR_EL2 bits reset to 0. Stela's test kernel runs at EL1.
    let el = if options.bundle { 2 } else { 1 };
    output::arguments(format_args!(
        "ENTRY pc={entry:#x} x0={x0:#x} el={el} mmu=off profile={} target={} apic_hz={apic_hz} \
         prediction_isolation={} faulting_data_barrier={}\n",
        profile.name,
        target.id(),
        speculation.contexts,
        speculation.faulting_data,
    ));
    let mut cpu = Cpu::of(profile.chip, entry, Pstate::reset(el));
    cpu.state.x[0] = x0;
    if el == 1 {
        // An EL1 entry gets the EL2 state boot firmware leaves for its
        // client: the physical counter and timer are not trapped
        // (CNTHCTL_EL2.EL1PCTEN, EL1PTEN with E2H set).
        cpu.registers
            .set(Register::CNTHCTL_EL2, 0, 1 << 10 | 1 << 11);
    }
    let now = stela_runtime::machine::Host::counter(&mut bare);
    let reset = options.bundle.then_some(entry);
    // Board device firmware images travel in the bundle by guest file name.
    let files = &handoff.files[..handoff.file_count];
    let firmware = |name: &str| -> Option<&[u8]> {
        match built.as_deref() {
            Some(built) => built
                .iter()
                .find(|(file, _)| file == name)
                .map(|(_, bytes)| bytes.as_slice()),
            None => files
                .iter()
                .find(|file| file.name() == name)
                .map(bundle::contents),
        }
    };
    let (devices, restore_usb) = match devices(
        board.as_ref(),
        read_only_region,
        reset,
        Clock {
            now,
            wall: handoff.wall_seconds.map(|seconds| WallClock {
                // The firmware's time, carried forward to the counter's `now`.
                unix_seconds: seconds + (host::rdtsc() - handoff.wall_tsc) / handoff.tsc_hz,
                counter: now,
            }),
        },
        Disks {
            backing,
            sep_state,
            sep_observe: options.sep_observe,
            agx_observe: options.agx_observe,
        },
        Cables {
            restore: options.restore || options.install.is_some(),
            input: options.input,
            usb: stela_runtime::machine::apple::UsbCables {
                disks: usb_disks,
                network: guest_network.as_ref().map(network::GuestNetwork::mac),
            },
            screen: handoff.screen,
        },
        &firmware,
    ) {
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
    machine.set_idle_skip(options.idle_skip);
    let strict = options.strict || options.restore;
    machine.set_strict(strict);
    machine.devices.set_strict(strict);
    output::arguments(format_args!(
        "UNSUPPORTED OPERATIONS {}\n",
        if strict {
            "strict: the first one stops the machine"
        } else {
            "graceful: each takes the SoC's error response and is reported once as UNMODELED"
        }
    ));
    if options.tss {
        output::arguments(format_args!(
            "TSS OPT-IN: the restore host may send this machine's ECID and component hashes \
             to gs.apple.com; this build's restore host does not request a LocalPolicy yet\n"
        ));
    }
    // Waits return to this loop often enough that a press of the host's
    // power button reaches a sleeping SoC, and other host inputs a waiting
    // guest, promptly.
    machine.set_wait_limit(Some(host::COUNTER_HZ / WAIT_POLLS_PER_SECOND));
    if !options.breakpoints.is_empty() {
        machine.set_breakpoints(&options.breakpoints);
    }
    if !options.traces.is_empty() {
        machine.set_traces(&options.traces);
    }
    if !options.watches.is_empty() {
        machine.set_watches(&options.watches);
    }
    let mut restore = source.map(|source| {
        // `--tss` hands the restore client Apple's signing service, for the
        // machine whose ECID the bundle names (`/chosen unique-chip-id`).
        let signer = options.tss.then(|| {
            let ecid = tree
                .and_then(stela_runtime::machine::adt::Node::root)
                .and_then(|root| root.child("chosen"))
                .and_then(|chosen| chosen.property("unique-chip-id"))
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_le_bytes)
                .filter(|&ecid| ecid != 0)
                .unwrap_or_else(|| {
                    output::fatal(
                        "--tss needs the bundle's machine ECID (stela boot prepare --ecid)",
                    )
                });
            stela_runtime::restore::tss::Signer {
                ecid,
                transport: alloc::boxed::Box::new(
                    host_network.take().expect("--tss opens the host network"),
                ),
            }
        });
        let mode = match (&options.install, options.update_restore) {
            (Some(_), false) => restore::Mode::Install,
            (Some(_), true) => restore::Mode::Update,
            (None, _) => restore::Mode::Study,
        };
        restore::Experiment::new(
            source,
            restore_usb.unwrap(),
            handoff,
            mode,
            options.restore_identity,
            match options.verify_on_read {
                true => Verify::OnRead,
                false => Verify::Full,
            },
            signer,
        )
        .unwrap_or_else(|error| {
            output::arguments(format_args!("restore preparation refusal: {error}\n"));
            output::fatal("restore preparation failed")
        })
    });
    let mut host_input = host_input;
    let mut guest_network = guest_network;
    let mut host_power = power::HostPowerControl::new(handoff.power, handoff.tsc_hz);
    let started = host::rdtsc();
    let stop = run(
        &mut machine,
        options.budget,
        display.as_mut(),
        handoff.tsc_hz,
        restore.as_mut(),
        host_input.as_mut(),
        guest_network.as_mut(),
        host_nor.as_mut(),
        &mut host_power,
    );
    let seconds = (host::rdtsc() - started) as f64 / handoff.tsc_hz as f64;
    finish(&mut machine, stop, seconds, &options.dumps, &host_power)
}

fn level_name(guarded: bool) -> &'static str {
    if guarded { "GL" } else { "EL" }
}

/// Blocks between checks of whether the screen or a heartbeat is due.
const SLICE: u64 = 1 << 18;

/// How often a wait of every PE returns to the run loop to take host
/// inputs (`Machine::set_wait_limit`).
const WAIT_POLLS_PER_SECOND: u64 = 20;

/// Seconds between heartbeats, which locate a guest that runs without output.
const BEAT_SECONDS: u64 = 10;

/// Run up to `budget` blocks (0: no limit), showing the guest framebuffer
/// about twice a second and at the stop, reporting the PE's position
/// every [`BEAT_SECONDS`], and making ANS namespace erases durable on the
/// host between slices and before the stop ([`erase`]).
#[allow(clippy::too_many_arguments)]
fn run(
    machine: &mut Machine<BareHost, AppleDevices>,
    budget: u64,
    mut display: Option<&mut display::Display>,
    tsc_hz: u64,
    mut restore: Option<&mut restore::Experiment>,
    mut host_input: Option<&mut input::HostInput>,
    mut guest_network: Option<&mut network::GuestNetwork>,
    mut host_nor: Option<&mut nor::HostNor>,
    host_power: &mut power::HostPowerControl,
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
    // Counter ticks spent compiling, the guest instructions compiled and
    // the blocks taken from the translation store, at the last beat.
    let mut translation = (
        machine.statistics.compile_ticks,
        machine.statistics.compiled_instructions,
        machine.statistics.stored,
    );
    // The PE's call chain at each slice end since the last heartbeat, and
    // how many of those were at EL0.
    let mut samples: Vec<[u64; CHAIN]> = Vec::new();
    let mut user = 0;
    let mut beats = 0u64;
    let mut host_erase = erase::HostErase::default();
    loop {
        let slice = machine.statistics.blocks + SLICE;
        let limit = if budget == 0 {
            slice
        } else {
            budget.min(slice)
        };
        let stop = machine.run(limit);
        unmodeled_report(machine);
        for hit in machine.take_trace_hits() {
            output::arguments(format_args!(
                "TRACE pc={:#x} pe={} el={} x0-x3={:#x} {:#x} {:#x} {:#x} lr={:#x} dropped={}\n",
                hit.pc,
                hit.pe,
                hit.el,
                hit.arguments[0],
                hit.arguments[1],
                hit.arguments[2],
                hit.arguments[3],
                hit.lr,
                hit.dropped
            ));
        }
        for hit in machine.take_watch_hits() {
            output::arguments(format_args!(
                "WATCH pc={:#x} pe={} {} pa={:#x} bytes={} value={:#x}{} dropped={}\n",
                hit.pc,
                hit.pe,
                if hit.write { "write" } else { "read" },
                hit.physical,
                hit.bytes,
                hit.value,
                if hit.completed { "" } else { " refused" },
                hit.dropped
            ));
        }
        while let Some(log) = machine.devices.take_usb_log() {
            use stela_runtime::machine::apple::UsbLog;
            match log {
                UsbLog::Descriptor(descriptor) => output::arguments(format_args!(
                    "USB descriptor type={} index={} lang={:#x} bytes={:02x?}\n",
                    descriptor.kind, descriptor.index, descriptor.language, descriptor.bytes
                )),
                UsbLog::MuxControl(bytes) => {
                    output::arguments(format_args!("USB mux control bytes={:02x?}\n", bytes))
                }
                UsbLog::MuxRejected(bytes) => {
                    output::arguments(format_args!("USB mux rejected bytes={:02x?}\n", bytes))
                }
                UsbLog::QueryTypeReply(bytes) => output::arguments(format_args!(
                    "USB QueryType reply bytes={:02x?} text={}\n",
                    bytes,
                    String::from_utf8_lossy(&bytes)
                )),
            }
        }

        while let Some(entry) = machine.devices.take_display_log() {
            display::print_log(&entry);
        }

        while let Some(log) = machine.devices.take_power_log() {
            use stela_runtime::machine::apple::PowerLog;
            match log {
                PowerLog::Sleep => output::arguments(format_args!(
                    "POWER SoC sleep: every PE is down after slpa\n"
                )),
                PowerLog::Wake(source) => {
                    output::arguments(format_args!("POWER SoC wake: {source}\n"))
                }
                PowerLog::Masked(source) => output::arguments(format_args!(
                    "POWER SoC wake by the {source} masked by the AP; still asleep\n"
                )),
            }
        }

        // A wait the limit or the host's inputs ended goes on like a slice.
        let waiting = matches!(stop, Stop::Waiting);
        if (waiting || matches!(stop, Stop::Budget))
            && let Some(experiment) = restore.as_deref_mut()
        {
            machine.exclude_host_time(|devices| experiment.poll(devices));
        }
        if let Some(input) = host_input.as_deref_mut() {
            machine.exclude_host_time(|devices| input.poll(devices));
        }
        if let Some(network) = guest_network.as_deref_mut() {
            machine.exclude_host_time(|devices| network.poll(devices));
        }
        if let Some(nor) = host_nor.as_deref_mut() {
            machine.exclude_host_time(|devices| nor.poll(devices));
        }
        machine.exclude_host_time(|devices| host_power.poll(devices));

        let sliced = waiting || matches!(stop, Stop::Budget) && limit != budget;
        if sliced {
            machine.exclude_host_time(|devices| host_erase.poll(devices));
        } else {
            machine.exclude_host_time(|devices| host_erase.finish(devices));
        }
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
            let beat_compiled = beat.3;
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
            translation = translation_report(machine, translation, compiled - beat_compiled);
            peers_report(machine);
            let stale = machine.stale_code();
            if stale.stale > 0 {
                output::arguments(format_args!("STALE {stale:?}\n"));
            }
            sample_report(&mut samples, user);
            timer_report(machine);
            for state in machine.devices.coprocessor_diagnostics() {
                output::arguments(format_args!("ASC {state}\n"));
            }
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
/// The frame records from `frame` on, read through the running PE's
/// translation regime (a parked PE's kernel frames share it).
fn frames(machine: &mut Machine<BareHost, AppleDevices>, label: &str, mut frame: u64) {
    for depth in 0..16 {
        let mut record = [0u8; 16];
        if frame == 0 || !frame.is_multiple_of(8) || !machine.read_virtual(frame, &mut record) {
            break;
        }
        let next = u64::from_le_bytes(record[..8].try_into().expect("8 bytes"));
        let link = u64::from_le_bytes(record[8..].try_into().expect("8 bytes"));
        output::arguments(format_args!("{label} {depth} fp={frame:#x} lr={link:#x}\n"));
        frame = next;
    }
}

/// The guest virtual ranges `--dump` names, 16 bytes a line, through the
/// stopped PE's translation regime.
fn dump_report(machine: &mut Machine<BareHost, AppleDevices>, dumps: &[(Base, u64)]) {
    for &(base, bytes) in dumps {
        let address = base.resolve(&machine.cpu.state.x);
        for line in (address..address + bytes).step_by(16) {
            let mut data = [0u8; 16];
            if !machine.read_virtual(line, &mut data) {
                output::arguments(format_args!("DUMP {line:#x}: unmapped\n"));
                break;
            }
            output::arguments(format_args!("DUMP {line:#x}:"));
            for word in data.as_chunks::<8>().0 {
                output::arguments(format_args!(" {:#018x}", u64::from_le_bytes(*word)));
            }
            output::arguments(format_args!("\n"));
        }
    }
}

fn stack_report(machine: &mut Machine<BareHost, AppleDevices>) {
    frames(machine, "FRAME", machine.cpu.state.x[29]);
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

/// Each unsupported operation answered outside strict mode for the first
/// time since the last report: machine effects and device accesses, then
/// coprocessor requests answered with their firmware's error reply.
fn unmodeled_report(machine: &mut Machine<BareHost, AppleDevices>) {
    for requirement in machine.take_unmodeled() {
        output::arguments(format_args!("UNMODELED {requirement}\n"));
    }
    for line in machine.devices.take_unmodeled() {
        output::arguments(format_args!("UNMODELED {line}\n"));
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

fn general_registers(cpu: &Cpu) {
    for (index, pair) in cpu.state.x.chunks(4).enumerate() {
        output::arguments(format_args!("X{}:", index * 4));
        for value in pair {
            output::arguments(format_args!(" {value:#018x}"));
        }
        output::arguments(format_args!("\n"));
    }
}

/// The translation cost since the last beat, `last` its compile ticks,
/// compiled instructions and stored blocks then, for the `compiled` blocks
/// compiled since: nanoseconds per block and per guest
/// instruction, and the blocks the translation store gave. The new `last`.
fn translation_report(
    machine: &Machine<BareHost, AppleDevices>,
    last: (u64, u64, u64),
    compiled: u64,
) -> (u64, u64, u64) {
    const NANOSECONDS: u128 = 1_000_000_000;
    let statistics = &machine.statistics;
    let now = (
        statistics.compile_ticks,
        statistics.compiled_instructions,
        statistics.stored,
    );
    let nanoseconds =
        u128::from(now.0.wrapping_sub(last.0)) * NANOSECONDS / u128::from(host::COUNTER_HZ);
    let instructions = now.1 - last.1;
    if compiled != 0 {
        output::arguments(format_args!(
            "TRANSLATION blocks={compiled} instructions={instructions} ns/block={} \
             ns/instruction={} stored={}\n",
            nanoseconds / u128::from(compiled),
            nanoseconds / u128::from(instructions.max(1)),
            now.2 - last.2,
        ));
    }
    now
}

/// Where every PE is: `R` running, `-` held in reset, `d` powered down,
/// or a parked PE's PC and its wait (`i` WFI, `e` WFE, `p` preempted), with
/// the switch count.
fn peers_report(machine: &Machine<BareHost, AppleDevices>) {
    output::arguments(format_args!("PES switches={}", machine.statistics.switches));
    for (number, state) in machine.peer_states().into_iter().enumerate() {
        match state {
            PeerState::Running => output::arguments(format_args!(" {number}:R")),
            PeerState::Off => output::arguments(format_args!(" {number}:-")),
            PeerState::Down => output::arguments(format_args!(" {number}:d")),
            PeerState::Parked { cpu, wfi } => {
                let wait = match wfi {
                    Some(true) => 'i',
                    Some(false) => 'e',
                    None => 'p',
                };
                output::arguments(format_args!(" {number}:{:#x}/{wait}", cpu.pc));
            }
        }
    }
    output::arguments(format_args!("\n"));
}

/// A PE's PC and its EL1 and EL2 exception registers.
struct Registers<'a>(&'a Cpu);

impl fmt::Display for Registers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cpu = self.0;
        write!(
            f,
            "pc={:#x} el={} sp={:#x} daif={:#x} nzcv={:#x}",
            cpu.pc, cpu.pstate.el, cpu.state.sp, cpu.pstate.daif, cpu.state.nzcv,
        )?;
        let banks = [
            (
                1,
                [
                    Register::ELR_EL1,
                    Register::SPSR_EL1,
                    Register::ESR_EL1,
                    Register::FAR_EL1,
                    Register::VBAR_EL1,
                    Register::SCTLR_EL1,
                ],
            ),
            (
                2,
                [
                    Register::ELR_EL2,
                    Register::SPSR_EL2,
                    Register::ESR_EL2,
                    Register::FAR_EL2,
                    Register::VBAR_EL2,
                    Register::SCTLR_EL2,
                ],
            ),
        ];
        for (el, bank) in banks {
            let [elr, spsr, esr, far, vbar, sctlr] = bank.map(|register| cpu.read(register));
            write!(
                f,
                " el{el}: elr={elr:#x} spsr={spsr:#x} esr={esr:#x} far={far:#x} vbar={vbar:#x} sctlr={sctlr:#x}"
            )?;
        }
        for (level, bank) in cpu.apple.guarded.iter().enumerate() {
            write!(
                f,
                " gl{}: elr={:#x} spsr={:#x} esr={:#x} far={:#x} vbar={:#x}",
                level + 1,
                bank.elr,
                bank.spsr,
                bank.esr,
                bank.far,
                bank.vbar
            )?;
        }
        write!(
            f,
            " guarded={} cntkctl={:#x} cnthctl={:#x}",
            cpu.pstate.guarded,
            cpu.read(Register::CNTKCTL_EL1),
            cpu.read(Register::CNTHCTL_EL2)
        )
    }
}

fn finish(
    machine: &mut Machine<BareHost, AppleDevices>,
    stop: Stop,
    seconds: f64,
    dumps: &[(Base, u64)],
    host_power: &power::HostPowerControl,
) -> ! {
    survey_report(machine);
    unmodeled_report(machine);
    stack_report(machine);
    dump_report(machine, dumps);
    let host = host::statistics();
    output::arguments(format_args!(
        "STATISTICS {:?} shadow_fills={} shadow_prefills={} shadow_resets={} lower_resets={} scoped_invalidations={} stray_interrupts={} events={} seconds={seconds:.3}\n",
        machine.statistics,
        host.fills,
        host.prefills,
        host.resets,
        host.lower_resets,
        host.scoped,
        host.stray,
        EVENTS.load(Ordering::Relaxed),
    ));
    exit_report(machine);
    output::arguments(format_args!("FINAL {}\n", Registers(&machine.cpu)));
    let mut parked_frames = Vec::new();
    for (number, state) in machine.peer_states().into_iter().enumerate() {
        let PeerState::Parked { cpu, wfi } = state else {
            output::arguments(format_args!("PE {number} {state:?}\n"));
            continue;
        };
        let wait = match wfi {
            Some(true) => "wfi",
            Some(false) => "wfe",
            None => "none",
        };
        output::arguments(format_args!(
            "PE {number} parked wait={wait} {}\n",
            Registers(cpu)
        ));
        general_registers(cpu);
        parked_frames.push((number, cpu.state.x[29]));
    }
    for (number, frame) in parked_frames {
        frames(machine, &alloc::format!("PE {number} FRAME"), frame);
    }
    let cpu = &machine.cpu;
    for (entry, reads, writes) in cpu.apple.impdef.used() {
        output::arguments(format_args!(
            "IMPDEF {} {:?} reads={reads} writes={writes}: {}\n",
            entry.name, entry.class, entry.evidence
        ));
    }
    general_registers(cpu);
    for line in machine.devices.sep_observations() {
        output::arguments(format_args!("SEP OBSERVE {line}\n"));
    }
    for line in machine.devices.agx_observations() {
        output::arguments(format_args!("{line}\n"));
    }
    match stop {
        Stop::Idle => {
            output::arguments(format_args!(
                "STOP idle: every PE is off or waits with no wake source\n"
            ));
            output::terminate(0x10)
        }
        Stop::Waiting => {
            output::arguments(format_args!(
                "STOP waiting: every PE waits for an input from outside the board\n"
            ));
            output::terminate(0x10)
        }
        Stop::Reset(reset) => {
            output::arguments(format_args!("STOP reset: {reset}\n"));
            translations::write();
            match reset.transition {
                Transition::Restart => host_power.restart(),
                Transition::PowerOff => host_power.power_off(),
                Transition::Halt => output::terminate(power::RESTART_CODE),
            }
        }
        Stop::Budget => {
            output::arguments(format_args!("STOP budget\n"));
            output::terminate(0x14)
        }
        Stop::Unsupported(requirement) => {
            output::arguments(format_args!("STOP UNSUPPORTED {requirement}\n"));
            output::terminate(0x13)
        }
        Stop::Breakpoint(pc) => {
            output::arguments(format_args!("STOP breakpoint pc={pc:#x}\n"));
            output::terminate(0x16)
        }
    }
}
