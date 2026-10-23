//! System mode, engine phase: runs in the Stela window after the loader has
//! loaded the engine's tables, switching to LA57 when the host has it. Host
//! physical memory is reached through the physmap.
//! Stela's host drivers address registers and DMA pages by identity, so
//! every access runs on the loader's identity map and its uncached device
//! mappings (`storage`). The hardware is probed once, before the host is
//! installed; `--preboot` builds the boot bundle from the installed
//! system's partition that probe opened.

pub(crate) mod bundle;
mod console_lines;
mod display;
mod erase;
pub(crate) mod host;
mod input;
pub(crate) mod install;
pub(crate) mod interrupts;
mod network;
pub(crate) mod nor;
pub(crate) mod power;
mod restore;
mod speculation;
pub(crate) mod storage;
mod topology;
pub(crate) mod translations;

use crate::{
    handoff::{Handoff, MAGIC},
    layout, output,
};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::{
    arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count},
    },
    cell::RefCell,
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use host::{Config, RamRange};
use stela_compiler::TargetCpu;
use stela_loader::{
    boot_bundle,
    boot_selection::{self, BootVolume},
    handoff::BootCommand as FirmwareBootCommand,
    installed, recovery,
};
use stela_runtime::machine::apple::WallClock;
use stela_runtime::machine::{
    Chip, Cpu, CpuProfile, Event, Host, Machine, PeerState, Stop, Transition,
    apple::{AicInput, AicLayout, AppleDevices, ConsoleBusy, ConsoleSink, Range},
    exception::Pstate,
    identification::Speculation,
    mount,
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
/// The restore host refuses a payload without recorded block hashes, which
/// it would read whole before StartRestore (`restore::store::Verify`).
pub const VERIFY_ON_READ_OPTION: &str = "--verify-on-read";
/// Stop at the first unsupported operation instead of answering it degraded
/// and reporting it (docs/design/runtime.md "Unsupported operations").
pub const STRICT_OPTION: &str = "--strict";
/// The install restores with the inventory's Update identity, over the
/// installed system and keeping its data, instead of erasing the target.
pub const UPDATE_RESTORE_OPTION: &str = "--update-restore";
/// Every host disk the engine leaves is the guest's external drive.
pub const EXTERNAL_DISKS_OPTION: &str = "--external-disks";

/// Apple T8112 DRAM base (Asahi Linux T8112 notes; the DeviceTree `/memory`).
const DRAM_BASE: u64 = 0x8_0000_0000;
/// The guest DRAM asked for without `--ram-bytes`, and the least a smaller
/// host may shrink a larger request to.
pub(crate) const DEFAULT_RAM: u64 = 4 << 30;
/// The most guest DRAM bytes, which a host with less free RAM shrinks to
/// whole GiB.
pub(crate) const RAM_OPTION: &str = "--ram-bytes";
/// The most of the engine heap (at least 512 MiB) `--storage-ram` may
/// take for written blocks; a restore or recovery boot writes far less.
const RAM_STORAGE_LIMIT: usize = 64 << 20;
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
    /// The entry origin retained after NVRAM's one-shot command is consumed.
    boot_command: Option<FirmwareBootCommand>,
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
    /// Instead, this many bytes of engine memory back them, and nothing
    /// persists (`--storage-ram`, `stela_drivers::block::Volatile`).
    storage_ram: Option<u64>,
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
    /// Refuse a payload without recorded block hashes, which would be read
    /// whole before StartRestore (`--verify-on-read`).
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
    /// Opt-in diagnostic of actual native pinned RAM in the shared window.
    native_memory_check: bool,
    /// Fixed physical native executors; never counts SMT siblings.
    native_cores: Option<usize>,
    /// Qualify owned AP startup/host resources, then stop before guest entry.
    native_bootstrap_check: bool,
    /// Bounded actual checked-memory kernel execution on the selected cores.
    native_shared_check: bool,
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
    /// Qualify exclusively owned conventional HDA after ExitBootServices.
    audio_check: Option<crate::audio_check::Mode>,
    /// Whole host disks, by serial, that the guest sees as USB mass
    /// storage behind the native hub (`--usb-storage SERIAL`, repeatable).
    usb_storage: Vec<String>,
    /// Every other host disk the engine does not open itself is USB mass
    /// storage too, up to the hub's free ports (`--external-disks`): the
    /// PC's disks are a Mac's external drives, which recoveryOS partitions,
    /// formats and installs macOS onto.
    external_disks: bool,
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
    /// instead of answering it degraded and reporting it once
    /// (docs/design/runtime.md "Unsupported operations"). Off by default
    /// for every run, restore studies included; `cargo xtask boot run`
    /// passes it with `--strict` or `STELA_STRICT=1`.
    strict: bool,
    /// Stop when a PE reaches one of these guest PCs (`--break`), with the
    /// stop's report.
    breakpoints: Vec<u64>,
    /// Log, without stopping, when a PE reaches one of these guest PCs
    /// (`--trace`; `Machine::set_traces`).
    traces: Vec<u64>,
    /// Log raw guarded entries, exits, exceptions and returns (`--monitor-trace`).
    monitor_trace: bool,
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

pub(crate) fn number(value: &str) -> Result<u64, &'static str> {
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
            boot_command: None,
            upgrade: false,
            recovery: None,
            storage: None,
            storage_ram: None,
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
            native_memory_check: false,
            native_cores: crate::native_smp::requested(text)?,
            native_bootstrap_check: false,
            native_shared_check: false,
            tss: false,
            ecid: None,
            network_check: None,
            audio_check: None,
            usb_storage: Vec::new(),
            external_disks: false,
            guest_network: false,
            sep_observe: false,
            agx_observe: false,
            strict: false,
            breakpoints: Vec::new(),
            traces: Vec::new(),
            monitor_trace: false,
            watches: Vec::new(),
            dumps: Vec::new(),
        };
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some("--system") {
            return Err("system options must start with --system");
        }
        while let Some(name) = words.next() {
            if name == "--monitor-trace" {
                options.monitor_trace = true;
                continue;
            }
            if name == "--native-shared-check" {
                if options.native_shared_check {
                    return Err("duplicate native shared check");
                }
                options.native_shared_check = true;
                continue;
            }
            if name == "--native-bootstrap-check" {
                if options.native_bootstrap_check {
                    return Err("duplicate native bootstrap check");
                }
                options.native_bootstrap_check = true;
                continue;
            }
            if name == crate::native_smp::OPTION {
                words.next().ok_or("missing native physical-core count")?;
                continue;
            }
            if name == "--native-memory-check" {
                options.native_memory_check = true;
                continue;
            }
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
            if name == EXTERNAL_DISKS_OPTION {
                options.external_disks = true;
                continue;
            }
            if name == "--audio-check" {
                if options.audio_check.is_some() {
                    return Err("duplicate audio check");
                }
                options.audio_check = Some(crate::audio_check::Mode::parse(
                    words.next().ok_or("missing audio check mode")?,
                )?);
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
                if options.storage_ram.is_some() || options.storage.replace(target).is_some() {
                    return Err("system mode accepts exactly one ANS backing");
                }
                continue;
            }
            if name == "--storage-ram" {
                let bytes = number(words.next().ok_or("missing RAM storage size")?)?;
                if options.storage.is_some() || options.storage_ram.replace(bytes).is_some() {
                    return Err("system mode accepts exactly one ANS backing");
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
            if name == boot_selection::BOOT_COMMAND_OPTION {
                let value = number(words.next().ok_or("missing boot command")?)?;
                let value = u8::try_from(value).map_err(|_| "boot command is not a byte")?;
                let command = FirmwareBootCommand::try_from(value)?;
                if options.boot_command.replace(command).is_some() {
                    return Err("duplicate boot command");
                }
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
                RAM_OPTION => options.ram_bytes = value,
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
                || options.boot_command.is_some()
                || options.safe_boot
                || options.upgrade
                || options.recovery.is_some())
        {
            return Err(
                "--boot-volume, --boot-command, --safe-boot, --upgrade, --paired-recovery and --system-recovery \
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
    let (vendor, basic, extended) = (__cpuid(0), __cpuid(1), __cpuid_count(7, 0));
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
        // Optional plain 128-bit loads need a documented vendor guarantee.
        (
            TargetCpu::atomic_load16_guaranteed([vendor.ebx, vendor.edx, vendor.ecx], basic.ecx),
            TargetCpu::with_atomic_load16,
        ),
        (extended.ebx & (1 << 3) != 0, TargetCpu::with_bmi1),
        (extended.ebx & (1 << 29) != 0, TargetCpu::with_sha),
        (
            [vendor.ebx, vendor.edx, vendor.ecx] == TargetCpu::INTEL_VENDOR,
            TargetCpu::with_line_atomic,
        ),
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

/// Assign guest DRAM from the free host ranges, lowest first: the bytes
/// asked for, or on a host with less free RAM what it has in whole GiB, down
/// to [`DEFAULT_RAM`] (`docs/design/system.md#memory-sizing`).
fn guest_ram(handoff: &Handoff, options: &mut Options) -> Result<Vec<RamRange>, &'static str> {
    const GIB: u64 = 1 << 30;
    let regions = &handoff.guest[..handoff.guest_count];
    let available: u64 = regions.iter().map(|region| region.bytes).sum();
    let requested = options.ram_bytes;
    if available < requested {
        if available < requested.min(DEFAULT_RAM) {
            output::arguments(format_args!(
                "guest DRAM requested={requested:#x} available={available:#x}\n"
            ));
            return Err("not enough free host RAM for the requested guest DRAM");
        }
        options.ram_bytes = (available / GIB * GIB).max(requested.min(DEFAULT_RAM));
        output::arguments(format_args!(
            "guest DRAM shrunk from {requested:#x} to {:#x}: the host has {available:#x} free\n",
            options.ram_bytes
        ));
    }
    let mut ranges = Vec::new();
    let mut assigned = 0;
    for region in regions {
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
/// (`machine::soc::board`), with the selected handoff PE running with EL2 as a VHE host. The
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
struct GuestConsole {
    lines: console_lines::Lines,
}

impl ConsoleSink for GuestConsole {
    fn transmit(&mut self, byte: u8) -> Result<(), ConsoleBusy> {
        if let Some(fragment) = self.lines.push(byte) {
            if let Ok(mut panic) = GUEST_PANIC.0.try_borrow_mut() {
                panic.observe(&fragment);
            }
            let line = fragment.text;
            output::arguments(format_args!("GUEST| {line}\n"));
            if !fragment.complete {
                output::arguments(format_args!(
                    "GUEST-FRAGMENT bytes={} continues=1\n",
                    fragment.bytes
                ));
            }
            if !line.trim().is_empty()
                && let Ok(mut lines) = GUEST_LINES.0.try_borrow_mut()
            {
                if lines.len() == crate::status::STREAM_LINES {
                    lines.remove(0);
                }
                lines.push(line.clone());
            }
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

/// The board's devices ([`mount::devices`]), or without a DeviceTree (the
/// test kernel) the J473AP console UART, watchdog and AIC2.
fn devices(
    board: Option<&soc::Board>,
    inputs: mount::Inputs<'_>,
    memory: Option<mount::MemoryResources>,
) -> Result<(AppleDevices, Option<stela_runtime::machine::apple::UsbId>), String> {
    if let Some(board) = board {
        return mount::devices_with_memory(
            board,
            GuestConsole::default(),
            inputs,
            memory,
            &mut |arguments| output::arguments(arguments),
        );
    }
    if memory.is_some() {
        return Err(String::from(
            "native board memory requires a live assigned DeviceTree",
        ));
    }
    if inputs.backing.is_some() {
        return Err("--storage was supplied but this DeviceTree exposes no modeled ANS2".into());
    }
    if inputs.restore {
        return Err("restore study requires a DT-placed USB device".into());
    }
    let place = |(offset, bytes, irq): (u64, u64, u32)| {
        (
            Range {
                physical: ARM_IO + offset,
                bytes,
            },
            AicInput::new(0, irq as u16),
        )
    };
    let (uart, wdt) = (place(J473_UART), place(J473_WDT));
    let mut devices = AppleDevices::new();
    devices
        .add_uart(GuestConsole::default(), &[uart.0], Some(uart.1))
        .map_err(|error| alloc::format!("UART placement: {error:?}"))?;
    devices
        .add_watchdog_with_side(wdt.0, None, Some(wdt.1), inputs.now)
        .map_err(|error| alloc::format!("watchdog placement: {error:?}"))?;
    devices.add_aic(
        ARM_IO + J473_AIC.0,
        J473_AIC.1,
        AicLayout::aic2(J473_AIC_EVENT, J473_AIC_TIMESTAMPS),
    )?;
    Ok((devices, None))
}

static EVENTS: AtomicU64 = AtomicU64::new(0);
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn report(event: &Event) {
    // Explicit monitor traces bypass the ordinary progress-event limit
    // without consuming its reporting allowance.
    if let Event::Monitor(trace) = event {
        output::arguments(format_args!(
            "MONITOR pe={} kind={:?} from={}{}:{:#x} il={} to={}{}:{:#x} il={} \
             x0-x7={:x?} x16={:#x} x17={:#x} lr={:#x}\n",
            trace.pe,
            trace.kind,
            level_name(trace.from.guarded),
            trace.from.el,
            trace.from.pc,
            trace.from.illegal,
            level_name(trace.to.guarded),
            trace.to.el,
            trace.to.pc,
            trace.to.illegal,
            trace.arguments,
            trace.x16,
            trace.x17,
            trace.lr,
        ));
        return;
    }
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
        Event::Monitor(_) => unreachable!("monitor traces are emitted before event throttling"),
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
/// How long a restart or power-off the guest asks for waits, so its reason
/// can be read on the screen first.
const STOP_HOLD_SECONDS: u64 = 10;

/// Show why the machine stopped on Stela's own screen, which it takes back
/// from the guest's last frame: the running step fails with `text`.
fn show_stop(text: &str) {
    crate::console::reclaim();
    crate::status::fail(text);
}

/// [`show_stop`], then halt until the PC is turned off.
fn stop_here(text: &str, code: u32) -> ! {
    show_stop(text);
    crate::status::info("Stela stopped. Turn the PC off to try again.");
    output::terminate(code)
}

/// The guest's console lines since the run loop showed them, the last
/// `status::STREAM_LINES` at most.
static GUEST_LINES: output::Global<Vec<String>> = output::Global(RefCell::new(Vec::new()));

/// The restore step `line` begins, by name, as the running step's detail.
fn installer_step(line: &str) -> Option<String> {
    // `[08:34:20.0721-GMT]{5>7} CHECKPOINT BEGIN: RESTORED:[0x067C] fdr_create`
    let (_, step) = line.split_once("CHECKPOINT BEGIN: ")?;
    let name = step.rsplit_once(']').map_or(step, |(_, name)| name);
    Some(format!("installer: {}", name.trim().replace('_', " ")))
}

/// The first kernel panic line the guest printed, which names a stop
/// better than how the machine went down after it.
static GUEST_PANIC: output::Global<console_lines::Panic> =
    output::Global(RefCell::new(console_lines::Panic::new()));

/// The first explicit panic header, falling back to nested metadata if the
/// buffered original header has not arrived. Repeated headers never replace it.
fn guest_panic() -> Option<String> {
    GUEST_PANIC
        .0
        .try_borrow()
        .ok()
        .and_then(|panic| panic.message().map(String::from))
}

/// How the guest went down: the first panic, else `otherwise`.
fn guest_down(otherwise: String) -> String {
    match guest_panic() {
        Some(message) => format!("macOS crashed: {message}"),
        None => otherwise,
    }
}

/// The boot bundle `--preboot` names, built from the installed system on
/// `partition`: its macOS, its staged update or its recoveryOS.
fn from_disk(
    partition: alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>,
    options: &Options,
) -> Vec<(String, Vec<u8>)> {
    crate::status::begin("Reading macOS's boot files from its disk");
    // The kernel's text on the screen and on the debug UART, which the
    // boot log records, as setup's bundles have it.
    let defaults = boot_bundle::Options {
        ecid: options.ecid,
        boot_command: options.boot_command,
        boot_args: "-v serial=3 serial-device-name=uart0".into(),
        ..boot_bundle::Options::default()
    };
    let result = if options.upgrade {
        bundle::upgrade_from_disk(partition, options.boot_volume, &defaults)
    } else if let Some(kind) = options.recovery {
        bundle::recovery_from_disk(partition, kind, options.boot_volume, &defaults)
    } else {
        let request = installed::Request {
            volume: options.boot_volume,
            ..installed::Request::default()
        };
        let mut defaults = defaults;
        if options.safe_boot {
            defaults.boot_args.push_str(" -x");
        }
        bundle::from_disk(partition, &request, &defaults)
    };
    let files = result.unwrap_or_else(|error| {
        output::arguments(format_args!("preboot refusal: {error}\n"));
        output::fatal("no boot bundle could be built from the Preboot volume")
    });
    let bytes: usize = files.iter().map(|(_, contents)| contents.len()).sum();
    crate::status::done(&format!("{} MB", bytes.div_ceil(1 << 20)));
    files
}

pub extern "sysv64" fn entry(handoff: u64) -> ! {
    output::disable_firmware_console();
    // SAFETY: the first engine code; interrupts are off and nothing else runs.
    unsafe { interrupts::install(interrupts::interrupt) };
    // SAFETY: the loader wrote the handoff page and passed its physmap address.
    let handoff = unsafe { &*(handoff as *const Handoff) };
    if handoff.magic != MAGIC {
        output::fatal("engine handoff has the wrong magic");
    }
    layout::set(handoff.placement);
    // SAFETY: the window heap is reserved for this allocator and still unused.
    unsafe { crate::ALLOCATOR.initialize(layout::heap() as *mut u8, handoff.heap.bytes as usize) };
    // SAFETY: this phase owns the reserved heap and its shared-window WB map.
    unsafe {
        crate::native_memory::initialize(
            layout::heap() as usize,
            handoff.heap.physical,
            handoff.heap.bytes as usize,
            layout::physical(0),
        )
    };
    // SAFETY: loader-reserved immutable pages, retained in every shared-window
    // physmap; metadata and Arc are created in this active engine allocator.
    let host_firmware =
        unsafe { handoff.host_firmware.after_ebs() }.unwrap_or_else(|error| output::fatal(error));
    crate::status::set_clock(handoff.tsc_hz);
    stela_drivers::on_wait(crate::status::tick);
    stela_drivers::on_work(crate::status::progress);
    crate::status::take_screen(
        handoff
            .screen
            .map(|screen| screen.relocated(layout::physical(screen.base as u64) as usize)),
    );
    crate::status::replay(&handoff.history[..handoff.history_bytes]);
    output::arguments(format_args!(
        "STELA SYSTEM ENGINE window={:#x} placement={:?} tsc_hz={} guest_ranges={} \
         heap={}M code={}M pool={}M\n",
        layout::window(),
        handoff.placement,
        handoff.tsc_hz,
        handoff.guest_count,
        handoff.heap.bytes >> 20,
        handoff.code.bytes >> 20,
        handoff.pool.bytes >> 20,
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
    // SAFETY: the loader handoff and all reservations stay pinned in the physmap.
    let native_processors = unsafe { crate::native_smp::validate(handoff, options.native_cores) }
        .unwrap_or_else(|error| output::fatal(error));
    if (options.native_bootstrap_check || options.native_shared_check)
        && options.native_cores.is_none()
    {
        output::fatal("native bootstrap check needs an explicit physical-core count");
    }
    if options.native_memory_check {
        match crate::native_memory::verify() {
            Ok(()) => output::arguments(format_args!(
                "CHECK native-memory PASS WB native pages: zero/read/write, CPU pin lifetime/reclaim, cache/alignment/bounds refusal; Linux PFN/refcount/compound/split/retirement\n"
            )),
            Err(error) => {
                output::arguments(format_args!("CHECK native-memory FAIL {error:?}\n"));
                output::fatal("native pinned RAM verification failed");
            }
        }
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
    if let Some(mode) = options.audio_check {
        let audio_handoff = handoff
            .storage
            .handoff()
            .unwrap_or_else(|| output::fatal("the loader found no host device handoff"));
        // SAFETY: --audio-check explicitly grants sole conventional HDA ownership;
        // before host::install, the retained identity root and DMA pages are live.
        unsafe { crate::audio_check::run(&audio_handoff, mode) }.unwrap_or_else(|error| {
            output::arguments(format_args!("AUDIO CHECK failed: {error}\n"));
            output::fatal("the audio check failed")
        });
    }
    let wants_network = options.tss || options.network_check.is_some();
    let (services, medium, preboot, host_input, host_network, usb_disks, guest_network, host_disks) =
        if targets.is_empty()
            && options.install_source.is_none()
            && options.preboot.is_none()
            && !options.input
            && !wants_network
            && options.usb_storage.is_empty()
            && !options.external_disks
            && !options.guest_network
            && translation_store.is_none()
        {
            (
                Vec::new(),
                None,
                None,
                None,
                None,
                Vec::new(),
                None,
                storage::HostDisks::none(),
            )
        } else {
            let mut storage_handoff = handoff
                .storage
                .handoff()
                .unwrap_or_else(|| output::fatal("the loader found no storage controllers"));
            storage_handoff.firmware = host_firmware.clone();
            if options.audio_check.is_some() {
                // The audio check retains the final slice even after shutdown.
                storage_handoff.dma.end -= crate::audio_check::DMA_BYTES;
            }
            crate::status::begin("Starting the PC's disks and USB devices");
            // SAFETY: before host::install, with sole ownership of DMA/controllers.
            let storage::Opened {
                services,
                medium,
                preboot,
                store,
                log,
                inputs,
                mut links,
                usb_disks,
                disks,
            } = unsafe {
                storage::open(
                    &storage_handoff,
                    &storage::Partitions {
                        targets: &targets,
                        medium: options.install_source,
                        preboot: options.preboot.as_ref(),
                        store: translation_store,
                        log: handoff.log_partition.map(Guid),
                    },
                    &options.usb_storage,
                    options.external_disks.then(|| {
                        stela_runtime::machine::apple::UsbCables::disk_ports(options.guest_network)
                            .saturating_sub(options.usb_storage.len())
                    }),
                )
            }
            .unwrap_or_else(|error| {
                output::arguments(format_args!("host storage refusal: {error}\n"));
                output::fatal(&format!("host storage could not be opened: {error}"))
            });
            let count = |count: usize, one: &str, many: &str| {
                format!("{count} {}", if count == 1 { one } else { many })
            };
            let partitions = count(
                services.len() + usize::from(medium.is_some()),
                "partition",
                "partitions",
            );
            crate::status::done(&match usb_disks.len() {
                0 => partitions,
                disks => format!(
                    "{partitions}, and {} macOS sees as USB drives",
                    count(disks, "disk", "disks")
                ),
            });
            if let Some(log) = log {
                crate::log_file::resume(log);
            }
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
            // A missing network is reported here and refused only by what
            // needs it, so the mount still boots and logs how far it gets.
            let network = wants_network.then(|| {
                crate::status::begin("Getting a network address");
                network::HostNetwork::open(links, storage_handoff.clock)
                    .inspect(|network| crate::status::done(network.describe()))
                    .inspect_err(|error| {
                        output::arguments(format_args!("host network refusal: {error}\n"));
                        crate::status::warn(error);
                    })
            });
            (
                services,
                medium,
                preboot,
                options.input.then(|| input::HostInput::new(inputs)),
                network,
                usb_disks,
                guest_network,
                disks,
            )
        };
    let built = preboot.map(|partition| from_disk(partition, &options));
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
    let ram = match guest_ram(handoff, &mut options) {
        Ok(ram) => ram,
        Err(error) => output::fatal(error),
    };
    for range in &ram {
        output::arguments(format_args!(
            "GUEST DRAM pa={:#x} bytes={:#x} host={:#x}\n",
            range.guest, range.bytes, range.host
        ));
    }
    let mut host_network = host_network;
    if let Some(url) = &options.network_check {
        let Some(Ok(network)) = host_network.as_mut() else {
            output::fatal("the network check failed")
        };
        let (host, path) = network::split_url(url).unwrap_or_else(|error| output::fatal(error));
        // Any HTTP status proves the path end to end; only a transport
        // failure (link, DHCP, DNS, TCP, malformed reply) fails the check.
        match network.post(host, path, "text/plain", b"") {
            Ok(body) => {
                output::arguments(format_args!(
                    "NETWORK CHECK body bytes={} sha256={}\n",
                    body.len(),
                    stela_runtime::sha256(&body)
                ));
                output::arguments(format_args!("NETWORK CHECK passed\n"))
            }
            Err(stela_runtime::net::NetError::Status(_)) => {
                output::arguments(format_args!("NETWORK CHECK passed\n"))
            }
            Err(_) => output::fatal("the network check failed"),
        }
    }
    // The restore client's signing-server transport (`restore::tss`)
    // takes `host_network` below; it lives for the whole run.
    let mut services = services.into_iter();
    let backing = options.storage.as_ref().map(|_| services.next().unwrap());
    let backing = backing.or_else(|| {
        let bytes = options.storage_ram?;
        let disk = stela_drivers::block::Volatile::new("STELARAM", bytes, RAM_STORAGE_LIMIT)
            .unwrap_or_else(|error| {
                output::arguments(format_args!("RAM storage refusal: {error}\n"));
                output::fatal("the RAM-backed storage could not be made")
            });
        output::arguments(format_args!(
            "STORAGE volatile: {bytes:#x} bytes of engine memory back the ANS namespaces, \
             at most {RAM_STORAGE_LIMIT:#x} written; nothing persists\n"
        ));
        Some(alloc::boxed::Box::new(disk)
            as alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>)
    });
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
            crate::status::begin("Finding the macOS install files on the USB");
            let opened = install::open(partition, &manifest, directory, hashes)?;
            crate::status::done("");
            Ok(restore::Source::new(opened))
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
    let nor = nor.map(|device| {
        crate::status::begin(&format!(
            "Opening the machine state on {}",
            device.identity().model
        ));
        let opened = nor::HostNor::open(device);
        crate::status::done("");
        opened
    });
    let (host_nor, nor_image, nvram, sep_state) = match nor {
        Some((host_nor, image, nvram, sep_state)) => {
            (Some(host_nor), Some(image), Some(nvram), Some(sep_state))
        }
        None => (None, None, None, None),
    };
    let partition = crate::native_smp::resources::partition(
        handoff.native_resources.cores as usize,
        0,
        handoff.code.bytes,
        handoff.pool.bytes,
    )
    .unwrap_or_else(|error| output::fatal(error));
    let native_tsc_base = host::rdtsc();
    let worker_ram = ram.clone();
    let config = Config {
        ram,
        pool_physical: handoff.pool.physical,
        pool_bytes: partition.pool_bytes,
        window_root: handoff.root,
        code_virtual: layout::code(),
        code_physical: handoff.code.physical,
        code_bytes: partition.code_bytes,
        tsc_base: native_tsc_base,
        tsc_hz: handoff.tsc_hz,
        apic_base: handoff.apic_base,
        placement: handoff.placement,
        bounce: Some((layout::bounce(), handoff.bounce)),
    };
    // SAFETY: once on the BSP, with interrupts off and owned native resources.
    // Retain the processor-local state through every native call and handler.
    let mut host_owner =
        unsafe { host::install(config) }.unwrap_or_else(|error| output::fatal(error));
    let apic_hz = host::statistics().apic_hz;
    // SAFETY: the retained physical inventory and loader-owned reservations
    // were validated before any SIPI; the BSP Host is installed, guest entry
    // is excluded, and APs remain parked until canonical worker publication.
    let executors = unsafe {
        crate::native_smp::executor::start(
            handoff,
            native_processors.expect("validated native roster"),
            &worker_ram,
            native_tsc_base,
        )
    }
    .unwrap_or_else(|error| {
        output::arguments(format_args!("native executor refusal: {error:?}\n"));
        output::fatal("owned native AP bootstrap refused")
    });
    let sender = crate::apic::Apic::new(
        handoff.apic_base,
        layout::physical(handoff.apic_base & crate::apic::BASE_ADDRESS),
    );
    if options.native_bootstrap_check || options.native_shared_check {
        for processor in executors.processors() {
            // SAFETY: BSP owns its ICR, physical AP/private descriptors ready.
            let doorbells = unsafe { processor.check_doorbell(&sender, handoff.tsc_hz) }
                .unwrap_or_else(|_| output::fatal("native AP doorbell did not complete"));
            let observed = processor.observation();
            let descriptors = processor.descriptors();
            output::arguments(format_args!(
                "NATIVE DESCRIPTORS slot={} rsp={:#x} gdt={:#x} idt={:#x} tr={:#x} gs={:#x} retained=boot-lifetime\n",
                processor.slot(),
                descriptors.rsp,
                descriptors.gdt,
                descriptors.idt,
                descriptors.task,
                descriptors.gs,
            ));
            output::arguments(format_args!(
                "NATIVE HOST slot={} apic={:#x} cr3={:#x} cr0={:#x} cr4={:#x} efer={:#x} pat={:#x} doorbells={}\n",
                processor.slot(),
                processor.apic_id(),
                observed.cr3,
                observed.cr0,
                observed.cr4,
                observed.efer,
                observed.pat,
                doorbells,
            ));
        }
        if options.native_shared_check {
            // SAFETY: the bounded fixture owns all source RAM and actual frame
            // loans; all AP returns are acquired before any borrowed release.
            unsafe {
                crate::native_smp::kernel_check::check(
                    handoff,
                    native_processors.expect("validated native roster"),
                    &executors,
                    &mut host_owner,
                    &sender,
                )
            }
            .unwrap_or_else(|error| output::fatal(error));
            output::terminate(0x10);
        }
        output::arguments(format_args!(
            "CHECK native-bootstrap PASS physical_cores={} owned_APs={}; guest SMP execution unqualified\n",
            options.native_cores.expect("validated native count"),
            executors.processors().len(),
        ));
        output::terminate(0x10);
    }
    let roster = topology::AssignedRoster::new(
        native_processors.expect("validated native roster"),
        &executors,
        &host_owner,
    )
    .unwrap_or_else(|error| output::fatal(&error));
    let mut bare = host_owner.host();
    let target = target();
    let speculation = speculation::probe();
    let mut read_only_region = None;
    let mut core_locks = stela_runtime::machine::ctrr::Handoff::default();
    let mut hidden_devices = Vec::new();
    let mut loaded_tree = None;
    let mut loaded_source = None;
    let mut bundle_boot_processor = None;
    let mut hidden_clpc = Vec::new();
    // A bundle's kernel gets a framebuffer the size of the firmware's mode.
    let framebuffer = handoff
        .screen
        .filter(|_| options.bundle)
        .and_then(|screen| {
            display::boot_framebuffer(screen.resolution(), options.dram_base + options.ram_bytes)
        });
    let (entry, x0) = if options.bundle {
        crate::status::begin("Loading macOS into memory");
        let files = &handoff.files[..handoff.file_count];
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
        core_locks = loaded.core_locks;
        hidden_devices = loaded.hidden_devices;
        bundle_boot_processor = loaded.boot_processor;
        hidden_clpc = loaded.hidden_clpc;
        loaded_tree = Some(loaded.live_tree);
        loaded_source = Some(loaded.source);
        crate::status::done("");
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
    let source_tree = loaded_tree.as_ref().map(|tree| tree.bytes());
    if source_tree.is_some() {
        crate::status::begin("Setting up the Mac's hardware");
    }
    let mut board = source_tree.map(|tree| {
        soc::board(tree).unwrap_or_else(|error| {
            output::arguments(format_args!("board refusal: {error}\n"));
            output::fatal("the board could not be modeled")
        })
    });
    let boot_processor = match board.as_ref() {
        Some(board) => {
            let boot = board
                .boot_processor
                .as_ref()
                .unwrap_or_else(|| output::fatal("the DeviceTree has no running boot PE"));
            if bundle_boot_processor != Some(boot.cpu) {
                output::fatal("the board boot PE differs from the verified bundle handoff");
            }
            output::arguments(format_args!(
                "BOOT PE index={} path={} affinity={:#x} cluster={}\n",
                boot.cpu,
                boot.path,
                boot.affinity,
                char::from(boot.cluster_type),
            ));
            boot.cpu
        }
        None => {
            if bundle_boot_processor.is_some() {
                output::fatal("a selected boot PE requires a live DeviceTree");
            }
            0
        }
    };
    let full_profile = match &board {
        Some(board) => board_profile(board, target, speculation),
        None => test_profile(),
    };
    let topology_source = match (loaded_source.as_ref(), loaded_tree.as_ref(), board.as_ref()) {
        (Some(intake), Some(live), Some(source_board)) => {
            let boot = source_board
                .boot_processor
                .as_ref()
                .expect("validated source boot PE");
            let identity = intake
                .topology_identity(full_profile.chip)
                .unwrap_or_else(|error| output::fatal(&error));
            let prepared = match identity.profile.soc {
                0x8112 => topology::Source::t8112_assigned(
                    intake.original(),
                    live,
                    identity,
                    boot.affinity,
                    handoff.native_resources.cores as usize,
                ),
                0x6000 if handoff.native_resources.cores == 1 => topology::Source::t6000(
                    intake.original(),
                    live.bytes(),
                    identity,
                    boot.affinity,
                ),
                _ => Err(String::from(
                    "native assigned topology for this source family is not qualified",
                )),
            };
            Some(prepared.unwrap_or_else(|error| output::fatal(&error)))
        }
        (None, None, None) if handoff.native_resources.cores == 1 => None,
        (None, None, None) => {
            output::fatal("an authored multi-PE image requires an explicit qualified topology")
        }
        _ => output::fatal("selected bundle source, live tree and board must be retained together"),
    };
    let assigned = topology_source.as_ref().map(|source| {
        source
            .prepare(&roster, full_profile.clone())
            .unwrap_or_else(|error| output::fatal(&error))
    });
    // SAFETY: all raw guest input copies have ended; AP executors are parked,
    // and no guest/device DMA producer has entered. The same loader bytes are
    // retained for every subsequent native CPU and synchronous device writer.
    let canonical_ram = unsafe { crate::native_smp::canonical::reserve(handoff, &worker_ram) }
        .unwrap_or_else(|error| output::fatal(error));
    if let Some(assigned) = &assigned {
        let candidate = assigned.tree.serialize();
        let parsed = soc::board(&candidate).unwrap_or_else(|error| output::fatal(&error));
        let boot = parsed
            .boot_processor
            .as_ref()
            .unwrap_or_else(|| output::fatal("assigned topology has no running boot PE"));
        let join = assigned
            .join(boot.affinity)
            .unwrap_or_else(|error| output::fatal(&error));
        if boot.cpu != join.logical
            || join.worker != 0
            || assigned
                .plan
                .pes()
                .iter()
                .find(|pe| pe.boot)
                .map(|pe| pe.logical)
                != Some(join.logical)
        {
            output::fatal("prepared boot PE differs from the actual assigned BSP");
        }
        if full_profile.processors.get(boot_processor) != assigned.profile.processors.get(boot.cpu)
        {
            output::fatal("assigned boot identity differs from the original source handoff");
        }
        output::arguments(format_args!(
            "NATIVE ASSIGNMENT original_boot={} assigned_boot={} physical_cores={} PEs={} boot_path={} removed={}\n",
            boot_processor,
            boot.cpu,
            handoff.native_resources.cores,
            assigned.joins.len(),
            assigned.receipt.boot_path,
            assigned.receipt.removed.len()
        ));
        board = Some(parsed);
    }
    let projected_bytes = assigned.as_ref().map(|assigned| assigned.tree.serialize());
    let tree = projected_bytes
        .as_deref()
        .or_else(|| loaded_tree.as_ref().map(|tree| tree.bytes()));
    let boot_processor = board
        .as_ref()
        .and_then(|board| board.boot_processor.as_ref())
        .map_or(0, |boot| boot.cpu);
    mount::clpc_absence(&hidden_clpc, options.strict, &mut |arguments| {
        output::arguments(arguments)
    })
    .unwrap_or_else(|error| {
        output::arguments(format_args!("board qualification refusal: {error}\n"));
        output::fatal("strict mode requires qualified CLPC controllers")
    });
    if options.strict
        && let Some(board) = board.as_ref()
    {
        mount::pmgr_qualifications(&board.pmgr_refusals, true, &mut |arguments| {
            output::arguments(arguments)
        })
        .unwrap_or_else(|error| {
            output::arguments(format_args!("board qualification refusal: {error}\n"));
            output::fatal("strict mode requires qualified PMGR register families")
        });
    }
    if let (Some(board), Some(tree)) = (board.as_mut(), tree)
        && let Some(states) = board.power_states.as_mut()
    {
        let unavailable = states
            .apply_admission(tree, &hidden_devices)
            .unwrap_or_else(|error| {
                output::arguments(format_args!("PMGR admission refusal: {error}\n"));
                output::fatal("the PMGR resource admission evidence is inconsistent")
            });
        output::arguments(format_args!(
            "DEVICES pmgr unavailable-resources={unavailable}\n"
        ));
    }
    if let Some(image) = nor_image {
        match board.as_mut().and_then(|board| board.spi_nor.as_mut()) {
            Some(spi) => spi.image = image,
            None => output::fatal("--nor was supplied but this DeviceTree exposes no modeled NOR"),
        }
    }
    let profile = assigned
        .as_ref()
        .map_or_else(|| full_profile.clone(), |assigned| assigned.profile.clone());
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
    let scanout = handoff.screen.map(|screen| {
        let screen = screen.relocated(layout::physical(screen.base as u64) as usize);
        alloc::boxed::Box::new(display::GopScanout::new(screen))
            as alloc::boxed::Box<dyn stela_runtime::machine::apple::Scanout>
    });
    let programmed = mount::memory_locks(read_only_region, &core_locks);
    let memory = board
        .as_ref()
        .filter(|board| board.memory_cache.is_some())
        .map(|board| {
            use stela_runtime::machine::apple::{
                memory_resources::t8112::cache::ZeroWayConfiguration, t8112_cold,
            };
            let configuration = t8112_cold::Configuration::clear_software_controls(
                ZeroWayConfiguration::DisableArgument,
            )
            .unwrap_or_else(|error| output::fatal(&error));
            let plan = t8112_cold::Plan::prepare(board, &canonical_ram, programmed, &configuration)
                .unwrap_or_else(|error| output::fatal(&error));
            mount::MemoryResources::T8112Cold(plan)
        });
    let cacheless_memory = memory.is_some();
    let (mut devices, restore_usb) = match devices(
        board.as_ref(),
        mount::Inputs {
            programmed,
            reset,
            now,
            wall: handoff.wall_seconds.map(|seconds| WallClock {
                // The firmware's time, carried forward to the counter's `now`.
                unix_seconds: seconds + (host::rdtsc() - handoff.wall_tsc) / handoff.tsc_hz,
                counter: now,
            }),
            backing,
            sep_state,
            sep_observe: options.sep_observe,
            agx_observe: options.agx_observe,
            entropy: alloc::boxed::Box::new(bundle::entropy),
            restore: options.restore || options.install.is_some(),
            input: options.input,
            usb: stela_runtime::machine::apple::UsbCables {
                disks: usb_disks,
                network: guest_network.as_ref().map(network::GuestNetwork::mac),
            },
            scanout,
            firmware: &firmware,
        },
        memory,
    ) {
        Ok(devices) => devices,
        Err(error) => {
            output::arguments(format_args!("device refusal: {error}\n"));
            output::fatal("the board devices could not be placed")
        }
    };
    let processor_power = match (&topology_source, &assigned, &loaded_source) {
        (Some(source), Some(assigned), Some(intake)) => {
            let original = stela_runtime::machine::adt::Node::root(intake.original())
                .unwrap_or_else(|| output::fatal("retained original source ADT is malformed"));
            devices
                .connect_processor_power(
                    source.resources.graph(),
                    &original,
                    &full_profile,
                    &assigned.plan,
                    0,
                )
                .unwrap_or_else(|error| output::fatal(&error))
        }
        (None, None, None) => Vec::new(),
        _ => output::fatal("assigned processor power lost its retained source owner"),
    };
    let worker_bindings = match &assigned {
        Some(assigned) => assigned
            .worker_bindings()
            .unwrap_or_else(|error| output::fatal(&error)),
        None => alloc::vec![stela_runtime::machine::engine::publication::WorkerBinding {
            pe: 0,
            worker: stela_runtime::machine::engine::publication::WorkerId(0),
        }],
    };
    if tree.is_some() {
        crate::status::done(profile.name);
    }
    let restore = source.map(|source| {
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
            // Stela holds the boot ROM's and the SEP ROM's nonces for the
            // restore, drawn once from the CPU's entropy.
            let mut nonces = stela_runtime::restore::tss::Nonces {
                ap: [0; 32],
                sep: [0; 20],
            };
            bundle::entropy(&mut nonces.ap)
                .and_then(|()| bundle::entropy(&mut nonces.sep))
                .unwrap_or_else(|error| output::fatal(error));
            stela_runtime::restore::tss::Signer {
                ecid,
                nonces,
                transport: match host_network.take().expect("--tss opens the host network") {
                    Ok(network) => alloc::boxed::Box::new(network),
                    Err(reason) => alloc::boxed::Box::new(network::Offline(reason)),
                },
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
    // All actual source/resource preparation precedes the first publication.
    // A reached write failure is terminal before any guest entry.
    let _published_tree = match &assigned {
        Some(assigned) => {
            // SAFETY: cold owner, parked APs, no frame loans or device DMA;
            // every earlier raw guest copy has completed.
            let mut memory = unsafe { bundle::live_tree::registered::ColdRam::new(&canonical_ram) };
            let live = loaded_tree.take().expect("retained source tree");
            let published = if cacheless_memory {
                live.publish_cacheless(&mut memory, &assigned.tree)
            } else {
                live.publish(&mut memory, &assigned.tree)
            }
            .unwrap_or_else(|error| output::fatal(&error));
            if Some(published.bytes()) != projected_bytes.as_deref() {
                output::fatal("published assigned topology differs from the prepared device graph");
            }
            Some(published)
        }
        None => None,
    };
    // The loader handle's last RAM copy preceded canonical registration; its
    // borrow has ended. It never executes a guest instruction.
    // SAFETY: actual started executors, retained source Plan/profile and exact
    // RAM/device owners remain live for the whole non-returning run below.
    let machine = unsafe {
        crate::native_smp::canonical::prepare_with_locks(
            handoff,
            native_processors.expect("validated native roster"),
            &executors,
            &sender,
            &mut host_owner,
            canonical_ram,
            cpu,
            devices,
            profile,
            boot_processor,
            &worker_bindings,
            &processor_power,
            Some(core_locks),
        )
    }
    .unwrap_or_else(|error| output::fatal(error));
    run_machine(
        machine,
        &options,
        handoff,
        RunIo {
            restore,
            host_input,
            guest_network,
            host_nor,
            host_disks,
        },
        |machine, limit| {
            // SAFETY: the same fixed workers and canonical producer set stay
            // retained; an unsupported native service returns without fallback.
            unsafe { crate::native_smp::canonical::run_slice(machine, limit) }
        },
    )
}

/// Retained host interfaces used by both ordinary authored inputs and the
/// canonical original-image execution path. Reporting cannot choose a fallback.
struct RunIo {
    restore: Option<restore::Experiment>,
    host_input: Option<input::HostInput>,
    guest_network: Option<network::GuestNetwork>,
    host_nor: Option<nor::HostNor>,
    host_disks: storage::HostDisks,
}

fn run_machine<H: Host>(
    mut machine: Machine<H, AppleDevices>,
    options: &Options,
    handoff: &Handoff,
    io: RunIo,
    execute: impl FnMut(&mut Machine<H, AppleDevices>, u64) -> Stop,
) -> ! {
    if options.survey {
        output::arguments(format_args!(
            "SURVEY RUN: device accesses without a model read 0 and drop writes; \
             the guest's behavior is unverified\n"
        ));
        machine.begin_survey();
    }
    machine.set_idle_skip(options.idle_skip);
    machine.set_strict(options.strict);
    machine.devices.set_strict(options.strict);
    output::arguments(format_args!(
        "UNSUPPORTED OPERATIONS {}\n",
        unsupported_mode(options.strict)
    ));
    if options.tss {
        output::arguments(format_args!(
            "TSS OPT-IN: the restore host sends this machine's ECID, the restore's nonces and \
             its component hashes to gs.apple.com for its root tickets and recoveryOS LocalPolicy\n"
        ));
    }
    // Waits return to this loop often enough that a press of the host's
    // power button reaches a sleeping SoC, and other host inputs a waiting
    // guest, promptly.
    machine.set_wait_limit(Some(host::COUNTER_HZ / WAIT_POLLS_PER_SECOND));
    if !options.breakpoints.is_empty() {
        machine.set_breakpoints(&options.breakpoints);
    }
    machine.set_monitor_tracing(options.monitor_trace);
    if options.monitor_trace {
        output::arguments(format_args!(
            "MONITOR TRACE enabled: raw guarded boundaries; endpoint ABI uninterpreted\n"
        ));
    }
    if !options.traces.is_empty() {
        machine.set_traces(&options.traces);
    }
    if !options.watches.is_empty() {
        machine.set_watches(&options.watches);
    }
    let RunIo {
        mut restore,
        mut host_input,
        mut guest_network,
        mut host_nor,
        host_disks,
    } = io;
    let mut host_power = power::HostPowerControl::new(handoff.power, handoff.tsc_hz, host_disks);
    crate::status::begin(match restore {
        Some(_) => "Starting the macOS installer",
        None => "Starting macOS",
    });
    let started = host::rdtsc();
    let stop = run(
        &mut machine,
        options.budget,
        handoff.tsc_hz,
        restore.as_mut(),
        host_input.as_mut(),
        guest_network.as_mut(),
        host_nor.as_mut(),
        &mut host_power,
        execute,
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

/// Run up to `budget` blocks (0: no limit), showing what macOS prints last
/// as the running step's detail, reporting the PE's position
/// every [`BEAT_SECONDS`], and making ANS namespace erases durable on the
/// host between slices and before the stop ([`erase`]). The caller supplies
/// its admitted execution path; reporting and host polling never select a
/// different memory or native-entry path.
#[allow(clippy::too_many_arguments)]
fn run<H: Host>(
    machine: &mut Machine<H, AppleDevices>,
    budget: u64,
    tsc_hz: u64,
    mut restore: Option<&mut restore::Experiment>,
    mut host_input: Option<&mut input::HostInput>,
    mut guest_network: Option<&mut network::GuestNetwork>,
    mut host_nor: Option<&mut nor::HostNor>,
    host_power: &mut power::HostPowerControl,
    mut execute: impl FnMut(&mut Machine<H, AppleDevices>, u64) -> Stop,
) -> Stop {
    let mut beat = (
        host::rdtsc(),
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
    let mut exits = ExitsSeen::default();
    let mut translated = TranslatedSeen::default();
    let mut occupancy = None;
    let mut host_erase = erase::HostErase::default();
    loop {
        let slice = machine.statistics.blocks + SLICE;
        let limit = if budget == 0 {
            slice
        } else {
            budget.min(slice)
        };
        let stop = execute(machine, limit);
        let lines = GUEST_LINES
            .0
            .try_borrow_mut()
            .map(|mut lines| core::mem::take(&mut *lines))
            .unwrap_or_default();
        if let Some(step) = lines.iter().rev().find_map(|line| installer_step(line)) {
            crate::status::progress(&step);
        }
        crate::status::stream(lines.iter().map(String::as_str));
        crate::status::tick();
        unmodeled_report(machine);
        sep_observation_report(machine);
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

        while let Some(log) = machine.devices.take_smc_log() {
            output::arguments(format_args!(
                "SMC key-write op={:#x} id={} flags={:#x} key={:#010x} command={:x?} request={:#018x} reply={:x?} dropped={}\n",
                log.request as u8,
                (log.request >> 12) & 0xf,
                (log.request >> 8) & 0xf,
                (log.request >> 32) as u32,
                log.system_event,
                log.request,
                log.reply,
                log.dropped_before
            ));
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
            let heap = crate::ALLOCATOR.usage();
            let shadow = host::statistics();
            output::arguments(format_args!(
                "BEAT blocks={blocks} pc={:#x} {}{} lr={:#x} ticks/block={} native={}% \
                 compiled={} discards={} evictions={} chained={}% exceptions={} interrupts={} \
                 waits={} \
                 heap={}M/{}M carved={}M peak={}M largest={}M \
                 shadow_peak={}M/{}M/{}M exhausted={}\n",
                cpu.pc,
                level_name(cpu.pstate.guarded),
                cpu.pstate.el,
                cpu.state.x[30],
                elapsed / (blocks - beat.2).max(1),
                (native - beat.1) * 100 / elapsed.max(1),
                compiled - beat.3,
                machine.statistics.code_discards,
                machine.statistics.code_evictions,
                (chained - beat.4) * 100 / (blocks - beat.2).max(1),
                events.0 - beat.5.0,
                events.1 - beat.5.1,
                events.2 - beat.5.2,
                heap.live >> 20,
                heap.total >> 20,
                heap.carved >> 20,
                heap.peak >> 20,
                heap.largest >> 20,
                shadow.shadow_peak[0] >> 20,
                shadow.shadow_peak[1] >> 20,
                shadow.shadow_bytes >> 20,
                shadow.exhausted,
            ));
            beat = (now, native, blocks, compiled, chained, events);
            translation = translation_report(machine, translation, compiled - beat_compiled);
            exits.report(machine);
            translated.report(machine);
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
            occupancy_report(machine, &mut occupancy);
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
fn call_chain<const N: usize, H: Host>(
    machine: &mut Machine<H, AppleDevices>,
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
fn suspension_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
    const SHOWN: usize = 32;
    let now = machine.host.counter();
    let frequency = stela_runtime::machine::timer::system_frequency(&machine.cpu).max(1);
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
fn timer_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
    use stela_runtime::machine::timer::CHANNELS;
    let (now, timers) = machine.timer_snapshot();
    output::arguments(format_args!(
        "TIMERS now={now:#x} daif={:#x}",
        machine.cpu.pstate.daif
    ));
    for (channel, (control, compare)) in CHANNELS.into_iter().zip(timers) {
        output::arguments(format_args!(
            " {:?}={:#x}/{:#x}",
            channel.control, control, compare
        ));
    }
    output::arguments(format_args!("\n"));
}

/// Whether the guest has yet been seen to reach addresses outside the
/// host's native ranges (`docs/design/system.md#host-placement`).
#[derive(Default)]
struct TranslatedSeen {
    reported: bool,
}

impl TranslatedSeen {
    /// Once per boot, the first guest PC and address that needed the
    /// translated variant, or that fell in the four-level guard, with the
    /// counts so far: such a guest runs correctly, through the translation
    /// helper, but slower, and may call for a different placement.
    fn report<H: Host>(&mut self, machine: &Machine<H, AppleDevices>) {
        let host = host::statistics();
        let first = machine.first_translated();
        if self.reported || (first.is_none() && host.guard_faults == 0) {
            return;
        }
        self.reported = true;
        let (pc, address) = first.unwrap_or_default();
        output::arguments(format_args!(
            "TRANSLATED pc={pc:#x} address={address:#x} pages={} helper_calls={} \
             helper_fills={} bounces={} guard_faults={}\n",
            machine.statistics.translated_pages,
            host.helper_calls,
            host.helper_fills,
            host.bounces,
            host.guard_faults,
        ));
    }
}

/// The engine's entries into compiled code, its exits by kind and the
/// exits by instruction word at the last heartbeat.
#[derive(Default)]
struct ExitsSeen {
    entries: u64,
    kinds: [u64; EXIT_KINDS],
    words: BTreeMap<u32, u64>,
    /// Lookup thunks installed, lookup hits, and the events that drop cached translations
    /// and lookups: translation control writes, TLBIs, TTBR0 writes and
    /// IC IVAU.
    lookups: [u64; 2],
    drops: [u64; 4],
}

/// The `ExitKind`s `Statistics::exit_kinds` counts.
const EXIT_KINDS: usize = 13;

impl ExitsSeen {
    /// Since the last heartbeat: the native runs the engine started (those
    /// that did not end in a counted exit ran out of their chain budget),
    /// the exits by `ExitKind`, and the instruction words that most often
    /// left compiled code, so the engine's exit causes can be ranked.
    fn report<H: Host>(&mut self, machine: &Machine<H, AppleDevices>) {
        const SHOWN: usize = 12;
        let statistics = &machine.statistics;
        let entries = statistics.blocks - statistics.chained;
        let kinds = statistics.exit_kinds;
        let lookups = [statistics.lookups, statistics.lookup_hits];
        let drops = [
            statistics.translation_changes,
            statistics.tlb_maintenance,
            statistics.table_base_changes,
            statistics.code_invalidations,
        ];
        let words = machine.exit_words();
        let mut top: Vec<_> = words
            .iter()
            .map(|(word, &count)| {
                let last = self.words.get(word).copied().unwrap_or_default();
                (count.saturating_sub(last), *word)
            })
            .filter(|&(count, _)| count != 0)
            .collect();
        top.sort_unstable_by(|a, b| b.cmp(a));
        let exits: u64 = kinds
            .iter()
            .zip(&self.kinds)
            .map(|(now, last)| now - last)
            .sum();
        output::arguments(format_args!(
            "EXITS entries={} exits={exits} kinds=",
            entries - self.entries
        ));
        for (index, (now, last)) in kinds.iter().zip(&self.kinds).enumerate() {
            let separator = if index == 0 { "" } else { "," };
            output::arguments(format_args!("{separator}{}", now - last));
        }
        output::arguments(format_args!(
            " thunks={} hits={} controls={} tlbi={} ttbr0={} ivau={}",
            lookups[0] - self.lookups[0],
            lookups[1] - self.lookups[1],
            drops[0] - self.drops[0],
            drops[1] - self.drops[1],
            drops[2] - self.drops[2],
            drops[3] - self.drops[3],
        ));
        for (count, word) in top.into_iter().take(SHOWN) {
            output::arguments(format_args!(" {word:#010x}:{count}"));
        }
        output::arguments(format_args!("\n"));
        *self = Self {
            entries,
            kinds,
            words,
            lookups,
            drops,
        };
    }
}

/// The instruction words that most often left compiled code for the engine.
fn exit_report<H: Host>(machine: &Machine<H, AppleDevices>) {
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
fn frames<H: Host>(machine: &mut Machine<H, AppleDevices>, label: &str, mut frame: u64) {
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
fn dump_report<H: Host>(machine: &mut Machine<H, AppleDevices>, dumps: &[(Base, u64)]) {
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

fn stack_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
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
fn text_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
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

/// The SEP's `--sep-observe` journal, printed as it fills: a graceful run
/// keeps going past each observed request and may end at the host timeout.
fn sep_observation_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
    for line in machine.devices.sep_observations() {
        output::arguments(format_args!("SEP OBSERVE {line}\n"));
    }
}

/// The boot log's account of the unsupported-operation policy.
fn unsupported_mode(strict: bool) -> &'static str {
    if strict {
        "mode=strict response=stop"
    } else {
        "mode=graceful response=degraded diagnostics=once"
    }
}

/// The distinct unsupported operations `UNMODELED` lines have reported.
static UNMODELED_REPORTED: AtomicU64 = AtomicU64::new(0);

/// Each unsupported operation answered outside strict mode for the first
/// time since the last report: machine operations and device accesses, then
/// coprocessor requests answered with their firmware's error reply or left
/// unanswered.
fn unmodeled_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
    static ORDER_NOTED: AtomicBool = AtomicBool::new(false);
    let requirements = machine.take_unmodeled();
    let requests = machine.devices.take_unmodeled();
    UNMODELED_REPORTED.fetch_add(
        (requirements.len() + requests.len()) as u64,
        Ordering::Relaxed,
    );
    if (!requirements.is_empty() || !requests.is_empty())
        && !ORDER_NOTED.swap(true, Ordering::Relaxed)
    {
        output::arguments(format_args!(
            "LOG ORDER these errors and trace/watch/device records are buffered; \
             guest console is immediate. Timestamps mark printing, not cross-stream event order.\n"
        ));
    }
    for requirement in requirements {
        output::arguments(format_args!("UNMODELED {requirement}\n"));
    }
    for line in requests {
        output::arguments(format_args!("UNMODELED {line}\n"));
    }
}

/// Each device register a survey answered for the first time since the last
/// report: guest PA, width, direction, the PC and link register that first
/// reached it, its count so far, the last value written and the refusal it replaced.
fn survey_report<H: Host>(machine: &mut Machine<H, AppleDevices>) {
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

/// The running regime's TTBR1 occupancy (`Machine::upper_occupancy`)
/// whenever it differs from the last one shown: the level-1 ranges its
/// tables map and the outermost mapped 32 MiB, which decide whether a
/// four-level host's upper window can lie below the guest's mappings.
fn occupancy_report<H: Host>(
    machine: &mut Machine<H, AppleDevices>,
    last: &mut Option<stela_runtime::machine::engine::Occupancy>,
) {
    let Some(now) = machine.upper_occupancy() else {
        return;
    };
    if last.as_ref() == Some(&now) {
        return;
    }
    output::arguments(format_args!(
        "OCCUPANCY ttbr1={:#x} lowest={:#x} highest={:#x} ranges=",
        now.root,
        now.lowest.unwrap_or(0),
        now.highest.unwrap_or(0)
    ));
    for (first, last) in &now.ranges {
        output::arguments(format_args!(" {first:#x}-{last:#x}"));
    }
    output::arguments(format_args!("\n"));
    *last = Some(now);
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
fn translation_report<H: Host>(
    machine: &Machine<H, AppleDevices>,
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
fn peers_report<H: Host>(machine: &Machine<H, AppleDevices>) {
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

fn finish<H: Host>(
    machine: &mut Machine<H, AppleDevices>,
    stop: Stop,
    seconds: f64,
    dumps: &[(Base, u64)],
    host_power: &power::HostPowerControl,
) -> ! {
    survey_report(machine);
    unmodeled_report(machine);
    // Machine answers are counted per access; coprocessor requests are
    // counted among the distinct reports only.
    output::arguments(format_args!(
        "UNSUPPORTED SUMMARY answered={} distinct={}\n",
        machine.statistics.degraded,
        UNMODELED_REPORTED.load(Ordering::Relaxed)
    ));
    stack_report(machine);
    dump_report(machine, dumps);
    let host = host::statistics();
    output::arguments(format_args!(
        "STATISTICS {:?} shadow_fills={} shadow_prefills={} shadow_resets={} shadow_exhausted={} shadow_peak={}M/{}M/{}M lower_resets={} scoped_invalidations={} stray_interrupts={} helper_calls={} helper_fills={} bounces={} guard_faults={} events={} seconds={seconds:.3}\n",
        machine.statistics,
        host.fills,
        host.prefills,
        host.resets,
        host.exhausted,
        host.shadow_peak[0] >> 20,
        host.shadow_peak[1] >> 20,
        host.shadow_bytes >> 20,
        host.lower_resets,
        host.scoped,
        host.stray,
        host.helper_calls,
        host.helper_fills,
        host.bounces,
        host.guard_faults,
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
    sep_observation_report(machine);
    for line in machine.devices.agx_observations() {
        output::arguments(format_args!("{line}\n"));
    }
    match stop {
        Stop::Idle => {
            output::arguments(format_args!(
                "STOP idle: every PE is off or waits with no wake source\n"
            ));
            stop_here(
                &guest_down(String::from(
                    "macOS stopped: every processor is off or waits with nothing to wake it",
                )),
                0x10,
            )
        }
        Stop::Waiting => {
            output::arguments(format_args!(
                "STOP waiting: every PE waits for an input from outside the board\n"
            ));
            stop_here(
                &guest_down(String::from(
                    "macOS stopped: it waits for something from outside the Mac",
                )),
                0x10,
            )
        }
        Stop::Reset(reset) => {
            if let Some(message) = guest_panic() {
                output::arguments(format_args!("STOP macOS crashed: {message}\n"));
                output::arguments(format_args!("RESET after panic: {reset}\n"));
            } else {
                output::arguments(format_args!("STOP reset: {reset}\n"));
            }
            // The run is over: its blocks' memory goes to proving the new
            // ones.
            machine.discard_blocks();
            translations::write();
            match reset.transition {
                Transition::Restart => {
                    show_stop(&guest_down(String::from("macOS restarted the Mac")));
                    crate::status::countdown("Restarting the PC", STOP_HOLD_SECONDS);
                    host_power.restart()
                }
                Transition::PowerOff => {
                    show_stop(&guest_down(String::from("macOS turned the Mac off")));
                    crate::status::countdown("Turning the PC off", STOP_HOLD_SECONDS);
                    host_power.power_off()
                }
                Transition::Halt => stop_here(
                    &guest_down(format!("macOS halted the Mac: {}", reset.reason)),
                    power::RESTART_CODE,
                ),
            }
        }
        Stop::Budget => {
            output::arguments(format_args!("STOP budget\n"));
            stop_here("the run reached its --budget", 0x14)
        }
        Stop::Unsupported(requirement) => {
            output::arguments(format_args!("STOP UNSUPPORTED {requirement}\n"));
            stop_here(
                &format!("macOS needs {requirement}, which Stela does not support yet"),
                0x13,
            )
        }
        Stop::DeviceRead(request) => {
            output::arguments(format_args!(
                "STOP canonical read requires its live continuation: {request:?}\n"
            ));
            stop_here(
                "the canonical device read was not consumed by its qualified scheduler",
                0x13,
            )
        }
        Stop::DeviceWrite(request) => {
            output::arguments(format_args!(
                "STOP canonical write requires its live continuation: {request:?}\n"
            ));
            stop_here(
                "the canonical device write was not consumed by its qualified scheduler",
                0x13,
            )
        }
        Stop::Breakpoint(pc) => {
            output::arguments(format_args!("STOP breakpoint pc={pc:#x}\n"));
            stop_here(&format!("Stela's breakpoint at {pc:#x}"), 0x16)
        }
    }
}
