//! `stela.cfg`'s system-mode options: one typed record, the one parser
//! `stela.efi`'s loader and engine read it with, and the one serializer
//! `stela setup` writes it with. The option line is whitespace-separated
//! words starting with `--system`; each option is a flag or a flag and one
//! value. The spellings are part of the setup/mount contract
//! (`stela_loader::mount_interface::OPTIONS_REVISION`).
use alloc::{string::String, vec::Vec};
use core::fmt;
use stela_loader::{
    boot_selection::{self, BootVolume},
    handoff::BootCommand,
    mount_interface, recovery,
};
use stela_runtime::pc::{gpt::Guid, storage::Target};

/// Apple T8112 DRAM base (Asahi Linux T8112 notes; the DeviceTree `/memory`).
pub const DRAM_BASE: u64 = 0x8_0000_0000;
const LARGE: u64 = 2 * 1024 * 1024;

pub const SYSTEM: &str = "--system";
pub const INSTALL: &str = mount_interface::INSTALL_OPTION;
pub const INSTALL_SOURCE: &str = "--install-source";
pub const VERIFY_ON_READ: &str = "--verify-on-read";
pub const STRICT: &str = "--strict";
pub const UPDATE_RESTORE: &str = mount_interface::UPDATE_RESTORE_OPTION;
pub const EXTERNAL_DISKS: &str = "--external-disks";
pub const NATIVE_CORES: &str = "--native-cores";
pub const WIFI: &str = "--wifi";
pub const WIFI_KEY: &str = "--wifi-key";
pub const WIFI_COUNTRY: &str = "--wifi-country";
/// The ESP file `--wifi` reads its key from without `--wifi-key`.
pub const DEFAULT_WIFI_KEY: &str = "\\EFI\\stela\\wifi.key";
/// IEEE 802.11 SSIDs are 1 to 32 octets.
const SSID_BYTES: core::ops::RangeInclusive<usize> = 1..=32;

/// The physical cores an explicit `--native-cores` may name.
pub const MAX_NATIVE_CORES: usize = 64;

/// A `--audio-check` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCheck {
    Playback,
    Duplex,
    TransportPlayback,
    TransportDuplex,
}

impl AudioCheck {
    const NAMES: [(&'static str, Self); 4] = [
        ("playback", Self::Playback),
        ("duplex", Self::Duplex),
        ("transport-playback", Self::TransportPlayback),
        ("transport-duplex", Self::TransportDuplex),
    ];

    pub fn parse(value: &str) -> Result<Self, &'static str> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, mode)| *mode)
            .ok_or(
                "audio check mode must be playback, duplex, transport-playback or transport-duplex",
            )
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, mode)| *mode == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }

    pub fn transport(self) -> bool {
        matches!(self, Self::TransportPlayback | Self::TransportDuplex)
    }

    pub fn duplex(self) -> bool {
        matches!(self, Self::Duplex | Self::TransportDuplex)
    }
}

/// Where a `--dump` range starts: a guest virtual address, or the stopped
/// PE's general register `xN` plus or minus an offset (`x21`, `x22+0x4000`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Address(u64),
    Register(usize, i64),
}

impl Base {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
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

    pub fn resolve(self, x: &[u64; 31]) -> u64 {
        match self {
            Self::Address(address) => address,
            Self::Register(index, offset) => x[index].wrapping_add_signed(offset),
        }
    }
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Address(address) => write!(f, "{address:#x}"),
            Self::Register(index, 0) => write!(f, "x{index}"),
            Self::Register(index, offset) if offset < 0 => {
                write!(f, "x{index}-{:#x}", offset.unsigned_abs())
            }
            Self::Register(index, offset) => write!(f, "x{index}+{offset:#x}"),
        }
    }
}

/// A number in `stela.cfg`: decimal, or hexadecimal after `0x` with optional
/// `_` separators.
pub fn number(value: &str) -> Result<u64, &'static str> {
    match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(&hex.replace('_', ""), 16),
        None => value.parse(),
    }
    .map_err(|_| "invalid number in system options")
}

/// Check an `http://HOST/PATH` URL and split it into host and path.
pub fn split_url(url: &str) -> Result<(&str, &str), &'static str> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// URLs are supported")?;
    let at = rest.find('/').ok_or("URL without a path")?;
    let (host, path) = rest.split_at(at);
    if host.is_empty() {
        return Err("URL without a host");
    }
    Ok((host, path))
}

/// The system-mode options of one `stela.cfg` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    pub dram_base: u64,
    /// `--dram-base` was given; otherwise a bundle's own base applies.
    pub dram_explicit: bool,
    pub load: u64,
    pub entry: u64,
    pub x0: u64,
    pub budget: u64,
    /// Load the boot bundle the loader read instead of `source.bin`.
    pub bundle: bool,
    /// The bundle's directory on the Stela volume (`--bundle DIR`).
    pub bundle_directory: Option<String>,
    /// Build the boot bundle from the installed system on this APFS
    /// partition instead (`SERIAL:GUID`).
    pub preboot: Option<Target>,
    /// The NVRAM boot volume the loader chose (`--boot-volume`), naming the
    /// Preboot disk's container and volume group.
    pub boot_volume: Option<BootVolume>,
    /// NVRAM asked for a safe-mode boot (`--safe-boot`).
    pub safe_boot: bool,
    /// The entry origin retained after NVRAM's one-shot command is consumed.
    pub boot_command: Option<BootCommand>,
    /// NVRAM chose a staged macOS update (`--upgrade`): build from the
    /// Preboot disk's Update volume.
    pub upgrade: bool,
    /// NVRAM chose a recoveryOS the Preboot disk holds: its Recovery
    /// volume's paired copy (`--paired-recovery`) or its RecoveryOSContainer's
    /// System Recovery (`--system-recovery`).
    pub recovery: Option<recovery::Kind>,
    /// One host partition backing all ANS namespaces.
    pub storage: Option<Target>,
    /// Instead, this many bytes of engine memory back them, and nothing
    /// persists (`--storage-ram`).
    pub storage_ram: Option<u64>,
    /// The host partition holding the NOR flash image (`--nor`); the
    /// `--storage` partition itself keeps it in its tail.
    pub nor: Option<Target>,
    /// `--restore-study`.
    pub restore: bool,
    pub restore_source: Option<Target>,
    /// `--restore-manifest PATH` was given.
    pub restore_manifest: bool,
    pub restore_manifest_path: Option<String>,
    pub restore_identity: Option<usize>,
    /// The install medium's `payload.json` (`--install`), whose directory
    /// holds its pieces: a restore with Apple's stock options.
    pub install: Option<String>,
    /// The install medium's partition, by its unique GUID alone.
    pub install_source: Option<Guid>,
    /// Refuse a payload without recorded block hashes, which would be read
    /// whole before StartRestore (`--verify-on-read`).
    pub verify_on_read: bool,
    /// Restore with the inventory's Update identity (`--update-restore`).
    pub update_restore: bool,
    /// Use restored's development-board policy to retain and report FDR
    /// failures while allowing the erase restore to continue
    /// (`--development-restore`), a degraded mode.
    pub development_restore: bool,
    /// Answer device accesses no model implements and list them
    /// (`--survey`): research runs only.
    pub survey: bool,
    /// Leap the counter over waits of every PE (`--idle-skip`): boot and
    /// install runs, not interactive use.
    pub idle_skip: bool,
    /// Cable the native USB keyboard and pointer to the last USB-C
    /// controller and feed it the host's virtio-input devices (`--input`).
    pub input: bool,
    /// Diagnostic of native pinned RAM in the shared window.
    pub native_memory_check: bool,
    /// Native MMIO/root/cache diagnostic; stops before guest entry.
    pub native_mmio_check: bool,
    /// Short native PM/LAPIC/IRQ fixture; stops before guest entry.
    pub native_clock_check: bool,
    /// Physical native executors (`--native-cores N`); never counts SMT
    /// siblings. Without it every physical core up to the executor's
    /// capacity is assigned.
    pub native_cores: Option<usize>,
    /// Qualify owned AP startup/host resources, then stop before guest entry.
    pub native_bootstrap_check: bool,
    /// Bounded checked-memory kernel execution on the selected cores.
    pub native_shared_check: bool,
    /// Emit full artifact identities (`--native-artifacts`).
    pub native_artifacts: bool,
    /// Execute PEs in checked native rounds on their assigned workers
    /// (`--native-rounds`) instead of serialized chained blocks on the BSP.
    pub native_rounds: bool,
    /// Run each PE on its own host core, the default. `--serialized` runs
    /// every PE on the BSP instead, as native rounds and checks do.
    pub parallel: bool,
    /// Time the engine's phases and report them with each heartbeat
    /// (`--profile`).
    pub profile: bool,
    /// The user opted in to Apple's signing server (`--tss`).
    pub tss: bool,
    /// The machine's ECID for a bundle built from the Preboot volume
    /// (`--ecid HEX`, nonzero).
    pub ecid: Option<u64>,
    /// POST once to this `http://` URL at start and report the reply
    /// (`--network-check URL`).
    pub network_check: Option<String>,
    /// Qualify exclusively owned conventional HDA after ExitBootServices.
    pub audio_check: Option<AudioCheck>,
    /// Whole host disks, by serial, that the guest sees as USB mass
    /// storage behind the native hub (`--usb-storage SERIAL`, repeatable).
    pub usb_storage: Vec<String>,
    /// Every other host disk the engine does not open itself is USB mass
    /// storage too, up to the hub's free ports (`--external-disks`).
    pub external_disks: bool,
    /// Give the guest a USB Ethernet adapter bridged to a host network
    /// adapter of its own (`--guest-network`).
    pub guest_network: bool,
    /// Join this Wi-Fi network for the mount's network (`--wifi SSID`). The
    /// line writes `%`, whitespace and control characters as `%XX`.
    pub ssid: Option<String>,
    /// The ESP file holding the network's passphrase or PSK (`--wifi-key
    /// PATH`); `DEFAULT_WIFI_KEY` when `--wifi` is set without it.
    pub wifi_key: Option<String>,
    /// The ISO 3166-1 alpha-2 regulatory country, uppercase
    /// (`--wifi-country XX`).
    pub wifi_country: Option<String>,
    /// Advertise and log the SEP services whose contracts are not recovered
    /// (`--sep-observe`), each request refused by name.
    pub sep_observe: bool,
    /// Stop every PE at the first unsupported operation (`--strict`)
    /// instead of answering it degraded and reporting it once.
    pub strict: bool,
    /// Stop when a PE reaches one of these guest PCs (`--break`).
    pub breakpoints: Vec<u64>,
    /// Log, without stopping, when a PE reaches one of these guest PCs
    /// (`--trace`).
    pub traces: Vec<u64>,
    /// Log raw guarded entries, exits, exceptions and returns (`--monitor-trace`).
    pub monitor_trace: bool,
    /// Log every device access in these physical ranges (`--watch BASE,BYTES`).
    pub watches: Vec<(u64, u64)>,
    /// Guest virtual ranges the stop's report shows (`--dump BASE,BYTES`).
    pub dumps: Vec<(Base, u64)>,
}

impl Default for System {
    fn default() -> Self {
        Self {
            dram_base: DRAM_BASE,
            dram_explicit: false,
            load: DRAM_BASE,
            entry: DRAM_BASE,
            x0: 0,
            budget: 0,
            bundle: false,
            bundle_directory: None,
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
            restore_manifest_path: None,
            restore_identity: None,
            install: None,
            install_source: None,
            verify_on_read: false,
            update_restore: false,
            development_restore: false,
            survey: false,
            idle_skip: false,
            input: false,
            native_memory_check: false,
            native_mmio_check: false,
            native_clock_check: false,
            native_cores: None,
            native_bootstrap_check: false,
            native_shared_check: false,
            native_artifacts: false,
            native_rounds: false,
            parallel: true,
            profile: false,
            tss: false,
            ecid: None,
            network_check: None,
            audio_check: None,
            usb_storage: Vec::new(),
            external_disks: false,
            guest_network: false,
            ssid: None,
            wifi_key: None,
            wifi_country: None,
            sep_observe: false,
            strict: false,
            breakpoints: Vec::new(),
            traces: Vec::new(),
            monitor_trace: false,
            watches: Vec::new(),
            dumps: Vec::new(),
        }
    }
}

/// A `--wifi` word: `%XX` escapes decoded, 1 to 32 bytes of UTF-8.
fn ssid(word: &str) -> Result<String, &'static str> {
    const MALFORMED: &str = "--wifi needs a 1 to 32 byte network name, with %XX escapes";
    let mut bytes = Vec::with_capacity(word.len());
    let mut rest = word.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let digits = rest.get(..2).ok_or(MALFORMED)?;
        let digits = core::str::from_utf8(digits).map_err(|_| MALFORMED)?;
        bytes.push(u8::from_str_radix(digits, 16).map_err(|_| MALFORMED)?);
        rest = &rest[2..];
    }
    if !SSID_BYTES.contains(&bytes.len()) {
        return Err(MALFORMED);
    }
    String::from_utf8(bytes).map_err(|_| MALFORMED)
}

/// An SSID as one `--wifi` word: `%`, whitespace and control characters as
/// `%XX`.
struct Ssid<'a>(&'a str);

impl fmt::Display for Ssid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            if character == '%' || character.is_whitespace() || character.is_control() {
                let mut bytes = [0; 4];
                for byte in character.encode_utf8(&mut bytes).bytes() {
                    write!(f, "%{byte:02X}")?;
                }
            } else {
                write!(f, "{character}")?;
            }
        }
        Ok(())
    }
}

fn flag(set: &mut bool, duplicate: &'static str) -> Result<(), &'static str> {
    if core::mem::replace(set, true) && !duplicate.is_empty() {
        return Err(duplicate);
    }
    Ok(())
}

impl System {
    /// The line starts with `--system`.
    pub fn is_system(text: &str) -> bool {
        text.split_ascii_whitespace().next() == Some(SYSTEM)
    }

    /// Parse a line the mount runs: `parse`, refusing an unreplaced `@disk`.
    pub fn parse_resolved(text: &str) -> Result<Self, &'static str> {
        let options = Self::parse(text)?;
        if [&options.storage, &options.nor, &options.preboot]
            .into_iter()
            .flatten()
            .any(is_chosen)
        {
            return Err("@disk names a disk Install macOS has not chosen");
        }
        Ok(options)
    }

    /// Parse and check one option line.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let mut options = Self::default();
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some(SYSTEM) {
            return Err("system options must start with --system");
        }
        let mut native_cores = false;
        while let Some(name) = words.next() {
            let mut value = || words.next();
            match name {
                "--native-artifacts" => options.native_artifacts = true,
                "--native-rounds" => options.native_rounds = true,
                "--parallel" => options.parallel = true,
                "--serialized" => options.parallel = false,
                "--profile" => options.profile = true,
                "--monitor-trace" => options.monitor_trace = true,
                "--native-shared-check" => flag(
                    &mut options.native_shared_check,
                    "duplicate native shared check",
                )?,
                "--native-bootstrap-check" => flag(
                    &mut options.native_bootstrap_check,
                    "duplicate native bootstrap check",
                )?,
                NATIVE_CORES => {
                    if core::mem::replace(&mut native_cores, true) {
                        return Err("--native-cores must occur once");
                    }
                    let count = value()
                        .ok_or("--native-cores needs a processor count")?
                        .parse::<usize>()
                        .map_err(|_| "--native-cores needs a processor count")?;
                    if !(1..=MAX_NATIVE_CORES).contains(&count) {
                        return Err(
                            "--native-cores is outside the supported physical-core capacity",
                        );
                    }
                    options.native_cores = Some(count);
                }
                "--native-memory-check" => options.native_memory_check = true,
                "--native-clock-check" => flag(
                    &mut options.native_clock_check,
                    "duplicate native clock check",
                )?,
                "--native-mmio-check" => flag(
                    &mut options.native_mmio_check,
                    "duplicate native MMIO check",
                )?,
                "--restore-study" => options.restore = true,
                "--restore-source" => {
                    let target = value().ok_or("missing restore source partition")?.parse()?;
                    if options.restore_source.replace(target).is_some() {
                        return Err("duplicate restore source");
                    }
                }
                "--restore-manifest" => {
                    let path = value().ok_or("missing restore manifest path")?;
                    if options.restore_manifest {
                        return Err("duplicate restore manifest");
                    }
                    options.restore_manifest = true;
                    options.restore_manifest_path = Some(String::from(path));
                }
                INSTALL => {
                    let path = value().ok_or("missing install medium manifest")?;
                    if options.install.replace(String::from(path)).is_some() {
                        return Err("duplicate install medium");
                    }
                }
                INSTALL_SOURCE => {
                    let guid = value().ok_or("missing install medium partition")?.parse()?;
                    if options.install_source.replace(guid).is_some() {
                        return Err("duplicate install medium partition");
                    }
                }
                "--restore-identity" => {
                    let index = number(value().ok_or("missing restore identity index")?)?;
                    let index = usize::try_from(index).map_err(|_| "restore identity too large")?;
                    if options.restore_identity.replace(index).is_some() {
                        return Err("duplicate restore identity");
                    }
                }
                "--bundle" => {
                    let directory = value().ok_or("missing bundle directory")?;
                    options.bundle = true;
                    options.bundle_directory = Some(String::from(directory));
                }
                "--survey" => options.survey = true,
                VERIFY_ON_READ => options.verify_on_read = true,
                UPDATE_RESTORE => options.update_restore = true,
                "--development-restore" => options.development_restore = true,
                "--idle-skip" => options.idle_skip = true,
                "--input" => options.input = true,
                "--tss" => options.tss = true,
                "--usb-storage" => {
                    let serial = value().ok_or("missing USB storage disk serial")?;
                    if options.usb_storage.iter().any(|other| other == serial) {
                        return Err("duplicate USB storage disk");
                    }
                    options.usb_storage.push(String::from(serial));
                }
                "--guest-network" => options.guest_network = true,
                WIFI => {
                    let ssid = ssid(value().ok_or("--wifi needs a network name")?)?;
                    if options.ssid.replace(ssid).is_some() {
                        return Err("duplicate --wifi");
                    }
                }
                WIFI_KEY => {
                    let path = value().ok_or("--wifi-key needs an ESP path")?;
                    if options.wifi_key.replace(String::from(path)).is_some() {
                        return Err("duplicate --wifi-key");
                    }
                }
                WIFI_COUNTRY => {
                    let code = value().ok_or("--wifi-country needs a two-letter country")?;
                    if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                        return Err("--wifi-country needs a two-letter country");
                    }
                    if options
                        .wifi_country
                        .replace(code.to_ascii_uppercase())
                        .is_some()
                    {
                        return Err("duplicate --wifi-country");
                    }
                }
                EXTERNAL_DISKS => options.external_disks = true,
                "--audio-check" => {
                    if options.audio_check.is_some() {
                        return Err("duplicate audio check");
                    }
                    let mode = AudioCheck::parse(value().ok_or("missing audio check mode")?)?;
                    options.audio_check = Some(mode);
                }
                "--network-check" => {
                    let url = value().ok_or("missing network check URL")?;
                    split_url(url)?;
                    if options.network_check.replace(String::from(url)).is_some() {
                        return Err("duplicate network check");
                    }
                }
                "--ecid" => {
                    let ecid = number(value().ok_or("missing ECID")?)?;
                    if ecid == 0 || options.ecid.replace(ecid).is_some() {
                        return Err("--ecid takes one nonzero ECID");
                    }
                }
                "--sep-observe" => options.sep_observe = true,
                STRICT => options.strict = true,
                "--storage" => {
                    let target = partition(value().ok_or("missing ANS storage partition")?)?;
                    if options.storage_ram.is_some() || options.storage.replace(target).is_some() {
                        return Err("system mode accepts exactly one ANS backing");
                    }
                }
                "--storage-ram" => {
                    let bytes = number(value().ok_or("missing RAM storage size")?)?;
                    if options.storage.is_some() || options.storage_ram.replace(bytes).is_some() {
                        return Err("system mode accepts exactly one ANS backing");
                    }
                }
                "--nor" => {
                    let target = partition(value().ok_or("missing NOR partition")?)?;
                    if options.nor.replace(target).is_some() {
                        return Err("duplicate NOR partition");
                    }
                }
                "--preboot" => {
                    let target = value().ok_or("missing Preboot disk")?;
                    options.preboot = Some(partition(target)?);
                    options.bundle = true;
                }
                "--watch" => {
                    let range = value().ok_or("missing watch range")?;
                    let (base, bytes) = range.split_once(',').ok_or("a watch is BASE,BYTES")?;
                    options.watches.push((number(base)?, number(bytes)?));
                }
                boot_selection::BOOT_VOLUME_OPTION => {
                    let volume =
                        BootVolume::parse(value().ok_or("missing boot volume")?.as_bytes())
                            .map_err(|_| "--boot-volume is not TYPE:PARTITION:GROUP")?;
                    if options.boot_volume.replace(volume).is_some() {
                        return Err("duplicate boot volume");
                    }
                }
                boot_selection::SAFE_BOOT_OPTION => options.safe_boot = true,
                boot_selection::BOOT_COMMAND_OPTION => {
                    let value = number(value().ok_or("missing boot command")?)?;
                    let value = u8::try_from(value).map_err(|_| "boot command is not a byte")?;
                    let command = BootCommand::try_from(value)?;
                    if options.boot_command.replace(command).is_some() {
                        return Err("duplicate boot command");
                    }
                }
                boot_selection::UPGRADE_OPTION => options.upgrade = true,
                boot_selection::PAIRED_RECOVERY_OPTION | boot_selection::SYSTEM_RECOVERY_OPTION => {
                    let kind = if name == boot_selection::PAIRED_RECOVERY_OPTION {
                        recovery::Kind::Paired
                    } else {
                        recovery::Kind::System
                    };
                    if options.recovery.replace(kind).is_some() {
                        return Err("--paired-recovery and --system-recovery name one recoveryOS");
                    }
                }
                "--dump" => {
                    let range = value().ok_or("missing dump range")?;
                    let (base, bytes) = range.split_once(',').ok_or("a dump is BASE,BYTES")?;
                    options.dumps.push((Base::parse(base)?, number(bytes)?));
                }
                _ => {
                    let value = number(value().ok_or("missing system option value")?)?;
                    match name {
                        "--break" => options.breakpoints.push(value),
                        "--trace" => options.traces.push(value),
                        "--dram-base" => {
                            options.dram_base = value;
                            options.dram_explicit = true;
                        }
                        "--load" => options.load = value,
                        "--entry" => options.entry = value,
                        "--x0" => options.x0 = value,
                        "--budget" => options.budget = value,
                        _ => return Err("unknown system option"),
                    }
                }
            }
        }
        if options.native_rounds || options.native_shared_check || options.native_bootstrap_check {
            options.parallel = false;
        }
        if options.ssid.is_some() && options.wifi_key.is_none() {
            options.wifi_key = Some(String::from(DEFAULT_WIFI_KEY));
        }
        options.check()?;
        Ok(options)
    }

    /// The combinations the engine refuses.
    pub fn check(&self) -> Result<(), &'static str> {
        let restore_inputs = self.restore_source.is_some()
            || self.restore_manifest
            || self.restore_identity.is_some();
        if self.restore
            && (!self.bundle
                || self.preboot.is_some()
                || self.storage.is_none()
                || self.restore_source.is_none()
                || !self.restore_manifest
                || self.restore_identity.is_none()
                || self.survey)
        {
            return Err(
                "--restore-study requires --bundle, --storage, --restore-source, --restore-manifest and --restore-identity; refuses --preboot/--survey",
            );
        }
        if !self.restore && restore_inputs {
            return Err("restore inputs require explicit --restore-study");
        }
        if self.ssid.is_none() && (self.wifi_key.is_some() || self.wifi_country.is_some()) {
            return Err("--wifi-key and --wifi-country configure a --wifi network");
        }
        if self.install_source.is_some() && self.install.is_none() {
            return Err("--install-source names the partition of an --install medium");
        }
        if self.install.is_some()
            && (!self.bundle
                || self.preboot.is_some()
                || self.storage.is_none()
                || self.nor.is_none()
                || self.restore
                || self.survey)
        {
            return Err(
                "--install requires --bundle, --storage and --nor; refuses --restore-study, --preboot and --survey",
            );
        }
        if self.update_restore && self.install.is_none() {
            return Err("--update-restore applies to --install");
        }
        if self.development_restore
            && (self.install.is_none() || self.update_restore || self.strict)
        {
            return Err(
                "--development-restore requires a non-strict erase --install and refuses --update-restore",
            );
        }
        if self.verify_on_read && self.install.is_none() && !self.restore {
            return Err("--verify-on-read applies to --install and --restore-study");
        }
        if self.install.is_some() && !self.tss {
            return Err(
                "--install needs --tss: required boot firmware is not covered by the IPSW's global ticket",
            );
        }
        if self.preboot.is_none()
            && (self.boot_volume.is_some()
                || self.boot_command.is_some()
                || self.safe_boot
                || self.upgrade
                || self.recovery.is_some())
        {
            return Err(
                "--boot-volume, --boot-command, --safe-boot, --upgrade, --paired-recovery and --system-recovery \
                 choose a --preboot boot",
            );
        }
        if self.upgrade && (self.recovery.is_some() || self.safe_boot) {
            return Err("--upgrade is neither a safe-mode boot nor a recoveryOS");
        }
        if self.recovery.is_some() && self.safe_boot {
            return Err("a recoveryOS boot is not a safe-mode boot");
        }
        if !self.dram_base.is_multiple_of(LARGE) {
            return Err("guest DRAM base must be 2 MiB aligned");
        }
        if self.native_clock_check {
            if self.native_cores != Some(1) {
                return Err("native clock check requires --native-cores 1");
            }
            if self.native_mmio_check
                || self.native_memory_check
                || self.native_bootstrap_check
                || self.native_shared_check
                || self.native_rounds
                || self.audio_check.is_some()
                || self.network_check.is_some()
                || self.storage.is_some()
                || self.storage_ram.is_some()
                || self.preboot.is_some()
                || self.nor.is_some()
                || self.input
                || self.guest_network
                || self.ssid.is_some()
                || self.external_disks
                || !self.usb_storage.is_empty()
                || self.tss
                || self.install.is_some()
                || self.restore
            {
                return Err("native clock check requires an exclusive diagnostic mode");
            }
        }
        Ok(())
    }
}

struct Line<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl Line<'_, '_> {
    fn flag(&mut self, name: &str, set: bool) -> fmt::Result {
        if set {
            write!(self.0, " {name}")?;
        }
        Ok(())
    }
    fn value(&mut self, name: &str, value: Option<impl fmt::Display>) -> fmt::Result {
        if let Some(value) = value {
            write!(self.0, " {name} {value}")?;
        }
        Ok(())
    }
}

struct Partition<'a>(&'a Target);

fn written(target: &Option<Target>) -> Option<Partition<'_>> {
    target.as_ref().map(Partition)
}

impl fmt::Display for Partition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_chosen(self.0) {
            return f.write_str(mount_interface::CHOSEN_DISK);
        }
        write!(f, "{}:{}", self.0.serial, self.0.partition)
    }
}

/// The partition `stela.efi`'s Install macOS chooses, written `@disk`
/// (`mount_interface::CHOSEN_DISK`). The mount replaces each `@disk` with the
/// chosen `SERIAL:GUID` before the engine reads the line
/// (`mount_interface::with_disk`).
pub fn chosen_disk() -> Target {
    Target {
        serial: String::from(mount_interface::CHOSEN_DISK),
        partition: Guid([0; 16]),
    }
}

/// `target` is `chosen_disk`.
pub fn is_chosen(target: &Target) -> bool {
    target.serial == mount_interface::CHOSEN_DISK && target.partition.is_zero()
}

fn partition(value: &str) -> Result<Target, &'static str> {
    if value == mount_interface::CHOSEN_DISK {
        return Ok(chosen_disk());
    }
    value.parse()
}

struct Hex(u64);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// An ECID as 16 hexadecimal digits, as `stela setup` prints it.
struct Ecid(u64);

impl fmt::Display for Ecid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// The canonical option line: `--system`, then each option that differs
/// from its default, in a fixed order. `System::parse` reads it back to an
/// equal record.
impl fmt::Display for System {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SYSTEM)?;
        let mut line = Line(f);
        line.value("--storage", written(&self.storage))?;
        line.value("--storage-ram", self.storage_ram.map(Hex))?;
        line.value("--nor", written(&self.nor))?;
        if self.preboot.is_some() {
            line.value("--preboot", written(&self.preboot))?;
        }
        line.value("--bundle", self.bundle_directory.as_deref())?;
        line.value("--ecid", self.ecid.map(Ecid))?;
        line.value(
            boot_selection::BOOT_VOLUME_OPTION,
            self.boot_volume
                .as_ref()
                .map(|volume| String::from_utf8_lossy(&volume.encode()).into_owned()),
        )?;
        line.value(
            boot_selection::BOOT_COMMAND_OPTION,
            self.boot_command.map(|command| command as u8),
        )?;
        line.flag(boot_selection::SAFE_BOOT_OPTION, self.safe_boot)?;
        line.flag(boot_selection::UPGRADE_OPTION, self.upgrade)?;
        line.flag(
            boot_selection::PAIRED_RECOVERY_OPTION,
            self.recovery == Some(recovery::Kind::Paired),
        )?;
        line.flag(
            boot_selection::SYSTEM_RECOVERY_OPTION,
            self.recovery == Some(recovery::Kind::System),
        )?;
        line.flag("--restore-study", self.restore)?;
        line.value("--restore-source", written(&self.restore_source))?;
        line.value("--restore-manifest", self.restore_manifest_path.as_deref())?;
        line.value("--restore-identity", self.restore_identity)?;
        line.value(INSTALL, self.install.as_deref())?;
        line.value(INSTALL_SOURCE, self.install_source)?;
        line.flag(VERIFY_ON_READ, self.verify_on_read)?;
        line.flag(UPDATE_RESTORE, self.update_restore)?;
        line.flag("--development-restore", self.development_restore)?;
        for serial in &self.usb_storage {
            line.value("--usb-storage", Some(serial))?;
        }
        line.flag(EXTERNAL_DISKS, self.external_disks)?;
        line.flag("--guest-network", self.guest_network)?;
        line.value(WIFI, self.ssid.as_deref().map(Ssid))?;
        line.value(
            WIFI_KEY,
            self.wifi_key
                .as_deref()
                .filter(|&path| path != DEFAULT_WIFI_KEY),
        )?;
        line.value(WIFI_COUNTRY, self.wifi_country.as_deref())?;
        line.flag("--tss", self.tss)?;
        line.flag("--input", self.input)?;
        line.flag("--idle-skip", self.idle_skip)?;
        line.flag("--survey", self.survey)?;
        line.flag("--sep-observe", self.sep_observe)?;
        line.flag(STRICT, self.strict)?;
        line.value(NATIVE_CORES, self.native_cores)?;
        line.flag("--native-rounds", self.native_rounds)?;
        line.flag("--native-artifacts", self.native_artifacts)?;
        line.flag("--native-memory-check", self.native_memory_check)?;
        line.flag("--native-mmio-check", self.native_mmio_check)?;
        line.flag("--native-clock-check", self.native_clock_check)?;
        line.flag("--native-bootstrap-check", self.native_bootstrap_check)?;
        line.flag("--native-shared-check", self.native_shared_check)?;
        let implied_serial =
            self.native_rounds || self.native_shared_check || self.native_bootstrap_check;
        line.flag("--serialized", !self.parallel && !implied_serial)?;
        line.flag("--profile", self.profile)?;
        line.flag("--monitor-trace", self.monitor_trace)?;
        line.value("--network-check", self.network_check.as_deref())?;
        line.value("--audio-check", self.audio_check.map(AudioCheck::name))?;
        if self.dram_explicit {
            line.value("--dram-base", Some(Hex(self.dram_base)))?;
        }
        for (name, value, default) in [
            ("--load", self.load, DRAM_BASE),
            ("--entry", self.entry, DRAM_BASE),
            ("--x0", self.x0, 0),
            ("--budget", self.budget, 0),
        ] {
            if value != default {
                line.value(name, Some(Hex(value)))?;
            }
        }
        for &address in &self.breakpoints {
            line.value("--break", Some(Hex(address)))?;
        }
        for &address in &self.traces {
            line.value("--trace", Some(Hex(address)))?;
        }
        for &(base, bytes) in &self.watches {
            write!(line.0, " --watch {base:#x},{bytes:#x}")?;
        }
        for &(base, bytes) in &self.dumps {
            write!(line.0, " --dump {base},{bytes:#x}")?;
        }
        Ok(())
    }
}

pub const HOST_CHECK: &str = "--host-check";
const DEFAULT_KEY_SECONDS: u64 = 60;

/// The options of a `--host-check` line: the standalone report on the PC
/// and its diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCheck {
    pub native_dma_check: bool,
    pub native_work_check: bool,
    pub native_irq_work_check: bool,
    pub native_dma_isolation_check: bool,
    /// Read the NOR image from this FAT32 partition's file (`--nor-file
    /// GUID:/PATH`).
    pub nor_file: Option<(Guid, String)>,
    /// Stop after this many seconds (`--deadline`).
    pub deadline: Option<u64>,
    /// How long a prompt waits for a key (`--key-seconds`).
    pub key_seconds: u64,
}

impl Default for HostCheck {
    fn default() -> Self {
        Self {
            native_dma_check: false,
            native_work_check: false,
            native_irq_work_check: false,
            native_dma_isolation_check: false,
            nor_file: None,
            deadline: None,
            key_seconds: DEFAULT_KEY_SECONDS,
        }
    }
}

fn seconds(value: Option<&str>) -> Result<u64, &'static str> {
    value
        .and_then(|value| value.parse().ok())
        .filter(|&seconds| seconds > 0)
        .ok_or("host check: a time option takes a positive number of seconds")
}

impl HostCheck {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some(HOST_CHECK) {
            return Err("host check: stela.cfg must start with --host-check");
        }
        let mut options = Self::default();
        while let Some(word) = words.next() {
            match word {
                "--native-irq-work-check" => options.native_irq_work_check = true,
                "--native-work-check" => options.native_work_check = true,
                "--native-dma-check" => options.native_dma_check = true,
                "--native-dma-isolation-check" => options.native_dma_isolation_check = true,
                "--nor-file" => {
                    let (guid, path) = words
                        .next()
                        .and_then(|value| value.split_once(':'))
                        .ok_or("host check: --nor-file takes GUID:/PATH")?;
                    options.nor_file = Some((guid.parse()?, String::from(path)));
                }
                "--deadline" => options.deadline = Some(seconds(words.next())?),
                "--key-seconds" => options.key_seconds = seconds(words.next())?,
                _ => return Err("host check: unknown option"),
            }
        }
        if u8::from(options.native_dma_check)
            + u8::from(options.native_dma_isolation_check)
            + u8::from(options.native_work_check)
            + u8::from(options.native_irq_work_check)
            > 1
        {
            return Err("host check: native diagnostic fixture modes are exclusive");
        }
        Ok(options)
    }
}

impl fmt::Display for HostCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(HOST_CHECK)?;
        let mut line = Line(f);
        line.flag("--native-dma-check", self.native_dma_check)?;
        line.flag(
            "--native-dma-isolation-check",
            self.native_dma_isolation_check,
        )?;
        line.flag("--native-work-check", self.native_work_check)?;
        line.flag("--native-irq-work-check", self.native_irq_work_check)?;
        if let Some((guid, path)) = &self.nor_file {
            write!(line.0, " --nor-file {guid}:{path}")?;
        }
        line.value("--deadline", self.deadline)?;
        if self.key_seconds != DEFAULT_KEY_SECONDS {
            line.value("--key-seconds", Some(self.key_seconds))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};

    #[test]
    fn host_check_lines_round_trip_and_refuse_combined_fixtures() {
        let line = "--host-check --native-dma-check \
                    --nor-file 11111111-2222-3333-4444-555555555555:/stela/nor.bin --deadline 30 \
                    --key-seconds 5";
        let options = HostCheck::parse(line).unwrap();
        assert_eq!(options.deadline, Some(30));
        assert_eq!(HostCheck::parse(&options.to_string()), Ok(options));
        assert_eq!(HostCheck::parse("--host-check"), Ok(HostCheck::default()));
        for text in [
            "--system",
            "--host-check --native-dma-check --native-work-check",
            "--host-check --deadline 0",
            "--host-check --nor-file x",
            "--host-check --unknown",
        ] {
            assert!(HostCheck::parse(text).is_err(), "{text}");
        }
    }

    const DISK: &str = "74EXN0LI:11111111-2222-3333-4444-555555555555";

    fn round_trip(text: &str) -> System {
        let options = System::parse(text).unwrap();
        let line = options.to_string();
        assert_eq!(System::parse(&line), Ok(options.clone()), "{line}");
        options
    }

    #[test]
    fn setup_lines_parse_and_serialize_identically() {
        let preboot = format!(
            "--system --storage {DISK} --nor {DISK} --preboot {DISK} --ecid 0x0000000000001234 \
             --external-disks --guest-network --tss"
        );
        let options = round_trip(&preboot);
        assert!(options.bundle && options.external_disks && options.tss);
        assert_eq!(options.ecid, Some(0x1234));
        assert_eq!(options.to_string(), preboot);
        let bundle = format!("--system --storage {DISK} --nor {DISK} --bundle \\EFI\\stela\\r");
        assert_eq!(round_trip(&bundle).to_string(), bundle);
    }

    #[test]
    fn chosen_disk_round_trips_and_the_mount_refuses_it_unreplaced() {
        let line = "--system --storage @disk --nor @disk --preboot @disk";
        let options = round_trip(line);
        assert!(options.storage.as_ref().is_some_and(is_chosen));
        assert_eq!(options.to_string(), line);
        assert!(System::parse_resolved(line).is_err());
        let resolved = line.replace("@disk", DISK);
        assert!(System::parse_resolved(&resolved).is_ok());
    }

    #[test]
    fn every_option_survives_a_round_trip() {
        let options = round_trip(&format!(
            "--system --storage {DISK} --nor {DISK} --bundle b --install p.json \
             --install-source 11111111-2222-3333-4444-555555555555 --tss --verify-on-read \
             --usb-storage A --usb-storage B --input --idle-skip --sep-observe --native-cores 3 \
             --native-artifacts --serialized --profile --monitor-trace \
             --network-check http://h/p --audio-check transport-duplex --dram-base 0x10000000000 \
             --load 0x10000004000 --entry 0x10000008000 --x0 7 --budget 99 --break 0x10 \
             --trace 0x20 --watch 0x30,0x40 --dump x21-0x8,0x10 --dump 0x50,0x60"
        ));
        assert_eq!(options.usb_storage, ["A", "B"]);
        assert_eq!(options.audio_check, Some(AudioCheck::TransportDuplex));
        assert!(!options.parallel);
        assert_eq!(options.dumps[0], (Base::Register(21, -8), 0x10));
        let restore = round_trip(&format!(
            "--system --bundle b --storage {DISK} --restore-study --restore-source {DISK} \
             --restore-manifest m.plist --restore-identity 2"
        ));
        assert_eq!(restore.restore_manifest_path.as_deref(), Some("m.plist"));
    }

    #[test]
    fn wifi_names_escape_spaces_and_the_key_path_defaults() {
        let options = round_trip("--system --wifi Home%20Net%25 --wifi-country gb");
        assert_eq!(options.ssid.as_deref(), Some("Home Net%"));
        assert_eq!(options.wifi_key.as_deref(), Some(DEFAULT_WIFI_KEY));
        assert_eq!(options.wifi_country.as_deref(), Some("GB"));
        assert_eq!(
            options.to_string(),
            "--system --wifi Home%20Net%25 --wifi-country GB"
        );
        let keyed = round_trip("--system --wifi caf\u{e9} --wifi-key \\EFI\\k");
        assert_eq!(keyed.ssid.as_deref(), Some("caf\u{e9}"));
        assert_eq!(keyed.wifi_key.as_deref(), Some("\\EFI\\k"));
        for text in [
            "--system --wifi-key \\k",
            "--system --wifi-country GB",
            "--system --wifi %",
            "--system --wifi %4",
            "--system --wifi %FF",
            "--system --wifi 0123456789abcdef0123456789abcdef0",
            "--system --wifi a --wifi b",
            "--system --wifi a --wifi-country GBR",
            "--system --wifi a --wifi-country 12",
        ] {
            assert!(System::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn native_checks_imply_serialized_execution_without_writing_it() {
        let options = round_trip("--system --native-cores 2 --native-rounds");
        assert!(!options.parallel);
        assert!(!options.to_string().contains("--serialized"));
        assert!(System::parse("--system").unwrap().parallel);
    }

    #[test]
    fn native_core_counts_refuse_duplicates_zero_and_over_capacity() {
        for text in [
            "--system --native-cores 1 --native-cores 1",
            "--system --native-cores 0",
            "--system --native-cores 65",
            "--system --native-cores x",
            "--system --native-cores",
        ] {
            assert!(System::parse(text).is_err(), "{text}");
        }
        assert_eq!(
            System::parse("--system --native-cores 64")
                .unwrap()
                .native_cores,
            Some(64)
        );
    }

    #[test]
    fn invalid_lines_refuse() {
        for text in [
            "--storage x",
            "--system --unknown 1",
            "--system --install p.json",
            "--system --ecid 0",
            "--system --safe-boot",
            "--system --network-check https://h/p",
            "--system --dram-base 0x1000",
            "--system --storage-ram 1 --storage-ram 2",
        ] {
            assert!(System::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn numbers_take_decimal_and_separated_hex() {
        assert_eq!(number("0x1_0000"), Ok(0x10000));
        assert_eq!(number("42"), Ok(42));
        assert!(number("0xg").is_err());
        assert_eq!(
            vec![Base::parse("x3+0x10").unwrap()],
            [Base::Register(3, 16)]
        );
    }
}
