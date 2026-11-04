//! `stela setup`'s command line: creating a setup takes `stela setup`'s own
//! flags, and each action on an existing setup is a subcommand with only
//! the options it takes, so the parser refuses every other combination.
//! Each form becomes one [`Request`] for the action it names.
use super::{Action, InstallImage, NextBoot, Request, builds, ecid::Ecid, wifi};
use clap::{Args, Subcommand, builder::TypedValueParser};
use std::path::PathBuf;
use stela_boot_core::options::Uuid;

/// `stela setup`.
#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct Setup {
    #[command(subcommand)]
    action: Option<Command>,
    #[command(flatten)]
    create: Create,
}

impl Setup {
    pub(crate) fn run(self) -> anyhow::Result<()> {
        self.request().run()
    }

    /// The request the command line names.
    pub(super) fn request(self) -> Request {
        match self.action {
            None => self.create.request(),
            Some(command) => command.request(),
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Report everything about the setup and check it, changing nothing;
    /// fails when something needs fixing.
    #[command(visible_alias = "doctor")]
    Status(Usb),
    /// Put back what the setup record says (the entry, stela.cfg, the
    /// startup choices); with `--ipsw` or `--fetch`, prepare
    /// the active build's restore bundles again.
    Repair(Repair),
    /// Update an existing setup in place.
    #[command(subcommand)]
    Update(Update),
    /// Remove everything a previous setup wrote to this USB.
    Uninstall(Plain),
    /// Change an install's NVRAM on its machine-state partition.
    #[command(subcommand)]
    Nvram(Nvram),
    /// Back up an install's machine state, or write a backup back.
    #[command(subcommand)]
    State(State),
    /// Print the boot log stela.efi keeps on the install's machine-state
    /// partition.
    BootLog(Machine),
    /// Change the settings of an existing setup.
    Configure(Configure),
    /// Install host-device firmware for the PC onto an existing USB.
    #[command(subcommand)]
    HostFirmware(HostFirmware),
}

impl Command {
    fn request(self) -> Request {
        match self {
            Self::Status(usb) => usb.request(Action::Status),
            Self::Repair(command) => command.request(),
            Self::Update(command) => command.request(),
            Self::Uninstall(command) => command.request(Action::Uninstall),
            Self::Nvram(command) => command.request(),
            Self::State(command) => command.request(),
            Self::BootLog(command) => command.request(Action::BootLog),
            Self::Configure(command) => command.request(),
            Self::HostFirmware(command) => command.request(),
        }
    }
}

/// A partition's name, given as is or by its device path (`/dev/disk1s2`,
/// `/dev/sdb1`), as `--usb` takes a whole disk.
fn partition_name(value: &str) -> Result<String, String> {
    Ok(value.strip_prefix("/dev/").unwrap_or(value).to_owned())
}

/// The USB a maintenance command acts on.
#[derive(Args)]
struct Usb {
    /// The USB's EFI partition, or another mounted volume of the same USB.
    #[arg(long, value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from))]
    usb: PathBuf,
}

impl Usb {
    fn request(self, action: Action) -> Request {
        Request {
            action,
            usb: self.usb,
            ..Request::default()
        }
    }
}

/// The USB and `--dry-run`.
#[derive(Args)]
struct Plain {
    #[command(flatten)]
    usb: Usb,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
}

impl Plain {
    fn request(self, action: Action) -> Request {
        Request {
            dry_run: self.dry_run,
            ..self.usb.request(action)
        }
    }
}

/// Where the restore image comes from.
#[derive(Args)]
struct Image {
    /// The macOS restore image (IPSW) of a supported build.
    #[arg(long, conflicts_with = "fetch")]
    ipsw: Option<PathBuf>,
    /// Download the restore image from Apple instead: its recovery members,
    /// or the whole IPSW with `--install-image offline`.
    #[arg(long)]
    fetch: bool,
    /// Where `--fetch` keeps the image.
    #[arg(long)]
    download_dir: Option<PathBuf>,
    /// The build `--fetch` downloads: the newest supported one by default.
    #[arg(long, default_value = builds::DEFAULT.build, hide = true)]
    build: String,
}

impl Image {
    fn apply(self, request: &mut Request) {
        request.ipsw = self.ipsw;
        request.fetch = self.fetch;
        request.download_dir = self.download_dir;
        request.build = self.build;
    }
}

/// The Wi-Fi network `stela.efi` joins.
#[derive(Args)]
struct Wifi {
    /// Join this Wi-Fi network for the install's network, beside or instead
    /// of Ethernet. Setup asks for its passphrase and writes it to the USB in
    /// plaintext (`EFI/stela/wifi.key`).
    #[arg(long, value_name = "SSID", value_parser = wifi::ssid)]
    wifi: Option<String>,
    /// Read the Wi-Fi passphrase (8 to 63 characters, or a 64-digit hex PSK)
    /// from this file instead of asking.
    #[arg(long, value_name = "FILE", requires = "wifi")]
    wifi_passphrase_file: Option<PathBuf>,
    /// The country whose Wi-Fi rules apply, as an ISO 3166 code such as US
    /// or DE.
    #[arg(long, value_name = "CODE", requires = "wifi", value_parser = wifi::country)]
    wifi_country: Option<String>,
}

impl Wifi {
    fn apply(self, request: &mut Request) {
        request.wifi = self.wifi;
        request.wifi_passphrase_file = self.wifi_passphrase_file;
        request.wifi_country = self.wifi_country;
    }
}

/// A USB4 device's UUID, in the spelling the boot log prints.
fn usb4_device(text: &str) -> Result<String, String> {
    Uuid::parse(text)
        .map(|uuid| uuid.to_string())
        .ok_or_else(|| "a USB4 device is named by its UUID, as the boot log prints it".into())
}

/// The addresses `stela.efi`'s network uses instead of DHCP's.
#[derive(Args)]
struct Addressing {
    /// Give the PC this IPv4 address and prefix length, such as
    /// 192.168.1.20/24, instead of asking DHCP.
    #[arg(long, value_name = "ADDRESS/PREFIX", value_parser = super::addresses::ipv4)]
    ipv4: Option<stela_boot_core::options::StaticIpv4>,
    /// The IPv4 default router: another address of --ipv4's subnet.
    #[arg(long, value_name = "ADDRESS", requires = "ipv4")]
    ipv4_gateway: Option<std::net::Ipv4Addr>,
    /// Resolve names with these servers (up to 3, comma-separated, IPv4 or
    /// IPv6) instead of the ones DHCP and the router announce.
    #[arg(long, value_name = "SERVERS", value_parser = super::addresses::servers)]
    dns: Option<super::addresses::Servers>,
}

impl Addressing {
    fn apply(self, request: &mut Request) {
        request.ipv4 = self.ipv4;
        request.ipv4_gateway = self.ipv4_gateway;
        request.dns = self.dns.map(|servers| servers.0);
    }
}

/// An install's machine state.
#[derive(Args)]
struct Machine {
    #[command(flatten)]
    usb: Usb,
    /// The install to act on (the default install otherwise).
    #[arg(long)]
    install: Option<String>,
    /// The install's machine-state partition, named again (the target
    /// itself when its tail holds the state).
    #[arg(long, value_parser = partition_name)]
    nor: Option<String>,
}

impl Machine {
    fn request(self, action: Action) -> Request {
        Request {
            install: self.install,
            nor: self.nor,
            ..self.usb.request(action)
        }
    }
}

/// Create a setup: the wizard without `--usb`.
#[derive(Args)]
struct Create {
    /// The USB's EFI partition, another mounted volume of the same USB, or
    /// the whole USB disk (such as disk5 on macOS, /dev/sdb on Linux or
    /// PhysicalDrive2 on Windows), which setup erases first into an EFI
    /// partition and a FAT32 volume. Without it, setup asks.
    #[arg(long, default_value = "", value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from))]
    usb: PathBuf,
    #[command(flatten)]
    image: Image,
    #[command(flatten)]
    wifi: Wifi,
    /// Give this USB4 device a PCIe tunnel on PCs without an IOMMU that
    /// confines it, where it can reach all of memory. Repeat for more
    /// devices. The boot log prints each refused device's UUID, which a
    /// device can claim falsely.
    #[arg(long, value_name = "UUID", value_parser = usb4_device)]
    usb4_approve: Vec<String>,
    #[command(flatten)]
    addressing: Addressing,
    /// Where an install reads the macOS restore image: `offline` copies the
    /// whole IPSW (about 27 GB) onto the USB; TSS still needs network.
    /// `online` writes only its inventory, and `stela.efi` streams
    /// the IPSW from Apple's servers during the install over the PC's wired
    /// network. A complete local IPSW defaults to offline, including for
    /// a disk chosen later in stela.efi. An image without the macOS system
    /// image (`--fetch`) defaults to online.
    #[arg(long, value_enum)]
    install_image: Option<InstallImage>,
    /// The `stela.efi` to install instead of the one built into `stela`.
    #[arg(long)]
    efi: Option<PathBuf>,
    /// The Mac model Stela presents (MacBookPro18,3, M1 Pro, by default).
    /// Preparation checks the selected board's platform requirements and
    /// refuses unsupported ones. Every install of a setup presents the same model.
    #[arg(long)]
    model: Option<String>,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// The PC's partition that becomes the Mac's internal SSD, such as
    /// disk1s2 on macOS, /dev/nvme0n1p2 on Linux or disk1p2 on Windows:
    /// Install macOS restores macOS onto it, and it is booted from it.
    /// Without --nor its last 16 MiB keep the machine state (NVRAM, the SEP's
    /// state and the boot log), which the guest never sees. On an existing
    /// setup, it adds another install.
    #[arg(long, value_parser = partition_name)]
    target: Option<String>,
    /// Optional: a separate PC partition (at least 1 MiB and 64 KiB) for the
    /// machine state instead of the target's tail: the Mac's NOR flash, where
    /// NVRAM persists, and the SEP's state; with at least 0x510000 bytes it
    /// also keeps stela.efi's boot log.
    #[arg(long, value_parser = partition_name, requires = "target")]
    nor: Option<String>,
    /// The serial number of the disk holding `--target` and `--nor`, when
    /// this computer cannot read it.
    #[arg(long, requires = "target")]
    disk_serial: Option<String>,
    /// Erase the other file system a `--target` holds, unmounting it first:
    /// the PC's own OS would mount it and clear Stela's machine state.
    #[arg(long, requires = "target")]
    erase_target: bool,
    /// Write a fresh NOR image over machine state that is neither blank nor
    /// one, and blank a foreign SEP area.
    #[arg(long, requires = "target")]
    initialize_nor: bool,
    /// The name of the new install.
    #[arg(long)]
    install: Option<String>,
    /// The ECID of the machine being set up, in hexadecimal: reuse a known
    /// machine's (from `status` of its old USB or a `state backup` file).
    #[arg(long, value_parser = |value: &str| Ecid::parse(value).map_err(|e| e.to_string()))]
    ecid: Option<Ecid>,
    /// Give the machine a new ECID although its machine state belongs to
    /// another one. Its LocalPolicy and SEP state are then orphaned.
    #[arg(long)]
    new_ecid: bool,
    /// Opt in to Apple's signing server: the restore host sends the
    /// machine's ECID, the restore's nonces and the build's component hashes
    /// to gs.apple.com for the restore's personalized root tickets and the
    /// recoveryOS LocalPolicy. Required for a new setup, which installs
    /// macOS: a local IPSW supplies the image files, but boot firmware still
    /// needs personalized tickets.
    #[arg(long)]
    tss: bool,
    /// Have every startup choice time the engine (its `--profile`): each
    /// heartbeat of the boot log then reports where the engine's time goes
    /// between translated blocks, by phase and by exit kind.
    #[arg(long)]
    profile: bool,
    /// Have the install refuse an IPSW without recorded block hashes, which
    /// it otherwise reads whole before the restore starts; with them it
    /// checks each block as the restore reads it either way. It adds the
    /// engine's `--verify-on-read` to the Install macOS choice.
    #[arg(long, requires = "target")]
    verify_on_read: bool,
    /// The USB's FAT32 data partition, when it has several, for the boot
    /// bundles, the install medium (the full IPSW in pieces or its
    /// inventory) and the translation store; the first one by default.
    #[arg(long)]
    install_volume: Option<PathBuf>,
    /// The bound of each translation pack `stela.efi` keeps on the USB, in
    /// bytes (64 MiB to the FAT32 file limit; 0 for none). Defaults to 1 GiB
    /// or what fits. The mount uses up to 1 GiB of each allocation.
    #[arg(long, value_name = "BYTES")]
    translation_store_bytes: Option<u64>,
    /// The model or size, as setup shows it, of the whole disk `--usb`
    /// names, which erasing a removable disk other than a USB (an SD card,
    /// a FireWire or Thunderbolt disk) needs typed back.
    #[arg(long, value_name = "MODEL|SIZE")]
    confirm_disk: Option<String>,
}

impl Create {
    fn request(self) -> Request {
        let mut request = Request {
            action: Action::Create,
            usb: self.usb,
            install_image: self.install_image,
            efi: self.efi,
            model: self.model,
            dry_run: self.dry_run,
            target: self.target,
            nor: self.nor,
            disk_serial: self.disk_serial,
            erase_target: self.erase_target,
            initialize_nor: self.initialize_nor,
            install: self.install,
            ecid: self.ecid,
            new_ecid: self.new_ecid,
            tss: self.tss,
            profile: self.profile,
            verify_on_read: self.verify_on_read,
            install_volume: self.install_volume,
            translation_store_bytes: self.translation_store_bytes,
            confirm_disk: self.confirm_disk,
            ..Request::default()
        };
        self.image.apply(&mut request);
        request.usb4_approve = self.usb4_approve;
        self.wifi.apply(&mut request);
        self.addressing.apply(&mut request);
        request
    }
}

#[derive(Args)]
struct Repair {
    #[command(flatten)]
    usb: Usb,
    #[command(flatten)]
    image: Image,
    /// Where an install reads the restore image the repaired medium holds
    /// (with `--ipsw` or `--fetch`).
    #[arg(long, value_enum)]
    install_image: Option<InstallImage>,
    /// Erase the other file system an install's Apple region holds: the
    /// PC's own OS would mount it and clear Stela's machine state.
    #[arg(long)]
    erase_target: bool,
    /// The machine's ECID, in hexadecimal, when its machine state cannot
    /// name it.
    #[arg(long, value_parser = |value: &str| Ecid::parse(value).map_err(|e| e.to_string()))]
    ecid: Option<Ecid>,
    /// Give the machine a new ECID although its machine state belongs to
    /// another one. Its LocalPolicy and SEP state are then orphaned.
    #[arg(long)]
    new_ecid: bool,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
}

impl Repair {
    fn request(self) -> Request {
        let mut request = Request {
            install_image: self.install_image,
            erase_target: self.erase_target,
            ecid: self.ecid,
            new_ecid: self.new_ecid,
            dry_run: self.dry_run,
            ..self.usb.request(Action::Repair)
        };
        self.image.apply(&mut request);
        request
    }
}

#[derive(Subcommand)]
enum Update {
    /// Replace `stela.efi` (`--efi`, or the one built into `stela`); `--ipsw`
    /// or `--fetch` lets it prepare the boot bundles again when it reads a
    /// new bundle schema or this `stela` prepares a new bundle revision.
    Stela(UpdateStela),
    /// Add a new macOS build's install medium and restore bundles (`--ipsw`
    /// or `--fetch`) for Install macOS.
    Os(UpdateOs),
}

impl Update {
    fn request(self) -> Request {
        match self {
            Self::Stela(command) => {
                let mut request = Request {
                    efi: command.efi,
                    dry_run: command.dry_run,
                    ..command.usb.request(Action::UpdateStela)
                };
                command.image.apply(&mut request);
                request
            }
            Self::Os(command) => {
                let mut request = Request {
                    install_image: command.install_image,
                    dry_run: command.dry_run,
                    ..command.usb.request(Action::UpdateOs)
                };
                command.image.apply(&mut request);
                request
            }
        }
    }
}

#[derive(Args)]
struct UpdateStela {
    #[command(flatten)]
    usb: Usb,
    /// The `stela.efi` to install instead of the one built into `stela`.
    #[arg(long)]
    efi: Option<PathBuf>,
    #[command(flatten)]
    image: Image,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct UpdateOs {
    #[command(flatten)]
    usb: Usb,
    #[command(flatten)]
    image: Image,
    /// Where an install reads the new build's restore image (see `stela
    /// setup --help`).
    #[arg(long, value_enum)]
    install_image: Option<InstallImage>,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Nvram {
    /// Choose the next boot of the installed disk in its NVRAM.
    NextBoot {
        #[arg(value_enum)]
        choice: NextBoot,
        #[command(flatten)]
        usb: Usb,
        /// The install to act on (the default install otherwise).
        #[arg(long)]
        install: Option<String>,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Write a fresh NVRAM to the install's machine-state partition; its
    /// SEP state is kept.
    Reset {
        #[command(flatten)]
        machine: Machine,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

impl Nvram {
    fn request(self) -> Request {
        match self {
            Self::NextBoot {
                choice,
                usb,
                install,
                dry_run,
            } => Request {
                install,
                dry_run,
                ..usb.request(Action::NextBoot(choice))
            },
            Self::Reset { machine, dry_run } => Request {
                dry_run,
                ..machine.request(Action::ResetNvram)
            },
        }
    }
}

#[derive(Subcommand)]
enum State {
    /// Copy the install's machine state (NVRAM and SEP state, with its keys)
    /// to a new private file.
    Backup {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[command(flatten)]
        machine: Machine,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Write a `state backup` file back to the install it came from.
    Restore {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[command(flatten)]
        machine: Machine,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

impl State {
    fn request(self) -> Request {
        let (action, machine, dry_run) = match self {
            Self::Backup {
                file,
                machine,
                dry_run,
            } => (Action::BackupState(file), machine, dry_run),
            Self::Restore {
                file,
                machine,
                dry_run,
            } => (Action::RestoreState(file), machine, dry_run),
        };
        Request {
            dry_run,
            ..machine.request(action)
        }
    }
}

#[derive(Args)]
struct Configure {
    #[command(flatten)]
    usb: Usb,
    /// Boot this install by default.
    #[arg(long)]
    default_install: Option<String>,
    /// Remove this install from the setup; its partitions are kept.
    #[arg(long)]
    remove_install: Option<String>,
    /// Seconds `stela.efi`'s startup choices wait (0: only when a key is
    /// held).
    #[arg(long)]
    chooser_timeout: Option<u32>,
    /// Turn the Apple signing server opt-in on (see `stela setup --help`).
    #[arg(long, conflicts_with = "no_tss")]
    tss: bool,
    /// Turn the Apple signing server opt-in off.
    #[arg(long)]
    no_tss: bool,
    /// Turn the engine profile on for every startup choice.
    #[arg(long, conflicts_with = "no_profile")]
    profile: bool,
    /// Turn the engine profile off.
    #[arg(long)]
    no_profile: bool,
    #[command(flatten)]
    wifi: Wifi,
    /// Give this USB4 device a PCIe tunnel on PCs without an IOMMU that
    /// confines it, where it can reach all of memory. Repeat for more
    /// devices; the list replaces the last one. The boot log prints each
    /// refused device's UUID, which a device can claim falsely.
    #[arg(long, value_name = "UUID", value_parser = usb4_device)]
    usb4_approve: Vec<String>,
    /// Approve no USB4 device.
    #[arg(long, conflicts_with = "usb4_approve")]
    no_usb4_approve: bool,
    /// Join no Wi-Fi network, and remove the key file.
    #[arg(long, conflicts_with = "wifi")]
    no_wifi: bool,
    #[command(flatten)]
    addressing: Addressing,
    /// Take the IPv4 address and router from DHCP again.
    #[arg(long, conflicts_with = "ipv4")]
    automatic_ipv4: bool,
    /// Take the DNS servers from DHCP and the router again.
    #[arg(long, conflicts_with = "dns")]
    automatic_dns: bool,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
}

impl Configure {
    fn request(self) -> Request {
        let mut request = Request {
            default_install: self.default_install,
            remove_install: self.remove_install,
            chooser_timeout: self.chooser_timeout,
            tss: self.tss,
            no_tss: self.no_tss,
            profile: self.profile,
            no_profile: self.no_profile,
            no_wifi: self.no_wifi,
            usb4_approve: self.usb4_approve,
            no_usb4_approve: self.no_usb4_approve,
            automatic_ipv4: self.automatic_ipv4,
            automatic_dns: self.automatic_dns,
            dry_run: self.dry_run,
            ..self.usb.request(Action::Configure)
        };
        self.wifi.apply(&mut request);
        self.addressing.apply(&mut request);
        request
    }
}

#[derive(Subcommand)]
enum HostFirmware {
    /// Install an authorized local host-device firmware package
    /// (manifest.json and resources) onto the USB; independent of Apple boot
    /// bundles.
    Install {
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,
        #[command(flatten)]
        usb: Usb,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Download pinned vendor firmware for exact requirements captured by
    /// native drivers. The inventory must come from the target PC, not this
    /// setup host.
    Fetch {
        #[arg(value_name = "REQUIREMENTS", required_unless_present = "gpu")]
        requirements: Option<PathBuf>,
        /// Also keep what the USB holds, and add what nouveau needs for this
        /// NVIDIA chip, which a boot without it names (`ga104`).
        #[arg(long, value_name = "CHIP")]
        gpu: Option<String>,
        #[command(flatten)]
        usb: Usb,
        /// Cache for pinned host firmware images and redistribution notices.
        #[arg(long, value_name = "DIRECTORY")]
        cache: Option<PathBuf>,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

impl HostFirmware {
    fn request(self) -> Request {
        match self {
            Self::Install {
                directory,
                usb,
                dry_run,
            } => Request {
                dry_run,
                ..usb.request(Action::HostFirmwareInstall(directory))
            },
            Self::Fetch {
                requirements,
                gpu,
                usb,
                cache,
                dry_run,
            } => Request {
                dry_run,
                host_firmware_cache: cache,
                ..usb.request(Action::HostFirmwareFetch { requirements, gpu })
            },
        }
    }
}
