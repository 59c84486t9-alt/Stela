//! The UEFI mount: build `stela.efi` and run it in x86 QEMU.
//!
//! The run puts the application on a FAT volume as the removable-media boot
//! file, beside `\EFI\stela\stela.cfg` (the mount options) and
//! `\EFI\stela\source.bin` (the system-mode guest image, when the run has
//! one), and boots it with QEMU's edk2 firmware, as a PC's firmware boots the
//! USB `stela setup` prepares. By default the guest is Stela's system-mode
//! test kernel.
//!
//! `--payload` runs install mode on a synthetic IPSW (no Apple bytes) split
//! onto the boot volume: `verify` checks every Erase member,
//! `verify-archive` does so from the whole IPSW instead, `stage` and
//! `stage-path`
//! also partitions a blank second disk and copies them into staging, which
//! the run then reads back on the host.
//!
//! `--preboot-disk IMAGE` attaches a disk image holding an installed
//! system's APFS Preboot volume; the mount builds the boot bundle from it at
//! boot and enters it, and the run checks the result against the bundle the
//! host builds from the same image.
use crate::{
    check::{BOOT_MANIFEST, BOOT_TARGET, BOOT_TARGET_DIR},
    tools::{binding, cargo, exec, qemu, root, stop, wait},
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command as Process, ExitCode, Stdio},
    time::{Duration, Instant},
};
use {
    stela_formats::payload::PayloadError, stela_formats::payload::PayloadSource,
    stela_formats::payload::ReadAt, stela_formats::payload::copy_verified,
    stela_formats::payload::gpt, stela_formats::payload::staging::StagedSource,
};

mod audio_check;
mod disks;
mod fat32;
mod host_firmware;
mod lan;
mod machine;
mod network;
mod network_check;
mod preboot;
mod report;
mod storage;

/// `isa-debug-exit` reports `(code << 1) | 1`; a timeout reports 124.
const TIMEOUT_EXIT: u8 = 124;
const MAX_TIMEOUT_SECONDS: f64 = 120.0;
/// QEMU's FAT16 directory volume holds at most 516 MB; keep a margin.
const VVFAT_BYTES: u64 = 480 * 1024 * 1024;
/// A real restore payload verifies, and a kernel bundle boots, in tens of
/// minutes under TCG; a whole install takes hours.
const MAX_LONG_TIMEOUT_SECONDS: f64 = 24.0 * 3600.0;
const FIRMWARE_CODE: &str = "edk2-x86_64-code.fd";
const FIRMWARE_VARIABLES: &str = "edk2-i386-vars.fd";

/// The blank target disk of a staging run, sparse on the host.
const TARGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Its PCI slot, which fixes its UEFI device path.
const TARGET_SLOT: u8 = 5;
/// The serial the NVMe target reports, which `stela.cfg` names.
const TARGET_SERIAL: &str = "STELA-TARGET-01";
/// Small slices, so the synthetic members span several.
const SYNTHETIC_SLICE_BYTES: u64 = 400_000;

/// Stela's system-mode test kernel (`boot/kernel.S`), loaded 16 KiB into the
/// J473AP DRAM base. Empty when xtask was built without clang.
const KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kernel.bin"));

fn kernel() -> Result<Vec<u8>> {
    ensure!(
        !KERNEL.is_empty(),
        "the system-mode test kernel was not assembled because clang was not found \
         when xtask was built; install clang (or set CLANG) and run again"
    );
    Ok(KERNEL.to_vec())
}
const KERNEL_OPTIONS: &str = "--system --load 0x800004000 --entry 0x800004000";
/// What the test kernel must leave in X0-X11 when it idles; X1 and X2, its
/// tasks' SVC counts, need only be nonzero.
const KERNEL_RESULTS: [(usize, Option<u64>); 12] = [
    (0, Some(0x5354_454c_4120_4f4b)),
    (1, None),
    (2, None),
    (3, Some(6)),
    // EL2 data abort: EC 0x25, IL, level 2 translation fault.
    (4, Some(0x9600_0006)),
    (5, Some(0xffff_ff80_0400_0000)),
    // EL2 SVC #0x10 and EL0 SVC #1.
    (6, Some(0x5600_0010)),
    (7, Some(0x5600_0001)),
    // EL2 load and store at the Stela window's address, outside both
    // ranges: level 0 translation faults, the store's with WnR.
    (8, Some(0x9600_0004)),
    (9, Some(0x9600_0044)),
    (10, Some(0x0040_0000_0000_0000)),
    // TEST_VA's pages across the TTBR0 switches: ASID 1's, 2's, 1's again,
    // 2's, 1's after a TLBI VAE1 while 2's tables were current, 2's, and
    // 1's after an ASIDE1.
    (11, Some(0x121_2321)),
];

/// System options for a boot bundle, which gets the VM's free RAM.
const BUNDLE_OPTIONS: &str = "--system --bundle \\EFI\\stela\\bundle";

/// The line the test kernel writes through the S5L UART model.
const KERNEL_BANNER: &str = "GUEST| STELA TEST KERNEL: MMU ON, UART MMIO";

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Scenario {
    /// The system-mode engine running Stela's own test kernel: a VHE host at
    /// EL2, 16 KiB granule, high-half kernel, EL2 abort and SVC, TTBR0
    /// switches, timer FIQ, two EL0 tasks.
    SystemKernel,
}

#[derive(Subcommand)]
pub enum Command {
    /// Build `stela.efi`.
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Boot `stela.efi` with an ARM image in x86 QEMU.
    Run(Box<Run>),
}

#[derive(Args)]
pub struct Run {
    /// The application; defaults to a fresh release build.
    #[arg(long)]
    image: Option<PathBuf>,
    /// Authorized local host-device firmware package, loaded before boot services end.
    #[arg(long, conflicts_with = "usb_image")]
    host_firmware: Option<PathBuf>,
    /// A system-mode guest image, run with the test kernel's options unless
    /// `--append` gives others; defaults to the scenario's image.
    #[arg(long)]
    module: Option<PathBuf>,
    /// The built-in image and options to run when no module is given.
    #[arg(long, value_enum, default_value_t = Scenario::SystemKernel)]
    scenario: Scenario,
    /// QEMU CPU model/properties. System mode defaults to an explicit Intel
    /// model: QEMU's AMD models lack the required AMD routing-control MSRs.
    #[arg(long)]
    cpu: Option<String>,
    /// Firmware-visible x86 cores, one thread each. This supplies the host
    /// inventory; the mount independently selects/qualifies native workers.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=64))]
    host_cores: u16,
    /// Firmware-visible SMT threads per core. Native execution independently
    /// selects one qualified thread per physical core.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..))]
    host_threads: u16,
    /// Guest machine memory for QEMU; defaults to 1G, 8G for system mode
    /// and 12G with a boot bundle.
    #[arg(long)]
    memory: Option<String>,
    /// A kernel boot bundle directory (`stela-dev boot prepare` output) to start
    /// on the system-mode engine; it is copied to `\EFI\stela\bundle`.
    #[arg(long, conflicts_with = "module")]
    bundle: Option<PathBuf>,
    /// A GPT disk image whose APFS container holds an installed system's
    /// Preboot volume, attached over NVMe through a snapshot: the mount
    /// builds the boot bundle from it with its own storage drivers and
    /// starts it on the system-mode engine.
    #[arg(long, conflicts_with_all = ["module", "bundle", "append", "payload"])]
    preboot_disk: Option<PathBuf>,
    /// A restore payload inventory (`stela-dev image-manifest
    /// --payload-manifest`), placed at `\EFI\stela\payload.json` for the
    /// mount's `--restore-manifest`, with the block hash file it names
    /// (`blocks.bin` beside it).
    #[arg(long, requires = "bundle")]
    restore_manifest: Option<PathBuf>,
    /// Have the restore host refuse a payload without recorded block
    /// hashes, which it would read whole before StartRestore: adds the
    /// mount's `--verify-on-read`. A USB image carries it in its install
    /// entry (`stela setup --verify-on-read`).
    #[arg(long, requires = "bundle")]
    verify_on_read: bool,
    /// Use QEMU's directory-backed FAT16 for a bundle that fits its
    /// volume, avoiding host disk-image utilities (QEMU rejects overflow).
    #[arg(long, requires = "bundle")]
    directory_volume: bool,
    /// Attach a raw GPT disk over NVMe, preserving writes; repeat for more
    /// disks. Select a partition with --storage SERIAL:GUID in --append, or
    /// give a USB image's entries the PC disk they name by its serial.
    #[arg(long, conflicts_with_all = ["storage_check", "payload", "preboot_disk"])]
    storage_disk: Vec<PathBuf>,
    /// NVMe serial of the --storage-disk at the same position. One disk
    /// defaults to STELAANS; several disks need distinct serials each.
    #[arg(long, requires = "storage_disk", value_parser = parse_storage_serial)]
    storage_serial: Vec<String>,
    /// Fresh directory for the boot volume, serial log and run report.
    #[arg(long)]
    output: PathBuf,
    /// Mount options, for example `--entry 0x100000 --budget 1000`.
    #[arg(long, allow_hyphen_values = true)]
    append: Option<String>,
    #[arg(long, default_value_t = 60.0)]
    timeout: f64,
    #[arg(long, value_enum, default_value_t = Display::None)]
    display: Display,
    /// Pause at reset with a GDB stub on this loopback port.
    #[arg(long)]
    gdb: Option<u16>,
    /// Serve the QEMU monitor over telnet on this loopback port.
    #[arg(long)]
    monitor: Option<u16>,
    /// Hide five-level paging from the guest CPU, so system mode runs on
    /// its four-level placement, as on a host without LA57.
    #[arg(long)]
    no_la57: bool,
    /// Advance QEMU's clocks by 2^SHIFT ns per executed x86 instruction
    /// (`-icount shift=SHIFT,sleep=off`) instead of host time, so that guest
    /// timeouts measure emulated work, as they would on hardware, and an idle
    /// guest skips ahead to its next timer.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=10))]
    icount: Option<u8>,
    /// Run the x86 guest on the host's processor through KVM instead of
    /// translating it with TCG, with the host's CPU model unless `--cpu`
    /// names one. Needs a Linux host with `/dev/kvm`.
    #[arg(long, conflicts_with = "icount")]
    kvm: bool,
    /// Attach a GPT disk image through virtio-blk, NVMe and AHCI, have the
    /// mount overwrite and read back one partition of each, and verify the
    /// mount's hashes and every byte of the images.
    #[arg(long)]
    storage_check: bool,
    /// Qualify native conventional HDA after ExitBootServices. Playback compares
    /// actual WAV PCM; duplex checks both DMA engines with a silent null source.
    #[arg(long, value_enum, num_args = 0..=1, default_missing_value = "duplex",
        conflicts_with_all = ["module", "usb_image", "payload", "storage_check"])]
    audio_check: Option<audio_check::Mode>,
    /// Controlled QEMU EDU/VT-d DMA roundtrip, stale-IOVA fault and teardown.
    #[arg(long, conflicts_with_all = [
        "module", "bundle", "append", "payload", "preboot_disk", "usb_image",
        "storage_check", "storage_disk", "network", "usb_network", "input",
        "usb_input", "usb_disk", "usb_storage_disk", "guest_network", "host_firmware", "audio_check"
    ])]
    native_dma_check: bool,
    /// Two isolated EDU domains, same IOVAs and a matched wrong-domain fault.
    #[arg(long, conflicts_with_all = [
        "native_dma_check", "module", "bundle", "append", "payload", "preboot_disk", "usb_image",
        "storage_check", "storage_disk", "network", "usb_network", "input",
        "usb_input", "usb_disk", "usb_storage_disk", "guest_network", "host_firmware", "audio_check"
    ])]
    native_dma_isolation_check: bool,
    /// Actual BSP deferred-work contexts, ABI/control/IRQ flags and guard proof.
    #[arg(long, conflicts_with_all = [
        "native_dma_check", "native_dma_isolation_check", "module", "bundle", "append", "payload", "preboot_disk", "usb_image",
        "storage_check", "storage_disk", "network", "usb_network", "input",
        "usb_input", "usb_disk", "usb_storage_disk", "guest_network", "host_firmware", "audio_check"
    ])]
    native_work_check: bool,
    /// Actual EDU MSI admission into the owned native BSP work executor.
    #[arg(long, conflicts_with_all = [
        "native_dma_check", "native_dma_isolation_check", "native_work_check", "module", "bundle", "append", "payload", "preboot_disk", "usb_image",
        "storage_check", "storage_disk", "network", "usb_network", "input", "usb_input", "usb_disk", "usb_storage_disk", "guest_network", "host_firmware", "audio_check"
    ])]
    native_irq_work_check: bool,
    /// Actual single-BSP MMIO mapping, context refusal, retirement and reuse.
    /// The root's wall time is an owned HPET, so it passes only with `--hpet`;
    /// without one the mount refuses at `stage=hpet-wholeblock`.
    #[arg(long, conflicts_with_all = [
        "native_dma_check", "native_dma_isolation_check", "native_work_check", "native_irq_work_check",
        "module", "bundle", "append", "payload", "preboot_disk", "usb_image",
        "storage_check", "storage_disk", "network", "usb_network", "input", "usb_input",
        "usb_disk", "usb_storage_disk", "guest_network", "host_firmware", "audio_check",
        "gdb", "monitor", "icount"
    ])]
    native_mmio_check: bool,
    /// Give the PC an IOMMU, which the mount takes over for the requesters
    /// its policy allows: Intel VT-d or AMD-Vi.
    #[arg(long, value_enum, conflicts_with_all = [
        "native_dma_check", "native_dma_isolation_check", "native_irq_work_check"
    ])]
    iommu: Option<Iommu>,
    /// Expose QEMU's real HPET to the owned Root/MMIO diagnostic.
    #[arg(long, requires = "native_mmio_check")]
    hpet: bool,
    /// Actual bounded PM/LAPIC clock, IRQ progress, idle waits and retirement.
    #[arg(long, conflicts_with_all = [
        "native_dma_check", "native_dma_isolation_check", "native_work_check", "native_irq_work_check", "native_mmio_check",
        "module", "bundle", "append", "payload", "preboot_disk", "usb_image",
        "storage_check", "storage_disk", "network", "usb_network", "input", "usb_input",
        "usb_disk", "usb_storage_disk", "guest_network", "host_firmware", "audio_check",
        "gdb", "monitor", "icount"
    ])]
    native_clock_check: bool,
    /// Boot an existing USB disk image, such as a copy of a stick `stela
    /// setup` prepared, from its removable-media boot loader, attached as a
    /// USB mass-storage device; writes go to a temporary overlay unless
    /// `--usb-writable`.
    #[arg(long, conflicts_with_all = [
        "payload", "module", "bundle", "append", "storage_check", "preboot_disk"
    ])]
    usb_image: Option<PathBuf>,
    /// The `--usb-image` stick's USB serial number, which its setup's
    /// `--storage` and `--nor` options name.
    #[arg(long, requires = "usb_image", default_value = "STELAUSBIMAGE")]
    usb_serial: String,
    /// Keep the guest's writes in the `--usb-image` file, so a restore's
    /// install boots in a later run.
    #[arg(long, requires = "usb_image")]
    usb_writable: bool,
    /// Resume a `savevm` checkpoint of a `.qcow2` `--usb-image`, whose UEFI
    /// variables live beside it in `<image>.vars.qcow2` so checkpoints keep
    /// every writable drive.
    #[arg(long, requires = "usb_image")]
    loadvm: Option<String>,
    /// Give a bundle's guest the native USB keyboard and pointer, fed by
    /// QEMU's virtio keyboard and tablet: adds both devices and the mount's
    /// `--input`.
    #[arg(long, conflicts_with_all = ["module", "usb_image", "payload"])]
    input: bool,
    /// Give the mount a host network adapter: a `virtio-net-pci`, which the
    /// mount drives after ExitBootServices for its own requests (`--tss`,
    /// `--network-check`), on a QEMU `stream` netdev to xtask's own LAN
    /// peer (`boot/lan.rs`): DHCP, DNS and TCP relayed to the host, logged
    /// to `network.log`. QEMU needs no slirp. A USB image's own entries say
    /// whether the mount uses it.
    #[arg(long, group = "network_adapter", conflicts_with_all = ["module", "payload"])]
    network: bool,
    /// PCI network controller exercised by --network. Physical-controller
    /// models test the same driver the mount uses on a PC.
    #[arg(long, value_enum, requires = "network")]
    network_model: Option<NetworkModel>,
    /// Have the mount POST once to this `http://` URL over the host network
    /// at start and report the reply: adds `--network-check URL`.
    #[arg(long, requires = "network_adapter")]
    network_check: Option<String>,
    /// Check DHCP, DNS, TCP and NIC ring reuse against a local HTTP peer
    /// with a 200,000-byte response whose digest the mount must reproduce.
    /// Requires system mode, such as --scenario system-kernel.
    #[arg(long, requires = "network_adapter", conflicts_with = "network_check")]
    network_self_check: bool,
    /// Give the guest its USB Ethernet adapter: a second `virtio-net-pci`
    /// on a LAN peer of its own (logged to `guest-network.log`), which the
    /// mount bridges to the guest's CDC-ECM adapter: adds `--guest-network`.
    #[arg(long, conflicts_with_all = ["module", "usb_image", "payload"])]
    guest_network: bool,
    /// Attach a raw disk over NVMe, preserving writes, that the guest sees
    /// whole as a USB mass storage device behind its native hub; repeat for
    /// more disks (at most six). Adds `--usb-storage STELAUSBn`.
    #[arg(long, conflicts_with_all = ["storage_check", "payload", "preboot_disk", "usb_image"])]
    usb_storage_disk: Vec<PathBuf>,
    /// Feed the guest's keyboard and pointer from USB HID devices the mount
    /// drives itself: a `qemu-xhci` with `usb-kbd`, `usb-tablet` and
    /// `usb-mouse`, and the mount's `--input`.
    #[arg(long, conflicts_with_all = ["module", "usb_image", "payload"])]
    usb_input: bool,
    /// Give the mount its host network adapter as a USB CDC-ECM device on
    /// the `qemu-xhci` (`usb-net`), on a LAN peer of its own
    /// (`usb-network.log`), for `--tss` and `--network-check`.
    #[arg(long, group = "network_adapter", conflicts_with_all = ["module", "usb_image", "payload"])]
    usb_network: bool,
    /// Attach a raw disk as a QEMU `usb-storage` device on the `qemu-xhci`,
    /// with serial `STELAUSBDISKn`, preserving writes; the mount drives it
    /// over Bulk-Only and selects it by that serial like any host disk.
    #[arg(long, conflicts_with_all = ["storage_check", "payload", "preboot_disk", "usb_image"])]
    usb_disk: Vec<PathBuf>,
    /// Physical USB mass-storage model, including UAS with actual xHCI streams.
    #[arg(long, value_enum, requires = "usb_disk")]
    usb_disk_model: Option<UsbDiskModel>,
    /// Run install mode on a synthetic restore payload.
    #[arg(long, value_enum, conflicts_with_all = ["module", "append"])]
    payload: Option<PayloadMode>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UsbDiskModel {
    Bot,
    Uas,
    /// Disable SuperSpeed root ports to exercise the USB2 READY handshake.
    UasUsb2,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PayloadMode {
    /// Verify the Erase members and write nothing.
    Verify,
    /// Verify them from the whole IPSW, read through its ZIP directory.
    VerifyArchive,
    /// Also partition a blank NVMe disk, named by serial, and stage the
    /// members on it.
    Stage,
    /// The same on a virtio disk named by device path and size.
    StagePath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Iommu {
    /// QEMU's `intel-iommu`, without interrupt remapping.
    Intel,
    /// QEMU's `amd-iommu`, without interrupt remapping.
    Amd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Display {
    None,
    /// Show the UART in a host window, Cocoa's on macOS and GTK's elsewhere;
    /// adds no guest display device.
    Window,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum NetworkModel {
    Virtio,
    /// Intel 82574L, PCI ID 8086:10d3.
    E1000e,
    /// Intel 82576, PCI ID 8086:10c9.
    Igb,
}

impl NetworkModel {
    fn device(self) -> &'static str {
        match self {
            Self::Virtio => "virtio-net-pci",
            Self::E1000e => "e1000e",
            Self::Igb => "igb",
        }
    }
}

/// A path inside a QEMU option list, where a comma separates options and a
/// literal comma is written twice (QEMU `docs/system/invocation`), so a
/// directory such as `bundles/Mac14,2` stays one value.
pub(crate) fn option_path(path: &std::path::Path) -> String {
    path.display().to_string().replace(',', ",,")
}

fn parse_storage_serial(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value.len() <= 20
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Ok(value.into())
    } else {
        Err("storage serial must be one to 20 ASCII letters, digits or hyphens".into())
    }
}

/// The NVMe serial of the --usb-storage-disk at `index`, which the mount's
/// `--usb-storage` names.
fn usb_serial(index: usize) -> String {
    format!("STELAUSB{index}")
}

/// Pair each --storage-disk with its serial. Distinct serials keep the
/// guest's `--storage SERIAL:GUID` selection unambiguous.
fn storage_disks(paths: &[PathBuf], serials: &[String]) -> Result<Vec<(PathBuf, String)>> {
    let serials = match (paths.len(), serials.len()) {
        (1, 0) => vec!["STELAANS".to_owned()],
        (disks, named) if disks == named => serials.to_vec(),
        _ => bail!("each --storage-disk needs its own --storage-serial"),
    };
    for (index, serial) in serials.iter().enumerate() {
        ensure!(
            !serials[..index].contains(serial),
            "storage serial {serial} is attached twice"
        );
    }
    for path in paths {
        ensure!(
            path.is_file(),
            "storage disk is not a file: {}",
            path.display()
        );
    }
    Ok(paths.iter().cloned().zip(serials).collect())
}

pub fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Build { release } => {
            println!("{}", build(release)?.display());
            Ok(ExitCode::SUCCESS)
        }
        Command::Run(arguments) => launch(*arguments),
    }
}

pub fn build(release: bool) -> Result<PathBuf> {
    let mut command = cargo();
    command.args(["build", "--locked", "--manifest-path", BOOT_MANIFEST]);
    command.args(["--target", BOOT_TARGET, "--target-dir", BOOT_TARGET_DIR]);
    if release {
        command.arg("--release");
    }
    exec(&mut command)?;
    let profile = if release { "release" } else { "debug" };
    Ok(root()
        .join(BOOT_TARGET_DIR)
        .join(BOOT_TARGET)
        .join(profile)
        .join("stela.efi"))
}

/// The directory of QEMU's bundled firmware, from `qemu -L help`.
fn firmware(qemu: &Path) -> Result<PathBuf> {
    let output = Process::new(qemu).args(["-L", "help"]).output()?;
    String::from_utf8(output.stdout)?
        .lines()
        .map(PathBuf::from)
        .find(|directory| directory.join(FIRMWARE_CODE).exists())
        .with_context(|| format!("QEMU has no {FIRMWARE_CODE}"))
}

/// Version reported by the configured launcher, which may establish its
/// runtime library environment before executing the native QEMU binary.
fn qemu_version(qemu: &Path) -> Result<String> {
    let output = Process::new(qemu).arg("--version").output()?;
    ensure!(output.status.success(), "QEMU --version failed");
    let version = String::from_utf8(output.stdout)?;
    ensure!(
        version.starts_with("QEMU emulator version "),
        "unexpected QEMU version output"
    );
    Ok(version.trim_end().to_owned())
}

/// Kernel-observed image of the launched process. If a custom wrapper forks
/// rather than execs, this identifies the wrapper process, not its child.
#[cfg(target_os = "macos")]
fn process_image(pid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut bytes = vec![0u8; 4096];
    // SAFETY: the buffer is writable for its advertised length; proc_pidpath
    // performs a read-only query on this task's child process.
    let count =
        unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if count <= 0 {
        return None;
    }
    bytes.truncate(bytes.iter().position(|byte| *byte == 0)?);
    Some(std::ffi::OsString::from_vec(bytes).into())
}

#[cfg(target_os = "linux")]
fn process_image(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_image(_pid: u32) -> Option<PathBuf> {
    None
}

fn qemu_cpu(requested: Option<&str>, no_la57: bool, system: bool) -> String {
    let model = requested.unwrap_or(if system {
        "max,vendor=GenuineIntel"
    } else {
        "qemu64"
    });
    if no_la57 {
        format!("{model},la57=off")
    } else {
        model.into()
    }
}

/// QEMU MTTCG runs one host thread per virtual CPU. Instruction counting
/// requires its single-thread engine (QEMU devel/tcg-icount.html).
/// Create a qcow2 `overlay` of raw `base` through QEMU's own monitor, the
/// tool this checkout has.
fn overlay(qemu: &Path, base: &Path, overlay: &Path) -> Result<()> {
    let mut child = Process::new(qemu)
        .args(["-machine", "none", "-nodefaults", "-display", "none"])
        .args(["-monitor", "stdio", "-drive"])
        .arg(format!(
            "if=none,id=base,format=raw,readonly=on,file={}",
            option_path(base)
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    use std::io::Write;
    writeln!(
        child.stdin.take().context("QEMU monitor")?,
        "snapshot_blkdev base {} qcow2\nquit",
        overlay.display()
    )?;
    ensure!(
        child.wait()?.success() && overlay.exists(),
        "create {}",
        overlay.display()
    );
    Ok(())
}

fn qemu_accelerator(icount: Option<u8>, kvm: bool) -> &'static str {
    if kvm {
        "kvm"
    } else if icount.is_some() {
        "tcg,thread=single"
    } else {
        "tcg,thread=multi"
    }
}

fn qemu_machine(keyboard: &str, hpet: bool) -> String {
    let hpet = if hpet { "on" } else { "off" };
    format!("q35,smm=off,sata=off,usb=off,smbus=off,hpet={hpet},i8042={keyboard},vmport=off")
}

fn native_root_preflight(arguments: &Run) -> Result<()> {
    // Clap conflicts can supersede `requires`; enforce the HPET mode before work.
    ensure!(
        !arguments.hpet || arguments.native_mmio_check,
        "--hpet requires the owned --native-mmio-check diagnostic"
    );
    if arguments.native_mmio_check || arguments.native_clock_check {
        ensure!(
            arguments.host_cores == 1
                && arguments.host_threads == 1
                && matches!(arguments.display, Display::None),
            "native root fixture requires one headless BSP"
        );
    }
    Ok(())
}

fn native_mmio_options() -> String {
    format!("{KERNEL_OPTIONS} --native-mmio-check")
}

fn native_clock_options() -> String {
    format!("{KERNEL_OPTIONS} --native-clock-check --native-cores 1")
}

fn launch(arguments: Run) -> Result<ExitCode> {
    // Refuse an incompatible diagnostic topology before building or opening inputs.
    native_root_preflight(&arguments)?;
    let limit = if arguments.usb_image.is_some() || arguments.bundle.is_some() {
        MAX_LONG_TIMEOUT_SECONDS
    } else {
        MAX_TIMEOUT_SECONDS
    };
    ensure!(
        arguments.timeout > 0.0 && arguments.timeout <= limit,
        "timeout must be in (0, {limit}] seconds"
    );
    let attached = storage_disks(&arguments.storage_disk, &arguments.storage_serial)?;
    let image = match &arguments.image {
        Some(image) => image.clone(),
        None => build(true)?,
    };
    let paths = storage::Paths::new(arguments.output.clone());
    if paths.output.exists() {
        bail!("{} already exists", paths.output.display());
    }
    let preboot = arguments
        .preboot_disk
        .as_deref()
        .map(preboot::prepare)
        .transpose()?;
    let (bytes, mut options) = guest(&arguments, preboot.as_ref())?;
    let disks = storage::check_disks(&arguments, &paths, &mut options)?;
    if arguments.input || arguments.usb_input {
        options.push_str(" --input");
    }
    storage::usb_options(&arguments, &mut options)?;
    if arguments.guest_network {
        options.push_str(" --guest-network");
    }
    if arguments.verify_on_read {
        options.push_str(" --verify-on-read");
    }
    let system = options.split_whitespace().next() == Some("--system");
    if arguments.audio_check.is_some()
        || arguments.network_self_check
        || arguments.network_check.is_some()
    {
        ensure!(
            system,
            "host audio/network checks require system mode: use --scenario system-kernel, --bundle or --append starting with --system"
        );
    }
    if let Some(mode) = arguments.audio_check {
        options.push_str(&format!(" --audio-check {}", mode.option()));
    }
    let network = network::Check::start(&arguments, &mut options)?;
    let options = storage::payload(&arguments, &paths, options)?;
    ensure!(
        arguments.host_firmware.is_none() || system,
        "host firmware qualification requires --scenario system-kernel or another --system boot"
    );
    let fat = storage::write_volume(&arguments, &paths, &image, bytes, &options)?;

    let qemu = qemu()?;
    let firmware = firmware(&qemu)?;
    let (variables, format) = machine::variables(&arguments, &qemu, &firmware, &paths.output)?;
    // A USB image carries the boot bundle that `stela setup` wrote.
    let bundle = arguments.bundle.is_some() || preboot.is_some() || arguments.usb_image.is_some();
    // QEMU numbers PCI devices in the order they are given, so the parts
    // attach theirs in a fixed order.
    let mut command = machine::command(
        &arguments, &qemu, &firmware, &variables, format, system, bundle,
    );
    storage::attach_volume(&arguments, &paths, fat.as_deref(), format, &mut command);
    machine::attach_exit(&arguments, &paths.output, &mut command);
    storage::attach_disks(&arguments, &paths, &disks, preboot.as_ref(), &mut command);
    machine::attach_display(&arguments, bundle, &mut command);
    network::attach(&arguments, &paths.output, &mut command)?;
    machine::attach_usb(&arguments, &mut command);
    storage::attach_usb_boot(&arguments, &mut command);
    machine::attach_usb_input(&arguments, &mut command);
    network::attach_usb(&arguments, &paths.output, &mut command)?;
    storage::attach_usb_disks(&arguments, &mut command);
    machine::attach_console(&arguments, &paths.serial, &mut command);
    storage::attach_storage_disks(&attached, &mut command);
    machine::attach_iommu(&arguments, &mut command);
    machine::attach_debugger(&arguments, &mut command);
    let command_line: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let qemu_version = qemu_version(&qemu)?;
    // Keep launch-time input identities: another build can replace these
    // paths while a long restore is still running. Completion must not bind
    // the old run to the replacement's bytes.
    let qemu_binding = binding(&qemu)?;
    let image_binding = binding(&image)?;
    let source_binding = paths
        .source
        .exists()
        .then(|| binding(&paths.source))
        .transpose()?;

    let started = Instant::now();
    let mut child = command
        .stdout(fs::File::create(paths.output.join("stdout.txt"))?)
        .stderr(fs::File::create(paths.output.join("stderr.txt"))?)
        .stdin(if arguments.audio_check.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()?;
    // The local launcher can be a shell wrapper. Observe its running image
    // after exec, keeping the launcher binding and QEMU version separately.
    std::thread::sleep(Duration::from_millis(10));
    let qemu_process_image = process_image(child.id()).and_then(|path| binding(&path).ok());
    // A paused debugging session has no deadline.
    let limit = match arguments.gdb {
        Some(_) => Duration::MAX,
        None => Duration::from_secs_f64(arguments.timeout).saturating_sub(started.elapsed()),
    };
    let waited = if arguments.audio_check.is_some() {
        audio_check::wait_for_stop(&mut child, &paths.serial, limit)
    } else {
        wait(&mut child, limit)
    };
    let status = match waited {
        Ok(status) => status,
        Err(error) => {
            stop(&mut child);
            return Err(error);
        }
    };
    report::finish(
        &arguments,
        report::Outcome {
            paths,
            preboot,
            disks,
            attached,
            network,
            options,
            command_line,
            qemu: qemu_binding,
            qemu_version,
            qemu_process_image,
            image: image_binding,
            source: source_binding,
            started,
            status,
        },
    )
}

impl Run {
    /// A native host fixture: the mount runs a host check, not a guest.
    fn host_check(&self) -> bool {
        self.native_dma_check
            || self.native_dma_isolation_check
            || self.native_work_check
            || self.native_irq_work_check
    }

    /// Install mode, the storage check and the host checks run no guest.
    fn guestless(&self) -> bool {
        self.host_check() || self.payload.is_some() || self.storage_check
    }
}

/// What the mount boots and its options: the system-mode guest image
/// `source.bin` holds (none for a bundle, a Preboot disk or a run without a
/// guest) and `stela.cfg`'s first options.
fn guest(arguments: &Run, preboot: Option<&preboot::Preboot>) -> Result<(Vec<u8>, String)> {
    let append = arguments.append.clone();
    let (bytes, mut options) = match (&arguments.module, arguments.scenario) {
        _ if arguments.native_mmio_check => (kernel()?, native_mmio_options()),
        _ if arguments.native_clock_check => (kernel()?, native_clock_options()),
        _ if preboot.is_some() => (Vec::new(), preboot.unwrap().options()),
        _ if arguments.bundle.is_some() => {
            (Vec::new(), append.unwrap_or_else(|| BUNDLE_OPTIONS.into()))
        }
        _ if arguments.guestless() => (Vec::new(), append.unwrap_or_default()),
        (Some(module), _) => (
            fs::read(module)?,
            append.unwrap_or_else(|| KERNEL_OPTIONS.into()),
        ),
        (None, Scenario::SystemKernel) => {
            (kernel()?, append.unwrap_or_else(|| KERNEL_OPTIONS.into()))
        }
    };
    if arguments.host_check() {
        ensure!(
            matches!(arguments.display, Display::None),
            "native fixture uses a headless single-BSP topology"
        );
        let mode = if arguments.native_irq_work_check {
            "--native-irq-work-check"
        } else if arguments.native_work_check {
            "--native-work-check"
        } else if arguments.native_dma_isolation_check {
            "--native-dma-isolation-check"
        } else {
            "--native-dma-check"
        };
        options = format!("--host-check {mode} --deadline 5 --key-seconds 1");
    }
    Ok((bytes, options))
}

/// The first printed requirement, including the diagnostics of operations
/// answered degraded. Buffered diagnostics are not a causal clock.
fn first_unsupported(serial: &str) -> Option<&str> {
    serial.lines().find_map(|line| {
        line.strip_prefix("UNMODELED ")
            .or_else(|| line.strip_prefix("STOP UNSUPPORTED "))
    })
}

/// The immediate guest console's first panic, before any nested panic or
/// subsequent machine reset. Ordinary messages about panic support do not match.
fn first_guest_panic(serial: &str) -> Option<&str> {
    serial.lines().find_map(|line| {
        let message = line.strip_prefix("GUEST|")?.trim_start();
        (message.starts_with("panic(") || message.starts_with("panic:")).then_some(message)
    })
}

/// Copy `bundle.json` and every file it lists.
fn copy_bundle(from: &Path, to: &Path) -> Result<()> {
    let manifest = fs::read(from.join("bundle.json"))
        .with_context(|| format!("{} has no bundle.json", from.display()))?;
    let value: Value = serde_json::from_slice(&manifest)?;
    fs::create_dir_all(to)?;
    fs::write(to.join("bundle.json"), &manifest)?;
    for file in value["files"]
        .as_array()
        .context("bundle.json lists no files")?
    {
        let name = file["name"]
            .as_str()
            .context("bundle file without a name")?;
        ensure!(
            !name.contains(['/', '\\']),
            "bundle file {name} names a directory"
        );
        fs::copy(from.join(name), to.join(name))?;
    }
    Ok(())
}

/// QEMU's exit status when the engine reports a terminal idle state.
const IDLE_EXIT: u8 = (0x10 << 1) | 1;
const FAILED_EXIT: u8 = 1;

/// Check the test kernel's results in the serial log.
fn verify_kernel(serial: &str) -> Result<(), String> {
    if !serial.contains("STOP idle") {
        return Err("the engine did not reach the kernel's final idle state".into());
    }
    if !serial.contains(KERNEL_BANNER) {
        return Err("the kernel's UART banner did not reach the console".into());
    }
    let mut registers = [0u64; 32];
    for line in serial.lines() {
        let Some(rest) = line.strip_prefix('X') else {
            continue;
        };
        let Some((first, values)) = rest.split_once(':') else {
            continue;
        };
        let Ok(first) = first.parse::<usize>() else {
            continue;
        };
        for (offset, value) in values.split_whitespace().enumerate() {
            let value = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                .map_err(|_| format!("bad register value {value}"))?;
            if let Some(slot) = registers.get_mut(first + offset) {
                *slot = value;
            }
        }
    }
    for (index, expected) in KERNEL_RESULTS {
        let actual = registers[index];
        let good = match expected {
            Some(value) => actual == value,
            None => actual != 0,
        };
        if !good {
            return Err(format!(
                "X{index} = {actual:#x}, expected {}",
                expected.map_or("nonzero".into(), |value| format!("{value:#x}"))
            ));
        }
    }
    Ok(())
}

/// A byte range of a host disk image.
struct Range {
    file: fs::File,
    start: u64,
    bytes: u64,
}

impl ReadAt for Range {
    type Error = std::io::Error;
    fn len(&self) -> u64 {
        self.bytes
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        self.file.seek(SeekFrom::Start(self.start + offset))?;
        self.file.read_exact(buffer)
    }
}

/// Read a staging run's target disk back: its GPT, and every staged member
/// checked against the staging header's SHA-256.
fn staged(target: &Path) -> Result<Value> {
    let disk = gpt::Disk {
        block_bytes: 512,
        blocks: fs::metadata(target)?.len() / 512,
    };
    let mut whole = Range {
        file: fs::File::open(target)?,
        start: 0,
        bytes: disk.blocks * 512,
    };
    let mut header = vec![0u8; 512];
    whole.read_at(512, &mut header)?;
    let error = |e: PayloadError| anyhow::anyhow!("{e}");
    let Some(info) = gpt::parse_header(disk, 1, &header).map_err(error)? else {
        return Ok(json!({"gpt": false}));
    };
    let mut entries = vec![0u8; info.entry_array_bytes() as usize];
    whole.read_at(info.entries_lba * 512, &mut entries)?;
    let table = gpt::parse_entries(&info, &entries).map_err(error)?;
    let partitions: Vec<Value> = table
        .partitions
        .iter()
        .map(|p| {
            json!({"role": format!("{:?}", p.role()), "first_lba": p.first_lba,
            "last_lba": p.last_lba, "guid": p.unique_guid.to_string()})
        })
        .collect();
    let staging = table
        .partitions
        .iter()
        .find(|p| p.role() == Some(gpt::Role::Staging))
        .context("no staging partition")?;
    let mut source = StagedSource::open(Range {
        file: fs::File::open(target)?,
        start: staging.first_lba * 512,
        bytes: staging.blocks() * 512,
    })
    .map_err(error)?;
    let members = source.manifest().members.clone();
    let mut buffer = vec![0u8; 1 << 20];
    for member in &members {
        copy_verified(&mut source, member, &mut buffer, |_| Ok::<(), ()>(()))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(json!({
        "gpt": true,
        "disk_guid": table.disk_guid.to_string(),
        "partitions": partitions,
        "members_verified": members.iter().map(|m| &m.name).collect::<Vec<_>>(),
    }))
}

fn directory_bytes(path: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        total += match entry.file_type()?.is_dir() {
            true => directory_bytes(&entry.path())?,
            false => entry.metadata()?.len(),
        };
    }
    Ok(total)
}

/// A raw FAT32 image of `volume`, without a partition table, which the
/// firmware mounts whole.
fn fat_image(volume: &Path, output: &Path) -> Result<PathBuf> {
    let bytes = directory_bytes(volume)?;
    let size = (bytes + bytes / 8 + (64 << 20)).next_multiple_of(1 << 20);
    let image = output.join("volume.img");
    fat32::write(volume, &image, size, "STELA")?;
    Ok(image)
}

fn native_irq_work_verified(serial: &str) -> bool {
    serial.lines().any(|line| {
        line.starts_with("CHECK native-irq-work PASS ")
            && [
                "roundtrip=verified",
                "teardown=IOTLB+TE-off-ack",
                "actual_cause=0x1",
                "IRQ_depth=real",
                "interrupted_SP=owned-foreground",
                "ISR_SP=separate-IST",
                "current_id=IRQ-refused",
                "enqueue=owned/noninline",
                "worker=owned-distinct-context",
                "async_FXSAVE=unchanged",
                "heap=aligned-zeroed-read-write-reclaimed",
                "heap_IF=off/on-preserved",
                "mask+hardware+IRR/ISR+inflight+work=drained",
                "late_delivery=absent",
                "stack_leases=4-released",
                "BSP_device_owner=!Send",
            ]
            .iter()
            .all(|s| line.contains(s))
    }) && !serial
        .lines()
        .any(|line| line.starts_with("CHECK native-irq-work FAIL "))
}

fn native_work_verified(serial: &str) -> bool {
    serial.lines().any(|line| {
        line.starts_with("CHECK native-work PASS ")
            && [
                "foreground=owned-stack",
                "ids=distinct/stable",
                "execute=deferred",
                "Notify=FIFO",
                "general=yield/resume",
                "Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified",
                "MXCSR+x87=preserved",
                "IF=off/on/clear-yield/exact",
                "guards=8-absent",
                "RW+NX+WB=verified",
                "idle_stack_leases=4-released",
                "pending_runtime+stacks=quarantined",
                "overflow+close=refused",
                "drain_cycles=refused",
                "source_IRQ_enqueue=not-qualified",
            ]
            .iter()
            .all(|marker| line.contains(marker))
    }) && !serial
        .lines()
        .any(|line| line.starts_with("CHECK native-work FAIL "))
}

/// Preserve the existing bounded fixture's raw observation, after quiet retire.
fn native_clock_proof(serial: &str) -> Option<&str> {
    if serial
        .lines()
        .any(|line| line.starts_with("CHECK native-clock FAIL"))
    {
        return None;
    }
    let mut proofs = serial
        .lines()
        .filter(|line| line.starts_with("CHECK native-clock PASS "));
    let line = proofs.next()?;
    if proofs.next().is_some() {
        return None;
    }
    let observation = line
        .split_once(" source=Observation { ")?
        .1
        .strip_suffix(" }; authored UP fixture, original Linux and hardware unqualified")?;
    let (digest, rest) = observation
        .strip_prefix("fadt_sha256: [")?
        .split_once("], ")?;
    let digest = digest.split(", ").collect::<Vec<_>>();
    if digest.len() != 32 || digest.iter().any(|byte| byte.parse::<u8>().is_err()) {
        return None;
    }
    // Validate the actual Debug record's framing/types, not source capability.
    let observation_fields = [
        ("pm_port: ", u64::from(u16::MAX)),
        ("pm_mask: ", u64::from(u32::MAX)),
        ("pm_hz: ", u64::MAX),
        ("apic_hz: ", u64::MAX),
        ("cpu: ", u64::from(u32::MAX)),
        ("root: ", u64::MAX),
        ("idt: ", u64::MAX),
        ("gs: ", u64::MAX),
        ("max_cpuid: ", u64::from(u32::MAX)),
        ("thermal_eax: ", u64::from(u32::MAX)),
    ];
    let observed = rest.split(", ").collect::<Vec<_>>();
    if observed.len() != observation_fields.len()
        || !observed
            .iter()
            .zip(observation_fields)
            .all(|(field, (key, max))| {
                field
                    .strip_prefix(key)
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|v| v <= max)
            })
    {
        return None;
    }
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    let value = |key: &str| {
        let mut matches = fields.iter().filter_map(|field| field.strip_prefix(key));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    };
    (value("busy_jiffies=")
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|v| v >= 8)
        && value("idle_waits=")
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 0)
        && value("guest_mux=") == Some("elapsed")
        && value("detach=") == Some("quiet")
        && value("source=") == Some("Observation"))
    .then_some(line)
}

/// The existing diagnostic owns its exact mapping and refusal observations.
/// Its early stop does not claim that a guest system kernel completed.
fn native_mmio_verified(serial: &str) -> bool {
    native_mmio_observation(serial).is_some()
}

fn native_stack_observation(serial: &str) -> Option<&str> {
    let mut lines = serial
        .lines()
        .filter(|line| line.starts_with("CHECK native-stack "));
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let pair = line
        .strip_prefix("CHECK native-stack finite=4 actual_rsp=")?
        .strip_suffix(" source=retired parent=clear+TLB; no Linux owner or CPU-time grant")?;
    let (first, second) = pair.split_once(',')?;
    let address = |text: &str| u64::from_str_radix(text.strip_prefix("0x")?, 16).ok();
    let (first, second) = (address(first)?, address(second)?);
    (first != 0 && second != 0 && first != second).then_some(line)
}

fn native_mmio_observation(serial: &str) -> Option<&str> {
    if serial
        .lines()
        .any(|line| line.starts_with("CHECK native-mmio FAIL"))
    {
        return None;
    }
    let mut proofs = serial
        .lines()
        .filter(|line| line.starts_with("CHECK native-mmio PASS "));
    let line = proofs.next()?;
    if proofs.next().is_some() {
        return None;
    }
    if !line.ends_with("; bounded authored diagnostic, Linux and physical hardware unqualified") {
        return None;
    }
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    let value = |key: &str| {
        let mut values = fields.iter().filter_map(|field| field.strip_prefix(key));
        let first = values.next()?;
        values.next().is_none().then_some(first)
    };
    let hex = |key| {
        value(key)
            .and_then(|text| text.trim_end_matches(';').strip_prefix("0x"))
            .and_then(|text| u64::from_str_radix(text, 16).ok())
    };
    let bus = |text: &str| {
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u8>().ok())
            .flatten()
    };
    let buses = value("buses=")
        .and_then(|text| text.split_once("..="))
        .and_then(|(start, end)| Some((bus(start)?, bus(end)?)))
        .is_some_and(|(start, end)| start <= end);
    ([
        ("authority=", "actual"),
        ("roots=", "all"),
        ("native_cpus=", "1"),
        ("effective_cache=", "Intel-UC"),
        ("aperture=", "owned-PTE"),
        ("map=", "published"),
        ("retire=", "actual-clear+TLB"),
        ("reuse=", "readback"),
        ("foreign-root=", "refused"),
        ("WC=", "refused"),
        ("clock=", "HPET64"),
        ("retained_hpet=", "1"),
        ("root_lifetime=", "kernel-image"),
    ]
    .iter()
    .all(|(key, expected)| value(key) == Some(*expected))
        && value("ioapics=")
            .and_then(|text| text.parse::<usize>().ok())
            .is_some_and(|count| count > 0)
        && hex("MCFG=").is_some()
        && hex("vendor=").is_some_and(|vendor| vendor > 0 && vendor < u64::from(u32::MAX))
        && buses
        && native_stack_observation(serial).is_some())
    .then_some(line)
}

/// Old single-requester output never qualifies the two-context fixture.
fn native_isolation_verified(serial: &str) -> bool {
    serial.lines().any(|line| {
        let reason = line
            .split("wrong_domain_reason=0x")
            .nth(1)
            .and_then(|v| v.split_ascii_whitespace().next())
            .and_then(|v| u8::from_str_radix(v, 16).ok());
        line.starts_with("CHECK native-dma-isolation PASS ")
            && reason.is_some_and(|v| v != 0)
            && [
                "rid_a=0x0010 did_a=1 rid_b=0x0018 did_b=2",
                "same_iova=disjoint-ram",
                "roundtrip_a=verified",
                "roundtrip_b=verified",
                "wrong_domain_rid=0x0018",
                "wrong_domain_address=0x3000",
                "wrong_domain_reason=0x",
                "retained_ram=unchanged",
                "owner_access=verified",
                "other_context_after_detach=verified",
                "teardown=context+IOTLB+TE-off-ack",
            ]
            .iter()
            .all(|marker| line.contains(marker))
    }) && !serial.lines().any(|line| {
        line.starts_with("CHECK native-dma FAIL ")
            || line.starts_with("CHECK native-dma-isolation FAIL ")
    })
}

/// An older MSI-only EFI cannot satisfy the extended level-IRQ fixture.
fn native_level_verified(serial: &str) -> bool {
    serial.lines().any(|line| {
        line.starts_with("CHECK native-irq PASS ")
            && line.split_whitespace().any(|field| {
                [
                    "DSDT=ed48c9772aee854066c14b36ce8f787bb69d279afa15dea729b8ba2f9b77256d",
                    "DSDT=dfe8afc13a175262e7bf69710bf7738c11d22051998d20d820685f373e31cf80",
                ]
                .contains(&field)
            })
            && [
                "INTx gsi=22 high+shared+level",
                "first=2 second=1",
                "hold→EOI→retrigger=verified",
                "RemoteIRR=observed/drained",
                "group_refs=released",
                "late_delivery=absent",
            ]
            .iter()
            .all(|marker| line.contains(marker))
    }) && !serial.lines().any(|line| {
        line.starts_with("CHECK native-irq FAIL ") || line.starts_with("CHECK native-dma FAIL ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_clock_requires_unique_progress_and_quiet_retirement_proof() {
        let full = "CHECK native-clock PASS busy_jiffies=8 idle_waits=1 guest_mux=elapsed detach=quiet source=Observation { fadt_sha256: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], pm_port: 0, pm_mask: 0, pm_hz: 0, apic_hz: 0, cpu: 0, root: 0, idt: 0, gs: 0, max_cpuid: 0, thermal_eax: 0 }; authored UP fixture, original Linux and hardware unqualified";
        assert_eq!(native_clock_proof(full), Some(full));
        for (field, replacement) in [
            ("busy_jiffies=8", "busy_jiffies=7"),
            ("busy_jiffies=8", "busy_jiffies=18446744073709551616"),
            ("idle_waits=1", "idle_waits=0"),
            ("idle_waits=1", "idle_waits=invalid"),
            ("guest_mux=elapsed", "guest_mux=pending"),
            ("detach=quiet", "detach=active"),
            ("source=Observation", "source=unobserved"),
        ] {
            assert!(native_clock_proof(&full.replace(field, replacement)).is_none());
        }
        for extra in [
            "busy_jiffies=8",
            "idle_waits=1",
            "guest_mux=elapsed",
            "detach=quiet",
            "source=Observation",
        ] {
            assert!(native_clock_proof(&format!("{full} {extra}")).is_none());
        }
        assert!(native_clock_proof(&format!("{full}\n{full}")).is_none());
        assert!(native_clock_proof(&format!("{full}\nCHECK native-clock FAIL retire")).is_none());
        assert!(native_clock_proof("CHECK native-mmio PASS roots=all").is_none());
        assert!(native_clock_proof(full.split_once(" source=").unwrap().0).is_none());
        assert!(
            native_clock_proof(&format!(
                "{} source=Observation",
                full.split_once(" source=").unwrap().0
            ))
            .is_none()
        );
        assert!(native_clock_proof(full.split_once("; authored").unwrap().0).is_none());
        assert!(native_clock_proof(&full.replace("thermal_eax: 0", "thermal_eax:")).is_none());
        assert!(native_clock_proof(&full.replace("pm_port: 0", "pm_port: 65536")).is_none());
    }

    #[test]
    fn native_clock_emits_only_system_options_and_refuses_shared_topologies() {
        use clap::Parser;
        let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-clock"];
        let parse = |options: Vec<&str>| {
            let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain(options))?;
            let crate::Task::Boot(Command::Run(run)) = parsed.task else {
                panic!("boot run")
            };
            Ok::<_, clap::Error>(run)
        };
        let run = parse(vec!["--native-clock-check"]).unwrap();
        assert!(run.native_clock_check);
        assert!(native_root_preflight(&run).is_ok());
        assert_eq!(
            native_clock_options(),
            format!("{KERNEL_OPTIONS} --native-clock-check --native-cores 1")
        );
        for conflict in [
            "--native-mmio-check",
            "--native-dma-check",
            "--native-dma-isolation-check",
            "--native-work-check",
            "--native-irq-work-check",
            "--network",
            "--storage-check",
            "--input",
            "--audio-check",
        ] {
            assert!(parse(vec!["--native-clock-check", conflict]).is_err());
            assert!(parse(vec![conflict, "--native-clock-check"]).is_err());
        }
        for (option, value) in [("--gdb", "1234"), ("--monitor", "1234"), ("--icount", "0")] {
            assert!(parse(vec!["--native-clock-check", option, value]).is_err());
        }
        for (option, value) in [
            ("--host-cores", "2"),
            ("--host-threads", "2"),
            ("--display", "window"),
        ] {
            assert!(
                native_root_preflight(&parse(vec!["--native-clock-check", option, value]).unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn native_mmio_requires_complete_actual_mapping_and_refusal_proof() {
        let stack = "CHECK native-stack finite=4 actual_rsp=0x9000,0xa000 source=retired parent=clear+TLB; no Linux owner or CPU-time grant";
        let mmio = "CHECK native-mmio PASS authority=actual roots=all native_cpus=1 effective_cache=Intel-UC aperture=owned-PTE map=published retire=actual-clear+TLB reuse=readback foreign-root=refused WC=refused clock=HPET64 retained_hpet=1 root_lifetime=kernel-image ioapics=1 MCFG=0xb0000000 buses=0..=0 vendor=0x12378086; bounded authored diagnostic, Linux and physical hardware unqualified";
        let full = format!("{stack}\n{mmio}");
        assert!(native_mmio_verified(&full));
        assert_eq!(native_mmio_observation(&full), Some(mmio));
        assert_eq!(native_stack_observation(&full), Some(stack));
        for field in [
            "authority=actual",
            "roots=all",
            "native_cpus=1",
            "effective_cache=Intel-UC",
            "aperture=owned-PTE",
            "map=published",
            "retire=actual-clear+TLB",
            "reuse=readback",
            "foreign-root=refused",
            "WC=refused",
            "clock=HPET64",
            "retained_hpet=1",
            "root_lifetime=kernel-image",
            "buses=0..=0",
            "source=retired",
            "parent=clear+TLB",
        ] {
            assert!(
                !native_mmio_verified(&full.replace(field, "unproven")),
                "{field}"
            );
        }
        for replacement in ["ioapics=0", "ioapics=invalid"] {
            assert!(!native_mmio_verified(
                &full.replace("ioapics=1", replacement)
            ));
        }
        for replacement in ["vendor=0x0;", "vendor=0xffffffff;", "vendor=invalid;"] {
            assert!(!native_mmio_verified(
                &full.replace("vendor=0x12378086;", replacement)
            ));
        }
        assert!(!native_mmio_verified("CHECK native-dma PASS old image"));
        assert!(!native_mmio_verified(&format!(
            "{full}\nCHECK native-mmio FAIL cleanup"
        )));
        assert!(!native_mmio_verified(&format!("{full}\n{full}")));
        assert!(!native_mmio_verified(mmio));
        assert!(!native_mmio_verified(stack));
        assert!(!native_mmio_verified(&format!("{full}\n{stack}")));
        assert!(!native_mmio_verified(
            &full.replace("clock=HPET64", "clock=HPET64 clock=PM24")
        ));
        assert!(!native_mmio_verified(&full.replace(
            "kernel-image ioapics",
            "kernel-image retained_hpet=0 ioapics"
        )));
        for pair in [
            "0x0,0xa000",
            "0x9000,0x0",
            "0x9000,0x9000",
            "9000,0xa000",
            "0x10000000000000000,0xa000",
            "0x9000,0xa000,0xb000",
        ] {
            assert!(
                !native_mmio_verified(&full.replace("0x9000,0xa000", pair)),
                "{pair}"
            );
        }
        for suffix in [
            "; no Linux owner or CPU-time grant",
            "; bounded authored diagnostic, Linux and physical hardware unqualified",
        ] {
            assert!(!native_mmio_verified(&full.replace(suffix, "")));
        }
        assert!(!native_mmio_verified("CHECK native-mmio FAIL MissingSdt"));
        assert!(!native_mmio_verified(&full.replace("buses=0..=0", "")));
        for range in [
            "1..=0",
            "0..=256",
            "-1..=0",
            "+0..=0",
            "0x0..=0",
            "0..0",
            "0..=",
            "0..=0..=0",
        ] {
            assert!(
                !native_mmio_verified(&full.replace("buses=0..=0", &format!("buses={range}"))),
                "{range}"
            );
        }
        assert!(!native_mmio_verified(
            &full.replace("buses=0..=0", "buses=0..=0 buses=1..=1")
        ));
        assert!(native_mmio_verified(
            &full.replace("buses=0..=0", "buses=1..=255")
        ));
    }

    #[test]
    fn native_mmio_hpet_is_explicit_and_restricted_before_work() {
        use clap::Parser;
        let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-mmio-hpet"];
        let parse = |options: Vec<&str>| {
            let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain(options))?;
            let crate::Task::Boot(Command::Run(run)) = parsed.task else {
                panic!("boot run")
            };
            Ok::<_, clap::Error>(run)
        };
        let default = parse(vec!["--native-mmio-check"]).unwrap();
        assert!(!default.hpet);
        let enabled = parse(vec!["--native-mmio-check", "--hpet"]).unwrap();
        assert!(enabled.hpet);
        assert!(native_root_preflight(&enabled).is_ok());
        assert!(parse(vec!["--hpet"]).is_err());
        for options in [
            vec!["--native-clock-check", "--hpet"],
            vec!["--network", "--hpet"],
            vec!["--module", "not-opened-by-preflight", "--hpet"],
        ] {
            let invalid = parse(options).unwrap();
            assert!(invalid.hpet && !invalid.native_mmio_check);
            assert!(native_root_preflight(&invalid).is_err());
        }
        assert!(
            native_root_preflight(
                &parse(vec!["--native-mmio-check", "--hpet", "--host-cores", "2"]).unwrap()
            )
            .is_err()
        );
        let off = qemu_machine("off", false);
        assert_eq!(
            off,
            "q35,smm=off,sata=off,usb=off,smbus=off,hpet=off,i8042=off,vmport=off"
        );
        assert_eq!(
            qemu_machine("off", true),
            off.replace("hpet=off", "hpet=on")
        );
        assert_eq!(
            qemu_machine("on", false),
            off.replace("i8042=off", "i8042=on")
        );
    }

    #[test]
    fn native_mmio_emits_system_options_without_host_check_only_keys() {
        let options = native_mmio_options();
        let words = options.split_ascii_whitespace().collect::<Vec<_>>();
        assert_eq!(words.first(), Some(&"--system"));
        assert_eq!(
            words
                .iter()
                .filter(|word| **word == "--native-mmio-check")
                .count(),
            1
        );
        assert!(options.starts_with(KERNEL_OPTIONS));
        for forbidden in ["--host-check", "--deadline", "--key-seconds"] {
            assert!(!words.contains(&forbidden));
        }
    }

    #[test]
    fn native_mmio_refuses_conflicting_cli_and_topology_before_work() {
        use clap::Parser;
        let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-mmio"];
        let parse = |options: Vec<&str>| {
            let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain(options))?;
            let crate::Task::Boot(Command::Run(run)) = parsed.task else {
                panic!("boot run")
            };
            Ok::<_, clap::Error>(run)
        };
        let run = parse(vec!["--native-mmio-check"]).unwrap();
        assert!(run.native_mmio_check);
        assert!(native_root_preflight(&run).is_ok());
        for conflict in [
            "--native-dma-check",
            "--native-dma-isolation-check",
            "--native-work-check",
            "--native-irq-work-check",
            "--storage-check",
            "--network",
            "--input",
            "--audio-check",
        ] {
            assert!(parse(vec!["--native-mmio-check", conflict]).is_err());
            assert!(parse(vec![conflict, "--native-mmio-check"]).is_err());
        }
        for (option, value) in [("--gdb", "1234"), ("--monitor", "1234"), ("--icount", "0")] {
            assert!(parse(vec!["--native-mmio-check", option, value]).is_err());
            assert!(parse(vec![option, value, "--native-mmio-check"]).is_err());
        }
        for (option, value) in [
            ("--host-cores", "2"),
            ("--host-threads", "2"),
            ("--display", "window"),
        ] {
            let run = parse(vec!["--native-mmio-check", option, value]).unwrap();
            assert!(native_root_preflight(&run).is_err());
        }
    }

    #[test]
    fn actual_parallel_cpu_execution_is_default_and_icount_keeps_its_required_mode() {
        assert_eq!(qemu_accelerator(None, false), "tcg,thread=multi");
        for shift in 0..=10 {
            assert_eq!(qemu_accelerator(Some(shift), false), "tcg,thread=single");
        }
        assert_eq!(qemu_accelerator(None, true), "kvm");
    }

    #[test]
    fn cpu_selection_records_an_explicit_model_and_keeps_baseline_overrides() {
        assert_eq!(qemu_cpu(None, false, true), "max,vendor=GenuineIntel");
        assert_eq!(qemu_cpu(None, false, false), "qemu64");
        assert_eq!(qemu_cpu(Some("Nehalem"), true, true), "Nehalem,la57=off");
        assert_eq!(
            qemu_cpu(Some("max,vendor=AuthenticAMD"), false, true),
            "max,vendor=AuthenticAMD"
        );
    }

    #[test]
    fn run_report_keeps_degraded_requirements_and_the_first_guest_panic() {
        let serial = concat!(
            "GUEST| panic handlers ready\r\n",
            "UNMODELED pc=0x1000 device write at PA 0x2000: missing lifecycle\r\n",
            "GUEST| panic(cpu 0 caller 0x3000): first failure\r\n",
            "UNMODELED pc=0x4000 debug sample: PE is off\r\n",
            "GUEST| panic: nested failure\r\n",
            "STOP UNSUPPORTED a later terminal requirement\r\n",
            "STOP reset: amcc: DRAM access disabled\r\n",
        );
        assert_eq!(
            first_unsupported(serial),
            Some("pc=0x1000 device write at PA 0x2000: missing lifecycle")
        );
        assert_eq!(
            first_guest_panic(serial),
            Some("panic(cpu 0 caller 0x3000): first failure")
        );
        assert_eq!(
            first_unsupported("STOP UNSUPPORTED pc=0x1000 instruction\n"),
            Some("pc=0x1000 instruction")
        );
        assert_eq!(
            first_guest_panic("GUEST| panic: first failure\n"),
            Some("panic: first failure")
        );
        for ordinary in [
            "GUEST| UNMODELED guest text\n",
            "GUEST| panic flow initialized\n",
            "STOP reset: ordinary restart\n",
        ] {
            assert_eq!(first_unsupported(ordinary), None);
            assert_eq!(first_guest_panic(ordinary), None);
        }
    }

    #[test]
    fn native_fixture_does_not_hide_a_real_guest_panic() {
        assert_eq!(
            first_guest_panic("CHECK native-dma PASS traffic\nGUEST| panic(cpu 0): failed\n"),
            Some("panic(cpu 0): failed")
        );
        assert_eq!(
            first_guest_panic("GUEST| panic handlers ready\nGUEST| panic flow initialized\n"),
            None
        );
    }

    #[test]
    fn isolation_fixture_requires_both_requesters_and_matched_fault() {
        use clap::Parser;
        let args = [
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/isolation",
            "--native-dma-isolation-check",
        ];
        assert!(crate::Cli::try_parse_from(args).is_ok());
        for conflict in ["--native-dma-check", "--network", "--storage-check"] {
            let mut bad = args.to_vec();
            bad.push(conflict);
            assert!(crate::Cli::try_parse_from(bad).is_err());
        }
        assert!(!native_isolation_verified(
            "CHECK native-dma PASS single EDU roundtrip=verified"
        ));
        let full = "CHECK native-dma-isolation PASS rid_a=0x0010 did_a=1 rid_b=0x0018 did_b=2 same_iova=disjoint-ram roundtrip_a=verified roundtrip_b=verified wrong_domain_rid=0x0018 wrong_domain_address=0x3000 wrong_domain_reason=0x6 retained_ram=unchanged owner_access=verified other_context_after_detach=verified teardown=context+IOTLB+TE-off-ack";
        assert!(native_isolation_verified(full));
        assert!(!native_isolation_verified(
            &full.replace("wrong_domain_reason=0x6", "wrong_domain_reason=0x0")
        ));
        for marker in [
            "wrong_domain_rid=0x0018",
            "retained_ram=unchanged",
            "other_context_after_detach=verified",
            "teardown=context+IOTLB+TE-off-ack",
        ] {
            assert!(!native_isolation_verified(
                &full.replace(marker, "unproven")
            ));
        }
        assert!(!native_isolation_verified(&format!(
            "{full}\nCHECK native-dma FAIL uncertain"
        )));
    }

    #[test]
    fn extended_irq_fixture_never_relabels_msi_only_or_partial_evidence() {
        let old = "CHECK native-irq PASS EDU vector=0x50 actual_cause=0x1 device_ACK+EOI=verified late_delivery=absent";
        assert!(!native_level_verified(old));
        let full = format!(
            "{old}; INTx gsi=22 high+shared+level first=2 second=1 hold→EOI→retrigger=verified RemoteIRR=observed/drained group_refs=released DSDT=ed48c9772aee854066c14b36ce8f787bb69d279afa15dea729b8ba2f9b77256d"
        );
        assert!(native_level_verified(&full));
        let intel = full.replace(
            "ed48c9772aee854066c14b36ce8f787bb69d279afa15dea729b8ba2f9b77256d",
            "dfe8afc13a175262e7bf69710bf7738c11d22051998d20d820685f373e31cf80",
        );
        assert!(native_level_verified(&intel));
        assert!(!native_level_verified(&format!("{intel}0")));
        assert!(!native_level_verified(&intel.replace("DSDT=df", "DSDT=00")));
        assert!(!native_level_verified(
            &full.replace("RemoteIRR=observed/drained", "RemoteIRR=unknown")
        ));
        assert!(!native_level_verified(&format!(
            "{full}\nCHECK native-dma FAIL stop uncertain"
        )));
    }

    #[test]
    fn qemu_host_inventory_does_not_synthesize_a_native_worker_grant() {
        use clap::Parser;
        let prefix = ["xtask", "boot", "run", "--output", "/tmp/owned-cores"];
        let parsed =
            crate::Cli::try_parse_from(prefix.into_iter().chain(["--host-cores", "2"])).unwrap();
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        assert_eq!(run.host_cores, 2);
        assert_eq!(run.host_threads, 1);
        assert!(run.append.is_none());
        let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain([
            "--host-cores",
            "8",
            "--host-threads",
            "2",
        ]))
        .unwrap();
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        assert_eq!((run.host_cores, run.host_threads), (8, 2));
        assert!(run.append.is_none());
        assert!(
            crate::Cli::try_parse_from(prefix.into_iter().chain(["--host-threads", "0",])).is_err()
        );
        for invalid in ["0", "65", "-1", "two"] {
            assert!(
                crate::Cli::try_parse_from(prefix.into_iter().chain(["--host-cores", invalid]))
                    .is_err()
            );
        }
    }

    #[test]
    fn native_irq_work_requires_actual_irq_and_async_state_proof_exclusively() {
        use clap::Parser;
        let full = "CHECK native-irq-work PASS roundtrip=verified teardown=IOTLB+TE-off-ack actual_cause=0x1 IRQ_depth=real interrupted_SP=owned-foreground ISR_SP=separate-IST current_id=IRQ-refused enqueue=owned/noninline worker=owned-distinct-context async_FXSAVE=unchanged heap=aligned-zeroed-read-write-reclaimed heap_IF=off/on-preserved mask+hardware+IRR/ISR+inflight+work=drained late_delivery=absent stack_leases=4-released BSP_device_owner=!Send";
        assert!(native_irq_work_verified(full));
        for marker in [
            "IRQ_depth=real",
            "interrupted_SP=owned-foreground",
            "current_id=IRQ-refused",
            "worker=owned-distinct-context",
            "async_FXSAVE=unchanged",
            "heap=aligned-zeroed-read-write-reclaimed",
            "heap_IF=off/on-preserved",
            "mask+hardware+IRR/ISR+inflight+work=drained",
            "BSP_device_owner=!Send",
        ] {
            assert!(!native_irq_work_verified(&full.replace(marker, "unproven")));
        }
        assert!(!native_irq_work_verified(
            "CHECK native-work PASS source_IRQ_enqueue=not-qualified"
        ));
        assert!(!native_irq_work_verified(
            "CHECK native-irq PASS actual_cause=0x1"
        ));
        assert!(!native_irq_work_verified(&format!(
            "{full}\nCHECK native-irq-work FAIL uncertain owner"
        )));
        let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-irq-work"];
        let parsed =
            crate::Cli::try_parse_from(prefix.into_iter().chain(["--native-irq-work-check"]))
                .unwrap();
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        assert!(run.native_irq_work_check);
        for conflict in [
            "--native-dma-check",
            "--native-dma-isolation-check",
            "--native-work-check",
            "--audio-check",
            "--network",
            "--storage-check",
        ] {
            for pair in [
                ["--native-irq-work-check", conflict],
                [conflict, "--native-irq-work-check"],
            ] {
                assert!(crate::Cli::try_parse_from(prefix.into_iter().chain(pair)).is_err());
            }
        }
    }

    #[test]
    fn native_work_requires_its_complete_fresh_proof_and_exclusive_cli() {
        use clap::Parser;
        let full = "CHECK native-work PASS foreground=owned-stack ids=distinct/stable execute=deferred Notify=FIFO general=yield/resume Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified MXCSR+x87=preserved IF=off/on/clear-yield/exact guards=8-absent RW+NX+WB=verified idle_stack_leases=4-released pending_runtime+stacks=quarantined overflow+close=refused drain_cycles=refused source_IRQ_enqueue=not-qualified";
        assert!(native_work_verified(full));
        for marker in [
            "foreground=owned-stack",
            "Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified",
            "IF=off/on/clear-yield/exact",
            "guards=8-absent",
            "pending_runtime+stacks=quarantined",
            "drain_cycles=refused",
            "source_IRQ_enqueue=not-qualified",
        ] {
            assert!(!native_work_verified(&full.replace(marker, "unproven")));
        }
        assert!(!native_work_verified("CHECK native-dma PASS old EFI"));
        assert!(!native_work_verified(&full.replace(
            "Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified",
            "Win64-shadow+callee-save=verified"
        )));
        assert!(!native_work_verified(&format!(
            "{full}\nCHECK native-work FAIL late teardown"
        )));
        let base = [
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/native-work",
            "--native-work-check",
        ];
        let parsed = crate::Cli::try_parse_from(base).unwrap();
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        assert!(run.native_work_check);
        for conflict in [
            "--native-dma-check",
            "--native-dma-isolation-check",
            "--network",
            "--storage-check",
        ] {
            assert!(crate::Cli::try_parse_from(base.into_iter().chain([conflict])).is_err());
        }
    }

    #[test]
    fn native_work_and_audio_fixtures_refuse_shared_ownership_in_either_option_order() {
        use clap::{Parser, error::ErrorKind};
        for mode in [
            "playback",
            "duplex",
            "transport-playback",
            "transport-duplex",
        ] {
            for options in [
                ["--native-work-check", "--audio-check", mode],
                ["--audio-check", mode, "--native-work-check"],
            ] {
                let error =
                    crate::Cli::try_parse_from(["xtask", "boot", "run"].into_iter().chain(options))
                        .err()
                        .expect("native-work and audio fixtures must be exclusive");
                assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
            }
        }
    }

    #[test]
    fn native_dma_fixture_requires_exclusive_test_topology() {
        use clap::Parser;
        let parsed = crate::Cli::try_parse_from([
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/native-dma",
            "--native-dma-check",
        ])
        .unwrap();
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run");
        };
        assert!(run.native_dma_check);
        assert!(
            crate::Cli::try_parse_from([
                "xtask",
                "boot",
                "run",
                "--output",
                "/tmp/native-dma",
                "--native-dma-check",
                "--audio-check",
                "transport-playback"
            ])
            .is_err()
        );
        assert!(
            crate::Cli::try_parse_from([
                "xtask",
                "boot",
                "run",
                "--output",
                "/tmp/native-dma",
                "--native-dma-check",
                "--append",
                "--system"
            ])
            .is_err()
        );
        assert!(
            crate::Cli::try_parse_from([
                "xtask",
                "boot",
                "run",
                "--output",
                "/tmp/native-dma",
                "--native-dma-check",
                "--network"
            ])
            .is_err()
        );
    }

    #[test]
    fn attached_storage_and_directory_volume_have_explicit_cli_contracts() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "xtask",
            "boot",
            "run",
            "--bundle",
            "/tmp/bundle",
            "--output",
            "/tmp/run",
            "--storage-disk",
            "/tmp/disk.raw",
            "--storage-serial",
            "ANS-1",
            "--directory-volume",
            "--append",
            "--system --storage ANS-1:GUID",
        ])
        .unwrap();
        let crate::Task::Boot(Command::Run(run)) = cli.task else {
            panic!("boot run");
        };
        assert_eq!(run.storage_serial, ["ANS-1"]);
        assert_eq!(run.storage_disk, [Path::new("/tmp/disk.raw")]);
        assert!(run.directory_volume);
        assert_eq!(run.append.as_deref(), Some("--system --storage ANS-1:GUID"));
        for extra in [
            vec!["--storage-disk", "/tmp/disk", "--storage-check"],
            vec!["--storage-serial", "ANS"],
            vec!["--directory-volume"],
            vec!["--network-check", "http://example.test/"],
            vec!["--usb-storage-disk", "/tmp/disk", "--storage-check"],
            vec!["--network", "--usb-network"],
            vec!["--network-model", "e1000e"],
            vec!["--network-self-check"],
            vec![
                "--network",
                "--network-self-check",
                "--network-check",
                "http://localhost/",
            ],
            vec!["--network", "--network-model", "unknown"],
            vec!["--usb-disk", "/tmp/disk", "--storage-check"],
            vec![
                "--storage-disk",
                "/tmp/disk",
                "--storage-serial",
                "bad,drive=x",
            ],
        ] {
            let args: Vec<_> = ["xtask", "boot", "run", "--output", "/tmp/run"]
                .into_iter()
                .chain(extra)
                .collect();
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn process_image_identifies_the_executing_binary() {
        assert_eq!(
            fs::canonicalize(process_image(std::process::id()).unwrap()).unwrap(),
            fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        );
    }

    #[test]
    fn audio_modes_select_explicit_evidence_backends() {
        use clap::Parser;
        for (extra, expected) in [
            (vec!["--audio-check"], audio_check::Mode::Duplex),
            (
                vec!["--audio-check", "playback"],
                audio_check::Mode::Playback,
            ),
            (vec!["--audio-check", "duplex"], audio_check::Mode::Duplex),
        ] {
            let args: Vec<_> = ["xtask", "boot", "run", "--output", "/tmp/run"]
                .into_iter()
                .chain(extra)
                .collect();
            let cli = crate::Cli::try_parse_from(args).unwrap();
            let crate::Task::Boot(Command::Run(run)) = cli.task else {
                panic!("boot run");
            };
            assert_eq!(run.audio_check, Some(expected));
        }
    }

    #[test]
    fn network_models_select_only_implemented_pci_drivers() {
        use clap::Parser;
        for (argument, expected) in [
            ("virtio", NetworkModel::Virtio),
            ("e1000e", NetworkModel::E1000e),
            ("igb", NetworkModel::Igb),
        ] {
            let cli = crate::Cli::try_parse_from([
                "xtask",
                "boot",
                "run",
                "--output",
                "/tmp/run",
                "--network",
                "--network-model",
                argument,
                "--network-check",
                "http://localhost/check",
            ])
            .unwrap();
            let crate::Task::Boot(Command::Run(run)) = cli.task else {
                panic!("boot run");
            };
            assert_eq!(run.network_model, Some(expected));
        }
    }

    #[test]
    fn storage_disks_pair_with_distinct_serials() {
        let file = std::env::current_exe().unwrap();
        let one = storage_disks(std::slice::from_ref(&file), &[]).unwrap();
        assert_eq!(one, [(file.clone(), "STELAANS".to_owned())]);
        let two = [file.clone(), file.clone()];
        let serials = ["TARGET".to_owned(), "SOURCE".to_owned()];
        assert_eq!(storage_disks(&two, &serials).unwrap()[1].1, "SOURCE");
        assert!(storage_disks(&two, &[]).is_err());
        assert!(storage_disks(&two, &["A".to_owned(), "A".to_owned()]).is_err());
        assert!(storage_disks(&[file.with_extension("missing")], &[]).is_err());
    }

    #[test]
    fn option_paths_double_their_commas() {
        let path = std::path::Path::new("/tmp/bundles/Mac14,2/variables.fd");
        assert_eq!(option_path(path), "/tmp/bundles/Mac14,,2/variables.fd");
    }
}
