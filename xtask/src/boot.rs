//! The UEFI mount: build `stela.efi` and run it in x86 QEMU.
//!
//! The run puts the application on a FAT volume as the removable-media boot
//! file, beside `\EFI\stela\stela.cfg` (the mount options) and
//! `\EFI\stela\source.bin` (the unchanged ARM bytes), and boots it with QEMU's
//! edk2 firmware, as a PC's firmware boots the USB `stela setup` prepares.
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
#[cfg(test)]
#[path = "../../crates/stela-boot/src/storage/options.rs"]
mod storage_options;

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
use stela_cli::efi;
use stela_runtime::payload::{
    PayloadError, PayloadSource, ReadAt, copy_verified, gpt, staging::StagedSource,
};

mod audio_check;
mod disks;
mod host_firmware;
mod lan;
mod network_check;
mod preboot;

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

/// The default ARM image: `movz x0, #0x1234; movz x1, #0x5678;
/// add x2, x0, x1; b .`, run at EL1 with the MMU off up to the branch.
const SMOKE: [u32; 4] = [0xd282_4680, 0xd28a_cf01, 0x8b01_0002, 0x1400_0000];
const SMOKE_OPTIONS: &str = "--entry 0x100000 --stop 0x10000c --budget 16";
/// The blank target disk of a staging run, sparse on the host.
const TARGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Its PCI slot, which fixes its UEFI device path.
const TARGET_SLOT: u8 = 5;
/// The serial the NVMe target reports, which `stela.cfg` names.
const TARGET_SERIAL: &str = "STELA-TARGET-01";
/// Small slices, so the synthetic members span several.
const SYNTHETIC_SLICE_BYTES: u64 = 400_000;

/// Stela's system-mode test kernel (`boot/kernel.S`), loaded 16 KiB into the
/// J473AP DRAM base.
const KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kernel.bin"));
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
    /// Four instructions on the bounded MMU-off EL1 diagnostic.
    Smoke,
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
    /// Original ARM bytes; defaults to the scenario's image.
    #[arg(long)]
    module: Option<PathBuf>,
    /// The built-in image and options to run when no module is given.
    #[arg(long, value_enum, default_value_t = Scenario::Smoke)]
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
    /// A kernel boot bundle directory (`stela boot prepare` output) to start
    /// on the system-mode engine; it is copied to `\EFI\stela\bundle`.
    #[arg(long, conflicts_with = "module")]
    bundle: Option<PathBuf>,
    /// A GPT disk image whose APFS container holds an installed system's
    /// Preboot volume, attached over NVMe through a snapshot: the mount
    /// builds the boot bundle from it with its own storage drivers and
    /// starts it on the system-mode engine.
    #[arg(long, conflicts_with_all = ["module", "bundle", "append", "payload"])]
    preboot_disk: Option<PathBuf>,
    /// A restore payload inventory (`stela image-manifest
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
    /// Stop a system-mode run at its first unsupported operation: adds the
    /// mount's `--strict`, as `STELA_STRICT=1` in the environment also does.
    /// Without it the run answers each degraded and reports it once as
    /// `UNMODELED`, as a user's boot does (docs/design/runtime.md
    /// "Unsupported operations").
    #[arg(long, conflicts_with_all = ["module", "usb_image", "payload"])]
    strict: bool,
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

fn build(release: bool) -> Result<PathBuf> {
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

fn launch(arguments: Run) -> Result<ExitCode> {
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
    let image = match arguments.image {
        Some(image) => image,
        None => build(true)?,
    };
    let output = arguments.output;
    if output.exists() {
        bail!("{} already exists", output.display());
    }
    let volume = output.join("volume");
    let source = volume.join("EFI/stela/source.bin");
    let preboot = arguments
        .preboot_disk
        .as_deref()
        .map(preboot::prepare)
        .transpose()?;
    let (bytes, mut options) = match (&arguments.module, arguments.scenario) {
        _ if preboot.is_some() => (Vec::new(), preboot.as_ref().unwrap().options()),
        _ if arguments.bundle.is_some() => (
            Vec::new(),
            arguments.append.unwrap_or_else(|| BUNDLE_OPTIONS.into()),
        ),
        (Some(module), _) => (fs::read(module)?, arguments.append.unwrap_or_default()),
        (None, Scenario::Smoke) => (
            SMOKE.iter().flat_map(|word| word.to_le_bytes()).collect(),
            arguments.append.unwrap_or_else(|| SMOKE_OPTIONS.into()),
        ),
        (None, Scenario::SystemKernel) => (
            KERNEL.to_vec(),
            arguments.append.unwrap_or_else(|| KERNEL_OPTIONS.into()),
        ),
    };
    if arguments.native_dma_check
        || arguments.native_dma_isolation_check
        || arguments.native_work_check
        || arguments.native_irq_work_check
    {
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
    let disks = match arguments.storage_check {
        true => {
            fs::create_dir_all(&output)?;
            disks::create(&output)?
        }
        false => Vec::new(),
    };
    options.extend(disks.iter().map(disks::Disk::option));
    if arguments.input || arguments.usb_input {
        options.push_str(" --input");
    }
    for path in &arguments.usb_disk {
        ensure!(path.is_file(), "USB disk is not a file: {}", path.display());
    }
    ensure!(
        arguments.usb_storage_disk.len() <= 6,
        "the guest's native hub carries at most six USB disks"
    );
    for (index, path) in arguments.usb_storage_disk.iter().enumerate() {
        ensure!(
            path.is_file(),
            "USB storage disk is not a file: {}",
            path.display()
        );
        options.push_str(&format!(" --usb-storage {}", usb_serial(index)));
    }
    if arguments.guest_network {
        options.push_str(" --guest-network");
    }
    if arguments.verify_on_read {
        options.push_str(" --verify-on-read");
    }
    let system = options.split_whitespace().next() == Some("--system");
    ensure!(
        system || !arguments.strict,
        "--strict applies to system-mode runs"
    );
    let strict = system && (arguments.strict || strict_environment());
    if strict {
        options.push_str(" --strict");
    }
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
    let fixture = arguments
        .network_self_check
        .then(network_check::Fixture::start)
        .transpose()?;
    let network_check_url = arguments
        .network_check
        .as_deref()
        .or_else(|| fixture.as_ref().map(|fixture| fixture.url.as_str()));
    if let Some(url) = network_check_url {
        ensure!(
            url.starts_with("http://") && !url.contains(char::is_whitespace),
            "the network check is one http:// URL"
        );
        options.push_str(&format!(" --network-check {url}"));
    }
    let target = output.join("target.img");
    let options = match arguments.payload {
        None => options,
        Some(mode) => {
            let ipsw = output.join("synthetic.ipsw");
            fs::create_dir_all(&output)?;
            efi::synthetic_ipsw(&ipsw)?;
            efi::write_payload(&efi::PayloadOptions {
                image: &ipsw,
                model: efi::SYNTHETIC_MODEL,
                root: &volume,
                layout: match mode {
                    PayloadMode::VerifyArchive => efi::PayloadLayout::Archive,
                    _ => efi::PayloadLayout::Split,
                },
                slice_bytes: SYNTHETIC_SLICE_BYTES,
                fetch_keys: false,
            })?;
            let mut install = format!(
                "{options} --install-build {} --install-mode ",
                efi::SYNTHETIC_BUILD
            );
            match mode {
                PayloadMode::Verify | PayloadMode::VerifyArchive => install.push_str("verify"),
                PayloadMode::Stage | PayloadMode::StagePath => {
                    fs::File::create_new(&target)?.set_len(TARGET_BYTES)?;
                    let identity = match mode {
                        PayloadMode::Stage => format!("--install-target-serial {TARGET_SERIAL}"),
                        _ => format!(
                            "--install-target-path PciRoot(0x0)/Pci({TARGET_SLOT:#x},0x0) \
                             --install-target-bytes {TARGET_BYTES}"
                        ),
                    };
                    // A 4 GiB disk: 1 GiB cache, and an Apple region of at
                    // least 1 GiB instead of a real restore's 64 GiB.
                    install.push_str(&format!(
                        "stage {identity} \
                         --install-cache-bytes 0x40000000 --install-min-apple-bytes 0x40000000"
                    ));
                }
            }
            install
        }
    };
    ensure!(
        arguments.host_firmware.is_none() || system,
        "host firmware qualification requires --scenario system-kernel or another --system boot"
    );
    if arguments.usb_image.is_some() {
        fs::create_dir_all(&output)?;
    } else {
        fs::create_dir_all(volume.join("EFI/BOOT"))?;
        fs::create_dir_all(volume.join("EFI/stela"))?;
        fs::copy(&image, volume.join("EFI/BOOT/BOOTX64.EFI"))?;
        fs::write(&source, bytes)?;
        fs::write(volume.join("EFI/stela/stela.cfg"), &options)?;
        if let Some(directory) = &arguments.host_firmware {
            let package = stela_loader::host_firmware::Package::read_for_mount(
                directory,
                &fs::read(&image)?,
            )?;
            package.publish(&volume.join(stela_loader::host_firmware::DIRECTORY))?;
        }
        if let Some(bundle) = &arguments.bundle {
            copy_bundle(bundle, &volume.join("EFI/stela/bundle"))?;
        }
        if let Some(manifest) = &arguments.restore_manifest {
            fs::copy(manifest, volume.join("EFI/stela/payload.json"))
                .with_context(|| format!("restore manifest {}", manifest.display()))?;
            // The block hashes the manifest names go beside it, so the
            // restore host needs no scan of the payload.
            let parsed = stela_runtime::payload::PayloadManifest::parse(&fs::read(manifest)?)
                .map_err(|error| anyhow::anyhow!("{}: {error}", manifest.display()))?;
            if let Some(blocks) = &parsed.block_hashes {
                let from = manifest.with_file_name(&blocks.file);
                fs::copy(&from, volume.join("EFI/stela").join(&blocks.file))
                    .with_context(|| format!("block hashes {}", from.display()))?;
            }
        }
    }

    // QEMU's directory volume is FAT16 and holds 516 MB; larger volumes,
    // such as a recovery bundle with its ramdisk, go into a FAT32 image.
    let fat = match &arguments.usb_image {
        None if !arguments.directory_volume && directory_bytes(&volume)? > VVFAT_BYTES => {
            Some(fat_image(&volume, &output)?)
        }
        _ => None,
    };
    let qemu = qemu()?;
    let firmware = firmware(&qemu)?;
    // A qcow2 stick keeps its variables in a qcow2 of its own, so `savevm`
    // can checkpoint the whole machine.
    let checkpointed = arguments
        .usb_image
        .as_ref()
        .is_some_and(|image| image.extension().is_some_and(|e| e == "qcow2"));
    let (variables, format) = if checkpointed {
        let variables = arguments
            .usb_image
            .as_ref()
            .unwrap()
            .with_extension("vars.qcow2");
        if !variables.exists() {
            overlay(&qemu, &firmware.join(FIRMWARE_VARIABLES), &variables)?;
        }
        (variables, "qcow2")
    } else {
        let variables = output.join("variables.fd");
        fs::copy(firmware.join(FIRMWARE_VARIABLES), &variables)?;
        (variables, "raw")
    };
    ensure!(
        arguments.loadvm.is_none() || checkpointed,
        "--loadvm needs a .qcow2 --usb-image"
    );
    let serial = output.join("serial.txt");
    let usb = arguments.usb_image.is_some();
    let mut command = Process::new(&qemu);
    // A USB's startup choices take a keyboard, and its setup writes the boot
    // log. System mode places the guest beside the window with LA57, which
    // the selected CPU exposes unless `--no-la57` hides it.
    let cpu = qemu_cpu(
        arguments.cpu.as_deref().or(arguments.kvm.then_some("host")),
        arguments.no_la57,
        usb || system
            || arguments.native_dma_check
            || arguments.native_dma_isolation_check
            || arguments.native_work_check
            || arguments.native_irq_work_check,
    );
    let (keyboard, access) = if usb {
        ("on", "readonly=off,file=fat:rw:")
    } else {
        ("off", "readonly=on,file=fat:")
    };
    // A USB image carries the boot bundle that `stela setup` wrote.
    let bundle = arguments.bundle.is_some() || preboot.is_some() || arguments.usb_image.is_some();
    let memory = arguments.memory.clone().unwrap_or_else(|| {
        match (bundle, system) {
            (true, _) => "12G",
            (false, true) => "8G",
            (false, false) => "1G",
        }
        .into()
    });
    command
        .arg("-machine")
        .arg(format!(
            "q35,smm=off,sata=off,usb=off,smbus=off,hpet=off,i8042={keyboard},vmport=off"
        ))
        .args([
            "-accel",
            qemu_accelerator(arguments.icount, arguments.kvm),
            "-cpu",
            &cpu,
            "-smp",
        ])
        .arg(format!(
            "cpus={},sockets=1,cores={},threads={}",
            u32::from(arguments.host_cores) * u32::from(arguments.host_threads),
            arguments.host_cores,
            arguments.host_threads
        ))
        .args(
            arguments
                .icount
                .map(|shift| ["-icount".into(), format!("shift={shift},sleep=off")])
                .into_iter()
                .flatten(),
        )
        .args(["-m", &memory, "-nodefaults", "-no-reboot"])
        .args(
            arguments
                .loadvm
                .iter()
                .flat_map(|tag| ["-loadvm", tag.as_str()]),
        )
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            option_path(&firmware.join(FIRMWARE_CODE))
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format={format},file={}",
            option_path(&variables)
        ))
        .arg("-drive")
        .arg(match &arguments.usb_image {
            Some(usb) => format!(
                "if=none,id=volume,format={format},snapshot={},file={}",
                if arguments.usb_writable { "off" } else { "on" },
                option_path(usb)
            ),
            None => match &fat {
                Some(image) => format!(
                    "if=none,id=volume,format=raw,readonly=on,file={}",
                    option_path(image)
                ),
                None => format!(
                    "if=none,id=volume,format=raw,{access}{}",
                    option_path(&volume)
                ),
            },
        });
    if !usb {
        command.args(["-device", "virtio-blk-pci,drive=volume"]);
    }
    if let Some(mode) = arguments.audio_check {
        mode.attach(&mut command, &output);
        // isa-debug-exit calls exit() before the audio backend finalizes its
        // WAV. Quit through QMP after the mount stops so cleanup can finish.
        command.args(["-qmp", "stdio"]);
    } else {
        command.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=4"]);
    }
    for (index, disk) in disks.iter().enumerate() {
        disk.attach(index, &mut command);
    }
    if let Some(preboot) = &preboot {
        preboot.attach(&mut command);
    }
    if target.exists() {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=target,format=raw,file={}",
                option_path(&target)
            ))
            .arg("-device")
            .arg(match arguments.payload {
                Some(PayloadMode::StagePath) => {
                    format!("virtio-blk-pci,drive=target,addr={TARGET_SLOT:#x}")
                }
                _ => format!("nvme,drive=target,serial={TARGET_SERIAL},addr={TARGET_SLOT:#x}"),
            });
    }
    // A bundle's kernel draws on a display through the mount's GOP.
    if bundle {
        command.args(["-device", "VGA"]);
    }
    if arguments.input {
        command.args([
            "-device",
            "virtio-keyboard-pci",
            "-device",
            "virtio-tablet-pci",
        ]);
    }
    if arguments.network {
        let port = lan::listen(output.join("network.log")).context("start the network peer")?;
        let model = arguments.network_model.unwrap_or(NetworkModel::Virtio);
        let bus = match model {
            NetworkModel::E1000e | NetworkModel::Igb => {
                // Exercise physical NIC drivers behind a PCIe bridge. For
                // e1000e this also checks the endpoint/parent ASPM workaround.
                command.args([
                    "-device",
                    "pcie-root-port,id=host-net-port,chassis=1,bus=pcie.0",
                ]);
                ",bus=host-net-port"
            }
            NetworkModel::Virtio => "",
        };
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=host-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .arg("-device")
            .arg(format!("{},netdev=host-net{bus}", model.device()));
    }
    // After the mount's own adapter, so the mount gives the guest the
    // second one when both are present.
    if arguments.guest_network {
        let port = lan::listen(output.join("guest-network.log"))
            .context("start the guest network peer")?;
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=guest-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .args(["-device", "virtio-net-pci,netdev=guest-net"]);
    }
    let host_usb =
        usb || arguments.usb_input || arguments.usb_network || !arguments.usb_disk.is_empty();
    if host_usb {
        command.args([
            "-device",
            if arguments.usb_disk_model == Some(UsbDiskModel::UasUsb2) {
                "qemu-xhci,id=host-usb,p3=0"
            } else {
                "qemu-xhci,id=host-usb"
            },
        ]);
    }
    if usb {
        command.arg("-device").arg(format!(
            "usb-storage,drive=volume,serial={},bus=host-usb.0,bootindex=0",
            arguments.usb_serial
        ));
    }
    if arguments.usb_input {
        for device in ["usb-kbd", "usb-tablet", "usb-mouse"] {
            command
                .arg("-device")
                .arg(format!("{device},bus=host-usb.0"));
        }
    }
    if arguments.usb_network {
        let port =
            lan::listen(output.join("usb-network.log")).context("start the USB network peer")?;
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=usb-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .args(["-device", "usb-net,netdev=usb-net,bus=host-usb.0"]);
    }
    for (index, path) in arguments.usb_disk.iter().enumerate() {
        command.arg("-drive").arg(format!(
            "if=none,id=usbdisk{index},format=raw,file={}",
            option_path(path)
        ));
        match arguments.usb_disk_model.unwrap_or(UsbDiskModel::Bot) {
            UsbDiskModel::Bot => {
                command.arg("-device").arg(format!(
                    "usb-storage,drive=usbdisk{index},serial=STELAUSBDISK{index},bus=host-usb.0"
                ));
            }
            UsbDiskModel::Uas | UsbDiskModel::UasUsb2 => {
                command.arg("-device").arg(format!(
                    "usb-uas,id=host-uas{index},serial=STELAUSBDISK{index},bus=host-usb.0"
                ));
                command.arg("-device").arg(format!(
                    "scsi-hd,drive=usbdisk{index},bus=host-uas{index}.0,scsi-id=0,lun=0"
                ));
            }
        }
    }
    for (index, path) in arguments.usb_storage_disk.iter().enumerate() {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=usb{index},format=raw,file={}",
                option_path(path)
            ))
            .arg("-device")
            .arg(format!(
                "nvme,drive=usb{index},serial={}",
                usb_serial(index)
            ));
    }
    match arguments.display {
        Display::None => command
            .args(["-display", "none"])
            .arg("-serial")
            .arg(format!("file:{}", serial.display())),
        // Cocoa sizes its text console from the chardev; GTK's VTE console
        // sizes itself and refuses the options.
        Display::Window if cfg!(target_os = "macos") => command
            .args(["-display", "cocoa", "-chardev"])
            .arg(format!(
                "vc,id=uart,cols=132,rows=50,logfile={}",
                option_path(&serial)
            ))
            .args(["-serial", "chardev:uart"]),
        Display::Window => command
            .args(["-display", "gtk", "-chardev"])
            .arg(format!("vc,id=uart,logfile={}", option_path(&serial)))
            .args(["-serial", "chardev:uart"]),
    };
    match arguments.monitor {
        Some(port) => command
            .arg("-monitor")
            .arg(format!("telnet:127.0.0.1:{port},server=on,wait=off")),
        None => command.args(["-monitor", "none"]),
    };
    for (index, (path, serial)) in attached.iter().enumerate() {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=ans{index},format=raw,file={}",
                option_path(path)
            ))
            .arg("-device")
            .arg(format!("nvme,drive=ans{index},serial={serial}"));
    }
    if arguments.native_dma_check
        || arguments.native_dma_isolation_check
        || arguments.native_irq_work_check
    {
        command.args(["-device", "intel-iommu,intremap=off,caching-mode=on"]);
        if arguments.native_dma_isolation_check {
            command.args(["-device", "edu,addr=2", "-device", "edu,addr=3"]);
        } else {
            command.args(["-device", "edu"]);
        }
    }
    if let Some(port) = arguments.gdb {
        command
            .arg("-gdb")
            .arg(format!("tcp:127.0.0.1:{port}"))
            .arg("-S");
        eprintln!("paused: gdb -ex 'target remote 127.0.0.1:{port}'");
    }
    let command_line: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let qemu_version = qemu_version(&qemu)?;

    let started = Instant::now();
    let mut child = command
        .stdout(fs::File::create(output.join("stdout.txt"))?)
        .stderr(fs::File::create(output.join("stderr.txt"))?)
        .stdin(if arguments.audio_check.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()?;
    // The local launcher can be a shell wrapper. Observe its running image
    // after exec, keeping the launcher binding and QEMU version separately.
    std::thread::sleep(Duration::from_millis(10));
    let qemu_process_image = process_image(child.id());
    // A paused debugging session has no deadline.
    let limit = match arguments.gdb {
        Some(_) => Duration::MAX,
        None => Duration::from_secs_f64(arguments.timeout).saturating_sub(started.elapsed()),
    };
    let waited = if arguments.audio_check.is_some() {
        audio_check::wait_for_stop(&mut child, &serial, limit)
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
    let mut code = match status {
        Some(status) => status.code().map_or(TIMEOUT_EXIT, |code| code as u8),
        None => TIMEOUT_EXIT,
    };
    let qemu_returncode = code;
    let serial_text = fs::read_to_string(&serial).unwrap_or_default();
    let mount_exit = arguments
        .audio_check
        .map(|_| audio_check::guest_exit(&serial_text));
    if let Some(result) = &mount_exit {
        code = result.as_ref().copied().unwrap_or(FAILED_EXIT);
    }
    let unsupported = first_unsupported(&serial_text);
    // The installed-system scenario ends at the bundle's entry: what the
    // engine meets after it is reported but does not fail the run.
    let mut entered = false;
    let verification = if let Some(preboot) = &preboot {
        let checked = preboot.verify(&serial_text);
        entered = checked.is_ok();
        Some(
            checked
                .unwrap_or_else(|error| json!({ "passed": false, "reason": format!("{error:#}") })),
        )
    } else if arguments.bundle.is_none()
        && arguments.module.is_none()
        && !arguments.native_dma_check
        && !arguments.native_dma_isolation_check
        && !arguments.native_work_check
        && !arguments.native_irq_work_check
        && arguments.scenario == Scenario::SystemKernel
    {
        let checked = verify_kernel(&serial_text);
        if checked.is_err() && code == IDLE_EXIT {
            code = FAILED_EXIT;
        }
        Some(checked.map_or_else(
            |error| json!({ "passed": false, "reason": error }),
            |()| json!({ "passed": true }),
        ))
    } else {
        None
    };

    let peer_path = output.join(if arguments.usb_network {
        "usb-network.log"
    } else {
        "network.log"
    });
    // LAN listeners run independently. Preserve exactly the peer bytes used
    // for this check rather than hashing a log another thread can append to.
    let peer_text = fs::read_to_string(peer_path).unwrap_or_default();
    let peer_snapshot = fixture
        .as_ref()
        .map(|_| output.join("network-check-peer.txt"));
    if let Some(path) = &peer_snapshot {
        fs::write(path, &peer_text)?;
    }
    let outputs: Vec<Value> = [
        "serial.txt",
        "stdout.txt",
        "stderr.txt",
        "network-check-peer.txt",
        audio_check::WAV,
    ]
    .into_iter()
    .map(|name| output.join(name))
    .filter(|path| path.exists())
    .map(|path| binding(&path))
    .collect::<Result<_>>()?;
    let storage = match arguments.storage_check {
        true => Some(disks::verify(&disks, &output.join("serial.txt"))),
        false => None,
    };
    let expected_driver = if arguments.usb_network {
        "usb-cdc"
    } else {
        match arguments.network_model.unwrap_or(NetworkModel::Virtio) {
            NetworkModel::Virtio => "virtio-net",
            NetworkModel::E1000e => "e1000e",
            NetworkModel::Igb => "igb",
        }
    };
    let network = network_check_url.map(|_| {
        network_check::verify(&serial_text, fixture.as_ref(), expected_driver, &peer_text)
    });
    let host_firmware = arguments
        .host_firmware
        .as_ref()
        .map(|_| host_firmware::report(&volume, &serial_text))
        .transpose()?;
    let audio = arguments.audio_check.map(|mode| {
        if let Some(Err(error)) = &mount_exit {
            bail!("invalid guest exit status: {error:#}");
        }
        audio_check::normal_exit(
            qemu_returncode,
            &fs::read_to_string(output.join("stdout.txt"))?,
        )?;
        let mut report = audio_check::verify(mode, &serial_text, &output)?;
        report["qemu_shutdown"] = json!("acknowledged-qmp-quit");
        report["mount_returncode"] =
            json!(mount_exit.as_ref().and_then(|result| result.as_ref().ok()));
        Ok::<_, anyhow::Error>(report)
    });
    let qemu_process_image = qemu_process_image.and_then(|path| binding(&path).ok());
    let native_irq_work = arguments.native_irq_work_check.then(|| {
        json!({ "passed": native_irq_work_verified(&serial_text) && status.is_some() && code == IDLE_EXIT
            && !serial_text.contains("STELA PANIC") && !serial_text.contains("STOP UNSUPPORTED") })
    });
    let native_work = arguments.native_work_check.then(|| {
        json!({
            "passed":native_work_verified(&serial_text) && status.is_some() && code==IDLE_EXIT
                && unsupported.is_none() && first_guest_panic(&serial_text).is_none()
        })
    });
    let native_dma = arguments.native_dma_check.then(|| {
        json!({
            "passed": serial_text.lines().any(|line| line.starts_with("CHECK native-dma PASS "))
                && !serial_text.lines().any(|line| line.starts_with("CHECK native-dma FAIL "))
                && status.is_some() && code == IDLE_EXIT
                && unsupported.is_none() && first_guest_panic(&serial_text).is_none(),
        })
    });
    let native_dma_isolation = arguments.native_dma_isolation_check.then(|| {
        json!({ "passed": native_isolation_verified(&serial_text)
            && status.is_some() && code == IDLE_EXIT
            && unsupported.is_none() && first_guest_panic(&serial_text).is_none() })
    });
    let native_irq = arguments.native_dma_check.then(|| {
        let level_passed = native_level_verified(&serial_text);
        json!({
            "level_passed": level_passed,
            "passed": level_passed && serial_text.lines().any(|line| line.starts_with("CHECK native-irq PASS "))
                && !serial_text.lines().any(|line| line.starts_with("CHECK native-irq FAIL "))
                && status.is_some() && code == IDLE_EXIT
                && unsupported.is_none() && first_guest_panic(&serial_text).is_none(),
        })
    });
    // Keep nested report expansion independent of the outer metadata object.
    let network_report = network.as_ref().map(|result| match result {
        Ok(()) => json!({
            "passed": true,
            "url": network_check_url,
            "driver": expected_driver,
            "peer_snapshot": peer_snapshot,
            "expected_body": fixture.as_ref().map(|fixture| json!({
                "bytes": network_check::BODY_BYTES,
                "sha256": fixture.sha256,
            })),
            "model": if arguments.usb_network {
                "usb-net"
            } else {
                arguments.network_model.unwrap_or(NetworkModel::Virtio).device()
            },
        }),
        Err(error) => json!({ "passed": false, "reason": error }),
    });
    let report = json!({
        "command": command_line,
        "qemu": binding(&qemu)?,
        "qemu_version": qemu_version,
        "host_firmware": host_firmware,
        "qemu_process_image": qemu_process_image,
        "image": binding(&image)?,
        "source": source.exists().then(|| binding(&source)).transpose()?,
        "usb_image": arguments.usb_image,
        "usb_serial": arguments.usb_image.as_ref().map(|_| &arguments.usb_serial),
        "usb_writable": arguments.usb_writable,
        "no_la57": arguments.no_la57,
        "qemu_host_cores": arguments.host_cores,
        "qemu_host_threads": arguments.host_threads,
        "qemu_accelerator": qemu_accelerator(arguments.icount, arguments.kvm),
        "native_dma": native_dma,
        "native_work": native_work,
        "native_irq_work": native_irq_work,
        "native_dma_isolation": native_dma_isolation,
        "native_irq": native_irq,
        "options": options,
        "scenario": verification,
        "bundle": arguments.bundle,
        "preboot_disk": arguments.preboot_disk,
        "directory_volume": arguments.directory_volume,
        "restore_manifest": arguments.restore_manifest,
        "verify_on_read": arguments.verify_on_read,
        "strict": strict,
        "storage_disks": attached
            .iter()
            .map(|(path, serial)| json!({ "path": path, "serial": serial }))
            .collect::<Vec<_>>(),
        "first_unsupported": unsupported,
        "first_guest_panic": first_guest_panic(&serial_text),
        "returncode": code,
        "qemu_returncode": qemu_returncode,
        "payload": arguments.payload.map(|mode| {
            matches!(mode, PayloadMode::Stage | PayloadMode::StagePath)
        }),
        "staging": target.exists().then(|| staged(&target)).transpose()?,
        "timed_out": status.is_none(),
        "wall_seconds": started.elapsed().as_secs_f64(),
        "outputs": outputs,
        "audio": audio.as_ref().map(|result| match result {
            Ok(report) => report.clone(),
            Err(error) => json!({ "passed": false, "reason": format!("{error:#}") }),
        }),
        "storage": storage.as_ref().map(|result| match result {
            Ok(disks) => disks.clone(),
            Err(error) => json!({ "error": format!("{error:#}") }),
        }),
        "network": network_report,
    });
    fs::write(output.join("run.json"), format!("{report:#}\n"))?;
    println!("{report:#}");
    if let Some(Err(error)) = storage {
        return Err(error.context("host storage check failed"));
    }
    ensure!(
        report["host_firmware"].is_null() || report["host_firmware"]["passed"] == true,
        "host firmware did not survive the before/after EBS verification"
    );
    if let Some(Err(error)) = network {
        bail!("host network check failed: {error}");
    }
    if let Some(Err(error)) = audio {
        return Err(error.context("native audio check failed"));
    }
    ensure!(
        !arguments.native_dma_check || report["native_dma"]["passed"] == true,
        "native DMA fixture did not verify actual device traffic, fault and teardown"
    );
    ensure!(
        !arguments.native_dma_check || report["native_irq"]["passed"] == true,
        "native IRQ fixture did not verify MSI and shared level delivery, ACK and drained removal"
    );
    ensure!(
        !arguments.native_dma_isolation_check || report["native_dma_isolation"]["passed"] == true,
        "native DMA isolation fixture did not verify two requesters, matched fault and teardown"
    );
    ensure!(
        !arguments.native_work_check || report["native_work"]["passed"] == true,
        "native work did not verify actual owned contexts, ABI/control/flags and teardown"
    );
    ensure!(
        !arguments.native_irq_work_check || report["native_irq_work"]["passed"] == true,
        "native IRQ work did not qualify actual MSI/context/deferred execution and lifecycle"
    );
    if arguments.native_dma_check
        || arguments.native_dma_isolation_check
        || arguments.native_work_check
        || arguments.native_irq_work_check
    {
        return Ok(ExitCode::SUCCESS);
    }
    Ok(ExitCode::from(match (preboot.is_some(), entered) {
        (true, true) => 0,
        (true, false) => FAILED_EXIT,
        (false, _) => code,
    }))
}

/// Whether `STELA_STRICT=1` asks for strict mode, as it does for `stela run`.
fn strict_environment() -> bool {
    std::env::var_os("STELA_STRICT").is_some_and(|value| value == "1")
}

/// The first printed requirement, including graceful-mode diagnostics which
/// do not terminate the engine. Buffered diagnostics are not a causal clock.
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
    ensure!(
        cfg!(target_os = "macos"),
        "volumes over {VVFAT_BYTES} bytes need a FAT32 image, which this host cannot make; \
         build it with hdiutil on macOS"
    );
    let bytes = directory_bytes(volume)?;
    let size = (bytes + bytes / 8 + (64 << 20)).div_ceil(1 << 20);
    let base = output.join("volume");
    exec(
        Process::new("hdiutil")
            .args([
                "create",
                "-quiet",
                "-fs",
                "MS-DOS FAT32",
                "-volname",
                "STELA",
            ])
            .args(["-layout", "NONE", "-format", "UDTO", "-size"])
            .arg(format!("{size}m"))
            .arg("-srcfolder")
            .arg(volume)
            .arg(&base),
    )?;
    Ok(output.join("volume.cdr"))
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
    fn run_report_keeps_graceful_requirements_and_the_first_guest_panic() {
        let serial = concat!(
            "UNSUPPORTED OPERATIONS mode=graceful\r\n",
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
            "UNSUPPORTED OPERATIONS mode=strict\n",
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
            "--strict",
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
        assert!(run.strict);
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
