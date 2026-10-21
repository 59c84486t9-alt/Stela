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

mod disks;
mod lan;
mod network_check;
mod preboot;

/// `isa-debug-exit` reports `(code << 1) | 1`; a timeout reports 124.
const TIMEOUT_EXIT: u8 = 124;
const MAX_TIMEOUT_SECONDS: f64 = 120.0;
/// QEMU's FAT16 directory volume holds at most 516 MB; keep a margin.
const VVFAT_BYTES: u64 = 480 * 1024 * 1024;
/// A real restore payload verifies, and a kernel bundle boots, in tens of
/// minutes under TCG.
const MAX_LONG_TIMEOUT_SECONDS: f64 = 4.0 * 3600.0;
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
/// J473AP DRAM base with 4 GiB of guest DRAM.
const KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kernel.bin"));
const KERNEL_OPTIONS: &str =
    "--system --load 0x800004000 --entry 0x800004000 --ram-bytes 0x100000000";
/// What the test kernel must leave in X0-X10 when it idles; X1 and X2, its
/// tasks' SVC counts, need only be nonzero.
const KERNEL_RESULTS: [(usize, Option<u64>); 11] = [
    (0, Some(0x5354_454c_4120_4f4b)),
    (1, None),
    (2, None),
    (3, Some(6)),
    // EL1 data abort: EC 0x25, IL, level 2 translation fault.
    (4, Some(0x9600_0006)),
    (5, Some(0xffff_ff80_0400_0000)),
    // EL1 SVC #0x10 and EL0 SVC #1.
    (6, Some(0x5600_0010)),
    (7, Some(0x5600_0001)),
    // EL1 load and store at the Stela window's address, outside both
    // ranges: level 0 translation faults, the store's with WnR.
    (8, Some(0x9600_0004)),
    (9, Some(0x9600_0044)),
    (10, Some(0x0040_0000_0000_0000)),
];

/// System options for a boot bundle: the J473AP DRAM base and 8 GiB.
const BUNDLE_OPTIONS: &str = "--system --bundle \\EFI\\stela\\bundle --ram-bytes 0x200000000";

/// The line the test kernel writes through the S5L UART model.
const KERNEL_BANNER: &str = "GUEST| STELA TEST KERNEL: MMU ON, UART MMIO";

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Scenario {
    /// Four instructions on the bounded MMU-off EL1 diagnostic.
    Smoke,
    /// The system-mode engine running Stela's own test kernel: 16 KiB
    /// granule, high-half kernel, EL1 abort and SVC, timer FIQ, two EL0 tasks.
    SystemKernel,
}

#[derive(Subcommand)]
pub enum Command {
    /// Build `stela.efi`.
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Boot `stela.efi` with an ARM image in single-CPU x86 QEMU.
    Run(Box<Run>),
}

#[derive(Args)]
pub struct Run {
    /// The application; defaults to a fresh release build.
    #[arg(long)]
    image: Option<PathBuf>,
    /// Original ARM bytes; defaults to the scenario's image.
    #[arg(long)]
    module: Option<PathBuf>,
    /// The built-in image and options to run when no module is given.
    #[arg(long, value_enum, default_value_t = Scenario::Smoke)]
    scenario: Scenario,
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
    /// Answer unsupported operations as the SoC and its firmware do and
    /// report each once as `UNMODELED`, as a user's boot does. Without it a
    /// system-mode run is a boot study: it adds the mount's `--strict`, so
    /// the first unsupported operation stops the run
    /// (docs/design/runtime.md "Unsupported operations").
    #[arg(long, conflicts_with_all = ["module", "usb_image", "payload"])]
    graceful: bool,
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
    /// Attach a GPT disk image through virtio-blk, NVMe and AHCI, have the
    /// mount overwrite and read back one partition of each, and verify the
    /// mount's hashes and every byte of the images.
    #[arg(long)]
    storage_check: bool,
    /// Boot an existing USB disk image, such as one `stela setup` prepared,
    /// from its removable-media boot loader; writes go to a temporary
    /// overlay.
    #[arg(long, conflicts_with_all = [
        "payload", "module", "bundle", "append", "storage_check", "preboot_disk"
    ])]
    usb_image: Option<PathBuf>,
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
    /// Run install mode on a synthetic restore payload.
    #[arg(long, value_enum, conflicts_with_all = ["module", "append"])]
    payload: Option<PayloadMode>,
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
    /// Show the UART in a host window; adds no guest display device.
    Cocoa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum NetworkModel {
    Virtio,
    /// Intel 82574L, PCI ID 8086:10d3.
    E1000e,
}

impl NetworkModel {
    fn device(self) -> &'static str {
        match self {
            Self::Virtio => "virtio-net-pci",
            Self::E1000e => "e1000e",
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
    let strict = (arguments.bundle.is_some() || preboot.is_some()) && !arguments.graceful;
    if strict {
        options.push_str(" --strict");
    }
    if arguments.network_self_check || arguments.network_check.is_some() {
        ensure!(
            options.split_whitespace().next() == Some("--system"),
            "network checks require system mode: use --scenario system-kernel, --bundle or --append starting with --system"
        );
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
    let system = options.starts_with("--system");
    if arguments.usb_image.is_some() {
        fs::create_dir_all(&output)?;
    } else {
        fs::create_dir_all(volume.join("EFI/BOOT"))?;
        fs::create_dir_all(volume.join("EFI/stela"))?;
        fs::copy(&image, volume.join("EFI/BOOT/BOOTX64.EFI"))?;
        fs::write(&source, bytes)?;
        fs::write(volume.join("EFI/stela/stela.cfg"), &options)?;
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
    let variables = output.join("variables.fd");
    fs::copy(firmware.join(FIRMWARE_VARIABLES), &variables)?;
    let serial = output.join("serial.txt");
    let usb = arguments.usb_image.is_some();
    let mut command = Process::new(&qemu);
    // A USB's startup choices take a keyboard, and its setup writes the boot
    // log. System mode places the guest beside the window with LA57, which
    // `max` provides unless `--no-la57` hides it.
    let max = if arguments.no_la57 {
        "max,la57=off"
    } else {
        "max"
    };
    let (keyboard, cpu, access) = if usb {
        ("on", max, "readonly=off,file=fat:rw:")
    } else if system {
        ("off", max, "readonly=on,file=fat:")
    } else {
        ("off", "qemu64", "readonly=on,file=fat:")
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
        .args(["-accel", "tcg,thread=single", "-cpu", cpu, "-smp", "1"])
        .args(
            arguments
                .icount
                .map(|shift| ["-icount".into(), format!("shift={shift},sleep=off")])
                .into_iter()
                .flatten(),
        )
        .args(["-m", &memory, "-nodefaults", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=4"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            option_path(&firmware.join(FIRMWARE_CODE))
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,file={}",
            option_path(&variables)
        ))
        .arg("-drive")
        .arg(match &arguments.usb_image {
            Some(usb) => format!(
                "if=none,id=volume,format=raw,snapshot=on,file={}",
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
        })
        .args(["-device", "virtio-blk-pci,drive=volume"]);
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
            NetworkModel::E1000e => {
                // Exercise the real driver's upstream bridge discovery and
                // endpoint/parent ASPM workaround, not just a root-bus NIC.
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
    let host_usb = arguments.usb_input || arguments.usb_network || !arguments.usb_disk.is_empty();
    if host_usb {
        command.args(["-device", "qemu-xhci,id=host-usb"]);
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
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=usbdisk{index},format=raw,file={}",
                option_path(path)
            ))
            .arg("-device")
            .arg(format!(
                "usb-storage,drive=usbdisk{index},serial=STELAUSBDISK{index},bus=host-usb.0"
            ));
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
        Display::Cocoa => command
            .args(["-display", "cocoa", "-chardev"])
            .arg(format!(
                "vc,id=uart,cols=132,rows=50,logfile={}",
                option_path(&serial)
            ))
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
        .stdin(Stdio::null())
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
    let status = match wait(&mut child, limit) {
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
    let serial_text = fs::read_to_string(&serial).unwrap_or_default();
    let unsupported = serial_text
        .lines()
        .find_map(|line| line.strip_prefix("STOP UNSUPPORTED "))
        .map(String::from);
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
        }
    };
    let network = network_check_url.map(|_| {
        network_check::verify(&serial_text, fixture.as_ref(), expected_driver, &peer_text)
    });
    let qemu_process_image = qemu_process_image.and_then(|path| binding(&path).ok());
    let report = json!({
        "command": command_line,
        "qemu": binding(&qemu)?,
        "qemu_version": qemu_version,
        "qemu_process_image": qemu_process_image,
        "image": binding(&image)?,
        "source": source.exists().then(|| binding(&source)).transpose()?,
        "usb_image": arguments.usb_image,
        "no_la57": arguments.no_la57,
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
        "returncode": code,
        "payload": arguments.payload.map(|mode| {
            matches!(mode, PayloadMode::Stage | PayloadMode::StagePath)
        }),
        "staging": target.exists().then(|| staged(&target)).transpose()?,
        "timed_out": status.is_none(),
        "wall_seconds": started.elapsed().as_secs_f64(),
        "outputs": outputs,
        "storage": storage.as_ref().map(|result| match result {
            Ok(disks) => disks.clone(),
            Err(error) => json!({ "error": format!("{error:#}") }),
        }),
        "network": network.as_ref().map(|result| match result {
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
        }),
    });
    fs::write(output.join("run.json"), format!("{report:#}\n"))?;
    println!("{report:#}");
    if let Some(Err(error)) = storage {
        return Err(error.context("host storage check failed"));
    }
    if let Some(Err(error)) = network {
        bail!("host network check failed: {error}");
    }
    Ok(ExitCode::from(match (preboot.is_some(), entered) {
        (true, true) => 0,
        (true, false) => FAILED_EXIT,
        (false, _) => code,
    }))
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
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(buffer, self.start + offset)
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

#[cfg(test)]
mod tests {
    use super::*;

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
            "--graceful",
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
        assert!(run.graceful);
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
    fn network_models_select_only_implemented_pci_drivers() {
        use clap::Parser;
        for (argument, expected) in [
            ("virtio", NetworkModel::Virtio),
            ("e1000e", NetworkModel::E1000e),
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
