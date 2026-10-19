//! The UEFI mount: build `stela.efi` and run it in x86 QEMU.
//!
//! The run puts the application on a FAT volume as the removable-media boot
//! file, beside `\EFI\stela\stela.cfg` (the mount options) and
//! `\EFI\stela\source.bin` (the unchanged ARM bytes), and boots it with QEMU's
//! edk2 firmware. A boot manager such as OpenCore uses the same layout:
//! `--opencore` boots a copy of an existing OpenCore EFI with the mount added
//! by `stela efi install`, and picks its entry in the boot picker.
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
    io::Write,
    path::{Path, PathBuf},
    process::{Command as Process, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};
use stela_cli::efi;
use stela_runtime::payload::{
    PayloadError, PayloadSource, ReadAt, copy_verified, gpt, staging::StagedSource,
};

mod disks;
mod lan;
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
/// How often an OpenCore run presses Enter in the boot picker.
const PICKER_KEY_INTERVAL: Duration = Duration::from_secs(2);

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
    #[arg(long, conflicts_with_all = ["module", "opencore"])]
    bundle: Option<PathBuf>,
    /// A GPT disk image whose APFS container holds an installed system's
    /// Preboot volume, attached over NVMe through a snapshot: the mount
    /// builds the boot bundle from it with its own storage drivers and
    /// starts it on the system-mode engine.
    #[arg(long, conflicts_with_all = ["module", "opencore", "bundle", "append", "payload"])]
    preboot_disk: Option<PathBuf>,
    /// A restore payload inventory (`stela image-manifest
    /// --payload-manifest`), placed at `\EFI\stela\payload.json` for the
    /// mount's `--restore-manifest`.
    #[arg(long, requires = "bundle")]
    restore_manifest: Option<PathBuf>,
    /// Use QEMU's directory-backed FAT16 for a bundle that fits its
    /// volume, avoiding host disk-image utilities (QEMU rejects overflow).
    #[arg(long, requires = "bundle")]
    directory_volume: bool,
    /// Attach a raw GPT disk over NVMe, preserving writes; repeat for more
    /// disks. Select a partition with --storage SERIAL:GUID in --append.
    #[arg(long, conflicts_with_all = ["storage_check", "payload", "preboot_disk", "usb_image"])]
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
    #[arg(long, conflicts_with = "opencore")]
    monitor: Option<u16>,
    /// Advance QEMU's clocks by 2^SHIFT ns per executed x86 instruction
    /// (`-icount shift=SHIFT,sleep=off`) instead of host time, so that guest
    /// timeouts measure emulated work, as they would on hardware, and an idle
    /// guest skips ahead to its next timer.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=10))]
    icount: Option<u8>,
    /// Boot through a copy of this OpenCore ESP (the directory holding
    /// `EFI/OC`), without `EFI/Microsoft`, with the mount installed as a tool.
    #[arg(long)]
    opencore: Option<PathBuf>,
    /// Disable this `UEFI.Drivers` path in the OpenCore copy; repeatable.
    #[arg(long, requires = "opencore")]
    disable_driver: Vec<String>,
    /// Attach a GPT disk image through virtio-blk, NVMe and AHCI, have the
    /// mount overwrite and read back one partition of each, and verify the
    /// mount's hashes and every byte of the images.
    #[arg(long)]
    storage_check: bool,
    /// Boot an existing USB disk image, such as one `stela setup` prepared,
    /// through its own OpenCore; writes go to a temporary overlay.
    #[arg(long, conflicts_with_all = [
        "opencore", "payload", "module", "bundle", "append", "storage_check", "preboot_disk"
    ])]
    usb_image: Option<PathBuf>,
    /// Give a bundle's guest the native USB keyboard and pointer, fed by
    /// QEMU's virtio keyboard and tablet: adds both devices and the mount's
    /// `--input`.
    #[arg(long, conflicts_with_all = ["module", "opencore", "usb_image", "payload"])]
    input: bool,
    /// Give the mount a host network adapter: a `virtio-net-pci`, which the
    /// mount drives after ExitBootServices for its own requests (`--tss`,
    /// `--network-check`), on a QEMU `stream` netdev to xtask's own LAN
    /// peer (`boot/lan.rs`): DHCP, DNS and TCP relayed to the host, logged
    /// to `network.log`. QEMU needs no slirp.
    #[arg(long, conflicts_with_all = ["module", "opencore", "usb_image", "payload"])]
    network: bool,
    /// Have the mount POST once to this `http://` URL over the host network
    /// at start and report the reply: adds `--network-check URL`.
    #[arg(long, requires = "network")]
    network_check: Option<String>,
    /// Run install mode on a synthetic restore payload.
    #[arg(long, value_enum, conflicts_with_all = ["opencore", "module", "append"])]
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
    if arguments.input {
        options.push_str(" --input");
    }
    if let Some(url) = &arguments.network_check {
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
    match &arguments.opencore {
        None if arguments.usb_image.is_some() => fs::create_dir_all(&output)?,
        None => {
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
            }
        }
        Some(esp) => {
            ensure!(
                esp.join("EFI/OC/config.plist").is_file(),
                "{} has no EFI/OC/config.plist",
                esp.display()
            );
            copy_efi(&esp.join("EFI"), &volume.join("EFI"), true)?;
            disable_drivers(&volume, &arguments.disable_driver)?;
            let module = output.join("source.bin");
            fs::write(&module, bytes)?;
            efi::install(&efi::Install {
                esp: volume.clone(),
                image: image.clone(),
                source: Some(module),
                options: Some(options.clone()),
                ipsw: None,
                model: "Mac14,3".into(),
                payload_root: None,
                payload_layout: efi::PayloadLayout::Split,
                slice_bytes: stela_runtime::payload::MAX_SLICE_BYTES,
                no_aea_keys: false,
            })?;
        }
    }

    // QEMU's directory volume is FAT16 and holds 516 MB; larger volumes,
    // such as a recovery bundle with its ramdisk, go into a FAT32 image.
    let fat = match (&arguments.usb_image, &arguments.opencore) {
        (None, None) if !arguments.directory_volume && directory_bytes(&volume)? > VVFAT_BYTES => {
            Some(fat_image(&volume, &output)?)
        }
        _ => None,
    };
    let qemu = qemu()?;
    let firmware = firmware(&qemu)?;
    let variables = output.join("variables.fd");
    fs::copy(firmware.join(FIRMWARE_VARIABLES), &variables)?;
    let serial = output.join("serial.txt");
    let picker = arguments.opencore.is_some() || arguments.usb_image.is_some();
    let mut command = Process::new(&qemu);
    // OpenCore's picker needs a keyboard and a display adapter, its HFS+
    // driver uses instructions beyond the qemu64 model, and it halts when a
    // configured log file cannot be written.
    // System mode needs LA57, which `max` provides.
    let (keyboard, cpu, access) = if picker {
        ("on", "max", "readonly=off,file=fat:rw:")
    } else if system {
        ("off", "max", "readonly=on,file=fat:")
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
    // The boot picker, and a bundle's kernel through the mount's GOP, draw
    // on a display.
    if picker || bundle {
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
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=host-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .args(["-device", "virtio-net-pci,netdev=host-net"]);
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
        None if picker => command.args(["-monitor", "stdio"]),
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

    let started = Instant::now();
    let mut child = command
        .stdout(fs::File::create(output.join("stdout.txt"))?)
        .stderr(fs::File::create(output.join("stderr.txt"))?)
        .stdin(if picker {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .spawn()?;
    // OpenCore never boots a tool on its own. The picker gives the host no
    // signal that it is up, so Enter goes in until QEMU exits; it continues
    // edk2's boot and then starts the first entry, Stela's.
    if let Some(mut monitor) = child.stdin.take() {
        thread::spawn(move || {
            while monitor
                .write_all(b"sendkey ret\n")
                .and_then(|()| monitor.flush())
                .is_ok()
            {
                thread::sleep(PICKER_KEY_INTERVAL);
            }
        });
    }
    // A paused debugging session has no deadline.
    let limit = match arguments.gdb {
        Some(_) => Duration::MAX,
        None => Duration::from_secs_f64(arguments.timeout),
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

    let outputs: Vec<Value> = ["serial.txt", "stdout.txt", "stderr.txt"]
        .into_iter()
        .map(|name| output.join(name))
        .filter(|path| path.exists())
        .map(|path| binding(&path))
        .collect::<Result<_>>()?;
    let storage = match arguments.storage_check {
        true => Some(disks::verify(&disks, &output.join("serial.txt"))),
        false => None,
    };
    let report = json!({
        "command": command_line,
        "qemu": binding(&qemu)?,
        "image": binding(&image)?,
        "source": source.exists().then(|| binding(&source)).transpose()?,
        "usb_image": arguments.usb_image,
        "options": options,
        "opencore": arguments.opencore,
        "scenario": verification,
        "bundle": arguments.bundle,
        "preboot_disk": arguments.preboot_disk,
        "directory_volume": arguments.directory_volume,
        "restore_manifest": arguments.restore_manifest,
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
    });
    fs::write(output.join("run.json"), format!("{report:#}\n"))?;
    println!("{report:#}");
    if let Some(Err(error)) = storage {
        return Err(error.context("host storage check failed"));
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

/// Copy an EFI directory tree; at its top, leave out Windows' boot files.
fn copy_efi(from: &Path, to: &Path, top: bool) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if top && name.eq_ignore_ascii_case("Microsoft") {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_efi(&entry.path(), &to.join(&name), false)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), to.join(&name))?;
        } else {
            bail!(
                "{} is neither a file nor a directory",
                entry.path().display()
            );
        }
    }
    Ok(())
}

/// Turn off the named `UEFI.Drivers` entries in the run's OpenCore copy.
fn disable_drivers(volume: &Path, paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let config = volume.join("EFI/OC/config.plist");
    let mut root = plist::Value::from_file(&config)?;
    let drivers = root
        .as_dictionary_mut()
        .and_then(|root| root.get_mut("UEFI"))
        .and_then(plist::Value::as_dictionary_mut)
        .and_then(|uefi| uefi.get_mut("Drivers"))
        .and_then(plist::Value::as_array_mut)
        .context("config.plist has no UEFI.Drivers array")?;
    for path in paths {
        let driver = drivers
            .iter_mut()
            .filter_map(plist::Value::as_dictionary_mut)
            .find(|driver| {
                driver
                    .get("Path")
                    .and_then(plist::Value::as_string)
                    .is_some_and(|name| name.eq_ignore_ascii_case(path))
            })
            .with_context(|| format!("config.plist has no driver {path}"))?;
        driver.insert("Enabled".into(), false.into());
    }
    root.to_file_xml(&config)?;
    Ok(())
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
