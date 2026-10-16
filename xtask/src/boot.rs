//! The UEFI mount: build `stela.efi` and run it in x86 QEMU.
//!
//! The run puts the application on a FAT volume as the removable-media boot
//! file, beside `\EFI\stela\stela.cfg` (the mount options) and
//! `\EFI\stela\source.bin` (the unchanged ARM bytes), and boots it with QEMU's
//! edk2 firmware. A boot manager such as OpenCore uses the same layout:
//! `--opencore` boots a copy of an existing OpenCore EFI with the mount added
//! by `stela efi install`, and picks its entry in the boot picker.
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

/// `isa-debug-exit` reports `(code << 1) | 1`; a timeout reports 124.
const TIMEOUT_EXIT: u8 = 124;
const MAX_TIMEOUT_SECONDS: f64 = 120.0;
const FIRMWARE_CODE: &str = "edk2-x86_64-code.fd";
const FIRMWARE_VARIABLES: &str = "edk2-i386-vars.fd";
/// How often an OpenCore run presses Enter in the boot picker.
const PICKER_KEY_INTERVAL: Duration = Duration::from_secs(2);

/// The default ARM image: `movz x0, #0x1234; movz x1, #0x5678;
/// add x2, x0, x1; b .`, run at EL1 with the MMU off up to the branch.
const SMOKE: [u32; 4] = [0xd282_4680, 0xd28a_cf01, 0x8b01_0002, 0x1400_0000];
const SMOKE_OPTIONS: &str = "--entry 0x100000 --stop 0x10000c --budget 16";

#[derive(Subcommand)]
pub enum Command {
    /// Build `stela.efi`.
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Boot `stela.efi` with an ARM image in single-CPU x86 QEMU.
    Run(Run),
}

#[derive(Args)]
pub struct Run {
    /// The application; defaults to a fresh release build.
    #[arg(long)]
    image: Option<PathBuf>,
    /// Original ARM bytes; defaults to a four-instruction smoke program.
    #[arg(long)]
    module: Option<PathBuf>,
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
    /// Boot through a copy of this OpenCore ESP (the directory holding
    /// `EFI/OC`), without `EFI/Microsoft`, with the mount installed as a tool.
    #[arg(long)]
    opencore: Option<PathBuf>,
    /// Disable this `UEFI.Drivers` path in the OpenCore copy; repeatable.
    #[arg(long, requires = "opencore")]
    disable_driver: Vec<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Display {
    None,
    /// Show the UART in a host window; adds no guest display device.
    Cocoa,
}

pub fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Build { release } => {
            println!("{}", build(release)?.display());
            Ok(ExitCode::SUCCESS)
        }
        Command::Run(arguments) => launch(arguments),
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
    ensure!(
        arguments.timeout > 0.0 && arguments.timeout <= MAX_TIMEOUT_SECONDS,
        "timeout must be in (0, {MAX_TIMEOUT_SECONDS}] seconds"
    );
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
    let (bytes, options) = match &arguments.module {
        Some(module) => (fs::read(module)?, arguments.append.unwrap_or_default()),
        None => (
            SMOKE.iter().flat_map(|word| word.to_le_bytes()).collect(),
            arguments.append.unwrap_or_else(|| SMOKE_OPTIONS.into()),
        ),
    };
    match &arguments.opencore {
        None => {
            fs::create_dir_all(volume.join("EFI/BOOT"))?;
            fs::create_dir_all(volume.join("EFI/stela"))?;
            fs::copy(&image, volume.join("EFI/BOOT/BOOTX64.EFI"))?;
            fs::write(&source, bytes)?;
            fs::write(volume.join("EFI/stela/stela.cfg"), &options)?;
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
            })?;
        }
    }

    let qemu = qemu()?;
    let firmware = firmware(&qemu)?;
    let variables = output.join("variables.fd");
    fs::copy(firmware.join(FIRMWARE_VARIABLES), &variables)?;
    let serial = output.join("serial.txt");
    let picker = arguments.opencore.is_some();
    let mut command = Process::new(&qemu);
    // OpenCore's picker needs a keyboard and a display adapter, its HFS+
    // driver uses instructions beyond the qemu64 model, and it halts when a
    // configured log file cannot be written.
    let (keyboard, cpu, access) = if picker {
        ("on", "max", "readonly=off,file=fat:rw:")
    } else {
        ("off", "qemu64", "readonly=on,file=fat:")
    };
    command
        .arg("-machine")
        .arg(format!(
            "q35,smm=off,sata=off,usb=off,smbus=off,hpet=off,i8042={keyboard},vmport=off"
        ))
        .args(["-accel", "tcg,thread=single", "-cpu", cpu, "-smp", "1"])
        .args(["-m", "1G", "-nodefaults", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=4"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            firmware.join(FIRMWARE_CODE).display()
        ))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", variables.display()))
        .arg("-drive")
        .arg(format!(
            "if=none,id=volume,format=raw,{access}{}",
            volume.display()
        ))
        .args(["-device", "virtio-blk-pci,drive=volume"]);
    if picker {
        command.args(["-device", "VGA"]);
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
                serial.display()
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
    let code = match status {
        Some(status) => status.code().map_or(TIMEOUT_EXIT, |code| code as u8),
        None => TIMEOUT_EXIT,
    };

    let outputs: Vec<Value> = ["serial.txt", "stdout.txt", "stderr.txt"]
        .into_iter()
        .map(|name| output.join(name))
        .filter(|path| path.exists())
        .map(|path| binding(&path))
        .collect::<Result<_>>()?;
    let report = json!({
        "command": command_line,
        "qemu": binding(&qemu)?,
        "image": binding(&image)?,
        "source": binding(&source)?,
        "options": options,
        "opencore": arguments.opencore,
        "returncode": code,
        "timed_out": status.is_none(),
        "wall_seconds": started.elapsed().as_secs_f64(),
        "outputs": outputs,
    });
    fs::write(output.join("run.json"), format!("{report:#}\n"))?;
    println!("{report:#}");
    Ok(ExitCode::from(code))
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
