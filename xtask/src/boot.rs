//! Freestanding Multiboot mount: build, package and run in x86 QEMU.
//!
//! The image is the real shared runtime linked for `x86_64-unknown-none`. The
//! ARM module (firmware or test code) is passed to QEMU unchanged as the
//! Multiboot module; placement and initial state travel on the command line.
use crate::{
    check::{BOOT_MANIFEST, BOOT_TARGET, BOOT_TARGET_DIR},
    tools::{binding, cargo, exec, qemu, root, stop, wait},
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand, ValueEnum};
use object::{
    Endianness, Object, ObjectSymbol,
    elf::PT_LOAD,
    read::elf::{ElfFile64, ProgramHeader},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command as Process, ExitCode, Stdio},
    time::{Duration, Instant},
};
use stela_runtime::sha256;

const IMAGE: &str = "stela-multiboot.bin";
const MULTIBOOT_MAGIC: u32 = 0x1bad_b002;
/// Page-aligned modules, memory map and address fields.
const MULTIBOOT_FLAGS: u32 = 0x0001_0003;
const MULTIBOOT_HEADER_WORDS: usize = 8;
const MULTIBOOT_SEARCH_BYTES: usize = 8192;
/// The image and its heap must stay inside the loader's identity window.
const IDENTITY_LIMIT: u64 = 0x1000_0000;
/// `isa-debug-exit` reports `(code << 1) | 1`; a timeout reports 124.
const TIMEOUT_EXIT: u8 = 124;
const MAX_TIMEOUT_SECONDS: f64 = 120.0;

#[derive(Subcommand)]
pub enum Command {
    /// Build the runtime image and package it for Multiboot.
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Run a packaged image with an ARM module in single-CPU x86 QEMU.
    Run(Run),
}

#[derive(Args)]
pub struct Run {
    /// Packaged image; defaults to a fresh release build.
    #[arg(long)]
    image: Option<PathBuf>,
    /// Original ARM bytes loaded as the Multiboot module.
    #[arg(long)]
    module: PathBuf,
    /// Fresh directory for the serial log and run report.
    #[arg(long)]
    output: PathBuf,
    /// Mount options, for example `--entry 0x100000 --budget 1000`.
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    append: String,
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
            let image = build(release)?;
            println!("{}", image.display());
            Ok(ExitCode::SUCCESS)
        }
        Command::Run(arguments) => launch(arguments),
    }
}

fn profile_directory(release: bool) -> PathBuf {
    let profile = if release { "release" } else { "debug" };
    root().join(BOOT_TARGET_DIR).join(BOOT_TARGET).join(profile)
}

fn build(release: bool) -> Result<PathBuf> {
    let mut command = cargo();
    command.args(["build", "--locked", "--manifest-path", BOOT_MANIFEST]);
    command.args(["--target", BOOT_TARGET, "--target-dir", BOOT_TARGET_DIR]);
    if release {
        command.arg("--release");
    }
    exec(&mut command)?;
    let directory = profile_directory(release);
    package(&directory.join("stela-boot"), &directory)
}

/// Copy the initialized bytes of the linked ELF into a flat Multiboot image.
///
/// QEMU's Multiboot loader uses the header's address fields, so the loadable
/// segments must form one identity-mapped file range followed only by BSS.
fn package(elf: &Path, output: &Path) -> Result<PathBuf> {
    let raw = fs::read(elf).with_context(|| format!("cannot read {}", elf.display()))?;
    let file = ElfFile64::<Endianness>::parse(&*raw)?;
    let endian = file.endian();
    let symbol = |name: &str| {
        file.symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .map(|symbol| symbol.address())
            .with_context(|| format!("missing linker symbol {name}"))
    };
    let start = symbol("__image_start")?;
    let load_end = symbol("__load_end")?;
    let image_end = symbol("__image_end")?;
    let header_address = symbol("stela_multiboot_header")?;
    let entry = symbol("stela_start32")?;

    let loads: Vec<_> = file
        .elf_program_headers()
        .iter()
        .filter(|header| header.p_type(endian) == PT_LOAD)
        .map(|header| {
            (
                header.p_offset(endian),
                header.p_vaddr(endian),
                header.p_paddr(endian),
                header.p_filesz(endian),
                header.p_memsz(endian),
            )
        })
        .collect();
    let (first_offset, ..) = *loads.first().context("ELF has no loadable segment")?;
    let bias = start - first_offset;
    let mut previous = start;
    for &(offset, virtual_address, physical, file_bytes, memory_bytes) in &loads {
        ensure!(
            virtual_address == physical && physical >= previous,
            "segments must be identity-mapped and ordered"
        );
        ensure!(
            file_bytes <= memory_bytes && offset + file_bytes <= raw.len() as u64,
            "segment exceeds its file"
        );
        if file_bytes != 0 {
            ensure!(
                physical - offset == bias,
                "initialized segments are not one file range"
            );
            ensure!(
                physical + file_bytes <= load_end,
                "initialized segment past __load_end"
            );
        }
        previous = physical + memory_bytes;
    }
    ensure!(
        start < load_end && load_end <= image_end && image_end < IDENTITY_LIMIT,
        "image does not fit the identity window"
    );
    ensure!(previous == image_end, "BSS does not end at __image_end");

    let image = &raw[(start - bias) as usize..(load_end - bias) as usize];
    let header_offset = (header_address - start) as usize;
    ensure!(
        header_offset.is_multiple_of(4)
            && header_offset + MULTIBOOT_HEADER_WORDS * 4
                <= image.len().min(MULTIBOOT_SEARCH_BYTES),
        "Multiboot header must be aligned within the first 8 KiB"
    );
    let header: Vec<u32> = image[header_offset..][..MULTIBOOT_HEADER_WORDS * 4]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&word| u32::from_le_bytes(word))
        .collect();
    let address_fields: Vec<u64> = header[3..].iter().map(|&word| word.into()).collect();
    ensure!(
        header[0] == MULTIBOOT_MAGIC
            && header[1] == MULTIBOOT_FLAGS
            && header[..3]
                .iter()
                .fold(0u32, |sum, &word| sum.wrapping_add(word))
                == 0
            && address_fields == [header_address, start, load_end, image_end, entry],
        "Multiboot header does not match the linked layout"
    );

    let flat = output.join(IMAGE);
    fs::write(&flat, image)?;
    let report = json!({
        "elf": { "path": elf, "bytes": raw.len(), "sha256": sha256(&raw) },
        "image": { "path": flat, "bytes": image.len(), "sha256": sha256(image) },
        "symbols": BTreeMap::from([
            ("__image_start", start), ("__load_end", load_end), ("__image_end", image_end),
            ("stela_multiboot_header", header_address), ("stela_start32", entry),
        ]),
        "bss_bytes": image_end - load_end,
    });
    fs::write(output.join("image.json"), format!("{report:#}\n"))?;
    Ok(flat)
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
    fs::create_dir_all(&output)?;
    let serial = output.join("serial.txt");
    let qemu = qemu()?;

    let mut command = Process::new(&qemu);
    command
        .args([
            "-machine",
            "q35,smm=off,sata=off,usb=off,smbus=off,hpet=off,i8042=off,vmport=off",
        ])
        .args([
            "-accel",
            "tcg,thread=single",
            "-cpu",
            "qemu64",
            "-smp",
            "1",
            "-m",
            "1G",
        ])
        .args([
            "-nodefaults",
            "-no-reboot",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=4",
        ])
        .arg("-kernel")
        .arg(&image)
        .arg("-initrd")
        .arg(&arguments.module)
        .args(["-append", &arguments.append]);
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
        None => command.args(["-monitor", "none"]),
    };
    if let Some(port) = arguments.gdb {
        command
            .arg("-gdb")
            .arg(format!("tcp:127.0.0.1:{port}"))
            .arg("-S");
        eprintln!(
            "paused: gdb {} -ex 'target remote 127.0.0.1:{port}'",
            image.with_file_name("stela-boot").display()
        );
    }
    let command_line: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();

    let started = Instant::now();
    let mut child = command
        .stdout(fs::File::create(output.join("stdout.txt"))?)
        .stderr(fs::File::create(output.join("stderr.txt"))?)
        .stdin(Stdio::null())
        .spawn()?;
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
        "module": binding(&arguments.module)?,
        "returncode": code,
        "timed_out": status.is_none(),
        "wall_seconds": started.elapsed().as_secs_f64(),
        "outputs": outputs,
    });
    fs::write(output.join("run.json"), format!("{report:#}\n"))?;
    println!("{report:#}");
    Ok(ExitCode::from(code))
}
