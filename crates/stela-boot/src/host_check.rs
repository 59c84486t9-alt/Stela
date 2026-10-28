//! `--host-check`: a report on the PC Stela runs on, with no system mode
//! (so no LA57) and no write to any internal disk.
//!
//! `stela.cfg`: `--host-check [--nor-file GUID:/PATH] [--deadline SECONDS]
//! [--key-seconds SECONDS]`.
//!
//! Each check ends with a `CHECK name PASS|FAIL|SKIP detail` line:
//!
//! - `cpu`, `tsc`, before ExitBootServices: the CPUID report and the
//!   x86-64-v2 floor; the TSC measured against the firmware's stall.
//! - `storage`, `gpt`: every disk the PC storage drivers bring up, and the
//!   GPT of each, read only, with every partition's unique GUID, name and
//!   size.
//! - `log`: with `--nor-file`, the persistent boot log in a preallocated
//!   file on a USB disk's FAT32 volume, laid out as a machine-state
//!   partition (`pc::boot_log`); `stela boot-log FILE --offset 0` reads it.
//!   Only that file's blocks are written, and only on a USB disk.
//! - `apic`, `interrupts`: the local APIC timer measured against the TSC,
//!   then one one-shot and 100 ms of periodic interrupts through the IDT's
//!   interrupt stacks.
//! - `display`, `keyboard`, `display-seen`: colour bars in the GOP
//!   framebuffer's bottom band, read back; then a USB keyboard key, which
//!   also answers whether the bars are visible.
//!
//! `HOST CHECK END` and the summary follow, all flushed to the log; then a
//! key restarts the machine (back to the boot manager), the power button
//! powers it off, and `--deadline` (counted from the start) stops it with
//! `STELA STOPPED`. Every wait prints `BEAT` every 10 s and flushes the log;
//! a fatal error, panic or x86 exception flushes it too (`output`).
use crate::{
    apic::{self, Apic, rdtsc},
    console::{self, Framebuffer},
    cpu,
    engine::{
        bundle::Bytes,
        interrupts::{self, Frame, SPURIOUS_VECTOR, TIMER_VECTOR},
        nor,
        power::HostPowerControl,
    },
    firmware, output,
    paging::{self, PAGE},
    storage,
};
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{
    arch::asm,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_drivers::{
    Handoff,
    block::{BlockDevice, Shared, Transport},
    bus::dma::RegionAllocator,
    input::Input,
    probe::probe,
    usb::hid::UsbInput,
};
use stela_runtime::pc::{
    self, boot_log,
    fat32::Fat32,
    gpt::{self, Guid},
    power::HostPower,
};
use uefi::boot;

pub const OPTION: &[u8] = b"--host-check";
const DEFAULT_KEY_SECONDS: u64 = 60;
const BEAT_SECONDS: u64 = 10;
/// The stop code at `--deadline`.
const DEADLINE_CODE: u32 = 0x10;
const MILLISECONDS: u64 = 1000;
const MICROSECONDS: u64 = 1_000_000;
/// The one-shot interrupt comes after 10 ms.
const ONE_SHOT_MILLISECONDS: u64 = 10;
/// The periodic interrupts run at 1 kHz for 100 ms.
const PERIODIC_HZ: u64 = 1000;
const PERIODIC_MILLISECONDS: u64 = 100;
const TOLERANCE_PERCENT: u64 = 10;
/// IA32_APIC_BASE bit 11: the APIC is enabled.
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
/// The bars take the bottom 1/BAND_FRACTION of the screen.
const BAND_FRACTION: usize = 8;
/// SMPTE-style bars, left to right.
const BARS: [(u8, u8, u8); 7] = [
    (0xff, 0xff, 0xff),
    (0xff, 0xff, 0x00),
    (0x00, 0xff, 0xff),
    (0x00, 0xff, 0x00),
    (0xff, 0x00, 0xff),
    (0xff, 0x00, 0x00),
    (0x00, 0x00, 0xff),
];
/// HID Keyboard/Keypad usages (HID Usage Tables, chapter 10).
const USAGE_N: u8 = 0x11;
const USAGE_Y: u8 = 0x1c;
/// LeftControl through Right GUI, which never answer a prompt alone.
const MODIFIERS: core::ops::RangeInclusive<u8> = 0xe0..=0xe7;

/// Timer interrupts the handler took, and other interrupts.
static TICKS: AtomicU64 = AtomicU64::new(0);
static STRAY: AtomicU64 = AtomicU64::new(0);
/// IA32_APIC_BASE, for the handler's EOI; the xAPIC page is identity-mapped.
static APIC_BASE: AtomicU64 = AtomicU64::new(0);

struct Options {
    native_dma_check: bool,
    native_work_check: bool,
    native_irq_work_check: bool,
    native_dma_isolation_check: bool,
    nor_file: Option<(Guid, String)>,
    deadline: Option<u64>,
    key_seconds: u64,
}

fn seconds(value: Option<&str>) -> Result<u64, &'static str> {
    value
        .and_then(|value| value.parse().ok())
        .filter(|&seconds| seconds > 0)
        .ok_or("host check: a time option takes a positive number of seconds")
}

impl Options {
    fn parse(text: &str) -> Result<Self, &'static str> {
        let mut words = text.split_ascii_whitespace();
        if words.next().map(str::as_bytes) != Some(OPTION) {
            return Err("host check: stela.cfg must start with --host-check");
        }
        let mut options = Self {
            native_dma_check: false,
            native_work_check: false,
            native_irq_work_check: false,
            native_dma_isolation_check: false,
            nor_file: None,
            deadline: None,
            key_seconds: DEFAULT_KEY_SECONDS,
        };
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
    Skip,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        })
    }
}

struct Check {
    name: &'static str,
    verdict: Verdict,
    detail: String,
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CHECK {} {} {}", self.name, self.verdict, self.detail)
    }
}

/// The TSC rate, the beats and the deadline every wait shares.
struct Timing {
    tsc_hz: u64,
    started: u64,
    next_beat: u64,
    deadline: Option<u64>,
}

impl Timing {
    fn elapsed_seconds(&self) -> u64 {
        (rdtsc() - self.started) / self.tsc_hz
    }

    /// Print a beat when one is due and stop at the deadline.
    fn tick(&mut self) {
        let now = rdtsc();
        if now >= self.next_beat {
            self.next_beat = now + BEAT_SECONDS * self.tsc_hz;
            output::arguments(format_args!("BEAT t={}s\n", self.elapsed_seconds()));
            output::flush_log();
        }
        if let Some(deadline) = self.deadline
            && now >= deadline
        {
            output::arguments(format_args!(
                "HOST CHECK deadline reached after {}s\n",
                self.elapsed_seconds()
            ));
            output::terminate(DEADLINE_CODE)
        }
    }
}

/// What the check takes from the firmware, handed to [`run`].
struct Machine {
    native_dma: Option<crate::native_dma::diagnostic::Prepared>,
    native_work: Option<crate::native_work_check::Prepared>,
    options: Options,
    timing: Timing,
    screen: Option<Framebuffer>,
    storage: Option<Handoff>,
    power: Option<HostPower>,
    apic_base: u64,
    stack_top: usize,
    checks: Vec<Check>,
}

impl Machine {
    fn record(&mut self, name: &'static str, verdict: Verdict, detail: String) {
        let check = Check {
            name,
            verdict,
            detail,
        };
        output::arguments(format_args!("{check}\n"));
        output::flush_log();
        self.checks.push(check);
    }
}

/// Run the host check from `stela.cfg`'s `options`; never returns.
pub fn boot(options: Vec<u8>) -> ! {
    let (mut machine, tables) = prepare(&options).unwrap_or_else(|error| output::fatal(error));
    let stack = machine.stack_top;
    // SAFETY: boot services have ended; the tables map the image, the heap,
    // the stack, every RAM byte in use, the framebuffer and the registers
    // the drivers and the APIC use.
    unsafe {
        asm!("cli", options(nomem, nostack));
        if let Err(error) = paging::activate(tables) {
            output::fatal(error);
        }
        asm!(
            "mov rsp, {top}",
            "call {run}",
            "ud2",
            top = in(reg) stack,
            run = sym run,
            in("rdi") &raw mut machine,
            options(noreturn),
        )
    }
}

/// Before ExitBootServices: the options, the CPU and TSC checks, and what
/// the rest needs from the firmware; then leave boot services.
fn prepare(options: &[u8]) -> Result<(Machine, paging::Tables), &'static str> {
    let text = core::str::from_utf8(options).map_err(|_| "stela.cfg is not UTF-8")?;
    let options = Options::parse(text)?;
    let started = rdtsc();
    output::arguments(format_args!("HOST CHECK {}\n", text.trim()));
    for line in cpu::report() {
        output::arguments(format_args!("CPU {line}\n"));
    }
    let tsc_hz = crate::firmware::tsc_hz();
    let mut machine = Machine {
        native_dma: None,
        native_work: None,
        timing: Timing {
            tsc_hz,
            started,
            next_beat: started,
            deadline: options.deadline.map(|seconds| started + seconds * tsc_hz),
        },
        options,
        screen: Framebuffer::from_firmware(),
        storage: None,
        power: crate::system::host_power(),
        apic_base: apic::base_msr(),
        stack_top: 0,
        checks: Vec::new(),
    };
    let missing = cpu::missing_floor();
    machine.record(
        "cpu",
        if missing.is_empty() {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        format!(
            "x86-64-v{} floor_missing={missing:?} la57={}",
            cpu::level(),
            cpu::LA57.present()
        ),
    );
    machine.record(
        "tsc",
        Verdict::Pass,
        format!(
            "hz={tsc_hz} invariant={} source={:?}",
            cpu::INVARIANT_TSC.present(),
            crate::firmware::tsc_source()
        ),
    );
    match storage::discover() {
        Ok(handoff) => machine.storage = Some(handoff),
        Err(error) => machine.record("storage", Verdict::Fail, format!("no PCI access: {error}")),
    }
    if machine.options.native_dma_check
        || machine.options.native_dma_isolation_check
        || machine.options.native_irq_work_check
    {
        let handoff = machine
            .storage
            .as_ref()
            .ok_or("native DMA fixture needs PCI discovery")?;
        let prepared = {
            // SAFETY: no firmware callback may access PCI while BAR sizing
            // temporarily disables decoding; restored before any service call.
            let _tpl = unsafe { boot::raise_tpl(uefi::boot::Tpl::HIGH_LEVEL) };
            crate::native_dma::diagnostic::Prepared::prepare(
                handoff,
                machine.options.native_dma_isolation_check,
            )
        };
        match prepared {
            Ok(prepared) => machine.native_dma = Some(prepared),
            Err(error) => {
                machine.record("native-dma", Verdict::Fail, error);
                return Err("native DMA fixture preparation failed");
            }
        }
    }
    if machine.options.native_work_check || machine.options.native_irq_work_check {
        let clock = machine
            .storage
            .as_ref()
            .ok_or("native work proof needs native clock")?
            .clock;
        machine.native_work = Some(crate::native_work_check::Prepared::prepare(clock)?);
    }
    let guard = firmware::pages(firmware::STACK_PAGES + 1)?;
    machine.stack_top = guard + (firmware::STACK_PAGES + 1) * PAGE;
    let image = firmware::Image::loaded()?;
    let work_arenas: Vec<_> = machine.native_work.iter().map(|p| p.arena()).collect();
    let mut tables = firmware::tables(&image, [0, guard], &work_arenas, machine.screen.as_ref())?;
    if let Some(prepared) = &machine.native_work {
        prepared.map(&mut tables)?;
    }
    for range in machine.storage.iter().flat_map(|handoff| &handoff.mapped) {
        tables.device(range.start as usize, range.end as usize)?;
    }
    if let Some(prepared) = &machine.native_dma {
        for range in prepared.mappings() {
            tables.device(range.start as usize, range.end as usize)?;
        }
    }
    let registers = (machine.apic_base & apic::BASE_ADDRESS) as usize;
    tables.device(registers, registers + PAGE)?;
    crate::output::leave_boot_services();
    // SAFETY: no protocol or pool allocation outlives this call; the heap,
    // stack and tables are LOADER_DATA, which Stela keeps.
    let map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(map);
    Ok((machine, tables))
}

/// The checks after ExitBootServices, on Stela's own stack and tables.
extern "sysv64" fn run(machine: &mut Machine) -> ! {
    let band = machine.screen.map(|screen| {
        let height = screen.resolution().1;
        let top = height - height / BAND_FRACTION;
        output::raw_screen();
        console::install(screen.top(top));
        top
    });
    output::arguments(format_args!("STELA HOST CHECK\n"));
    // SAFETY: interrupts are disabled and nothing else uses the tables.
    unsafe { interrupts::install(interrupt) };
    APIC_BASE.store(machine.apic_base, Ordering::Relaxed);
    if let Some(prepared) = machine.native_dma.take() {
        let result = if machine.options.native_irq_work_check {
            match machine.native_work.take() {
                Some(work) => prepared.run_irq_work(work),
                None => Err(String::from("IRQ work stacks missing")),
            }
        } else {
            prepared.run()
        };
        match result {
            Ok(crate::native_dma::diagnostic::Report::IrqWork(proof)) => {
                machine.record("native-irq-work", Verdict::Pass, proof);
            }
            Ok(crate::native_dma::diagnostic::Report::Single(dma, irq)) => {
                machine.record("native-dma", Verdict::Pass, dma);
                machine.record("native-irq", Verdict::Pass, irq);
            }
            Ok(crate::native_dma::diagnostic::Report::Isolation(proof)) => {
                machine.record("native-dma-isolation", Verdict::Pass, proof);
            }
            Err(error) => {
                machine.record(
                    if machine.options.native_irq_work_check {
                        "native-irq-work"
                    } else {
                        "native-dma"
                    },
                    Verdict::Fail,
                    error,
                );
                // The unit/requester may be in an uncertain DMA state. Unit
                // and lease Drop retained its resources; do not resume probe.
                output::fatal("native DMA fixture failed; normal probing inhibited");
            }
        }
    }
    if let Some(prepared) = machine.native_work.take() {
        match prepared.run() {
            Ok(proof) => machine.record("native-work", Verdict::Pass, proof),
            Err(error) => {
                machine.record("native-work", Verdict::Fail, error);
                output::fatal("native work failed; pending contexts retained");
            }
        }
    }
    match crate::native_memory::verify() {
        Ok(()) => machine.record(
            "native-memory",
            Verdict::Pass,
            String::from("WB native pages: zero/read/write, CPU pin lifetime/reclaim, cache/alignment/bounds refusal; Linux PFN/refcount/compound/split/retirement"),
        ),
        Err(error) => machine.record("native-memory", Verdict::Fail, format!("{error:?}")),
    }
    let mut keyboards = match machine.storage.take() {
        Some(handoff) => disks(machine, &handoff),
        None => Vec::new(),
    };
    timer(machine);
    match (machine.screen, band) {
        (Some(screen), Some(top)) => bars(machine, &screen, top),
        _ => machine.record(
            "display",
            Verdict::Fail,
            String::from("the firmware has no 32-bit GOP framebuffer"),
        ),
    }
    keyboard(machine, &mut keyboards);
    finish(machine, &mut keyboards)
}

/// The storage, GPT and log checks; returns the USB keyboards.
fn disks(machine: &mut Machine, handoff: &Handoff) -> Vec<UsbInput> {
    // SAFETY: one CPU after ExitBootServices; `dma` was reserved for this.
    let mut dma = unsafe { RegionAllocator::new(handoff.dma.clone()) };
    // SAFETY: this handoff describes the running machine and its tables.
    let mut disks = unsafe { probe(handoff, &mut dma) };
    for window in &disks.unmapped {
        output::arguments(format_args!("STORAGE UNMAPPED ecam={window:x?}\n"));
    }
    for (address, error) in &disks.failures {
        output::arguments(format_args!("STORAGE FAILED pci={address} error={error}\n"));
    }
    for (address, class, why) in &disks.unsupported {
        output::arguments(format_args!(
            "HOST UNSUPPORTED pci={address} class={:02x}{:02x}{:02x}: {why}\n",
            class[0], class[1], class[2]
        ));
    }
    for (location, error) in &disks.device_failures {
        output::arguments(format_args!("STORAGE FAILED {location}: {error}\n"));
    }
    for (location, error) in &disks.usb_failures {
        output::arguments(format_args!(
            "USB FAILED {location}: {}\n",
            stela_drivers::usb::xhci::explain(error)
        ));
    }
    for (location, why) in &disks.usb_unused {
        output::arguments(format_args!("USB UNUSED {location}: {why}\n"));
    }
    for device in &disks.usb_inputs {
        output::arguments(format_args!("USB INPUT {}\n", device.name));
    }
    let failures = disks.failures.len() + disks.device_failures.len() + disks.usb_failures.len();
    machine.record(
        "storage",
        if disks.devices.is_empty() || failures > 0 {
            Verdict::Fail
        } else {
            Verdict::Pass
        },
        format!(
            "disks={} usb_inputs={} failures={failures}",
            disks.devices.len(),
            disks.usb_inputs.len()
        ),
    );
    let (mut internal, mut tables) = (0, 0);
    for device in &mut disks.devices {
        let id = device.identity().clone();
        output::arguments(format_args!(
            "DISK {:?} at {} serial={:?} model={:?} blocks={} block_size={} bytes={}\n",
            id.transport,
            id.location,
            id.serial,
            id.model,
            id.blocks,
            id.block_size,
            id.bytes()
        ));
        let is_internal = matches!(id.transport, Transport::Nvme | Transport::Ahci);
        internal += usize::from(is_internal);
        match gpt::read(&mut **device) {
            Ok(table) => {
                tables += usize::from(is_internal);
                output::arguments(format_args!(
                    "  GPT disk={} partitions={}\n",
                    table.disk,
                    table.partitions.len()
                ));
                for (index, partition) in table.partitions.iter().enumerate() {
                    output::arguments(format_args!(
                        "  PARTITION #{} unique={} type={} name={:?} first_lba={} bytes={}\n",
                        index + 1,
                        partition.unique,
                        partition.kind,
                        partition.name,
                        partition.first_lba,
                        partition.blocks() * u64::from(id.block_size)
                    ));
                }
            }
            Err(error) => output::arguments(format_args!("  GPT none: {error}\n")),
        }
    }
    machine.record(
        "gpt",
        if internal > 0 && tables == internal {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        format!("internal NVMe/AHCI disks={internal} with a GPT={tables} (read only)"),
    );
    match machine.options.nor_file.clone() {
        Some((guid, path)) => {
            let (verdict, detail) = match open_log(&mut disks.devices, guid, &path) {
                Ok(detail) => (Verdict::Pass, detail),
                Err(error) => (Verdict::Fail, error),
            };
            machine.record("log", verdict, detail);
        }
        None => machine.record("log", Verdict::Skip, String::from("no --nor-file")),
    }
    core::mem::take(&mut disks.usb_inputs)
}

/// Keep the output in the file at `path` on USB partition `guid`.
fn open_log(
    devices: &mut Vec<Box<dyn BlockDevice>>,
    guid: Guid,
    path: &str,
) -> Result<String, String> {
    let partition = pc::storage::open_unique(devices, guid)
        .map_err(|error| format!("partition {guid}: {error}"))?;
    let transport = partition.disk().transport;
    if transport != Transport::Usb {
        return Err(format!(
            "partition {guid} is on a {transport:?} disk: the host check writes only USB disks"
        ));
    }
    let block = u64::from(partition.identity().block_size);
    let mut volume =
        Fat32::open(Bytes::new(partition)).map_err(|error| format!("partition {guid}: {error}"))?;
    let file = volume
        .file(path)
        .map_err(|error| format!("partition {guid}: {error}"))?;
    let runs = boot_log::file_runs(&file, block, boot_log::PARTITION_BYTES)
        .map_err(|error| format!("{path}: {error}"))?;
    let pieces = runs.len();
    let partition = volume.into_inner().into_inner();
    let file = Shared::new(Box::new(partition))
        .runs(runs)
        .map_err(|error| format!("{path}: {error}"))?;
    let blocks = file.identity().blocks;
    if !nor::open_log(&Shared::new(Box::new(file)), block, blocks * block) {
        return Err(format!("{path}: the boot log could not be opened"));
    }
    Ok(format!(
        "{path} on partition {guid}: {blocks} blocks of {block} bytes in {pieces} runs"
    ))
}

/// The APIC timer's rate, then a one-shot and periodic interrupts.
fn timer(machine: &mut Machine) {
    let base = machine.apic_base;
    if base & APIC_GLOBAL_ENABLE == 0 {
        machine.record(
            "apic",
            Verdict::Fail,
            format!("IA32_APIC_BASE={base:#x}: the firmware left the APIC disabled"),
        );
        machine.record("interrupts", Verdict::Skip, String::from("no APIC"));
        return;
    }
    APIC_BASE.store(base, Ordering::Relaxed);
    let apic = Apic::new(base, base & apic::BASE_ADDRESS);
    let tsc_hz = machine.timing.tsc_hz;
    let hz = apic.start(SPURIOUS_VECTOR, TIMER_VECTOR, tsc_hz);
    machine.record(
        "apic",
        if hz > 0 { Verdict::Pass } else { Verdict::Fail },
        format!(
            "mode={} base={base:#x} timer_hz={hz} arat={} tsc_deadline={}",
            if apic.is_x2apic() { "x2APIC" } else { "xAPIC" },
            cpu::ARAT.present(),
            cpu::TSC_DEADLINE.present()
        ),
    );
    if hz == 0 {
        machine.record("interrupts", Verdict::Skip, String::from("no APIC timer"));
        return;
    }
    let ticks = |count: u64| (count.clamp(1, u64::from(u32::MAX))) as u32;
    // One one-shot interrupt, given ten times its delay.
    TICKS.store(0, Ordering::Relaxed);
    apic.write(apic::LVT_TIMER, u32::from(TIMER_VECTOR));
    apic.write(
        apic::INITIAL,
        ticks(hz * ONE_SHOT_MILLISECONDS / MILLISECONDS),
    );
    let one_shot = enabled(tsc_hz * ONE_SHOT_MILLISECONDS * 10 / MILLISECONDS, || {
        TICKS.load(Ordering::Relaxed) > 0
    });
    let one_shot_us = one_shot * MICROSECONDS / tsc_hz;
    let one_shot_ticks = TICKS.load(Ordering::Relaxed);
    // Periodic interrupts for a fixed time.
    TICKS.store(0, Ordering::Relaxed);
    apic.write(
        apic::LVT_TIMER,
        apic::TIMER_PERIODIC | u32::from(TIMER_VECTOR),
    );
    apic.write(apic::INITIAL, ticks(hz / PERIODIC_HZ));
    enabled(tsc_hz * PERIODIC_MILLISECONDS / MILLISECONDS, || false);
    apic.write(apic::INITIAL, 0);
    apic.write(apic::LVT_TIMER, apic::LVT_MASKED | u32::from(TIMER_VECTOR));
    let periodic = TICKS.load(Ordering::Relaxed);
    let within =
        |value: u64, expected: u64| value.abs_diff(expected) * 100 <= expected * TOLERANCE_PERCENT;
    let expected_us = ONE_SHOT_MILLISECONDS * MILLISECONDS;
    let expected = PERIODIC_HZ * PERIODIC_MILLISECONDS / MILLISECONDS;
    machine.record(
        "interrupts",
        if one_shot_ticks == 1 && within(one_shot_us, expected_us) && within(periodic, expected) {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        format!(
            "one_shot={one_shot_ticks} after {one_shot_us} us (expected 1 after {expected_us}) \
             periodic={periodic} in {PERIODIC_MILLISECONDS} ms (expected {expected}) stray={}",
            STRAY.load(Ordering::Relaxed)
        ),
    );
}

/// Spin with interrupts enabled until `done` or `ticks` TSC ticks pass;
/// returns the ticks spent.
fn enabled(ticks: u64, mut done: impl FnMut() -> bool) -> u64 {
    let start = rdtsc();
    // SAFETY: the IDT is installed and every enabled source is handled.
    unsafe { asm!("sti", options(nomem, nostack)) };
    while !done() && rdtsc() - start < ticks {
        core::hint::spin_loop();
    }
    // SAFETY: as above.
    unsafe { asm!("cli", options(nomem, nostack)) };
    rdtsc() - start
}

extern "sysv64" fn interrupt(frame: &mut Frame) {
    // SAFETY: unchanged IDT/IST entry supplies this actual hardware frame.
    if unsafe { crate::native_irq::dispatch_frame(frame.vector as u8, frame.rsp as usize) } {
        return;
    }
    let eoi = || {
        let base = APIC_BASE.load(Ordering::Relaxed);
        Apic::new(base, base & apic::BASE_ADDRESS).eoi();
    };
    match frame.vector as u8 {
        TIMER_VECTOR => {
            TICKS.fetch_add(1, Ordering::Relaxed);
            eoi();
        }
        SPURIOUS_VECTOR => {}
        32.. => {
            STRAY.fetch_add(1, Ordering::Relaxed);
            eoi();
        }
        _ => {
            interrupts::report(frame);
            output::fatal("unexpected x86 exception in the host check")
        }
    }
}

/// Colour bars in the band below the console, read back.
fn bars(machine: &mut Machine, screen: &Framebuffer, top: usize) {
    let (width, height) = screen.resolution();
    let bar = width / BARS.len();
    let middle = (top + height) / 2;
    let mut mismatches = 0;
    for (index, &(red, green, blue)) in BARS.iter().enumerate() {
        let value = screen.rgb(red, green, blue);
        screen.rectangle(index * bar, top, bar, height - top, value);
        let read = screen.read(index * bar + bar / 2, middle);
        if read & 0x00ff_ffff != value {
            output::arguments(format_args!(
                "DISPLAY bar {index} wrote {value:#08x} read {read:#08x}\n"
            ));
            mismatches += 1;
        }
    }
    machine.record(
        "display",
        if mismatches == 0 {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        format!(
            "{width}x{height} stride={} {} base={:#x} bytes={:#x} bars={} read_back_mismatches={mismatches}",
            screen.stride(),
            screen.format(),
            screen.base,
            screen.bytes,
            BARS.len()
        ),
    );
}

/// The first non-modifier key pressed on any of `keyboards`, logged with
/// the raw report it arrived in.
fn key(keyboards: &mut [UsbInput]) -> Option<u8> {
    keyboards.iter_mut().find_map(|device| {
        let usage = device.poll().into_iter().find_map(|input| match input {
            Input::Key {
                usage,
                pressed: true,
            } if !MODIFIERS.contains(&usage) => Some(usage),
            _ => None,
        })?;
        output::arguments(format_args!(
            "KEY usage={usage:#04x} report={:02x?} from {}\n",
            device.last_report(),
            device.name
        ));
        Some(usage)
    })
}

/// A key within `--key-seconds`, which also says whether the bars show.
fn keyboard(machine: &mut Machine, keyboards: &mut [UsbInput]) {
    if keyboards.is_empty() {
        machine.record(
            "keyboard",
            Verdict::Fail,
            String::from("no USB HID device was brought up"),
        );
        machine.record("display-seen", Verdict::Skip, String::from("no keyboard"));
        return;
    }
    let seconds = machine.options.key_seconds;
    output::arguments(format_args!(
        "\n>>> Press Y on the USB keyboard if the bottom of the screen shows seven colour bars \
         (white yellow cyan green magenta red blue), N if it does not. Waiting {seconds} s.\n"
    ));
    output::flush_log();
    let end = rdtsc() + seconds * machine.timing.tsc_hz;
    let pressed = loop {
        machine.timing.tick();
        if let Some(usage) = key(keyboards) {
            break Some(usage);
        }
        if rdtsc() >= end {
            break None;
        }
        core::hint::spin_loop();
    };
    let Some(usage) = pressed else {
        machine.record(
            "keyboard",
            Verdict::Fail,
            format!("no key pressed in {seconds} s"),
        );
        machine.record("display-seen", Verdict::Skip, String::from("no key"));
        return;
    };
    machine.record("keyboard", Verdict::Pass, format!("usage={usage:#04x}"));
    let (verdict, detail) = match usage {
        USAGE_Y => (Verdict::Pass, "the user saw the bars"),
        USAGE_N => (Verdict::Fail, "the user did not see the bars"),
        _ => (Verdict::Skip, "the key was neither Y nor N"),
    };
    machine.record("display-seen", verdict, String::from(detail));
}

/// The summary, then a restart, a power-off or the deadline.
fn finish(machine: &mut Machine, keyboards: &mut [UsbInput]) -> ! {
    output::arguments(format_args!("\nHOST CHECK SUMMARY\n"));
    for check in &machine.checks {
        output::arguments(format_args!("{check}\n"));
    }
    let count = |verdict| {
        machine
            .checks
            .iter()
            .filter(|check| check.verdict == verdict)
            .count()
    };
    output::arguments(format_args!(
        "HOST CHECK END pass={} fail={} skip={}\n",
        count(Verdict::Pass),
        count(Verdict::Fail),
        count(Verdict::Skip)
    ));
    output::flush_log();
    // The host check keeps the firmware's tables, which map no runtime
    // services for a firmware power-off.
    let mut power = HostPowerControl::new(
        machine.power,
        None,
        None,
        machine.timing.tsc_hz,
        crate::engine::storage::HostDisks::none(),
    );
    output::arguments(format_args!(
        "\n>>> The log is saved; powering off is safe now. Press a key to restart, or press the \
         power button (or hold it 4 s) to power off.\n"
    ));
    output::flush_log();
    // Keys held from the last prompt do not count.
    key(keyboards);
    loop {
        machine.timing.tick();
        if key(keyboards).is_some() {
            power.restart();
        }
        if power.pressed() {
            power.power_off();
        }
        core::hint::spin_loop();
    }
}
