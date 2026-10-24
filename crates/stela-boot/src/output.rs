//! The mount's detailed output: every line goes to the UART and, from the
//! very first line, into a bounded record for the persistent boot logs
//! (`pc::boot_log`): the USB's `EFI/stela/boot.log` ([`crate::log_file`])
//! and the machine state's, once `--nor` opens it. [`add_log`] adds one,
//! which starts with everything the record still holds, and [`flush_log`]
//! stores what each has not: at every step, between engine slices and at
//! every stop, which [`terminate`] reaches. The screen shows the curated
//! steps of [`status`](crate::status) instead, and a fatal error or panic, which
//! reach it before the console exists through the firmware's.
use crate::{console, serial::Serial};
use alloc::{boxed::Box, vec::Vec};
use core::{
    arch::asm,
    cell::RefCell,
    convert::Infallible,
    fmt::{self, Write},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_drivers::block::{BlockDevice, BlockError};
use stela_runtime::pc::boot_log::{PENDING_BYTES, Pending, Unkept, Writer};

/// `isa-debug-exit` under QEMU; an unused port on a PC.
const EXIT_PORT: u16 = 0xf4;

/// One engine-wide value. The mount runs on one processor and its handlers
/// only print; every access is a `try_borrow`, so output that arrives while
/// the value is in use (a line printed during a flush) is skipped instead of
/// re-entering it.
pub(crate) struct Global<T>(pub(crate) RefCell<T>);
// SAFETY: one processor runs the mount, and no access blocks or assumes
// the value is free.
unsafe impl<T> Sync for Global<T> {}

/// The newest output bytes since the first line, which every log reads
/// from its own position.
static RECORD: Global<Pending<[u8; PENDING_BYTES]>> =
    Global(RefCell::new(Pending::new([0; PENDING_BYTES])));

/// An open log, the blocks that hold it and its position in the record.
struct Sink {
    writer: Writer,
    device: Box<dyn BlockDevice>,
    kind: Log,
    stored: u64,
}

/// What a log is kept for, which decides what its failure does.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Log {
    /// The machine state's: a failed store stops the machine.
    Machine,
    /// The USB's file through the firmware, closed as boot services end.
    Firmware,
    /// The USB's file through Stela's drivers.
    Usb,
}

static SINKS: Global<Vec<Sink>> = Global(RefCell::new(Vec::new()));
/// A flush is running: a fatal or panic raised inside it halts without
/// flushing again.
static FLUSHING: AtomicBool = AtomicBool::new(false);
/// Boot services still run, so the firmware's console can show a fatal
/// error before Stela's own console takes the screen.
static FIRMWARE_CONSOLE: AtomicBool = AtomicBool::new(true);
/// `--host-check` shows its report itself, so every line reaches the screen.
static RAW_SCREEN: AtomicBool = AtomicBool::new(false);
/// The time-stamp counter's rate, once known, which stamps each line the
/// logs keep with the seconds since the PC started.
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// The record's next byte starts a line.
static LINE_START: AtomicBool = AtomicBool::new(true);

/// Stamp the logs' lines from now on with the time from the counter running
/// at `tsc_hz`.
pub fn set_clock(tsc_hz: u64) {
    TSC_HZ.store(tsc_hz, Ordering::Relaxed);
}

/// `[  12.345] `: the seconds since the PC started, as the kernel's own
/// lines show them; nothing before the counter's rate is known.
fn stamp(record: &mut Pending<[u8; PENDING_BYTES]>) {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz == 0 {
        return;
    }
    // SAFETY: RDTSC has no memory effects.
    let millis = unsafe { core::arch::x86_64::_rdtsc() } / (hz / 1000).max(1);
    let mut text = Stamp::default();
    let _ = write!(text, "[{:5}.{:03}] ", millis / 1000, millis % 1000);
    record.push(&text.bytes[..text.length]);
}

/// A line's stamp, formatted without the heap.
#[derive(Default)]
struct Stamp {
    bytes: [u8; 24],
    length: usize,
}

impl Write for Stamp {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.length + value.len();
        self.bytes
            .get_mut(self.length..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

/// Stop the marker's firmware timer, store the logs and close those the
/// firmware holds, then stop writing to the firmware's console: called just before boot services end, which
/// take both with them.
pub fn leave_boot_services() {
    crate::firmware::stop_ticker();
    flush_log();
    if let Ok(mut sinks) = SINKS.0.try_borrow_mut() {
        sinks.retain(|sink| sink.kind != Log::Firmware);
    }
    disable_firmware_console();
}

/// The relocated engine has its own statics, not the loader image's updated
/// console flag. Revoke this image's firmware access before any engine error
/// can consult the expired system table. This makes no firmware calls and
/// needs neither the engine heap nor a valid handoff.
pub fn disable_firmware_console() {
    FIRMWARE_CONSOLE.store(false, Ordering::Relaxed);
}

/// Send every line to the screen as well, for a report that is all detail.
pub fn raw_screen() {
    RAW_SCREEN.store(true, Ordering::Relaxed);
}

/// Write `text` to the firmware's console while boot services run and the
/// firmware has one.
fn firmware_console(text: &str) {
    // SAFETY: the firmware's system table, valid while boot services run.
    let console = || {
        uefi::table::system_table_raw()
            .is_some_and(|table| unsafe { !table.as_ref().stdout.is_null() })
    };
    if FIRMWARE_CONSOLE.load(Ordering::Relaxed) && console() {
        uefi::system::with_stdout(|out| {
            let _ = out.write_str(text);
        });
    }
}

struct Output;
impl Write for Output {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let _ = Serial.write_str(value);
        if RAW_SCREEN.load(Ordering::Relaxed) {
            console::write(&[(value, console::Color::Text)]);
        }
        if let Ok(mut record) = RECORD.0.try_borrow_mut() {
            for line in value.split_inclusive('\n') {
                if LINE_START.load(Ordering::Relaxed) {
                    stamp(&mut record);
                }
                record.push(line.as_bytes());
                LINE_START.store(line.ends_with('\n'), Ordering::Relaxed);
            }
        }
        Ok(())
    }
}

/// Why [`add_log`] did not keep a log.
pub enum Unopened {
    /// The device refused the first store.
    Store(BlockError),
    /// The device took the first store and does not hold it.
    Unkept(Unkept),
}

impl fmt::Display for Unopened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::Unkept(unkept) => write!(f, "{unkept}"),
        }
    }
}

/// Keep the output in `writer`'s log on `device` from now on, starting with
/// everything since the first line that the record still holds. The first
/// store is read back before the log counts as open.
pub fn add_log(
    mut writer: Writer,
    mut device: Box<dyn BlockDevice>,
    kind: Log,
) -> Result<(), Unopened> {
    let stored = match RECORD.0.try_borrow() {
        Ok(record) => {
            let Ok(reached) = record.copy_since(0, |bytes| {
                writer.append(bytes);
                Ok::<_, Infallible>(())
            });
            reached
        }
        Err(_) => 0,
    };
    writer.flush(&mut *device).map_err(Unopened::Store)?;
    writer.verify(&mut *device).map_err(Unopened::Unkept)?;
    if let Ok(mut sinks) = SINKS.0.try_borrow_mut() {
        sinks.push(Sink {
            writer,
            device,
            kind,
            stored,
        });
    }
    Ok(())
}

/// Store what every open log lacks and close them all, before the disks
/// they live on are shut down; later output reaches the serial port only.
pub fn close_logs() {
    flush_log();
    if let Ok(mut sinks) = SINKS.0.try_borrow_mut() {
        sinks.clear();
    }
}

/// Store in every open log the output it does not hold yet. A USB log that
/// fails is reported and closed; a failed machine-state store stops the
/// machine. Output printed during the flush is not recorded.
pub fn flush_log() {
    if FLUSHING.swap(true, Ordering::Acquire) {
        return;
    }
    let mut failed = Vec::new();
    if let (Ok(mut sinks), Ok(record)) = (SINKS.0.try_borrow_mut(), RECORD.0.try_borrow()) {
        let mut index = 0;
        while index < sinks.len() {
            let Sink {
                writer,
                device,
                stored,
                ..
            } = &mut sinks[index];
            let Ok(reached) = record.copy_since(*stored, |bytes| {
                writer.append(bytes);
                Ok::<_, Infallible>(())
            });
            *stored = reached;
            match writer.flush(&mut **device) {
                Ok(()) => index += 1,
                Err(error) => failed.push((sinks.remove(index).kind, error)),
            }
        }
    }
    FLUSHING.store(false, Ordering::Release);
    for (kind, error) in failed {
        arguments(format_args!("BOOT LOG refusal: {error}\n"));
        if kind == Log::Machine {
            fatal("the boot log could not be stored");
        }
    }
}

pub fn arguments(args: fmt::Arguments<'_>) {
    let _ = Output.write_fmt(args);
}

/// Report `code` to QEMU's `isa-debug-exit`, which ends a harness run
/// there; on a PC the port is unused and execution continues.
pub fn debug_exit(code: u32) {
    // SAFETY: an otherwise unused PC port.
    unsafe {
        asm!("out dx, eax", in("dx") EXIT_PORT, in("eax") code, options(nostack, preserves_flags));
    }
}

/// Report `code` to QEMU, then halt. On a PC the screen keeps the output
/// until the machine is powered off.
pub fn terminate(code: u32) -> ! {
    arguments(format_args!(
        "STELA STOPPED code={code:#x}; power off to continue\n"
    ));
    flush_log();
    debug_exit(code);
    loop {
        unsafe {
            asm!("cli", "hlt", options(nostack));
        }
    }
}

/// Show `message` as the reason the mount stopped: as a failed step on
/// Stela's console, or on the firmware's before it exists.
fn stopped(message: &str) {
    console::reclaim();
    if console::active() && !RAW_SCREEN.load(Ordering::Relaxed) {
        crate::status::fail(message);
        crate::status::info("Stela stopped. Turn the PC off to try again.");
    } else if FIRMWARE_CONSOLE.load(Ordering::Relaxed) {
        firmware_console(&alloc::format!("\nStela stopped: {message}\n"));
    }
}

pub fn fatal(message: &str) -> ! {
    arguments(format_args!("\nSTELA FATAL {message}\n"));
    stopped(message);
    terminate(0x11)
}

pub fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let message = info.message();
    // Logged before anything allocates: the panic may be the heap running
    // out.
    match info.location() {
        Some(at) => arguments(format_args!(
            "\nSTELA PANIC at {}:{}: {message}\n",
            at.file(),
            at.line()
        )),
        None => arguments(format_args!("\nSTELA PANIC: {message}\n")),
    }
    stopped(&alloc::format!("internal error: {message}"));
    terminate(0x11)
}
