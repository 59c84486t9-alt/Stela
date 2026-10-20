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
    sync::atomic::{AtomicBool, Ordering},
};
use stela_runtime::pc::{
    block::BlockDevice,
    boot_log::{PENDING_BYTES, Pending, Writer},
};

/// `isa-debug-exit` under QEMU; an unused port on a PC.
const EXIT_PORT: u16 = 0xf4;

/// One engine-wide value. The mount runs on one processor and its handlers
/// only print; every access is a `try_borrow`, so output that arrives while
/// the value is in use (a line printed during a flush) is skipped instead of
/// re-entering it.
struct Global<T>(RefCell<T>);
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

/// Store the logs and close those the firmware holds, then stop writing to
/// the firmware's console: called just before boot services end, which
/// take both with them.
pub fn leave_boot_services() {
    flush_log();
    if let Ok(mut sinks) = SINKS.0.try_borrow_mut() {
        sinks.retain(|sink| sink.kind != Log::Firmware);
    }
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
            record.push(value.as_bytes());
        }
        Ok(())
    }
}

/// Keep the output in `writer`'s log on `device` from now on, starting with
/// everything since the first line that the record still holds.
pub fn add_log(writer: Writer, device: Box<dyn BlockDevice>, kind: Log) {
    if let Ok(mut sinks) = SINKS.0.try_borrow_mut() {
        sinks.push(Sink {
            writer,
            device,
            kind,
            stored: 0,
        });
    }
    flush_log();
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
    if console::active() && !RAW_SCREEN.load(Ordering::Relaxed) {
        crate::status::fail(message);
        crate::status::info("Stela stopped. Turn the PC off to try again.");
    } else {
        firmware_console(&alloc::format!("\nStela stopped: {message}\n"));
    }
}

pub fn fatal(message: &str) -> ! {
    arguments(format_args!("\nSTELA FATAL {message}\n"));
    stopped(message);
    terminate(0x11)
}

pub fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let place = info
        .location()
        .map(|location| alloc::format!(" at {}:{}", location.file(), location.line()))
        .unwrap_or_default();
    arguments(format_args!("\nSTELA PANIC{place}\n"));
    stopped(&alloc::format!("internal error{place}"));
    terminate(0x11)
}
