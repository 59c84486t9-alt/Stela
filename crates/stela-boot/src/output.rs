//! The mount's output: every line goes to the UART and, once installed, the
//! framebuffer console, and waits from the very first line in a bounded
//! buffer for the persistent boot log (`pc::boot_log`). Once `--nor` opens
//! the log ([`install_log`]), [`flush_log`] stores what waits: between
//! engine slices and at every stop, which [`terminate`] reaches.
use crate::{console, serial::Serial};
use alloc::boxed::Box;
use core::{
    arch::asm,
    cell::RefCell,
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

/// Every output byte since the first line that the log has not stored.
static PENDING: Global<Pending<[u8; PENDING_BYTES]>> =
    Global(RefCell::new(Pending::new([0; PENDING_BYTES])));

/// The open log and its window of the machine-state partition.
struct Sink {
    writer: Writer,
    device: Box<dyn BlockDevice>,
}

static SINK: Global<Option<Sink>> = Global(RefCell::new(None));
/// A flush is running: a fatal or panic raised inside it halts without
/// flushing again.
static FLUSHING: AtomicBool = AtomicBool::new(false);

struct Output(console::Color);
impl Write for Output {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let _ = Serial.write_str(value);
        console::write(value, self.0);
        if let Ok(mut pending) = PENDING.0.try_borrow_mut() {
            pending.push(value.as_bytes());
        }
        Ok(())
    }
}

/// Keep the output in `writer`'s log on `device` from now on, starting with
/// everything printed so far.
pub fn install_log(writer: Writer, device: Box<dyn BlockDevice>) {
    if let Ok(mut sink) = SINK.0.try_borrow_mut() {
        *sink = Some(Sink { writer, device });
    }
    flush_log();
}

/// Store the pending output in the log, when one is open. A failed store
/// stops the machine; output printed during the flush is not logged.
pub fn flush_log() {
    if FLUSHING.swap(true, Ordering::Acquire) {
        return;
    }
    let result = match (SINK.0.try_borrow_mut(), PENDING.0.try_borrow_mut()) {
        (Ok(mut sink), Ok(mut pending)) => match sink.as_mut() {
            Some(Sink { writer, device }) => writer.flush_from(&mut **device, &mut pending),
            None => Ok(()),
        },
        _ => Ok(()),
    };
    if let Err(error) = result {
        // FLUSHING stays set: the log is not stored again.
        arguments(format_args!("BOOT LOG refusal: {error}\n"));
        fatal("the boot log could not be stored");
    }
    FLUSHING.store(false, Ordering::Release);
}

pub fn arguments(args: fmt::Arguments<'_>) {
    let _ = Output(console::Color::Text).write_fmt(args);
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

pub fn fatal(message: &str) -> ! {
    let _ = Output(console::Color::Fatal).write_fmt(format_args!("\nSTELA FATAL {message}\n"));
    terminate(0x11)
}

pub fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut output = Output(console::Color::Fatal);
    let _ = output.write_str("\nSTELA PANIC");
    if let Some(location) = info.location() {
        let _ = write!(output, " {}:{}", location.file(), location.line());
    }
    let _ = output.write_str("\n");
    terminate(0x11)
}
