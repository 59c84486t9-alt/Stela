//! The mount's detailed output: every line goes to the UART and, from the
//! very first line, into a bounded record for the persistent boot logs
//! (`pc::boot_log`): the USB's `EFI/stela/boot.log` ([`crate::log_file`])
//! and the machine state's, once `--nor` opens it. [`add_log`] adds one,
//! which starts with everything the record still holds, and [`flush_log`]
//! stores what each has not: at every step and at every stop, which
//! [`terminate`] reaches. Between engine slices [`flush_due`] stores the
//! machine state's log every [`MACHINE_FLUSH_SECONDS`], as ext4 commits its
//! journal, and the USB's, slow flash the guest waits on, only every
//! [`USB_FLUSH_SECONDS`]. The screen shows the curated
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
use stela_drivers::block::{BlockDevice, BlockError, Submission};
use stela_runtime::pc::boot_log::{PENDING_BYTES, Pending, Unkept, Writer};

/// `isa-debug-exit` under QEMU; an unused port on a PC.
mod terminal;
use terminal::EXIT_PORT;
pub(crate) use terminal::panic;

/// One engine-wide value. The mount runs on one processor and its handlers
/// only print; every access is a `try_borrow`, so output that arrives while
/// the value is in use (a line printed during a flush) is skipped instead of
/// re-entering it. Values other processors reach too are reached only under
/// a lock: the record under [`WRITING`], the guest's lines under the board's.
pub(crate) struct Global<T>(pub(crate) RefCell<T>);
// SAFETY: one processor at a time reaches each value (above), and no access
// blocks or assumes the value is free.
unsafe impl<T> Sync for Global<T> {}

/// A processor writes the record and the serial port. Others wait for it at
/// most [`WRITING_WAIT_MICROS`], longer than a long line takes at the serial
/// port's speed, then write to the serial port alone: the holder may be this
/// processor itself, interrupted or failing inside a write.
static WRITING: AtomicBool = AtomicBool::new(false);
const WRITING_WAIT_MICROS: u64 = 250_000;
/// Spins to wait while the counter's rate is not known yet.
const WRITING_WAIT_SPINS: u64 = 1 << 22;

/// Run `f` while no other processor writes the record; `None` when the
/// wait ran out.
fn exclusive<R>(f: impl FnOnce() -> R) -> Option<R> {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    let started = rdtsc();
    let mut spins = 0u64;
    while WRITING
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spins += 1;
        let waited = match hz {
            0 => spins >= WRITING_WAIT_SPINS,
            hz => rdtsc().wrapping_sub(started) >= hz / 1_000_000 * WRITING_WAIT_MICROS,
        };
        if waited {
            return None;
        }
        core::hint::spin_loop();
    }
    let result = f();
    WRITING.store(false, Ordering::Release);
    Some(result)
}

/// Output for the serial port while every PE runs on a core of its own
/// ([`queue_serial`]). The port takes 16 bytes per transmit FIFO, each
/// burst a port access a hypervisor traps and a real port drains at its
/// baud rate, so a long report sent where it is printed would hold that
/// processor, and the PE it runs, for a quarter second or more. Queued
/// bytes go out from a PE that waits for an interrupt anyway
/// ([`send_queued`]). Reached only under [`WRITING`], which covers copies
/// into and out of the queue and never a port access.
static SERIAL_QUEUE: Global<Option<Queue>> = Global(RefCell::new(None));
const SERIAL_QUEUE_BYTES: usize = 8 << 20;
/// Whether the queue holds bytes, read without the lock.
static SERIAL_QUEUED: AtomicBool = AtomicBool::new(false);
/// One processor at a time feeds the port from the queue, so its bursts
/// neither interleave nor overrun the FIFO it found empty; the others do
/// not wait for it.
static SENDING: AtomicBool = AtomicBool::new(false);
/// The bytes [`send_queued`] sends at once: with each line feed sent as two,
/// at most the 16 a 16550's transmit FIFO takes once it is empty.
const SERIAL_BURST: usize = 8;

/// A ring of bytes not yet sent.
struct Queue {
    bytes: Box<[u8]>,
    head: usize,
    len: usize,
    /// Bytes left out while the queue was full, not reported yet: the
    /// record and the logs keep them.
    dropped: usize,
}

impl Queue {
    /// Queue `data`, or count it as dropped while the queue cannot take it
    /// whole: a writer never waits for the port. The first output that
    /// fits again begins with a note of how much was dropped.
    fn push(&mut self, data: &[u8]) {
        if self.dropped != 0 {
            let note = alloc::format!(
                "
[serial: {} bytes dropped]
",
                self.dropped
            );
            if self.room() < note.len() + data.len() {
                self.dropped += data.len();
                return;
            }
            self.dropped = 0;
            self.copy(note.as_bytes());
        }
        if self.room() < data.len() {
            self.dropped = data.len();
            return;
        }
        self.copy(data);
    }

    fn room(&self) -> usize {
        self.bytes.len() - self.len
    }

    /// Append `data`, which fits.
    fn copy(&mut self, data: &[u8]) {
        let size = self.bytes.len();
        let tail = (self.head + self.len) % size;
        let first = data.len().min(size - tail);
        self.bytes[tail..tail + first].copy_from_slice(&data[..first]);
        self.bytes[..data.len() - first].copy_from_slice(&data[first..]);
        self.len += data.len();
        SERIAL_QUEUED.store(true, Ordering::Release);
    }

    /// Move the oldest bytes into `out`, as many as fit; how many.
    fn take(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.len);
        for slot in &mut out[..count] {
            *slot = self.bytes[self.head];
            self.head = (self.head + 1) % self.bytes.len();
        }
        self.len -= count;
        SERIAL_QUEUED.store(self.len != 0, Ordering::Release);
        count
    }
}

/// Queue the serial port's output from now on, for [`send_queued`].
pub fn queue_serial() {
    let queue = Queue {
        bytes: alloc::vec![0; SERIAL_QUEUE_BYTES].into_boxed_slice(),
        head: 0,
        len: 0,
        dropped: 0,
    };
    let _ = exclusive(|| {
        if let Ok(mut slot) = SERIAL_QUEUE.0.try_borrow_mut() {
            *slot = Some(queue);
        }
    });
}

/// Send a burst of queued bytes if the port takes it now without waiting;
/// whether this processor should send more. Never waits for another
/// processor: while one sends, the others leave the port to it.
pub fn send_queued() -> bool {
    if !SERIAL_QUEUED.load(Ordering::Acquire)
        || SENDING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return false;
    }
    if crate::serial::ready() {
        let mut burst = [0u8; SERIAL_BURST];
        let taken = exclusive(|| {
            SERIAL_QUEUE
                .0
                .try_borrow_mut()
                .ok()
                .and_then(|mut slot| slot.as_mut().map(|queue| queue.take(&mut burst)))
                .unwrap_or(0)
        })
        .unwrap_or(0);
        crate::serial::burst(&burst[..taken]);
    }
    SENDING.store(false, Ordering::Release);
    SERIAL_QUEUED.load(Ordering::Acquire)
}

/// Send `bytes` to the serial port: queued once [`queue_serial`] ran, else
/// here and now. Under [`WRITING`].
fn serial(bytes: &[u8]) {
    if let Ok(mut slot) = SERIAL_QUEUE.0.try_borrow_mut()
        && let Some(queue) = slot.as_mut()
    {
        queue.push(bytes);
        return;
    }
    Serial.write_bytes(bytes);
}

/// Send what the serial queue holds here and stop queueing: the boot is
/// stopping, and no PE may wait again.
fn unqueue_serial() {
    let _ = exclusive(|| {
        if let Ok(mut slot) = SERIAL_QUEUE.0.try_borrow_mut()
            && let Some(mut queue) = slot.take()
        {
            let mut burst = [0u8; SERIAL_BURST];
            loop {
                let taken = queue.take(&mut burst);
                if taken == 0 {
                    break;
                }
                Serial.write_bytes(&burst[..taken]);
            }
        }
    });
}

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
    /// The counter at its last store.
    flushed: u64,
    /// Its stores so far and the counter ticks they took.
    stores: u64,
    ticks: u64,
    /// The counter when the store in progress began.
    began: Option<u64>,
    /// The store's request in progress on the device.
    request: Option<Submission>,
}

impl Sink {
    /// Move the store in progress on: collect the running request's result
    /// and start the next; with `wait`, until the store is done.
    fn advance(&mut self, wait: bool) -> Result<(), BlockError> {
        loop {
            if let Some(request) = self.request.as_mut() {
                let Some(finished) = request.poll(&mut *self.device) else {
                    if !wait {
                        return Ok(());
                    }
                    core::hint::spin_loop();
                    continue;
                };
                self.request = None;
                self.writer.completed(finished)?;
            }
            let Some(request) = self.writer.next_request() else {
                if let Some(began) = self.began.take() {
                    self.flushed = rdtsc();
                    self.stores += 1;
                    self.ticks += self.flushed.wrapping_sub(began);
                }
                return Ok(());
            };
            match Submission::new(request, self.device.identity()) {
                Ok(request) => self.request = Some(request),
                Err(error) => {
                    let _ = self.writer.completed(Err(error.clone()));
                    return Err(error);
                }
            }
        }
    }
}

/// Seconds between the machine state's log stores while the engine runs:
/// ext4's default journal commit interval. A stop stores at once.
const MACHINE_FLUSH_SECONDS: u64 = 5;
/// Seconds between the USB log's stores while the engine runs.
const USB_FLUSH_SECONDS: u64 = 10;

fn rdtsc() -> u64 {
    // SAFETY: RDTSC has no memory effects.
    unsafe { core::arch::x86_64::_rdtsc() }
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

/// The open logs, which any processor may flush or report: reached only
/// while holding [`HELD`].
static SINKS: Global<Vec<Sink>> = Global(RefCell::new(Vec::new()));
/// A processor holds [`SINKS`]: a fatal or panic raised inside a flush
/// halts without flushing again.
static HELD: AtomicBool = AtomicBool::new(false);

/// Run `f` on the open logs once no other processor holds them, or `None`
/// at once when one does and `wait` is false.
fn with_sinks<R>(wait: bool, f: impl FnOnce(&mut Vec<Sink>) -> R) -> Option<R> {
    while HELD
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        if !wait {
            return None;
        }
        core::hint::spin_loop();
    }
    let result = SINKS.0.try_borrow_mut().ok().map(|mut sinks| f(&mut sinks));
    HELD.store(false, Ordering::Release);
    result
}
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
    let millis = rdtsc() / (hz / 1000).max(1);
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
    with_sinks(true, |sinks| {
        sinks.retain(|sink| sink.kind != Log::Firmware)
    });
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
#[cfg(feature = "diagnostics")]
pub fn raw_screen() {
    RAW_SCREEN.store(true, Ordering::Relaxed);
}

/// Write `text` to the firmware's console while boot services run and the
/// firmware has one.
fn firmware_console(text: &str) {
    let console = || {
        uefi::table::system_table_raw()
            // SAFETY: the firmware's system table, valid while boot services run.
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
        serial(value.as_bytes());
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
    let stored = exclusive(|| match RECORD.0.try_borrow() {
        Ok(record) => {
            let Ok(reached) = record.copy_since(0, |bytes| {
                writer.append(bytes);
                Ok::<_, Infallible>(())
            });
            reached
        }
        Err(_) => 0,
    })
    .unwrap_or(0);
    writer.flush(&mut *device).map_err(Unopened::Store)?;
    writer.verify(&mut *device).map_err(Unopened::Unkept)?;
    with_sinks(true, |sinks| {
        sinks.push(Sink {
            writer,
            device,
            kind,
            stored,
            flushed: rdtsc(),
            stores: 0,
            ticks: 0,
            began: None,
            request: None,
        })
    });
    Ok(())
}

/// Store what every open log lacks and close them all, before the disks
/// they live on are shut down; later output reaches the serial port only.
pub fn close_logs() {
    flush_log();
    with_sinks(true, Vec::clear);
}

/// Store in every open log the output it does not hold yet, waiting for
/// the stores. A USB log that fails is reported and closed; a failed
/// machine-state store stops the machine. Output printed during the flush
/// is not recorded.
pub fn flush_log() {
    flush_where(|_| true, true);
}

/// Begin storing the logs whose store is due, the machine state's every
/// [`MACHINE_FLUSH_SECONDS`] and the USB's every [`USB_FLUSH_SECONDS`], and
/// move every store in progress on; never waits for a device
/// ([`advance_logs`]).
pub fn flush_due() {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    let now = rdtsc();
    flush_where(
        |sink| {
            let seconds = match sink.kind {
                Log::Usb => USB_FLUSH_SECONDS,
                _ => MACHINE_FLUSH_SECONDS,
            };
            now.wrapping_sub(sink.flushed) >= seconds * hz
        },
        false,
    );
}

/// Move the log stores in progress on; nothing to do while none runs.
pub fn advance_logs() {
    if STORING.load(Ordering::Acquire) {
        flush_where(|_| false, false);
    }
}

/// A log store is in progress ([`advance_logs`]).
static STORING: AtomicBool = AtomicBool::new(false);

fn flush_where(due: impl Fn(&Sink) -> bool, wait: bool) {
    let mut failed = Vec::new();
    with_sinks(false, |sinks| {
        // A log whose store is in progress takes new bytes at its next one.
        let due: Vec<bool> = sinks
            .iter()
            .map(|sink| !sink.writer.storing() && due(sink))
            .collect();
        // Take the record's new bytes while no processor adds to it, then
        // store them without holding the others' output up.
        let _ = exclusive(|| {
            let Ok(record) = RECORD.0.try_borrow() else {
                return;
            };
            for (sink, _) in sinks.iter_mut().zip(&due).filter(|(_, due)| **due) {
                let Ok(reached) = record.copy_since(sink.stored, |bytes| {
                    sink.writer.append(bytes);
                    Ok::<_, Infallible>(())
                });
                sink.stored = reached;
            }
        });
        let mut index = 0;
        let mut position = 0;
        while index < sinks.len() {
            let is_due = due[position];
            position += 1;
            let sink = &mut sinks[index];
            if is_due && sink.writer.begin_store() {
                sink.began = Some(rdtsc());
            }
            match sink.advance(wait) {
                Ok(()) => index += 1,
                Err(error) => failed.push((sinks.remove(index).kind, error)),
            }
        }
        STORING.store(
            sinks.iter().any(|sink| sink.writer.storing()),
            Ordering::Release,
        );
    });
    for (kind, error) in failed {
        arguments(format_args!("BOOT LOG refusal: {error}\n"));
        if kind == Log::Machine {
            fatal("the boot log could not be stored");
        }
    }
}

/// The counter now, for [`millis_since`].
pub fn now() -> u64 {
    rdtsc()
}

/// Milliseconds since counter value `start`; 0 before the rate is known.
pub fn millis_since(start: u64) -> u64 {
    match TSC_HZ.load(Ordering::Relaxed) {
        0 => 0,
        hz => rdtsc().wrapping_sub(start) / (hz / 1000).max(1),
    }
}

/// Report each open log's stores so far and the milliseconds they took.
pub fn report_log_stores() {
    let hz = TSC_HZ.load(Ordering::Relaxed).max(1);
    let Some(costs) = with_sinks(false, |sinks| {
        sinks
            .iter()
            .map(|sink| (sink.kind, sink.stores, sink.ticks * 1000 / hz))
            .collect::<Vec<(Log, u64, u64)>>()
    }) else {
        return;
    };
    for (kind, stores, millis) in costs {
        let name = match kind {
            Log::Machine => "machine",
            Log::Firmware => "firmware",
            Log::Usb => "usb",
        };
        arguments(format_args!(
            "BOOT LOG {name} stores={stores} ms={millis}\n"
        ));
    }
}

pub fn arguments(args: fmt::Arguments<'_>) {
    if exclusive(|| Output.write_fmt(args)).is_none() {
        let _ = Serial.write_fmt(args);
    }
}

/// Report `code` to QEMU's `isa-debug-exit`, which ends a harness run
/// there; on a PC the port is unused and execution continues.
pub fn debug_exit(code: u32) {
    // The run may end here: whatever waits for the serial port goes first.
    unqueue_serial();
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
    halt(code)
}

/// Stop before allocator initialization. UART/record formatting and UEFI's
/// stack-buffered text writer need no Rust allocation; neither log flushing nor
/// the allocating status/panic presentation path is entered here. Call only
/// while firmware boot services and its system table remain live.
pub(crate) fn early_fatal(message: &str) -> ! {
    arguments(format_args!("\nSTELA FATAL {message}\n"));
    firmware_console("\nStela stopped: ");
    firmware_console(message);
    firmware_console("\n");
    arguments(format_args!(
        "STELA STOPPED code=0x11; power off to continue\n"
    ));
    halt(0x11)
}

fn halt(code: u32) -> ! {
    debug_exit(code);
    loop {
        // SAFETY: native mount termination runs at CPL0; after the debug-exit
        // attempt no task resumes, so maskable interrupts remain disabled.
        unsafe { asm!("cli", "hlt", options(nostack)) };
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
        firmware_console("\nStela stopped: ");
        firmware_console(message);
        firmware_console("\n");
    }
}

pub fn fatal(message: &str) -> ! {
    arguments(format_args!("\nSTELA FATAL {message}\n"));
    stopped(message);
    terminate(0x11)
}
