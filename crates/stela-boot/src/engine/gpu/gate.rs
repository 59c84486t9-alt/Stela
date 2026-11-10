//! The Metal service over NVK, which the guest reaches through StelaGPU's gate,
//!
//! It opens on the boot CPU once nouveau has bound the GPUs, before the guest's
//! DeviceTree is final, so the tree has a gate only with a device behind it,
//! and one for each GPU that opened.
//!
//! Each service runs on a stack of its own, deep enough for a compile. Its
//! lock means one is enough; opening comes before any caller. A second
//! stack takes the pipeline compilations that run outside the lock, one at
//! a time under the compiler's own lock.
use super::{
    BOOT_CPU, Bound, Installed, PAGE, client, installed, look_again, pump_waiting,
    stack::{self, Stack},
};
use crate::{engine::host, output};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{
    ffi::{c_char, c_void},
    hint,
    num::NonZeroU64,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering},
};
use stela_contracts::gate::{BundleReport, GateService, MemoryRange, window};
use stela_drivers::gpu::metal::{
    compiler::{self, AirCompiler},
    device::lifecycle::QuiesceStatus,
    error::Error,
    native::{ExportedMemory, Loader, MemoryExporter, NativeBackend, vk},
    nvidia::{
        Attachment,
        open::{Gpu, OpenError, open, reopen},
    },
    service::{Served, ServiceHost, SharedService, identity::DeviceEpoch, wire::Status},
    timing::Totals,
    vulkan::physical::PciBusInfo,
};
use stela_linux::{
    client::Run,
    function::{dma_quarantine_status, quarantined_functions},
};
use stela_loader::{apple_device_tree::DeviceTree, stela_gpu};

type Shared = SharedService<NativeBackend, AirCompiler>;

/// A process's main stack, as big as the deepest compile LLVM bounds.
const STACK_BYTES: usize = 16 << 20;

/// How long a GPU's accepted work may go without progress as the PC stops:
/// with the guest stopped, an event it waits on will never signal.
const STOP_STALL_SECONDS: u64 = 5;
/// How long the stop waits for a GSP to unload.
const STOP_UNLOAD_SECONDS: u64 = 10;

/// The services for the kernel's interrupts, once all are open.
static SERVICES: AtomicPtr<Vec<Arc<Shared>>> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" {
    fn stela_nvk_nir_options(physical: vk::PhysicalDevice) -> *const c_void;
}

fn run(stack: u64, body: &mut dyn FnMut()) {
    // SAFETY: a service's stack lives for the boot, and only the opener or a
    // turn's holder is here.
    unsafe { stack::on_stack(stack, body) };
}

pub(super) fn relax() {
    // What this waits for may be retiring a mapping, which waits for this.
    crate::native_mmio::shootdown::service();
    if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
        pump_waiting();
    }
    hint::spin_loop();
}

/// A table of the texts a log line has shown, and a count of the distinct
/// ones it had no room left to hold.
struct Seen<const N: usize> {
    hashes: [AtomicU64; N],
    unheld: AtomicU64,
}

impl<const N: usize> Seen<N> {
    const fn new() -> Self {
        Self {
            hashes: [const { AtomicU64::new(0) }; N],
            unheld: AtomicU64::new(0),
        }
    }

    /// Whether to show `text`: the first time, by its FNV-1a hash, since a
    /// text is built per call and only its bytes identify it. Once the table
    /// fills, a text it cannot hold is shown only at each power-of-two count
    /// of such texts, which the [`Unheld`] it answers names, so a flood of distinct
    /// texts stays bounded.
    fn first_time(&self, text: &str) -> Option<Unheld> {
        let hash = text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        });
        for slot in &self.hashes {
            match slot.compare_exchange(0, hash, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(Unheld(0)),
                Err(known) if known == hash => return None,
                Err(_) => {}
            }
        }
        let unheld = self.unheld.fetch_add(1, Ordering::Relaxed) + 1;
        unheld.is_power_of_two().then_some(Unheld(unheld))
    }
}

/// How many distinct texts a full [`Seen`] has counted, shown after a line.
struct Unheld(u64);

impl core::fmt::Display for Unheld {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            0 => Ok(()),
            count => write!(formatter, " ({count} distinct past the log's table)"),
        }
    }
}

/// Logs why the service refused a guest's call, once for each reason.
fn report(reason: &str) {
    static SEEN: Seen<512> = Seen::new();
    if let Some(unheld) = SEEN.first_time(reason) {
        output::arguments(format_args!("GPU REFUSED {reason}{unheld}\n"));
    }
}

/// Logs each distinct error or warning NVK reports, such as why a call failed
/// with only a generic result.
fn driver_message(text: &str) {
    static SEEN: Seen<128> = Seen::new();
    if let Some(unheld) = SEEN.first_time(text) {
        output::arguments(format_args!("GPU DRIVER {text}{unheld}\n"));
        report_peaks();
    }
}

/// Logs what a guest call made or met, such as a render pipeline, once for
/// each distinct note, with the heap's live bytes and high-water mark after
/// it: a compile that raised the mark shows it against the note before.
fn note(text: &str) {
    static SEEN: Seen<512> = Seen::new();
    if let Some(unheld) = SEEN.first_time(text) {
        let heap = crate::ALLOCATOR.usage();
        output::arguments(format_args!(
            "GPU {text} heap={}M peak={}M{unheld}\n",
            heap.live >> 20,
            heap.peak >> 20
        ));
        report_peaks();
    }
}

/// Stacks of the allocations that raised the heap's high-water mark, each
/// the carved bytes then and the image offsets of code on the stack.
const PEAK_SLOTS: usize = 16;
const PEAK_WORDS: usize = 24;
static PEAKS: [[AtomicU64; PEAK_WORDS + 1]; PEAK_SLOTS] =
    [const { [const { AtomicU64::new(0) }; PEAK_WORDS + 1] }; PEAK_SLOTS];
static PEAKS_TAKEN: AtomicU32 = AtomicU32::new(0);
static PEAKS_SHOWN: AtomicU32 = AtomicU32::new(0);

/// The heap's peak hook: keeps the allocating stack's code offsets. Runs
/// under the heap's lock, so it only reads the stack and stores words.
pub(super) fn peak_passed(carved: usize) {
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    let slot = PEAKS_TAKEN.load(Ordering::Relaxed) as usize;
    if slot >= PEAK_SLOTS {
        return;
    }
    let base = &raw const __ImageBase as u64;
    // SAFETY: the mapped PE headers of this image: `e_lfanew`, then the
    // optional header's SizeOfCode and BaseOfCode.
    let (code, size) = unsafe {
        let header = u64::from((base as *const u32).byte_add(0x3c).read_unaligned());
        let pe = (base + header) as *const u32;
        (
            u64::from(pe.byte_add(0x2c).read_unaligned()),
            u64::from(pe.byte_add(0x1c).read_unaligned()),
        )
    };
    let stack: *const u64;
    // SAFETY: reads the stack pointer.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack, options(nomem, nostack, preserves_flags));
    }
    let words = &PEAKS[slot];
    words[0].store(carved as u64, Ordering::Relaxed);
    let mut kept = 0;
    for word in 0..512 {
        // SAFETY: as for a panic, an allocation runs 512 words from its stack's end.
        let offset = unsafe { stack.add(word).read() }.wrapping_sub(base);
        if offset.wrapping_sub(code) < size {
            kept += 1;
            words[kept].store(offset, Ordering::Relaxed);
            if kept == PEAK_WORDS {
                break;
            }
        }
    }
    PEAKS_TAKEN.store(slot as u32 + 1, Ordering::Release);
}

/// Logs the peak stacks taken since the last call, and once that the
/// slots filled, after which higher peaks show only in `BEAT peak=`.
fn report_peaks() {
    use core::fmt::Write;
    let taken = PEAKS_TAKEN.load(Ordering::Acquire);
    let shown = PEAKS_SHOWN.swap(taken, Ordering::AcqRel);
    if shown < taken && taken as usize == PEAK_SLOTS {
        output::arguments(format_args!(
            "HEAP PEAK the {PEAK_SLOTS} stack slots are full; later peaks are not traced\n"
        ));
    }
    for words in &PEAKS[shown as usize..taken as usize] {
        let mut line = format!(
            "HEAP PEAK carved={}M stack",
            words[0].load(Ordering::Relaxed) >> 20
        );
        for word in &words[1..] {
            let offset = word.load(Ordering::Relaxed);
            if offset != 0 {
                let _ = write!(line, " {offset:#x}");
            }
        }
        output::arguments(format_args!("{line}\n"));
    }
}

/// Whether this boot is single-user: macOS starts no Metal client, and a
/// maintenance installation may put the plugin in place.
static SINGLE_USER: AtomicBool = AtomicBool::new(false);

pub(super) fn single_user(single_user: bool) {
    SINGLE_USER.store(single_user, Ordering::Relaxed);
}

/// What the kext found of the Metal plugin, the bundle whose code this boot's
/// trust cache lists. A multi-user boot's Metal clients cannot start without
/// it, so the boot stops with the remedy rather than let WindowServer fail.
/// The stop is an orderly power-off, not a fatal one: the GPUs' firmware is
/// running by now, and only the boot CPU's service, outside Linux's
/// callbacks, unloads it before the reset that would otherwise take down the
/// card's link.
fn bundle(report: BundleReport) {
    let single_user = SINGLE_USER.load(Ordering::Relaxed);
    match report {
        BundleReport::Current => {
            output::arguments(format_args!("GPU StelaGPU.bundle is this stela.efi's\n"));
        }
        BundleReport::Updated => {
            output::arguments(format_args!(
                "GPU StelaGPU.bundle updated to this stela.efi's\n"
            ));
        }
        BundleReport::Missing | BundleReport::Failed if single_user => {
            output::arguments(format_args!(
                "GPU StelaGPU.bundle is not installed ({report:?}); this single-user boot may install it\n"
            ));
        }
        BundleReport::Missing => stop(
            "StelaGPU.bundle is not installed in /Library/GPUBundles, and a kext cannot create \
             its directories: install it from a single-user maintenance boot \
             (docs/installation.md)",
        ),
        BundleReport::Failed => stop(
            "the StelaGPU kext could not install StelaGPU.bundle; its StelaGPU lines above say why",
        ),
    }

    fn stop(reason: &str) {
        output::stopping(reason);
        super::super::service::request_shutdown(true);
    }
}

/// The guest calls one operation's gate served since the last report.
struct Calls {
    /// The operation plus one; zero while the slot is free.
    key: AtomicU32,
    count: AtomicU64,
    /// TSC ticks holding the service, the longest one call held it, and
    /// waiting for another call's turn.
    held: AtomicU64,
    longest: AtomicU64,
    waited: AtomicU64,
    /// Calls answered `Unmapped`, which the frontend repeats.
    unmapped: AtomicU64,
    /// Requests the calls posted to the host's Linux environment, and the
    /// ticks they waited for the boot CPU to serve them.
    posted: AtomicU64,
    posted_waited: AtomicU64,
    /// The longest one wait for the turn, the ticks compiling outside the
    /// lock, and the compilations that were.
    longest_wait: AtomicU64,
    compiled: AtomicU64,
    deferrals: AtomicU64,
}

/// More slots than the protocol has operations.
static CALLS: [Calls; 96] = [const {
    Calls {
        key: AtomicU32::new(0),
        count: AtomicU64::new(0),
        held: AtomicU64::new(0),
        longest: AtomicU64::new(0),
        waited: AtomicU64::new(0),
        unmapped: AtomicU64::new(0),
        posted: AtomicU64::new(0),
        posted_waited: AtomicU64::new(0),
        longest_wait: AtomicU64::new(0),
        compiled: AtomicU64::new(0),
        deferrals: AtomicU64::new(0),
    }
}; 96];

/// The phases of the calls timed by phase since the last report.
static PHASES: Totals = Totals::new();

/// A timed call of a second over this or longer shows a line of its own:
/// 100 ms.
const SLOW_CALL_DIVISOR: u64 = 10;

/// Counts a call the gate served: the PE that rang runs no guest code until
/// it returns, so a call that holds the service long is guest time lost.
fn served(served: Served) {
    if let Some(call) = served.phases {
        let tsc_hz = installed().map_or(0, |gpu| gpu.tsc_hz);
        if PHASES.add(&call, tsc_hz / SLOW_CALL_DIVISOR) {
            output::arguments(format_args!("{}\n", call.slow_line(tsc_hz)));
        }
    }
    // The display compares each swap with the GPU's progress.
    if let Some((submitted, completed)) = served.progress {
        stela_soc::dcp::gpu::note(submitted, completed);
    }
    // The PE ran nothing but this call since the last one it served.
    let (posted, posted_waited) = client::take_mine();
    let key = served.operation.wrapping_add(1);
    // Slots fill in order and stay claimed: the first that is free or
    // already this operation's is its own.
    let Some(calls) = CALLS.iter().find(|calls| {
        match calls
            .key
            .compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => true,
            Err(claimed) => claimed == key,
        }
    }) else {
        return;
    };
    calls.count.fetch_add(1, Ordering::Relaxed);
    calls.held.fetch_add(served.held, Ordering::Relaxed);
    calls.longest.fetch_max(served.held, Ordering::Relaxed);
    calls.waited.fetch_add(served.waited, Ordering::Relaxed);
    if served.status == Status::Unmapped {
        calls.unmapped.fetch_add(1, Ordering::Relaxed);
    }
    calls.posted.fetch_add(posted, Ordering::Relaxed);
    calls
        .posted_waited
        .fetch_add(posted_waited, Ordering::Relaxed);
    calls
        .longest_wait
        .fetch_max(served.longest_wait, Ordering::Relaxed);
    calls.compiled.fetch_add(served.compiled, Ordering::Relaxed);
    calls
        .deferrals
        .fetch_add(u64::from(served.deferrals), Ordering::Relaxed);
}

/// What a device holds: its allocation with the part waiting for submitted
/// work, that work, its memory blocks with the resources placed in them and
/// those in memory of their own, and the connections counting the most
/// bytes, each as
/// id:objects/MiB. Nothing while a call holds the service.
fn report_memory(service: &Shared) {
    const SHOWN: usize = 4;
    let Some(mut memory) = service.memory() else {
        return;
    };
    let mib = |bytes: u64| bytes >> 20;
    let device = memory.device;
    output::arguments(format_args!(
        "GPU MEMORY allocated={}M deferred={}/{}M in_flight={} completed={}/{} recycled={}/{}M reused={}/{} blocks={}/{}M placed={}/{}M own={} connections={}",
        mib(device.allocated),
        device.deferred,
        mib(device.deferred_bytes),
        device.in_flight,
        device.completed,
        device.submitted,
        device.recycled.textures,
        mib(device.recycled.bytes),
        device.recycled.hits,
        device.recycled.hits + device.recycled.misses,
        device.blocks.blocks,
        mib(device.blocks.block_bytes),
        device.blocks.placed,
        mib(device.blocks.placed_bytes),
        device.blocks.own,
        memory.connections.len(),
    ));
    memory
        .connections
        .sort_unstable_by_key(|connection| core::cmp::Reverse(connection.allocated));
    for connection in memory.connections.iter().take(SHOWN) {
        output::arguments(format_args!(
            " {}:{}/{}M",
            connection.id,
            connection.objects,
            mib(connection.allocated)
        ));
    }
    output::arguments(format_args!("\n"));
}

/// The operations whose calls held the service longest since the last
/// report: each as count/held/longest/waited/unmapped/posted/posted_waited,
/// microseconds between.
pub(in crate::engine) fn report_calls(tsc_hz: u64) {
    const SHOWN: usize = 8;
    // Peaks a compile or allocation raised with no GPU line after it.
    report_peaks();
    shared().iter().for_each(|service| report_memory(service));
    let micros = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1));
    // How long submitted work took to be seen complete: the GPU's time plus
    // the wait for its interrupt and a look at the device.
    for service in shared().iter() {
        let (count, total, longest) = service.take_latency();
        if let Some(average) = total.checked_div(count) {
            output::arguments(format_args!(
                "GPU LATENCY completed={count} average_us={} longest_us={}\n",
                micros(average),
                micros(longest),
            ));
        }
    }
    // Which part of that latency was waiting for the GPU to start, the GPU's
    // own time, and waiting for the look after it finished.
    for service in shared().iter() {
        let Some(times) = service.gpu_times() else {
            continue;
        };
        if times.timed == 0 && times.waiting == 0 {
            continue;
        }
        let average = |total: u64, count: u64| total.checked_div(count).unwrap_or(0);
        output::arguments(format_args!(
            "GPU TIMES timed={} busy_us={} average_us={} longest_us={}@{}:{} idle_us={} \
             overlap_us={} placed={} queued_us={}/{} noticed_us={}/{} waiting={} \
             span_us={}@{}:{}/{}:{}\n",
            times.timed,
            times.busy_ns / 1000,
            average(times.busy_ns, times.timed) / 1000,
            times.longest_ns / 1000,
            times.longest_serial,
            times.longest_entries,
            times.idle_ns / 1000,
            times.overlap_ns / 1000,
            times.placed,
            micros(average(times.queued_ticks, times.placed)),
            micros(times.longest_queued_ticks),
            micros(average(times.noticed_ticks, times.placed)),
            micros(times.longest_noticed_ticks),
            times.waiting,
            times.span_ns / 1000,
            times.span_serial,
            times.span_index,
            times.span_count,
            times.span_entries,
        ));
    }
    // The display's presents, and how long they held the boot CPU while a
    // posted call waited for it.
    let [presents, total, longest, on_boot, blocked] = client::take_presents();
    if presents != 0 {
        output::arguments(format_args!(
            "GPU PRESENTS count={presents} on_boot={on_boot} total_us={} longest_us={} \
             blocking_us={}\n",
            micros(total),
            micros(longest),
            micros(blocked),
        ));
    }
    // Where the time of the slowest operations went, phase by phase.
    for taken in PHASES.take() {
        output::arguments(format_args!("{}\n", taken.line(tsc_hz)));
    }
    for service in shared().iter() {
        if let Some(line) = service.compiler_report() {
            output::arguments(format_args!("{line}\n"));
        }
    }
    report_lock(tsc_hz);
    let mut taken: Vec<_> = CALLS
        .iter()
        .filter_map(|calls| {
            let key = calls.key.load(Ordering::Relaxed);
            let count = calls.count.swap(0, Ordering::Relaxed);
            (key != 0 && count != 0).then(|| {
                (
                    key - 1,
                    count,
                    calls.held.swap(0, Ordering::Relaxed),
                    calls.longest.swap(0, Ordering::Relaxed),
                    calls.waited.swap(0, Ordering::Relaxed),
                    calls.unmapped.swap(0, Ordering::Relaxed),
                    calls.posted.swap(0, Ordering::Relaxed),
                    calls.posted_waited.swap(0, Ordering::Relaxed),
                )
            })
        })
        .collect();
    if let Some(pool) = client::pool_report(tsc_hz) {
        output::arguments(format_args!("{pool}\n"));
    }
    let posted = client::take_posted();
    if taken.is_empty() && posted.is_empty() {
        return;
    }
    taken.sort_unstable_by_key(|&(_, _, held, ..)| core::cmp::Reverse(held));
    let held: u64 = taken.iter().map(|&(_, _, held, ..)| held).sum();
    output::arguments(format_args!(
        "GPU CALLS held_us={} operation:count/held_us/longest_us/waited_us/unmapped/posted/posted_us",
        micros(held)
    ));
    for &(operation, count, held, longest, waited, unmapped, posted, posted_waited) in
        taken.iter().take(SHOWN)
    {
        output::arguments(format_args!(
            " {operation:#x}:{count}/{}/{}/{}/{unmapped}/{posted}/{}",
            micros(held),
            micros(longest),
            micros(waited),
            micros(posted_waited),
        ));
    }
    // The host's Linux work the calls asked the boot CPU for, by ioctl.
    let (shootdowns, shot) = crate::native_mmio::shootdown::take_waits();
    output::arguments(format_args!(
        "\nGPU POSTED shootdowns={shootdowns}/{}us request:count/waited_us",
        micros(shot)
    ));
    for &(request, count, waited) in posted.iter().take(SHOWN) {
        output::arguments(format_args!(" {request:#x}:{count}/{}", micros(waited)));
    }
    // How long they waited for the boot CPU to take them.
    output::arguments(format_args!("\nGPU TAKEN request:count/us"));
    for &(request, count, taken) in client::take_taken().iter().take(SHOWN) {
        output::arguments(format_args!(" {request:#x}:{count}/{}", micros(taken)));
    }
    // How long they waited for a worker to take them.
    output::arguments(format_args!("\nGPU QUEUED request:count/us"));
    for &(request, count, queued) in client::take_queued().iter().take(SHOWN) {
        output::arguments(format_args!(" {request:#x}:{count}/{}", micros(queued)));
    }
    // What performing them took the service task, waits for the GPU included.
    output::arguments(format_args!("\nGPU SERVED request:count/us"));
    for &(request, count, took) in client::take_served().iter().take(SHOWN) {
        output::arguments(format_args!(" {request:#x}:{count}/{}", micros(took)));
    }
    output::arguments(format_args!("\n"));
}

/// `GPU LOCK operation:held_us/waited_us/longest_wait_us/compiled_us/compiles`:
/// for each operation that held or waited for the service's turn since the
/// last report, the turn's time, the waits for it, the longest one wait,
/// and the compilations it ran outside the turn. Reads before
/// [`report_calls`]'s `GPU CALLS`, which takes the counts.
fn report_lock(tsc_hz: u64) {
    const SHOWN: usize = 12;
    let micros = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1));
    let mut rows: Vec<_> = CALLS
        .iter()
        .filter_map(|calls| {
            let key = calls.key.load(Ordering::Relaxed);
            let longest_wait = calls.longest_wait.swap(0, Ordering::Relaxed);
            let compiled = calls.compiled.swap(0, Ordering::Relaxed);
            let deferrals = calls.deferrals.swap(0, Ordering::Relaxed);
            let held = calls.held.load(Ordering::Relaxed);
            let waited = calls.waited.load(Ordering::Relaxed);
            (key != 0 && (held | waited | compiled) != 0).then_some((
                key - 1,
                held,
                waited,
                longest_wait,
                compiled,
                deferrals,
            ))
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    rows.sort_unstable_by_key(|&(_, held, waited, ..)| core::cmp::Reverse(held + waited));
    let mut line =
        String::from("GPU LOCK operation:held_us/waited_us/longest_wait_us/compiled_us/compiles");
    for &(operation, held, waited, longest, compiled, deferrals) in rows.iter().take(SHOWN) {
        line.push_str(&format!(
            " {operation:#x}:{}/{}/{}/{}/{deferrals}",
            micros(held),
            micros(waited),
            micros(longest),
            micros(compiled),
        ));
    }
    output::arguments(format_args!("{line}\n"));
}

/// NVK's entry point, as Vulkan types it.
unsafe extern "system" fn entry(
    instance: vk::Instance,
    name: *const c_char,
) -> vk::PFN_vkVoidFunction {
    use vk::Handle;
    // SAFETY: the loader's call, and both ends are one function pointer.
    unsafe {
        core::mem::transmute(stela_mesa::vk_icdGetInstanceProcAddr(
            instance.as_raw() as *mut c_void,
            name,
        ))
    }
}

/// The host pages behind whole pages of guest RAM.
fn guest_pages(ranges: &[MemoryRange]) -> Result<Vec<Run>, Error> {
    const NOT_RAM: Error = Error::Invalid("imported memory is whole pages of guest RAM");
    let mut runs: Vec<Run> = Vec::new();
    for range in ranges {
        if !(range.address | range.bytes).is_multiple_of(PAGE) {
            return Err(NOT_RAM);
        }
        let whole = host::guest_runs(range.address, range.bytes, |physical, bytes| {
            match runs.last_mut() {
                Some(last) if last.physical + last.bytes == physical => last.bytes += bytes,
                _ => runs.push(Run { physical, bytes }),
            }
        });
        if !whole {
            return Err(NOT_RAM);
        }
    }
    Ok(runs)
}

/// Guest RAM the kext wired, for NVK to import. The GPU reaches it through
/// the host pages behind it.
struct Exporter;

impl MemoryExporter for Exporter {
    fn export(&self, ranges: &[MemoryRange]) -> Result<ExportedMemory, Error> {
        let runs = guest_pages(ranges)?;
        let (fd, pointer) = client::export(&runs).ok_or(Error::OutOfMemory)?;
        let bytes = runs.iter().map(|run| run.bytes).sum();
        Ok(ExportedMemory { fd, pointer, bytes })
    }

    fn close(&self, exported: ExportedMemory) {
        client::close_descriptor(exported.fd);
        self.unmap(exported);
    }

    fn unmap(&self, exported: ExportedMemory) {
        client::unmap_export(exported.pointer.as_ptr() as u64, exported.bytes);
    }
}

fn service(gpu: &Gpu, stack: u64) -> Result<Arc<Shared>, OpenError> {
    let compiler = |physical| {
        // SAFETY: NVK's own physical device, whose options last as long.
        let options = unsafe { stela_nvk_nir_options(physical) };
        compiler::Service::linked(NonNull::new(options.cast_mut()).expect("NVK has NIR options"))
    };
    let loader = Loader {
        get_instance_proc_addr: entry,
        log: driver_message,
    };
    // SAFETY: the linked NVK and compiler, which last for the boot.
    let service = unsafe {
        open(
            loader,
            Box::new(Exporter),
            compiler,
            gpu,
            DeviceEpoch::from_registered(NonZeroU64::MIN),
        )
    }?;
    let gpu = *gpu;
    // A lost device's channels are gone, so the next client gets a new one,
    // opened on the service's stack as the first was.
    // SAFETY: as above.
    let service = service.with_reopen(Box::new(move || unsafe {
        reopen(loader, Box::new(Exporter), compiler, &gpu)
    }));
    Ok(Arc::new(SharedService::new(
        service,
        ServiceHost {
            relax,
            stack,
            run,
            report,
            note,
            ticks: host::rdtsc,
            served,
            wake: look_again,
            bundle,
        },
    )))
}

/// Open a service over every bound GPU. What stops one is reported, and the
/// Mac boots without Metal on that GPU.
pub(in crate::engine) fn open_service() {
    let Some(gpu) = installed() else {
        return;
    };
    let mut constructed = false;
    let services: Vec<_> = gpu
        .start
        .bound
        .iter()
        .enumerate()
        .filter_map(|(index, bound)| open_gpu(gpu, index, bound, &mut constructed))
        .collect();
    SERVICES.store(Box::into_raw(Box::new(services)), Ordering::Release);
}

/// Runs the image's C constructors once, on the stack of whoever opens first.
fn construct(constructed: &mut bool) {
    if !core::mem::replace(constructed, true) {
        // SAFETY: the one call, before any other of the C's.
        unsafe { stela_mesa::stela_constructors() };
    }
}

/// The service of `bound`, at DRM minor `index`, whose failure is reported.
fn open_gpu(
    gpu: &Installed,
    index: usize,
    bound: &Bound,
    constructed: &mut bool,
) -> Option<Arc<Shared>> {
    let refuse = |reason: &str| {
        crate::output::arguments(format_args!("GPU {}: {reason}\n", bound.name));
        None
    };
    let Some(link) = bound.link else {
        return refuse("no PCIe link");
    };
    let Some(chipset) = client::chipset(index as u32) else {
        return refuse("no chipset reported");
    };
    let Some(stack) = Stack::map(gpu.window, STACK_BYTES) else {
        return refuse("no memory for its service");
    };
    let top = stack.top();
    // It serves for the boot.
    core::mem::forget(stack);
    let target = Gpu {
        pci: PciBusInfo {
            domain: bound.drm.segment.into(),
            bus: bound.drm.bus.into(),
            device: bound.drm.slot.into(),
            function: bound.drm.function.into(),
        },
        chipset,
        // A GPU in a Thunderbolt enclosure reaches Stela as the function
        // firmware enumerated, like any other in a slot.
        attachment: Attachment {
            link,
            external: false,
            location_number: index as u64,
        },
    };
    let mut opened = None;
    run(top, &mut || {
        construct(constructed);
        opened = Some(service(&target, top));
    });
    match opened? {
        Ok(service) => {
            // Without a second stack, every compilation stays in its turn.
            if let Some(compiling) = Stack::map(gpu.window, STACK_BYTES) {
                service.set_compile_stack(compiling.top());
                core::mem::forget(compiling);
            } else {
                output::arguments(format_args!(
                    "GPU {}: no memory for a compile stack; compilations hold the service\n",
                    bound.name
                ));
            }
            Some(service)
        }
        Err(error) => refuse(&format!("Metal could not open: {error:?}")),
    }
}

pub(super) fn shared() -> &'static [Arc<Shared>] {
    // SAFETY: the published services are leaked, so they live for the boot.
    unsafe { SERVICES.load(Ordering::Acquire).as_ref() }.map_or(&[], Vec::as_slice)
}

/// Tell the services a GPU interrupted: its MSI says nothing of which.
pub(super) fn interrupted() {
    shared().iter().for_each(|service| service.interrupted());
}

/// Waits on the completion timeline of each device that has not yet given
/// it, as a newly opened or reopened device has: completed work is then
/// looked for at once.
pub(super) fn watch_completions() {
    for (index, service) in shared().iter().enumerate() {
        if let Some((fd, timeline)) = service.take_completion() {
            super::waiter::start(fd, index, timeline);
        }
    }
}

/// Service `index`'s completion timeline `timeline` reached `value`.
pub(super) fn completed_through(index: usize, timeline: u64, value: u64) {
    if let Some(service) = shared().get(index) {
        service.completed_through(timeline, value);
    }
}

/// Bring every GPU to rest before the PC resets or turns off, on the boot CPU
/// outside Linux's callbacks. Admission closes for good and accepted work
/// finishes; `close_gates` then releases what the guest held of each GPU that
/// proved idle, answering the imports still in reach. Whatever could not be
/// proven stays alive and is reported: the transition itself ends the DMA.
pub(in crate::engine) fn stop(close_gates: impl FnOnce() -> u64) {
    let Some(gpu) = installed() else {
        return;
    };
    let services = shared();
    let ms = |since: u64| host::rdtsc().wrapping_sub(since) / (gpu.tsc_hz / 1000).max(1);
    let began = host::rdtsc();
    services.iter().for_each(|service| service.begin_quiesce());
    for (index, service) in services.iter().enumerate() {
        let status = settle(service, gpu.tsc_hz);
        output::arguments(format_args!("GPU {index} at the stop: {status:?}\n"));
    }
    let quiesce_ms = ms(began);
    let closing = host::rdtsc();
    let reachable = close_gates();
    let close_ms = ms(closing);
    let quarantine = dma_quarantine_status();
    output::arguments(format_args!(
        "GPU stopped: {reachable} imports in reach, {} DMA mappings of {} bytes and {} functions quarantined\n",
        quarantine.mappings,
        quarantine.bytes,
        quarantined_functions(),
    ));
    super::waiter::stop();
    let unloading = host::rdtsc();
    let interrupts = super::interrupts();
    let done = client::shutdown(STOP_UNLOAD_SECONDS);
    // Whether the GPU still interrupted while its driver unloaded, and
    // whether Linux's timers still ran, which its message waits sleep on.
    output::arguments(format_args!(
        "GPU UNLOAD waited_ms={} done={done} quiesce_ms={quiesce_ms} close_ms={close_ms} \
         interrupts={} timer_failure={:?}\n",
        ms(unloading),
        super::interrupts().wrapping_sub(interrupts),
        stela_linux::service::timer_delivery_failure(),
    ));
    if done {
        output::arguments(format_args!("GPU drivers stopped\n"));
    } else {
        output::arguments(format_args!(
            "GPU drivers still stopping after {STOP_UNLOAD_SECONDS} s\n"
        ));
        // The calls still running, the stop among them, and for how long.
        if let Some(line) = client::pool_report(gpu.tsc_hz) {
            output::arguments(format_args!("{line}\n"));
        }
    }
}

/// Unload the GPUs' firmware before a fatal stop ends the machine: the reset
/// that follows takes down the link of a card whose GSP still runs, until a
/// power cycle. The Linux environment that unloads it runs on the boot CPU,
/// so a stop raised there leaves the firmware running and says so. Once.
pub(in crate::engine) fn stop_for_fatal() {
    static STOPPING: AtomicBool = AtomicBool::new(false);
    if installed().is_none() || STOPPING.swap(true, Ordering::AcqRel) {
        return;
    }
    if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
        output::arguments(format_args!(
            "GPU firmware left running: the stop is on the CPU that unloads it\n"
        ));
    } else if client::shutdown_for_fatal(STOP_UNLOAD_SECONDS) {
        output::arguments(format_args!("GPU drivers stopped before the fatal stop\n"));
    } else {
        output::arguments(format_args!(
            "GPU drivers still stopping after {STOP_UNLOAD_SECONDS} s; the firmware may still run\n"
        ));
    }
}

/// Step `service` until accepted work ends or stops moving.
fn settle(service: &Shared, tsc_hz: u64) -> QuiesceStatus {
    let (mut last, mut moved) = (None, host::rdtsc());
    loop {
        let status = service.quiesce_step();
        let QuiesceStatus::Pending { completed, .. } = status else {
            return status;
        };
        if last != Some(completed) {
            (last, moved) = (Some(completed), host::rdtsc());
        } else if host::rdtsc() - moved >= STOP_STALL_SECONDS * tsc_hz {
            return status;
        }
        relax();
    }
}

/// Add each service's gate node to `tree`, for what the board mounts there.
pub(in crate::engine) fn place(
    tree: &mut DeviceTree,
) -> Vec<(stela_gpu::Placement, Arc<dyn GateService>)> {
    let mut gates = Vec::new();
    for (index, service) in shared().iter().enumerate() {
        match stela_gpu::place_gpu_gate(tree, index, window::BYTES) {
            Ok(placement) => gates.push((placement, service.clone() as Arc<dyn GateService>)),
            Err(error) => {
                crate::status::warn(&format!("GPU {index}'s gate has no place: {error}"));
            }
        }
    }
    gates
}
