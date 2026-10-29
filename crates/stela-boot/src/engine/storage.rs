//! Persistent storage service across the engine's shadow-page-table roots.
//!
//! PC drivers currently use identity addresses for their ECAM/MMIO and DMA
//! buffers. Keep their accesses in the loader's retained root, which also
//! maps the engine window, and restore the current engine root afterwards.
//! This boundary never maps host identity addresses into a guest root. All
//! buffers passed here belong to the engine window, not guest virtual RAM.
//!
//! The drivers keep each controller's state in `Rc` and `RefCell`, for one
//! owner at a time, while the service and every PE reach host devices from
//! cores of their own: a USB disk the guest drives and the USB keyboard the
//! service reads share one xHCI controller. [`RestoreRoot`] is the only way
//! into a driver, so it also holds the host drivers' lock, which serializes
//! them and orders each holder's writes before the next holder's reads.
//!
//! While the engine runs ([`TaggedRoots`]), the loader's root has a TLB
//! context of its own, so a driver call keeps the engine's translations.
use crate::output;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_drivers::{
    Handoff,
    block::{
        BlockDevice, BlockError, CallbackStats, Command, Direction, Finished, Identity, Shared,
        Window,
    },
    bus::dma::RegionAllocator,
    input::InputDevice,
    probe::{NativeServices, probe_with_provider},
};
use stela_runtime::pc::{
    gpt::{Guid, PartitionDevice},
    storage::{self, Named, Target},
};

/// CR4.PCIDE: TLB entries tagged by their root's context.
const PCIDE: u64 = 1 << 17;
/// CR3's context, which holds PWT and PCD without PCIDE.
const CONTEXT: u64 = 0xfff;
/// The loader root's context while tagged; every engine root keeps 0.
const LOADER_CONTEXT: u64 = 1;
/// A CR3 write that keeps the entering context's TLB entries.
const KEEP_ENTRIES: u64 = 1 << 63;

/// Tags this core's TLB entries by root while the engine runs. Entering the
/// loader's root ([`RestoreRoot`]) then flushes only its own context and
/// leaving it flushes nothing, so the engine's translations survive a call
/// into the host drivers. Every engine root keeps context 0, whose CR3
/// writes still flush, so INVLPG and root reloads keep their meaning; no
/// engine mapping changes inside a driver call. Dropped, CR4 is restored
/// for the native qualifications, which require PCIDE clear.
pub(super) struct TaggedRoots {
    cr4: u64,
}
impl TaggedRoots {
    /// None without PCIDs, or with cache controls in the current root's
    /// context bits.
    pub(super) fn enable() -> Option<Self> {
        if core::arch::x86_64::__cpuid(1).ecx & 1 << 17 == 0 {
            return None;
        }
        let (cr3, cr4): (u64, u64);
        // SAFETY: CPL0 control register reads.
        unsafe {
            asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        }
        if cr4 & PCIDE != 0 || cr3 & CONTEXT != 0 {
            return None;
        }
        // SAFETY: the processor has PCIDs and the current root context 0.
        unsafe { asm!("mov cr4, {}", in(reg) cr4 | PCIDE, options(nostack, preserves_flags)) };
        Some(Self { cr4 })
    }
}
impl Drop for TaggedRoots {
    fn drop(&mut self) {
        // SAFETY: outside a driver call the current root has context 0;
        // clearing PCIDE flushes every context.
        unsafe { asm!("mov cr4, {}", in(reg) self.cr4, options(nostack, preserves_flags)) };
    }
}

/// Held while a core is inside the host drivers ([`RestoreRoot`]).
static HOST_DRIVERS: AtomicBool = AtomicBool::new(false);
static HOST_DRIVERS_GS: AtomicU64 = AtomicU64::new(0);

/// Validate the existing manager's actual same-CPU entered loader context.
/// Allocation and CPU authority remain with the caller's genuine retained owner.
pub(super) fn entered_loader_root(owner: &crate::paging::loader::LoaderTables) -> bool {
    if !HOST_DRIVERS.load(Ordering::Acquire) {
        return false;
    }
    let (root, cr4, gs): (u64, u64, u64);
    // SAFETY: this internal query follows RootIdentity's CPL0/CPU admission.
    unsafe {
        asm!("mov {}, cr3", "mov {}, cr4", out(reg) root, out(reg) cr4, options(nomem, nostack, preserves_flags));
        gs = crate::cpu::msr::GS_BASE.read();
    }
    let expected = if cr4 & PCIDE != 0 {
        owner.root() | LOADER_CONTEXT
    } else {
        owner.root()
    };
    gs != 0 && HOST_DRIVERS_GS.load(Ordering::Acquire) == gs && root == expected
}
/// Counter ticks cores waited for [`HOST_DRIVERS`] since the last report,
/// and the longest wait.
static HOST_DRIVERS_WAITED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Take the host drivers' lock, counting the wait.
fn lock_host_drivers() {
    if HOST_DRIVERS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return;
    }
    let started = super::host::rdtsc();
    while HOST_DRIVERS
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let waited = super::host::rdtsc().wrapping_sub(started);
    HOST_DRIVERS_WAITED[0].fetch_add(waited, Ordering::Relaxed);
    HOST_DRIVERS_WAITED[1].fetch_max(waited, Ordering::Relaxed);
}

/// The time cores waited for the host drivers since the last report, in
/// total and at most, in microseconds.
pub(super) fn host_drivers_waited(tsc_hz: u64) -> (u128, u128) {
    let micros = |slot: &AtomicU64| {
        u128::from(slot.swap(0, Ordering::Relaxed)) * 1_000_000 / u128::from(tsc_hz.max(1))
    };
    (
        micros(&HOST_DRIVERS_WAITED[0]),
        micros(&HOST_DRIVERS_WAITED[1]),
    )
}

/// Inside the host drivers: the loader's root, with interrupts masked and
/// the host drivers' lock held, until dropped.
pub(super) struct RestoreRoot {
    root: u64,
    flags: u64,
    tagged: bool,
    _local: core::marker::PhantomData<*mut ()>,
}
impl RestoreRoot {
    /// Wait for the host drivers' lock, which no holder takes again: a
    /// driver never calls back into the engine's host interfaces.
    ///
    /// # Safety
    /// `root` is the live loader root, retaining the engine window.
    pub(super) unsafe fn enter(root: u64) -> Self {
        lock_host_drivers();
        let (previous, flags, cr4): (u64, u64, u64);
        // SAFETY: CPL0 control register reads; interrupts remain off until
        // the original root has been restored.
        unsafe {
            asm!("pushfq","pop {flags}","cli","mov {previous}, cr3","mov {cr4}, cr4",flags=out(reg)flags,previous=out(reg)previous,cr4=out(reg)cr4);
        }
        // SAFETY: actual native CPU; this records the same concrete manager
        // owner while IF0 excludes its own IRQ/reentrant root transition.
        let gs = unsafe { crate::cpu::msr::GS_BASE.read() };
        HOST_DRIVERS_GS.store(gs, Ordering::Release);
        let tagged = cr4 & PCIDE != 0;
        // Tagged, entering flushes the loader's context alone.
        let root = if tagged {
            root & !CONTEXT | LOADER_CONTEXT
        } else {
            root
        };
        // SAFETY: live roots with the same engine code/stack/window.
        unsafe { asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) };
        Self {
            root: previous,
            flags,
            tagged,
            _local: core::marker::PhantomData,
        }
    }
}
impl Drop for RestoreRoot {
    fn drop(&mut self) {
        // Tagged, the engine root's entries are still its own: nothing in
        // a driver call changes an engine mapping.
        let root = if self.tagged {
            self.root | KEEP_ENTRIES
        } else {
            self.root
        };
        // SAFETY: the original live root; no borrowed identity address
        // survives a BlockDevice call.
        unsafe {
            asm!("mov cr3, {}",in(reg)root,options(nostack,preserves_flags));
        }
        HOST_DRIVERS_GS.store(0, Ordering::Release);
        HOST_DRIVERS.store(false, Ordering::Release);
        // SAFETY: only IF was changed by enter().
        unsafe {
            if self.flags & (1 << 9) != 0 {
                asm!("sti", options(nomem, nostack));
            }
        }
    }
}

struct Service {
    inner: Box<dyn BlockDevice>,
    root: u64,
}
impl BlockDevice for Service {
    fn identity(&self) -> &Identity {
        self.inner.identity()
    }
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        // SAFETY: open() captured the loader root; callers supply window RAM.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.read(lba, buffer)
    }
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.write(lba, data)
    }
    fn flush_cache(&mut self) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.flush_cache()
    }
    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.write_fua(lba, data)
    }
    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.discard(lba, blocks)
    }
    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.write_zeroes(lba, blocks, unmap)
    }
    fn depth(&self) -> usize {
        self.inner.depth()
    }
    fn room(&self) -> bool {
        self.inner.room()
    }
    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.start(command)
    }
    fn finish(&mut self, tag: u32) -> Option<Finished> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.finish(tag)
    }
    fn posted(&self) -> bool {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.posted()
    }
    fn signals(&self) -> bool {
        // SAFETY: as in read(); this query reaches shared controller state.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.signals()
    }
}

/// The host disks [`open`] took, each once with its serial, to report
/// their I/O and to shut down before the PC restarts or turns off.
pub struct HostDisks {
    disks: Vec<(String, Shared)>,
    root: u64,
}

impl HostDisks {
    pub fn none() -> Self {
        Self {
            disks: Vec::new(),
            root: 0,
        }
    }

    fn add(&mut self, disk: &Shared) {
        if !self.disks.iter().any(|(_, taken)| taken.same(disk)) {
            let serial = disk.whole().identity().serial.clone();
            self.disks.push((serial, disk.clone()));
        }
    }

    pub fn profile_callbacks(&self, enabled: bool) {
        for (_, disk) in &self.disks {
            disk.set_callback_profile(enabled);
        }
    }

    /// Each disk's I/O since it was opened, as Linux's `/proc/diskstats`:
    /// per kind its commands, KiB, mean microseconds from submission to
    /// completion and requests merged; the device's busy milliseconds and
    /// the most commands it ran at once.
    pub fn report(&self, tsc_hz: u64) {
        let micros = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1));
        for (serial, disk) in &self.disks {
            let stats = disk.stats();
            let mut line = format!("HOST DISK IO serial={serial}");
            for direction in Direction::ALL {
                let counts = stats.directions[direction as usize];
                if counts.ios != 0 {
                    line.push_str(&format!(
                        " {}={}/{}KiB/{}us/{}",
                        direction.name(),
                        counts.ios,
                        counts.bytes >> 10,
                        micros(counts.ticks) / u128::from(counts.ios),
                        counts.merges,
                    ));
                }
            }
            output::arguments(format_args!(
                "{line} busy_ms={} deepest={}\n",
                micros(stats.busy) / 1000,
                stats.deepest
            ));
            if let Some(callbacks) = stats.callbacks {
                Self::report_callback(serial, callbacks, tsc_hz, "periodic");
            }
        }
    }

    /// One bounded snapshot before stop-time persistence; never waits for a
    /// disk owner, changes roots or accesses an active driver's registers.
    pub fn report_callbacks(&self, tsc_hz: u64) {
        for (serial, disk) in &self.disks {
            if let Some(activity) = disk.callback_activity() {
                output::arguments(format_args!(
                    "HOST DISK ACTIVITY serial={serial} counter_hz={tsc_hz} observed_before={} observed_after={} advance={:?} direct={:?} none=idle-or-raced coherent=false authority=none\n",
                    activity.observed_before_ticks,
                    activity.observed_after_ticks,
                    activity.advance,
                    activity.direct,
                ));
            }
            match disk.callback_stats() {
                Some(callbacks) => Self::report_callback(serial, callbacks, tsc_hz, "guest-stop"),
                None => output::arguments(format_args!(
                    "HOST DISK CALLBACK serial={serial} phase=guest-stop unavailable=disabled-unpublished-or-held\n"
                )),
            }
        }
    }

    fn report_callback(serial: &str, callbacks: CallbackStats, tsc_hz: u64, phase: &str) {
        let micros = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1));
        let advance = callbacks.advance;
        let direct = callbacks.direct;
        output::arguments(format_args!(
            "HOST DISK CALLBACK serial={serial} phase={phase} nested-not-additive=true advance_calls={} advance_total_us={} advance_max_us={} starts={} finishes={} max_starts={} max_finishes={} direct_calls={} direct_total_us={} direct_max_us={}\n",
            advance.calls,
            micros(advance.elapsed_ticks),
            micros(advance.maximum_ticks),
            advance.starts,
            advance.finishes,
            advance.maximum_starts,
            advance.maximum_finishes,
            direct.calls,
            micros(direct.elapsed_ticks),
            micros(direct.maximum_ticks)
        ));
    }

    /// Give every disk its shutdown notice; a failure is reported and the
    /// transition still goes ahead, as it would for a disk that is gone.
    pub fn shutdown(&self, power_off: bool) {
        if self.disks.is_empty() {
            return;
        }
        // SAFETY: open() captured the loader root, as for every service call.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        for (_, disk) in &self.disks {
            if let Err(error) = disk.shutdown(power_off) {
                output::arguments(format_args!("HOST DISK shutdown failed: {error}\n"));
            }
        }
    }
}

/// The partitions [`open`] opens, each named explicitly.
#[derive(Clone, Copy)]
pub struct Partitions<'a> {
    /// The guest's disks, in order: one service each.
    pub targets: &'a [&'a Target],
    /// The install medium, by its GUID.
    pub medium: Option<Guid>,
    /// The installed system `--preboot` names.
    pub preboot: Option<&'a Target>,
    /// The translation store, by its GUID; left out when it cannot open.
    pub store: Option<Guid>,
    /// The USB's boot log, by its GUID; left out when it cannot open.
    pub log: Option<Guid>,
    /// Required host-owned durable FDR file volume, when explicitly staged.
    pub fdr: Option<Guid>,
}

/// Open the explicitly selected partitions in the loader's identity root
/// `root` ([`RestoreRoot`]), and bring up every host input device and
/// network adapter. No guessed disk/partition, no writes at open. Ownership lasts
/// with the returned services. Probe once for all consumers;
/// do not reset a controller or reuse its DMA pages for a second probe.
///
/// # Safety
/// The handoff describes this running machine, only this service uses its
/// reserved DMA pages, `root` is the loader's root, and it and the window
/// remain live for the boot. The actual owned work dispatcher already holds
/// its RestoreRoot/host-driver guard and this is a real admitted continuation;
/// acquiring that non-reentrant guard again is forbidden.
pub unsafe fn open(
    handoff: &Handoff,
    root: u64,
    services: Option<&dyn NativeServices>,
    partitions: &Partitions<'_>,
    usb_disks: &[String],
    wifi: Option<&stela_drivers::probe::WifiConfig>,
    external: Option<usize>,
) -> Result<Opened, String> {
    let Partitions {
        targets,
        medium,
        preboot,
        store,
        log,
        fdr,
    } = *partitions;
    if let Some(serial) = usb_disks
        .iter()
        .find(|serial| targets.iter().any(|target| &target.serial == *serial))
    {
        return Err(format!(
            "host disk {serial} is both a USB storage disk and a partition target"
        ));
    }
    // SAFETY: the caller owns the handoff's DMA pages and controllers.
    let mut dma = unsafe { RegionAllocator::new(handoff.dma.clone()) };
    let firmware = stela_drivers::probe::handoff_provider(handoff);
    // SAFETY: the loader mapped these ranges uncached and identity-mapped.
    let mut devices = unsafe { probe_with_provider(handoff, &mut dma, firmware, services, wifi) };
    // The owners native attachments keep, and those of failed ones, stay
    // for the boot: their mappings and DMA domains outlive the devices.
    Vec::leak(core::mem::take(&mut devices.owners));
    for (address, error) in &devices.failures {
        output::arguments(format_args!("STORAGE FAILED pci={address} error={error}\n"));
    }
    for (location, error) in &devices.platform_failures {
        output::arguments(format_args!("PLATFORM FAILED {location}: {error}\n"));
    }
    match &devices.regulatory {
        Some(Ok(_)) => output::arguments(format_args!("HOST Wi-Fi regulatory database loaded\n")),
        Some(Err(error)) => output::arguments(format_args!(
            "HOST Wi-Fi regulatory database missing ({error:?}): the Wi-Fi adapters stay off\n"
        )),
        None => {}
    }
    for (address, warning) in &devices.warnings {
        output::arguments(format_args!("HOST WARNING pci={address}: {warning}\n"));
    }
    for (location, error) in devices.bluetooth_failures() {
        output::arguments(format_args!("BLUETOOTH FAILED {location}: {error}\n"));
    }
    output::arguments(format_args!(
        "BLUETOOTH PLATFORM {:?}\n",
        devices.bluetooth_platform.observation
    ));
    for (location, error) in &devices.usb_vendor_failures {
        output::arguments(format_args!("USB VENDOR FAILED {location}: {error}\n"));
    }
    for (address, class, why) in &devices.unsupported {
        output::arguments(format_args!(
            "HOST UNSUPPORTED pci={address} class={:02x}{:02x}{:02x}: {why}\n",
            class[0], class[1], class[2]
        ));
    }
    for (location, error) in &devices.device_failures {
        output::arguments(format_args!("STORAGE FAILED {location}: {error}\n"));
    }
    for (location, error) in &devices.usb_failures {
        output::arguments(format_args!(
            "USB FAILED {location}: {}\n",
            stela_drivers::usb::xhci::explain(error)
        ));
    }
    for (location, why) in &devices.usb_unused {
        output::arguments(format_args!("USB UNUSED {location}: {why}\n"));
    }
    let inputs = Inputs {
        devices: core::mem::take(&mut devices.inputs),
        root,
    };
    let links = super::network::Links {
        devices: core::mem::take(&mut devices.nics),
        root,
    };
    let usb = super::usb::HostUsb::new(
        core::mem::take(&mut devices.usb_hosts),
        dma,
        handoff.firmware.clone(),
        root,
        handoff.clock.ticks_per_microsecond * 1_000_000,
    );
    // One disk may hold several of them: the stick holds the Mac's internal
    // SSD, the install medium, the translation store and the boot log, and
    // the internal SSD the installed system the Preboot volume names. The
    // store and the log are optional: one that cannot be opened is reported
    // and left out.
    let mut named: Vec<Named> = targets
        .iter()
        .map(|target| Named::Disk((*target).clone()))
        .chain(medium.map(Named::Unique))
        .chain(preboot.map(|target| Named::Disk(target.clone())))
        .chain(fdr.map(Named::Host))
        .collect();
    let required = named.len();
    let mut optional: Vec<(Named, Optional)> = store
        .map(|guid| (Named::Unique(guid), Optional::Store))
        .into_iter()
        .chain(log.map(|guid| (Named::Host(guid), Optional::Log)))
        .collect();
    let describe = |named: &Named, error: storage::StorageError| match named {
        Named::Disk(target) => format!("{}:{}: {error}", target.serial, target.partition),
        Named::Unique(guid) | Named::Host(guid) => format!("partition {guid}: {error}"),
    };
    let mut opened = loop {
        named.truncate(required);
        named.extend(optional.iter().map(|(named, _)| named.clone()));
        match storage::open_shared(&mut devices.disks, &named) {
            Ok(opened) => break opened,
            Err((at, error)) if at >= required => {
                let (named, which) = optional.remove(at - required);
                output::arguments(format_args!(
                    "HOST PARTITION {} left out: {}\n",
                    which.role(),
                    describe(&named, error)
                ));
            }
            Err((at, error)) => return Err(describe(&named[at], error)),
        }
    };
    let mut host_disks = HostDisks {
        disks: Vec::new(),
        root,
    };
    for partition in &opened {
        host_disks.add(partition.device().shared());
    }
    let service = |partition: PartitionDevice<Window>, role: &str| -> Box<dyn BlockDevice> {
        output::arguments(format_args!(
            "HOST PARTITION serial={} partition={} blocks={} block_size={}{role}\n",
            partition.disk().serial,
            partition.partition().unique,
            partition.identity().blocks,
            partition.identity().block_size
        ));
        Box::new(Service {
            inner: Box::new(partition),
            root,
        })
    };
    let (mut store_partition, mut log_partition) = (None, None);
    for (_, which) in optional.iter().rev() {
        let role = format!(" ({})", which.role());
        let partition = Some(service(opened.pop().expect("an optional partition"), &role));
        match which {
            Optional::Store => store_partition = partition,
            Optional::Log => log_partition = partition,
        }
    }
    let fdr = fdr.map(|_| service(opened.pop().expect("FDR storage"), " (FDR storage)"));
    let preboot = preboot.map(|_| {
        service(
            opened.pop().expect("the installed system"),
            " (installed system)",
        )
    });
    let medium = medium.map(|_| service(opened.pop().expect("the medium"), " (install medium)"));
    let services = opened
        .into_iter()
        .map(|partition| service(partition, ""))
        .collect();
    let mut taken = usb_disks
        .iter()
        .map(|serial| {
            storage::take(&mut devices.disks, serial)
                .map_err(|error| format!("USB storage {serial}: {error}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    // With `--external-disks`, every disk left, in probe order, up to the
    // hub's free ports; the rest are reported.
    if let Some(ports) = external {
        let rest = core::mem::take(&mut devices.disks);
        for (index, disk) in rest.into_iter().enumerate() {
            if index < ports {
                taken.push(disk);
            } else {
                output::arguments(format_args!(
                    "HOST DISK serial={} left out: the guest's hub has no free port\n",
                    disk.identity().serial
                ));
            }
        }
    }
    let usb_disks = taken
        .into_iter()
        .map(|disk| {
            let disk = Shared::new(disk);
            host_disks.add(&disk);
            let disk = disk.whole();
            output::arguments(format_args!(
                "HOST USB DISK serial={} model={:?} blocks={} block_size={} read_only={}\n",
                disk.identity().serial,
                disk.identity().model,
                disk.identity().blocks,
                disk.identity().block_size,
                disk.identity().read_only
            ));
            Box::new(Service {
                inner: Box::new(disk),
                root,
            }) as Box<dyn BlockDevice>
        })
        .collect();
    Ok(Opened {
        services,
        medium,
        preboot,
        store: store_partition,
        log: log_partition,
        fdr,
        inputs,
        links,
        usb,
        usb_disks,
        disks: host_disks,
        power: core::mem::take(&mut devices.power),
    })
}

/// A partition [`open`] leaves out when it cannot be opened.
#[derive(Clone, Copy)]
enum Optional {
    Store,
    Log,
}

impl Optional {
    fn role(self) -> &'static str {
        match self {
            Optional::Store => "translation store",
            Optional::Log => "boot log",
        }
    }
}

/// What [`open`] brought up: a service per target, in order, and the
/// host's input devices and network adapters.
pub struct Opened {
    pub power: stela_drivers::probe::Power,
    pub services: alloc::vec::Vec<Box<dyn BlockDevice>>,
    /// The install medium's partition, found by its GUID.
    pub medium: Option<Box<dyn BlockDevice>>,
    /// The partition `--preboot` names, which the boot bundle is built from.
    pub preboot: Option<Box<dyn BlockDevice>>,
    /// The translation store's partition, found by its GUID.
    pub store: Option<Box<dyn BlockDevice>>,
    /// The partition holding the USB's boot log, found by its GUID.
    pub log: Option<Box<dyn BlockDevice>>,
    pub fdr: Option<Box<dyn BlockDevice>>,
    pub inputs: Inputs,
    pub links: super::network::Links,
    /// The xHCI controllers' topology owners, polled for hotplug.
    pub usb: super::usb::HostUsb,
    /// Whole disks for the guest's USB mass storage, in option order.
    pub usb_disks: alloc::vec::Vec<Box<dyn BlockDevice>>,
    /// Every disk taken above, for its shutdown notice.
    pub disks: HostDisks,
}

/// The host's input devices and the loader root their registers and DMA
/// pages are reached through.
pub struct Inputs {
    pub devices: alloc::vec::Vec<InputDevice>,
    pub root: u64,
}
