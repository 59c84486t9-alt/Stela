//! Persistent storage service across the engine's shadow-page-table roots.
//!
//! PC drivers currently use identity addresses for their ECAM/MMIO and DMA
//! buffers. Keep their accesses in the loader's retained root, which also
//! maps the engine window, and restore the current engine root afterwards.
//! This boundary never maps host identity addresses into a guest root. All
//! buffers passed here belong to the engine window, not guest virtual RAM.
use crate::output;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::arch::asm;
use stela_drivers::{
    Handoff,
    block::{BlockDevice, BlockError, Identity, Shared, Window},
    bus::dma::RegionAllocator,
    input::virtio::VirtioInput,
    probe::probe,
    usb::hid::UsbInput,
};
use stela_runtime::pc::{
    gpt::{Guid, PartitionDevice},
    storage::{self, Named, Target},
};

pub(super) struct RestoreRoot {
    root: u64,
    flags: u64,
}
impl RestoreRoot {
    /// # Safety
    /// `root` is the live loader root, retaining the engine window, and the
    /// engine is serialized: no other PE/interrupt may drive this controller.
    pub(super) unsafe fn enter(root: u64) -> Self {
        let (previous, flags): (u64, u64);
        // SAFETY: CPL0, live roots with the same engine code/stack/window.
        // Interrupts remain off until the original root has been restored.
        unsafe {
            asm!("pushfq","pop {flags}","cli","mov {previous}, cr3","mov cr3, {root}",flags=out(reg)flags,previous=out(reg)previous,root=in(reg)root);
        }
        Self {
            root: previous,
            flags,
        }
    }
}
impl Drop for RestoreRoot {
    fn drop(&mut self) {
        // SAFETY: the original live root; no borrowed identity address
        // survives a BlockDevice call. Only IF was changed by enter().
        unsafe {
            asm!("mov cr3, {}",in(reg)self.root,options(nostack,preserves_flags));
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
    fn flush(&mut self) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.flush()
    }
}

/// The host disks [`open`] took, each once, to shut down before the PC
/// restarts or turns off.
pub struct HostDisks {
    disks: Vec<Shared>,
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
        if !self.disks.iter().any(|taken| taken.same(disk)) {
            self.disks.push(disk.clone());
        }
    }

    /// Give every disk its shutdown notice; a failure is reported and the
    /// transition still goes ahead, as it would for a disk that is gone.
    pub fn shutdown(&self, power_off: bool) {
        if self.disks.is_empty() {
            return;
        }
        // SAFETY: open() captured the loader root, as for every service call.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        for disk in &self.disks {
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

/// Open the explicitly selected partitions while the loader's identity root
/// is still active, before host::install, and bring up every host input
/// device and network adapter. No guessed disk/partition, no writes at open. Ownership lasts
/// with the returned services. Probe once for all consumers;
/// do not reset a controller or reuse its DMA pages for a second probe.
///
/// # Safety
/// The handoff describes this running machine, only this service uses its
/// reserved DMA pages, and the loader root/window remain live for the boot.
pub unsafe fn open(
    handoff: &Handoff,
    partitions: &Partitions<'_>,
    usb_disks: &[String],
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
    let root: u64;
    // SAFETY: engine CPL0, before switching away from the loader root.
    unsafe {
        asm!("mov {}, cr3",out(reg)root,options(nomem,nostack,preserves_flags));
    }
    // SAFETY: the caller owns the handoff's DMA pages and controllers.
    let mut dma = unsafe { RegionAllocator::new(handoff.dma.clone()) };
    // SAFETY: the loader mapped these ranges uncached and identity-mapped.
    let mut disks = unsafe { probe(handoff, &mut dma) };
    for (address, error) in &disks.failures {
        output::arguments(format_args!("STORAGE FAILED pci={address} error={error}\n"));
    }
    for (address, warning) in &disks.warnings {
        output::arguments(format_args!("HOST WARNING pci={address}: {warning}\n"));
    }
    for (location, error) in disks.bluetooth_failures() {
        output::arguments(format_args!("BLUETOOTH FAILED {location}: {error}\n"));
    }
    output::arguments(format_args!(
        "BLUETOOTH PLATFORM {:?}\n",
        disks.bluetooth_platform.observation
    ));
    for (location, error) in &disks.usb_vendor_failures {
        output::arguments(format_args!("USB VENDOR FAILED {location}: {error}\n"));
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
    let inputs = Inputs {
        devices: core::mem::take(&mut disks.inputs),
        usb: core::mem::take(&mut disks.usb_inputs),
        root,
    };
    let links = super::network::Links {
        devices: core::mem::take(&mut disks.links),
        root,
    };
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
        match storage::open_shared(&mut disks.devices, &named) {
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
            storage::take(&mut disks.devices, serial)
                .map_err(|error| format!("USB storage {serial}: {error}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    // With `--external-disks`, every disk left, in probe order, up to the
    // hub's free ports; the rest are reported.
    if let Some(ports) = external {
        let rest = core::mem::take(&mut disks.devices);
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
        usb_disks,
        disks: host_disks,
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
    /// Whole disks for the guest's USB mass storage, in option order.
    pub usb_disks: alloc::vec::Vec<Box<dyn BlockDevice>>,
    /// Every disk taken above, for its shutdown notice.
    pub disks: HostDisks,
}

/// The host's input devices and the loader root their registers and DMA
/// pages are reached through.
pub struct Inputs {
    pub devices: alloc::vec::Vec<VirtioInput>,
    pub usb: alloc::vec::Vec<UsbInput>,
    pub root: u64,
}
