//! The host storage hook: what `stela.efi` records for the runtime's PC
//! storage drivers before boot services end, and the disk report and check
//! it runs after.
//!
//! `--storage SERIAL:GUID` in `stela.cfg` opens one partition and reports it
//! without writing. `--storage-check SERIAL:GUID` also overwrites the start
//! of that partition with a known pattern, reads it back and reports its
//! hash. Without either option nothing here touches the hardware.
use crate::{output, paging::Tables};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::time::Duration;
use stela_drivers::{
    Clock, Handoff,
    block::BlockDevice,
    bus::{
        dma::RegionAllocator,
        pci::{Bar, Function},
    },
    input, net,
    probe::probe,
    storage::{ahci, nvme, virtio},
    usb::xhci,
};
use stela_runtime::pc::{
    acpi,
    storage::{self, Target},
};
use uefi::{
    boot::{self, AllocateType, MemoryType, Tpl},
    table::cfg::ConfigTableEntry,
};

const DMA_PAGES: usize = 2048;
/// Bytes the check writes: several transfers, past one PRP list page.
const CHECK_BYTES: usize = 1024 * 1024 + 3 * 4096;

pub struct Prepared {
    handoff: Handoff,
    open: Vec<Target>,
    check: Vec<Target>,
}

/// The storage options, and the rest of `stela.cfg` for the mount.
pub fn split(options: &str) -> Result<(Vec<Target>, Vec<Target>, String), &'static str> {
    let mut open = Vec::new();
    let mut check = Vec::new();
    let mut rest = String::new();
    let mut words = options.split_ascii_whitespace();
    while let Some(word) = words.next() {
        let list = match word {
            "--storage" => &mut open,
            "--storage-check" => &mut check,
            _ => {
                rest.push_str(word);
                rest.push(' ');
                continue;
            }
        };
        list.push(words.next().ok_or("missing storage target")?.parse()?);
    }
    Ok((open, check, rest))
}

pub fn rsdp() -> Option<u64> {
    uefi::system::with_config_table(|entries| {
        let find = |guid| entries.iter().find(|entry| entry.guid == guid);
        find(ConfigTableEntry::ACPI2_GUID)
            .or_else(|| find(ConfigTableEntry::ACPI_GUID))
            .map(|entry| entry.address as u64)
    })
}

/// Before ExitBootServices: find ECAM, reserve DMA pages, measure the TSC
/// and collect the storage controllers' register ranges.
pub fn prepare(
    options: &[u8],
    firmware: Option<Arc<stela_drivers::firmware::Catalog>>,
) -> Result<Option<Prepared>, &'static str> {
    let text = core::str::from_utf8(options).map_err(|_| "stela.cfg is not UTF-8")?;
    let (open, check, _) = split(text)?;
    if open.is_empty() && check.is_empty() {
        return Ok(None);
    }
    let mut handoff = discover()?;
    handoff.firmware = firmware;
    Ok(Some(Prepared {
        handoff,
        open,
        check,
    }))
}

/// What the storage drivers need after ExitBootServices: the ECAM windows,
/// DMA pages below 4 GiB, the TSC rate and every range to map uncached.
/// Runs before ExitBootServices.
pub fn discover() -> Result<Handoff, &'static str> {
    let rsdp = rsdp().ok_or("firmware has no ACPI tables")?;
    // SAFETY: the firmware's RSDP, its tables mapped while boot services last.
    let mcfg = unsafe { acpi::find(rsdp, b"MCFG") }.map_err(|_| "no valid ACPI MCFG table")?;
    let ecam = acpi::mcfg(mcfg).map_err(|_| "invalid ACPI MCFG table")?;
    let dma = boot::allocate_pages(
        AllocateType::MaxAddress(0xffff_ffff),
        MemoryType::LOADER_DATA,
        DMA_PAGES,
    )
    .map_err(|_| "firmware has no DMA pages below 4 GiB")?
    .as_ptr() as u64;
    // SAFETY: RDTSC has no memory effects.
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    boot::stall(Duration::from_millis(10));
    // SAFETY: RDTSC has no memory effects.
    let ticks = unsafe { core::arch::x86_64::_rdtsc() } - start;
    let mut mapped: Vec<_> = ecam.iter().map(|window| window.range()).collect();
    {
        // Size BARs with no firmware event able to reach the devices.
        // SAFETY: restored when the guard drops, before any boot service.
        let _tpl = unsafe { boot::raise_tpl(Tpl::HIGH_LEVEL) };
        for window in &ecam {
            // SAFETY: the firmware maps configuration space while it runs.
            for mut function in unsafe { Function::enumerate(window) } {
                let storage = virtio::matches(&function)
                    || input::virtio::matches(&function)
                    || net::virtio::matches(&function)
                    || net::igc::matches(&function)
                    || net::e1000e::matches(&function)
                    || net::igb::matches(&function)
                    || net::realtek::matches(&function)
                    || stela_drivers::audio::hda::pci::identify(&function).is_ok()
                    || function.class == nvme::CLASS
                    || function.class == ahci::CLASS
                    || function.class == xhci::CLASS;
                if storage {
                    mapped.extend(function.bars().iter().filter_map(|bar| match bar {
                        Some(bar @ Bar::Memory { .. }) => bar.memory(),
                        _ => None,
                    }));
                }
            }
        }
    }
    Ok(Handoff {
        firmware: None,
        ecam,
        mapped,
        dma: dma..dma + (DMA_PAGES * crate::paging::PAGE) as u64,
        clock: Clock {
            ticks_per_microsecond: (ticks / 10_000).max(1),
        },
    })
}

impl Prepared {
    /// Map ECAM and the controllers' registers uncached.
    pub fn map(&self, tables: &mut Tables) -> Result<(), &'static str> {
        self.handoff
            .mapped
            .iter()
            .try_for_each(|range| tables.device(range.start as usize, range.end as usize))
    }

    /// After ExitBootServices: bring up the controllers, report every disk,
    /// then open and check the named partitions. Any failure is fatal.
    pub fn run(self) {
        // SAFETY: one CPU after ExitBootServices; `dma` was reserved for this.
        let mut dma = unsafe { RegionAllocator::new(self.handoff.dma.clone()) };
        // SAFETY: this handoff describes the running machine and its tables.
        let mut disks = unsafe { probe(&self.handoff, &mut dma) };
        for window in &disks.unmapped {
            output::arguments(format_args!("STORAGE UNMAPPED ecam={window:x?}\n"));
        }
        for (address, error) in &disks.failures {
            output::arguments(format_args!("STORAGE FAILED pci={address} error={error}\n"));
        }
        for (address, warning) in &disks.warnings {
            output::arguments(format_args!("HOST WARNING pci={address}: {warning}\n"));
        }
        for (location, error) in disks.bluetooth_failures() {
            output::arguments(format_args!("BLUETOOTH FAILED {location}: {error}\n"));
        }
        for device in &disks.devices {
            let id = device.identity();
            output::arguments(format_args!(
                "STORAGE DEVICE {:?} at {} serial={:?} model={:?} blocks={} block_size={}\n",
                id.transport, id.location, id.serial, id.model, id.blocks, id.block_size
            ));
        }
        let targets = self
            .open
            .iter()
            .map(|target| (target, false))
            .chain(self.check.iter().map(|target| (target, true)));
        for (target, write) in targets {
            let mut partition = match storage::open(&mut disks.devices, target) {
                Ok(partition) => partition,
                Err(error) => {
                    output::arguments(format_args!(
                        "STORAGE REFUSED {}:{} {error}\n",
                        target.serial, target.partition
                    ));
                    output::fatal("storage target refused")
                }
            };
            let disk = partition.disk().clone();
            let blocks = partition.identity().blocks;
            let result = if write {
                storage::check(&mut partition, CHECK_BYTES)
            } else {
                let mut first = alloc::vec![0; disk.block_size as usize];
                partition
                    .read(0, &mut first)
                    .map(|()| stela_runtime::sha256(&first))
                    .map_err(storage::StorageError::Device)
            };
            match result {
                Ok(hash) => output::arguments(format_args!(
                    "STORAGE {} {:?} serial={} partition={} blocks={} bytes={} sha256={hash}\n",
                    if write { "CHECKED" } else { "OPENED" },
                    disk.transport,
                    disk.serial,
                    target.partition,
                    blocks,
                    if write {
                        CHECK_BYTES
                    } else {
                        disk.block_size as usize
                    },
                )),
                Err(error) => {
                    output::arguments(format_args!(
                        "STORAGE ERROR {}:{} {error}\n",
                        target.serial, target.partition
                    ));
                    output::fatal("storage check failed")
                }
            }
        }
    }
}
