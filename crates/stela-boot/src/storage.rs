//! The host storage hook: what `stela.efi` records for the runtime's PC
//! storage drivers before boot services end, and the disk report and check
//! it runs after.
//!
//! `--storage SERIAL:GUID` in `stela.cfg` opens one partition and reports it
//! without writing. `--storage-check SERIAL:GUID` also overwrites the start
//! of that partition with a known pattern, reads it back and reports its
//! hash. Without either option nothing here touches the hardware.
mod bluetooth_platform;
mod media_check;
mod options;
mod reset_check;
pub use options::split;

use crate::{output, paging::Tables};
use alloc::{sync::Arc, vec::Vec};
use core::time::Duration;
use stela_drivers::{
    Clock, Handoff,
    block::BlockDevice,
    bus::{
        dma::RegionAllocator,
        pci::{Bar, Function},
    },
    probe::probe,
};
use stela_runtime::pc::{
    acpi,
    storage::{self, Target},
};
use uefi::{
    boot::{self, AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams, Tpl},
    proto::nvme::{NvmeQueueType, NvmeRequestBuilder, pass_thru::NvmePassThru},
    table::cfg::ConfigTableEntry,
};

const DMA_PAGES: usize = 2048;
/// `max_host_mem_size_mb`: the most host memory buffer one NVMe controller
/// gets.
const HOST_MEMORY_MAXIMUM: u64 = 128 << 20;
/// Bytes the check writes: several transfers, past one PRP list page.
const CHECK_BYTES: usize = 1024 * 1024 + 3 * 4096;

pub struct Prepared {
    handoff: Handoff,
    open: Vec<Target>,
    check: Vec<Target>,
    usb_reset_check: bool,
    usb_media_check: bool,
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
    wifi_platform: stela_drivers::net::wifi::intel::platform::Observations,
) -> Result<Option<Prepared>, &'static str> {
    let text = core::str::from_utf8(options).map_err(|_| "stela.cfg is not UTF-8")?;
    let (open, check, _) = split(text)?;
    let usb_reset_check = options::reset_requested(text, &open, &check)?;
    let usb_media_check = options::media_requested(text, &open, &check)?;
    if open.is_empty() && check.is_empty() {
        return Ok(None);
    }
    let mut handoff = discover()?;
    handoff.firmware = firmware;
    handoff.wifi_platform = wifi_platform;
    Ok(Some(Prepared {
        handoff,
        open,
        check,
        usb_reset_check,
        usb_media_check,
    }))
}

/// The pages host memory buffers take in the DMA pool, for each NVMe
/// controller the firmware drives, as `nvme_setup_host_mem` sizes them:
/// HMPRE capped at `max_host_mem_size_mb`, none when HMMIN exceeds that,
/// and a page for each descriptor list.
fn host_memory_pages() -> usize {
    let Ok(handles) = boot::find_handles::<NvmePassThru>() else {
        return 0;
    };
    let required = |handle| {
        // SAFETY: one Identify Controller while boot services run; the
        // firmware keeps driving the controller.
        let pass_thru = unsafe {
            boot::open_protocol::<NvmePassThru>(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .ok()?;
        let request = NvmeRequestBuilder::new(pass_thru.io_align(), 0x06, NvmeQueueType::ADMIN)
            .with_timeout(Duration::from_secs(1))
            .with_cdw10(1)
            .with_transfer_buffer(4096)
            .ok()?
            .build();
        let response = pass_thru.controller().execute_command(request).ok()?;
        let identify = response.transfer_buffer()?;
        let pages = |at: usize| {
            let bytes = identify.get(at..at + 4)?;
            Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?)) * 4096)
        };
        let (preferred, minimum) = (pages(272)?, pages(276)?);
        if preferred == 0 || minimum > HOST_MEMORY_MAXIMUM {
            return None;
        }
        Some(preferred.min(HOST_MEMORY_MAXIMUM) as usize / crate::paging::PAGE + 1)
    };
    handles.iter().copied().filter_map(required).sum()
}

/// What the storage drivers need after ExitBootServices: the ECAM windows,
/// DMA pages below 4 GiB, the TSC rate and every range to map uncached.
/// Runs before ExitBootServices.
pub fn discover() -> Result<Handoff, &'static str> {
    let rsdp = rsdp().ok_or("firmware has no ACPI tables")?;
    // SAFETY: the firmware's RSDP, its tables mapped while boot services last.
    let mcfg = unsafe { acpi::find(rsdp, b"MCFG") }.map_err(|_| "no valid ACPI MCFG table")?;
    let ecam = acpi::mcfg(mcfg).map_err(|_| "invalid ACPI MCFG table")?;
    let allocate = |pages| {
        boot::allocate_pages(
            AllocateType::MaxAddress(0xffff_ffff),
            MemoryType::LOADER_DATA,
            pages,
        )
        .map(|pages| pages.as_ptr() as u64)
    };
    // Without room for the host memory buffers the controllers run without
    // them, as Linux's do when that allocation fails.
    let extra = host_memory_pages();
    let (dma, pages) = match allocate(DMA_PAGES + extra) {
        Ok(dma) => (dma, DMA_PAGES + extra),
        Err(_) => (
            allocate(DMA_PAGES).map_err(|_| "firmware has no DMA pages below 4 GiB")?,
            DMA_PAGES,
        ),
    };
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
                if stela_drivers::probe::claims(&function) {
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
        bluetooth_platform: bluetooth_platform::capture(),
        wifi_platform: Default::default(),
        ecam,
        mapped,
        dma: dma..dma + (pages * crate::paging::PAGE) as u64,
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
        let mut disks = if self.usb_media_check {
            // SAFETY: same exclusive post-EBS grant as probe; this explicit
            // fixture diagnostic attaches native USB and retains every owner.
            match unsafe { media_check::probe_and_rescan(&self.handoff, &mut dma, &self.check[0]) }
            {
                Ok(disks) => disks,
                Err(error) => output::fatal(error),
            }
        } else if self.usb_reset_check {
            // SAFETY: the same exclusive post-EBS grant as probe, restricted
            // to native USB attachment for this explicit diagnostic.
            match unsafe { reset_check::probe_and_reset(&self.handoff, &mut dma, &self.check[0]) } {
                Ok(disks) => disks,
                Err(error) => output::fatal(error),
            }
        } else {
            // SAFETY: this handoff describes the running machine and its tables.
            unsafe { probe(&self.handoff, &mut dma) }
        };
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
        output::arguments(format_args!(
            "BLUETOOTH PLATFORM {:?}\n",
            disks.bluetooth_platform.observation
        ));
        for (location, error) in &disks.usb_vendor_failures {
            output::arguments(format_args!("USB VENDOR FAILED {location}: {error}\n"));
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
