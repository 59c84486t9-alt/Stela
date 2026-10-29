//! A board's whole machine: every device model its DeviceTree describes
//! (`soc::board`), placed on one [`AppleDevices`] and connected to its PMGR
//! lifecycle. The host's inputs (console, disks, cables, scanout, entropy and
//! board firmware files) come from the caller, so `stela.efi` and
//! `stela-dev boot check` mount the same machine.
use super::apple::AicInput;
use super::apple::AppleDevices;
use super::apple::AscLines;
use super::apple::ConsoleSink;
use super::apple::Range;
use super::apple::RtcEpoch;
use super::apple::Scanout;
use super::apple::SepEntropy;
use super::apple::SepProvisioning;
use super::apple::UsbCables;
use super::apple::UsbId;
use super::apple::memory_resources::t6000_cold;
use super::apple::memory_resources::t8112;
use super::apple::sep_state;
use super::apple::typec;
use super::soc::{Board, PmgrBankRefusal};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::fmt;
use stela_drivers::block::BlockDevice;
use stela_engine::machine::ctrr;
use stela_soc_data::pmu::WallClock;

/// Already constructed native owners, consumed by the board mount. Descriptor
/// equality is checked before any host input or bus placement is consumed.
/// This is placement, not canonical execution or native PMP admission.
#[allow(
    clippy::large_enum_variant,
    reason = "cold placement resources are moved once and consumed together before guest entry"
)]
pub enum MemoryResources {
    /// Source-checked cold resources whose lifecycle is sampled from the actual
    /// placed PMGR before the native memory owners are constructed.
    T8112Cold(super::apple::t8112_cold::Plan),
    /// Direct MCC/AMCC/PTD frontend; keeps its full source graph and canonical
    /// RAM separate from the T8112 cache/quota protocol.
    T6000Cold(t6000_cold::Plan),
    T8112 {
        memory: t8112::Prepared,
        cache: t8112::cache::EmptyResource,
    },
}

impl MemoryResources {
    fn validate(
        &self,
        controller: Option<&super::soc::MemoryController>,
        descriptor: Option<&super::soc::MemoryCache>,
        direct: Option<&super::soc::DirectMemoryCache>,
    ) -> Result<(), String> {
        if direct.is_some() && !matches!(self, Self::T6000Cold(_)) {
            return Err("cache/quota native memory cannot adopt a direct MCC descriptor".into());
        }
        match self {
            Self::T8112Cold(plan) => plan.validate(controller, descriptor),
            Self::T6000Cold(plan) => {
                if descriptor.is_some() {
                    return Err("direct native memory cannot adopt a cache/quota descriptor".into());
                }
                plan.validate(controller, direct)
            }
            Self::T8112 { memory, cache } => {
                if descriptor != Some(memory.descriptor()) || controller != Some(cache.source()) {
                    return Err(
                        "native memory resources differ from the live board descriptors".into(),
                    );
                }
                if !alloc::sync::Arc::ptr_eq(memory.registered_ram(), cache.registered_ram()) {
                    return Err(
                        "native memory resources require the same actual registered RAM".into(),
                    );
                }
                if cache.binding().0.checked_add(cache.binding().1)
                    != Some(memory.descriptor().channels.0)
                {
                    return Err("native cache and DCS physical ownership is not contiguous".into());
                }
                Ok(())
            }
        }
    }
}

/// The regions iBoot leaves in the memory controller's lock groups:
/// CTRR-A over the bundle's read-only run, and CTRR-C and CTRR-D over the
/// cores' regions of those names, which SPTM requires the AMCC's to match
/// before it locks them (`amcc`). CTRR-B stays unprogrammed.
pub fn memory_locks(
    read_only_region: Option<(u64, u64)>,
    core_locks: &ctrr::CoreLocks,
) -> stela_soc_data::amcc::Programmed {
    let mut programmed = stela_soc_data::amcc::ctrr_a(read_only_region);
    for locked in &core_locks.locked {
        let group = match locked.region {
            ctrr::LockRegion::CtrrC => 2,
            ctrr::LockRegion::CtrrD => 3,
            _ => continue,
        };
        programmed[group] = Some((locked.first, locked.last + 1 - locked.first));
    }
    programmed
}

/// Report unsupported PMGR qualifications once, before a device is placed.
/// A diagnostic supplies no successful MMIO or lifecycle response.
pub fn pmgr_qualifications(refusals: &[PmgrBankRefusal], log: &mut dyn FnMut(fmt::Arguments<'_>)) {
    for (index, refusal) in refusals.iter().enumerate() {
        if refusals[..index].contains(refusal) {
            continue;
        }
        log(format_args!(
            "UNMODELED PMGR {:?}: {}; no register/lifecycle model\n",
            refusal.bank, refusal.reason,
        ));
    }
}

/// Paths qualified by immutable source identity and bundle admission. Keeping
/// CLPC unavailable is a documented degradation, not a successful controller.
pub fn clpc_absence(hidden: &[String], log: &mut dyn FnMut(fmt::Arguments<'_>)) {
    for (index, path) in hidden.iter().enumerate() {
        if hidden[..index].contains(path) {
            continue;
        }
        log(format_args!(
            "UNMODELED CLPC {path}: controller hidden; closed-loop CPU power control unavailable\n"
        ));
    }
}

/// What the host connects to the board.
pub struct Inputs<'f> {
    /// The region iBoot leaves in each memory-controller lock group.
    pub programmed: stela_soc_data::amcc::Programmed,
    /// The entry point a boot bundle hands off to, on which boot firmware
    /// locks every PE's RVBAR.
    pub reset: Option<u64>,
    /// The system counter at placement and the host's wall time at it.
    pub now: u64,
    pub wall: Option<WallClock>,
    /// The internal SSD's backing (`--storage`).
    pub backing: Option<Box<dyn BlockDevice>>,
    /// The SEP's state on the machine-state partition (`--nor`); volatile
    /// without one.
    pub sep_state: Option<sep_state::Location>,
    /// Advertise and log the SEP `sks`/`pnon`/`scrd` services.
    pub sep_observe: bool,
    pub entropy: Box<dyn SepEntropy>,
    /// A restore host on the first USB-C connector.
    pub restore: bool,
    /// The native keyboard and pointer, with `usb`'s disks and Ethernet
    /// adapter, on the last connector.
    pub input: bool,
    pub usb: UsbCables,
    /// The display coprocessor's monitor.
    pub scanout: Option<Box<dyn Scanout>>,
    /// Board device firmware images by guest file name.
    pub firmware: &'f dyn Fn(&str) -> Option<&'f [u8]>,
    /// The boot bundle's macOS build, whose firmware protocols the
    /// coprocessor models speak; `None` without a bundle.
    pub build: Option<&'static stela_formats::builds::Build>,
}

/// Place `board`'s devices, writing `DEVICES` summaries to `log`, and return
/// them with the USB controller a restore host is cabled to.
pub fn devices<C: ConsoleSink + 'static>(
    board: &Board,
    console: C,
    inputs: Inputs<'_>,
    log: &mut dyn FnMut(fmt::Arguments<'_>),
) -> Result<(AppleDevices, Option<UsbId>), String> {
    devices_with_memory(board, console, inputs, None, log)
}

/// Mount the ordinary board around actual native memory owners. Callers must
/// retain their registered RAM and close all native/host writers before guest
/// entry. No legacy memory constructor is used when native owners are supplied.
pub fn devices_with_memory<C: ConsoleSink + 'static>(
    board: &Board,
    console: C,
    inputs: Inputs<'_>,
    memory: Option<MemoryResources>,
    log: &mut dyn FnMut(fmt::Arguments<'_>),
) -> Result<(AppleDevices, Option<UsbId>), String> {
    if board.direct_memory_cache.is_some() && memory.is_none() {
        return Err("direct MCC/AMCC/PTD requires its actual qualified native memory owner".into());
    }
    if let Some(memory) = memory.as_ref() {
        match memory {
            MemoryResources::T8112Cold(plan) => plan.validate_power(board.power_states.as_ref())?,
            MemoryResources::T6000Cold(plan) => plan.validate_power(board.power_states.as_ref())?,
            MemoryResources::T8112 { .. } => {}
        }
        memory.validate(
            board.memory_controller.as_ref(),
            board.memory_cache.as_ref(),
            board.direct_memory_cache.as_ref(),
        )?;
    }
    let native_memory = memory.is_some();
    pmgr_qualifications(&board.pmgr_refusals, log);
    let Inputs {
        programmed,
        reset,
        now,
        wall,
        backing,
        sep_state,
        sep_observe,
        entropy,
        restore,
        input,
        mut usb,
        scanout,
        firmware,
        build,
    } = inputs;
    let build =
        build.ok_or("the board's coprocessors need the boot bundle's supported macOS build")?;
    let place = |device: super::soc::Device| {
        (
            Range {
                physical: device.physical,
                bytes: device.bytes,
            },
            AicInput::new(0, device.irq as u16),
        )
    };
    let (uart, wdt, aic) = (place(board.uart), place(board.watchdog), board.aic);
    // Templates with no running node are useful for mount diagnostics. Actual
    // boot intake independently requires a verified selected handoff PE.
    let boot = board.boot_processor.as_ref().map_or(0, |boot| boot.cpu);
    let mut devices = AppleDevices::for_boot_processor(boot);
    devices
        .add_uart(console, &[uart.0], Some(uart.1))
        .map_err(|error| format!("UART placement: {error:?}"))?;
    devices
        .add_watchdog_with_side(wdt.0, board.watchdog_side.as_ref(), Some(wdt.1), now)
        .map_err(|error| format!("watchdog placement: {error:?}"))?;
    devices.add_aic_for_processors(
        aic.physical,
        aic.inputs,
        aic.layout,
        board.cpus.processors.len(),
    )?;
    if let Some(gpio) = &board.gpio {
        let selects: Vec<u32> = board.spi_nor.iter().filter_map(|spi| spi.select).collect();
        let interrupts: Vec<u32> = board
            .i2cs
            .iter()
            .flat_map(|controller| &controller.targets)
            .filter_map(|target| target.interrupt)
            .collect();
        devices.add_gpio(gpio, &selects, &interrupts)?;
    }
    for aux in &board.aux_gpios {
        devices.add_aux_gpio(aux)?;
    }
    if let Some(spi) = board.spi_nor.as_ref() {
        devices.add_spi_nor(spi)?;
    }
    match (board.ans.as_ref(), backing) {
        (Some(ans), Some(backing)) => devices.add_ans(ans, backing, build)?,
        (Some(_), None) => return Err("a visible ANS2 requires --storage SERIAL:GUID".into()),
        (None, Some(_)) => {
            return Err(
                "--storage was supplied but this DeviceTree exposes no modeled ANS2".into(),
            );
        }
        (None, None) => (),
    }
    if let Some(smc) = board.smc.as_ref() {
        devices.add_smc(smc, build)?;
    }
    if let Some(pmp) = board.pmp.as_ref() {
        devices.add_pmp(pmp, build)?;
    }
    for spmi in &board.spmis {
        // A newly created Stela PMIC starts with its own oscillator origin
        // and no pending native fault or off-to-wake events. These are explicit
        // cold resource inputs, not Apple persistent/reset-state measurements.
        // Retained PMIC resources must instead supply their actual history.
        let history = spmi
            .pmus
            .iter()
            .flat_map(|pmu| {
                pmu.retained()
                    .map(|(kind, window)| (pmu.sid, kind, vec![0; usize::from(window.bytes)]))
            })
            .collect::<Vec<_>>();
        devices.add_spmi_with_resources(
            spmi,
            wall,
            RtcEpoch {
                counter: now,
                ticks: 0,
            },
            &history,
        )?;
    }
    for component in &board.coresight {
        devices
            .add_coresight_lock(component.physical)
            .map_err(|error| format!("CoreSight lock placement: {error:?}"))?;
        if let Some(physical) = component.pc_sampler() {
            devices
                .add_coresight_sampler(component.cpu, physical)
                .map_err(|error| format!("UTTDBG sampler placement: {error:?}"))?;
        }
    }
    for block in &board.lockdown {
        let range = Range {
            physical: block.physical,
            bytes: block.bytes,
        };
        let rvbar = block.cpu.zip(reset);
        devices
            .add_lockdown(block.name, block.control, range, rvbar)
            .map_err(|error| format!("{} placement: {error:?}", block.name))?;
    }
    if let Some(entry) = reset {
        for block in &board.processor_registers {
            if board
                .lockdown
                .iter()
                .any(|legacy| legacy.cpu == Some(block.cpu))
            {
                continue;
            }
            devices
                .add_processor_registers(
                    block.cpu,
                    Range {
                        physical: block.physical,
                        bytes: block.bytes,
                    },
                    entry,
                )
                .map_err(|error| format!("PE startup register placement: {error:?}"))?;
        }
    }
    for block in &board.counters {
        devices
            .add_core_counters(block.cpu, block.physical, block.layout)
            .map_err(|error| format!("sampler counter placement: {error:?}"))?;
    }
    let mpidrs: Vec<u64> = board.cpus.processors.iter().map(|pe| pe.mpidr).collect();
    devices.add_fast_ipi(&mpidrs);
    if let Some((physical, clusters)) = board.cpu_start {
        devices.add_cpu_start(physical, clusters, &mpidrs)?;
    }
    for controller in &board.i2cs {
        devices.add_i2c(controller, firmware)?;
    }
    for phy in &board.typec_phys {
        devices
            .add_atc_phy(phy)
            .map_err(|error| format!("ATC PHY placement: {error:?}"))?;
    }
    let mut darts = Vec::new();
    for dart in &board.darts {
        let ranges: Vec<_> = dart
            .instances
            .iter()
            .map(|instance| Range {
                physical: instance.physical,
                bytes: instance.bytes,
            })
            .collect();
        let irq = AicInput::new(0, dart.irq as u16);
        let placed = devices
            .add_dart_group_for_profile(
                dart.profile,
                &ranges,
                usize::from(dart.streams),
                Some(irq),
                dart.apf,
            )
            .map_err(|error| format!("DART placement: {error}"))?;
        if let Some((physical, bytes)) = dart.smmu {
            devices
                .add_dart_smmu(placed[0], Range { physical, bytes })
                .map_err(|error| format!("DART SMMU placement: {error:?}"))?;
        }
        darts.push(placed);
    }
    let native_dart = |group: usize, instance: usize| {
        let mounted = darts
            .get(group)
            .ok_or("native DMA route names an unmounted DART group")?;
        let declared = board
            .darts
            .get(group)
            .ok_or("native DMA route has no declared DART group")?;
        if mounted.len() != declared.instances.len() {
            return Err("native DMA mounted DART group differs from its complete declaration");
        }
        mounted
            .get(instance)
            .copied()
            .ok_or("native DMA route names an unmounted DART instance")
    };
    // The PMGR's power states precede the display, whose views reach into
    // its windows.
    if let Some(states) = board.power_states.as_ref() {
        let blocks: Vec<Range> = states
            .blocks
            .iter()
            .map(|&(physical, bytes)| Range { physical, bytes })
            .collect();
        devices.add_power_states(&blocks, &states.registers)?;
        log(format_args!(
            "DEVICES pmgr power-states={} blocks={}\n",
            states.registers.len(),
            blocks.len()
        ));
    }
    // The display's PTD update view must borrow this actual publication bank,
    // before a broad display container can claim any overlapping bytes.
    if let Some(memory) = memory {
        match memory {
            MemoryResources::T6000Cold(plan) => {
                plan.install(&mut devices)?;
                log(format_args!(
                    "DEVICES mcc native direct MCC/AMCC/PTD share canonical RAM and source power graph\n"
                ));
            }
            MemoryResources::T8112Cold(plan) => {
                plan.install(&mut devices)?;
                log(format_args!(
                    "DEVICES mcc native cold cache/DCS/PTD follow actual PMGR and canonical RAM\n"
                ));
            }
            MemoryResources::T8112 { memory, cache } => {
                devices.add_t8112_empty_memory_resources(memory, cache)?;
                log(format_args!(
                    "DEVICES mcc native DCS/PTD and cache share registered RAM\n"
                ));
            }
        }
    }
    // The dcpext display coprocessor and its register apertures, presenting
    // to the host's scanout, mastering through its DART and reading swap
    // surfaces through the display pipe's.
    if let Some(dcp) = board.dcp.as_ref() {
        for route in &dcp.surface_routes {
            devices.validate_native_dart(
                "DCP declared surface mapper",
                native_dart(route.iommu, route.instance)?,
                route.stream as usize,
            )?;
        }
        let scanout = scanout.ok_or("visible external DCP requires one actual scanout")?;
        let range = |(physical, bytes): (u64, u64)| Range { physical, bytes };
        devices.add_dcpext(
            range(dcp.wrapper),
            dcp.interrupts,
            dcp.quiesced,
            dcp.role,
            dcp.identity,
            scanout,
            (native_dart(dcp.iommu, dcp.instance)?, dcp.stream as usize),
            dcp.window,
            match (
                dcp.surface,
                dcp.surface_instance,
                dcp.surface_routes.first(),
            ) {
                (Some((iommu, stream)), Some(instance), Some(primary))
                    if (primary.iommu, primary.instance, primary.stream)
                        == (iommu, instance, stream) =>
                {
                    Some((native_dart(iommu, instance)?, stream as usize))
                }
                (None, None, None) => None,
                _ => return Err("DCP surface DMA owner metadata is incomplete".into()),
            },
            build,
        )?;
        let regions: Vec<(&'static str, Range)> = dcp
            .regions
            .iter()
            .map(|&(name, reg)| (name, range(reg)))
            .collect();
        let mut display_darts = Vec::new();
        for group in
            core::iter::once(dcp.iommu).chain(dcp.surface_routes.iter().map(|route| route.iommu))
        {
            let instances = darts.get(group).ok_or("display DART group is missing")?;
            for instance in 0..instances.len() {
                let owner = native_dart(group, instance)?;
                if !display_darts.contains(&owner) {
                    display_darts.push(owner);
                }
            }
        }
        devices.add_display_with_darts(&regions, dcp.role, &display_darts)?;
    }
    if let Some(sep) = board.sep {
        let group = darts.get(sep.iommu).ok_or("SEP DART group is missing")?;
        let [dart] = group.as_slice() else {
            return Err("SEP DMA owner requires explicit multiple-TRAD selection".into());
        };
        if sep.instance != 0 {
            return Err("SEP selected TRAD is outside its sole-owner group".into());
        }
        let ranges = sep
            .ranges
            .map(|(physical, bytes)| Range { physical, bytes });
        let lines = AscLines::from_interrupts(sep.irqs.map(|irq| AicInput::new(0, irq as u16)));
        let ecid = sep
            .ecid
            .ok_or("SEP needs /chosen unique-chip-id (the machine ECID); none in the tree")?;
        let state = match sep_state {
            Some(location) => {
                log(format_args!("SEP state on the machine-state partition\n"));
                location
            }
            None => {
                // Without `--nor` no host partition holds it: the roots
                // and anti-replay store last this power cycle.
                log(format_args!(
                    "SEP state volatile: nonces end at power-off\n"
                ));
                sep_state::Location::Volatile
            }
        };
        devices.add_sep(
            ranges,
            lines,
            (*dart, sep.stream as usize),
            entropy,
            SepProvisioning {
                security: sep.security,
                ecid,
                observe: sep_observe,
                state,
            },
        )?;
    }
    let mut restore_usb = None;
    let usbs = board.usbs.len();
    for (index, controller) in board.usbs.iter().enumerate() {
        // The controller's stream translates through the group's first TRAD
        // instance, as SEP and AES masters do; per-instance selection is the
        // bus master's contract (`soc::Iommu`).
        let group = darts
            .get(controller.iommu)
            .ok_or("USB DART group is missing")?;
        for (instance, _) in group.iter().enumerate() {
            devices.validate_native_dart(
                "USB declared bank",
                native_dart(controller.iommu, instance)?,
                controller.stream as usize,
            )?;
        }
        let id = devices.add_usb(controller, native_dart(controller.iommu, 0)?)?;
        // The native keyboard and pointer plug into the last connector
        // (J473AP usb-drd1), the Mac being the downstream-facing port.
        let hub = input || !usb.disks.is_empty() || usb.network.is_some();
        if hub && index + 1 == usbs && index != 0 {
            let disks = usb.disks.len();
            let network = usb.network;
            devices.attach_input(controller.port, core::mem::take(&mut usb))?;
            log(format_args!(
                "INPUT attached to USB-C port {} with {disks} USB disks, network={network:?}\n",
                controller.port
            ));
        }
        // The first controller (J473AP usb-drd0, the back-left connector) is
        // the one a restore host or the native client uses; the others are
        // left uncabled.
        if index != 0 {
            continue;
        }
        if restore {
            // A restore host is cabled to this connector from power-on: it
            // is the USB host and sources VBUS, so the Mac is a USB2 device.
            // The connector's HPM die and controller observe the same cable.
            let host = typec::Attached {
                orientation: typec::Orientation::Normal,
                role: typec::DataRole::Ufp,
                source: false,
                vbus: true,
                speed: typec::Usb2Speed::High,
            };
            devices.set_connection(controller.port, Some(host))?;
            restore_usb = Some(id);
        } else {
            devices.usb_client(id)?.query_type()?;
        }
    }
    if let Some(aes) = board.aes {
        let ranges: Vec<Range> = aes
            .ranges
            .into_iter()
            .chain(aes.dkey)
            .map(|(physical, bytes)| Range { physical, bytes })
            .collect();
        // No per-installation UID1 key is provisioned yet: the engine
        // reports every hardware key disabled.
        devices.add_aes(
            &ranges,
            aes.config,
            Some(AicInput::new(0, aes.irq as u16)),
            (native_dart(aes.iommu, aes.instance)?, aes.stream as usize),
            None,
        )?;
    }
    for bank in &board.bridges {
        devices.add_bridge(
            bank.physical,
            &bank.fields,
            bank.header,
            &bank.configs,
            bank.axi,
        )?;
    }
    if let Some(bank) = board.soc_dpe.as_ref() {
        devices.add_soc_dpe(bank.physical, &bank.samples)?;
    }
    for bank in &board.power_banks {
        devices.add_soc_power(bank.physical, bank.kind)?;
    }
    if let Some(bank) = board.wake_masks.as_ref() {
        devices.add_wake_masks(bank.physical, bank.valid, bank.smc_wake)?;
    }
    for bank in &board.performance {
        devices.add_performance_counters(bank.physical, &bank.selectors)?;
    }
    for bank in &board.energy {
        devices.add_cpu_energy(bank.physical, bank.cpm)?;
    }
    for (index, cluster) in board.clusters.iter().enumerate() {
        let events = board
            .cluster_events
            .get(index)
            .ok_or("CPU cluster has no DT event selection")?;
        // The board validated each CPM word against the translated DT reg.
        devices.add_cpm_power(
            cluster.base + stela_soc_data::cpm::T8112_OFFSET,
            cluster.counter_map,
        )?;
        devices.add_cpu_cluster(
            cluster.base,
            cluster.dvmr,
            cluster.pstates,
            cluster.counter_capacity,
            cluster.counter_map,
            events,
        )?;
    }
    if let Some((physical, _)) = board.aon_fuses {
        devices.add_aon_fuses(physical)?;
    }
    let memory_controller = board.memory_controller.as_ref();
    let memory_cache = board.memory_cache.as_ref();
    if !native_memory && let Some(controller) = memory_controller {
        let mut programmed = programmed;
        for (region, group) in programmed.iter_mut().zip(controller.layout.groups) {
            if group.is_none() {
                *region = None;
            }
        }
        devices.add_memory_controller(
            &controller.apertures,
            controller.layout,
            programmed,
            memory_cache.map(|mcc| mcc.cache),
        )?;
    }
    if let Some(controller) = board.io_access_controller.as_ref() {
        devices.add_io_access_controller(
            &controller.apertures,
            controller.layout,
            stela_soc_data::amcc::ctrr_a(programmed[0]),
        )?;
    }
    if !native_memory && let Some(mcc) = memory_cache {
        let (physical, bytes, channels) = mcc.channels;
        devices.add_memory_channels(
            Range { physical, bytes },
            channels,
            mcc.ptd.physical,
            &mcc.ptd.ranges,
        )?;
        log(format_args!(
            "DEVICES mcc cache={}MiB ways={} dcs-channels={channels} ptd={:#x} ptd-ranges={}\n",
            mcc.cache.bytes >> 20,
            mcc.cache.ways,
            mcc.ptd.physical,
            mcc.ptd.ranges.len()
        ));
    }
    log(format_args!(
        "DEVICES uart={:#x}+{:#x} irq={} wdt={:#x}+{:#x} irq={} aic={:#x} nr_irq={} \
         lockdown-blocks={} amcc-apertures={} darts={} aes={} aic-timebase=unplaced\n",
        uart.0.physical,
        uart.0.bytes,
        uart.1.irq,
        wdt.0.physical,
        wdt.0.bytes,
        wdt.1.irq,
        aic.physical,
        aic.inputs,
        board.lockdown.len(),
        memory_controller.map_or(0, |controller| controller.apertures.len()),
        darts.len(),
        board.aes.is_some()
    ));
    // Last: the `sgx` window spans other banks (gfx-asc, a PMGR fabric
    // bridge) and owns only the bytes they leave.
    if let Some(gfx) = board.gfx.as_ref() {
        devices.add_gfx(gfx, build)?;
    }
    // Finalize only after every native constructor, including SGX's final
    // overlapping-window placement, has registered its actual banks.
    if let Some(states) = board.power_states.as_ref() {
        let retention = board
            .darts
            .iter()
            .map(|dart| dart.retention)
            .collect::<Vec<_>>();
        devices.connect_power_resources(states, &darts, &retention)?;
        log(format_args!(
            "DEVICES pmgr lifecycle-refusals={} resources={}\n",
            devices.power_refusals().len(),
            states.resources.len()
        ));
    } else if board
        .darts
        .iter()
        .any(|dart| !dart.clock_gates.is_empty() || !dart.power_gates.is_empty())
    {
        return Err("DART resource gates require a modeled PMGR".into());
    }
    if restore && restore_usb.is_none() {
        return Err("restore study requires a DT-placed USB device".into());
    }
    Ok((devices, restore_usb))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::soc::PmgrBank;

    #[test]
    fn native_memory_preflight_matches_live_descriptors_and_actual_ram() {
        let (memory, cache) = t8112::cache::EmptyResource::service_test_components();
        let descriptor = memory.descriptor().clone();
        let controller = cache.source().clone();
        let resources = MemoryResources::T8112 { memory, cache };
        assert_eq!(
            resources.validate(Some(&controller), Some(&descriptor), None),
            Ok(())
        );

        let mut changed = descriptor.clone();
        changed.ptd.interrupts[0] ^= 1;
        assert!(
            resources
                .validate(Some(&controller), Some(&changed), None)
                .is_err()
        );
        let mut changed = controller.clone();
        changed.apertures[0] += 0x40000;
        assert!(
            resources
                .validate(Some(&changed), Some(&descriptor), None)
                .is_err()
        );
        assert!(resources.validate(None, Some(&descriptor), None).is_err());
        assert!(resources.validate(Some(&controller), None, None).is_err());

        let (memory, _) = t8112::cache::EmptyResource::service_test_components();
        let (_, cache) = t8112::cache::EmptyResource::service_test_components();
        assert!(
            MemoryResources::T8112 { memory, cache }
                .validate(Some(&controller), Some(&descriptor), None)
                .unwrap_err()
                .contains("same actual registered RAM")
        );
    }

    #[test]
    fn clpc_absence_reports_each_path_once() {
        let paths = [
            "/arm-io/pmgr/clpc".into(),
            "/arm-io/pmgr/clpc".into(),
            "/arm-io/die1/clpc".into(),
        ];
        let mut messages = Vec::new();
        clpc_absence(&paths, &mut |message| messages.push(format!("{message}")));
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("UNMODELED CLPC /arm-io/pmgr/clpc: controller hidden"));
    }

    #[test]
    fn pmgr_qualifications_report_each_requirement_once_without_a_model() {
        let unsupported = PmgrBankRefusal {
            bank: PmgrBank::CpuClusters,
            reason: "unknown cluster layout",
        };
        let bridge = PmgrBankRefusal {
            bank: PmgrBank::Bridges,
            reason: "unknown bridge layout",
        };
        let mut messages = Vec::new();
        pmgr_qualifications(&[unsupported, unsupported, bridge], &mut |message| {
            messages.push(format!("{message}"))
        });
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("UNMODELED PMGR CpuClusters"));
        assert!(
            messages
                .iter()
                .all(|message| message.contains("no register/lifecycle model"))
        );
    }
}
