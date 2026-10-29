//! Engine start: from the loader's handoff to the first guest instruction, in
//! phases that each own what they start.

use super::*;
use crate::Result;
use alloc::string::ToString;
use stela_contracts::refuse;

/// The boot bundle `--preboot` names, built from the installed system on
/// `partition`: its macOS, its staged update or its recoveryOS.
fn from_disk(
    partition: alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>,
    options: &Options,
) -> Vec<(String, Vec<u8>)> {
    crate::status::begin("Reading macOS's boot files from its disk");
    // The kernel's text on the screen and on the debug UART, which the
    // boot log records, as setup's bundles have it.
    let defaults = boot_bundle::Options {
        ecid: options.ecid,
        boot_command: options.boot_command,
        boot_args: "-v serial=3 serial-device-name=uart0".into(),
        ..boot_bundle::Options::default()
    };
    let result = if options.upgrade {
        bundle::upgrade_from_disk(partition, options.boot_volume, &defaults)
    } else if let Some(kind) = options.recovery {
        bundle::recovery_from_disk(partition, kind, options.boot_volume, &defaults)
    } else {
        let request = installed::Request {
            volume: options.boot_volume,
            ..installed::Request::default()
        };
        let mut defaults = defaults;
        if options.safe_boot {
            defaults.boot_args.push_str(" -x");
        }
        bundle::from_disk(partition, &request, &defaults)
    };
    let files = result.unwrap_or_else(|error| {
        output::arguments(format_args!("preboot refusal: {error}\n"));
        output::fatal("no boot bundle could be built from the Preboot volume")
    });
    let bytes: usize = files.iter().map(|(_, contents)| contents.len()).sum();
    crate::status::done(&format!("{} MB", bytes.div_ceil(1 << 20)));
    files
}

/// Engine-phase entry, called by the loader on the window stack.
pub extern "sysv64" fn entry(handoff: u64) -> ! {
    let Started {
        handoff,
        mut options,
        host_firmware,
        native_processors,
    } = start(handoff);
    let mut host = open_host(handoff, &mut options, host_firmware, native_processors);
    let storage = open_storage(handoff, &options, &mut host);
    let boot = Boot {
        handoff,
        options: &options,
        native_processors,
    };
    let processors = start_processors(boot, &mut host);
    run_guest(boot, host, storage, processors)
}

/// What every phase after the host's reads: the loader's handoff,
/// `stela.cfg` and the validated physical processors.
#[derive(Clone, Copy)]
struct Boot<'a> {
    handoff: &'static Handoff,
    options: &'a Options,
    native_processors: Option<&'static crate::native_smp::firmware::Capture>,
}

/// The engine's own start: its interrupts, heap, entropy and screen taken,
/// `stela.cfg` parsed and the physical processors validated.
struct Started {
    handoff: &'static Handoff,
    options: Options,
    host_firmware: Option<alloc::sync::Arc<stela_drivers::firmware::Catalog>>,
    native_processors: Option<&'static crate::native_smp::firmware::Capture>,
}

fn start(handoff: u64) -> Started {
    output::disable_firmware_console();
    // SAFETY: the first engine code; interrupts are off and nothing else runs.
    unsafe { interrupts::install(interrupts::interrupt) };
    // SAFETY: the loader wrote the handoff page and passed its physmap address.
    let handoff = unsafe { &*(handoff as *const Handoff) };
    if handoff.magic != MAGIC {
        output::fatal("engine handoff has the wrong magic");
    }
    layout::set(handoff.placement);
    // Use the physmap directly: its CPU and physical bases have the
    // same alignment phase. A separately placed heap alias cannot in general
    // satisfy higher-order CPU/physical page alignment simultaneously.
    let heap = layout::physical(handoff.heap.physical);
    // SAFETY: this reserved heap is unused and its RW+NX physmap is shared by
    // every native root for the complete engine lifetime.
    unsafe { crate::ALLOCATOR.initialize(heap as *mut u8, handoff.heap.bytes as usize) };
    // SAFETY: this loader-owned private seed is held in the shared physmap,
    // exclusively consumed here before any native service is published.
    if let Err(error) = unsafe { crate::random::initialize(handoff.random_seed) } {
        output::arguments(format_args!("HOST entropy unavailable: {error:?}\n"));
    }
    // SAFETY: this phase owns that reserved heap and kept WB mapping.
    unsafe {
        crate::native_memory::initialize(
            heap as usize,
            handoff.heap.physical,
            handoff.heap.bytes as usize,
            layout::physical(0),
        )
    };
    // SAFETY: loader-reserved immutable pages, kept in every shared-window
    // physmap; metadata and Arc are created in this active engine allocator.
    let host_firmware = unsafe { crate::host_firmware::after_ebs(&handoff.host_firmware) }
        .unwrap_or_else(|error| output::fatal(error));
    crate::status::set_clock(handoff.tsc_hz);
    stela_drivers::on_wait(crate::status::tick);
    stela_drivers::on_work(crate::status::progress);
    crate::status::take_screen(
        handoff
            .screen
            .map(|screen| screen.relocated(layout::physical(screen.base as u64) as usize)),
    );
    crate::status::replay(&handoff.history[..handoff.history_bytes]);
    output::arguments(format_args!(
        "STELA SYSTEM ENGINE window={:#x} placement={:?} tsc_hz={} guest_ranges={} \
         heap={}M code={}M pool={}M\n",
        layout::window(),
        handoff.placement,
        handoff.tsc_hz,
        handoff.guest_count,
        handoff.heap.bytes >> 20,
        handoff.code.bytes >> 20,
        handoff.pool.bytes >> 20,
    ));
    // SAFETY: the options were left allocated by the loader.
    let text = unsafe {
        core::slice::from_raw_parts(
            layout::physical(handoff.options.physical) as *const u8,
            handoff.options.bytes as usize,
        )
    };
    let options = match core::str::from_utf8(text)
        .map_err(|_| refuse!("stela.cfg is not UTF-8"))
        .and_then(Options::parse)
    {
        Ok(options) => options,
        Err(error) => output::fatal(error),
    };
    // SAFETY: the loader handoff and all reservations stay pinned in the physmap.
    let native_processors = unsafe { crate::native_smp::validate(handoff, options.native_cores) }
        .unwrap_or_else(|error| output::fatal(error));
    if (options.native_bootstrap_check || options.native_shared_check)
        && options.native_cores.is_none()
    {
        output::fatal("native bootstrap check needs an explicit physical-core count");
    }
    // Refuse physical and implicit persistent-device setup before translation
    // stores, FDR placement, storage::open or any independent native driver.
    if options.native_clock_check
        && (handoff.native_resources.cores != 1
            || handoff.storage.present
            || handoff.files[..handoff.file_count]
                .iter()
                .any(|file| file.name() == translations::FILE)
            || restore::inventory_file(handoff, stela_runtime::restore::fdr::FILE).is_some())
    {
        output::arguments(format_args!(
            "CHECK native-clock FAIL unsupported physical or persistent resources\n"
        ));
        output::fatal("native clock fixture requires one exclusive processor and volatile input");
    }
    #[cfg(feature = "diagnostics")]
    if options.native_memory_check {
        output::arguments(format_args!(
            "CHECK native-memory heap cpu={heap:#x} physical={:#x} bytes={:#x}\n",
            handoff.heap.physical, handoff.heap.bytes,
        ));
        match crate::native_memory::verify() {
            Ok(()) => output::arguments(format_args!(
                "CHECK native-memory PASS WB native pages: zero/read/write, CPU pin lifetime/reclaim, cache/alignment/bounds refusal; Linux PFN/refcount/compound/split/retirement\n"
            )),
            Err(error) => {
                output::arguments(format_args!("CHECK native-memory FAIL {error:?}\n"));
                output::fatal("native pinned RAM verification failed");
            }
        }
    }
    Started {
        handoff,
        options,
        host_firmware,
        native_processors,
    }
}

/// The installed host with its platform and devices, and the guest's RAM
/// placed at the DRAM base its bundle was prepared for.
struct OpenedHost {
    owner: host::HostOwner,
    apic_hz: u64,
    /// The TSC origin every physical executor shares.
    tsc_base: u64,
    /// Whether the BSP runs every PE.
    serialized: bool,
    acpi: Option<&'static aml::HostAcpi>,
    /// The owned MMIO aperture, which the processor diagnostics check.
    #[cfg(feature = "diagnostics")]
    mmio: Option<&'static crate::native_mmio::Source>,
    devices: HostDevices,
    ram: Vec<RamRange>,
    /// The boot bundle `--preboot` built from the installed system.
    built: Option<Vec<(String, Vec<u8>)>>,
    /// Whether `--nor` keeps the machine state in the `--storage`
    /// partition's tail.
    state_in_storage: bool,
    /// Whether an install streams its remote image.
    remote_image: bool,
}

/// Install the host, start its platform and devices, and place the guest's
/// RAM.
fn open_host(
    handoff: &'static Handoff,
    options: &mut Options,
    host_firmware: Option<alloc::sync::Arc<stela_drivers::firmware::Catalog>>,
    native_processors: Option<&'static crate::native_smp::firmware::Capture>,
) -> OpenedHost {
    // The guest's RAM at the configured DRAM base. A bundle's own base is
    // read from its disk by the host drivers, which run after the host is
    // installed; the placements then move there (`HostOwner::place_ram`).
    let mut ram = guest_ram(handoff, options).unwrap_or_else(|error| output::fatal(error));
    // The translation store the loader read, and its partition when the
    // pack can be rewritten.
    let translation_store = handoff.files[..handoff.file_count]
        .iter()
        .find(|file| file.name() == translations::FILE)
        .and_then(|file| translations::install(bundle::contents(file)))
        .filter(|_| handoff.storage.present);
    let fdr_placement = restore::inventory_file(handoff, stela_runtime::restore::fdr::FILE)
        .map(fdr::Placement::parse)
        .transpose()
        .unwrap_or_else(|error| output::fatal(&error));
    let fdr_partition = fdr_placement.as_ref().map(|placement| placement.partition);
    // `--nor` naming the `--storage` partition keeps the machine state in
    // that partition's tail (`pc::machine_state`): one device, split below.
    let state_in_storage = options.nor.is_some() && options.nor == options.storage;
    let targets: Vec<&Target> = options
        .storage
        .iter()
        .chain(options.restore_source.iter())
        .chain(options.nor.iter().filter(|_| !state_in_storage))
        .collect();
    #[cfg(feature = "diagnostics")]
    if let Some(mode) = options.audio_check {
        let audio_handoff = handoff
            .storage
            .handoff()
            .unwrap_or_else(|| output::fatal("the loader found no host device handoff"));
        // SAFETY: --audio-check explicitly grants sole conventional HDA ownership;
        // before host::install, the identity root and DMA pages are live.
        unsafe { crate::audio_check::run(&audio_handoff, mode) }.unwrap_or_else(|error| {
            output::arguments(format_args!("AUDIO CHECK failed: {error}\n"));
            output::fatal("the audio check failed")
        });
    }
    let InstalledHost {
        owner: mut host_owner,
        apic_hz,
        tsc_base: native_tsc_base,
        serialized,
    } = install_host(handoff, options, &ram);
    let Platform {
        acpi: host_acpi,
        mmio: native_mmio,
        remappers,
        _work: kernel_work,
    } = start_platform(handoff, &mut host_owner);
    // The signing service is asked only during a restore, so a boot that
    // restores nothing leaves the adapter to the guest.
    let restoring = options.install.is_some() || options.restore_source.is_some();
    // An install without a medium partition streams its remote image.
    let remote_image = options.install.is_some() && options.install_source.is_none();
    let wants_network =
        (options.tss && restoring) || remote_image || options.network_check.is_some();
    let mut devices = start_devices(
        handoff,
        options,
        &Wanted {
            firmware: host_firmware.clone(),
            processors: native_processors,
            targets: &targets,
            store: translation_store,
            fdr: fdr_partition,
            network: wants_network,
        },
        host_acpi,
        &native_mmio,
        remappers,
        kernel_work,
    );
    remappers.report_faults();
    let built = devices
        .preboot
        .take()
        .map(|partition| from_disk(partition, options));
    // A bundle runs at the DRAM base it was prepared for, its SoC's.
    if options.bundle && !options.dram_explicit {
        let files = &handoff.files[..handoff.file_count];
        options.dram_base = match bundle::dram_base(files, built.as_deref()) {
            Ok(base) if base.is_multiple_of(LARGE) => base,
            Ok(_) => output::fatal("the bundle's DRAM base is not 2 MiB aligned"),
            Err(error) => {
                output::arguments(format_args!("bundle refusal: {error}\n"));
                output::fatal("the boot bundle's DRAM base could not be read")
            }
        };
    }
    ram::place(&mut ram, options.dram_base);
    host_owner
        .place_ram(options.dram_base)
        .unwrap_or_else(|error| output::fatal(error));
    for range in &ram {
        output::arguments(format_args!(
            "GUEST DRAM pa={:#x} bytes={:#x} host={:#x}\n",
            range.guest, range.bytes, range.host
        ));
    }
    #[cfg(feature = "diagnostics")]
    if let Some(url) = &options.network_check {
        let Some(Ok(network)) = &devices.host_network else {
            output::fatal("the network check failed")
        };
        // Any HTTP status proves the path end to end; only a transport
        // failure (link, DHCP, DNS, TCP, malformed reply) fails the check.
        let checked = network.0.borrow_mut().post_url(url, &[], "text/plain", b"");
        match checked {
            Ok(body) => {
                output::arguments(format_args!(
                    "NETWORK CHECK body bytes={} sha256={}\n",
                    body.len(),
                    stela_formats::sha256(&body)
                ));
                output::arguments(format_args!("NETWORK CHECK passed\n"))
            }
            Err(stela_runtime::net::NetError::Status(_)) => {
                output::arguments(format_args!("NETWORK CHECK passed\n"))
            }
            Err(_) => output::fatal("the network check failed"),
        }
    }
    OpenedHost {
        owner: host_owner,
        apic_hz,
        tsc_base: native_tsc_base,
        serialized,
        acpi: host_acpi,
        #[cfg(feature = "diagnostics")]
        mmio: native_mmio,
        devices,
        ram,
        built,
        state_in_storage,
        remote_image,
    }
}

/// The guest's storage, its restore source and its machine state.
struct Storage {
    /// What backs the guest's ANS namespaces.
    backing: Option<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    /// The restore host's IPSW.
    source: Option<restore::Source>,
    host_nor: Option<nor::HostNor>,
    nor_image: Option<stela_soc_data::nor::Image>,
    nvram: Option<stela_formats::boot_bundle::Nvram>,
    sep_state: Option<stela_runtime::machine::apple::sep_state::Location>,
}

/// Open the guest's storage, the restore source and the machine state from
/// the partitions the host devices opened.
fn open_storage(handoff: &'static Handoff, options: &Options, host: &mut OpenedHost) -> Storage {
    let OpenedHost {
        devices:
            HostDevices {
                ref mut services,
                ref mut medium,
                ref host_network,
                ..
            },
        state_in_storage,
        remote_image,
        ..
    } = *host;
    let medium = medium.take();
    // The restore client's signing-server transport (`restore::tss`) and a
    // remote install image share `host_network`; it lives for the whole run.
    let mut services = core::mem::take(services).into_iter();
    let backing = options.storage.as_ref().map(|_| services.next().unwrap());
    let backing = backing.or_else(|| {
        let bytes = options.storage_ram?;
        let disk = stela_drivers::block::Volatile::new("STELARAM", bytes, RAM_STORAGE_LIMIT)
            .unwrap_or_else(|error| {
                output::arguments(format_args!("RAM storage refusal: {error}\n"));
                output::fatal("the RAM-backed storage could not be made")
            });
        output::arguments(format_args!(
            "STORAGE volatile: {bytes:#x} bytes of engine memory back the ANS namespaces, \
             at most {RAM_STORAGE_LIMIT:#x} written; nothing persists\n"
        ));
        Some(alloc::boxed::Box::new(disk)
            as alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>)
    });
    let source = options
        .restore_source
        .as_ref()
        .map(|_| services.next().unwrap());
    // The restore host's IPSW: the study's raw extent, the install medium's
    // pieces, found through FAT32 and joined, or the remote image.
    let source = match (source, medium) {
        (Some(partition), _) => Some(
            restore::inventory(handoff)
                .and_then(|manifest| restore::Source::extent(partition, manifest.source.bytes)),
        ),
        (None, Some(partition)) => Some(restore::inventory(handoff).and_then(|manifest| {
            let path = options.install.as_deref().unwrap_or_default();
            let directory = path
                .rsplit_once('\\')
                .map_or("", |(directory, _)| directory);
            let hashes = restore::inventory_file(handoff, crate::system::INSTALL_PIECES_FILE)
                .ok_or(refuse!("the install medium's piece hashes were not loaded"))?;
            crate::status::begin("Finding the macOS install files on the USB");
            let opened = install::open(partition, &manifest, directory, hashes)?;
            crate::status::done("");
            Ok(restore::Source::new(opened))
        })),
        (None, None) if remote_image => Some(restore::inventory(handoff).and_then(|manifest| {
            let network = match &host_network {
                Some(Ok(network)) => network.clone(),
                Some(Err(reason)) => return Err(reason.clone()),
                None => unreachable!("a remote install opens the host network"),
            };
            Ok(restore::Source::remote(remote::Remote::new(
                network, &manifest,
            )?))
        })),
        (None, None) => None,
    }
    .map(|source| {
        source.unwrap_or_else(|error| {
            output::arguments(format_args!("restore source refusal: {error}\n"));
            output::fatal("the restore source could not be opened")
        })
    });
    let (backing, nor) = match backing {
        Some(partition) if state_in_storage => {
            let (namespace, state) = nor::split(partition);
            (Some(namespace), Some(state))
        }
        backing => (
            backing,
            options.nor.as_ref().map(|_| services.next().unwrap()),
        ),
    };
    let nor = nor.map(|device| {
        crate::status::begin(&format!(
            "Opening the machine state on {}",
            device.identity().model
        ));
        let opened = nor::HostNor::open(device);
        crate::status::done("");
        opened
    });
    let (host_nor, nor_image, nvram, sep_state) = match nor {
        Some((host_nor, image, nvram, sep_state)) => {
            (Some(host_nor), Some(image), Some(nvram), Some(sep_state))
        }
        None => (None, None, None, None),
    };
    Storage {
        backing,
        source,
        host_nor,
        nor_image,
        nvram,
        sep_state,
    }
}

/// The other host processors, started and parked, and the boot
/// processor's local APIC that signals them.
struct Processors {
    executors: crate::native_smp::executor::Executors,
    sender: crate::apic::Apic,
}

/// Start the other host processors over the guest's RAM, and run the
/// bounded diagnostics that stop on them.
fn start_processors(boot: Boot<'_>, host: &mut OpenedHost) -> Processors {
    let Boot {
        handoff,
        options,
        native_processors,
    } = boot;
    let OpenedHost {
        tsc_base: native_tsc_base,
        serialized,
        ram: ref worker_ram,
        ..
    } = *host;
    crate::status::begin("Starting the other host processors");
    // SAFETY: the physical inventory and loader-owned reservations
    // were validated before any SIPI; the BSP Host is installed, guest entry
    // is excluded, and APs remain parked until canonical worker publication.
    let executors = unsafe {
        crate::native_smp::executor::start(
            handoff,
            native_processors.expect("validated native roster"),
            worker_ram,
            native_tsc_base,
            options.native_bootstrap_check,
            serialized,
        )
    }
    .unwrap_or_else(|error| {
        output::arguments(format_args!("native executor refusal: {error:?}\n"));
        output::fatal("owned native AP bootstrap refused")
    });
    crate::status::done("");
    let sender = crate::apic::Apic::new(
        handoff.apic_base,
        layout::physical(handoff.apic_base & crate::apic::BASE_ADDRESS),
    );
    #[cfg(feature = "diagnostics")]
    if options.native_bootstrap_check || options.native_shared_check {
        check_processors(boot, host, &executors, &sender);
    }
    Processors { executors, sender }
}

/// Load the guest's image, model its board and assign its PEs to the host's
/// processors, place the board's devices over its RAM, publish its topology
/// and run it until it stops. The assigned topology borrows the loaded
/// source and the roster for the whole run.
fn run_guest(boot: Boot<'_>, host: OpenedHost, storage: Storage, processors: Processors) -> ! {
    let Boot {
        handoff,
        options,
        native_processors,
    } = boot;
    let OpenedHost {
        owner: mut host_owner,
        apic_hz,
        acpi: host_acpi,
        devices:
            HostDevices {
                host_input,
                host_usb,
                host_network,
                usb_disks,
                guest_network,
                host_disks,
                fdr: mut fdr_device,
                ..
            },
        ram: worker_ram,
        built,
        ..
    } = host;
    let Storage {
        backing,
        source,
        host_nor,
        nor_image,
        nvram,
        sep_state,
    } = storage;
    let Processors { executors, sender } = processors;
    let mut roster = topology::AssignedRoster::new(
        native_processors.expect("validated native roster"),
        &executors,
        &host_owner,
    )
    .unwrap_or_else(|error| output::fatal(&error));
    let mut bare = host_owner.host();
    let target = target(options.parallel);
    let speculation = speculation::probe();
    let boot_image::GuestImage {
        entry,
        x0,
        read_only_region,
        core_locks,
        hidden_devices,
        live_tree: mut loaded_tree,
        source: loaded_source,
        boot_processor: bundle_boot_processor,
        hidden_clpc,
    } = boot_image::load(&mut bare, handoff, options, built.as_deref(), nvram);
    let Modeled {
        mut board,
        boot_processor,
        full_profile,
        active_workers,
    } = model_board(
        boot,
        loaded_tree.as_ref(),
        bundle_boot_processor,
        target,
        speculation,
    );
    let topology_source = source_topology(
        loaded_source.as_ref(),
        loaded_tree.as_ref(),
        board.as_ref(),
        &full_profile,
        active_workers,
    );
    let assigned = assign(boot, &mut roster, topology_source.as_ref(), &full_profile);
    // SAFETY: all raw guest input copies have ended; AP executors are parked,
    // and no guest/device DMA producer has entered. The same loader bytes are
    // for every subsequent native CPU and synchronous device writer.
    let canonical_ram = unsafe {
        crate::native_smp::canonical::reserve_for_workers(
            handoff,
            &worker_ram,
            native_processors.expect("validated native roster"),
            &executors,
        )
    }
    .unwrap_or_else(|error| output::fatal(error));
    if let Some(assigned) = &assigned {
        board = Some(assigned_board(
            handoff,
            assigned,
            &full_profile,
            boot_processor,
        ));
    }
    let projected_bytes = assigned.as_ref().map(|assigned| assigned.tree.serialize());
    let tree = projected_bytes
        .as_deref()
        .or_else(|| loaded_tree.as_ref().map(|tree| tree.bytes()));
    let boot_processor = board
        .as_ref()
        .and_then(|board| board.boot_processor.as_ref())
        .map_or(0, |boot| boot.cpu);
    mount::clpc_absence(&hidden_clpc, &mut |arguments| output::arguments(arguments));
    admit_board(&mut board, tree, &hidden_devices, nor_image);
    let profile = assigned
        .as_ref()
        .map_or_else(|| full_profile.clone(), |assigned| assigned.profile.clone());
    // The real kernelcache starts SPTM at EL2: it writes TPIDR_EL2 and keeps
    // its per-CPU pointer in TPIDR_GL2. HCR_EL2.E2H is RES1 on this profile
    // (SPTM installs its vectors through VBAR_EL1 before it ORs TGE and E2H
    // into HCR_EL2, which reaches VBAR_EL2 only with E2H already set); the
    // other HCR_EL2 bits reset to 0. Every other image starts there too:
    // the canonical memory owner admits MMU-off execution at EL2 alone
    // (`docs/design/runtime.md`), and Stela's test kernel makes itself a
    // VHE host as XNU does.
    let el = 2;
    output::arguments(format_args!(
        "ENTRY pc={entry:#x} x0={x0:#x} el={el} mmu=off profile={} target={} apic_hz={apic_hz} \
         prediction_isolation={} faulting_data_barrier={}\n",
        profile.name,
        target.id(),
        speculation.contexts,
        speculation.faulting_data,
    ));
    let mut cpu = Cpu::of(profile.chip, entry, Pstate::reset(el));
    cpu.state.x[0] = x0;
    let now = stela_engine::machine::Host::counter(&mut bare);
    let Placed {
        mut devices,
        restore_usb,
        cacheless_memory,
    } = place_devices(
        boot,
        Placement {
            built: built.as_deref(),
            entry,
            now,
            read_only_region,
            backing,
            sep_state,
            usb_disks,
            guest_mac: guest_network.as_ref().map(network::GuestNetwork::mac),
        },
        board.as_ref(),
        &core_locks,
        &canonical_ram,
        loaded_source.as_ref(),
        tree,
    );
    let processor_power = connect_processor_power(
        &mut devices,
        topology_source.as_ref(),
        assigned.as_ref(),
        loaded_source.as_ref(),
        &full_profile,
    );
    let worker_bindings = worker_bindings(assigned.as_ref());
    if tree.is_some() {
        crate::status::done(profile.name);
    }
    let restore = source.map(|source| {
        prepare_restore(
            boot,
            source,
            restore_usb.unwrap(),
            tree,
            &host_network,
            fdr_device.take(),
        )
    });
    // All source/resource preparation precedes the first publication.
    // A reached write failure is terminal before any guest entry.
    let _published_tree = assigned.as_ref().map(|assigned| {
        publish_assigned(
            assigned,
            loaded_tree.take().expect("retained source tree"),
            &canonical_ram,
            cacheless_memory,
            projected_bytes.as_deref(),
        )
    });
    let boot_progress = boot_progress(loaded_source.as_ref());
    drop(assigned);
    drop(roster);
    start_machine(
        boot,
        MachineParts {
            owner: host_owner,
            executors,
            sender,
            ram: canonical_ram,
            cpu,
            devices,
            profile,
            boot_processor,
            worker_bindings,
            processor_power,
            core_locks,
            _published: _published_tree,
            io: RunIo {
                restore,
                host_input,
                host_usb,
                guest_network,
                host_nor,
                host_disks,
                host_acpi,
                boot_progress,
            },
        },
    )
}

/// The guest's board as its live DeviceTree describes it, its boot PE and
/// CPU profile, and how many host processors run its PEs.
struct Modeled {
    board: Option<board::Board>,
    boot_processor: usize,
    full_profile: CpuProfile,
    active_workers: usize,
}

/// Model the board of the loaded DeviceTree, whose boot PE must be the one
/// the verified bundle hands off to.
fn model_board(
    boot: Boot<'_>,
    loaded_tree: Option<&bundle::live_tree::LiveTree>,
    bundle_boot_processor: Option<usize>,
    target: TargetCpu,
    speculation: Speculation,
) -> Modeled {
    let Boot {
        handoff, options, ..
    } = boot;
    let source_tree = loaded_tree.as_ref().map(|tree| tree.bytes());
    if source_tree.is_some() {
        crate::status::begin("Setting up the Mac's hardware");
    }
    let board = source_tree.map(|tree| {
        board::board(tree).unwrap_or_else(|error| {
            output::arguments(format_args!("board refusal: {error}\n"));
            output::fatal("the board could not be modeled")
        })
    });
    let boot_processor = match board.as_ref() {
        Some(board) => {
            let boot = board
                .boot_processor
                .as_ref()
                .unwrap_or_else(|| output::fatal("the DeviceTree has no running boot PE"));
            if bundle_boot_processor != Some(boot.cpu) {
                output::fatal("the board boot PE differs from the verified bundle handoff");
            }
            output::arguments(format_args!(
                "BOOT PE index={} path={} affinity={:#x} cluster={}\n",
                boot.cpu,
                boot.path,
                boot.affinity,
                char::from(boot.cluster_type),
            ));
            boot.cpu
        }
        None => {
            if bundle_boot_processor.is_some() {
                output::fatal("a selected boot PE requires a live DeviceTree");
            }
            0
        }
    };
    let full_profile = match &board {
        Some(board) => board_profile(board, target, speculation),
        None => test_profile(target, speculation),
    };
    let active_workers = crate::native_smp::topology::guest_assignment_count(
        options.native_cores,
        handoff.native_resources.cores as usize,
        full_profile.processors.len().max(1),
    )
    .unwrap_or_else(|error| output::fatal(error));
    output::arguments(format_args!(
        "NATIVE ACTIVE workers={active_workers} parked={} source_PEs={}\n",
        handoff.native_resources.cores as usize - active_workers,
        full_profile.processors.len().max(1),
    ));
    Modeled {
        board,
        boot_processor,
        full_profile,
        active_workers,
    }
}

/// Connect the assigned PEs' power to the PMGR resources of the source
/// board they were assigned from.
fn connect_processor_power(
    devices: &mut AppleDevices,
    topology_source: Option<&topology::Source<'_>>,
    assigned: Option<&topology::Prepared<'_>>,
    loaded_source: Option<&bundle::source::Intake>,
    full_profile: &CpuProfile,
) -> Vec<stela_engine::machine::engine::ProcessorBinding> {
    match (topology_source, assigned, loaded_source) {
        (Some(source), Some(assigned), Some(intake)) => {
            let original = stela_contracts::adt::Node::root(intake.original())
                .unwrap_or_else(|| output::fatal("retained original source ADT is malformed"));
            devices
                .connect_processor_power(
                    source.resources.graph(),
                    &original,
                    full_profile,
                    &assigned.plan,
                    source.acc_harvesting(),
                )
                .unwrap_or_else(|error| output::fatal(&error))
        }
        (None, None, None) => Vec::new(),
        _ => output::fatal("assigned processor power lost its retained source owner"),
    }
}

/// Which host worker runs each PE: the assignment's, else the boot
/// processor runs PE 0.
fn worker_bindings(
    assigned: Option<&topology::Prepared<'_>>,
) -> Vec<stela_engine::machine::engine::publication::WorkerBinding> {
    match assigned {
        Some(assigned) => assigned
            .worker_bindings()
            .unwrap_or_else(|error| output::fatal(&error)),
        None => alloc::vec![stela_engine::machine::engine::publication::WorkerBinding {
            pe: 0,
            worker: stela_engine::machine::engine::publication::WorkerId(0),
        }],
    }
}

/// What the machine is made from once the guest's topology is published.
struct MachineParts {
    owner: host::HostOwner,
    executors: crate::native_smp::executor::Executors,
    sender: crate::apic::Apic,
    ram: alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
    cpu: Cpu,
    devices: AppleDevices,
    profile: CpuProfile,
    boot_processor: usize,
    worker_bindings: Vec<stela_engine::machine::engine::publication::WorkerBinding>,
    processor_power: Vec<stela_engine::machine::engine::ProcessorBinding>,
    core_locks: stela_engine::machine::ctrr::CoreLocks,
    /// The published DeviceTree, kept for the whole run.
    _published: Option<bundle::live_tree::LiveTree>,
    io: RunIo,
}

/// Make the machine on the host's processors, in parallel when asked, and
/// run it until it stops.
fn start_machine(boot: Boot<'_>, parts: MachineParts) -> ! {
    let Boot {
        handoff,
        options,
        native_processors,
    } = boot;
    let MachineParts {
        owner: mut host_owner,
        executors,
        sender,
        ram: canonical_ram,
        cpu,
        devices,
        profile,
        boot_processor,
        worker_bindings,
        processor_power,
        core_locks,
        _published,
        io,
    } = parts;
    let capture = native_processors.expect("validated native roster");
    let hub = stela_engine::machine::engine::Hub::new(
        profile.processors.len().max(1),
        parallel::Doorbells::new(profile.processors.len().max(1), &worker_bindings, |slot| {
            let selected = *capture.selected.get(slot)? as usize;
            u32::try_from(capture.processors.get(selected)?.apic_id).ok()
        }),
    );
    // Profile observations copy only the owners' last materialized images;
    // they are stale diagnostics, not coherent source-state receipts.
    hub.set_source_observations(options.profile);
    let devices = parallel::Board::new(devices, hub.clone());
    let settings = parallel::Settings {
        profile: profile.clone(),
        target: canonical_ram.target(),
        traces: options.traces.clone(),
        watches: options.watches.clone(),
    };
    // The loader handle's last RAM copy preceded canonical registration; its
    // borrow has ended. It never executes a guest instruction.
    // SAFETY: started executors, kept source Plan/profile and exact
    // RAM/device owners remain live for the whole non-returning run below.
    let mut machine = unsafe {
        crate::native_smp::canonical::prepare_with_locks(
            crate::native_smp::canonical::Preparation {
                handoff,
                capture: native_processors.expect("validated native roster"),
                executors: &executors,
                sender: &sender,
                owner: &mut host_owner,
                ram: canonical_ram,
                cpu,
                devices,
                profile,
                boot_processor,
                assignments: &worker_bindings,
                processor_power: &processor_power,
            },
            options.native_artifacts,
            Some(core_locks),
        )
    }
    .unwrap_or_else(|error| output::fatal(error));
    if options.parallel {
        // The workers are held for good, and their cores run PEs instead.
        // SAFETY: as for `run_serialized` below.
        if let Err(stop) = unsafe { machine.hold_serialized() } {
            output::arguments(format_args!("PARALLEL refused: {stop:?}\n"));
            output::fatal("the serial workers could not be held");
        }
        machine
            .enter_parallel(hub)
            .unwrap_or_else(|error| output::fatal(error));
        translations::share(parallel::SHARED_CODE_BYTES);
        parallel::spawn(
            &machine,
            &worker_bindings,
            &executors,
            &sender,
            handoff.tsc_hz,
            &settings,
        )
        .unwrap_or_else(|error| output::fatal(error));
    }
    // The run's driver calls keep the engine's TLB entries; the serialized
    // workers' validations require PCIDE clear.
    let _tagged = options
        .parallel
        .then(storage::TaggedRoots::enable)
        .flatten();
    run_machine(machine, options, handoff, io, |machine, limit| {
        // SAFETY: the same fixed workers and canonical producer set stay
        // kept; an unsupported native service returns without fallback.
        unsafe {
            if options.native_rounds {
                crate::native_smp::canonical::run_slice_for(
                    machine,
                    limit,
                    handoff.tsc_hz / WAIT_POLLS_PER_SECOND,
                )
            } else {
                machine.run_serialized_with_budget(parallel::RunBudget {
                    blocks: limit,
                    host_ticks: Some(host::COUNTER_HZ / WAIT_POLLS_PER_SECOND),
                })
            }
        }
    })
}

/// What the board's devices are placed from besides the board itself.
struct Placement<'a> {
    built: Option<&'a [(alloc::string::String, Vec<u8>)]>,
    entry: u64,
    now: u64,
    read_only_region: Option<(u64, u64)>,
    backing: Option<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    sep_state: Option<stela_runtime::machine::apple::sep_state::Location>,
    usb_disks: Vec<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    guest_mac: Option<stela_drivers::net::Mac>,
}

/// The placed devices, the USB port a restore drives, and whether guest
/// memory is placed without the translation cache.
struct Placed {
    devices: AppleDevices,
    restore_usb: Option<stela_runtime::machine::apple::UsbId>,
    cacheless_memory: bool,
}

/// Place the board's devices with their firmware, scanout, clocks and
/// storage, and bind the native PMP when guest memory is cacheless.
fn place_devices(
    boot: Boot<'_>,
    placement: Placement<'_>,
    board: Option<&board::Board>,
    core_locks: &stela_engine::machine::ctrr::CoreLocks,
    canonical_ram: &alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
    loaded_source: Option<&bundle::source::Intake>,
    tree: Option<&[u8]>,
) -> Placed {
    let Boot {
        handoff,
        options,
        native_processors,
    } = boot;
    let Placement {
        built, entry, now, ..
    } = placement;
    let reset = options.bundle.then_some(entry);
    // Board device firmware images travel in the bundle by guest file name.
    let files = &handoff.files[..handoff.file_count];
    let firmware = |name: &str| -> Option<&[u8]> {
        match built {
            Some(built) => built
                .iter()
                .find(|(file, _)| file == name)
                .map(|(_, bytes)| bytes.as_slice()),
            None => files
                .iter()
                .find(|file| file.name() == name)
                .map(bundle::contents),
        }
    };
    let scanout = handoff.screen.map(|screen| {
        let screen = screen.relocated(layout::physical(screen.base as u64) as usize);
        alloc::boxed::Box::new(display::GopScanout::new(screen))
            as alloc::boxed::Box<dyn stela_runtime::machine::apple::Scanout>
    });
    let programmed = mount::memory_locks(placement.read_only_region, core_locks);
    let memory = board.and_then(|board| memory_resources(board, canonical_ram, programmed));
    let cacheless_memory = memory.is_some();
    let (mut devices, restore_usb) = match devices(
        board,
        mount::Inputs {
            programmed,
            reset,
            now,
            wall: handoff.wall_seconds.map(|seconds| WallClock {
                // The firmware's time, carried forward to the counter's `now`.
                unix_seconds: seconds + (host::rdtsc() - handoff.wall_tsc) / handoff.tsc_hz,
                counter: now,
            }),
            backing: placement.backing,
            sep_state: placement.sep_state,
            sep_observe: options.sep_observe,
            entropy: alloc::boxed::Box::new(bundle::entropy),
            restore: options.restore || options.install.is_some(),
            input: options.input,
            usb: stela_runtime::machine::apple::UsbCables {
                disks: placement.usb_disks,
                network: placement.guest_mac,
            },
            scanout,
            firmware: &firmware,
            build: loaded_source.map(|source| {
                stela_formats::builds::find(&source.selected().product_build)
                    .unwrap_or_else(|error| output::fatal(error))
            }),
        },
        memory,
    ) {
        Ok(devices) => devices,
        Err(error) => {
            output::arguments(format_args!("device refusal: {error}\n"));
            output::fatal("the board devices could not be placed")
        }
    };
    if cacheless_memory
        && let (Some(board), Some(intake), Some(tree)) = (board, loaded_source, tree)
    {
        bind_native_pmp(
            &mut devices,
            board,
            intake,
            tree,
            native_processors,
            canonical_ram,
        );
    }
    Placed {
        devices,
        restore_usb,
        cacheless_memory,
    }
}

/// Publish the assigned topology over the loaded DeviceTree in guest
/// memory. A write failure is terminal before any guest entry.
fn publish_assigned(
    assigned: &topology::Prepared<'_>,
    live: bundle::live_tree::LiveTree,
    canonical_ram: &alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
    cacheless_memory: bool,
    projected: Option<&[u8]>,
) -> bundle::live_tree::LiveTree {
    // SAFETY: cold owner, parked APs, no frame loans or device DMA;
    // every earlier raw guest copy has completed.
    let mut memory = unsafe { bundle::live_tree::registered::ColdRam::new(canonical_ram) };
    let published = if cacheless_memory {
        live.publish_cacheless(&mut memory, &assigned.tree)
    } else {
        live.publish(&mut memory, &assigned.tree)
    }
    .unwrap_or_else(|error| output::fatal(&error));
    if Some(published.bytes()) != projected {
        output::fatal("published assigned topology differs from the prepared device graph");
    }
    published
}

/// Track boot progress through the source manifest's regions.
fn boot_progress(loaded_source: Option<&bundle::source::Intake>) -> progress::BootProgress {
    loaded_source.map_or_else(progress::BootProgress::default, |source| {
        progress::BootProgress::new(
            source
                .manifest()
                .regions
                .iter()
                .map(|region| (region.name.as_str(), region.guest_pa, region.memory_bytes)),
        )
    })
}

/// Select the host workers for the source board's topology, or the boot
/// processor alone, and prepare the topology assigned to them.
fn assign<'s>(
    boot: Boot<'_>,
    roster: &'s mut topology::AssignedRoster<'_>,
    topology_source: Option<&'s topology::Source<'_>>,
    full_profile: &CpuProfile,
) -> Option<topology::Prepared<'s>> {
    let Boot {
        options,
        native_processors,
        ..
    } = boot;
    if let Some(source) = topology_source {
        roster
            .select_for(source, native_processors.expect("validated native roster"))
            .unwrap_or_else(|error| output::fatal(&error));
    } else {
        roster
            .select(&[0])
            .unwrap_or_else(|error| output::fatal(&error));
    }
    let mut assigned = topology_source.map(|source| {
        source
            .prepare_on(
                &*roster,
                full_profile.clone(),
                native_processors.expect("validated native roster"),
            )
            .unwrap_or_else(|error| output::fatal(&error))
    });
    if options.development_restore {
        let assigned = assigned.as_mut().unwrap_or_else(|| {
            output::fatal("--development-restore needs a selected original Apple board")
        });
        let target = development_restore_hardware_model(&mut assigned.tree)
            .unwrap_or_else(|error| output::fatal(&error));
        output::arguments(format_args!(
            "DEVELOPMENT RESTORE hw-model={target} FDR failures remain logged and unprovisioned\n"
        ));
    }
    assigned
}

/// `--native-bootstrap-check` and `--native-shared-check`: each started
/// processor's doorbell, descriptors and host state, the MMIO aperture's
/// shootdown and the shared-kernel fixture. Both stop the engine.
#[cfg(feature = "diagnostics")]
fn check_processors(
    boot: Boot<'_>,
    host: &mut OpenedHost,
    executors: &crate::native_smp::executor::Executors,
    sender: &crate::apic::Apic,
) -> ! {
    let Boot {
        handoff,
        options,
        native_processors,
    } = boot;
    let OpenedHost {
        owner: ref mut host_owner,
        mmio: native_mmio,
        ..
    } = *host;
    for processor in executors.processors() {
        // SAFETY: BSP owns its ICR, physical AP/private descriptors ready.
        let doorbells = unsafe { processor.check_doorbell(sender, handoff.tsc_hz) }
            .unwrap_or_else(|_| output::fatal("native AP doorbell did not complete"));
        let observed = processor.observation();
        let descriptors = processor.descriptors();
        output::arguments(format_args!(
            "NATIVE DESCRIPTORS slot={} rsp={:#x} gdt={:#x} idt={:#x} tr={:#x} gs={:#x} retained=boot-lifetime\n",
            processor.slot(),
            descriptors.rsp,
            descriptors.gdt,
            descriptors.idt,
            descriptors.task,
            descriptors.gs,
        ));
        output::arguments(format_args!(
            "NATIVE HOST slot={} apic={:#x} cr3={:#x} cr0={:#x} cr4={:#x} efer={:#x} pat={:#x} doorbells={}\n",
            processor.slot(),
            processor.apic_id(),
            observed.cr3,
            observed.cr0,
            observed.cr4,
            observed.efer,
            observed.pat,
            doorbells,
        ));
    }
    if let Some(mmio) = &native_mmio {
        // SAFETY: the check owns the host's devices; bus 0's first
        // function is only read here.
        let generation = unsafe { mmio.check_shootdown() }.unwrap_or_else(|error| {
            output::arguments(format_args!("CHECK native-shootdown FAIL {error:?}\n"));
            output::fatal("the MMIO aperture's shootdown failed")
        });
        output::arguments(format_args!(
            "CHECK native-shootdown PASS generation={generation} processors={}\n",
            executors.processors().len()
        ));
    }
    if options.native_shared_check {
        // SAFETY: the bounded fixture owns all source RAM and frame
        // loans; all AP returns are acquired before any borrowed release.
        unsafe {
            crate::native_smp::kernel_check::check(
                handoff,
                native_processors.expect("validated native roster"),
                executors,
                host_owner,
                sender,
            )
        }
        .unwrap_or_else(|error| output::fatal(error));
        output::terminate(0x10);
    }
    output::arguments(format_args!(
        "CHECK native-bootstrap PASS physical_cores={} owned_APs={}; guest SMP execution unqualified\n",
        handoff.native_resources.cores,
        executors.processors().len(),
    ));
    output::terminate(0x10);
}

/// The qualified native topology of the selected source board, which
/// `active_workers` PEs run: none for an authored single-PE image.
fn source_topology<'a>(
    loaded_source: Option<&'a bundle::source::Intake>,
    loaded_tree: Option<&bundle::live_tree::LiveTree>,
    board: Option<&board::Board>,
    full_profile: &CpuProfile,
    active_workers: usize,
) -> Option<topology::Source<'a>> {
    match (loaded_source, loaded_tree, board) {
        (Some(intake), Some(live), Some(source_board)) => {
            let boot = source_board
                .boot_processor
                .as_ref()
                .expect("validated source boot PE");
            let identity = intake
                .topology_identity(full_profile.chip)
                .unwrap_or_else(|error| output::fatal(&error));
            let prepared = match identity.profile.soc {
                0x8112 => topology::Source::t8112_assigned(
                    intake.original(),
                    live,
                    identity,
                    boot.affinity,
                    active_workers,
                ),
                0x6000 => topology::Source::t6000_assigned(
                    intake.original(),
                    live,
                    identity,
                    boot.affinity,
                    active_workers,
                ),
                _ => Err(refuse!(
                    "native assigned topology for this source family is not qualified"
                )),
            };
            Some(prepared.unwrap_or_else(|error| output::fatal(&error)))
        }
        (None, None, None) if active_workers == 1 => None,
        (None, None, None) => {
            output::fatal("an authored multi-PE image requires an explicit qualified topology")
        }
        _ => output::fatal("selected bundle source, live tree and board must be retained together"),
    }
}

/// The board of the assigned topology's DeviceTree, whose boot PE must be
/// the one the host's boot processor runs and the source handed off.
fn assigned_board(
    handoff: &Handoff,
    assigned: &topology::Prepared<'_>,
    full_profile: &CpuProfile,
    boot_processor: usize,
) -> board::Board {
    let candidate = assigned.tree.serialize();
    let parsed = board::board(&candidate).unwrap_or_else(|error| output::fatal(&error));
    let boot = parsed
        .boot_processor
        .as_ref()
        .unwrap_or_else(|| output::fatal("assigned topology has no running boot PE"));
    let join = assigned
        .join(boot.affinity)
        .unwrap_or_else(|error| output::fatal(&error));
    if boot.cpu != join.logical
        || join.worker != 0
        || assigned
            .plan
            .pes()
            .iter()
            .find(|pe| pe.boot)
            .map(|pe| pe.logical)
            != Some(join.logical)
    {
        output::fatal("prepared boot PE differs from the actual assigned BSP");
    }
    if full_profile.processors.get(boot_processor) != assigned.profile.processors.get(boot.cpu) {
        output::fatal("assigned boot identity differs from the original source handoff");
    }
    output::arguments(format_args!(
        "NATIVE ASSIGNMENT original_boot={} assigned_boot={} physical_cores={} PEs={} boot_path={} removed={}\n",
        boot_processor,
        boot.cpu,
        handoff.native_resources.cores,
        assigned.joins.len(),
        assigned.receipt.boot_path,
        assigned.receipt.removed.len()
    ));
    parsed
}

/// Apply the PMGR's resource admission from the DeviceTree the guest boots
/// with, and give the modeled NOR `--nor`'s image.
fn admit_board(
    board: &mut Option<board::Board>,
    tree: Option<&[u8]>,
    hidden_devices: &[String],
    nor_image: Option<stela_soc_data::nor::Image>,
) {
    if let (Some(board), Some(tree)) = (board.as_mut(), tree)
        && let Some(states) = board.power_states.as_mut()
    {
        let unavailable = states
            .apply_admission(tree, hidden_devices)
            .unwrap_or_else(|error| {
                output::arguments(format_args!("PMGR admission refusal: {error}\n"));
                output::fatal("the PMGR resource admission evidence is inconsistent")
            });
        output::arguments(format_args!(
            "DEVICES pmgr unavailable-resources={unavailable}\n"
        ));
    }
    if let Some(image) = nor_image {
        match board.as_mut().and_then(|board| board.spi_nor.as_mut()) {
            Some(spi) => spi.image = image,
            None => output::fatal("--nor was supplied but this DeviceTree exposes no modeled NOR"),
        }
    }
}

/// The cold plan of the memory cache's controls for a cacheless frontend:
/// the board's direct memory cache, else its memory cache, else none.
fn memory_resources(
    board: &board::Board,
    canonical_ram: &alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
    programmed: stela_soc_data::amcc::Programmed,
) -> Option<mount::MemoryResources> {
    if let Some(direct) = board.direct_memory_cache.as_ref() {
        use stela_runtime::machine::apple::memory_resources::t6000_cold;
        // Equal nonzero software quota weights; these are policy for a
        // new cacheless frontend, never a measured Apple reset image.
        let configuration =
            t6000_cold::Configuration::zeroed_control_image(direct.apertures.len(), [1; 32])
                .unwrap_or_else(|error| output::fatal(&error));
        let plan =
            t6000_cold::Plan::prepare_ap_frontend(board, canonical_ram, programmed, &configuration)
                .unwrap_or_else(|error| output::fatal(&error));
        Some(mount::MemoryResources::T6000Cold(plan))
    } else if board.memory_cache.is_some() {
        use stela_runtime::machine::apple::{
            memory_resources::t8112::cache::ZeroWayConfiguration, t8112_cold,
        };
        let configuration = t8112_cold::Configuration::clear_software_controls(
            ZeroWayConfiguration::DisableArgument,
        )
        .unwrap_or_else(|error| output::fatal(&error));
        let plan =
            t8112_cold::Plan::prepare_ap_frontend(board, canonical_ram, programmed, &configuration)
                .unwrap_or_else(|error| output::fatal(&error));
        Some(mount::MemoryResources::T8112Cold(plan))
    } else {
        None
    }
}

/// Bind the native PMP services of a cacheless frontend to the canonical
/// RAM, unless the board's PMP system endpoint is unmodeled.
fn bind_native_pmp(
    devices: &mut AppleDevices,
    board: &board::Board,
    intake: &bundle::source::Intake,
    tree: &[u8],
    native_processors: Option<&'static crate::native_smp::firmware::Capture>,
    canonical_ram: &alloc::sync::Arc<stela_engine::memory::RegisteredSystemRam>,
) {
    let refusal = AppleDevices::native_pmp_system_endpoint_refusal(board)
        .unwrap_or_else(|error| output::fatal(&error));
    if let Some(reason) = refusal {
        output::arguments(format_args!("UNMODELED {reason}\n"));
    } else {
        use stela_runtime::machine::apple::{
            ExplicitRuntimeConfiguration, NativePmpClock, SourceProvenance,
        };
        let pmp = board
            .pmp
            .as_ref()
            .unwrap_or_else(|| output::fatal("native memory's PMP descriptor is missing"));
        let source = SourceProvenance::from_trees(intake.original(), tree, pmp)
            .unwrap_or_else(|error| output::fatal(&error));
        let observation = native_processors
            .expect("validated native roster")
            .snapshots[0]
            .get(1, 0)
            .unwrap_or_else(|| {
                output::fatal("native PMP has no actual admitted CPUID leaf1 observation")
            });
        let configuration = ExplicitRuntimeConfiguration::from_observed_cpuid(
            source,
            observation.ebx,
            observation.edx,
        )
        .unwrap_or_else(|error| output::fatal(&error));
        // This is the native Stela Host's configured counter source,
        // with an explicit software offset0, not an Apple frequency observation.
        let clock = NativePmpClock::new(host::fresh_counter, host::COUNTER_HZ as u32, 0)
            .unwrap_or_else(|error| output::fatal(error));
        // SAFETY: cold before first guest/frame publication; same canonical
        // RAM, parked real APs and exclusive closed devices. Every later
        // transfer runs under held/fenced canonical worker sessions.
        unsafe {
            devices.bind_native_pmp_services(
                board,
                alloc::sync::Arc::clone(canonical_ram),
                configuration,
                clock,
            )
        }
        .unwrap_or_else(|error| output::fatal(&error));
    }
}

/// The restore the guest's installer runs against `source`: the signing
/// service and guest-facing proxy `--tss` selects, and the restore's mode.
fn prepare_restore(
    boot: Boot<'_>,
    source: restore::Source,
    usb: stela_runtime::machine::apple::UsbId,
    tree: Option<&[u8]>,
    host_network: &Option<Result<network::Shared>>,
    fdr_storage: Option<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
) -> restore::Experiment {
    let Boot {
        handoff, options, ..
    } = boot;
    let boot_ecid = tree
        .and_then(stela_contracts::adt::Node::root)
        .and_then(|root| root.child("chosen"))
        .and_then(|chosen| chosen.property("unique-chip-id"))
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .filter(|&ecid| ecid != 0);
    // `--tss` hands the restore client Apple's signing service, for the
    // machine whose ECID the bundle names (`/chosen unique-chip-id`).
    let signer = options.tss.then(|| {
        let ecid = boot_ecid.unwrap_or_else(|| {
            output::fatal("--tss needs the bundle's machine ECID (stela-dev boot prepare --ecid)")
        });
        stela_runtime::restore::tss::Signer {
            ecid,
            // The restore takes the boot ROM's and the SEP ROM's nonces
            // from the ticket the bundle boots under (`Answers::boot_with`).
            nonces: stela_runtime::restore::tss::Nonces {
                ap: [0; 32],
                sep: [0; 20],
            },
            transport: match host_network.as_ref().expect("--tss opens the host network") {
                Ok(network) => alloc::boxed::Box::new(network.clone()),
                Err(reason) => alloc::boxed::Box::new(network::Offline(reason.clone())),
            },
        }
    });
    // Development restores keep the original DEV-board FDR failure
    // policy without exposing Apple's FDR service. TSS, when selected,
    // uses the host signer directly; the image reader also owns its own
    // network access independently of this guest reverse proxy.
    let proxy_network = (options.tss && !options.development_restore)
        .then(|| {
            host_network
                .as_ref()
                .and_then(|network| network.as_ref().ok())
                .cloned()
        })
        .flatten();
    output::arguments(format_args!(
        "RESTORE PROXY wiring host={} ready={} enabled={}\n",
        host_network.is_some(),
        matches!(host_network, Some(Ok(_))),
        proxy_network.is_some()
    ));
    let mode = match (
        &options.install,
        options.update_restore,
        options.development_restore,
    ) {
        (Some(_), false, true) => restore::Mode::DevelopmentInstall,
        (Some(_), false, false) => restore::Mode::Install,
        (Some(_), true, false) => restore::Mode::Update,
        (None, _, false) => restore::Mode::Study,
        _ => unreachable!("validated restore-mode combination"),
    };
    restore::Experiment::new(
        source,
        usb,
        handoff,
        mode,
        options.restore_identity,
        match options.verify_on_read {
            true => Verify::OnRead,
            false => Verify::Full,
        },
        restore::Services {
            signer,
            fdr_storage,
            network: proxy_network,
        },
    )
    .unwrap_or_else(|error| {
        output::arguments(format_args!("restore preparation refusal: {error}\n"));
        output::fatal("restore preparation failed")
    })
}

/// The boot processor's installed host, with what the later phases need.
struct InstalledHost {
    owner: host::HostOwner,
    apic_hz: u64,
    /// The TSC origin every physical executor shares.
    tsc_base: u64,
    /// Whether the BSP runs every PE.
    serialized: bool,
}

/// Install the boot processor's host state over `ram`, and run the bounded
/// diagnostics that stop on it.
fn install_host(handoff: &'static Handoff, options: &Options, ram: &[RamRange]) -> InstalledHost {
    // Serialized, the BSP runs every PE and the workers no guest code.
    let serialized = !(options.parallel
        || options.native_rounds
        || options.native_shared_check
        || options.native_bootstrap_check);
    let partition = crate::native_smp::resources::partition(
        handoff.native_resources.cores as usize,
        0,
        handoff.code.bytes,
        handoff.pool.bytes,
        serialized,
    )
    .unwrap_or_else(|error| output::fatal(error));
    let native_tsc_base = host::rdtsc();
    let config = Config {
        ram: ram.to_vec(),
        pool_physical: handoff.pool.physical,
        pool_bytes: partition.pool_bytes,
        window_root: handoff.root,
        loader_tables: &handoff.native_loader_tables,
        code_virtual: layout::code(),
        code_physical: handoff.code.physical,
        code_bytes: partition.code_bytes,
        tsc_base: native_tsc_base,
        tsc_hz: handoff.tsc_hz,
        apic_base: handoff.apic_base,
        placement: handoff.placement,
        bounce: Some((layout::bounce(), handoff.bounce)),
    };
    crate::status::begin("Installing the host processor state");
    // SAFETY: once on the BSP, with interrupts off and owned native resources. Keep the
    // processor-local state through every native call and handler.
    let host_owner = unsafe { host::install(config) }.unwrap_or_else(|error| output::fatal(error));
    #[cfg(feature = "diagnostics")]
    let mut host_owner = host_owner;
    #[cfg(feature = "diagnostics")]
    if options.native_bootstrap_check {
        host::fp_diagnostic::check(&mut host_owner.host())
            .unwrap_or_else(|error| output::fatal(error));
    }
    let apic_hz = host::statistics().apic_hz;
    crate::status::done("");
    #[cfg(feature = "diagnostics")]
    if options.native_clock_check {
        // SAFETY: explicit original UP/controller ownership; HPET uses the
        // production Source, or absent HPET preserves the bounded PM
        // fixture's complete <=1second gap contract. No driver is published.
        unsafe { crate::native_mmio::diagnostic::clock(handoff, &mut host_owner) }.unwrap_or_else(
            |error| {
                output::arguments(format_args!("CHECK native-clock FAIL {error}\n"));
                output::fatal("native clock fixture failed")
            },
        );
        stop_here("bounded native clock fixture complete", 0x10);
    }
    #[cfg(feature = "diagnostics")]
    if options.native_mmio_check {
        // SAFETY: this explicit UP entry owns its separately reserved mixed32
        // diagnostic pool. It retires every view before the MMIO phases and
        // never activates a second permission or publishes a service.
        unsafe { kernel_work::check_mixed(handoff, &mut host_owner) }.unwrap_or_else(|error| {
            output::arguments(format_args!("CHECK native-mixed32 FAIL {error}\n"));
            output::fatal("mixed32 native stack qualification failed")
        });
        // SAFETY: explicit bounded native diagnostic on the original kept
        // handoff/owner. Success stops before guest entry; permanent mapping
        // and IRQ registries keep this exact physical root until VM shutdown.
        unsafe { crate::native_mmio::diagnostic::check(handoff, &mut host_owner) }.unwrap_or_else(
            |error| {
                output::arguments(format_args!("CHECK native-mmio FAIL {error:?}\n"));
                output::fatal("native MMIO root qualification failed")
            },
        );
        stop_here("native MMIO root qualification complete", 0x10);
    }
    InstalledHost {
        owner: host_owner,
        apic_hz,
        tsc_base: native_tsc_base,
        serialized,
    }
}

/// The firmware's ACPI namespace and the owned MMIO permission, each `None`
/// when the host does not check, which is reported. The device interrupt
/// registry is attached here too, or its refusal reported.
struct Platform {
    acpi: Option<&'static aml::HostAcpi>,
    mmio: Option<&'static crate::native_mmio::Source>,
    remappers: &'static remapping::Remappers,
    /// Affine runtime/source remain held through paused/quarantined frames.
    /// Its producer services require their own complete admission graph.
    _work: Option<&'static kernel_work::KernelWork>,
}

fn start_platform(handoff: &'static Handoff, host_owner: &mut host::HostOwner) -> Platform {
    // The owned MMIO permission the host devices' services map through. A
    // host it cannot check is reported, and those services refuse.
    // SAFETY: this boot's capture, on the installed boot processor before
    // the other host processors start.
    let native_mmio = unsafe { crate::native_mmio::captured(handoff) }
        .and_then(|wire| unsafe {
            crate::native_mmio::Source::activate(wire, host_owner, handoff.tsc_hz)
        })
        .inspect(|_| output::arguments(format_args!("NATIVE MMIO aperture owned\n")))
        .inspect_err(|error| {
            output::arguments(format_args!("NATIVE MMIO unavailable: {error:?}\n"));
        })
        .ok()
        .map(|source| &*alloc::boxed::Box::leak(alloc::boxed::Box::new(source)));
    // SAFETY: the installed boot processor with interrupts off; the engine's
    // IDT routes the device vectors to native_irq, and the physmap maps the
    // local APIC in every root.
    match unsafe {
        crate::native_irq::start(
            layout::physical(handoff.apic_base & crate::apic::BASE_ADDRESS),
            handoff.tsc_hz,
        )
    } {
        Ok(()) => output::arguments(format_args!("NATIVE IRQ device vectors attached\n")),
        Err(error) => output::arguments(format_args!("NATIVE IRQ unavailable: {error:?}\n")),
    }
    // The remapping units, taken before any host driver starts DMA.
    let remappers = match (&native_mmio, handoff.storage.handoff()) {
        // SAFETY: no host driver has started; the loader root maps the ACPI
        // tables and configuration space, and the firmware's translation
        // was turned off at ExitBootServices.
        (Some(mmio), Some(storage)) => unsafe {
            remapping::Remappers::take(
                handoff.rsdp,
                handoff.root,
                &storage.ecam,
                storage.dma.clone(),
                mmio,
                handoff.tsc_hz,
            )
        },
        _ => remapping::Remappers::none(),
    };
    // SAFETY: validated BSP handoff, before AP/driver producers.
    let work = match unsafe { kernel_work::KernelWork::prepare(handoff, host_owner) } {
        Ok(work) => {
            #[cfg(feature = "diagnostics")]
            output::arguments(format_args!(
                "NATIVE WORK owned stacks=16 foreground=verified services=unpublished\n"
            ));
            Some(&*alloc::boxed::Box::leak(alloc::boxed::Box::new(work)))
        }
        Err(error) => {
            output::arguments(format_args!("NATIVE WORK unavailable: {error}\n"));
            None
        }
    };
    let prepared_sci = match (&native_mmio, &handoff.power) {
        (Some(mmio), Some(power)) => {
            // SAFETY: firmware is stopped, APs have not started, and native
            // probing has not published any PCI/controller owner yet.
            let prepared = unsafe { mmio.mask_pci_intx() }
                .map_err(|error| refuse!("PCI INTx handoff: {error}", ?error))
                .and_then(|()| {
                    // SAFETY: PCI INTx contributors are disabled; the boot
                    // owns the fixed/GPE sources and complete IOAPIC handoff.
                    unsafe { aml::sci::Prepared::capture(mmio, power.clone()) }
                        .map_err(|error| refuse!("SCI route: {error}", ?error))
                });
            match prepared {
                Ok(prepared) => Some(prepared),
                Err(error) => {
                    output::arguments(format_args!("HOST ACPI SCI unavailable: {error}\n"));
                    None
                }
            }
        }
        _ => None,
    };
    let host_acpi = aml::HostAcpi::start(
        handoff.rsdp,
        handoff.root,
        handoff
            .storage
            .handoff()
            .map(|storage| storage.ecam)
            .unwrap_or_default(),
        handoff.tsc_hz,
        prepared_sci,
        work,
    );
    Platform {
        acpi: host_acpi,
        mmio: native_mmio,
        remappers: alloc::boxed::Box::leak(alloc::boxed::Box::new(remappers)),
        _work: work,
    }
}

/// The network `--wifi` names, with the secret of the key file the loader
/// read, whose bytes are wiped here. A file it cannot use is reported once,
/// without its contents, and no network is joined.
fn wifi_network(handoff: &Handoff, options: &Options) -> Option<stela_drivers::probe::WifiConfig> {
    let ssid = options.ssid.as_ref()?;
    let path = options
        .wifi_key
        .as_deref()
        .unwrap_or(stela_boot_core::options::DEFAULT_WIFI_KEY);
    let bytes = handoff.wifi_key.bytes as usize;
    if bytes == 0 {
        output::arguments(format_args!(
            "HOST Wi-Fi key {path} is missing, empty or unreadable: the network is not joined\n"
        ));
        return None;
    }
    // SAFETY: the loader left the key's bytes allocated, and only this
    // reads them.
    let key = unsafe {
        core::slice::from_raw_parts_mut(
            layout::physical(handoff.wifi_key.physical) as *mut u8,
            bytes,
        )
    };
    let secret = stela_drivers::probe::WifiSecret::parse(key);
    for byte in key.iter_mut() {
        // SAFETY: a byte of the key, which nothing else reads.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    let secret = match secret {
        Ok(secret) => secret,
        Err(error) => {
            output::arguments(format_args!(
                "HOST Wi-Fi key {path} unusable ({error}): the network is not joined\n"
            ));
            return None;
        }
    };
    let country = options
        .wifi_country
        .as_deref()
        .and_then(|code| code.as_bytes().try_into().ok());
    Some(stela_drivers::probe::WifiConfig {
        ssid: ssid.as_bytes().to_vec(),
        secret,
        country,
    })
}

/// What the host devices are opened for.
struct Wanted<'a> {
    firmware: Option<alloc::sync::Arc<stela_drivers::firmware::Catalog>>,
    processors: Option<&'static crate::native_smp::firmware::Capture>,
    targets: &'a [&'a Target],
    store: Option<Guid>,
    fdr: Option<Guid>,
    /// Whether the mount's own network is needed.
    network: bool,
}

/// The host devices the engine and the guest use.
struct HostDevices {
    services: Vec<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    medium: Option<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    preboot: Option<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    host_input: Option<input::HostInput>,
    host_usb: Option<usb::HostUsb>,
    host_network: Option<Result<network::Shared>>,
    usb_disks: Vec<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
    guest_network: Option<network::GuestNetwork>,
    host_disks: storage::HostDisks,
    fdr: Option<alloc::boxed::Box<dyn stela_drivers::block::BlockDevice>>,
}

/// Probe the host's devices once, with the native services when the
/// platform has them, and open the partitions, inputs and networks.
fn start_devices(
    handoff: &Handoff,
    options: &Options,
    wanted: &Wanted<'_>,
    host_acpi: Option<&'static aml::HostAcpi>,
    native_mmio: &Option<&'static crate::native_mmio::Source>,
    remappers: &'static remapping::Remappers,
    kernel_work: Option<&'static kernel_work::KernelWork>,
) -> HostDevices {
    let &Wanted {
        firmware: ref host_firmware,
        processors: native_processors,
        targets,
        store: translation_store,
        fdr: fdr_partition,
        network: wants_network,
    } = wanted;
    let mut fdr_device = None;
    let mut host_usb = None;
    let (services, medium, preboot, host_input, host_network, usb_disks, guest_network, host_disks) =
        if targets.is_empty()
            && options.install_source.is_none()
            && options.preboot.is_none()
            && !options.input
            && !wants_network
            && options.usb_storage.is_empty()
            && !options.external_disks
            && !options.guest_network
            && translation_store.is_none()
            && fdr_partition.is_none()
        {
            (
                Vec::new(),
                None,
                None,
                None,
                None,
                Vec::new(),
                None,
                storage::HostDisks::none(),
            )
        } else {
            let mut storage_handoff = handoff
                .storage
                .handoff()
                .unwrap_or_else(|| output::fatal("the loader found no storage controllers"));
            storage_handoff.firmware = host_firmware.clone();
            // Disks that can signal their completions wake the BSP, which
            // runs the engine's devices.
            let bsp = native_processors.expect("validated native roster");
            storage_handoff.completion =
                host::completion_signal(bsp.processors[bsp.selected[0] as usize].apic_id);
            #[cfg(feature = "diagnostics")]
            if options.audio_check.is_some() {
                // The audio check keeps the final slice even after shutdown.
                storage_handoff.dma.end -= crate::audio_check::DMA_BYTES;
            }
            crate::status::begin("Starting the PC's disks and USB devices");
            // Every admitted input is owned or a boot owner.
            // No probe callback can borrow this dispatcher stack on timeout.
            let owned_targets: Vec<_> = targets.iter().map(|target| (**target).clone()).collect();
            let owned_preboot = options.preboot.clone();
            let owned_usb = options.usb_storage.clone();
            let owned_wifi = wifi_network(handoff, options);
            let external = options.external_disks.then(|| {
                stela_runtime::machine::apple::UsbCables::disk_ports(options.guest_network)
                    .saturating_sub(owned_usb.len())
            });
            let root = handoff.root;
            let heap = handoff.heap.physical..handoff.heap.physical + handoff.heap.bytes;
            let tsc_hz = handoff.tsc_hz;
            let host_clock = storage_handoff.clock;
            let mmio = *native_mmio;
            let medium_partition = options.install_source;
            let log_partition = handoff.log_partition.map(Guid);
            let work = kernel_work
                .unwrap_or_else(|| output::fatal("native probe requires an owned continuation"));
            let opened = work.call_owned(60_000_000, move || {
                let native = mmio
                    .map(|mmio| services::Services::new(mmio, remappers, host_acpi, heap, tsc_hz));
                let targets: Vec<_> = owned_targets.iter().collect();
                // SAFETY: one admitted foreground task under the work
                // dispatcher's loader-root/driver guard. Owned handoff, inputs
                // and kept services survive completion or quarantine.
                unsafe {
                    storage::open(
                        &storage_handoff,
                        root,
                        native
                            .as_ref()
                            .map(|native| native as &dyn stela_drivers::probe::NativeServices),
                        &storage::Partitions {
                            targets: &targets,
                            medium: medium_partition,
                            preboot: owned_preboot.as_ref(),
                            store: translation_store,
                            log: log_partition,
                            fdr: fdr_partition,
                        },
                        &owned_usb,
                        owned_wifi.as_ref(),
                        external,
                    )
                }
            });
            let storage::Opened {
                services,
                medium,
                preboot,
                store,
                log,
                fdr,
                inputs,
                mut links,
                usb,
                usb_disks,
                disks,
                power,
            } = opened
                .unwrap_or_else(|error| {
                    Err(refuse!("native probe admission failed: {error}", %error))
                })
                .unwrap_or_else(|error| {
                    output::arguments(format_args!("host storage refusal: {error}\n"));
                    output::fatal(format_args!("host storage could not be opened: {error}"))
                });
            if let Some(acpi) = host_acpi {
                acpi.retain_power(power);
            }
            disks.profile_callbacks(options.profile);
            let count = |count: usize, one: &str, many: &str| {
                format!("{count} {}", if count == 1 { one } else { many })
            };
            let partitions = count(
                services.len() + usize::from(medium.is_some()),
                "partition",
                "partitions",
            );
            crate::status::done(&match usb_disks.len() {
                0 => partitions,
                disks => format!(
                    "{partitions}, and {} macOS sees as USB drives",
                    count(disks, "disk", "disks")
                ),
            });
            if let Some(log) = log {
                crate::log_file::resume(log);
            }
            if let Some(store) = store {
                translations::set_partition(store);
            }
            fdr_device = fdr;
            host_usb = Some(usb);
            // The guest's adapter is its own: the mount's client keeps the
            // first one. Without one the Mac boots with no network, which
            // is reported once.
            let guest_network = options
                .guest_network
                .then(|| {
                    network::GuestNetwork::open(&mut links, wants_network)
                        .inspect_err(|error| {
                            output::arguments(format_args!("guest network refusal: {error}\n"));
                            crate::status::warn(&error.to_string());
                        })
                        .ok()
                })
                .flatten();
            // A missing network is reported here and refused only by what
            // needs it, so the mount still boots and logs how far it gets.
            let network = wants_network.then(|| {
                crate::status::begin("Getting a network address");
                network::HostNetwork::open(links, host_clock)
                    .inspect(|network| crate::status::done(network.describe()))
                    .map(|network| network::Shared(Rc::new(RefCell::new(network))))
                    .inspect_err(|error| {
                        output::arguments(format_args!("host network refusal: {error}\n"));
                        crate::status::warn(&error.to_string());
                    })
            });
            (
                services,
                medium,
                preboot,
                options.input.then(|| input::HostInput::new(inputs)),
                network,
                usb_disks,
                guest_network,
                disks,
            )
        };
    HostDevices {
        services,
        medium,
        preboot,
        host_input,
        host_usb,
        host_network,
        usb_disks,
        guest_network,
        host_disks,
        fdr: fdr_device,
    }
}
