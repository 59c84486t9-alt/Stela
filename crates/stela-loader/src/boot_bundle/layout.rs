//! Placing images and contents in physical memory, the memory map, the bundle
//! files and their hashes.

use super::*;

/// The options with the physical base raised past iBoot's carveouts, which
/// sit below the managed range, and the carveouts placed.
pub(super) struct Placement {
    pub(super) options: Options,
    pub(super) carveouts: Vec<Placed>,
    pub(super) dram_end: u64,
}

impl Placement {
    pub(super) fn new(inputs: &Inputs, options: &Options) -> Result<Self> {
        let table = inputs
            .target
            .chip_id
            .map(carveouts::for_chip)
            .unwrap_or_default();
        let reservation = carveouts::reserve(&table, options.dram_base, options.dram_size)?;
        let dram_end = options
            .dram_base
            .checked_add(options.dram_size)
            .context("DRAM end overflows")?;
        let options = Options {
            phys_base: options.phys_base.max(reservation.managed_floor()),
            ..options.clone()
        };
        if let (Some(chip_id), Some(base)) = (inputs.target.chip_id, inputs.dram_base()?) {
            ensure!(
                options.dram_base == base,
                "guest DRAM base {:#x} is not ApChipID {chip_id:#x}'s {base:#x}",
                options.dram_base
            );
        }
        ensure!(
            options.phys_base >= options.dram_base
                && options.phys_base < dram_end
                && options.phys_base.is_multiple_of(PAGE_BYTES)
                && options.load_offset.is_multiple_of(PAGE_BYTES),
            "phys_base must be a page-aligned address inside DRAM"
        );
        Ok(Self {
            options,
            carveouts: reservation.into_regions(),
            dram_end,
        })
    }
}

/// The three boot images, split into their regions.
pub(super) struct Images {
    pub(super) kernel: LoadedImage,
    pub(super) sptm: LoadedImage,
    pub(super) txm: LoadedImage,
}

impl Images {
    pub(super) fn load(inputs: &Inputs) -> Result<Self> {
        Ok(Self {
            kernel: LoadedImage::new(
                "BootKC",
                KERNEL_FILE,
                KernelCollection::parse(inputs.kernel_collection.bytes)?,
                inputs.kernel_collection.bytes,
                KERNEL_SPLITS,
            )?,
            sptm: LoadedImage::new(
                "SPTM",
                SPTM_FILE,
                KernelCollection::parse_executable(inputs.sptm.bytes)?,
                inputs.sptm.bytes,
                SPTM_SPLITS,
            )?,
            txm: LoadedImage::new(
                "TXM",
                TXM_FILE,
                KernelCollection::parse_executable(inputs.txm.bytes)?,
                inputs.txm.bytes,
                TXM_SPLITS,
            )?,
        })
    }

    /// The manifest's images, SPTM's first: where execution starts.
    pub(super) fn manifest_images(&self, regions: &[Region]) -> Result<Vec<Image>> {
        [&self.sptm, &self.txm, &self.kernel]
            .into_iter()
            .map(|image| {
                let offset = image.collection.entry_offset();
                let (name, range) = image
                    .pieces
                    .iter()
                    .find(|(_, r)| r.contains(&offset))
                    .context("entry lies outside every region")?;
                let region = regions
                    .iter()
                    .find(|r| r.name == *name)
                    .with_context(|| format!("no region {name}"))?;
                Ok(Image {
                    name: image.name.into(),
                    file: image.file.into(),
                    uuid: image.collection.uuid.clone(),
                    vm_base: image.collection.vm_base,
                    vm_bytes: image.collection.image_bytes(),
                    entry: Entry {
                        image: image.name.into(),
                        virtual_address: image.collection.thread.pc,
                        physical_address: region.guest_pa + (offset - range.start),
                    },
                    fileset_entries: image.collection.fileset_entries.len(),
                })
            })
            .collect()
    }
}

/// The DeviceTree as iBoot hands it over, before the memory map is laid
/// out, and what shaping it decided.
pub(super) struct Shaped {
    pub(super) tree: DeviceTree,
    pub(super) placeholders: Vec<PlaceholderDecision>,
    pub(super) boot_cpu: BootCpu,
    pub(super) security: Vec<Decision>,
    pub(super) unresolved: Vec<String>,
    pub(super) nvram_published: bool,
    pub(super) memory_controller: Option<&'static lock_regs::MemoryController>,
    pub(super) hidden_devices: Vec<String>,
    pub(super) boot_manifest_object: Option<boot_manifests::Object>,
}

impl Shaped {
    pub(super) fn new(inputs: &Inputs, options: &Options, carveouts: &[Placed]) -> Result<Self> {
        let boot_manifest = inputs
            .boot_manifest
            .as_ref()
            .map(|input| im4m::parse(input.bytes))
            .transpose()?;
        let cryptex1_manifest = inputs
            .cryptex1_manifest
            .as_ref()
            .map(|input| im4m::parse(input.bytes))
            .transpose()?;
        for manifest in boot_manifest.iter().chain(&cryptex1_manifest) {
            check_board(manifest, &inputs.target)?;
        }
        let mut tree = DeviceTree::parse(inputs.device_tree.bytes)?;
        let original_tree = tree.clone();
        // iBoot merges the fused variant's overlays as it loads the tree.
        let (variant, variant_decisions) =
            soc_variant::apply(&mut tree, inputs.target.chip_id, inputs.target.board_id)?
                .map_or((None, vec![]), |(variant, decisions)| {
                    (Some(variant), decisions)
                });
        let placeholders = resolve_placeholders(&mut tree, options)?;
        let boot_cpu = select_boot_cpu(&tree, &original_tree, options.boot_cpu.as_deref())?;
        let mut unresolved = shape_device_tree(&mut tree, &inputs.target, options, &boot_cpu)?;
        let (mut security, policy_unresolved) = boot_policy::apply(
            &mut tree,
            &options.security,
            boot_manifest.as_ref(),
            cryptex1_manifest.as_ref(),
        )?;
        unresolved.extend(policy_unresolved);
        security.extend(variant_decisions);
        let mut shaped = Self {
            tree,
            placeholders,
            boot_cpu,
            security,
            unresolved,
            nvram_published: false,
            memory_controller: None,
            hidden_devices: vec![],
            boot_manifest_object: None,
        };
        shaped.hand_off(inputs, options, boot_manifest.as_ref())?;
        let fused = variant.map(|variant| variant.name);
        shaped.publish_platform(inputs, carveouts, fused)?;
        apply_overlay(&mut shaped.tree, &options.overlay)?;
        verify_boot_cpu(&shaped.tree, &original_tree, &shaped.boot_cpu)?;
        shaped
            .unresolved
            .extend(platform_gaps(&shaped.tree, inputs));
        shaped.boot_manifest_object = shaped.boot_manifest_object(inputs, options)?;
        Ok(shaped)
    }

    pub(super) fn record(&mut self, (decisions, gaps): (Vec<Decision>, Vec<String>)) {
        self.security.extend(decisions);
        self.unresolved.extend(gaps);
    }

    /// The root, the OS environment, the boot command and the machine
    /// identity iBoot writes into `/chosen`.
    pub(super) fn hand_off(
        &mut self,
        inputs: &Inputs,
        options: &Options,
        boot_manifest: Option<&im4m::Manifest>,
    ) -> Result<()> {
        if let Some(root_hash) = &inputs.root_hash {
            if root_hash.volume == boot_policy::SealedVolume::BaseSystem {
                boot_policy::require_image_boot(&options.boot_args)?;
            }
            let manifest = inputs
                .boot_manifest
                .as_ref()
                .zip(boot_manifest)
                .map(|(input, manifest)| (input.bytes, manifest));
            let applied = boot_policy::apply_root_hash(
                &mut self.tree,
                root_hash.volume,
                root_hash.im4p.as_ref().map(|input| input.bytes),
                manifest,
            )?;
            self.record(applied);
        }
        if let Some(environment) = options.osenvironment {
            let applied = boot_policy::apply_environment(&mut self.tree, environment)?;
            self.record(applied);
        }
        // iBoot deletes the environments once one is applied.
        self.security
            .extend(handoff::remove_environments(&mut self.tree));
        let applied = handoff::apply(&mut self.tree, inputs.target.chip_id)?;
        self.record(applied);
        let applied = handoff::apply_boot_command(&mut self.tree, options.boot_command)?;
        self.record(applied);
        let applied = handoff::apply_identity(&mut self.tree, options.ecid, inputs.target.chip_id)?;
        self.record(applied);
        match &options.root {
            Some(root) => self
                .security
                .extend(root_selection::apply(&mut self.tree, root)?),
            None => self.unresolved.push(
                "/chosen apfs-preboot-uuid, boot-uuid, boot-objects-path: no root volume was named; \
                 template values kept"
                    .into(),
            ),
        }
        boot_policy::refuse_ramdisk_image_root(&options.boot_args)
    }

    /// The carveouts, interrupt controller, NVRAM, memory-controller locks,
    /// DARTs, operating points and device admissions iBoot publishes.
    pub(super) fn publish_platform(
        &mut self,
        inputs: &Inputs,
        carveouts: &[Placed],
        fused: Option<&'static str>,
    ) -> Result<()> {
        let tree = &mut self.tree;
        let unresolved = &mut self.unresolved;
        carveouts::publish(tree, carveouts)?;
        if let Some(chip_id) = inputs.target.chip_id {
            aic::publish(tree, chip_id)?;
        }
        self.nvram_published = nvram::publish(tree)?;
        self.memory_controller = match inputs
            .target
            .chip_id
            .and_then(|chip| lock_regs::table(chip, fused))
        {
            Some(controller) if lock_regs::publish(tree, controller)? => Some(controller),
            Some(_) => {
                unresolved.push(format!(
                    "{}: the template has no node for iBoot's AMCC map; SPTM's CTRR setup stops",
                    lock_regs::AMCC
                ));
                None
            }
            None if tree.node(lock_regs::AMCC).is_some() => {
                unresolved.push(format!(
                    "{}: no iBoot AMCC map for this SoC; the template stays empty and SPTM's CTRR \
                     setup stops on it",
                    lock_regs::AMCC
                ));
                None
            }
            None => None,
        };
        if let Some(controller) = inputs
            .target
            .chip_id
            .and_then(|chip| lock_regs::ioa_table(chip, fused))
        {
            lock_regs::publish_ioa(tree, controller)?;
        }
        darts::publish(tree)?;
        if let Some(chip_id) = inputs.target.chip_id {
            for table in dvfs::publish(tree, chip_id)? {
                let (name, domain) = (&table.name, &table.domain);
                unresolved.push(match table.contents {
                    dvfs::Contents::OperatingPoints => format!(
                        "/arm-io/pmgr {name}: {domain} operating points without calibrated voltages (0)"
                    ),
                    dvfs::Contents::SingleState => {
                        format!("/arm-io/pmgr {name}: {domain} has one state; its clock is not modeled")
                    }
                    dvfs::Contents::Unpublished => format!(
                        "/arm-io/pmgr {name}: ApChipID {chip_id:#x} has no {domain} operating points; \
                         the table is left out and ApplePMGR stops on it"
                    ),
                });
            }
        }
        self.hidden_devices = devices::hide_unmodeled(tree);
        if !self.hidden_devices.is_empty() {
            unresolved.push(format!(
                "{} device admissions are restricted by missing models or providers (hidden_devices)",
                self.hidden_devices.len()
            ));
        }
        if let Some(chip_id) = inputs.target.chip_id
            && let Some(tables) = gpu_dvfs::publish(tree, chip_id)?
        {
            unresolved.push(format!(
                "/arm-io/sgx perf-states, perf-states-sram: {} GPU operating points in {} table \
                 without calibrated voltages (0)",
                tables.states, tables.tables
            ));
        }
        Ok(())
    }

    /// The boot manifest's object, reserved in the tree: the IM4M boot
    /// policy selected, unchanged. The payload tag belongs to the source
    /// input, not a guessed iBoot identity or name. A tethered restore loads
    /// the IPSW's firmware under the same ticket.
    pub(super) fn boot_manifest_object(
        &mut self,
        inputs: &Inputs,
        options: &Options,
    ) -> Result<Option<boot_manifests::Object>> {
        let restore = options.boot_command == Some(handoff::BootCommand::TetheredRestore);
        let object = inputs
            .boot_manifest
            .as_ref()
            .map(|manifest| {
                boot_manifests::Object::new(
                    &self.tree,
                    &inputs.kernel_collection.source.payload_type,
                    manifest.bytes,
                )
                .map(|object| match restore {
                    true => object.admits_firmware(),
                    false => object,
                })
            })
            .transpose()?;
        if let Some(object) = &object {
            object.reserve(&mut self.tree)?;
            self.unresolved.push(
                "/chosen/secure-boot-hashes state: iBoot's loaded-object authentication flags are \
                 not reproduced; only the supplied original kernel manifest is forwarded"
                    .into(),
            );
        }
        Ok(object)
    }
}

/// Every region's content in [`REGION_ORDER`], before placement; the
/// DeviceTree's size is set once the memory map is laid out.
pub(super) fn contents(
    inputs: &Inputs,
    ramdisk_bytes: Option<usize>,
    trust_cache: &[u8],
    images: &Images,
    core_locks_handed_off: bool,
    unresolved: &mut Vec<String>,
) -> Result<Vec<Content>> {
    let content = |name: &str, file: &str, bytes: u64, memory_bytes: u64| Content {
        name: name.into(),
        file: file.into(),
        file_offset: 0,
        bytes,
        memory_bytes,
        virtual_address: None,
    };
    let mut contents = vec![];
    for name in REGION_ORDER {
        let content = match *name {
            "TrustCache" => content(
                name,
                TRUST_CACHE_FILE,
                trust_cache.len() as u64,
                page_round(trust_cache.len() as u64),
            ),
            "BootManifest" => match &inputs.boot_manifest {
                Some(manifest) => content(
                    name,
                    BOOT_MANIFEST_FILE,
                    manifest.bytes.len() as u64,
                    page_round(manifest.bytes.len() as u64),
                ),
                None => continue,
            },
            "DeviceTree" => content(name, DEVICE_TREE_FILE, 0, 0),
            "RAMDisk" => match ramdisk_bytes {
                Some(bytes) => content(name, RAMDISK_FILE, bytes as u64, page_round(bytes as u64)),
                None => continue,
            },
            // iBoot adds the SEPFW entry whether or not it loaded SEP firmware
            // (0x29dd8, before its loaded test at 0x29df4); only
            // `sepfw-loaded`/`sepfw-booted`/`sep-boot-slot` depend on a load.
            // The run-time load needs the region: `seputil --restore` reaches
            // `AppleSEPFirmware::_initFromMemory`, whose
            // `_setupSepFirmwareMemoryRegion` panics without SEPFW and whose
            // `_copyInData` copies the delivered image into it, refusing an
            // image longer than the region. Stela's SEP has no `fromPreload`
            // path, so the region is reserved (zero-filled), large enough for
            // the SEP image in the `IMG4` container the restore host delivers,
            // and `sepfw-loaded` stays unpublished.
            "SEPFW" => match &inputs.sep_firmware {
                Some(sep) => content(
                    name,
                    SEP_FILE,
                    0,
                    page_round(sep_firmware_region_bytes(sep.bytes)),
                ),
                None => {
                    unresolved.push("SEPFW: no SEP firmware input; the region is absent".into());
                    continue;
                }
            },
            lock_regs::CL4_DUMMY_PAGE if core_locks_handed_off => content(
                name,
                CL4_DUMMY_PAGE_FILE,
                lock_regs::CL4_DUMMY_PAGE_BYTES as u64,
                lock_regs::CL4_DUMMY_PAGE_BYTES as u64,
            ),
            lock_regs::CL4_DUMMY_PAGE => continue,
            "BootArgs" => content(
                name,
                BOOT_ARGS_FILE,
                boot_args::BYTES as u64,
                BOOT_ARGS_REGION_BYTES,
            ),
            piece => {
                let image = [&images.kernel, &images.sptm, &images.txm]
                    .into_iter()
                    .find(|image| piece.starts_with(image.name))
                    .with_context(|| format!("no image provides {piece}"))?;
                let range = image
                    .pieces
                    .iter()
                    .find(|(n, _)| n == piece)
                    .map(|(_, r)| r.clone())
                    .with_context(|| format!("{} has no split {piece}", image.name))?;
                Content {
                    name: piece.into(),
                    file: image.file.into(),
                    file_offset: range.start,
                    bytes: range.end - range.start,
                    memory_bytes: range.end - range.start,
                    virtual_address: Some(image.collection.vm_base + range.start),
                }
            }
        };
        contents.push(content);
    }
    unresolved.push(
        "RTBuddySeg: iBoot-provided RTKit buddy segment; content unknown, the region is absent"
            .into(),
    );
    Ok(contents)
}

/// Lays the memory map out with zero values first: its size is fixed by the
/// entry count, so the DeviceTree size is known before placement. Returns
/// that size, which the DeviceTree content now has.
pub(super) fn reserve_memory_map(tree: &mut DeviceTree, contents: &mut [Content]) -> Result<u64> {
    let memory_map = tree
        .node_mut(MEMORY_MAP)
        .context("DeviceTree has no /chosen/memory-map")?;
    memory_map
        .properties
        .retain(|p| !p.name().starts_with(RESERVED_ENTRY_PREFIX));
    let extra_entries = [
        "slide",
        "TXM-entry",
        "TXM-virt",
        "BootKC-entry",
        "BootKC-virt",
        "SPTM-rm",
    ]
    .into_iter()
    .chain(ABSENT_SECURE_KERNEL);
    for name in contents
        .iter()
        .map(|c| c.name.as_str())
        .chain(extra_entries)
    {
        memory_map.set_property(name, vec![0; MEMORY_MAP_ENTRY_BYTES])?;
    }
    let device_tree_bytes = tree.encoded_bytes() as u64;
    for content in contents {
        if content.name == "DeviceTree" {
            content.bytes = device_tree_bytes;
            content.memory_bytes = page_round(device_tree_bytes);
        }
    }
    Ok(device_tree_bytes)
}

/// Every region back to back from `load_base`, each in whole pages, and
/// where the last one ends.
pub(super) fn place(contents: Vec<Content>, load_base: u64) -> Result<(Vec<Region>, u64)> {
    let mut cursor = load_base;
    let mut regions = vec![];
    for content in contents {
        regions.push(Region {
            name: content.name,
            file: content.file,
            file_offset: content.file_offset,
            bytes: content.bytes,
            guest_pa: cursor,
            memory_bytes: content.memory_bytes,
            sha256: String::new(),
            virtual_address: content.virtual_address,
        });
        cursor = cursor
            .checked_add(page_round(content.memory_bytes))
            .context("loaded region end overflows")?;
    }
    Ok((regions, cursor))
}

/// The placed regions and the auxiliary entries in `/chosen/memory-map`.
pub(super) fn fill_memory_map(
    tree: &mut DeviceTree,
    regions: &[Region],
    images: &Images,
    options: &Options,
    load_base: u64,
) -> Result<()> {
    let memory_map = tree.node_mut(MEMORY_MAP).context("memory-map")?;
    for region in regions {
        memory_map.set_property(
            &region.name,
            range_value(region.guest_pa, region.memory_bytes),
        )?;
    }
    let sptm_span = sptm_image_span(regions)?;
    for (name, value) in [
        (
            "slide",
            range_value(options.phys_base, load_base - options.phys_base),
        ),
        (
            "TXM-entry",
            range_value(images.txm.collection.entry_offset(), 0),
        ),
        ("TXM-virt", range_value(0, 0)),
        (
            "BootKC-entry",
            range_value(images.kernel.collection.entry_offset(), 0),
        ),
        ("BootKC-virt", range_value(0, 0)),
        (
            "SPTM-rm",
            range_value(sptm_span.start, sptm_span.end - sptm_span.start),
        ),
    ]
    .into_iter()
    .chain(ABSENT_SECURE_KERNEL.map(|name| (name, range_value(u64::MAX, u64::MAX))))
    {
        memory_map.set_property(name, value)?;
    }
    Ok(())
}

pub(super) fn boot_args_for(
    options: &Options,
    dram_end: u64,
    top_of_kernel_data: u64,
    device_tree_region: &Region,
    device_tree_length: usize,
) -> Result<BootArgs> {
    let virt_base = VIRT_BASE + (options.phys_base % VIRT_BASE_ALIGNMENT);
    Ok(BootArgs {
        revision: boot_args::REVISION,
        version: boot_args::VERSION,
        virt_base,
        phys_base: options.phys_base,
        mem_size: dram_end - options.phys_base,
        top_of_kernel_data,
        video: Video::default(),
        machine_type: 0,
        device_tree: device_tree_region.guest_pa - options.phys_base + virt_base,
        device_tree_length: u32::try_from(device_tree_length)?,
        command_line: options.boot_args.clone(),
        boot_flags: 0,
        mem_size_actual: options.dram_size,
    })
}

/// Bundle files by name, in manifest order.
pub(super) type Files = Vec<(String, Vec<u8>)>;

/// The bundle's files in manifest order, and the ramdisk's source.
pub(super) fn files(
    inputs: &Inputs,
    images: Images,
    device_tree: Vec<u8>,
    trust_cache: Vec<u8>,
    boot_args_bytes: Vec<u8>,
    core_locks_handed_off: bool,
    owned: Option<OwnedRamdisk>,
) -> Result<(Files, Option<Source>)> {
    let mut files = vec![
        (KERNEL_FILE.to_owned(), images.kernel.memory),
        (SPTM_FILE.to_owned(), images.sptm.memory),
        (TXM_FILE.to_owned(), images.txm.memory),
        (DEVICE_TREE_FILE.to_owned(), device_tree),
        (
            ORIGINAL_DEVICE_TREE_FILE.to_owned(),
            inputs.device_tree.bytes.to_vec(),
        ),
        (TRUST_CACHE_FILE.to_owned(), trust_cache),
        (BOOT_ARGS_FILE.to_owned(), boot_args_bytes),
    ];
    if let Some(manifest) = &inputs.boot_manifest {
        files.push((BOOT_MANIFEST_FILE.to_owned(), manifest.bytes.to_vec()));
    }
    if core_locks_handed_off {
        files.push((CL4_DUMMY_PAGE_FILE.to_owned(), lock_regs::cl4_dummy_page()));
    }
    if let Some(sep) = &inputs.sep_firmware {
        files.push((SEP_FILE.to_owned(), sep.bytes.to_vec()));
    }
    let ramdisk_source = match owned {
        Some(ramdisk) => {
            files.push((RAMDISK_FILE.to_owned(), ramdisk.bytes));
            Some(ramdisk.source)
        }
        None => inputs.ramdisk.as_ref().map(|ramdisk| {
            files.push((RAMDISK_FILE.to_owned(), ramdisk.bytes.to_vec()));
            source_of(ramdisk)
        }),
    };
    for (name, image) in &inputs.board_firmware {
        // The manifest admits only simple names; these checks keep the name
        // within the engine handoff and distinct from the bundle's own files.
        ensure!(
            name.len() <= MAX_FILE_NAME && !files.iter().any(|(file, _)| file == name),
            "board firmware name {name:?} is too long or already a bundle file"
        );
        files.push((name.clone(), image.bytes.to_vec()));
    }
    Ok((files, ramdisk_source))
}

/// Each region's hash, over the bytes its file supplies.
pub(super) fn hash_regions(regions: &mut [Region], files: &[(String, Vec<u8>)]) -> Result<()> {
    for region in regions {
        let (_, bytes) = files
            .iter()
            .find(|(name, _)| *name == region.file)
            .with_context(|| format!("no file {}", region.file))?;
        let start = usize::try_from(region.file_offset)?;
        let end = start + usize::try_from(region.bytes)?;
        ensure!(
            end <= bytes.len(),
            "region {} exceeds its file",
            region.name
        );
        region.sha256 = sha256(&bytes[start..end]);
    }
    Ok(())
}

/// Every input's source, in manifest order.
pub(super) fn sources(inputs: &Inputs, ramdisk_source: Option<Source>) -> Vec<Source> {
    let mut sources = vec![
        source_of(&inputs.kernel_collection),
        source_of(&inputs.sptm),
        source_of(&inputs.txm),
        source_of(&inputs.device_tree),
        source_of(&inputs.static_trust_cache),
    ];
    sources.extend(
        inputs
            .sep_firmware
            .iter()
            .chain(&inputs.boot_manifest)
            .chain(&inputs.cryptex1_manifest)
            .chain(&inputs.extra_trust_caches)
            .map(source_of),
    );
    sources.extend(ramdisk_source);
    sources.extend(
        inputs
            .root_hash
            .iter()
            .filter_map(|r| r.im4p.as_ref())
            .chain(inputs.board_firmware.iter().map(|(_, image)| image))
            .map(source_of),
    );
    sources
}

/// TAG_OFFSET_EL2 as iBoot locks it on a chip with memory tagging, 0
/// elsewhere: the tag storage at the top of the managed range
/// (`stela_engine::machine::tag_storage`), which must lie above every
/// placed region.
pub(super) fn tag_offset(
    chip: Option<stela_contracts::Chip>,
    options: &Options,
    dram_end: u64,
    top_of_kernel_data: u64,
) -> Result<u64> {
    if !chip.is_some_and(|chip| stela_contracts::Feature::FEAT_MTE.on(chip)) {
        return Ok(0);
    }
    let value = tag_storage::hand_off(
        options.phys_base,
        dram_end - options.phys_base,
        options.dram_size,
    )
    .context("the tag storage's base does not fit TAG_OFFSET_EL2")?;
    ensure!(
        tag_storage::base(value) >= top_of_kernel_data,
        "the tag storage at {:#x} overlaps the regions ending at {top_of_kernel_data:#x}",
        tag_storage::base(value)
    );
    Ok(value)
}
