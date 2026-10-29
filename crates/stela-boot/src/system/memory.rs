//! Firmware reservations and page-table construction for the engine handoff.
use super::*;

/// The relocated engine image and the host ranges its mappings must reach.
pub(super) struct EngineImage {
    pub snapshot: Snapshot,
    pub image: firmware::Image,
    pub engine: Region,
    pub ram: Vec<(usize, usize)>,
    pub screen: Option<Framebuffer>,
    pub apic_base: u64,
    pub apic: u64,
    pub placement: Placement,
}

/// Firmware-owned allocations retained by the engine and its native workers.
pub(super) struct EngineMemory {
    pub heap: Region,
    pub native_resources: NativeResources,
    pub native_task_allocations: crate::native_smp::resources::TaskAllocations,
    pub stack: Region,
    pub code: Region,
    pub pool: Region,
    pub handoff_page: Region,
    pub trampoline: u64,
    pub root: u64,
}

/// Copy and relocate the pristine image into the selected host window.
pub(super) fn prepare_image() -> Result<EngineImage, &'static str> {
    // SAFETY: written once at entry, read here.
    let snapshot = unsafe { *PRISTINE.0.get() }.ok_or("no pristine image copy")?;
    let image = firmware::Image::loaded()?;
    if image.start != snapshot.start || image.end - image.start != snapshot.bytes {
        return Err("image layout changed after the snapshot");
    }
    let engine = allocate(snapshot.bytes as u64)?;
    // SAFETY: two distinct live allocations of `bytes`.
    unsafe {
        core::ptr::copy_nonoverlapping(
            snapshot.copy as *const u8,
            engine.physical as *mut u8,
            snapshot.bytes,
        );
    }
    let ram = firmware::ram()?;
    let screen = Framebuffer::from_firmware();
    let apic_base = crate::apic::base_msr();
    // The physmap reaches RAM, the framebuffer and the local APIC.
    let apic = apic_base & crate::apic::BASE_ADDRESS;
    let top = ram
        .iter()
        .map(|r| r.1 as u64)
        .chain(screen.iter().map(|s| (s.base + s.bytes) as u64))
        .chain(core::iter::once(apic + PAGE))
        .max()
        .unwrap_or(0);
    let placement = layout::choose(crate::cpu::LA57.present(), top)
        .ok_or("host physical addresses lie beyond what any placement's physmap reaches")?;
    layout::set(placement);
    relocate(
        engine.physical as usize,
        snapshot.bytes,
        layout::image().wrapping_sub(image.start as u64),
    )?;
    Ok(EngineImage {
        snapshot,
        image,
        engine,
        ram,
        screen,
        apic_base,
        apic,
        placement,
    })
}

/// Reserve the engine's working memory and each physical worker's resources.
pub(super) fn reserve(
    system: &System,
    cores: usize,
    ram: &[(usize, usize)],
) -> Result<EngineMemory, &'static str> {
    let sizes = Sizes::for_host(free_ram()?, cores, system.parallel);
    let heap = allocate(sizes.heap)?;
    // The engine allocator uses this existing physmap directly. Prove the
    // complete firmware reservation is covered before publishing the handoff.
    if !ram.iter().any(|&(start, end)| {
        start as u64 <= heap.physical
            && heap
                .physical
                .checked_add(heap.bytes)
                .is_some_and(|top| top <= end as u64)
    }) {
        return Err("engine heap is outside the retained RAM physmap");
    }
    let stacks = allocate(STACK_BYTES * cores as u64)?;
    let invocations = allocate(
        crate::native_smp::resources::invocation_stacks(cores)
            .map_err(|_| "invalid native invocation-stack geometry")?
            .physical_bytes(),
    )?;
    use crate::native_smp::resources::{TaskAllocations, TaskPool};
    let prototype_bytes = if system.native_mmio_check {
        if cores != 1 {
            return Err("mixed32 diagnostic requires one actual host core");
        }
        Some(
            crate::native_smp::resources::prototype_tasks(layout::prototype_task_stacks())
                .map_err(|_| "mixed32 diagnostic stack geometry overflow")?
                .raw_allocation_bytes(),
        )
    } else {
        None
    };
    let native_task_allocations = TaskAllocations::reserve(
        crate::native_smp::resources::task_stacks().physical_bytes(),
        prototype_bytes,
    )
    .map_err(|error| {
        output::arguments(format_args!("TASK MEMORY allocation failed: {error}\n"));
        "firmware task allocation unavailable"
    })?;
    let mut native_resources = NativeResources {
        cores: cores as u32,
        stacks,
        invocations,
        tasks: native_task_allocations
            .region(TaskPool::Uniform)
            .ok_or("task allocation absent")?,
        ..NativeResources::default()
    };
    // Only the existing explicit UP MMIO diagnostic requests this additional
    // plan. Production's uniform16 reservation and constructor stay separate.
    if let Some(raw) = native_task_allocations.region(TaskPool::Prototype) {
        native_resources.prototype_tasks = raw;
        native_resources.prototype_task_plan =
            crate::native_smp::resources::PrototypeTaskPlan::FirmwarePrototype32Mixed;
    }
    if cores > 1 {
        let page = boot::allocate_pages(
            AllocateType::MaxAddress(0x9f000),
            MemoryType::LOADER_CODE,
            1,
        )
        .map_err(|_| "no owned SIPI page below 1 MiB")?;
        let physical = page.as_ptr() as u64;
        if physical < PAGE {
            return Err("SIPI page overlaps real-mode vector table");
        }
        // SAFETY: the allocation is owned by Stela through every AP's lifetime.
        unsafe {
            page.as_ptr().write_bytes(0, PAGE as usize);
        }
        native_resources.sipi = physical;
    }
    let stack = Region {
        physical: native_resources.stacks.physical,
        bytes: STACK_BYTES,
    };
    let code = allocate(sizes.code)?;
    let pool = allocate(sizes.pool)?;
    crate::native_smp::resources::partition(cores, cores - 1, code.bytes, pool.bytes, false)?;
    let handoff_page = allocate(size_of::<Handoff>() as u64)?;
    let trampoline = low_page(MemoryType::LOADER_CODE)?;
    let root = low_page(MemoryType::LOADER_DATA)?;
    Ok(EngineMemory {
        heap,
        native_resources,
        native_task_allocations,
        stack,
        code,
        pool,
        handoff_page,
        trampoline,
        root,
    })
}

/// Build the identity root and shared engine window over those reservations.
pub(super) fn map(
    image: &EngineImage,
    memory: &mut EngineMemory,
    runtime: &Runtime,
    storage: Option<&stela_drivers::Handoff>,
    native_mmio: Option<&crate::native_mmio::Prepared>,
    host_firmware: &crate::host_firmware::Resources,
) -> Result<Storage, &'static str> {
    let EngineImage {
        snapshot,
        image,
        engine,
        ram,
        screen,
        apic,
        ..
    } = image;
    let EngineMemory {
        native_resources,
        code,
        trampoline,
        root,
        ..
    } = memory;
    let (root, trampoline, apic) = (*root, *trampoline, *apic);
    let cores = native_resources.cores as usize;
    let mut frames = FirmwareFrames;
    let mut image_rights: Vec<(u64, u64, u64)> = image
        .sections
        .iter()
        .map(|&(start, end, rights)| (start as u64, end as u64, rights))
        .chain(core::iter::once((trampoline, trampoline + PAGE, PRESENT)))
        .chain(runtime.code())
        .collect();
    if native_resources.sipi != 0 {
        image_rights.push((native_resources.sipi, native_resources.sipi + PAGE, PRESENT));
    }
    identity(&mut frames, root, ram, &image_rights)?;
    if let Some(storage) = storage {
        map_devices(&mut frames, root, ram, &storage.mapped)?;
    }
    let mapped = storage
        .as_ref()
        .map_or(&[][..], |storage| &storage.mapped[..]);
    runtime.map(&mut frames, root, ram, mapped)?;
    let mut storage = match storage {
        Some(storage) => Storage::new(storage)?,
        None => Storage::absent(),
    };
    storage.wifi_platform = host_firmware.wifi_observations();
    // The framebuffer is written, never read back, so its writes combine.
    let video = PRESENT | WRITABLE | NX | WRITE_COMBINING;
    if let Some(screen) = screen {
        let start = screen.base as u64 & !(PAGE - 1);
        let end = (screen.base + screen.bytes) as u64;
        tables::map_range(
            &mut frames,
            root,
            start,
            start,
            end.next_multiple_of(PAGE) - start,
            video,
        )?;
    }
    // The window: the engine image with section rights, heap, stack, code.
    for page in (0..snapshot.bytes as u64).step_by(PAGE as usize) {
        let rights = image.rights(image.start + page as usize);
        tables::map_page(
            &mut frames,
            root,
            layout::image() + page,
            engine.physical + page,
            rights,
        )?;
    }
    let data = PRESENT | WRITABLE | NX;
    for slot in 0..cores {
        tables::map_range(
            &mut frames,
            root,
            layout::stack() + slot as u64 * STACK_STRIDE + PAGE,
            native_resources.stacks.physical + slot as u64 * STACK_BYTES,
            STACK_BYTES,
            data,
        )?;
    }
    // These real LoaderData allocations outlive every root and continuation.
    // Map usable pages only; both guard pages of each slot remain absent.
    // This happens before AP/root clones and grants no execution capability.
    for (base, region, geometry) in [
        (
            layout::invocation_stacks(),
            native_resources.invocations,
            crate::native_smp::resources::invocation_stacks(cores)
                .map_err(|_| "invalid native invocation-stack geometry")?,
        ),
        (
            layout::task_stacks(),
            native_resources.tasks,
            crate::native_smp::resources::task_stacks(),
        ),
    ] {
        for index in 0..geometry.count() {
            let slot = geometry
                .slot(base, index)
                .map_err(|_| "guarded stack virtual range overflow")?;
            tables::map_range(
                &mut frames,
                root,
                slot.usable.start,
                region.physical
                    + geometry
                        .physical_offset(index)
                        .map_err(|_| "guarded stack physical offset overflow")?,
                slot.usable.end - slot.usable.start,
                data,
            )?;
        }
    }
    if native_resources.prototype_task_plan
        == crate::native_smp::resources::PrototypeTaskPlan::FirmwarePrototype32Mixed
    {
        let geometry =
            crate::native_smp::resources::prototype_tasks(layout::prototype_task_stacks())
                .map_err(|_| "mixed32 diagnostic virtual range overflow")?;
        let raw = native_resources.prototype_tasks;
        let end = raw
            .physical
            .checked_add(raw.bytes)
            .ok_or("mixed32 raw reservation wraps")?;
        if raw.bytes != geometry.raw_allocation_bytes() {
            return Err("mixed32 raw reservation size changed");
        }
        for index in 0..geometry.count() {
            let slot = geometry.slot(index).map_err(|_| "mixed32 slot overflow")?;
            let backing = geometry
                .backing(raw.physical..end, index)
                .map_err(|_| "mixed32 backing alignment overflow")?;
            tables::map_range(
                &mut frames,
                root,
                slot.usable.start,
                backing.start,
                backing.end - backing.start,
                data,
            )?;
        }
    }
    tables::map_range(
        &mut frames,
        root,
        layout::code(),
        code.physical,
        code.bytes,
        PRESENT,
    )?;
    // The physmap: all RAM, the framebuffer and the local APIC.
    for &(start, end) in ram {
        let (start, end) = (start as u64, end as u64);
        tables::map_range(
            &mut frames,
            root,
            layout::physical(start),
            start,
            end - start,
            data,
        )?;
    }
    if let Some(screen) = screen {
        let start = screen.base as u64 & !(PAGE - 1);
        let end = ((screen.base + screen.bytes) as u64).next_multiple_of(PAGE);
        if !ram.iter().any(|r| r.0 as u64 <= start && end <= r.1 as u64) {
            tables::map_range(
                &mut frames,
                root,
                layout::physical(start),
                start,
                end - start,
                video,
            )?;
        }
    }
    // The xAPIC page must be strong uncacheable (Intel SDM Vol. 3A 11.4.1);
    // the entry says so rather than relying on the firmware's MTRRs.
    if !ram.iter().any(|r| r.0 as u64 <= apic && apic < r.1 as u64) {
        tables::map_page(
            &mut frames,
            root,
            layout::physical(apic),
            apic,
            data | UNCACHED,
        )?;
    }
    // The bounce slot's leaf entries, which the translation helper points
    // at guest frames; until then they map a scratch page.
    for slot in 0..cores {
        for index in 0..2 {
            let scratch = allocate(PAGE)?.physical;
            let address = layout::bounce() + (slot * 2 + index) as u64 * PAGE;
            tables::map_page(&mut frames, root, address, scratch, data)?;
            let entry = tables::entry(&mut frames, root, address, 0, false)?;
            native_resources.bounce[slot][index] = entry.ok_or("bounce slot unmapped")? as u64;
        }
    }

    if let Some(prepared) = native_mmio {
        prepared.aperture(&mut frames, root, cores)?;
    }

    Ok(storage)
}
