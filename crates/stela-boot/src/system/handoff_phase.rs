//! Boot files, final memory-map inventory and the engine transfer.
use super::*;
use crate::Result;
use stela_contracts::refuse;

pub(super) struct RetainedFiles {
    pub options: Region,
    pub source: Region,
    pub files: [File; MAX_FILES],
    pub file_count: usize,
}

/// Keep loader input allocations for engine reads through the physmap.
pub(super) fn retain_files(
    options: Vec<u8>,
    source: Vec<u8>,
    bundle: BundleFiles,
) -> Result<RetainedFiles> {
    let options_region = Region {
        physical: options.as_ptr() as u64,
        bytes: options.len() as u64,
    };
    let source_region = Region {
        physical: source.as_ptr() as u64,
        bytes: source.len() as u64,
    };
    let mut files = [File::default(); MAX_FILES];
    for (slot, (name, contents)) in files.iter_mut().zip(&bundle) {
        if name.len() > MAX_NAME {
            return Err(refuse!("bundle file name too long"));
        }
        slot.name[..name.len()].copy_from_slice(name.as_bytes());
        slot.name_bytes = name.len();
        slot.contents = *contents;
    }
    let file_count = bundle.len();
    // All stay allocated: the engine reads them through the physmap.
    core::mem::forget(options);
    core::mem::forget(source);
    core::mem::forget(bundle);
    Ok(RetainedFiles {
        options: options_region,
        source: source_region,
        files,
        file_count,
    })
}

pub(super) struct GuestMemory {
    pub ranges: [Region; MAX_GUEST_RANGES],
    pub count: usize,
    pub installed: u64,
}

/// Collect guest candidates from the final firmware map in entry order.
pub(super) fn guest_memory(map: &impl MemoryMap) -> GuestMemory {
    let mut guest = [Region::default(); MAX_GUEST_RANGES];
    let mut count = 0;
    let mut installed = 0;
    for entry in map.entries() {
        if is_ram(entry.ty) {
            installed += entry.page_count * PAGE;
        }
        if !matches!(
            entry.ty,
            MemoryType::CONVENTIONAL
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA
        ) {
            continue;
        }
        let start = entry.phys_start.next_multiple_of(LARGE);
        let end = (entry.phys_start + entry.page_count * PAGE) & !(LARGE - 1);
        if end <= start || count == MAX_GUEST_RANGES {
            continue;
        }
        // Adjacent firmware entries merge into one range.
        if count > 0 && guest[count - 1].physical + guest[count - 1].bytes == start {
            guest[count - 1].bytes += end - start;
        } else {
            guest[count] = Region {
                physical: start,
                bytes: end - start,
            };
            count += 1;
        }
    }
    GuestMemory {
        ranges: guest,
        count,
        installed,
    }
}

/// The live root, stack window and entry that receive the completed handoff.
pub(super) struct Transfer {
    pub placement: Placement,
    pub root: u64,
    pub trampoline: u64,
    pub engine_entry: u64,
    pub handoff: *mut Handoff,
}

impl Transfer {
    /// # Safety
    /// Boot services have ended. `root` maps this code and the trampoline,
    /// and the engine's image, stack, handoff and shared physmap.
    pub(super) unsafe fn enter(self) -> Result<core::convert::Infallible> {
        let Self {
            placement,
            root,
            trampoline,
            engine_entry,
            handoff,
        } = self;
        // SAFETY: the caller supplied live identity and engine-window mappings.
        unsafe {
            asm!("cli", options(nomem, nostack));
            paging::take_over()?;
            match placement {
                Placement::FiveLevel => la57::enable(root, trampoline),
                Placement::FourLevel { .. } => {
                    asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags))
                }
            }
            asm!(
                "mov rsp, {stack}",
                "call {entry}",
                "ud2",
                stack = in(reg) layout::stack() + PAGE + STACK_BYTES,
                entry = in(reg) engine_entry,
                in("rdi") layout::physical(handoff as u64),
                options(noreturn),
            )
        }
    }
}
