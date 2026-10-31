//! x86 page tables, five-level under LA57 and four-level otherwise
//! (`layout::top_level`), built from any frame source. The loader uses
//! firmware pages reached by identity; the engine uses its own pool reached
//! through the physmap.
use crate::Result;
use crate::layout;
use stela_contracts::refuse;

pub const PAGE: u64 = 4096;
pub const LARGE: u64 = 2 * 1024 * 1024;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
/// A user page, which SMAP keeps supervisor data accesses out of while
/// RFLAGS.AC is clear. Every level must set it for a page to be one, so
/// intermediate entries always do and a leaf alone decides.
pub const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
/// Kept across CR3 writes while CR4.PGE is set: only for mappings every
/// root shares and nothing changes.
pub const GLOBAL: u64 = 1 << 8;
pub const NX: u64 = 1 << 63;
/// PWT and PCD: uncached, for device registers.
pub const UNCACHED: u64 = 1 << 3 | 1 << 4;
/// PWT alone: PAT entry 1, which `paging::take_over` makes write-combining,
/// for the framebuffer.
pub const WRITE_COMBINING: u64 = 1 << 3;
pub const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const ENTRIES: u64 = 512;

/// Zeroed 4 KiB table pages and a way to reach them.
pub trait Frames {
    /// The physical address of a fresh, zeroed page.
    fn frame(&mut self) -> Option<u64>;
    /// A pointer to the page-table entries at `physical`.
    fn table(&self, physical: u64) -> *mut u64;
}

pub fn index(address: u64, level: u32) -> usize {
    ((address >> (12 + 9 * level)) & (ENTRIES - 1)) as usize
}

/// The entry for `address` at `level` (0 = PT, 3 = PML4) under `root`,
/// creating tables on the way when `create`.
pub fn entry(
    frames: &mut dyn Frames,
    root: u64,
    address: u64,
    level: u32,
    create: bool,
) -> Result<Option<*mut u64>> {
    let mut table = root;
    for current in (level + 1..=layout::top_level()).rev() {
        let slot = frames.table(table).wrapping_add(index(address, current));
        // SAFETY: `table` is a live table page owned by this builder.
        let value = unsafe { slot.read_volatile() };
        if value & PRESENT == 0 {
            if !create {
                return Ok(None);
            }
            let next = frames.frame().ok_or(refuse!("no page-table frame left"))?;
            // SAFETY: as above; intermediate entries never carry NX.
            unsafe { slot.write_volatile(next | PRESENT | WRITABLE | USER) };
            table = next;
        } else if value & HUGE != 0 {
            return Err(refuse!("address already mapped by a large page"));
        } else {
            table = value & ADDRESS;
        }
    }
    Ok(Some(
        frames.table(table).wrapping_add(index(address, level)),
    ))
}

/// Map one 4 KiB page.
pub fn map_page(
    frames: &mut dyn Frames,
    root: u64,
    address: u64,
    physical: u64,
    rights: u64,
) -> Result<()> {
    let slot = entry(frames, root, address, 0, true)?.expect("created");
    // SAFETY: a live leaf slot of this builder's tables.
    unsafe { slot.write_volatile((physical & ADDRESS) | rights) };
    Ok(())
}

/// Map one 2 MiB page; both addresses are 2 MiB aligned.
pub fn map_large(
    frames: &mut dyn Frames,
    root: u64,
    address: u64,
    physical: u64,
    rights: u64,
) -> Result<()> {
    let slot = entry(frames, root, address, 1, true)?.expect("created");
    // SAFETY: a live directory slot of this builder's tables.
    unsafe {
        if slot.read_volatile() & PRESENT != 0 && slot.read_volatile() & HUGE == 0 {
            return Err(refuse!("2 MiB page over an existing table"));
        }
        slot.write_volatile((physical & ADDRESS) | rights | HUGE);
    }
    Ok(())
}

/// Map `[physical, physical + bytes)` at `address`, using 2 MiB pages
/// wherever both sides are aligned.
pub fn map_range(
    frames: &mut dyn Frames,
    root: u64,
    address: u64,
    physical: u64,
    bytes: u64,
    rights: u64,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes {
        let (va, pa) = (address + offset, physical + offset);
        if va.is_multiple_of(LARGE) && pa.is_multiple_of(LARGE) && bytes - offset >= LARGE {
            map_large(frames, root, va, pa, rights)?;
            offset += LARGE;
        } else {
            map_page(frames, root, va, pa, rights)?;
            offset += PAGE;
        }
    }
    Ok(())
}

/// Unmap `first..=last`, a canonical address range in one half: clear the
/// pages it holds, descending into every table it reaches. The tables stay
/// linked, empty where the range covers them, so a later map of the range
/// takes no new frame: clearing their entries instead would leave their
/// frames taken and unreachable until the whole pool resets. The TLB is the
/// caller's.
pub fn unmap(frames: &dyn Frames, root: u64, first: u64, last: u64) {
    clear(frames, root, layout::top_level(), first, last);
}

/// [`unmap`] the part of `first..=last` that the root entry `entry` maps,
/// which holds the range, whether or not the entry is in a root.
pub fn unmap_under(frames: &dyn Frames, entry: u64, first: u64, last: u64) {
    if entry & PRESENT != 0 && entry & HUGE == 0 {
        clear(
            frames,
            entry & ADDRESS,
            layout::top_level() - 1,
            first,
            last,
        );
    }
}

fn clear(frames: &dyn Frames, table: u64, level: u32, first: u64, last: u64) {
    let shift = 12 + 9 * level;
    // The table maps the aligned region holding the range.
    let region = first & !((1u64 << (shift + 9)) - 1);
    for slot in index(first, level)..=index(last, level) {
        let start = region | (slot as u64) << shift;
        let end = start | ((1u64 << shift) - 1);
        let entry = frames.table(table).wrapping_add(slot);
        // SAFETY: `table` is a live table page of these frames.
        let value = unsafe { entry.read_volatile() };
        if value & PRESENT == 0 {
            continue;
        }
        if level == 0 || value & HUGE != 0 {
            // SAFETY: as above.
            unsafe { entry.write_volatile(0) };
        } else {
            clear(
                frames,
                value & ADDRESS,
                level - 1,
                first.max(start),
                last.min(end),
            );
        }
    }
}
