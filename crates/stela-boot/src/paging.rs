//! Final supervisor mappings: image RX, constants R, data/heap/stack RW+NX, and
//! initially unmapped arenas for native code and guest RAM.
use crate::multiboot::Transport;
use core::{
    arch::asm,
    ptr::{self, NonNull},
};
use stela_runtime::freestanding::BootArena;
pub const PAGE: usize = 4096;
const TABLE_ENTRIES: usize = 512;
const LARGE_PAGE: usize = PAGE * TABLE_ENTRIES;
const IMAGE_TABLES: usize = 128;
const NATIVE_BASE: usize = 0x2000_0000;
const RAM_BASE: usize = 0x2200_0000;
const NATIVE_TABLES: usize = 2;
const RAM_TABLES: usize = 8;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const NX: u64 = 1 << 63;
#[repr(C, align(4096))]
struct Table([u64; TABLE_ENTRIES]);
static mut IMAGE: [Table; IMAGE_TABLES] = [const { Table([0; TABLE_ENTRIES]) }; IMAGE_TABLES];
static mut NATIVE: [Table; NATIVE_TABLES] = [const { Table([0; TABLE_ENTRIES]) }; NATIVE_TABLES];
static mut RAM: [Table; RAM_TABLES] = [const { Table([0; TABLE_ENTRIES]) }; RAM_TABLES];
unsafe extern "C" {
    static mut stela_boot_pd: [u64; TABLE_ENTRIES];
    static stela_boot_pml4: u8;
    static __image_start: u8;
    static __text_end: u8;
    static __data_start: u8;
    static __image_end: u8;
    static stela_stack_bottom: u8;
}
pub fn image_end() -> usize {
    ptr::addr_of!(__image_end) as usize
}
pub fn native_arenas() -> [BootArena; NATIVE_TABLES] {
    core::array::from_fn(|i| BootArena {
        base: NonNull::new((NATIVE_BASE + i * LARGE_PAGE) as *mut u8).unwrap(),
        pages: TABLE_ENTRIES,
    })
}
pub fn ram_arenas() -> [BootArena; RAM_TABLES] {
    core::array::from_fn(|i| BootArena {
        base: NonNull::new((RAM_BASE + i * LARGE_PAGE) as *mut u8).unwrap(),
        pages: TABLE_ENTRIES,
    })
}
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Gate {
    low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    middle: u16,
    high: u32,
    zero: u32,
}
impl Gate {
    const MISSING: Self = Self {
        low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        middle: 0,
        high: 0,
        zero: 0,
    };
    fn fatal(address: usize) -> Self {
        Self {
            low: address as u16,
            selector: 8,
            ist: 0,
            attributes: 0x8e,
            middle: (address >> 16) as u16,
            high: (address >> 32) as u32,
            zero: 0,
        }
    }
}
#[repr(C, packed)]
struct Descriptor {
    limit: u16,
    base: u64,
}
static mut IDT: [Gate; 256] = [Gate::MISSING; 256];
unsafe extern "C" {
    fn stela_fatal_interrupt();
    fn stela_fatal_nmi();
    fn stela_fatal_page_fault();
}
pub fn fatal_interrupts() {
    // SAFETY: early BSP with IF clear. Table is boot-private permanent RAM.
    // Every handler aborts in assembly without Rust, allocation or lock entry.
    unsafe {
        let table = ptr::addr_of_mut!(IDT).cast::<Gate>();
        for i in 0..256 {
            table
                .add(i)
                .write(Gate::fatal(stela_fatal_interrupt as *const () as usize));
        }
        table
            .add(2)
            .write(Gate::fatal(stela_fatal_nmi as *const () as usize));
        table
            .add(14)
            .write(Gate::fatal(stela_fatal_page_fault as *const () as usize));
        let descriptor = Descriptor {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: table as u64,
        };
        asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));
    }
}
/// # Safety
/// One boot BSP, no external root/PTE writer/DMA/SMI/preemption/migration. The
/// trusted loader owns every static image/table/stack byte and module extent.
/// Claimed arenas must remain reserved through all original runtime owners.
pub unsafe fn install(transport: &Transport) -> Result<(), &'static str> {
    let image_start = ptr::addr_of!(__image_start) as usize;
    let text_end = ptr::addr_of!(__text_end) as usize;
    let data_start = ptr::addr_of!(__data_start) as usize;
    let end = image_end();
    if end > IMAGE_TABLES * LARGE_PAGE || !transport.normal_ram(image_start, end - image_start)? {
        return Err("linked boot image is outside actual RAM/window");
    }
    if transport.overlaps(image_start, end - image_start)? {
        return Err("trusted-loader metadata/source overlaps boot image/heap/tables");
    }
    for (start, count) in [(NATIVE_BASE, NATIVE_TABLES), (RAM_BASE, RAM_TABLES)] {
        let bytes = count * LARGE_PAGE;
        if !transport.normal_ram(start, bytes)?
            || start < end
            || transport.overlaps(start, bytes)?
        {
            return Err("reserved frame arena overlaps live resources or non-RAM");
        }
    }
    // SAFETY: actual identity mappings currently cover the complete low1GiB;
    // all static tables are exclusive boot image storage with no Rust aliases.
    unsafe {
        let directory = ptr::addr_of_mut!(stela_boot_pd).cast::<u64>();
        let tables = ptr::addr_of_mut!(IMAGE).cast::<Table>();
        let stack_guard = ptr::addr_of!(stela_stack_bottom) as usize;
        for index in 0..IMAGE_TABLES {
            let table = tables.add(index);
            for slot in 0..TABLE_ENTRIES {
                let address = index * LARGE_PAGE + slot * PAGE;
                let rights = if address == 0 || address == stack_guard {
                    0
                } else if address >= image_start && address < text_end {
                    PRESENT
                } else if address >= image_start && address < data_start {
                    PRESENT | NX
                } else {
                    PRESENT | WRITABLE | NX
                };
                ptr::addr_of_mut!((*table).0)
                    .cast::<u64>()
                    .add(slot)
                    .write(if rights == 0 {
                        0
                    } else {
                        address as u64 | rights
                    });
            }
            directory
                .add(index)
                .write(table as u64 | PRESENT | WRITABLE);
        }
        for (start, tables, count) in [
            (
                NATIVE_BASE,
                ptr::addr_of_mut!(NATIVE).cast::<Table>(),
                NATIVE_TABLES,
            ),
            (RAM_BASE, ptr::addr_of_mut!(RAM).cast::<Table>(), RAM_TABLES),
        ] {
            for index in 0..count {
                let table = tables.add(index);
                ptr::addr_of_mut!((*table).0)
                    .cast::<u64>()
                    .write_bytes(0, TABLE_ENTRIES);
                directory
                    .add(start / LARGE_PAGE + index)
                    .write(table as u64 | PRESENT | WRITABLE);
            }
        }
        // PCID/PGE were excluded by the bootstrap. Reload the SAME original
        // root to remove every bootstrap huge translation before any claim.
        asm!("mov cr3, {}", in(reg) ptr::addr_of!(stela_boot_pml4) as u64, options(nostack, preserves_flags));
    }
    Ok(())
}
