//! Stela's own identity page tables and fatal exception handlers, which
//! replace the firmware's once boot services end.
use core::arch::{asm, naked_asm};

pub const PAGE: usize = 4096;
const ENTRIES: usize = 512;
pub const LARGE_PAGE: usize = PAGE * ENTRIES;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
const LARGE: u64 = 1 << 7;
/// Write-through and cache-disable: PAT entry 3, uncached.
const UNCACHED: u64 = 1 << 3 | 1 << 4;
const DEVICE: u64 = PRESENT | WRITABLE | UNCACHED | NX;
pub const NX: u64 = 1 << 63;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

const CR0_MONITOR_FPU: u64 = 1 << 1;
const CR0_EMULATE_FPU: u64 = 1 << 2;
const CR0_TASK_SWITCHED: u64 = 1 << 3;
const CR0_WRITE_PROTECT: u64 = 1 << 16;
const CR4_PAE: u64 = 1 << 5;
const CR4_GLOBAL: u64 = 1 << 7;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_LA57: u64 = 1 << 12;
const CR4_PCID: u64 = 1 << 17;
const EFER_MSR: u32 = 0xc000_0080;
const EFER_NX_ENABLE: u64 = 1 << 11;
const IA32_PAT: u32 = 0x277;
/// The memory type of PAT entry 1, which a page with PWT alone selects
/// (Intel SDM vol. 3A, "Selecting a Memory Type from the PAT"). Reset makes
/// it write-through; Stela makes it write-combining for the framebuffer
/// (`tables::WRITE_COMBINING`).
const PAT_ENTRY_1: u64 = 0xff << 8;
const PAT_WRITE_COMBINING: u64 = 0x01 << 8;

type Table = [u64; ENTRIES];

/// Four-level identity tables under construction. Every nonleaf entry is
/// supervisor RW, as the runtime's frame arenas require of their path.
pub struct Tables {
    root: *mut Table,
}

fn new_table() -> Result<*mut Table, &'static str> {
    let page = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::LOADER_DATA,
        1,
    )
    .map_err(|_| "no memory for a page table")?;
    let table = page.as_ptr().cast::<Table>();
    // SAFETY: a fresh page owned by Stela for the rest of the boot.
    unsafe { table.write_bytes(0, 1) };
    Ok(table)
}

impl Tables {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self { root: new_table()? })
    }

    pub fn root(&self) -> u64 {
        self.root as u64
    }

    /// The child table under `table[index]`, created when absent.
    fn child(table: *mut Table, index: usize) -> Result<*mut Table, &'static str> {
        // SAFETY: `table` is one of this builder's live pages.
        let entry = unsafe { &mut (*table)[index] };
        if *entry & LARGE != 0 {
            return Err("2 MiB chunk mapped twice");
        }
        if *entry == 0 {
            *entry = new_table()? as u64 | PRESENT | WRITABLE;
        }
        Ok((*entry & ADDRESS) as *mut Table)
    }

    /// The page-directory entry of the 2 MiB chunk at `address`.
    fn directory_entry(&mut self, address: usize) -> Result<*mut u64, &'static str> {
        let pointers = Self::child(self.root, (address >> 39) & (ENTRIES - 1))?;
        let directory = Self::child(pointers, (address >> 30) & (ENTRIES - 1))?;
        // SAFETY: the directory is one of this builder's live pages.
        Ok(unsafe { &raw mut (*directory)[(address >> 21) & (ENTRIES - 1)] })
    }

    /// Map the 2 MiB chunk at `address` as one RW+NX page.
    pub fn large(&mut self, address: usize) -> Result<(), &'static str> {
        let entry = self.directory_entry(address)?;
        // SAFETY: a live directory entry, unused until now.
        unsafe {
            if *entry != 0 {
                return Err("2 MiB chunk mapped twice");
            }
            *entry = address as u64 | PRESENT | WRITABLE | LARGE | NX;
        }
        Ok(())
    }

    /// Give the 2 MiB chunk at `address` an empty 4 KiB page table.
    pub fn small(&mut self, address: usize) -> Result<(), &'static str> {
        let entry = self.directory_entry(address)?;
        // SAFETY: a live directory entry, unused until now.
        unsafe {
            if *entry != 0 {
                return Err("2 MiB chunk mapped twice");
            }
            *entry = new_table()? as u64 | PRESENT | WRITABLE;
        }
        Ok(())
    }

    /// Map device registers at `start..end` uncached RW+NX, with 2 MiB pages
    /// where a chunk is otherwise unmapped. RAM mappings are never changed.
    pub fn device(&mut self, start: usize, end: usize) -> Result<(), &'static str> {
        let start = start & !(PAGE - 1);
        let end = end.next_multiple_of(PAGE);
        let mut chunk = start & !(LARGE_PAGE - 1);
        while chunk < end {
            let entry = self.directory_entry(chunk)?;
            let whole = start <= chunk && chunk + LARGE_PAGE <= end;
            // SAFETY: a live directory entry of this builder.
            let current = unsafe { *entry };
            if current == 0 && whole {
                // SAFETY: as above, unused until now.
                unsafe { *entry = chunk as u64 | DEVICE | LARGE };
            } else if current & LARGE != 0 {
                if current & !ADDRESS & !LARGE != DEVICE {
                    return Err("device registers overlap mapped RAM");
                }
            } else {
                if current == 0 {
                    self.small(chunk)?;
                }
                // SAFETY: the entry now names one of this builder's tables.
                let table = unsafe { (*entry & ADDRESS) as *mut Table };
                for page in (chunk.max(start)..(chunk + LARGE_PAGE).min(end)).step_by(PAGE) {
                    // SAFETY: as above.
                    let slot = unsafe { &mut (*table)[(page >> 12) & (ENTRIES - 1)] };
                    if *slot != 0 && *slot & !ADDRESS != DEVICE {
                        return Err("device registers overlap mapped RAM");
                    }
                    *slot = page as u64 | DEVICE;
                }
            }
            chunk += LARGE_PAGE;
        }
        Ok(())
    }

    /// Map one 4 KiB page of a chunk that [`Tables::small`] prepared.
    pub fn page(&mut self, address: usize, rights: u64) -> Result<(), &'static str> {
        let entry = self.directory_entry(address)?;
        // SAFETY: the entry names one of this builder's 4 KiB tables.
        unsafe {
            if *entry & LARGE != 0 || *entry == 0 {
                return Err("page outside a 4 KiB chunk");
            }
            let table = (*entry & ADDRESS) as *mut Table;
            (*table)[(address >> 12) & (ENTRIES - 1)] = address as u64 | rights;
        }
        Ok(())
    }
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
    const MISSING: Self = Self::new(0, 0);

    const fn new(handler: usize, selector: u16) -> Self {
        Self {
            low: handler as u16,
            selector,
            ist: 0,
            attributes: if handler == 0 { 0 } else { 0x8e },
            middle: (handler >> 16) as u16,
            high: (handler >> 32) as u32,
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

/// Terminal handlers: report one letter on the UART, exit QEMU and halt. They
/// never enter Rust, allocate, take a lock or resume native code.
macro_rules! fatal_handler {
    ($name:ident, $letter:literal) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            naked_asm!(
                concat!("mov al, ", $letter),
                "mov dx, 0x3f8",
                "out dx, al",
                "mov eax, 0x12",
                "mov dx, 0xf4",
                "out dx, eax",
                "2: cli",
                "hlt",
                "jmp 2b",
            )
        }
    };
}
fatal_handler!(fatal_interrupt, "'I'");
fatal_handler!(fatal_nmi, "'N'");
fatal_handler!(fatal_page_fault, "'P'");

/// Take over the machine: fatal handlers, the controls the runtime requires
/// and the new page tables.
///
/// # Safety
/// Boot services have ended and interrupts are disabled. `tables` maps every
/// byte the code, stack and data in use touch. Nothing else runs.
pub unsafe fn activate(tables: Tables) -> Result<(), &'static str> {
    // SAFETY: the caller's contract.
    unsafe {
        take_over()?;
        asm!("mov cr3, {}", in(reg) tables.root(), options(nostack, preserves_flags));
    }
    Ok(())
}

/// Install the fatal handlers and the controls the runtime requires, still
/// under the firmware's four-level tables.
///
/// # Safety
/// Boot services have ended and interrupts are disabled; nothing else runs.
pub unsafe fn take_over() -> Result<(), &'static str> {
    let selector: u16;
    let (mut cr0, mut cr4): (u64, u64);
    let (low, high): (u32, u32);
    // SAFETY: ring 0 after boot services, with interrupts disabled.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) selector, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("rdmsr", in("ecx") EFER_MSR, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    if cr4 & CR4_LA57 != 0 {
        return Err("five-level paging firmware is unsupported");
    }
    // SAFETY: the table is image data with no other references.
    unsafe {
        let idt = &raw mut IDT;
        for gate in (*idt).iter_mut() {
            *gate = Gate::new(fatal_interrupt as *const () as usize, selector);
        }
        (*idt)[2] = Gate::new(fatal_nmi as *const () as usize, selector);
        (*idt)[14] = Gate::new(fatal_page_fault as *const () as usize, selector);
        let descriptor = Descriptor {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: idt as u64,
        };
        asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));
    }
    cr0 = (cr0 | CR0_MONITOR_FPU | CR0_WRITE_PROTECT) & !(CR0_EMULATE_FPU | CR0_TASK_SWITCHED);
    cr4 = (cr4 | CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT) & !(CR4_GLOBAL | CR4_PCID);
    let efer = (u64::from(low) | (u64::from(high) << 32)) | EFER_NX_ENABLE;
    // SAFETY: NX is enabled before tables that use it are loaded; clearing
    // PGE flushes every global firmware translation.
    unsafe {
        asm!("wrmsr", in("ecx") EFER_MSR, in("eax") efer as u32, in("edx") (efer >> 32) as u32,
            options(nostack, preserves_flags));
        asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
    }
    // Make the framebuffer write-combining whatever type the firmware's
    // MTRRs give its range: a write-combining PAT type over an uncached MTRR
    // range is write-combining (SDM vol. 3A, "Memory Type Setting for the
    // PAT and MTRRs"). Otherwise a video BAR that the firmware leaves
    // uncached takes one bus write per pixel. Every x86-64 processor has the
    // PAT. No Stela table uses PWT alone except for the framebuffer, and the
    // firmware's tables, which might, are replaced next. The caches are
    // written back on both sides of the change, as SDM vol. 3A "Programming
    // the PAT" orders.
    // SAFETY: ring 0 with interrupts disabled; IA32_PAT is architectural.
    unsafe {
        let (low, high): (u32, u32);
        asm!("rdmsr", in("ecx") IA32_PAT, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
        let pat = (u64::from(low) | u64::from(high) << 32) & !PAT_ENTRY_1 | PAT_WRITE_COMBINING;
        asm!("wbinvd", options(nostack, preserves_flags));
        asm!("wrmsr", in("ecx") IA32_PAT, in("eax") pat as u32, in("edx") (pat >> 32) as u32,
            options(nostack, preserves_flags));
        asm!("wbinvd", options(nostack, preserves_flags));
    }
    Ok(())
}
