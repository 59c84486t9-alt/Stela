//! Switch from the firmware's four-level paging to five-level paging (LA57).
//!
//! CR4.LA57 can only change while paging is off, which in turn requires
//! leaving 64-bit mode (Intel SDM Vol. 3A 4.1.2 and 9.8.5.4; AMD APM Vol. 2
//! 5.3.6). The trampoline therefore runs from a page below 4 GiB that is
//! identity-mapped in both the old and new tables: it drops to a 32-bit code
//! segment, turns paging off, sets LA57, loads the new PML5 root, turns paging
//! on and far-jumps back to 64-bit code. It touches no stack in 32-bit mode.
use core::arch::global_asm;

global_asm!(
    ".balign 16",
    ".global stela_la57_start",
    "stela_la57_start:",
    // %rdi = PML5 root, %rsi = this copy's base; both below 4 GiB.
    "push %rbx",
    "push %rbp",
    "push %r12",
    "push %r13",
    "push %r14",
    "push %r15",
    "mov %rsp, (stela_la57_rsp - stela_la57_start)(%rsi)",
    "lgdt (stela_la57_gdtr - stela_la57_start)(%rsi)",
    "mov $0x10, %ax",
    "mov %ax, %ds",
    "mov %ax, %es",
    "mov %ax, %ss",
    "lea (stela_la57_compat - stela_la57_start)(%rsi), %rax",
    "push $0x18",
    "push %rax",
    "lretq",
    ".code32",
    "stela_la57_compat:",
    "mov %cr0, %eax",
    "and $0x7fffffff, %eax",
    "mov %eax, %cr0",
    "mov %cr4, %eax",
    "or $0x1000, %eax",
    "mov %eax, %cr4",
    "mov %edi, %cr3",
    "mov %cr0, %eax",
    "or $0x80000000, %eax",
    "mov %eax, %cr0",
    "ljmp *(stela_la57_far - stela_la57_start)(%esi)",
    ".code64",
    ".global stela_la57_long",
    "stela_la57_long:",
    "mov $0x10, %ax",
    "mov %ax, %ds",
    "mov %ax, %es",
    "mov %ax, %ss",
    "mov stela_la57_rsp(%rip), %rsp",
    "pop %r15",
    "pop %r14",
    "pop %r13",
    "pop %r12",
    "pop %rbp",
    "pop %rbx",
    "ret",
    ".balign 8",
    "stela_la57_rsp: .quad 0",
    ".global stela_la57_far",
    "stela_la57_far: .long 0",
    ".word 0x08",
    ".balign 8",
    ".global stela_la57_gdt",
    "stela_la57_gdt:",
    ".quad 0",
    // 0x08: 64-bit code, 0x10: data, 0x18: 32-bit code.
    ".quad 0x00af9a000000ffff",
    ".quad 0x00cf92000000ffff",
    ".quad 0x00cf9a000000ffff",
    ".global stela_la57_gdtr",
    "stela_la57_gdtr: .word 31",
    ".quad 0",
    ".global stela_la57_end",
    "stela_la57_end:",
    options(att_syntax),
);

unsafe extern "C" {
    static stela_la57_start: u8;
    static stela_la57_long: u8;
    static stela_la57_far: u8;
    static stela_la57_gdt: u8;
    static stela_la57_gdtr: u8;
    static stela_la57_end: u8;
}

/// Bytes of trampoline code and data.
pub fn bytes() -> usize {
    // SAFETY: link-time symbols of the block above.
    unsafe { (&raw const stela_la57_end).offset_from(&raw const stela_la57_start) as usize }
}

fn offset(symbol: *const u8) -> usize {
    // SAFETY: every symbol lies inside the trampoline block.
    unsafe { symbol.offset_from(&raw const stela_la57_start) as usize }
}

/// Copy the trampoline to `page` and enter five-level paging with `root`.
///
/// # Safety
/// Interrupts are disabled and boot services have ended. `page` is a writable
/// and executable identity-mapped page below 4 GiB of at least [`bytes`]
/// bytes, and it stays identity-mapped and executable under `root`, as do the
/// current stack and code. `root` is a PML5 page below 4 GiB. CR4.PCIDE is
/// clear and EFER.NXE is set when the new tables use NX.
pub unsafe fn enable(root: u64, page: u64) {
    assert!(root < 1 << 32 && page < 1 << 32 && page + bytes() as u64 <= 1 << 32);
    // SAFETY: the caller provides the page; the source is the image's text.
    unsafe {
        let code = &raw const stela_la57_start;
        core::ptr::copy_nonoverlapping(code, page as *mut u8, bytes());
        let far = (page as usize + offset(&raw const stela_la57_far)) as *mut u32;
        far.write_unaligned((page as usize + offset(&raw const stela_la57_long)) as u32);
        let base = (page as usize + offset(&raw const stela_la57_gdtr) + 2) as *mut u64;
        base.write_unaligned(page + offset(&raw const stela_la57_gdt) as u64);
        let entry: extern "sysv64" fn(u64, u64) = core::mem::transmute(page as usize);
        entry(root, page);
    }
}
