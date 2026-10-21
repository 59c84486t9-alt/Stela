//! Owned INIT/SIPI entry, independent of firmware AP stacks and callbacks.
//! The single low page is reused only after the preceding AP has acknowledged
//! entry into permanently pinned high-window code and stopped reading it.
use core::arch::global_asm;

use super::memory_types::{Image, MAX_WRITABLE, Write, amd};
use crate::tables::PAGE;

global_asm!(
    ".balign 16",
    ".global stela_ap_start",
    "stela_ap_start:",
    ".code16",
    "cli",
    "cld",
    "mov %cs, %ax",
    "mov %ax, %ds",
    "lgdtl (stela_ap_gdtr - stela_ap_start)",
    "movl (stela_ap_base - stela_ap_start), %ebp",
    "mov %cr0, %eax",
    // Before reading shared high memory: no cache fills; INIT retains cache
    // contents, so flush them rather than assuming reset emptied the cache.
    "andl $0xdfffffff, %eax", // NW=0
    "orl $0x40000001, %eax",  // CD=1, PE=1
    "mov %eax, %cr0",
    "wbinvd",
    "ljmpl *(stela_ap_far32 - stela_ap_start)",
    ".code32",
    ".global stela_ap_protected",
    "stela_ap_protected:",
    "mov $0x10, %ax",
    "mov %ax, %ds",
    "mov %ax, %es",
    "mov %ax, %ss",
    "mov (stela_ap_cr4 - stela_ap_start)(%ebp), %eax",
    "mov %eax, %cr4",
    "mov (stela_ap_root - stela_ap_start)(%ebp), %eax",
    "mov %eax, %cr3",
    // The AP has qualified long mode/NX/PAT/FXSR/SSE before INIT. It never
    // inherits firmware PCID, CET or unqualified OS XSTATE controls.
    "mov $0xc0000080, %ecx",
    "mov $0x900, %eax", // LME | NXE; LMA is hardware-owned.
    "xor %edx, %edx",
    "wrmsr",
    // The BSP configuration is not changed. This initial, never-admitted
    // AP must match source capacity/physical width before writing any MTRR.
    "mov $0x80000008, %eax",
    "xor %ecx, %ecx",
    "cpuid",
    "cmp (stela_ap_phys_bits - stela_ap_start)(%ebp), %al",
    "jne 90f",
    "mov $0xfe, %ecx",
    "rdmsr",
    "cmp (stela_ap_mtrr_cap - stela_ap_start)(%ebp), %eax",
    "jne 90f",
    "cmp (stela_ap_mtrr_cap - stela_ap_start + 4)(%ebp), %edx",
    "jne 90f",
    // AMD's fixed attribute visibility is separate from effective routing.
    // Recheck this AP's captured identity before touching AMD64 control MSRs.
    "cmpl $0, (stela_ap_amd - stela_ap_start)(%ebp)",
    "je 6f",
    "xor %eax, %eax",
    "cpuid",
    "cmp ${amd_ebx}, %ebx", // AuthenticAMD, independently rechecked after INIT
    "jne 90f",
    "cmp ${amd_edx}, %edx",
    "jne 90f",
    "cmp ${amd_ecx}, %ecx",
    "jne 90f",
    "mov $1, %eax",
    "xor %ecx, %ecx",
    "cpuid",
    "cmp (stela_ap_signature - stela_ap_start)(%ebp), %eax",
    "jne 90f",
    "mov ${amd_syscfg}, %ecx",
    "rdmsr",
    "mov %eax, %esi",
    "xor (stela_ap_syscfg - stela_ap_start)(%ebp), %eax",
    "and ${amd_preserved}, %eax", // only MFDM visibility may differ
    "jnz 90f",
    "cmp (stela_ap_syscfg - stela_ap_start + 4)(%ebp), %edx",
    "jne 90f",
    "testl $0x100, (stela_ap_mtrr_cap - stela_ap_start)(%ebp)",
    "jz 6f", // no fixed attributes to expose without MTRRcap.FIX
    "mov %esi, %eax",
    "or ${amd_fixed_modify}, %eax", // MFDM: expose actual RdMem/WrMem for writes
    "wrmsr", // preserve every effective routing/non-memory control for now
    "6: mov $0x2ff, %ecx",
    "xor %eax, %eax",
    "xor %edx, %edx",
    "wrmsr", // disabled, UC while the complete image is installed
    "cmpl $0, (stela_ap_amd - stela_ap_start)(%ebp)",
    "jne 3f",
    "lea (stela_ap_mtrrs - stela_ap_start)(%ebp), %esi",
    "mov (stela_ap_mtrr_count - stela_ap_start)(%ebp), %edi",
    "test %edi, %edi",
    "jz 3f",
    "2: mov (%esi), %ecx",
    "wrmsr", // initialize all fields to zero, including invalid pairs
    "add ${mtrr_stride}, %esi",
    "dec %edi",
    "jnz 2b",
    "3: lea (stela_ap_mtrrs - stela_ap_start)(%ebp), %esi",
    "mov (stela_ap_mtrr_count - stela_ap_start)(%ebp), %edi",
    "test %edi, %edi",
    "jz 5f",
    "4: mov (%esi), %ecx",
    "mov 4(%esi), %eax",
    "mov 8(%esi), %edx",
    "wrmsr",
    "add ${mtrr_stride}, %esi",
    "dec %edi",
    "jnz 4b",
    "5: cmpl $0, (stela_ap_amd - stela_ap_start)(%ebp)",
    "je 7f",
    "mov ${amd_syscfg}, %ecx",
    "mov (stela_ap_syscfg - stela_ap_start)(%ebp), %eax",
    "mov (stela_ap_syscfg - stela_ap_start + 4)(%ebp), %edx",
    "wrmsr", // complete known memory controls; retain identical opaque fields
    "7: mov $0x277, %ecx",
    "mov (stela_ap_pat - stela_ap_start)(%ebp), %eax",
    "mov (stela_ap_pat - stela_ap_start + 4)(%ebp), %edx",
    "wrmsr",
    "mov $0x2ff, %ecx",
    "mov (stela_ap_mtrr_default - stela_ap_start)(%ebp), %eax",
    "mov (stela_ap_mtrr_default - stela_ap_start + 4)(%ebp), %edx",
    "wrmsr",
    "wbinvd",
    "mov %cr3, %eax",
    "mov %eax, %cr3",
    "mov $0x80010033, %eax", // PG | WP | NE | ET | MP | PE; caches enabled.
    "mov %eax, %cr0",
    "ljmp *(stela_ap_far64 - stela_ap_start)(%ebp)",
    "90: cli",
    "hlt",
    "jmp 90b",
    ".code64",
    ".global stela_ap_long",
    "stela_ap_long:",
    "mov $0x10, %ax",
    "mov %ax, %ds",
    "mov %ax, %es",
    "mov %ax, %ss",
    "xor %eax, %eax",
    "mov %ax, %fs",
    "mov %ax, %gs",
    "mov stela_ap_stack(%rip), %rsp",
    "and $-16, %rsp",
    "xor %ebp, %ebp",
    "fninit",
    "ldmxcsr stela_ap_mxcsr(%rip)",
    "mov stela_ap_argument(%rip), %rdi",
    "mov stela_ap_entry(%rip), %rax",
    "call *%rax",
    // Returning cannot authorize low-page reuse or resource reclamation.
    "1: cli",
    "hlt",
    "jmp 1b",
    ".balign 8",
    ".global stela_ap_gdt",
    "stela_ap_gdt:",
    ".quad 0",
    ".quad 0x00af9a000000ffff", // 0x08 long code
    ".quad 0x00cf92000000ffff", // 0x10 data
    ".quad 0x00cf9a000000ffff", // 0x18 protected code
    ".global stela_ap_gdtr",
    "stela_ap_gdtr: .word 31",
    ".long 0",
    ".global stela_ap_far32",
    "stela_ap_far32: .long 0",
    ".word 0x18",
    ".global stela_ap_far64",
    "stela_ap_far64: .long 0",
    ".word 0x08",
    ".balign 8",
    ".global stela_ap_base",
    "stela_ap_base: .long 0",
    ".global stela_ap_cr4",
    "stela_ap_cr4: .long 0",
    ".global stela_ap_root",
    "stela_ap_root: .long 0",
    "stela_ap_mxcsr: .long 0x1f80",
    ".global stela_ap_pat",
    "stela_ap_pat: .quad 0",
    ".global stela_ap_stack",
    "stela_ap_stack: .quad 0",
    ".global stela_ap_argument",
    "stela_ap_argument: .quad 0",
    ".global stela_ap_entry",
    "stela_ap_entry: .quad 0",
    ".balign 4",
    ".global stela_ap_phys_bits",
    "stela_ap_phys_bits: .long 0",
    ".global stela_ap_mtrr_count",
    "stela_ap_mtrr_count: .long 0",
    ".global stela_ap_mtrr_cap",
    "stela_ap_mtrr_cap: .quad 0",
    ".global stela_ap_mtrr_default",
    "stela_ap_mtrr_default: .quad 0",
    ".global stela_ap_amd",
    "stela_ap_amd: .long 0",
    ".global stela_ap_signature",
    "stela_ap_signature: .long 0",
    ".global stela_ap_syscfg",
    "stela_ap_syscfg: .quad 0",
    ".global stela_ap_mtrrs",
    "stela_ap_mtrrs: .zero {mtrr_bytes}",
    ".global stela_ap_end",
    "stela_ap_end:",
    amd_syscfg = const amd::SYSCFG,
    amd_ebx = const amd::VENDOR[0],
    amd_edx = const amd::VENDOR[1],
    amd_ecx = const amd::VENDOR[2],
    amd_fixed_modify = const amd::FIXED_MODIFY,
    amd_preserved = const !(amd::FIXED_MODIFY as u32),
    mtrr_stride = const core::mem::size_of::<Write>(),
    mtrr_bytes = const MAX_WRITABLE * core::mem::size_of::<Write>(),
    options(att_syntax),
);

unsafe extern "C" {
    static stela_ap_start: u8;
    static stela_ap_end: u8;
    static stela_ap_protected: u8;
    static stela_ap_long: u8;
    static stela_ap_gdt: u8;
    static stela_ap_gdtr: u8;
    static stela_ap_far32: u8;
    static stela_ap_far64: u8;
    static stela_ap_base: u8;
    static stela_ap_cr4: u8;
    static stela_ap_root: u8;
    static stela_ap_pat: u8;
    static stela_ap_stack: u8;
    static stela_ap_argument: u8;
    static stela_ap_entry: u8;
    static stela_ap_phys_bits: u8;
    static stela_ap_mtrr_count: u8;
    static stela_ap_mtrr_cap: u8;
    static stela_ap_mtrr_default: u8;
    static stela_ap_mtrrs: u8;
    static stela_ap_amd: u8;
    static stela_ap_signature: u8;
    static stela_ap_syscfg: u8;
}

fn offset(symbol: *const u8) -> usize {
    // SAFETY: each caller supplies a symbol inside this single assembly block.
    unsafe { symbol.offset_from(&raw const stela_ap_start) as usize }
}

pub(crate) struct Entry<'a> {
    /// Identity-mapped paging root, below 4 GiB, containing the low page and
    /// the permanently pinned high-window entry/stack/argument mappings.
    pub root: u64,
    pub five_level: bool,
    /// This selected physical AP's own immutable firmware CPUID1 EAX, not
    /// the BSP's signature or a model name selected by the ARM guest profile.
    pub processor_signature: u32,
    /// The BSP's installed PAT, qualified against each AP's memory-type state.
    pub pat: u64,
    pub memory_types: &'a Image,
    pub stack_top: u64,
    pub argument: u64,
    pub entry: unsafe extern "sysv64" fn(u64) -> !,
}

/// Copy and patch the low page without using a firmware callback or stack.
///
/// # Safety
/// `mapped` is the exclusive writable alias of one owned page at `physical`.
/// No AP is reading that page, including a timed-out prior startup. The page,
/// root, entry, stack and argument mappings remain live through AP entry and
/// recovery; the caller has qualified this AP's features and memory types.
/// The low identity alias is executable and the high stack is writable/NX.
pub(crate) unsafe fn prepare(
    mapped: *mut u8,
    physical: u64,
    entry: Entry<'_>,
) -> Result<u8, &'static str> {
    let bytes = offset(&raw const stela_ap_end);
    if !(PAGE..1 << 20).contains(&physical)
        || !physical.is_multiple_of(PAGE)
        || bytes > PAGE as usize
        || entry.memory_types.count > MAX_WRITABLE
        || entry.root == 0
        || entry.root >= 1 << 32
        || !entry.root.is_multiple_of(PAGE)
        || entry.stack_top == 0
        || entry.stack_top & 15 != 0
    {
        return Err("invalid owned AP bootstrap mappings");
    }
    // SAFETY: exclusive owned destination and immutable assembly text. All
    // patch symbols lie inside `bytes`, which fits in the supplied page.
    unsafe {
        core::ptr::copy_nonoverlapping(&raw const stela_ap_start, mapped, bytes);
        let put32 = |symbol, value: u32| {
            mapped
                .add(offset(symbol))
                .cast::<u32>()
                .write_unaligned(value)
        };
        let put64 = |symbol, value: u64| {
            mapped
                .add(offset(symbol))
                .cast::<u64>()
                .write_unaligned(value)
        };
        put32(&raw const stela_ap_base, physical as u32);
        put32(&raw const stela_ap_root, entry.root as u32);
        put32(
            &raw const stela_ap_cr4,
            0x620 | if entry.five_level { 1 << 12 } else { 0 },
        );
        put32(
            &raw const stela_ap_far32,
            (physical + offset(&raw const stela_ap_protected) as u64) as u32,
        );
        put32(
            &raw const stela_ap_far64,
            (physical + offset(&raw const stela_ap_long) as u64) as u32,
        );
        mapped
            .add(offset(&raw const stela_ap_gdtr) + 2)
            .cast::<u32>()
            .write_unaligned((physical + offset(&raw const stela_ap_gdt) as u64) as u32);
        put32(
            &raw const stela_ap_amd,
            u32::from(entry.memory_types.amd.is_some()),
        );
        put32(&raw const stela_ap_signature, entry.processor_signature);
        put64(
            &raw const stela_ap_syscfg,
            entry.memory_types.amd.map_or(0, |amd| amd.syscfg),
        );
        put32(
            &raw const stela_ap_phys_bits,
            u32::from(entry.memory_types.physical_bits),
        );
        put32(
            &raw const stela_ap_mtrr_count,
            entry.memory_types.count as u32,
        );
        put64(&raw const stela_ap_mtrr_cap, entry.memory_types.cap);
        put64(&raw const stela_ap_mtrr_default, entry.memory_types.default);
        core::ptr::copy_nonoverlapping(
            entry.memory_types.writes.as_ptr(),
            mapped
                .add(offset(&raw const stela_ap_mtrrs))
                .cast::<Write>(),
            entry.memory_types.count,
        );
        put64(&raw const stela_ap_pat, entry.pat);
        put64(&raw const stela_ap_stack, entry.stack_top);
        put64(&raw const stela_ap_argument, entry.argument);
        put64(&raw const stela_ap_entry, entry.entry as *const () as u64);
    }
    // Serializes the current core's stores before APIC sends; the AP's INIT/
    // SIPI fetch supplies its architectural startup serialization separately.
    core::arch::x86_64::__cpuid(0);
    // SAFETY: initial executor bootstrap only, before any guest/native loan;
    // caller owns the system's unchanged shared memory-type configuration.
    unsafe {
        core::arch::asm!("wbinvd", options(nostack, preserves_flags));
    }
    Ok((physical / PAGE) as u8)
}
