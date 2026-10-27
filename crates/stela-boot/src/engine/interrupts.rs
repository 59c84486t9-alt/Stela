//! The engine's GDT, TSS and IDT, all in the window.
//!
//! Every vector runs on an interrupt stack (IST), never on the interrupted
//! stack, so native code may use any stack space below its RSP. Faults raised
//! by native code go to the host's fault handler; host interrupts set a flag;
//! anything else is fatal with its x86 detail. The host check
//! (`crate::host_check`) installs the same tables with its own handler.
use super::host;
use crate::output;
use core::arch::{asm, global_asm};

pub const TIMER_VECTOR: u8 = 0x40;
/// Native worker doorbell; host-device IRQs own 0x50..=0x5f.
pub(crate) const NATIVE_WAKE_VECTOR: u8 = 0x60;
pub const SPURIOUS_VECTOR: u8 = 0xff;
const CODE_SELECTOR: u16 = 0x08;
const DATA_SELECTOR: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x18;
const IST_BYTES: usize = 64 * 1024;
// Explicit space retained below the largest entry image for the baseline Rust
// handler. Runtime/disassembly stack-budget validation remains a required gate.
const HANDLER_STACK_BYTES: usize = 32 * 1024;

/// The registers an interrupt stub saves, then the CPU's frame.
#[repr(C)]
#[derive(Debug)]
pub struct Frame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C, packed)]
struct TaskState {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map: u16,
}

#[repr(C, align(64))]
struct Stack([u8; IST_BYTES]);

/// Private descriptors, interrupt stacks and GS-local record for one physical
/// host processor. These addresses stay pinned even after its executor parks.
pub(crate) struct Tables {
    local: host::local::Local,
    xstate: Option<super::xstate::XstateOwner>,
    tss: TaskState,
    gdt: [u64; 5],
    idt: [[u64; 2]; 256],
    fault_stack: Stack,
    fatal_stack: Stack,
}

impl Tables {
    pub(crate) const fn new() -> Self {
        Self {
            local: host::local::Local::new(),
            xstate: None,
            tss: TaskState {
                reserved0: 0,
                rsp: [0; 3],
                reserved1: 0,
                ist: [0; 7],
                reserved2: 0,
                reserved3: 0,
                io_map: size_of::<TaskState>() as u16,
            },
            gdt: [0, 0x00af_9a00_0000_ffff, 0x00cf_9200_0000_ffff, 0, 0],
            idt: [[0; 2]; 256],
            fault_stack: Stack([0; IST_BYTES]),
            fatal_stack: Stack([0; IST_BYTES]),
        }
    }
}

impl Tables {
    pub(crate) fn matches(&self, observed: Observation) -> bool {
        observed.gdt == &raw const self.gdt as u64
            && observed.idt == &raw const self.idt as u64
            && observed.gs == &raw const self.local as u64
            && observed.task == TSS_SELECTOR
    }
}

// The BSP needs descriptors before its engine heap is installed. APs use their
// own separately pinned Tables; they never modify this bootstrap allocation.
static mut BSP_TABLES: Tables = Tables::new();

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

// The real GPR/CPU Frame remains unchanged. Each entry image lives below it
// on that actual retained IST; ordinary and terminal vectors use distinct
// allocations. Returning nested ordinary entries are explicitly refused.
global_asm!(
    r#"
stela_interrupt_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    mov rbx, rsp
    xor r10d, r10d
    mov rax, [rbx + {vector}]
    cmp rax, 2
    je stela_xstate_terminal_slot
    cmp rax, 8
    je stela_xstate_terminal_slot
    cmp rax, 18
    jne stela_xstate_slot
stela_xstate_terminal_slot:
    mov r10d, 8
stela_xstate_slot:
    cmp qword ptr gs:[r10 + {active}], 0
    jne stela_xstate_refuse
    mov qword ptr gs:[r10 + {active}], 1
    mov r11, gs:[{image_bytes}]
    cmp r11, 512
    jb stela_xstate_refuse
    cmp r11, {max_image_bytes}
    ja stela_xstate_refuse
    sub rsp, r11
    sub rsp, {metadata_bytes}
    and rsp, -64

    // No Rust or FP/SIMD instruction precedes this save. The controls are
    // those configuration qualified (`EntryAbi::extended`).
    cmp qword ptr gs:[{extended}], 0
    jne stela_xstate_save_extended
    mov qword ptr [rsp + r11 + {format}], {fxsave}
    mov qword ptr [rsp + r11 + {mask}], 0
    fxsave64 [rsp]
    jmp stela_xstate_saved
stela_xstate_save_extended:
    cmp qword ptr gs:[{available}], 1
    jne stela_xstate_refuse
    xor ecx, ecx
    xgetbv
    mov r9d, eax
    shl rdx, 32
    or r9, rdx
    test r9, 1
    jz stela_xstate_refuse
    mov rax, gs:[{supported_mask}]
    not rax
    test r9, rax
    jnz stela_xstate_refuse
    mov rax, {refused_mask}
    test r9, rax
    jnz stela_xstate_refuse
    mov [rsp + r11 + {mask}], r9
    mov qword ptr [rsp + r11 + {format}], {xsave}
    test r9, 2
    jnz stela_xstate_header
    // XCR0.SSE does not gate legacy SSE execution. XSAVE(mask1) leaves
    // XMM/MXCSR untouched in this compatible legacy area; retain them first.
    fxsave64 [rsp]
    mov qword ptr [rsp + r11 + {format}], {xsave_legacy}
stela_xstate_header:
    // Standard XSAVE does not initialize XCOMP_BV/reserved header fields.
    xor eax, eax
    mov [rsp + {header} + 0], rax
    mov [rsp + {header} + 8], rax
    mov [rsp + {header} + 16], rax
    mov [rsp + {header} + 24], rax
    mov [rsp + {header} + 32], rax
    mov [rsp + {header} + 40], rax
    mov [rsp + {header} + 48], rax
    mov [rsp + {header} + 56], rax
    mov rax, r9
    mov rdx, r9
    shr rdx, 32
    xsave64 [rsp]
stela_xstate_saved:
    fninit
    ldmxcsr [rip + stela_interrupt_mxcsr]
    mov rdi, rbx
    mov rax, [rbx + {vector}]
    cmp rax, 2
    je stela_xstate_terminal
    cmp rax, 8
    je stela_xstate_terminal
    cmp rax, 18
    je stela_xstate_terminal
    call qword ptr gs:[{handler}]

    // The handler may not change the state contract underneath an
    // outstanding image. Refuse before partial restoration if XCR0 changed.
    mov r11, gs:[{image_bytes}]
    cmp qword ptr [rsp + r11 + {format}], {fxsave}
    je stela_xstate_restore_legacy
    cmp qword ptr gs:[{extended}], 0
    je stela_xstate_refuse
    xor ecx, ecx
    xgetbv
    mov r9d, eax
    shl rdx, 32
    or r9, rdx
    cmp r9, [rsp + r11 + {mask}]
    jne stela_xstate_refuse
    cmp qword ptr [rsp + r11 + {format}], {xsave}
    je stela_xstate_check_sse_tag
    cmp qword ptr [rsp + r11 + {format}], {xsave_legacy}
    jne stela_xstate_refuse
    test r9, 2
    jnz stela_xstate_refuse
    jmp stela_xstate_restore_extended
stela_xstate_check_sse_tag:
    test r9, 2
    jz stela_xstate_refuse
stela_xstate_restore_extended:
    mov rax, r9
    mov rdx, r9
    shr rdx, 32
    xrstor64 [rsp]
    cmp qword ptr [rsp + r11 + {format}], {xsave_legacy}
    jne stela_xstate_restored
    fxrstor64 [rsp]
    jmp stela_xstate_restored
stela_xstate_restore_legacy:
    cmp qword ptr gs:[{extended}], 0
    jne stela_xstate_refuse
    fxrstor64 [rsp]
stela_xstate_restored:
    mov qword ptr gs:[{active}], 0
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq
stela_xstate_terminal:
    call {terminal_handler}
stela_xstate_refuse:
    // No FP-using Rust callback is safe before a complete save. This is a
    // terminal contract violation, never a degraded or partially saved return.
    cli
stela_xstate_halt:
    hlt
    jmp stela_xstate_halt
.section .rdata
.balign 4
stela_interrupt_mxcsr:
    .long 0x1f80
.text
"#,
    vector = const core::mem::offset_of!(Frame, vector),
    metadata_bytes = const super::xstate::ENTRY_METADATA_BYTES,
    header = const super::xstate::STANDARD_HEADER_OFFSET,
    format = const super::xstate::ENTRY_FORMAT_OFFSET,
    mask = const super::xstate::ENTRY_MASK_OFFSET,
    fxsave = const super::xstate::FORMAT_FXSAVE,
    xsave = const super::xstate::FORMAT_XSAVE,
    xsave_legacy = const super::xstate::FORMAT_XSAVE_LEGACY_SSE,
    max_image_bytes = const super::xstate::MAX_IMAGE_BYTES,
    refused_mask = const !super::xstate::ADMITTED_MASK,
    image_bytes = const host::local::XSTATE_IMAGE_BYTES_OFFSET,
    supported_mask = const host::local::XSTATE_SUPPORTED_MASK_OFFSET,
    available = const host::local::XSTATE_AVAILABLE_OFFSET,
    extended = const host::local::XSTATE_EXTENDED_OFFSET,
    active = const host::local::XSTATE_ACTIVE_OFFSET,
    handler = const host::local::HANDLER_OFFSET,
    terminal_handler = sym terminal_interrupt,
);

// Separate terminal IST resources are retained for NMI/DF/MCE. They cannot
// return through an interrupted transition or overwrite a normal entry image.
extern "sysv64" fn terminal_interrupt(frame: &Frame) -> ! {
    fatal(frame)
}

// One stub per vector: push a zero error code when the CPU pushes none,
// then the vector, and join the common path. The table lists them in order.
macro_rules! vectors {
    ($($vector:literal $error:ident),* $(,)?) => {
        const VECTOR_NUMBERS: &[usize] = &[$($vector),*];
        global_asm!(
            $(
                concat!(".global stela_vector_", stringify!($vector)),
                concat!("stela_vector_", stringify!($vector), ":"),
                vectors!(@error $error),
                concat!("push ", stringify!($vector)),
                "jmp stela_interrupt_common",
            )*
            ".section .rdata",
            ".balign 8",
            ".global stela_vector_table",
            "stela_vector_table:",
            $(concat!(".quad stela_vector_", stringify!($vector)),)*
            ".text",
        );
    };
    (@error code) => { "" };
    (@error none) => { "push 0" };
}

vectors!(
    0 none, 1 none, 2 none, 3 none, 4 none, 5 none, 6 none, 7 none,
    8 code, 9 none, 10 code, 11 code, 12 code, 13 code, 14 code, 15 none,
    16 none, 17 code, 18 none, 19 none, 20 none, 21 code, 22 none, 23 none,
    24 none, 25 none, 26 none, 27 none, 28 none, 29 code, 30 code, 31 none,
    32 none, 33 none, 34 none, 35 none, 36 none, 37 none, 38 none, 39 none,
    40 none, 41 none, 42 none, 43 none, 44 none, 45 none, 46 none, 47 none,
    48 none, 49 none, 50 none, 51 none, 52 none, 53 none, 54 none, 55 none,
    56 none, 57 none, 58 none, 59 none, 60 none, 61 none, 62 none, 63 none,
    64 none,
    80 none, 81 none, 82 none, 83 none, 84 none, 85 none, 86 none, 87 none,
    88 none, 89 none, 90 none, 91 none, 92 none, 93 none, 94 none, 95 none,
    96 none, 255 none,
);

unsafe extern "C" {
    static stela_vector_table: [usize; VECTOR_NUMBERS.len()];
}

fn gate(handler: usize, ist: u8) -> [u64; 2] {
    let handler = handler as u64;
    let low = (handler & 0xffff)
        | (u64::from(CODE_SELECTOR) << 16)
        | (u64::from(ist) << 32)
        | (0x8e << 40)
        | ((handler >> 16) & 0xffff) << 48;
    [low, handler >> 32]
}

/// Load the GDT, TSS and IDT, with every vector going to `handler`. Runs
/// first in the engine phase, with the engine's [`interrupt`].
///
/// # Safety
/// Interrupts are disabled and nothing else uses the descriptor tables.
pub unsafe fn install(handler: extern "sysv64" fn(&mut Frame)) {
    let tables = &raw mut BSP_TABLES;
    // SAFETY: only the BSP installs its permanent static tables, once.
    unsafe { install_on(&mut *tables, handler) };
}

/// Install the descriptor/IST/local storage of this host processor.
///
/// # Safety
/// `tables` belongs exclusively to this processor and stays pinned and mapped
/// for its whole lifetime, including its parked state. Interrupts are disabled;
/// no native execution/handler can still refer to preceding tables or GS state.
pub(crate) unsafe fn install_on(
    tables: &'static mut Tables,
    handler: extern "sysv64" fn(&mut Frame),
) {
    if tables.xstate.is_some() {
        output::fatal("native xstate descriptor owner cannot be reinstalled");
    }
    // SAFETY: install_on owns this actual CPU and permanently pinned Tables,
    // including both distinct IST arrays, before HostOwner or AP READY.
    let owner = unsafe { super::xstate::XstateOwner::capture() }.unwrap_or_else(|error| {
        output::arguments(format_args!("native xstate entry refused: {error:?}\n"));
        output::fatal("native IRQ state contract unavailable")
    });
    for stack in [&tables.fault_stack, &tables.fatal_stack] {
        let bottom = &raw const stack.0 as usize;
        let top = bottom + IST_BYTES;
        let frame = top - size_of::<Frame>();
        if owner
            .check_entry_extent(frame, bottom + HANDLER_STACK_BYTES, top)
            .is_err()
        {
            output::fatal("native IST cannot retain full xstate image and handler budget");
        }
    }
    // SAFETY: the configured ABI is inseparable from this actual retained
    // owner and the real private stacks. No controls or feature flags change.
    unsafe { host::local::configure_xstate(&mut tables.local, &owner) }
        .unwrap_or_else(|_| output::fatal("native xstate local configuration refused"));
    tables.xstate = Some(owner);
    // SAFETY: all data here is private to this physical processor.
    unsafe {
        let tss = &raw mut tables.tss;
        (*tss).ist[0] = (&raw mut tables.fault_stack as u64) + IST_BYTES as u64;
        (*tss).ist[1] = (&raw mut tables.fatal_stack as u64) + IST_BYTES as u64;
        let base = tss as u64;
        let limit = (size_of::<TaskState>() - 1) as u64;
        let gdt = &raw mut tables.gdt;
        (*gdt)[3] = (limit & 0xffff)
            | ((base & 0xff_ffff) << 16)
            | (0x89 << 40)
            | (((base >> 24) & 0xff) << 56);
        (*gdt)[4] = base >> 32;
        let pointer = Pointer {
            limit: (size_of::<[u64; 5]>() - 1) as u16,
            base: gdt as u64,
        };
        asm!(
            "lgdt [{pointer}]",
            "push {code}",
            "lea {scratch}, [rip + 2f]",
            "push {scratch}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov ss, {data:x}",
            "mov fs, {data:x}",
            "mov gs, {data:x}",
            "ltr {tss:x}",
            pointer = in(reg) &pointer,
            code = in(reg) u64::from(CODE_SELECTOR),
            scratch = out(reg) _,
            data = in(reg) DATA_SELECTOR,
            tss = in(reg) TSS_SELECTOR,
        );
        // Loading a GS selector above resets its base; establish the private
        // CPL0 record after GDT/segment setup, before making our IDT active.
        host::local::activate(&mut tables.local, handler);
        let idt = &raw mut tables.idt;
        let table = &stela_vector_table;
        for (&vector, &handler) in VECTOR_NUMBERS.iter().zip(table) {
            // Double fault, NMI and machine check use their own stack.
            let ist = if matches!(vector, 2 | 8 | 18) { 2 } else { 1 };
            (*idt)[vector] = gate(handler, ist);
        }
        let pointer = Pointer {
            limit: (size_of::<[[u64; 2]; 256]>() - 1) as u16,
            base: idt as u64,
        };
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
}

fn cr2() -> u64 {
    let value;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

pub extern "sysv64" fn interrupt(frame: &mut Frame) {
    if crate::native_irq::dispatch(frame.vector as u8) {
        return;
    }
    match frame.vector as u8 {
        14 => host::page_fault(frame, cr2()),
        13 | 6 => host::native_exception(frame),
        TIMER_VECTOR => host::timer_interrupt(),
        NATIVE_WAKE_VECTOR => host::wake_interrupt(),
        SPURIOUS_VECTOR => {}
        vector @ 32.. => host::stray_interrupt(vector),
        _ => fatal(frame),
    }
}

/// Actual processor-local descriptor/control observations, for validating the
/// owned AP startup path. These numbers do not grant a native frame lease.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Observation {
    pub rsp: u64,
    pub gdt: u64,
    pub idt: u64,
    pub task: u16,
    pub gs: u64,
}

/// # Safety
/// CPL0 with this processor's permanently pinned descriptor/GS storage active.
/// The private tables cannot be changed concurrently with these observations.
pub(crate) unsafe fn observe() -> Observation {
    let mut gdt = Pointer { limit: 0, base: 0 };
    let mut idt = Pointer { limit: 0, base: 0 };
    let (rsp, task): (u64, u16);
    let (low, high): (u32, u32);
    // SAFETY: caller is the owning CPL0 processor with stable private tables.
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut gdt, options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) &mut idt, options(nostack, preserves_flags));
        asm!("str {0:x}", out(reg) task, options(nostack, preserves_flags));
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        asm!("rdmsr", in("ecx") 0xc000_0101u32, out("eax") low, out("edx") high,
            options(nostack, preserves_flags));
    }
    Observation {
        rsp,
        gdt: gdt.base,
        idt: idt.base,
        task,
        gs: u64::from(low) | u64::from(high) << 32,
    }
}

/// Report an x86 exception that is a Stela failure, never a guest event.
pub fn fatal(frame: &Frame) -> ! {
    report(frame);
    output::fatal("unexpected x86 exception in the system engine")
}

/// Print an x86 exception's detail.
pub fn report(frame: &Frame) {
    output::arguments(format_args!(
        "x86 exception vector={} error={:#x} rip={:#x} rsp={:#x} cr2={:#x} rflags={:#x}\n",
        frame.vector,
        frame.error,
        frame.rip,
        frame.rsp,
        cr2(),
        frame.rflags
    ));
}
