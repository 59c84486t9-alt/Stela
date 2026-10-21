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
pub const SPURIOUS_VECTOR: u8 = 0xff;
const CODE_SELECTOR: u16 = 0x08;
const DATA_SELECTOR: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x18;
const IST_BYTES: usize = 64 * 1024;

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

#[repr(C, align(16))]
struct Stack([u8; IST_BYTES]);

/// Private descriptors, interrupt stacks and GS-local record for one physical
/// host processor. These addresses stay pinned even after its executor parks.
pub(crate) struct Tables {
    local: host::local::Local,
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

// The BSP needs descriptors before its engine heap is installed. APs use their
// own separately pinned Tables; they never modify this bootstrap allocation.
static mut BSP_TABLES: Tables = Tables::new();

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

global_asm!(
    "stela_interrupt_common:",
    "push rax",
    "push rcx",
    "push rdx",
    "push rbx",
    "push rbp",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "cld",
    "mov rdi, rsp",
    "call qword ptr gs:[{handler}]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rbp",
    "pop rbx",
    "pop rdx",
    "pop rcx",
    "pop rax",
    "add rsp, 16",
    "iretq",
    handler = const host::local::HANDLER_OFFSET,
);

// One stub per vector: push a zero error code when the CPU pushes none,
// then the vector, and join the common path. The table lists them in order.
macro_rules! vectors {
    ($($vector:literal $error:ident),* $(,)?) => {
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
    64 none, 255 none,
);

unsafe extern "C" {
    static stela_vector_table: [usize; 66];
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
        for (index, &handler) in table.iter().enumerate() {
            let vector = if index == 65 { 255 } else { index };
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
    match frame.vector as u8 {
        14 => host::page_fault(frame, cr2()),
        13 | 6 => host::native_exception(frame),
        TIMER_VECTOR => host::timer_interrupt(),
        SPURIOUS_VECTOR => {}
        vector @ 32.. => host::stray_interrupt(vector),
        _ => fatal(frame),
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
