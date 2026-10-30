//! Processor idle, as Linux's ACPI processor idle driver enters `_CST`
//! states: each CPU waits for an interrupt in the deepest state its
//! firmware declares and its own CPUID admits whose target residency fits
//! the wait. A CPU without a declaration halts.
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{
    arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count},
    },
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};
use stela_drivers::platform::acpi::processor::{
    self, Admitted, CState, Cpu, CstError, Declaration, Declared, Enter, Handshake,
};

/// CPUID.01H:ECX[3], MONITOR/MWAIT.
const MWAIT: u32 = 1 << 3;
/// CPUID.06H:EAX[2], the always-running APIC timer.
const ARAT: u32 = 1 << 2;
/// CPUID.80000007H:EDX[8], the invariant TSC.
const INVARIANT_TSC: u32 = 1 << 8;

/// A declared processor and the states it admitted, which the CPU itself
/// publishes on its first wait.
struct Processor {
    apic: u32,
    declared: Vec<CState>,
    admission: AtomicPtr<Admission>,
}

struct Admission {
    states: Vec<Admitted>,
    /// `X86_BUG_CLFLUSH_MONITOR`: the monitored line is flushed before
    /// MONITOR arms it.
    flush_monitor: bool,
}

/// The declared processors by APIC ID, published once by [`install`].
static PROCESSORS: AtomicPtr<Vec<Processor>> = AtomicPtr::new(ptr::null_mut());

/// The line MONITOR arms. Nothing writes it, so only interrupts end a wait.
#[repr(align(64))]
struct Line([u8; 64]);
static LINE: Line = Line([0; 64]);

/// The processor capabilities to declare to the firmware, from the
/// bootstrap processor's CPUID as Linux reads `cpu_data(0)`.
pub(crate) fn capabilities() -> u32 {
    processor::capabilities(__cpuid(1).ecx & MWAIT != 0)
}

/// Install the firmware's idle declaration, or report why idle halts.
/// This processor's states, and each one it leaves out, are reported.
pub(crate) fn install(declaration: Option<Declaration>) {
    let Some(declaration) = declaration else {
        crate::output::arguments(format_args!(
            "HOST IDLE: no ACPI processor declaration; processors halt\n"
        ));
        return;
    };
    let capabilities = capabilities();
    match declaration.handshake {
        Handshake::Osc => crate::output::arguments(format_args!(
            "HOST IDLE processor capabilities {capabilities:#x} accepted by _OSC\n"
        )),
        Handshake::Pdc {
            accepted: 0,
            present,
        } => crate::output::arguments(format_args!(
            "HOST IDLE: none of {} has _OSC or _PDC for capabilities {capabilities:#x}\n",
            count(present)
        )),
        Handshake::Pdc { accepted, present } => crate::output::arguments(format_args!(
            "HOST IDLE processor capabilities {capabilities:#x} declared by _PDC to {accepted} of {}\n",
            count(present)
        )),
    }
    let mut processors = Vec::new();
    let (mut absent, mut refused) = (0, Vec::new());
    for Declared { apic, cst } in declaration.processors {
        match cst {
            Some(Ok(declared)) => processors.push(Processor {
                apic,
                declared,
                admission: AtomicPtr::new(ptr::null_mut()),
            }),
            Some(Err(error)) => refused.push((apic, error)),
            None => absent += 1,
        }
    }
    if absent != 0 {
        crate::output::arguments(format_args!(
            "HOST IDLE: {} without _CST halt; FADT I/O C-states are not entered\n",
            count(absent)
        ));
    }
    for (apic, error) in refused {
        let reason = match error {
            CstError::Invalid => "not a package of states",
            CstError::Inconsistent => "its count disagrees with its states",
        };
        crate::output::arguments(format_args!(
            "HOST IDLE APIC {apic:#x}: _CST refused, {reason}; it halts\n"
        ));
    }
    processors.sort_by_key(|processor| processor.apic);
    let apic = apic_id();
    if let Ok(index) = processors.binary_search_by_key(&apic, |processor| processor.apic) {
        let (admitted, refused) = processor::admit(&processors[index].declared, &cpu());
        let states: Vec<String> = admitted.iter().map(describe).collect();
        let refused: Vec<String> = refused
            .iter()
            .map(|(state, refusal)| {
                format!("C{} exit {} us ({refusal})", state.kind, state.latency_us)
            })
            .collect();
        crate::output::arguments(format_args!(
            "HOST IDLE APIC {apic:#x}: {}{}{}\n",
            states.join(", "),
            if refused.is_empty() {
                ""
            } else {
                "; left out "
            },
            refused.join(", ")
        ));
    }
    PROCESSORS.store(Box::leak(Box::new(processors)), Ordering::Release);
}

fn count(processors: usize) -> String {
    match processors {
        1 => String::from("1 processor"),
        n => format!("{n} processors"),
    }
}

fn describe(state: &Admitted) -> String {
    match state.enter {
        Enter::Halt => format!("C{} HLT", state.kind),
        Enter::Mwait(hint) => format!(
            "C{} MWAIT {hint:#x} exit {} us",
            state.kind, state.latency_us
        ),
    }
}

/// Wait for an interrupt and take it, in the deepest state this CPU
/// admitted whose target residency fits `budget_us` microseconds until its
/// next timer (None when none is due).
///
/// # Safety
///
/// Interrupts are disabled, and this CPU's IDT takes the interrupt that
/// ends the wait.
pub(crate) unsafe fn wait(budget_us: Option<u64>) {
    let enter = admission().and_then(|admission| {
        let state = processor::select(&admission.states, budget_us)?;
        Some((state.enter, admission.flush_monitor))
    });
    match enter {
        Some((Enter::Mwait(hint), flush_monitor)) => {
            let line = LINE.0.as_ptr();
            // SAFETY: the line is mapped write-back memory MONITOR may arm.
            // MWAIT with interrupts as break events, entered with them
            // disabled as `mwait_idle_with_hints` enters it, ends on any
            // interrupt, including one already pending; STI's shadow then
            // takes it at the NOP's boundary.
            unsafe {
                if flush_monitor {
                    asm!("mfence", "clflush [{line}]", "mfence", line = in(reg) line, options(nostack));
                }
                asm!("monitor", in("rax") line, in("ecx") 0, in("edx") 0, options(nostack));
                asm!("mwait", "sti", "nop", "cli", in("eax") hint, in("ecx") 1, options(nostack));
            }
        }
        // SAFETY: STI's interrupt shadow covers HLT, so no wake-up is lost.
        _ => unsafe { asm!("sti", "hlt", "cli", options(nostack)) },
    }
}

/// This CPU's admitted states, admitted on its first wait from its own
/// CPUID, as `acpi_processor_ffh_cstate_probe` probes on the target CPU.
fn admission() -> Option<&'static Admission> {
    let processors = PROCESSORS.load(Ordering::Acquire);
    // SAFETY: published once, leaked, never written again.
    let processors = unsafe { processors.as_ref() }?;
    let apic = apic_id();
    let index = processors
        .binary_search_by_key(&apic, |processor| processor.apic)
        .ok()?;
    let processor = &processors[index];
    // SAFETY: only this CPU publishes its admission, which is leaked.
    if let Some(admission) = unsafe { processor.admission.load(Ordering::Acquire).as_ref() } {
        return Some(admission);
    }
    let cpu = cpu();
    let leaf = __cpuid(1).eax;
    let model = (leaf >> 4) & 0xf | (leaf >> 12) & 0xf0;
    let admission = Box::leak(Box::new(Admission {
        states: processor::admit(&processor.declared, &cpu).0,
        flush_monitor: cpu.intel && (leaf >> 8) & 0xf == 6 && matches!(model, 0x1d | 0x2e | 0x2f),
    }));
    processor.admission.store(admission, Ordering::Release);
    Some(admission)
}

/// The facts of this CPU's CPUID that admit its states.
fn cpu() -> Cpu {
    let leaf = __cpuid(0);
    let vendor = (leaf.ebx, leaf.edx, leaf.ecx);
    // "GenuineIntel", "AuthenticAMD" and "HygonGenuine".
    let intel = vendor == (0x756e_6547, 0x4965_6e69, 0x6c65_746e);
    let mwait_vendor = intel
        || vendor == (0x6874_7541, 0x6974_6e65, 0x444d_4163)
        || vendor == (0x6f67_7948, 0x6e65_476e, 0x656e_6975);
    let mwait = (leaf.eax >= 5 && __cpuid(1).ecx & MWAIT != 0).then(|| {
        let leaf = __cpuid(5);
        (leaf.ecx, leaf.edx)
    });
    Cpu {
        mwait_vendor,
        intel,
        mwait,
        always_running_timer: leaf.eax >= 6 && __cpuid(6).eax & ARAT != 0,
        nonstop_tsc: __cpuid(0x8000_0000).eax >= 0x8000_0007
            && __cpuid(0x8000_0007).edx & INVARIANT_TSC != 0,
    }
}

/// This CPU's local APIC ID: its x2APIC ID from leaf 0xB when the CPU
/// has that leaf, else the initial xAPIC ID.
fn apic_id() -> u32 {
    if __cpuid(0).eax >= 0xb {
        let topology = __cpuid_count(0xb, 0);
        if topology.ebx != 0 {
            return topology.edx;
        }
    }
    __cpuid(1).ebx >> 24
}
