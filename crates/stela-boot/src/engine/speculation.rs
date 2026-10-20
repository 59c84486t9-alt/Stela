//! The branch prediction isolation the bare-metal host gives guest code,
//! which the engine discloses in ID_AA64PFR0_EL1.CSV2
//! (`identification::Speculation`).
//!
//! Every guest exception level runs as CPL0 code on this one logical
//! processor, so the CPU's own privilege separation of predictions does not
//! apply. FEAT_CSV2 holds where the CPU has an indirect branch prediction
//! barrier: the engine calls [`isolate`] at every guest context change
//! (`engine::PredictionContext`), which issues IBPB and refills the return
//! stack buffer.
use core::{
    arch::{
        asm,
        x86_64::{__cpuid, __cpuid_count},
    },
    sync::atomic::{AtomicBool, Ordering},
};
use stela_runtime::machine::identification::Speculation;

/// IA32_PRED_CMD (MSR 49H) bit 0, IBPB: indirect branch predictions after
/// it are not controlled by code before it (Intel, "Speculative Execution
/// Side Channel Mitigations"; AMD, "Software Techniques for Managing
/// Speculation on AMD Processors").
const IA32_PRED_CMD: u32 = 0x49;
const PRED_CMD_IBPB: u32 = 1;
/// CPUID.(EAX=07H,ECX=0):EDX bit 26: IBRS and IBPB (Intel).
const CPUID_7_EDX_SPEC_CTRL: u32 = 1 << 26;
/// CPUID.80000008H:EBX bit 12: IBPB (AMD).
const CPUID_80000008_EBX_IBPB: u32 = 1 << 12;
/// CPUID.80000021H:EAX bit 28, IBPB_BRTYPE: IBPB also flushes branch type
/// predictions; bit 29, SRSO_NO: no speculative return stack overflow.
const CPUID_80000021_EAX_IBPB_BRTYPE: u32 = 1 << 28;
const CPUID_80000021_EAX_SRSO_NO: u32 = 1 << 29;
/// AMD Family 19h (Zen 3 and Zen 4), whose IBPB isolates return predictions
/// only where CPUID enumerates IBPB_BRTYPE or SRSO_NO.
const AMD_ZEN3_FAMILY: u32 = 0x19;
/// Entries a return stack refill writes: at least the depth of any current
/// x86 core's return stack buffer.
const RETURN_STACK_ENTRIES: usize = 32;

/// [`isolate`] issues IBPB.
static BARRIER: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vendor {
    Intel,
    Amd,
    Other,
}

fn vendor() -> Vendor {
    let leaf = __cpuid(0);
    match (leaf.ebx, leaf.edx, leaf.ecx) {
        // "GenuineIntel" and "AuthenticAMD".
        (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Vendor::Intel,
        (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Vendor::Amd,
        _ => Vendor::Other,
    }
}

/// The display family of CPUID leaf 1 (base plus extended family).
fn family() -> u32 {
    let eax = __cpuid(1).eax;
    let base = (eax >> 8) & 0xf;
    if base == 0xf {
        base + ((eax >> 20) & 0xff)
    } else {
        base
    }
}

/// CPUID leaf `leaf` of the extended range, when the CPU has it.
fn extended(leaf: u32) -> Option<core::arch::x86_64::CpuidResult> {
    (__cpuid(0x8000_0000).eax >= leaf).then(|| __cpuid(leaf))
}

/// The host's guarantees, probed once before guest code runs; the barrier
/// [`isolate`] issues follows the result.
pub fn probe() -> Speculation {
    let contexts = match vendor() {
        Vendor::Intel => __cpuid_count(7, 0).edx & CPUID_7_EDX_SPEC_CTRL != 0,
        // From Zen 3, IBPB isolates return predictions only where it also
        // flushes branch types or no return stack overflow exists; Zen 1
        // and 2's IBPB flushes them.
        Vendor::Amd => {
            extended(0x8000_0008).is_some_and(|leaf| leaf.ebx & CPUID_80000008_EBX_IBPB != 0)
                && (family() != AMD_ZEN3_FAMILY
                    || extended(0x8000_0021).is_some_and(|leaf| {
                        leaf.eax & (CPUID_80000021_EAX_IBPB_BRTYPE | CPUID_80000021_EAX_SRSO_NO)
                            != 0
                    }))
        }
        Vendor::Other => false,
    };
    BARRIER.store(contexts, Ordering::Relaxed);
    Speculation { contexts }
}

/// Keep branch predictions trained before the call from steering
/// speculation after it: IBPB, then a refill of the return stack buffer
/// with entries that each lead to a trap, so a return that underflows it
/// cannot use an earlier context's target. Nothing where the CPU has no
/// IBPB, which then identifies no FEAT_CSV2.
pub fn isolate() {
    if !BARRIER.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: [`probe`] found IBPB enumerated; ring 0. Each refill call
    // pushes its return address, which the final addition pops; nothing
    // executes the INT3s but speculation.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_PRED_CMD,
            in("eax") PRED_CMD_IBPB,
            in("edx") 0,
            options(nostack, preserves_flags),
        );
        asm!(
            ".rept {entries}",
            "call 2f",
            "int3",
            "2:",
            ".endr",
            "add rsp, {bytes}",
            "lfence",
            entries = const RETURN_STACK_ENTRIES,
            bytes = const RETURN_STACK_ENTRIES * 8,
        );
    }
}
