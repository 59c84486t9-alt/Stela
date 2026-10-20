//! The speculation guarantees the bare-metal host gives guest code, which
//! the engine discloses in ID_AA64PFR0_EL1.CSV2 and CSV3
//! (`identification::Speculation`).
//!
//! Every guest exception level runs as CPL0 code on this one logical
//! processor, so the CPU's own privilege separation of predictions does not
//! apply. FEAT_CSV2 holds where the CPU has an indirect branch prediction
//! barrier: the engine calls [`isolate`] at every guest context change
//! (`engine::PredictionContext`), which issues IBPB and refills the return
//! stack buffer.
//!
//! FEAT_CSV3 holds where the CPU documents that its loads forward no data
//! from a faulting access, nor stale buffer data to one, to later
//! speculative instructions ([`forwards_no_faulting_data`]). Native guest
//! accesses then fault through the shadow tables, an address a mispredicted
//! range check lets through is masked into an unmapped entry
//! (`x86_64::GUEST_RANGE_CHECK`), and [`fence`] keeps each of the engine's
//! own guest reads behind the translation that allows it.
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

/// CPUID.(EAX=07H,ECX=0):EDX bit 29: IA32_ARCH_CAPABILITIES (Intel).
const CPUID_7_EDX_ARCH_CAPABILITIES: u32 = 1 << 29;
/// CPUID.(EAX=07H,ECX=0):EBX bit 11: RTM, Intel TSX.
const CPUID_7_EBX_RTM: u32 = 1 << 11;
/// IA32_ARCH_CAPABILITIES (MSR 10AH) and the bits that each rule out one
/// way a load forwards data to speculation (Intel, "Affected Processors:
/// Transient Execution Attacks"): RDCL_NO (rogue data cache load and L1
/// terminal fault), MDS_NO (microarchitectural data sampling), TAA_NO
/// (TSX asynchronous abort, which needs RTM), GDS_NO (gather data
/// sampling) and RFDS_NO (register file data sampling).
const IA32_ARCH_CAPABILITIES: u32 = 0x10a;
const ARCH_CAP_RDCL_NO: u64 = 1 << 0;
const ARCH_CAP_MDS_NO: u64 = 1 << 5;
const ARCH_CAP_TAA_NO: u64 = 1 << 8;
const ARCH_CAP_GDS_NO: u64 = 1 << 26;
const ARCH_CAP_RFDS_NO: u64 = 1 << 27;
/// CPUID.80000021H:EAX bit 2: LFENCE is always dispatch serializing, so it
/// orders speculation without a DE_CFG write (AMD).
const CPUID_80000021_EAX_LFENCE_SERIALIZING: u32 = 1 << 2;
/// CPUID.80000021H:ECX bits 1 and 2, TSA_SQ_NO and TSA_L1_NO: no transient
/// scheduler attack through the store queue or the L1 data cache (AMD
/// security bulletin AMD-SB-7029). AMD's Zen processors do not forward
/// data from faulting loads otherwise (AMD, "Speculation Behavior in AMD
/// Micro-Architectures").
const CPUID_80000021_ECX_TSA_SQ_NO: u32 = 1 << 1;
const CPUID_80000021_ECX_TSA_L1_NO: u32 = 1 << 2;

/// [`isolate`] issues IBPB.
static BARRIER: AtomicBool = AtomicBool::new(false);
/// [`fence`] issues LFENCE.
static FENCE: AtomicBool = AtomicBool::new(false);

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
    let faulting_data = forwards_no_faulting_data(vendor());
    FENCE.store(faulting_data, Ordering::Relaxed);
    Speculation {
        contexts,
        faulting_data,
    }
}

/// Whether the CPU documents that no load forwards data from a faulting
/// access, or stale buffer data to one, to later speculative instructions,
/// and has an LFENCE that stops speculation.
fn forwards_no_faulting_data(vendor: Vendor) -> bool {
    match vendor {
        Vendor::Intel => {
            let leaf = __cpuid_count(7, 0);
            if leaf.edx & CPUID_7_EDX_ARCH_CAPABILITIES == 0 {
                return false;
            }
            // SAFETY: CPUID enumerates the MSR; ring 0.
            let capabilities = unsafe { super::read_msr(IA32_ARCH_CAPABILITIES) };
            let tsx = leaf.ebx & CPUID_7_EBX_RTM != 0;
            let all = |bits: u64| capabilities & bits == bits;
            all(ARCH_CAP_RDCL_NO | ARCH_CAP_MDS_NO | ARCH_CAP_GDS_NO | ARCH_CAP_RFDS_NO)
                && (!tsx || all(ARCH_CAP_TAA_NO))
        }
        Vendor::Amd => extended(0x8000_0021).is_some_and(|leaf| {
            let no_tsa = CPUID_80000021_ECX_TSA_SQ_NO | CPUID_80000021_ECX_TSA_L1_NO;
            leaf.eax & CPUID_80000021_EAX_LFENCE_SERIALIZING != 0 && leaf.ecx & no_tsa == no_tsa
        }),
        Vendor::Other => false,
    }
}

/// Keep the reads after the call from executing before the branches before
/// it resolve, where the host gives FEAT_CSV3: LFENCE, which Intel and (with
/// an always-serializing LFENCE) AMD document as stopping speculation.
pub fn fence() {
    if FENCE.load(Ordering::Relaxed) {
        // SAFETY: LFENCE has no effect but ordering.
        unsafe { asm!("lfence", options(nostack, nomem, preserves_flags)) };
    }
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
