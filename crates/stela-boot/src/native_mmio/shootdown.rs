//! The MMIO aperture's TLB shootdown: a retirement on one processor clears
//! the leaf entries, flushes its own TLB, then publishes a generation
//! ([`aperture::Processors::request`]) and sends [`SHOOTDOWN_VECTOR`] to every
//! other processor that joined. Each flushes every PCID's translations and
//! acknowledges the generation, in the vector's handler when it waits with
//! interrupts on, or at its next safe point with them off: each native
//! return, each engine wait and each turn of its executor's mailbox loop
//! ([`service`]). Native epochs end at their deadlines, which bounds how
//! long a processor runs without a safe point.
//!
//! [`SHOOTDOWN_VECTOR`]: crate::engine::interrupts::SHOOTDOWN_VECTOR
use super::PROCESSORS;
use core::{
    arch::{asm, x86_64::__cpuid_count},
    sync::atomic::{AtomicU8, Ordering},
};

/// How long a retirement waits for every acknowledgement.
const WAIT_MS: u64 = 100;
const CR4_PGE: u64 = 1 << 7;
const CR4_PCIDE: u64 = 1 << 17;
/// CPUID.(EAX=7,ECX=0):EBX.INVPCID.
const INVPCID: u32 = 1 << 10;
/// INVPCID type 2: every context's translations, global ones included
/// (Intel SDM Vol. 2A, INVPCID).
const ALL_CONTEXTS: u64 = 2;

/// Whether INVPCID is available: 0 unknown, 1 absent, 2 present.
static INVPCID_PRESENT: AtomicU8 = AtomicU8::new(0);

pub(crate) fn invpcid() -> bool {
    match INVPCID_PRESENT.load(Ordering::Relaxed) {
        0 => {
            let present = __cpuid_count(7, 0).ebx & INVPCID != 0;
            INVPCID_PRESENT.store(1 + u8::from(present), Ordering::Relaxed);
            present
        }
        known => known == 2,
    }
}

/// Drop every aperture translation from this processor's TLB and paging
/// structure caches, in every PCID.
fn flush() {
    let cr4: u64;
    // SAFETY: CPL0 observation.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    if cr4 & CR4_PCIDE == 0 {
        // Without PCIDs a CR3 write drops every non-global translation, and
        // the aperture's leaves are not global.
        // SAFETY: rewrites the live root.
        unsafe {
            asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack, preserves_flags))
        };
    } else if invpcid() {
        let descriptor = [0u64; 2];
        // SAFETY: a valid all-contexts INVPCID; the descriptor is ignored.
        unsafe {
            asm!("invpcid {}, [{}]", in(reg) ALL_CONTEXTS, in(reg) &descriptor,
                options(nostack, preserves_flags))
        };
    } else {
        // Any change to CR4.PGE drops every PCID's translations (Intel SDM
        // Vol. 3A 4.10.4.1, AMD APM Vol. 2 5.5.3).
        let saved: u64;
        // SAFETY: interrupts stay off across the toggle; CR4 is restored.
        unsafe {
            asm!("pushfq", "pop {}", "cli", out(reg) saved);
            asm!("mov cr4, {}", in(reg) cr4 ^ CR4_PGE, options(nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
            asm!("push {}", "popfq", in(reg) saved);
        }
    }
}

/// Flush and acknowledge the latest request if this processor joined and
/// has not flushed it yet. Cheap when nothing is requested: two loads.
pub(crate) fn service() {
    let requested = PROCESSORS.requested();
    let (slot, flushed) = crate::engine::host::shootdown();
    if flushed.load(Ordering::Relaxed) >= requested {
        return;
    }
    let Some(slot) = slot else {
        return;
    };
    flush();
    flushed.store(requested, Ordering::Relaxed);
    PROCESSORS.acknowledge(slot, requested);
}

/// After the caller cleared retired leaf entries and flushed its own TLB:
/// shoot them down on every other joined processor. Whether each
/// acknowledged within [`WAIT_MS`]; until then a processor may still
/// translate through them.
pub(super) fn retire(tsc_hz: u64) -> bool {
    if PROCESSORS.alone() {
        return true;
    }
    let base = crate::apic::base_msr();
    let sender = crate::apic::Apic::new(
        base,
        crate::layout::physical(base & crate::apic::BASE_ADDRESS),
    );
    let me = PROCESSORS.slot(sender.id());
    let generation = PROCESSORS.request();
    for (slot, apic) in PROCESSORS.sharers() {
        if Some(slot) == me || PROCESSORS.acknowledged(slot) >= generation {
            continue;
        }
        // A processor halted with interrupts on wakes for the vector and
        // sees the request stored above; one with them off takes it at its
        // next safe point, whether or not this delivery completes.
        // SAFETY: every joined processor's IDT routes the vector to its
        // shootdown handler; the caller holds the aperture's lock with
        // interrupts off.
        let _ = unsafe { sender.notify(apic, crate::engine::interrupts::SHOOTDOWN_VECTOR, tsc_hz) };
    }
    let start = crate::apic::rdtsc();
    let limit = tsc_hz / 1000 * WAIT_MS;
    while !PROCESSORS.flushed(generation, me) {
        if crate::apic::rdtsc().wrapping_sub(start) >= limit {
            report_unacknowledged(generation, me);
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

fn report_unacknowledged(generation: u64, me: Option<usize>) {
    for (slot, apic) in PROCESSORS.sharers() {
        if Some(slot) != me && PROCESSORS.acknowledged(slot) < generation {
            crate::output::arguments(format_args!(
                "NATIVE MMIO shootdown {generation} unacknowledged by APIC {apic:#x}; the mapping stays reserved\n"
            ));
        }
    }
}
