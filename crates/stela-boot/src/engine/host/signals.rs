//! Interrupts, doorbells and TLB shootdowns between host CPUs, and timed
//! sleeps.

use super::*;

pub fn timer_interrupt() {
    crate::native_clock::interrupt();
    local::interrupt();
    let apic = &state().apic;
    apic.eoi();
    // No handler runs under this one (entries never nest), so a vector
    // still in service after the timer's own EOI has none: end it. One
    // register read when there is none.
    if apic::stale::holds_stale(apic.read(apic::stale::PPR), task_priority()) {
        end_stale_in_service(apic);
    }
}

/// The task priority as CR8 holds it (TPR bits 7:4), without an APIC read.
fn task_priority() -> u32 {
    let cr8: u64;
    // SAFETY: CPL0 read of the task priority.
    unsafe { asm!("mov {}, cr8", out(reg) cr8, options(nomem, nostack, preserves_flags)) };
    (cr8 as u32 & 0xf) << 4
}

/// The vectors found in service with no handler running and ended, and
/// those already reported (vector 0 in bit 0 of the first word).
static STALE_ENDED: [core::sync::atomic::AtomicU32; 8] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 8];
static STALE_REPORTED: [core::sync::atomic::AtomicU32; 8] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 8];
/// How many vectors were ended so.
static STALE_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// End every vector in service on this processor, whose caller runs no
/// handler with an EOI still due: in process code, or in a handler after
/// its own EOI. Each is kept for [`stale_in_service_report`]. Whether any
/// was ended.
pub(crate) fn end_stale_in_service(apic: &Apic) -> bool {
    let ended = apic::stale::end_stale(|offset| apic.read(offset), || apic.eoi());
    let mut any = false;
    for (word, bits) in STALE_ENDED.iter().zip(ended) {
        if bits != 0 {
            word.fetch_or(bits, core::sync::atomic::Ordering::Relaxed);
            STALE_COUNT.fetch_add(
                u64::from(bits.count_ones()),
                core::sync::atomic::Ordering::Relaxed,
            );
            any = true;
        }
    }
    any
}

/// A line naming each vector found in service with no handler running
/// that no earlier line named, once: the interrupt whose handler did not
/// end it is that device's or signal's.
pub(crate) fn stale_in_service_report() -> Option<alloc::string::String> {
    use core::fmt::Write;
    let mut fresh = [0u32; 8];
    for ((ended, reported), fresh) in STALE_ENDED.iter().zip(&STALE_REPORTED).zip(&mut fresh) {
        let ended = ended.load(core::sync::atomic::Ordering::Relaxed);
        *fresh = ended & !reported.fetch_or(ended, core::sync::atomic::Ordering::Relaxed);
    }
    if fresh == [0; 8] {
        return None;
    }
    let mut line = alloc::string::String::from("UNSUPPORTED interrupt vectors");
    for vector in apic::stale::vectors(&fresh) {
        let _ = write!(line, " {vector:#x}");
    }
    let _ = write!(
        line,
        " stayed in service with no handler running, which held every vector of their class and below (the timer's too, while it was below them): each was ended with an EOI ({} so far)",
        STALE_COUNT.load(core::sync::atomic::Ordering::Relaxed)
    );
    Some(line)
}

pub(crate) fn root_irq_active() -> bool {
    local::irq_active()
}

/// An idle-worker doorbell only. Stop requests live in generation-bound
/// mailboxes; delivery cannot authorize native-frame recovery or settlement.
/// Whether an interrupt came for this core since [`clear_interrupted`].
pub(crate) fn interrupted() -> bool {
    local::interrupted()
}

pub(crate) fn clear_interrupted() {
    local::clear_interrupt();
}

pub(crate) fn wake_interrupt() {
    state().apic.eoi();
    DOORBELLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // Release publication follows EOI; startup evidence cannot race
    // ahead of retirement of the directed interrupt at this physical LAPIC.
    local::doorbell();
}

/// A host device's completion signal: a doorbell, counted apart too.
pub(crate) fn signal_interrupt() {
    SIGNALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    wake_interrupt();
}

/// The doorbells any core has taken.
static DOORBELLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The completion signals host devices sent.
static SIGNALS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The completion signals host devices sent ([`completion_signal`]), which
/// unlike [`doorbells`] no other core's doorbell moves.
pub(crate) fn device_signals() -> u64 {
    SIGNALS.load(core::sync::atomic::Ordering::Relaxed)
}

/// The doorbells any core has taken, a host disk's completion signals among
/// them: until this moves, a disk that signals has nothing new to look at.
pub(crate) fn doorbells() -> u64 {
    DOORBELLS.load(core::sync::atomic::Ordering::Relaxed)
}

/// The message a host disk sends as it completes a command: the signal
/// vector, a doorbell counted apart, fixed and edge-triggered, to the
/// processor with APIC ID `id`,
/// which runs the engine's devices and looks for the disk's completions.
/// `None` where the ID needs more than a compatibility-format MSI address
/// holds.
/// Whether this host processor is inside an interrupt or exception handler.
pub(crate) fn in_interrupt() -> bool {
    local::irq_active()
}

/// Sleep until an interrupt, at most `micros`: a completion signal, the
/// engine's own timer or this one-shot. The engine's armed one-shot count
/// is put back less the time slept; a periodic or TSC-deadline timer, or a
/// timer not yet measured, leaves the caller to poll.
pub(crate) fn sleep_for(micros: u64) {
    if micros == 0 || crate::native_clock::host_sleep(micros) {
        return;
    }
    const MASKED: u32 = 1 << 16;
    const MODE: u32 = 3 << 17;
    let state = state();
    let lvt = state.apic.read(apic::LVT_TIMER);
    if state.apic_hz == 0 || lvt & MODE != 0 {
        return;
    }
    let remaining = state.apic.read(apic::CURRENT);
    let armed = lvt & MASKED == 0 && remaining != 0;
    let ticks = (u128::from(micros) * u128::from(state.apic_hz) / 1_000_000)
        .clamp(1, u128::from(u32::MAX)) as u32;
    let ticks = if armed { ticks.min(remaining) } else { ticks };
    state.apic.write(apic::LVT_TIMER, u32::from(TIMER_VECTOR));
    state.apic.write(apic::INITIAL, ticks);
    // SAFETY: interrupts are disabled and the host IDT takes the timer.
    unsafe { crate::native_idle::wait(|| Some(u64::from(ticks) * 1_000_000 / state.apic_hz)) };
    let slept = ticks - state.apic.read(apic::CURRENT);
    state.apic.write(apic::LVT_TIMER, lvt);
    // Ours again only if it was ours before: the hand-back count read now
    // is the one the host's own write would have seen.
    state.timer_lvt = state
        .timer_lvt
        .filter(|_| lvt == u32::from(TIMER_VECTOR))
        .filter(|&seen| {
            seen == crate::native_clock::TIMER_HANDOVERS.load(core::sync::atomic::Ordering::Acquire)
        });
    // A count that ran out during the sleep fires at once.
    state.apic.write(
        apic::INITIAL,
        if armed { (remaining - slept).max(1) } else { 0 },
    );
}

pub(crate) fn completion_signal(id: u64) -> Option<stela_drivers::bus::irq::MsiMessage> {
    (id < 255).then(|| stela_drivers::bus::irq::MsiMessage {
        address: 0xfee0_0000 | id << 12,
        data: u32::from(super::super::interrupts::SIGNAL_VECTOR),
    })
}

/// [`completion_signal`] for a host network adapter's arriving frames, to
/// the processor with APIC ID `id`, on a vector of its own
/// ([`network_interrupt`]) so that a disk does not take it for a completion.
pub(crate) fn network_signal(id: u64) -> Option<stela_drivers::bus::irq::MsiMessage> {
    (id < 255).then(|| stela_drivers::bus::irq::MsiMessage {
        address: 0xfee0_0000 | id << 12,
        data: u32::from(super::super::interrupts::NETWORK_VECTOR),
    })
}

/// Frames reached a host network adapter since [`take_network_signal`].
static NETWORK_SIGNALLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// A host network adapter's signal: a doorbell ([`wake_interrupt`]) that
/// also notes the frames, which the woken core's wait pass serves
/// (`Host::host_work_due`) instead of sleeping on to the service's tick.
pub(crate) fn network_interrupt() {
    NETWORK_SIGNALLED.store(true, core::sync::atomic::Ordering::Release);
    wake_interrupt();
}

/// Whether frames reached a host network adapter since the last call,
/// on any core.
pub(crate) fn take_network_signal() -> bool {
    NETWORK_SIGNALLED.load(core::sync::atomic::Ordering::Relaxed)
        && NETWORK_SIGNALLED.swap(false, core::sync::atomic::Ordering::AcqRel)
}

/// Doorbells a local APIC did not deliver since the last report: each may
/// leave its processor asleep until its next wake.
pub(super) static UNDELIVERED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Ring the doorbell of the processor whose APIC ID is `destination`,
/// through this processor's own local APIC.
pub(crate) fn ring(destination: u32) {
    let state = state();
    // SAFETY: interrupts are off in the engine, so nothing else on this
    // processor writes its ICR meanwhile; every installed host handles the
    // doorbell vector.
    let sent = unsafe {
        state.apic.notify(
            destination,
            super::super::interrupts::NATIVE_WAKE_VECTOR,
            state.tsc_hz,
        )
    };
    if sent.is_err() {
        UNDELIVERED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Send an NMI to the processor whose APIC ID is `destination`, through
/// this processor's own local APIC: the step watchdog's, to the boot
/// processor stuck in a Linux step (`step_watchdog::look`).
pub(crate) fn nmi(destination: u32) {
    let state = state();
    // SAFETY: interrupts are off in the engine, so nothing else on this
    // processor writes its ICR meanwhile; every installed host's NMI gate
    // stops the boot with the step watchdog's reason.
    if unsafe { state.apic.notify_nmi(destination, state.tsc_hz) }.is_err() {
        UNDELIVERED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// The doorbells left undelivered since the last call.
pub(crate) fn undelivered_doorbells() -> u64 {
    UNDELIVERED.swap(0, core::sync::atomic::Ordering::Relaxed)
}

/// Join this processor to the aperture shootdown at `slot`. Its own
/// interrupt tables are installed, whose NMI gate answers a retirement's
/// NMI (`native_mmio::shootdown::answer_nmi`).
pub(crate) fn join_shootdown(slot: usize) {
    local::shootdown()
        .0
        .store(slot + 1, core::sync::atomic::Ordering::Relaxed);
    crate::native_mmio::PROCESSORS.set_reachable(slot);
}

/// This processor's aperture shootdown slot and the generation it flushed.
pub(crate) fn shootdown() -> (Option<usize>, &'static core::sync::atomic::AtomicU64) {
    let (slot, flushed) = local::shootdown();
    (
        slot.load(core::sync::atomic::Ordering::Relaxed)
            .checked_sub(1),
        flushed,
    )
}

/// The aperture shootdown's interrupt: flush, acknowledge, EOI.
pub(crate) fn shootdown_interrupt() {
    crate::native_mmio::shootdown::service();
    state().apic.eoi();
}

pub(crate) fn doorbell_counter() -> &'static core::sync::atomic::AtomicU64 {
    local::doorbell_counter()
}

pub fn stray_interrupt(_vector: u8) {
    let state = state();
    state.stray += 1;
    state.apic.eoi();
}

/// A true APIC spurious event sets no ISR bit. A delayed ordinary fixed
/// interrupt may use the newly reserved spurious vector and still needs EOI.
/// Common entry keeps IF off, the original per-CPU APIC and this IDT/GS record
/// live; no callback/source allocation or attribution is involved.
pub fn spurious_interrupt() {
    let state = state();
    let isr = state.apic.read(0x170);
    if isr == u32::MAX {
        crate::output::fatal("native spurious-vector ISR is unreadable");
    }
    if isr & (1 << 31) != 0 {
        state.apic.eoi();
    }
}
