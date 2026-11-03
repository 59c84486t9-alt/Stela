//! Explicit short native-root fixture. PM/LAPIC/IDT/HLT effects are
//! checked; these authored words are not an original Linux timer-wheel test.
use super::*;
use stela_linux::owner::MinimumDeadline as _;

struct Words {
    jiffies: AtomicU64,
    generation: AtomicU64,
}

/// # Safety
/// Explicit bounded diagnostic on the native HostOwner. The
/// trusted test platform preserves the PM source and guarantees no >1-second
/// sample gap, including firmware/VMM interruptions. This permission checks
/// only this short fixture; no arbitrary original driver execution is admitted.
pub(crate) unsafe fn check(
    owner: &mut host::HostOwner,
    prepared: Prepared,
) -> Result<(), WorkError> {
    // SAFETY: caller's explicit short-root profile, not an IRQ-count inference.
    let source = unsafe { prepared.qualify_bounded(pm::NS)? };
    let root_execution = owner.enter_root()?;
    // SAFETY: real owner and unchanged kept tables/roots satisfy attach.
    let installed = unsafe { Installed::attach(owner, &root_execution, source)? };
    run(installed, None)
}

/// # Safety
/// Production Source counter/root identity and complete original
/// controller/IRQ/idle handoff remain owned through this bounded native proof.
/// No finite RAM-absence scope is held or recreated by this constructor.
pub(crate) unsafe fn check_native(
    identity: Arc<host::RootIdentity>,
    prepared: Prepared,
) -> Result<(), WorkError> {
    if prepared.hpet_counter().is_none() {
        return Err(WorkError::Unavailable);
    }
    // SAFETY: this owner supplies complete HPET/LAPIC/IDT delivery and
    // lifecycle; constructor checks exact Source identity and ARAT.
    let installed = unsafe { Installed::attach_native(identity.clone(), prepared)? };
    let services = installed.services()?;
    services.check_identity(&identity)?;
    let epoch = services.epoch()?;
    drop(services);
    run(installed, Some(epoch))
}

fn run(installed: Installed, epoch: Option<CounterEpoch>) -> Result<(), WorkError> {
    if let Some(epoch) = &epoch {
        let start = epoch.sample()?;
        let minimum = epoch.minimum_deadline(100_000)?;
        if minimum.remaining_quanta_ceil(10)? > 10 {
            return Err(WorkError::CorruptContext);
        }
        while !minimum.ready()? {
            core::hint::spin_loop();
        }
        let end = epoch.sample()?;
        let wake = u64::try_from(minimum.wake_ns()?).map_err(|_| WorkError::CorruptContext)?;
        if epoch.now_ns()?.saturating_add(1) < wake
            || minimum.remaining_quanta_ceil(10)? != 0
            || epoch.elapsed_bounds(&start, &end)?.lower_ns < 100_000
        {
            return Err(WorkError::CorruptContext);
        }
    }
    let epoch_start = epoch.as_ref().map(CounterEpoch::sample).transpose()?;
    let observation = installed.observation()?;
    let clock = Arc::clone(&installed.clock);
    let idle = Arc::clone(&installed.idle);
    let words = Arc::new(Words {
        jiffies: AtomicU64::new(u64::MAX - 5),
        generation: AtomicU64::new(1),
    });
    let initial = words.jiffies.load(Ordering::Acquire);
    let origin = clock.now_ns()?;
    let retained: RetainedOwner = words.clone();
    // SAFETY: aligned atomic storage kept independently; same Clock,
    // same logical HZ and generation. There is no C callback/storage.
    unsafe {
        installed.bind_counter(
            NonNull::from(&words.jiffies),
            NonNull::from(&words.generation),
            1,
            initial,
            origin,
            retained,
        )?;
    }
    // Bind performs one real elapsed publication in process context. Establish
    // the busy-loop baseline AFTER it, so setup delays cannot impersonate ISR
    // progress. The eight additional increments below must come from IRQs.
    let busy_initial = words.jiffies.load(Ordering::Acquire);
    // SAFETY: explicit fixture root grants physical interrupt delivery while
    // its host owner, IDT/IST/xstate and all word/code owners stay live.
    let execution = unsafe { installed.enter_driver_execution()? };
    let limit = origin.checked_add(pm::NS).ok_or(WorkError::Exhausted)?;
    // No service pass, software tick or process publication occurs in this
    // loop. Only the existing timer ISR can advance the observed word.
    while words
        .jiffies
        .load(Ordering::Acquire)
        .wrapping_sub(busy_initial)
        < 8
    {
        if clock.now_ns()? >= limit {
            return Err(WorkError::TimedOut);
        }
        core::hint::spin_loop();
    }
    let busy_ticks = words
        .jiffies
        .load(Ordering::Acquire)
        .wrapping_sub(busy_initial);
    idle.notify()?;
    idle.wait_until_ns(None)?; // Pending event avoids sleeping.
    let deadline = clock
        .now_ns()?
        .checked_add(5 * TICK_NS)
        .ok_or(WorkError::Exhausted)?;
    let mut waits = 0u64;
    while clock.now_ns()? < deadline {
        idle.wait_until_ns(Some(deadline))?;
        waits += 1;
    }
    if waits == 0 {
        return Err(WorkError::CorruptContext);
    }
    // Exercise the existing guest owner's timer through the same mux. Its
    // deadline survives intervening 1-ms driver heartbeats and is retired only
    // once PM time reaches it. This supplies no guest execution claim.
    let guest_ticks =
        u32::try_from((installed.state.apic_hz / 100).max(1)).map_err(|_| WorkError::Exhausted)?;
    let saved = flags_disable();
    if !arm_guest(Some(guest_ticks)) {
        // SAFETY: `saved` came from `flags_disable` on this CPU above.
        unsafe {
            restore(saved);
        }
        return Err(WorkError::CorruptContext);
    }
    // SAFETY: `saved` came from `flags_disable` on this CPU above.
    unsafe {
        restore(saved);
    }
    let guest = installed.state.guest.load(Ordering::Acquire);
    while installed.state.guest.load(Ordering::Acquire) != NONE {
        let now = clock.now_ns()?;
        if now >= limit {
            return Err(WorkError::TimedOut);
        }
        core::hint::spin_loop();
    }
    if clock.now_ns()? < guest {
        return Err(WorkError::CorruptContext);
    }
    installed.detach_publications()?;
    words.generation.store(2, Ordering::Release);
    let stopped = words.jiffies.load(Ordering::Acquire);
    let after = clock
        .now_ns()?
        .checked_add(3 * TICK_NS)
        .ok_or(WorkError::Exhausted)?;
    while clock.now_ns()? < after {
        core::hint::spin_loop();
    }
    if words.jiffies.load(Ordering::Acquire) != stopped {
        return Err(WorkError::CorruptContext);
    }
    // This brackets real ISR-only progress and HLT wakeups, rather than a
    // model clock or authored successful callback. Only native admission above
    // can create the epoch; the bounded PM diagnostic has no such token.
    let epoch_bounds = match (&epoch, &epoch_start) {
        (Some(epoch), Some(start)) => {
            let end = epoch.sample()?;
            let bounds = epoch.elapsed_bounds(start, &end)?;
            if bounds.lower_ns == 0 || bounds.upper_ns < bounds.lower_ns {
                return Err(WorkError::CorruptContext);
            }
            Some(bounds)
        }
        (None, None) => None,
        _ => return Err(WorkError::CorruptContext),
    };
    drop(execution);
    drop(idle);
    drop(clock);
    // SAFETY: no original producer/task exists; real ISR views detached, all
    // waits/borrowed execution scopes have returned and provider clones ended.
    unsafe {
        installed.retire()?;
    }
    if let Some(epoch) = epoch {
        if !matches!(epoch.sample(), Err(WorkError::Closed)) {
            return Err(WorkError::CorruptContext);
        }
        let bounds = epoch_bounds.ok_or(WorkError::CorruptContext)?;
        crate::output::arguments(format_args!(
            "CHECK native-counter-epoch PASS elapsed_ns={}..={} retired=closed; source-bound IRQ/HLT control, physical platform qualification pending\n",
            bounds.lower_ns, bounds.upper_ns
        ));
    }
    crate::output::arguments(format_args!(
        "CHECK native-clock PASS busy_jiffies={busy_ticks} idle_waits={waits} guest_mux=elapsed detach=quiet source={observation:?}; authored UP fixture, original Linux and hardware unqualified\n"
    ));
    Ok(())
}
