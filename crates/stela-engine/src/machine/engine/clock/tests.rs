use super::*;
use alloc::vec::Vec;

#[test]
fn repeated_slow_slices_charge_their_full_host_duration() {
    let mut clock = Clock::default();
    let mut previous = 0;
    // Four concurrent PEs get ten counts per forty blocks. Each slice
    // takes 100 host counts: after the initial overshoot, work must
    // advance the count by ten, not by a share of the host's slowdown.
    for slice in 0..100 {
        clock.start_slice(|| slice * 100, slice * 40, 4);
        let during = clock.read(|| slice * 100 + 50);
        assert!(during >= previous);
        clock.end_slice(|| (slice + 1) * 100, (slice + 1) * 40);
        let after = clock.read(|| (slice + 1) * 100);
        assert!(after >= during);
        assert_eq!(after, 100 + slice * 10);
        previous = after;
    }
    // The final read's bounded overshoot holds briefly, then ordinary
    // idle time reaches the translated deadline exactly.
    assert_eq!(clock.read(|| 10_089), 1090);
    assert_eq!(clock.read(|| 10_100), 1100);
    assert_eq!(clock.host_deadline(2000), 11_000);
    assert_eq!(clock.read(|| 10_999), 1999);
    assert_eq!(clock.read(|| 11_000), 2000);
}

#[test]
fn host_work_excluded_mid_slice_is_not_charged_again() {
    let mut clock = Clock::default();
    for slice in 0..100 {
        clock.start_slice(|| slice * 100, slice * 10, 1);
        // Eighty counts were host-only work; the other twenty ran ten
        // blocks. Only ten more counts become slice lag.
        clock.exclude(80);
        clock.end_slice(|| (slice + 1) * 100, (slice + 1) * 10);
        assert_eq!(clock.read(|| (slice + 1) * 100), 20 + slice * 10);
    }
    assert_eq!(clock.host_deadline(2000), 11_000);
    assert_eq!(clock.read(|| 11_000), 2000);
}

#[test]
fn idle_leaps_from_a_held_count_keep_deadlines_coherent() {
    let mut clock = Clock::default();
    clock.start_slice(|| 1000, 0, 1);
    clock.end_slice(|| 2000, 100);
    assert_eq!(clock.read(|| 2000), 2000);
    // The observed count is held above the host minus lag. Leaping to
    // 5000 must advance that underlying count too, so it can continue
    // from 5000 and translate the very next deadline correctly.
    clock.skip_to(2000, 5000);
    assert_eq!(clock.read(|| 2000), 5000);
    assert_eq!(clock.host_deadline(5001), 2001);
    assert_eq!(clock.read(|| 2001), 5001);
    clock.start_slice(|| 2001, 100, 1);
    clock.end_slice(|| 2101, 120);
    assert_eq!(clock.read(|| 2101), 5101);
    assert_eq!(clock.host_deadline(6000), 3080);
    assert_eq!(clock.read(|| 3079), 5999);
    assert_eq!(clock.read(|| 3080), 6000);
    clock.exclude(500);
    assert_eq!(clock.read(|| 3580), 6000);
}

#[test]
fn slices_advance_by_their_blocks_and_waits_by_the_host() {
    // The blocks that account for `counts` counts.
    let blocks = |counts: u64| counts / TICKS_PER_BLOCK;
    let mut clock = Clock::default();
    clock.start_slice(|| 1000, 0, 2);
    // Within a slice the host's counter shows through.
    assert_eq!(clock.read(|| 1500), 1500);
    // Blocks shared by two PEs account for 200 counts, so the 800 more
    // the slice showed become lag and the count holds.
    clock.end_slice(|| 2000, blocks(400));
    assert_eq!(clock.read(|| 2000), 2000);
    assert_eq!(clock.read(|| 2500), 2000);
    assert_eq!(clock.read(|| 2900), 2100);
    assert_eq!(clock.host_deadline(2200), 3000);
    // A slice within its bound adds no lag.
    clock.start_slice(|| 3000, blocks(400), 1);
    clock.end_slice(|| 3200, blocks(800));
    assert_eq!(clock.read(|| 3300), 2500);
    // Waiting outside a slice follows the host.
    assert_eq!(clock.read(|| 10_000), 9200);
    clock.end_slice(|| 11_000, blocks(800));
    assert_eq!(clock.read(|| 11_000), 10_200);
}

#[test]
fn excluded_host_time_never_reaches_the_count() {
    let mut clock = Clock::default();
    assert_eq!(clock.read(|| 100), 100);
    clock.exclude(900);
    assert_eq!(clock.read(|| 1000), 100);
    assert_eq!(clock.read(|| 1010), 110);
}

#[test]
fn idle_skips_leap_to_the_deadline_and_keep_counting_from_there() {
    let mut clock = Clock::default();
    assert_eq!(clock.read(|| 100), 100);
    clock.skip_to(150, 5_000);
    assert_eq!(clock.read(|| 150), 5_000);
    assert_eq!(clock.read(|| 200), 5_050);
    assert_eq!(clock.host_deadline(6_000), 1_150);
    // A deadline already reached leaps nowhere.
    clock.skip_to(300, 10);
    assert_eq!(clock.read(|| 300), 5_150);
    // Lag from a slow slice still holds the count back: 90 of the 100
    // counts it showed, until the host catches up.
    clock.start_slice(|| 300, 0, 1);
    clock.end_slice(|| 400, 10 / TICKS_PER_BLOCK);
    assert_eq!(clock.read(|| 490), 5_250);
    assert_eq!(clock.read(|| 500), 5_260);
}

/// A counter frequency at which the stall limit is 1200 counts and the
/// timer delay 240.
const FREQUENCY: u64 = 24_000;

/// Two PEs reading one shared clock, continuing a serialized count of
/// 1000 at host 1000.
fn pair() -> (Arc<SharedClock>, Clock, Clock) {
    let shared = Arc::new(SharedClock::new(2));
    let mut serialized = Clock::default();
    serialized.seed(&shared, 1000, FREQUENCY);
    let (mut first, mut second) = (Clock::default(), Clock::default());
    first.attach(Arc::clone(&shared), 0);
    second.attach(Arc::clone(&shared), 1);
    (shared, first, second)
}

#[test]
fn a_shared_count_is_the_host_s_however_slow_a_pe_runs() {
    let (shared, mut first, mut second) = pair();
    let sequence = shared.state.sequence.load(Ordering::Relaxed);
    first.start_slice(|| 1000, 0, 1);
    second.start_slice(|| 1000, 0, 1);
    // The first PE runs a million blocks a slice, the second one block in
    // all, and waits now and then: neither moves the count off the host's.
    for slice in 1..=100u64 {
        let host = 1000 + slice * 480;
        first.end_slice(|| host, slice * 1_000_000);
        first.start_slice(|| host, slice * 1_000_000, 1);
        if slice % 7 == 0 {
            second.wait(|| host);
        }
        assert_eq!(first.read(|| host), host);
        assert_eq!(second.read(|| host + 1), host + 1);
        assert_eq!(shared.count(|| host + 2), host + 2);
    }
    assert_eq!(second.host_deadline(90_000), 90_000);
    assert_eq!(second.wake_at(90_000, 50_000), 90_000);
    // Slices, waits and reads leave the state native reads share untouched.
    assert_eq!(shared.state.sequence.load(Ordering::Relaxed), sequence);
}

#[test]
fn readers_of_one_shared_count_never_disagree_backwards() {
    let (shared, mut first, mut second) = pair();
    let (mut shared_seen, mut seen) = (0, [0; 2]);
    for step in 0..400u64 {
        let host = 1000 + step * 37;
        if step % 50 == 0 {
            first.leave(|| host, 0, false);
        }
        if step % 50 == 45 {
            first.resume(|| host, 0);
        }
        let count = shared.count(|| host);
        assert!(
            count >= shared_seen,
            "step {step}: {count} after {shared_seen}"
        );
        shared_seen = count;
        // A reader whose host counter lags another core's still never
        // reads less than it read before.
        for (reader, clock) in [&mut first, &mut second].into_iter().enumerate() {
            let count = clock.read(|| host - (step + reader as u64) % 3 * 20);
            assert!(
                count >= seen[reader],
                "step {step}: {count} after {}",
                seen[reader]
            );
            seen[reader] = count;
        }
    }
}

#[test]
fn a_pe_stopped_in_the_kernel_holds_the_count_only_past_the_stall_limit() {
    let (shared, mut first, mut second) = pair();
    // A short stop in the kernel costs guest time nothing.
    assert!(first.leave(|| 2000, 0, false));
    assert!(!first.leave(|| 2000, 0, false), "stopped once");
    assert_eq!(second.read(|| 2500), 2500);
    first.resume(|| 2600, 0);
    assert_eq!(second.read(|| 3000), 3000);
    assert_eq!(shared.take_stalled(), 0);
    // A long one stops the count 1200 counts (50 ms) after it began; the
    // rest becomes lag, and the count goes on from there.
    assert!(first.leave(|| 4000, 0, false));
    assert_eq!(second.read(|| 6000), 5200);
    assert_eq!(
        second.wake_at(5300, 6000),
        7200,
        "looks again a limit later"
    );
    first.resume(|| 10_000, 0);
    assert_eq!(shared.take_stalled(), 4800);
    assert_eq!(second.read(|| 10_000), 5200);
    assert_eq!(second.read(|| 10_100), 5300);
    // As early as the slew can bring it: 10,800 less one count in 101.
    assert_eq!(second.host_deadline(6000), 10_793);
    // Host work at EL0 holds no lock the kernel times. Each look from here
    // repays a count of the lag for each 100 host counts.
    assert!(first.leave(|| 11_000, 0, true));
    second.look(|| 15_000);
    assert_eq!(second.read(|| 20_000), 15_250);
    first.resume(|| 20_000, 0);
    assert_eq!(shared.take_stalled(), 0);
    // Nor host work while its guest waits for an interrupt.
    first.idle(|| 20_000, 0, None);
    assert!(!first.leave(|| 20_000, 0, false));
    second.look(|| 30_000);
    assert_eq!(second.read(|| 30_000), 25_400);
    assert_eq!(shared.take_repaid(), 200);
}

/// 200 ms at the stall limit's 50 ms.
const LONG_STALL: u64 = 4 * FREQUENCY * STALL_MILLIS / 1000;

#[test]
fn a_pe_with_guest_work_that_retires_nothing_holds_the_count_only_past_the_limit() {
    let (shared, mut first, mut second) = pair();
    first.idle(|| 1000, 0, None);
    first.busy(|| 1000, 0, None);
    second.idle(|| 1000, 0, None);
    second.busy(|| 1000, 0, None);
    let limit = 1000 + FREQUENCY * STALL_MILLIS / 1000;
    // The first PE, in host work or a compile, retires nothing for 200 ms;
    // the second runs and marks its progress every 10 counts.
    let mut retired = 0;
    for host in (1010..1000 + LONG_STALL).step_by(10) {
        retired += 100;
        second.mark(|| host, retired, None);
        assert_eq!(second.read(|| host), host.min(limit), "at {host}");
    }
    assert_eq!(shared.take_stalled(), 0, "held, not yet lifted");
    // It runs again: the count goes on from the limit, and only the excess
    // over the limit became lag.
    first.mark(|| 1000 + LONG_STALL, 1, None);
    assert_eq!(shared.take_stalled(), LONG_STALL - (limit - 1000));
    assert_eq!(second.read(|| 1000 + LONG_STALL), limit);
    assert_eq!(second.read(|| 1100 + LONG_STALL), limit + 100);
    assert_eq!(shared.state.ceiling.load(Ordering::Relaxed), UNBOUNDED);
    // Its gap is reported, with no phase known without step timing; the
    // second PE's 10-count gaps are too short to name.
    assert_eq!(shared.take_stalls(), [(LONG_STALL, STALL_UNKNOWN), (0, 0)]);
    assert_eq!(shared.take_stalls(), [(0, 0), (0, 0)]);
}

#[test]
fn a_waiting_pe_sets_the_limit_of_a_stalled_one() {
    let (shared, mut first, mut second) = pair();
    first.idle(|| 1000, 0, None);
    first.busy(|| 1000, 0, None);
    second.idle(|| 1000, 0, None);
    // The only other PE waits, and looks when it wakes.
    second.look(|| 1100);
    assert_eq!(shared.state.ceiling.load(Ordering::Relaxed), UNBOUNDED);
    second.look(|| 1400);
    assert_eq!(shared.count(|| 5000), 2200);
    first.mark(|| 5000, 1, None);
    assert_eq!(shared.take_stalled(), 2800);
}

#[test]
fn waiting_pes_hold_nothing() {
    let (shared, mut first, mut second) = pair();
    let sequence = shared.state.sequence.load(Ordering::Relaxed);
    first.idle(|| 1000, 0, None);
    first.busy(|| 1000, 0, None);
    first.idle(|| 1010, 5, None);
    // Its guest waits 200 ms; the other runs and looks.
    let mut retired = 0;
    for host in (1000..1000 + LONG_STALL).step_by(10) {
        retired += 100;
        second.mark(|| host, retired, None);
        assert_eq!(second.read(|| host), host);
    }
    assert_eq!(shared.take_stalled(), 0);
    assert_eq!(shared.state.sequence.load(Ordering::Relaxed), sequence);
}

#[test]
fn running_pes_keep_the_count_at_the_host_s_rate() {
    let (shared, mut first, mut second) = pair();
    let sequence = shared.state.sequence.load(Ordering::Relaxed);
    let start = 1000;
    first.idle(|| start, 0, None);
    first.busy(|| start, 0, None);
    second.idle(|| start, 0, None);
    second.busy(|| start, 0, None);
    // Ten seconds of both running, one slower and in uneven steps.
    let end = start + 10 * FREQUENCY;
    let mut retired = [0; 2];
    for (step, host) in (start..end).step_by(7).enumerate() {
        retired[0] += 3;
        first.mark(|| host, retired[0], None);
        if step % 3 == 0 {
            retired[1] += 1;
            second.mark(|| host, retired[1], None);
        }
    }
    assert_eq!(second.read(|| end), end);
    assert_eq!(shared.take_stalled(), 0);
    // Not a single write to the state native reads share.
    assert_eq!(shared.state.sequence.load(Ordering::Relaxed), sequence);
}

#[test]
fn a_gap_is_named_by_the_phase_that_took_most_of_it() {
    let then = Some((0, [0; super::super::step_timing::Phase::COUNT]));
    // Fetch (compiling) took 60 of 100 ticks.
    assert_eq!(Clock::stall_phase(then, Some((100, [10, 0, 60, 5, 5]))), 2);
    // Host work outside the step loop took 95.
    assert_eq!(
        Clock::stall_phase(then, Some((100, [1, 1, 1, 1, 1]))),
        STALL_HOST
    );
    assert_eq!(Clock::stall_phase(None, then), STALL_UNKNOWN);
}

#[test]
fn two_stops_hold_the_count_at_the_earlier_one_s_limit() {
    let (shared, mut first, mut second) = pair();
    assert!(first.leave(|| 2000, 0, false));
    assert!(second.leave(|| 2500, 0, false));
    assert_eq!(shared.count(|| 9000), 3200);
    first.resume(|| 9000, 0);
    // The second stop's limit, 3700, now holds the count from 3200.
    assert_eq!(shared.count(|| 9400), 3600);
    assert_eq!(shared.count(|| 9600), 3700);
    second.resume(|| 9600, 0);
    assert_eq!(shared.count(|| 9700), 3800);
    assert_eq!(shared.take_stalled(), 5800 + 100);
}

#[test]
fn a_busy_pe_s_timers_wait_for_its_share_of_work() {
    let (_, mut first, _) = pair();
    // Its first timer interrupt waits for nothing.
    assert_eq!(first.timer_due(Some(900)), Some(900));
    first.timer_taken(1000, 0);
    assert_eq!(first.timer_due(Some(900)), Some(1000));
    // It then retired half the work in 100 counts: its timers wait 200
    // counts from the next interrupt.
    first.timer_taken(1100, TIMER_WORK / 2);
    assert_eq!(first.timer_due(Some(1150)), Some(1300));
    assert_eq!(first.timer_due(Some(1400)), Some(1400));
    // A PE that waits had time to spare: its timers signal when due.
    first.wait(|| 1200);
    assert_eq!(first.timer_due(Some(1250)), Some(1250));
    first.timer_taken(1250, TIMER_WORK);
    assert_eq!(first.timer_due(Some(1250)), Some(1250));
    // A serialized clock's timers are never held.
    assert_eq!(Clock::default().timer_due(Some(5)), Some(5));
}

#[test]
fn a_pe_back_from_a_long_host_pause_takes_no_flood_of_timer_interrupts() {
    let (_, mut first, _) = pair();
    // The guest rearms its timer in the past at each interrupt, as a
    // periodic timer that fell behind does. The PE retires TIMER_WORK in
    // 100 counts, except during a host pause of 5000 counts.
    let (mut retired, mut deliveries) = (0u64, Vec::new());
    for count in 1000..20_000u64 {
        let paused = (5000..10_000).contains(&count);
        if !paused {
            retired += TIMER_WORK / 100;
        }
        if !paused && first.timer_due(Some(0)).is_some_and(|due| count >= due) {
            first.timer_taken(count, retired);
            deliveries.push(count);
        }
    }
    // After the first two, interrupts come 100 counts apart while it runs,
    // and the first after the pause waits out the 240-count delay at most.
    for pair in deliveries.windows(2).skip(1) {
        let gap = pair[1] - pair[0];
        assert!(gap >= 100 || pair[0] < 1002, "{pair:?}");
    }
    let after = deliveries
        .iter()
        .position(|&count| count >= 10_000)
        .unwrap();
    assert_eq!(deliveries[after], 10_000);
    assert_eq!(deliveries[after + 1] - deliveries[after], 240);
    assert!(deliveries.len() < (20_000 - 1000 - 5000) / 100 + 4);
}

/// `pes` PEs reading one shared clock seeded at count 1000 at host 1000,
/// counting at `frequency` Hz, each with guest work from host 1000.
fn busy_clocks(pes: usize, frequency: u64) -> (Arc<SharedClock>, Vec<Clock>) {
    let shared = Arc::new(SharedClock::new(pes));
    Clock::default().seed(&shared, 1000, frequency);
    let clocks = (0..pes)
        .map(|pe| {
            let mut clock = Clock::default();
            clock.attach(Arc::clone(&shared), pe);
            clock.idle(|| 1000, 0, None);
            clock.busy(|| 1000, 0, None);
            clock
        })
        .collect();
    (shared, clocks)
}

#[test]
fn a_stall_s_lag_is_repaid_by_a_bounded_slew_with_timers_on_their_count() {
    let (shared, mut clocks) = busy_clocks(3, FREQUENCY);
    let stall = FREQUENCY * STALL_MILLIS / 1000;
    // PE 2 waits, for a timer re-armed 1000 counts after each one fires.
    clocks[2].idle(|| 1000, 0, None);
    let step = shared.slew_step();
    let (mut deadline, mut fired, mut armed) = (1500, 0, 1000);
    let mut wake = clocks[2].wake_at(deadline, 1000);
    // PE 0 retires nothing for 200 ms, then runs; PE 1 runs throughout.
    let resumed = 1000 + LONG_STALL;
    let lag = LONG_STALL - stall;
    let repaid_by = resumed + lag * SLEW_PARTS + 2 * step;
    let end = repaid_by + 10_000;
    let (mut retired, mut seen, mut repaid) = ([0u64; 2], [0u64; 3], 0);
    for host in 1001..end {
        if host % 10 == 0 {
            for pe in 0..2 {
                if pe == 0 && host < resumed {
                    continue;
                }
                retired[pe] += 100;
                clocks[pe].mark(|| host, retired[pe], None);
            }
            // A PE that is sure the deadline is ahead is right.
            if clocks[1].below(deadline, || host) {
                assert!(shared.count(|| host) < deadline, "at {host}");
            }
        }
        if host == wake {
            clocks[2].look(|| host);
            let count = clocks[2].read(|| host);
            if count >= deadline {
                // On its count, a count or two late at most for the steps'
                // rounding; one armed before the hold was lifted waited for
                // the stopped PE.
                if armed > resumed {
                    assert!(count - deadline <= 2, "at {host}: {count} for {deadline}");
                }
                fired += 1;
                deadline = count + 1000;
                armed = host;
            }
            wake = clocks[2].wake_at(deadline, host);
            assert!(wake > host, "at {host}: waits again at once");
        }
        // Monotonic for every reader; never past the host's count.
        for (pe, clock) in clocks.iter_mut().enumerate() {
            let count = clock.read(|| host);
            assert!(count >= seen[pe], "at {host}: {count} after {}", seen[pe]);
            assert!(count <= host, "at {host}: overshoot to {count}");
            seen[pe] = count;
        }
        if host == resumed + 1 {
            // Held 50 ms in, the rest became lag.
            assert_eq!(shared.lag(), lag);
            assert_eq!(seen[1], 1000 + stall + 1);
            assert_eq!(shared.take_repaid(), 0);
        }
        if host > resumed && host < repaid_by - 2 * step {
            // No slew while held; after it, about one count per hundred.
            let since = host - resumed;
            let owed = shared.lag();
            assert!(owed > 0, "at {host}");
            let expected = lag - since / SLEW_PARTS;
            assert!(
                owed.abs_diff(expected) <= step / SLEW_PARTS + 2,
                "at {host}: {owed}"
            );
        }
        if host % 1000 == 0 {
            repaid += shared.take_repaid();
        }
    }
    repaid += shared.take_repaid();
    assert_eq!((shared.lag(), repaid), (0, lag));
    assert_eq!(clocks[1].read(|| end), end, "back on the host's count");
    assert!(fired > lag * SLEW_PARTS / 1100, "{fired} timers fired");
}

#[test]
fn no_slew_runs_while_a_hold_is_in_force() {
    let (shared, mut first, second) = pair();
    // A first stop leaves lag, a second one holds the count again.
    assert!(first.leave(|| 2000, 0, false));
    second.look(|| 8000);
    first.resume(|| 8000, 0);
    let lag = shared.lag();
    assert_eq!(lag, 8000 - 3200);
    assert!(first.leave(|| 9000, 0, false));
    for host in (9000..40_000).step_by(50) {
        second.look(|| host);
    }
    assert_eq!(shared.take_repaid(), 0);
    first.resume(|| 40_000, 0);
    assert!(shared.lag() > lag);
}

#[test]
fn a_look_reads_no_slot_until_one_could_look_stalled() {
    // 256 PEs at 24 MHz, each marking every 10,000 host counts in turn.
    const PES: usize = 256;
    let frequency = 24_000_000;
    let (shared, mut clocks) = busy_clocks(PES, frequency);
    shared.loads.store(0, Ordering::Relaxed);
    let span = 10 * frequency;
    let mut retired = [0u64; PES];
    let mut looks = 0u64;
    for (turn, host) in (1000..1000 + span).step_by(10_000 / PES).enumerate() {
        let pe = turn % PES;
        let published = clocks[pe].shared.as_ref().unwrap().progress.published;
        retired[pe] += 1000;
        clocks[pe].mark(|| host, retired[pe], None);
        looks += u64::from(clocks[pe].shared.as_ref().unwrap().progress.published != published);
    }
    // A scan of every slot once a part of the limit (12.5 ms) at most.
    let suspect = frequency * STALL_MILLIS / 1000 / SUSPECT_PARTS;
    let scans = span / (suspect / 2) + 2;
    let loads = shared.loads.load(Ordering::Relaxed);
    assert!(looks > 30_000, "{looks} looks");
    assert!(
        loads <= scans * PES as u64,
        "{loads} slot loads for {looks} looks"
    );
    assert_eq!(shared.count(|| 1000 + span), 1000 + span);
    assert_eq!(shared.take_stalled(), 0);
}
