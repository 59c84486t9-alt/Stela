use super::*;
use alloc::string::ToString;

/// A report as nouveau leaves it after `rounds` rounds that saw `seen`,
/// the last at `pstate`.
fn sampled(rounds: u32, pstate: u32, seen: u32) -> Report {
    let report = Report::new();
    report.started.store(1, Ordering::Relaxed);
    report.rounds.store(rounds, Ordering::Relaxed);
    report.pstate.store(pstate, Ordering::Relaxed);
    report.pstates.store(seen | pstate, Ordering::Relaxed);
    report
}

const P0: u32 = 1;
const P5: u32 = 1 << 5;
const P8: u32 = 1 << 8;

#[test]
fn the_layout_is_nouveaus() {
    // `struct nvkm_perf_report`: five 32-bit words.
    assert_eq!(core::mem::size_of::<Report>(), 20);
    assert_eq!(core::mem::offset_of!(Report, pstate_status), 16);
}

#[test]
fn nothing_is_taken_before_gsp_starts_or_without_a_round() {
    let report = Report::new();
    report.rounds.store(3, Ordering::Relaxed);
    assert_eq!(report.take(), None);
    assert_eq!(sampled(0, P8, 0).take(), None);
}

#[test]
fn a_take_clears_the_counts_and_keeps_the_current_pstate() {
    let report = sampled(10, P8, P5);
    let taken = report.take().unwrap();
    assert_eq!(
        taken,
        Taken {
            rounds: 10,
            pstate: P8,
            pstates: P5 | P8,
            status: 0,
        }
    );
    assert_eq!(taken.to_string(), "pstate=P8 seen=P5+P8 rounds=10");
    // The next beat starts empty but for the P-state RM last gave.
    report.rounds.store(1, Ordering::Relaxed);
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=P8 seen=- rounds=1"
    );
}

#[test]
fn a_refused_control_is_named_with_its_errno() {
    let report = sampled(1, 0, 0);
    report.pstate_status.store(-22, Ordering::Relaxed);
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=unknown(error -22) rounds=1"
    );
}

#[test]
fn a_line_comes_first_and_then_only_when_the_state_changes() {
    let reported = Reported::new();
    let idle = sampled(10, P8, 0).take().unwrap();
    assert_eq!(
        reported.line(&idle).as_deref(),
        Some("GPU PERF pstate=P8 seen=P8 rounds=10")
    );
    // The count of rounds is no change.
    assert_eq!(reported.line(&sampled(9, P8, 0).take().unwrap()), None);
    // Load raises the P-state.
    let busy = sampled(10, P0, P8).take().unwrap();
    assert_eq!(
        reported.line(&busy).as_deref(),
        Some("GPU PERF pstate=P0 seen=P0+P8 rounds=10")
    );
    assert_eq!(reported.line(&busy), None);
}
