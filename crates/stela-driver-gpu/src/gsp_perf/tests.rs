use super::*;
use alloc::string::ToString;

/// A report as nouveau leaves it after `rounds` rounds at `pstate`, with
/// GPC samples `gpc` and memory samples `mem`, in MHz.
fn sampled(rounds: u32, pstate: u32, gpc: &[u32], mem: &[u32]) -> Report {
    let report = Report::new();
    report.started.store(1, Ordering::Relaxed);
    report.rounds.store(rounds, Ordering::Relaxed);
    report.pstate.store(pstate, Ordering::Relaxed);
    report.pstates.fetch_or(pstate, Ordering::Relaxed);
    for &mhz in gpc {
        report.gpc_min_mhz.fetch_min(mhz, Ordering::Relaxed);
        report.gpc_max_mhz.fetch_max(mhz, Ordering::Relaxed);
        report
            .gpc_sum_mhz
            .fetch_add(u64::from(mhz), Ordering::Relaxed);
        report.gpc_samples.fetch_add(1, Ordering::Relaxed);
    }
    for &mhz in mem {
        report.mem_min_mhz.fetch_min(mhz, Ordering::Relaxed);
        report.mem_max_mhz.fetch_max(mhz, Ordering::Relaxed);
    }
    report
}

const P0: u32 = 1;
const P8: u32 = 1 << 8;

#[test]
fn the_layout_is_nouveaus() {
    // `struct nvkm_perf_report`: twelve 32-bit words, then the sum.
    assert_eq!(core::mem::size_of::<Report>(), 56);
    assert_eq!(core::mem::offset_of!(Report, pstate_status), 36);
    assert_eq!(core::mem::offset_of!(Report, gpc_sum_mhz), 48);
}

#[test]
fn nothing_is_taken_before_gsp_starts_or_without_a_round() {
    let report = Report::new();
    report.rounds.store(3, Ordering::Relaxed);
    assert_eq!(report.take(), None);
    let report = sampled(0, P8, &[], &[]);
    assert_eq!(report.take(), None);
}

#[test]
fn a_take_clears_the_counts_and_keeps_the_current_pstate() {
    let report = sampled(10, P8, &[210, 2520, 1200], &[405, 10501]);
    report.pstates.fetch_or(P0, Ordering::Relaxed);
    let taken = report.take().unwrap();
    assert_eq!(
        taken,
        Taken {
            rounds: 10,
            pstate: P8,
            pstates: P0 | P8,
            gpc: Some(Clocks {
                min: 210,
                mean: 1310,
                max: 2520
            }),
            samples: 3,
            mem: Some((405, 10501)),
            pstate_status: 0,
            clk_status: 0,
        }
    );
    assert_eq!(
        taken.to_string(),
        "pstate=P8 seen=P0+P8 gpc_mhz=210/1310/2520 mem_mhz=405/10501 samples=3 rounds=10"
    );
    // The next beat starts empty but for the P-state RM last gave.
    report.rounds.store(1, Ordering::Relaxed);
    let next = report.take().unwrap();
    assert_eq!(
        (next.pstate, next.pstates, next.gpc, next.mem),
        (P8, 0, None, None)
    );
    assert_eq!(
        next.to_string(),
        "pstate=P8 seen=- gpc_mhz=- mem_mhz=- samples=0 rounds=1"
    );
}

#[test]
fn a_refused_control_is_named_with_its_errno() {
    let report = sampled(4, 0, &[], &[]);
    report.pstate_status.store(-22, Ordering::Relaxed);
    report.clk_status.store(-34, Ordering::Relaxed);
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=unknown(error -22) clocks=unknown(error -34) samples=0 rounds=4"
    );
}

#[test]
fn a_line_comes_first_and_then_only_when_the_state_changes() {
    let reported = Reported::new();
    let idle = sampled(10, P8, &[210, 225], &[405]).take().unwrap();
    assert_eq!(
        reported.line(&idle).as_deref(),
        Some("GPU PERF pstate=P8 seen=P8 gpc_mhz=210/217/225 mem_mhz=405/405 samples=2 rounds=10")
    );
    // Counts, the mean and steps within a bucket are no change.
    let again = sampled(9, P8, &[212, 230, 240], &[420]).take().unwrap();
    assert_eq!(reported.line(&again), None);
    // Load raises the P-state and the clocks.
    let busy = sampled(10, P0, &[210, 2520], &[405, 10501]).take().unwrap();
    assert!(
        reported
            .line(&busy)
            .unwrap()
            .starts_with("GPU PERF pstate=P0 seen=P0 ")
    );
    assert_eq!(reported.line(&busy), None);
    // A control refused later is a change.
    let report = sampled(10, P0, &[210, 2520], &[405, 10501]);
    report.clk_status.store(-22, Ordering::Relaxed);
    assert!(reported.line(&report.take().unwrap()).is_some());
}
