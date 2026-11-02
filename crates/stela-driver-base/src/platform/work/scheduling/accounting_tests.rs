//! Exact native ledger arithmetic, independent of source credentials/clock grants.
use super::*;
fn enabled() -> Board {
    let mut b = Board::new();
    b.enabled = true;
    b
}
#[test]
fn unweighted_cpu_is_distinct_from_nice_and_queries_do_not_double_charge() {
    let mut b = enabled();
    let id = ContextId(1);
    b.insert(id, 9, false).unwrap();
    let nice = Snapshot {
        base: BasePolicy::NormalNice(-20),
        effective: 100,
    };
    b.update(id, 9, Snapshot::NORMAL, nice, false, Some(0))
        .unwrap();
    b.running(id, 9, 100).unwrap();
    assert_eq!(b.execution(id, 9, 110), Ok((10, 110, 100)));
    assert_eq!(b.execution(id, 9, 110), Ok((10, 110, 100)));
    b.account(110).unwrap();
    b.account(110).unwrap();
    assert_eq!(b.execution(id, 9, 120), Ok((20, 120, 100)));
    let r = b.rows[b.index(id, 9).unwrap()].unwrap();
    assert_eq!(r.execution_ns, 10);
    assert_eq!(r.virtual_ns, (10u128 << 32) * 1024 / 88761);
    b.account(120).unwrap();
    b.suspend(id, 9, LeaveReason::Blocked).unwrap();
    assert_eq!(b.execution(id, 9, 1_000_000), Ok((20, 120, 100)));
    assert_eq!(b.activity(id, 9), Ok(Activity::Blocked));
    b.wake(id, 9).unwrap();
    assert_eq!(b.activity(id, 9), Ok(Activity::Ready));
    b.running(id, 9, 1_000_000).unwrap();
    assert_eq!(
        b.execution(id, 9, 1_000_030),
        Ok((50, 1_000_030, 1_000_000))
    );
}
#[test]
fn sequence_replacement_resets_metric_while_retaining_scheduler_debt() {
    let mut b = enabled();
    let id = ContextId(1);
    b.insert(id, 1, false).unwrap();
    b.running(id, 1, 10).unwrap();
    b.account(110).unwrap();
    b.remove(id, 1).unwrap();
    b.insert(id, 2, false).unwrap();
    assert_eq!(b.execution(id, 1, 120), Err(WorkError::Closed));
    assert_eq!(b.execution(id, 2, 120), Ok((0, 0, 0)));
    assert!(b.rows[b.index(id, 2).unwrap()].unwrap().virtual_ns > 0);
    b.running(id, 2, 120).unwrap();
    assert_eq!(b.execution(id, 2, 130), Ok((10, 130, 120)));
}
#[test]
fn invalid_counter_and_overflow_leave_all_metric_fields_unmodified() {
    let mut b = enabled();
    let id = ContextId(1);
    b.insert(id, 1, false).unwrap();
    b.running(id, 1, 100).unwrap();
    assert_eq!(b.account(99), Err(WorkError::CorruptContext));
    let i = b.index(id, 1).unwrap();
    let before = b.rows[i].unwrap();
    assert_eq!((before.execution_ns, before.started_ns), (0, 100));
    b.rows[i].as_mut().unwrap().execution_ns = u64::MAX;
    assert_eq!(b.account(101), Err(WorkError::Exhausted));
    let after = b.rows[i].unwrap();
    assert_eq!(
        (after.execution_ns, after.started_ns, after.virtual_ns),
        (u64::MAX, 100, before.virtual_ns)
    );
    assert_eq!(b.execution(id, 1, 101), Err(WorkError::Exhausted));
}
#[test]
fn only_one_actual_row_runs_and_disabled_activity_is_unavailable() {
    let mut b = Board::new();
    assert_eq!(b.activity(ContextId(1), 1), Err(WorkError::Unavailable));
    assert_eq!(b.execution(ContextId(1), 1, 5), Err(WorkError::Unavailable));
    b.enabled = true;
    b.insert(ContextId(1), 1, false).unwrap();
    b.insert(ContextId(2), 2, false).unwrap();
    b.running(ContextId(1), 1, 1).unwrap();
    assert_eq!(
        b.running(ContextId(2), 2, 2),
        Err(WorkError::CorruptContext)
    );
    assert_eq!(b.activity(ContextId(2), 2), Ok(Activity::Ready));
    b.account(2).unwrap();
    b.suspend(ContextId(1), 1, LeaveReason::Yield).unwrap();
    b.running(ContextId(2), 2, 3).unwrap();
    assert_eq!(b.execution(ContextId(1), 1, 100), Ok((1, 2, 1)));
}
