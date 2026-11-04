//! Bounded scheduler ledger controls; no C/native execution authority supplied.
use super::*;
#[test]
fn dormant_activation_reserves_last_real_order_credit_before_publication() {
    let mut board = Board::new();
    board.enabled = true;
    board.tail = u64::MAX - 1;
    board
        .insert_dormant(ContextId(11), 1, Snapshot::NORMAL)
        .unwrap();
    assert_eq!(board.reserved_tail, 1);
    assert_eq!(
        board.rows[board.index(ContextId(11), 1).unwrap()]
            .unwrap()
            .state,
        State::Dormant
    );
    // A competing ordinary stamp cannot consume the actual reserved wake.
    assert_eq!(
        board.insert(ContextId(12), 2, false),
        Err(WorkError::Exhausted)
    );
    assert_eq!(board.tail, u64::MAX - 1);
    assert_eq!(board.reserved_tail, 1);
    board.activate(ContextId(11), 1).unwrap();
    assert_eq!(board.tail, u64::MAX);
    assert_eq!(board.reserved_tail, 0);
    assert_eq!(
        board.rows[board.index(ContextId(11), 1).unwrap()]
            .unwrap()
            .state,
        State::Ready
    );
    assert_eq!(
        board.activate(ContextId(11), 1),
        Err(WorkError::CorruptContext)
    );
}
#[test]
fn exhausted_order_refuses_before_any_dormant_row_or_credit_publication() {
    let mut board = Board::new();
    board.enabled = true;
    board.tail = u64::MAX;
    assert_eq!(
        board.insert_dormant(ContextId(11), 1, Snapshot::NORMAL),
        Err(WorkError::Exhausted)
    );
    assert_eq!(board.reserved_tail, 0);
    assert!(board.rows.iter().all(Option::is_none));
}
#[test]
fn dormant_rows_do_not_raise_the_real_running_normal_service_floor() {
    let mut board = Board::new();
    board.enabled = true;
    board.fair_normal = true;
    board.normal_history[0] = (11, 123456);
    board
        .insert_dormant(ContextId(11), 1, Snapshot::NORMAL)
        .unwrap();
    assert_eq!(board.normal_floor(), 0);
    board.insert(ContextId(12), 2, false).unwrap();
    assert_eq!(
        board.rows[board.index(ContextId(12), 2).unwrap()]
            .unwrap()
            .virtual_ns,
        0
    );
    board.activate(ContextId(11), 1).unwrap();
    assert_eq!(
        board.rows[board.index(ContextId(11), 1).unwrap()]
            .unwrap()
            .virtual_ns,
        123456
    );
}
#[test]
fn outgoing_yield_preflight_preserves_actual_reserved_activation_credit() {
    let mut board = Board::new();
    board.enabled = true;
    board.insert(ContextId(12), 2, false).unwrap();
    board.running(ContextId(12), 2, 0).unwrap();
    board.tail = u64::MAX - 1;
    board
        .insert_dormant(ContextId(11), 1, Snapshot::NORMAL)
        .unwrap();
    assert_eq!(
        board.can_suspend(ContextId(12), 2, LeaveReason::Yield),
        Err(WorkError::Exhausted)
    );
    assert_eq!(board.reserved_tail, 1);
    board.activate(ContextId(11), 1).unwrap();
}
#[test]
fn actual_initial_rank_is_validated_and_preserved_before_dormant_publication() {
    let mut board = Board::new();
    board.enabled = true;
    let invalid = Snapshot {
        base: BasePolicy::Fifo(0),
        effective: 0,
    };
    assert_eq!(
        board.insert_dormant(ContextId(11), 1, invalid),
        Err(WorkError::Unavailable)
    );
    assert!(board.rows.iter().all(Option::is_none));
    assert_eq!(board.reserved_tail, 0);
    let actual = Snapshot {
        base: BasePolicy::Fifo(7),
        effective: 92,
    };
    board.insert_dormant(ContextId(11), 1, actual).unwrap();
    assert_eq!(board.snapshot(ContextId(11), 1), Ok(actual));
    board.activate(ContextId(11), 1).unwrap();
    assert_eq!(board.snapshot(ContextId(11), 1), Ok(actual));
}
#[test]
fn dormant_source_publication_requires_the_actual_enabled_scheduler() {
    let mut board = Board::new();
    let rank = Snapshot {
        base: BasePolicy::Fifo(7),
        effective: 92,
    };
    assert_eq!(
        board.insert_dormant(ContextId(11), 1, rank),
        Err(WorkError::Unavailable)
    );
    assert_eq!(
        board.activate(ContextId(11), 1),
        Err(WorkError::Unavailable)
    );
    assert!(board.rows.iter().all(Option::is_none));
    assert_eq!(board.reserved_tail, 0);
}

#[test]
fn reserved_child_rejects_inherited_pi_and_releases_capacity_on_cancel() {
    let mut board = Board::new();
    board.enabled = true;
    let normal = Snapshot::NORMAL;
    let boosted = Snapshot {
        effective: 5,
        ..normal
    };
    let id = ContextId(17);

    assert_eq!(
        board.reserve_child(id, 1, boosted),
        Err(WorkError::Unavailable)
    );
    assert_eq!(board.reserved_tail, 0);
    let rank = Snapshot {
        base: BasePolicy::NormalNice(-2),
        effective: 118,
    };
    board.reserve_child(id, 1, rank).unwrap();
    assert_eq!(board.activity(id, 1), Err(WorkError::Pending));
    assert!(board.activate(id, 1).is_err());
    assert!(!board.fair_normal);
    let slot = board.reserved_child(id, 1, rank).unwrap();
    board.cancel_reserved_child(slot);
    assert_eq!(board.reserved_tail, 0);
    assert!(
        board
            .normal_history
            .iter()
            .all(|history| *history == (0, 0))
    );

    board.reserve_child(id, 2, rank).unwrap();
    let slot = board.reserved_child(id, 2, rank).unwrap();
    board.publish_reserved_child(slot);
    assert_eq!(board.activity(id, 2), Ok(Activity::Dormant));
    assert!(board.fair_normal);
    board.activate(id, 2).unwrap();
    assert_eq!(board.reserved_tail, 0);
    assert_eq!(board.snapshot(id, 2), Ok(rank));
}
