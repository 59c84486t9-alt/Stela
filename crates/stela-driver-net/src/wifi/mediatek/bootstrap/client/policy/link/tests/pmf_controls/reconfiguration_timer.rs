// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! AP removal countdowns and cancellation through the owning MLD station.
use super::*;
fn beacon(link: &TestLink, model: &Model, reconfiguration: Option<&[u8]>) {
    let mut elements = link
        .station()
        .association_context()
        .unwrap()
        .beacon()
        .elements
        .clone();
    if let Some(reconfiguration) = reconfiguration {
        elements.extend(reconfiguration);
    }
    let mut body = vec![0; 8];
    body.extend(100u16.to_le_bytes());
    body.extend(0x11u16.to_le_bytes());
    body.extend(elements);
    let mut frame = response(0x80, &body);
    frame[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(model, &frame, None, false);
}
fn removal(link: u8, count: u16) -> Vec<u8> {
    let mut element = vec![255, 11, 107, 2, 0, 1, 0, 5, link | 0x40, 0, 3];
    element.extend(count.to_le_bytes());
    element
}
fn clock(link: &TestLink) -> crate::Clock {
    link.state()
        .client
        .client
        .state()
        .controller
        .state()
        .control
        .clock
}
#[test]
fn announced_countdown_preserves_the_association_before_expiry() {
    let _time = crate::test_clock::virtualize();
    let (mut link, model) = authorized_two_link_association();
    let epoch = link.station().association_epoch();
    beacon(&link, &model, Some(&removal(1, 10)));
    link.service().unwrap();
    assert!(
        link.carrier(),
        "the AP still offers the link during its removal countdown"
    );
    assert_eq!(link.station().association_epoch(), epoch);
    crate::test_clock::advance(clock(&link), 500_000);
    link.service().unwrap();
    assert!(link.carrier());
    stop(&mut link, &model);
}
#[test]
fn empty_reconfiguration_cancels_a_pending_countdown() {
    let _time = crate::test_clock::virtualize();
    let (mut link, model) = authorized_two_link_association();
    beacon(&link, &model, Some(&removal(1, 10)));
    link.service().unwrap();
    beacon(&link, &model, Some(&[255, 4, 107, 2, 0, 1]));
    link.service().unwrap();
    crate::test_clock::advance(clock(&link), 1_100_000);
    link.service().unwrap();
    assert!(
        link.carrier(),
        "a cancelled countdown must not end the association"
    );
    assert_eq!(link.station().link_contexts().len(), 1);
    stop(&mut link, &model);
}
#[test]
fn absent_reconfiguration_keeps_the_countdown_and_reports_expiry_once() {
    let _time = crate::test_clock::virtualize();
    let (mut link, model) = authorized_two_link_association();
    beacon(&link, &model, Some(&removal(1, 10)));
    link.service().unwrap();
    assert!(link.carrier());
    beacon(&link, &model, None);
    link.service().unwrap();
    drop(drain_notices(&mut link));
    crate::test_clock::advance(clock(&link), 1_100_000);
    link.service().unwrap();
    // Runtime per-link retirement is still unsupported: this checks that the
    // existing degraded response happens at the deadline, including idle RX.
    let notices = drain_notices(&mut link);
    assert_eq!(
        notices
            .iter()
            .filter(|notice| matches!(
                notice.event,
                LinkEvent::Controller(Event::Unsupported(
                    "an AP MLD taking a link from an association: it ends"
                ))
            ))
            .count(),
        1
    );
    link.service().unwrap();
    assert!(
        !drain_notices(&mut link)
            .iter()
            .any(|notice| matches!(notice.event, LinkEvent::Controller(Event::Unsupported(_))))
    );
    while link.phase() == Phase::Removing {
        finish_tx(&model);
        link.service().unwrap();
    }
    retire(&mut link, &model);
}

#[test]
fn duplicate_timers_and_zero_initialization_follow_the_kernel_link_order() {
    let _time = crate::test_clock::virtualize();
    for first_link in [0, 1] {
        let (mut link, model) = authorized_two_link_association();
        let mut element = removal(first_link, 0);
        let last = removal(1, 10);
        element[1] += (last.len() - 6) as u8;
        element.extend(&last[6..]);
        beacon(&link, &model, Some(&element));
        link.service().unwrap();
        // mlme.c overwrites duplicate profiles' timers, and initializes a
        // zero delay again when the next link has a positive delay.
        assert!(link.carrier());
        crate::test_clock::advance(clock(&link), 500_000);
        link.service().unwrap();
        assert!(link.carrier());
        stop(&mut link, &model);
    }
}
#[test]
fn an_idle_vector_wakes_by_the_removal_deadline() {
    let _time = crate::test_clock::virtualize();
    let (link, model) = authorized_two_link_association();
    let mut link = link.with_vector();
    beacon(&link, &model, Some(&removal(1, 2)));
    link.service().unwrap();
    assert!(link.carrier());
    drop(drain_notices(&mut link));
    let upper = clock(&link).now_us().saturating_add(100 * 1024);
    crate::test_clock::advance(clock(&link), 90_000);
    assert!(link.signals());
    assert!(
        link.due_us().unwrap() <= upper,
        "idle sleep must not postpone AP removal"
    );
    stop(&mut link, &model);
}

#[test]
fn an_unassociated_link_does_not_start_a_countdown() {
    let _time = crate::test_clock::virtualize();
    let (mut link, model) = authorized_two_link_association();
    let epoch = link.station().association_epoch();
    beacon(&link, &model, Some(&removal(7, 0)));
    link.service().unwrap();
    crate::test_clock::advance(clock(&link), 1_100_000);
    link.service().unwrap();
    assert!(link.carrier());
    assert_eq!(link.station().association_epoch(), epoch);
    assert_eq!(link.station().link_contexts().len(), 1);
    stop(&mut link, &model);
}
