//! Root-path invalidation/drain completion and failure retention.
use super::*;

#[test]
fn requester_drain_covers_its_aliases_without_replacing_mappings() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0]);
    // SAFETY: the isolated synchronous peer has no active producers or IRQ/work.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let pages = peer.pages(4096);
    let physical = pages.physical_pages()[0];
    let mapping = requester
        .map(pages.into(), Direction::FromDevice, u32::MAX as u64)
        .unwrap();
    for rid in [0x20, 0x21] {
        assert_eq!(
            peer.walk(rid, mapping.address()),
            Some((physical, false, true))
        );
    }
    let before = peer.commands().len();
    requester.drain_posted_writes().unwrap();
    let commands = peer.commands();
    let added = &commands[before..];
    assert_eq!(added.len(), 4);
    assert_eq!(added[0], [0x20, 2 << 28, 0, 0]);
    assert_eq!(added[2], [0x21, 2 << 28, 0, 0]);
    for command in [added[1], added[3]] {
        assert_eq!(command[1] >> 28, 1);
        assert_eq!(command[0] & 7, 1, "exact store, no fabricated drain bit");
    }
    assert_eq!(
        u64::from(added[3][2]) | u64::from(added[3][3]) << 32,
        (u64::from(added[1][2]) | u64::from(added[1][3]) << 32) + 1
    );
    for rid in [0x20, 0x21] {
        assert_eq!(
            peer.walk(rid, mapping.address()),
            Some((physical, false, true))
        );
    }
    // SAFETY: this test has no device/IRQ/work access to the retained pins.
    unsafe { requester.unmap(&mapping) }.unwrap();
    // SAFETY: all modeled mappings and device/IRQ/work accesses have retired.
    unsafe { requester.detach() }.unwrap();
    let before = peer.commands();
    assert_eq!(
        requester.drain_posted_writes(),
        Err(DmaError::InvalidationFailed)
    );
    assert_eq!(
        peer.commands(),
        before,
        "retired requester performs no MMIO"
    );
}

#[test]
fn unit_drain_requires_invalidation_followed_by_exact_completion() {
    let (mut unit, peer) = model::unit();
    let before = peer.commands().len();
    peer.mode(Mode::StoreBeforeHead);
    unit.drain_posted_writes().unwrap();
    let commands = peer.commands();
    assert_eq!(commands.len() - before, 2);
    assert_eq!(commands[before], [0, 8 << 28, 0, 0]);
    assert_eq!(commands[before + 1][1] >> 28, 1);
    // SAFETY: the cold model has no attached requesters or active DMA/work.
    unsafe { unit.retire() }.unwrap();
    let before = peer.commands();
    assert_eq!(
        unit.drain_posted_writes(),
        Err(DmaError::InvalidationFailed)
    );
    assert_eq!(peer.commands(), before);
}

#[test]
fn an_unacknowledged_drain_keeps_root_payload_and_configuration_owners() {
    for mode in [
        Mode::HeadOnly,
        Mode::OldStore,
        Mode::FutureStore,
        Mode::BadHead,
        Mode::Halt,
        Mode::Event,
        Mode::Overflow,
        Mode::HardwareError,
        Mode::AlterBase,
    ] {
        let (mut unit, peer) = model::unit();
        let (function, counters) = function_with_counters(0x20);
        // SAFETY: the isolated synchronous model has no active DMA/IRQ/work.
        let mut requester = unsafe { unit.attach(function) }.unwrap();
        let pages = peer.pages(4096);
        let physical = pages.physical_pages()[0];
        let _mapping = requester
            .map(pages.into(), Direction::FromDevice, u32::MAX as u64)
            .unwrap();
        let root = unit.table.borrow().snapshot(0x20).unwrap()[0] & 0x000f_ffff_ffff_f000;
        peer.mode(mode);
        assert_eq!(
            requester.drain_posted_writes(),
            Err(DmaError::InvalidationFailed),
            "{mode:?}"
        );
        let commands = peer.commands();
        assert_eq!(
            requester.drain_posted_writes(),
            Err(DmaError::InvalidationFailed)
        );
        assert_eq!(
            peer.commands(),
            commands,
            "poisoned drain cannot submit again"
        );
        drop(requester);
        drop(unit);
        assert!(peer.retains(physical), "{mode:?}");
        assert!(peer.retains(root), "original hardware root: {mode:?}");
        assert_eq!(
            counters
                .resource_drops
                .load(core::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            counters
                .platform_drops
                .load(core::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            counters.unmaps.load(core::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}

#[test]
fn requester_drain_completes_alias_writes_and_leaves_other_domains_pending() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0, 2, 0x28, 0, 0]);
    // SAFETY: isolated synchronous model; no earlier DMA, IRQ or work exists.
    let mut first = unsafe { unit.attach(function(0x20)) }.unwrap();
    // SAFETY: the second function has its own original configuration owner.
    let mut other = unsafe { unit.attach(function(0x28)) }.unwrap();
    let pages = peer.pages(4096);
    let first_pa = pages.physical_pages()[0];
    let a = first
        .map(pages.into(), Direction::FromDevice, u32::MAX as u64)
        .unwrap();
    let pages = peer.pages(4096);
    let other_pa = pages.physical_pages()[0];
    let b = other
        .map(pages.into(), Direction::FromDevice, u32::MAX as u64)
        .unwrap();
    peer.post_write(0x20, a.address(), 0x12345678);
    peer.post_write(0x21, a.address() + 4, 0x87654321);
    peer.post_write(0x28, b.address(), 0xfeedbeef);
    assert_eq!(peer.payload_word(first_pa), 0);
    assert_eq!(peer.payload_word(first_pa + 4), 0);
    assert_eq!(peer.payload_word(other_pa), 0);
    first.drain_posted_writes().unwrap();
    assert_eq!(peer.payload_word(first_pa), 0x12345678);
    assert_eq!(peer.payload_word(first_pa + 4), 0x87654321);
    assert_eq!(
        peer.payload_word(other_pa),
        0,
        "an unrelated requester remains pending"
    );
    unit.drain_posted_writes().unwrap();
    assert_eq!(peer.payload_word(other_pa), 0xfeedbeef);
    // SAFETY: queued writes have completed; no producer or IRQ/work can resume.
    unsafe { first.unmap(&a) }.unwrap();
    // SAFETY: queued writes have completed; no producer or IRQ/work can resume.
    unsafe { other.unmap(&b) }.unwrap();
    // SAFETY: the first requester has no remaining mappings or device users.
    unsafe { first.detach() }.unwrap();
    // SAFETY: the second requester has no remaining mappings or device users.
    unsafe { other.detach() }.unwrap();
    drop(first);
    drop(other);
    // SAFETY: every covered requester and all model transactions have retired.
    unsafe { unit.retire() }.unwrap();
}

#[test]
fn initial_window_drain_rejects_private_contexts_including_aliases() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0]);
    let pages = peer.pages(4096);
    let physical = pages.physical_pages()[0];
    // SAFETY: original isolated cold peer; this pin is the only window target
    // and remains owned by the unit until its acknowledged retirement.
    unsafe { unit.window(&[0x20], vec![pages.into()]) }.unwrap();
    peer.post_write(0x21, physical, 0x98765432);
    assert_eq!(peer.payload_word(physical), 0);
    unit.drain_initial_requester(0x20).unwrap();
    assert_eq!(peer.payload_word(physical), 0x98765432);
    let before = peer.commands();
    assert_eq!(
        unit.drain_initial_requester(0x28),
        Err(DmaError::IommuUnavailable)
    );
    assert_eq!(peer.commands(), before);
    // SAFETY: prior payload completed above; this peer has no IRQ/work users
    // and no producer can restart while attachment replaces the original DTE.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let before = peer.commands();
    for rid in [0x20, 0x21] {
        assert_eq!(
            unit.drain_initial_requester(rid),
            Err(DmaError::IommuUnavailable)
        );
    }
    assert_eq!(
        peer.commands(),
        before,
        "private aliases must not use an old-root receipt"
    );
    // SAFETY: no mappings or producers exist in the fresh private domain.
    unsafe { requester.detach() }.unwrap();
    drop(requester);
    // SAFETY: every covered requester and earlier window transaction retired.
    unsafe { unit.retire() }.unwrap();
}
