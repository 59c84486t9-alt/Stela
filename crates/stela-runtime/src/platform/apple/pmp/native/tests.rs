use super::*;
use alloc::format;
use {
    crate::platform::apple::ptd::Ptd, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::Width, stela_contracts::interrupt::InterruptLatch,
};

const IDS: [u32; 15] = [1, 2, 3, 4, 5, 6, 7, 0, 0, 9, 10, 11, 12, 13, 0];
const PACKETS: Packets = Packets([
    0x0123456789abcdef,
    0xfedcba9876543210,
    7,
    0x8000000000000001,
    99,
    101,
]);
const OBSERVER_PACKETS: Packets = Packets([42, 43, 44, 45, 46, 47]);

fn life() -> LifecycleState {
    LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    }
}
fn local() -> LocalNotifications {
    let ranges: Vec<_> = [
        (1, 0, 1),
        (2, 1, 1),
        (3, 8, 4),
        (4, 12, 4),
        (5, 16, 16),
        (6, 32, 16),
        (7, 48, 16),
        (9, 64, 184),
        (10, 248, 8),
        (11, 256, 8),
        (12, 264, 40),
        (13, 304, 11),
    ]
    .into_iter()
    .map(|(id, start, count)| Range {
        id,
        start,
        count,
        name: format!("source range{id}"),
    })
    .collect();
    Ptd::initialized_local(384, &ranges, life()).unwrap().1
}
struct Backend {
    groups: u32,
    refresh_busy: bool,
    refresh_calls: Vec<Request>,
    observer_snapshot: bool,
    calls: Vec<(Effect, Request)>,
    targets: Vec<PublicationTarget>,
    before: Option<Effect>,
    after: Option<Effect>,
    busy: Option<Effect>,
}
impl Backend {
    fn new() -> Self {
        Self {
            groups: 3,
            refresh_busy: false,
            refresh_calls: Vec::new(),
            observer_snapshot: false,
            calls: Vec::new(),
            targets: Vec::new(),
            before: None,
            after: None,
            busy: None,
        }
    }
}
impl Resources for Backend {
    fn inventory(&self) -> Inventory {
        Inventory {
            power_groups: self.groups,
        }
    }
    fn refresh_power_states(&mut self, request: &Request, _: &mut Access<'_>) -> Refresh {
        self.refresh_calls.push(request.clone());
        if core::mem::take(&mut self.refresh_busy) {
            Refresh::Busy { deadline: Some(17) }
        } else {
            self.observer_snapshot = false;
            Refresh::Retired {
                packets: PACKETS,
                refusal: None,
            }
        }
    }
    fn snapshot_observer_packets(&mut self, _: &Request, _: &mut Access<'_>) -> Refresh {
        self.observer_snapshot = true;
        Refresh::Retired {
            packets: OBSERVER_PACKETS,
            refusal: None,
        }
    }
    fn effect(
        &mut self,
        request: &Request,
        effect: Effect,
        target: Option<&PublicationTarget>,
        packets: &Packets,
        _: &mut Access<'_>,
    ) -> Step {
        assert_eq!(
            *packets,
            if self.observer_snapshot {
                OBSERVER_PACKETS
            } else {
                PACKETS
            }
        );
        self.calls.push((effect, request.clone()));
        if self.before == Some(effect) {
            self.before = None;
            return Step::Refused("actual device effect unavailable");
        }
        if self.busy == Some(effect) {
            self.busy = None;
            return Step::Busy { deadline: Some(31) };
        }
        if let Effect::BindPacketSource(_) = effect {
            self.targets.push(target.unwrap().clone());
        }
        if self.after == Some(effect) {
            self.after = None;
            return Step::Retired {
                refusal: Some("later native callback refused"),
            };
        }
        Step::Retired { refusal: None }
    }
}
fn step(
    owner: &mut Owner<Backend>,
    latch: &mut InterruptLatch,
    now: u64,
) -> Result<Progress, Error> {
    owner.advance(&mut Access::new(0, now, latch))
}
fn latest(local: &LocalNotifications, entry: u32) -> Option<u64> {
    local
        .bank()
        .requests()
        .iter()
        .rfind(|r| r.entry == entry)
        .map(|r| r.value)
}

#[test]
fn refresh_busy_precedes_actual_publication_and_all_source_effects_precede_status() {
    let local = local();
    let mut backend = Backend::new();
    backend.refresh_busy = true;
    backend.busy = Some(Effect::EnableEventInterrupts);
    let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
    assert!(owner.notifications().owns(local.bank()));
    let mut latch = InterruptLatch::new();
    owner.begin_startup().unwrap();
    assert_eq!(
        step(&mut owner, &mut latch, 1).unwrap(),
        Progress::Busy { deadline: Some(17) }
    );
    assert_eq!(owner.committed_prefix(), 0);
    assert!(local.bank().requests().is_empty());
    assert_eq!(
        step(&mut owner, &mut latch, 17).unwrap(),
        Progress::Busy { deadline: Some(31) }
    );
    assert_eq!(owner.phase(), Phase::Starting);
    assert_eq!(latest(&local, 1), None);
    for entry in 8..12 {
        assert_eq!(
            latest(&local, entry),
            Some(PACKETS.0[usize::try_from(entry - 8).unwrap()])
        );
    }
    assert_eq!(owner.resources().targets.len(), 4);
    for (target, start, count) in owner
        .resources()
        .targets
        .iter()
        .zip([16, 32, 48, 64])
        .zip([16, 16, 16, 184])
        .map(|((t, s), c)| (t, s, c))
    {
        assert!(target.owns(&local));
        assert_eq!(target.range().start, start);
        assert_eq!(target.range().count, count);
    }
    let requests = local.bank().requests();
    assert_eq!(requests.len(), 4);
    assert!(owner.begin_exit().is_err());
    assert_eq!(step(&mut owner, &mut latch, 31).unwrap(), Progress::Idle);
    assert_eq!(owner.phase(), Phase::Active);
    assert_eq!(latest(&local, 1), Some(1));
    assert_eq!(local.bank().requests()[..4], requests);
    assert_eq!(owner.resources().refresh_calls.len(), 2);
    assert!(owner.resources().refresh_calls[0].same_operation(&owner.resources().refresh_calls[1]));
    let busy: Vec<_> = owner
        .resources()
        .calls
        .iter()
        .filter(|(e, _)| *e == Effect::EnableEventInterrupts)
        .collect();
    assert_eq!(busy.len(), 2);
    assert!(busy[0].1.same_operation(&busy[1].1));
    assert!(latch.take_aic_inputs().is_empty());
}

#[test]
fn actual_routes_masks_and_device_targets_share_bank_without_ordinal_ap_wires() {
    let local = local();
    let mut bank = local.bank().clone();
    let mut latch = InterruptLatch::new();
    // Unselected neighbor survives route RMW and W1S control.
    bank.write(
        0x18400,
        Width::Word,
        0x30,
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    bank.write(0x18200, Width::Word, 2, &mut Access::new(0, 0, &mut latch))
        .unwrap();
    let mut owner = Owner::initialized(local.clone(), IDS, Backend::new()).unwrap();
    owner.begin_startup().unwrap();
    step(&mut owner, &mut latch, 9).unwrap();
    for (first, last, route) in [
        (0u32, 0u32, 0u64),
        (12, 15, 1),
        (248, 255, 4),
        (264, 303, 5),
        (304, 314, 6),
    ] {
        for entry in first..=last {
            let word = bank
                .read(
                    0x18400 + u64::from(entry / 8) * 4,
                    Width::Word,
                    &mut Access::new(0, 9, &mut latch),
                )
                .unwrap();
            assert_eq!(word >> ((entry % 8) * 4) & 0xf, route);
            transport::publish(&local, entry, 123, &mut Access::new(0, 9, &mut latch)).unwrap();
            assert_eq!(local.asserted(), (1 << 3) | (1 << route));
            bank.consume_entry(entry, &mut Access::new(0, 9, &mut latch))
                .unwrap();
            assert_eq!(local.asserted(), 1 << 3);
        }
    }
    assert_eq!(
        bank.read(0x18400, Width::Word, &mut Access::new(0, 9, &mut latch))
            .unwrap()
            & 0xf0,
        0x30
    );
    assert_eq!(local.asserted(), 1 << 3); // STATUS pending on the separately enabled route3.
    let target = &owner.resources().targets[0];
    target
        .publish(15, 55, &mut Access::new(0, 10, &mut latch))
        .unwrap();
    assert_eq!(latest(&local, 31), Some(55));
    let prefix = bank.requests();
    assert!(
        target
            .publish(16, 99, &mut Access::new(0, 11, &mut latch))
            .is_err()
    );
    assert_eq!(bank.requests(), prefix);
    assert!(!target.owns(&self::local()));
    assert!(latch.take_aic_inputs().is_empty());
}

#[test]
fn every_backend_refusal_preserves_prefix_and_post_effect_refusal_never_replays() {
    let effects = [
        Effect::BindPacketSource(Family::Pmgr),
        Effect::BindPacketSource(Family::Dpe),
        Effect::BindPacketSource(Family::Device),
        Effect::BindPacketSource(Family::SocDevice),
        Effect::EnableDirectPublishers,
        Effect::NotifyPacketObservers,
        Effect::StartFastDie,
        Effect::ClearAccountingMasks,
        Effect::StartControlLoops,
        Effect::EnableAggregateInterrupt,
        Effect::EnableDeviceInterrupts,
        Effect::EnablePowerActions,
        Effect::EnableEventInterrupts,
    ];
    for effect in effects {
        let local = local();
        let mut backend = Backend::new();
        backend.before = Some(effect);
        let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
        let mut latch = InterruptLatch::new();
        owner.begin_startup().unwrap();
        assert!(matches!(
            step(&mut owner, &mut latch, 1),
            Err(Error::Backend(_))
        ));
        let cursor = owner.committed_prefix();
        let prefix = local.bank().requests();
        assert_eq!(latest(&local, 1), None);
        assert_eq!(owner.refusal(), Some("actual device effect unavailable"));
        assert!(owner.begin_startup().is_err());
        let mut bank = local.bank().clone();
        bank.set_lifecycle(
            LifecycleState {
                clocked: false,
                ..life()
            },
            &mut Access::new(0, 2, &mut latch),
        );
        assert!(matches!(
            step(&mut owner, &mut latch, 2),
            Err(Error::Contract(_))
        ));
        assert_eq!(owner.committed_prefix(), cursor);
        assert_eq!(local.bank().requests(), prefix);
        bank.set_lifecycle(life(), &mut Access::new(0, 3, &mut latch));
        step(&mut owner, &mut latch, 3).unwrap();
        assert_eq!(owner.phase(), Phase::Active);
        assert_eq!(local.bank().requests()[..prefix.len()], prefix);
        let calls: Vec<_> = owner
            .resources()
            .calls
            .iter()
            .filter(|(e, _)| *e == effect)
            .collect();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].1.same_operation(&calls[1].1));
    }
    let local = local();
    let mut backend = Backend::new();
    backend.after = Some(Effect::EnableEventInterrupts);
    let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
    let mut latch = InterruptLatch::new();
    owner.begin_startup().unwrap();
    assert!(step(&mut owner, &mut latch, 1).is_err());
    assert_eq!(owner.pending_operations(), 1);
    assert_eq!(latest(&local, 1), None);
    step(&mut owner, &mut latch, 2).unwrap();
    assert_eq!(latest(&local, 1), Some(1));
    assert_eq!(
        owner
            .resources()
            .calls
            .iter()
            .filter(|(e, _)| *e == Effect::EnableEventInterrupts)
            .count(),
        1
    );
}

#[test]
fn exit_zeroes_only_actual_ack_groups_then_status_before_retained_cleanup_tail() {
    let local = local();
    let mut backend = Backend::new();
    backend.before = Some(Effect::DisablePowerActions);
    let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
    let memory = owner.claim_memory_services().unwrap();
    assert!(owner.claim_memory_services().is_err());
    let registry = owner.claim_registry_services().unwrap();
    assert!(owner.claim_registry_services().is_err());
    let counter_frames = owner.claim_counter_frames().unwrap();
    assert!(owner.claim_counter_frames().is_err());
    let mut latch = InterruptLatch::new();
    owner.begin_startup().unwrap();
    step(&mut owner, &mut latch, 1).unwrap();
    let stale = owner.resources().targets[0].clone();
    owner.begin_exit().unwrap();
    assert!(step(&mut owner, &mut latch, 2).is_err());
    assert_eq!(owner.phase(), Phase::Stopping);
    assert_eq!(latest(&local, 1), Some(0));
    for entry in 256..259 {
        assert_eq!(latest(&local, entry), Some(0));
    }
    assert_eq!(latest(&local, 259), None);
    let prefix = local.bank().requests();
    let requests = prefix.len();
    assert!(owner.begin_startup().is_err());
    assert!(owner.begin_exit().is_err());
    step(&mut owner, &mut latch, 3).unwrap();
    assert_eq!(owner.phase(), Phase::Dormant);
    assert!(memory.check().is_ok());
    assert!(registry.check().is_ok());
    assert!(counter_frames.check().is_ok());
    assert_eq!(local.bank().requests().len(), requests);
    assert_eq!(local.bank().requests(), prefix);
    assert!(
        stale
            .publish(0, 55, &mut Access::new(0, 3, &mut latch))
            .is_err()
    );
    owner.begin_startup().unwrap();
    step(&mut owner, &mut latch, 4).unwrap();
    let resumed = local.bank().requests();
    assert!(
        stale
            .publish(0, 55, &mut Access::new(0, 4, &mut latch))
            .is_err()
    );
    assert_eq!(local.bank().requests(), resumed);
    owner
        .resources()
        .targets
        .last()
        .unwrap()
        .publish(0, 77, &mut Access::new(0, 4, &mut latch))
        .unwrap();
    assert_eq!(latest(&local, 64), Some(77));
    assert!(latch.take_aic_inputs().is_empty());
    assert!(memory.check().is_ok());
    drop(owner);
    assert!(memory.check().is_err());
    assert!(registry.check().is_err());
    assert!(counter_frames.check().is_err());
    drop(memory);
    assert!(Owner::initialized(local, IDS, Backend::new()).is_err());
}

#[test]
fn constructor_validates_actual_selected_ids_inventory_and_request_identity() {
    let local = local();
    let prefix = local.bank().requests();
    let mut invalid = IDS;
    invalid[3] = 999;
    assert!(Owner::initialized(local.clone(), invalid, Backend::new()).is_err());
    invalid = IDS;
    invalid[4] = 1;
    assert!(Owner::initialized(local.clone(), invalid, Backend::new()).is_err());
    invalid = IDS;
    invalid[1] = 0;
    assert!(Owner::initialized(local.clone(), invalid, Backend::new()).is_err());
    let mut backend = Backend::new();
    backend.groups = 9;
    assert!(Owner::initialized(local.clone(), IDS, backend).is_err());
    assert_eq!(local.bank().requests(), prefix);
    let mut first = Owner::initialized(local.clone(), IDS, Backend::new()).unwrap();
    drop(first.claim_memory_services().unwrap());
    assert!(first.claim_memory_services().is_err());
    drop(first.claim_registry_services().unwrap());
    assert!(first.claim_registry_services().is_err());
    assert!(Owner::initialized(local.clone(), IDS, Backend::new()).is_err());
    let mut second = Owner::initialized(self::local(), IDS, Backend::new()).unwrap();
    let mut latch = InterruptLatch::new();
    first.begin_startup().unwrap();
    second.begin_startup().unwrap();
    step(&mut first, &mut latch, 1).unwrap();
    step(&mut second, &mut latch, 1).unwrap();
    let a = &first.resources().refresh_calls[0];
    let b = &second.resources().refresh_calls[0];
    assert_eq!(a.serial(), b.serial());
    assert_eq!(a.operation(), b.operation());
    assert!(!a.same_operation(b));
    let abandoned = first.resources().targets[0].clone();
    let retained = local.bank().requests();
    drop(first);
    assert!(
        abandoned
            .publish(0, 5, &mut Access::new(0, 2, &mut latch))
            .is_err()
    );
    assert_eq!(local.bank().requests(), retained);
    assert_eq!(latest(&local, 1), Some(1));
    assert!(Owner::initialized(local.clone(), IDS, Backend::new()).is_err());
    let late = self::local();
    transport::publish(&late, 1, 1, &mut Access::new(0, 2, &mut latch)).unwrap();
    assert!(Owner::initialized(late, IDS, Backend::new()).is_err());
}

#[test]
fn exit_failure_boundaries_preserve_real_ack_and_status_order() {
    for (effect, ack, status) in [
        (Effect::DisableCompletionInterrupts, None, Some(1)),
        (Effect::StopFastDie, None, Some(1)),
        (Effect::StopControlLoops, Some(0), Some(1)),
        (Effect::ReleaseRunStateAndSampleCounter, Some(0), Some(0)),
    ] {
        let local = local();
        let mut backend = Backend::new();
        backend.after = Some(effect);
        let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
        let mut latch = InterruptLatch::new();
        owner.begin_startup().unwrap();
        step(&mut owner, &mut latch, 1).unwrap();
        owner.begin_exit().unwrap();
        assert!(step(&mut owner, &mut latch, 2).is_err());
        assert_eq!(latest(&local, 256), ack);
        assert_eq!(latest(&local, 1), status);
        let prefix = local.bank().requests();
        step(&mut owner, &mut latch, 3).unwrap();
        assert_eq!(owner.phase(), Phase::Dormant);
        assert_eq!(local.bank().requests()[..prefix.len()], prefix);
        assert_eq!(
            owner
                .resources()
                .calls
                .iter()
                .filter(|(e, _)| *e == effect)
                .count(),
            1
        );
    }
}
