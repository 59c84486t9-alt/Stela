use super::super::profile::tests::fixture;
use super::*;
use alloc::vec;
use stela_contracts::interrupt::InterruptLatch;
struct Snapshot(u128, u128);
impl Pending for Snapshot {
    fn bits(&self, start: u32, count: u32) -> Result<u128, &'static str> {
        let x = if start < 128 {
            self.0 >> (start - 16)
        } else {
            self.1 >> (start - 128)
        };
        Ok(if count == 128 {
            x
        } else {
            x & ((1u128 << count) - 1)
        })
    }
}
struct TestBackend {
    calls: Vec<(Request, Effect)>,
    reads: Vec<(Request, Observation)>,
    captures: u32,
    manager: Vec<(Request, ManagerEffect, usize, usize, ManagerContext)>,
    snapshot: (u128, u128),
    tick: u64,
    observer: u32,
    stamp: u32,
    payload: u64,
    busy: bool,
    refuse: bool,
    after: bool,
    hook_buffer: Option<u32>,
    bad_hook: bool,
    controls: Vec<ControlFlags>,
    packets: Packets,
}
impl TestBackend {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            reads: Vec::new(),
            captures: 0,
            manager: Vec::new(),
            snapshot: (0, 0),
            tick: 1000,
            observer: 0xf0,
            stamp: 1000,
            payload: 0,
            busy: false,
            refuse: false,
            after: false,
            hook_buffer: None,
            bad_hook: false,
            controls: Vec::new(),
            packets: Packets([0x403, 0, 0x403, 0, 0, 0]),
        }
    }
}
impl Backend for TestBackend {
    type Snapshot = Snapshot;
    fn observe(
        &mut self,
        request: &Request,
        observation: Observation,
        snapshot: Option<&Self::Snapshot>,
        _: &mut Access<'_>,
    ) -> Completion<Value> {
        self.reads.push((request.clone(), observation));
        Completion::Retired {
            value: match observation {
                Observation::Clock => Value::Tick(self.tick),
                Observation::PolicyPackets => Value::Packets(self.packets),
                Observation::ProviderStates { .. } => Value::ProviderStateCount(8),
                Observation::Observer { .. } => Value::ObserverWord(self.observer),
                Observation::ConsumeFreshnessValue { .. } => {
                    assert!(snapshot.is_some());
                    Value::ConsumedValueLow32(self.stamp)
                }
                Observation::DeviceRequest { .. } => Value::Payload(self.payload),
                Observation::CounterControls => Value::Controls(self.controls.clone()),
                Observation::DispatchControl => Value::DispatchControl {
                    trace_enabled: 0,
                    trace_result: None,
                },
            },
            refusal: None,
        }
    }
    fn capture_pending(
        &mut self,
        _: &Request,
        _: Slice,
        _: &mut Access<'_>,
    ) -> Completion<Snapshot> {
        self.captures += 1;
        Completion::Retired {
            value: Snapshot(self.snapshot.0, self.snapshot.1),
            refusal: None,
        }
    }
    fn manager_effect(
        &mut self,
        request: &Request,
        effect: ManagerEffect,
        _: &Profile,
        context: ManagerContext,
        snapshot: Option<&Self::Snapshot>,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        assert!(snapshot.is_some());
        self.manager.push((
            request.clone(),
            effect,
            self.calls.len(),
            self.reads.len(),
            context,
        ));
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
    fn effect(
        &mut self,
        request: &Request,
        effect: &Effect,
        _: &Descriptor,
        snapshot: Option<&Self::Snapshot>,
        _: &mut Access<'_>,
    ) -> Completion<EffectValue> {
        if matches!(effect, Effect::DiscardCounters { .. }) {
            assert!(snapshot.is_some());
        }
        self.calls.push((request.clone(), effect.clone()));
        if self.busy {
            self.busy = false;
            return Completion::Busy { deadline: Some(22) };
        }
        if self.refuse {
            self.refuse = false;
            return Completion::Refused("authored unavailable native effect");
        }
        let refusal = if self.after {
            self.after = false;
            Some("authored retired effect refusal")
        } else {
            None
        };
        let value = match effect {
            Effect::Hook {
                hook: Hook::Capture | Hook::Postprocess,
                counters,
                ..
            } if !self.bad_hook => EffectValue::Hook {
                buffer_index: self.hook_buffer.unwrap_or(counters.buffer_index),
                state_index: counters.state_index,
                previous_state_index: counters.previous_state_index,
            },
            _ => EffectValue::Complete,
        };
        Completion::Retired { value, refusal }
    }
}
fn step(o: &mut Owner<TestBackend>) -> Result<Progress, Error> {
    let mut latch = InterruptLatch::new();
    o.advance(&mut Access::new(0, 1, &mut latch))
}
fn owner() -> Owner<TestBackend> {
    let mut o = Owner::initialized_software(fixture(), TestBackend::new());
    o.begin_initialize().unwrap();
    assert_eq!(step(&mut o), Ok(Progress::Idle));
    o.begin_start().unwrap();
    step(&mut o).unwrap();
    o
}
fn selection(o: &mut Owner<TestBackend>, bits: u64) {
    let p = super::super::super::power::policy::Policy::t8112(table(), None).unwrap();
    o.begin_selection(p.resolve(bits).unwrap()).unwrap();
    step(o).unwrap();
}
fn table() -> super::super::super::power::DeviceTable {
    let raw: Vec<u8> = [
        1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
    ]
    .into_iter()
    .map(|id| {
        let mut r = [0u32; 31];
        r[0] = id;
        r
    })
    .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
    .collect();
    super::super::super::power::DeviceTable::from_properties(&raw, &0x3fff0u64.to_le_bytes(), None)
        .unwrap()
}
fn ordinal(i: u8) -> Ordinal {
    Ordinal::new(i).unwrap()
}
#[test]
fn manager_stages_bracket_hooks_and_cursor_exhaustion_precedes_backend() {
    let mut o = owner();
    selection(&mut o, 1 << 8);
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    let stages = &o.backend.manager;
    assert_eq!(stages.len(), 3);
    assert_eq!(stages[0].1, ManagerEffect::BeforeCapture);
    assert_eq!(stages[1].1, ManagerEffect::RestoreControllers);
    assert_eq!(stages[2].1, ManagerEffect::AccumulateCounters);
    assert!(
        stages
            .iter()
            .all(|stage| stage.4.current_packet == o.backend.packets)
    );
    let captures = &o.backend.calls[stages[0].2..stages[1].2];
    assert!(!captures.is_empty());
    assert!(captures.iter().all(|(_, e)| matches!(
        e,
        Effect::Hook {
            hook: Hook::Capture,
            ..
        }
    )));
    let posts = &o.backend.calls[stages[1].2..stages[2].2];
    assert!(!posts.is_empty());
    assert!(posts.iter().all(|(_, e)| matches!(
        e,
        Effect::Hook {
            hook: Hook::Postprocess,
            ..
        }
    )));
    assert_eq!(o.backend.reads[stages[1].3 - 1].1, Observation::Clock);
    let initial_tick = o.states[8].tick;
    assert!(captures.iter().all(|(_, e)| matches!(e, Effect::Hook { counters, .. } if counters.evaluation_tick == initial_tick && counters.current_packet == o.backend.packets)));
    o.begin_counter_controls().unwrap();
    o.batch.as_mut().unwrap().cursor = u64::MAX;
    let before = o.backend.reads.len();
    assert_eq!(
        step(&mut o),
        Err(Error::Contract(
            "native platform operation cursor exhausted"
        ))
    );
    assert_eq!(o.backend.reads.len(), before);
}

#[test]
fn both_passes_share_one_snapshot_and_aggregate_uses_current_leaf_ordinals() {
    let mut o = owner();
    selection(&mut o, 1 << 8);
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    let out = o.last_evaluation().unwrap();
    assert_eq!(out.eligible & 0xf, 0xf);
    assert_ne!(out.eligible & (1 << 8), 0);
    assert_eq!(o.backend.captures, 1);
    assert_eq!(o.evaluated(ordinal(4)), 0);
    assert_eq!(o.activation(ordinal(4)), 1);
    let hooks: Vec<_> = o
        .backend
        .calls
        .iter()
        .filter_map(|(_, e)| {
            if let Effect::Hook { ordinal, hook, .. } = e {
                Some((ordinal.index(), *hook))
            } else {
                None
            }
        })
        .collect();
    let split = hooks.iter().position(|x| x.1 == Hook::Postprocess).unwrap();
    assert!(hooks[..split].iter().all(|x| x.1 == Hook::Capture));
    selection(&mut o, 0);
    assert_eq!(o.evaluated(ordinal(8)), 0);
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.last_evaluation().unwrap().eligible, 0);
}
#[test]
fn observer_parent_hysteresis_and_freshness_use_exact_branches() {
    let mut o = owner();
    selection(&mut o, 1 << 9);
    o.backend.observer = 0xe0;
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.evaluated(ordinal(9)), 0);
    o.backend.observer = 0xf0;
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.evaluated(ordinal(9)), 1);
    o.states[9].parent_gate = 1;
    o.states[1].evaluated = 0;
    let reads = o.backend.reads.len();
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.evaluated(ordinal(9)), 0);
    assert!(
        !o.backend.reads[reads..]
            .iter()
            .any(|x| matches!(x.1, Observation::Observer { .. }))
    );
    let i = 4;
    o.profile.descriptors[i].selection =
        super::super::CounterSelection::initialized(Vec::new(), 1).unwrap();
    o.profile.descriptors[i].hysteresis = 2;
    o.backend.snapshot.1 = 1;
    o.states[i].freshness_arm = 1;
    o.backend.stamp = 900;
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.evaluated(ordinal(4)), 1);
    o.backend.snapshot.1 = 0;
    for expected in [1, 1, 0] {
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(4)), expected);
    }
    o.backend.snapshot.1 = 1;
    o.backend.stamp = 0;
    o.states[i].pending = 1;
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.evaluated(ordinal(4)), 0);
    assert_eq!(o.states[i].activity, 1);
    assert_ne!(o.last_evaluation().unwrap().prior_pending & (1 << i), 0);
}
#[test]
fn discards_keep_source_prefix_and_request_identity() {
    let mut o = owner();
    selection(&mut o, 1 << 8);
    o.profile.descriptors[4].selection =
        super::super::CounterSelection::initialized(Vec::new(), 1).unwrap();
    o.states[4].evaluated = 1;
    o.states[4].activity = u32::MAX;
    o.backend.snapshot.1 = 1;
    o.backend.busy = true;
    o.begin_cycle().unwrap();
    assert_eq!(step(&mut o), Ok(Progress::Busy { deadline: Some(22) }));
    let cursor = o.committed_prefix();
    let request = o.backend.calls.last().unwrap().0.clone();
    assert_eq!(o.states[4].activity, 0);
    assert!(o.begin_cycle().is_err());
    step(&mut o).unwrap();
    let calls: Vec<_> = o
        .backend
        .calls
        .iter()
        .filter(|(_, e)| matches!(e, Effect::DiscardCounters { .. }))
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(request.same_operation(&calls[1].0));
    assert!(cursor.is_some());
    o.backend.after = true;
    o.begin_cycle().unwrap();
    assert!(step(&mut o).is_err());
    let n = o.backend.calls.len();
    step(&mut o).unwrap();
    assert!(
        !o.backend.calls[n..]
            .iter()
            .any(|(r, _)| r.same_operation(&o.backend.calls[n - 1].0))
    );
}
#[test]
fn refusal_does_not_admit_init_start_selection_or_pending_reset() {
    let mut o = Owner::initialized_software(fixture(), TestBackend::new());
    o.backend.refuse = true;
    o.begin_initialize().unwrap();
    assert!(step(&mut o).is_err());
    assert!(o.begin_start().is_err());
    assert!(!o.initialized);
    step(&mut o).unwrap();
    o.begin_start().unwrap();
    step(&mut o).unwrap();
    let p = super::super::super::power::policy::Policy::t8112(table(), None).unwrap();
    o.backend.refuse = true;
    o.begin_selection(p.resolve(1 << 8).unwrap()).unwrap();
    assert!(step(&mut o).is_err());
    assert_eq!(o.selected(), 0);
    assert_eq!(o.activation(ordinal(0)), 1);
    assert_eq!(o.evaluated(ordinal(0)), 0);
    step(&mut o).unwrap();
    assert_ne!(o.selected(), 0);
    o.backend.controls = vec![ControlFlags {
        ordinal: ordinal(8),
        low: 1,
        high: 0,
    }];
    o.begin_counter_controls().unwrap();
    step(&mut o).unwrap();
    o.backend.refuse = true;
    o.begin_reset_control(ordinal(8)).unwrap();
    assert!(step(&mut o).is_err());
    assert_eq!(o.pending_control(ordinal(8)), 1);
    step(&mut o).unwrap();
    assert_eq!(o.pending_control(ordinal(8)), 0);
}
#[test]
fn packet_observation_drives_isp_mode1_tuple_and_periodic_refresh() {
    let mut o = owner();
    selection(&mut o, 1 << 8);
    o.backend.payload = (1000 << 16) | 363;
    o.begin_device_request(ordinal(8)).unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.logical_request(ordinal(8)).nibble(1), Some(1));
    o.states[8].interpolation.as_mut().unwrap().advance(489);
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.logical_request(ordinal(8)).nibble(1), Some(0));
    assert!(o.backend.calls.iter().any(|(_,e)|matches!(e,Effect::Refresh{ordinal,logical,..}if ordinal.index()==8&&logical.nibble(1)==Some(0))));
    o.backend.payload = 31 | (4 << 32);
    o.begin_device_request(ordinal(4)).unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.states[4].state_index, 7);
    assert_eq!(o.logical_request(ordinal(4)).nibble(1), Some(4));
}
#[test]
fn stop_deactivates_before_each_stop_and_keeps_inactive_tail_effects() {
    let mut o = owner();
    selection(&mut o, 1 << 8);
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert_eq!(o.evaluated(ordinal(8)), 1);
    o.backend.refuse = true;
    let n = o.backend.calls.len();
    o.begin_stop().unwrap();
    assert!(step(&mut o).is_err());
    assert_eq!(o.activation(ordinal(0)), 0);
    assert_eq!(o.evaluated(ordinal(0)), 0);
    assert!(
        !o.backend.calls[n..]
            .iter()
            .any(|(_, e)| matches!(e, Effect::Stop { .. }))
    );
    step(&mut o).unwrap();
    assert_eq!(o.activation(ordinal(8)), 0);
    assert_eq!(o.evaluated(ordinal(8)), 0);
    assert!(!o.started);
    let tail: Vec<_> = o.backend.calls[n..]
        .iter()
        .filter_map(|(_, e)| match e {
            Effect::Activation {
                ordinal,
                enable: false,
                ..
            } => Some((ordinal.index(), 0)),
            Effect::Stop { ordinal, .. } => Some((ordinal.index(), 1)),
            _ => None,
        })
        .collect();
    assert_eq!(tail.len(), 37); //one refused activation plus18 kept pairs
    assert_eq!(tail[0], tail[1]);
    for (i, pair) in tail[1..].as_chunks::<2>().0.iter().enumerate() {
        assert_eq!(*pair, [(i, 0), (i, 1)]);
    }
}
#[test]
fn hook_products_feed_next_stage_and_absent_products_cannot_succeed() {
    let mut o = owner();
    selection(&mut o, 1 << 8);
    o.backend.hook_buffer = Some(7);
    let n = o.backend.calls.len();
    o.begin_cycle().unwrap();
    step(&mut o).unwrap();
    assert!(o.backend.calls[n..].iter().any(|(_,e)|matches!(e,Effect::Hook{hook:Hook::Postprocess,counters,..}if counters.buffer_index==7)));
    o.backend.bad_hook = true;
    o.begin_cycle().unwrap();
    assert!(matches!(
        step(&mut o),
        Err(Error::Contract(
            "native counter hook software products absent"
        ))
    ));
    assert!(o.begin_cycle().is_err());
    assert!(step(&mut o).is_err());
}
#[test]
fn source_enable_and_configuration_are_policy_data_without_activation_permission() {
    let mut o = owner();
    o.apply_source_enable(ordinal(8), 5).unwrap();
    assert_eq!(o.activation(ordinal(8)), 0);
    assert_eq!(o.evaluated(ordinal(8)), 0);
    o.apply_configuration(ordinal(4), super::super::Configuration::Hysteresis(2))
        .unwrap();
    assert_eq!(o.profile.descriptors[4].hysteresis, 2);
    assert_eq!(
        super::super::Configuration::Hysteresis(0).source_offset(),
        0x260
    );
    o.apply_configuration(ordinal(4), super::super::Configuration::PeriodShift(32))
        .unwrap();
    assert_eq!(o.profile.descriptors[4].times(), (170, 7));
    selection(&mut o, 1 << 8);
    o.apply_source_enable(ordinal(8), 0).unwrap();
    o.begin_cycle().unwrap();
    assert!(o.apply_source_enable(ordinal(8), 1).is_err());
    step(&mut o).unwrap();
    assert_eq!(o.last_evaluation().unwrap().eligible, 0);
    assert_eq!(o.activation(ordinal(8)), 1);
}
