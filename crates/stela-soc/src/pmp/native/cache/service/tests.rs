use super::super::{policy, publisher};
use super::*;
use alloc::vec::Vec;
use core::cell::RefCell;
use owner::{Completion, EffectValue};
use stela_contracts::refuse;
use {
    crate::machine::memory_resources::t8112::Prepared,
    crate::machine::memory_resources::t8112::cache::EmptyResource, crate::pmp::native,
    crate::ptd::transport::Entry, stela_contracts::interrupt::InterruptLatch,
};

struct MissingResources;
impl native::Resources for MissingResources {
    fn inventory(&self) -> native::Inventory {
        native::Inventory { power_groups: 1 }
    }
    fn refresh_power_states(&mut self, _: &native::Request, _: &mut Access<'_>) -> native::Refresh {
        native::Refresh::Refused(refuse!("authored whole native startup remains unavailable"))
    }
    fn snapshot_observer_packets(
        &mut self,
        _: &native::Request,
        _: &mut Access<'_>,
    ) -> native::Refresh {
        native::Refresh::Refused(refuse!("authored packet observer unavailable"))
    }
    fn effect(
        &mut self,
        _: &native::Request,
        _: native::Effect,
        _: Option<&native::PublicationTarget>,
        _: &native::Packets,
        _: &mut Access<'_>,
    ) -> native::Step {
        native::Step::Refused(refuse!("authored whole resource effect unavailable"))
    }
}
struct NoProviders;
impl ingestion::Backend for NoProviders {
    fn call(
        &mut self,
        _: &ingestion::Request,
        _: &ingestion::Call,
        _: &mut Access<'_>,
    ) -> Completion<ingestion::Value> {
        Completion::Refused(refuse!("authored AMCC provider unavailable"))
    }
}
struct ManagerBackend {
    frames: Rc<RefCell<Frames>>,
}
impl owner::Backend for ManagerBackend {
    type Snapshot = native::counters::Captured;
    fn observe(
        &mut self,
        _: &owner::Request,
        op: owner::Observation,
        _: Option<&Self::Snapshot>,
        _: &mut Access<'_>,
    ) -> Completion<owner::Value> {
        let value = match op {
            owner::Observation::Clock => owner::Value::Tick(1000),
            owner::Observation::PolicyPackets => {
                owner::Value::Packets(native::Packets([0x403, 0, 0x403, 0, 0, 0]))
            }
            owner::Observation::ProviderStates { .. } => owner::Value::ProviderStateCount(8),
            owner::Observation::Observer { .. } => owner::Value::ObserverWord(0xf0),
            owner::Observation::ConsumeFreshnessValue { .. } => {
                return Completion::Refused(refuse!("authored freshness source not reached"));
            }
            owner::Observation::DeviceRequest { .. } => owner::Value::Payload(0),
            owner::Observation::CounterControls => owner::Value::Controls(Vec::new()),
            owner::Observation::DispatchControl => owner::Value::DispatchControl {
                trace_enabled: 0,
                trace_result: None,
            },
        };
        Completion::Retired {
            value,
            refusal: None,
        }
    }
    fn capture_pending(
        &mut self,
        _: &owner::Request,
        _: platform::Slice,
        access: &mut Access<'_>,
    ) -> Completion<Self::Snapshot> {
        match self.frames.borrow_mut().capture_pending(access) {
            Ok(value) => Completion::Retired {
                value,
                refusal: None,
            },
            Err(reason) => Completion::Refused(reason),
        }
    }
    fn manager_effect(
        &mut self,
        _: &owner::Request,
        _: owner::ManagerEffect,
        _: &platform::Profile,
        _: owner::ManagerContext,
        _: Option<&Self::Snapshot>,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
    fn effect(
        &mut self,
        _: &owner::Request,
        effect: &owner::Effect,
        _: &platform::Descriptor,
        _: Option<&Self::Snapshot>,
        _: &mut Access<'_>,
    ) -> Completion<EffectValue> {
        let value = if let owner::Effect::Hook {
            hook: platform::Hook::Capture | platform::Hook::Postprocess,
            counters,
            ..
        } = effect
        {
            EffectValue::Hook {
                buffer_index: counters.buffer_index,
                state_index: counters.state_index,
                previous_state_index: counters.previous_state_index,
            }
        } else {
            EffectValue::Complete
        };
        Completion::Retired {
            value,
            refusal: None,
        }
    }
}
#[derive(Default)]
struct Sink {
    effects: Vec<(metrics::Request, metrics::Effect)>,
    registrations: Vec<(u32, metrics::MetricKind, metrics::Counter)>,
    wakes: u32,
    notified: bool,
    trace: u32,
    refuse_trace: bool,
    busy_wake: bool,
    busy_notify: bool,
    retire_exit: bool,
}
type CallbackSlot = Rc<RefCell<alloc::rc::Weak<RefCell<Option<Fixture>>>>>;
struct Destinations {
    sink: Rc<RefCell<Sink>>,
    runtime: scheduler::Runtime,
    queue: Option<scheduler::Queue>,
    work: Option<scheduler::Work>,
    callback: CallbackSlot,
}
struct InvokeMetrics(CallbackSlot);
impl scheduler::Callback for InvokeMetrics {
    fn advance(&mut self, i: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        let Some(fixture) = self.0.borrow().upgrade() else {
            return Completion::Refused(refuse!("authored MC service owner absent"));
        };
        let mut fixture = fixture.borrow_mut();
        let Some(f) = fixture.as_mut() else {
            return Completion::Refused(refuse!("authored MC service owner moved"));
        };
        match f.service.dispatch_metrics(
            i,
            Sources {
                manager: &f.manager,
                amcc: &mut f.amcc,
                frames: &f.frames.borrow(),
            },
            a,
        ) {
            Ok(Progress::MetricsComplete) => Completion::Retired {
                value: 0,
                refusal: None,
            },
            Ok(Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(_) => Completion::Refused(refuse!("authored MC callback returned unrelated stage")),
            Err(Error::Metrics(metrics::Error::Contract(e) | metrics::Error::Backend(e)))
            | Err(Error::Contract(e)) => Completion::Refused(e),
            Err(_) => Completion::Refused(refuse!("authored MC callback source check refused")),
        }
    }
}
impl metrics::Backend for Destinations {
    fn work(&self) -> Option<&scheduler::Work> {
        self.work.as_ref()
    }
    fn effect(
        &mut self,
        request: &metrics::Request,
        effect: &metrics::Effect,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        let mut sink = self.sink.borrow_mut();
        if matches!(effect, metrics::Effect::Wake) && sink.busy_wake {
            sink.busy_wake = false;
            return Completion::Busy { deadline: Some(99) };
        }
        if matches!(effect, metrics::Effect::NotifyStop) && sink.busy_notify {
            sink.busy_notify = false;
            return Completion::Busy {
                deadline: Some(101),
            };
        }
        if matches!(effect, metrics::Effect::Trace { .. }) && sink.refuse_trace {
            sink.refuse_trace = false;
            return Completion::Refused(refuse!("authored trace destination refused"));
        }
        if matches!(effect, metrics::Effect::DrainWait) && !sink.notified {
            return Completion::Busy { deadline: None };
        }
        match effect {
            metrics::Effect::InitializeQueue {
                name,
                stack_bytes,
                priority,
            } => {
                self.queue = Some(
                    self.runtime
                        .create_queue(scheduler::QueueConfiguration {
                            name: (*name).into(),
                            stack_bytes: *stack_bytes,
                            priority: *priority,
                        })
                        .unwrap(),
                )
            }
            metrics::Effect::BindWork { priority } => {
                self.work = Some(
                    self.runtime
                        .bind_work(*priority, InvokeMetrics(self.callback.clone()))
                        .unwrap(),
                )
            }
            metrics::Effect::RegisterWork => {
                return self
                    .runtime
                    .register_work(self.queue.as_ref().unwrap(), self.work.as_ref().unwrap());
            }
            metrics::Effect::RegisterMetric {
                group,
                kind,
                counter,
                ..
            } => sink.registrations.push((*group, *kind, counter.clone())),
            metrics::Effect::Wake => {
                self.runtime.wake(self.work.as_ref().unwrap()).unwrap();
                sink.wakes += 1;
                sink.notified = false;
            }
            metrics::Effect::NotifyStop => sink.notified = true,
            metrics::Effect::Trace { .. } | metrics::Effect::DrainWait => {}
        }
        sink.effects.push((request.clone(), effect.clone()));
        if let metrics::Effect::Trace {
            event: 0x860bb010,
            args: [0, 0, 0, 0],
        } = effect
            && sink.retire_exit
        {
            sink.retire_exit = false;
            return Completion::Retired {
                value: (),
                refusal: Some(refuse!("authored retired exit trace refusal")),
            };
        }
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
    fn trace_control(&mut self, _: &metrics::Request, _: &mut Access<'_>) -> Completion<u32> {
        Completion::Retired {
            value: self.sink.borrow().trace,
            refusal: None,
        }
    }
}
struct Fixture {
    native: native::Owner<MissingResources>,
    memory: Prepared,
    cache: EmptyResource,
    frames: Rc<RefCell<Frames>>,
    manager: owner::Owner<ManagerBackend>,
    amcc: amcc::Owner<NoProviders>,
    service: Owner<Destinations>,
    sink: Rc<RefCell<Sink>>,
    latch: InterruptLatch,
}
impl Fixture {
    fn new() -> Self {
        let (memory, mut cache) = EmptyResource::service_test_components();
        let local = memory.notifications().clone();
        let mut native = native::Owner::initialized(
            local.clone(),
            [1, 2, 3, 4, 0, 0, 0, 0, 0, 9, 10, 11, 12, 13, 0],
            MissingResources,
        )
        .unwrap();
        let claim = native.claim_cache_services(14, 30).unwrap();
        assert!(native.claim_cache_services(14, 30).is_err());
        let profile = platform::authored_profile();
        let raw: Vec<_> = profile
            .descriptors()
            .iter()
            .flat_map(|d| d.raw_soc_device().iter().flat_map(|v| v.to_le_bytes()))
            .collect();
        let table =
            native::power::DeviceTable::from_properties(&raw, &0x3fff0u64.to_le_bytes(), None)
                .unwrap();
        let frames = Rc::new(RefCell::new(
            Frames::initialized(native.claim_counter_frames().unwrap(), &table, &[0xa5; 144])
                .unwrap(),
        ));
        let amcc = amcc::Owner::initialized_software(
            amcc::Configuration::t8112(&profile.descriptors()[1]).unwrap(),
            NoProviders,
        )
        .unwrap();
        let manager = owner::Owner::initialized_software(
            profile,
            ManagerBackend {
                frames: frames.clone(),
            },
        );
        let rows: Vec<_> = (0..4u32)
            .flat_map(|group| {
                [group, 0, 1, group, 0, 0, 3, 8192, 0, 0, 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
            })
            .collect();
        let binding = memory.bind_quota_publisher(&mut cache).unwrap();
        let publisher = Publisher::new(
            binding,
            &mut cache.quota_view(),
            &rows,
            policy::Inputs {
                budget: 64,
                reference: 64,
                hardware_scale: 0,
                hardware_multiplier: 0,
                feature_word: 0,
                slot_flags: [0; 32],
                quota_words: [0; 32],
            },
            publisher::Configuration {
                response_range: 30,
                response_words: 5,
                ack_words: 1,
                retain_attributes: true,
                suppression: Some(0),
            },
        )
        .unwrap();
        let sink = Rc::new(RefCell::new(Sink::default()));
        let metrics = metrics::Owner::initialized_source(
            metrics::Configuration::t8112(),
            Destinations {
                sink: sink.clone(),
                runtime: scheduler::Runtime::new(),
                queue: None,
                work: None,
                callback: Rc::new(RefCell::new(alloc::rc::Weak::new())),
            },
        );
        let mut amcc = amcc;
        let service = Owner::initialized_software(
            claim,
            publisher,
            metrics,
            Sources {
                manager: &manager,
                amcc: &mut amcc,
                frames: &frames.borrow(),
            },
            Configuration {
                request_words: 4,
                command_words: 3,
            },
        )
        .unwrap();
        Self {
            native,
            memory,
            cache,
            frames,
            manager,
            amcc,
            service,
            sink,
            latch: InterruptLatch::new(),
        }
    }
    fn step(&mut self) -> Result<Progress, Error> {
        let result = self.service.advance(
            Sources {
                manager: &self.manager,
                amcc: &mut self.amcc,
                frames: &self.frames.borrow(),
            },
            &mut self.cache.quota_view(),
            &mut Access::new(0, 1000, &mut self.latch),
        );
        // Independent real scheduler progress while the foreground Stop
        // keeps its authored destination wait. Never inline advance().
        if matches!(result, Ok(Progress::Busy { .. }))
            && self
                .service
                .batch
                .as_ref()
                .is_some_and(|b| matches!(b.stage, Stage::Stop))
            && (self.service.metrics.queued() || self.service.metrics.callback_executing())
        {
            let _ = self.dispatch()?;
        }
        result
    }
    fn dispatch(&mut self) -> Result<Progress, Error> {
        let runtime = self.service.metrics.backend().runtime.clone();
        let slot = self.service.metrics.backend().callback.clone();
        let loan = Rc::new(RefCell::new(Some(core::mem::replace(self, Self::new()))));
        *slot.borrow_mut() = Rc::downgrade(&loan);
        let mut irq = InterruptLatch::new();
        let result = runtime.step(&mut Access::new(0, 1000, &mut irq));
        *slot.borrow_mut() = alloc::rc::Weak::new();
        *self = loan.borrow_mut().take().unwrap();
        match result {
            Ok(scheduler::Progress::Retired { refusal: None, .. }) => Ok(Progress::MetricsComplete),
            Ok(scheduler::Progress::Retired {
                refusal: Some(e), ..
            })
            | Err(scheduler::Error::Callback(e)) => Err(Error::Metrics(metrics::Error::Backend(e))),
            Ok(scheduler::Progress::Busy { deadline }) => Ok(Progress::Busy { deadline }),
            Ok(scheduler::Progress::Idle) => Ok(Progress::Busy { deadline: None }),
            Err(scheduler::Error::Contract(e)) => Err(Error::Contract(e)),
        }
    }
    fn finish(&mut self) -> Result<Progress, Error> {
        for _ in 0..256 {
            match self.step()? {
                Progress::Busy { .. } => {}
                value => return Ok(value),
            }
        }
        panic!("authored MC service did not finish bounded work")
    }
    fn start(&mut self) {
        self.service.begin_initialize().unwrap();
        assert_eq!(self.finish(), Ok(Progress::Initialized));
        self.service.begin_start().unwrap();
        assert_eq!(self.finish(), Ok(Progress::Started));
    }
    fn activate_manager(&mut self) {
        let mut access = Access::new(0, 1000, &mut self.latch);
        self.manager.begin_initialize().unwrap();
        assert_eq!(self.manager.advance(&mut access), Ok(owner::Progress::Idle));
        self.manager.begin_start().unwrap();
        self.manager.advance(&mut access).unwrap();
        let raw: Vec<_> = self
            .manager
            .profile()
            .descriptors()
            .iter()
            .flat_map(|d| d.raw_soc_device().iter().flat_map(|v| v.to_le_bytes()))
            .collect();
        let table =
            native::power::DeviceTable::from_properties(&raw, &0x3fff0u64.to_le_bytes(), None)
                .unwrap();
        let policy = native::power::policy::Policy::t8112(table, None).unwrap();
        self.manager
            .begin_selection(policy.resolve(1 << 8).unwrap())
            .unwrap();
        self.manager.advance(&mut access).unwrap();
        self.manager.begin_cycle().unwrap();
        self.manager.advance(&mut access).unwrap();
        assert_eq!(
            self.manager.evaluated(platform::Ordinal::new(1).unwrap()),
            1
        );
    }
    fn publish(&mut self, entry: u32, value: u64) {
        self.memory
            .publication_bank()
            .clone()
            .write(
                UPDATE_OFFSET + u64::from(entry) * 8,
                Width::Double,
                value,
                &mut Access::new(0, 24, &mut self.latch),
            )
            .unwrap();
    }
    fn command(&mut self, id: u16, op: u8) {
        self.publish(198, u64::from(id) | (u64::from(op) << 12));
    }
    fn latest(&self, entry: u32) -> Option<u64> {
        self.memory
            .publication_bank()
            .requests()
            .iter()
            .rev()
            .find(|r| r.entry == entry)
            .map(|r| r.value)
    }
    fn raw(&self, entry: u32) -> Entry {
        self.memory
            .publication_bank()
            .consume_entry(entry, &mut Access::new(0, 1000, &mut InterruptLatch::new()))
            .unwrap()
    }
    fn ingest_all_groups(&mut self) {
        let d = self.manager.profile().descriptors()[1].clone();
        self.publish(16, 70 | (100u64 << 32));
        for group in 0..GROUPS as u32 {
            let a = if group == 0 { u32::MAX } else { group + 10 };
            let b = if group == 0 { u32::MAX - 1 } else { group + 20 };
            self.publish(32 + group * 4, u64::from(a) | (u64::from(b) << 32));
        }
        let mut frames = self.frames.borrow_mut();
        let capture = frames
            .capture_pending(&Access::new(0, 48, &mut self.latch))
            .unwrap();
        let selected = capture.bits(16, 112).unwrap() & d.selection().bits();
        frames
            .begin_copy(&capture, 1, d.selection().bits())
            .unwrap();
        while frames
            .step(&mut Access::new(0, 49, &mut self.latch))
            .unwrap()
            != native::counters::CopyStep::Complete
        {}
        let copy = frames.finish_copy().unwrap();
        let mut c = owner::CounterContext {
            selected,
            evaluation_tick: 1000,
            current_packet: native::Packets([0x43, 0, 0, 0, 0, 0]),
            activity: 1,
            buffer_index: 0,
            state_index: 0,
            previous_state_index: 0,
            evaluated: 1,
            pending: 0,
        };
        self.amcc
            .begin_capture(&frames, &capture, amcc::Input::Copied(copy), &d, c, 1)
            .unwrap();
        let ingestion::Progress::Complete(EffectValue::Hook {
            buffer_index,
            state_index,
            previous_state_index,
        }) = self
            .amcc
            .advance(&frames, &mut Access::new(0, 50, &mut self.latch))
            .unwrap()
        else {
            panic!("authored AMCC local capture did not retire")
        };
        c.buffer_index = buffer_index;
        c.state_index = state_index;
        c.previous_state_index = previous_state_index;
        self.amcc.begin_postprocess(&frames, &d, c, 1).unwrap();
        assert!(matches!(
            self.amcc
                .advance(&frames, &mut Access::new(0, 51, &mut self.latch))
                .unwrap(),
            ingestion::Progress::Complete(_)
        ));
        assert_eq!(self.amcc.arrivals(), d.selection().bits() >> 16);
    }
}
#[test]
fn real_initialized_cache_and_ptd_start_stop_restart_preserve_deferred_work() {
    let mut f = Fixture::new();
    f.start();
    assert_eq!(f.service.run_state(), 1);
    assert_eq!(f.sink.borrow().registrations.len(), 8);
    assert_eq!(f.native.phase(), native::Phase::Dormant); //
    assert!(f.service.publisher.awaiting_publication());
    f.service.begin_stop().unwrap();
    assert_eq!(f.finish(), Ok(Progress::Stopped));
    f.service.begin_start().unwrap();
    assert_eq!(f.finish(), Ok(Progress::Started));
    assert_eq!(f.sink.borrow().registrations.len(), 8);
    assert!(f.service.publisher.awaiting_publication());
}
#[test]
fn evaluated_gate_preserves_pending_command_and_never_echoes_an_ack() {
    let mut f = Fixture::new();
    f.start();
    f.command(0xabc, 0);
    f.publish(194, 3);
    f.service.begin_event().unwrap();
    assert_eq!(f.finish(), Ok(Progress::EventComplete { command_id: 0 }));
    assert_ne!(
        f.memory
            .publication_bank()
            .pending_range(198, 3)
            .unwrap()
            .low
            & 1,
        0
    );
    assert_eq!(f.latest(213), None);
    assert_eq!(f.sink.borrow().wakes, 0);
}
#[test]
fn mismatched_arrivals_skip_housekeeping_but_real_command_publishes_before_ack() {
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.publish(194, 3);
    f.command(0xabc, 0);
    f.service.begin_event().unwrap();
    assert_eq!(
        f.finish(),
        Ok(Progress::EventComplete { command_id: 0xabc })
    );
    assert_eq!(f.cache.image().quota_words[0] & 511, 3);
    assert_eq!(f.latest(208).unwrap() & 0xfff, 3);
    assert_eq!(f.latest(213), Some(0xabc));
    assert_eq!(
        f.memory
            .publication_bank()
            .pending_range(194, 7)
            .unwrap()
            .low,
        0
    );
    assert_eq!(f.sink.borrow().wakes, 0);
    assert_eq!(f.amcc.arrivals(), 0);
    let log = f.memory.publication_bank().requests();
    let ack = log.iter().rposition(|r| r.entry == 213).unwrap();
    assert_eq!(log[ack - 1].entry, 208);
    assert_eq!(
        f.service
            .metrics
            .counter(0, metrics::MetricKind::Hits)
            .unwrap()
            .value(),
        0
    );
}
#[test]
fn equal_real_arrivals_copy_scale_and_queue_before_ack_without_callback_completion() {
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.ingest_all_groups();
    f.service
        .apply_registry_control(metrics::RegistryControl::Statistics(1))
        .unwrap();
    f.sink.borrow_mut().trace = 1;
    f.sink.borrow_mut().busy_wake = true;
    f.command(0x321, 7);
    f.service.begin_event().unwrap();
    let mut stopped = false;
    for _ in 0..256 {
        match f.step().unwrap() {
            Progress::Busy { deadline: Some(99) } => {
                stopped = true;
                break;
            }
            Progress::Busy { .. } => {}
            other => panic!("expected actual pending wake, got {other:?}"),
        }
    }
    assert!(stopped);
    assert_eq!(f.amcc.arrivals(), 0);
    assert_eq!(f.latest(213), None);
    assert_eq!(
        u32::from_le_bytes(f.service.samples.group(0).unwrap()[..4].try_into().unwrap()),
        u32::MAX
    );
    let expected = u64::from(u32::MAX.wrapping_mul(2048));
    assert_eq!(
        f.service
            .metrics
            .counter(0, metrics::MetricKind::Hits)
            .unwrap()
            .value(),
        expected
    );
    assert_eq!(
        f.finish(),
        Ok(Progress::EventComplete { command_id: 0x321 })
    );
    assert_eq!(f.latest(213), Some(0x321));
    assert_eq!(f.sink.borrow().wakes, 1);
    assert!(f.service.metrics.pending());
    assert!(f.service.metrics.queued());
    assert!(!f.sink.borrow().notified);
    let sink = f.sink.borrow();
    let getter = &sink
        .registrations
        .iter()
        .find(|(g, k, _)| *g == 0 && *k == metrics::MetricKind::Hits)
        .unwrap()
        .2;
    assert_eq!(getter.value(), expected);
    drop(sink);
    f.command(0x322, 5);
    f.service.begin_event().unwrap();
    assert_eq!(
        f.finish(),
        Ok(Progress::EventComplete { command_id: 0x322 })
    );
    assert_eq!(f.sink.borrow().wakes, 1);
    assert!(f.service.metrics.pending());
    f.service.begin_stop().unwrap();
    assert!(
        f.service
            .apply_registry_control(metrics::RegistryControl::Statistics(0))
            .is_err()
    );
    assert_eq!(f.finish(), Ok(Progress::Stopped));
    assert!(!f.service.metrics.pending());
    assert!(!f.service.metrics.queued());
    assert!(f.sink.borrow().notified);
    assert_eq!(f.service.run_state(), 0);
    let miss = u64::from((u32::MAX - 1).wrapping_mul(2048));
    assert!(f.sink.borrow().effects.iter().any(|(_, e)| matches!(
        e,
        metrics::Effect::Trace { event: 0x860bb400, args }
            if *args == [(expected * 1_000_000 / 56) >> 20,
                (miss * 1_000_000 / 56) >> 20, expected, miss]
    )));
}
#[test]
fn stop_after_pending_clear_keeps_tail_and_refuses_restart_before_effects() {
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.ingest_all_groups();
    f.service.begin_event().unwrap();
    assert_eq!(f.finish(), Ok(Progress::EventComplete { command_id: 0 }));
    f.sink.borrow_mut().busy_notify = true;
    let mut reached_notify = false;
    for _ in 0..32 {
        if f.dispatch().unwrap()
            == (Progress::Busy {
                deadline: Some(101),
            })
        {
            reached_notify = true;
            break;
        }
    }
    assert!(reached_notify && f.service.metrics.callback_executing());
    assert!(!f.service.metrics.pending());
    f.service.begin_stop().unwrap();
    assert_eq!(f.finish(), Ok(Progress::Stopped));
    assert!(!f.sink.borrow().notified);
    let effects = f.sink.borrow().effects.len();
    let publications = f.memory.publication_bank().requests().len();
    assert!(f.service.begin_start().is_err());
    assert_eq!(f.sink.borrow().effects.len(), effects);
    assert_eq!(f.memory.publication_bank().requests().len(), publications);
    let mut completed = false;
    for _ in 0..8 {
        if f.dispatch().unwrap() == Progress::MetricsComplete {
            completed = true;
            break;
        }
    }
    assert!(completed && f.sink.borrow().notified);
    f.service.begin_start().unwrap();
    assert_eq!(f.finish(), Ok(Progress::Started));
}
#[test]
fn consumed_budget_payload_is_not_replayed_after_real_cache_pause_and_new_input() {
    use {stela_contracts::bus::Lifecycle, stela_contracts::bus::LifecycleState};
    let live = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.publish(199, (1u64 << 48) | (17u64 << 17));
    f.command(0x456, 1);
    f.cache.set_lifecycle(
        LifecycleState {
            quiesced: true,
            ..live
        },
        &mut Access::new(0, 25, &mut f.latch),
    );
    f.service.begin_event().unwrap();
    assert!(matches!(f.finish(), Err(Error::Publication(_))));
    assert_eq!(f.service.publisher.policy().inputs().budget, 17);
    assert_eq!(f.latest(213), None);
    assert_eq!(
        f.memory
            .publication_bank()
            .pending_range(198, 2)
            .unwrap()
            .low,
        0
    );
    f.publish(199, 31 << 17);
    f.cache
        .set_lifecycle(live, &mut Access::new(0, 26, &mut f.latch));
    assert_eq!(
        f.finish(),
        Ok(Progress::EventComplete { command_id: 0x456 })
    );
    assert_eq!(f.service.publisher.policy().inputs().budget, 17);
    assert_eq!(f.latest(213), Some(0x456));
    assert_eq!(
        f.memory
            .publication_bank()
            .pending_range(199, 1)
            .unwrap()
            .low,
        1
    );
    let entry = f.raw(199);
    assert_eq!(entry.value, 31 << 17);
    assert_ne!(entry.metadata & NEW_DATA, 0);
}
#[test]
fn retired_exit_trace_refusal_keeps_single_ack_and_does_not_replay_trace() {
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.sink.borrow_mut().trace = 1;
    f.sink.borrow_mut().retire_exit = true;
    f.command(0x789, 9);
    f.service.begin_event().unwrap();
    assert_eq!(
        f.finish(),
        Err(Error::Metrics(metrics::Error::Backend(refuse!(
            "authored retired exit trace refusal"
        ))))
    );
    assert_eq!(f.latest(213), Some(0x789));
    assert_eq!(
        f.finish(),
        Ok(Progress::EventComplete { command_id: 0x789 })
    );
    assert_eq!(
        f.memory
            .publication_bank()
            .requests()
            .iter()
            .filter(|r| r.entry == 213)
            .count(),
        1
    );
    assert_eq!(
        f.sink
            .borrow()
            .effects
            .iter()
            .filter(|(_, e)| matches!(
                e,
                metrics::Effect::Trace {
                    event: 0x860bb010,
                    args: [0, 0, 0, 0]
                }
            ))
            .count(),
        1
    );
}
#[test]
fn foreign_quota_bank_refuses_before_trace_or_irreversible_ptd_consumption() {
    let mut f = Fixture::new();
    let mut other = Fixture::new();
    f.start();
    f.activate_manager();
    f.command(0x999, 0);
    f.publish(194, 6);
    f.service.begin_event().unwrap();
    let before = f.sink.borrow().effects.len();
    assert!(matches!(
        f.service.advance(
            Sources {
                manager: &f.manager,
                amcc: &mut f.amcc,
                frames: &f.frames.borrow()
            },
            &mut other.cache.quota_view(),
            &mut Access::new(0, 1000, &mut f.latch)
        ),
        Err(Error::Publication(_))
    ));
    assert_eq!(f.sink.borrow().effects.len(), before);
    assert_eq!(
        f.memory
            .publication_bank()
            .pending_range(194, 7)
            .unwrap()
            .low,
        17
    );
    assert_eq!(
        f.finish(),
        Ok(Progress::EventComplete { command_id: 0x999 })
    );
    assert_eq!(f.cache.image().quota_words[0] & 511, 6);
}
#[test]
fn consumed_zero_id_command_still_applies_real_requests_without_ack_publication() {
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.publish(194, 7);
    f.command(0, 0);
    f.service.begin_event().unwrap();
    assert_eq!(f.finish(), Ok(Progress::EventComplete { command_id: 0 }));
    assert_eq!(f.cache.image().quota_words[0] & 511, 7);
    assert_eq!(f.latest(208).unwrap() & 0xfff, 7);
    assert_eq!(f.latest(213), None);
    assert_eq!(
        f.memory
            .publication_bank()
            .pending_range(194, 7)
            .unwrap()
            .low,
        0
    );
}
#[test]
fn native_owner_abandonment_invalidates_kept_service_before_effects() {
    let mut f = Fixture::new();
    f.start();
    f.activate_manager();
    f.command(0x123, 0);
    f.service.begin_event().unwrap();
    let before = f.memory.publication_bank().requests().len();
    drop(f.native);
    assert_eq!(
        f.service.advance(
            Sources {
                manager: &f.manager,
                amcc: &mut f.amcc,
                frames: &f.frames.borrow()
            },
            &mut f.cache.quota_view(),
            &mut Access::new(0, 1000, &mut f.latch)
        ),
        Err(Error::Contract(refuse!(
            "PMP cache service native owner was abandoned"
        )))
    );
    assert_eq!(f.memory.publication_bank().requests().len(), before);
    assert_ne!(
        f.memory
            .publication_bank()
            .pending_range(198, 1)
            .unwrap()
            .low,
        0
    );
}
#[test]
fn abandoning_cache_service_does_not_reopen_the_native_recipient_claim() {
    let mut f = Fixture::new();
    drop(f.service);
    assert!(f.native.claim_cache_services(14, 30).is_err());
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_MCC_J473_DT, STELA_TEST_PMP_T8112"]
fn original_t8112_mc_command_housekeeping_ack_and_initialized_geometry_match() {
    let b = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&b),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    for (start, len, hash) in [
        (
            0x426c,
            1336,
            "94b459e6b28e452c98943fb07db8df932336955ce973c97ebb7dadc2188a39c4",
        ),
        (
            0x47a4,
            1304,
            "c65d5dc752b1592321cc44d79ed14fe0eb386cedb02d33772cfaa98bb0dd0966",
        ),
        (
            0x50b0,
            520,
            "de72571fe3bba53a8c2ae3058a4b09b323ee2976026efb334ed10f04d03c05c3",
        ),
    ] {
        assert_eq!(stela_formats::sha256(&b[start..start + len]), hash);
    }
    let w = |a: usize| u32::from_le_bytes(b[a - 0xfff000..a - 0xfff000 + 4].try_into().unwrap());
    for (a, word) in [
        (0x10032c8, 0xb9485934),
        (0x1003318, 0xf901f260),
        (0x1003800, 0xb943c268),
        (0x1003810, 0xb9429908),
        (0x1003908, 0x94003ce1),
        (0x1003a98, 0x94003c7d),
        (0x1003ad4, 0x54ffebc1),
        (0x1003b54, 0x97fffd1d),
        (0x1003bb8, 0xf9043b09),
        (0x1003bbc, 0xf9043f08),
        (0x1003bf8, 0x531a65ad),
        (0x1003c68, 0x1b117db1),
        (0x1003c74, 0x8b314011),
        (0x1003ca8, 0x9400b18f),
        (0x1003890, 0xf828492a),
        (0x100416c, 0x97ffff5f),
        (0x1004224, 0x97ffff57),
        (0x10040dc, 0xb903c268),
        (0x10042a8, 0xb903c268),
        (0x1032f90, 0xfd41d680),
        (0x1032fa8, 0x0ea09801),
        (0x1032fbc, 0x2ea11c40),
        (0x1032fc8, 0xfd020260),
        (0x1019cc4, 0xb9026a6a),
        (0x1019cc8, 0xf9013a69),
    ] {
        assert_eq!(w(a), word, "{a:x}");
    }
    let bl = |a: usize| (a as i64 + i64::from((w(a) << 6) as i32 >> 4)) as usize;
    for (a, target) in [
        (0x1003908, 0x1012c8c),
        (0x1003a98, 0x1012c8c),
        (0x1003b54, 0x1002fc8),
        (0x1003ca8, 0x10302e4),
        (0x100416c, 0x1003ee8),
        (0x1004224, 0x1003f80),
    ] {
        assert_eq!(bl(a), target);
    }
    let mismatch = w(0x1003ad4);
    let displacement = (((mismatch >> 5) & 0x7ffff) << 13) as i32 >> 11;
    assert_eq!((0x1003ad4i64 + i64::from(displacement)) as usize, 0x100384c);
    assert_eq!(mismatch & 15, 1);
    assert_eq!((w(0x1003c74) >> 13) & 7, 2); // ADD uses UXTW after W32 multiplication.
    let scale = w(0x1046ab8 + 0x270)
        .wrapping_mul(w(0x1046ab8 + 0x274))
        .wrapping_mul(w(0x1034380))
        .wrapping_shl(6);
    assert_eq!(SCALE, scale);
    assert_eq!(SCALE, 2048);
    assert_eq!([w(0x1046ab8 + 0x3a8), w(0x1046ab8 + 0x3ac)], [0, 0]);
    assert_eq!([w(0x1034380), w(0x1034384)], [8, 2]);
    let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&dt),
        "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
    );
    let root = stela_contracts::adt::Node::root(&dt).unwrap();
    let nub = root
        .child("arm-io")
        .unwrap()
        .child("pmp")
        .unwrap()
        .child("iop-pmp-nub")
        .unwrap();
    let raw = nub.property("soc-device").unwrap();
    let banks = u32::from_le_bytes(raw[124 + 12..124 + 16].try_into().unwrap());
    assert_eq!((banks - w(0x1046ab8 + 0x278)) * w(0x1034384), GROUPS as u32);
    let f = Fixture::new();
    assert_eq!(f.amcc.generic().periods().1, 7);
}
