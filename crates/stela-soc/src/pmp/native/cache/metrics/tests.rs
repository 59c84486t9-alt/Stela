use super::*;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;
#[derive(Clone)]
struct Samples {
    geometry: Geometry,
    data: Vec<[u8; 64]>,
    forbid_read: bool,
}
impl Samples {
    fn new() -> Self {
        Self {
            geometry: Geometry {
                groups: 2,
                platform_scale: 8,
                interval: 7,
            },
            data: alloc::vec![[0;64];2],
            forbid_read: false,
        }
    }
}
impl SamplesView for Samples {
    fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn group(&self, g: u32) -> Result<&[u8; 64], Error> {
        if self.forbid_read {
            return Err(Error::Contract(refuse!("authored sample read forbidden")));
        }
        self.data
            .get(g as usize)
            .ok_or(Error::Contract(refuse!("authored sample group absent")))
    }
}
// Authored destination fault controls stay cfg(test). Queue binding and
// callback dispatch themselves use the scheduler, with Weak owner
// capture; no production local scheduler or duplicate pending bit exists.
type Slot = Rc<core::cell::RefCell<alloc::rc::Weak<core::cell::RefCell<Option<Owner<Sink>>>>>>;
struct Sink {
    runtime: super::super::super::scheduler::Runtime,
    queue: Option<super::super::super::scheduler::Queue>,
    work: Option<Work>,
    owner: Slot,
    samples: Rc<core::cell::RefCell<Samples>>,
    effects: Vec<(Request, Effect)>,
    reads: Vec<Request>,
    trace: u32,
    busy_notify: bool,
    refuse_trace: bool,
    retired_trace: bool,
    notifications: u32,
    wait: bool,
    refuse_init: bool,
    omit_registration: bool,
    omit_wake: bool,
    check_replay: bool,
    refuse_metric: Option<(u32, MetricKind)>,
}
impl Sink {
    fn new() -> Self {
        Self {
            runtime: super::super::super::scheduler::Runtime::new(),
            queue: None,
            work: None,
            owner: Rc::new(core::cell::RefCell::new(alloc::rc::Weak::new())),
            samples: Rc::new(core::cell::RefCell::new(Samples::new())),
            effects: Vec::new(),
            reads: Vec::new(),
            trace: 0,
            busy_notify: false,
            refuse_trace: false,
            retired_trace: false,
            notifications: 0,
            wait: false,
            refuse_init: false,
            omit_registration: false,
            omit_wake: false,
            check_replay: false,
            refuse_metric: None,
        }
    }
}
struct InvokeMetrics {
    owner: Slot,
    samples: Rc<core::cell::RefCell<Samples>>,
}
impl super::super::super::scheduler::Callback for InvokeMetrics {
    fn advance(&mut self, invocation: &Invocation, access: &mut Access<'_>) -> Completion<u32> {
        let Some(owner) = self.owner.borrow().upgrade() else {
            return Completion::Refused(refuse!("authored actual metrics owner absent"));
        };
        let mut owner = owner.borrow_mut();
        let Some(owner) = owner.as_mut() else {
            return Completion::Refused(refuse!("authored actual metrics owner moved"));
        };
        match owner.dispatch(invocation, &*self.samples.borrow(), access) {
            Ok(Progress::CallbackComplete) => {
                if owner.backend.check_replay {
                    assert!(matches!(
                        owner.dispatch(invocation, &*self.samples.borrow(), access),
                        Err(Error::Contract(
                            reason
                        )) if reason == refuse!("MC callback source return already retired for this invocation")
                    ));
                }
                Completion::Retired {
                    value: 0,
                    refusal: None,
                }
            }
            Ok(Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(_) => {
                Completion::Refused(refuse!("authored metrics callback returned wrong progress"))
            }
            Err(Error::Backend(reason) | Error::Contract(reason)) => Completion::Refused(reason),
        }
    }
}
impl Backend for Sink {
    fn work(&self) -> Option<&Work> {
        self.work.as_ref()
    }
    fn effect(&mut self, r: &Request, e: &Effect, _: &mut Access<'_>) -> Completion<()> {
        self.effects.push((r.clone(), e.clone()));
        if let Effect::RegisterMetric { group, kind, .. } = e
            && self.refuse_metric == Some((*group, *kind))
        {
            self.refuse_metric = None;
            return Completion::Refused(refuse!("authored unavailable metric destination"));
        }
        if matches!(e, Effect::InitializeQueue { .. }) && self.refuse_init {
            self.refuse_init = false;
            return Completion::Refused(refuse!("authored missing native queue resource"));
        }

        if matches!(e, Effect::NotifyStop) && self.busy_notify {
            self.busy_notify = false;
            return Completion::Busy { deadline: Some(9) };
        }
        if matches!(e, Effect::Trace { .. }) && self.refuse_trace {
            self.refuse_trace = false;
            return Completion::Refused(refuse!("authored unavailable trace destination"));
        }
        if matches!(e, Effect::DrainWait) && self.wait && self.notifications == 0 {
            return Completion::Busy { deadline: Some(11) };
        }
        if matches!(e, Effect::NotifyStop) {
            self.notifications += 1;
        }
        use super::super::super::scheduler::QueueConfiguration;
        match e {
            Effect::InitializeQueue {
                name,
                stack_bytes,
                priority,
            } => {
                self.queue = Some(
                    self.runtime
                        .create_queue(QueueConfiguration {
                            name: (*name).into(),
                            stack_bytes: *stack_bytes,
                            priority: *priority,
                        })
                        .unwrap(),
                );
            }
            Effect::BindWork { priority } => {
                self.work = Some(
                    self.runtime
                        .bind_work(
                            *priority,
                            InvokeMetrics {
                                owner: self.owner.clone(),
                                samples: self.samples.clone(),
                            },
                        )
                        .unwrap(),
                );
            }
            Effect::RegisterWork if !self.omit_registration => {
                return self
                    .runtime
                    .register_work(self.queue.as_ref().unwrap(), self.work.as_ref().unwrap());
            }
            Effect::Wake if !self.omit_wake => {
                self.runtime.wake(self.work.as_ref().unwrap()).unwrap()
            }
            _ => {}
        }
        let refusal = if matches!(e, Effect::Trace { .. }) && self.retired_trace {
            self.retired_trace = false;
            Some(refuse!("authored trace retired prefix refusal"))
        } else {
            None
        };
        Completion::Retired { value: (), refusal }
    }
    fn trace_control(&mut self, r: &Request, _: &mut Access<'_>) -> Completion<u32> {
        self.reads.push(r.clone());
        Completion::Retired {
            value: self.trace,
            refusal: None,
        }
    }
}
fn callback_step(o: &mut Owner<Sink>, s: &Samples) -> Result<Progress, Error> {
    let runtime = o.backend.runtime.clone();
    let slot = o.backend.owner.clone();
    *o.backend.samples.borrow_mut() = s.clone();
    // The authored fixture temporarily loans this same owner into a Weak
    // callback slot. There is no pointer cast or Work->Rc<Owner> cycle.
    let placeholder = Owner::initialized_source(Configuration::t8112(), Sink::new());
    let loan = Rc::new(core::cell::RefCell::new(Some(core::mem::replace(
        o,
        placeholder,
    ))));
    *slot.borrow_mut() = Rc::downgrade(&loan);
    let mut latch = InterruptLatch::new();
    let result = runtime.step(&mut Access::new(0, 100, &mut latch));
    *slot.borrow_mut() = alloc::rc::Weak::new();
    *o = loan.borrow_mut().take().unwrap();
    use super::super::super::scheduler;
    match result {
        Ok(scheduler::Progress::Retired { refusal: None, .. }) => Ok(Progress::CallbackComplete),
        Ok(scheduler::Progress::Retired {
            refusal: Some(reason),
            ..
        }) => Err(Error::Backend(reason)),
        Ok(scheduler::Progress::Busy { deadline }) => Ok(Progress::Busy { deadline }),
        Ok(scheduler::Progress::Idle) => Ok(Progress::Busy { deadline: None }),
        Err(scheduler::Error::Contract(reason)) => Err(Error::Contract(reason)),
        Err(scheduler::Error::Callback(reason)) => Err(Error::Backend(reason)),
    }
}
fn step(o: &mut Owner<Sink>, s: &Samples) -> Result<Progress, Error> {
    if o.control.is_some() {
        let mut latch = InterruptLatch::new();
        let result = o.advance(s, &mut Access::new(0, 100, &mut latch));
        // Authored harness supplies the independent executor while a
        // foreground source Stop wait is held. Production root owns it.
        if matches!(result, Ok(Progress::Busy { .. }))
            && o.stopping
            && (o.queued() || o.callback_executing())
        {
            let _ = callback_step(o, s)?;
        }
        result
    } else if o.queued() || o.callback_executing() {
        callback_step(o, s)
    } else {
        let mut latch = InterruptLatch::new();
        o.advance(s, &mut Access::new(0, 100, &mut latch))
    }
}
fn until(o: &mut Owner<Sink>, s: &Samples, want: Progress) {
    for _ in 0..256 {
        if step(o, s).unwrap() == want {
            return;
        }
    }
    panic!("bounded metrics work did not reach {want:?}")
}
fn initialized() -> (Owner<Sink>, Samples) {
    let mut o = Owner::initialized_source(Configuration::t8112(), Sink::new());
    let s = Samples::new();
    o.begin_initialize().unwrap();
    until(&mut o, &s, Progress::Initialized);
    (o, s)
}
#[test]
fn scheduler_registration_and_wake_cannot_be_replaced_by_effect_success() {
    let mut sink = Sink::new();
    sink.omit_registration = true;
    let mut o = Owner::initialized_source(Configuration::t8112(), sink);
    let samples = Samples::new();
    o.begin_initialize().unwrap();
    step(&mut o, &samples).unwrap();
    step(&mut o, &samples).unwrap();
    assert_eq!(
        step(&mut o, &samples),
        Err(Error::Contract(refuse!(
            "MC actual work registration did not occur"
        )))
    );
    assert!(!o.initialized() && !o.queued());
    let (mut o, samples) = initialized();
    o.backend.omit_wake = true;
    o.submit_after_housekeeping().unwrap();
    assert!(o.pending() && !o.queued()); // No local shadow pending on submit.
    assert_eq!(
        step(&mut o, &samples),
        Err(Error::Contract(refuse!(
            "MC Wake retired without scheduling actual Work"
        )))
    );
    assert!(o.pending() && !o.queued());
}
#[test]
fn missing_weak_callback_owner_refuses_and_same_invocation_can_retry() {
    let (mut o, samples) = initialized();
    o.backend.check_replay = true;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &samples, Progress::Scheduled);
    let runtime = o.backend.runtime.clone();
    let mut irq = InterruptLatch::new();
    assert!(matches!(
        runtime.step(&mut Access::new(0, 100, &mut irq)),
        Err(super::super::super::scheduler::Error::Callback(
            reason
        )) if reason == refuse!("authored actual metrics owner absent")
    ));
    assert!(!o.queued() && o.pending() && !o.callback_executing());
    // Retry enters the scheduler Invocation rather than re-waking
    // or manufacturing a completion after the weak lookup failure.
    for _ in 0..32 {
        if callback_step(&mut o, &samples).unwrap() == Progress::CallbackComplete {
            break;
        }
    }
    assert!(!o.pending() && !o.queued());
    assert_eq!(o.backend.notifications, 1);
    assert!(o.last_dispatch.as_ref().unwrap().check_current().is_err());
}
#[test]
fn registration_live_getters_and_source_once_flag() {
    let (mut o, s) = initialized();
    assert!(o.initialized());
    o.begin_register(5).unwrap();
    until(&mut o, &s, Progress::Registered);
    assert!(o.registered());
    assert_eq!(o.group_association(0), Ok(Some(0)));
    assert_eq!(o.group_association(1), Ok(None));
    assert_eq!(o.group_association(2), Ok(Some(2)));
    let bindings: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter_map(|(_, e)| {
            if let Effect::RegisterMetric {
                group,
                kind,
                format,
                unit_descriptor,
                counter,
                name,
                namespace,
            } = e
            {
                assert_eq!(*format, 2);
                assert_eq!(*unit_descriptor, 0x0900820000000000);
                assert_eq!(*namespace, "DSID Stats");
                assert_eq!(
                    *name,
                    format!(
                        "Grp{} {}",
                        group,
                        if *kind == MetricKind::Hits {
                            "Hits"
                        } else {
                            "Misses"
                        }
                    )
                );
                Some((*group, *kind, counter.clone()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(bindings.len(), 4);
    o.accumulate(2, [u32::MAX, 7]).unwrap();
    assert_eq!(bindings[2].2.value(), u64::from(u32::MAX));
    assert_eq!(bindings[3].2.value(), 7);
    assert!(
        bindings[2]
            .2
            .same_counter(&o.counter(2, MetricKind::Hits).unwrap())
    );
    let n = o.backend.effects.len();
    o.begin_register(5).unwrap();
    until(&mut o, &s, Progress::Registered);
    assert_eq!(o.backend.effects.len(), n);
    assert!(o.begin_register(1).is_err());
}
#[test]
fn group_association_requires_both_registrations_and_preserves_prior_prefix() {
    let (mut o, s) = initialized();
    o.backend.refuse_metric = Some((1, MetricKind::Misses));
    o.begin_register(3).unwrap();
    assert_eq!(o.group_association(0), Ok(None));
    step(&mut o, &s).unwrap(); // Group0 Hits retires.
    assert_eq!(o.group_association(0), Ok(None));
    step(&mut o, &s).unwrap(); // Group0 Misses retires.
    assert_eq!(o.group_association(0), Ok(None));
    step(&mut o, &s).unwrap(); // Associate0, then Group1 Hits.
    assert_eq!(o.group_association(0), Ok(Some(0)));
    assert_eq!(o.group_association(1), Ok(None));
    assert!(matches!(step(&mut o, &s), Err(Error::Backend(_))));
    assert_eq!(o.group_association(0), Ok(Some(0)));
    assert_eq!(o.group_association(1), Ok(None));
    assert!(!o.registered());
    let refused = o.backend.effects.last().unwrap().0.clone();
    step(&mut o, &s).unwrap();
    assert!(refused.same_operation(&o.backend.effects.last().unwrap().0));
    assert_eq!(o.group_association(1), Ok(None));
    assert_eq!(step(&mut o, &s), Ok(Progress::Registered));
    assert_eq!(o.group_association(1), Ok(Some(1)));
    assert!(o.group_association(32).is_err());
}
#[test]
fn schedule_deduplicates_without_inline_callback_and_fast_cleanup_notifies() {
    let (mut o, mut s) = initialized();
    o.begin_register(1).unwrap();
    until(&mut o, &s, Progress::Registered);
    s.forbid_read = true;
    assert!(o.submit_after_housekeeping().unwrap());
    assert!(!o.submit_after_housekeeping().unwrap());
    until(&mut o, &s, Progress::Scheduled);
    assert!(o.pending() && o.queued());
    assert!(!o.callback_executing());
    assert!(o.backend.reads.is_empty());
    until(&mut o, &s, Progress::CallbackComplete);
    assert!(!o.pending() && !o.queued());
    assert_eq!(o.backend.notifications, 1);
}
#[test]
fn detailed_callback_uses_fields_and_native_wrapping_arithmetic() {
    let (mut o, mut s) = initialized();
    o.begin_register(1).unwrap();
    until(&mut o, &s, Progress::Registered);
    o.apply_registry_control(RegistryControl::Statistics(1));
    o.backend.trace = 1;
    s.data[0][..8].copy_from_slice(&(70u64 | (100u64 << 32)).to_le_bytes());
    s.data[0][32..40].copy_from_slice(&(5u64 | (2u64 << 32)).to_le_bytes());
    s.data[0][48..56].copy_from_slice(&(9u64 << 32).to_le_bytes());
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    until(&mut o, &s, Progress::CallbackComplete);
    let traces: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter_map(|(_, e)| {
            if let Effect::Trace { event, args } = e {
                Some((*event, *args))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(traces.len(), 4);
    assert_eq!(traces[0], (0x860bb000, [1, 0, 0, 0]));
    assert_eq!(
        traces[1],
        (
            0x860bb400,
            [
                (70 * 2048u64 * 1_000_000 / 56) >> 20,
                (100 * 2048u64 * 1_000_000 / 56) >> 20,
                70 * 2048,
                100 * 2048
            ]
        )
    );
    assert_eq!(traces[2], (0x860bb410, [1280, 4608, 0, 2]));
    assert_eq!(traces[3], (0x860bb000, [0; 4]));
    assert_eq!(o.backend.notifications, 1);
}
#[test]
fn rate_udiv_zero_preserves_raw_counts_for_zero_and_wrapped_intervals() {
    for interval in [0, 1u64 << 61] {
        let (mut o, mut s) = initialized();
        o.begin_register(1).unwrap();
        until(&mut o, &s, Progress::Registered);
        o.apply_registry_control(RegistryControl::Statistics(1));
        o.backend.trace = 1;
        s.geometry.interval = interval;
        s.data[0][..8].copy_from_slice(&(70u64 | (100u64 << 32)).to_le_bytes());
        o.submit_after_housekeeping().unwrap();
        until(&mut o, &s, Progress::Scheduled);
        until(&mut o, &s, Progress::CallbackComplete);
        assert!(o.backend.effects.iter().any(|(_, e)| matches!(
            e,
            Effect::Trace { event: 0x860bb400, args }
                if *args == [0, 0, 70 * 2048, 100 * 2048]
        )));
        assert_eq!(o.backend.notifications, 1);
    }
}
#[test]
fn callback_retirement_and_busy_keep_both_pending_lifecycles() {
    let (mut o, s) = initialized();
    o.backend.busy_notify = true;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    for _ in 0..32 {
        if step(&mut o, &s).unwrap() == (Progress::Busy { deadline: Some(9) }) {
            break;
        }
    }
    assert!(!o.pending() && !o.queued());
    let notify = o.backend.effects.last().unwrap().0.clone();
    assert!(o.submit_after_housekeeping().unwrap());
    until(&mut o, &s, Progress::Scheduled);
    assert!(o.pending() && o.queued());
    until(&mut o, &s, Progress::CallbackComplete);
    assert!(o.pending() && o.queued());
    let retries: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter(|(_, e)| matches!(e, Effect::NotifyStop))
        .collect();
    assert!(notify.same_operation(&retries[1].0));
    until(&mut o, &s, Progress::CallbackComplete);
    assert!(!o.pending() && !o.queued());
    assert_eq!(o.backend.notifications, 2);
}
#[test]
fn stop_drives_real_queued_callback_and_wait_notification() {
    let (mut o, s) = initialized();
    o.backend.wait = true;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    o.begin_stop().unwrap();
    until(&mut o, &s, Progress::Drained);
    assert_eq!(o.backend.notifications, 1);
    assert!(!o.pending() && !o.queued());
    let waits: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter(|(_, e)| matches!(e, Effect::DrainWait))
        .collect();
    assert!(waits.len() >= 2);
    assert!(waits[0].0.same_operation(&waits[1].0));
}
#[test]
fn stop_after_pending_clear_preserves_callback_tail_without_entering_wait() {
    let (mut o, s) = initialized();
    o.backend.busy_notify = true;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    let mut reached_notify = false;
    for _ in 0..32 {
        if step(&mut o, &s).unwrap() == (Progress::Busy { deadline: Some(9) }) {
            reached_notify = true;
            break;
        }
    }
    assert!(reached_notify && o.callback_executing());
    assert!(!o.pending() && !o.queued());
    let notify = o.backend.effects.last().unwrap().0.clone();
    o.begin_stop().unwrap();
    assert_eq!(step(&mut o, &s), Ok(Progress::Drained));
    assert!(o.callback_executing());
    assert_eq!(o.backend.notifications, 0);
    assert!(
        !o.backend
            .effects
            .iter()
            .any(|(_, e)| matches!(e, Effect::DrainWait))
    );
    until(&mut o, &s, Progress::CallbackComplete);
    assert!(!o.callback_executing());
    assert_eq!(o.backend.notifications, 1);
    assert!(notify.same_operation(&o.backend.effects.last().unwrap().0));
}
#[test]
fn trace_refusal_and_retired_prefix_cannot_complete_absent_destination() {
    let (mut o, s) = initialized();
    o.backend.trace = 1;
    o.backend.retired_trace = true;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    let mut refused = false;
    for _ in 0..32 {
        if matches!(step(&mut o, &s), Err(Error::Backend(_))) {
            refused = true;
            break;
        }
    }
    assert!(refused && o.pending());
    let n = o
        .backend
        .effects
        .iter()
        .filter(|(_, e)| matches!(e, Effect::Trace { .. }))
        .count();
    until(&mut o, &s, Progress::CallbackComplete);
    assert_eq!(
        o.backend
            .effects
            .iter()
            .filter(|(_, e)| matches!(e, Effect::Trace { .. }))
            .count(),
        n + 1
    );
}
#[test]
fn foreground_event_traces_leave_queued_work_untouched() {
    let (mut o, s) = initialized();
    o.backend.trace = 1;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    for event in [
        EventTrace::Enter,
        EventTrace::Request {
            group: 3,
            requested_bytes: 7 << 17,
        },
        EventTrace::Exit,
    ] {
        o.begin_event_trace(event).unwrap();
        until(&mut o, &s, Progress::TraceComplete);
        assert!(o.pending() && o.queued());
        assert!(o.callback.is_none())
    }
    let traces: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter_map(|(_, e)| {
            if let Effect::Trace { event, args } = e {
                Some((*event, *args))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        traces,
        alloc::vec![
            (0x860bb010, [1, 0, 0, 0]),
            (0x860bb10c, [7 << 17, 0, 0, 0]),
            (0x860bb010, [0; 4])
        ]
    );
    step(&mut o, &s).unwrap();
    assert!(o.callback_executing());
    assert!(o.begin_event_trace(EventTrace::Enter).is_err());
    until(&mut o, &s, Progress::CallbackComplete);
}
#[test]
fn absent_native_queue_cannot_initialize_or_admit_registration() {
    let mut sink = Sink::new();
    sink.refuse_init = true;
    let mut o = Owner::initialized_source(Configuration::t8112(), sink);
    let s = Samples::new();
    o.begin_initialize().unwrap();
    assert_eq!(
        step(&mut o, &s),
        Err(Error::Backend(refuse!(
            "authored missing native queue resource"
        )))
    );
    assert!(!o.initialized());
    assert!(!o.registered());
    assert!(o.begin_register(1).is_err());
    assert!(!o.pending() && !o.queued());
    until(&mut o, &s, Progress::Initialized);
    assert!(o.initialized());
    let a = &o.backend.effects;
    assert!(a[0].0.same_operation(&a[1].0));
}
#[test]
fn callback_widths_truncate_before_rates_and_nonzero_service_branch_still_notifies() {
    let (mut o, mut s) = initialized();
    o.begin_register(1).unwrap();
    until(&mut o, &s, Progress::Registered);
    o.apply_registry_control(RegistryControl::Statistics(1));
    o.backend.trace = 1;
    s.data[0][..8].copy_from_slice(&u64::MAX.to_le_bytes());
    s.data[0][32..40].copy_from_slice(&(u64::from(u32::MAX) | (1 << 32)).to_le_bytes());
    s.data[0][48..56].copy_from_slice(&(u64::from(u32::MAX) << 32).to_le_bytes());
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    until(&mut o, &s, Progress::CallbackComplete);
    let traces: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter_map(|(_, e)| {
            if let Effect::Trace { event, args } = e {
                Some((*event, *args))
            } else {
                None
            }
        })
        .collect();
    let scaled = u32::MAX.wrapping_mul(2048);
    assert_eq!(traces[1].1[2], u64::from(scaled));
    assert_eq!(
        traces[2].1[1],
        u64::from(u32::MAX.wrapping_shl(7).wrapping_mul(4))
    );
    o.service_word = 1;
    s.forbid_read = true;
    o.submit_after_housekeeping().unwrap();
    until(&mut o, &s, Progress::Scheduled);
    until(&mut o, &s, Progress::CallbackComplete);
    assert_eq!(o.backend.notifications, 2);
}
#[test]
fn preflight_serial_and_cursor_exhaustion_precede_effects() {
    let (mut o, s) = initialized();
    o.serial = u64::MAX;
    assert!(o.submit_after_housekeeping().is_err());
    assert!(!o.pending() && !o.queued());
    o.serial = 5;
    o.submit_after_housekeeping().unwrap();
    let n = o.backend.effects.len();
    o.control.as_mut().unwrap().cursor = u64::MAX;
    assert!(matches!(step(&mut o, &s), Err(Error::Contract(_))));
    assert_eq!(o.backend.effects.len(), n);
    assert!(o.pending() && !o.queued());
    assert!(step(&mut o, &s).is_err());
}
