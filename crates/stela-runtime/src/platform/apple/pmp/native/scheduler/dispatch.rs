//! Actual callback execution and source queue scan ordering.
use super::*;

impl State {
    fn ready(&self, frame: &Frame, now: u64) -> bool {
        frame.status.get() == Status::Active
            && !frame.executing.get()
            && frame.deadline.get().is_none_or(|deadline| now >= deadline)
            && waits::runnable(self, &frame.thread)
    }
    fn scan(&mut self, queue: usize) -> Option<usize> {
        // At most the retained scan plus one coalesced wake/retry cycle. No
        // callback or absent-work completion is manufactured by an empty scan.
        for _ in 0..3 {
            let q = &mut self.queues[queue];
            if !q.scanning {
                if !q.notified {
                    return None;
                }
                q.notified = false;
                q.scanning = true;
                q.cursor = 0;
                q.retry_cycle = false;
            }
            while q.cursor < q.order.len() {
                let work = q.order[q.cursor];
                if self.works[work].cells.enabled.get() && self.works[work].cells.pending.get() {
                    return Some(work);
                }
                q.cursor += 1;
            }
            if q.retry_cycle {
                q.retry_cycle = false;
                q.cursor = 0;
            } else {
                q.scanning = false;
            }
        }
        None
    }
}
impl Runtime {
    /// Actual retained runnable work only. Key/mutex-blocked threads have no
    /// deadline until their real owner wakes/unlocks them; zero means runnable.
    pub fn next_deadline(&self) -> Option<u64> {
        let s = self.state.borrow();
        let mut deadline = None;
        let mut add = |frame: &Frame| {
            if frame.status.get() == Status::Active
                && !frame.executing.get()
                && waits::runnable(&s, &frame.thread)
            {
                let next = frame.deadline.get().unwrap_or(0);
                deadline = Some(deadline.map_or(next, |prior: u64| prior.min(next)));
            }
        };
        for queue in &s.queues {
            if let Some(id) = queue.active {
                if let Some(frame) = s.works[id].target.frame.as_ref() {
                    add(frame);
                }
            }
        }
        for immediate in &s.immediate {
            if let Some(frame) = immediate.target.frame.as_ref() {
                add(frame);
            }
        }
        if s.queues.iter().any(|q| {
            q.active.is_none()
                && q.lock.is_none()
                && q.order
                    .iter()
                    .any(|id| s.works[*id].cells.enabled.get() && s.works[*id].cells.pending.get())
        }) {
            return Some(0);
        }
        deadline
    }
    /// One actual callback step. Queues use source thread priorities (larger
    /// numeric priority first) and stable source work-list order. An unfinished
    /// callback retains its queue thread; releasing a lock for a drain does not
    /// create a second worker on the same queue.
    pub fn step(&self, access: &mut Access<'_>) -> Result<Progress> {
        let kind = {
            let mut s = self.state.borrow_mut();
            let mut queues: Vec<usize> = (0..s.queues.len()).collect();
            queues.sort_by_key(|id| core::cmp::Reverse(s.queues[*id].thread.priority));
            let mut selected = None;
            for queue in queues {
                if let Some(work) = s.queues[queue].active {
                    let frame = s.works[work]
                        .target
                        .frame
                        .as_ref()
                        .ok_or(Error::Contract("native active work has no invocation"))?;
                    if s.ready(frame, access.now) {
                        selected = Some(Kind::Work(work));
                        break;
                    }
                    continue;
                }
                if s.queues[queue].lock.is_some() {
                    continue;
                }
                let pending = s.queues[queue]
                    .order
                    .iter()
                    .any(|id| s.works[*id].cells.enabled.get() && s.works[*id].cells.pending.get());
                if !pending {
                    // Retire the real empty scan/wake credit too.
                    s.scan(queue);
                    continue;
                }
                // Preflight serial before consuming wake credit, changing scan
                // state, acquiring the lock or clearing the actual pending bit.
                let serial = s.next_serial()?;
                let Some(work) = s.scan(queue) else {
                    continue;
                };
                let thread = s.queues[queue].thread.clone();
                let frame = Rc::new(Frame {
                    serial,
                    kind: Kind::Work(work),
                    thread: thread.clone(),
                    status: Cell::new(Status::Active),
                    executing: Cell::new(false),
                    deadline: Cell::new(None),
                    leases: Cell::new(0),
                });
                let q = &mut s.queues[queue];
                q.active = Some(work);
                q.lock = Some(thread.id);
                q.depth = 1;
                s.serial = serial;
                s.works[work].cells.pending.set(false);
                fence(Ordering::SeqCst);
                s.works[work].target.frame = Some(frame);
                selected = Some(Kind::Work(work));
                break;
            }
            selected
        };
        match kind {
            Some(kind) => self.execute(kind, access),
            None => Ok(Progress::Idle),
        }
    }
    /// Invoke the mandatory registered immediate endpoint callback, including
    ///while a DB work callback retains a key wait/recursive queue lock. Incoming
    ///message ownership remains with the actual mailbox driver; this API does
    ///not mint input or pretend a missing callback accepted it.
    pub fn invoke(&self, immediate: &Immediate, access: &mut Access<'_>) -> Result<Progress> {
        self.check_runtime(&immediate.runtime)?;
        let kind = Kind::Immediate(immediate.id);
        {
            let mut s = self.state.borrow_mut();
            if let Some(frame) = s.target(kind).frame.as_ref() {
                if frame.executing.get() {
                    return Err(Error::Contract(
                        "same native immediate callback already executing",
                    ));
                }
                if !s.ready(frame, access.now) {
                    return Ok(Progress::Busy {
                        deadline: frame.deadline.get(),
                    });
                }
            } else {
                let serial = s.next_serial()?;
                let thread = s.immediate[immediate.id].thread.clone();
                s.serial = serial;
                s.target_mut(kind).frame = Some(Rc::new(Frame {
                    serial,
                    kind,
                    thread,
                    status: Cell::new(Status::Active),
                    executing: Cell::new(false),
                    deadline: Cell::new(None),
                    leases: Cell::new(0),
                }));
            }
        }
        self.execute(kind, access)
    }
    fn execute(&self, kind: Kind, access: &mut Access<'_>) -> Result<Progress> {
        let (mut callback, invocation) = {
            let mut s = self.state.borrow_mut();
            if s.target(kind).retired.is_some() {
                return self.finish_retired_locked(&mut s, kind);
            }
            let frame = s
                .target(kind)
                .frame
                .as_ref()
                .ok_or(Error::Contract("native dispatch lacks invocation"))?
                .clone();
            if frame.executing.get() {
                return Err(Error::Contract(
                    "native callback recursively reentered itself",
                ));
            }
            let callback = s
                .target_mut(kind)
                .callback
                .take()
                .ok_or(Error::Contract("native registered callback is absent"))?;
            frame.executing.set(true);
            s.context.push(frame.clone());
            (
                callback,
                Invocation {
                    runtime: Rc::downgrade(&self.state),
                    frame,
                },
            )
        };
        // No scheduler RefCell borrow is held across the actual callback.
        // It may wake work, wait/unlock, or invoke a different immediate target.
        let result = callback.advance(&invocation, access);
        let mut s = self.state.borrow_mut();
        let top = s
            .context
            .pop()
            .ok_or(Error::Contract("native callback context disappeared"))?;
        if !Rc::ptr_eq(&top, &invocation.frame) {
            return Err(Error::Contract("native callback context nesting corrupted"));
        }
        invocation.frame.executing.set(false);
        s.target_mut(kind).callback = Some(callback);
        match result {
            Completion::Busy { deadline } => {
                let deadline = if waits::notified(&invocation.frame.thread) {
                    None
                } else {
                    deadline
                };
                invocation.frame.deadline.set(deadline);
                Ok(Progress::Busy { deadline })
            }
            Completion::Refused(reason) => Err(Error::Callback(reason)),
            Completion::Retired { value, refusal } => {
                invocation.frame.deadline.set(None);
                s.target_mut(kind).retired = Some((value, refusal));
                self.finish_retired_locked(&mut s, kind)
            }
        }
    }
    fn finish_retired_locked(&self, s: &mut State, kind: Kind) -> Result<Progress> {
        let frame = s
            .target(kind)
            .frame
            .as_ref()
            .ok_or(Error::Contract("retired native callback lost invocation"))?
            .clone();
        let (source_return, refusal) = s
            .target(kind)
            .retired
            .ok_or(Error::Contract("native callback has not actually retired"))?;
        if frame.leases.get() != 0
            || frame.thread.wait.borrow().is_some()
            || frame.thread.mutex.get().is_some()
        {
            // Preserve the already-retired result. Never rerun an actual callback
            // just because its adapter failed to retire a lock/wait prefix.
            return Err(Error::Contract(
                "native callback returned while retaining lock/wait ownership",
            ));
        }
        if let Kind::Work(work) = kind {
            let queue = s.works[work]
                .queue
                .ok_or(Error::Contract("native callback lost registered queue"))?;
            let q = &s.queues[queue];
            if q.active != Some(work) || q.lock != Some(frame.thread.id) || q.depth != 1 {
                return Err(Error::Contract(
                    "native callback did not restore its queue lock",
                ));
            }
            if source_return != 0 {
                s.works[work].cells.pending.set(true);
            }
            let q = &mut s.queues[queue];
            q.active = None;
            q.lock = None;
            q.depth = 0;
            if source_return != 0 {
                q.retry_cycle = true;
            }
            q.cursor = if q.sorted {
                0
            } else {
                q.order
                    .iter()
                    .position(|id| *id == work)
                    .ok_or(Error::Contract("native registered work disappeared"))?
                    + 1
            };
        }
        frame.status.set(Status::Retired);
        let target = s.target_mut(kind);
        target.frame = None;
        target.retired = None;
        Ok(Progress::Retired {
            invocation: Invocation {
                runtime: Rc::downgrade(&self.state),
                frame,
            },
            source_return,
            refusal,
        })
    }
    pub fn immediate_name(&self, immediate: &Immediate) -> Result<String> {
        self.check_runtime(&immediate.runtime)?;
        Ok(self.state.borrow().immediate[immediate.id].name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    struct Order {
        name: &'static str,
        log: Rc<RefCell<Vec<&'static str>>>,
    }
    impl Callback for Order {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            i.check_current().unwrap();
            self.log.borrow_mut().push(self.name);
            Completion::Retired {
                value: 0,
                refusal: None,
            }
        }
    }
    fn step(r: &Runtime) -> Result<Progress> {
        let mut latch = InterruptLatch::new();
        r.step(&mut Access::new(0, 100, &mut latch))
    }
    #[test]
    fn real_callbacks_follow_thread_and_work_priority_with_stable_equal_order() {
        let r = Runtime::new();
        let log = Rc::new(RefCell::new(Vec::new()));
        let global = r
            .create_queue(QueueConfiguration::global_reporting())
            .unwrap();
        let mc = r.create_queue(QueueConfiguration::mc_metrics()).unwrap();
        for (queue, name, priority) in [
            (&global, "global", 15),
            (&mc, "a", 15),
            (&mc, "b", 15),
            (&mc, "high", 16),
        ] {
            let work = r
                .bind_work(
                    priority,
                    Order {
                        name,
                        log: log.clone(),
                    },
                )
                .unwrap();
            r.register_work(queue, &work);
            r.wake(&work).unwrap();
        }
        for _ in 0..4 {
            assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        }
        assert_eq!(&*log.borrow(), &["high", "a", "b", "global"]);
    }
    struct Rewake {
        runtime: Runtime,
        work: Rc<RefCell<Option<Work>>>,
        calls: u32,
        first: Option<Invocation>,
        seen: Rc<Cell<u32>>,
    }
    impl Callback for Rewake {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.calls += 1;
            self.seen.set(self.calls);
            let work = self.work.borrow();
            let work = work.as_ref().unwrap();
            work.validate_dispatch(i).unwrap();
            if self.calls == 1 {
                assert!(!work.pending());
                self.first = Some(i.clone());
                self.runtime.wake(work).unwrap();
                return Completion::Busy { deadline: None };
            }
            if self.calls == 2 {
                assert!(self.first.as_ref().unwrap().same_dispatch(i));
                assert!(work.pending());
            } else {
                assert!(!self.first.as_ref().unwrap().same_dispatch(i));
                assert!(!work.pending());
            }
            Completion::Retired {
                value: 0,
                refusal: None,
            }
        }
    }
    #[test]
    fn callback_wake_during_busy_survives_actual_return_zero_and_retries_same_lease() {
        let r = Runtime::new();
        let q = r.create_queue(QueueConfiguration::mc_metrics()).unwrap();
        let handle = Rc::new(RefCell::new(None));
        let seen = Rc::new(Cell::new(0));
        let w = r
            .bind_work(
                15,
                Rewake {
                    runtime: r.clone(),
                    work: handle.clone(),
                    calls: 0,
                    first: None,
                    seen: seen.clone(),
                },
            )
            .unwrap();
        *handle.borrow_mut() = Some(w.clone());
        r.register_work(&q, &w);
        r.wake(&w).unwrap();
        assert!(matches!(step(&r).unwrap(), Progress::Busy { .. }));
        assert!(w.pending());
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert!(w.pending());
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert!(!w.pending());
        assert_eq!(seen.get(), 3);
    }
    struct Refuses {
        seen: Rc<RefCell<Vec<Invocation>>>,
    }
    impl Callback for Refuses {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.seen.borrow_mut().push(i.clone());
            if self.seen.borrow().len() == 1 {
                Completion::Refused("actual native callback destination refused")
            } else {
                Completion::Retired {
                    value: 1,
                    refusal: Some("actual retired callback diagnostic"),
                }
            }
        }
    }
    #[test]
    fn refusal_keeps_actual_invocation_and_retired_diagnostic_requeues_once() {
        let r = Runtime::new();
        let q = r.create_queue(QueueConfiguration::mc_metrics()).unwrap();
        let seen = Rc::new(RefCell::new(Vec::new()));
        let w = r.bind_work(15, Refuses { seen: seen.clone() }).unwrap();
        r.register_work(&q, &w);
        r.wake(&w).unwrap();
        assert!(matches!(step(&r), Err(Error::Callback(_))));
        assert!(!w.pending());
        assert!(matches!(
            step(&r).unwrap(),
            Progress::Retired {
                source_return: 1,
                refusal: Some(_),
                ..
            }
        ));
        assert!(w.pending());
        let seen = seen.borrow();
        assert!(seen[0].same_dispatch(&seen[1]));
        assert!(seen[0].check_current().is_err());
    }
}

#[cfg(test)]
mod retained_tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    struct AbandonedLease {
        runtime: Runtime,
        queue: Queue,
        calls: Rc<Cell<u32>>,
    }
    impl Callback for AbandonedLease {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.calls.set(self.calls.get() + 1);
            let Completion::Retired { value, .. } = self.runtime.lock(&self.queue, i) else {
                panic!("native test lock unavailable")
            };
            drop(value); // Source has not executed unlock; dropping cannot fake it.
            Completion::Retired {
                value: 0,
                refusal: None,
            }
        }
    }
    #[test]
    fn already_retired_callback_with_abandoned_lock_is_never_replayed() {
        let r = Runtime::new();
        let q = r.global_reporting_queue().unwrap();
        let calls = Rc::new(Cell::new(0));
        let w = r
            .bind_work(
                15,
                AbandonedLease {
                    runtime: r.clone(),
                    queue: q.clone(),
                    calls: calls.clone(),
                },
            )
            .unwrap();
        r.register_work(&q, &w);
        r.wake(&w).unwrap();
        let mut irq = InterruptLatch::new();
        for _ in 0..2 {
            assert!(matches!(
                r.step(&mut Access::new(0, 0, &mut irq)),
                Err(Error::Contract(_))
            ));
        }
        assert_eq!(calls.get(), 1);
        assert_eq!(r.queue_lock_depth(&q).unwrap(), 2);
        assert!(!w.pending());
    }
}
