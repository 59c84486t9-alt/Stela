//! Real identity-keyed wait, recursive queue lease, notify and reacquisition.
use super::*;

#[derive(Clone)]
pub struct Key {
    runtime: Weak<RefCell<State>>,
    identity: Rc<()>,
}
impl Key {
    pub fn same_key(&self, other: &Self) -> bool {
        self.runtime.ptr_eq(&other.runtime) && Rc::ptr_eq(&self.identity, &other.identity)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Waiting,
    Notified,
    Retired,
}
pub(super) struct Waiting {
    key: Key,
    thread: Weak<Thread>,
    frame: Weak<Frame>,
    released: Option<(usize, u32)>,
    phase: Cell<Phase>,
}
/// A real registered thread/key wait. Non-Clone, no signal/complete setter.
/// Dropping it does not wake or silently remove an outstanding source wait.
pub struct Wait {
    runtime: Weak<RefCell<State>>,
    waiting: Rc<Waiting>,
}
/// Actual recursive queue acquisition. Non-Clone and no Drop-time unlock:
/// source unlock must execute at its reached cursor. An abandoned lease leaves
/// the callback unable to claim retirement, preserving the unfinished effect.
pub struct Lease {
    runtime: Weak<RefCell<State>>,
    queue: usize,
    frame: Weak<Frame>,
    active: bool,
}
pub(super) fn notified(thread: &Thread) -> bool {
    thread
        .wait
        .borrow()
        .as_ref()
        .is_some_and(|wait| wait.phase.get() == Phase::Notified)
}
pub(super) fn runnable(state: &State, thread: &Thread) -> bool {
    if let Some(wait) = thread.wait.borrow().as_ref() {
        if wait.phase.get() == Phase::Waiting {
            return false;
        }
        if let Some((queue, _)) = wait.released
            && state.queues[queue].lock.is_some_and(|id| id != thread.id)
        {
            return false;
        }
    }
    if let Some(queue) = thread.mutex.get()
        && state.queues[queue].lock.is_some_and(|id| id != thread.id)
    {
        return false;
    }
    true
}
impl Runtime {
    pub fn key(&self) -> Key {
        Key {
            runtime: Rc::downgrade(&self.state),
            identity: Rc::new(()),
        }
    }
    /// Source1030048/1030210 recursive acquisition. Contention blocks this
    /// actual thread rather than spinning a high-priority callback and starving
    /// the lower-priority owner which must release the mutex.
    pub fn lock(&self, queue: &Queue, invocation: &Invocation) -> Completion<Lease> {
        if self
            .check_runtime(&queue.runtime)
            .and_then(|()| self.check_runtime(&invocation.runtime))
            .and_then(|()| invocation.check_current())
            .is_err()
        {
            return Completion::Refused("foreign or nonexecuting native queue acquisition");
        }
        if invocation.frame.thread.wait.borrow().is_some() {
            return Completion::Refused("native lock acquisition before wait retirement");
        }
        let mut s = self.state.borrow_mut();
        let q = &mut s.queues[queue.id];
        if q.lock
            .is_some_and(|thread| thread != invocation.thread_id())
        {
            invocation.frame.thread.mutex.set(Some(queue.id));
            return Completion::Busy { deadline: None };
        }
        let Some(depth) = q.depth.checked_add(1) else {
            return Completion::Refused("native queue recursion exhausted");
        };
        let Some(leases) = invocation.frame.leases.get().checked_add(1) else {
            return Completion::Refused("native queue lease count exhausted");
        };
        q.lock = Some(invocation.thread_id());
        q.depth = depth;
        invocation.frame.leases.set(leases);
        invocation.frame.thread.mutex.set(None);
        Completion::Retired {
            value: Lease {
                runtime: Rc::downgrade(&self.state),
                queue: queue.id,
                frame: Rc::downgrade(&invocation.frame),
                active: true,
            },
            refusal: None,
        }
    }
    /// Actual source-key wait, retaining held queue locks. Reporting publication
    /// uses an independent immediate ACK callback to notify this same key.
    pub fn wait(&self, invocation: &Invocation, key: &Key) -> Result<Wait> {
        self.register_wait(invocation, key, None)
    }
    ///1030250 atomically registers the actual waiter BEFORE dropping every
    /// recursive acquisition of this queue. Other queue work/immediate callbacks
    ///can then execute; returning Wait alone is not wait completion.
    pub fn drain_wait(&self, queue: &Queue, invocation: &Invocation, key: &Key) -> Result<Wait> {
        self.check_runtime(&queue.runtime)?;
        self.register_wait(invocation, key, Some(queue.id))
    }
    fn register_wait(
        &self,
        invocation: &Invocation,
        key: &Key,
        release: Option<usize>,
    ) -> Result<Wait> {
        self.check_runtime(&invocation.runtime)?;
        self.check_runtime(&key.runtime)?;
        invocation.check_current()?;
        let thread = invocation.frame.thread.clone();
        if thread.wait.borrow().is_some() || thread.mutex.get().is_some() {
            return Err(Error::Contract(
                "native thread already has an unfinished wait",
            ));
        }
        let mut s = self.state.borrow_mut();
        let released = if let Some(queue) = release {
            let q = &s.queues[queue];
            if q.lock != Some(thread.id) || q.depth == 0 {
                return Err(Error::Contract(
                    "native drain does not own recursive queue lock",
                ));
            }
            Some((queue, q.depth))
        } else {
            None
        };
        let waiting = Rc::new(Waiting {
            key: key.clone(),
            thread: Rc::downgrade(&thread),
            frame: Rc::downgrade(&invocation.frame),
            released,
            phase: Cell::new(Phase::Waiting),
        });
        // One borrow covers registration and release: no lost-notify gap.
        *thread.wait.borrow_mut() = Some(waiting.clone());
        s.waiters.push(Rc::downgrade(&waiting));
        if let Some((queue, _)) = released {
            s.queues[queue].lock = None;
            s.queues[queue].depth = 0;
        }
        fence(Ordering::SeqCst);
        Ok(Wait {
            runtime: Rc::downgrade(&self.state),
            waiting,
        })
    }
    ///1023624/10302bc wakes ALL actual waiters of the same identity. No numeric
    /// key alias, remembered notify credit, source-predicate update or callback
    /// completion is created. A later wait needs another actual notification.
    pub fn notify(&self, key: &Key) -> Result<usize> {
        self.check_runtime(&key.runtime)?;
        let mut s = self.state.borrow_mut();
        let mut count = 0;
        s.waiters.retain(|weak| {
            let Some(wait) = weak.upgrade() else {
                return false;
            };
            if wait.phase.get() == Phase::Waiting && wait.key.same_key(key) {
                wait.phase.set(Phase::Notified);
                if let Some(frame) = wait.frame.upgrade() {
                    frame.deadline.set(None);
                }
                count += 1;
            }
            wait.phase.get() == Phase::Waiting
        });
        fence(Ordering::Release);
        Ok(count)
    }
    pub fn queue_lock_depth(&self, queue: &Queue) -> Result<u32> {
        self.check_runtime(&queue.runtime)?;
        Ok(self.state.borrow().queues[queue.id].depth)
    }
}
impl Wait {
    /// Actual source wait completion/reacquisition, callable only by its same
    /// executing native invocation. Notification alone never advances source
    /// predicates or makes this a transferable success receipt.
    pub fn advance(&mut self) -> Completion<()> {
        let Some(state) = self.runtime.upgrade() else {
            return Completion::Refused("native wait scheduler abandoned");
        };
        let Some(frame) = self.waiting.frame.upgrade() else {
            return Completion::Refused("native waiting invocation abandoned");
        };
        let invocation = Invocation {
            runtime: self.runtime.clone(),
            frame,
        };
        if invocation.check_current().is_err() {
            return Completion::Refused("native wait resumed from foreign context");
        }
        match self.waiting.phase.get() {
            Phase::Waiting => return Completion::Busy { deadline: None },
            Phase::Retired => return Completion::Refused("native wait already retired"),
            Phase::Notified => {}
        }
        let Some(thread) = self.waiting.thread.upgrade() else {
            return Completion::Refused("native waiting thread abandoned");
        };
        if !thread
            .wait
            .borrow()
            .as_ref()
            .is_some_and(|w| Rc::ptr_eq(w, &self.waiting))
        {
            return Completion::Refused("native wait lost its actual thread registration");
        }
        let mut s = state.borrow_mut();
        if let Some((queue, depth)) = self.waiting.released {
            let q = &mut s.queues[queue];
            if q.lock.is_some_and(|owner| owner != thread.id) {
                return Completion::Busy { deadline: None };
            }
            if q.lock.is_some() || q.depth != 0 {
                return Completion::Refused("native drain lock was reacquired outside its wait");
            }
            q.lock = Some(thread.id);
            q.depth = depth;
        }
        fence(Ordering::Acquire);
        *thread.wait.borrow_mut() = None;
        self.waiting.phase.set(Phase::Retired);
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
}
impl Lease {
    pub fn release(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::Contract("native queue lease already released"));
        }
        let state = self
            .runtime
            .upgrade()
            .ok_or(Error::Contract("native lease scheduler abandoned"))?;
        let frame = self
            .frame
            .upgrade()
            .ok_or(Error::Contract("native lease invocation abandoned"))?;
        Invocation {
            runtime: self.runtime.clone(),
            frame: frame.clone(),
        }
        .check_current()?;
        let mut s = state.borrow_mut();
        let q = &mut s.queues[self.queue];
        if q.lock != Some(frame.thread.id)
            || q.depth == 0
            || frame.leases.get() == 0
            || frame.thread.wait.borrow().is_some()
        {
            return Err(Error::Contract(
                "native lease release lost its lock or unfinished wait",
            ));
        }
        q.depth -= 1;
        if q.depth == 0 {
            q.lock = None;
        }
        frame.leases.set(frame.leases.get() - 1);
        self.active = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    fn done(value: u32) -> Completion<u32> {
        Completion::Retired {
            value,
            refusal: None,
        }
    }
    fn step(r: &Runtime) -> Result<Progress> {
        let mut irq = InterruptLatch::new();
        r.step(&mut Access::new(0, 5, &mut irq))
    }
    fn invoke(r: &Runtime, i: &Immediate) -> Result<Progress> {
        let mut irq = InterruptLatch::new();
        r.invoke(i, &mut Access::new(0, 5, &mut irq))
    }
    struct Ack {
        runtime: Runtime,
        key: Key,
        count: Rc<Cell<u32>>,
        thread: Rc<Cell<u32>>,
    }
    impl Callback for Ack {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.thread.set(i.thread_id());
            self.count.set(self.count.get() + 1);
            self.runtime.notify(&self.key).unwrap();
            done(1)
        }
    }
    struct Db {
        runtime: Runtime,
        key: Key,
        immediate: Rc<RefCell<Option<Immediate>>>,
        wait: Option<Wait>,
        thread: Rc<Cell<u32>>,
        calls: Rc<Cell<u32>>,
    }
    impl Callback for Db {
        fn advance(&mut self, i: &Invocation, a: &mut Access<'_>) -> Completion<u32> {
            self.thread.set(i.thread_id());
            self.calls.set(self.calls.get() + 1);
            if self.wait.is_none() {
                self.wait = Some(self.runtime.wait(i, &self.key).unwrap());
                // Actual reentrant endpoint callback executes while this DB
                // invocation/recursive global mutex is retained.
                let handle = self.immediate.borrow();
                assert!(matches!(
                    self.runtime.invoke(handle.as_ref().unwrap(), a).unwrap(),
                    Progress::Retired { .. }
                ));
                assert!(self.runtime.current().unwrap().same_dispatch(i));
                return Completion::Busy { deadline: None };
            }
            match self.wait.as_mut().unwrap().advance() {
                Completion::Retired { .. } => {
                    self.wait = None;
                    done(0)
                }
                Completion::Busy { deadline } => Completion::Busy { deadline },
                Completion::Refused(e) => Completion::Refused(e),
            }
        }
    }
    #[test]
    fn immediate_receive_executes_reentrantly_and_wakes_real_db_registration_wait() {
        let r = Runtime::new();
        let q = r.global_reporting_queue().unwrap();
        let key = r.key();
        let immediate = Rc::new(RefCell::new(None));
        let dbthread = Rc::new(Cell::new(0));
        let ackthread = Rc::new(Cell::new(0));
        let count = Rc::new(Cell::new(0));
        let calls = Rc::new(Cell::new(0));
        let ack = r
            .register_immediate(
                "actual reporting ACK",
                63,
                Ack {
                    runtime: r.clone(),
                    key: key.clone(),
                    count: count.clone(),
                    thread: ackthread.clone(),
                },
            )
            .unwrap();
        *immediate.borrow_mut() = Some(ack);
        let work = r
            .bind_work(
                15,
                Db {
                    runtime: r.clone(),
                    key,
                    immediate,
                    wait: None,
                    thread: dbthread.clone(),
                    calls: calls.clone(),
                },
            )
            .unwrap();
        r.register_work(&q, &work);
        r.wake(&work).unwrap();
        assert!(matches!(step(&r).unwrap(), Progress::Busy { .. }));
        assert_eq!(count.get(), 1);
        assert_ne!(dbthread.get(), ackthread.get());
        assert_eq!(r.queue_lock_depth(&q).unwrap(), 1);
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert_eq!(calls.get(), 2);
        assert_eq!(r.queue_lock_depth(&q).unwrap(), 0);
    }
    struct Drain {
        runtime: Runtime,
        queue: Queue,
        key: Key,
        wait: Option<Wait>,
        leases: Vec<Lease>,
        calls: Rc<Cell<u32>>,
    }
    impl Callback for Drain {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.calls.set(self.calls.get() + 1);
            if self.wait.is_none() {
                for _ in 0..2 {
                    let Completion::Retired { value, .. } = self.runtime.lock(&self.queue, i)
                    else {
                        panic!("actual recursive queue lock unavailable")
                    };
                    self.leases.push(value);
                }
                assert_eq!(self.runtime.queue_lock_depth(&self.queue).unwrap(), 3);
                self.wait = Some(self.runtime.drain_wait(&self.queue, i, &self.key).unwrap());
                assert_eq!(self.runtime.queue_lock_depth(&self.queue).unwrap(), 0);
                return Completion::Busy { deadline: None };
            }
            match self.wait.as_mut().unwrap().advance() {
                Completion::Retired { .. } => {
                    self.wait = None;
                    assert_eq!(self.runtime.queue_lock_depth(&self.queue).unwrap(), 3);
                    for lease in &mut self.leases {
                        lease.release().unwrap();
                    }
                    self.leases.clear();
                    done(0)
                }
                Completion::Busy { deadline } => Completion::Busy { deadline },
                Completion::Refused(e) => Completion::Refused(e),
            }
        }
    }
    struct Hold {
        runtime: Runtime,
        queue: Queue,
        lease: Option<Lease>,
    }
    impl Callback for Hold {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            if self.lease.is_none() {
                match self.runtime.lock(&self.queue, i) {
                    Completion::Retired { value, .. } => {
                        self.lease = Some(value);
                        return Completion::Busy { deadline: None };
                    }
                    Completion::Busy { deadline } => return Completion::Busy { deadline },
                    Completion::Refused(e) => return Completion::Refused(e),
                }
            }
            self.lease.as_mut().unwrap().release().unwrap();
            self.lease = None;
            done(0)
        }
    }
    #[test]
    fn drain_restores_all_recursion_only_after_actual_notify_and_mutex_release() {
        let r = Runtime::new();
        let q = r.global_reporting_queue().unwrap();
        let key = r.key();
        let calls = Rc::new(Cell::new(0));
        let w = r
            .bind_work(
                15,
                Drain {
                    runtime: r.clone(),
                    queue: q.clone(),
                    key: key.clone(),
                    wait: None,
                    leases: Vec::new(),
                    calls: calls.clone(),
                },
            )
            .unwrap();
        r.register_work(&q, &w);
        r.wake(&w).unwrap();
        assert!(matches!(step(&r).unwrap(), Progress::Busy { .. }));
        assert!(matches!(step(&r).unwrap(), Progress::Idle));
        assert_eq!(calls.get(), 1);
        let hold = r
            .register_immediate(
                "actual synchronous queue operation",
                63,
                Hold {
                    runtime: r.clone(),
                    queue: q.clone(),
                    lease: None,
                },
            )
            .unwrap();
        assert!(matches!(invoke(&r, &hold).unwrap(), Progress::Busy { .. }));
        assert_eq!(r.queue_lock_depth(&q).unwrap(), 1);
        assert_eq!(r.notify(&key).unwrap(), 1);
        assert!(matches!(step(&r).unwrap(), Progress::Idle));
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            invoke(&r, &hold).unwrap(),
            Progress::Retired { .. }
        ));
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert_eq!(calls.get(), 2);
        assert_eq!(r.queue_lock_depth(&q).unwrap(), 0);
    }
    struct Low {
        log: Rc<RefCell<Vec<&'static str>>>,
        calls: u32,
    }
    impl Callback for Low {
        fn advance(&mut self, _: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.calls += 1;
            self.log.borrow_mut().push("low");
            if self.calls == 1 {
                Completion::Busy { deadline: None }
            } else {
                done(0)
            }
        }
    }
    struct High {
        runtime: Runtime,
        queue: Queue,
        log: Rc<RefCell<Vec<&'static str>>>,
    }
    impl Callback for High {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            self.log.borrow_mut().push("high");
            match self.runtime.lock(&self.queue, i) {
                Completion::Busy { deadline } => Completion::Busy { deadline },
                Completion::Refused(e) => Completion::Refused(e),
                Completion::Retired { mut value, .. } => {
                    value.release().unwrap();
                    done(0)
                }
            }
        }
    }
    #[test]
    fn contended_high_priority_thread_blocks_so_real_lower_priority_owner_can_run() {
        let r = Runtime::new();
        let global = r.global_reporting_queue().unwrap();
        let mc = r.create_queue(QueueConfiguration::mc_metrics()).unwrap();
        let log = Rc::new(RefCell::new(Vec::new()));
        let low = r
            .bind_work(
                15,
                Low {
                    log: log.clone(),
                    calls: 0,
                },
            )
            .unwrap();
        let high = r
            .bind_work(
                15,
                High {
                    runtime: r.clone(),
                    queue: global.clone(),
                    log: log.clone(),
                },
            )
            .unwrap();
        r.register_work(&global, &low);
        r.register_work(&mc, &high);
        r.wake(&low).unwrap();
        assert!(matches!(step(&r).unwrap(), Progress::Busy { .. }));
        r.wake(&high).unwrap();
        assert!(matches!(step(&r).unwrap(), Progress::Busy { .. }));
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert_eq!(&*log.borrow(), &["low", "high", "low", "high"]);
    }
    struct PlainWait {
        runtime: Runtime,
        key: Key,
        wait: Option<Wait>,
    }
    impl Callback for PlainWait {
        fn advance(&mut self, i: &Invocation, _: &mut Access<'_>) -> Completion<u32> {
            if self.wait.is_none() {
                self.wait = Some(self.runtime.wait(i, &self.key).unwrap());
                return Completion::Busy { deadline: None };
            }
            match self.wait.as_mut().unwrap().advance() {
                Completion::Retired { .. } => {
                    self.wait = None;
                    done(0)
                }
                Completion::Busy { deadline } => Completion::Busy { deadline },
                Completion::Refused(e) => Completion::Refused(e),
            }
        }
    }
    #[test]
    fn foreign_key_cannot_wake_this_runtime_and_notify_creates_no_future_credit() {
        let r = Runtime::new();
        let other = Runtime::new();
        let key = r.key();
        assert_eq!(r.notify(&key).unwrap(), 0);
        assert!(other.notify(&key).is_err());
        assert!(!key.same_key(&other.key()));
        let q = r.global_reporting_queue().unwrap();
        let w = r
            .bind_work(
                15,
                PlainWait {
                    runtime: r.clone(),
                    key: key.clone(),
                    wait: None,
                },
            )
            .unwrap();
        r.register_work(&q, &w);
        r.wake(&w).unwrap();
        assert!(matches!(step(&r).unwrap(), Progress::Busy { .. }));
        assert!(matches!(step(&r).unwrap(), Progress::Idle));
        assert_eq!(r.notify(&key).unwrap(), 1);
        assert!(matches!(step(&r).unwrap(), Progress::Retired { .. }));
        assert_eq!(r.notify(&key).unwrap(), 0);
    }
}
