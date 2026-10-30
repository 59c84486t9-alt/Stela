use super::*;
use stela_contracts::interrupt::InterruptLatch;
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
            // Reentrant endpoint callback executes while this DB
            // invocation/recursive global mutex is held.
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
                let Completion::Retired { value, .. } = self.runtime.lock(&self.queue, i) else {
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
fn drain_restores_all_recursion_only_after_notify_and_mutex_release() {
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
