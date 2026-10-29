//! Endpoint4 resources and independently dispatched publication ACK.
use super::*;
use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{Ordering, fence};
use reporting::resources::{self, WaitKey, Wake};
struct Armed {
    source: WaitKey,
    key: scheduler::Key,
    wait: Option<scheduler::Wait>,
    notified: bool,
}
pub(super) struct Shared {
    pub init_started: Cell<bool>,
    pub runtime: scheduler::WeakRuntime,
    pub global: scheduler::Queue,
    broker: dma::Broker,
    clock: Clock,
    mailbox: RefCell<channel::Mailbox>,
    pub slot: Slot<Report>,
    pub work: RefCell<Option<scheduler::Work>>,
    waits: RefCell<Vec<Armed>>,
    buffer_key: scheduler::Key,
    buffer_wait: RefCell<Option<scheduler::Wait>>,
    refresh: RefCell<VecDeque<u64>>,
    pub claimed: Cell<bool>,
    pub ready: Cell<bool>,
}
impl Shared {
    pub fn new(
        runtime: scheduler::WeakRuntime,
        global: scheduler::Queue,
        broker: dma::Broker,
        clock: Clock,
        mailbox: channel::Mailbox,
        slot: Slot<Report>,
    ) -> Self {
        let buffer_key = runtime.upgrade().unwrap().key();
        Self {
            init_started: Cell::new(false),
            runtime,
            global,
            broker,
            clock,
            mailbox: RefCell::new(mailbox),
            slot,
            work: RefCell::new(None),
            waits: RefCell::new(Vec::new()),
            buffer_key,
            buffer_wait: RefCell::new(None),
            refresh: RefCell::new(VecDeque::new()),
            claimed: Cell::new(false),
            ready: Cell::new(false),
        }
    }
    pub fn pending_input(&self) -> bool {
        self.mailbox.borrow().pending_input()
    }
    pub fn started(&self) -> bool {
        self.mailbox.borrow().started()
    }
    fn wake(&self) -> Result<(), &'static str> {
        let works = self.work.borrow();
        let work = works.as_ref().ok_or("IOReporting actual Work is absent")?;
        runtime(&self.runtime)?.wake(work).map_err(schedule_error)
    }
}
pub struct Resources {
    shared: Rc<Shared>,
}
impl Resources {
    pub(super) fn new(shared: Rc<Shared>) -> Self {
        Self { shared }
    }
}
impl resources::Resources for Resources {
    type Mapping = dma::ReportingMapping;
    fn claim(&mut self, _: &resources::Request, _: &mut Access<'_>) -> Completion<()> {
        let r = match runtime(&self.shared.runtime) {
            Ok(r) => r,
            Err(e) => return Completion::Refused(e),
        };
        if !self.shared.started() {
            return Completion::Busy { deadline: None };
        }
        if self.shared.work.borrow().is_none() {
            let callback = Worker {
                shared: self.shared.clone(),
                receiver: None,
                refreshing: false,
            };
            let work = match r.bind_work(15, callback) {
                Ok(w) => w,
                Err(e) => return Completion::Refused(schedule_error(e)),
            };
            *self.shared.work.borrow_mut() = Some(work);
        }
        let result = r.register_work(
            &self.shared.global,
            self.shared.work.borrow().as_ref().unwrap(),
        );
        if matches!(result, Completion::Retired { .. }) {
            self.shared.claimed.set(true);
        }
        result
    }
    fn map(
        &mut self,
        request: &resources::Request,
        buffer: reporting::wire::Buffer,
        flags: u32,
        _: &mut Access<'_>,
    ) -> Completion<resources::MapResult<Self::Mapping>> {
        self.shared.broker.map_reporting(request, buffer, flags)
    }
    fn dsb_sy(&mut self, _: &resources::Request, _: &mut Access<'_>) -> Completion<()> {
        fence(Ordering::SeqCst);
        done(())
    }
    fn converted_clock(&mut self, _: &resources::Request, _: &mut Access<'_>) -> Completion<u64> {
        done(self.shared.clock.converted())
    }
    fn send(
        &mut self,
        _: &resources::Request,
        endpoint: u8,
        payload: u64,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        if endpoint != reporting::wire::ENDPOINT {
            return Completion::Refused("IOReporting send endpoint differs from bound slot");
        }
        if !self.shared.started() {
            return Completion::Busy { deadline: None };
        }
        if let Err(e) = self.shared.mailbox.borrow_mut().send(payload) {
            return Completion::Refused(e);
        }
        if payload == reporting::wire::BUFFER_REQUEST {
            // Mailbox.send invokes no callback. Under the cooperative BSP
            // contract no AP input can interleave between send and this wait.
            let r = match runtime(&self.shared.runtime) {
                Ok(r) => r,
                Err(e) => {
                    return Completion::Retired {
                        value: (),
                        refusal: Some(e),
                    };
                }
            };
            let i = match current(&self.shared.runtime) {
                Ok(i) => i,
                Err(e) => {
                    return Completion::Retired {
                        value: (),
                        refusal: Some(e),
                    };
                }
            };
            match r.wait(&i, &self.shared.buffer_key) {
                Ok(w) => *self.shared.buffer_wait.borrow_mut() = Some(w),
                Err(e) => {
                    return Completion::Retired {
                        value: (),
                        refusal: Some(schedule_error(e)),
                    };
                }
            }
        }
        if payload == reporting::wire::REGISTERED {
            let mut waits = self.shared.waits.borrow_mut();
            let Some(armed) = waits.last_mut() else {
                return Completion::Retired {
                    value: (),
                    refusal: Some("IOReporting REGISTERED send has no armed source key"),
                };
            };
            if !armed.notified {
                let r = match runtime(&self.shared.runtime) {
                    Ok(r) => r,
                    Err(e) => {
                        return Completion::Retired {
                            value: (),
                            refusal: Some(e),
                        };
                    }
                };
                let i = match current(&self.shared.runtime) {
                    Ok(i) => i,
                    Err(e) => {
                        return Completion::Retired {
                            value: (),
                            refusal: Some(e),
                        };
                    }
                };
                match r.wait(&i, &armed.key) {
                    Ok(w) => armed.wait = Some(w),
                    Err(e) => {
                        return Completion::Retired {
                            value: (),
                            refusal: Some(schedule_error(e)),
                        };
                    }
                }
            }
        }
        done(())
    }
    fn arm_wait(
        &mut self,
        _: &resources::Request,
        key: &WaitKey,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        if self
            .shared
            .waits
            .borrow()
            .iter()
            .any(|w| w.source.same_waiter(key))
        {
            return Completion::Refused("IOReporting publication waiter already armed");
        }
        let r = match runtime(&self.shared.runtime) {
            Ok(r) => r,
            Err(e) => return Completion::Refused(e),
        };
        let actual = r.key();
        let mut waits = self.shared.waits.borrow_mut();
        waits.retain(|w| !(w.notified && w.wait.is_none()));
        waits.push(Armed {
            source: key.clone(),
            key: actual,
            wait: None,
            notified: false,
        });
        done(())
    }
    fn wait(
        &mut self,
        _: &resources::Request,
        key: &WaitKey,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        let mut waits = self.shared.waits.borrow_mut();
        let Some(index) = waits.iter().position(|w| w.source.same_waiter(key)) else {
            return Completion::Refused("IOReporting actual publication wait absent");
        };
        if waits[index].notified && waits[index].wait.is_none() {
            waits.remove(index);
            return done(());
        }
        if waits[index].wait.is_none() {
            let r = match runtime(&self.shared.runtime) {
                Ok(r) => r,
                Err(e) => return Completion::Refused(e),
            };
            let i = match current(&self.shared.runtime) {
                Ok(i) => i,
                Err(e) => return Completion::Refused(e),
            };
            match r.wait(&i, &waits[index].key) {
                Ok(w) => waits[index].wait = Some(w),
                Err(e) => return Completion::Refused(schedule_error(e)),
            }
        }
        let result = waits[index].wait.as_mut().unwrap().advance();
        if matches!(result, Completion::Retired { .. }) {
            waits.remove(index);
        }
        result
    }
    fn unmap(
        &mut self,
        r: &resources::Request,
        m: &mut Self::Mapping,
        a: &mut Access<'_>,
    ) -> Completion<()> {
        m.unmap(r, a)
    }
    fn release(
        &mut self,
        r: &resources::Request,
        m: &mut Self::Mapping,
        a: &mut Access<'_>,
    ) -> Completion<()> {
        m.release(r, a)
    }
}
struct ReceiverWake {
    shared: Rc<Shared>,
}
impl Wake for ReceiverWake {
    fn publication_ack(&mut self, key: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
        let mut waits = self.shared.waits.borrow_mut();
        let Some(armed) = waits.iter_mut().find(|w| w.source.same_waiter(key)) else {
            return Completion::Refused("IOReporting ACK has no actual keyed waiter");
        };
        match runtime(&self.shared.runtime)
            .and_then(|r| r.notify(&armed.key).map_err(schedule_error))
        {
            Ok(_) => {
                armed.notified = true;
                done(())
            }
            Err(e) => Completion::Refused(e),
        }
    }
    fn queue_refresh(&mut self, _: &mut Access<'_>) -> Completion<()> {
        match self.shared.wake() {
            Ok(()) => done(()),
            Err(e) => Completion::Refused(e),
        }
    }
}
pub(super) struct Input {
    shared: Rc<Shared>,
    receiver: reporting::Receiver,
    raw: Option<u64>,
}
impl Input {
    pub fn new(shared: Rc<Shared>, receiver: reporting::Receiver) -> Self {
        Self {
            shared,
            receiver,
            raw: None,
        }
    }
}
impl scheduler::Callback for Input {
    fn advance(&mut self, _: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        if !self.shared.started() || !self.shared.claimed.get() {
            return done(0);
        }
        if self.raw.is_none() {
            self.raw = match self.shared.mailbox.borrow_mut().receive() {
                Ok(v) => v,
                Err(e) => return Completion::Refused(e),
            };
        }
        let Some(raw) = self.raw else {
            return done(0);
        };
        if reporting::wire::kind(raw) == 1 {
            // Keep every refresh command. An ACK behind one remains
            // independently dispatchable; a bool cannot discard duplicate input.
            if let Err(e) = self.shared.wake() {
                return Completion::Refused(e);
            }
            self.shared.refresh.borrow_mut().push_back(raw);
            self.raw = None;
            return done(0);
        }
        match self.receiver.receive(
            raw,
            &mut ReceiverWake {
                shared: self.shared.clone(),
            },
            a,
        ) {
            Completion::Retired { refusal, .. } => {
                self.raw = None;
                if reporting::wire::kind(raw) == 0
                    && let Err(e) = runtime(&self.shared.runtime)
                        .and_then(|r| r.notify(&self.shared.buffer_key).map_err(schedule_error))
                {
                    return Completion::Retired {
                        value: 0,
                        refusal: Some(e),
                    };
                }
                Completion::Retired { value: 0, refusal }
            }
            Completion::Busy { deadline } => Completion::Busy { deadline },
            Completion::Refused(e) => Completion::Refused(e),
        }
    }
}
struct Worker {
    shared: Rc<Shared>,
    receiver: Option<reporting::Receiver>,
    refreshing: bool,
}
impl scheduler::Callback for Worker {
    fn advance(&mut self, i: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        if let Err(e) = self
            .shared
            .work
            .borrow()
            .as_ref()
            .ok_or("IOReporting actual Work lost")
            .and_then(|w| w.validate_dispatch(i).map_err(schedule_error))
        {
            return Completion::Refused(e);
        }
        let cell = match owner(&self.shared.slot) {
            Ok(v) => v,
            Err(e) => return Completion::Refused(e),
        };
        let mut db = match cell.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => {
                return Completion::Refused("IOReporting owner is executing another native caller");
            }
        };
        if !self.refreshing {
            let Some(raw) = self.shared.refresh.borrow_mut().pop_front() else {
                return done(0);
            };
            let receiver = self.receiver.get_or_insert_with(|| db.receiver());
            match receiver.receive(
                raw,
                &mut ReceiverWake {
                    shared: self.shared.clone(),
                },
                a,
            ) {
                Completion::Retired { refusal: None, .. } => self.refreshing = true,
                Completion::Retired {
                    refusal: Some(e), ..
                }
                | Completion::Refused(e) => {
                    self.shared.refresh.borrow_mut().push_front(raw);
                    return Completion::Refused(e);
                }
                Completion::Busy { deadline } => {
                    self.shared.refresh.borrow_mut().push_front(raw);
                    return Completion::Busy { deadline };
                }
            }
        }
        match db.advance(a) {
            Ok(reporting::Progress::Finished(reporting::Finished::Refreshed)) => {
                self.refreshing = false;
                if self.shared.refresh.borrow().is_empty() {
                    done(0)
                } else {
                    Completion::Busy { deadline: None }
                }
            }
            Ok(reporting::Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(reporting::Progress::Idle) => {
                Completion::Refused("IOReporting refresh input retired without refresh job")
            }
            Ok(_) => Completion::Refused("IOReporting queued worker reached another caller's job"),
            Err(e) => Completion::Refused(e),
        }
    }
}
pub(super) struct Initialize {
    shared: Rc<Shared>,
    begun: bool,
    lease: Option<scheduler::Lease>,
}
impl Initialize {
    pub fn new(shared: Rc<Shared>) -> Self {
        Self {
            shared,
            begun: false,
            lease: None,
        }
    }
}
impl scheduler::Callback for Initialize {
    fn advance(&mut self, i: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        if self.shared.ready.get() {
            return done(0);
        }
        if self.shared.buffer_wait.borrow().is_some() {
            let result = self
                .shared
                .buffer_wait
                .borrow_mut()
                .as_mut()
                .unwrap()
                .advance();
            match result {
                Completion::Retired { refusal: None, .. } => {
                    self.shared.buffer_wait.borrow_mut().take();
                }
                Completion::Busy { deadline } => return Completion::Busy { deadline },
                Completion::Refused(e)
                | Completion::Retired {
                    refusal: Some(e), ..
                } => return Completion::Refused(e),
            }
        }
        if self.lease.is_none() {
            let r = match runtime(&self.shared.runtime) {
                Ok(r) => r,
                Err(e) => return Completion::Refused(e),
            };
            match r.lock(&self.shared.global, i) {
                Completion::Retired {
                    value,
                    refusal: None,
                } => self.lease = Some(value),
                Completion::Busy { deadline } => return Completion::Busy { deadline },
                Completion::Refused(e)
                | Completion::Retired {
                    refusal: Some(e), ..
                } => return Completion::Refused(e),
            }
        }
        let cell = match owner(&self.shared.slot) {
            Ok(v) => v,
            Err(e) => return Completion::Refused(e),
        };
        let mut db = cell.borrow_mut();
        if !self.begun {
            if let Err(e) = db.enter(false) {
                return Completion::Refused(e);
            }
            self.begun = true;
            self.shared.init_started.set(true);
        }
        match db.advance(a) {
            Ok(reporting::Progress::Finished(reporting::Finished::Ready)) => {
                if let Err(e) = self.lease.as_mut().unwrap().release() {
                    return Completion::Refused(schedule_error(e));
                }
                self.lease = None;
                self.shared.ready.set(true);
                done(0)
            }
            Ok(reporting::Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(_) => Completion::Refused("IOReporting source enter returned wrong phase"),
            Err(e) => Completion::Refused(e),
        }
    }
}
