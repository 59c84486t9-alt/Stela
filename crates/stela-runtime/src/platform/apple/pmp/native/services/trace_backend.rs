//! Actual trace destination: DMA mappings, source work and native context.
use super::*;
use alloc::collections::VecDeque;
use core::sync::atomic::{Ordering, fence};
pub(super) struct Shared {
    pub init_started: Cell<bool>,
    pub runtime: scheduler::WeakRuntime,
    pub global: scheduler::Queue,
    broker: dma::Broker,
    clock: Clock,
    mailbox: RefCell<channel::Mailbox>,
    incoming: RefCell<VecDeque<u64>>,
    pub slot: Slot<Trace>,
    pub work: RefCell<Option<scheduler::Work>>,
    bound: Cell<bool>,
    lifecycle: RefCell<Option<scheduler::Immediate>>,
    pub lifecycle_input: RefCell<VecDeque<(u32, u32)>>,
    key: scheduler::Key,
    drain: RefCell<Option<(trace::Request, scheduler::Wait)>>,
}
impl Shared {
    pub fn new(
        runtime: scheduler::WeakRuntime,
        global: scheduler::Queue,
        broker: dma::Broker,
        clock: Clock,
        mailbox: channel::Mailbox,
        slot: Slot<Trace>,
    ) -> Self {
        let key = runtime.upgrade().unwrap().key();
        Self {
            init_started: Cell::new(false),
            runtime,
            global,
            broker,
            clock,
            mailbox: RefCell::new(mailbox),
            incoming: RefCell::new(VecDeque::new()),
            slot,
            work: RefCell::new(None),
            bound: Cell::new(false),
            lifecycle: RefCell::new(None),
            lifecycle_input: RefCell::new(VecDeque::new()),
            key,
            drain: RefCell::new(None),
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
        let work = works.as_ref().ok_or("trace actual Work absent")?;
        runtime(&self.runtime)?.wake(work).map_err(schedule_error)
    }
    pub fn advance_lifecycle(&self, a: &mut Access<'_>) -> Result<(), &'static str> {
        if let Some(handle) = self.lifecycle.borrow().as_ref() {
            runtime(&self.runtime)?
                .invoke(handle, a)
                .map_err(schedule_error)?;
        }
        Ok(())
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
impl trace::Backend for Resources {
    type Mapping = dma::TraceMapping;
    fn effect(
        &mut self,
        request: &trace::Request,
        e: trace::Effect,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        let r = match runtime(&self.shared.runtime) {
            Ok(r) => r,
            Err(e) => return Completion::Refused(e),
        };
        match e {
            trace::Effect::RegisterWork { priority } => {
                if priority != 15 {
                    return Completion::Refused("trace source Work priority differs");
                }
                if self.shared.work.borrow().is_none() {
                    let work = match r.bind_work(
                        priority,
                        Worker {
                            shared: self.shared.clone(),
                        },
                    ) {
                        Ok(w) => w,
                        Err(e) => return Completion::Refused(schedule_error(e)),
                    };
                    *self.shared.work.borrow_mut() = Some(work);
                }
                r.register_work(
                    &self.shared.global,
                    self.shared.work.borrow().as_ref().unwrap(),
                )
            }
            trace::Effect::BindEndpoint { endpoint } => {
                if endpoint != trace::ENDPOINT || self.shared.bound.get() {
                    return Completion::Refused("trace endpoint binding is duplicate or foreign");
                }
                if !self.shared.started() {
                    return Completion::Busy { deadline: None };
                }
                self.shared.bound.set(true);
                done(())
            }
            trace::Effect::RegisterLifecycle { slot } => {
                if slot != 0 || self.shared.lifecycle.borrow().is_some() {
                    return Completion::Refused("trace lifecycle slot is duplicate or unsupported");
                }
                match r.register_immediate(
                    "trace actual source lifecycle",
                    57,
                    Lifecycle {
                        shared: self.shared.clone(),
                        command: None,
                        begun: false,
                        lease: None,
                    },
                ) {
                    Ok(handle) => {
                        *self.shared.lifecycle.borrow_mut() = Some(handle);
                        done(())
                    }
                    Err(e) => Completion::Refused(schedule_error(e)),
                }
            }
            trace::Effect::Wake => match self.shared.wake() {
                Ok(()) => done(()),
                Err(e) => Completion::Refused(e),
            },
            trace::Effect::Send { endpoint, message } => {
                if endpoint != trace::ENDPOINT || !self.shared.bound.get() {
                    return Completion::Refused("trace send lacks actual endpoint binding");
                }
                if !self.shared.started() {
                    return Completion::Busy { deadline: None };
                }
                match self.shared.mailbox.borrow_mut().send(message) {
                    Ok(()) => done(()),
                    Err(e) => Completion::Refused(e),
                }
            }
            trace::Effect::Ordering(order) => {
                // Executed on the actual cooperative BSP under Services safety
                // contract, after required actual DMA synchronization. No MCC ACK.
                fence(match order {
                    trace::Ordering::ReservationFull => Ordering::SeqCst,
                    trace::Ordering::TimestampRelease => Ordering::Release,
                });
                done(())
            }
            trace::Effect::DrainWait => {
                let mut drain = self.shared.drain.borrow_mut();
                if let Some((prior, _)) = drain.as_ref() {
                    if !prior.same_operation(request) {
                        return Completion::Refused("trace retained drain request changed");
                    }
                } else {
                    let i = match current(&self.shared.runtime) {
                        Ok(i) => i,
                        Err(e) => return Completion::Refused(e),
                    };
                    match r.drain_wait(&self.shared.global, &i, &self.shared.key) {
                        Ok(wait) => *drain = Some((request.clone(), wait)),
                        Err(e) => return Completion::Refused(schedule_error(e)),
                    }
                }
                let result = drain.as_mut().unwrap().1.advance();
                if matches!(result, Completion::Retired { .. }) {
                    drain.take();
                }
                result
            }
            trace::Effect::NotifyWaiters => match r.notify(&self.shared.key) {
                Ok(_) => done(()),
                Err(e) => Completion::Refused(schedule_error(e)),
            },
        }
    }
    fn map(
        &mut self,
        request: &trace::Request,
        _: trace::Buffer,
        geometry: trace::Geometry,
        _: &mut Access<'_>,
    ) -> Completion<Self::Mapping> {
        self.shared.broker.map_trace(request, geometry)
    }
    fn receive(&mut self, _: &trace::Request, _: &mut Access<'_>) -> Completion<Option<u64>> {
        if !self.shared.started() {
            return Completion::Busy { deadline: None };
        }
        done(self.shared.incoming.borrow_mut().pop_front())
    }
    fn clock(&mut self, _: &trace::Request, _: &mut Access<'_>) -> Completion<u64> {
        done(self.shared.clock.raw())
    }
    fn thread_id(&mut self, _: &trace::Request, _: &mut Access<'_>) -> Completion<u32> {
        match current(&self.shared.runtime) {
            Ok(i) => done(i.thread_id()),
            Err(e) => Completion::Refused(e),
        }
    }
    fn flush_context(
        &mut self,
        _: &trace::Request,
        _: &mut Access<'_>,
    ) -> Completion<trace::FlushContext> {
        match current(&self.shared.runtime).and_then(|i| i.context().map_err(schedule_error)) {
            Ok(scheduler::Context::CooperativeThread { .. }) => {
                // Stela callbacks execute outside scheduler critical sections.
                // This is that native scheduler's context, not an observation
                // of Apple's IF/DAIF or a host IF=enabled assertion. Root BSP
                // hardware interrupts remain disabled during canonical service.
                done(trace::FlushContext {
                    on_thread_stack: true,
                    irq_masked: false,
                    scheduler_flag: 1,
                })
            }
            Err(e) => Completion::Refused(e),
        }
    }
}
pub(super) struct Input {
    shared: Rc<Shared>,
    wake_pending: bool,
}
impl Input {
    pub fn new(shared: Rc<Shared>) -> Self {
        Self {
            shared,
            wake_pending: false,
        }
    }
}
impl scheduler::Callback for Input {
    fn advance(&mut self, _: &scheduler::Invocation, _: &mut Access<'_>) -> Completion<u32> {
        if !self.shared.started() {
            return done(0);
        }
        if !self.wake_pending {
            let raw = match self.shared.mailbox.borrow_mut().receive() {
                Ok(v) => v,
                Err(e) => return Completion::Refused(e),
            };
            let Some(raw) = raw else {
                return done(0);
            };
            self.shared.incoming.borrow_mut().push_back(raw);
            self.wake_pending = true;
        }
        match self.shared.wake() {
            Ok(()) => {
                self.wake_pending = false;
                done(0)
            }
            Err(e) => Completion::Refused(e),
        }
    }
}
struct Worker {
    shared: Rc<Shared>,
}
impl scheduler::Callback for Worker {
    fn advance(&mut self, i: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        if let Err(e) = self
            .shared
            .work
            .borrow()
            .as_ref()
            .ok_or("trace actual Work lost")
            .and_then(|w| w.validate_dispatch(i).map_err(schedule_error))
        {
            return Completion::Refused(e);
        }
        let cell = match owner(&self.shared.slot) {
            Ok(v) => v,
            Err(e) => return Completion::Refused(e),
        };
        let mut trace = match cell.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return Completion::Refused("trace owner is executing another caller"),
        };
        if !trace.is_initialized() {
            return Completion::Busy { deadline: None };
        }
        if !trace.dispatch_pending()
            && let Err(e) = trace.begin_dispatch()
        {
            return Completion::Refused(trace_error(e));
        }
        match trace.advance_dispatch(a) {
            Ok(trace::Progress::Dispatched { consumed, .. }) => done(u32::from(consumed)),
            Ok(trace::Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(_) => Completion::Refused("trace queued worker returned another phase"),
            Err(e) => Completion::Refused(trace_error(e)),
        }
    }
}
pub(super) struct Initialize {
    shared: Rc<Shared>,
    begun: bool,
}
impl Initialize {
    pub fn new(shared: Rc<Shared>) -> Self {
        Self {
            shared,
            begun: false,
        }
    }
}
impl scheduler::Callback for Initialize {
    fn advance(&mut self, _: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        let cell = match owner(&self.shared.slot) {
            Ok(v) => v,
            Err(e) => return Completion::Refused(e),
        };
        let mut trace = cell.borrow_mut();
        if trace.is_initialized() {
            return done(0);
        }
        if !self.begun {
            if let Err(e) = trace.begin_initialize() {
                return Completion::Refused(trace_error(e));
            }
            self.begun = true;
            self.shared.init_started.set(true);
        }
        match trace.advance(a) {
            Ok(trace::Progress::Initialized) => done(0),
            Ok(trace::Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(_) => Completion::Refused("trace source initialization returned wrong phase"),
            Err(e) => Completion::Refused(trace_error(e)),
        }
    }
}
struct Lifecycle {
    shared: Rc<Shared>,
    command: Option<(u32, u32)>,
    begun: bool,
    lease: Option<scheduler::Lease>,
}
impl scheduler::Callback for Lifecycle {
    fn advance(&mut self, i: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        if self.command.is_none() {
            self.command = self.shared.lifecycle_input.borrow_mut().pop_front();
        }
        let Some((prior, next)) = self.command else {
            return done(0);
        };
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
        let mut trace = cell.borrow_mut();
        if !self.begun {
            if let Err(e) = trace.begin_lifecycle(prior, next) {
                return Completion::Refused(trace_error(e));
            }
            self.begun = true;
        }
        match trace.advance_lifecycle(a) {
            Ok(
                trace::Progress::Paused
                | trace::Progress::Resumed
                | trace::Progress::LifecycleUnchanged,
            ) => {
                if let Err(e) = self.lease.as_mut().unwrap().release() {
                    return Completion::Refused(schedule_error(e));
                }
                self.lease = None;
                self.command = None;
                self.begun = false;
                done(0)
            }
            Ok(trace::Progress::Busy { deadline }) => Completion::Busy { deadline },
            Ok(_) => Completion::Refused("trace source lifecycle returned wrong phase"),
            Err(e) => Completion::Refused(trace_error(e)),
        }
    }
}
