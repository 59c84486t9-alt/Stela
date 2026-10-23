//! Real MC destinations on the same reporting/trace/scheduler owners.
use super::super::cache::metrics;
use super::*;
use alloc::vec::Vec;
struct Forward(Box<dyn scheduler::Callback>);
impl scheduler::Callback for Forward {
    fn advance(&mut self, i: &scheduler::Invocation, a: &mut Access<'_>) -> Completion<u32> {
        self.0.advance(i, a)
    }
}
struct Registration {
    request: metrics::Request,
    token: reporting::Registration,
    lease: Option<scheduler::Lease>,
    started: bool,
    result: Option<reporting::RegistrationResult>,
}
struct Emission {
    request: metrics::Request,
    lease: Option<scheduler::Lease>,
    started: bool,
    result: Option<trace::Emission>,
}
struct Drain {
    request: metrics::Request,
    lease: Option<scheduler::Lease>,
    wait: Option<scheduler::Wait>,
}
/// Production destination owner. Callback is mandatory; factory callers retain
/// Weak MC service/Samples ownership rather than a Work->Rc<service> cycle.
/// Queued work and callback return/pending belong solely to scheduler::Work.
pub struct MetricsBackend {
    runtime: scheduler::Runtime,
    global: scheduler::Queue,
    report: Weak<RefCell<Report>>,
    trace: Weak<RefCell<Trace>>,
    callback: Option<Box<dyn scheduler::Callback>>,
    queue: Option<scheduler::Queue>,
    work: Option<scheduler::Work>,
    key: scheduler::Key,
    drain: Option<Drain>,
    registration: Option<Registration>,
    emission: Option<Emission>,
    registrations: Vec<(metrics::Request, reporting::RegistrationResult)>,
    last_emission: Option<(metrics::Request, trace::Emission)>,
}
impl MetricsBackend {
    pub(super) fn new<C: scheduler::Callback + 'static>(
        runtime: scheduler::Runtime,
        global: scheduler::Queue,
        report: Weak<RefCell<Report>>,
        trace: Weak<RefCell<Trace>>,
        callback: C,
    ) -> Self {
        let key = runtime.key();
        Self {
            runtime,
            global,
            report,
            trace,
            callback: Some(Box::new(callback)),
            queue: None,
            work: None,
            key,
            drain: None,
            registration: None,
            emission: None,
            registrations: Vec::new(),
            last_emission: None,
        }
    }
    /// Outer source synchronous MC service calls acquire this actual queue;
    /// Stop's predicate-only return is not permission to skip that caller lock.
    pub fn queue(&self) -> Option<&scheduler::Queue> {
        self.queue.as_ref()
    }
    pub fn registrations(&self) -> &[(metrics::Request, reporting::RegistrationResult)] {
        &self.registrations
    }
    pub fn last_emission(&self) -> Option<&(metrics::Request, trace::Emission)> {
        self.last_emission.as_ref()
    }
    fn invocation(&self) -> Result<scheduler::Invocation, &'static str> {
        self.runtime
            .current()
            .ok_or("MC destination requires actual native invocation")
    }
    fn register_metric(
        &mut self,
        r: &metrics::Request,
        name: &str,
        counter: metrics::Counter,
        a: &mut Access<'_>,
    ) -> Completion<()> {
        if self
            .registration
            .as_ref()
            .is_some_and(|job| !job.request.same_operation(r))
        {
            return Completion::Refused(
                "MC metric registration request changed across actual prefix",
            );
        }
        if self.registration.is_none() {
            self.registration = Some(Registration {
                request: r.clone(),
                token: reporting::Registration::new(),
                lease: None,
                started: false,
                result: None,
            });
        }
        let i = match self.invocation() {
            Ok(i) => i,
            Err(e) => return Completion::Refused(e),
        };
        let job = self.registration.as_mut().unwrap();
        if job.lease.is_none() {
            match self.runtime.lock(&self.global, &i) {
                Completion::Retired {
                    value,
                    refusal: None,
                } => job.lease = Some(value),
                Completion::Busy { deadline } => return Completion::Busy { deadline },
                Completion::Refused(e)
                | Completion::Retired {
                    refusal: Some(e), ..
                } => return Completion::Refused(e),
            }
        }
        let Some(cell) = self.report.upgrade() else {
            return Completion::Refused("MC actual reporting owner abandoned");
        };
        let mut db = match cell.try_borrow_mut() {
            Ok(db) => db,
            Err(_) => {
                return Completion::Refused(
                    "MC reporting owner is executing another native caller",
                );
            }
        };
        if !job.started {
            match db.register_mc(job.token.clone(), name.as_bytes(), counter) {
                Ok(result) => {
                    job.result = result;
                    job.started = true;
                }
                Err(e) => {
                    if let Some(result) = db.registration_result(&job.token) {
                        job.result = Some(result);
                        job.started = true;
                    } else {
                        return Completion::Refused(e);
                    }
                }
            }
        }
        if job.result.is_none() {
            match db.advance(a) {
                Ok(reporting::Progress::Finished(reporting::Finished::Registered(result))) => {
                    job.result = Some(result)
                }
                Ok(reporting::Progress::Busy { deadline }) => return Completion::Busy { deadline },
                Ok(_) => return Completion::Refused("MC registration reached unrelated DB job"),
                Err(e) => return Completion::Refused(e),
            }
        }
        let result = job.result.unwrap();
        if let Err(e) = job.lease.as_mut().unwrap().release() {
            return Completion::Refused(schedule_error(e));
        }
        self.registration = None;
        self.registrations.push((r.clone(), result));
        //1007d04/MC ignore the source DB return, but retain its actual failure
        // instead of claiming publication. The caller retires this prefix first.
        Completion::Retired {
            value: (),
            refusal: match result {
                reporting::RegistrationResult::Published { .. } => None,
                reporting::RegistrationResult::SourceError(reporting::NO_DATABASE) => {
                    Some("native IOReporting registration returned80000007 without database")
                }
                reporting::RegistrationResult::SourceError(_) => {
                    Some("native IOReporting registration returned a source error")
                }
                reporting::RegistrationResult::Refused(e) => Some(e),
            },
        }
    }
    fn emit(
        &mut self,
        r: &metrics::Request,
        event: u32,
        args: [u64; 4],
        a: &mut Access<'_>,
    ) -> Completion<()> {
        if self
            .emission
            .as_ref()
            .is_some_and(|job| !job.request.same_operation(r))
        {
            return Completion::Refused("MC trace request changed across actual prefix");
        }
        if self.emission.is_none() {
            self.emission = Some(Emission {
                request: r.clone(),
                lease: None,
                started: false,
                result: None,
            });
        }
        let i = match self.invocation() {
            Ok(i) => i,
            Err(e) => return Completion::Refused(e),
        };
        let job = self.emission.as_mut().unwrap();
        if job.lease.is_none() {
            // Cooperative serialization of the actual typed trace owner. This
            // is not an assertion that source101f594 acquires this queue lock.
            match self.runtime.lock(&self.global, &i) {
                Completion::Retired {
                    value,
                    refusal: None,
                } => job.lease = Some(value),
                Completion::Busy { deadline } => return Completion::Busy { deadline },
                Completion::Refused(e)
                | Completion::Retired {
                    refusal: Some(e), ..
                } => return Completion::Refused(e),
            }
        }
        let Some(cell) = self.trace.upgrade() else {
            return Completion::Refused("MC actual trace owner abandoned");
        };
        let mut trace = match cell.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => {
                return Completion::Refused("MC trace owner is executing another native caller");
            }
        };
        if !job.started {
            if let Err(e) = trace.begin_emit(event, args) {
                return Completion::Refused(trace_error(e));
            }
            job.started = true;
        }
        if job.result.is_none() {
            match trace.advance(a) {
                Ok(trace::Progress::Emitted(result)) => job.result = Some(result),
                Ok(trace::Progress::Busy { deadline }) => return Completion::Busy { deadline },
                Ok(_) => {
                    return Completion::Refused("MC trace destination returned unrelated phase");
                }
                Err(e) => return Completion::Refused(trace_error(e)),
            }
        }
        let result = job.result.unwrap();
        if let Err(e) = job.lease.as_mut().unwrap().release() {
            return Completion::Refused(schedule_error(e));
        }
        self.emission = None;
        self.last_emission = Some((r.clone(), result));
        Completion::Retired {
            value: (),
            refusal: result.diagnostic(),
        }
    }
    fn drain(&mut self, r: &metrics::Request) -> Completion<()> {
        if self
            .drain
            .as_ref()
            .is_some_and(|d| !d.request.same_operation(r))
        {
            return Completion::Refused("MC retained drain request changed");
        }
        if self.drain.is_none() {
            self.drain = Some(Drain {
                request: r.clone(),
                lease: None,
                wait: None,
            });
        }
        let i = match self.invocation() {
            Ok(i) => i,
            Err(e) => return Completion::Refused(e),
        };
        let Some(queue) = self.queue.as_ref() else {
            return Completion::Refused("MC actual queue absent for drain");
        };
        let d = self.drain.as_mut().unwrap();
        if d.lease.is_none() {
            match self.runtime.lock(queue, &i) {
                Completion::Retired {
                    value,
                    refusal: None,
                } => d.lease = Some(value),
                Completion::Busy { deadline } => return Completion::Busy { deadline },
                Completion::Refused(e)
                | Completion::Retired {
                    refusal: Some(e), ..
                } => return Completion::Refused(e),
            }
        }
        if d.wait.is_none() {
            match self.runtime.drain_wait(queue, &i, &self.key) {
                Ok(w) => d.wait = Some(w),
                Err(e) => return Completion::Refused(schedule_error(e)),
            }
        }
        match d.wait.as_mut().unwrap().advance() {
            Completion::Retired {
                value: (),
                refusal: None,
            } => {
                if let Err(e) = d.lease.as_mut().unwrap().release() {
                    return Completion::Refused(schedule_error(e));
                }
                self.drain = None;
                done(())
            }
            other => other,
        }
    }
}
impl metrics::Backend for MetricsBackend {
    fn work(&self) -> Option<&scheduler::Work> {
        self.work.as_ref()
    }
    fn effect(
        &mut self,
        r: &metrics::Request,
        e: &metrics::Effect,
        a: &mut Access<'_>,
    ) -> Completion<()> {
        match e {
            metrics::Effect::InitializeQueue {
                name,
                stack_bytes,
                priority,
            } => {
                let expected = scheduler::QueueConfiguration::mc_metrics();
                if (*name, *stack_bytes, *priority)
                    != (
                        expected.name.as_str(),
                        expected.stack_bytes,
                        expected.priority,
                    )
                    || self.queue.is_some()
                {
                    return Completion::Refused(
                        "MC actual queue initialization is duplicate or not source geometry",
                    );
                }
                match self.runtime.create_queue(expected) {
                    Ok(q) => {
                        self.queue = Some(q);
                        done(())
                    }
                    Err(e) => Completion::Refused(schedule_error(e)),
                }
            }
            metrics::Effect::BindWork { priority } => {
                if *priority != 15 || self.work.is_some() {
                    return Completion::Refused(
                        "MC actual Work binding is duplicate or not source priority",
                    );
                }
                let Some(callback) = self.callback.take() else {
                    return Completion::Refused("MC required actual service callback absent");
                };
                match self.runtime.bind_work(*priority, Forward(callback)) {
                    Ok(w) => {
                        self.work = Some(w);
                        done(())
                    }
                    Err(e) => Completion::Refused(schedule_error(e)),
                }
            }
            metrics::Effect::RegisterWork => {
                let (Some(q), Some(w)) = (&self.queue, &self.work) else {
                    return Completion::Refused("MC actual queue/work absent at registration");
                };
                self.runtime.register_work(q, w)
            }
            metrics::Effect::Wake => match self
                .work
                .as_ref()
                .ok_or("MC actual Work absent at Wake")
                .and_then(|w| self.runtime.wake(w).map_err(schedule_error))
            {
                Ok(()) => done(()),
                Err(e) => Completion::Refused(e),
            },
            metrics::Effect::RegisterMetric {
                namespace,
                name,
                format,
                unit_descriptor,
                counter,
                ..
            } => {
                if *namespace != "DSID Stats"
                    || *format != 2
                    || *unit_descriptor != 0x0900820000000000
                {
                    return Completion::Refused(
                        "MC metric registration operands differ from source",
                    );
                }
                self.register_metric(r, name, counter.clone(), a)
            }
            metrics::Effect::Trace { event, args } => self.emit(r, *event, *args, a),
            metrics::Effect::DrainWait => self.drain(r),
            metrics::Effect::NotifyStop => match self.runtime.notify(&self.key) {
                Ok(_) => done(()),
                Err(e) => Completion::Refused(schedule_error(e)),
            },
        }
    }
    fn trace_control(&mut self, _: &metrics::Request, _: &mut Access<'_>) -> Completion<u32> {
        let Some(cell) = self.trace.upgrade() else {
            return Completion::Refused("MC actual trace control owner abandoned");
        };
        match cell.try_borrow() {
            Ok(trace) => done(trace.trace_control()),
            Err(_) => Completion::Refused("MC trace control currently borrowed by actual owner"),
        }
    }
}
