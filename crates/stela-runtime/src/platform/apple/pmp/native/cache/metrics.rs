//! Native MC metrics registration, kept queue work and stop drain.
//!
//! Original26A434 T8112 PMP SHA256 b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!1003344..3378 binds work10042b8;1004170..421c registers live counters;
//!1003c94..3cac submits;102ff00..ff68 dispatches;1004264..42b8 drains;
//!10042b8..4584 computes callback traces, clears MCpending and notifies.
//! Evidence: pmgr/cache-metrics-r1. No firmware executes. Samples/arrival and
//! command ACK remain service-owned. Numeric increments are software DATA.
//! Shared Work/Invocation binding: pmgr/metrics-shared-work-r1.
use super::super::{
    platform::owner::Completion,
    scheduler::{Invocation, Work},
};
use alloc::{format, rc::Rc, string::String, vec::Vec};
use core::{
    cell::Cell,
    sync::atomic::{Ordering, fence},
};
use stela_contracts::bus::Access;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Contract(&'static str),
    Backend(&'static str),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricKind {
    Hits,
    Misses,
}
impl MetricKind {
    fn index(self) -> usize {
        match self {
            Self::Hits => 0,
            Self::Misses => 1,
        }
    }
}
/// Live getter destination1007dfc. Cloning keeps the counter cell,
/// never a copied value or any timing/event/completion permission.
#[derive(Clone, Debug)]
pub struct Counter(Rc<Cell<u64>>);
impl Counter {
    pub fn value(&self) -> u64 {
        self.0.get()
    }
    pub fn same_counter(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
#[derive(Clone, Debug)]
pub struct Request {
    owner: Rc<()>,
    serial: u64,
    operation: u64,
}
impl Request {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.serial == other.serial
            && self.operation == other.operation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub groups: u32,
    pub platform_scale: u32,
    pub interval: u64,
}
/// Borrow the sole service snapshot allocation. No arrival or lifecycle token
/// is accepted or created by this data interface.
pub trait SamplesView {
    fn geometry(&self) -> Geometry;
    fn group(&self, group: u32) -> Result<&[u8; 64], Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryControl {
    /// Actual10045a8 O2a0 data update, not readiness.
    Statistics(u32),
}
#[derive(Clone, Debug)]
pub enum Effect {
    InitializeQueue {
        name: &'static str,
        stack_bytes: u32,
        priority: u8,
    },
    BindWork {
        priority: u8,
    },
    RegisterWork,
    RegisterMetric {
        group: u32,
        kind: MetricKind,
        namespace: &'static str,
        name: String,
        format: u32,
        unit_descriptor: u64,
        counter: Counter,
    },
    Wake,
    /// Actual1030250 queue wait/unlock/relock boundary. May remain Busy while
    /// this owner's queued callback runs, then retires after notification.
    DrainWait,
    Trace {
        event: u32,
        args: [u64; 4],
    },
    NotifyStop,
}
/// Fixed queue/registry/trace/waiter owner. No default implementation.
/// Every reached destination must retire, stay Busy or refuse while
/// keeping its own inner prefix under Request. Source addresses are evidence
/// only, never runtime dispatch keys. Trace-control reads observe the real
/// global source control, not a successful absent observer.
pub trait Backend {
    /// BindWork destination. None before that source cursor; afterwards
    /// every RegisterWork/Wake/dispatch must reference this same shared Work.
    /// Production factories bind a mandatory Weak service callback, never an
    /// absent callback or local shadow pending state.
    fn work(&self) -> Option<&Work>;
    fn effect(
        &mut self,
        request: &Request,
        effect: &Effect,
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn trace_control(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<u32>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    TraceComplete,
    Initialized,
    Registered,
    Scheduled,
    CallbackComplete,
    Drained,
    Busy { deadline: Option<u64> },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventTrace {
    Enter,
    Request { group: u32, requested_bytes: u32 },
    Exit,
}
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    trace_base: u32,
    factors: [u32; 2],
    fields: [Field; 5],
}
#[derive(Clone, Copy, Debug)]
struct Field {
    start: u32,
    width: u32,
}
impl Field {
    fn read(self, group: &[u8; 64]) -> Result<u64, Error> {
        if self.width == 0 {
            return Ok(0);
        }
        let index = (self.start / 64) as usize;
        let offset = index
            .checked_mul(16)
            .ok_or(Error::Contract("MC metric field offset overflow"))?;
        let bytes = group.get(offset..offset + 8).ok_or(Error::Contract(
            "MC metric field exceeds actual64-byte group",
        ))?;
        let value = u64::from_le_bytes(bytes.try_into().unwrap());
        let mask = u64::MAX.wrapping_shr(self.width.wrapping_neg() & 63);
        Ok(value.wrapping_shr(self.start & 63) & mask)
    }
}
impl Configuration {
    pub const fn t8112() -> Self {
        Self {
            trace_base: 0x860bb000,
            factors: [1, 4],
            fields: [
                Field {
                    start: 0,
                    width: 32,
                },
                Field {
                    start: 32,
                    width: 32,
                },
                Field {
                    start: 160,
                    width: 32,
                },
                Field {
                    start: 128,
                    width: 32,
                },
                Field {
                    start: 224,
                    width: 32,
                },
            ],
        }
    }
}
#[derive(Clone, Debug)]
enum Op {
    Effect(Effect),
    ZeroCounter(u32, MetricKind),
    AssociateGroup(u32),
    RegistrationDone,
    TraceRead,
    TraceIf { event: u32, args: [u64; 4] },
    Details,
    Group(u32),
    Auxiliary(u32),
    ClearPending,
    CallbackDone,
    StopCheck,
}
struct Job {
    serial: u64,
    cursor: u64,
    ops: alloc::collections::VecDeque<Op>,
    terminal: Progress,
    trace: u32,
    scale: Option<u32>,
    groups: Option<u32>,
}
impl Job {
    fn new(serial: u64, ops: Vec<Op>, terminal: Progress) -> Self {
        Self {
            serial,
            cursor: 0,
            ops: ops.into(),
            terminal,
            trace: 0,
            scale: None,
            groups: None,
        }
    }
}
/// Source-initialized software cells, distinct from observed hardware. The
/// queue executes this concrete callback; there is no completion/pending setter.
pub struct Owner<B: Backend> {
    identity: Rc<()>,
    serial: u64,
    backend: B,
    config: Configuration,
    counters: [[Counter; 2]; 32],
    associations: [Option<u32>; 32],
    initialized: bool,
    registration_flag: bool,
    active: Option<u32>,
    service_word: u32,
    statistics_word: u32,
    mc_pending: bool,
    bound_work: Option<Work>,
    dispatch_identity: Option<Invocation>,
    last_dispatch: Option<Invocation>,
    control: Option<Job>,
    callback: Option<Job>,
    stopping: bool,
    drained: bool,
    fault: Option<&'static str>,
}
impl<B: Backend> Owner<B> {
    pub fn initialized_source(config: Configuration, backend: B) -> Self {
        Self {
            identity: Rc::new(()),
            serial: 0,
            backend,
            config,
            counters: core::array::from_fn(|_| {
                core::array::from_fn(|_| Counter(Rc::new(Cell::new(0))))
            }),
            associations: [None; 32],
            initialized: false,
            registration_flag: true,
            active: None,
            service_word: 0,
            statistics_word: 0,
            mc_pending: false,
            bound_work: None,
            dispatch_identity: None,
            last_dispatch: None,
            control: None,
            callback: None,
            stopping: false,
            drained: false,
            fault: None,
        }
    }
    pub fn initialized(&self) -> bool {
        self.initialized
    }
    pub fn registered(&self) -> bool {
        !self.registration_flag
    }
    pub fn pending(&self) -> bool {
        self.mc_pending
    }
    pub fn queued(&self) -> bool {
        self.bound_work.as_ref().is_some_and(Work::pending)
    }
    /// Preflight foreground service work before keeping/consuming its input.
    /// Queued-only work is distinct and does not require serialization.
    pub fn callback_executing(&self) -> bool {
        self.callback.is_some()
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn counter(&self, group: u32, kind: MetricKind) -> Result<Counter, Error> {
        Ok(self
            .counters
            .get(group as usize)
            .ok_or(Error::Contract("MC metric group exceeds source32 slots"))?[kind.index()]
        .clone())
    }
    /// Source1004204 row+30 registration metadata. It becomes present only
    /// after both metric registrations for that group retire, and grants
    /// no event, arrival, readiness or completion permission.
    pub fn group_association(&self, group: u32) -> Result<Option<u32>, Error> {
        self.associations
            .get(group as usize)
            .copied()
            .ok_or(Error::Contract("MC metric group exceeds source32 slots"))
    }
    /// Source W32 increments have already been derived from sole Samples
    /// by the service; only this source software accumulation occurs here.
    pub fn accumulate(&mut self, group: u32, increments: [u32; 2]) -> Result<(), Error> {
        let counters = self
            .counters
            .get(group as usize)
            .ok_or(Error::Contract("MC metric group exceeds source32 slots"))?;
        for (c, increment) in counters.iter().zip(increments) {
            c.0.set(c.value().wrapping_add(u64::from(increment)))
        }
        Ok(())
    }
    pub fn apply_registry_control(&mut self, control: RegistryControl) {
        match control {
            RegistryControl::Statistics(value) => self.statistics_word = value,
        }
    }
    fn reserve(&self) -> Result<u64, Error> {
        if let Some(reason) = self.fault {
            return Err(Error::Contract(reason));
        }
        self.serial.checked_add(1).ok_or(Error::Contract(
            "MC metric operation serial exhausted before effects",
        ))
    }
    fn idle_control(&self) -> Result<(), Error> {
        if self.control.is_some() {
            Err(Error::Contract(
                "MC metric control operation already retained",
            ))
        } else {
            Ok(())
        }
    }
    pub fn begin_initialize(&mut self) -> Result<(), Error> {
        self.idle_control()?;
        if self.initialized {
            return Err(Error::Contract("MC metric queue already initialized"));
        }
        let serial = self.reserve()?;
        self.serial = serial;
        self.control = Some(Job::new(
            serial,
            alloc::vec![
                Op::Effect(Effect::InitializeQueue {
                    name: "mem-cache",
                    stack_bytes: 0x800,
                    priority: 59
                }),
                Op::Effect(Effect::BindWork { priority: 15 }),
                Op::Effect(Effect::RegisterWork)
            ],
            Progress::Initialized,
        ));
        Ok(())
    }
    pub fn begin_register(&mut self, active: u32) -> Result<(), Error> {
        self.idle_control()?;
        if !self.initialized {
            return Err(Error::Contract(
                "MC metric registration requires actual queue initialization",
            ));
        }
        if self.active.is_some_and(|old| old != active) {
            return Err(Error::Contract(
                "MC source active group mask changed after registration",
            ));
        }
        let serial = self.reserve()?;
        let mut ops = Vec::new();
        if self.registration_flag && self.service_word == 0 {
            for group in 0..32 {
                if active & (1 << group) == 0 {
                    continue;
                }
                for kind in [MetricKind::Hits, MetricKind::Misses] {
                    let counter = self.counter(group, kind)?;
                    ops.push(Op::ZeroCounter(group, kind));
                    ops.push(Op::Effect(Effect::RegisterMetric {
                        group,
                        kind,
                        namespace: "DSID Stats",
                        name: format!(
                            "Grp{} {}",
                            group,
                            if kind == MetricKind::Hits {
                                "Hits"
                            } else {
                                "Misses"
                            }
                        ),
                        format: 2,
                        unit_descriptor: 0x0900820000000000,
                        counter,
                    }));
                }
                ops.push(Op::AssociateGroup(group));
            }
        }
        ops.push(Op::RegistrationDone);
        self.active = Some(active);
        self.serial = serial;
        self.control = Some(Job::new(serial, ops, Progress::Registered));
        Ok(())
    }
    /// Invoke only at the service's equality-housekeeping cursor1003c94.
    /// Sets source MCpending then issues Wake, whose scheduler owns the
    /// sole work.pending cell. Scheduled returns before callback execution.
    pub fn submit_after_housekeeping(&mut self) -> Result<bool, Error> {
        if !self.initialized {
            return Err(Error::Contract(
                "MC metrics submission requires actual registered queue",
            ));
        }
        if self.mc_pending {
            return Ok(false);
        }
        self.idle_control()?;
        if self.stopping {
            return Err(Error::Contract("MC metric source queue is draining"));
        }
        let serial = self.reserve()?;
        self.serial = serial;
        self.mc_pending = true;
        fence(Ordering::Release);
        self.control = Some(Job::new(
            serial,
            alloc::vec![Op::Effect(Effect::Wake)],
            Progress::Scheduled,
        ));
        Ok(true)
    }
    /// Foreground source event tracing may run while callback work is queued;
    /// it never consumes or replaces the queued work. Executing
    /// callbacks currently require explicit serialization by the caller.
    pub fn begin_event_trace(&mut self, event: EventTrace) -> Result<(), Error> {
        self.idle_control()?;
        if self.callback.is_some() {
            return Err(Error::Contract(
                "MC event trace requires serialization with retained executing callback",
            ));
        }
        if !self.initialized {
            return Err(Error::Contract(
                "MC event trace requires actual queue initialization",
            ));
        }
        let serial = self.reserve()?;
        let (event, args) = match event {
            EventTrace::Enter => (self.config.trace_base.wrapping_add(0x10), [1, 0, 0, 0]),
            EventTrace::Exit => (self.config.trace_base.wrapping_add(0x10), [0; 4]),
            EventTrace::Request {
                group,
                requested_bytes,
            } => {
                if group >= 32 || requested_bytes & 0x1ffff != 0 || requested_bytes >> 17 > 0xfff {
                    return Err(Error::Contract(
                        "MC event trace request exceeds source group/lane encoding",
                    ));
                }
                (
                    self.config
                        .trace_base
                        .wrapping_add(0x100)
                        .wrapping_add(group * 4),
                    [u64::from(requested_bytes), 0, 0, 0],
                )
            }
        };
        self.serial = serial;
        self.control = Some(Job::new(
            serial,
            alloc::vec![Op::TraceRead, Op::TraceIf { event, args }],
            Progress::TraceComplete,
        ));
        Ok(())
    }
    pub fn begin_stop(&mut self) -> Result<(), Error> {
        self.idle_control()?;
        if !self.initialized {
            return Err(Error::Contract(
                "MC metrics stop requires actual queue initialization",
            ));
        }
        let serial = self.reserve()?;
        self.serial = serial;
        self.stopping = true;
        self.drained = false;
        self.control = Some(Job::new(
            serial,
            alloc::vec![Op::StopCheck],
            Progress::Drained,
        ));
        Ok(())
    }
    fn callback_job(&mut self) -> Result<Job, Error> {
        let serial = self.reserve()?;
        self.serial = serial;
        Ok(Job::new(
            serial,
            alloc::vec![
                Op::TraceRead,
                Op::TraceIf {
                    event: self.config.trace_base,
                    args: [1, 0, 0, 0]
                },
                Op::Details,
                Op::ClearPending,
                Op::TraceRead,
                Op::TraceIf {
                    event: self.config.trace_base,
                    args: [0; 4]
                },
                Op::Effect(Effect::NotifyStop),
                Op::CallbackDone
            ],
            Progress::CallbackComplete,
        ))
    }
    /// Foreground source cursor only. Callbacks are entered exclusively
    /// through dispatch under the scheduler Invocation. A kept DrainWait
    /// releases its queue lock; the parent continues real scheduler and
    /// immediate endpoint dispatch independently, never inline fake callback work.
    pub fn advance(
        &mut self,
        samples: &dyn SamplesView,
        access: &mut Access<'_>,
    ) -> Result<Progress, Error> {
        if let Some(reason) = self.fault {
            return Err(Error::Contract(reason));
        }
        let Some(mut job) = self.control.take() else {
            return if self.drained {
                Ok(Progress::Drained)
            } else {
                Err(Error::Contract(
                    "MC metrics have no retained foreground work",
                ))
            };
        };
        let result = self.run(&mut job, samples, access);
        match result {
            Ok(Some(terminal)) if !matches!(terminal, Progress::Busy { .. }) => {
                if terminal == Progress::Initialized {
                    self.initialized = true;
                }
                if terminal == Progress::Drained {
                    self.drained = true;
                    self.stopping = false;
                }
                Ok(terminal)
            }
            other => {
                if let Err(Error::Contract(reason)) = other {
                    self.fault = Some(reason);
                }
                self.control = Some(job);
                other.map(|p| p.unwrap_or(Progress::Busy { deadline: None }))
            }
        }
    }
    /// Only the scheduler-entered callback for the Work may
    /// execute this source callback. Its Work.pending was cleared by scheduler
    /// before entry; a later Wake survives callback return0. Stop may
    /// keep its independent foreground wait while this callback advances.
    pub fn dispatch(
        &mut self,
        invocation: &Invocation,
        samples: &dyn SamplesView,
        access: &mut Access<'_>,
    ) -> Result<Progress, Error> {
        if let Some(reason) = self.fault {
            return Err(Error::Contract(reason));
        }
        if !self.initialized {
            return Err(Error::Contract(
                "MC callback before actual queue initialization",
            ));
        }
        let work = self
            .bound_work
            .as_ref()
            .ok_or(Error::Contract("MC callback has no bound native Work"))?;
        let actual = self
            .backend
            .work()
            .ok_or(Error::Contract("MC backend lost bound native Work"))?;
        if !actual.same_work(work) || work.validate_dispatch(invocation).is_err() {
            return Err(Error::Contract(
                "MC callback requires actual same Work invocation",
            ));
        }
        if self
            .last_dispatch
            .as_ref()
            .is_some_and(|prior| prior.same_dispatch(invocation))
        {
            return Err(Error::Contract(
                "MC callback source return already retired for this invocation",
            ));
        }
        if let Some(prior) = self.dispatch_identity.as_ref() {
            if !prior.same_dispatch(invocation) {
                return Err(Error::Contract(
                    "MC callback invocation changed across retained prefix",
                ));
            }
        } else {
            if self
                .control
                .as_ref()
                .is_some_and(|job| job.terminal != Progress::Drained)
            {
                return Err(Error::Contract(
                    "MC callback serialized behind retained foreground operation",
                ));
            }
            // Preflight before installing invocation or callback software state.
            let job = self.callback_job()?;
            self.callback = Some(job);
            self.dispatch_identity = Some(invocation.clone());
        }
        let mut job = self
            .callback
            .take()
            .ok_or(Error::Contract("MC callback invocation lost source job"))?;
        let result = self.run(&mut job, samples, access);
        if matches!(result, Ok(Some(Progress::CallbackComplete))) {
            self.dispatch_identity = None;
            self.last_dispatch = Some(invocation.clone());
        } else {
            if let Err(Error::Contract(reason)) = result {
                self.fault = Some(reason);
            }
            self.callback = Some(job);
        }
        result.map(|p| p.unwrap_or(Progress::Busy { deadline: None }))
    }
    fn run(
        &mut self,
        job: &mut Job,
        samples: &dyn SamplesView,
        access: &mut Access<'_>,
    ) -> Result<Option<Progress>, Error> {
        while !job.ops.is_empty() {
            let next = job
                .cursor
                .checked_add(1)
                .ok_or(Error::Contract("MC metric cursor exhausted before effects"))?;
            let op = job.ops.pop_front().unwrap();
            let request = Request {
                owner: self.identity.clone(),
                serial: job.serial,
                operation: job.cursor,
            };
            let mut retired_refusal = None;
            match &op {
                Op::Effect(effect) => match self.backend.effect(&request, effect, access) {
                    Completion::Busy { deadline } => {
                        job.ops.push_front(op);
                        return Ok(Some(Progress::Busy { deadline }));
                    }
                    Completion::Refused(reason) => {
                        job.ops.push_front(op);
                        return Err(Error::Backend(reason));
                    }
                    Completion::Retired { value: (), refusal } => {
                        // Resource identity is opaque and cannot be minted
                        // by metrics. Keep the same Work from source bind onward.
                        if matches!(
                            effect,
                            Effect::BindWork { .. } | Effect::RegisterWork | Effect::Wake
                        ) {
                            let actual = self.backend.work().ok_or(Error::Contract(
                                "MC actual Work effect retired without bound resource",
                            ))?;
                            if let Some(bound) = self.bound_work.as_ref() {
                                if !actual.same_work(bound) {
                                    return Err(Error::Contract("MC backend replaced bound Work"));
                                }
                            } else if matches!(effect, Effect::BindWork { .. }) {
                                self.bound_work = Some(actual.clone());
                            } else {
                                return Err(Error::Contract(
                                    "MC native work used before source BindWork",
                                ));
                            }
                            if matches!(effect, Effect::RegisterWork) {
                                let queue = actual
                                    .registered_queue()
                                    .map_err(|_| Error::Contract("MC Work scheduler abandoned"))?
                                    .ok_or(Error::Contract(
                                        "MC actual work registration did not occur",
                                    ))?;
                                if queue
                                    .configuration()
                                    .map_err(|_| Error::Contract("MC queue scheduler abandoned"))?
                                    != super::super::scheduler::QueueConfiguration::mc_metrics()
                                {
                                    return Err(Error::Contract(
                                        "MC actual registered queue differs from source configuration",
                                    ));
                                }
                            }
                            if matches!(effect, Effect::Wake) && !actual.pending() {
                                return Err(Error::Contract(
                                    "MC Wake retired without scheduling actual Work",
                                ));
                            }
                        }
                        retired_refusal = refusal;
                    }
                },
                Op::TraceRead => match self.backend.trace_control(&request, access) {
                    Completion::Busy { deadline } => {
                        job.ops.push_front(op);
                        return Ok(Some(Progress::Busy { deadline }));
                    }
                    Completion::Refused(reason) => {
                        job.ops.push_front(op);
                        return Err(Error::Backend(reason));
                    }
                    Completion::Retired { value, refusal } => {
                        job.trace = value;
                        retired_refusal = refusal
                    }
                },
                Op::ZeroCounter(group, kind) => {
                    self.counters[*group as usize][kind.index()].0.set(0)
                }
                Op::AssociateGroup(group) => self.associations[*group as usize] = Some(*group),
                Op::RegistrationDone => self.registration_flag = false,
                Op::TraceIf { event, args } => {
                    if job.trace != 0 {
                        job.ops.push_front(Op::Effect(Effect::Trace {
                            event: *event,
                            args: *args,
                        }))
                    }
                }
                Op::Details => {
                    if self.service_word == 0 && self.statistics_word != 0 {
                        let geometry = samples.geometry();
                        if geometry.groups > 32 {
                            return Err(Error::Contract(
                                "MC metric callback geometry exceeds source32 groups",
                            ));
                        }
                        job.groups = Some(geometry.groups);
                        job.scale = Some(
                            self.config.factors[0]
                                .wrapping_mul(self.config.factors[1])
                                .wrapping_mul(geometry.platform_scale)
                                .wrapping_shl(6),
                        );
                        for group in (0..geometry.groups).rev() {
                            job.ops.push_front(Op::Group(group));
                        }
                    }
                }
                Op::Group(group) => {
                    if self.active.unwrap_or(0) & 1u32.wrapping_shl(*group & 31) != 0 {
                        let geometry = samples.geometry();
                        let data = samples.group(*group)?;
                        let a = self.config.fields[0].read(data)? as u32;
                        let b = self.config.fields[1].read(data)? as u32;
                        if job.groups != Some(geometry.groups) {
                            return Err(Error::Contract(
                                "MC metric sample geometry changed during retained callback",
                            ));
                        }
                        let scale = job
                            .scale
                            .ok_or(Error::Contract("MC metric initial callback scale absent"))?;
                        let a = scale.wrapping_mul(a);
                        let b = scale.wrapping_mul(b);
                        let denominator = geometry
                            .interval
                            .wrapping_mul(u64::from(geometry.platform_scale));
                        // A64 UDIV returns zero for a zero denominator, including
                        // a wrapped product of otherwise nonzero source values.
                        let rates = [a, b].map(|value| {
                            (1_000_000 * u64::from(value))
                                .checked_div(denominator)
                                .unwrap_or(0)
                                >> 20
                        });
                        let event = self
                            .config
                            .trace_base
                            .wrapping_add(0x400)
                            .wrapping_add(group.wrapping_mul(0x20));
                        job.ops.push_front(Op::Auxiliary(*group));
                        job.ops.push_front(Op::TraceIf {
                            event,
                            args: [rates[0], rates[1], u64::from(a), u64::from(b)],
                        });
                        job.ops.push_front(Op::TraceRead);
                    }
                }
                Op::Auxiliary(group) => {
                    let data = samples.group(*group)?;
                    let denominator = self.config.fields[2].read(data)?;
                    let numerator = self.config.fields[3].read(data)? as u32;
                    let ratio = if denominator as u32 == 0 {
                        0
                    } else {
                        ((u64::from(numerator) << 7) / u64::from(denominator as u32)) as u32
                    };
                    let ratio = ratio
                        .wrapping_mul(self.config.factors[0])
                        .wrapping_mul(self.config.factors[1]);
                    let third = (self.config.fields[4].read(data)? as u32)
                        .wrapping_shl(7)
                        .wrapping_mul(self.config.factors[0])
                        .wrapping_mul(self.config.factors[1]);
                    let event = self
                        .config
                        .trace_base
                        .wrapping_add(0x410)
                        .wrapping_add(group.wrapping_mul(0x20));
                    job.ops.push_front(Op::TraceIf {
                        event,
                        args: [u64::from(ratio), u64::from(third), 0, denominator],
                    });
                    job.ops.push_front(Op::TraceRead);
                }
                Op::ClearPending => self.mc_pending = false,
                Op::CallbackDone => {}
                Op::StopCheck => {
                    // Source1004280..100429c tests O3f8, not callback-tail
                    // lifetime. An already kept DrainWait still must retire.
                    if self.mc_pending {
                        job.ops.push_front(Op::StopCheck);
                        job.ops.push_front(Op::Effect(Effect::DrainWait));
                    }
                }
            }
            job.cursor = next;
            if let Some(reason) = retired_refusal {
                return Err(Error::Backend(reason));
            }
            // A completed external operation returns to the scheduler before dispatching
            // unrelated work, especially Schedule→Callback. Pure source prefix is kept.
            if matches!(op, Op::Effect(_) | Op::TraceRead) && !job.ops.is_empty() {
                return Ok(None);
            }
        }
        Ok(Some(job.terminal))
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "std"))]
mod original_tests {
    use super::*;
    fn source() -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let b = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&b)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        b
    }
    fn word(b: &[u8], a: usize) -> u32 {
        u32::from_le_bytes(b[a - 0xfff000..a - 0xfff000 + 4].try_into().unwrap())
    }
    fn pair(b: &[u8], a: usize) -> u64 {
        u64::from_le_bytes(b[a - 0xfff000..a - 0xfff000 + 8].try_into().unwrap())
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_metrics_registration_and_queue_operands() {
        let b = source();
        for (a, v) in [
            (0x1007d24, 0xf900001f),
            (0x1007dfc, 0xf9400000),
            (0x1004170, 0x394f1268),
            (0x10041d0, 0x52800043),
            (0x1004204, 0xb8396918),
            (0x10302f4, 0xd5033bbf),
            (0x10302f8, 0x39000409),
            (0x102ff10, 0x3900077f),
            (0x1004310, 0x390fe27f),
            (0x1004280, 0x394fe268), // Load MC-pending byte.
            (0x1004284, 0x7100051f),
            (0x1004288, 0x540000c1), // Initial non-one skips drain.
            (0x100429c, 0x3707ff88), // Wait loops on pending bit0.
        ] {
            assert_eq!(word(&b, a), v, "{a:x}");
        }
        assert_eq!(pair(&b, 0x10350b8 + 16), 0x0900820000000000);
        assert_eq!(pair(&b, 0x1045f18 + 0x60), 0x800);
        assert_eq!(b[0x1045f18 + 0x68 - 0xfff000], 2);
        for (a, s) in [
            (0x1035afb, "Grp%d Hits"),
            (0x1035b06, "DSID Stats"),
            (0x1035b11, "Grp%d Misses"),
            (0x1035d21, "mem-cache"),
        ] {
            let bytes = &b[a - 0xfff000..];
            let len = bytes.iter().position(|x| *x == 0).unwrap();
            assert_eq!(&bytes[..len], s.as_bytes());
        }
        let branch = word(&b, 0x1004330);
        assert_eq!(branch >> 26, 0x25);
        let offset = ((branch << 6) as i32 >> 6) as i64;
        assert_eq!(0x1004330i64 + offset * 4, 0x10302bc);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_metric_callback_fields_scale_and_trace_operands() {
        let b = source();
        let c = Configuration::t8112();
        assert_eq!(c.trace_base, word(&b, 0x1045f18 + 0x14));
        for (i, o) in [0x3b8, 0x3d0, 0x430, 0x418, 0x460].into_iter().enumerate() {
            let raw = pair(&b, 0x1046ab8 + o);
            assert_eq!(c.fields[i].start, raw as u32);
            assert_eq!(c.fields[i].width, (raw >> 32) as u32);
        }
        assert_eq!(
            c.factors,
            [word(&b, 0x1046ab8 + 0x270), word(&b, 0x1046ab8 + 0x274)]
        );
        assert_eq!(pair(&b, 0x1046ab8 + 0x3a8), 0);
        assert_eq!((word(&b, 0x1034380), word(&b, 0x1034384)), (8, 2));
        assert_eq!(word(&b, 0x1032fc8), 0xfd020260);
        assert_eq!(word(&b, 0x1046ab8 + 0x400), 96);
        for (a, v) in [
            (0x1004394, 0x1b0a7d6a),
            (0x1004398, 0x1b097d49),
            (0x1004414, 0x1b0a7eea),
            (0x1004430, 0x9b0d7dc9),
            (0x1004500, 0x1b0a7d6a),
            (0x1004558, 0x1b087d68),
            (0x1019cc8, 0xf9013a69),
        ] {
            assert_eq!(word(&b, a), v, "{a:x}");
        }
    }
}
