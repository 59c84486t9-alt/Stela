//! Native RTKit endpoint3 trace owner, independent of PMP endpoint0x20 registry.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! 1006094..60a8 initializes TRCE=1;101f494..f7c4 owns ring selection,
//! overflow/filter/32-byte records;102d110..d7dc owns endpoint3 and lifecycle.
//! Source audit: pmgr/metrics-backend-destinations-r1. Source addresses are
//! provenance only. No firmware executes. Mappings, native thread/clock,
//! queue/wait and mailbox effects are mandatory moved-in resources.
//!
//! Default AP-buffer initialization is admitted. Alternate native-heap and
//! secondary-ring construction are explicitly unchecked, rather than fake
//! allocations. A no-buffer/disabled/filtered return is an Emitted
//! outcome with its source code; it does not claim any record was published.
use super::platform::owner::Completion;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use stela_contracts::bus::Access;

mod protocol;
use protocol::{Command, encode_body};

pub const ENDPOINT: u8 = 3;
pub const RECORD_BYTES: u64 = 32;
pub const FILTER_BYTES: u64 = 0x2000;
pub const NO_BUFFER: u32 = 0x8000_0008;
pub const DISABLED: u32 = 0x8000_0007;
pub const OVERFLOW: u32 = 0x8000_000e;
pub const FILTERED: u32 = 2;
const OVERFLOW_EVENT: u32 = 0x86ff_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Contract(&'static str),
    Backend(&'static str),
}
/// Source configuration DATA, not allocation, arrival or readiness permission.
/// The parent must keep its native configuration producer. The source
/// startup reads n then initializes n+1 slots and replaces threshold n/10 with
/// n/2 at10061d4..dc. No Apple SKU count is inferred here.
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    slots: u32,
    threshold: u32,
}
impl Configuration {
    /// Original1032e00..e64 joins1072608+20 to10446a0, whose first
    /// word is0x8000. This is native configuration, not a reset measurement.
    pub const fn t8112() -> Self {
        Self {
            slots: 0x8001,
            threshold: 0x4000,
        }
    }
    pub fn from_source_capacity(capacity: u32) -> Result<Self, Error> {
        let slots = capacity
            .checked_add(1)
            .ok_or(Error::Contract("trace slot count overflow"))?;
        if capacity == 0 || slots > 0x00ff_ffff {
            return Err(Error::Contract(
                "trace source capacity exceeds endpoint3 count field",
            ));
        }
        Ok(Self {
            slots,
            threshold: capacity / 2,
        })
    }
    pub fn slots(self) -> u32 {
        self.slots
    }
    pub fn threshold(self) -> u32 {
        self.threshold
    }
    pub fn ring_bytes(self) -> u64 {
        (u64::from(self.slots) * RECORD_BYTES + 0xfff) & !0xfff
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
pub enum Buffer {
    Primary,
    Filter,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub address: u64,
    pub bytes: u64,
    /// Literal source102d528/624 mode, not an inferred host cache mode.
    pub flags: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Synchronization {
    /// Actual102b5d0 descriptor preparation, including reached cache guards.
    Prepare,
    /// Actual102b67c completion before producer-index flush publication.
    Complete,
}
/// A live canonical RAM/DMA mapping, moved into this owner after the
/// endpoint3 reply is consumed. No copied Vec, numeric address or host pointer
/// alone grants buffer ownership. Each write/read keeps its prefix
/// under Request across Busy/refusal; Retired never means enqueued.
pub trait Mapping {
    fn geometry(&self) -> Geometry;
    fn read(
        &mut self,
        request: &Request,
        offset: u64,
        output: &mut [u8],
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn write(
        &mut self,
        request: &Request,
        offset: u64,
        input: &[u8],
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn synchronize(
        &mut self,
        request: &Request,
        operation: Synchronization,
        access: &mut Access<'_>,
    ) -> Completion<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ordering {
    ReservationFull,
    TimestampRelease,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    ///102d354..398: work enabled1,pending0,priority15,global queue.
    RegisterWork {
        priority: u8,
    },
    BindEndpoint {
        endpoint: u8,
    },
    RegisterLifecycle {
        slot: u16,
    },
    Wake,
    Send {
        endpoint: u8,
        message: u64,
    },
    Ordering(Ordering),
    /// Waiter keyed by this owner's flush-busy cell; releases/reacquires
    /// queue lock. A real consumed-index callback can execute while it waits.
    DrainWait,
    NotifyWaiters,
}
/// Native execution-context observations corresponding to101fb40,
///102d1d0..dc and1023ad4. These are data from the cooperative scheduler owner,
/// not a public ready flag or an invented host-pointer thread identity.
/// The backend keeps the real scheduler critical-section read/mask/restore
/// prefix corresponding to1023ad4; source EL0/assert contexts must refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushContext {
    pub on_thread_stack: bool,
    pub irq_masked: bool,
    pub scheduler_flag: u8,
}
impl FlushContext {
    fn blocked(self) -> bool {
        self.on_thread_stack && self.irq_masked && self.scheduler_flag & 1 == 0
    }
}
/// Fixed real owners. No default implementation or successful absent sink.
/// Receive returns a consumed endpoint3 message, not caller-supplied
/// synthetic commands. Clock reads the bound source/native clock; thread_id is
/// assigned by the cooperative native owner (never a host pointer cast
/// or an ad hoc zero). Mapping/sync/ordering/send effects retire work.
pub trait Backend {
    type Mapping: Mapping;
    fn effect(
        &mut self,
        request: &Request,
        effect: Effect,
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn map(
        &mut self,
        request: &Request,
        buffer: Buffer,
        geometry: Geometry,
        access: &mut Access<'_>,
    ) -> Completion<Self::Mapping>;
    fn receive(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<Option<u64>>;
    fn clock(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<u64>;
    fn thread_id(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<u32>;
    fn flush_context(
        &mut self,
        request: &Request,
        access: &mut Access<'_>,
    ) -> Completion<FlushContext>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Requested,
    OverflowMarker,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Emission {
    pub source_return: u32,
    /// Data describing a timestamp-last write, not completion permission
    /// for MC, PTD or any unrelated device.
    pub record: Option<RecordKind>,
}
impl Emission {
    /// The caller may report a source-return failure once without claiming
    /// that tracing succeeded; MC itself ignores W0. Filtering is expected
    /// source selection and does not describe an unsupported destination.
    pub fn diagnostic(self) -> Option<&'static str> {
        match self.source_return {
            NO_BUFFER => Some("native trace returned80000008: no actual buffer"),
            DISABLED => Some("native trace returned80000007: primary disabled"),
            OVERFLOW => Some("native trace returned8000000e: ring overflow"),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Initialized,
    Emitted(Emission),
    /// Source worker handles one input then returns1; no input returns0.
    Dispatched {
        consumed: bool,
        kind: Option<u8>,
    },
    Paused,
    Resumed,
    LifecycleUnchanged,
    Busy {
        deadline: Option<u64>,
    },
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Effect(Effect),
    Initialized,
    Select,
    FilterRead,
    FilterSelect,
    Clock,
    Reserve,
    Space,
    NotifyContext,
    NotifyApply,
    Thread,
    Body,
    Timestamp,
    FlushCheck,
    FlushConfiguration,
    FlushSync,
    FlushSend,
    Receive,
    Decode,
    Map(Buffer, Geometry),
    ValidateMap(Buffer, Geometry),
    Prepare(Buffer),
    CommitMap(Buffer),
    RefreshFilter,
    Enable(bool),
    RequestFlush,
    ClearConsumed,
    CommitConsumed,
    ResetBegin,
    ResetClear,
    ResetDone,
    PauseBegin,
    PauseWait,
    Resume,
}
struct Job {
    serial: u64,
    cursor: u64,
    ops: VecDeque<Op>,
    terminal: Progress,
    event: u32,
    args: [u64; 4],
    clock: u64,
    thread: u32,
    slot: u32,
    scratch: [u8; 1],
    raw: Option<u64>,
    clear: u32,
    target: u32,
    restore_enabled: bool,
    wait_reached: bool,
    flush_context: Option<FlushContext>,
    refusal: Option<&'static str>,
}
impl Job {
    fn new(serial: u64, ops: Vec<Op>, terminal: Progress) -> Self {
        Self {
            serial,
            cursor: 0,
            ops: ops.into(),
            terminal,
            event: 0,
            args: [0; 4],
            clock: 0,
            thread: 0,
            slot: 0,
            scratch: [0],
            raw: None,
            clear: 0,
            target: 0,
            restore_enabled: false,
            wait_reached: false,
            flush_context: None,
            refusal: None,
        }
    }
    fn prepend(&mut self, ops: &[Op]) {
        for op in ops.iter().rev() {
            self.ops.push_front(*op);
        }
    }
    fn emission(&mut self, source_return: u32, record: Option<RecordKind>) {
        self.terminal = Progress::Emitted(Emission {
            source_return,
            record,
        });
    }
}
enum Flow {
    Done,
    Expand(Vec<Op>),
    Busy(Option<u64>),
}
macro_rules! retired {
    ($job:expr, $call:expr) => {
        match $call {
            Completion::Busy { deadline } => return Ok(Flow::Busy(deadline)),
            Completion::Refused(reason) => return Err(Error::Backend(reason)),
            Completion::Retired { value, refusal } => {
                $job.refusal = refusal;
                value
            }
        }
    };
}
/// Concrete ring/filter/command owner. Pure source-initialized cells are
/// explicitly software state, never observed hardware. No set-ready/enabled,
/// buffer injection, mark-published, replacement backend or cancellation API.
/// Protocol processing remains independent of a lifecycle DrainWait,
/// so the consumed-index callback can clear busy and wake that waiter.
/// Other foreground/protocol overlap is refused before consuming input; full
/// multithreaded producer interleavings are not claimed by this serialized
/// cooperative owner. Rust ownership provides exclusive index reservation.
pub struct Owner<B: Backend> {
    identity: Rc<()>,
    serial: u64,
    backend: B,
    configuration: Configuration,
    initialized: bool,
    control: u32,
    enabled: bool,
    paused: bool,
    pending: bool,
    flush_busy: bool,
    read: u32,
    write: u32,
    last_configuration: u32,
    primary: Option<B::Mapping>,
    filter: Option<B::Mapping>,
    mapping: Option<(Buffer, B::Mapping)>,
    foreground: Option<Job>,
    protocol: Option<Job>,
}
impl<B: Backend> Owner<B> {
    pub fn initialized(configuration: Configuration, backend: B) -> Self {
        Self {
            identity: Rc::new(()),
            serial: 0,
            backend,
            configuration,
            initialized: false,
            control: 1,
            enabled: false,
            paused: false,
            pending: false,
            flush_busy: false,
            read: 0,
            write: 0,
            last_configuration: 0,
            primary: None,
            filter: None,
            mapping: None,
            foreground: None,
            protocol: None,
        }
    }
    pub fn trace_control(&self) -> u32 {
        self.control
    }
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
    pub fn foreground_pending(&self) -> bool {
        self.foreground.is_some()
    }
    pub fn dispatch_pending(&self) -> bool {
        self.protocol.is_some()
    }
    pub fn indices(&self) -> (u32, u32) {
        (self.read, self.write)
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn flush_pending(&self) -> bool {
        self.pending
    }
    pub fn flush_busy(&self) -> bool {
        self.flush_busy
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    fn serial(&self) -> Result<u64, Error> {
        self.serial
            .checked_add(1)
            .ok_or(Error::Contract("trace request serial exhausted"))
    }
    fn available(&self) -> Result<(), Error> {
        if self.foreground.is_some() || self.protocol.is_some() {
            Err(Error::Contract(
                "trace owner retains an unfinished operation",
            ))
        } else {
            Ok(())
        }
    }
    pub fn begin_initialize(&mut self) -> Result<(), Error> {
        self.available()?;
        if self.initialized {
            return Err(Error::Contract("trace owner already initialized"));
        }
        let serial = self.serial()?;
        let ops = vec![
            Op::Effect(Effect::RegisterWork { priority: 15 }),
            Op::Effect(Effect::BindEndpoint { endpoint: ENDPOINT }),
            Op::Effect(Effect::RegisterLifecycle { slot: 0 }),
            Op::Effect(Effect::Wake),
            Op::Initialized,
        ];
        self.foreground = Some(Job::new(serial, ops, Progress::Initialized));
        self.serial = serial;
        Ok(())
    }
    pub fn begin_emit(&mut self, event: u32, args: [u64; 4]) -> Result<(), Error> {
        self.available()?;
        if !self.initialized {
            return Err(Error::Contract("trace endpoint work not initialized"));
        }
        let serial = self.serial()?;
        let mut job = Job::new(
            serial,
            vec![Op::Select],
            Progress::Emitted(Emission {
                source_return: NO_BUFFER,
                record: None,
            }),
        );
        job.event = event;
        job.args = args;
        self.foreground = Some(job);
        self.serial = serial;
        Ok(())
    }
    pub fn begin_dispatch(&mut self) -> Result<(), Error> {
        if !self.initialized || self.protocol.is_some() {
            return Err(Error::Contract(
                "trace dispatcher unavailable or still retained",
            ));
        }
        // A source pause releases the queue lock while waiting; its ACK callback
        // must be dispatched independently. Other interleavings need an owner.
        if self
            .foreground
            .as_ref()
            .is_some_and(|j| j.ops.front().is_none_or(|op| !matches!(op, Op::PauseWait)))
        {
            return Err(Error::Contract(
                "trace producer and command execution are serialized",
            ));
        }
        let serial = self.serial()?;
        self.protocol = Some(Job::new(
            serial,
            vec![Op::FlushCheck, Op::Receive, Op::Decode],
            Progress::Dispatched {
                consumed: false,
                kind: None,
            },
        ));
        self.serial = serial;
        Ok(())
    }
    pub fn begin_lifecycle(&mut self, prior: u32, next: u32) -> Result<(), Error> {
        self.available()?;
        if !self.initialized {
            return Err(Error::Contract(
                "trace lifecycle before actual endpoint initialization",
            ));
        }
        let serial = self.serial()?;
        let (ops, terminal) = if prior <= 8 && next == 0x21 {
            (vec![Op::Resume], Progress::Resumed)
        } else if prior == 0x21 && next <= 8 {
            (vec![Op::PauseBegin, Op::PauseWait], Progress::Paused)
        } else {
            (Vec::new(), Progress::LifecycleUnchanged)
        };
        self.foreground = Some(Job::new(serial, ops, terminal));
        self.serial = serial;
        Ok(())
    }
    /// One bounded operation retires per call. A Retired-with-refusal advances
    /// before reporting its diagnostic; a before-retirement refusal retries
    /// only that same stable operation. No committed prefix is replayed.
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        self.advance_job(self.protocol.is_some(), access)
    }
    /// Advance the real lifecycle independently of an unfinished command tail.
    /// A cleared predicate does not require unrelated Notify tail completion,
    /// but an already-entered DrainWait must still retire through its owner.
    pub fn advance_lifecycle(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        if !self.foreground.as_ref().is_some_and(|j| {
            matches!(
                j.terminal,
                Progress::Paused | Progress::Resumed | Progress::LifecycleUnchanged
            )
        }) {
            return Err(Error::Contract("trace has no retained lifecycle operation"));
        }
        self.advance_job(false, access)
    }
    pub fn advance_dispatch(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        self.advance_job(true, access)
    }
    fn advance_job(&mut self, protocol: bool, access: &mut Access<'_>) -> Result<Progress, Error> {
        let retained = if protocol {
            self.protocol.take()
        } else {
            self.foreground.take()
        };
        let mut job = retained.ok_or(Error::Contract("trace has no retained operation"))?;
        if job.ops.is_empty() {
            return Ok(job.terminal);
        }
        let next = match job.cursor.checked_add(1) {
            Some(next) => next,
            None => {
                if protocol {
                    self.protocol = Some(job);
                } else {
                    self.foreground = Some(job);
                }
                return Err(Error::Contract("trace operation cursor exhausted"));
            }
        };
        let request = Request {
            owner: self.identity.clone(),
            serial: job.serial,
            operation: job.cursor,
        };
        let op = *job.ops.front().unwrap();
        let result = self.step(&mut job, &request, op, access);
        let outcome = match result {
            Ok(Flow::Busy(deadline)) => Ok(Progress::Busy { deadline }),
            Err(error) => Err(error),
            Ok(flow) => {
                job.ops.pop_front();
                job.cursor = next;
                if let Flow::Expand(ops) = flow {
                    job.prepend(&ops);
                }
                if let Some(reason) = job.refusal.take() {
                    Err(Error::Backend(reason))
                } else {
                    Ok(Progress::Busy { deadline: None })
                }
            }
        };
        if protocol {
            self.protocol = Some(job);
        } else {
            self.foreground = Some(job);
        }
        outcome
    }
    fn mapping_mut(&mut self, buffer: Buffer) -> Result<&mut B::Mapping, Error> {
        match buffer {
            Buffer::Primary => self.primary.as_mut(),
            Buffer::Filter => self.filter.as_mut(),
        }
        .ok_or(Error::Contract(
            "trace operation has no actual mapped buffer",
        ))
    }
    fn step(
        &mut self,
        job: &mut Job,
        request: &Request,
        op: Op,
        access: &mut Access<'_>,
    ) -> Result<Flow, Error> {
        match op {
            Op::Effect(effect) => {
                retired!(job, self.backend.effect(request, effect, access));
            }
            Op::Initialized => {
                self.initialized = true;
            }
            Op::Select => {
                if self.primary.is_none() {
                    job.emission(NO_BUFFER, None);
                } else if !self.enabled {
                    job.emission(DISABLED, None);
                } else if self.filter.is_some() {
                    return Ok(Flow::Expand(vec![Op::FilterRead, Op::FilterSelect]));
                } else {
                    return Ok(Flow::Expand(vec![Op::Clock, Op::Reserve]));
                }
            }
            Op::FilterRead => {
                retired!(
                    job,
                    self.mapping_mut(Buffer::Filter)?.read(
                        request,
                        u64::from(job.event >> 19),
                        &mut job.scratch,
                        access
                    )
                );
            }
            Op::FilterSelect => {
                if job.scratch[0] & (1 << ((job.event >> 16) & 7)) == 0 {
                    job.emission(FILTERED, None);
                } else {
                    return Ok(Flow::Expand(vec![Op::Clock, Op::Reserve]));
                }
            }
            Op::Clock => {
                job.clock = retired!(job, self.backend.clock(request, access));
            }
            Op::Reserve => {
                let old = self.write;
                let next = (old + 1) % self.configuration.slots;
                if next == self.read {
                    job.emission(OVERFLOW, None);
                    return Ok(Flow::Expand(vec![Op::NotifyContext, Op::NotifyApply]));
                }
                // Exclusive owner reservation implements source LDXR/STXR; the
                // DSB is a separate mandatory kept effect below.
                self.write = next;
                job.slot = old;
                return Ok(Flow::Expand(vec![
                    Op::Effect(Effect::Ordering(Ordering::ReservationFull)),
                    Op::Space,
                ]));
            }
            Op::Space => {
                let old = job.slot;
                // Preserve W-register wrap BEFORE the source unsigned modulo.
                // n+1 need not be a power of2 (original default is0x8001).
                let free = if self.read < old {
                    self.read + self.configuration.slots - old - 1
                } else {
                    self.read.wrapping_sub(old).wrapping_sub(1) % self.configuration.slots
                };
                let mut ops = Vec::new();
                if free <= self.configuration.threshold {
                    ops.extend([Op::NotifyContext, Op::NotifyApply]);
                }
                if free == 1 {
                    job.event = OVERFLOW_EVENT;
                    job.args = [0; 4];
                    job.emission(OVERFLOW, Some(RecordKind::OverflowMarker));
                } else {
                    job.emission(0, Some(RecordKind::Requested));
                }
                ops.extend([
                    Op::Thread,
                    Op::Body,
                    Op::Effect(Effect::Ordering(Ordering::TimestampRelease)),
                    Op::Timestamp,
                ]);
                return Ok(Flow::Expand(ops));
            }
            Op::NotifyContext => {
                job.flush_context =
                    Some(retired!(job, self.backend.flush_context(request, access)));
            }
            Op::NotifyApply => {
                if !job
                    .flush_context
                    .ok_or(Error::Contract("trace flush context missing"))?
                    .blocked()
                    && !self.pending
                {
                    self.pending = true;
                    return Ok(Flow::Expand(vec![Op::Effect(Effect::Wake)]));
                }
            }
            Op::Thread => {
                job.thread = retired!(job, self.backend.thread_id(request, access));
            }
            Op::Body => {
                let body = encode_body(job.event, job.thread, job.args);
                retired!(
                    job,
                    self.mapping_mut(Buffer::Primary)?.write(
                        request,
                        u64::from(job.slot) * RECORD_BYTES + 8,
                        &body,
                        access
                    )
                );
            }
            Op::Timestamp => {
                retired!(
                    job,
                    self.mapping_mut(Buffer::Primary)?.write(
                        request,
                        u64::from(job.slot) * RECORD_BYTES,
                        &job.clock.to_le_bytes(),
                        access
                    )
                );
            }
            Op::FlushCheck => {
                if !self.paused && self.pending && !self.flush_busy {
                    if self.primary.is_none() {
                        return Err(Error::Contract(
                            "trace pending flush without actual primary mapping",
                        ));
                    }
                    self.flush_busy = true;
                    return Ok(Flow::Expand(vec![
                        Op::FlushConfiguration,
                        Op::FlushSync,
                        Op::FlushSend,
                    ]));
                }
            }
            Op::FlushConfiguration => {
                if self.last_configuration != 1 {
                    retired!(
                        job,
                        self.backend.effect(
                            request,
                            Effect::Send {
                                endpoint: ENDPOINT,
                                message: (6u64 << 48) | 1
                            },
                            access
                        )
                    );
                    self.last_configuration = 1;
                }
            }
            Op::FlushSync => {
                retired!(
                    job,
                    self.mapping_mut(Buffer::Primary)?.synchronize(
                        request,
                        Synchronization::Complete,
                        access
                    )
                );
            }
            Op::FlushSend => {
                retired!(
                    job,
                    self.backend.effect(
                        request,
                        Effect::Send {
                            endpoint: ENDPOINT,
                            message: (4u64 << 48) | u64::from(self.write)
                        },
                        access
                    )
                );
            }
            Op::Receive => {
                job.raw = retired!(job, self.backend.receive(request, access));
                if let Some(raw) = job.raw {
                    job.terminal = Progress::Dispatched {
                        consumed: true,
                        kind: Some((raw >> 48) as u8),
                    };
                }
            }
            Op::Decode => {
                let Some(raw) = job.raw else {
                    return Ok(Flow::Done);
                };
                return self.command(job, Command::decode(raw));
            }
            Op::Map(buffer, geometry) => {
                if self.mapping.is_some() {
                    return Err(Error::Contract("trace retains an unfinished mapping"));
                }
                let mapping = retired!(job, self.backend.map(request, buffer, geometry, access));
                self.mapping = Some((buffer, mapping));
            }
            Op::ValidateMap(buffer, geometry) => {
                let (kind, mapping) = self
                    .mapping
                    .as_ref()
                    .ok_or(Error::Contract("trace map returned no resource"))?;
                if *kind != buffer || mapping.geometry() != geometry {
                    return Err(Error::Contract(
                        "trace map returned foreign geometry; resource retained",
                    ));
                }
            }
            Op::Prepare(buffer) => {
                let (kind, mapping) = self
                    .mapping
                    .as_mut()
                    .ok_or(Error::Contract("trace preparation lacks actual map"))?;
                if *kind != buffer {
                    return Err(Error::Contract("trace preparation target mismatch"));
                }
                retired!(
                    job,
                    mapping.synchronize(request, Synchronization::Prepare, access)
                );
            }
            Op::CommitMap(buffer) => {
                let (kind, mapping) = self
                    .mapping
                    .take()
                    .ok_or(Error::Contract("trace commit lacks actual map"))?;
                // Earlier preflight guarantees empty destination and identity.
                if kind != buffer {
                    self.mapping = Some((kind, mapping));
                    return Err(Error::Contract("trace mapping target mismatch"));
                }
                match buffer {
                    Buffer::Primary => self.primary = Some(mapping),
                    Buffer::Filter => self.filter = Some(mapping),
                }
            }
            Op::RefreshFilter => {
                if let Some(mapping) = self.filter.as_mut() {
                    retired!(
                        job,
                        mapping.synchronize(request, Synchronization::Prepare, access)
                    );
                }
            }
            Op::Enable(value) => {
                self.enabled = value;
            }
            Op::RequestFlush => {
                self.pending = true;
            }
            Op::ClearConsumed => {
                if job.clear != job.target {
                    retired!(
                        job,
                        self.mapping_mut(Buffer::Primary)?.write(
                            request,
                            u64::from(job.clear) * RECORD_BYTES,
                            &0u64.to_le_bytes(),
                            access
                        )
                    );
                    job.clear = (job.clear + 1) % self.configuration.slots;
                    return Ok(Flow::Expand(vec![Op::ClearConsumed]));
                }
            }
            Op::CommitConsumed => {
                self.flush_busy = false;
                self.pending = false;
                self.read = job.target;
                return Ok(Flow::Expand(vec![Op::Effect(Effect::NotifyWaiters)]));
            }
            Op::ResetBegin => {
                job.restore_enabled = self.enabled;
                self.enabled = false;
                job.clear = 0;
            }
            Op::ResetClear => {
                if job.clear < self.configuration.slots {
                    retired!(
                        job,
                        self.mapping_mut(Buffer::Primary)?.write(
                            request,
                            u64::from(job.clear) * RECORD_BYTES,
                            &0u64.to_le_bytes(),
                            access
                        )
                    );
                    job.clear += 1;
                    return Ok(Flow::Expand(vec![Op::ResetClear]));
                }
            }
            Op::ResetDone => {
                self.write = 0;
                self.read = 0;
                self.enabled = job.restore_enabled;
            }
            Op::PauseBegin => {
                self.paused = true;
            }
            Op::PauseWait => {
                if self.flush_busy || job.wait_reached {
                    job.wait_reached = true;
                    retired!(job, self.backend.effect(request, Effect::DrainWait, access));
                    job.wait_reached = false;
                    // Source while-loop rechecks its busy cell. Each
                    // retired wait is distinct; Busy retries preserve identity.
                    return Ok(Flow::Expand(vec![Op::PauseWait]));
                }
            }
            Op::Resume => {
                self.paused = false;
                return Ok(Flow::Expand(vec![Op::Effect(Effect::Wake)]));
            }
        }
        Ok(Flow::Done)
    }
    fn command(&mut self, job: &mut Job, command: Command) -> Result<Flow, Error> {
        let ops = match command {
            Command::Primary(address) | Command::Filter(address) => {
                let buffer = if matches!(command, Command::Primary(_)) {
                    Buffer::Primary
                } else {
                    Buffer::Filter
                };
                if (buffer == Buffer::Primary && self.primary.is_some())
                    || (buffer == Buffer::Filter && self.filter.is_some())
                    || self.mapping.is_some()
                {
                    return Err(Error::Contract(
                        "trace replacement mapping needs qualified release ownership",
                    ));
                }
                let geometry = Geometry {
                    address,
                    bytes: if buffer == Buffer::Primary {
                        self.configuration.ring_bytes()
                    } else {
                        FILTER_BYTES
                    },
                    flags: 0x202,
                };
                address
                    .checked_add(geometry.bytes)
                    .ok_or(Error::Contract("trace AP buffer range overflow"))?;
                vec![
                    Op::Map(buffer, geometry),
                    Op::ValidateMap(buffer, geometry),
                    Op::Prepare(buffer),
                    Op::CommitMap(buffer),
                ]
            }
            Command::Consumed(target) => {
                if target >= self.configuration.slots || self.primary.is_none() {
                    return Err(Error::Contract(
                        "trace consumed index lacks valid actual primary slice",
                    ));
                }
                job.target = target;
                job.clear = self.read;
                vec![Op::ClearConsumed, Op::CommitConsumed]
            }
            Command::Reset => {
                if self.primary.is_none() {
                    return Err(Error::Contract("trace reset has no actual primary buffer"));
                }
                vec![Op::ResetBegin, Op::ResetClear, Op::ResetDone]
            }
            Command::Disable => vec![Op::Enable(false)],
            Command::Enable => vec![Op::Enable(true)],
            Command::RequestFlush => vec![Op::RequestFlush],
            Command::HostReady => vec![Op::Effect(Effect::Send {
                endpoint: ENDPOINT,
                message: (1u64 << 48) | u64::from(self.configuration.slots),
            })],
            Command::FilterChanged => vec![Op::RefreshFilter],
            // Source worker returns after consuming unknown type. Expose the
            // consumed kind in terminal DATA; do not invent a reply or effect.
            Command::Unknown => Vec::new(),
        };
        Ok(Flow::Expand(ops))
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "std"))]
mod original_tests {
    use sha2::{Digest, Sha256};
    fn image() -> Vec<u8> {
        let b = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&b)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        b
    }
    fn window(b: &[u8], start: usize, end: usize, sha: &str) {
        assert_eq!(
            hex::encode(Sha256::digest(&b[start - 0xfff000..end - 0xfff000])),
            sha
        );
    }
    fn word(b: &[u8], va: usize) -> u32 {
        u32::from_le_bytes(b[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap())
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_trace_configuration_join_and_final_threshold() {
        let b = image();
        window(
            &b,
            0x1006094,
            0x10061e0,
            "37ef5980e7dcb892904d686d7667ca236f5c3b7afd8990cf00e5107db1e4c540",
        );
        window(
            &b,
            0x1032e00,
            0x1032e68,
            "ace57127ea448fd2b7f595bb95894f6e042ec9ff1d03baf1a715b90727931b06",
        );
        assert_eq!(word(&b, 0x10446a0), 0x8000);
        assert_eq!(word(&b, 0x104bf44), 1);
        assert_eq!(word(&b, 0x1032e48), 0x911a816b); // ADD X11,X11,#6a0
        assert_eq!(word(&b, 0x1032e64), 0xa90226cb); // STR pair into config+20
        assert_eq!(word(&b, 0x10061d8), 0x53017d00); // n>>1
        assert_eq!(super::Configuration::t8112().slots(), 0x8001);
        assert_eq!(super::Configuration::t8112().threshold(), 0x4000);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_trace_low32_timestamp_last_and_endpoint3_commands() {
        let b = image();
        window(
            &b,
            0x101f494,
            0x101f7c4,
            "ec0497db304a36bc6e8947dd69aea5462a102d4e74f64401bb1f287c898a5015",
        );
        window(
            &b,
            0x102d110,
            0x102d43c,
            "da9de5f0d2071fc14d77faf46426e826bbffd95b61264be06d36687810786ef9",
        );
        window(
            &b,
            0x102d43c,
            0x102d7dc,
            "e2dae3b883475523e51b24ac68faeffc198aeebe1262359db4c1ed3094e1dee8",
        );
        for (va, w) in [
            (0x101f574, 0xb940016b),
            (0x101f580, 0xb828794b),
            (0x101f658, 0x88087ef8),
            (0x101f664, 0xd5033f9f),
            (0x101f7b8, 0xd5033bbf),
            (0x101f7bc, 0xf90002d4),
            (0x102d528, 0x52804044),
            (0x102d624, 0x52804044),
        ] {
            assert_eq!(word(&b, va), w);
        }
    }
}
