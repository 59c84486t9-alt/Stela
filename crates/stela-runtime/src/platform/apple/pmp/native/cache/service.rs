//! Native MC command/event service on the quota/PTD and AMCC owners.
//!
//! Original26A434 T8112 PMP b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!100326c initializes the sole MC samples allocation;10037a4..1003cbc
//! consumes commands, conditionally copies/clears arrivals, accumulates,
//! schedules work, publishes, then ACKs a consumed nonzero low12 command ID.
//!10040b0..10042b8 starts after real defaults/registration/allocation and stops
//! after real pending work drains. No Apple firmware executes here.
use super::super::{
    counters::Frames,
    platform::{self, amcc, ingestion, owner},
    scheduler,
};
use super::{
    metrics,
    publisher::{Bank, Publisher},
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;
use {
    crate::platform::apple::ptd::transport::Entry,
    crate::platform::apple::ptd::transport::notifications::LocalNotifications,
    stela_contracts::bus::Access, stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
    stela_soc_data::ptd::Range, stela_soc_data::ptd::UPDATE_OFFSET,
};

const GROUPS: usize = 24;
const GROUP_BYTES: usize = 64;
const NEW_DATA: u64 = 2;
const SCALE: u32 = 1u32.wrapping_mul(4).wrapping_mul(8).wrapping_shl(6);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Contract(&'static str),
    Platform(ingestion::Error),
    Metrics(metrics::Error),
    Publication(&'static str),
}

impl From<&'static str> for Error {
    fn from(reason: &'static str) -> Self {
        Self::Contract(reason)
    }
}

/// Non-reissuable native recipient association, not startup or ACK permission.
pub struct Claim {
    local: LocalNotifications,
    request: Range,
    response: Range,
    alive: Rc<Cell<bool>>,
}
impl Claim {
    pub(in crate::platform::apple::pmp::native) fn new(
        local: LocalNotifications,
        request: Range,
        response: Range,
        alive: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            local,
            request,
            response,
            alive,
        }
    }
    pub(in crate::platform::apple::pmp::native) fn check(&self) -> Result<(), &'static str> {
        if self.alive.get() {
            Ok(())
        } else {
            Err("PMP cache service native owner was abandoned")
        }
    }
}

/// Registry-resolved directional counts. They describe ranges, never
/// command consumption, readiness, cache capacity or event completion.
#[derive(Clone, Copy)]
pub struct Configuration {
    pub request_words: u32,
    pub command_words: u32,
}

/// Borrows of kept owners, rechecked at every service advance.
/// Keeping the same numeric profile on a replacement object is insufficient.
pub struct Sources<'a, M: owner::Backend, I: ingestion::Backend> {
    pub manager: &'a owner::Owner<M>,
    pub amcc: &'a mut amcc::Owner<I>,
    pub frames: &'a Frames,
}

/// Sole source O3e0 allocation. Initial zero bytes are software initialization,
/// not observed hardware counters or an invented copied-frame receipt.
pub struct Samples {
    groups: Vec<[u8; GROUP_BYTES]>,
}
impl Samples {
    pub fn group(&self, group: usize) -> Option<&[u8; GROUP_BYTES]> {
        self.groups.get(group)
    }
}
struct View<'a> {
    samples: &'a Samples,
    interval: u64,
}
impl metrics::SamplesView for View<'_> {
    fn geometry(&self) -> metrics::Geometry {
        metrics::Geometry {
            groups: GROUPS as u32,
            platform_scale: 8,
            interval: self.interval,
        }
    }
    fn group(&self, group: u32) -> Result<&[u8; GROUP_BYTES], metrics::Error> {
        self.samples
            .group(group as usize)
            .ok_or(metrics::Error::Contract(
                "MC samples group exceeds its actual allocation",
            ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Busy { deadline: Option<u64> },
    Initialized,
    Started,
    EventComplete { command_id: u16 },
    Stopped,
    MetricsComplete,
}
#[derive(Clone, Copy)]
enum Stage {
    Initialize,
    StartDefaults,
    StartPublisher,
    RegisterBegin,
    Register,
    Allocate,
    StartCommit,
    TraceEnterBegin,
    TraceEnter,
    Gate,
    Header,
    RequestPending,
    RequestRead,
    Lanes,
    TraceLane,
    StoreLane,
    Budget,
    BudgetApply,
    BudgetPublisher,
    Housekeeping,
    Accumulate(usize),
    Submit,
    Submitted,
    PublishBegin,
    Publish,
    Ack,
    TraceExitBegin,
    TraceExit,
    StopBegin,
    Stop,
    StopCommit,
}
struct Batch {
    stage: Stage,
    command_id: u16,
    remaining: u32,
    word_index: u32,
    word: Option<Entry>,
    lane: u8,
    allocate: bool,
}

pub struct Owner<B: metrics::Backend> {
    claim: Claim,
    publisher: Publisher,
    metrics: metrics::Owner<B>,
    samples: Samples,
    configuration: Configuration,
    manager_identity: Rc<()>,
    amcc_identity: Rc<()>,
    run_state: u32,
    batch: Option<Batch>,
}
impl<B: metrics::Backend> Owner<B> {
    pub fn initialized_software<M: owner::Backend, I: ingestion::Backend>(
        claim: Claim,
        publisher: Publisher,
        metrics: metrics::Owner<B>,
        sources: Sources<'_, M, I>,
        configuration: Configuration,
    ) -> Result<Self, Error> {
        claim.check()?;
        sources.frames.check_bank(&claim.local)?;
        let d = sources
            .manager
            .profile()
            .descriptors()
            .get(1)
            .ok_or(Error::Contract(
                "MC service requires its actual AMCC descriptor",
            ))?;
        if d.source_id() != 2
            || d.counter_slice()
                != Some(platform::Slice {
                    start: 16,
                    count: 112,
                })
            || sources.amcc.group_count() != GROUPS
        {
            return Err(Error::Contract(
                "MC service source geometry is not qualified",
            ));
        }
        if configuration.request_words == 0
            || configuration.request_words > 8
            || !(2..=128).contains(&configuration.command_words)
            || configuration
                .request_words
                .checked_add(configuration.command_words)
                != Some(claim.request.count)
        {
            return Err(Error::Contract(
                "MC command counts differ from actual directional ownership",
            ));
        }
        let response = publisher.response_range();
        if !publisher.notifications().owns(claim.local.bank())
            || response.id != claim.response.id
            || response.start != claim.response.start
            || response.count != claim.response.count
            || publisher.response_words() < configuration.request_words
        {
            return Err(Error::Contract(
                "MC service publisher differs from its actual PTD association",
            ));
        }
        publisher.idle().map_err(Error::Publication)?;
        if publisher.policy().active_groups() & !((1u32 << GROUPS) - 1) != 0 {
            return Err(Error::Contract(
                "MC active group exceeds actual AMCC sample storage",
            ));
        }
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(GROUPS)
            .map_err(|_| Error::Contract("MC source sample allocation failed"))?;
        groups.resize(GROUPS, [0; GROUP_BYTES]);
        Ok(Self {
            claim,
            publisher,
            metrics,
            samples: Samples { groups },
            configuration,
            manager_identity: sources.manager.identity(),
            amcc_identity: sources.amcc.identity(),
            run_state: 0,
            batch: None,
        })
    }
    pub fn run_state(&self) -> u32 {
        self.run_state
    }
    pub fn samples(&self) -> &Samples {
        &self.samples
    }
    pub fn publisher(&self) -> &Publisher {
        &self.publisher
    }
    pub fn metrics(&self) -> &metrics::Owner<B> {
        &self.metrics
    }
    /// Source10045a8 updates O2a0 data; it grants no work/readiness permission.
    pub fn apply_registry_control(
        &mut self,
        control: metrics::RegistryControl,
    ) -> Result<(), Error> {
        self.claim.check()?;
        if self.batch.is_some() || self.metrics.callback_executing() {
            return Err(Error::Contract(
                "MC registry control overlaps retained service or callback work",
            ));
        }
        self.metrics.apply_registry_control(control);
        Ok(())
    }
    fn begin(&mut self, stage: Stage) -> Result<(), Error> {
        self.claim.check()?;
        if self.batch.is_some() {
            return Err(Error::Contract("MC service has retained work"));
        }
        self.batch = Some(Batch {
            stage,
            command_id: 0,
            remaining: 0,
            word_index: 0,
            word: None,
            lane: 0,
            allocate: false,
        });
        Ok(())
    }
    pub fn begin_initialize(&mut self) -> Result<(), Error> {
        self.claim.check()?;
        if self.batch.is_some() {
            return Err(Error::Contract("MC service has retained work"));
        }
        self.metrics.begin_initialize().map_err(Error::Metrics)?;
        self.begin(Stage::Initialize)
    }
    pub fn begin_start(&mut self) -> Result<(), Error> {
        if !self.metrics.initialized() {
            return Err(Error::Contract(
                "MC start requires actual queue initialization",
            ));
        }
        if self.run_state == 0 && self.metrics.callback_executing() {
            return Err(Error::Contract(
                "MC restart concurrency with an executing callback is unqualified",
            ));
        }
        self.begin(if self.run_state == 0 {
            Stage::StartDefaults
        } else {
            Stage::StartCommit
        })
    }
    pub fn begin_event(&mut self) -> Result<(), Error> {
        if !self.metrics.initialized() {
            return Err(Error::Contract(
                "MC event requires actual initialized work resources",
            ));
        }
        if self.metrics.callback_executing() {
            return Err(Error::Contract(
                "MC event concurrency with an executing callback is unqualified",
            ));
        }
        self.begin(Stage::TraceEnterBegin)
    }
    pub fn begin_stop(&mut self) -> Result<(), Error> {
        self.begin(if self.run_state == 1 {
            Stage::StopBegin
        } else {
            Stage::StopCommit
        })
    }
    fn check<M: owner::Backend, I: ingestion::Backend>(
        &self,
        sources: &Sources<'_, M, I>,
    ) -> Result<(), Error> {
        self.claim.check()?;
        sources.frames.check_bank(&self.claim.local)?;
        if !Rc::ptr_eq(&self.manager_identity, &sources.manager.identity())
            || !Rc::ptr_eq(&self.amcc_identity, &sources.amcc.identity())
        {
            return Err(Error::Contract(
                "MC service borrowed a replacement platform owner",
            ));
        }
        Ok(())
    }
    fn metric_advance(
        &mut self,
        interval: u64,
        access: &mut Access<'_>,
    ) -> Result<metrics::Progress, Error> {
        self.metrics
            .advance(
                &View {
                    samples: &self.samples,
                    interval,
                },
                access,
            )
            .map_err(Error::Metrics)
    }
    fn stage(&mut self, stage: Stage) {
        self.batch.as_mut().unwrap().stage = stage;
    }
    pub fn dispatch_metrics<M: owner::Backend, I: ingestion::Backend>(
        &mut self,
        invocation: &scheduler::Invocation,
        sources: Sources<'_, M, I>,
        access: &mut Access<'_>,
    ) -> Result<Progress, Error> {
        self.check(&sources)?;
        if self
            .batch
            .as_ref()
            .is_some_and(|batch| !matches!(batch.stage, Stage::Stop))
        {
            return Err(Error::Contract(
                "MC callback overlaps retained foreground service work",
            ));
        }
        match self
            .metrics
            .dispatch(
                invocation,
                &View {
                    samples: &self.samples,
                    interval: sources.amcc.generic().periods().1,
                },
                access,
            )
            .map_err(Error::Metrics)?
        {
            metrics::Progress::Busy { deadline } => Ok(Progress::Busy { deadline }),
            metrics::Progress::CallbackComplete => Ok(Progress::MetricsComplete),
            _ => Err(Error::Contract(
                "MC metrics dispatcher returned a foreign stage",
            )),
        }
    }
    pub fn advance<M: owner::Backend, I: ingestion::Backend>(
        &mut self,
        sources: Sources<'_, M, I>,
        bank: &mut impl Bank,
        access: &mut Access<'_>,
    ) -> Result<Progress, Error> {
        self.check(&sources)?;
        self.publisher
            .check_bank_identity(bank)
            .map_err(Error::Publication)?;
        loop {
            let stage = self
                .batch
                .as_ref()
                .ok_or(Error::Contract("MC service has no retained work"))?
                .stage;
            let interval = sources.amcc.generic().periods().1;
            match stage {
                Stage::Initialize
                | Stage::Register
                | Stage::Submitted
                | Stage::Stop
                | Stage::TraceEnter
                | Stage::TraceLane
                | Stage::TraceExit => {
                    let result = self.metric_advance(interval, access)?;
                    if let metrics::Progress::Busy { deadline } = result {
                        return Ok(Progress::Busy { deadline });
                    }
                    match (stage, result) {
                        (Stage::Initialize, metrics::Progress::Initialized) => {
                            self.batch = None;
                            return Ok(Progress::Initialized);
                        }
                        (Stage::Register, metrics::Progress::Registered) => {
                            self.stage(Stage::Allocate)
                        }
                        (Stage::Submitted, metrics::Progress::Scheduled) => {
                            self.stage(Stage::PublishBegin)
                        }
                        (Stage::Stop, metrics::Progress::Drained) => self.stage(Stage::StopCommit),
                        // Draining cooperatively executes real queued work;
                        // its return precedes the stop-wait completion.
                        (Stage::Stop, metrics::Progress::CallbackComplete) => {}
                        (Stage::TraceEnter, metrics::Progress::TraceComplete) => {
                            self.stage(Stage::Gate)
                        }
                        (Stage::TraceLane, metrics::Progress::TraceComplete) => {
                            self.stage(Stage::StoreLane)
                        }
                        (Stage::TraceExit, metrics::Progress::TraceComplete) => {
                            let command_id = self.batch.take().unwrap().command_id;
                            return Ok(Progress::EventComplete { command_id });
                        }
                        _ => {
                            return Err(Error::Contract(
                                "MC metrics operation returned a foreign stage",
                            ));
                        }
                    }
                }
                Stage::StartDefaults => {
                    self.publisher
                        .begin_service_pass()
                        .map_err(Error::Publication)?;
                    self.publisher
                        .start_defaults()
                        .map_err(Error::Publication)?;
                    self.stage(Stage::StartPublisher);
                }
                Stage::StartPublisher => {
                    self.publisher
                        .advance(bank, access)
                        .map_err(Error::Publication)?;
                    self.stage(Stage::RegisterBegin);
                }
                Stage::RegisterBegin => {
                    self.metrics
                        .begin_register(self.publisher.policy().active_groups())
                        .map_err(Error::Metrics)?;
                    self.stage(Stage::Register);
                }
                Stage::Allocate => {
                    self.publisher.allocate().map_err(Error::Publication)?;
                    self.stage(Stage::StartCommit);
                }
                Stage::StartCommit => {
                    self.run_state = 1;
                    self.batch = None;
                    return Ok(Progress::Started);
                }
                Stage::TraceEnterBegin => {
                    self.publisher
                        .begin_service_pass()
                        .map_err(Error::Publication)?;
                    self.metrics
                        .begin_event_trace(metrics::EventTrace::Enter)
                        .map_err(Error::Metrics)?;
                    self.stage(Stage::TraceEnter);
                }
                Stage::TraceExitBegin => {
                    self.metrics
                        .begin_event_trace(metrics::EventTrace::Exit)
                        .map_err(Error::Metrics)?;
                    self.stage(Stage::TraceExit);
                }
                Stage::Gate => {
                    if sources.manager.committed_prefix().is_some() {
                        return Err(Error::Contract(
                            "MC event overlaps its manager's retained operation",
                        ));
                    }
                    let d = &sources.manager.profile().descriptors()[1];
                    if self.run_state != 1 || sources.manager.evaluated(d.ordinal()) != 1 {
                        self.stage(Stage::PublishBegin);
                    } else {
                        let start = self.claim.request.start + self.configuration.request_words;
                        let pending = self
                            .claim
                            .local
                            .bank()
                            .pending_range(start, self.configuration.command_words)?;
                        self.stage(if pending.low & 1 == 0 {
                            Stage::Housekeeping
                        } else {
                            Stage::Header
                        });
                    }
                }
                Stage::Header => {
                    let entry = self.claim.local.bank().consume_entry(
                        self.claim.request.start + self.configuration.request_words,
                        access,
                    )?;
                    self.batch.as_mut().unwrap().command_id = entry.value as u16 & 0xfff;
                    self.stage(match (entry.value >> 12) & 15 {
                        0 => Stage::RequestPending,
                        1 => Stage::Budget,
                        _ => Stage::Housekeeping,
                    });
                }
                Stage::RequestPending => {
                    let pending = self.claim.local.bank().pending_range(
                        self.claim.request.start,
                        self.configuration.request_words,
                    )?;
                    self.batch.as_mut().unwrap().remaining = pending.low as u32;
                    self.stage(Stage::RequestRead);
                }
                Stage::RequestRead => {
                    let batch = self.batch.as_ref().unwrap();
                    if batch.remaining == 0 {
                        if batch.allocate {
                            self.publisher.allocate().map_err(Error::Publication)?;
                        }
                        self.stage(Stage::Housekeeping);
                    } else {
                        let index = batch.remaining.trailing_zeros();
                        let entry = self
                            .claim
                            .local
                            .bank()
                            .consume_entry(self.claim.request.start + index, access)?;
                        let batch = self.batch.as_mut().unwrap();
                        batch.remaining &= batch.remaining - 1;
                        batch.word_index = index;
                        batch.word = Some(entry);
                        batch.lane = 0;
                        batch.stage = Stage::Lanes;
                    }
                }
                Stage::Lanes => {
                    let batch = self.batch.as_mut().unwrap();
                    if batch.lane == 4 {
                        batch.word = None;
                        batch.stage = Stage::RequestRead;
                        continue;
                    }
                    let group = batch.word_index * 4 + u32::from(batch.lane);
                    let entry = batch.word.as_ref().unwrap();
                    if entry.metadata & NEW_DATA == 0
                        || self.publisher.policy().active_groups() & (1 << group) == 0
                    {
                        batch.lane += 1;
                    } else {
                        let lane = (entry.value >> (16 * batch.lane)) as u16;
                        self.metrics
                            .begin_event_trace(metrics::EventTrace::Request {
                                group,
                                requested_bytes: (u32::from(lane) & 0xfff).wrapping_shl(17),
                            })
                            .map_err(Error::Metrics)?;
                        self.stage(Stage::TraceLane);
                    }
                }
                Stage::StoreLane => {
                    let batch = self.batch.as_mut().unwrap();
                    let group = batch.word_index * 4 + u32::from(batch.lane);
                    let lane = (batch.word.as_ref().unwrap().value >> (16 * batch.lane)) as u16;
                    batch.allocate |= self
                        .publisher
                        .set_request(group as u8, lane)
                        .map_err(Error::Publication)?;
                    batch.lane += 1;
                    batch.stage = Stage::Lanes;
                }
                Stage::Budget => {
                    // Source consumes header+1 regardless of its NEW metadata.
                    let entry = self.claim.local.bank().consume_entry(
                        self.claim.request.start + self.configuration.request_words + 1,
                        access,
                    )?;
                    self.batch.as_mut().unwrap().word = Some(entry);
                    self.stage(Stage::BudgetApply);
                }
                Stage::BudgetApply => {
                    self.publisher
                        .set_budget_payload(
                            self.batch.as_ref().unwrap().word.as_ref().unwrap().value,
                        )
                        .map_err(Error::Publication)?;
                    self.batch.as_mut().unwrap().word = None;
                    self.stage(Stage::BudgetPublisher);
                }
                Stage::BudgetPublisher => {
                    self.publisher
                        .advance(bank, access)
                        .map_err(Error::Publication)?;
                    self.stage(Stage::Housekeeping);
                }
                Stage::Housekeeping => {
                    let expected = sources.manager.profile().descriptors()[1]
                        .selection()
                        .bits()
                        >> 16;
                    let copied = sources
                        .amcc
                        .copy_completed_groups(sources.frames, expected, &mut self.samples.groups)
                        .map_err(Error::Platform)?;
                    self.stage(if copied.is_some() {
                        Stage::Accumulate(0)
                    } else {
                        Stage::PublishBegin
                    });
                }
                Stage::Accumulate(group) if group < GROUPS => {
                    if self.publisher.policy().active_groups() & (1 << group) != 0 {
                        let bytes = &self.samples.groups[group];
                        let a =
                            u32::from_le_bytes(bytes[..4].try_into().unwrap()).wrapping_mul(SCALE);
                        let b =
                            u32::from_le_bytes(bytes[4..8].try_into().unwrap()).wrapping_mul(SCALE);
                        self.metrics
                            .accumulate(group as u32, [a, b])
                            .map_err(Error::Metrics)?;
                    }
                    self.stage(Stage::Accumulate(group + 1));
                }
                Stage::Accumulate(_) => self.stage(Stage::Submit),
                Stage::Submit => {
                    if self
                        .metrics
                        .submit_after_housekeeping()
                        .map_err(Error::Metrics)?
                    {
                        self.stage(Stage::Submitted);
                    } else {
                        self.stage(Stage::PublishBegin);
                    }
                }
                Stage::PublishBegin => {
                    let dirty = self.publisher.policy().dirty_masks();
                    if self.publisher.awaiting_publication() {
                        self.publisher
                            .publish_allocated()
                            .map_err(Error::Publication)?;
                        self.stage(Stage::Publish);
                    } else if dirty.hardware != 0 || dirty.responses != 0 {
                        self.publisher
                            .publish_pending()
                            .map_err(Error::Publication)?;
                        self.stage(Stage::Publish);
                    } else {
                        self.stage(Stage::Ack);
                    }
                }
                Stage::Publish => {
                    self.publisher
                        .advance(bank, access)
                        .map_err(Error::Publication)?;
                    self.stage(Stage::Ack);
                }
                Stage::Ack => {
                    let id = self.batch.as_ref().unwrap().command_id;
                    if id != 0 {
                        let entry = self.claim.response.start + self.publisher.response_words();
                        self.claim
                            .local
                            .bank()
                            .clone()
                            .write(
                                UPDATE_OFFSET + u64::from(entry) * 8,
                                Width::Double,
                                u64::from(id),
                                access,
                            )
                            .map_err(|_| {
                                Error::Contract("MC actual PTD command ACK publication refused")
                            })?;
                    }
                    self.stage(Stage::TraceExitBegin);
                }
                Stage::StopBegin => {
                    self.metrics.begin_stop().map_err(Error::Metrics)?;
                    self.stage(Stage::Stop);
                }
                Stage::StopCommit => {
                    self.run_state = 0;
                    self.batch = None;
                    return Ok(Progress::Stopped);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
