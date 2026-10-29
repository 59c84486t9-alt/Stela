//! Source DB program over the AP mapping. One source queue/lock
//! serializes jobs; receive ACK remains independent. No firmware is executed.
use super::super::platform::owner::Completion;
use super::{
    getter::LiveGetter,
    receive::{Inbox, Receiver},
    record::{self, Layout, Metadata},
    resources::{MapResult, Mapping, Request, Resources, WaitKey},
    wire,
};
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::RefCell;
use stela_contracts::bus::Access;

pub const NO_DATABASE: u32 = 0x8000_0007;
#[derive(Clone, Debug)]
pub struct Registration(Rc<()>);
impl Default for Registration {
    fn default() -> Self {
        Self::new()
    }
}
impl Registration {
    /// Keep one token for one source registration; do not recreate it
    /// on a Busy/refusal retry. It is not a channel ID or a PTD completion.
    pub fn new() -> Self {
        Self(Rc::new(()))
    }
    fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationResult {
    Published { epoch: u64, channel: u64 },
    SourceError(u32),
    Refused(&'static str),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finished {
    Ready,
    Registered(RegistrationResult),
    Refreshed,
    LabelsChanged,
    Released,
    SourceError(u32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    Idle,
    Busy { deadline: Option<u64> },
    Finished(Finished),
}
struct Record {
    offset: u64,
    metadata: Metadata,
    getter: LiveGetter,
}
#[derive(Clone)]
enum Op {
    Claim,
    RequestBuffer,
    Map,
    Zero(u64),
    Write {
        offset: u64,
        bytes: Vec<u8>,
        cursor: usize,
    },
    Reserve {
        record: usize,
        end: u64,
        cursor: usize,
    },
    Get {
        record: usize,
        index: u32,
    },
    Count,
    Sync {
        offset: u64,
        bytes: u64,
    },
    Dsb,
    Clock,
    Header,
    Arm(WaitKey),
    Send(u64),
    Wait(WaitKey),
    ReadFlags {
        record: usize,
    },
    Unmap,
    Release,
    Clear,
}
impl Op {
    fn write(offset: u64, bytes: impl Into<Vec<u8>>) -> Self {
        Self::Write {
            offset,
            bytes: bytes.into(),
            cursor: 0,
        }
    }
}
struct Job {
    request: Request,
    ops: VecDeque<Op>,
    finished: Finished,
    registration: Option<Registration>,
    clock: Option<u64>,
    poisoned: Option<&'static str>,
}
/// Source global singleton, including channel ordinal and once-registration
/// lifetime. A memory-loss exit discards records, not registration history.
/// Callers must not replace the owner to resurrect once-only MC metadata.
pub struct Owner<R: Resources> {
    resources: R,
    identity: Rc<()>,
    receiver: Receiver,
    mapping: Option<R::Mapping>,
    records: Vec<Record>,
    returned: Vec<(Registration, RegistrationResult)>,
    job: Option<Job>,
    serial: u64,
    epoch: u64,
    ordinal: u64,
    first_counter: Option<super::super::cache::metrics::Counter>,
    used: u64,
    count: u32,
    claimed: bool,
    active: bool,
    sleeping: bool,
    state: u8,
}
impl<R: Resources> Owner<R> {
    pub fn new(resources: R) -> Self {
        Self {
            resources,
            identity: Rc::new(()),
            receiver: Receiver(Rc::new(RefCell::new(Inbox::default()))),
            mapping: None,
            records: Vec::new(),
            returned: Vec::new(),
            job: None,
            serial: 0,
            epoch: 0,
            ordinal: 0,
            first_counter: None,
            used: 0,
            count: 0,
            claimed: false,
            active: false,
            sleeping: false,
            state: 0,
        }
    }
    pub fn receiver(&self) -> Receiver {
        self.receiver.clone()
    }
    pub fn used_bytes(&self) -> u64 {
        self.used
    }
    pub fn record_count(&self) -> u32 {
        self.count
    }
    pub fn channel_ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn registration_result(&self, token: &Registration) -> Option<RegistrationResult> {
        self.returned
            .iter()
            .find(|(t, _)| t.same(token))
            .map(|(_, r)| *r)
    }
    fn start(
        &mut self,
        ops: VecDeque<Op>,
        finished: Finished,
        registration: Option<Registration>,
    ) -> Result<(), &'static str> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or("IOReporting job identity exhausted")?;
        self.job = Some(Job {
            request: Request {
                owner: self.identity.clone(),
                serial: self.serial,
                operation: 0,
            },
            ops,
            finished,
            registration,
            clock: None,
            poisoned: None,
        });
        Ok(())
    }
    fn identity_available(&self) -> Result<(), &'static str> {
        if self.serial == u64::MAX {
            return Err("IOReporting job identity exhausted");
        }
        Ok(())
    }
    fn available(&self) -> Result<(), &'static str> {
        self.identity_available()?;
        if self.job.is_some() {
            return Err("IOReporting source DB queue has retained work");
        }
        if self.sleeping {
            return Err("IOReporting lifecycle blocks new DB work while asleep");
        }
        Ok(())
    }
    /// Only the constructor-selected AP allocation mode is checked. Enter
    /// never advertises an AP-owned address back to its allocator.
    pub fn enter(&mut self, local_heap: bool) -> Result<(), &'static str> {
        self.available()?;
        if self.epoch == u64::MAX {
            return Err("IOReporting lifecycle epoch exhausted");
        }
        if local_heap {
            return Err("alternate IOReporting native heap/map owner is unqualified");
        }
        if self.active
            || self.mapping.is_some()
            || self.state > 32
            || ((0x1_0000_001fu64 >> self.state) & 1) == 0
        {
            return Err("IOReporting lifecycle enter transition is not source-admitted");
        }
        let mut ops = VecDeque::new();
        if !self.claimed {
            ops.push_back(Op::Claim);
        }
        ops.extend([
            Op::RequestBuffer,
            Op::Map,
            Op::Zero(0),
            Op::Clock,
            Op::Header,
            Op::Sync {
                offset: 0,
                bytes: 16,
            },
            Op::Send(wire::READY),
        ]);
        self.state = 0x21;
        self.start(ops, Finished::Ready, None)?;
        Ok(())
    }
    pub fn exit(&mut self, state: u8) -> Result<(), &'static str> {
        self.identity_available()?;
        if self.job.is_some() {
            return Err("IOReporting exit must wait outstanding DB work");
        }
        if self.state != 0x21 || state > 32 || ((0x1_0000_001fu64 >> state) & 1) == 0 {
            return Err("IOReporting lifecycle exit transition is not source-admitted");
        }
        self.state = state;
        self.start(
            VecDeque::from([Op::Unmap, Op::Release, Op::Clear]),
            Finished::Released,
            None,
        )?;
        Ok(())
    }
    /// Lifecycle caller waits outstanding DB work first. Pending AP requests
    /// survive preserving sleep and run after awake; no records are resurrected.
    pub fn sleep(&mut self) -> Result<(), &'static str> {
        self.available()?;
        self.sleeping = true;
        Ok(())
    }
    pub fn awake(&mut self) {
        self.sleeping = false;
    }
    /// Once-only source registration. A returned source error is held;
    /// submitting the same token again never publishes or reallocates a channel.
    pub fn register(
        &mut self,
        token: Registration,
        metadata: Metadata,
        getter: LiveGetter,
    ) -> Result<Option<RegistrationResult>, &'static str> {
        if let Some(result) = self.registration_result(&token) {
            return Ok(Some(result));
        }
        self.available()?;
        if self.mapping.is_none() {
            self.returned
                .push((token, RegistrationResult::SourceError(NO_DATABASE)));
            return Ok(Some(RegistrationResult::SourceError(NO_DATABASE)));
        }
        if !self.active {
            return Err("IOReporting mapping is not initialized/ready");
        }
        if metadata.layout != getter.layout() || metadata.layout.count() == 0 {
            return Err("IOReporting live getter shape differs from descriptor");
        }
        if self
            .records
            .iter()
            .any(|r| r.metadata.channel == metadata.channel)
        {
            return Err("duplicate IOReporting channel");
        }
        let header = metadata.header()?;
        let end = self
            .used
            .checked_add(metadata.layout.bytes())
            .ok_or("IOReporting record extent overflow")?;
        if end > self.mapping.as_ref().unwrap().geometry().bytes || self.count == u32::MAX {
            return Err("IOReporting source capacity assertion (no fabricated registration)");
        }
        let offset = self.used;
        let index = self.records.len();
        let channel = metadata.channel;
        let mut ops = VecDeque::new();
        // Original D18 is advanced after the first kind write, before the
        // remainder/getter. D78 advances only after getter refresh completes.
        ops.push_back(Op::Reserve {
            record: index,
            end,
            cursor: 0,
        });
        ops.push_back(Op::write(offset, header[..8].to_vec()));
        ops.push_back(Op::write(offset + 12, header[12..0x4c].to_vec()));
        // Preserve AP-consumed flags+4c, labels/gaps and every untouched byte.
        ops.push_back(Op::write(offset + 0x4e, header[0x4e..].to_vec()));
        let aux = offset + 0x50 + metadata.layout.stride() * u64::from(metadata.layout.count());
        for (i, row) in metadata.descriptions.iter().enumerate() {
            ops.push_back(Op::write(aux + i as u64 * 16, row.to_vec()));
        }
        for i in 0..metadata.layout.count() {
            ops.push_back(Op::Get {
                record: index,
                index: i,
            });
        }
        ops.push_back(Op::Count);
        self.records.push(Record {
            offset,
            metadata,
            getter,
        });
        self.append_publication(&mut ops, true, end);
        self.start(
            ops,
            Finished::Registered(RegistrationResult::Published {
                epoch: self.epoch,
                channel,
            }),
            Some(token),
        )?;
        Ok(None)
    }
    /// Source1007d04 global wrapping allocation precedes the DB attempt, even
    /// when D8 is absent. Caller supplies the same zeroed Counter/token.
    pub fn register_mc(
        &mut self,
        token: Registration,
        name: &[u8],
        counter: super::super::cache::metrics::Counter,
    ) -> Result<Option<RegistrationResult>, &'static str> {
        if let Some(result) = self.registration_result(&token) {
            return Ok(Some(result));
        }
        self.available()?;
        // No replay after a failed DB attempt: the token is installed by
        // register, or kept in a pending job before the caller can retry.
        let ordinal = self.ordinal.wrapping_add(1);
        // Original MC producer1004194 forms VA1035b06 (file36b06):
        // b"DSID Stats\0", including the space, SHA256 b6c69d456fba4884fe70cfa8fe0ef376054f3d7889f0e846ebff4004417bcca3.
        let metadata = Metadata {
            channel: record::counter_channel(ordinal),
            category: 2,
            name: record::Name::new(name),
            group: record::Name::new(b"DSID Stats"),
            unit: 0x0900_8200_0000_0000,
            layout: Layout::Scalar,
            descriptions: Vec::new(),
        };
        self.ordinal = ordinal;
        if self.first_counter.is_none() {
            self.first_counter = Some(counter.clone());
        }
        match self.register(
            token.clone(),
            metadata,
            LiveGetter::Scalar(Box::new(counter)),
        ) {
            Ok(result) => Ok(result),
            Err(e) => {
                // Structural/capacity refusal must not cause another n++ when
                // the source caller retries the same registration.
                self.returned.push((token, RegistrationResult::Refused(e)));
                Err(e)
            }
        }
    }
    fn append_publication(&self, ops: &mut VecDeque<Op>, registration: bool, end: u64) {
        ops.extend([
            Op::Sync {
                offset: 16,
                bytes: end.saturating_sub(16),
            },
            Op::Dsb,
            Op::Clock,
            Op::Header,
            Op::Sync {
                offset: 0,
                bytes: 16,
            },
        ]);
        if registration {
            let key = WaitKey(Rc::new(()));
            ops.extend([
                Op::Arm(key.clone()),
                Op::Send(wire::REGISTERED),
                Op::Wait(key),
            ]);
        } else {
            ops.push_back(Op::Send(wire::UPDATE));
        }
    }
    /// Label words are source metadata, not getter results. Refresh writes only
    /// value lanes and will preserve labels and gaps present in AP RAM.
    pub fn labels(&mut self, channel: u64, labels: &[(u32, u64)]) -> Result<(), &'static str> {
        self.available()?;
        if !self.active {
            return Err("IOReporting labels have no active database");
        }
        let index = self
            .records
            .iter()
            .position(|r| r.metadata.channel == channel)
            .ok_or("IOReporting label channel absent")?;
        let record = &self.records[index];
        let lane = match record.metadata.layout {
            Layout::Scalar => return Err("scalar IOReporting label mutation is unqualified"),
            Layout::Pairs(_) => 16,
            Layout::Scalars(_) => 8,
            Layout::States { .. } => 32,
        };
        let mut seen = alloc::collections::BTreeSet::new();
        let mut ops = VecDeque::new();
        for &(i, value) in labels {
            if i >= record.metadata.layout.count() || !seen.insert(i) {
                return Err("IOReporting label index duplicate/outside record");
            }
            ops.push_back(Op::write(
                record.offset + 0x50 + u64::from(i) * record.metadata.layout.stride() + lane,
                value.to_le_bytes().to_vec(),
            ));
        }
        if labels.is_empty() {
            return Err("IOReporting label mutation is empty");
        }
        ops.push_back(Op::Sync {
            offset: record.offset,
            bytes: record.metadata.layout.bytes(),
        });
        ops.push_back(Op::ReadFlags { record: index });
        self.start(ops, Finished::LabelsChanged, None)?;
        Ok(())
    }
    fn refresh(&mut self) -> Result<(), &'static str> {
        self.identity_available()?;
        let mut ops = VecDeque::new();
        for (record, value) in self.records.iter().enumerate() {
            for index in 0..value.metadata.layout.count() {
                ops.push_back(Op::Get { record, index });
            }
        }
        self.append_publication(&mut ops, false, self.used);
        self.start(ops, Finished::Refreshed, None)?;
        self.receiver.0.borrow_mut().refresh = false;
        Ok(())
    }
    /// One bounded source effect per call (plus its local prefix). Retired
    /// values advance before post-effect diagnostics; Busy/refusal never replay
    /// a prior write/getter/map/send. Invoke again after reporting the error.
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, &'static str> {
        if self.job.is_none() {
            if self.active && !self.sleeping && self.receiver.0.borrow().refresh {
                self.refresh()?;
            } else {
                return Ok(Progress::Idle);
            }
        }
        let mut job = self.job.take().unwrap();
        if let Some(error) = job.poisoned {
            self.job = Some(job);
            return Err(error);
        }
        let Some(op) = job.ops.front().cloned() else {
            if let (Some(token), Finished::Registered(result)) = (job.registration, &job.finished) {
                self.returned.push((token, *result));
            }
            return Ok(Progress::Finished(job.finished));
        };
        let Some(next_operation) = job.request.operation.checked_add(1) else {
            let error = "IOReporting backend operation identity exhausted";
            job.poisoned = Some(error);
            self.job = Some(job);
            return Err(error);
        };
        match self.execute(&job.request, &op, job.clock, access) {
            Completion::Busy { deadline } => {
                self.job = Some(job);
                Ok(Progress::Busy { deadline })
            }
            Completion::Refused(error) => {
                self.job = Some(job);
                Err(error)
            }
            Completion::Retired { value, refusal } => {
                job.ops.pop_front();
                let result = self.retire(&op, value, &mut job);
                job.request.operation = next_operation;
                if let Err(error) = result {
                    job.poisoned = Some(error);
                }
                self.job = Some(job);
                result?;
                if let Some(error) = refusal {
                    return Err(error);
                }
                Ok(Progress::Busy { deadline: None })
            }
        }
    }
    fn execute(
        &mut self,
        request: &Request,
        op: &Op,
        clock: Option<u64>,
        access: &mut Access<'_>,
    ) -> Completion<Value<R::Mapping>> {
        fn unit<M>(c: Completion<()>) -> Completion<Value<M>> {
            convert(c, |_| Value::Unit)
        }
        let mapping = || "IOReporting source operation has no actual mapping";
        match op {
            Op::Claim => unit(self.resources.claim(request, access)),
            Op::RequestBuffer => {
                self.receiver.0.borrow_mut().buffer_expected = true;
                convert(
                    self.resources
                        .send(request, wire::ENDPOINT, wire::BUFFER_REQUEST, access),
                    |_| Value::Requested,
                )
            }
            Op::Map => {
                let Some(buffer) = self.receiver.0.borrow().buffer else {
                    return Completion::Busy { deadline: None };
                };
                convert(
                    self.resources.map(request, buffer, 0x202, access),
                    Value::Map,
                )
            }
            Op::Zero(offset) => match &mut self.mapping {
                Some(m) => {
                    let remaining = m.geometry().bytes.saturating_sub(*offset).min(1024) as usize;
                    if remaining == 0 {
                        return Completion::Refused(
                            "IOReporting zero cursor exceeds actual allocation",
                        );
                    }
                    convert(
                        m.write(request, *offset, &[0; 1024][..remaining], access),
                        Value::Written,
                    )
                }
                None => Completion::Refused(mapping()),
            },
            Op::Write {
                offset,
                bytes,
                cursor,
            } => match &mut self.mapping {
                Some(m) => convert(
                    m.write(request, *offset + *cursor as u64, &bytes[*cursor..], access),
                    Value::Written,
                ),
                None => Completion::Refused(mapping()),
            },
            Op::Reserve { record, cursor, .. } => match &mut self.mapping {
                Some(m) => {
                    let row = &self.records[*record];
                    let kind = row.metadata.layout.kind().to_le_bytes();
                    convert(
                        m.write(
                            request,
                            row.offset + 8 + *cursor as u64,
                            &kind[*cursor..],
                            access,
                        ),
                        Value::Written,
                    )
                }
                None => Completion::Refused(mapping()),
            },
            Op::Count | Op::Clear => Completion::Retired {
                value: Value::Unit,
                refusal: None,
            },
            Op::Get { record, index } => convert(
                self.records[*record].getter.get(request, *index, access),
                Value::Bytes,
            ),
            Op::Sync { offset, bytes } => {
                let Some(m) = &mut self.mapping else {
                    return Completion::Refused(mapping());
                };
                let granule = match m.synchronization_granule() {
                    Ok(g) if g.is_power_of_two() => g,
                    _ => {
                        return Completion::Refused(
                            "IOReporting runtime synchronization granule is not qualified",
                        );
                    }
                };
                let start = offset & !(granule - 1);
                let Some(end) = offset
                    .checked_add(*bytes)
                    .and_then(|end| end.checked_add(granule - 1))
                    .map(|end| end & !(granule - 1))
                else {
                    return Completion::Refused(
                        "IOReporting aligned synchronization extent overflows",
                    );
                };
                if end > m.geometry().bytes || end < start {
                    return Completion::Refused(
                        "IOReporting aligned synchronization exceeds actual allocation",
                    );
                }
                unit(m.synchronize(request, start, end - start, access))
            }
            Op::Dsb => unit(self.resources.dsb_sy(request, access)),
            Op::Clock => convert(
                self.resources.converted_clock(request, access),
                Value::Clock,
            ),
            Op::Header => {
                let Some(clock) = clock else {
                    return Completion::Refused("IOReporting header lacks actual converted clock");
                };
                let mut writes = Vec::new();
                if !self.active {
                    writes.push(Op::write(0, record::MAGIC.to_le_bytes().to_vec()));
                }
                writes.push(Op::write(
                    4,
                    [
                        self.count.to_le_bytes().to_vec(),
                        clock.to_le_bytes().to_vec(),
                    ]
                    .concat(),
                ));
                Completion::Retired {
                    value: Value::Expand(writes),
                    refusal: None,
                }
            }
            Op::Arm(key) => unit(self.resources.arm_wait(request, key, access)),
            Op::Send(payload) => {
                unit(
                    self.resources
                        .send(request, wire::ENDPOINT, *payload, access),
                )
            }
            Op::Wait(key) => {
                if !self.receiver.0.borrow().ack {
                    return Completion::Busy { deadline: None };
                }
                unit(self.resources.wait(request, key, access))
            }
            Op::ReadFlags { record } => match &mut self.mapping {
                Some(m) => convert(
                    m.read(request, self.records[*record].offset + 0x4c, 2, access),
                    Value::Bytes,
                ),
                None => Completion::Refused(mapping()),
            },
            Op::Unmap => match &mut self.mapping {
                Some(m) => unit(self.resources.unmap(request, m, access)),
                None => Completion::Retired {
                    value: Value::Unit,
                    refusal: None,
                },
            },
            Op::Release => match &mut self.mapping {
                Some(m) => unit(self.resources.release(request, m, access)),
                None => Completion::Retired {
                    value: Value::Unit,
                    refusal: None,
                },
            },
        }
    }
    fn retire(
        &mut self,
        op: &Op,
        value: Value<R::Mapping>,
        job: &mut Job,
    ) -> Result<(), &'static str> {
        match (op, value) {
            (Op::Claim, Value::Unit) => {
                self.claimed = true;
                self.receiver.0.borrow_mut().alive = true;
            }
            (Op::RequestBuffer, Value::Requested) => {}
            (Op::Map, Value::Map(MapResult::Mapped(mapping))) => {
                let expected = self.receiver.0.borrow_mut().buffer.take().unwrap();
                let geometry = mapping.geometry();
                let granule = mapping.synchronization_granule();
                // Keep the object even if the provider broke its
                // contract. No Ready, replacement, implicit free or fake map.
                self.mapping = Some(mapping);
                if geometry != expected {
                    return Err("IOReporting map owner returned a different allocation");
                }
                if !granule.is_ok_and(|g| g.is_power_of_two() && geometry.bytes.is_multiple_of(g)) {
                    return Err(
                        "IOReporting mapping lacks complete runtime synchronization geometry",
                    );
                }
            }
            (Op::Map, Value::Map(MapResult::SourceError(status))) => {
                if status == 0 {
                    return Err("IOReporting map owner returned success status without a mapping");
                }
                job.ops.clear();
                job.finished = Finished::SourceError(status);
                self.receiver.0.borrow_mut().buffer = None;
            }
            (Op::Zero(offset), Value::Written(bytes)) => {
                let end = self.mapping.as_ref().unwrap().geometry().bytes;
                let remaining = end.saturating_sub(*offset).min(1024) as usize;
                if bytes == 0 || bytes > remaining {
                    return Err("IOReporting zero write returned invalid committed prefix");
                }
                let offset = *offset + bytes as u64;
                if offset < end {
                    job.ops.push_front(Op::Zero(offset));
                } else {
                    self.used = 16;
                    self.count = 0;
                    self.epoch = self
                        .epoch
                        .checked_add(1)
                        .ok_or("IOReporting lifecycle epoch exhausted")?;
                }
            }
            (
                Op::Write {
                    offset,
                    bytes,
                    cursor,
                },
                Value::Written(written),
            ) => {
                if written == 0 || written > bytes.len() - cursor {
                    return Err("IOReporting write returned invalid committed prefix");
                }
                let cursor = cursor + written;
                if cursor < bytes.len() {
                    job.ops.push_front(Op::Write {
                        offset: *offset,
                        bytes: bytes.clone(),
                        cursor,
                    });
                }
            }
            (
                Op::Reserve {
                    record,
                    end,
                    cursor,
                },
                Value::Written(written),
            ) => {
                if written == 0 || written > 4 - cursor {
                    return Err("IOReporting kind write returned invalid committed prefix");
                }
                let cursor = cursor + written;
                if cursor < 4 {
                    job.ops.push_front(Op::Reserve {
                        record: *record,
                        end: *end,
                        cursor,
                    });
                } else {
                    if self.records[*record].offset != self.used {
                        return Err("IOReporting record reservation diverged from D18");
                    }
                    self.used = *end;
                }
            }
            (Op::Get { record, index }, Value::Bytes(bytes)) => {
                let row = &self.records[*record];
                let expected = match row.metadata.layout {
                    Layout::Scalar | Layout::Scalars(_) => 8,
                    Layout::Pairs(_) => 16,
                    Layout::States { .. } => 32,
                };
                if bytes.len() != expected {
                    return Err("IOReporting typed getter returned wrong value width");
                }
                job.ops.push_front(Op::write(
                    row.offset + 0x50 + u64::from(*index) * row.metadata.layout.stride(),
                    bytes,
                ));
            }
            (Op::Count, Value::Unit) => {
                self.count = self
                    .count
                    .checked_add(1)
                    .ok_or("IOReporting D78 record count overflow")?;
            }
            (Op::Clock, Value::Clock(clock)) => {
                job.clock = Some(clock);
            }
            (Op::Header, Value::Expand(writes)) => {
                for write in writes.into_iter().rev() {
                    job.ops.push_front(write);
                }
            }
            (Op::Arm(key), Value::Unit) => {
                let mut inbox = self.receiver.0.borrow_mut();
                if inbox.waiter.is_some() {
                    return Err("IOReporting previous publication waiter is still armed");
                }
                inbox.ack = false;
                inbox.waiter = Some(key.clone());
            }
            (Op::Send(payload), Value::Unit) if *payload == wire::READY => {
                self.active = true;
            }
            (Op::Wait(_), Value::Unit) => {
                self.receiver.0.borrow_mut().ack = false;
            }
            (Op::ReadFlags { record }, Value::Bytes(bytes)) => {
                let bytes: [u8; 2] = bytes
                    .try_into()
                    .map_err(|_| "IOReporting actual flags read is incomplete")?;
                job.ops.push_front(Op::write(
                    self.records[*record].offset + 0x4c,
                    (u16::from_le_bytes(bytes) | 1).to_le_bytes().to_vec(),
                ));
            }
            (Op::Clear, Value::Unit) => {
                self.mapping = None;
                self.records.clear();
                self.used = 0;
                self.count = 0;
                self.active = false;
                let mut inbox = self.receiver.0.borrow_mut();
                inbox.buffer = None;
                inbox.buffer_expected = false;
                inbox.waiter = None;
                inbox.ack = false;
                inbox.refresh = false;
            }
            (Op::Sync { .. } | Op::Dsb | Op::Send(_) | Op::Unmap | Op::Release, Value::Unit) => {}
            _ => return Err("IOReporting resource returned a mismatched retired value"),
        }
        Ok(())
    }
    /// Explicit cleanup of a poisoned provider/geometry contract; the
    /// mapping still requires ordered unmap/release. Never silently restart it.
    pub fn release_failed_entry(&mut self, state: u8) -> Result<(), &'static str> {
        self.identity_available()?;
        if self.job.as_ref().is_none_or(|j| j.poisoned.is_none())
            || self.active
            || state > 32
            || ((0x1_0000_001fu64 >> state) & 1) == 0
        {
            return Err("IOReporting failed-entry cleanup has no matching retained failure");
        }
        self.job = None;
        self.state = state;
        self.start(
            VecDeque::from([Op::Unmap, Op::Release, Op::Clear]),
            Finished::Released,
            None,
        )?;
        Ok(())
    }
}
impl<R: Resources> Drop for Owner<R> {
    fn drop(&mut self) {
        self.receiver.0.borrow_mut().alive = false;
    }
}
enum Value<M> {
    Unit,
    Requested,
    Map(MapResult<M>),
    Written(usize),
    Bytes(Vec<u8>),
    Clock(u64),
    Expand(Vec<Op>),
}
fn convert<T, U>(value: Completion<T>, f: impl FnOnce(T) -> U) -> Completion<U> {
    match value {
        Completion::Busy { deadline } => Completion::Busy { deadline },
        Completion::Refused(error) => Completion::Refused(error),
        Completion::Retired { value, refusal } => Completion::Retired {
            value: f(value),
            refusal,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::{getter, resources::Wake};
    use super::*;
    use alloc::vec;
    use core::cell::Cell;
    use stela_contracts::interrupt::InterruptLatch;

    fn done<T>(value: T) -> Completion<T> {
        Completion::Retired {
            value,
            refusal: None,
        }
    }
    struct Ram {
        bytes: Rc<RefCell<Vec<u8>>>,
        events: Rc<RefCell<Vec<&'static str>>>,
        fail_kind: Rc<Cell<bool>>,
    }
    impl Mapping for Ram {
        fn geometry(&self) -> wire::Buffer {
            wire::Buffer {
                bus: 0x100000,
                bytes: wire::REQUEST_BYTES,
            }
        }
        fn synchronization_granule(&self) -> Result<u64, &'static str> {
            Ok(64)
        }
        fn write(
            &mut self,
            _: &Request,
            offset: u64,
            bytes: &[u8],
            _: &mut Access<'_>,
        ) -> Completion<usize> {
            self.bytes.borrow_mut()[offset as usize..offset as usize + bytes.len()]
                .copy_from_slice(bytes);
            self.events.borrow_mut().push("write");
            let refusal = if offset == 24 && self.fail_kind.replace(false) {
                Some("authored post-kind-store diagnostic")
            } else {
                None
            };
            Completion::Retired {
                value: bytes.len(),
                refusal,
            }
        }
        fn read(
            &mut self,
            _: &Request,
            offset: u64,
            bytes: usize,
            _: &mut Access<'_>,
        ) -> Completion<Vec<u8>> {
            done(self.bytes.borrow()[offset as usize..offset as usize + bytes].to_vec())
        }
        fn synchronize(
            &mut self,
            _: &Request,
            offset: u64,
            bytes: u64,
            _: &mut Access<'_>,
        ) -> Completion<()> {
            assert!(offset.is_multiple_of(64) && bytes.is_multiple_of(64));
            self.events.borrow_mut().push("sync");
            done(())
        }
    }
    struct Host {
        bytes: Rc<RefCell<Vec<u8>>>,
        events: Rc<RefCell<Vec<&'static str>>>,
        fail_kind: Rc<Cell<bool>>,
        sent: Vec<u64>,
    }
    impl Host {
        fn new() -> Self {
            Self {
                bytes: Rc::new(RefCell::new(vec![0xa5; wire::REQUEST_BYTES as usize])),
                events: Rc::new(RefCell::new(Vec::new())),
                fail_kind: Rc::new(Cell::new(false)),
                sent: Vec::new(),
            }
        }
    }
    impl Resources for Host {
        type Mapping = Ram;
        fn claim(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("claim");
            done(())
        }
        fn map(
            &mut self,
            _: &Request,
            buffer: wire::Buffer,
            flags: u32,
            _: &mut Access<'_>,
        ) -> Completion<MapResult<Ram>> {
            assert_eq!(flags, 0x202);
            assert_eq!(buffer.bus, 0x100000);
            self.events.borrow_mut().push("map");
            done(MapResult::Mapped(Ram {
                bytes: self.bytes.clone(),
                events: self.events.clone(),
                fail_kind: self.fail_kind.clone(),
            }))
        }
        fn dsb_sy(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("dsb");
            done(())
        }
        fn converted_clock(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
            self.events.borrow_mut().push("clock");
            done(1234)
        }
        fn send(
            &mut self,
            _: &Request,
            endpoint: u8,
            payload: u64,
            _: &mut Access<'_>,
        ) -> Completion<()> {
            assert_eq!(endpoint, 4);
            self.sent.push(payload);
            self.events.borrow_mut().push("send");
            done(())
        }
        fn arm_wait(&mut self, _: &Request, _: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("arm");
            done(())
        }
        fn wait(&mut self, _: &Request, _: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("wait");
            done(())
        }
        fn unmap(&mut self, _: &Request, _: &mut Ram, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("unmap");
            done(())
        }
        fn release(&mut self, _: &Request, _: &mut Ram, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("release");
            done(())
        }
    }
    struct Immediate {
        events: Rc<RefCell<Vec<&'static str>>>,
    }
    impl Wake for Immediate {
        fn publication_ack(&mut self, _: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("ack");
            done(())
        }
        fn queue_refresh(&mut self, _: &mut Access<'_>) -> Completion<()> {
            self.events.borrow_mut().push("queue");
            done(())
        }
    }
    fn step(owner: &mut Owner<Host>) -> Result<Progress, &'static str> {
        owner.advance(&mut Access::new(0, 1, &mut InterruptLatch::new()))
    }
    fn receive(owner: &Owner<Host>, payload: u64) -> Completion<()> {
        let mut wake = Immediate {
            events: owner.resources.events.clone(),
        };
        owner.receiver().receive(
            payload,
            &mut wake,
            &mut Access::new(0, 1, &mut InterruptLatch::new()),
        )
    }
    fn until(owner: &mut Owner<Host>, result: Finished) {
        for _ in 0..1024 {
            if step(owner).unwrap() == Progress::Finished(result.clone()) {
                return;
            }
        }
        panic!("authored reporting work failed to retire");
    }
    fn entered() -> Owner<Host> {
        let mut owner = Owner::new(Host::new());
        owner.enter(false).unwrap();
        for _ in 0..8 {
            step(&mut owner).unwrap();
            if owner.resources.sent == [wire::BUFFER_REQUEST] {
                break;
            }
        }
        assert!(matches!(
            receive(&owner, wire::BUFFER_REQUEST | 0x100000),
            Completion::Retired { .. }
        ));
        until(&mut owner, Finished::Ready);
        assert_eq!(owner.resources.sent, [wire::BUFFER_REQUEST, wire::READY]);
        assert_eq!(owner.used_bytes(), 16);
        assert_eq!(owner.record_count(), 0);
        assert_eq!(
            &owner.resources.bytes.borrow()[..4],
            &record::MAGIC.to_le_bytes()
        );
        assert!(owner.resources.bytes.borrow()[16..].iter().all(|b| *b == 0));
        assert!(matches!(
            receive(&owner, wire::BUFFER_REQUEST | 0x100000),
            Completion::Refused(_)
        ));
        owner
    }
    struct Live {
        value: Rc<Cell<u64>>,
        calls: Rc<Cell<u32>>,
    }
    impl getter::Scalar for Live {
        fn get(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
            self.calls.set(self.calls.get() + 1);
            done(self.value.get())
        }
    }
    impl getter::Pair for Live {
        fn get(&mut self, _: &Request, index: u32, _: &mut Access<'_>) -> Completion<(u64, u64)> {
            self.calls.set(self.calls.get() + 1);
            done((self.value.get() + u64::from(index), 17))
        }
    }
    impl getter::Indexed for Live {
        fn get(&mut self, _: &Request, index: u32, _: &mut Access<'_>) -> Completion<u64> {
            self.calls.set(self.calls.get() + 1);
            done(self.value.get() + u64::from(index))
        }
    }
    impl getter::State for Live {
        fn get(&mut self, _: &Request, index: u32, _: &mut Access<'_>) -> Completion<[u64; 4]> {
            self.calls.set(self.calls.get() + 1);
            done([self.value.get() + u64::from(index), 2, 3, 4])
        }
    }
    fn metadata(channel: u64, layout: Layout) -> Metadata {
        Metadata {
            channel,
            category: 2,
            name: record::Name::new(b"Live"),
            group: record::Name::new(b"Authored"),
            unit: 1,
            layout,
            descriptions: if let Layout::States { descriptions, .. } = layout {
                vec![[9; 16]; descriptions as usize]
            } else {
                Vec::new()
            },
        }
    }
    fn registered(
        owner: &mut Owner<Host>,
        token: Registration,
        metadata: Metadata,
        getter: LiveGetter,
    ) {
        let channel = metadata.channel;
        let prior = owner.resources.sent.len();
        owner.register(token, metadata, getter).unwrap();
        for _ in 0..128 {
            step(owner).unwrap();
            if owner.resources.sent.len() > prior
                && owner.resources.sent.last() == Some(&wire::REGISTERED)
            {
                break;
            }
        }
        assert_eq!(step(owner).unwrap(), Progress::Busy { deadline: None });
        assert!(matches!(
            receive(owner, wire::REGISTERED),
            Completion::Retired { .. }
        ));
        until(
            owner,
            Finished::Registered(RegistrationResult::Published { epoch: 1, channel }),
        );
    }
    #[test]
    fn ap_owned_ready_independent_ack_and_retired_kind_prefix_are_real() {
        let mut owner = entered();
        let token = Registration::new();
        let value = Rc::new(Cell::new(71));
        let calls = Rc::new(Cell::new(0));
        owner.resources.fail_kind.set(true);
        owner
            .register(
                token.clone(),
                metadata(1, Layout::Scalar),
                LiveGetter::Scalar(Box::new(Live {
                    value: value.clone(),
                    calls: calls.clone(),
                })),
            )
            .unwrap();
        assert_eq!(step(&mut owner), Err("authored post-kind-store diagnostic"));
        assert_eq!(owner.used_bytes(), 0x68);
        assert_eq!(owner.record_count(), 0);
        assert_eq!(calls.get(), 0);
        for _ in 0..64 {
            step(&mut owner).unwrap();
            if owner.resources.sent.last() == Some(&wire::REGISTERED) {
                break;
            }
        }
        assert_eq!(owner.record_count(), 1);
        assert_eq!(calls.get(), 1);
        assert_eq!(owner.registration_result(&token), None);
        assert_eq!(step(&mut owner).unwrap(), Progress::Busy { deadline: None });
        // Update is queued while the synchronous registration waits.
        assert!(matches!(
            receive(&owner, wire::UPDATE),
            Completion::Retired { .. }
        ));
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            receive(&owner, wire::REGISTERED),
            Completion::Retired { .. }
        ));
        until(
            &mut owner,
            Finished::Registered(RegistrationResult::Published {
                epoch: 1,
                channel: 1,
            }),
        );
        value.set(90);
        until(&mut owner, Finished::Refreshed);
        assert_eq!(calls.get(), 2);
        assert_eq!(
            &owner.resources.bytes.borrow()[0x60..0x68],
            &90u64.to_le_bytes()
        );
        let events = owner.resources.events.borrow();
        let dsb = events.iter().position(|e| *e == "dsb").unwrap();
        assert_eq!(events[dsb - 1], "sync");
        assert_eq!(events[dsb + 1], "clock");
    }
    #[test]
    fn all_getter_kinds_preserve_live_labels_and_once_registration_across_mapping_loss() {
        let mut owner = entered();
        let value = Rc::new(Cell::new(10));
        let calls = Rc::new(Cell::new(0));
        for (channel, layout) in [
            (1, Layout::Pairs(2)),
            (2, Layout::Scalars(2)),
            (
                3,
                Layout::States {
                    count: 2,
                    descriptions: 1,
                },
            ),
        ] {
            let live = Box::new(Live {
                value: value.clone(),
                calls: calls.clone(),
            });
            let getter = match layout {
                Layout::Pairs(count) => LiveGetter::Pairs {
                    count,
                    getter: live,
                },
                Layout::Scalars(count) => LiveGetter::Scalars {
                    count,
                    getter: live,
                },
                Layout::States {
                    count,
                    descriptions,
                } => LiveGetter::States {
                    count,
                    descriptions,
                    getter: live,
                },
                _ => unreachable!(),
            };
            registered(
                &mut owner,
                Registration::new(),
                metadata(channel, layout),
                getter,
            );
            owner.labels(channel, &[(1, 0xfeed)]).unwrap();
            until(&mut owner, Finished::LabelsChanged);
        }
        let before = owner.resources.bytes.borrow().clone();
        value.set(40);
        assert!(matches!(
            receive(&owner, wire::UPDATE),
            Completion::Retired { .. }
        ));
        until(&mut owner, Finished::Refreshed);
        for row in &owner.records {
            let lane = match row.metadata.layout {
                Layout::Pairs(_) => 16,
                Layout::Scalars(_) => 8,
                _ => 32,
            };
            let offset = (row.offset + 0x50 + row.metadata.layout.stride() + lane) as usize;
            assert_eq!(
                &owner.resources.bytes.borrow()[offset..offset + 8],
                &before[offset..offset + 8]
            );
            assert_eq!(
                &owner.resources.bytes.borrow()
                    [row.offset as usize + 0x38..row.offset as usize + 0x48],
                &[0; 16]
            );
        }
        let token = Registration::new();
        registered(
            &mut owner,
            token.clone(),
            metadata(4, Layout::Scalar),
            LiveGetter::Scalar(Box::new(Live {
                value: value.clone(),
                calls: calls.clone(),
            })),
        );
        owner.sleep().unwrap();
        owner.exit(0).unwrap();
        until(&mut owner, Finished::Released);
        assert_eq!(
            owner.registration_result(&token),
            Some(RegistrationResult::Published {
                epoch: 1,
                channel: 4
            })
        );
        assert_eq!(owner.record_count(), 0);
        let events = owner.resources.events.borrow();
        assert_eq!(&events[events.len() - 2..], &["unmap", "release"]);
    }
    #[test]
    fn retired_getter_diagnostic_keeps_the_observed_value_without_a_second_call() {
        struct Diagnosed {
            value: Rc<Cell<u64>>,
            calls: Rc<Cell<u32>>,
        }
        impl getter::Scalar for Diagnosed {
            fn get(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
                self.calls.set(self.calls.get() + 1);
                Completion::Retired {
                    value: self.value.get(),
                    refusal: Some("authored retired getter diagnostic"),
                }
            }
        }
        let mut owner = entered();
        let value = Rc::new(Cell::new(55));
        let calls = Rc::new(Cell::new(0));
        owner
            .register(
                Registration::new(),
                metadata(1, Layout::Scalar),
                LiveGetter::Scalar(Box::new(Diagnosed {
                    value: value.clone(),
                    calls: calls.clone(),
                })),
            )
            .unwrap();
        let mut reached = false;
        for _ in 0..32 {
            if step(&mut owner) == Err("authored retired getter diagnostic") {
                reached = true;
                break;
            }
        }
        assert!(reached);
        assert_eq!(calls.get(), 1);
        assert_eq!(owner.record_count(), 0);
        value.set(99);
        for _ in 0..64 {
            step(&mut owner).unwrap();
            if owner.resources.sent.last() == Some(&wire::REGISTERED) {
                break;
            }
        }
        assert_eq!(
            &owner.resources.bytes.borrow()[0x60..0x68],
            &55u64.to_le_bytes()
        );
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            receive(&owner, wire::REGISTERED),
            Completion::Retired { .. }
        ));
        until(
            &mut owner,
            Finished::Registered(RegistrationResult::Published {
                epoch: 1,
                channel: 1,
            }),
        );
    }
    #[test]
    fn backend_identities_refuse_exhaustion_before_any_resource_effect() {
        let mut owner = Owner::new(Host::new());
        owner.serial = u64::MAX;
        assert_eq!(
            owner.enter(false),
            Err("IOReporting job identity exhausted")
        );
        assert!(owner.resources.events.borrow().is_empty());
        assert!(owner.job.is_none());
        assert_eq!(owner.state, 0);
        owner.serial = 0;
        owner.epoch = u64::MAX;
        assert_eq!(
            owner.enter(false),
            Err("IOReporting lifecycle epoch exhausted")
        );
        assert!(owner.resources.events.borrow().is_empty());
        owner.epoch = 0;
        owner.enter(false).unwrap();
        owner.job.as_mut().unwrap().request.operation = u64::MAX;
        assert_eq!(
            step(&mut owner),
            Err("IOReporting backend operation identity exhausted")
        );
        assert!(owner.resources.events.borrow().is_empty());
        assert_eq!(owner.job.as_ref().unwrap().request.operation, u64::MAX);
        assert_eq!(
            step(&mut owner),
            Err("IOReporting backend operation identity exhausted")
        );
    }
    #[test]
    fn absent_database_is_a_retained_source_failure_without_getter_or_publication() {
        let mut owner = Owner::new(Host::new());
        let token = Registration::new();
        let calls = Rc::new(Cell::new(0));
        for _ in 0..2 {
            let result = owner
                .register(
                    token.clone(),
                    metadata(1, Layout::Scalar),
                    LiveGetter::Scalar(Box::new(Live {
                        value: Rc::new(Cell::new(0)),
                        calls: calls.clone(),
                    })),
                )
                .unwrap();
            assert_eq!(result, Some(RegistrationResult::SourceError(NO_DATABASE)));
        }
        assert!(owner.resources.sent.is_empty());
        assert_eq!(calls.get(), 0);
        assert_eq!(owner.returned.len(), 1);
        assert!(owner.enter(true).is_err());
    }
}
