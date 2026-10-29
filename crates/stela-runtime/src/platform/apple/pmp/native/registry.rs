//! Original native PMP registry producer and class4 callback. Allocations are
//! class1 client objects; no numeric slot/DMA address grants ownership.
use super::{Progress, Step, memory};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::Cell;
use memory::Mapping;
use stela_contracts::bus::Access;
mod operations;
mod wire;
use wire::Kind;

type Error = &'static str;
const BUFFER_BYTES: u32 = 0x4000;
/// Original initialized native object52424..524c4, not a hardware reset value.
const CAPACITY: usize = 0x400;

pub struct Claim {
    owner: Rc<()>,
    alive: Rc<Cell<bool>>,
}
impl Claim {
    pub(super) fn new(owner: Rc<()>, alive: Rc<Cell<bool>>) -> Self {
        Self { owner, alive }
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.alive.get() {
            Ok(())
        } else {
            Err("PMP native registry owner was abandoned")
        }
    }
}
#[derive(Clone)]
pub struct Request {
    owner: Rc<()>,
    serial: u64,
    operation: usize,
}
impl Request {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.serial == other.serial
            && self.operation == other.operation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Synchronization {
    Prepare,
    Complete,
}
/// Original mode2 mapping prepare4a734 and complete4a7e0, including
/// descriptor flags/cache guards, DC IVAC/CIVAC and DSB SY where reached.
/// The canonical owner must keep affected writers and each reached prefix.
/// No default, unrelated MFENCE or queue-enqueue completion is supplied here.
pub trait PublicationMapping: Mapping {
    /// Source memcpy effects, kept under this operation across partial
    /// copies, busy and refusal. Output storage remains owned and stable until
    /// retirement. Retired-with-refusal may not replay a copied prefix.
    fn read_publication(
        &mut self,
        request: &Request,
        output: &mut [u8],
        access: &mut Access<'_>,
    ) -> Step;
    fn write_publication(
        &mut self,
        request: &Request,
        input: &[u8],
        access: &mut Access<'_>,
    ) -> Step;
    fn synchronize(
        &mut self,
        request: &Request,
        operation: Synchronization,
        access: &mut Access<'_>,
    ) -> Step;
}
pub enum Input<'a, M: Mapping> {
    Local(&'a [u8]),
    Shared { mapping: &'a mut M, bytes: usize },
}
pub enum CallbackStep {
    Busy {
        deadline: Option<u64>,
    },
    Retired {
        accepted: bool,
        refusal: Option<Error>,
    },
    Refused(Error),
}
/// Moved-in native invocation/context owner. Shared input is the live
/// mapped AP buffer, not a staged copy: callback RAM effects must occur through
/// that same mapping and survive busy/refusal. Local-set ignores accepted;
/// incoming-set uses the native callback's zero/nonzero return.
pub trait Callback<B: memory::Backend> {
    fn apply(
        &mut self,
        request: &Request,
        index: u16,
        input: Input<'_, B::Mapping>,
        access: &mut Access<'_>,
    ) -> CallbackStep;
}
#[derive(Clone)]
pub struct Entry {
    owner: Rc<()>,
    object: Rc<()>,
    index: usize,
}
#[derive(Clone)]
pub struct Configuration {
    pub name: [u8; 48],
    pub unit: [u8; 8],
    pub value_type: [u8; 8],
    /// Original native bits0..4: remote, AP writable, metadata, kept name,
    /// and remote-only value. Preserve source bits rather than infer policy.
    pub flags: u32,
}
impl Configuration {
    fn check(&self) -> Result<(), Error> {
        if self.flags & !31 != 0
            || !self.name.contains(&0)
            || !self.unit.contains(&0)
            || !self.value_type.contains(&0)
        {
            return Err(
                "PMP registry configuration has unqualified flags or unterminated source strings",
            );
        }
        Ok(())
    }
    fn remote(&self) -> bool {
        self.flags & 1 != 0
    }
    fn local_value(&self) -> bool {
        self.flags & 0x11 != 0x11
    }
}
struct Record<B: memory::Backend> {
    object: Rc<()>,
    configuration: Configuration,
    bytes: usize,
    value: Option<Vec<u8>>,
    callback: Option<Box<dyn Callback<B>>>,
}
#[derive(Clone, Copy)]
enum Target {
    Outgoing,
    Incoming,
    Temporary,
}
#[derive(Clone, Copy)]
enum Operation {
    InitializeMemory,
    Allocate(Target, u32),
    Prepare(Target),
    Complete(Target),
    WriteInit,
    WriteDescriptor,
    WriteOutgoing,
    Send(Kind),
    Wait,
    FreeTemporary,
    ResolveAdd,
    ReadDefault,
    CommitInit,
    CommitAdd,
    CommitRemove,
    CommitSet,
    ApplyLocalCallback,
}
struct Plan<B: memory::Backend> {
    request: Request,
    ops: Vec<Operation>,
    cursor: usize,
    memory_started: bool,
    callback_active: bool,
    expected: Option<Kind>,
    reply: Option<u32>,
    index: usize,
    configuration: Option<Configuration>,
    data: Vec<u8>,
    value: Option<Vec<u8>>,
    callback: Option<Box<dyn Callback<B>>>,
    failed: Option<Error>,
}
pub enum Completion {
    Initialized,
    Added(Option<Entry>),
    Removed {
        entry: Entry,
        ap_result: Option<u32>,
    },
    Set {
        entry: Entry,
        ap_bytes: Option<u32>,
    },
}
#[derive(Clone, Copy)]
enum IncomingStage {
    PrepareCallback,
    Callback,
    PrepareCopy,
    Copy,
    Reply,
}
struct Incoming {
    request: Request,
    index: usize,
    object: Option<Rc<()>>,
    stage: IncomingStage,
    result: u32,
}

/// Owns the class1 client, persistent AP buffers, registry objects and
/// class3/class4 slots. Startup/exit does not replace this owner or allocations.
/// There is no reset/cancel/drop-time AP cleanup or generic readiness setter.
pub struct Owner<B: memory::Backend> {
    claim: Claim,
    memory: memory::Client<B>,
    outgoing: Option<memory::Allocation>,
    incoming: Option<memory::Allocation>,
    temporary: Option<memory::Allocation>,
    entries: Vec<Option<Record<B>>>,
    serial: u64,
    initialized: bool,
    plan: Option<Plan<B>>,
    received: Option<Incoming>,
    completion: Option<Completion>,
    regions: Option<Option<Vec<memory::Region>>>,
}
/// Failed admission returns the claims/client, including any reached
/// mapping/remote-allocation prefix. It does not silently drop those resources.
pub struct Admission<B: memory::Backend> {
    pub reason: Error,
    pub claim: Claim,
    pub memory: memory::Client<B>,
}
impl<B: memory::Backend> core::fmt::Debug for Admission<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PmpRegistryAdmission")
            .field(&self.reason)
            .finish()
    }
}
impl<B: memory::Backend> Owner<B>
where
    B::Mapping: PublicationMapping,
{
    pub fn new(claim: Claim, memory: memory::Client<B>) -> Result<Self, Box<Admission<B>>> {
        let reason = claim
            .check()
            .err()
            .or_else(|| {
                (!memory.owns(&claim.owner))
                    .then_some("PMP registry memory belongs to another actual native owner")
            })
            .or_else(|| {
                (!memory.fresh()).then_some(
                    "PMP cold registry admission requires the untouched actual memory client",
                )
            });
        if let Some(reason) = reason {
            return Err(Box::new(Admission {
                reason,
                claim,
                memory,
            }));
        }
        Ok(Self {
            claim,
            memory,
            outgoing: None,
            incoming: None,
            temporary: None,
            entries: core::iter::repeat_with(|| None).take(CAPACITY).collect(),
            serial: 0,
            initialized: false,
            plan: None,
            received: None,
            completion: None,
            regions: None,
        })
    }
    /// None means init has not retired. Some(None) is AP unavailability;
    /// Some(Some(rows)) keeps the read table, which is not permission.
    pub fn regions(&self) -> Option<&Option<Vec<memory::Region>>> {
        self.regions.as_ref()
    }
    fn request(&mut self) -> Result<Request, Error> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or("PMP registry transaction identity exhausted")?;
        Ok(Request {
            owner: self.claim.owner.clone(),
            serial: self.serial,
            operation: 0,
        })
    }
    fn begin(
        &mut self,
        ops: Vec<Operation>,
        index: usize,
        configuration: Option<Configuration>,
        data: Vec<u8>,
        callback: Option<Box<dyn Callback<B>>>,
    ) -> Result<(), Error> {
        self.claim.check()?;
        if self.plan.is_some() || self.completion.is_some() || self.received.is_some() {
            return Err("PMP registry still retains an operation, incoming callback or result");
        }
        let request = self.request()?;
        self.plan = Some(Plan {
            request,
            ops,
            cursor: 0,
            memory_started: false,
            callback_active: false,
            expected: None,
            reply: None,
            index,
            configuration,
            data,
            value: None,
            callback,
            failed: None,
        });
        Ok(())
    }
    pub fn begin_init(&mut self) -> Result<(), Error> {
        if self.initialized {
            return Err("PMP registry initialization already completed");
        }
        self.begin(
            alloc::vec![
                Operation::InitializeMemory,
                Operation::Allocate(Target::Outgoing, BUFFER_BYTES),
                Operation::Allocate(Target::Incoming, BUFFER_BYTES),
                Operation::Allocate(Target::Temporary, 16),
                Operation::Prepare(Target::Temporary),
                Operation::WriteInit,
                Operation::Complete(Target::Temporary),
                Operation::Send(Kind::Init),
                Operation::Wait,
                Operation::FreeTemporary,
                Operation::CommitInit
            ],
            0,
            None,
            Vec::new(),
            None,
        )
    }
    fn index(&self, entry: &Entry) -> Result<usize, Error> {
        self.claim.check()?;
        if !Rc::ptr_eq(&entry.owner, &self.claim.owner)
            || !self
                .entries
                .get(entry.index)
                .and_then(Option::as_ref)
                .is_some_and(|r| Rc::ptr_eq(&r.object, &entry.object))
        {
            return Err("PMP registry entry is foreign, removed or replaced");
        }
        Ok(entry.index)
    }
    fn entry(&self, index: usize) -> Entry {
        Entry {
            owner: self.claim.owner.clone(),
            object: self.entries[index].as_ref().unwrap().object.clone(),
            index,
        }
    }
    /// `None` requires an absent configured native callback. Missing
    /// invocation support for a present callback must refuse, never become None.
    pub fn begin_add(
        &mut self,
        configuration: Configuration,
        data: &[u8],
        callback: Option<Box<dyn Callback<B>>>,
    ) -> Result<(), Error> {
        configuration.check()?;
        if !self.initialized {
            return Err("PMP registry has not completed actual buffer initialization");
        }
        if data.len() > BUFFER_BYTES as usize {
            return Err("PMP registry value exceeds its actual shared buffer");
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or("PMP registry actual initialized slots exhausted")?;
        let mut ops = Vec::new();
        if configuration.remote() {
            ops.extend([
                Operation::Allocate(Target::Temporary, 88),
                Operation::Prepare(Target::Temporary),
                Operation::WriteDescriptor,
                Operation::Complete(Target::Temporary),
            ]);
            if !data.is_empty() {
                ops.extend([
                    Operation::Prepare(Target::Outgoing),
                    Operation::WriteOutgoing,
                    Operation::Complete(Target::Outgoing),
                ]);
            }
            ops.extend([
                Operation::Send(Kind::Add),
                Operation::Wait,
                Operation::FreeTemporary,
            ]);
        }
        ops.push(Operation::ResolveAdd);
        let local_value = configuration.local_value() && !data.is_empty();
        self.begin(ops, index, Some(configuration), data.to_vec(), callback)?;
        if local_value {
            self.plan.as_mut().unwrap().value = Some(data.to_vec());
        }
        Ok(())
    }
    pub fn begin_remove(&mut self, entry: &Entry) -> Result<(), Error> {
        let index = self.index(entry)?;
        let mut ops = Vec::new();
        if self.entries[index].as_ref().unwrap().configuration.remote() {
            ops.extend([Operation::Send(Kind::Remove), Operation::Wait]);
        }
        ops.push(Operation::CommitRemove);
        self.begin(ops, index, None, Vec::new(), None)
    }
    pub fn begin_set(&mut self, entry: &Entry, data: &[u8]) -> Result<(), Error> {
        let index = self.index(entry)?;
        let record = self.entries[index].as_ref().unwrap();
        if data.len() > record.bytes || data.len() > BUFFER_BYTES as usize {
            return Err("PMP registry set exceeds its retained entry or shared buffer");
        }
        let mut ops = Vec::new();
        if record.configuration.remote() {
            ops.extend([
                Operation::Prepare(Target::Outgoing),
                Operation::WriteOutgoing,
                Operation::Complete(Target::Outgoing),
                Operation::Send(Kind::Set),
                Operation::Wait,
            ]);
        }
        ops.extend([Operation::ApplyLocalCallback, Operation::CommitSet]);
        self.begin(ops, index, None, data.to_vec(), None)?;
        // Original115ec updates the local value before AP publication.
        if let Some(value) = &mut self.entries[index].as_mut().unwrap().value {
            value[..data.len()].copy_from_slice(data);
        }
        Ok(())
    }
    fn allocation(&self, target: Target) -> Result<memory::Allocation, Error> {
        match target {
            Target::Outgoing => &self.outgoing,
            Target::Incoming => &self.incoming,
            Target::Temporary => &self.temporary,
        }
        .clone()
        .ok_or("PMP registry lacks its actual AP allocation")
    }
    fn bus(&mut self, target: Target) -> Result<u64, Error> {
        let a = self.allocation(target)?;
        Ok(self.memory.mapping(&a)?.geometry().bus)
    }
    pub fn take_completion(&mut self) -> Result<Option<Completion>, Error> {
        self.claim.check()?;
        Ok(self.completion.take())
    }
    /// Commit at most one word. No fallible operation follows an outgoing push.
    pub fn emit(&mut self, outbox: &mut Vec<u64>) -> Result<bool, Error> {
        self.claim.check()?;
        if self
            .received
            .as_ref()
            .is_some_and(|r| matches!(r.stage, IncomingStage::Reply))
        {
            let r = self.received.take().unwrap();
            outbox.push(Kind::Set.reply_word(r.result));
            return Ok(true);
        }
        if self.memory.emit(outbox)? {
            return Ok(true);
        }
        let Some(plan) = self.plan.as_ref() else {
            return Ok(false);
        };
        if let Some(reason) = plan.failed {
            return Err(reason);
        }
        let Some(Operation::Send(kind)) = plan.ops.get(plan.cursor).copied() else {
            return Ok(false);
        };
        let body = match kind {
            Kind::Init | Kind::Add => self.bus(Target::Temporary)?,
            Kind::Remove | Kind::Set => u64::try_from(plan.index).unwrap(),
        };
        let word = kind.request(body);
        let plan = self.plan.as_mut().unwrap();
        outbox.push(word);
        plan.expected = Some(kind);
        plan.cursor += 1;
        Ok(true)
    }
    pub fn receive(&mut self, payload: u64) -> Result<(), Error> {
        self.claim.check()?;
        match payload >> 52 & 15 {
            1 => self.memory.receive(payload),
            3 => {
                let p = self
                    .plan
                    .as_mut()
                    .ok_or("PMP registry reply has no class3 waiter")?;
                let expected = p
                    .expected
                    .ok_or("PMP registry reply precedes actual publication")?;
                if p.reply.is_some() {
                    return Err("PMP registry reply repeats a retained reply");
                }
                p.reply = Some(expected.reply(payload)?);
                Ok(())
            }
            4 => {
                let index = wire::incoming(payload)?;
                if index >= CAPACITY {
                    return Err("PMP class4 slot exceeds actual initialized native storage");
                }
                if !self.initialized || self.received.is_some() {
                    return Err("PMP class4 callback is unavailable or already retained");
                }
                let object = self
                    .entries
                    .get(index)
                    .and_then(Option::as_ref)
                    .map(|r| r.object.clone());
                let request = self.request()?;
                self.received = Some(Incoming {
                    request,
                    index,
                    object,
                    stage: IncomingStage::PrepareCallback,
                    result: 0,
                });
                Ok(())
            }
            _ => Err("PMP registry input has an unqualified class"),
        }
    }
    fn sync(
        &mut self,
        target: Target,
        request: &Request,
        operation: Synchronization,
        access: &mut Access<'_>,
    ) -> Step {
        let result = self
            .allocation(target)
            .and_then(|a| self.memory.mapping(&a));
        match result {
            Ok(mapping) => mapping.synchronize(request, operation, access),
            Err(reason) => Step::Refused(reason),
        }
    }
    fn incoming_step(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        loop {
            let incoming = self.received.as_ref().unwrap();
            let index = incoming.index;
            let valid = self
                .entries
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(|r| {
                    incoming
                        .object
                        .as_ref()
                        .is_some_and(|object| Rc::ptr_eq(&r.object, object))
                });
            if !valid {
                self.received.as_mut().unwrap().stage = IncomingStage::Reply;
                return Ok(Progress::Idle);
            }
            let request = incoming.request.clone();
            let next = match incoming.stage {
                IncomingStage::PrepareCallback => {
                    if self.entries[index].as_ref().unwrap().callback.is_some() {
                        match self.sync(
                            Target::Incoming,
                            &request,
                            Synchronization::Prepare,
                            access,
                        ) {
                            Step::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                            Step::Refused(reason) => return Err(reason),
                            Step::Retired { refusal } => {
                                let r = self.received.as_mut().unwrap();
                                r.stage = IncomingStage::Callback;
                                r.request.operation += 1;
                                if let Some(reason) = refusal {
                                    return Err(reason);
                                }
                                continue;
                            }
                        }
                    }
                    IncomingStage::PrepareCopy
                }
                IncomingStage::Callback => {
                    let record = self.entries[index].as_mut().unwrap();
                    let mapping = self.memory.mapping(self.incoming.as_ref().unwrap())?;
                    match record.callback.as_mut().unwrap().apply(
                        &request,
                        u16::try_from(index).unwrap(),
                        Input::Shared {
                            mapping,
                            bytes: record.bytes,
                        },
                        access,
                    ) {
                        CallbackStep::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                        CallbackStep::Refused(reason) => return Err(reason),
                        CallbackStep::Retired { accepted, refusal } => {
                            let r = self.received.as_mut().unwrap();
                            r.stage = if accepted {
                                IncomingStage::PrepareCopy
                            } else {
                                IncomingStage::Reply
                            };
                            r.request.operation += 1;
                            if let Some(reason) = refusal {
                                return Err(reason);
                            }
                            continue;
                        }
                    }
                }
                IncomingStage::PrepareCopy => {
                    let record = self.entries[index].as_ref().unwrap();
                    if record.value.is_some() {
                        match self.sync(
                            Target::Incoming,
                            &request,
                            Synchronization::Prepare,
                            access,
                        ) {
                            Step::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                            Step::Refused(reason) => return Err(reason),
                            Step::Retired { refusal } => {
                                let r = self.received.as_mut().unwrap();
                                r.stage = IncomingStage::Copy;
                                r.request.operation += 1;
                                if let Some(reason) = refusal {
                                    return Err(reason);
                                }
                                continue;
                            }
                        }
                    }
                    self.received.as_mut().unwrap().result = u32::try_from(record.bytes).unwrap();
                    IncomingStage::Reply
                }
                IncomingStage::Copy => {
                    let record = self.entries[index].as_mut().unwrap();
                    let step = self
                        .memory
                        .mapping(self.incoming.as_ref().unwrap())?
                        .read_publication(&request, record.value.as_mut().unwrap(), access);
                    match step {
                        Step::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                        Step::Refused(reason) => return Err(reason),
                        Step::Retired { refusal } => {
                            let r = self.received.as_mut().unwrap();
                            r.result = u32::try_from(record.bytes).unwrap();
                            r.stage = IncomingStage::Reply;
                            r.request.operation += 1;
                            if let Some(reason) = refusal {
                                return Err(reason);
                            }
                            continue;
                        }
                    }
                }
                IncomingStage::Reply => return Ok(Progress::Idle),
            };
            let r = self.received.as_mut().unwrap();
            r.stage = next;
            r.request.operation += 1;
        }
    }
    fn retire(&mut self, step: Step) -> Result<Option<Progress>, Error> {
        match step {
            Step::Busy { deadline } => Ok(Some(Progress::Busy { deadline })),
            Step::Refused(reason) => Err(reason),
            Step::Retired { refusal } => {
                self.plan.as_mut().unwrap().cursor += 1;
                if let Some(reason) = refusal {
                    return Err(reason);
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests;
