//! Original native PMP registry producer and class4 callback. Allocations are
//! actual class1 client objects; no numeric slot/DMA address grants ownership.
use super::{Progress, Step, memory};
use crate::platform::apple::bus::Access;
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::Cell;
use memory::Mapping;
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
/// Original mode2 mapping prepare4a734 and complete4a7e0, including actual
/// descriptor flags/cache guards, DC IVAC/CIVAC and DSB SY where reached.
/// The canonical owner must retain affected writers and each reached prefix.
/// No default, unrelated MFENCE or queue-enqueue completion is supplied here.
pub trait PublicationMapping: Mapping {
    /// Source memcpy effects, retained under this operation across partial
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
/// Moved-in actual native invocation/context owner. Shared input is the live
/// mapped AP buffer, not a staged copy: callback RAM effects must occur through
/// that same mapping and survive busy/refusal. Local-set ignores accepted;
/// incoming-set uses the actual native callback's zero/nonzero return.
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
    /// Original native bits0..4: remote, AP writable, metadata, retained name,
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

/// Owns the actual class1 client, persistent AP buffers, registry objects and
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
/// Failed admission returns the actual claims/client, including any reached
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
    /// None means init has not retired. Some(None) is actual AP unavailability;
    /// Some(Some(rows)) retains the actual read table, which is not authority.
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
    /// `None` requires an actually absent configured native callback. Missing
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
        // Original115ec updates the actual local value before AP publication.
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
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    use alloc::{
        collections::{BTreeMap, VecDeque},
        vec,
    };
    use core::cell::RefCell;
    struct Object {
        data: Vec<u8>,
        mapped: bool,
    }
    #[derive(Clone, Copy)]
    enum Outcome {
        Busy,
        Refuse,
        Prefix,
        RetireRefuse,
    }
    #[derive(Default)]
    struct Lab {
        objects: BTreeMap<u64, Rc<RefCell<Object>>>,
        next: u64,
        allocations: usize,
        fail_allocation: Option<usize>,
        outgoing: Option<Rc<RefCell<Object>>>,
        incoming: Option<Rc<RefCell<Object>>>,
        values: BTreeMap<u16, Vec<u8>>,
        headers: Vec<[u8; 88]>,
        wire: Vec<u64>,
        acks: Vec<u32>,
        sync_steps: VecDeque<Outcome>,
        copy_steps: VecDeque<Outcome>,
        syncs: Vec<Request>,
        copies: Vec<Request>,
        prefix: Option<(Request, usize)>,
        events: Vec<&'static str>,
    }
    #[derive(Clone)]
    struct Backing(Rc<RefCell<Lab>>);
    struct Mapped {
        lab: Rc<RefCell<Lab>>,
        object: Rc<RefCell<Object>>,
        geometry: memory::MapRequest,
    }
    impl memory::Mapping for Mapped {
        fn geometry(&self) -> memory::MapRequest {
            self.geometry
        }
        fn read(
            &mut self,
            offset: u64,
            output: &mut [u8],
            _: &mut Access<'_>,
        ) -> Result<(), Error> {
            assert!(self.object.borrow().mapped);
            let at = usize::try_from(offset).unwrap();
            output.copy_from_slice(&self.object.borrow().data[at..at + output.len()]);
            Ok(())
        }
        fn write(&mut self, offset: u64, input: &[u8], _: &mut Access<'_>) -> Result<(), Error> {
            assert!(self.object.borrow().mapped);
            let at = usize::try_from(offset).unwrap();
            self.object.borrow_mut().data[at..at + input.len()].copy_from_slice(input);
            Ok(())
        }
    }
    impl PublicationMapping for Mapped {
        fn synchronize(
            &mut self,
            request: &Request,
            _: Synchronization,
            _: &mut Access<'_>,
        ) -> Step {
            let mut lab = self.lab.borrow_mut();
            lab.syncs.push(request.clone());
            match lab.sync_steps.pop_front() {
                Some(Outcome::Busy) => Step::Busy { deadline: Some(13) },
                Some(Outcome::Refuse) => Step::Refused("actual synchronization refused"),
                Some(Outcome::RetireRefuse) => Step::Retired {
                    refusal: Some("post-sync refusal"),
                },
                _ => Step::Retired { refusal: None },
            }
        }
        fn read_publication(
            &mut self,
            request: &Request,
            output: &mut [u8],
            _: &mut Access<'_>,
        ) -> Step {
            assert!(self.object.borrow().mapped);
            let mut lab = self.lab.borrow_mut();
            lab.copies.push(request.clone());
            let cursor = lab
                .prefix
                .as_ref()
                .filter(|(r, _)| r.same_operation(request))
                .map_or(0, |(_, at)| *at);
            match lab.copy_steps.pop_front() {
                Some(Outcome::Busy) => Step::Busy { deadline: Some(14) },
                Some(Outcome::Refuse) => Step::Refused("actual copy refused"),
                Some(Outcome::Prefix) => {
                    output[0] = self.object.borrow().data[0];
                    lab.prefix = Some((request.clone(), 1));
                    Step::Refused("actual read prefix retained")
                }
                value => {
                    let end = output.len();
                    output[cursor..].copy_from_slice(&self.object.borrow().data[cursor..end]);
                    lab.prefix = None;
                    Step::Retired {
                        refusal: matches!(value, Some(Outcome::RetireRefuse))
                            .then_some("post-copy refusal"),
                    }
                }
            }
        }
        fn write_publication(
            &mut self,
            request: &Request,
            input: &[u8],
            _: &mut Access<'_>,
        ) -> Step {
            assert!(self.object.borrow().mapped);
            let mut lab = self.lab.borrow_mut();
            lab.copies.push(request.clone());
            let cursor = lab
                .prefix
                .as_ref()
                .filter(|(r, _)| r.same_operation(request))
                .map_or(0, |(_, at)| *at);
            match lab.copy_steps.pop_front() {
                Some(Outcome::Busy) => Step::Busy { deadline: Some(14) },
                Some(Outcome::Refuse) => Step::Refused("actual copy refused"),
                Some(Outcome::Prefix) => {
                    self.object.borrow_mut().data[0] = input[0];
                    lab.prefix = Some((request.clone(), 1));
                    Step::Refused("actual write prefix retained")
                }
                value => {
                    self.object.borrow_mut().data[cursor..input.len()]
                        .copy_from_slice(&input[cursor..]);
                    lab.prefix = None;
                    Step::Retired {
                        refusal: matches!(value, Some(Outcome::RetireRefuse))
                            .then_some("post-copy refusal"),
                    }
                }
            }
        }
    }
    impl memory::Backend for Backing {
        type Mapping = Mapped;
        fn map(
            &mut self,
            _: &memory::Request,
            geometry: memory::MapRequest,
            _: &mut Access<'_>,
        ) -> memory::MapStep<Mapped> {
            let object = self.0.borrow().objects.get(&geometry.bus).unwrap().clone();
            assert!(!object.borrow().mapped);
            assert_eq!(geometry.bytes, object.borrow().data.len() as u64);
            object.borrow_mut().mapped = true;
            memory::MapStep::Retired {
                mapping: Mapped {
                    lab: self.0.clone(),
                    object,
                    geometry,
                },
                refusal: None,
            }
        }
        fn unmap(&mut self, _: &memory::Request, mapping: &mut Mapped, _: &mut Access<'_>) -> Step {
            assert!(mapping.object.borrow().mapped);
            mapping.object.borrow_mut().mapped = false;
            self.0.borrow_mut().events.push("unmap");
            Step::Retired { refusal: None }
        }
    }
    /// Explicit synthetic AP peer. It owns real test allocation objects and
    /// executes requests against their bytes; it is never production routing.
    fn peer(owner: &mut Owner<Backing>, lab: &Rc<RefCell<Lab>>, word: u64) {
        let mut l = lab.borrow_mut();
        l.wire.push(word);
        let class = word >> 52 & 15;
        let kind = word >> 48 & 15;
        let body = word & ((1 << 48) - 1);
        let reply = match (class, kind) {
            (1, 0) => 0x0011_0000_0000_0000,
            (1, 2) => {
                l.allocations += 1;
                let bus = if l.fail_allocation == Some(l.allocations) {
                    0
                } else {
                    l.next += 0x1_0000;
                    let bus = l.next;
                    l.objects.insert(
                        bus,
                        Rc::new(RefCell::new(Object {
                            data: vec![0; body as usize],
                            mapped: false,
                        })),
                    );
                    bus
                };
                0x0013_0000_0000_0000 | bus
            }
            (1, 4) => {
                let object = l.objects.remove(&body).unwrap();
                assert!(!object.borrow().mapped);
                assert_eq!(l.events.last(), Some(&"unmap"));
                l.events.push("ap-free");
                0x0015_0000_0000_0000
            }
            (3, 0) => {
                let descriptor = l.objects.get(&body).unwrap().borrow();
                let out = u64::from_le_bytes(descriptor.data[..8].try_into().unwrap());
                let incoming = u64::from_le_bytes(descriptor.data[8..16].try_into().unwrap());
                drop(descriptor);
                l.outgoing = Some(l.objects.get(&out).unwrap().clone());
                l.incoming = Some(l.objects.get(&incoming).unwrap().clone());
                assert_eq!(l.outgoing.as_ref().unwrap().borrow().data.len(), 0x4000);
                0x0031_0000_0000_0000
            }
            (3, 2) => {
                let descriptor = l.objects.get(&body).unwrap().borrow();
                let mut header = [0; 88];
                header.copy_from_slice(&descriptor.data[..88]);
                drop(descriptor);
                let bytes = u64::from_le_bytes(header[64..72].try_into().unwrap()) as usize;
                let index =
                    u16::try_from(u64::from_le_bytes(header[72..80].try_into().unwrap())).unwrap();
                let data = if bytes == 0 {
                    let value = vec![0x61, 0x62, 0x63, 0x64];
                    l.outgoing.as_ref().unwrap().borrow_mut().data[..4].copy_from_slice(&value);
                    value
                } else {
                    l.outgoing.as_ref().unwrap().borrow().data[..bytes].to_vec()
                };
                let result = data.len() as u64;
                l.values.insert(index, data);
                l.headers.push(header);
                0x0033_0000_0000_0000 | result
            }
            (3, 4) => {
                let removed = l.values.remove(&(body as u16)).is_some();
                0x0035_0000_0000_0000 | u64::from(removed)
            }
            (3, 6) => {
                let bytes = l.values.get(&(body as u16)).unwrap().len();
                let data = l.outgoing.as_ref().unwrap().borrow().data[..bytes].to_vec();
                l.values.insert(body as u16, data);
                0x0037_0000_0000_0000 | bytes as u64
            }
            (3, 7) => {
                l.acks.push(word as u32);
                return;
            }
            _ => panic!("unqualified synthetic AP word {word:x}"),
        };
        drop(l);
        owner.receive(reply).unwrap();
    }
    fn step(owner: &mut Owner<Backing>, lab: &Rc<RefCell<Lab>>) -> Result<(), Error> {
        owner.advance(&mut Access::new(0, 7, &mut InterruptLatch::new()))?;
        let mut out = Vec::new();
        while owner.emit(&mut out)? {
            assert_eq!(out.len(), 1);
            peer(owner, lab, out.pop().unwrap());
        }
        Ok(())
    }
    fn run(owner: &mut Owner<Backing>, lab: &Rc<RefCell<Lab>>) {
        for _ in 0..500 {
            step(owner, lab).unwrap();
            if owner.plan.is_none() && owner.received.is_none() {
                return;
            }
        }
        panic!("service failed to retire")
    }
    fn setup() -> (Owner<Backing>, Rc<RefCell<Lab>>) {
        let lab = Rc::new(RefCell::new(Lab::default()));
        let identity = Rc::new(());
        let alive = Rc::new(Cell::new(true));
        let memory = memory::Client::new(
            memory::Claim::new(identity.clone(), alive.clone()),
            Backing(lab.clone()),
        )
        .unwrap();
        let owner = Owner::new(Claim::new(identity, alive), memory).unwrap();
        (owner, lab)
    }
    fn initialized() -> (Owner<Backing>, Rc<RefCell<Lab>>) {
        let (mut owner, lab) = setup();
        owner.begin_init().unwrap();
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Initialized)
        ));
        (owner, lab)
    }
    fn configuration(flags: u32) -> Configuration {
        let mut name = [0; 48];
        name[..5].copy_from_slice(b"value");
        Configuration {
            name,
            unit: [0; 8],
            value_type: [0; 8],
            flags,
        }
    }
    fn added(
        owner: &mut Owner<Backing>,
        lab: &Rc<RefCell<Lab>>,
        data: &[u8],
        callback: Option<Box<dyn Callback<Backing>>>,
    ) -> Entry {
        owner
            .begin_add(configuration(0x0f), data, callback)
            .unwrap();
        run(owner, lab);
        match owner.take_completion().unwrap().unwrap() {
            Completion::Added(Some(entry)) => entry,
            _ => panic!("missing actual entry"),
        }
    }
    #[derive(Default)]
    struct Capture {
        calls: Vec<Request>,
        steps: VecDeque<Outcome>,
        accepted: bool,
        modified: bool,
    }
    struct NativeCallback(Rc<RefCell<Capture>>);
    impl Callback<Backing> for NativeCallback {
        fn apply(
            &mut self,
            request: &Request,
            _: u16,
            input: Input<'_, Mapped>,
            access: &mut Access<'_>,
        ) -> CallbackStep {
            let mut c = self.0.borrow_mut();
            c.calls.push(request.clone());
            if let Input::Shared { mapping, .. } = input
                && !c.modified
            {
                let mut value = [0];
                mapping.read(0, &mut value, access).unwrap();
                value[0] += 1;
                mapping.write(0, &value, access).unwrap();
                c.modified = true;
            }
            match c.steps.pop_front() {
                Some(Outcome::Busy) => CallbackStep::Busy { deadline: Some(15) },
                Some(Outcome::Refuse) => CallbackStep::Refused("actual callback refused"),
                value => CallbackStep::Retired {
                    accepted: c.accepted,
                    refusal: matches!(value, Some(Outcome::RetireRefuse))
                        .then_some("post-callback refusal"),
                },
            }
        }
    }
    #[test]
    fn cold_init_retains_static_result_two_real_buffers_and_frees_only_temporary_after_reply() {
        let (owner, lab) = initialized();
        let l = lab.borrow();
        assert_eq!(owner.regions(), Some(&None));
        assert_eq!(l.allocations, 3);
        assert_eq!(l.objects.len(), 2);
        assert_eq!(l.events, ["unmap", "ap-free"]);
        assert!(l.objects.values().all(|o| o.borrow().mapped));
        let kinds: Vec<_> = l.wire.iter().map(|w| w >> 48 & 255).collect();
        assert_eq!(kinds, [0x10, 0x12, 0x12, 0x12, 0x30, 0x14]);
        assert!(owner.temporary.is_none());
        assert!(owner.initialized);
    }
    #[test]
    fn full_remote_add_set_remove_and_slot_reuse_keep_actual_descriptor_and_object_identity() {
        let (mut owner, lab) = initialized();
        let entry = added(&mut owner, &lab, &[1, 2, 3, 4], None);
        let header = lab.borrow().headers[0];
        assert_eq!(&header[..5], b"value");
        assert_eq!(u64::from_le_bytes(header[64..72].try_into().unwrap()), 4);
        assert_eq!(u64::from_le_bytes(header[72..80].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(header[80..88].try_into().unwrap()), 3);
        owner.begin_set(&entry, &[9, 8]).unwrap();
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Set {
                ap_bytes: Some(4),
                ..
            })
        ));
        assert_eq!(lab.borrow().values[&0], [9, 8, 3, 4]);
        assert_eq!(
            owner.entries[0].as_ref().unwrap().value.as_deref(),
            Some(&[9, 8, 3, 4][..])
        );
        owner.begin_remove(&entry).unwrap();
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Removed {
                ap_result: Some(1),
                ..
            })
        ));
        assert!(owner.begin_set(&entry, &[0]).is_err());
        let replacement = added(&mut owner, &lab, &[5, 6, 7, 8], None);
        assert_eq!(entry.index, replacement.index);
        assert!(!Rc::ptr_eq(&entry.object, &replacement.object));
        assert!(owner.begin_remove(&entry).is_err());
        let (mut foreign, _) = initialized();
        assert!(foreign.begin_remove(&replacement).is_err());
        assert_eq!(lab.borrow().objects.len(), 2);
    }
    #[test]
    fn class4_callback_retains_actual_mapping_effect_and_runs_during_class3_wait() {
        let (mut owner, lab) = initialized();
        let capture = Rc::new(RefCell::new(Capture {
            accepted: true,
            steps: VecDeque::from([Outcome::Busy, Outcome::Refuse, Outcome::RetireRefuse]),
            ..Capture::default()
        }));
        let entry = added(
            &mut owner,
            &lab,
            &[1, 2, 3, 4],
            Some(Box::new(NativeCallback(capture.clone()))),
        );
        owner.begin_set(&entry, &[7, 7, 7, 7]).unwrap();
        loop {
            owner
                .advance(&mut Access::new(0, 8, &mut InterruptLatch::new()))
                .unwrap();
            let mut out = Vec::new();
            if owner.emit(&mut out).unwrap() {
                assert_eq!(out[0] >> 48 & 255, 0x36);
                break;
            }
        }
        lab.borrow().incoming.as_ref().unwrap().borrow_mut().data[..4]
            .copy_from_slice(&[10, 11, 12, 13]);
        owner.receive(0x0046_0000_0000_0000).unwrap();
        assert!(owner.receive(0x0046_0000_0000_0000).is_err());
        assert_eq!(
            owner
                .advance(&mut Access::new(0, 9, &mut InterruptLatch::new()))
                .unwrap(),
            Progress::Busy { deadline: Some(15) }
        );
        assert!(
            owner
                .advance(&mut Access::new(0, 10, &mut InterruptLatch::new()))
                .is_err()
        );
        assert_eq!(
            owner.advance(&mut Access::new(0, 11, &mut InterruptLatch::new())),
            Err("post-callback refusal")
        );
        assert_eq!(capture.borrow().calls.len(), 3);
        assert!(
            capture
                .borrow()
                .calls
                .windows(2)
                .all(|r| r[0].same_operation(&r[1]))
        );
        owner
            .advance(&mut Access::new(0, 12, &mut InterruptLatch::new()))
            .unwrap();
        let mut out = Vec::new();
        assert!(owner.emit(&mut out).unwrap());
        assert_eq!(out, [0x0037_0000_0000_0004]);
        assert_eq!(
            owner.entries[0].as_ref().unwrap().value.as_deref(),
            Some(&[11, 11, 12, 13][..])
        );
        assert_eq!(capture.borrow().calls.len(), 3);
        owner.receive(0x0037_0000_0000_0004).unwrap();
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Set { .. })
        ));
    }
    #[test]
    fn actual_default_read_prefix_and_published_copy_retirement_never_replay() {
        let (mut owner, lab) = initialized();
        owner.begin_add(configuration(1), &[], None).unwrap();
        loop {
            step(&mut owner, &lab).unwrap();
            let l = lab.borrow();
            if l.headers.len() == 1 && l.wire.last().is_some_and(|w| w >> 48 & 255 == 0x14) {
                break;
            }
        }
        lab.borrow_mut().copy_steps.push_back(Outcome::Prefix);
        assert_eq!(
            owner.advance(&mut Access::new(0, 8, &mut InterruptLatch::new())),
            Err("actual read prefix retained")
        );
        lab.borrow().outgoing.as_ref().unwrap().borrow_mut().data[0] = 0xee;
        run(&mut owner, &lab);
        let entry = match owner.take_completion().unwrap().unwrap() {
            Completion::Added(Some(e)) => e,
            _ => panic!(),
        };
        assert_eq!(
            owner.entries[entry.index]
                .as_ref()
                .unwrap()
                .value
                .as_deref(),
            Some(&[0x61, 0x62, 0x63, 0x64][..])
        );
        owner.begin_set(&entry, &[8, 7, 6, 5]).unwrap();
        lab.borrow_mut().copy_steps.push_back(Outcome::RetireRefuse);
        assert_eq!(
            owner.advance(&mut Access::new(0, 9, &mut InterruptLatch::new())),
            Err("post-copy refusal")
        );
        let count = lab.borrow().copies.len();
        run(&mut owner, &lab);
        assert_eq!(lab.borrow().copies.len(), count);
        assert!(owner.take_completion().unwrap().is_some());
    }
    #[test]
    fn synchronization_prefix_reply_admission_and_irreversible_allocation_failure_are_explicit() {
        let (mut owner, lab) = setup();
        assert!(owner.receive(0x0031_0000_0000_0000).is_err());
        assert!(owner.receive(0x0046_0000_0000_0000).is_err());
        owner.begin_init().unwrap();
        lab.borrow_mut().sync_steps =
            VecDeque::from([Outcome::Busy, Outcome::Refuse, Outcome::RetireRefuse]);
        loop {
            step(&mut owner, &lab).unwrap();
            if lab.borrow().syncs.len() == 1 {
                break;
            }
        }
        assert_eq!(
            owner.advance(&mut Access::new(0, 9, &mut InterruptLatch::new())),
            Err("actual synchronization refused")
        );
        assert_eq!(
            owner.advance(&mut Access::new(0, 10, &mut InterruptLatch::new())),
            Err("post-sync refusal")
        );
        let count = lab.borrow().syncs.len();
        run(&mut owner, &lab);
        assert_eq!(lab.borrow().syncs.len(), count + 1);
        assert!(owner.take_completion().unwrap().is_some());
        assert!(owner.receive(0x0031_0000_0000_0000).is_err());
        assert!(owner.receive(0x0046_0000_0000_0400).is_err());
        assert!(owner.receive(0x0146_0000_0000_0000).is_err());
        let (mut failed, l) = setup();
        l.borrow_mut().fail_allocation = Some(2);
        failed.begin_init().unwrap();
        let error = loop {
            if let Err(e) = step(&mut failed, &l) {
                break e;
            }
        };
        assert!(error.contains("allocation failed"));
        assert!(!failed.initialized);
        assert!(failed.outgoing.is_some());
        assert!(failed.incoming.is_none());
        assert!(l.borrow().objects.values().all(|o| o.borrow().mapped));
        assert!(failed.begin_init().is_err());
        assert!(failed.emit(&mut Vec::new()).is_err());
    }
    #[test]
    fn local_remote_only_bounds_callback_refusal_and_owner_abandonment_preserve_resources() {
        let (mut owner, lab) = initialized();
        let before = lab.borrow().wire.len();
        owner.begin_add(configuration(8), &[1, 2], None).unwrap();
        run(&mut owner, &lab);
        let local = match owner.take_completion().unwrap().unwrap() {
            Completion::Added(Some(e)) => e,
            _ => panic!(),
        };
        assert_eq!(lab.borrow().wire.len(), before);
        assert!(owner.begin_set(&local, &[1, 2, 3]).is_err());
        let mut invalid = configuration(1);
        invalid.name.fill(0x61);
        assert!(owner.begin_add(invalid, &[], None).is_err());
        assert!(owner.begin_add(configuration(32), &[], None).is_err());
        assert!(
            owner
                .begin_add(configuration(1), &vec![0; 0x4001], None)
                .is_err()
        );
        owner.begin_add(configuration(0x11), &[3, 4], None).unwrap();
        run(&mut owner, &lab);
        let remote = match owner.take_completion().unwrap().unwrap() {
            Completion::Added(Some(e)) => e,
            _ => panic!(),
        };
        assert!(
            owner.entries[remote.index]
                .as_ref()
                .unwrap()
                .value
                .is_none()
        );
        let capture = Rc::new(RefCell::new(Capture::default()));
        let rejected = added(
            &mut owner,
            &lab,
            &[1, 2, 3, 4],
            Some(Box::new(NativeCallback(capture))),
        );
        owner
            .receive(0x0046_0000_0000_0000 | rejected.index as u64)
            .unwrap();
        run(&mut owner, &lab);
        assert_eq!(lab.borrow().acks.last(), Some(&0));
        assert_eq!(
            owner.entries[rejected.index]
                .as_ref()
                .unwrap()
                .value
                .as_deref(),
            Some(&[1, 2, 3, 4][..])
        );
        owner.claim.alive.set(false);
        let count = lab.borrow().objects.len();
        assert!(
            owner
                .advance(&mut Access::new(0, 0, &mut InterruptLatch::new()))
                .is_err()
        );
        assert!(owner.emit(&mut Vec::new()).is_err());
        assert!(owner.begin_remove(&remote).is_err());
        assert_eq!(lab.borrow().objects.len(), count);
    }
    #[test]
    fn failed_admission_returns_actual_owned_client_instead_of_losing_resources() {
        let lab = Rc::new(RefCell::new(Lab::default()));
        let identity = Rc::new(());
        let alive = Rc::new(Cell::new(true));
        let memory =
            memory::Client::new(memory::Claim::new(identity, alive.clone()), Backing(lab)).unwrap();
        let failure = match Owner::new(Claim::new(Rc::new(()), alive), memory) {
            Err(e) => e,
            Ok(_) => panic!(),
        };
        assert!(failure.reason.contains("another actual"));
        assert!(failure.memory.fresh());
    }

    fn publish_until(owner: &mut Owner<Backing>, lab: &Rc<RefCell<Lab>>, kind: u64) -> u64 {
        for _ in 0..100 {
            owner
                .advance(&mut Access::new(0, 8, &mut InterruptLatch::new()))
                .unwrap();
            let mut out = Vec::new();
            while owner.emit(&mut out).unwrap() {
                let word = out.pop().unwrap();
                if word >> 48 & 255 == kind {
                    return word;
                }
                peer(owner, lab, word);
            }
        }
        panic!("source request did not reach publication")
    }

    #[test]
    fn actual_ap_zero_results_and_bad_replies_preserve_source_cleanup_and_local_prefix() {
        let (mut owner, lab) = initialized();
        owner
            .begin_add(configuration(1), &[1, 2, 3, 4], None)
            .unwrap();
        publish_until(&mut owner, &lab, 0x32);
        for wrong in [
            0x0031_0000_0000_0000,
            0x0043_0000_0000_0004,
            0x0033_0001_0000_0000,
        ] {
            assert!(owner.receive(wrong).is_err());
        }
        owner.receive(0x0033_0000_0000_0000).unwrap();
        assert!(owner.receive(0x0033_0000_0000_0004).is_err());
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Added(None))
        ));
        assert!(owner.entries.iter().all(Option::is_none));
        assert_eq!(lab.borrow().objects.len(), 2);
        let capture = Rc::new(RefCell::new(Capture::default()));
        let entry = added(
            &mut owner,
            &lab,
            &[1, 2, 3, 4],
            Some(Box::new(NativeCallback(capture.clone()))),
        );
        owner.begin_set(&entry, &[8, 7, 6, 5]).unwrap();
        publish_until(&mut owner, &lab, 0x36);
        lab.borrow_mut().values.remove(&0);
        owner.receive(0x0037_0000_0000_0000).unwrap();
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Set {
                ap_bytes: Some(0),
                ..
            })
        ));
        assert_eq!(
            owner.entries[0].as_ref().unwrap().value.as_deref(),
            Some(&[8, 7, 6, 5][..])
        );
        assert_eq!(capture.borrow().calls.len(), 1);
        owner.begin_remove(&entry).unwrap();
        run(&mut owner, &lab);
        assert!(matches!(
            owner.take_completion().unwrap(),
            Some(Completion::Removed {
                ap_result: Some(0),
                ..
            })
        ));
        assert!(owner.index(&entry).is_err());
        assert!(owner.receive(0x0035_0000_0000_0000).is_err());
        owner
            .begin_add(configuration(1), &[1, 2, 3, 4], None)
            .unwrap();
        publish_until(&mut owner, &lab, 0x32);
        owner.receive(0x0033_0000_0000_4001).unwrap();
        let reason = loop {
            if let Err(reason) = step(&mut owner, &lab) {
                break reason;
            }
        };
        assert!(reason.contains("unqualified length"));
        assert!(owner.plan.as_ref().unwrap().failed.is_some());
        assert_eq!(lab.borrow().objects.len(), 2);
        assert!(owner.take_completion().unwrap().is_none());
    }

    #[test]
    fn actual_initialized_capacity_is_enforced_without_wire_truncation_or_an_extra_slot() {
        let (mut owner, lab) = initialized();
        let words = lab.borrow().wire.len();
        let mut last = None;
        for expected in 0..CAPACITY {
            owner.begin_add(configuration(8), &[0x61], None).unwrap();
            run(&mut owner, &lab);
            let Some(Completion::Added(Some(entry))) = owner.take_completion().unwrap() else {
                panic!()
            };
            assert_eq!(entry.index, expected);
            last = Some(entry);
        }
        assert_eq!(last.unwrap().index, 1023);
        assert!(owner.begin_add(configuration(8), &[0x62], None).is_err());
        assert_eq!(lab.borrow().wire.len(), words);
    }

    #[test]
    fn descriptor_write_resumes_only_unapplied_bytes_and_callback_resource_does_not_reenter() {
        let (mut owner, lab) = initialized();
        owner
            .begin_add(configuration(1), &[1, 2, 3, 4], None)
            .unwrap();
        lab.borrow_mut().copy_steps.push_back(Outcome::Prefix);
        loop {
            if let Err(reason) = step(&mut owner, &lab) {
                assert_eq!(reason, "actual write prefix retained");
                break;
            }
        }
        let temporary = owner.temporary.as_ref().unwrap().clone();
        let bus = owner.memory.mapping(&temporary).unwrap().geometry().bus;
        lab.borrow().objects[&bus].borrow_mut().data[0] = 0xee;
        run(&mut owner, &lab);
        assert_eq!(lab.borrow().headers[0][0], 0xee);
        assert!(owner.take_completion().unwrap().is_some());

        let capture = Rc::new(RefCell::new(Capture {
            accepted: true,
            steps: VecDeque::from([Outcome::Busy]),
            ..Capture::default()
        }));
        let entry = added(
            &mut owner,
            &lab,
            &[1, 2, 3, 4],
            Some(Box::new(NativeCallback(capture.clone()))),
        );
        owner.begin_set(&entry, &[5, 6, 7, 8]).unwrap();
        loop {
            step(&mut owner, &lab).unwrap();
            if !capture.borrow().calls.is_empty() {
                break;
            }
        }
        assert!(owner.plan.as_ref().unwrap().callback_active);
        lab.borrow().incoming.as_ref().unwrap().borrow_mut().data[..4]
            .copy_from_slice(&[10, 11, 12, 13]);
        owner
            .receive(0x0046_0000_0000_0000 | entry.index as u64)
            .unwrap();
        run(&mut owner, &lab);
        let c = capture.borrow();
        assert_eq!(c.calls.len(), 3);
        assert!(c.calls[0].same_operation(&c.calls[1]));
        assert!(!c.calls[1].same_operation(&c.calls[2]));
        assert_eq!(lab.borrow().acks.last(), Some(&4));
    }
}
