//! Native class1 AP-memory client. Original PMP25d34..25ea4,3a3f8..3a540,
//! 3c6fc..3ca18 and ApplePMPv2 memory handlers keep the contracts below.
//! A wire reply is not local mapping permission. The backend must keep the
//! canonical RAM/DMA mapping and retire each real map/unmap operation.
use super::{Progress, Step};
use crate::Result;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;
use stela_contracts::Refusal;
use stela_contracts::bus::Access;
use stela_contracts::refuse;

mod regions;
mod wire;
pub use regions::Region;
use wire::{Kind, PAGE, TABLE_BYTES};

/// Unique admission to the native owner's class1 callback/mutex slot.
/// No Clone, reset, replacement or drop-time remote cleanup is provided.
pub struct Claim {
    owner: Rc<()>,
    alive: Rc<Cell<bool>>,
}
impl Claim {
    pub(super) fn new(owner: Rc<()>, alive: Rc<Cell<bool>>) -> Self {
        Self { owner, alive }
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.alive.get() {
            Ok(())
        } else {
            Err(refuse!("PMP native memory owner was abandoned"))
        }
    }
}

/// Original native4ab08 inputs. Mode2 is held as a source encoding;
/// it does not assert an unchecked cacheability or access-permission meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapRequest {
    pub bus: u64,
    pub bytes: u64,
    pub source_mode: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Map,
    Unmap,
}
#[derive(Clone)]
pub struct Request {
    owner: Rc<()>,
    serial: u64,
    effect: Effect,
}
impl Request {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.serial == other.serial
            && self.effect == other.effect
    }
    pub fn effect(&self) -> Effect {
        self.effect
    }
}

/// A kept mapping, not an IOVA or copied region-table row. Reads
/// and writes must use that mapping's live canonical resource and original
/// fault/prefix semantics; dropping it must not pretend to unmap/free remotely.
pub trait Mapping {
    fn geometry(&self) -> MapRequest;
    fn read(&mut self, offset: u64, output: &mut [u8], access: &mut Access<'_>) -> Result<()>;
    fn write(&mut self, offset: u64, input: &[u8], access: &mut Access<'_>) -> Result<()>;
}
pub enum MapStep<M> {
    Busy {
        deadline: Option<u64>,
    },
    Retired {
        mapping: M,
        refusal: Option<Refusal>,
    },
    Refused(Refusal),
}
/// Backend effects remain under the same request through Busy/refusal. Map
/// refusal may not discard a published mapping; return Retired with its
/// object instead. Unmap retirement requires local mapping removal,
/// preceding the AP free request, never an enqueued unmap command.
pub trait Backend {
    type Mapping: Mapping;
    fn map(
        &mut self,
        request: &Request,
        geometry: MapRequest,
        access: &mut Access<'_>,
    ) -> MapStep<Self::Mapping>;
    fn unmap(
        &mut self,
        request: &Request,
        mapping: &mut Self::Mapping,
        access: &mut Access<'_>,
    ) -> Step;
}

/// Identity survives bus-address reuse. Access requires this same live client
/// and its allocation record. Dropping a handle does not free memory.
#[derive(Clone)]
pub struct Allocation {
    owner: Rc<()>,
    object: Rc<()>,
}
struct Record<M> {
    object: Rc<()>,
    requested: u64,
    bus: u64,
    mapping: Option<M>,
    released: bool,
}
enum Operation {
    Init,
    Allocate { requested: u64, rounded: u64 },
    Free { index: usize },
}
struct Pending<M> {
    operation: Operation,
    request: Request,
    sent: bool,
    reply: Option<u64>,
    mapping: Option<M>,
    unmapped: bool,
}
impl<M> Pending<M> {
    fn kind(&self) -> Kind {
        match self.operation {
            Operation::Init => Kind::Init,
            Operation::Allocate { .. } => Kind::Allocate,
            Operation::Free { .. } => Kind::Free,
        }
    }
    fn geometry(&self) -> MapRequest {
        let bytes = match self.operation {
            Operation::Allocate { rounded, .. } => rounded,
            _ => PAGE,
        };
        MapRequest {
            bus: self.reply.unwrap(),
            bytes,
            source_mode: 2,
        }
    }
}

pub enum Completion {
    /// None is the AP zero-address failure, distinct from a read empty
    /// table. Table descriptors are held separately, never dynamic-freed.
    Initialized(Option<Vec<Region>>),
    Allocated(Option<Allocation>),
    Freed(Allocation),
}

/// One native class transaction at a time, as original3a3f8's class mutex and
/// saved callback slot require. There is no wire nonce: transport must keep
/// the same ordered endpoint session. A replay matching a later same-
/// kind request is wire-indistinguishable and cannot be authenticated here.
pub struct Client<B: Backend> {
    claim: Claim,
    backend: B,
    serial: u64,
    pending: Option<Pending<B::Mapping>>,
    completion: Option<Completion>,
    initialized: bool,
    table: Option<B::Mapping>,
    allocations: Vec<Record<B::Mapping>>,
}
impl<B: Backend> Client<B> {
    pub fn new(claim: Claim, backend: B) -> Result<Self> {
        claim.check()?;
        Ok(Self {
            claim,
            backend,
            serial: 0,
            pending: None,
            completion: None,
            initialized: false,
            table: None,
            allocations: Vec::new(),
        })
    }
    fn begin(&mut self, operation: Operation) -> Result<()> {
        self.claim.check()?;
        if self.pending.is_some() || self.completion.is_some() {
            return Err(refuse!(
                "PMP memory callback slot still retains a transaction or result"
            ));
        }
        let serial = self
            .serial
            .checked_add(1)
            .ok_or(refuse!("PMP memory transaction identity exhausted"))?;
        self.serial = serial;
        self.pending = Some(Pending {
            operation,
            request: Request {
                owner: self.claim.owner.clone(),
                serial,
                effect: Effect::Map,
            },
            sent: false,
            reply: None,
            mapping: None,
            unmapped: false,
        });
        Ok(())
    }
    pub fn begin_init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(refuse!(
                "PMP static memory table initialization already completed"
            ));
        }
        self.begin(Operation::Init)
    }
    pub fn begin_allocate(&mut self, bytes: u32) -> Result<()> {
        self.begin(Operation::Allocate {
            requested: u64::from(bytes),
            rounded: wire::allocation_bytes(bytes)?,
        })
    }
    fn index(&self, allocation: &Allocation) -> Result<usize> {
        self.claim.check()?;
        if !Rc::ptr_eq(&allocation.owner, &self.claim.owner) {
            return Err(refuse!(
                "PMP allocation belongs to another actual native owner"
            ));
        }
        self.allocations
            .iter()
            .position(|r| Rc::ptr_eq(&r.object, &allocation.object))
            .ok_or(refuse!(
                "PMP allocation is not retained by this actual client"
            ))
    }
    pub fn begin_free(&mut self, allocation: &Allocation) -> Result<()> {
        let index = self.index(allocation)?;
        self.begin(Operation::Free { index })?;
        if self.allocations[index].released {
            self.pending = None;
            self.completion = Some(Completion::Freed(allocation.clone()));
        }
        Ok(())
    }
    /// Commit a request exactly once to the endpoint's outgoing queue.
    /// Free is withheld until real local unmap retirement. No callback is
    /// credited before publication, and no fallible work follows this push.
    pub fn emit(&mut self, outbox: &mut Vec<u64>) -> Result<bool> {
        self.claim.check()?;
        let Some(p) = &mut self.pending else {
            return Ok(false);
        };
        if p.sent {
            return Ok(false);
        }
        let body = match p.operation {
            Operation::Init => 0,
            Operation::Allocate { rounded, .. } => rounded,
            Operation::Free { index } => {
                if !p.unmapped {
                    return Ok(false);
                }
                self.allocations[index].bus
            }
        };
        outbox.push(p.kind().request(body));
        p.sent = true;
        Ok(true)
    }
    pub fn receive(&mut self, payload: u64) -> Result<()> {
        self.claim.check()?;
        let p = self
            .pending
            .as_mut()
            .ok_or(refuse!("PMP memory reply has no pending class callback"))?;
        if !p.sent || p.reply.is_some() {
            return Err(refuse!(
                "PMP memory reply is premature or repeats a retained reply"
            ));
        }
        let body = p.kind().reply(payload)?;
        p.reply = Some(body);
        Ok(())
    }
    pub fn take_completion(&mut self) -> Result<Option<Completion>> {
        self.claim.check()?;
        Ok(self.completion.take())
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub(super) fn owns(&self, owner: &Rc<()>) -> bool {
        Rc::ptr_eq(&self.claim.owner, owner)
    }
    pub(super) fn fresh(&self) -> bool {
        self.serial == 0
    }
    pub(super) fn mapping(&mut self, allocation: &Allocation) -> Result<&mut B::Mapping> {
        self.usable(allocation, 0, 0)
    }
    fn usable(
        &mut self,
        allocation: &Allocation,
        offset: u64,
        bytes: usize,
    ) -> Result<&mut B::Mapping> {
        let index = self.index(allocation)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| matches!(p.operation,Operation::Free { index: i } if i == index))
        {
            return Err(refuse!("PMP allocation is being released"));
        }
        let r = &mut self.allocations[index];
        if r.released
            || offset
                .checked_add(
                    u64::try_from(bytes)
                        .map_err(|_| refuse!("PMP memory access length exceeds u64"))?,
                )
                .is_none_or(|end| end > r.requested)
        {
            return Err(refuse!(
                "PMP memory access exceeds its live requested allocation"
            ));
        }
        r.mapping
            .as_mut()
            .ok_or(refuse!("PMP allocation has no actual local mapping"))
    }
    pub fn read(
        &mut self,
        allocation: &Allocation,
        offset: u64,
        output: &mut [u8],
        access: &mut Access<'_>,
    ) -> Result<()> {
        self.usable(allocation, offset, output.len())?
            .read(offset, output, access)
    }
    pub fn write(
        &mut self,
        allocation: &Allocation,
        offset: u64,
        input: &[u8],
        access: &mut Access<'_>,
    ) -> Result<()> {
        self.usable(allocation, offset, input.len())?
            .write(offset, input, access)
    }
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress> {
        self.claim.check()?;
        let Some(p) = &mut self.pending else {
            return Ok(Progress::Idle);
        };
        if let Operation::Free { index } = p.operation {
            if !p.unmapped {
                p.request.effect = Effect::Unmap;
                let mapping = self.allocations[index]
                    .mapping
                    .as_mut()
                    .ok_or(refuse!("PMP free lost its actual local mapping"))?;
                match self.backend.unmap(&p.request, mapping, access) {
                    Step::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                    Step::Refused(reason) => return Err(reason),
                    Step::Retired { refusal } => {
                        self.allocations[index].mapping = None;
                        p.unmapped = true;
                        if let Some(reason) = refusal {
                            return Err(reason);
                        }
                    }
                }
            }
            if p.reply.is_none() {
                return Ok(Progress::Busy { deadline: None });
            }
            self.allocations[index].released = true;
            self.completion = Some(Completion::Freed(Allocation {
                owner: self.claim.owner.clone(),
                object: self.allocations[index].object.clone(),
            }));
        } else {
            let Some(bus) = p.reply else {
                return Ok(Progress::Busy { deadline: None });
            };
            if bus == 0 {
                match p.operation {
                    Operation::Init => {
                        self.initialized = true;
                        self.completion = Some(Completion::Initialized(None));
                    }
                    Operation::Allocate { .. } => {
                        self.completion = Some(Completion::Allocated(None))
                    }
                    Operation::Free { .. } => unreachable!(),
                }
            } else {
                let geometry = p.geometry();
                if p.mapping.is_none() {
                    match self.backend.map(&p.request, geometry, access) {
                        MapStep::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                        MapStep::Refused(reason) => return Err(reason),
                        MapStep::Retired { mapping, refusal } => {
                            p.mapping = Some(mapping);
                            if let Some(reason) = refusal {
                                return Err(reason);
                            }
                        }
                    }
                }
                let mapping = p.mapping.as_mut().unwrap();
                if mapping.geometry() != geometry {
                    return Err(refuse!(
                        "PMP backend returned a mismatched mapping; actual object remains quarantined"
                    ));
                }
                match p.operation {
                    Operation::Init => {
                        let mut bytes = [0; TABLE_BYTES];
                        mapping.read(0, &mut bytes, access)?;
                        let regions = regions::parse(&bytes);
                        self.table = p.mapping.take();
                        self.initialized = true;
                        self.completion = Some(Completion::Initialized(Some(regions)));
                    }
                    Operation::Allocate { requested, .. } => {
                        let object = Rc::new(());
                        let allocation = Allocation {
                            owner: self.claim.owner.clone(),
                            object: object.clone(),
                        };
                        self.allocations.push(Record {
                            object,
                            requested,
                            bus,
                            mapping: p.mapping.take(),
                            released: false,
                        });
                        self.completion = Some(Completion::Allocated(Some(allocation)));
                    }
                    Operation::Free { .. } => unreachable!(),
                }
            }
        }
        self.pending = None;
        Ok(Progress::Idle)
    }
}

#[cfg(test)]
mod tests;
