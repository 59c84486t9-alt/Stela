//! Native class1 AP-memory client. Original PMP25d34..25ea4,3a3f8..3a540,
//! 3c6fc..3ca18 and ApplePMPv2 memory handlers retain the contracts below.
//! A wire reply is not local mapping authority. The backend must retain the
//! actual canonical RAM/DMA mapping and retire each real map/unmap operation.
use super::{Progress, Step};
use crate::platform::apple::bus::Access;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;

mod regions;
mod wire;
pub use regions::Region;
use wire::{Kind, PAGE, TABLE_BYTES};

type Error = &'static str;

/// Unique admission to the actual native owner's class1 callback/mutex slot.
/// No Clone, reset, replacement or drop-time remote cleanup is provided.
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
            Err("PMP native memory owner was abandoned")
        }
    }
}

/// Exact original native4ab08 inputs. Mode2 is retained as a source encoding;
/// it does not assert an unqualified cacheability or access-permission meaning.
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

/// An actual retained mapping, not an IOVA or copied region-table row. Reads
/// and writes must use that mapping's live canonical resource and original
/// fault/prefix semantics; dropping it must not pretend to unmap/free remotely.
pub trait Mapping {
    fn geometry(&self) -> MapRequest;
    fn read(
        &mut self,
        offset: u64,
        output: &mut [u8],
        access: &mut Access<'_>,
    ) -> Result<(), Error>;
    fn write(&mut self, offset: u64, input: &[u8], access: &mut Access<'_>) -> Result<(), Error>;
}
pub enum MapStep<M> {
    Busy { deadline: Option<u64> },
    Retired { mapping: M, refusal: Option<Error> },
    Refused(Error),
}
/// Backend effects remain under the same request through Busy/refusal. Map
/// refusal may not discard a published mapping; return Retired with its actual
/// object instead. Unmap retirement requires actual local mapping removal,
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
/// and its retained allocation record. Dropping a handle does not free memory.
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
    /// None is the actual AP zero-address failure, distinct from a read empty
    /// table. Table descriptors are retained separately, never dynamic-freed.
    Initialized(Option<Vec<Region>>),
    Allocated(Option<Allocation>),
    Freed(Allocation),
}

/// One native class transaction at a time, as original3a3f8's class mutex and
/// saved callback slot require. There is no wire nonce: transport must retain
/// the same ordered actual endpoint session. A replay matching a later same-
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
    pub fn new(claim: Claim, backend: B) -> Result<Self, Error> {
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
    fn begin(&mut self, operation: Operation) -> Result<(), Error> {
        self.claim.check()?;
        if self.pending.is_some() || self.completion.is_some() {
            return Err("PMP memory callback slot still retains a transaction or result");
        }
        let serial = self
            .serial
            .checked_add(1)
            .ok_or("PMP memory transaction identity exhausted")?;
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
    pub fn begin_init(&mut self) -> Result<(), Error> {
        if self.initialized {
            return Err("PMP static memory table initialization already completed");
        }
        self.begin(Operation::Init)
    }
    pub fn begin_allocate(&mut self, bytes: u32) -> Result<(), Error> {
        self.begin(Operation::Allocate {
            requested: u64::from(bytes),
            rounded: wire::allocation_bytes(bytes)?,
        })
    }
    fn index(&self, allocation: &Allocation) -> Result<usize, Error> {
        self.claim.check()?;
        if !Rc::ptr_eq(&allocation.owner, &self.claim.owner) {
            return Err("PMP allocation belongs to another actual native owner");
        }
        self.allocations
            .iter()
            .position(|r| Rc::ptr_eq(&r.object, &allocation.object))
            .ok_or("PMP allocation is not retained by this actual client")
    }
    pub fn begin_free(&mut self, allocation: &Allocation) -> Result<(), Error> {
        let index = self.index(allocation)?;
        self.begin(Operation::Free { index })?;
        if self.allocations[index].released {
            self.pending = None;
            self.completion = Some(Completion::Freed(allocation.clone()));
        }
        Ok(())
    }
    /// Commit a request exactly once to the actual endpoint's outgoing queue.
    /// Free is withheld until real local unmap retirement. No callback is
    /// credited before publication, and no fallible work follows this push.
    pub fn emit(&mut self, outbox: &mut Vec<u64>) -> Result<bool, Error> {
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
    pub fn receive(&mut self, payload: u64) -> Result<(), Error> {
        self.claim.check()?;
        let p = self
            .pending
            .as_mut()
            .ok_or("PMP memory reply has no pending class callback")?;
        if !p.sent || p.reply.is_some() {
            return Err("PMP memory reply is premature or repeats a retained reply");
        }
        let body = p.kind().reply(payload)?;
        p.reply = Some(body);
        Ok(())
    }
    pub fn take_completion(&mut self) -> Result<Option<Completion>, Error> {
        self.claim.check()?;
        Ok(self.completion.take())
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    fn usable(
        &mut self,
        allocation: &Allocation,
        offset: u64,
        bytes: usize,
    ) -> Result<&mut B::Mapping, Error> {
        let index = self.index(allocation)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| matches!(p.operation,Operation::Free { index: i } if i == index))
        {
            return Err("PMP allocation is being released");
        }
        let r = &mut self.allocations[index];
        if r.released
            || offset
                .checked_add(
                    u64::try_from(bytes).map_err(|_| "PMP memory access length exceeds u64")?,
                )
                .is_none_or(|end| end > r.requested)
        {
            return Err("PMP memory access exceeds its live requested allocation");
        }
        r.mapping
            .as_mut()
            .ok_or("PMP allocation has no actual local mapping")
    }
    pub fn read(
        &mut self,
        allocation: &Allocation,
        offset: u64,
        output: &mut [u8],
        access: &mut Access<'_>,
    ) -> Result<(), Error> {
        self.usable(allocation, offset, output.len())?
            .read(offset, output, access)
    }
    pub fn write(
        &mut self,
        allocation: &Allocation,
        offset: u64,
        input: &[u8],
        access: &mut Access<'_>,
    ) -> Result<(), Error> {
        self.usable(allocation, offset, input.len())?
            .write(offset, input, access)
    }
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
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
                    .ok_or("PMP free lost its actual local mapping")?;
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
                    return Err(
                        "PMP backend returned a mismatched mapping; actual object remains quarantined",
                    );
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
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    use alloc::{collections::VecDeque, vec};
    struct Mapped {
        geometry: MapRequest,
        bytes: Vec<u8>,
        fail_read: bool,
    }
    impl Mapping for Mapped {
        fn geometry(&self) -> MapRequest {
            self.geometry
        }
        fn read(
            &mut self,
            offset: u64,
            output: &mut [u8],
            _: &mut Access<'_>,
        ) -> Result<(), Error> {
            if self.fail_read {
                self.fail_read = false;
                return Err("actual RAM read fault");
            }
            let at = usize::try_from(offset).unwrap();
            output.copy_from_slice(&self.bytes[at..at + output.len()]);
            Ok(())
        }
        fn write(&mut self, offset: u64, input: &[u8], _: &mut Access<'_>) -> Result<(), Error> {
            let at = usize::try_from(offset).unwrap();
            self.bytes[at..at + input.len()].copy_from_slice(input);
            Ok(())
        }
    }
    #[derive(Clone, Copy)]
    enum Outcome {
        Busy,
        Refuse,
        Retire,
        RetireRefuse,
    }
    struct Backing {
        maps: Vec<Request>,
        unmaps: Vec<Request>,
        map_steps: VecDeque<Outcome>,
        unmap_steps: VecDeque<Outcome>,
        table: Vec<u8>,
        fail_read: bool,
        bad_geometry: bool,
    }
    impl Backing {
        fn new() -> Self {
            Self {
                maps: Vec::new(),
                unmaps: Vec::new(),
                map_steps: VecDeque::new(),
                unmap_steps: VecDeque::new(),
                table: vec![0; 4096],
                fail_read: false,
                bad_geometry: false,
            }
        }
    }
    impl Backend for Backing {
        type Mapping = Mapped;
        fn map(
            &mut self,
            request: &Request,
            mut geometry: MapRequest,
            _: &mut Access<'_>,
        ) -> MapStep<Mapped> {
            self.maps.push(request.clone());
            match self.map_steps.pop_front().unwrap_or(Outcome::Retire) {
                Outcome::Busy => MapStep::Busy { deadline: Some(11) },
                Outcome::Refuse => MapStep::Refused("actual mapping unavailable"),
                value => {
                    if self.bad_geometry {
                        geometry.bus += PAGE;
                    }
                    let mut bytes = vec![0; usize::try_from(geometry.bytes).unwrap()];
                    if bytes.len() >= self.table.len() {
                        bytes[..self.table.len()].copy_from_slice(&self.table);
                    }
                    MapStep::Retired {
                        mapping: Mapped {
                            geometry,
                            bytes,
                            fail_read: core::mem::take(&mut self.fail_read),
                        },
                        refusal: matches!(value, Outcome::RetireRefuse)
                            .then_some("post-map refusal"),
                    }
                }
            }
        }
        fn unmap(&mut self, request: &Request, _: &mut Mapped, _: &mut Access<'_>) -> Step {
            self.unmaps.push(request.clone());
            match self.unmap_steps.pop_front().unwrap_or(Outcome::Retire) {
                Outcome::Busy => Step::Busy { deadline: Some(12) },
                Outcome::Refuse => Step::Refused("actual unmap unavailable"),
                value => Step::Retired {
                    refusal: matches!(value, Outcome::RetireRefuse).then_some("post-unmap refusal"),
                },
            }
        }
    }
    fn client(backing: Backing) -> Client<Backing> {
        Client::new(Claim::new(Rc::new(()), Rc::new(Cell::new(true))), backing).unwrap()
    }
    fn advance(c: &mut Client<Backing>) -> Result<Progress, Error> {
        c.advance(&mut Access::new(0, 5, &mut InterruptLatch::new()))
    }
    fn allocated(c: &mut Client<Backing>, bus: u64) -> Allocation {
        c.begin_allocate(5000).unwrap();
        let mut out = Vec::new();
        assert!(c.emit(&mut out).unwrap());
        assert_eq!(out, [0x0012_0000_0000_2000]);
        c.receive(0x0013_0000_0000_0000 | bus).unwrap();
        advance(c).unwrap();
        match c.take_completion().unwrap().unwrap() {
            Completion::Allocated(Some(a)) => a,
            _ => panic!("expected actual mapping"),
        }
    }
    #[test]
    fn shared_slot_reply_and_outgoing_prefix_survive_busy_and_refusal() {
        let mut backend = Backing::new();
        backend.map_steps = VecDeque::from([Outcome::Busy, Outcome::Refuse, Outcome::RetireRefuse]);
        let mut c = client(backend);
        c.begin_allocate(5000).unwrap();
        assert!(c.begin_init().is_err());
        assert!(c.receive(0x0013_0000_0000_4000).is_err());
        let mut out = Vec::new();
        c.emit(&mut out).unwrap();
        for wrong in [
            0x0011_0000_0000_4000,
            0x0015_0000_0000_0000,
            0x0113_0000_0000_4000,
            0x0013_0000_0000_4001,
        ] {
            assert!(c.receive(wrong).is_err());
        }
        c.receive(0x0013_0000_0000_4000).unwrap();
        for duplicate in [0x0013_0000_0000_4000, 0x0013_0000_0000_8000] {
            assert!(c.receive(duplicate).is_err());
        }
        assert_eq!(advance(&mut c), Ok(Progress::Busy { deadline: Some(11) }));
        assert!(advance(&mut c).is_err());
        assert_eq!(advance(&mut c), Err("post-map refusal"));
        assert!(!c.emit(&mut out).unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(c.backend.maps.len(), 3);
        assert!(
            c.backend
                .maps
                .windows(2)
                .all(|r| r[0].same_operation(&r[1]))
        );
        advance(&mut c).unwrap();
        assert_eq!(c.backend.maps.len(), 3);
        assert!(c.begin_allocate(1).is_err());
        let allocation = match c.take_completion().unwrap().unwrap() {
            Completion::Allocated(Some(a)) => a,
            _ => panic!(),
        };
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 6, &mut latch);
        c.write(&allocation, 4999, &[0x72], &mut a).unwrap();
        let mut value = [0];
        c.read(&allocation, 4999, &mut value, &mut a).unwrap();
        assert_eq!(value, [0x72]);
        assert!(c.write(&allocation, 5000, &[1], &mut a).is_err());
        assert!(c.read(&allocation, u64::MAX, &mut value, &mut a).is_err());
        assert!(c.receive(0x0013_0000_0000_4000).is_err());
    }
    #[test]
    fn local_unmap_retires_before_wire_free_and_equal_bus_reuse_has_new_identity() {
        let mut backing = Backing::new();
        backing.unmap_steps =
            VecDeque::from([Outcome::Busy, Outcome::Refuse, Outcome::RetireRefuse]);
        let mut c = client(backing);
        let first = allocated(&mut c, 0x4000);
        c.begin_free(&first).unwrap();
        let mut out = Vec::new();
        assert!(!c.emit(&mut out).unwrap());
        assert_eq!(advance(&mut c), Ok(Progress::Busy { deadline: Some(12) }));
        assert!(advance(&mut c).is_err());
        assert!(!c.emit(&mut out).unwrap());
        assert_eq!(advance(&mut c), Err("post-unmap refusal"));
        assert!(c.emit(&mut out).unwrap());
        assert_eq!(out, [0x0014_0000_0000_4000]);
        assert!(!c.emit(&mut out).unwrap());
        assert!(
            c.read(
                &first,
                0,
                &mut [0],
                &mut Access::new(0, 0, &mut InterruptLatch::new())
            )
            .is_err()
        );
        assert!(
            c.backend
                .unmaps
                .windows(2)
                .all(|r| r[0].same_operation(&r[1]))
        );
        assert_eq!(c.backend.unmaps[0].effect(), Effect::Unmap);
        assert!(!c.backend.maps[0].same_operation(&c.backend.unmaps[0]));
        assert!(c.receive(0x0015_0000_0000_4000).is_err());
        c.receive(0x0015_0000_0000_0000).unwrap();
        advance(&mut c).unwrap();
        assert_eq!(c.backend.unmaps.len(), 3);
        assert!(matches!(
            c.take_completion().unwrap(),
            Some(Completion::Freed(_))
        ));
        let second = allocated(&mut c, 0x4000);
        assert!(!Rc::ptr_eq(&first.object, &second.object));
        c.begin_free(&first).unwrap();
        assert!(!c.emit(&mut out).unwrap());
        assert!(matches!(
            c.take_completion().unwrap(),
            Some(Completion::Freed(_))
        ));
        let mut foreign = client(Backing::new());
        assert!(foreign.begin_free(&second).is_err());
        assert!(
            c.read(
                &first,
                0,
                &mut [0],
                &mut Access::new(0, 0, &mut InterruptLatch::new())
            )
            .is_err()
        );
        c.read(
            &second,
            0,
            &mut [0],
            &mut Access::new(0, 0, &mut InterruptLatch::new()),
        )
        .unwrap();
    }
    #[test]
    fn static_table_is_actual_read_prefix_not_mapping_authority_or_dynamic_allocation() {
        let mut backing = Backing::new();
        backing.fail_read = true;
        backing.table[..8].copy_from_slice(&0x8000_0000u64.to_le_bytes());
        backing.table[8..16].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        backing.table[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        let mut c = client(backing);
        c.begin_init().unwrap();
        let mut out = Vec::new();
        c.emit(&mut out).unwrap();
        assert_eq!(out, [0x0010_0000_0000_0000]);
        c.receive(0x0011_0000_0000_1000).unwrap();
        assert_eq!(advance(&mut c), Err("actual RAM read fault"));
        assert!(c.table.is_none());
        advance(&mut c).unwrap();
        assert_eq!(c.backend.maps.len(), 1);
        assert_eq!(c.backend.unmaps.len(), 0);
        assert!(c.table.is_some());
        let regions = match c.take_completion().unwrap().unwrap() {
            Completion::Initialized(Some(r)) => r,
            _ => panic!(),
        };
        assert_eq!(
            regions,
            [Region {
                physical: 0x8000_0000,
                bus: 0x1_8000_0000,
                bytes: 0x2000
            }]
        );
        assert!(c.begin_init().is_err());
        assert_eq!(c.allocations.len(), 0);
        assert_eq!(
            c.table.as_ref().unwrap().geometry(),
            MapRequest {
                bus: 0x1000,
                bytes: 4096,
                source_mode: 2
            }
        );
    }
    #[test]
    fn actual_zero_reply_and_read_empty_table_are_distinct_and_abandonment_does_not_cleanup() {
        for bus in [0, 0x1000] {
            let mut c = client(Backing::new());
            c.begin_init().unwrap();
            c.emit(&mut Vec::new()).unwrap();
            c.receive(0x0011_0000_0000_0000 | bus).unwrap();
            advance(&mut c).unwrap();
            match c.take_completion().unwrap().unwrap() {
                Completion::Initialized(value) => {
                    assert_eq!(value, if bus == 0 { None } else { Some(Vec::new()) })
                }
                _ => panic!(),
            }
            assert_eq!(c.backend.maps.len(), usize::from(bus != 0));
        }
        let mut c = client(Backing::new());
        c.begin_allocate(0).unwrap();
        c.emit(&mut Vec::new()).unwrap();
        c.receive(0x0013_0000_0000_0000).unwrap();
        advance(&mut c).unwrap();
        assert!(matches!(
            c.take_completion().unwrap(),
            Some(Completion::Allocated(None))
        ));
        assert!(c.backend.maps.is_empty());
        let allocation = allocated(&mut c, 0x4000);
        c.claim.alive.set(false);
        assert!(c.begin_free(&allocation).is_err());
        assert!(c.emit(&mut Vec::new()).is_err());
        assert!(advance(&mut c).is_err());
        assert!(c.receive(0x0015_0000_0000_0000).is_err());
        assert!(c.take_completion().is_err());
        assert!(c.allocations[0].mapping.is_some());
        assert!(c.backend.unmaps.is_empty());
    }
    #[test]
    fn bad_backend_geometry_is_retained_and_never_credited_or_replayed() {
        let mut backing = Backing::new();
        backing.bad_geometry = true;
        let mut c = client(backing);
        c.begin_allocate(1).unwrap();
        c.emit(&mut Vec::new()).unwrap();
        c.receive(0x0013_0000_0000_4000).unwrap();
        for _ in 0..2 {
            assert!(advance(&mut c).is_err());
        }
        assert_eq!(c.backend.maps.len(), 1);
        assert!(c.pending.as_ref().unwrap().mapping.is_some());
        assert!(c.take_completion().unwrap().is_none());
        assert!(
            c.begin_free(&Allocation {
                owner: c.claim.owner.clone(),
                object: Rc::new(())
            })
            .is_err()
        );
    }
}
