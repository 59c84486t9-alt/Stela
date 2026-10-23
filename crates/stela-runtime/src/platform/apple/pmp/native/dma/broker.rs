use super::super::{platform::owner::Completion, reporting, trace};
use super::{
    mapping::{Client, ReportingMapping, TraceMapping},
    service::Service,
};
use crate::platform::dma::{DmaError, TransferFault};
use alloc::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    vec::Vec,
};
use core::cell::RefCell;

/// Placement selected by the actual device dispatcher. Numeric topology does
/// not authorize a substitute Port: Owners must name the same actual objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub mapper: u32,
    pub iommu: usize,
    pub instance: usize,
    pub context: u32,
    pub stream: usize,
}
/// Root retains these identities with the actual DART, canonical registered
/// RAM generation and AP allocator/session. They are not host pointer exports.
#[derive(Clone)]
pub struct Owners {
    pub dart: Rc<()>,
    pub canonical_ram: Rc<()>,
    pub allocator: Rc<()>,
}
impl Owners {
    pub(super) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.dart, &other.dart)
            && Rc::ptr_eq(&self.canonical_ram, &other.canonical_ram)
            && Rc::ptr_eq(&self.allocator, &other.allocator)
    }
}
/// Explicit qualified software/configuration inputs; no default or tag guess.
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    pub mapper_index: u32,
    pub asc_dram_mask: u64,
    pub synchronization_granule: u64,
}
/// Native mapping descriptor/grant, not an AP allocation or cached PA. Its
/// lifetime never claims that guest DART tables remain unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub(super) id: u64,
    pub iova: u64,
    pub bytes: u64,
    pub flags: u32,
    pub route: Route,
}
impl Descriptor {
    pub fn identity(&self) -> u64 {
        self.id
    }
}
#[derive(Clone, Debug)]
pub struct ServiceRequest {
    pub(super) owner: Rc<()>,
    pub(super) serial: u64,
}
impl ServiceRequest {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner) && self.serial == other.serial
    }
}
#[derive(Clone)]
pub(super) enum Key {
    Reporting(reporting::resources::Request),
    Trace(trace::Request),
    #[cfg(test)]
    Authored(Rc<()>),
}
impl Key {
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Reporting(a), Self::Reporting(b)) => a.same_operation(b),
            (Self::Trace(a), Self::Trace(b)) => a.same_operation(b),
            #[cfg(test)]
            (Self::Authored(a), Self::Authored(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Life {
    Mapped,
    Unmapped,
    Released,
}
pub(super) struct Grant {
    pub descriptor: Descriptor,
    pub life: Life,
}
pub(super) enum Op {
    Map(Descriptor),
    Read {
        descriptor: Descriptor,
        offset: u64,
        bytes: usize,
    },
    Write {
        descriptor: Descriptor,
        offset: u64,
        bytes: Vec<u8>,
    },
    Effect {
        descriptor: Descriptor,
        effect: super::service::Effect,
    },
}
pub(super) struct Job {
    pub request: ServiceRequest,
    pub op: Op,
    pub checked: bool,
}
pub(super) enum Output {
    Mapped(Descriptor),
    Read {
        bytes: Vec<u8>,
        fault: Option<TransferFault>,
    },
    Written {
        completed: usize,
        fault: Option<TransferFault>,
    },
    Unit,
}
pub(super) struct Reply {
    pub output: Output,
    pub refusal: Option<&'static str>,
}
pub(super) struct MapAttempt {
    key: Key,
    descriptor: Descriptor,
    ticket: Option<u64>,
    returned: bool,
}
pub(super) struct State {
    pub identity: Rc<()>,
    pub owners: Owners,
    pub route: Route,
    pub configuration: Configuration,
    pub serial: u64,
    pub queue: VecDeque<Job>,
    pub replies: BTreeMap<u64, Completion<Reply>>,
    pub grants: BTreeMap<u64, Grant>,
    pub dispatching: bool,
    pub alive: bool,
    maps: Vec<MapAttempt>,
}
#[derive(Clone)]
pub struct Broker {
    pub(super) state: Rc<RefCell<State>>,
}
/// Pairing is performed by the root's actual device/resource composition.
/// Neither endpoint can be replaced by a successful absent dispatcher.
pub fn pair(
    route: Route,
    owners: Owners,
    configuration: Configuration,
) -> Result<(Broker, Service), &'static str> {
    if route.mapper == 0
        || configuration.mapper_index != 0
        || configuration.asc_dram_mask != 0
        || !configuration.synchronization_granule.is_power_of_two()
    {
        return Err("native PMP DMA needs a qualified actual mapper and zero-mask configuration");
    }
    let state = Rc::new(RefCell::new(State {
        identity: Rc::new(()),
        owners,
        route,
        configuration,
        serial: 0,
        queue: VecDeque::new(),
        replies: BTreeMap::new(),
        grants: BTreeMap::new(),
        dispatching: false,
        alive: true,
        maps: Vec::new(),
    }));
    Ok((
        Broker {
            state: state.clone(),
        },
        Service::new(state),
    ))
}
impl Broker {
    pub fn route(&self) -> Route {
        self.state.borrow().route
    }
    pub fn synchronization_granule(&self) -> u64 {
        self.state.borrow().configuration.synchronization_granule
    }
    pub(super) fn enqueue(&self, op: Op) -> Result<u64, &'static str> {
        let mut state = self.state.borrow_mut();
        if !state.alive {
            return Err("native PMP DMA dispatcher was abandoned");
        }
        let serial = state
            .serial
            .checked_add(1)
            .ok_or("native PMP DMA request identity exhausted")?;
        state.serial = serial;
        let request = ServiceRequest {
            owner: state.identity.clone(),
            serial,
        };
        state.queue.push_back(Job {
            request,
            op,
            checked: false,
        });
        Ok(serial)
    }
    pub(super) fn reply(&self, ticket: u64) -> Result<Option<Completion<Reply>>, &'static str> {
        let mut state = self.state.borrow_mut();
        if !state.alive {
            return Err("native PMP DMA dispatcher was abandoned");
        }
        Ok(state.replies.remove(&ticket))
    }
    pub(super) fn check(
        &self,
        descriptor: Descriptor,
        offset: u64,
        bytes: u64,
        life: Life,
    ) -> Result<(), &'static str> {
        let state = self.state.borrow();
        if !state.alive {
            return Err("native PMP DMA dispatcher was abandoned");
        }
        let grant = state
            .grants
            .get(&descriptor.id)
            .ok_or("native PMP DMA descriptor is not owned")?;
        if grant.descriptor != descriptor || grant.life != life {
            return Err("native PMP DMA descriptor/lifetime changed");
        }
        if offset
            .checked_add(bytes)
            .is_none_or(|end| end > descriptor.bytes)
        {
            return Err("native PMP DMA extent exceeds its actual descriptor");
        }
        Ok(())
    }
    pub(super) fn map(&self, key: Key, iova: u64, bytes: u64, flags: u32) -> Completion<Client> {
        let (index, ticket, descriptor) = {
            let mut state = self.state.borrow_mut();
            if !state.alive {
                return Completion::Refused("native PMP DMA dispatcher was abandoned");
            }
            if iova == 0
                || !iova.is_multiple_of(0x1000)
                || bytes == 0
                || !bytes.is_multiple_of(0x1000)
                || iova.checked_add(bytes).is_none()
                || flags != 0x202
                || !bytes.is_multiple_of(state.configuration.synchronization_granule)
                || usize::try_from(bytes).is_err()
            {
                return Completion::Refused(
                    "native PMP DMA geometry/flags are not source qualified",
                );
            }
            let index = state.maps.iter().position(|attempt| attempt.key.same(&key));
            if let Some(index) = index {
                let attempt = &state.maps[index];
                if (
                    attempt.descriptor.iova,
                    attempt.descriptor.bytes,
                    attempt.descriptor.flags,
                ) != (iova, bytes, flags)
                    || attempt.returned
                {
                    return Completion::Refused(
                        "native PMP DMA map request changed or was already delivered",
                    );
                }
                (index, attempt.ticket, attempt.descriptor)
            } else {
                let Some(id) = state.serial.checked_add(1) else {
                    return Completion::Refused("native PMP DMA descriptor identity exhausted");
                };
                state.serial = id;
                let descriptor = Descriptor {
                    id,
                    iova,
                    bytes,
                    flags,
                    route: state.route,
                };
                state.maps.push(MapAttempt {
                    key,
                    descriptor,
                    ticket: None,
                    returned: false,
                });
                (state.maps.len() - 1, None, descriptor)
            }
        };
        let Some(ticket) = ticket else {
            return match self.enqueue(Op::Map(descriptor)) {
                Ok(ticket) => {
                    self.state.borrow_mut().maps[index].ticket = Some(ticket);
                    Completion::Busy { deadline: None }
                }
                Err(error) => Completion::Refused(error),
            };
        };
        match self.reply(ticket) {
            Err(error) => Completion::Refused(error),
            Ok(None) => Completion::Busy { deadline: None },
            Ok(Some(Completion::Busy { deadline })) => Completion::Busy { deadline },
            Ok(Some(Completion::Refused(error))) => Completion::Refused(error),
            Ok(Some(Completion::Retired {
                value:
                    Reply {
                        output: Output::Mapped(actual),
                        refusal,
                    },
                refusal: outer,
            })) => {
                if actual != descriptor {
                    return Completion::Refused("native PMP DMA map receipt changed descriptor");
                }
                self.state.borrow_mut().maps[index].returned = true;
                Completion::Retired {
                    value: Client::new(self.clone(), descriptor),
                    refusal: refusal.or(outer),
                }
            }
            Ok(Some(_)) => Completion::Refused("native PMP DMA map receipt has wrong operation"),
        }
    }
    pub fn map_reporting(
        &self,
        request: &reporting::resources::Request,
        buffer: reporting::wire::Buffer,
        flags: u32,
    ) -> Completion<reporting::resources::MapResult<ReportingMapping>> {
        convert(
            self.map(
                Key::Reporting(request.clone()),
                buffer.bus,
                buffer.bytes,
                flags,
            ),
            |client| reporting::resources::MapResult::Mapped(ReportingMapping(client)),
        )
    }
    pub fn map_trace(
        &self,
        request: &trace::Request,
        geometry: trace::Geometry,
    ) -> Completion<TraceMapping> {
        convert(
            self.map(
                Key::Trace(request.clone()),
                geometry.address,
                geometry.bytes,
                geometry.flags,
            ),
            TraceMapping::from,
        )
    }
}
pub(super) fn convert<T, U>(c: Completion<T>, f: impl FnOnce(T) -> U) -> Completion<U> {
    match c {
        Completion::Busy { deadline } => Completion::Busy { deadline },
        Completion::Refused(e) => Completion::Refused(e),
        Completion::Retired { value, refusal } => Completion::Retired {
            value: f(value),
            refusal,
        },
    }
}
pub(super) fn reason(error: DmaError) -> &'static str {
    match error {
        DmaError::Fault(_) => "actual PMP DART translation fault",
        DmaError::Memory => "actual PMP canonical RAM transfer refused",
        DmaError::Unsupported(reason) => reason,
    }
}
