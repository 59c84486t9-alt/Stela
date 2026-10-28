//! Mapping handles over a `Broker`. `ReportingMapping` and `TraceMapping`
//! turn reads, writes, synchronization, unmap and release into queued
//! operations that keep their reached prefix across Busy results, and refuse a
//! request that has already retired or has changed.
use super::super::{platform::owner::Completion, reporting, trace};
use super::{
    broker::{Broker, Descriptor, Key, Life, Op, Output, Reply, convert, reason},
    service::Effect,
};
use alloc::vec::Vec;
use stela_contracts::bus::Access;

#[derive(Clone, PartialEq, Eq)]
enum Action {
    Read(usize),
    Write(Vec<u8>),
    Effect(Effect),
}
struct Pending {
    key: Key,
    offset: u64,
    action: Action,
    cursor: usize,
    read: Vec<u8>,
    ticket: Option<u64>,
}
pub(super) struct Client {
    broker: Broker,
    descriptor: Descriptor,
    pending: Option<Pending>,
    last_retired: Option<Key>,
}
impl Client {
    pub(super) fn new(broker: Broker, descriptor: Descriptor) -> Self {
        Self {
            broker,
            descriptor,
            pending: None,
            last_retired: None,
        }
    }
    fn begin(&mut self, key: Key, offset: u64, action: Action) -> Result<(), &'static str> {
        if self
            .last_retired
            .as_ref()
            .is_some_and(|last| last.same(&key))
        {
            return Err("native PMP DMA request was already retired");
        }
        if let Some(p) = &self.pending {
            if !p.key.same(&key) || p.offset != offset || p.action != action {
                return Err("native PMP DMA request changed before its prefix retired");
            }
            return Ok(());
        }
        let bytes = match &action {
            Action::Read(n) => *n as u64,
            Action::Write(b) => b.len() as u64,
            Action::Effect(Effect::ReportingSynchronize { bytes, .. }) => *bytes,
            _ => 0,
        };
        let life = if action == Action::Effect(Effect::Release) {
            Life::Unmapped
        } else {
            Life::Mapped
        };
        self.broker.check(self.descriptor, offset, bytes, life)?;
        if matches!(&action, Action::Read(0)) || matches!(&action,Action::Write(b) if b.is_empty())
        {
            return Err("native PMP DMA empty transfer is not a source effect");
        }
        self.pending = Some(Pending {
            key,
            offset,
            action,
            cursor: 0,
            read: Vec::new(),
            ticket: None,
        });
        Ok(())
    }
    fn poll(&mut self) -> Completion<Reply> {
        let p = self.pending.as_mut().unwrap();
        let Some(ticket) = p.ticket else {
            let op = match &p.action {
                Action::Read(bytes) => Op::Read {
                    descriptor: self.descriptor,
                    offset: p.offset + p.cursor as u64,
                    bytes: bytes - p.cursor,
                },
                Action::Write(bytes) => Op::Write {
                    descriptor: self.descriptor,
                    offset: p.offset + p.cursor as u64,
                    bytes: bytes[p.cursor..].to_vec(),
                },
                Action::Effect(effect) => Op::Effect {
                    descriptor: self.descriptor,
                    effect: *effect,
                },
            };
            return match self.broker.enqueue(op) {
                Ok(ticket) => {
                    p.ticket = Some(ticket);
                    Completion::Busy { deadline: None }
                }
                Err(error) => Completion::Refused(error),
            };
        };
        match self.broker.reply(ticket) {
            Err(error) => Completion::Refused(error),
            Ok(None) => Completion::Busy { deadline: None },
            Ok(Some(Completion::Retired { value, refusal })) => {
                p.ticket = None;
                Completion::Retired { value, refusal }
            }
            Ok(Some(other)) => other,
        }
    }
    fn read(&mut self, key: Key, offset: u64, bytes: usize) -> Completion<Vec<u8>> {
        if let Err(error) = self.begin(key, offset, Action::Read(bytes)) {
            return Completion::Refused(error);
        }
        match self.poll() {
            Completion::Busy { deadline } => Completion::Busy { deadline },
            Completion::Refused(error) => Completion::Refused(error),
            Completion::Retired {
                value:
                    Reply {
                        output: Output::Read { bytes: data, fault },
                        refusal,
                    },
                refusal: outer,
            } => {
                let p = self.pending.as_mut().unwrap();
                if data.len() > bytes - p.cursor || fault.is_some_and(|f| f.completed != data.len())
                {
                    return Completion::Refused("native PMP DMA read receipt has invalid prefix");
                }
                p.cursor += data.len();
                p.read.extend(data);
                let diagnostic = fault.map(|f| reason(f.error)).or(refusal).or(outer);
                if p.cursor == bytes {
                    let p = self.pending.take().unwrap();
                    self.last_retired = Some(p.key);
                    Completion::Retired {
                        value: p.read,
                        refusal: diagnostic,
                    }
                } else {
                    Completion::Refused(
                        diagnostic.unwrap_or("native PMP DMA read retired an incomplete extent"),
                    )
                }
            }
            Completion::Retired { .. } => {
                Completion::Refused("native PMP DMA read received another operation")
            }
        }
    }
    fn write(&mut self, key: Key, offset: u64, bytes: &[u8], whole: bool) -> Completion<usize> {
        if let Err(error) = self.begin(key, offset, Action::Write(bytes.to_vec())) {
            return Completion::Refused(error);
        }
        match self.poll() {
            Completion::Busy { deadline } => Completion::Busy { deadline },
            Completion::Refused(error) => Completion::Refused(error),
            Completion::Retired {
                value:
                    Reply {
                        output: Output::Written { completed, fault },
                        refusal,
                    },
                refusal: outer,
            } => {
                let p = self.pending.as_mut().unwrap();
                if completed > bytes.len() - p.cursor
                    || fault.is_some_and(|f| f.completed != completed)
                {
                    return Completion::Refused("native PMP DMA write receipt has invalid prefix");
                }
                p.cursor += completed;
                let diagnostic = fault.map(|f| reason(f.error)).or(refusal).or(outer);
                if whole && p.cursor < bytes.len() {
                    return Completion::Refused(
                        diagnostic.unwrap_or("native PMP DMA write retired an incomplete extent"),
                    );
                }
                if !whole && completed == 0 {
                    // No bytes committed. Keep the same source request but a
                    // fresh actual transfer ticket on a caller-authorized retry.
                    return Completion::Refused(
                        diagnostic.unwrap_or("native PMP DMA write has no retired prefix"),
                    );
                }
                let p = self.pending.take().unwrap();
                self.last_retired = Some(p.key);
                Completion::Retired {
                    value: if whole { p.cursor } else { completed },
                    refusal: diagnostic,
                }
            }
            Completion::Retired { .. } => {
                Completion::Refused("native PMP DMA write received another operation")
            }
        }
    }
    fn effect(&mut self, key: Key, effect: Effect) -> Completion<()> {
        let offset = if let Effect::ReportingSynchronize { offset, .. } = effect {
            offset
        } else {
            0
        };
        if let Err(error) = self.begin(key, offset, Action::Effect(effect)) {
            return Completion::Refused(error);
        }
        match self.poll() {
            Completion::Busy { deadline } => Completion::Busy { deadline },
            Completion::Refused(error) => Completion::Refused(error),
            Completion::Retired {
                value:
                    Reply {
                        output: Output::Unit,
                        refusal,
                    },
                refusal: outer,
            } => {
                self.last_retired = Some(self.pending.take().unwrap().key);
                Completion::Retired {
                    value: (),
                    refusal: refusal.or(outer),
                }
            }
            Completion::Retired { .. } => {
                Completion::Refused("native PMP DMA synchronization received another operation")
            }
        }
    }
}
/// Non-Clone mapping handle. A descriptor does not hold a host pointer or PA.
pub struct ReportingMapping(pub(super) Client);
impl ReportingMapping {
    pub fn descriptor(&self) -> Descriptor {
        self.0.descriptor
    }
    pub fn unmap(
        &mut self,
        request: &reporting::resources::Request,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        self.0
            .effect(Key::Reporting(request.clone()), Effect::Unmap)
    }
    pub fn release(
        &mut self,
        request: &reporting::resources::Request,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        self.0
            .effect(Key::Reporting(request.clone()), Effect::Release)
    }
}
impl reporting::resources::Mapping for ReportingMapping {
    fn geometry(&self) -> reporting::wire::Buffer {
        reporting::wire::Buffer {
            bus: self.0.descriptor.iova,
            bytes: self.0.descriptor.bytes,
        }
    }
    fn synchronization_granule(&self) -> Result<u64, &'static str> {
        Ok(self.0.broker.synchronization_granule())
    }
    fn write(
        &mut self,
        request: &reporting::resources::Request,
        offset: u64,
        bytes: &[u8],
        _: &mut Access<'_>,
    ) -> Completion<usize> {
        self.0
            .write(Key::Reporting(request.clone()), offset, bytes, false)
    }
    fn read(
        &mut self,
        request: &reporting::resources::Request,
        offset: u64,
        bytes: usize,
        _: &mut Access<'_>,
    ) -> Completion<Vec<u8>> {
        self.0.read(Key::Reporting(request.clone()), offset, bytes)
    }
    fn synchronize(
        &mut self,
        request: &reporting::resources::Request,
        offset: u64,
        bytes: u64,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        let granule = self.0.broker.synchronization_granule();
        if !offset.is_multiple_of(granule) || !bytes.is_multiple_of(granule) {
            return Completion::Refused(
                "native PMP DMA synchronization is not runtime-granule aligned",
            );
        }
        self.0.effect(
            Key::Reporting(request.clone()),
            Effect::ReportingSynchronize { offset, bytes },
        )
    }
}
pub struct TraceMapping(Client);
impl From<Client> for TraceMapping {
    fn from(client: Client) -> Self {
        Self(client)
    }
}
impl TraceMapping {
    pub fn descriptor(&self) -> Descriptor {
        self.0.descriptor
    }
    /// Root must join actual trace memory-loss lifecycle before dropping the
    /// owner. Drop performs no fabricated remote unmap/release.
    pub fn unmap(&mut self, request: &trace::Request, _: &mut Access<'_>) -> Completion<()> {
        self.0.effect(Key::Trace(request.clone()), Effect::Unmap)
    }
    pub fn release(&mut self, request: &trace::Request, _: &mut Access<'_>) -> Completion<()> {
        self.0.effect(Key::Trace(request.clone()), Effect::Release)
    }
}
impl trace::Mapping for TraceMapping {
    fn geometry(&self) -> trace::Geometry {
        trace::Geometry {
            address: self.0.descriptor.iova,
            bytes: self.0.descriptor.bytes,
            flags: self.0.descriptor.flags,
        }
    }
    fn read(
        &mut self,
        request: &trace::Request,
        offset: u64,
        output: &mut [u8],
        _: &mut Access<'_>,
    ) -> Completion<()> {
        convert(
            self.0
                .read(Key::Trace(request.clone()), offset, output.len()),
            |data| output.copy_from_slice(&data),
        )
    }
    fn write(
        &mut self,
        request: &trace::Request,
        offset: u64,
        input: &[u8],
        _: &mut Access<'_>,
    ) -> Completion<()> {
        convert(
            self.0
                .write(Key::Trace(request.clone()), offset, input, true),
            |_| (),
        )
    }
    fn synchronize(
        &mut self,
        request: &trace::Request,
        operation: trace::Synchronization,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        self.0.effect(
            Key::Trace(request.clone()),
            match operation {
                trace::Synchronization::Prepare => Effect::TracePrepare,
                trace::Synchronization::Complete => Effect::TraceComplete,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Coherence, Configuration, Owners, Route, Service, ServiceRequest, pair};
    use super::*;
    use alloc::{rc::Rc, vec};
    use core::cell::Cell;
    use {
        stela_contracts::dma, stela_contracts::dma::DmaError, stela_contracts::dma::Memory,
        stela_contracts::dma::Port, stela_contracts::dma::TransferFault,
        stela_contracts::interrupt::InterruptLatch,
    };
    struct Ram {
        bytes: Vec<u8>,
        writes: Vec<(u64, usize)>,
        short: Option<usize>,
    }
    impl Memory for Ram {
        fn read(&mut self, p: u64, b: &mut [u8]) -> bool {
            b.copy_from_slice(&self.bytes[(p - 0x8000) as usize..(p - 0x8000) as usize + b.len()]);
            true
        }
        fn write(&mut self, p: u64, b: &[u8]) -> bool {
            self.writes.push((p, b.len()));
            self.bytes[(p - 0x8000) as usize..(p - 0x8000) as usize + b.len()].copy_from_slice(b);
            true
        }
        fn check_range(&mut self, p: u64, n: usize, _: bool) -> Result<(), DmaError> {
            if p >= 0x8000 && p.checked_add(n as u64).is_some_and(|end| end <= 0x9000) {
                Ok(())
            } else {
                Err(DmaError::Memory)
            }
        }
        fn write_progress(&mut self, p: u64, b: &[u8]) -> Result<(), TransferFault> {
            if let Some(n) = self.short.take() {
                let n = n.min(b.len());
                self.write(p, &b[..n]);
                return Err(TransferFault {
                    error: DmaError::Memory,
                    completed: n,
                });
            }
            self.write(p, b);
            Ok(())
        }
    }
    struct Shift {
        hole: Option<u64>,
    }
    impl dma::Iommu for Shift {
        fn page(&self) -> u64 {
            16
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            _: usize,
            iova: u64,
            _: u64,
            _: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            if self.hole == Some(iova / 16) {
                Err(DmaError::Fault(7))
            } else {
                Ok(iova + 0x4000)
            }
        }
    }
    struct Sync {
        broker: Broker,
        effects: Vec<Effect>,
        busy: bool,
        calls: Rc<Cell<usize>>,
    }
    impl Coherence for Sync {
        fn effect(
            &mut self,
            _: &ServiceRequest,
            _: &Owners,
            d: Descriptor,
            e: Effect,
            _: &mut Port<'_, '_>,
        ) -> Completion<()> {
            // This accesses the shared broker inside the actual callback. A
            // held RefCell borrow in dispatch would panic rather than pass.
            assert_eq!(self.broker.route(), d.route);
            self.calls.set(self.calls.get() + 1);
            if self.busy {
                self.busy = false;
                return Completion::Busy { deadline: Some(8) };
            }
            self.effects.push(e);
            Completion::Retired {
                value: (),
                refusal: None,
            }
        }
    }
    fn setup() -> (Broker, Service, Owners, Ram, Shift, Sync) {
        let owners = Owners {
            dart: Rc::new(()),
            canonical_ram: Rc::new(()),
            allocator: Rc::new(()),
        };
        let (broker, service) = pair(
            Route {
                mapper: 0x7d,
                iommu: 0,
                instance: 0,
                context: 0,
                stream: 0,
            },
            owners.clone(),
            Configuration {
                mapper_index: 0,
                asc_dram_mask: 0,
                synchronization_granule: 16,
            },
        )
        .unwrap();
        let sync = Sync {
            broker: broker.clone(),
            effects: Vec::new(),
            busy: false,
            calls: Rc::new(Cell::new(0)),
        };
        (
            broker,
            service,
            owners,
            Ram {
                bytes: vec![0; 0x1000],
                writes: Vec::new(),
                short: None,
            },
            Shift { hole: None },
            sync,
        )
    }
    fn dispatch(
        service: &mut Service,
        owners: &Owners,
        ram: &mut Ram,
        dart: &mut Shift,
        sync: &mut Sync,
    ) -> Completion<()> {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 1, &mut latch);
        service.dispatch(
            owners,
            &mut Port {
                iommu: dart,
                stream: 0,
                memory: ram,
                access: &mut access,
            },
            sync,
        )
    }
    fn mapped(
        broker: &Broker,
        service: &mut Service,
        owners: &Owners,
        ram: &mut Ram,
        dart: &mut Shift,
        sync: &mut Sync,
    ) -> Client {
        let key = Key::Authored(Rc::new(()));
        assert!(matches!(
            broker.map(key.clone(), 0x4000, 0x1000, 0x202),
            Completion::Busy { .. }
        ));
        assert!(matches!(
            dispatch(service, owners, ram, dart, sync),
            Completion::Retired { .. }
        ));
        match broker.map(key, 0x4000, 0x1000, 0x202) {
            Completion::Retired {
                value,
                refusal: None,
            } => value,
            _ => panic!("authored actual map did not retire"),
        }
    }
    #[test]
    fn queued_io_requires_the_same_real_dispatcher_and_actual_port() {
        let (broker, mut service, owners, mut ram, mut dart, mut sync) = setup();
        let key = Key::Authored(Rc::new(()));
        assert!(matches!(
            broker.map(key.clone(), 0x4000, 0x1000, 0x202),
            Completion::Busy { .. }
        ));
        assert!(ram.writes.is_empty());
        assert!(sync.effects.is_empty());
        let wrong = Owners {
            allocator: Rc::new(()),
            ..owners.clone()
        };
        assert!(matches!(
            dispatch(&mut service, &wrong, &mut ram, &mut dart, &mut sync),
            Completion::Refused(_)
        ));
        assert!(matches!(
            broker.map(key.clone(), 0x4000, 0x1000, 0x202),
            Completion::Busy { .. }
        ));
        assert!(matches!(
            dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync),
            Completion::Retired { .. }
        ));
        let mut client = match broker.map(key, 0x4000, 0x1000, 0x202) {
            Completion::Retired { value, .. } => value,
            _ => panic!(),
        };
        let key = Key::Authored(Rc::new(()));
        assert!(matches!(
            client.write(key.clone(), 0, &[1; 8], false),
            Completion::Busy { .. }
        ));
        assert!(ram.writes.is_empty());
        dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
        assert!(matches!(
            client.write(key.clone(), 0, &[1; 8], false),
            Completion::Retired {
                value: 8,
                refusal: None
            }
        ));
        assert_eq!(ram.writes, [(0x8000, 8)]);
        assert!(matches!(
            client.write(key, 0, &[1; 8], false),
            Completion::Refused(_)
        ));
    }
    #[test]
    fn trace_write_retains_later_page_and_within_page_prefixes_without_replay() {
        for short in [None, Some(3)] {
            let (broker, mut service, owners, mut ram, mut dart, mut sync) = setup();
            let mut client = mapped(
                &broker,
                &mut service,
                &owners,
                &mut ram,
                &mut dart,
                &mut sync,
            );
            ram.short = short;
            if short.is_none() {
                dart.hole = Some(0x4010 / 16);
            }
            let key = Key::Authored(Rc::new(()));
            let data = [9; 32];
            assert!(matches!(
                client.write(key.clone(), 0, &data, true),
                Completion::Busy { .. }
            ));
            dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
            assert!(matches!(
                client.write(key.clone(), 0, &data, true),
                Completion::Refused(_)
            ));
            let prefix = short.unwrap_or(16);
            assert_eq!(ram.writes, [(0x8000, prefix)]);
            assert!(matches!(
                client.write(key.clone(), 0, &[8; 32], true),
                Completion::Refused(_)
            ));
            dart.hole = None;
            assert!(matches!(
                client.write(key.clone(), 0, &data, true),
                Completion::Busy { .. }
            ));
            dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
            assert!(matches!(
                client.write(key, 0, &data, true),
                Completion::Retired {
                    value: 32,
                    refusal: None
                }
            ));
            assert_eq!(ram.writes.iter().filter(|(p, _)| *p == 0x8000).count(), 1);
            assert_eq!(&ram.bytes[..32], &data);
        }
    }
    #[test]
    fn sync_and_lifecycle_wait_for_real_coherence_and_reads_rewalk_changed_dart() {
        let (broker, mut service, owners, mut ram, mut dart, mut sync) = setup();
        let mut client = mapped(
            &broker,
            &mut service,
            &owners,
            &mut ram,
            &mut dart,
            &mut sync,
        );
        let key = Key::Authored(Rc::new(()));
        sync.busy = true;
        assert!(matches!(
            client.effect(key.clone(), Effect::TracePrepare),
            Completion::Busy { .. }
        ));
        assert!(matches!(
            dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync),
            Completion::Busy { deadline: Some(8) }
        ));
        assert!(matches!(
            client.effect(key.clone(), Effect::TracePrepare),
            Completion::Busy { .. }
        ));
        dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
        assert!(matches!(
            client.effect(key, Effect::TracePrepare),
            Completion::Retired { .. }
        ));
        dart.hole = Some(0x4000 / 16);
        let read = Key::Authored(Rc::new(()));
        assert!(matches!(
            client.read(read.clone(), 0, 8),
            Completion::Busy { .. }
        ));
        dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
        assert!(matches!(
            client.read(read.clone(), 0, 8),
            Completion::Refused(_)
        ));
        dart.hole = None;
        assert!(matches!(
            client.read(read.clone(), 0, 8),
            Completion::Busy { .. }
        ));
        dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
        assert!(
            matches!(client.read(read,0,8),Completion::Retired { value,refusal:None } if value==[0;8])
        );
        for effect in [Effect::Unmap, Effect::Release] {
            let key = Key::Authored(Rc::new(()));
            assert!(matches!(
                client.effect(key.clone(), effect),
                Completion::Busy { .. }
            ));
            dispatch(&mut service, &owners, &mut ram, &mut dart, &mut sync);
            assert!(matches!(
                client.effect(key, effect),
                Completion::Retired { .. }
            ));
        }
        assert!(matches!(
            client.read(Key::Authored(Rc::new(())), 0, 8),
            Completion::Refused(_)
        ));
        assert_eq!(
            &sync.effects[sync.effects.len() - 2..],
            &[Effect::Unmap, Effect::Release]
        );
    }
}
