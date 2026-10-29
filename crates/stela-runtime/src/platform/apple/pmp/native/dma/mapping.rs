//! Mapping handles over a `Broker`. `ReportingMapping` and `TraceMapping`
//! turn reads, writes, synchronization, unmap and release into queued
//! operations that keep their reached prefix across Busy results, and refuse a
//! request that has already retired or has changed.
use super::super::{platform::owner::Completion, reporting, trace};
use super::{
    broker::{Broker, Descriptor, Key, Life, Op, Output, Reply, convert, reason},
    service::Effect,
};
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::bus::Access;
use stela_contracts::refuse;

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
    fn begin(&mut self, key: Key, offset: u64, action: Action) -> Result<()> {
        if self
            .last_retired
            .as_ref()
            .is_some_and(|last| last.same(&key))
        {
            return Err(refuse!("native PMP DMA request was already retired"));
        }
        if let Some(p) = &self.pending {
            if !p.key.same(&key) || p.offset != offset || p.action != action {
                return Err(refuse!(
                    "native PMP DMA request changed before its prefix retired"
                ));
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
            return Err(refuse!(
                "native PMP DMA empty transfer is not a source effect"
            ));
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
                if data.len() > bytes - p.cursor
                    || fault.as_ref().is_some_and(|f| f.completed != data.len())
                {
                    return Completion::Refused(refuse!(
                        "native PMP DMA read receipt has invalid prefix"
                    ));
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
                        diagnostic
                            .unwrap_or(refuse!("native PMP DMA read retired an incomplete extent")),
                    )
                }
            }
            Completion::Retired { .. } => {
                Completion::Refused(refuse!("native PMP DMA read received another operation"))
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
                    || fault.as_ref().is_some_and(|f| f.completed != completed)
                {
                    return Completion::Refused(refuse!(
                        "native PMP DMA write receipt has invalid prefix"
                    ));
                }
                p.cursor += completed;
                let diagnostic = fault.map(|f| reason(f.error)).or(refusal).or(outer);
                if whole && p.cursor < bytes.len() {
                    return Completion::Refused(
                        diagnostic.unwrap_or(refuse!(
                            "native PMP DMA write retired an incomplete extent"
                        )),
                    );
                }
                if !whole && completed == 0 {
                    // No bytes committed. Keep the same source request but a
                    // fresh transfer ticket on a caller-authorized retry.
                    return Completion::Refused(
                        diagnostic.unwrap_or(refuse!("native PMP DMA write has no retired prefix")),
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
                Completion::Refused(refuse!("native PMP DMA write received another operation"))
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
            Completion::Retired { .. } => Completion::Refused(refuse!(
                "native PMP DMA synchronization received another operation"
            )),
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
    fn synchronization_granule(&self) -> Result<u64> {
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
            return Completion::Refused(refuse!(
                "native PMP DMA synchronization is not runtime-granule aligned"
            ));
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
    /// Root must join trace memory-loss lifecycle before dropping the
    /// owner. Drop performs no invented remote unmap/release.
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
mod tests;
