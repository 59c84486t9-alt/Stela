//! Asynchronous event sources (interrupts, debug events) of a software PE.
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceClass {
    Irq,
    Fiq,
    SError,
    Nmi,
    Debug,
}

struct SourceKey {
    domain: Arc<()>,
    id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Editr { word: u32, sequence: u64 },
    CrossHalt { sequence: u64 },
}
struct PendingEvent {
    source: u64,
    kind: PendingKind,
}
#[derive(Debug)]
struct CrossHaltOutput {
    source: u64,
    sequence: u64,
    targets: Vec<u64>,
}

pub(super) struct SoftwareAsyncDomain {
    identity: Arc<()>,
    next_source: u64,
    next_event: u64,
    cross_halt_sequence: u64,
    cross_halt_outputs: Vec<CrossHaltOutput>,
    registered: BTreeMap<u64, SourceClass>,
    pending: VecDeque<PendingEvent>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AsyncError {
    RegisteredProducer,
    PendingEvent,
    WrongProducer,
    SequenceExhausted,
    Capacity,
    UnsupportedPending,
    SourceChanged,
}

impl SoftwareAsyncDomain {
    /// # Safety
    /// The software CPU constructor owns this domain and every possible IRQ,
    /// FIQ, SError, NMI and debug producer for its lifetime. Every producer
    /// (timers, devices, other PEs, debug injection) must register here before
    /// it can signal, and nothing may signal around the domain. Never use this
    /// for hardware or for a domain that already has producers.
    pub(super) unsafe fn fresh_software_pe() -> Self {
        Self {
            identity: Arc::new(()),
            next_source: 0,
            next_event: 0,
            cross_halt_sequence: 0,
            cross_halt_outputs: Vec::new(),
            registered: BTreeMap::new(),
            pending: VecDeque::new(),
        }
    }

    fn register(&mut self, class: SourceClass) -> Result<SourceKey, AsyncError> {
        let id = self
            .next_source
            .checked_add(1)
            .ok_or(AsyncError::SequenceExhausted)?;
        self.next_source = id;
        self.registered.insert(id, class);
        Ok(SourceKey {
            domain: self.identity.clone(),
            id,
        })
    }

    /// Registration is permanent: dropping a producer neither clears its
    /// pending effects nor restores a domain without producers. Any registered
    /// producer needs arbitration and delivery, which this provider does not
    /// implement.
    pub(super) fn lease_no_sources(&mut self) -> Result<NoAsyncSources<'_>, AsyncError> {
        if !self.registered.is_empty() {
            return Err(AsyncError::RegisteredProducer);
        }
        if !self.pending.is_empty() {
            return Err(AsyncError::PendingEvent);
        }
        Ok(NoAsyncSources {
            identity: Arc::clone(&self.identity),
            domain: self,
        })
    }
}

/// An exclusive borrow of the whole producer registry, which prevents
/// registration or injection while it is held.
pub(super) struct NoAsyncSources<'pe> {
    identity: Arc<()>,
    domain: &'pe mut SoftwareAsyncDomain,
}

// Additive source inside retirement::software_async. Lead owns application.
impl NoAsyncSources<'_> {
    pub(super) fn check_registry(&self) -> Result<(), AsyncError> {
        if !Arc::ptr_eq(&self.identity, &self.domain.identity) {
            return Err(AsyncError::WrongProducer);
        }
        // Every asynchronous class belongs to this complete software domain.
        // No registered producer of any class is admitted by this route.
        let classes = [
            SourceClass::Irq,
            SourceClass::Fiq,
            SourceClass::SError,
            SourceClass::Nmi,
            SourceClass::Debug,
        ];
        if self
            .domain
            .pending
            .iter()
            .any(|event| !self.domain.registered.contains_key(&event.source))
        {
            return Err(AsyncError::WrongProducer);
        }
        if classes.iter().any(|class| {
            self.domain
                .registered
                .values()
                .any(|registered| registered == class)
        }) {
            return Err(AsyncError::RegisteredProducer);
        }
        if !self.domain.pending.is_empty() {
            return Err(AsyncError::PendingEvent);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

mod debug;
pub(super) use debug::{CtiRoute, DebugSources, EditrSource};
