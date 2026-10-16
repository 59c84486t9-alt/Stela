//! Private real source-registration/pending owner for a declared software PE.
//! This does not infer the interrupt inventory of Apple hardware or firmware.
//! No Clone/default or interior-mutable producer aliases exist. All producer
//! registration/injection requires this same actual domain's exclusive borrow.
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
    #[cfg(test)]
    Unqualified,
    Editr {
        word: u32,
        sequence: u64,
    },
    CrossHalt {
        sequence: u64,
    },
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
    /// The actual fresh declared-software CPU constructor owns this domain and
    /// every possible IRQ/FIQ/SError/NMI/debug producer for its executable
    /// lifetime. Each producer must register here before it can emit, including
    /// timers/devices/other PEs and software debug injection. No external raw
    /// signal/MMIO/queue writer may bypass this domain. This constructor may not
    /// be used to assert anything about a captured hardware CPU or an existing
    /// PE, or to replace a domain with registered/unknown producers.
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

    #[cfg(test)]
    fn inject(&mut self, key: &SourceKey) -> Result<(), AsyncError> {
        if !Arc::ptr_eq(&self.identity, &key.domain) || !self.registered.contains_key(&key.id) {
            return Err(AsyncError::WrongProducer);
        }
        self.pending.push_back(PendingEvent {
            source: key.id,
            kind: PendingKind::Unqualified,
        });
        Ok(())
    }

    /// Registration is intentionally sticky. Dropping a producer does not
    /// erase architectural pending effects or reestablish a no-source universe.
    /// A nonempty registry requires the real source-class arbitration/delivery
    /// implementation, which this first bounded provider explicitly lacks.
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

/// Lifetime-bound exclusive borrow of the actual complete producer registry.
/// It cannot be minted from an empty pending queue, ID field or copied epoch.
/// Its lifetime prevents any registration/injection during the retained run.
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
