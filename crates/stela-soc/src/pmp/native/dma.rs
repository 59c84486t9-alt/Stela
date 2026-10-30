//! Canonical native PMP DMA broker. Source-checked zero ASC mask means the
//! AP-published address is the mapper IOVA, never an AP physical address.
//! See loader/pmp-mapper-address-r1 and docs/research/apple-mcc.md. No firmware
//! executes and no queued request is reported as a retired memory effect.
mod broker;
mod mapping;
mod service;
pub use broker::{Broker, Configuration, Descriptor, Owners, Route, ServiceRequest, pair};
pub use mapping::{ReportingMapping, TraceMapping};
pub use service::{Coherence, Effect, Service};
